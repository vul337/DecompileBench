import argparse
import functools
import os
import pathlib
import re
import subprocess
from itertools import chain
from multiprocessing import Pool

import clang.cindex
import datasets
import yaml
from loguru import logger
from tqdm import tqdm

from evaluate_rsr import DockerContainer
from libclang import set_libclang_path

set_libclang_path()

repo_path = pathlib.Path(__file__).resolve().parent


parser = argparse.ArgumentParser(description="Compile OSS-Fuzz projects")
parser.add_argument('--config', type=str, default="./config.yaml",
                    help='Path to the configuration file')
parser.add_argument('--output', type=str, default='./dataset/ossfuzz',
                    help='Output directory for compiled datasets')
parser.add_argument('--num_workers', type=int, default=os.cpu_count(),
                    help='Number of workers to compile the projects')

args = parser.parse_args()

with open(args.config, 'r') as f:
    config = yaml.safe_load(f)

oss_fuzz_path = pathlib.Path(config['oss_fuzz_path'])
opt_options = config['opts']
OUTPUT_PATH = pathlib.Path(args.output).resolve()

project_path = oss_fuzz_path / 'build' / 'functions'

projects = [p for p in project_path.iterdir() if p.is_dir()]
num_projects = len(projects)
print(f"Number of projects: {num_projects}")


def find_functions(file_path):
    # Create an index
    index = clang.cindex.Index.create()

    # Parse the C file
    translation_unit = index.parse(file_path)

    # Traverse the AST to find functions
    for cursor in translation_unit.cursor.walk_preorder():
        if cursor.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            yield cursor


def is_elf(file_path):
    if file_path.is_dir():
        return False
    with open(file_path, 'rb') as f:
        elf_magic_number = b'\x7fELF'
        file_magic_number = f.read(4)
        return file_magic_number == elf_magic_number


def extract_function_body(splited_contet, child):
    sr = child.extent
    start = sr.start
    end = sr.end
    start_line = start.line
    start_column = start.column
    end_line = end.line
    end_column = end.column

    if start_column == end_column and start_line == end_line:
        return None

    src = b''

    if start_line == end_line:
        src = splited_contet[start_line-1][start_column-1:end_column]
    else:
        for line_no in range(start_line, end_line+1):
            line = splited_contet[line_no-1]

            if line == start_line:
                src += line[start_column-1:] + b'\n'
            elif line == end_line:
                src += line[:end_column]
            else:
                src += line + b'\n'
    return src


undef_pattern = re.compile(r'#undef\s.*')


def process_project(project):
    test_list = []
    project_name = str(project).split('/')[-1]
    if project.is_dir():
        if project.name == 'cpython3':
            return
        for file in project.iterdir():
            if not file.is_file():
                continue
            content = file.read_bytes()
            try:
                splited_contet = content.splitlines()
                content = content.decode('utf-8', errors='replace')
            except UnicodeDecodeError as e:
                print(f"Error decoding file {file}: {e}")
                return
            for function in find_functions(file):
                func_name = function.spelling
                if func_name != file.stem:
                    continue
                if not function.is_definition():
                    declaration_body = extract_function_body(
                        splited_contet, function)
                    if declaration_body:
                        declaration_body = declaration_body.decode()
                        content = content.replace(declaration_body, '', 1)
                        continue

                test_func = extract_function_body(
                    splited_contet, function)

                if test_func:
                    test_func = test_func.decode()

                    test_func_pos = content.find(test_func)
                    include_content_part1 = content[:test_func_pos]
                    test_func_end = test_func_pos + len(test_func)
                    include_content_part2 = content[test_func_end:]

                    include_content_part2 = undef_pattern.sub(
                        '', include_content_part2)

                    test_list.append({
                        'project': project.stem,
                        'file': file.stem,
                        'func': test_func,
                        'include': include_content_part1 + include_content_part2,
                    })
    return test_list


def process_project_linearly(project_path):
    test_lists = []
    for project in tqdm(reversed(list(project_path.iterdir()))):
        result = process_project(project)
        if result is not None:
            test_lists.extend(result)
    return test_lists


test_list = process_project_linearly(project_path)
ds = datasets.Dataset.from_list(test_list)
ds = ds.add_column('idx', range(len(ds)))
outpath = OUTPUT_PATH / 'eval'
ds.save_to_disk(outpath.as_posix())


OUTPUT_BINARY_PATH = OUTPUT_PATH / "binary"
OUTPUT_BINARY_PATH.mkdir(exist_ok=True, parents=True)

extra_flags = [
    "-mno-sse",
    "-fno-eliminate-unused-debug-types",
    "-fno-lto",
    "-fno-inline-functions",
    # "-fno-inline-small-functions",  # not supported in clang
    # "-fno-inline-functions-called-once",  # not supported in clang
    "-fno-inline",
    # "-fno-reorder-blocks-and-partition",  # not supported in clang
]


def compile(row, container: DockerContainer):
    idx = f"{row['project']}_{row['file']}"
    include = row['include']
    func = row['func']
    function_name = row['file']

    challenge = []

    filepath = f'/dev/shm/oss-fuzz-{function_name}.c'
    try:
        for opt in opt_options:
            with open(filepath, 'w') as f:
                f.write(include)
                f.write('\n')
                f.write(func)

            output_file = OUTPUT_BINARY_PATH / f'task-{idx}-{opt}.so'
            output_file_indocker = pathlib.Path('/challenges/binary') / f'task-{idx}-{opt}.so'
            cmd = ['clang', filepath, f'-{opt}', '-shared', '-fPIC',
                   '-o', str(output_file_indocker)] + extra_flags + ['-lm']
            out = container.exec_in_container(
                cmd, cwd='/challenges', shell=False, check=True, capture_output=True)

            ret = subprocess.run(
                f'nm {output_file} | egrep " {function_name}$"', stdout=subprocess.PIPE, shell=True, check=True)
            ret = ret.stdout.decode()
            location = int(ret.split(" ")[0], 16)

            challenge.append({
                **row,
                'addr': location,
                'opt': opt,
                'path': str(output_file.relative_to(OUTPUT_PATH)),
            })
    except subprocess.CalledProcessError as e:
        logger.error(f"Error compiling {idx} with {opt}: {e}")
    finally:
        # os.remove(filepath)
        pass

    return challenge


def tqdm_progress_map(func, iterable, num_workers):
    results = []
    with Pool(num_workers) as pool:
        for result in tqdm(pool.imap_unordered(func, iterable), total=len(iterable)):
            results.append(result)
    return results


with DockerContainer('evaluate_in_docker', {
    f'{OUTPUT_PATH}': '/challenges',
    '/dev/shm': '/dev/shm'
}) as container:
    res = tqdm_progress_map(functools.partial(compile, container=container), ds, args.num_workers)
res = list(chain(*res))
ds = datasets.Dataset.from_list(res)
print(len(ds))
ds.save_to_disk(str(OUTPUT_PATH / 'compiled_ds'))
