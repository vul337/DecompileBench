# %%
import os
import subprocess
from multiprocessing import Pool
from itertools import chain
import datasets
from tqdm import tqdm
from pathlib import Path
import clang.cindex
import pathlib
import zipfile
import shutil
import json
from datasets import load_from_disk, Dataset
import pandas as pd

try:
    clang.cindex.Config.set_library_file(
        '/usr/lib/llvm-16/lib/libclang-16.so.1')
except Exception:
    pass

import argparse

parser = argparse.ArgumentParser(description="Compile OSS-Fuzz projects")
parser.add_argument('--oss_fuzz_path', type=str, default='/mnt/data/oss-fuzz', help='Path to the OSS-Fuzz directory')
parser.add_argument('--output', type=str, default='./dataset/ossfuzz', help='Output directory for compiled datasets')

args = parser.parse_args()

oss_fuzz_path = pathlib.Path(args.oss_fuzz_path)
OUTPUT = pathlib.Path(args.output)

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


def covered_function_fuzzer(project, fuzzer):
    stats_path = oss_fuzz_path / 'build' / 'stats' / project / f'{fuzzer}_result.json'
    if not stats_path.exists():
        return {}, []
    with open(stats_path, 'r') as f:
        data = json.load(f)
    functions = {}
    all_functions = []
    for function in data['data'][0]['functions']:
        c_files = [file for file in function['filenames'] if file.endswith('.c')]
        if function['count'] < 10 or not c_files or ':' in function['name'] or function['name'] == 'LLVMFuzzerTestOneInput' or any(fuzzer in file for file in c_files) or not any(project in file for file in c_files):
            continue
        functions[function['name']] = c_files[0]
        all_functions.append(function)
    return functions, all_functions

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
                    include_content = content.replace(
                        '#undef NULL', '').replace(test_func, '')

                    test_list.append({
                        'project': project.stem,
                        'file': file.stem,
                        'func': test_func,
                        'test': '',
                        'include': include_content,
                    })
    return test_list

        
def process_project_linearly(project_path):
    test_lists = []
    for project in tqdm(reversed(list(project_path.iterdir()))):
        result = process_project(project)
        if result is not None:
            test_lists.extend(result)

test_list = process_project_linearly(project_path)
ds = datasets.Dataset.from_list(test_list)
ds = ds.add_column('idx', range(len(ds)))
outpath = OUTPUT / 'eval'
ds.save_to_disk(outpath)

# Create a new dictionary to hold the sampled data
# sampled_data = {}

# # Sample 50 items for each project
# for project in project_counts.keys():
#     # Assuming `ds` is a Dataset object that contains the data
#     project_data = ds.filter(lambda x: x['project'] == project)
#     sampled_items = project_data.shuffle(seed=42).select(range(min(50, len(project_data))))  # Sample up to 50 items
#     sampled_data[project] = sampled_items

# all_sampled_items = []
# for project, items in sampled_data.items():
#     all_sampled_items.extend(items)

# new_dataset = Dataset.from_list(all_sampled_items)
# new_dataset.save_to_disk("./ossfuzz_sample50")


OUTPUT_BINAEY = OUTPUT / "binary"
if not OUTPUT.exists():
    OUTPUT.mkdir()
if not OUTPUT_BINAEY.exists():
    OUTPUT_BINAEY.mkdir()

extra_flags = ' '.join([
    "-mno-sse",
    "-fno-eliminate-unused-debug-types",
    "-fno-lto",
    "-fno-inline-functions",
    "-fno-inline-small-functions",
    "-fno-inline-functions-called-once",
    "-fno-inline",
    "-fno-reorder-blocks-and-partition",
])


def compile(row):
    idx = f"{row['project']}_{row['file']}"
    include = row['include']
    func = row['func']
    test = row['test']
    function_name = row['file']

    challenge = []

    for opt in ['O0', 'O1', 'O2', 'O3', 'Os']:
        with open(f"/tmp/{idx}.c", "w") as f:
            f.write(include)
            f.write('\n')
            f.write(func)
            f.write('\n')
            f.write(test)

        output_file = OUTPUT_BINAEY / f'task-{idx}-{opt}.so'
        os.system(
            f"clang /tmp/{idx}.c -{opt} -shared -fPIC -o {output_file} {extra_flags} -lm")

        ret = subprocess.run(
            f'nm {output_file} | egrep " {function_name}$"', stdout=subprocess.PIPE, shell=True)
        ret = ret.stdout
        if not ret:
            continue
        # assert ret
        ret = ret.decode()
        location = int(ret.split(" ")[0], 16)

        for f in [output_file]:
            challenge.append({
                **row,
                'addr': location,
                'opt': opt,
                'path': str(f.relative_to(BASE_DIR)),
            })

    os.remove(f"/tmp/{idx}.c")
    return challenge


def tqdm_progress_map(func, iterable, num_workers):
    results = []
    with Pool(num_workers) as pool:
        for result in tqdm(pool.imap_unordered(func, iterable), total=len(iterable)):
            results.append(result)
    return results


res = tqdm_progress_map(compile, ds, 64)
res = list(chain(*res))
ds = datasets.Dataset.from_list(res)
print(len(ds))
ds.save_to_disk(str(OUTPUT / 'compiled_ds'))

