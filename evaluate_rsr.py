import argparse
import importlib
import multiprocessing
import os
import pathlib
import re
import subprocess
from typing import Set

import clang.cindex
import datasets
import pandas as pd
import yaml
from tqdm import tqdm
from libclang import set_libclang_path


set_libclang_path()

repo_path = pathlib.Path(__file__).resolve().parent

oss_fuzz_path: pathlib.Path | None = None
decompilers: Set[str] = set()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default="./config.yaml",
                        help='Path to the configuration file')
    parser.add_argument("--decompiled-dataset", type=str, required=True,
                        help="Path to the merged decompiled dataset produced earlier")
    parser.add_argument("--decompilers", type=str, nargs='*',
                        help="Decompilers to evaluate, leave empty to evaluate all decompilers specified in the config")
    return parser.parse_args()


class DockerContainer:
    def __init__(self, container_name, volume_mappings):
        self.container_name = container_name
        self.volume_mappings = volume_mappings

    def __enter__(self):
        result = subprocess.run(f"docker ps | grep {self.container_name}",
                                shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            subprocess.run(
                f"docker rm -f {self.container_name}", shell=True, check=True)
        else:
            print(
                f"Container {self.container_name} does not exist, creating new container")

        volume_args = ' '.join(
            [f'-v {os.path.abspath(host)}:{container}' for host, container in self.volume_mappings.items()])
        docker_cmd = f'''docker run -dit --privileged --rm --name {self.container_name} \
        {volume_args} \
        -e ARCHITECTURE=x86_64 \
        gcr.io/oss-fuzz-base/base-builder /bin/bash'''

        result = subprocess.run(docker_cmd, shell=True,
                                capture_output=True, text=True)
        if result.returncode != 0:
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")
            exit(1)
        else:
            print(f"Container {self.container_name} created successfully")

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        subprocess.run(
            f"docker rm -f {self.container_name}", shell=True, check=True)

    def exec_in_container(self, cmd, cwd=None, envs=[], **kwargs):
        cmd = [
            'docker', 'exec',
            *(['-w', cwd] if cwd else []),
            *sum([['-e', e] for e in envs], []),
            self.container_name,
            *cmd
        ]
        check = kwargs.pop('check', True)
        return subprocess.run(cmd, check=check, **kwargs)


def make_function_static(source, target_function_name):
    def get_function_attributes(cursor):
        attributes = []
        if cursor.storage_class == clang.cindex.StorageClass.STATIC:  # type: ignore
            attributes.append('static')
        if cursor.storage_class == clang.cindex.StorageClass.EXTERN:  # type: ignore
            attributes.append('extern')
        return attributes

    index = clang.cindex.Index.create()
    tu = index.parse("input.c", args=[], unsaved_files=[("input.c", source)])

    lines = source.split('\n')
    patches = []

    for cursor in tu.cursor.walk_preorder():
        if cursor.kind == clang.cindex.CursorKind.FUNCTION_DECL:  # type: ignore
            if cursor.spelling == target_function_name:
                attributes = get_function_attributes(cursor)
                start_line = cursor.extent.start.line - 1
                end_line = cursor.extent.end.line - 1

                if 'static' in attributes:
                    continue
                elif 'extern' in attributes:
                    patches.append(('extern', start_line, end_line))
                else:
                    patches.append(('normal', start_line, end_line))

    patches.sort(key=lambda x: x[1], reverse=True)

    for patch_type, sl, el in patches:
        if patch_type == 'extern':
            lines.insert(sl, '#define extern static')
            lines.insert(el + 2, '#undef extern')
        elif patch_type == 'normal':
            lines[sl] = 'static ' + lines[sl]

    return '\n'.join(lines)


def remove_extern(source):
    lines = source.split('\n')
    for i, line in enumerate(lines):
        if re.match(r'^extern\s+', line):
            lines[i] = line.replace('extern', '')
    return '\n'.join(lines)


TEMPLATE = """
#define MMAP 9
#define MUNMAP 11
#define EXIT 60
#define MAP_FAILED ((void *)-1)

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED 0x10

long int syscall(long number, ...);

__attribute__((no_instrument_function))
__attribute__((constructor))
void initializer() {{
    unsigned long pagesize = 4096;
    void *desired_addr = (void *)0xbabe0000;

    void **address = (void **)syscall(MMAP, desired_addr, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (address == MAP_FAILED) {{
        syscall(EXIT, 1);
    }}

    *(void **)(0xbabe0000) = {function};
}}

__attribute__((no_instrument_function))
__attribute__((destructor))
void finalizer() {{
    syscall(MUNMAP, (void *)0xbabe0000, 4096);
}}
"""


def parse_path(path):
    project_pattern = re.compile(r'task-([^_]+)_(.*)-(O\w).so')

    matched = project_pattern.match(path)
    if matched is None:
        raise ValueError(f"Invalid path: {path}")

    project = matched.group(1)
    function = matched.group(2)
    option = matched.group(3)
    strip = path.endswith('.strip')
    option += '.strip' if strip else ''
    return project, function, option


warning_pattern = re.compile(r'\[-W(.*)\]')


def evaluate_func(args):
    compiler: str = args[0]
    container: DockerContainer = args[1]
    params: dict = args[2]
    try:
        c_include, c_func_decompile = (
            params["include"],
            params["decompile_code"],
        )

        metadata = params["metadata"]

        project, function, option = parse_path(metadata['path'].split('/')[-1])
        if compiler == 'func':
            result_path = pathlib.Path('/challenges') / \
                project / function / "libfunction.so"
            c_path = pathlib.Path(
                f'{oss_fuzz_path}/build/challenges') / project / function / f"{function}.c"
            c_path_docker = pathlib.Path(
                '/challenges') / project / function / f"{function}.c"
        else:
            result_path = pathlib.Path(
                '/challenges') / project / function / option / f"{compiler}" / "libfunction.so"
            c_path = pathlib.Path(
                f'{oss_fuzz_path}/build/challenges') / project / function / option / f"{compiler}" / f"{function}.c"
            c_path_docker = pathlib.Path(
                '/challenges') / project / function / option / f"{compiler}" / f"{function}.c"
        container.exec_in_container(['mkdir', '-p', str(result_path.parent)])
        container.exec_in_container(['chmod', '777', str(result_path.parent)])
        container.exec_in_container(['rm', '-f', str(result_path)])
        timeout = 10
        flag_compile = 0

        c_include = """
        #include <defs.h>
        """+c_include

        if not c_func_decompile or 'Failed to decompile the function' in c_func_decompile:
            return 0

        fixer = importlib.import_module("fix." + compiler)
        if compiler in ['deepseek', 'qwen', 'gpt-4o-mini', 'gpt-4o', 'claude']:
            c_func_decompile = fixer.fix(c_func_decompile, function)
        else:
            c_func_decompile = fixer.fix(c_func_decompile)

        c_onlyfunc = c_include + "\n" + c_func_decompile
        c_onlyfunc = make_function_static(c_onlyfunc, function)

        with open(c_path, "w") as f:
            f.write(c_onlyfunc)
            f.write(TEMPLATE.format(function=function))

        extra_include_path = os.path.join('/fix', compiler)

        docker_cmd = [
            "clang",
            f"-I{extra_include_path}",
            c_path_docker.as_posix(),
            "-shared",
            "-fPIC",
            "-o",
            result_path.as_posix(),
            "-fprofile-instr-generate", "-fcoverage-mapping", "-pthread", "-Wl,--no-as-needed", "-Wl,-ldl", "-Wl,-lm", "-Wno-unused-command-line-argument",
        ]

        def run_cmd(extra_args):
            flag_compile = 0
            warnings = []
            try:
                ret = container.exec_in_container(
                    docker_cmd+extra_args, cwd='/', timeout=timeout, stderr=subprocess.PIPE, check=False)
                stderr = ret.stderr.decode()
                warnings = warning_pattern.findall(stderr)
                ret.check_returncode()
                flag_compile = 1
            except Exception:
                return flag_compile, warnings

            return flag_compile, warnings

        flag_compile, warnings = run_cmd([])
        if flag_compile == 0 and warnings:
            flag_compile, warnings = run_cmd([
                '-Wno-' + w
                for w in warnings
            ])

        return flag_compile
    except Exception as e:
        print(f"Error: {e}")
        return 0


def decompile_pass_rate(gen_results, compiler, num_workers, container):

    with multiprocessing.Pool(num_workers) as pool:
        tasks = [
            (
                compiler, container, {
                    "include": output["include"],
                    "decompile_code": output[compiler],
                    "metadata": output,
                }
            )
            for _, output in gen_results.iterrows()
        ]

        eval_results = list(
            tqdm(pool.imap(evaluate_func, tasks), total=len(tasks)))

    ret = []
    for _, ((_, output), flag) in enumerate(
        tqdm(
            zip(gen_results.iterrows(), eval_results),
            total=len(gen_results),
            desc="Evaluating",
        )
    ):

        ret.append({
            **{
                k: v for k, v in output.items() if k not in decompilers
            },
            "flag_compile": flag,
        })

    return ret


def main():
    global oss_fuzz_path, decompilers

    args = parse_args()

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    oss_fuzz_path = pathlib.Path(config['oss_fuzz_path'])
    decompilers = set(config['decompilers'])

    if args.decompilers:
        decompilers = decompilers.intersection(set(args.decompilers))

    if not args.decompiled_dataset:
        raise ValueError(
            "--decompiled-dataset is required. Please provide the path to the merged dataset.")

    ds_with_decompile_code = datasets.Dataset.load_from_disk(
        args.decompiled_dataset)

    for col in ['include', 'opt']:
        if col not in ds_with_decompile_code.column_names:
            raise ValueError(
                f"Column {col} not found in the dataset, please make sure the dataset is a merged dataset")

    df = ds_with_decompile_code.to_pandas()
    assert isinstance(df, pd.DataFrame)

    for d in decompilers:
        print(f'Decompiler: {d}')

        if d not in df.columns:
            continue

        with DockerContainer('evaluate_in_docker', {
            f'{oss_fuzz_path}/build/challenges': '/challenges',
            f'{repo_path}/fix': '/fix'
        }) as container:
            eval_result_df = pd.DataFrame(
                decompile_pass_rate(df, d, 64, container))

        for opt, per_opt_df in eval_result_df.groupby('opt'):
            compile_rate = per_opt_df['flag_compile'].mean()

            print(
                f"Optimization {opt}: Compile Rate: {compile_rate:.4f}")
        print('-' * 30)

    rm_docker_cmd = "docker rm -f evaluate_in_docker"
    result = subprocess.run(rm_docker_cmd, shell=True,
                            capture_output=True, text=True)
    if result.returncode == 0:
        print("Container evaluate_in_docker removed successfully")


if __name__ == "__main__":
    main()
