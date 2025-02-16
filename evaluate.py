# %%

import pathlib
import os
import json
import subprocess
from multiprocessing import Pool
import multiprocessing
from itertools import chain
import datasets
import tempfile
import importlib
import pandas as pd
import asyncio
from tqdm import tqdm
import argparse
import re
import clang.cindex
import lief
import subprocess
from datasets import Dataset
# %%

parser = argparse.ArgumentParser()
parser.add_argument("--decompile_result", type=str,
                    default="/code/decompilebench-evaluation/decompileeval/output_dataset/ossfuzz_all_updated")
parser.add_argument("--decompiler", type=str, default="all", nargs='+')
parser.add_argument("--debug", action="store_true")
parser.add_argument("--partial", action="store_true")
args = parser.parse_args()

debug = args.debug
ds_with_decompile_code = datasets.Dataset.load_from_disk(args.decompile_result)

df = ds_with_decompile_code.to_pandas()

DECOMPILERS = [
    # "angr",
    # "binja", "dewolf", "ghidra",
    "hexrays",
    # "retdec",
    # "mlm", 
    # "llm4decompile",
    # 'qwen',
    # 'deepseek',
    # "gpt-4o-mini",
    # "gpt-4o",
    # "func",
]
# DECOMPILERS = []
# DECOMPILERS.extend([ "mlm","llm4decompile"])

# %%
clang.cindex.Config.set_library_file('/usr/lib/llvm-16/lib/libclang-16.so.1')
index = clang.cindex.Index.create()


def make_function_static(source, target_function_name):
    def get_function_attributes(cursor):
        attributes = []
        if cursor.storage_class == clang.cindex.StorageClass.STATIC:
            attributes.append('static')
        if cursor.storage_class == clang.cindex.StorageClass.EXTERN:
            attributes.append('extern')
        return attributes

    index = clang.cindex.Index.create()
    tu = index.parse("input.c", args=[], unsaved_files=[("input.c", source)])

    lines = source.split('\n')
    patches = []

    for cursor in tu.cursor.walk_preorder():
        if cursor.kind == clang.cindex.CursorKind.FUNCTION_DECL:
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

__attribute__((constructor)) void initializer() {{
    unsigned long pagesize = 4096;
    void *desired_addr = (void *)0xbabe0000;

    void **address = (void **)syscall(MMAP, desired_addr, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (address == MAP_FAILED) {{
        syscall(EXIT, 1);
    }}
    
    *(void **)(0xbabe0000) = {function};
}}

__attribute__((destructor)) void finalizer() {{
    syscall(MUNMAP, (void *)0xbabe0000, 4096);
}}
"""


def parse_path(path):
    project_pattern = re.compile(r'task-([^_]+)_(.*)-(O\w).so')

    matched = project_pattern.match(path)
    project = matched.group(1)
    function = matched.group(2)
    option = matched.group(3)
    strip = path.endswith('.strip')
    option += '.strip' if strip else ''
    return project, function, option


warning_pattern = re.compile(r'\[-W(.*)\]')


def evaluate_func(params):
    compiler, params = params
    c_include, c_test, c_func_decompile = (
        params["include"],
        params["test"],
        params["decompile_code"],
    )

    metadata = params["metadata"]

    project, function, option = parse_path(metadata['path'].split('/')[-1])
    if compiler == 'func':
        result_path = pathlib.Path('/challenges') / \
            project / function / "libfunction.so"
        c_path = pathlib.Path(
            '/mnt/data/oss-fuzz/build/challenges') / project / function / f"{function}.c"
        c_path_docker = pathlib.Path(
            '/challenges') / project / function / f"{function}.c"
    else:
        result_path = pathlib.Path(
            '/challenges') / project / function / option / f"{compiler}" / "libfunction.so"
        c_path = pathlib.Path('/mnt/data/oss-fuzz/build/challenges') / \
            project / function / option / f"{compiler}" / f"{function}.c"
        c_path_docker = pathlib.Path(
            '/challenges') / project / function / option / f"{compiler}" / f"{function}.c"
    mkdir_res = subprocess.run(
        ['docker', 'exec', 'evaluate_in_docker', 'mkdir', '-p', str(result_path.parent)], check=True)
    if mkdir_res.returncode != 0:
        print(f"Failed to create directory {result_path.parent}")
        return 0, 0, 0
    else:
        chmod_res = subprocess.run(['docker', 'exec', 'evaluate_in_docker',
                 'chmod', '777', str(result_path.parent)], check=True)
        if chmod_res.returncode != 0:
            print(f"Failed to chmod {result_path.parent}")
            return 0, 0, 0
    clean_cmd = ['docker', 'exec', 'evaluate_in_docker',
                 'rm', '-f', str(result_path)]
    clean_res = subprocess.run(clean_cmd, check=True)
    if clean_res.returncode != 0:
        print(f"Failed to clean {result_path}")
        return 0, 0, 0
    timeout = 10
    flag_compile = 0
    flag_run = 0
    
    c_include = """
    #include <defs.h>
    """+c_include

    if not c_func_decompile or 'Failed to decompile the function' in c_func_decompile:
        return 0, 0, 0

    import re
    
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
    "docker", "exec", "evaluate_in_docker", "clang",
    f"-I{extra_include_path}",
    c_path_docker,
    "-shared",
    "-fPIC",
    "-o",
    result_path,
    "-fprofile-instr-generate", "-fcoverage-mapping", "-pthread", "-Wl,--no-as-needed", "-Wl,-ldl", "-Wl,-lm", "-Wno-unused-command-line-argument",
    ]

    def run_cmd(extra_args):
        warning_count = 0
        flag_compile = 0
        warnings = []
        try:
            ret = subprocess.run(
                docker_cmd + extra_args, timeout=timeout,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            stderr = ret.stderr.decode()
            if debug and len(extra_args) != 0:
                print(c_path)
                print(stderr)
                print('-'*20)
                print(c_func_decompile)
                print('-'*20)
            
            warnings = warning_pattern.findall(stderr)
            ret.check_returncode()
            flag_compile = 1
        except Exception:
            return flag_compile, flag_run, warning_count, warnings

        return flag_compile, flag_run, warning_count, warnings
    
    flag_compile, flag_run, warning_count, warnings = run_cmd([])
    if flag_compile == 0 and warnings:
        flag_compile, flag_run, warning_count, warnings = run_cmd([
            '-Wno-' + w
            for w in warnings
        ])

    return flag_compile, flag_run, warning_count



def decompile_pass_rate(gen_results, compiler, num_workers):
    with multiprocessing.Pool(num_workers) as pool:
        tasks = [
            (
                compiler, {
                    "include": output["include"],
                    "test": output["test"],
                    "decompile_code": output[compiler],
                    "metadata": output,
                }
            )
            for _, output in gen_results.iterrows()
        ]

        if True:
            eval_results = list(
                tqdm(pool.imap(evaluate_func, tasks), total=len(tasks)))
        else:
            eval_results = []
            for task in tasks:
                eval_results.append(evaluate_func(task))

    pool.terminate()
    pool.join()

    ret = []
    for _, ((_, output), flag) in enumerate(
        tqdm(
            zip(gen_results.iterrows(), eval_results),
            total=len(gen_results),
            desc="Evaluating",
        )
    ):
        flag_compile, flag_run, warninig_count = flag[0], flag[1], flag[2]

        ret.append({
            **{
                k: v for k, v in output.items() if k not in DECOMPILERS
            },
            "flag_compile": flag_compile,
            "flag_run": flag_run,
            "warning_count": warninig_count,
        })

    return ret


# %%


if 'all' in args.decompiler:
    args.decompiler = DECOMPILERS
result = subprocess.run("docker ps | grep evaluate_in_docker",
                        shell=True, capture_output=True, text=True)
if result.returncode == 0:
    subprocess.run("docker rm -f evaluate_in_docker", shell=True, check=True)
else:
    print("Container does not exist, creating new container")


docker_cmd = '''docker run -dit --privileged --rm --name evaluate_in_docker \
-v /mnt/data/oss-fuzz/build/challenges:/challenges \
-v /code/decompilebench-evaluation/decompileeval/decompileeval/fix:/fix \
-e FUZZING_ENGINE=libfuzzer \
-e SANITIZER=coverage -e ARCHITECTURE=x86_64 -e HELPER=True -e FUZZING_LANGUAGE=c++ \
-e 'CFLAGS=-fPIC -fvisibility=default  -Wl,-export-dynamic ' \
-e 'CXXFLAGS=-fPIC -fvisibility=default -Wl,-export-dynamic' \
gcr.io/oss-fuzz-base/base-builder  /bin/bash'''

result = subprocess.run(docker_cmd, shell=True, capture_output=True, text=True)
if result.returncode != 0:
    print(result.stdout)
    print(result.stderr)
    exit(1)
else:
    print("Container evaluate_in_docker created successfully")

if not args.partial:
    if args.debug:
        df = df.sample(frac=1).reset_index(drop=True)[:100] 
    for d in args.decompiler:
        print(f'Decompiler: {d}')

        if d not in df.columns:
            continue

        eval_result_df = pd.DataFrame(decompile_pass_rate(df, d, 64))

        for opt, per_opt_df in eval_result_df.groupby('opt'):
            compile_rate = per_opt_df['flag_compile'].mean()
            run_rate = per_opt_df['flag_run'].mean()
            warning_count = per_opt_df[
                per_opt_df['flag_compile'] == 1
            ]['warning_count'].mean()

            print(
                f"Optimization {opt}: Compile Rate: {compile_rate:.4f}, Run Rate: {run_rate:.4f}, average_warning: {warning_count:.4f}")
        print('-' * 30)

    rm_docker_cmd = "docker rm -f evaluate_in_docker"
    result = subprocess.run(rm_docker_cmd, shell=True, capture_output=True, text=True)
    if result.returncode ==0:
        print("Container evaluate_in_docker removed successfully")

