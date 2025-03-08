
import argparse
import json
from loguru import logger
import os
import pathlib
import subprocess
from multiprocessing import Pool

import datasets
import lief
from regex import F
import yaml
from datasets import load_from_disk
from keystone import KS_ARCH_X86, KS_MODE_64, Ks

from extract_functions import OSSFuzzDatasetGenerator
from extract_functions import run_in_docker

log_path = 'diff_branches_ossfuzz.txt'

CODE = b"""" \
xor rax, rax;
mov eax, 0xbabe0000;
mov rax, [rax];
jmp rax
"""

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_64)
ENCODING, count = ks.asm(CODE)


def patch_fuzzer(file_path, target_function, output_file):
    binary = lief.parse(file_path)
    if not binary:
        raise Exception(f"Failed to parse {file_path}")

    target_function_addr = binary.get_function_address(target_function)
    assert isinstance(target_function_addr, int), \
        f"Failed to get address of {target_function}: {target_function_addr}"

    binary.patch_address(target_function_addr, ENCODING)
    binary.write(output_file)


WORKER_COUNT = os.cpu_count()


class ReexecutableRateEvaluator(OSSFuzzDatasetGenerator):
    def do_execute(self):
        if 'language' not in self.project_info or self.project_info['language'] not in ['c', 'c++']:
            print(f"Skipping {self.project} as it is not a C/C++ project")
            return
        with self.start_container(keep=False):
            logger.info("Linking and Testing Fuzzers")
            # return parallel_link_and_test(self)

            tasks = []
            for fuzzer, function_info in self.functions.items():
                for function, _ in function_info.items():
                    tasks.append((fuzzer, function))

            logger.info(f"Testing {len(tasks)} functions")
            Pool(WORKER_COUNT).starmap(self.link_and_test_for_function, tasks)

    def link_and_test_for_function(self, fuzzer, function_name):
        base_txt_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / fuzzer / 'base.txt'
        if base_txt_path.exists():
            return True
        try:
            if self.patch_binary_jmp_to_function(fuzzer, function_name):
                self.diff_base_for_function(fuzzer, function_name)
        except Exception as e:
            logger.error(
                f"link_and_test_for_function failed: {e}")
            return

    def patch_binary_jmp_to_function(self, fuzzer, function_name):
        fuzzer_path = self.oss_fuzz_path / 'build' / 'out' / self.project / fuzzer
        patched_fuzzer_path = self.oss_fuzz_path / 'build' / 'out' / \
            self.project / f'{fuzzer}_{function_name}_patched'

        if fuzzer_path.exists():
            if patched_fuzzer_path.exists():
                return True
            patch_fuzzer(
                str(fuzzer_path.resolve()),
                function_name,
                str(patched_fuzzer_path.resolve()),
            )
            docker_final_fuzzer_path = f'/out/{fuzzer}_{function_name}_patched'
            self.exec_in_container(['chmod', '755', docker_final_fuzzer_path])
            return True
        else:
            raise Exception(f"Fuzzer {fuzzer_path} not exists")

    def diff_base_for_function(self, fuzzer, function_name):
        challenges_path = self.oss_fuzz_path / 'build' / 'out' / self.project / fuzzer
        base_lib_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / 'libfunction.so'

        if not base_lib_path.exists():
            return False
        if not challenges_path.exists():
            print(f"fuzzer path {challenges_path} does not exist")
            logger.error(
                f"testing: fuzzer path {challenges_path} does not exist")
            return False

        cmd = [
            'bash',
            '-c',
            f'''\
            /out/{fuzzer}_{function_name}_patched -runs=0 -seed=3918206239 /corpus/{fuzzer}
            && llvm-profdata merge -sparse $LLVM_PROFILE_FILE -o $OUTPUT_PROFDATA
            && llvm-cov show -instr-profile $OUTPUT_PROFDATA -object=/out/{fuzzer}_{function_name}_patched > $OUTPUT_TXT'''
        ]

        base_txt_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / fuzzer / 'base.txt'
        max_trails = 3
        txt_length = 0
        log_set = []
        for _ in range(max_trails):
            try:
                result = self.exec_in_container(cmd=cmd, envs=[
                    f'LD_LIBRARY_PATH=/challenges/{function_name}:/work/lib/',
                    f'LLVM_PROFILE_FILE=/challenges/{function_name}/{fuzzer}/base.profraw',
                    f'OUTPUT_PROFDATA=/challenges/{function_name}/{fuzzer}/base.profdata',
                    f'OUTPUT_TXT=/challenges/{function_name}/{fuzzer}/base.txt',
                    f'LD_PRELOAD=/challenges/{function_name}/libfunction.so',
                ], timeout=240)
                result.check_returncode()
                with open(str(base_txt_path), 'r') as f:
                    base_result = f.read()
                if txt_length != 0 and len(base_result) != txt_length:
                    logger.error(
                        f"base txt length mismatch, expected {txt_length}, got {len(base_result)}")
                    return False
                txt_length = len(base_result)
                if len(log_set) == 0:
                    log_set = [set() for _ in range(txt_length)]
                for i, line in enumerate(base_result):
                    log_set[i].add(line)

            except Exception as e:
                logger.error(
                    f"base txt generation failed:{e},{result.stderr.decode()},{result.stdout.decode()}")
                return False

        target_libs = {}
        for decompiler in self.decompilers:
            for option in self.options:
                target_lib_path = pathlib.Path(self.oss_fuzz_path) / 'build' / 'challenges' / \
                    self.project / function_name / option / decompiler / 'libfunction.so'
                if target_lib_path.exists():
                    target_libs[f'{decompiler}-{option}'] = f'/challenges/{function_name}/{option}/{decompiler}'
        for options, target_lib_path in target_libs.items():
            target_txt_path = pathlib.Path(self.oss_fuzz_path) / 'build' / 'challenges' / \
                self.project / function_name / fuzzer / f'{options}.txt'
            try:
                result = self.exec_in_container(cmd=cmd, envs=[
                    f'LD_LIBRARY_PATH=/challenges/{function_name}:/work/lib/',
                    f'LLVM_PROFILE_FILE=/challenges/{function_name}/{fuzzer}/{options}.profraw',
                    f'OUTPUT_PROFDATA=/challenges/{function_name}/{fuzzer}/{options}.profdata',
                    f'OUTPUT_TXT=/challenges/{function_name}/{fuzzer}/{options}.txt',
                    f'LD_PRELOAD={target_lib_path}/libfunction.so',
                ], timeout=240)
                if result.returncode != 0:
                    logger.error(
                        f"--- target txt diff {self.project} {function_name} {fuzzer} {options}, differences length: target txt generation failed")
                else:
                    with open(str(target_txt_path), 'r') as f:
                        target_result = f.read()
                    target_difference = []
                    for i, line in enumerate(target_result):
                        if len(log_set[i]) == 1 and line not in log_set[i]:
                            target_difference.append(i)
                    if len(target_difference) > 0:
                        logger.info(
                            f"--- target txt diff {self.project} {function_name} {fuzzer} {options}")
                    else:
                        logger.error(
                            f"--- target txt diff {self.project} {function_name} {fuzzer} {options}, differences length:{len(target_difference)}")
            except Exception as e:
                logger.error(
                    f"--- target txt diff {self.project} {function_name} {fuzzer} {options}, differences length: target txt generation failed")

        run_in_docker(
            [self.oss_fuzz_path],
            f'''rm -rf /challenges/{function_name}/{fuzzer}/*.txt &&
            rm -rf /challenges/{function_name}/{fuzzer}/*.profraw &&
            rm -rf /challenges/{function_name}/{fuzzer}/*.profdata''',
        )
        run_in_docker(
            [self.oss_fuzz_path],
            f'rm -f /out/{fuzzer}_{function_name}_patched',
        )
        return True


def parse_log(log_path):
    with open(log_path, 'r') as f:
        lines = f.readlines()
    target_diff_result = {}
    for line in lines:
        if 'target txt diff' in line and 'INFO' in line:
            line = line.split('\n')[0]
            project = line.split(' ')[-4]
            function = line.split(' ')[-3]
            fuzzer = line.split(' ')[-2]
            options = line.split(' ')[-1]
            decompiler, option = options.rsplit('-', 1)

            target_diff_result.setdefault(project, {}) \
                .setdefault(function, {}) \
                .setdefault(decompiler, {}) \
                .setdefault(option, []) \
                .append((fuzzer, True))

        elif 'target txt diff' in line and 'ERROR' in line:
            line = line.split(', differences')[0]
            project = line.split(' ')[-4]
            function = line.split(' ')[-3]
            fuzzer = line.split(' ')[-2]
            options = line.split(' ')[-1]
            decompiler, option = options.rsplit('-', 1)

            target_diff_result.setdefault(project, {}) \
                .setdefault(function, {}) \
                .setdefault(decompiler, {}) \
                .setdefault(option, []) \
                .append((fuzzer, False))

    return target_diff_result


def main():
    parser = argparse.ArgumentParser(
        description='Generate the dataset for a given project in oss-fuzz')
    parser.add_argument('--config', type=str,
                        help='Path to the configuration file')
    parser.add_argument('--dataset', type=str,
                        help='Path to the dataset')
    parser.add_argument('--worker-count', type=int,
                        help='Number of workers to use', default=os.cpu_count())
    args = parser.parse_args()

    global WORKER_COUNT
    WORKER_COUNT = args.worker_count

    dataset = load_from_disk(args.dataset)
    assert isinstance(dataset, datasets.Dataset)

    config_path = args.config
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    projects = list(set([
        dataset[i]['project']
        for i in range(len(dataset))
    ]))

    for project in projects:
        try:
            evaluator = ReexecutableRateEvaluator(config_path, project)
            evaluator.do_execute()
        except KeyboardInterrupt:
            break
        except:
            continue


if __name__ == '__main__':
    main()
    cer_result = parse_log(log_path)
