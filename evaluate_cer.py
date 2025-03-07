
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

        base_cmd = ['docker', 'exec', '-e', f'LD_LIBRARY_PATH=/challenges/{function_name}:/work/lib/',
                    '-e', f'LLVM_PROFILE_FILE=/challenges/{function_name}/{fuzzer}/base.profraw', f'{self.project}']

        cmd = base_cmd + [
            'bash',
            '-c',
            f'LD_PRELOAD=/challenges/{function_name}/libfunction.so /out/{fuzzer}_{function_name}_patched -runs=0 -seed=3918206239 /corpus/{fuzzer} &&\
            llvm-profdata merge -sparse /challenges/{function_name}/{fuzzer}/base.profraw -o /challenges/{function_name}/{fuzzer}/base.profdata &&\
            llvm-cov show -instr-profile /challenges/{function_name}/{fuzzer}/base.profdata -object=/out/{fuzzer}_{function_name}_patched > /challenges/{function_name}/{fuzzer}/base.txt'
        ]

        base_cmd1 = ['docker', 'exec', '-e', f'LD_LIBRARY_PATH=/challenges/{function_name}:/work/lib/',
                     '-e', f'LLVM_PROFILE_FILE=/challenges/{function_name}/{fuzzer}/base1.profraw', f'{self.project}']
        cmd1 = base_cmd1 + [
            'bash',
            '-c',
            f'LD_PRELOAD=/challenges/{function_name}/libfunction.so /out/{fuzzer}_{function_name}_patched -runs=0 -seed=3918206239 /corpus/{fuzzer} &&\
            llvm-profdata merge -sparse /challenges/{function_name}/{fuzzer}/base1.profraw -o /challenges/{function_name}/{fuzzer}/base1.profdata &&\
            llvm-cov show -instr-profile /challenges/{function_name}/{fuzzer}/base1.profdata -object=/out/{fuzzer}_{function_name}_patched > /challenges/{function_name}/{fuzzer}/base1.txt'

        ]
        base_txt_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / fuzzer / 'base.txt'
        base_txt_path1 = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / fuzzer / 'base1.txt'
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
            result.check_returncode()

        except Exception as e:
            logger.error(
                f"base txt generation failed:{e},{result.stderr.decode()},{result.stdout.decode()}")
            if 'undefined symbol:' in result.stdout.decode():
                try:
                    undefined_symbol = result.stdout.decode().split(
                        'undefined symbol:')[1].strip()
                    cmd = [
                        'nm', '-D', f'/out/{fuzzer}_{function_name}_patched', '|', 'grep', undefined_symbol]
                    result = subprocess.run(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    logger.info(
                        f"undefined symbol: {undefined_symbol}, {result.stdout.decode()}")
                except Exception as e:
                    logger.error(f"undefined symbol extraction failed, {e}")
            return False

        try:
            result1 = subprocess.run(
                cmd1, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
            result1.check_returncode()
        except Exception as e:
            return False

        try:
            with open(str(base_txt_path), 'r') as f:
                base_result = f.read()
            with open(str(base_txt_path1), 'r') as f:
                base_result1 = f.read()
            min_length = min(len(base_result), len(base_result1))
            differences = []
            for i in range(min_length):
                if base_result[i] != base_result1[i]:
                    differences.append(i)
            # if len(differences) > 0:
            #     logger.info(f"--- base txt diff {self.project} {function_name} {fuzzer} differences: {differences}")
        except Exception as e:
            # logger.error(f"testing: diffing base profraw failed: - {e}")
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
            base_cmd = ['docker', 'exec', '-e', f'LD_LIBRARY_PATH={target_lib_path}:/work/lib/', '-e',
                        f'LLVM_PROFILE_FILE=/challenges/{function_name}/{fuzzer}/{options}.profraw', f'{self.project}']

            cmd = base_cmd + [
                'bash',
                '-c',
                f'LD_PRELOAD={target_lib_path}/libfunction.so  /out/{fuzzer}_{function_name}_patched -runs=0 -seed=3918206239 /corpus/{fuzzer} &&\
                llvm-profdata merge -sparse /challenges/{function_name}/{fuzzer}/{options}.profraw -o /challenges/{function_name}/{fuzzer}/{options}.profdata &&\
                llvm-cov show -instr-profile /challenges/{function_name}/{fuzzer}/{options}.profdata -object=/out/{fuzzer}_{function_name}_patched > /challenges/{function_name}/{fuzzer}/{options}.txt'
            ]
            try:
                result = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
                if result.returncode != 0:
                    # logger.error(
                    #     f"target txt generation failed: {result.stderr.decode()},{result.stdout.decode()}, target_lib_path:{target_lib_path}")
                    logger.error(
                        f"--- target txt diff {self.project} {function_name} {fuzzer} {options}, differences length: target txt generation failed")
                else:
                    # logger.info(
                    #     f"target txt generation success: {target_txt_path}")
                    with open(str(target_txt_path), 'r') as f:
                        target_result = f.read()
                    target_difference = []
                    for i in range(min(len(base_result1), len(target_result))):
                        if base_result1[i] != target_result[i]:
                            target_difference.append(i)
                    if differences == target_difference or len(target_difference) == 0:
                        logger.info(
                            f"--- target txt diff {self.project} {function_name} {fuzzer} {options}")
                    else:
                        logger.error(
                            f"--- target txt diff {self.project} {function_name} {fuzzer} {options}, differences length:{len(target_difference)}")
            except Exception as e:
                logger.error(
                    f"--- target txt diff {self.project} {function_name} {fuzzer} {options}, differences length: target txt generation failed")
        cmd = ['docker', 'exec', f'{self.project}']
        cmd = cmd + [
            'rm',
            '-rf',
            f'/challenges/{function_name}/{fuzzer}/*.txt'
        ]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        cmd = ['docker', 'exec', f'{self.project}']
        cmd = cmd + [
            'rm',
            '-f',
            f'/out/{fuzzer}_{function_name}_patched'
        ]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
