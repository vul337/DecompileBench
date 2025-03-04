
import logging
import argparse
import subprocess
import yaml
import pathlib
import zipfile
import json
import copy
import shutil
import importlib
import tqdm
import os
import stat
from multiprocessing import Pool
import re
import tempfile
from datasets import load_from_disk
import json
log_path = 'diff_branches_ossfuzz.txt'
logging.basicConfig(filename=log_path, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
import clang.cindex
import lief
from keystone import *
CODE = b"xor rax, rax;mov eax,0xbabe0000; mov rax, [rax]; jmp rax"
try:
    # Initialize engine in X86-32bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    ENCODING, count = ks.asm(CODE)
except KsError as e:
    print("ERROR: %s" % e)

clang.cindex.Config.set_library_file('/usr/lib/llvm-16/lib/libclang-16.so.1')
index = clang.cindex.Index.create()

def patch_fuzzer(file_path, target_function, output_file):
    binary = lief.parse(file_path)
    target_function_addr = binary.get_function_address(target_function)
    binary.patch_address(target_function_addr, ENCODING)
    binary.write(output_file)

with open('diff_base_result_group.json', 'r') as f:
    global_data = json.load(f)

def parse_args():
    parser = argparse.ArgumentParser(
        description='Generate the dataset for a given project in oss-fuzz')
    parser.add_argument('--config', type=str,
                        help='Path to the configuration file')
    parser.add_argument('--dataset', type=str,
                        help='Path to the dataset')
    return parser.parse_args()

dataset = load_from_disk(args.dataset)

def is_elf(file_path):
    if file_path.is_dir():
        return False
    with open(file_path, 'rb') as f:
        elf_magic_number = b'\x7fELF'
        file_magic_number = f.read(4)
        return file_magic_number == elf_magic_number

pool = Pool(96)

def parallel_link_and_test(generator):
    tasks = []
    for fuzzer, function_info in generator.functions.items():
        for function, _ in function_info.items():
            tasks.append((generator, fuzzer, function))
    print(f"Linking and testing {len(tasks)} tasks")
    return pool.starmap(OSSFuzzDatasetGenerator.link_and_test_for_function, tasks)

class OSSFuzzDatasetGenerator:
    def __init__(self, config_path, project):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.project = project
        self.oss_fuzz_path = self.config['oss_fuzz_path']
        self.projects_path = pathlib.Path(self.oss_fuzz_path) / 'projects'
        self.project_info_path = pathlib.Path(self.projects_path) / project / 'project.yaml'
        with open(self.project_info_path, 'r') as f:
            self.project_info = yaml.safe_load(f)
        self._fuzzers = None
        self._functions = None
        self._commands = None
        self._link = None
        self.decompilers = self.config['decompilers']
        self.options = self.config['options']

    def generate(self):
        if 'language' not in self.project_info or self.project_info['language'] not in ['c', 'c++']:
            print(f"Skipping {self.project} as it is not a C/C++ project")
            return
        logger.info(f"Generating diffing results for {self.project}")
        with self:
            logger.info("--- Linking and Testing Fuzzers")
            return parallel_link_and_test(self)


    def covered_function_fuzzer(self, fuzzer):

        stats_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'stats' / self.project / f'{fuzzer}_result.json'
        if not stats_path.exists():
            return {}
        with open(stats_path, 'r') as f:
            data = json.load(f)
        functions = {}
        for function in data['data'][0]['functions']:
            c_files = [file for file in function['filenames']
                       if file.endswith('.c')]
            if function['count'] < 10 or not c_files or ':' in function['name'] or function['name'] == 'LLVMFuzzerTestOneInput' or any([fuzzer in file for file in c_files]) or not any([self.project in file for file in c_files]):
                continue
            functions[function['name']] = c_files[0]
        return functions


    def compile_command(self, source_path):
        if self._commands is not None:
            return self._commands[source_path]
        compile_commands_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'work' / self.project / 'compile_commands.json'
        if not compile_commands_path.exists():
            print(
                f"Compile commands path {compile_commands_path} does not exist, {compile_commands_path}")
            return None
        else:
            print(f"Compile commands path {compile_commands_path} exists")
        with open(compile_commands_path, 'r') as f:
            compile_commands = json.load(f)
        commands = {}
        for item in compile_commands:
            commands[item['file']] = item
        if source_path not in commands:
            print(f"Source path {source_path} not found in compile commands")
            # logger.error(f"Source path {source_path} not found in compile commands")
            return None
        # else:
        #     logger.info(f"Source path {source_path} found in compile commands,output path: {item['output']}")
        self._commands = commands
        return commands[source_path]


    def link_command(self, fuzzer):
        return self.link_commands[fuzzer]

    @property
    def link_commands(self):
        if self._link is not None:
            return self._link
        link_path = pathlib.Path(self.oss_fuzz_path) / \
            'build' / 'work' / self.project / 'link.json'
        with open(link_path, 'r') as f:
            link = json.load(f)
        self._link = {}
        for item in link:
            if not 'output' in item:
                continue
            exe = pathlib.Path(item['output']).name
            if not exe in self.fuzzers:
                continue
            self._link[exe] = item
        return self._link

    @property
    def functions(self):
        if self._functions is not None:
            return self._functions
        functions = {}
        for fuzzer in self.fuzzers:
            functions[fuzzer] = self.covered_function_fuzzer(fuzzer)
        self._functions = functions
        return self._functions

    @property
    def fuzzers(self):
        if self._fuzzers is not None:
            return self._fuzzers
        output_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'out' / self.project
        fuzzers = [fuzzer.name for fuzzer in output_path.iterdir() if is_elf(
            fuzzer) and fuzzer.name != 'llvm-symbolizer' and not fuzzer.name.endswith('_patched')]
        self._fuzzers = fuzzers
        return self._fuzzers

    def link_for_function(self, fuzzer, function_name):
        fuzzer_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'out' / self.project / fuzzer
        final_fuzzer_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'out' / self.project / f'{fuzzer}_{function_name}_patched'

        if os.path.exists(str(fuzzer_path.resolve())):
            patch_fuzzer(str(fuzzer_path.resolve()), function_name,
                         str(final_fuzzer_path.resolve()))

            docker_final_fuzzer_path = f'/out/{fuzzer}_{function_name}_patched'
            cmd = ['docker', 'exec', f'{self.project}',
                   'chmod', '777', docker_final_fuzzer_path]
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                return False
        else:
            return False
        return True

    def diff_base_for_function(self, fuzzer, function_name):
        challenges_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'out' / self.project / fuzzer
        base_lib_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / 'libfunction.so'

        if not base_lib_path.exists():
            return False
        if not challenges_path.exists():
            print(f"fuzzer path {challenges_path} does not exist")
            logger.error(
                f"testing: fuzzer path {challenges_path} does not exist")
            return False

        corpus_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'corpus' / self.project / fuzzer
        src_path = pathlib.Path(self.oss_fuzz_path) / \
            'build' / 'out' / self.project / 'src'
        image_name = f'gcr.io/oss-fuzz/{self.project}'
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
            logger.error(f"base txt generation failed:{e},{result.stderr.decode()},{result.stdout.decode()}")
            if 'undefined symbol:' in result.stdout.decode():
                try:
                    undefined_symbol = result.stdout.decode().split('undefined symbol:')[1].strip()
                    cmd = ['nm', '-D', f'/out/{fuzzer}_{function_name}_patched', '|', 'grep', undefined_symbol]
                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    logger.info(f"undefined symbol: {undefined_symbol}, {result.stdout.decode()}")
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
                target_lib_path = pathlib.Path('/mnt/data/oss-fuzz') / 'build' / 'challenges' / \
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
                    logger.error(f"--- target txt diff {self.project} {function_name} {fuzzer} {options}, differences length: target txt generation failed")
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
                        logger.info(f"--- target txt diff {self.project} {function_name} {fuzzer} {options}")
                    else:
                        logger.error(f"--- target txt diff {self.project} {function_name} {fuzzer} {options}, differences length:{len(target_difference)}")
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


    def link_and_test_for_function(self, fuzzer, function_name):
        base_txt_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / fuzzer / 'base.txt'
        if base_txt_path.exists():
            return True
        if self.link_for_function(fuzzer, function_name):
            self.diff_base_for_function(fuzzer, function_name)

    def __enter__(self):
        challenges_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'challenges' / self.project
        if not challenges_path.exists():
            challenges_path.mkdir(parents=True)
       
        fuzzers_path = pathlib.Path(self.oss_fuzz_path) / 'build' / 'out' / self.project
        if len(list(fuzzers_path.glob('*.zip'))) == 0:
            cmd = ['python', f'{self.oss_fuzz_path}/infra/helper.py', 'build_fuzzers', '--clean', '--sanitizer', 'coverage', 
            self.project]
            # '-e CFLAGS=-fPIC -fvisibility=default -Wl,--export-dynamic',
            # '-e CXXFLAGS=-fPIC -fvisibility=default -Wl,--export-dynamic']
            subprocess.run(cmd)
            
        cmd = ['docker', 'rm', '-f', f'{self.project}']
        result = subprocess.run(cmd)
        cmd = [
            'docker',
            'run',
            '-dit',
            '--privileged',
            '--name',
            f'{self.project}',
            '-v',
            f'{self.oss_fuzz_path}/build/challenges/{self.project}:/challenges',
            '-v',
            f'{self.oss_fuzz_path}/build/corpus/{self.project}:/corpus',
            '-v',
            f'{self.oss_fuzz_path}/build/out/{self.project}:/out',
            '-v', '/dev/shm:/dev/shm',
            '-v',
            f'{self.oss_fuzz_path}/build/out/{self.project}/src:/src',
            '-v',
            f'{self.oss_fuzz_path}/build/functions/{self.project}:/functions',
            '-v',
            f'{self.oss_fuzz_path}/build/work/{self.project}:/work',
            '-v',
            f'/mnt/data/oss-fuzz/build/dummy:/dummy',
            '-v',
            f'{self.oss_fuzz_path}/build/stats/{self.project}:/stats',
            '-v',
            f'/code/decompilebench-evaluation/decompileeval/decompileeval/fix:/fix',

            '-e',
            'FUZZING_ENGINE=libfuzzer',
            '-e',
            'SANITIZER=coverage',
            '-e',
            'ARCHITECTURE=x86_64',
            '-e',
            'HELPER=True',
            '-e',
            'FUZZING_LANGUAGE=c++',
            '-e',
            'CFLAGS= -fPIC -fvisibility=default  -Wl,-export-dynamic -Wno-error -Qunused-arguments',
            '-e',
            'CXXFLAGS= -fPIC -fvisibility=default  -Wl,-export-dynamic -Wno-error -Qunused-arguments',
            '-e',
            'CC=clang',
            '-e',
            'CXX=clang++',
            '-e',
            'LD_LIBRARY_PATH=/dummy',
            f'gcr.io/oss-fuzz/{self.project}',
            '/bin/bash'
        ]

        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise Exception(
                f"Failed to start docker container for {self.project}")
        else:
            print(f"Started docker container for {self.project}")
        return self
        
        chmod_cmd = ['docker', 'exec', f'{self.project}', 
        'bash', '-c', 'chmod 755 /out/*.zip']
        chmod_result = subprocess.run(chmod_cmd)
        if chmod_result.returncode != 0:
            raise Exception(f"Failed to chmod 755 /out/*.zip")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        cmd = ['docker', 'rm', '-f', f'{self.project}']

        subprocess.run(cmd)


class OSSFuzzProjects:
    def __init__(self, config_path):
        self.config_path = config_path
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.oss_fuzz_path = self.config['oss_fuzz_path']
        self.projects_path = pathlib.Path(self.oss_fuzz_path) / 'projects'
        self.projects = list(set([dataset[i]['project']
                             for i in range(len(dataset))]))
        
    def gen(self):
        final_result = {}
        for project in self.projects:
            try:
                generator = OSSFuzzDatasetGenerator(self.config_path, project)
                print(f"Generating {project}")
                result = generator.generate()
                final_result[project] = result
            except KeyboardInterrupt:
                break
            except:
                continue

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
            if 'gpt-4o-mini' in options:
                decompiler='gpt-4o-mini'
                option=options.split('-')[-1]
            elif 'gpt-4o' in options:
                decompiler='gpt-4o'
                option=options.split('-')[-1]
            else:
                decompiler, option = options.split('-')
            if project not in target_diff_result:
                target_diff_result[project] = {}
            if function not in target_diff_result[project]:
                target_diff_result[project][function] = {}
            if decompiler not in target_diff_result[project][function]:
                target_diff_result[project][function][decompiler] = {}
            if option not in target_diff_result[project][function][decompiler]:
                target_diff_result[project][function][decompiler][option] = []
            target_diff_result[project][function][decompiler][option].append((fuzzer, True))
        elif 'target txt diff' in line and 'ERROR' in line:
            line = line.split(', differences')[0]
            project = line.split(' ')[-4]
            function = line.split(' ')[-3]
            fuzzer = line.split(' ')[-2]
            options = line.split(' ')[-1]
            if 'gpt-4o-mini' in options:
                decompiler='gpt-4o-mini'
                option=options.split('-')[-1]
            elif 'gpt-4o' in options:
                decompiler='gpt-4o'
                option=options.split('-')[-1]
            else:
                decompiler, option = options.split('-')
            if project not in target_diff_result:
                target_diff_result[project] = {}
            if function not in target_diff_result[project]:
                target_diff_result[project][function] = {}
            if decompiler not in target_diff_result[project][function]:
                target_diff_result[project][function][decompiler] = {}
            if option not in target_diff_result[project][function][decompiler]:
                target_diff_result[project][function][decompiler][option] = []
            if fuzzer not in target_diff_result[project][function][decompiler][option]:
                target_diff_result[project][function][decompiler][option].append((fuzzer,False))

    return target_diff_result

def main():
    args = parse_args()
    projects = OSSFuzzProjects(args.config)
    projects.gen()

if __name__ == '__main__':
    main()
    cer_result = parse_log(log_path)


