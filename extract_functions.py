
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from typing import Optional
import zipfile
from multiprocessing import Pool

import clang.cindex
import yaml
from loguru import logger

clang.cindex.Config.set_library_file('/usr/lib/llvm-16/lib/libclang-16.so.1')
index = clang.cindex.Index.create()


def parse_args():
    parser = argparse.ArgumentParser(
        description='Generate the dataset for a given project in oss-fuzz')
    parser.add_argument('--config', type=str,
                        help='Path to the configuration file')
    parser.add_argument('--project', type=str,
                        help='Name of the projects, separated by ","', default=None)
    parser.add_argument('--worker-count', type=int,
                        help='Number of workers to use', default=os.cpu_count())
    return parser.parse_args()


def is_elf(file_path):
    if file_path.is_dir():
        return False
    with open(file_path, 'rb') as f:
        elf_magic_number = b'\x7fELF'
        file_magic_number = f.read(4)
        return file_magic_number == elf_magic_number


def extract_for_function_wrapper(generator: 'OSSFuzzDatasetGenerator', function_name, source_path):
    """Wrapper function to call extract_for_function as a static method."""
    return generator.extract_for_function(function_name, source_path)


WORKER_COUNT = os.cpu_count()


def parallel_extract(generator: 'OSSFuzzDatasetGenerator'):
    logger.info(f"Extracting functions for {generator.project}")
    tasks = []
    functions_path = pathlib.Path(
        generator.oss_fuzz_path) / 'build' / 'functions' / generator.project
    functions_path.mkdir(parents=True, exist_ok=True)
    for _, function_info in generator.functions.items():
        for function, source_path in function_info.items():
            tasks.append((generator, function, source_path))
    logger.info(f"Extracting {len(tasks)} functions")
    Pool(WORKER_COUNT).starmap(extract_for_function_wrapper, tasks)


class OSSFuzzDatasetGenerator:
    def __init__(self, config_path, project):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.project = project
        self.oss_fuzz_path = self.config['oss_fuzz_path']
        self.project_info_path = pathlib.Path(
            self.oss_fuzz_path) / 'projects' / project / 'project.yaml'
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
            logger.info(
                f"Skipping {self.project} as it is not a C/C++ project")
            return
        self.build_fuzzer()
        self.run_coverage()
        with self:
            parallel_extract(self)

    def build_fuzzer(self):
        output_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'out' / self.project
        work_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'work' / self.project / 'compile_commands.json'
        if output_path.exists() and work_path.exists():
            logger.info(f"Skipping build for {self.project}")
            return
        cwd = self.oss_fuzz_path
        sanitizer = ','.join(self.config['sanitizer'])
        env = sum([['-e', f'{key}={value}']
                  for key, value in self.config['env'].items()], [])
        cmd = ['python3', 'infra/helper.py', 'build_fuzzers',
               '--clean', '--sanitizer', sanitizer, self.project]
        logger.info(f"cmd: {' '.join(cmd)}")
        build_fuzzer_res = subprocess.run(cmd, cwd=cwd, stderr=subprocess.PIPE)
        if build_fuzzer_res.returncode != 0:
            logger.info(
                f"build_fuzzer failed for {self.project}")
            print(build_fuzzer_res.stdout.decode())
            print(build_fuzzer_res.stderr.decode())
            raise Exception(f"Failed to build fuzzer for {self.project}")
        else:
            logger.info(f"Build success for {self.project}")

    def run_coverage_fuzzer(self, fuzzer):
        stats_result_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'stats' / self.project / f'{fuzzer}_result.json'
        stats_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'out' / self.project / 'fuzzer_stats' / f'{fuzzer}.json'
        if stats_result_path.exists():
            return
        corpus_dir = pathlib.Path(self.oss_fuzz_path) / \
            'build' / 'corpus' / self.project / fuzzer
        corpus_zip = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'out' / self.project / f'{fuzzer}_seed_corpus.zip'
        if not corpus_zip.exists():
            logger.info(
                f"coverage failed: Corpus zip file {corpus_zip} does not exist")

            return
        with zipfile.ZipFile(corpus_zip, 'r') as zip_ref:
            zip_ref.extractall(corpus_dir)
        cwd = self.oss_fuzz_path
        cmd = ['python3', 'infra/helper.py', 'coverage', self.project,
               f'--fuzz-target={fuzzer}', f'--corpus-dir={corpus_dir}', '--no-serve']
        cov_ret = subprocess.run(cmd, cwd=cwd)
        if cov_ret.returncode != 0:
            logger.info(
                f"Coverage failed for {fuzzer}, {cov_ret.stderr.decode()}")

        else:
            logger.info(f"Coverage success for {fuzzer}")
        if not stats_result_path.parent.exists():
            stats_result_path.parent.mkdir(parents=True)
        shutil.copy(stats_path, stats_result_path)

    def run_coverage(self):
        for fuzzer in self.fuzzers:
            self.run_coverage_fuzzer(fuzzer)

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

    def extract_for_function(self, function_name, source_path):
        logger.info(f"Extracting function {function_name} from {source_path}")
        cmd = self.compile_command(source_path)
        if cmd is None:
            logger.info(
                f"Compile command for extracting {source_path} not found")
            return
        else:
            logger.info(f"Compile command for extracting {source_path} found")

        self.clang_and_extract(cmd, function_name)

    def compile_command(self, source_path):
        if self._commands is not None:
            return self._commands[source_path]
        compile_commands_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'work' / self.project / 'compile_commands.json'
        if not compile_commands_path.exists():
            logger.info(
                f"Compile commands path {compile_commands_path} does not exist, {compile_commands_path}")
            return None
        else:
            logger.info(
                f"Compile commands path {compile_commands_path} exists")
        with open(compile_commands_path, 'r') as f:
            compile_commands = json.load(f)
        commands = {}
        for item in compile_commands:
            commands[item['file']] = item
        if source_path not in commands:
            logger.info(
                f"Source path {source_path} not found in compile commands")
            return None
        self._commands = commands
        return commands[source_path]

    def clang_and_extract(self, cmd_info, function_name):

        args = cmd_info['arguments']
        if args[1:4] == [
            "-L/functions",
            "-lfunction",
            "-Wl,-rpath=.",
        ]:
            args[1:4] = []
        functions_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'functions' / self.project
        if not functions_path.exists():
            functions_path.mkdir(parents=True)
        output_file_path = functions_path / f'{function_name}.c'

        if output_file_path.exists():
            return

        args.extend(['-E', '-C', '-fdirectives-only'])
        cwd = cmd_info['directory']
        cmd = ['docker', 'exec', '-w', cwd, f'{self.project}']
        cmd.extend(args)
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            logger.error(f"clang failed: {result.stderr.decode()}")
            logger.error(f"Commands: {' '.join(cmd)}")
            return
        else:
            logger.info(f"clang success: {output_file_path}")

            line_no_directive_pattern = re.compile(r'^# \d+ ')
            try:
                with tempfile.NamedTemporaryFile(dir="/dev/shm/", mode="w+", delete=True) as temp_file:
                    for line in result.stdout.decode().splitlines():
                        if line_no_directive_pattern.match(line):
                            continue
                        temp_file.write(line + '\n')
                args_extract = [
                    '/src/clang-extract/clang-extract', temp_file.name,
                    f'-DCE_EXTRACT_FUNCTIONS={function_name}',
                    f'-DCE_OUTPUT_FILE=/functions/{function_name}.c',
                    '-c'  # Add -c flag to generate exactly one compiler job
                ]
            except Exception as e:
                return
            try:
                cmd = ['docker', 'exec', '-w', cwd, f'{self.project}']
                cmd.extend(args_extract)
                result = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                logger.error(f"extract error: {e}")
            if result.returncode != 0:
                logger.error(
                    f"clang-extract failed: /functions/{function_name}.c")
                return

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

    def __enter__(self):
        challenges_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'challenges' / self.project
        if not challenges_path.exists():
            challenges_path.mkdir(parents=True)

        fuzzers_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'out' / self.project
        if len(list(fuzzers_path.glob('*.zip'))) == 0:
            cmd = ['python', f'{self.oss_fuzz_path}/infra/helper.py', 'build_fuzzers', '--clean', '--sanitizer', 'coverage',
                   self.project]
            subprocess.run(cmd)

        cmd = ['docker', 'rm', '-f', f'{self.project}']
        result = subprocess.run(cmd, capture_output=True)
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
            f'{self.oss_fuzz_path}/build/dummy:/dummy',
            '-v',
            f'{self.oss_fuzz_path}/build/stats/{self.project}:/stats',
            '-v',
            f'{os.getcwd()}/fix:/fix',

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
            logger.info(f"Started docker container for {self.project}")
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
    def __init__(self, config_path, project: Optional[str] = None):
        self.config_path = config_path
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.oss_fuzz_path = self.config['oss_fuzz_path']
        self.projects_path = pathlib.Path(self.oss_fuzz_path) / 'projects'
        self.projects = list(
            os.listdir(self.projects_path)
        ) if project is None else project.split(',')

    def gen(self):
        final_result = {}
        for project in self.projects:
            try:
                generator = OSSFuzzDatasetGenerator(self.config_path, project)
                logger.info(f"Generating {project}")
                result = generator.generate()
                final_result[project] = result
            except KeyboardInterrupt:
                break
            except:
                continue


def main():
    args = parse_args()
    global WORKER_COUNT
    WORKER_COUNT = args.worker_count
    projects = OSSFuzzProjects(args.config, args.project)
    projects.gen()


if __name__ == '__main__':
    main()
