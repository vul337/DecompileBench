
import argparse
from contextlib import contextmanager
import json
import os
import pathlib
import re
import subprocess
import tempfile
from multiprocessing import Pool
from typing import List

import clang.cindex
import yaml
from loguru import logger

clang.cindex.Config.set_library_file('/usr/lib/llvm-16/lib/libclang-16.so.1')
index = clang.cindex.Index.create()


def is_elf(file_path):
    if file_path.is_dir():
        return False
    with open(file_path, 'rb') as f:
        elf_magic_number = b'\x7fELF'
        file_magic_number = f.read(4)
        return file_magic_number == elf_magic_number


WORKER_COUNT = os.cpu_count()


def run_in_docker(
    paths: List[pathlib.Path],
    command: str,
    cwd: pathlib.Path = pathlib.Path.cwd(),
    image: str = 'alpine',
):
    cmd = [
        'docker', 'run', '--rm',
        *sum([['-v', f'{path.resolve()}:{path.resolve()}']
             for path in paths], []),
        '-w', str(cwd.resolve()),
        image,
        'sh', '-c',
        command,
    ]
    logger.info(f"Running in docker: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


class OSSFuzzDatasetGenerator:
    def __init__(self, config, project):
        self.config = config
        self.project: str = project
        self.oss_fuzz_path = pathlib.Path(
            self.config['oss_fuzz_path']).resolve()
        self.project_info_path = self.oss_fuzz_path / \
            'projects' / project / 'project.yaml'
        with open(self.project_info_path, 'r') as f:
            self.project_info = yaml.safe_load(f)
        self._fuzzers = None
        self._functions = None
        self._commands = None
        self._link = None
        self.decompilers = self.config['decompilers']
        self.options = self.config['options']
        self.line_no_directive_pattern = re.compile(r'^# \d+ ')

    def generate(self):
        if 'language' not in self.project_info or self.project_info['language'] not in ['c', 'c++']:
            logger.info(
                f"Skipping {self.project} as it is not a C/C++ project")
            return
        self.build_fuzzer()

        for fuzzer in self.fuzzers:
            self.run_coverage_fuzzer(fuzzer)

        with self.start_container(keep=False):
            logger.info(f"Extracting functions for {self.project}")
            tasks = []
            functions_path = pathlib.Path(
                self.oss_fuzz_path) / 'build' / 'functions' / self.project

            run_in_docker(
                [self.oss_fuzz_path],
                f'mkdir -p {functions_path}',
            )

            for _, function_info in self.functions.items():
                for function, source_path in function_info.items():
                    tasks.append((function, source_path))
            logger.info(f"Extracting {len(tasks)} functions")
            Pool(WORKER_COUNT).starmap(self.extract_for_function, tasks)

    def build_fuzzer(self):
        output_path = self.oss_fuzz_path / 'build' / 'out' / self.project
        compile_commands_path = self.oss_fuzz_path / 'build' / \
            'work' / self.project / 'compile_commands.json'
        if output_path.exists() and compile_commands_path.exists():
            logger.info(f"Skipping build for {self.project}")
            return

        sanitizer = ','.join(self.config['sanitizer'])
        cmd = [
            'python3', 'infra/helper.py',
            'build_fuzzers',
            self.project,
            os.getcwd(),
            '--mount_path', '/oss-fuzz',
            '--clean',
            '--sanitizer', sanitizer,
            '-e', 'CFLAGS=-fPIC -fvisibility=default -Wl,-export-dynamic -Wno-error',
            '-e', 'CXXFLAGS=-fPIC -fvisibility=default -Wl,-export-dynamic -Wno-error',
            '-e', 'CC=clang -L/oss-fuzz -ldummy -Wl,-rpath=/oss-fuzz',
            '-e', 'CXX=clang++ -L/oss-fuzz -ldummy -Wl,-rpath=/oss-fuzz',
            '-e', 'LDFLAGS=-Qunused-arguments -L/oss-fuzz -ldummy',
        ]

        logger.info(f"Executing build_fuzzer with command: {cmd}")
        subprocess.run(
            cmd,
            cwd=str(self.oss_fuzz_path),
            check=True,
        )
        logger.info(f"Build success for {self.project}")

    def run_coverage_fuzzer(self, fuzzer: str):
        stats_result_path = self.oss_fuzz_path / 'build/stats' / \
            self.project / f'{fuzzer}_result.json'
        stats_path = self.oss_fuzz_path / 'build/out' / \
            self.project / 'fuzzer_stats' / f'{fuzzer}.json'

        if stats_result_path.exists():
            logger.info(
                f"Skipping coverage for {fuzzer} as it already exists")
            return
        corpus_dir = self.oss_fuzz_path / \
            'build' / 'corpus' / self.project / fuzzer
        corpus_zip = pathlib.Path(
            self.oss_fuzz_path) / 'build/out' / self.project / f'{fuzzer}_seed_corpus.zip'

        if not corpus_zip.exists():
            logger.warning(
                f"Coverage skip: Corpus zip file {corpus_zip} does not exist")
            return

        # Use docker to extract the corpus to avoid permission issues
        run_in_docker(
            [corpus_zip, corpus_dir],
            f'mkdir -p {corpus_dir} && unzip -o {corpus_zip} -d {corpus_dir} -q',
        )

        cwd = self.oss_fuzz_path
        cmd = [
            'python3', 'infra/helper.py',
            'coverage', self.project,
            f'--fuzz-target={fuzzer}',
            f'--corpus-dir={corpus_dir.resolve()}',
            '--no-serve',
        ]
        logger.info(f"Running coverage for {fuzzer}, cmd: {' '.join(cmd)}")
        subprocess.run(cmd, cwd=cwd, check=True)
        logger.info(f"Coverage success for {fuzzer}")

        run_in_docker(
            [self.oss_fuzz_path],
            f'mkdir -p {stats_result_path.parent} && cp {stats_path} {stats_result_path}',
        )

    def covered_function_fuzzer(self, fuzzer):
        stats_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'stats' / self.project / f'{fuzzer}_result.json'
        if not stats_path.exists():
            return {}
        with open(stats_path, 'r') as f:
            data = json.load(f)
        functions = {}
        for function in data['data'][0]['functions']:
            c_files = [
                file for file in function['filenames']
                if file.endswith('.c')
            ]
            if function['count'] < 10 or not c_files or ':' in function['name'] or function['name'] == 'LLVMFuzzerTestOneInput' or any([fuzzer in file for file in c_files]) or not any([self.project in file for file in c_files]):
                continue
            functions[function['name']] = c_files[0]
        return functions

    def extract_for_function(self, function_name, source_path):
        try:
            logger.info(
                f"Extracting function {function_name} from {source_path}")
            cmd = self.compile_command(source_path)
            self.clang_and_extract(cmd, function_name)
        except Exception as e:
            logger.error(f"Error in extracting {function_name}: {e}")

    def compile_command(self, source_path) -> List[str]:
        if self._commands is not None:
            return self._commands[source_path]
        compile_commands_path = self.oss_fuzz_path / \
            'build/work' / self.project / 'compile_commands.json'
        if not compile_commands_path.exists():
            raise Exception(
                f"Compile commands path {compile_commands_path} does not exist")
        else:
            logger.info(
                f"Compile commands path {compile_commands_path} exists")
        with open(compile_commands_path, 'r') as f:
            compile_commands = json.load(f)
        commands = {}
        for item in compile_commands:
            commands[item['file']] = item
        if source_path not in commands:
            raise Exception(
                f"Source path {source_path} not found in compile commands")
        self._commands = commands
        return commands[source_path]

    def clang_and_extract(self, cmd_info, function_name):
        cwd = cmd_info['directory']

        functions_path = self.oss_fuzz_path / 'build' / 'functions' / self.project
        output_file_path = functions_path / f'{function_name}.c'

        if output_file_path.exists():
            return

        compile_args = cmd_info['arguments'][1:]  # Skip the compiler path

        try:
            output_file_indicator = compile_args.index('-o')
            compile_args[output_file_indicator: output_file_indicator + 2] = []
        except ValueError:
            pass

        def clang_extract_directly():
            cmd = [
                'docker', 'exec', '-w', cwd, f'{self.project}',
                '/src/clang-extract/clang-extract',
                '-I/usr/local/lib/clang/18/include',
                '-I/usr/local/include',
                '-I/usr/include/x86_64-linux-gnu',
                '-I/usr/include',
                *compile_args,
                f'-DCE_EXTRACT_FUNCTIONS={function_name}',
                f'-DCE_OUTPUT_FILE=/functions/{function_name}.c',
                # '-c'  # Add -c flag to generate exactly one compiler job
            ]
            subprocess.run(cmd, check=True)

        def preprocess_then_clang_extract():
            cmd = [
                'docker', 'exec',
                '-w', cwd,
                f'{self.project}',
                *compile_args,
                '-E', '-C', '-fdirectives-only'
            ]
            clang_result = subprocess.run(
                cmd, check=True, stdout=subprocess.PIPE)

            code = '\n'.join([
                line for line in clang_result.stdout.decode().splitlines()
                if not self.line_no_directive_pattern.match(line)
            ])
            assert code, "Preprocessed code is empty"

            with tempfile.NamedTemporaryFile(prefix="/dev/shm/oss-fuzz-", mode="w", suffix='.c', delete=True) as temp_file:
                temp_file.write(code)
                temp_file.flush()

                compile_options = [
                    a for a in compile_args if a.startswith('-')
                ]

                cmd = [
                    'docker', 'exec', '-w', cwd, f'{self.project}',
                    '/src/clang-extract/clang-extract',
                    *compile_options,
                    temp_file.name,
                    f'-DCE_EXTRACT_FUNCTIONS={function_name}',
                    f'-DCE_OUTPUT_FILE=/functions/{function_name}.c',
                    '-c'  # Add -c flag to generate exactly one compiler job
                ]
                subprocess.run(cmd, check=True)

        try:
            clang_extract_directly()
        except Exception:
            preprocess_then_clang_extract()

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
        output_path = self.oss_fuzz_path / 'build' / 'out' / self.project
        fuzzers = [
            fuzzer.name for fuzzer in output_path.iterdir()
            if
            is_elf(fuzzer)
            and fuzzer.name != 'llvm-symbolizer'
            and not fuzzer.name.endswith('_patched')
        ]
        self._fuzzers = fuzzers
        return self._fuzzers

    @contextmanager
    def start_container(self, keep: bool = False):
        try:
            challenges_path = pathlib.Path(
                self.oss_fuzz_path) / 'build' / 'challenges' / self.project
            if not challenges_path.exists():
                challenges_path.mkdir(parents=True)

            fuzzers_path = self.oss_fuzz_path / 'build' / 'out' / self.project
            if len(list(fuzzers_path.glob('*.zip'))) == 0:
                self.build_fuzzer()

            cmd = ['docker', 'rm', '-f', f'{self.project}']
            result = subprocess.run(cmd, capture_output=True)
            cmd = [
                'docker',
                'run',
                '-dit',
                '--privileged',
                '--name',
                f'{self.project}',

                '-v', '/dev/shm:/dev/shm',
                '-v', f'{self.oss_fuzz_path}/build/challenges/{self.project}:/challenges',
                '-v', f'{self.oss_fuzz_path}/build/corpus/{self.project}:/corpus',
                '-v', f'{self.oss_fuzz_path}/build/out/{self.project}:/out',
                '-v', f'{self.oss_fuzz_path}/build/out/{self.project}/src:/src',
                '-v', f'{self.oss_fuzz_path}/build/functions/{self.project}:/functions',
                '-v', f'{self.oss_fuzz_path}/build/work/{self.project}:/work',
                '-v', f'{self.oss_fuzz_path}/build/stats/{self.project}:/stats',
                '-v', f'{os.getcwd()}/fix:/fix',
                '-v', f'{os.getcwd()}/libdummy.so:/oss-fuzz/libdummy.so',

                '-e', 'FUZZING_ENGINE=libfuzzer',
                '-e', 'SANITIZER=coverage',
                '-e', 'ARCHITECTURE=x86_64',
                '-e', 'HELPER=True',
                '-e', 'FUZZING_LANGUAGE=c++',
                '-e', 'CFLAGS= -fPIC -fvisibility=default  -Wl,-export-dynamic -Wno-error -Qunused-arguments',
                '-e', 'CXXFLAGS= -fPIC -fvisibility=default  -Wl,-export-dynamic -Wno-error -Qunused-arguments',
                '-e', 'CC=clang',
                '-e', 'CXX=clang++',

                f'gcr.io/oss-fuzz/{self.project}',
                '/bin/bash'
            ]

            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                print(result.stdout.decode())
                print(result.stderr.decode())
                raise Exception(
                    f"Failed to start docker container for {self.project}")
            else:
                logger.info(f"Started docker container for {self.project}")

            yield self
        finally:
            if not keep:
                cmd = ['docker', 'rm', '-f', f'{self.project}']
                subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(
        description='Generate the dataset for a given project in oss-fuzz')
    parser.add_argument('--config', type=str,
                        help='Path to the configuration file')
    parser.add_argument('--project', type=str,
                        help='Name of the projects, separated by ","', default=None)
    parser.add_argument('--worker-count', type=int,
                        help='Number of workers to use', default=os.cpu_count())
    args = parser.parse_args()

    config_path = args.config

    global WORKER_COUNT
    WORKER_COUNT = args.worker_count

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    oss_fuzz_path = config['oss_fuzz_path']
    projects_path = pathlib.Path(oss_fuzz_path) / 'projects'
    projects = list(
        os.listdir(projects_path)
    ) if args.project is None else args.project.split(',')

    for project in projects:
        try:
            generator = OSSFuzzDatasetGenerator(config, project)
            logger.info(f"Generating {project}")
            generator.generate()
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Error in {project}: {e}")
            raise


if __name__ == '__main__':
    main()
