
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
# Initialize logger
logging.basicConfig(filename='diff_branches_ossfuzz.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
diff_failed = []
from datasets import load_from_disk
dataset = load_from_disk(
    'ossfuzz_all_updated')
fuzzer_functions_path = pathlib.Path('function_fuzzer')
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


def parse_args():
    parser = argparse.ArgumentParser(
        description='Generate the dataset for a given project in oss-fuzz')
    parser.add_argument('--project', type=str, help='Name of the project')
    parser.add_argument('--config', type=str,
                        help='Path to the configuration file')
    return parser.parse_args()


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


def diff_json_dict(base, target):

    base_functions = base['data'][0]['functions']
    target_functions = target['data'][0]['functions']

    def get_diff_json(branches_2, branches_1):
        diff_branches = []
        covered_branches = 0
        for i in range(len(branches_1)):
            total_cnt_1 = branches_1[i][4] + branches_1[i][5]
            total_cnt_2 = branches_2[i][4] + branches_2[i][5]
            if total_cnt_1 == 0 and total_cnt_2 == 0:
                continue
        covered_branches += 1
        if branches_2[i] != branches_1[i]:
            diff_branches.append({
                'branch_2': branches_2[i],
                'branch_1': branches_1[i]
            })

        return diff_branches, covered_branches

    for i in range(len(target_functions)):
        diff_branches, covered_branches = get_diff_json(
            target_functions[i]['branches'], base_functions[i]['branches'])
        if len(diff_branches) > 0:
            return False
    return True


def is_elf(file_path):
    if file_path.is_dir():
        return False
    with open(file_path, 'rb') as f:
        elf_magic_number = b'\x7fELF'
        file_magic_number = f.read(4)
        return file_magic_number == elf_magic_number


class OSSFuzzDatasetGenerator:
    def __init__(self, config_path, project):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.project = project
        self.oss_fuzz_path = self.config['oss_fuzz_path']
        self.project_info_path = pathlib.Path(
            '/mnt/data/oss-fuzz/projects') / project / 'project.yaml'
        print(self.project_info_path)#/mnt/data/oss-fuzz/projects/unit/project.yaml
        with open(self.project_info_path, 'r') as f:
            self.project_info = yaml.safe_load(f)
        # print(f"Project info: {self.project_info}")
        self._fuzzers = None
        self._functions = None
        self._commands = None
        self._link = None
        self.decompilers = self.config['decompilers']
        self.options = self.config['options']
        print(self.config)

    def generate(self):
        if 'language' not in self.project_info or self.project_info['language'] not in ['c', 'c++']:
            print(f"Skipping {self.project} as it is not a C/C++ project")
            return
        print(f"Generating dataset for {self.project}")
        logger.info(f"Generating dataset for {self.project}")
        # print("--- Building fuzzer")
        # self.build_fuzzer()
        # print("--- Running coverage")
        # self.run_coverage()
        with self:
            # logger.info("--- Extracting functions")
            print("Build docker success")
            # parallel_extract(self)
            # self.compile_fuzzer()
            # logger.info(f"--- Building challenges for {self.project}")
            # parallel_build_challenge(self)
            logger.info("--- Linking and Testing Fuzzers")
            return parallel_link_and_test(self)

    def build_fuzzer(self):
        output_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'out' / self.project
        work_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'work' / self.project / 'compile_commands.json'
        # if output_path.exists() and work_path.exists():
        #     return
        cwd = self.oss_fuzz_path
        sanitizer = ','.join(self.config['sanitizer'])
        env = sum([['-e', f'{key}={value}']
                  for key, value in self.config['env'].items()], [])
        cmd = ['python3', 'infra/helper.py', 'build_fuzzers',
               '--clean', '--sanitizer', sanitizer, self.project]
        build_fuzzer_res = subprocess.run(cmd, cwd=cwd, stderr=subprocess.PIPE)
        if build_fuzzer_res.returncode!=0:
            logger.info(f"--- build_fuzzer_res for {self.project}: {build_fuzzer_res.stderr.decode()}")

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
            print(
                f"coverage failed: Corpus zip file {corpus_zip} does not exist")
            logger.error(
                f"coverage failed: Corpus zip file {corpus_zip} does not exist")
            '''
            orpus zip file /mnt/data/oss-fuzz/build/out/opensc/fuzz_asn1_print_seed_corpus.zip does not exist
            '''
            return
        with zipfile.ZipFile(corpus_zip, 'r') as zip_ref:
            zip_ref.extractall(corpus_dir)
        cwd = self.oss_fuzz_path
        print('-'*20)
        cmd = ['python3', 'infra/helper.py', 'coverage', self.project,
               f'--fuzz-target={fuzzer}', f'--corpus-dir={corpus_dir}', '--no-serve']
        print('-'*20)
        cov_ret = subprocess.run(cmd, cwd=cwd)
        if cov_ret.returncode != 0:
            print(f"Coverage failed for {fuzzer}, {cov_ret.stderr.decode()}")
            # logger.error(
            #     f"Coverage failed for {fuzzer}, {cov_ret.stderr.decode()}")
        else:
            logger.info(f"Coverage success for {fuzzer}")
            # return
        if not stats_result_path.parent.exists():
            stats_result_path.parent.mkdir(parents=True)
        shutil.copy(stats_path, stats_result_path)

    def run_coverage(self):
        for fuzzer in self.fuzzers:
            # print(f"Running coverage for {fuzzer}")
            self.run_coverage_fuzzer(fuzzer)

    def covered_function_fuzzer(self, fuzzer):

        stats_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'stats' / self.project / f'{fuzzer}_result.json'
        if not stats_path.exists():
            return {}
        with open(stats_path, 'r') as f:
            data = json.load(f)
        # /mnt/data/oss-fuzz/build/stats/tmux/input-fuzzer_result.json
        functions = {}
        for function in data['data'][0]['functions']:
            c_files = [file for file in function['filenames']
                       if file.endswith('.c')]
            if function['count'] < 10 or not c_files or ':' in function['name'] or function['name'] == 'LLVMFuzzerTestOneInput' or any([fuzzer in file for file in c_files]) or not any([self.project in file for file in c_files]):
                continue
            functions[function['name']] = c_files[0]
        return functions

# %%
    def extract_for_function(self, function_name, source_path):
        print(f"Extracting function {function_name} from {source_path}")
        cmd = self.compile_command(source_path)
        if cmd is None:
            logger.error(f"Compile command for extracting {source_path} not found")
            print(f"Compile command for extracting {source_path} not found")
            return
        else:
            print(f"Compile command for extracting {source_path} found")
            # logger.info(f"Compile command for extracting {source_path} found")

        self.clang_and_extract(cmd, function_name)
        # self.clang_extract(cmd, function_name)

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

    def compile_fuzzer(self):
        print(f"Compiling fuzzers for {self.project}, fuzzers:{self.fuzzers}")
        compile_commands_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'work' / self.project / 'compile_commands.json'
        if not compile_commands_path.exists():
            print(
                f"Compile commands path {compile_commands_path} does not exist, {compile_commands_path}")
            return None
        with open(compile_commands_path, 'r') as f:
            compile_commands = json.load(f)
        commands = {}
        for item in compile_commands:
            if 'fuzz' in item['file']:
                commands[item['file']] = item
        # for fuzzer in self.fuzzers:
        for file in commands.keys():
            cmd = commands[file]
            self.clang_compile(cmd)

    def clang_compile(self, cmd_info):
        args = cmd_info['arguments']
        if args[1:4] == [
            "-L/functions",
            "-lfunction",
            "-Wl,-rpath=.",
        ]:
            args[1:4] = []
        cwd = cmd_info['directory']
        cmd = ['docker', 'exec', '-w', cwd, f'{self.project}']
        cmd.extend(args)
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            # print(f"clang compile failed: {result.stderr.decode()}")
            logger.error(
                f"clang compile failed: {result.stderr.decode()},output to {cmd_info['output']}, err info {result.stderr.decode()}")

    def clang_extract(self, cmd_info, function_name):
        args = cmd_info['arguments']
        args[0] = '/src/clang-extract/clang-extract'
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

        args.extend([f'-DCE_EXTRACT_FUNCTIONS={function_name}',
                    f'-DCE_OUTPUT_FILE=/functions/{function_name}.c', '-I/usr/local/lib/clang/18/include'])
        cwd = cmd_info['directory']
        cmd = ['docker', 'exec', '-w', cwd, f'{self.project}']
        cmd.extend(args)
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            # print(result.stderr.decode())
            # print(f"Commands: {' '.join(cmd)}")
            logger.error(f"clang-extract failed: {result.stderr.decode()}")
            logger.error(f"Commands: {' '.join(cmd)}")
            return

    def clang_and_extract(self, cmd_info, function_name):
       
        args = cmd_info['arguments']
        # args[0] = '/src/clang-extract/clang-extract'
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
        # args.extend([f'-DCE_EXTRACT_FUNCTIONS={function_name}',
        #             f'-DCE_OUTPUT_FILE=/functions/{function_name}.c', '-I/usr/local/lib/clang/18/include'])
        cwd = cmd_info['directory']
        cmd = ['docker', 'exec', '-w', cwd, f'{self.project}']
        cmd.extend(args)
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            # print(result.stderr.decode())
            # print(f"Commands: {' '.join(cmd)}")
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
                    '-c' # Add -c flag to generate exactly one compiler job
                ]
            except Exception as e:
                # logger.info(f"writing tmp file failed: {e}")
                return
            # logger.info(f"Commands: {' '.join(args_extract)}")
            try:
                cmd = ['docker', 'exec', '-w', cwd, f'{self.project}']
                cmd.extend(args_extract)
                result = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                logger.error(f"extract error: {e}")
            if result.returncode != 0:
                logger.error(f"clang-extract failed: /functions/{function_name}.c")
                return
            # else:
            #     logger.info(f"clang-extract success: {output_file_path}")

    def extract_functions(self):
        functions_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'functions' / self.project
        if functions_path.exists():
            return
        local_src = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'out' / self.project / 'src' / 'clang-extract'
        if not local_src.exists():
            print(f"Clang extract source code not found in {local_src}")
            return
        tbar = tqdm.tqdm(self.functions.items(), position=0)
        for fuzzer, function_info in tbar:
            tbar.set_postfix_str(f'{fuzzer:50s}')
            fbar = tqdm.tqdm(function_info.items(), position=1)
            for function, source_path in fbar:
                fbar.set_postfix_str(f'{function:50s}')
                cmd = self.compile_command(source_path)
                if cmd is None:
                    continue
                self.clang_extract(cmd, function)

    def build_challenge_for_function(self, function_name,is_base, decompiler=None,option=None,func=None):
        
        base_so_path = pathlib.Path(self.oss_fuzz_path) / 'build' / 'challenges' / self.project / function_name / 'libfunction.so'
        if base_so_path.exists():
            print(f"Challenge for {function_name} already exists")
            return True

        base_cmd = ['docker', 'exec', f'{self.project}']
        shared_lib_cmd = copy.deepcopy(base_cmd)
        if not is_base:
            target_so_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
                'decompile' / self.project / function_name / option / decompiler / 'libfunction.so'
            decompiled_challenge_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
                'challenges' / self.project / function_name / option / decompiler
            if not decompiled_challenge_path.exists():
                decompiled_challenge_path.mkdir(parents=True)
            
            shared_lib_cmd.extend(['clang',  f"-I/fix/{decompiler}",f'/challenges/{function_name}/{option}/{decompiler}/{function_name}.c','-fPIC', '-shared', 
                                    '-o', f'/challenges/{function_name}/{option}/{decompiler}/libfunction.so', 
                                    "-fprofile-instr-generate", "-fcoverage-mapping", "-pthread", "-Wl,--no-as-needed", "-Wl,-ldl", "-Wl,-lm", "-Wno-unused-command-line-argument"
                                    ])
            result = subprocess.run(
                shared_lib_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                print(f"building target failed :{result.stderr.decode()}")
                logger.error(f"building target failed : {' '.join(shared_lib_cmd)}")
                return False
            else:
                logger.info(f"building target success: {target_so_path}")
        else:
            function_source_path = pathlib.Path(
                self.oss_fuzz_path) / 'build' / 'functions' / self.project / f'{function_name}.c'  # include?
            function_challenge_path = pathlib.Path(
                self.oss_fuzz_path) / 'build' / 'challenges' / self.project / function_name

            if not function_source_path.exists():
                logger.error(f"Source path {function_source_path} does not exist")
                return False
            if not function_challenge_path.exists():
                logger.info(f"Challenge path {function_challenge_path} does not exist")
                function_challenge_path.mkdir(parents=True, exist_ok=True)

            with open(function_source_path, 'r') as f:
                source = f.read()
            with open(function_challenge_path / f'{function_name}.c', 'w') as f:
                try:
                    f.write(make_function_static(source, function_name))
                except Exception as e:
                    print(f"Error making function static for {function_name}: {e}")
                    return False
                f.write(TEMPLATE.format(function=function_name))
                f.flush()
            
            shared_lib_cmd.extend(['clang', '-fPIC', '-shared', '-o',
                                    f'/challenges/{function_name}/libfunction.so', f'/challenges/{function_name}/{function_name}.c',
                                    "-fprofile-instr-generate", "-fcoverage-mapping", "-pthread", "-Wl,--no-as-needed", "-Wl,-ldl", "-Wl,-lm", "-Wno-unused-command-line-argument"
                                    ])
            result = subprocess.run(
                shared_lib_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                print(f"building base failed :{result.stderr.decode()}")
                logger.error(f"building base failed :{result.stderr.decode()}")
                return False
            else:
                logger.info(f"building base success: {function_challenge_path}")
        return True

    def build_challenges(self):
        challenges_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'challenges' / self.project
        if challenges_path.exists():
            return
        functions_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'functions' / self.project
        tbar = tqdm.tqdm(self.functions.items(), position=0)
        for fuzzer, function_info in tbar:
            tbar.set_postfix_str(f'{fuzzer:50s}')
            fuzzer_challenge_path = challenges_path / fuzzer
            if not fuzzer_challenge_path.exists():
                fuzzer_challenge_path.mkdir(parents=True)
            fbar = tqdm.tqdm(function_info.items(), position=1)
            for function, _ in fbar:
                fbar.set_postfix_str(f'{function:50s}')
                function_challenge_path = fuzzer_challenge_path / function
                if not (functions_path / f'{function}.c').exists():
                    continue
                with open(functions_path / f'{function}.c', 'r') as f:
                    source = f.read()
                if not function_challenge_path.exists():
                    function_challenge_path.mkdir(parents=True)
                with open(function_challenge_path / f'{function}.c', 'w') as f:
                    f.write(make_function_static(source, function))
                    f.write(TEMPLATE.format(function=function))
                    f.flush()
                base_cmd = ['docker', 'exec', f'{self.project}']
                shared_lib_cmd = copy.deepcopy(base_cmd)
                shared_lib_cmd.extend(['clang', '-fPIC', '-shared', '-o',
                                      f'/challenges/{function}/libfunction.so', f'/challenges/{function}/{function}.c'])
                result = subprocess.run(
                    shared_lib_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode != 0:
                    print(result.stderr.decode())
                    shutil.rmtree(function_challenge_path)
                    continue

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
        fuzzer_functions = fuzzer_functions_path
        with open(fuzzer_functions / f'{self.project}.json', 'r') as f:
            preset_functions = json.load(f)
        for fuzzer in self.fuzzers:
            # functions[fuzzer] = self.covered_function_fuzzer(fuzzer)
            functions[fuzzer] = preset_functions[fuzzer]
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
                # logger.error(f"chmod failed: {result.stderr.decode()}")
                return False
        else:
            # logger.error(
            #     f"patched fuzzer failed: {str(fuzzer_path.resolve())}")
            return False
        return True

    def diff_base_for_function(self, fuzzer, function_name):
        challenges_path = pathlib.Path(
            self.oss_fuzz_path) / 'build' / 'out' / self.project / fuzzer
        base_lib_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / 'libfunction.so'

        if not base_lib_path.exists():
            # print(f"base lib path {base_lib_path} does not exist")
            # logger.error(
            #     f"testing: base lib path {base_lib_path} does not exist")
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
        # base_profraw_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
        #     'challenges' / self.project / function_name / fuzzer / 'base.profraw'
        # base_json_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
        #     'challenges' / self.project / function_name / fuzzer / 'base.json'
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
        # base_profraw_path1 = pathlib.Path(self.oss_fuzz_path) / 'build' / \
        #     'challenges' / self.project / function_name / fuzzer / 'base1.profraw'
        # base_json_path1 = pathlib.Path(self.oss_fuzz_path) / 'build' / \
        #     'challenges' / self.project / function_name / fuzzer / 'base1.json'
        base_txt_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / fuzzer / 'base.txt'
        base_txt_path1 = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / fuzzer / 'base1.txt'
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
            result.check_returncode()
            # logger.info(
            #     f"base txt generation success: {base_txt_path}")
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
        # logger.info(f"target libs:{target_libs}, of project:{self.project}")
        for options, target_lib_path in target_libs.items():
            # target_profraw_path = pathlib.Path(self.oss_fuzz_path) / 'build' / 'challenges' / \
            #     self.project / function_name / fuzzer / f'{options}.profraw'
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
        # cmd = cmd + [
        #     'rm',
        #     '-f',
        #     f'/out/{fuzzer}_{function_name}_patched'
        # ]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True


    # def link_and_test_for_function(self, fuzzer, function_name, cmd_info):
    def link_and_test_for_function(self, fuzzer, function_name):
        base_txt_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / fuzzer / 'base.txt'
        if base_txt_path.exists():
            return True
        if self.link_for_function(fuzzer, function_name):
            self.diff_base_for_function(fuzzer, function_name)

    def recompile(self):
        clean_cmd = ['docker', 'exec',
                     f'{self.project}', 'bash', '-c', 'rm -rf /work/*']
        subprocess.run(clean_cmd, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        clean_cmd = ['docker', 'exec',
                     f'{self.project}', 'bash', '-c', 'rm -rf /out/*']
        subprocess.run(clean_cmd, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        build_cmd = [
            'docker',
            'exec',
            # '-w',
            # f'/src/{self.project}',
            f'{self.project}',
            'bash',
            '-c',
            'bear --config /src/bear_config.json --output /work/compile_commands.json -- compile'
        ]

        build_result = subprocess.run(
            build_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if build_result.returncode != 0:
            # raise Exception(f"Failed to build {self.project}")
            logger.error(f"Failed to build {self.project}, {build_result.stderr.decode()}")

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


pool = Pool(96)


def parallel_extract(generator):
    print(f"Extracting functions for {generator.project}")
    tasks = []
    functions_path = pathlib.Path(
        generator.oss_fuzz_path) / 'build' / 'functions' / generator.project
    
    functions_path.mkdir(parents=True, exist_ok=True)
    for _, function_info in generator.functions.items():
        for function, source_path in function_info.items():
            tasks.append((generator, function, source_path))
    print(f"Extracting {len(tasks)} functions")
    pool.starmap(OSSFuzzDatasetGenerator.extract_for_function, tasks)


def parallel_build_challenge(generator):
    tasks = set()
    challenges_path = pathlib.Path(
        generator.oss_fuzz_path) / 'build' / 'challenges' / generator.project
    if not challenges_path.exists():
        challenges_path.mkdir(parents=True, exist_ok=True)
    for _, function_info in generator.functions.items():
        for function, source_path in function_info.items():
            # if function not in all_funtions:
            #     continue
            tasks.add((generator, function,True))
            
    print(f"--- Project {generator.project} Building {len(tasks)} base challenges")
    pool.starmap(OSSFuzzDatasetGenerator.build_challenge_for_function, tasks)



def parallel_link_and_test(generator):
    tasks = []
    for fuzzer, function_info in generator.functions.items():
        for function, _ in function_info.items():
            # cmd = generator.link_command(fuzzer)
            tasks.append((generator, fuzzer, function))
    print(f"Linking and testing {len(tasks)} tasks")
    # import ipdb; ipdb.set_trace()
    return pool.starmap(OSSFuzzDatasetGenerator.link_and_test_for_function, tasks)


def parallel_diff(generator):
    tasks = []
    for fuzzer, function_info in generator.functions.items():
        for function, _ in function_info.items():
            tasks.append((generator, fuzzer, function))
    print(f"Diffing {len(tasks)} fuzzers")
    result = pool.starmap(OSSFuzzDatasetGenerator.diff_for_function, tasks)
    # print(result)
    return result


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
        with open(f'{self.config["result_path"]}', 'w') as f:
            json.dump(final_result, f)


def main():
    args = parse_args()
    projects = OSSFuzzProjects(args.config)
    projects.gen()

if __name__ == '__main__':
    main()



# %%
