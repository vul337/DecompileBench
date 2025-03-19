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

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

log_path = 'diff_branches_ossfuzz.txt'
# Configure loguru to write to both console and file
logger.add(log_path, rotation="500 MB", level="INFO",
           format="{time} - {level} - {message}")
# logging.basicConfig(filename=log_path, level=logging.INFO,
#                     format='%(asctime)s - %(levelname)s - %(message)s')
# logger = logging.getLogger(__name__)

CODE = b"""\
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


def get_func_offsets(so_path: pathlib.Path,
                     binary_path: pathlib.Path,
                     output_path: pathlib.Path):
    try:
        # Use pyelftools to read relocations
        offset_func = []

        with open(so_path, 'rb') as f:
            elf = ELFFile(f)

            # Find the .rela.plt section
            rela_plt = None
            for section in elf.iter_sections():
                if isinstance(section, RelocationSection) and section.name == '.rela.plt':
                    rela_plt = section
                    break

            if rela_plt:
                # Get the symbol table referenced by this relocation section
                symtable = elf.get_section(rela_plt['sh_link'])

                # Process each relocation entry
                for reloc in rela_plt.iter_relocations():
                    symbol_idx = reloc['r_info_sym']
                    symbol = symtable.get_symbol(symbol_idx)
                    symbol_name = symbol.name

                    if symbol_name:
                        offset_func.append({
                            "so_offset": hex(reloc['r_offset']),
                            "so_func": symbol_name
                        })

        # Find binary offsets using pyelftools instead of nm
        with open(binary_path, 'rb') as f:
            binary_elf = ELFFile(f)

            # Get all symbol tables
            symbol_tables = [s for s in binary_elf.iter_sections()
                             if isinstance(s, SymbolTableSection)]

            # Create a lookup dictionary for all symbols
            binary_symbols = {}
            for symtab in symbol_tables:
                for symbol in symtab.iter_symbols():
                    if symbol.name and symbol['st_value'] != 0:
                        binary_symbols[symbol.name] = symbol['st_value']

            # Match symbols from so_file with binary symbols
            for item in offset_func:
                if item['so_func'] in binary_symbols:
                    item['binary_offset'] = hex(
                        binary_symbols[item['so_func']])

        with open(output_path, "w") as f:
            f.write(binary_path.name + "\n")
            for item in offset_func:
                if 'binary_offset' in item:
                    f.write(f"{item['binary_offset']} {item['so_offset']}\n")
    except Exception as e:
        logger.error(f"get_func_offsets failed: {e}")
        return


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
            results = Pool(WORKER_COUNT).starmap(
                self.link_and_test_for_function, tasks)
            self.exec_in_container(
                [
                    'bash', '-c',
                    'rm -rf /out/*_patched',
                ],
            )
            return results

    def link_and_test_for_function(self, fuzzer, function_name):
        try:
            if self.patch_binary_jmp_to_function(fuzzer, function_name):
                return self.diff_base_for_function(fuzzer, function_name)
        except Exception as e:
            logger.error(
                f"link_and_test_for_function failed: {e}")
            return (fuzzer, function_name, {})

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
            logger.error(f"Fuzzer {fuzzer_path} not exists")
            raise Exception(f"Fuzzer {fuzzer_path} not exists")

    def diff_base_for_function(self, fuzzer: str, function_name: str):
        patched_fuzzer_path = self.oss_fuzz_path / 'build' / 'out' / \
            self.project / f'{fuzzer}_{function_name}_patched'
        base_lib_path = pathlib.Path(self.oss_fuzz_path) / 'build' / \
            'challenges' / self.project / function_name / 'libfunction.so'

        if not base_lib_path.exists():
            print(f"base lib path {base_lib_path} does not exist")
            return (fuzzer, function_name, {})

        if not patched_fuzzer_path.exists():
            print(f"fuzzer path {patched_fuzzer_path} does not exist")
            logger.error(
                f"testing: fuzzer path {patched_fuzzer_path} does not exist")
            return (fuzzer, function_name, {})

        output_mapping_path = base_lib_path.parent / 'address_mapping.txt'
        get_func_offsets(base_lib_path, patched_fuzzer_path,
                         output_mapping_path)
        cmd = [
            'bash',
            '-c',
            f'/out/{fuzzer}_{function_name}_patched -runs=0 -seed=3918206239 /corpus/{fuzzer} && ' +
            'llvm-profdata merge -sparse $LLVM_PROFILE_FILE -o $OUTPUT_PROFDATA && ' +
            f'llvm-cov show -instr-profile $OUTPUT_PROFDATA -object=/out/{fuzzer}_{function_name}_patched > $OUTPUT_TXT'
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
                    f'MAPPING_TXT=/challenges/{function_name}/address_mapping.txt',
                    f'LD_PRELOAD=/oss-fuzz/ld.so'
                ], timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # result.check_returncode()
                with open(str(base_txt_path), 'r') as f:
                    base_result = f.read()
                if txt_length != 0 and len(base_result) != txt_length:
                    logger.error(
                        f"base txt length mismatch, expected {txt_length}, got {len(base_result)}")
                    return (fuzzer, function_name, {})
                txt_length = len(base_result)
                if len(log_set) == 0:
                    log_set = [set() for _ in range(txt_length)]
                for i, line in enumerate(base_result):
                    log_set[i].add(line)

            except Exception as e:
                logger.error(
                    f"base txt generation failed:{e}")
                return (fuzzer, function_name, {})

        diff_result = {}
        target_libs = {}
        for decompiler in self.decompilers:
            for option in self.opt_options:
                target_lib_path = pathlib.Path(self.oss_fuzz_path) / 'build' / 'challenges' / \
                    self.project / function_name / option / decompiler / 'libfunction.so'
                if target_lib_path.exists():
                    target_libs[f'{decompiler}-{option}'] = f'/challenges/{function_name}/{option}/{decompiler}'
                else:
                    diff_result[f'{decompiler}-{option}'] = False
        
        for options, target_lib_path in target_libs.items():
            target_txt_path = pathlib.Path(self.oss_fuzz_path) / 'build' / 'challenges' / \
                self.project / function_name / fuzzer / f'{options}.txt'
            try:
                result = self.exec_in_container(cmd=cmd, envs=[
                    f'LD_LIBRARY_PATH={target_lib_path}:/work/lib/',
                    f'LLVM_PROFILE_FILE=/challenges/{function_name}/{fuzzer}/{options}.profraw',
                    f'OUTPUT_PROFDATA=/challenges/{function_name}/{fuzzer}/{options}.profdata',
                    f'OUTPUT_TXT=/challenges/{function_name}/{fuzzer}/{options}.txt',
                    f'MAPPING_TXT=/challenges/{function_name}/address_mapping.txt',
                    f'LD_PRELOAD=/oss-fuzz/ld.so',
                ], timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # result.check_returncode()
                with open(str(target_txt_path), 'r') as f:
                    target_result = f.read()
                target_difference = []
                for i, line in enumerate(target_result):
                    if len(log_set[i]) == 1 and line not in log_set[i]:
                        target_difference.append(i)
                if len(target_difference) == 0:
                    logger.info(
                        f"--- target txt diff {self.project} {function_name} {fuzzer} {options}")
                    diff_result[options] = True
                else:
                    logger.error(
                        f"--- target txt diff {self.project} {function_name} {fuzzer} {options}, differences length:{len(target_difference)}")
                    diff_result[options] = False
            except Exception as e:
                logger.error(
                    f"--- target txt diff {self.project} {function_name} {fuzzer} {options}: target txt generation failed")
                diff_result[options] = False

        self.exec_in_container(
            [
                'bash', '-c',
                f'''
                    rm -rf /challenges/{function_name}/{fuzzer}/*.txt &&
                    rm -rf /challenges/{function_name}/{fuzzer}/*.profraw &&
                    rm -rf /challenges/{function_name}/{fuzzer}/*.profdata
                ''',
            ]
        )

        return (fuzzer, function_name, diff_result)


def process_results(results_list):
    """Process the results from evaluator.do_execute() into a structured format."""
    processed_results = {}
    
    for result in results_list:
        if not result or len(result) != 3:
            continue
            
        fuzzer, function, diff_results = result
        
        for option_key, success in diff_results.items():
            decompiler, option = option_key.rsplit('-', 1)
            
            # Build the nested dictionary structure
            processed_results.setdefault(function, {}) \
                .setdefault(decompiler, {}) \
                .setdefault(option, []) \
                .append((fuzzer, success))
    
    return processed_results

def show_statistics(all_project_results,dataset,decompilers,opts):
    pass_count = {}
    function_count = {project: len(dataset.filter(lambda x: x['project']==project and x['opt']=='O0')) for project in list(set(dataset['project']))}
    
    # Count passes and totals
    for project, results in all_project_results.items():
        pass_count[project] = {}
        for decompiler in decompilers:
            pass_count[project].setdefault(decompiler, {})
            for option in opts:
                pass_count[project][decompiler].setdefault(option, 0)
        for function, decompiler_results in results.items():
            for decompiler,option_results in decompiler_results.items():
                for option, results in option_results.items():
                    all_passed = all(result[1] for result in results)
                    if all_passed:
                        pass_count[project][decompiler][option] += 1

    # Print statistics
    
    all_total = 0
    for project in pass_count:
        total = function_count[project]
        all_total += total
    for decompiler in decompilers:
        for option in opts:
            passes = sum([pass_count[project][decompiler][option] for project in pass_count])
            rate = passes / all_total
            print(f"decompiler:{decompiler}, option:{option}, rate:{rate:.2f}")

def main():
    parser = argparse.ArgumentParser(
        description='Generate the dataset for a given project in oss-fuzz')
    parser.add_argument('--config', type=str, default="./config.yaml",
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

    decompilers = None
    opts = None
    if not os.path.exists('tmp_results'):
        os.makedirs('tmp_results')
    all_project_results = {}
    for project in projects:
        try:
            print(config_path, project)
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            evaluator = ReexecutableRateEvaluator(config, project)
            if not decompilers:
                decompilers = evaluator.decompilers
            if not opts:
                opts = evaluator.opt_options
            results = evaluator.do_execute()
            if results:
                # Process the results into a structured format
                processed_results = process_results(results)
                all_project_results[project] = processed_results
                
                # Also save the raw results for reference
                with open(f'tmp_results/{project}_raw_results.json', 'w') as f:
                    json.dump(results, f, default=str)
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Error processing project {project}: {e}")
            continue
    
    # Save the processed results
    with open('cer_results.json', 'w') as f:
        json.dump(all_project_results, f)
    try:
        show_statistics(all_project_results, dataset, decompilers,opts)
    except Exception as e:
        import ipdb;ipdb.set_trace()



if __name__ == '__main__':
    main()
