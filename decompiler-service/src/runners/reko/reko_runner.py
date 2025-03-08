import os
import subprocess
from pathlib import Path
import argparse
import json
import re

pattern = re.compile(r"// ([0-9A-Fa-f]+):")
REKO_INSTALL = Path(os.getenv("REKO_INSTALL_PATH", "/home/decompiler_user/reko"))
REKO_DECOMPILE = REKO_INSTALL / 'reko'


def read_code_str(binary_path):
    
    decomp = subprocess.run([REKO_DECOMPILE, binary_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if decomp.returncode != 0:
        return ""
    bin_path_list = binary_path.split('.')
    if len(bin_path_list) >= 2:
        binary_path = '.'.join(bin_path_list[:-1])
    outputs = Path(binary_path + ".reko")
    output_str = ""
    seen = set()
    for source in outputs.glob('*text*.c'):
        with open(source, 'r') as f:
            seen.add(source)
            output_str = output_str + f.read()
    for source in outputs.glob('*.c'):
        if source in seen:
            continue
        with open(source, 'r') as f:
            output_str = output_str + f.read()
                        
    os.system(f"rm -rf {outputs}")
    return output_str
    
def extract_function_bodies(code, address_list):
    if not code:
        return {}
    functions = {}
    address_list_int = [int(address, 16) for address in address_list]
    for match in pattern.finditer(code):
        address = match.group(1)
        if int(address, 16) not in address_list_int:
            continue
        start_index = match.end()
        end_index = -1
        bracket_count = 0

        real_start = start_index
        start_setted = False

        for i in range(start_index, len(code)):
            char = code[i]
            if char == '\n' and not start_setted:
                real_start = i+1
                start_setted = True
            if char == '{':
                bracket_count += 1
            elif char == '}':
                bracket_count -= 1
                if bracket_count == 0:
                    end_index = i + 1  
                    break

        function_body = code[real_start:end_index].strip()
        functions[hex(int(address,16))] = function_body

    return functions

def decompile_functions(binary_path, addresses):
    code = read_code_str(binary_path)
    return extract_function_bodies(code, addresses)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Decompile functions at given addresses in a binary.')
    parser.add_argument('--binary', required=True, help='Path to the binary file')
    parser.add_argument('--address', required=True, nargs='+', help='List of addresses to decompile')
    parser.add_argument('--file', required=True, help='Path to the output file')
    return parser.parse_args()


def main():
    args = parse_arguments()
    binary_path = args.binary
    addresses = args.address
    
    decompiled_functions = decompile_functions(binary_path, addresses)
    
    with open(args.file, 'w') as f:
        f.write(json.dumps(decompiled_functions, indent=4))

if __name__ == '__main__':
    main()