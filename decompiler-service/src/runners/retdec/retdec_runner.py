import argparse
import json
import re
from pathlib import Path
import os
import subprocess
import tempfile

pattern = re.compile(r"0x\w+")
RETDEC_INSTALL = Path(os.getenv("RETDEC_INSTALL_PATH", "/home/decompiler_user/retdec/bin"))
RETDEC_DECOMPILER = RETDEC_INSTALL / 'retdec-decompiler'

def match_addr(input_str):
    if not input_str:
        return None
    if not "// Address range:" in input_str:
        return None
    match = pattern.search(input_str)
    addr = match.group() if match else None
    return addr
    
def parse_arguments():
    parser = argparse.ArgumentParser(description='Decompile functions at given addresses in a binary.')
    parser.add_argument('--binary', required=True, help='Path to the binary file')
    parser.add_argument('--address', required=True, nargs='+', help='List of addresses to decompile')
    parser.add_argument('--file', required=True, help='Path to the output file')
    return parser.parse_args()

def read_output(json_file: str):
    with open(json_file, 'r') as f:
        return json.load(f)

def extract_function_bodies(tokens, function_addresses):
    function_bodies = {}

    output = ""
    brace_count = 0
    in_function = False
    current_function_address = None
    start = False

    for token in tokens:
        
        if token.get("kind") == "cmnt":
            addr = match_addr(token.get("val"))
            if addr in function_addresses:
                current_function_address = addr
                in_function = True
                continue

        if in_function:
            if token.get("val") == '{':
                start = True
                brace_count += 1
            elif token.get("val") == '}':
                brace_count -= 1

            if token.get("val") is not None:
                output = output + token.get("val")

            if brace_count == 0 and start:
                function_bodies[current_function_address] = output.strip()
                in_function = False
                start = False

    return function_bodies

def decompile_functions(binary_path, addresses):
    with tempfile.TemporaryDirectory() as tempdir:
        outfile = tempfile.NamedTemporaryFile(dir=tempdir, delete=False)
        decomp = subprocess.run([RETDEC_DECOMPILER, '-f', 'json-human', '--output', outfile.name, '--cleanup', '--silent', binary_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if decomp.returncode == 0:
            json_content = read_output(outfile.name)
            tokens = json_content['tokens']
            os.system(f"rm {outfile.name}.bc {outfile.name}.config.json {outfile.name}.dsm {outfile.name}.ll")
            return extract_function_bodies(tokens, addresses)
        else:
            return {}

def main():
    args = parse_arguments()
    binary_path = args.binary
    addresses = args.address
    
    decompiled_functions = decompile_functions(binary_path, addresses)
    
    with open(args.file, 'w') as f:
        f.write(json.dumps(decompiled_functions, indent=4))

if __name__ == '__main__':
    main()
