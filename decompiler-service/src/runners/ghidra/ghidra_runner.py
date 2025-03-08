import pyhidra
import argparse
import lief
import json
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

def is_pie(file_path):
    binary = lief.parse(file_path)
    return binary.is_pie

def parse_arguments():
    parser = argparse.ArgumentParser(description='Decompile functions at given addresses in a binary.')
    parser.add_argument('--binary', required=True, help='Path to the binary file')
    parser.add_argument('--address', required=True, nargs='+', help='List of addresses to decompile')
    parser.add_argument('--file', required=True, help='Path to the output file')
    return parser.parse_args()
    
def decompile_functions(binary_path, addresses):
    
    PIE = is_pie(binary_path)
    with pyhidra.open_program(binary_path) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        def getAddress(offset):
            if not PIE:
                return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
            else:
                baseAddress = program.getImageBase()
                return baseAddress.add(offset)
        
        addr = getAddress(int(addresses[0], 16))  
        function = fm.getFunctionAt(addr)
        
        decomp_api = FlatDecompilerAPI(flat_api)
        decompiled_code = decomp_api.decompile(function)
        decompiled_code = {}
        for address in addresses:
            addr = getAddress(int(address, 16))  
            function = fm.getFunctionAt(addr)
            code = decomp_api.decompile(function)
            decompiled_code[address] = code.strip()
    
    return decompiled_code

def main():
    args = parse_arguments()
    binary_path = args.binary
    addresses = args.address
    
    decompiled_functions = decompile_functions(binary_path, addresses)
    
    with open(args.file, 'w') as f:
        f.write(json.dumps(decompiled_functions, indent=4))

if __name__ == '__main__':
    main()
            
        