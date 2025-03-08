import sys
import json
import argparse
import angr

def parse_arguments():
    parser = argparse.ArgumentParser(description='Decompile functions at given addresses in a binary using angr.')
    parser.add_argument('--binary', required=True, help='Path to the binary file')
    parser.add_argument('--address', required=True, nargs='+', help='List of addresses to decompile')
    parser.add_argument('--file', required=True, help='Path to the output file')
    return parser.parse_args()

def is_pie(project):
    return project.loader.main_object.pic

def get_base_address(project):
    return project.loader.main_object.mapped_base

def decompile_functions(binary_path, addresses):
    # Load the binary file with angr
    p = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

    # Generate CFG
    cfg = p.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True, data_references=True)
    p.analyses.CompleteCallingConventions(cfg=cfg.model, recover_variables=True, analyze_callsites=True)

    base_address = get_base_address(p) if is_pie(p) else 0

    decompiled_code = {}

    for address in addresses:
        addr = int(address, 16) + base_address  # Adjust address for PIE

        func = cfg.functions.get(addr)

        if func is None:
            decompiled_code[address] = "Failed to find the function at the given address."
            continue

        try:
            decompiler = p.analyses.Decompiler(func, cfg=cfg.model)
            if decompiler.codegen is None:
                decompiled_code[address] = f"// No decompilation output for function at address {address}\n"
            else:
                decompiled_code[address] = decompiler.codegen.text
        except Exception as e:
            decompiled_code[address] = f"Exception thrown decompiling function at address {address}: {e}"

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