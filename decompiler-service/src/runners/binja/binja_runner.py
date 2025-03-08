import argparse
import binaryninja
from binaryninja import lineardisassembly
from binaryninja.function import DisassemblySettings
from binaryninja.enums import DisassemblyOption, LinearDisassemblyLineType, InstructionTextTokenType
import json

def parse_arguments():
    parser = argparse.ArgumentParser(description='Decompile functions at given addresses in a binary.')
    parser.add_argument('--binary', required=True, help='Path to the binary file')
    parser.add_argument('--address', required=True, nargs='+', help='List of addresses to decompile')
    parser.add_argument('--file', required=True, help='Path to the output file')
    return parser.parse_args()

def decompile_functions(binary_path, addresses):
    # Open the binary file with Binary Ninja
    bv = binaryninja.load(binary_path, update_analysis=True)
    if bv is None:
        raise Exception("Unable to open view for binary")

    settings = DisassemblySettings()
    settings.set_option(DisassemblyOption.ShowVariableTypesWhenAssigned)
    settings.set_option(DisassemblyOption.GroupLinearDisassemblyFunctions)
    settings.set_option(DisassemblyOption.WaitForIL)

    bv.update_analysis_and_wait()

    decompiled_code = {}

    for address in addresses:
        addr = int(address, 16)  # Convert address from hex string to integer
        func = bv.get_function_at(addr)

        if func is None:
            # If there is no function at the address, define one and update analysis
            bv.add_function(addr)
            func = bv.get_function_at(addr)

        if func is not None:
            # Get the pseudocode representation
            obj = lineardisassembly.LinearViewObject.single_function_language_representation(func, settings)
            cursor = obj.cursor
            output = ""
            while True:
                for line in cursor.lines:
                    if line.type in [
                        LinearDisassemblyLineType.FunctionHeaderStartLineType,
                        LinearDisassemblyLineType.FunctionHeaderEndLineType,
                        LinearDisassemblyLineType.AnalysisWarningLineType,
                    ]:
                        continue
                    for i in line.contents.tokens:
                        if i.type == InstructionTextTokenType.TagToken:
                            continue
                        output += str(i)
                    output += "\n"
                if not cursor.next():
                    break
            decompiled_code[address] = output
        else:
            decompiled_code[address] = "Failed to decompile the function."

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
