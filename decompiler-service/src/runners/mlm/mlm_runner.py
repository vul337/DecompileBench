import argparse
import json
import os

from ric import RICConfig, RIC
import openai
import asyncio

client = openai.AsyncClient()
MODEL = os.getenv("MODEL_NAME", "mlm")
TEMPERATURE = float(os.getenv("TEMPERATURE", 0.1))


async def generate(client: openai.AsyncClient, code, address):
    response = await client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": code
            }
        ],
        model=MODEL,
        temperature=TEMPERATURE,
    )
    return address, response.choices[0].message.content


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Decompile functions at given addresses in a binary using Hex-Rays Decompiler.')
    parser.add_argument('--binary', required=True,
                        help='Path to the binary file')
    parser.add_argument('--address', required=True, nargs='+',
                        help='List of addresses to decompile')
    parser.add_argument('--file', required=True,
                        help='Path to the output file')
    return parser.parse_args()


def decompile_function(idaapi, ida_hexrays, ea):
    func = idaapi.get_func(ea)
    if not func:
        return None

    cfunc = ida_hexrays.decompile(func)
    if not cfunc:
        return None

    return str(cfunc)


async def decompile_functions(idaapi, idc, ida_hexrays, addresses):
    decompiled_code = {}
    tasks = []
    for address in addresses:
        addr = int(address, 16)  # Convert address from hex string to integer
        decompiled = decompile_function(idaapi, ida_hexrays, addr)
        tasks.append(asyncio.create_task(
            generate(client, decompiled, address)))

    for task in tasks:
        addr, decompiled = await task
        if decompiled is not None:
            decompiled_code[addr] = decompiled
        else:
            decompiled_code[addr] = "ERROR"
    return decompiled_code


async def main():
    args = parse_arguments()
    binary_path = args.binary
    addresses = args.address
    output_file = args.file

    # Initialize RIC
    config = RICConfig(binary=binary_path)
    ric = RIC(config)
    ric.start()

    # "Import" IDA modules
    idaapi = ric.get_module('idaapi')
    idc = ric.get_module('idc')
    ida_hexrays = ric.get_module('ida_hexrays')

    # Wait for IDA to finish analyzing the binary
    idc.auto_wait()

    # Decompile the specified functions
    decompiled_functions = await decompile_functions(idaapi, idc, ida_hexrays, addresses)

    # Stop RIC
    ric.stop()

    # Save the results to the output file
    with open(output_file, 'w') as f:
        f.write(json.dumps(decompiled_functions, indent=4))

    os.system(f"rm {binary_path}.i64")

if __name__ == '__main__':
    asyncio.run(main())
