import argparse
import asyncio
import json
from pathlib import Path

import openai
from datasets import load_from_disk
from tqdm import tqdm


def parse_arguments():
    parser = argparse.ArgumentParser(description="Decompile with LLM")
    parser.add_argument("--dataset", type=str, required=True,
                        help="Path to the dataset")
    parser.add_argument("--output", type=str, required=True,
                        help="Path to the output directory")
    parser.add_argument("--model", type=str, required=True, help="Model name")
    return parser.parse_args()


args = parse_arguments()

client = openai.AsyncClient()


def format_message(message, role):
    return f"<s>{role}\n{message}</s>\n"


def prompt_format_decompile(decompile_code: str, opt: str, model: str) -> str:
    if model == "LLM4Binary/llm4decompile-22b-v2":
        prompt = f"# This is the assembly code:\n"
        prompt = prompt + decompile_code.strip() + f"# What is the source code?\n"
    elif model == "MLM":
        prompt = format_message(
            "Rewrite the following decompiled code for better clarity.", "system")
        prompt = prompt + format_message(decompile_code, "user")
        prompt = prompt + "<s>assistant\nassistant\n"
    return prompt


async def generate(client, addr, code, opt):
    try:
        response = await client.completions.create(
            prompt=prompt_format_decompile(code, opt, model=args.model),
            model=args.model,
            max_tokens=4096,
            temperature=0.7,
            stop=["<|im_end|>", "</s>"]
        )
    except Exception as e:
        print(f"Error: {e}")
        return addr, None
    return addr, response.choices[0].text


def decompile_function(idaapi, ida_hexrays, ea):
    func = idaapi.get_func(ea)
    if not func:
        return None

    cfunc = ida_hexrays.decompile(func)
    if not cfunc:
        return None

    return str(cfunc)


async def decompile_functions(decompiled_code):
    tasks = []
    decompile_result = []
    for addr, decompiled, opt in decompiled_code:

        tasks.append(asyncio.create_task(
            generate(client, addr, decompiled, opt)))

    for task in tqdm(tasks):
        addr, decompiled = await task
        if decompiled is not None:
            decompile_result.append((addr, decompiled))
        else:
            decompile_result.append((addr, "ERROR"))
    return decompile_result


async def main():

    ds = load_from_disk(args.dataset)
    outpath = args.output
    if args.model == 'LLM4Binary/llm4decompile-22b-v2':
        src_dec = 'ghidra'
    else:
        src_dec = 'hexrays'

    output_file = f"{outpath}/{args.model}.jsonl"
    decompiled_list = []
    non_idx = []
    inner_idx = 0
    begin_index = 0
    margin = 10
    for start in range(begin_index, len(ds), margin):
        inner_idx += margin
        decompiled_list = []
        non_idx = []
        for i in range(start, start + margin):
            if i >= len(ds):
                break
            if ds[i] == "":
                non_idx.append(i)
                continue
            decompiled_list.append((i, ds[i][src_dec], ds[i]['opt']))

        # Decompile the specified functions
        decompiled_functions = await decompile_functions(decompiled_list)
        for none_i in non_idx:
            decompiled_functions.append((none_i, "", ""))
        decompiled_functions = sorted(decompiled_functions, key=lambda x: x[0])

        decompiled_json = [{"idx": idx, "code": code}
                           for (idx, code) in decompiled_functions]

        with open(output_file, 'a') as f:
            for item in decompiled_json:
                f.write(json.dumps(item) + '\n')

if __name__ == '__main__':
    outpath = args.output
    Path(outpath).mkdir(parents=True, exist_ok=True)
    asyncio.run(main())
