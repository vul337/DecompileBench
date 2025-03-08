import argparse
import asyncio
import concurrent.futures
import json
import os
import pathlib
import random
import re
import time
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import json5
import json5.parser
import openai
import pandas as pd
from datasets import load_from_disk
from langchain.prompts import HumanMessagePromptTemplate
from langchain_core.exceptions import OutputParserException
from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.outputs import Generation
from langchain_core.prompts.chat import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnableLambda
from langchain_core.utils.json import _parse_json, parse_partial_json
from langchain_openai import ChatOpenAI
from tqdm import tqdm


def parse_arguments():
    parser = argparse.ArgumentParser(description="Decompile with LLM")
    parser.add_argument("--dataset", type=str, required=True,
                        help="Path to the dataset")
    parser.add_argument("--output", type=str, required=True,
                        help="Path to the output directory")
    parser.add_argument("--model", type=str, required=True, help="Model name")
    parser.add_argument("--mode", type=str, choices=["general", "specialized"],
                        default="general", help="Mode to run in: general or specialized")
    parser.add_argument("--chunk_size", type=int, default=10,
                        help="Chunk size for processing")
    return parser.parse_args()


args = parse_arguments()

# Ensure output directory exists
Path(args.output).mkdir(parents=True, exist_ok=True)
outpath = f'{args.output}/{args.model}.jsonl'

# Create client for specialized mode
if args.mode == "specialized":
    client = openai.AsyncClient()


def extract_code_block(output: str) -> str:
    start_marker = "```refined\n"
    end_marker = "\n```"

    start_index = output.find(start_marker)
    end_index = output.rfind(end_marker)

    if start_index != -1 and end_index != -1 and end_index > start_index:
        code_block = output[start_index + len(start_marker):end_index].strip()
        return code_block
    return "not found " + output


def invoke_general(dec, metadata):
    try:
        ret = chain.invoke({'decompiled_code': dec})
        return {
            'ret': ret,
            'metadata': metadata,
        }
    except Exception as e:
        print(f"Error in invoke: {e}")
        return {
            'ret': {'raw_output': "None"},
            'metadata': metadata,
        }


def execute_from_generator(
    generator,
    fn,
    max_workers=8,
    parallel=False,
):
    futures = {}
    finished = False
    pbar = tqdm()
    ret_list = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        while True:
            if futures:
                done, not_done = concurrent.futures.wait(
                    futures, return_when=concurrent.futures.FIRST_COMPLETED)
            else:
                done, not_done = set(), set()
                not_done.add(None)

            available_workers = max(0, max_workers * 2 - len(not_done))
            print(f"available_workers: {available_workers}")
            for _ in range(available_workers):
                try:
                    task = next(generator)
                    if parallel:
                        future = executor.submit(fn, **task)
                        futures[future] = task
                    else:
                        ret = fn(**task)
                        ret_list.append(ret)
                except StopIteration:
                    finished = True
                    break

            for future in done:
                print(f"future: {future}")
                task = futures[future]
                task_exception = future.exception()
                pbar.update()

                if task_exception is not None:
                    print(f'Task failed: {task_exception}')
                else:
                    result = future.result()
                    yield result
                del futures[future]

            pbar.set_description(
                f"Remaining Tasks: {len(not_done)}, Finished: {finished}")

            if len(not_done) == 0 and finished:
                break

            if available_workers == 0 and len(done) == 0:
                time.sleep(1)
    return ret_list


def get_tasks(df):
    for idx, row in enumerate(df):
        dec = row['hexrays']
        yield {
            "dec": dec,
            "metadata": {
                "idx": row["real_idx"],
            }
        }


def run_general(df, max_workers):
    result = []
    print("="*15)
    for ret in execute_from_generator(
        get_tasks(df),
        invoke_general,
        max_workers=max_workers,
        parallel=True,
    ):
        try:
            ret['ret']['raw_output'] = extract_code_block(
                ret['ret']['raw_output'])
        except Exception as e:
            print(f"Cannot extract: {e}")
        ret = {"idx": ret['metadata']['idx'], "code": ret['ret']['raw_output']}
        print("="*15)
        result.append(ret)
    print(f"result: {len(result)}")
    return result


# =================== SPECIALIZED MODE FUNCTIONS ===================

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


async def run_specialized(ds, chunk_size):
    if args.model == 'LLM4Binary/llm4decompile-22b-v2':
        src_dec = 'ghidra'
    else:
        src_dec = 'hexrays'

    for start in range(0, len(ds), chunk_size):
        decompiled_list = []
        non_idx = []

        # Prepare batch
        for i in range(start, min(start + chunk_size, len(ds))):
            if ds[i] == "":
                non_idx.append(i)
                continue
            decompiled_list.append((i, ds[i][src_dec], ds[i]['opt']))

        # Process batch
        decompiled_functions = await decompile_functions(decompiled_list)

        # Handle any skipped items
        for none_i in non_idx:
            decompiled_functions.append((none_i, "", ""))

        # Sort by original index
        decompiled_functions = sorted(decompiled_functions, key=lambda x: x[0])

        # Format results
        decompiled_json = [{"idx": idx, "code": code}
                           for (idx, code) in decompiled_functions]

        # Write results
        with open(outpath, 'a') as f:
            for item in decompiled_json:
                f.write(json.dumps(item) + '\n')


# =================== MAIN FUNCTIONS ===================

def main_general(df, outpath):
    ret = run_general(df, len(df) // 2)
    with open(outpath, 'a') as f:
        for item in ret:
            f.write(json.dumps(item) + '\n')


async def main():
    # Load dataset
    df = load_from_disk(args.dataset)

    try:
        df = df.add_column("real_idx", range(0, len(df)))
    except:
        pass

    # Apply sampling if using Claude model
    if args.model == 'claude-3-5-sonnet-v2@20241022':
        seed_value = 42
        random.seed(seed_value)
        df = df.select(random.sample(range(len(df)), int(len(df) * 0.2)))

    # Process based on mode
    if args.mode == "general":
        # Set up LangChain components for general mode
        global evaluation_prompt, chain, json_output_parser

        evaluation_prompt = pathlib.Path("./prompt.md").read_text()

        llm = ChatOpenAI(model=args.model, max_tokens=8192, timeout=60*60,
                         base_url=os.getenv("BASE_URL"), api_key=os.getenv("API_KEY"))

        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=evaluation_prompt),
            HumanMessagePromptTemplate.from_template(template='''\

Decompiled code:
{decompiled_code}

''')
        ])

        chain = (prompt | llm | {
            "raw_output": RunnableLambda(lambda x: x.content),
        })

        # Process in chunks
        chunks = [df.select(range(i, min(i + args.chunk_size, len(df))))
                  for i in range(0, len(df), args.chunk_size)]
        for idx, chunk in enumerate(chunks):
            main_general(chunk, outpath=outpath)

    elif args.mode == "specialized":
        await run_specialized(df, args.chunk_size)


if __name__ == "__main__":
    asyncio.run(main())
