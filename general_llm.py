# %%

import argparse
import concurrent.futures
import json
import os
import pathlib
import random
import re
import time
from json import JSONDecodeError
from typing import Any, Callable

import json5
import json5.parser
import pandas as pd
from langchain.prompts import HumanMessagePromptTemplate
from langchain_core.exceptions import OutputParserException
from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import JsonOutputParser
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
    return parser.parse_args()


args = parse_arguments()
evaluation_prompt = pathlib.Path("./prompt.md").read_text()


def json5_loads(x, *args, **kwargs):
    try:
        return json5.loads(x)
    except ValueError as e:
        raise JSONDecodeError("Expecting value", x, 0) from e


json.loads = json5_loads


def enforce_prefix_parse_json_markdown(
    json_string: str, *args, parser: Callable[[str], Any] = parse_partial_json, require_prefix=True,
) -> dict:
    def parse_json5_before(s: str, *, strict: bool = False):
        try:
            return json5.loads(s)
        except Exception:
            return parser(s)

    try:
        return _parse_json(json_string, parser=parser)
    except json.JSONDecodeError:
        if require_prefix:
            pattern = r"```json(.*)```"
        else:
            pattern = r"```(.*)```"
        match = re.search(pattern, json_string, re.DOTALL)

        if match is None:
            json_str = json_string
        else:
            json_str = match.group(1)

    try:
        return _parse_json(json_str, parser=parser)
    except json.JSONDecodeError as e:
        if require_prefix is True:
            return enforce_prefix_parse_json_markdown(json_string, *args, parser, require_prefix=False)
        else:
            raise e


class EnforcePrefixJsonOutputParser(JsonOutputParser):
    def parse_result(self, result: List[Generation], *, partial: bool = False) -> Any:
        text = result[0].text
        text = text.strip()
        if partial:
            try:
                return enforce_prefix_parse_json_markdown(text)
            except JSONDecodeError:
                return None
        else:
            try:
                return enforce_prefix_parse_json_markdown(text)
            except JSONDecodeError as e:
                msg = f"Invalid json output: {text}"
                raise OutputParserException(msg, llm_output=text) from e


llm = ChatOpenAI(model=args.model, max_tokens=8192, timeout=60 *
                 60, base_url=os.getenv("BASE_URL"), api_key=os.getenv("API_KEY"))
json_output_parser = EnforcePrefixJsonOutputParser()

# %%


def parse_generation(text, partial: bool = False):
    text = text.strip()
    if partial:
        try:
            return enforce_prefix_parse_json_markdown(text)
        except JSONDecodeError:
            return None
    else:
        try:
            return enforce_prefix_parse_json_markdown(text)
        except JSONDecodeError as e:
            msg = f"Invalid json output: {text}"
            raise OutputParserException(msg, llm_output=text) from e
# %%


prompt = ChatPromptTemplate.from_messages([
    SystemMessage(content=evaluation_prompt),
    HumanMessagePromptTemplate.from_template(template='''\

Decompiled code:
{decompiled_code}

''')
])

chain = (prompt | llm | {
    "raw_output": RunnableLambda(lambda x: x.content),
    # "parsed_output": json_output_parser,
})


def invoke(dec, metadata):
    # print(f"Invoking with {metadata}")
    # for i in range(3):
    for i in range(1):
        # print(f"invoking:{3}")
        try:
            ret = chain.invoke({
                'decompiled_code': dec,

            })

            break
        except Exception as e:
            print(i, e)
            ret = {'raw_output': "None"}
    return {
        'ret': ret,
        'metadata': metadata,
    }


def extract_code_block(output: str) -> str:
    start_marker = "```refined\n"
    end_marker = "\n```"

    start_index = output.find(start_marker)
    end_index = output.rfind(end_marker)

    if start_index != -1 and end_index != -1 and end_index > start_index:
        code_block = output[start_index + len(start_marker):end_index].strip()
        return code_block
    return "not found "+output


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

            available_workers = max(
                0, max_workers * 2 - len(not_done))
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
                f"Remaining Tasks: {len(not_done)}, Finished: {finished}")  # average 1min+ per item

            if len(not_done) == 0 and finished:
                break

            if available_workers == 0 and len(done) == 0:
                time.sleep(1)
    return ret_list


def get_tasks(df: pd.DataFrame):
    # for idx, row in df.iterrows():
    for idx, row in enumerate(df):
        # for dec_a in decompilers:
        # print(row)
        dec = row['hexrays']

        yield {
            "dec": dec,

            "metadata": {
                # "idx": row['idx'],
                "idx": row["real_idx"],
            }
        }


def run(df: pd.DataFrame, max_workers):
    result = []
    print("="*15)
    for ret in execute_from_generator(
        get_tasks(df),  # dict_keys(['src', 'dec_a', 'dec_b', 'metadata'])
        invoke,
        max_workers=max_workers,
        parallel=True,
    ):
        try:
            ret['ret']['raw_output'] = extract_code_block(
                ret['ret']['raw_output'])
        except:
            prunt("cannot extract")
        ret = {"idx": ret['metadata']['idx'], "code": ret['ret']['raw_output']}
        print("="*15)
        result.append(ret)
    print(f"result: {len(result)}")
    return result


def main(df, outpath):
    ret = run(df, len(df) // 2)
    with open(outpath, 'a') as f:
        for item in ret:
            f.write(json.dumps(item) + '\n')


if __name__ == "__main__":
    from datasets import load_from_disk
    df = load_from_disk(args.dataset)
    outpath = f'{args.output}/{args.model}.jsonl'

    try:
        df = df.add_column("real_idx", range(0, len(df)))
    except:
        pass
    if True:
        if args.model == 'claude-3-5-sonnet-v2@20241022':
            seed_value = 42
            random.seed(seed_value)
            df = df.select(random.sample(range(len(df)), int(len(df) * 0.2)))

        begin_index = 0
        chunks = [df.select(range(i, min(i + chunk_size, len(df))))
                  for i in range(begin_index, len(df), chunk_size)]
        for idx, chunk in enumerate(chunks):
            main(chunk, outpath=outpath)
