# %%
from datasets import load_from_disk
from pathlib import Path
import asyncio
from declient import DecompilerClient
import os
from tqdm import tqdm
import numpy as np
from collections import defaultdict
import json
import argparse

HOST = "http://localhost:12337"
key="sk-123456"


BASE_DIR = Path(__file__).parent


parser = argparse.ArgumentParser()
parser.add_argument(
    '--dataset', type=str,
    default=str(BASE_DIR / "compiled_ds"))
parser.add_argument(
    "--output", type=str,
    default=str(BASE_DIR / "decompile_result"),
)
parser.add_argument(
    "--only-dump-result", action="store_true",
)
parser.add_argument(
    "--ck_id", type=int,
    default=0,
)
parser.add_argument(
    "--ck_size", type=int,
    default=10000,
)
args = parser.parse_args()


RESULT =f"tmp_results/result_patch.json.2"
if not os.path.exists(RESULT):
    os.makedirs("tmp_results", exist_ok=True)
only_dump_result = args.only_dump_result

print(f'only_dump_result: {only_dump_result}')

ds = load_from_disk(args.dataset)
end_idx = min(args.ck_id*args.ck_size + args.ck_size,len(ds))
ds = ds.select(range(args.ck_id*args.ck_size, end_idx))
do_resume = os.path.exists(RESULT)

client = DecompilerClient(
    max_concurrent_requests=50,
    persistent_file_path=RESULT,
    target_url=HOST,
)

DECOMPILERS = [
    "angr", 
    "binja", 
    "dewolf", 
    "ghidra",
    "hexrays", 
    "retdec"
]


async def submit_tasks():
    for decompiler in DECOMPILERS:
        await asyncio.gather(*[
            asyncio.create_task(client.decompile_async(
                row['path'], [hex(row['addr'])], decompiler,
                save_task_queue=False,
                idx=idx, decompiler=decompiler,
            )) for idx, row in enumerate(ds)
        ])
        await client.save_task_queue()

def save_result():
    ds1 = load_from_disk(args.dataset)
    with open(RESULT, 'r') as f:
        data = json.load(f)
    result_map = {
        decompiler: ds1[decompiler]
        for decompiler in DECOMPILERS
    }
    for item in data:
        if 'result' in item:
            idx = item['metadata']['idx']
            decompiler = item['metadata']['decompiler']
            if item['result'] != '' and ds1[idx][decompiler] == '':
                result_map[decompiler][idx] = list(item['result'].values())[0]
                if decompiler == 'hexrays':
                    print(idx)
    for decompiler in DECOMPILERS:
        if decompiler in ds1.column_names:
            ds1 = ds1.remove_columns(decompiler)
    for decompiler, result in result_map.items():
        ds1 = ds1.add_column(decompiler, result)
    ds1.save_to_disk(args.output)

async def main():
    if not only_dump_result:
        if not do_resume:
            await submit_tasks()

        print('Waiting for tasks to be completed')
        await client.process_task_queue()
    
    save_result()

asyncio.run(main())