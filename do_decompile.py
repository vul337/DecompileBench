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
'''
python3 do_decompile.py --dataset  /code/decompilebench-evaluation/decompileeval/output_dataset/assembly --output ./output_dataset/decompile_result_1 --ck_id 0 --ck_size 10000
python3 do_decompile.py --dataset  /code/decompilebench-evaluation/decompileeval/output_dataset/assembly --output ./output_dataset/decompile_result_2 --ck_id 1 --ck_size 10000
python3 do_decompile.py --dataset  /code/decompilebench-evaluation/decompileeval/output_dataset/assembly --output ./output_dataset/decompile_result_3 --ck_id 2 --ck_size 10000

python3 do_decompile.py --dataset  /code/decompilebench-evaluation/decompileeval/output_dataset/assembly --output ./output_dataset/decompile_result_patch --ck_id 0 --ck_size 30000 --only-dump-result

'''
HOST = "http://mira.vul337.team:12337"
# HOST="https://cloud.vul337.team:9447/v1"
# curl http://mira.vul337.team:12337/get_decompilers
key="sk-N0GNT3EdIzN1KxCGCdB22dB6C5974d8597C36336430c3aC8"


BASE_DIR = Path(__file__).parent



# HTTP error occurred: Cannot connect to host mira.vul337.team:12337 ssl:default [Connect call failed ('198.18.0.209', 12337)]
parser = argparse.ArgumentParser()
parser.add_argument(
    '--dataset', type=str,
    default=str(BASE_DIR / "dataset" / "llm4decompile_eval"))
parser.add_argument(
    "--output", type=str,
    default=str(BASE_DIR / "dataset" / "llm4decompile_eval" / "llm4decompile_result"),
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

# DECOMPILERS = await client.get_decompilers_async()
DECOMPILERS = [
    "angr", 
    "binja", "dewolf", "ghidra",
    "hexrays", 
    "retdec"
]


def save_result():
    global ds
    tasks = client.get_completed_tasks()
    
    result_map = {}
    
    for task in tqdm(tasks):
        try:
            metadata = task['metadata']
            result = list(task['result'].values())[0]

            idx = metadata['idx']
            decompiler = metadata['decompiler']
            # if decompiler == 'hexrays':
            #     import ipdb; ipdb.set_trace()
            result_map.setdefault(
                decompiler, ["" for _ in range(len(ds))]
            )[idx] = result
            
        except Exception as e:
            print(e)
            pass
    for key,value in result_map.items():
        ds = ds.add_column(key, value)
    ds.save_to_disk(args.output)

from datasets import load_from_disk, concatenate_datasets

# Load the two datasets
def combine_result():
    dataset_3 = load_from_disk('/code/decompilebench-evaluation/decompileeval/output_dataset/decompile_result_3')
    dataset_2 = load_from_disk('/code/decompilebench-evaluation/decompileeval/output_dataset/decompile_result_2')
    dataset_1 = load_from_disk('/code/decompilebench-evaluation/decompileeval/output_dataset/decompile_result_1')
    # Concatenate the datasets
    combined_dataset = concatenate_datasets([dataset_1, dataset_2, dataset_3])

    # Save the combined dataset to disk
    combined_dataset.save_to_disk('/code/decompilebench-evaluation/decompileeval/output_dataset/combined_decompile_result')

    print("Datasets concatenated and saved successfully.")



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

async def patch_empty():
    ds1 = load_from_disk('/code/decompilebench-evaluation/decompileeval/output_dataset/combined_decompile_result')
    for decompiler in DECOMPILERS:
        await asyncio.gather(*[
            asyncio.create_task(client.decompile_async(
                row['path'], [hex(row['addr'])], decompiler,
                save_task_queue=False,
                idx=idx, decompiler=decompiler,
            )) for idx, row in enumerate(ds1) if row[decompiler] == ''
        ])

async def main():
    if not only_dump_result:
        if not do_resume:
            await submit_tasks()

        print('Waiting for tasks to be completed')
        await client.process_task_queue()
    else:
        await patch_empty()
        await client.process_task_queue()
    # save_result()

def patch():
    ds1 = load_from_disk(args.dataset)
    with open(RESULT, 'r') as f:
        data = json.load(f)
    print(data[0].keys())
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
    print(ds1[406]['hexrays'])
# asyncio.run(main())
# asyncio.run(save_result())
# combine_result()
patch()
# python do_decompile.py --dataset  /code/decompilebench-evaluation/decompileeval/output_dataset/combined_decompile_result --output ./output_dataset/decompile_result_patch --ck_id 0 --ck_size 30000 --only-dump-result