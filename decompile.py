# %%
import argparse
import asyncio
import json
import os
from pathlib import Path

import datasets
from datasets import load_from_disk
from declient import DecompilerClient

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
parser.add_argument(
    "--decompile-client-host", type=str,
    default="http://localhost:8000",
)
args = parser.parse_args()


RESULT = f"{args.output}/result.jsonl"
if not os.path.exists(args.output):
    os.makedirs(args.output, exist_ok=True)
only_dump_result = args.only_dump_result

print(f'only_dump_result: {only_dump_result}')

ds = load_from_disk(args.dataset)
end_idx = min(args.ck_id*args.ck_size + args.ck_size, len(ds))
assert isinstance(ds, datasets.Dataset)
ds = ds.select(range(args.ck_id*args.ck_size, end_idx))
assert isinstance(ds, datasets.Dataset)
do_resume = os.path.exists(RESULT)

client = DecompilerClient(
    max_concurrent_requests=50,
    persistent_file_path=RESULT,
    target_url=args.decompile_client_host,
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
                row['path'],
                [hex(row['addr'])],
                decompiler,
                save_task_queue=False,
                idx=idx, decompiler=decompiler,
            )) for idx, row in enumerate(ds)
        ])
        await client.save_task_queue()


def save_result():
    ds1 = load_from_disk(args.dataset)
    assert isinstance(ds1, datasets.Dataset)
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
