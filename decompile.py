# %%
import argparse
import asyncio
import json
import os
from pathlib import Path
from loguru import logger

import datasets
from datasets import load_from_disk
from declient import DecompilerClient


parser = argparse.ArgumentParser()
parser.add_argument(
    '--base-dataset-path', type=str,
)
parser.add_argument(
    "--output", type=str,
)
parser.add_argument(
    "--only-dump-result", action="store_true",
    help="Only dump the result without submitting new tasks",
)
parser.add_argument(
    "--ck_id", type=int,
    default=None,
)
parser.add_argument(
    "--ck_size", type=int,
    default=None,
)
parser.add_argument(
    "--decompile-client-host", type=str,
    default="http://localhost:12337",
)
parser.add_argument(
    "--decompilers",
    type=lambda x: x.split(','),
    help="Comma separated list of decompilers",
    default="",
)
args = parser.parse_args()


RESULT = f"{args.output}/result.jsonl"
if not os.path.exists(args.output):
    os.makedirs(args.output, exist_ok=True)
only_dump_result = args.only_dump_result

dataset_path = Path(args.base_dataset_path)

ds = load_from_disk((dataset_path / 'compiled_ds').as_posix())
assert isinstance(ds, datasets.Dataset)

if args.ck_id is not None and args.ck_size is not None:
    assert args.ck_id >= 0
    assert args.ck_size > 0
    assert args.ck_id * args.ck_size < len(ds)

    end_idx = min(args.ck_id * args.ck_size + args.ck_size, len(ds))
    ds = ds.select(range(args.ck_id * args.ck_size, end_idx))
    assert isinstance(ds, datasets.Dataset)

do_resume = os.path.exists(RESULT)

client = DecompilerClient(
    max_concurrent_requests=50,
    persistent_file_path=RESULT,
    target_url=args.decompile_client_host,
)

DECOMPILERS = args.decompilers
logger.info(f'Decompilers: {DECOMPILERS}')

assert DECOMPILERS, "No decompilers specified"

logger.info(f'Number of tasks: {len(ds)}')


async def submit_tasks():
    for decompiler in DECOMPILERS:
        logger.info(f'Submitting tasks for decompiler: {decompiler}')
        await asyncio.gather(*[
            asyncio.create_task(client.decompile_async(
                (dataset_path / row['path']).as_posix(),
                [hex(row['addr'])],
                decompiler,
                save_task_queue=False,
                idx=idx, decompiler=decompiler,
            )) for idx, row in enumerate(ds)
        ])
        await client.save_task_queue()


def save_result():
    # assert isinstance(ds, datasets.Dataset)
    with open(RESULT, 'r') as f:
        data = json.load(f)
    result_map = {
        decompiler: [None] * len(ds)
        for decompiler in DECOMPILERS
    }
    for item in data:
        if 'result' in item and item.get('status') == 'completed':
            idx = item['metadata']['idx']
            decompiler = item['metadata']['decompiler']
            if item['result'] != '':
                result_map[decompiler][idx] = list(item['result'].values())[0]

    result_ds = datasets.Dataset.from_dict(result_map)
    result_ds.save_to_disk(args.output)


async def main():
    if not only_dump_result:
        if not do_resume:
            await submit_tasks()

        logger.info('Waiting for tasks to be completed')
        await client.process_task_queue()

    save_result()

asyncio.run(main())
