import asyncio
from pathlib import Path
from declient import DecompilerClient
PRESSURE = 1000


async def main():

    client = DecompilerClient(
        max_concurrent_requests=50,
        persistent_file_path="my_task_queue.json",
        target_url="http://localhost:8000",
    )

    DECOMPILERS = await client.get_decompilers_async()

    assert DECOMPILERS, "No decompilers available"

    binary_path = Path(__file__).parent / "testcases" / "test.bin.strip"
    address_list = ["0x1a00", "0x1b00"]  # Example address list

    DECOMPILERS = DECOMPILERS * PRESSURE
    tasks = [
        client.decompile_async(binary_path, address_list, decompiler_name)
        for decompiler_name in DECOMPILERS
    ]

    await asyncio.gather(*tasks)

    # process the task queue
    await client.process_task_queue()

    # handling completed tasks
    completed_tasks = client.get_completed_tasks()
    for task in completed_tasks:
        print(f"Task {task['uuid']} completed with result: {task['result']}")


if __name__ == "__main__":
    asyncio.run(main())
