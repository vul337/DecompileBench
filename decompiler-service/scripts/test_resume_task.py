import asyncio
from declient import DecompilerClient

base_url = "http://localhost:8000"  # Example base URL
output = "my_task_queue.json"


async def main():
    client = DecompilerClient(
        max_concurrent_requests=50,
        persistent_file_path=output,
        target_url=base_url,
    )

    # resume quering tasks
    await client.process_task_queue()

    # get results
    tasks = client.get_completed_tasks()
    for task in tasks:
        print(f"Task {task['uuid']} completed with result: {task['result']}")

asyncio.run(main())
