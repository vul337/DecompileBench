# Decompilebench Client (declient)

## Asynchronous Request 
```python
from pathlib import Path
import asyncio
from declient import DecompilerClient

binary_path = Path(__file__).parent / "testcases" / "test.bin.strip"
address_list = ["0x1a00", "0x1b00"]  # Example address list
base_url = "http://localhost:8000"  # Example base URL
output = "my_task_queue.json"
async def main():
    client = DecompilerClient(
        max_concurrent_requests=50,
        persistent_file_path=output,
        target_url=base_url,
    )
    
    DECOMPILERS = await client.get_decompilers_async()
    
    tasks = [
        asyncio.create_task(client.decompile_async(binary_path, address_list, decompiler_name))
        for decompiler_name in DECOMPILERS
    ]
    for task in tasks:
        print(await task)
        
    # query and wait for tasks to be completed
    await client.process_task_queue()
    
    # get results
    tasks = client.get_completed_tasks()
    for task in tasks:
        print(f"Task {task['uuid']} completed with result: {task['result']}")

asyncio.run(main())
```

## Asynchronous Resume
```python
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
```

## Synchronous Request
```python
from pathlib import Path
from declient import get_decompilers, decompile

binary_path = Path(__file__).parent / "testcases" / "test.bin.strip"
address_list = ["0x1a00", "0x1b00"]  
base_url = "http://localhost:8000"  
decompilers = get_decompilers(base_url)
for decompiler in decompilers:
    print(decompiler, decompile(binary_path, address_list, decompiler, base_url))

```