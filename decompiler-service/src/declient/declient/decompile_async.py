import aiohttp
import asyncio
import json
import base64
import os
from tqdm import tqdm


class DecompilerClient:
    def __init__(self, max_concurrent_requests=100, persistent_file_path="task_queue.json", target_url="http://localhost:8000"):
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        self.persistent_file_path = persistent_file_path
        self.lock = asyncio.Lock()  # lock for task_queue
        self.task_queue = self.load_task_queue()
        self.target_url = target_url

    def encode_binary_file(self, file_path):
        with open(file_path, "rb") as f:
            binary_content = f.read()
        return base64.b64encode(binary_content).decode("utf-8")

    async def save_task_queue(self):
        with open(self.persistent_file_path, "w") as f:
            json.dump(self.task_queue, f)

    def load_task_queue(self):
        if os.path.exists(self.persistent_file_path):
            with open(self.persistent_file_path, "r") as f:
                return json.load(f)
        return []

    async def create_decompile_task(self, payload, base_url):
        async with self.semaphore:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post(f"{base_url}/decompile", json=payload) as response:
                        if response.status == 200:
                            return (await response.json())["uuid"]
                        else:
                            print(
                                f"Failed to create decompile task: {response.status}")
                            return None
                except aiohttp.ClientError as e:
                    print(f"HTTP error occurred: {e}")
                    return None

    async def get_decompile_resp(self, task_uuid, base_url):
        async with self.semaphore:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(f"{base_url}/status/{task_uuid}") as response:
                        if response.status == 200:
                            return (await response.json())["results"]
                        else:
                            print(
                                f"Failed to get decompile status: {response.status}")
                            return None
                except aiohttp.ClientError as e:
                    print(f"HTTP error occurred: {e}")
                    return None

    async def decompile_async(self, binary_path, address_list, decompiler_name, save_task_queue=True, **metadata):
        payload = {
            "binary": self.encode_binary_file(binary_path),
            "address": address_list,
            "decompiler": decompiler_name,
        }

        task_uuid = await self.create_decompile_task(payload, self.target_url)
        if task_uuid:
            async with self.lock:
                status = {
                    "uuid": task_uuid, "status": "processing",
                    "metadata": metadata, "decompiler": decompiler_name
                }
                self.task_queue.append(status)
                if save_task_queue:
                    await self.save_task_queue()
        return task_uuid

    async def process_task_queue(self):
        while True:
            async with self.lock:
                pending_tasks = [
                    task for task in self.task_queue if task["status"] == "processing"]
            if not pending_tasks:
                break

            try:
                for task in tqdm(pending_tasks, desc="Requesting Pending Tasks"):
                    task_uuid = task["uuid"]
                    resp = await self.get_decompile_resp(task_uuid, self.target_url)
                    if resp:
                        if resp["status"] == "completed":
                            async with self.lock:
                                task["status"] = "completed"
                                try:
                                    task["result"] = json.loads(resp["result"])
                                except json.JSONDecodeError:
                                    task["status"] = "error"
                                    task["result"] = resp["result"]
                        elif resp["status"] == "error":
                            async with self.lock:
                                task["status"] = "error"
                                task["error"] = resp.get(
                                    "result", "Unknown error")
            except KeyboardInterrupt:
                print("Interrupted by user")
            finally:
                await self.save_task_queue()
            await asyncio.sleep(5)

    def get_completed_tasks(self):
        return [task for task in self.task_queue if task["status"] == "completed"]

    async def get_decompilers_async(self):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"{self.target_url}/get_decompilers") as response:
                    if response.status == 200:
                        return (await response.json())["decompilers"]
                    else:
                        print(f"Failed to get decompilers: {response.status}")
                        return None
            except aiohttp.ClientError as e:
                print(f"HTTP error occurred: {e}")
                return None
