import requests
import time
from pathlib import Path
import json
import base64


def encode_binary_file(file_path):
    with open(file_path, "rb") as f:
        binary_content = f.read()
    return base64.b64encode(binary_content).decode("utf-8")


def create_decompile_task(payload, base_url):
    response = requests.post(f"{base_url}/decompile", json=payload)
    if response.status_code == 200:
        return response.json()["uuid"]
    else:
        print(f"Failed to create decompile task: {response.text}")
        return None


def get_decompile_status(task_uuid, base_url):
    response = requests.get(f"{base_url}/status/{task_uuid}")
    if response.status_code == 200:
        return response.json()["results"]
    else:
        print(f"Failed to get decompile status: {response.text}")
        return None


def decompile(
    binary_path, address_list, decompiler_name, base_url="http://localhost:8000"
):
    payload = {
        "binary": encode_binary_file(binary_path),
        "address": address_list,
        "decompiler": decompiler_name,
    }

    # Create a decompile task
    task_uuid = create_decompile_task(payload, base_url)
    if not task_uuid:
        return None

    # Poll the server for the status of the decompile task
    while True:
        status = get_decompile_status(task_uuid, base_url)
        if not status:
            return None

        if status["status"] == "completed":
            return json.loads(status["result"])
        elif status["status"] == "error":
            return None

        # Wait for a few seconds before polling again
        time.sleep(2)


def get_decompilers(base_url="http://localhost:8000"):
    response = requests.get(f"{base_url}/get_decompilers")
    if response.status_code == 200:
        return response.json()["decompilers"]
    else:
        print(f"Failed to get decompilers: {response.text}")
        return None


# Example usage
if __name__ == "__main__":
    binary_path = Path(__file__).parent / "testcases" / "test.bin.strip"
    address_list = ["0x1a00", "0x1b00"]  # Example address list
    decompiler_name = "hexrays"  # Example decompiler name
    base_url = "http://localhost:8000"  # Example base URL

    result = decompile(binary_path, address_list, decompiler_name, base_url)
    print(json.loads(result))
