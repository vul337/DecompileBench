import subprocess
import sys
import os
import base64
from celery import Celery
from .utils import generate_uuid, set_limits
from typing import List
import redis

redis_client = redis.StrictRedis(host="redis", port=6379, db=2)

DECOMPILER_WORKER = os.getenv("DECOMPILER_WORKER", "worker")
TIMEOUT = os.getenv("DECOMPILER_TIMEOUT", "600")

celery_app = Celery(
    DECOMPILER_WORKER, broker="redis://redis:6379/0", backend="redis://redis:6379/1"
)


@celery_app.task
def run_decompiler_worker(binary: str, address: List[str], decompiler: str, task_uuid: str) -> str:
    try:
        uuid = generate_uuid()
        binary_path = f"/tmp/{uuid}.bin"
        with open(binary_path, "wb") as f:
            f.write(base64.b64decode(binary))

        log_path = f"/tmp/{uuid}.output"
        if decompiler != "ghidra":
            subprocess.run(
                [
                    sys.executable,
                    f"/runners/{decompiler}_runner.py",
                    "--binary",
                    binary_path,
                    "--address",
                ]
                + address
                + [
                    "--file",
                    log_path,
                ],
                timeout=int(TIMEOUT),
                check=True,
            )
            with open(log_path, "r") as f:
                result = f.read()
            os.system(f"rm {binary_path} {log_path}")
        else:
            subprocess.run(
                [
                    "pyhidra",
                    f"/runners/{decompiler}_runner.py",
                    "--binary",
                    binary_path,
                    "--address",
                ]
                + address
                + [
                    "--file",
                    log_path,
                ],
                timeout=int(TIMEOUT),
                check=True,
            )
            with open(log_path, "r") as f:
                result = f.read()
            os.system(
                f"rm -rf {binary_path} {log_path} {binary_path+'_ghidra'}")
        redis_client.set(task_uuid, f"completed:{result}")
        return result
    except Exception as e:
        redis_client.set(task_uuid, f"failed:{str(e)}")
        return str(e)
