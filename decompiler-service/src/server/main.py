from fastapi import FastAPI, BackgroundTasks
from server.models import (
    DecompileRequest,
    DecompileResponse,
    DecompileResult,
    DecompilerResponse,
)
from server.worker import run_decompiler_worker
import os
from .utils import generate_uuid
import redis

decompilers = os.getenv("DECOMPILERS", "hexrays,binja,dewolf,mlm,ghidra").split(",")
app = FastAPI()
redis_client = redis.StrictRedis(host="redis", port=6379, db=2)
tasks = {}


@app.get("/get_decompilers", response_model=DecompilerResponse)
def get_decompilers():
    return {"decompilers": decompilers}


@app.post("/decompile", response_model=DecompileResponse)
def create_decompile_task(request: DecompileRequest, background_tasks: BackgroundTasks):
    task_uuid = generate_uuid()
    redis_client.set(task_uuid, "processing: Task created")

    request_decompiler = request.decompiler
    if request_decompiler not in decompilers:
        redis_client.set(task_uuid, "completed: Unknown decompiler")
    else:
        queue_name = request_decompiler + "_queue"
        background_tasks.add_task(run_decompiler, task_uuid, request, queue_name)
    return DecompileResponse(uuid=task_uuid)


def run_decompiler(task_uuid: str, request: DecompileRequest, queue_name):
    try:
        result = run_decompiler_worker.apply_async(
            args=[request.binary, request.address, request.decompiler, task_uuid],
            queue=queue_name,
            retry=True,
            retry_policy={
                "max_retries": 3,
                "interval_start": 0,
                "interval_step": 0.2,
                "interval_max": 0.2,
                "retry_errors": None,
            },
        )
        redis_client.set(task_uuid, f"processing: {result.id}")
    except Exception as e:
        redis_client.set(task_uuid, f"error: {str(e)}")


@app.get("/status/{task_uuid}", response_model=DecompileResult)
async def get_decompile_status(task_uuid: str):
    try:
        status = redis_client.get(task_uuid)
        if not status:
            return DecompileResult(
                results={"status": "completed", "result": "Task not found"}
            )

        status = status.decode("utf-8")
        if status.startswith("completed:") or status.startswith("error:"):
            return DecompileResult(
                results={"status": status.split(":")[0], "result": status[10:].strip()}
            )

        if status.startswith("processing:"):
            return DecompileResult(results={"status": "processing", "result": None})
        
        if status.startswith("failed:"):
            return DecompileResult(results={"status": "error", "result": status[7:]})

    except Exception as e:
        return DecompileResult(results={"status": "error", "result": str(e)})
