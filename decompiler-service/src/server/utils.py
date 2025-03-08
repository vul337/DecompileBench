import uuid
import resource


def generate_uuid() -> str:
    return str(uuid.uuid4())


def set_limits(soft_mem, hard_mem):
    resource.setrlimit(resource.RLIMIT_AS, (soft_mem, hard_mem))
