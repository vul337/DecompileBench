from pydantic import BaseModel
from typing import List
from pydantic import BaseModel
from typing import Dict, Union


class DecompileResponse(BaseModel):
    uuid: str


class DecompileResult(BaseModel):
    results: Dict[str, Union[str, None]]


class DecompileRequest(BaseModel):
    binary: str
    address: List[str]
    decompiler: str

class DecompilerResponse(BaseModel):
    decompilers: List[str]
    
