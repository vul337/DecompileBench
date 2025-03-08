from pathlib import Path
from declient import get_decompilers, decompile

binary_path = Path(__file__).parent / "testcases" / "test.bin.strip"
address_list = ["0x1a00", "0x1b00"]
base_url = "http://localhost:8000"
decompilers = get_decompilers(base_url) or []

for decompiler in decompilers:
    print(decompiler, decompile(binary_path, address_list, decompiler, base_url))
