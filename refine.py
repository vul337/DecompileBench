import argparse
import asyncio
import json
import re
from pathlib import Path

import datasets
import openai
from datasets import load_from_disk
from tqdm import tqdm


def parse_arguments():
    parser = argparse.ArgumentParser(description="Decompile with LLM")
    parser.add_argument("--dataset", type=str, required=True,
                        help="Path to the dataset")
    parser.add_argument("--output-file", type=str, required=True,
                        help="Path to the output file")
    parser.add_argument("--model", type=str, required=True, help="Model name")
    parser.add_argument("--concurrency", type=int, default=5,
                        help="Number of concurrent API calls")
    return parser.parse_args()


args = parse_arguments()
model = args.model

client = openai.AsyncClient()

# semaphore for rate limiting
sem = asyncio.Semaphore(args.concurrency)


def load_prompts():
    general_prompt = Path("./prompt.md").read_text()
    return {
        "llm4decompile": "# This is the assembly code:\n{code}\n# What is the source code?\n",
        "general": general_prompt
    }


prompt_templates = load_prompts()


def extract_code_block(output: str) -> str:
    # Using regex to extract code between ```refined and ``` markers
    pattern = r"```refined\n(.*?)\n```"
    match = re.search(pattern, output, re.DOTALL)
    if match:
        return match.group(1).strip()
    return output


async def format_prompt(code: str, model: str) -> dict:
    if "mlm" in model.lower():
        return {
            "message": [
                {"role": "user", "content": code}
            ],
            "is_chat": True,
            "max_tokens": 4096,
        }
    elif "llm4decompile" in model.lower():
        return {
            "prompt": prompt_templates["llm4decompile"].format(code=code.strip()),
            "is_chat": False,
            "max_tokens": 4096,
        }
    else:
        return {
            "messages": [
                {"role": "system", "content": prompt_templates["general"]},
                {"role": "user", "content": f"Decompiled code:\n{code}"}
            ],
            "is_chat": True,
            "max_tokens": 4096,
        }


def is_general_model(model_name: str) -> bool:
    if "mlm" in model_name.lower():
        return False
    elif "llm4decompile" in model_name.lower():
        return False
    else:
        return True


async def generate(client, addr, code):
    try:
        async with sem:  # Use semaphore to limit concurrent API calls
            is_general = is_general_model(args.model)
            prompt_data = await format_prompt(code, model)

            if prompt_data["is_chat"]:
                response = await client.chat.completions.create(
                    messages=prompt_data["messages"],
                    model=args.model,
                    max_tokens=prompt_data.get("max_tokens", 4096),
                    temperature=0.7,
                )
                result = response.choices[0].message.content
                if is_general:
                    result = extract_code_block(result)
            else:
                response = await client.completions.create(
                    prompt=prompt_data["prompt"],
                    model=args.model,
                    max_tokens=prompt_data.get("max_tokens", 4096),
                    temperature=0.7,
                )
                result = response.choices[0].text

            return addr, result.strip()
    except Exception as e:
        print(f"Error with addr {addr}: {e}")
        return addr, None


async def process_all(decompiled_list, output_file, processed_indexes):
    tasks = []

    # Create tasks for all unprocessed items
    for idx, decompiled in decompiled_list:
        if idx not in processed_indexes:
            tasks.append(asyncio.create_task(
                generate(client, idx, decompiled)))

    # Process results as they complete
    for future in tqdm(asyncio.as_completed(tasks), total=len(tasks)):
        idx, result = await future

        # Write result to file immediately
        with open(output_file, "a") as f:
            f.write(json.dumps({
                "idx": idx,
                "code": result or "ERROR"
            }) + "\n")


async def main():
    output_file = args.output_file
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)

    # Check for existing results and gather processed indexes
    processed_indexes = set()
    found_metadata = False
    if Path(output_file).exists():
        with open(output_file, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if "model" in data:
                        assert data["model"] == args.model, "Model mismatch"
                        found_metadata = True
                    else:
                        processed_indexes.add(data["idx"])
                except json.JSONDecodeError:
                    continue
        print(
            f"Found {len(processed_indexes)} already processed items, will skip them.")

    if not found_metadata:
        with open(output_file, "a") as f:
            f.write(json.dumps({"model": args.model}) + "\n")  # metadata

    dataset = load_from_disk(args.dataset)
    assert isinstance(dataset, datasets.Dataset)

    src_dec = 'ghidra' if "llm4decompile" in args.model.lower() else 'hexrays'
    # Prepare all items at once
    decompiled_list = [
        (i, item[src_dec])
        for i, item in enumerate(dataset)
        if item.get(src_dec)
    ]

    # Process all items with rate limiting
    await process_all(decompiled_list, output_file, processed_indexes)

if __name__ == '__main__':
    asyncio.run(main())
