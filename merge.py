import argparse
import json
import os
from pathlib import Path

import datasets
from datasets import load_from_disk
from loguru import logger


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Merge decompiled datasets with base dataset")
    parser.add_argument("--base-dataset-path", type=str, required=True,
                        help="Path to the base dataset")
    parser.add_argument("--decompiled-datasets", type=str, nargs='+', required=True,
                        help="Paths to decompiled datasets (folders or jsonl files)")
    parser.add_argument("--output", type=str, required=True,
                        help="Path to save the merged dataset")
    return parser.parse_args()


def load_jsonl_dataset(file_path, base_ds_len: int):
    """Load a dataset from a jsonl file, sorting by idx."""
    data = [None for _ in range(base_ds_len)]
    model_name = None

    with open(file_path, 'r') as f:
        for line in f:
            try:
                item = json.loads(line)
                if "model" in item:
                    model_name = item["model"]
                else:
                    idx = item.get("idx")
                    if idx is None:
                        logger.warning(
                            f"No idx found in line in {file_path}, skipping")
                        continue
                    data[idx] = item['code']
            except json.JSONDecodeError:
                logger.warning(f"Could not parse line in {file_path}")

    if not model_name:
        model_name = Path(file_path).stem
        logger.warning(
            f"No model name found in {file_path}, using {model_name}")

    return {
        "model_name": model_name,
        "data": data
    }


def process_decompiled_dataset(path, base_ds_len: int):
    """Process a decompiled dataset path which can be a folder or jsonl file."""
    path = Path(path)

    if path.is_dir():
        logger.info(f"Loading dataset from directory: {path}")
        ds = load_from_disk(str(path))
        assert isinstance(ds, datasets.Dataset)
        assert len(ds) == base_ds_len
        return ds
    elif path.suffix == '.jsonl':
        logger.info(f"Loading dataset from jsonl file: {path}")
        result = load_jsonl_dataset(str(path), base_ds_len)
        # Create dataset with column name as the model name
        return datasets.Dataset.from_dict({
            result["model_name"]: result["data"]
        })
    else:
        raise ValueError(f"Unsupported dataset format: {path}")


def main():
    args = parse_arguments()

    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)

    # Load base dataset
    base_dataset_path = Path(args.base_dataset_path)
    logger.info(
        f"Loading base dataset from: {base_dataset_path / 'compiled_ds'}")
    base_ds = load_from_disk((base_dataset_path / 'compiled_ds').as_posix())
    assert isinstance(base_ds, datasets.Dataset)

    base_ds_len = len(base_ds)
    logger.info(f"Base dataset length: {base_ds_len}")

    # Process each decompiled dataset
    for decompiled_path in args.decompiled_datasets:
        decompiled_ds = process_decompiled_dataset(
            decompiled_path, base_ds_len)

        # Check if decompiled dataset has appropriate length
        for column in decompiled_ds.column_names:
            if column not in base_ds.column_names:
                if len(decompiled_ds[column]) != len(base_ds):
                    logger.warning(
                        f"Column {column} has length {len(decompiled_ds[column])}, "
                        f"but base dataset has length {len(base_ds)}. "
                        f"Will pad with None values."
                    )

                # Add the column to the base dataset
                base_ds = base_ds.add_column(
                    column,
                    decompiled_ds[column] + [None] *
                    (len(base_ds) - len(decompiled_ds[column]))
                    if len(decompiled_ds[column]) < len(base_ds)
                    else decompiled_ds[column][:len(base_ds)]
                )
                logger.info(f"Added column {column} to base dataset")

    # Save the merged dataset
    logger.info(f"Saving merged dataset to: {args.output}")
    base_ds.save_to_disk(args.output)
    logger.info(f"Merged dataset saved with columns: {base_ds.column_names}")


if __name__ == "__main__":
    main()
