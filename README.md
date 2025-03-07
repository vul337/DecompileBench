# DecompileBench Evaluation

This repository provides scripts and tools for evaluating the performance of decompilation processes using both traditional decompilers and large language models (LLMs).

## Dependencies

LLVM 18, install from [LLVM Debian/Ubuntu nightly packages](https://apt.llvm.org)

## Preparation

To begin, clone the `oss-fuzz` project.

```shell
git clone https://github.com/google/oss-fuzz.git
```

Then we modify the `base-builder` Dockerfile to include `bear` and `clang-extract` to support the function extraction.

```shell
# Download prebuilt clang-extract
wget 'https://seafile.vul337.team:8443/f/1f11e8c4a8eb46dcb981/?dl=1' -O oss-fuzz/infra/base-images/base-builder/clang-extract.tar.gz

# Add bear and clang-extract to base-builder Dockerfile
cd oss-fuzz
git checkout 4bca88f3a369679336485181961db305161fe240
git apply ../oss-fuzz-patch/*.diff
```

Then we build the Docker image.

```shell
python infra/helper.py build_image base-builder --cache --pull
python infra/helper.py build_image base-runner --cache --no-pull
```

Then we compile the dummy library for linking with the fuzzer.

```shell
docker run -it --rm -w /work -v $(pwd):/work gcr.io/oss-fuzz-base/base-builder clang dummy.c -o libfunction.so -O2 -fPIC -shared
```

## Extract Functions

```shell
python extract_functions.py --config coverage.yaml
```

Optionally, extract only several selected projects with 96 workers

```shell
python3 extract_functions.py --config coverage.yaml --worker-count 96 --project file,libprotobuf-mutator
```


Initially, execute the fuzzers to collect covered functions, including their names and corresponding files. Coverage information is recorded in `{oss_fuzz_path}/build/stats/{project}/{fuzzer}_result.json`. 
For each function covered by the fuzzer, use `clang` and `clang-extract` to extract functions with external dependencies from each project, storing them in `f{oss_fuzz_path}/functions/{project}`.


## Compilation

To compile the extracted functions, ensure that LLVM and Clang are installed on your system. Specify the library file path, for example, `/usr/lib/llvm-16/lib/libclang-16.so.1`, adjusting it to match your installation path.

Set the `oss_fuzz_path` and the desired output path, then execute the following command:

```shell
python compile_ossfuzz.py --oss_fuzz_path your_oss_fuzz_path --output your_output_path
```

This script organizes all functions into a dataset, formatted as `datasets`. It compiles these functions using `clang`, applying optimization levels from `O0` to `Os`. The resulting binaries are stored in `OUTPUT / 'binary'`, and the final dataset is located in `OUTPUT / 'compiled_ds'`.

## Decompilation

This section outlines the scripts used for decompilation, utilizing both traditional decompilers and large language models (LLMs).

### Traditional Decompilers

To obtain decompiled code from traditional decompilers, run:

```shell
python decompile.py --dataset ./compiled_ds --output ./decompile_result
```

- `dataset`: Path to the dataset output from the previous compilation step.
- `output`: Path where the decompiled code dataset will be stored.

This script interfaces with a server hosting six traditional decompilers, such as Hex-Rays, to request decompiled code asynchronously.

### LLM Decompilers

To generate decompiled results using general models, execute:

```shell
python general_llm.py --dataset ./compiled_ds --output ./test --model Qwen/Qwen2.5-Coder-32B-Instruct
```

This script queries general large language models to produce refined decompiled code, employing few-shot learning techniques as specified in `prompt.md`.

- `dataset`: Path to the dataset output from the previous compilation step.
- `output`: Parent path for the output JSONL file.
- `model`: Choose from `qwen`, `gpt-4o-mini`, `claude-3-5-sonnet-v2@20241022`, `gpt-4o-2024-11-20`, or `deepseek-coder`.

For specialized models hosted locally, run:

```shell
python specialized_llm.py --dataset ./compiled_ds --output ./test --model LLM4Binary/llm4decompile-22b-v2
```

The parameters are consistent with the previous section.

## Evaluation

This section describes the evaluation of decompiled code.

Before evaluation, integrate all decompiler outputs, including those from LLMs, into a single dataset saved at `./decompiled_ds_all`. Then, execute:

```shell
python evaluate_rsr.py --decompile_result ./decompiled_ds_all --decompiler all --ossfuzz_path your_oss_fuzz_path
```

Before running, you can set the model's URL (BASE_URL) and API key (API_KEY) in the environment variables.
Enable the debug parameter to print error messages for specific data. This script recompiles the specified decompiler outputs in Docker, applies fixes, and reports success rates across different optimization levels. Successfully compiled functions are stored as shared libraries in `f'{args.ossfuzz_path}/build/challenges'` for further evaluation.

To assess coverage differences before and after replacing with decompiled code, run:

```shell
python evaluate_cer.py --dataset ./decompiled_ds_all --config coverage.yaml
```

This script generates coverage reports for each function by linking the reference (base) shared object and the decompiled function's shared object separately.

Finally, evaluate code quality by running:

```shell
python code_quality.py --run --model your_model --dataset ./decompiled_ds_all --output your_output_path
```

This script conducts an LLM arena evaluation across 12 dimensions, computing Elo scores to assess code quality. The output path will contain all scoring information in PKL files. Use the `rate` parameter instead of `run` to calculate Elo scores for different aspects and overall performance.
