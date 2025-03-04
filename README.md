# DecompileBench Evaluation

This repository provides scripts and tools for evaluating the performance of decompilation processes using both traditional decompilers and large language models (LLMs).

## Preparation

To begin, download the `oss-fuzz` project and compile all projects to obtain the fuzzers or project binaries.

For evaluating each function within a project, a Docker container is utilized. The base image for all Docker containers is `oss-fuzz`'s `base_builder`. We have modified the `base_builder` Dockerfile to include `bear` and `clang-extract`.

```shell
cd oss-fuzz
cat >> infra/base-images/base-builder/Dockerfile <<EOF
RUN apt install -y pkg-config python3-apt libssl-dev ninja-build && \
    git clone https://github.com/5c4lar/Bear -b main-for-pr-to-original-repo --depth 1 && \
    cd Bear && \
    cmake -DENABLE_UNIT_TESTS=OFF -DENABLE_FUNC_TESTS=OFF -GNinja -B build && \
    ninja -C build install && \
    cd .. && \
    rm -rf Bear

COPY bear_config.json /src/bear_config.json
ADD clang-extract.tar.gz /src/clang-extract
RUN patchelf --set-interpreter "/src/clang-extract/ld-linux-x86-64.so.2" /src/clang-extract/clang-extract

CMD ["bear", "--config", "/src/bear_config.json", "--output", "/work/compile_commands.json", "--", "compile"]
EOF
python infra/helper.py build_image base-builder
```

## Extract Functions

Run `python extract_functions.py --config coverage.yaml`. Initially, execute the fuzzers to collect covered functions, including their names and corresponding files. Coverage information is recorded in `f{oss_fuzz_path}/build/stats/{project}/{fuzzer}_result.json`. 
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
python general_llm.py --dataset ./compiled_ds --output ./test.jsonl --model qwen --key your_key
```

This script queries general large language models to produce refined decompiled code, employing few-shot learning techniques as specified in `prompt.md`.

- `dataset`: Path to the dataset output from the previous compilation step.
- `output`: Path for the output JSONL file.
- `model`: Choose from `qwen`, `gpt-4o-mini`, `claude-3-5-sonnet-v2@20241022`, `gpt-4o-2024-11-20`, or `deepseek-coder`.

For specialized models hosted locally, run:

```shell
python specialized_llm.py --dataset ./compiled_ds --output ./test.jsonl --model LLM4Binary/llm4decompile-22b-v2 --key your_key
```

The parameters are consistent with the previous section.

## Evaluation

This section describes the evaluation of decompiled code.

Before evaluation, integrate all decompiler outputs, including those from LLMs, into a single dataset saved at `./decompiled_ds_all`. Then, execute:

```shell
python evaluate_rsr.py --decompile_result ./decompiled_ds_all --decompiler all --ossfuzz_path your_oss_fuzz_path
```

Enable the debug parameter to print error messages for specific data. This script recompiles the specified decompiler outputs in Docker, applies fixes, and reports success rates across different optimization levels. Successfully compiled functions are stored as shared libraries in `f'{args.ossfuzz_path}/build/challenges'` for further evaluation.

To assess coverage differences before and after replacing with decompiled code, run:

```shell
python evaluate_cer.py --dataset ./decompiled_ds_all --config coverage.yaml
```

This script generates coverage reports for each function by linking the reference (base) shared object and the decompiled function's shared object separately.

Finally, evaluate code quality by running:

```shell
python code_quality.py --run --model your_model --dataset ./decompiled_ds_all --url your_url --api_key your_key --output your_output_path
```

This script conducts an LLM arena evaluation across 12 dimensions, computing Elo scores to assess code quality. The output path will contain all scoring information in PKL files. Use the `rate` parameter to calculate Elo scores for different aspects and overall performance.
