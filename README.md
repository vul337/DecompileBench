# DecompileBench Review

This repository contains scripts and tools for evaluating the performance of decompilation processes using both traditional decompilers and large language models (LLMs). Below is a brief description of each script and its purpose:

- **compile_ossfuzz.py**: Extracts covered functions from ossfuzz, then uses clang-extract to gather dependencies needed to compile individual functions, and finally compiles them. The results are stored in the assembly directory of the output dataset.

- **decompile.py**: This script requests a server to obtain decompiled code from traditional decompilers such as Hex-Rays.

- **general_llm.py**: This script queries general large language models to generate refined decompiled code using few-shot learning techniques and requirements as outlined in `prompt.md`.

- **specialized_llm.py**: This script queries LLM4Decompile and MLM for decompiled codes in a zero-shot manner.

- **evaluate_rsr.py**: This script recompiles each decompiled code into a shared library and evaluates the Recompile Success Rate (RSR) simultaneously.

- **evaluate_cer.py**: This script generates coverage reports for each function by separately linking the reference (base) shared object and the decompiled function's shared object.
To evaluate each function in a project, a Docker container is used. The base image for all Docker containers is `oss-fuzz`'s `base_builder`.
We modified the `base_builder` Dockerfile to include `bear` and `clang-extract`.
```shell
git clone https://github.com/google/oss-fuzz
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

- **code_quality.py**: This script performs an LLM arena evaluation across 12 dimensions, computing Elo scores to assess code quality.


