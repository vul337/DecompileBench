# DecompileBench Review

This repository contains scripts and tools for evaluating the performance of decompilation processes using both traditional decompilers and large language models (LLMs). Below is a brief description of each script and its purpose:

- **decompile.py**: This script requests a server to obtain decompiled code from traditional decompilers such as Hex-Rays.

- **general_llm.py**: This script queries general large language models to generate refined decompiled code using few-shot learning techniques and requirements as outlined in `prompt.md`.

- **specialized_llm**: This script queries LLM4Decompile and MLM for decompiled codes in a zero-shot manner.

- **evaluate_rsr.py**: This script recompiles each decompiled code into a shared library and evaluates the Recompile Success Rate (RSR) simultaneously.

- **evaluate_cer.py**: For each function, this script generates coverage reports by separately linking the reference (base) shared object and the decompiled function's shared object.

- **code_quality.py**: This script performs an LLM arena evaluation across 12 dimensions, computing Elo scores to assess code quality.
