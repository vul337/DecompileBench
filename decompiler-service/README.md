# DecompileBench-Service

## Pre-requisites
- Install Docker, Docker Compose and Python 3.8 or higher
- To build some decompiler images, you need to provide binaries and licenses that are not publicly available. For hexrays, binaryninja, dewolf and mlm, you need to have a license for the respective decompiler.

### Hexrays
From a Linux installation, you must first run IDA and accept the terms of service. Then, you can copy the following:

Copy the binaries:
- `cp -r /path/to/idapro src/runners/tools/hexrays/ida`

Copy the registry:
- `cp -r ~/.idapro src/runners/tools/hexrays`

Copy efd64 for batch processing:
- `cp efd64 src/runners/tools/hexrays`

### BinaryNinja and Dewolf
From a Linux installation, you have to copy the binaries and license information:

Copy the binaries:
- `cp -r ~/binaryninja src/runners/tools/binja/`

Copy the license:
- `cp ~/.binaryninja/license.dat src/runners/tools/binja/`

## Quick Start
- Use the `manage.py` to start the service
    ```bash
    usage: manage.py [-h] [--image-name IMAGE_NAME] [--with-angr] [--with-binja] [--with-boomerang] [--with-dewolf] [--with-ghidra] [--with-hexrays]
                    [--with-recstudio] [--with-reko] [--with-retdec] [--with-snowman]
                    {build,start,stop} ...

    Manage decompiler

    positional arguments:
    {build,start,stop}

    optional arguments:
    -h, --help            show this help message and exit
    --image-name IMAGE_NAME
                            Name of the Docker image to use
    --with-angr           Enable angr decompiler
    --with-binja          Enable Binary Ninja decompiler
    --with-dewolf         Enable dewolf decompiler
    --with-ghidra         Enable Ghidra decompiler
    --with-hexrays        Enable Hex Rays decompiler
    --with-recstudio      Enable REC Studio decompiler
    --with-reko           Enable Reko decompiler
    --with-retdec         Enable RetDec decompiler
    ```
- To build the service, run the following command
    ```bash
    python manage.py build --with-binja --with-dewolf --with-hexrays --with-ghidra # ...
    ```

- To start the service, run the following command
    ```bash
    usage: manage.py start [-h] [--debug] [--replicas REPLICAS] [--timeout TIMEOUT]

    optional arguments:
    -h, --help           show this help message and exit
    --debug              Show debug output
    --replicas REPLICAS  Number of replicas for the decompiler runners
    --timeout TIMEOUT    Timeout duration for runners (default: 120)
    ```
