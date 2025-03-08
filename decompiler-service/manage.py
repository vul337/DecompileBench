#!/usr/bin/env python3

import argparse
import os
import subprocess

from pathlib import Path

BASE_DIR = Path(__file__).parent

DECOMPILERS = [
    ("angr", "angr"),
    ("ghidra", "Ghidra"),
    ("recstudio", "REC Studio"),
    ("reko", "Reko"),
    ("retdec", "RetDec"),
]

if not (BASE_DIR / "src" / "runners" / "tools" / "binja" / "license.dat").exists():
    print("Binary Ninja key not detected... Excluding from build")
else:
    DECOMPILERS.append(("binja", "Binary Ninja"))
    DECOMPILERS.append(("dewolf", "dewolf"))

if (
    not (
        BASE_DIR / "src" / "runners" / "tools" / "hexrays" / ".idapro" / "ida.reg"
    ).exists()
    or not (
        BASE_DIR / "src" / "runners" / "tools" / "hexrays" / "ida" / "idat64"
    ).exists()
    or not (BASE_DIR / "src" / "runners" / "tools" / "hexrays" / "efd64").exists()
):
    print("IDA install key not detected... Excluding from build")
else:
    DECOMPILERS.append(("hexrays", "Hex Rays"))
    DECOMPILERS.append(("mlm", "MLM"))

if not (BASE_DIR / "src" / "runners" / "tools" / "relyze" / "License.txt").exists():
    print("Relyze license file not detected... Excluding from build")
else:
    DECOMPILERS.append(("relyze", "Relyze"))

DECOMPILERS.sort(key=lambda d: d[0])

parser = argparse.ArgumentParser(description="Manage decompiler")

parser.add_argument(
    "--image-name", help="Name of the Docker image to use", default="decompiler_service"
)

for decomp in DECOMPILERS:
    parser.add_argument(
        f"--with-{decomp[0]}",
        dest=decomp[0],
        action="store_true",
        help=f"Enable {decomp[1]} decompiler",
        default=False,
    )


subparsers = parser.add_subparsers(dest="subcommand_name")

build_parser = subparsers.add_parser("build")
build_parser.add_argument("--prod", action="store_true",
                          help="Build for production")

start_parser = subparsers.add_parser("start")
start_parser.add_argument(
    "--debug", action="store_true", help="Show debug output")
start_parser.add_argument(
    "--replicas", default=1, help="Number of replicas for the decompiler runners"
)
start_parser.add_argument(
    "--timeout", default=1200, help="Timeout duration for runners (default: 120)"
)

stop_parser = subparsers.add_parser("stop")
stop_parser.add_argument("--prod", action="store_true",
                         help="Stop production server")


def build_server(args):
    env = os.environ.copy()
    env.update({"IMAGE_NAME": args.image_name})

    config_files = f"-f {BASE_COMPOSE_FILE}"

    services = [
        "server",
        "redis",
        "monitor"
    ]
    for d in DECOMPILERS:
        if getattr(args, d[0]):
            services.append(d[0])

    cmd = f"docker compose {config_files} build"
    final = cmd.split(" ") + services
    subprocess.run(final, env=env, check=True)


def start_server(args):
    config_files = f"-f {BASE_COMPOSE_FILE}"

    services = [
        "server",
        "redis",
        "monitor"
    ]
    decompiler_services = []
    for d in DECOMPILERS:
        if getattr(args, d[0]):
            services.append(d[0])
            decompiler_services.append(d[0])

    env = os.environ.copy()
    env.update(
        {
            "REPLICAS": str(args.replicas),
            "IMAGE_NAME": args.image_name,
        }
    )

    if "DECOMPILER_TIMEOUT" in os.environ:
        env["DECOMPILER_TIMEOUT"] = os.environ["DECOMPILER_TIMEOUT"]
    elif args.timeout:
        env["DECOMPILER_TIMEOUT"] = str(args.timeout)

    if args.debug:
        env["DEBUG"] = "1"

    env["DECOMPILERS"] = ",".join(decompiler_services)

    cmd = f"docker compose {config_files} up"

    final = cmd.split(" ") + services + ["-d"]

    subprocess.run(final, env=env, check=True)


def stop_server():
    config_files = f"-f {BASE_COMPOSE_FILE}"
    services = [
        "server",
        "redis",
        "monitor"
    ]
    for d in DECOMPILERS:
        if getattr(args, d[0]):
            services.append(d[0])

    cmd = f"docker compose {config_files} down"

    final = cmd.split(" ") + services
    subprocess.run(final, check=True)


args = parser.parse_args()
BASE_COMPOSE_FILE = BASE_DIR / f"docker-compose.yaml"

subcommand = args.subcommand_name

if subcommand == "build":
    build_server(args)
elif subcommand == "start":
    start_server(args)
elif subcommand == "stop":
    stop_server()
else:
    parser.print_help()
