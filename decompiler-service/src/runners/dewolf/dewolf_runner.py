#!/usr/bin/env python3
"""Main decompiler Interface."""
from __future__ import annotations
import sys
sys.path.append('/home/decompiler_user/dewolf/')
from typing import Dict, List, Optional, Tuple

from decompiler.backend.codegenerator import CodeGenerator
from decompiler.frontend import BinaryninjaFrontend, Frontend
from decompiler.pipeline.pipeline import DecompilerPipeline
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


class Decompiler:
    """Main Interface to the decompiler."""

    def __init__(self, frontend: Frontend):
        """
        Initialize a new decompiler on the given view.

        frontend -- The disassembler frontend to be used.
        """
        self._frontend = frontend
        self._backend = CodeGenerator()

    @classmethod
    def create_options(cls) -> Options:
        """Create Options from defaults"""
        return Options.load_default_options()

    @classmethod
    def from_path(cls, path: str, options: Optional[Options] = None, frontend: Frontend = BinaryninjaFrontend) -> Decompiler:
        """Create a decompiler instance by invoking the given frontend on the given sample."""
        if not options:
            options = Decompiler.create_options()
        return cls(frontend.from_path(path, options))

    @classmethod
    def from_raw(cls, data, frontend: Frontend = BinaryninjaFrontend) -> Decompiler:
        """Create a decompiler instance from existing frontend instance (e.g. a binaryninja view)."""
        return cls(frontend.from_raw(data))

    def decompile(self, function: str, task_options: Optional[Options] = None) -> DecompilerTask:
        """Decompile the target function."""
        # Sanity check to ensure task_options is populated
        if task_options is None:
            task_options = Decompiler.create_options()
        # Start decompiling
        pipeline = DecompilerPipeline.from_strings(task_options.getlist("pipeline.cfg_stages"), task_options.getlist("pipeline.ast_stages"))
        task = self._frontend.create_task(function, task_options)
        pipeline.run(task)
        task.code = self._backend.generate([task])
        return task

    def decompile_all(self, task_options: Optional[Options] = None) -> str:
        """Decompile all functions in the binary"""
        tasks = list()
        # Sanity check to ensure task_options is populated
        if task_options is None:
            task_options = Decompiler.create_options()
        # Start decompiling
        pipeline = DecompilerPipeline.from_strings(task_options.getlist("pipeline.cfg_stages"), task_options.getlist("pipeline.ast_stages"))
        functions = self._frontend.get_all_function_names()
        for function in functions:
            task = self._frontend.create_task(function, task_options)
            pipeline.run(task)
            tasks.append(task)
        code = self._backend.generate(tasks)
        return code
    
"""Command line interface for the decompiler."""

from argparse import SUPPRESS, ArgumentParser
from enum import Enum
from os.path import isfile
import json

from decompiler.logger import configure_logging
from decompiler.util.decoration import DecoratedCode
from decompiler.util.options import Options

VERBOSITY_TO_LOG_LEVEL = {0: "ERROR", 1: "WARNING", 2: "INFO", 3: "DEBUG"}


class Colorize(str, Enum):
    """Enum specifying if output should be colorized. note: subclass str for json.dumps"""

    ALWAYS = "always"
    NEVER = "never"
    AUTO = "auto"

    def __str__(self):
        """Print choices=list(Colorize) as {always, never, auto}"""
        return self.value


def parse_commandline():
    """Parse the current command line options for the arguments required for the decompiler."""

    def _is_valid_decompile_target(path: str):
        """Check if the given path is a valid decompilation target."""
        if not isfile(path):
            raise ValueError(f"{path} is not a valid file for decompilation!")
        else:
            return path

    parser = ArgumentParser(description=__doc__, epilog="", argument_default=SUPPRESS, add_help=False)
    # register CLI-specific arguments
    parser.add_argument('--binary', required=True, help='Path to the binary file')
    parser.add_argument('--address', required=True, nargs='+', help='List of addresses to decompile')
    parser.add_argument('--file', required=True, help='Path to the output file')
    parser.add_argument("--help", "-h", action="help", help="Show this help message and exit")
    parser.add_argument(
        "--verbose", "-v", dest="verbose", action="count", help="Set logging verbosity, e.g., -vvv for DEBUG logging", default=0
    )
    parser.add_argument("--color", type=Colorize, choices=list(Colorize), default=Colorize.AUTO)
    parser.add_argument("--output", "-o", dest="outfile", help="The file in which to place decompilation output", default=None)
    parser.add_argument("--all", "-a", dest="all", action="store_true", help="Decompile all functions in this binary", default=False)
    parser.add_argument("--print-config", dest="print", action="store_true", help="Print current config and exit", default=False)
    parser.usage = parser.format_usage().lstrip("usage: ")  # Don't add expert args to usage
    Options.register_defaults_in_argument_parser(parser)  # register expert arguments
    return parser.parse_args()


def main(interface: "Decompiler"):
    """Main function for command line invocation."""
    args = parse_commandline()
    configure_logging(level=VERBOSITY_TO_LOG_LEVEL[min(3, args.verbose)])

    options = Options.from_cli(args)
    if args.print:
        print(options)
        return

    decompiled_functions = {}
    decompiler = interface.from_path(args.binary, options)
    try:
        for address in args.address:
            task = decompiler.decompile(address, options)
            code = DecoratedCode.formatted_plain(task.code).strip()
            decompiled_functions[address] = code
    except Exception as e:
        pass
    
    with open(args.file, 'w') as f:
        f.write(json.dumps(decompiled_functions, indent=4))
        
"""When invoked as a script, run the commandline interface."""
if __name__ == "__main__":
    # from decompiler.util.commandline import main

    main(Decompiler)