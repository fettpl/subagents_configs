"""Command-line interface for the isolated validation helper."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from .runner import run_isolated


def parse_command(argv: Sequence[str]) -> tuple[str, ...]:
    if not argv or argv[0] != "--" or len(argv) < 2:
        raise ValueError("usage: run-validation-isolated.py -- COMMAND ARG...")
    command = tuple(str(item) for item in argv[1:])
    if not command or not command[0]:
        raise ValueError("validation command is empty")
    return command


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        command = parse_command(arguments)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        result = run_isolated(command, Path.cwd(), sys.platform)
    except subprocess.TimeoutExpired:
        print("validation blocked: validation command timed out", file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError):
        # Exception text can contain hostile paths, environment values, or
        # backend diagnostics.  The runner already records typed evidence;
        # the command-line boundary emits only this bounded stable outcome.
        print("validation blocked: validation failed", file=sys.stderr)
        return 1
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    for evidence in result.evidence:
        print(evidence, file=sys.stderr)
    return result.returncode
