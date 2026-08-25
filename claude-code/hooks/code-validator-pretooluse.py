#!/usr/bin/env python3
"""Fail-closed Claude PreToolUse gate for the repository validator.

The hook parses a Claude event and validates a fixed argv-shaped command.  It
never executes the command; Claude remains responsible for invoking this hook
before a Bash tool call.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, TextIO


@dataclass(frozen=True)
class PreToolUseEvent:
    tool_name: str
    command: str


_TOP_KEYS = {"tool_name", "tool_input"}
_INPUT_KEYS = {"command"}
_SHELL_META = frozenset(";&|<>$`(){}[]!#'\"\\")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _reject_duplicate_pairs(pairs: list[tuple[object, object]]) -> dict[object, object]:
    result: dict[object, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("invalid event shape")
    if any(type(key) is not str for key in value):
        raise ValueError("invalid event keys")
    return value


def _contains_command_syntax(value: str) -> bool:
    return any(
        character in _SHELL_META
        or ord(character) < 0x20
        or ord(character) == 0x7F
        or unicodedata.category(character) in {"Cc", "Cf"}
        for character in value
    )


def parse_pretooluse_event(raw: bytes) -> PreToolUseEvent:
    """Parse one exact Claude Bash event without exposing input in errors."""

    if type(raw) is not bytes or not raw or len(raw) > 1_048_576:
        raise ValueError("invalid event")
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("invalid JSON number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        raise ValueError("invalid event") from None
    top = _object(decoded, _TOP_KEYS)
    if top["tool_name"] != "Bash":
        raise ValueError("invalid event")
    tool_input = _object(top["tool_input"], _INPUT_KEYS)
    command = tool_input["command"]
    if (
        type(command) is not str
        or not command
        or len(command) > 16_384
        or _contains_command_syntax(command)
    ):
        raise ValueError("invalid event")
    return PreToolUseEvent("Bash", command)


def _safe_relative_argument(value: str) -> bool:
    if not value or "\x00" in value or value in {".", ".."}:
        return False
    try:
        path = PurePosixPath(value)
    except (TypeError, ValueError):
        return False
    return not path.is_absolute() and ".." not in path.parts


def _safe_helper(value: str) -> bool:
    if type(value) is not str or not value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return path.is_absolute() and ".." not in path.parts and "\\" not in value


def validate_validator_command(command: str, helper: str) -> tuple[str, ...]:
    """Return the only accepted validator argv, treating all fields as data."""

    if type(command) is not str or not command or len(command) > 16_384:
        raise ValueError("validation command denied")
    if not _safe_helper(helper):
        raise ValueError("validation command denied")
    if _contains_command_syntax(command):
        raise ValueError("validation command denied")
    try:
        argv = tuple(shlex.split(command, posix=True))
    except (ValueError, TypeError):
        raise ValueError("validation command denied") from None
    if len(argv) < 4 or argv[:3] != ("python3", helper, "--"):
        raise ValueError("validation command denied")
    for value in argv[3:]:
        if not _safe_relative_argument(value):
            raise ValueError("validation command denied")
        if _ASSIGNMENT.match(value):
            raise ValueError("validation command denied")
    return argv


def _rendered_helper() -> str:
    # The hook is installed next to the private validation runtime.  Resolving
    # this repository-controlled relative path does not inspect user input.
    return str(Path(__file__).resolve().parent.parent / "validation" / "run-validation-isolated.py")


VALIDATION_HELPER = _rendered_helper()


def hook_main(stdin: BinaryIO, stdout: TextIO, stderr: TextIO) -> int:
    """Allow only the fixed helper shape; never run the resulting argv."""

    try:
        event = parse_pretooluse_event(stdin.read(1_048_577))
        validate_validator_command(event.command, VALIDATION_HELPER)
    except (OSError, ValueError, TypeError):
        stderr.write("validation command denied\n")
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - Claude invokes hook_main
    raise SystemExit(hook_main(sys.stdin.buffer, sys.stdout, sys.stderr))
