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
    session_id: str
    cwd: str
    tool_name: str
    command: str
    tool_use_id: str
    permission_mode: str | None = None
    agent_id: str | None = None
    agent_type: str | None = None
    prompt_id: str | None = None
    effort: dict[str, str] | None = None
    description: str | None = None
    timeout: int | None = None
    run_in_background: bool | None = None


_EVENT_REQUIRED_KEYS = {
    "session_id",
    "cwd",
    "hook_event_name",
    "tool_name",
    "tool_input",
    "tool_use_id",
}
_EVENT_OPTIONAL_KEYS = {
    "transcript_path",
    "permission_mode",
    "agent_id",
    "agent_type",
    "prompt_id",
    "effort",
}
_TOP_KEYS = _EVENT_REQUIRED_KEYS | _EVENT_OPTIONAL_KEYS
_INPUT_KEYS = {"command", "description", "timeout", "run_in_background"}
_PERMISSION_MODES = frozenset(
    {"default", "auto", "acceptEdits", "plan", "bypassPermissions", "dontAsk"}
)
_EFFORT_KEYS = {"level"}
_EFFORT_LEVELS = frozenset({"low", "medium", "high", "xhigh", "max"})
_EVENT_NAME = "PreToolUse"
_TOOL_NAME = "Bash"
_SHELL_META = frozenset(
    {
        ";",
        "&",
        "|",
        "<",
        ">",
        "$",
        "`",
        "(",
        ")",
        "{",
        "}",
        "[",
        "]",
        "!",
        "#",
    }
)
_GLOB_META = frozenset({"*", "?", "~"})
_HELPER_GLOB_META = frozenset({"*", "?", "[", "]"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_BLOCKED_EXECUTABLES = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "csh",
        "fish",
        "env",
        "xargs",
        "exec",
        "command",
        "su" + "do",
        "doas",
        "nohup",
        "setsid",
        "timeout",
        "stdbuf",
        "nice",
        "python",
        "python2",
        "python3",
        "python3.14",
        "pypy",
        "perl",
        "ruby",
        "node",
        "deno",
        "bun",
        "java",
        "go",
        "cargo",
        "rustc",
        "make",
    }
)
_DIRECT_VALIDATORS = frozenset({"unittest", "pytest", "ruff", "shellcheck"})
_PYTHON_VALIDATOR_MODULES = frozenset({"unittest", "compileall", "pytest"})


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


def _safe_text(value: object, *, max_length: int = 4096) -> bool:
    return (
        type(value) is str
        and bool(value)
        and len(value) <= max_length
        and not any(
            ord(character) < 0x20
            or ord(character) == 0x7F
            or unicodedata.category(character) in {"Cc", "Cf"}
            for character in value
        )
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
    if (
        type(decoded) is not dict
        or any(type(key) is not str for key in decoded)
        or not _EVENT_REQUIRED_KEYS <= set(decoded)
        or not set(decoded) <= _TOP_KEYS
    ):
        raise ValueError("invalid event")
    top = decoded
    if any(key not in top for key in _EVENT_REQUIRED_KEYS):
        raise ValueError("invalid event")
    if any(not _safe_text(top[key]) for key in ("session_id", "cwd", "tool_use_id")):
        raise ValueError("invalid event")
    if top["hook_event_name"] != _EVENT_NAME:
        raise ValueError("invalid event")
    if top["tool_name"] != _TOOL_NAME:
        raise ValueError("invalid event")
    for key in {"transcript_path", "agent_id", "agent_type", "prompt_id"}:
        if key in top and not _safe_text(top[key]):
            raise ValueError("invalid event")
    if "permission_mode" in top and top["permission_mode"] not in _PERMISSION_MODES:
        raise ValueError("invalid event")
    effort = top.get("effort")
    if "effort" in top:
        if (
            type(effort) is not dict
            or set(effort) != _EFFORT_KEYS
            or not _safe_text(effort["level"])
            or effort["level"] not in _EFFORT_LEVELS
        ):
            raise ValueError("invalid event")
    if "agent_type" in top and top["agent_type"] != "code-validator":
        raise ValueError("invalid event")
    tool_input = top["tool_input"]
    if (
        type(tool_input) is not dict
        or not isinstance(tool_input.get("command"), str)
        or set(tool_input) - _INPUT_KEYS
        or any(type(key) is not str for key in tool_input)
    ):
        raise ValueError("invalid event")
    for key in ("description",):
        if key in tool_input and not _safe_text(tool_input[key]):
            raise ValueError("invalid event")
    if "timeout" in tool_input and (
        type(tool_input["timeout"]) is not int
        or not 0 <= tool_input["timeout"] <= 86_400_000
    ):
        raise ValueError("invalid event")
    if (
        "run_in_background" in tool_input
        and type(tool_input["run_in_background"]) is not bool
    ):
        raise ValueError("invalid event")
    command = tool_input["command"]
    if (
        type(command) is not str
        or not command
        or len(command) > 16_384
        or _contains_command_syntax(command)
    ):
        raise ValueError("invalid event")
    return PreToolUseEvent(
        session_id=top["session_id"],
        cwd=top["cwd"],
        tool_name=_TOOL_NAME,
        command=command,
        tool_use_id=top["tool_use_id"],
        permission_mode=top.get("permission_mode"),
        agent_id=top.get("agent_id"),
        agent_type=top.get("agent_type"),
        prompt_id=top.get("prompt_id"),
        effort=effort,
        description=tool_input.get("description"),
        timeout=tool_input.get("timeout"),
        run_in_background=tool_input.get("run_in_background"),
    )


def _safe_relative_argument(value: str) -> bool:
    if (
        not value
        or "\x00" in value
        or value == ".."
        or any(character in _GLOB_META or character == "\\" for character in value)
    ):
        return False
    try:
        path = PurePosixPath(value)
    except (TypeError, ValueError):
        return False
    return not path.is_absolute() and ".." not in path.parts


def _safe_helper(value: str) -> bool:
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or any(character in _HELPER_GLOB_META for character in value)
    ):
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
    payload = argv[3:]
    executable = payload[0]
    if executable in _DIRECT_VALIDATORS:
        if executable == "ruff" and (
            len(payload) < 2 or payload[1] not in {"check", "format"}
        ):
            raise ValueError("validation command denied")
    elif (
        executable == "python3"
        and len(payload) >= 3
        and payload[1] == "-m"
        and payload[2] in _PYTHON_VALIDATOR_MODULES
    ):
        pass
    else:
        raise ValueError("validation command denied")
    for index, value in enumerate(payload):
        if not _safe_relative_argument(value):
            raise ValueError("validation command denied")
        if _ASSIGNMENT.match(value):
            raise ValueError("validation command denied")
        basename = PurePosixPath(value).name.lower()
        if index > 0 and (
            value.lower() in _BLOCKED_EXECUTABLES or basename in _BLOCKED_EXECUTABLES
        ):
            raise ValueError("validation command denied")
        if index == 0 and ("/" in value or value.startswith("-")):
            raise ValueError("validation command denied")
    return argv


def _rendered_helper() -> str:
    # The hook is installed next to the private validation runtime.  Resolving
    # this repository-controlled relative path does not inspect user input.
    return str(
        Path(__file__).resolve().parent.parent
        / "validation"
        / "run-validation-isolated.py"
    )


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
