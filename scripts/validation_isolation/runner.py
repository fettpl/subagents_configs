"""Snapshot, probe, run, and verify validation commands."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from .backend import (
    _private_directory,
    build_backend_argv,
    probe_backend,
    run_process,
    run_verified_process,
    select_backend,
    validate_command_argv,
    verify_backend,
)
from .environment import build_child_environment
from .errors import ValidationIsolationError
from .git_snapshot import assert_checkout_unchanged, create_snapshot, locate_worktree


@dataclass(frozen=True)
class ValidationResult:
    returncode: int
    stdout: str
    stderr: str
    evidence: tuple[str, ...]


ProcessRunner: TypeAlias = Callable[
    [Sequence[str], Path, Mapping[str, str], float | None],
    subprocess.CompletedProcess[str],
]
MAX_OUTPUT = 8192
COMMAND_TIMEOUT = 900.0


def _bounded(value: object) -> str:
    if not isinstance(value, str):
        raise ValidationIsolationError("validation command output is invalid")
    text = value
    if len(text) <= MAX_OUTPUT:
        return text
    suffix = "\n[output truncated]"
    return text[: MAX_OUTPUT - len(suffix)] + suffix


def _trusted_executable_dirs(python_executable: Path) -> tuple[Path, ...]:
    del python_executable
    directories = []
    for candidate in (Path("/usr/bin"), Path("/bin")):
        try:
            canonical = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if canonical == candidate:
            directories.append(candidate)
    return tuple(directories)


def run_isolated(
    command: Sequence[str],
    start_dir: Path,
    platform_name: str,
    process_runner=run_process,
) -> ValidationResult:
    if not command:
        raise ValidationIsolationError("validation command is empty")
    worktree = locate_worktree(start_dir)
    command = validate_command_argv(command, worktree)
    python_executable = Path(sys.executable)
    sandbox_exec = Path("/usr/bin/sandbox-exec")
    bwrap = next(
        (
            candidate
            for candidate in (Path("/usr/bin/bwrap"), Path("/bin/bwrap"))
            if candidate.exists()
        ),
        None,
    )
    isolation_root = Path(tempfile.mkdtemp(prefix="subagents-validation-")).resolve()
    snapshot = None
    result = None
    primary_error = None
    try:
        snapshot = create_snapshot(worktree, isolation_root / "snapshot")
        temp_root = isolation_root / "temp"
        temp_root.mkdir(mode=0o700)
        environment = build_child_environment(
            os.environ, temp_root, _trusted_executable_dirs(python_executable)
        )
        backend = select_backend(platform_name, sandbox_exec, bwrap, python_executable)
        try:
            probe_backend(
                backend,
                snapshot.snapshot_root,
                temp_root,
                environment,
                process_runner,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValidationIsolationError(
                "validation isolation probe timed out"
            ) from exc
        verify_backend(backend)
        private_roots = (
            _private_directory(snapshot.snapshot_root, "snapshot"),
            _private_directory(temp_root, "validation temporary root"),
        )
        argv = build_backend_argv(
            backend, command, snapshot.snapshot_root, temp_root, environment
        )
        try:
            completed = run_verified_process(
                backend,
                argv,
                snapshot.snapshot_root,
                environment,
                COMMAND_TIMEOUT,
                process_runner,
                private_roots=private_roots,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValidationIsolationError("validation command timed out") from exc
        except (OSError, TimeoutError) as exc:
            raise ValidationIsolationError(
                "validation command failed to launch"
            ) from exc
        result = ValidationResult(
            int(completed.returncode),
            _bounded(completed.stdout),
            _bounded(completed.stderr),
            (f"backend={backend.name}", "probe=passed"),
        )
    except BaseException as exc:
        primary_error = exc

    mutation_error = None
    if snapshot is not None:
        try:
            assert_checkout_unchanged(snapshot)
        except BaseException as exc:
            mutation_error = exc

    cleanup_error = None
    try:
        shutil.rmtree(isolation_root, ignore_errors=False)
    except BaseException as exc:
        cleanup_error = exc

    if mutation_error is not None:
        raise mutation_error
    if cleanup_error is not None:
        raise ValidationIsolationError(
            "validation temporary cleanup failed"
        ) from cleanup_error
    if primary_error is not None:
        raise primary_error
    if result is None:
        raise ValidationIsolationError("validation did not produce a result")
    return result
