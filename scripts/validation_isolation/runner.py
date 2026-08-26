"""Snapshot, probe, run, and verify validation commands."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys  # noqa: F401 - retained for compatibility with validation test seams
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
    cleanup: CleanupResult | None = None


@dataclass(frozen=True)
class ValidationFailure:
    """Bounded primary-failure evidence suitable for cleanup precedence."""

    code: str
    message: str


@dataclass(frozen=True)
class CleanupRootIdentity:
    """Pinned identity for the private root owned by one validation run."""

    device: int
    inode: int
    mode: int

    @classmethod
    def from_path(cls, path: Path) -> CleanupRootIdentity:
        item = os.lstat(path)
        if not stat.S_ISDIR(item.st_mode):
            raise ValidationIsolationError("validation cleanup root is unsafe")
        return cls(item.st_dev, item.st_ino, stat.S_IMODE(item.st_mode))


@dataclass(frozen=True)
class CleanupResult:
    """Stable cleanup outcome; no filesystem or exception details are exposed."""

    code: str
    primary_present: bool

    def __repr__(self) -> str:
        return (
            f"CleanupResult(code={self.code!r}, "
            f"primary_present={self.primary_present!r})"
        )


class ValidationCleanupError(ValidationIsolationError):
    """Stable sanitized failure for cleanup after a successful child."""

    def __init__(self, cleanup: CleanupResult) -> None:
        self.cleanup = cleanup
        super().__init__("validation cleanup failed")


_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
    os, "O_NOFOLLOW", 0
)


def _suppress_top_directory_error(function, path, error_info) -> None:
    """Allow fd-relative rmtree to leave removal of the opened root to us."""

    if function is os.rmdir and path == ".":
        return
    raise error_info[1]


def _cleanup_directory_fd(descriptor: int) -> None:
    """Remove contents through an opened directory, never through its path."""

    shutil.rmtree(".", dir_fd=descriptor, onerror=_suppress_top_directory_error)


def _before_final_cleanup(parent_descriptor: int, name: str) -> None:
    """Test seam immediately before final identity revalidation."""


def _identity_matches_descriptor(
    identity: CleanupRootIdentity, descriptor: int
) -> bool:
    item = os.fstat(descriptor)
    return identity == CleanupRootIdentity(
        item.st_dev, item.st_ino, stat.S_IMODE(item.st_mode)
    ) and stat.S_ISDIR(item.st_mode)


def _entry_exists(parent_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _entry_matches_descriptor(
    parent_descriptor: int, name: str, descriptor: int
) -> bool:
    """Check that a no-follow parent entry is still the opened directory."""

    try:
        entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        opened = os.fstat(descriptor)
    except OSError:
        return False
    return (
        stat.S_ISDIR(entry.st_mode)
        and stat.S_ISDIR(opened.st_mode)
        and os.path.samestat(entry, opened)
        and stat.S_IMODE(entry.st_mode) == stat.S_IMODE(opened.st_mode)
    )


def _failure_for(exc: BaseException) -> ValidationFailure:
    if isinstance(exc, subprocess.TimeoutExpired):
        return ValidationFailure("timeout", "validation command timed out")
    if isinstance(exc, OSError):
        return ValidationFailure("launch_failed", "validation command failed to launch")
    return ValidationFailure("validation_failed", "validation was blocked")


def _failure_for_result(result: ValidationResult) -> ValidationFailure | None:
    if result.returncode == 0:
        return None
    return ValidationFailure("child_failed", "validation command returned nonzero")


def cleanup_validation_root(
    root: Path,
    *,
    primary: ValidationFailure | None,
    expected_identity: CleanupRootIdentity | None = None,
) -> CleanupResult:
    """Remove a private validation root and return only stable typed evidence."""

    parent_descriptor = None
    quarantine_descriptor = None
    try:
        parent_descriptor = os.open(root.parent, _DIRECTORY_FLAGS)
        quarantine = Path(
            tempfile.mkdtemp(prefix="subagents-validation-cleanup-", dir=root.parent)
        )
        os.rmdir(quarantine)
    except BaseException:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        return CleanupResult("cleanup_failed", primary is not None)

    try:
        os.rename(
            root.name,
            quarantine.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
    except OSError:
        os.close(parent_descriptor)
        return CleanupResult("cleanup_root_changed", primary is not None)

    try:
        quarantine_descriptor = os.open(
            quarantine.name, _DIRECTORY_FLAGS, dir_fd=parent_descriptor
        )
    except OSError:
        os.close(parent_descriptor)
        return CleanupResult("cleanup_root_changed", primary is not None)

    if expected_identity is not None and not _identity_matches_descriptor(
        expected_identity, quarantine_descriptor
    ):
        try:
            if not _entry_exists(parent_descriptor, root.name):
                os.rename(
                    quarantine.name,
                    root.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
        except OSError:
            pass
        os.close(quarantine_descriptor)
        os.close(parent_descriptor)
        return CleanupResult("cleanup_root_changed", primary is not None)

    try:
        _cleanup_directory_fd(quarantine_descriptor)
        _before_final_cleanup(parent_descriptor, quarantine.name)
        # Python has no portable unlinkat-by-open-directory-fd primitive.
        # Revalidate the no-follow parent entry against the opened directory
        # immediately before the dir-fd-relative rmdir, then verify that the
        # opened object remained the one removed and its name is gone.
        before_removal = os.fstat(quarantine_descriptor)
        if not _entry_matches_descriptor(
            parent_descriptor, quarantine.name, quarantine_descriptor
        ):
            return CleanupResult("cleanup_failed", primary is not None)
        os.rmdir(quarantine.name, dir_fd=parent_descriptor)
        after_removal = os.fstat(quarantine_descriptor)
        if not os.path.samestat(before_removal, after_removal):
            return CleanupResult("cleanup_failed", primary is not None)
        try:
            os.stat(quarantine.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return CleanupResult("cleaned", primary is not None)
        except OSError:
            return CleanupResult("cleanup_failed", primary is not None)
        return CleanupResult("cleanup_failed", primary is not None)
    except BaseException:
        return CleanupResult("cleanup_failed", primary is not None)
    finally:
        if quarantine_descriptor is not None:
            os.close(quarantine_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


ProcessRunner: TypeAlias = Callable[
    [Sequence[str], Path, Mapping[str, str], float | None],
    subprocess.CompletedProcess[str],
]
MAX_OUTPUT = 8192
COMMAND_TIMEOUT = 900.0

_SYSTEM_INTERPRETER_CANDIDATES = {
    "linux": (Path("/usr/bin/python3"), Path("/usr/bin/python3.12")),
    "darwin": (
        Path("/usr/bin/python3"),
        Path(
            "/Library/Developer/CommandLineTools/Library/Frameworks/"
            "Python3.framework/Versions/3.9/bin/python3.9"
        ),
    ),
}


def _trusted_system_interpreter(platform_name: str, configured: str | None) -> Path:
    """Select only a reviewed, canonical system interpreter."""

    candidates = _SYSTEM_INTERPRETER_CANDIDATES.get(platform_name)
    if candidates is None:
        raise ValidationIsolationError("unsupported validation platform")
    approved = {str(candidate) for candidate in candidates}
    if configured is not None:
        if configured not in approved:
            raise ValidationIsolationError("unapproved validation interpreter")
        candidates = (Path(configured),)
    for candidate in candidates:
        try:
            canonical = candidate.resolve(strict=True)
            from .backend import _validate_trusted_interpreter

            trusted_platform = "macOS" if platform_name == "darwin" else "Linux"
            _validate_trusted_interpreter(canonical, trusted_platform)
            return canonical
        except (OSError, RuntimeError, ValidationIsolationError):
            continue
    raise ValidationIsolationError("reviewed validation interpreter unavailable")


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
    process_runner: ProcessRunner = run_process,
) -> ValidationResult:
    if not command:
        raise ValidationIsolationError("validation command is empty")
    worktree = locate_worktree(start_dir)
    command = validate_command_argv(command, worktree)
    configured_interpreter = (
        os.environ["VALIDATION_SYSTEM_PYTHON"]
        if "VALIDATION_SYSTEM_PYTHON" in os.environ
        else None
    )
    python_executable = _trusted_system_interpreter(
        platform_name, configured_interpreter
    )
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
    cleanup_identity = CleanupRootIdentity.from_path(isolation_root)
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
        except (OSError, ValueError, RuntimeError):
            raise ValidationIsolationError(
                "validation isolation probe failed"
            ) from None
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

    primary_exception = mutation_error or primary_error
    if primary_exception is not None:
        primary_for_cleanup = _failure_for(primary_exception)
    else:
        primary_for_cleanup = None if result is None else _failure_for_result(result)
    cleanup_result = cleanup_validation_root(
        isolation_root,
        primary=primary_for_cleanup,
        expected_identity=cleanup_identity,
    )

    if mutation_error is not None:
        raise mutation_error
    if primary_error is not None:
        raise primary_error
    if result is None:
        raise ValidationIsolationError("validation did not produce a result")
    if cleanup_result.code != "cleaned" and result.returncode == 0:
        raise ValidationCleanupError(cleanup_result)
    return ValidationResult(
        result.returncode,
        result.stdout,
        result.stderr,
        (*result.evidence, f"cleanup={cleanup_result.code}"),
        cleanup_result,
    )
