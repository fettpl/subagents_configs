"""Persistent per-target transaction locks and identity evidence."""

from __future__ import annotations

import asyncio
import errno
import fcntl
import os
import stat
import threading
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from .models import IdentityEvidence, Target
from .paths import assert_safe_home, normalized_absolute
from .targets import targets_for_request

_LOCK_LEASE: ContextVar[object | None] = ContextVar(
    "subagents_configs_lock_lease", default=None
)

_DIRECTORY_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
)


class _LockLease:
    def __init__(
        self,
        owner: tuple[int, asyncio.Task[object] | None],
        homes: frozenset[Path],
        identities: dict[Path, tuple[int, int]],
    ) -> None:
        self.owner = owner
        self.homes = homes
        self.identities = identities
        self.released = False


def _execution_owner() -> tuple[int, asyncio.Task[object] | None]:
    try:
        task = asyncio.current_task()
    except RuntimeError:
        task = None
    return threading.get_ident(), task


def _current_lease() -> _LockLease | None:
    lease = _LOCK_LEASE.get()
    if not isinstance(lease, _LockLease):
        return None
    if lease.released or lease.owner != _execution_owner():
        return None
    return lease


def _after_home_validation(home: Path) -> None:
    """Race-test seam between lexical validation and descriptor traversal."""


def lock_held() -> bool:
    """Return whether this execution context already owns target locks."""

    return _current_lease() is not None


def homes_locked(homes: Mapping[Target, Path]) -> bool:
    """Return whether every requested home is held by this context."""

    requested = frozenset(normalized_absolute(path) for path in homes.values())
    lease = _current_lease()
    if lease is None or not requested <= lease.homes:
        return False
    for home in requested:
        if not _locked_home_path_matches(home):
            raise ValueError("locked target home identity changed")
    return True


def _locked_home_path_matches(path: Path) -> bool:
    """Check the lexical target path still names the locked directory inode."""

    normalized = normalized_absolute(path)
    lease = _current_lease()
    if lease is None:
        return True
    for home, identity in lease.identities.items():
        try:
            normalized.relative_to(home)
        except ValueError:
            continue
        try:
            result = os.lstat(home)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(result.st_mode) or not stat.S_ISDIR(result.st_mode):
            return False
        if (result.st_dev, result.st_ino) != identity:
            return False
    return True


def verify_locked_home_path(path: Path) -> None:
    """Fail closed when a locked target home was replaced or redirected."""

    if not _locked_home_path_matches(path):
        raise ValueError("locked target home identity changed")


def verify_locked_home_descriptor(path: Path, descriptor: int) -> None:
    """Bind a pinned directory descriptor to the context's locked home inode."""

    normalized = normalized_absolute(path)
    lease = _current_lease()
    if lease is None:
        return
    for home, identity in lease.identities.items():
        try:
            normalized.relative_to(home)
        except ValueError:
            continue
        if normalized == home:
            result = os.fstat(descriptor)
            if (result.st_dev, result.st_ino) != identity:
                raise ValueError("locked target home identity changed")


def _validate_target_sequence(homes: Mapping[Target, Path], targets: Sequence[Target]):
    requested = tuple(targets)
    if not requested or len(set(requested)) != len(requested):
        raise ValueError("lock targets must be unique")
    expected = targets_for_request(requested, False)
    if requested != expected:
        raise ValueError("lock targets are not in descriptor order")
    if any(not isinstance(target, Target) for target in requested):
        raise ValueError("lock targets must be Target values")
    if set(homes) != set(requested):
        raise ValueError("lock homes must exactly match requested targets")
    normalized: dict[Target, Path] = {}
    for target in requested:
        home = homes[target]
        if not isinstance(home, Path):
            raise ValueError("lock home must be a Path")
        normalized_home = normalized_absolute(home)
        normalized[target] = normalized_home
    if len(set(normalized.values())) != len(normalized):
        raise ValueError("lock homes must be distinct")
    return normalized


def _directory_identity_snapshot(path: Path) -> dict[Path, tuple[int, int]]:
    """Capture identities of existing lexical directory components."""

    absolute = normalized_absolute(path)
    identities: dict[Path, tuple[int, int]] = {}
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            result = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(result.st_mode) or not stat.S_ISDIR(result.st_mode):
            raise ValueError("target home contains a symlink or non-directory")
        identities[current] = (result.st_dev, result.st_ino)
    return identities


def _open_directory_path(
    path: Path, expected: Mapping[Path, tuple[int, int]] | None = None
) -> int:
    """Open an existing directory path with descriptor-relative no-following."""

    absolute = normalized_absolute(path)
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            try:
                next_descriptor = os.open(
                    component, _DIRECTORY_FLAGS, dir_fd=descriptor
                )
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ValueError("target home contains a symlink") from exc
                raise
            os.close(descriptor)
            descriptor = next_descriptor
            current /= component
            if expected is not None and current in expected:
                result = os.fstat(descriptor)
                if (result.st_dev, result.st_ino) != expected[current]:
                    raise ValueError("target home ancestor identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _prepare_home(home: Path) -> tuple[int, tuple[int, int]]:
    """Open/create only the final home component beneath an existing parent."""

    normalized = normalized_absolute(home)
    assert_safe_home(normalized)
    expected_ancestors = _directory_identity_snapshot(normalized.parent)
    try:
        expected_home = os.lstat(normalized)
    except FileNotFoundError:
        expected_home_identity = None
    else:
        expected_home_identity = (expected_home.st_dev, expected_home.st_ino)
    _after_home_validation(normalized)
    try:
        parent_descriptor = _open_directory_path(normalized.parent, expected_ancestors)
    except FileNotFoundError as exc:
        raise ValueError("target home parent must already exist") from exc
    home_descriptor = None
    try:
        try:
            existing = os.stat(
                normalized.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            if stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode):
                raise ValueError("target home must be a private directory")
            if (
                expected_home_identity is None
                or (
                    existing.st_dev,
                    existing.st_ino,
                )
                != expected_home_identity
            ):
                raise ValueError("target home identity changed")
        except FileNotFoundError:
            try:
                os.mkdir(normalized.name, 0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                existing = os.stat(
                    normalized.name, dir_fd=parent_descriptor, follow_symlinks=False
                )
                if stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode):
                    raise ValueError(
                        "target home must be a private directory"
                    ) from None
                if (
                    expected_home_identity is not None
                    or (
                        existing.st_dev,
                        existing.st_ino,
                    )
                    != expected_home_identity
                ):
                    raise ValueError("target home identity changed") from None
        home_descriptor = os.open(
            normalized.name, _DIRECTORY_FLAGS, dir_fd=parent_descriptor
        )
        result = os.fstat(home_descriptor)
        if not stat.S_ISDIR(result.st_mode) or result.st_uid != os.getuid():
            raise ValueError("target home ownership is invalid")
        if (
            expected_home_identity is not None
            and (
                result.st_dev,
                result.st_ino,
            )
            != expected_home_identity
        ):
            raise ValueError("target home identity changed")
        return home_descriptor, (result.st_dev, result.st_ino)
    except BaseException:
        if home_descriptor is not None:
            os.close(home_descriptor)
        raise
    finally:
        os.close(parent_descriptor)


def _ensure_home(home: Path) -> None:
    """Create an absent final target-home component without ancestor creation."""

    descriptor, _identity = _prepare_home(home)
    os.close(descriptor)


@contextmanager
def locked_target_homes(homes: Mapping[Target, Path], targets: Sequence[Target]):
    """Hold persistent exclusive locks in canonical descriptor order."""

    normalized = _validate_target_sequence(homes, targets)
    current = _current_lease()
    requested_homes = frozenset(normalized.values())
    if current is not None:
        if requested_homes <= current.homes:
            yield
            return
        raise ValueError("incompatible nested target lock set")
    descriptors: list[int] = []
    home_descriptors: list[int] = []
    home_identities: dict[Path, tuple[int, int]] = {}
    try:
        for target in targets:
            home = normalized[target]
            home_descriptor, identity = _prepare_home(home)
            home_descriptors.append(home_descriptor)
            home_identities[home] = identity
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(
                    ".subagents_configs.lock", flags, 0o600, dir_fd=home_descriptor
                )
            except OSError as exc:
                raise ValueError("cannot open target lock anchor") from exc
            try:
                result = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(result.st_mode)
                    or stat.S_IMODE(result.st_mode) != 0o600
                    or result.st_uid != os.getuid()
                    or result.st_nlink != 1
                ):
                    raise ValueError("target lock anchor identity is invalid")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            except BaseException:
                os.close(descriptor)
                raise
            descriptors.append(descriptor)
        lease = _LockLease(
            _execution_owner(), frozenset(normalized.values()), home_identities
        )
        lease_token = _LOCK_LEASE.set(lease)
        try:
            yield
        finally:
            lease.released = True
            _LOCK_LEASE.reset(lease_token)
    finally:
        for descriptor in reversed(descriptors):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        for descriptor in reversed(home_descriptors):
            os.close(descriptor)


def capture_evidence(path: Path, label: str) -> IdentityEvidence | None:
    from .filesystem import capture_evidence

    return capture_evidence(path, label)


def compare_and_swap(
    path: Path,
    before: IdentityEvidence | None,
    after_content: bytes | None,
    after_mode: int | None,
    action: str,
) -> IdentityEvidence | None:
    from .filesystem import compare_and_swap

    return compare_and_swap(path, before, after_content, after_mode, action)


__all__ = [
    "IdentityEvidence",
    "capture_evidence",
    "compare_and_swap",
    "homes_locked",
    "lock_held",
    "locked_target_homes",
]
