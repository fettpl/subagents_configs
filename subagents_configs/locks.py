"""Persistent per-target transaction locks and identity evidence."""

from __future__ import annotations

import asyncio
import ctypes
import errno
import fcntl
import os
import platform
import secrets
import stat
import sys
import threading
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from types import MappingProxyType

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
        bindings: Mapping[Target, Path],
        identities: dict[Path, tuple[int, int]],
    ) -> None:
        self.owner = owner
        self.bindings = MappingProxyType(dict(bindings))
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


def _after_home_mkdir(home: Path) -> None:
    """Race-test seam between creating and opening an absent final home."""


def _after_home_publish(home: Path) -> None:
    """Race-test seam after exclusive publication and before final proof."""


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    """Publish one directory entry without replacing an existing destination."""

    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = getattr(libc, "renameatx_np", None)
        if function is None:
            raise ValueError("exclusive home publication is unavailable")
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(
            parent_fd,
            source_bytes,
            parent_fd,
            destination_bytes,
            0x00000004,
        )
    elif sys.platform == "linux":
        function = getattr(libc, "renameat2", None)
        if function is not None:
            function.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            function.restype = ctypes.c_int
            result = function(
                parent_fd,
                source_bytes,
                parent_fd,
                destination_bytes,
                0x00000001,
            )
        else:
            syscall_numbers = {
                "x86_64": 316,
                "aarch64": 276,
                "arm64": 276,
                "riscv64": 276,
            }
            number = syscall_numbers.get(platform.machine())
            syscall = getattr(libc, "syscall", None)
            if number is None or syscall is None:
                raise ValueError("exclusive home publication is unavailable")
            syscall.argtypes = [
                ctypes.c_long,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            syscall.restype = ctypes.c_long
            result = syscall(
                number,
                parent_fd,
                source_bytes,
                parent_fd,
                destination_bytes,
                0x00000001,
            )
    else:
        raise ValueError("exclusive home publication is unavailable")
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(destination)
    if error in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP):
        raise ValueError("exclusive home publication is unavailable")
    raise OSError(error, "exclusive home publication failed")


def _cleanup_owned_directory(
    parent_fd: int, name: str, identity: tuple[int, int]
) -> None:
    """Remove only an empty directory whose identity we captured ourselves."""

    try:
        result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(result.st_mode) and (result.st_dev, result.st_ino) == identity:
        os.rmdir(name, dir_fd=parent_fd)


def _create_and_publish_home(
    parent_fd: int, normalized: Path
) -> tuple[int, tuple[int, int]]:
    """Create, bind, and exclusively publish an absent final home directory."""

    temporary_name = None
    for _attempt in range(16):
        candidate = f".{normalized.name}.tmp-{secrets.token_hex(16)}"
        try:
            os.mkdir(candidate, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        temporary_name = candidate
        break
    if temporary_name is None:
        raise ValueError("cannot allocate private home publication")

    descriptor = None
    temporary_identity = None
    identity = None
    published = False
    try:
        created = os.stat(temporary_name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(created.st_mode) or created.st_uid != os.getuid():
            raise ValueError("target home ownership is invalid")
        temporary_identity = (created.st_dev, created.st_ino)
        descriptor = os.open(temporary_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        result = os.fstat(descriptor)
        opened_identity = (result.st_dev, result.st_ino)
        if opened_identity != temporary_identity:
            raise ValueError("temporary home identity changed")
        if not stat.S_ISDIR(result.st_mode) or result.st_uid != os.getuid():
            raise ValueError("target home ownership is invalid")
        identity = opened_identity
        _after_home_mkdir(normalized)
        try:
            _rename_noreplace(parent_fd, temporary_name, normalized.name)
        except FileExistsError as exc:
            raise ValueError("target home appeared during publication") from exc
        published = True
        _after_home_publish(normalized)
        final = os.stat(normalized.name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(final.st_mode) or not stat.S_ISDIR(final.st_mode):
            raise ValueError("target home must be a private directory")
        if (final.st_dev, final.st_ino) != identity:
            raise ValueError("target home identity changed")
        return descriptor, identity
    except BaseException:
        cleanup_identity = identity or temporary_identity
        if cleanup_identity is not None:
            cleanup_name = normalized.name if published else temporary_name
            _cleanup_owned_directory(parent_fd, cleanup_name, cleanup_identity)
        if descriptor is not None:
            os.close(descriptor)
        raise


def lock_held() -> bool:
    """Return whether this execution context already owns target locks."""

    return _current_lease() is not None


def homes_locked(homes: Mapping[Target, Path]) -> bool:
    """Return whether every requested home is held by this context."""

    requested = {target: normalized_absolute(path) for target, path in homes.items()}
    lease = _current_lease()
    if lease is None or any(
        lease.bindings.get(target) != home for target, home in requested.items()
    ):
        return False
    for home in requested.values():
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
                return _create_and_publish_home(parent_descriptor, normalized)
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
    if current is not None:
        if all(
            current.bindings.get(target) == home for target, home in normalized.items()
        ):
            if any(not _locked_home_path_matches(home) for home in normalized.values()):
                raise ValueError("locked target home identity changed")
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
        lease = _LockLease(_execution_owner(), normalized, home_identities)
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
