"""Persistent per-target transaction locks and identity evidence."""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from .models import Target
from .paths import assert_safe_home, normalized_absolute
from .targets import DESCRIPTOR_ORDER

_LOCK_DEPTH: ContextVar[int] = ContextVar("subagents_configs_lock_depth", default=0)
_LOCK_HOMES: ContextVar[frozenset[Path]] = ContextVar(
    "subagents_configs_lock_homes", default=frozenset()
)


def lock_held() -> bool:
    """Return whether this execution context already owns target locks."""

    return _LOCK_DEPTH.get() > 0


def homes_locked(homes: Mapping[Target, Path]) -> bool:
    """Return whether every requested home is held by this context."""

    requested = frozenset(normalized_absolute(path) for path in homes.values())
    return requested <= _LOCK_HOMES.get()


@dataclass(frozen=True)
class IdentityEvidence:
    device: int
    inode: int
    size: int
    nlink: int
    mode: int
    sha256: str


def _validate_target_sequence(homes: Mapping[Target, Path], targets: Sequence[Target]):
    requested = tuple(targets)
    if not requested or len(set(requested)) != len(requested):
        raise ValueError("lock targets must be unique")
    expected = tuple(target for target in DESCRIPTOR_ORDER if target in requested)
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


def _ensure_home(home: Path) -> None:
    """Create an absent target home as the private lock substrate."""

    assert_safe_home(home)
    try:
        home.mkdir(mode=0o700, parents=True)
    except FileExistsError:
        pass
    result = home.lstat()
    if not stat.S_ISDIR(result.st_mode):
        raise ValueError("target home must be a private directory")
    if result.st_uid != os.getuid():
        raise ValueError("target home ownership is invalid")


@contextmanager
def locked_target_homes(homes: Mapping[Target, Path], targets: Sequence[Target]):
    """Hold persistent exclusive locks in canonical descriptor order."""

    normalized = _validate_target_sequence(homes, targets)
    # Validate/create all directory substrates before opening any lock.
    for home in normalized.values():
        _ensure_home(home)
    descriptors: list[int] = []
    try:
        for target in targets:
            home = normalized[target]
            anchor = home / ".subagents_configs.lock"
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(anchor, flags, 0o600)
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
        token = _LOCK_DEPTH.set(_LOCK_DEPTH.get() + 1)
        homes_token = _LOCK_HOMES.set(
            _LOCK_HOMES.get() | frozenset(normalized.values())
        )
        try:
            yield
        finally:
            _LOCK_HOMES.reset(homes_token)
            _LOCK_DEPTH.reset(token)
    finally:
        for descriptor in reversed(descriptors):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def capture_evidence(path: Path, label: str) -> IdentityEvidence | None:
    from .filesystem import capture_evidence as _capture

    return _capture(path, label)


def compare_and_swap(
    path: Path,
    before: IdentityEvidence | None,
    after_content: bytes | None,
    after_mode: int | None,
    action: str,
) -> IdentityEvidence | None:
    from .filesystem import compare_and_swap as _compare_and_swap

    return _compare_and_swap(path, before, after_content, after_mode, action)


__all__ = [
    "IdentityEvidence",
    "capture_evidence",
    "compare_and_swap",
    "homes_locked",
    "lock_held",
    "locked_target_homes",
]
