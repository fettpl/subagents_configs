"""Immutable public data returned by the validation-isolation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class SnapshotFile:
    relative_path: PurePosixPath
    exists: bool
    sha256: str | None
    mode: int | None


@dataclass(frozen=True)
class CheckoutState:
    git_status: bytes
    files: tuple[SnapshotFile, ...]


@dataclass(frozen=True)
class GitSnapshot:
    worktree: Path
    snapshot_root: Path
    before: CheckoutState
