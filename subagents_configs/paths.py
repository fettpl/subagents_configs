"""Lexical path containment and non-following filesystem checks."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path, PurePosixPath


def normalized_absolute(path: Path) -> Path:
    """Return an absolute, lexically normalized path without resolving links."""

    if not isinstance(path, Path):
        path = Path(path)
    return Path(os.path.normpath(os.path.abspath(os.fspath(path.expanduser()))))


def strict_relative_path(value: str) -> PurePosixPath:
    """Parse a state path, accepting only strict relative POSIX components."""

    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("path must be a non-empty relative path")
    # State paths are portable identifiers, not host-native paths.  Reject
    # backslashes and drive prefixes even when running on POSIX.
    if "\\" in value or (len(value) >= 2 and value[1] == ":"):
        raise ValueError(f"invalid relative path: {value!r}")
    if value.startswith("/"):
        raise ValueError(f"path must be relative: {value!r}")
    components = value.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise ValueError(f"path contains an invalid component: {value!r}")
    return PurePosixPath(*components)


def lstat_existing(path: Path, label: str) -> os.stat_result | None:
    """Lstat *path*, returning ``None`` only when it does not exist.

    A symlink is rejected rather than being returned, so callers cannot
    accidentally use a result that was obtained by following an attacker-
    controlled link later in the operation.
    """

    try:
        result = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None
        if exc.errno == errno.ENOTDIR:
            raise ValueError(f"{label} has a non-directory component: {path}") from exc
        raise OSError(f"cannot inspect {label}: {path}") from exc
    if stat.S_ISLNK(result.st_mode):
        raise ValueError(f"{label} must not be a symlink: {path}")
    return result


def _existing_components(path: Path, label: str) -> list[tuple[Path, os.stat_result]]:
    """Lstat every existing lexical component of an absolute path."""

    absolute = normalized_absolute(path)
    current = Path(absolute.anchor)
    components: list[tuple[Path, os.stat_result]] = []
    root_stat = lstat_existing(current, label)
    if root_stat is not None:
        components.append((current, root_stat))
    for component in absolute.parts[1:]:
        current /= component
        result = lstat_existing(current, label)
        if result is None:
            break
        components.append((current, result))
    return components


def assert_contained(home: Path, candidate: Path) -> None:
    """Require candidate to be lexically below (or equal to) home."""

    normalized_home = normalized_absolute(home)
    normalized_candidate = normalized_absolute(candidate)
    try:
        normalized_candidate.relative_to(normalized_home)
    except ValueError as exc:
        raise ValueError(
            f"candidate path is outside home: {normalized_candidate}"
        ) from exc


def assert_safe_home(home: Path) -> None:
    """Validate all existing home components and require the home be a dir."""

    absolute = normalized_absolute(home)
    components = _existing_components(absolute, "home")
    for component, result in components[:-1]:
        if not stat.S_ISDIR(result.st_mode):
            raise ValueError(f"home component is not a directory: {component}")
    result = lstat_existing(absolute, "home")
    if result is not None and not stat.S_ISDIR(result.st_mode):
        raise ValueError(f"home is not a directory: {absolute}")


def assert_safe_managed_path(home: Path, candidate: Path, label: str) -> None:
    """Validate containment and every existing component of a managed path."""

    normalized_home = normalized_absolute(home)
    normalized_candidate = normalized_absolute(candidate)
    assert_contained(normalized_home, normalized_candidate)
    if normalized_candidate == normalized_home:
        raise ValueError(f"{label} must not be the home directory")

    components = _existing_components(normalized_candidate, label)
    for component, result in components[:-1]:
        if not stat.S_ISDIR(result.st_mode):
            raise ValueError(f"{label} component is not a directory: {component}")
    result = lstat_existing(normalized_candidate, label)
    if result is not None and not stat.S_ISREG(result.st_mode):
        raise ValueError(f"{label} is not a regular file: {normalized_candidate}")
