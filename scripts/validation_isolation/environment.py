"""Build the exact, empty-derived environment for a validation child."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path

from .errors import EnvironmentBuildError

SAFE_ENV_KEYS = frozenset(
    {
        "CI",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
    }
)


def _absolute_without_symlinks(
    path: Path, label: str, *, allow_missing_final: bool = False
) -> Path:
    if not path.is_absolute():
        raise EnvironmentBuildError(f"{label} must be absolute")
    if any(component in (".", "..") for component in path.parts[1:]):
        raise EnvironmentBuildError(f"{label} contains traversal components")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            item = os.lstat(current)
        except FileNotFoundError as exc:
            if allow_missing_final and current == path:
                break
            raise EnvironmentBuildError(f"{label} does not exist") from exc
        # macOS exposes the system temporary tree through the conventional
        # ``/var`` alias.  It is a fixed platform alias, not a user-controlled
        # component; all user-controlled components remain no-follow.
        if stat.S_ISLNK(item.st_mode) and not (
            current == Path("/var")
            and Path(os.path.realpath(current)) == Path("/private/var")
        ):
            raise EnvironmentBuildError(f"{label} contains a symlink")
    return path


def _private_directory(path: Path, label: str) -> os.stat_result:
    _absolute_without_symlinks(path, label, allow_missing_final=True)
    parent_descriptor = _open_directory(path.parent, f"{label} parent")
    try:
        try:
            item = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            os.mkdir(path.name, 0o700, dir_fd=parent_descriptor)
            item = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            raise EnvironmentBuildError(f"{label} is not a directory")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        try:
            item = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if stat.S_IMODE(item.st_mode) & 0o077:
            raise EnvironmentBuildError(f"{label} is not private")
        owner = os.getuid() if hasattr(os, "getuid") else item.st_uid
        if item.st_uid not in (0, owner):
            raise EnvironmentBuildError(f"{label} has an unexpected owner")
        return item
    except OSError as exc:
        raise EnvironmentBuildError(f"{label} is unsafe") from exc
    finally:
        os.close(parent_descriptor)


def _open_directory(path: Path, label: str) -> int:
    if path.parts[1:2] == ("var",) and Path("/var").is_symlink():
        if Path(os.path.realpath("/var")) != Path("/private/var"):
            raise EnvironmentBuildError(f"{label} contains an unexpected system alias")
        path = Path("/private/var", *path.parts[2:])
    descriptor = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise EnvironmentBuildError(f"{label} is unsafe") from exc


def _validate_temp_root(temp_root: Path) -> Path:
    if not temp_root.is_absolute():
        raise EnvironmentBuildError("temp_root must be absolute")
    _absolute_without_symlinks(temp_root, "temp_root")
    item = _private_directory(temp_root, "temp_root")
    owner = os.getuid() if hasattr(os, "getuid") else item.st_uid
    if item.st_uid not in (0, owner):
        raise EnvironmentBuildError("temp_root has an unexpected owner")
    return temp_root


def _validate_executable_directory(path: Path) -> tuple[os.stat_result, Path]:
    _absolute_without_symlinks(path, "executable directory")
    canonical = path.resolve(strict=True)
    if path != canonical and not (
        path.parts[1:2] == ("var",)
        and Path(os.path.realpath("/var")) == Path("/private/var")
    ):
        raise EnvironmentBuildError("executable directory is not canonical")
    descriptor = _open_directory(canonical, "executable directory")
    try:
        item = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if stat.S_IMODE(item.st_mode) & 0o022:
        raise EnvironmentBuildError("executable directory is writable by group/other")
    if not item.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise EnvironmentBuildError("executable directory is not searchable")
    owner = os.getuid() if hasattr(os, "getuid") else item.st_uid
    if item.st_uid not in (0, owner):
        raise EnvironmentBuildError("executable directory has an unexpected owner")
    return item, canonical


def build_child_environment(
    source_env: Mapping[str, str],
    temp_root: Path,
    executable_dirs: Sequence[Path],
) -> dict[str, str]:
    """Return a sterile environment without reading any source value.

    ``source_env`` is intentionally accepted for the public interface but is
    never consulted.  This makes accidental future allowlisting impossible;
    all returned values are derived from the validated private root and fixed
    system directories, so hostile caller environment values cannot cross the
    child-process boundary.
    """

    del source_env
    root = _validate_temp_root(temp_root)
    names = ("home", "tmp", "cache", "config")
    directories: dict[str, Path] = {}
    identities: set[tuple[int, int]] = {(os.lstat(root).st_dev, os.lstat(root).st_ino)}
    for name in names:
        path = root / name
        item = _private_directory(path, name)
        identity = (item.st_dev, item.st_ino)
        if identity in identities:
            raise EnvironmentBuildError("private environment directories alias")
        identities.add(identity)
        directories[name] = path

    path_entries: list[str] = []
    executable_identities: set[tuple[int, int]] = set()
    for executable_dir in executable_dirs:
        item, canonical = _validate_executable_directory(executable_dir)
        identity = (item.st_dev, item.st_ino)
        if identity not in executable_identities:
            executable_identities.add(identity)
            path_entries.append(str(canonical))

    if not path_entries:
        raise EnvironmentBuildError(
            "at least one trusted executable directory is required"
        )

    return {
        "CI": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(directories["home"]),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.pathsep.join(path_entries),
        "TMPDIR": str(directories["tmp"]),
        "XDG_CACHE_HOME": str(directories["cache"]),
        "XDG_CONFIG_HOME": str(directories["config"]),
    }
