"""Fixtures shared by the validation-isolation tests."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_AUTHOR_NAME": "Validation Tests",
    "GIT_AUTHOR_EMAIL": "validation@example.invalid",
    "GIT_COMMITTER_NAME": "Validation Tests",
    "GIT_COMMITTER_EMAIL": "validation@example.invalid",
}


def system_executable(name: str) -> Path:
    """Return a canonical fixed system executable or skip its dependent test."""

    candidate = Path("/usr/bin") / name
    try:
        resolved = candidate.resolve(strict=True)
        item = os.lstat(resolved)
    except (OSError, RuntimeError) as exc:
        raise unittest.SkipTest(
            f"system executable is unavailable: {candidate}"
        ) from exc
    if not stat.S_ISREG(item.st_mode) or not item.st_mode & (
        stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    ):
        raise unittest.SkipTest(f"system executable is unusable: {candidate}")
    return resolved


def trusted_parent_tempdir():
    """Create a fixture below the checkout when its full parent chain is trusted."""

    root = Path(__file__).parents[1].resolve()
    current = Path(root.anchor)
    allowed_owners = {0}
    if hasattr(os, "getuid"):
        allowed_owners.add(os.getuid())
    for component in root.parts[1:]:
        current /= component
        try:
            item = os.lstat(current)
        except OSError as exc:
            raise unittest.SkipTest("trusted fixture root is unavailable") from exc
        if (
            stat.S_ISLNK(item.st_mode)
            or not stat.S_ISDIR(item.st_mode)
            or item.st_uid not in allowed_owners
            or stat.S_IMODE(item.st_mode) & 0o022
        ):
            raise unittest.SkipTest("checkout parent chain is not trusted")
    return tempfile.TemporaryDirectory(prefix=".validation-fixture-", dir=root)


def git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment.update(GIT_ENV)
    return subprocess.run(  # noqa: S603
        ["/usr/bin/git", *arguments],
        cwd=repository,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
    )


def make_repository(root: Path) -> Path:
    repository = root / "repository"
    repository.mkdir()
    git(repository, "init", "--quiet")
    (repository / ".gitignore").write_text(
        "ignored.txt\n.env*\n.envrc\ncache/\nnode_modules/\n", encoding="utf-8"
    )
    (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    (repository / "script.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(repository / "script.sh", 0o755)  # noqa: S103
    git(repository, "add", "--all")
    git(repository, "commit", "--quiet", "-m", "initial")
    return repository


def complete_process(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=("git",), returncode=returncode, stdout=stdout, stderr=stderr
    )
