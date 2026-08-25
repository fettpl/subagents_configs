#!/usr/bin/env python3
"""Run the repository's one canonical, read-only validation sequence."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

SCRIPT_PATH = Path(__file__)
_SHELL_FILES = (
    "install.sh",
    "uninstall.sh",
    "install-codex.sh",
    "uninstall-codex.sh",
    "install-opencode.sh",
    "uninstall-opencode.sh",
    "install-claude-code.sh",
    "uninstall-claude-code.sh",
)


def _run(argv: Sequence[str], *, env: dict[str, str], cwd: Path) -> tuple[int, str]:
    try:
        completed = subprocess.run(  # noqa: S603
            list(argv),
            cwd=cwd,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return 1, ""
    return completed.returncode, completed.stdout


def _environment(root: Path) -> dict[str, str]:
    home = root / "home"
    tmp = root / "tmp"
    cache = root / "cache"
    config = root / "config"
    pycache = root / "pycache"
    ruff_cache = root / "ruff-cache"
    for directory in (home, tmp, cache, config, pycache, ruff_cache):
        directory.mkdir(mode=0o700)
    path_entries = [str(Path(sys.executable).parent)]
    for candidate in (
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
        Path("/usr/bin"),
        Path("/bin"),
    ):
        if candidate.is_dir() and candidate not in [
            Path(item) for item in path_entries
        ]:
            path_entries.append(str(candidate))
    environment = {
        key: os.environ[key]
        for key in ("CI", "LANG", "LC_ALL", "VALIDATION_SYSTEM_PYTHON")
        if key in os.environ
    }
    environment.update(
        {
            "HOME": str(home),
            "PATH": os.pathsep.join(path_entries),
            "TMPDIR": str(tmp),
            "XDG_CACHE_HOME": str(cache),
            "XDG_CONFIG_HOME": str(config),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": str(pycache),
            "RUFF_CACHE_DIR": str(ruff_cache),
            "VALIDATION_SMOKE_MODE": "required",
        }
    )
    return environment


def _checks() -> tuple[tuple[str, tuple[str, ...]], ...]:
    python = (sys.executable,)
    return (
        ("catalog validation", (*python, "scripts/validate-catalogs.py")),
        (
            "unit test discovery",
            (
                *python,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_*.py",
                "-q",
            ),
        ),
        (
            "Ruff check",
            ("ruff", "check", "claude-code", "subagents_configs", "scripts", "tests"),
        ),
        (
            "Ruff format",
            (
                "ruff",
                "format",
                "--check",
                "claude-code",
                "subagents_configs",
                "scripts",
                "tests",
            ),
        ),
        ("shell syntax", ("sh", "-n", *_SHELL_FILES)),
        (
            "compileall",
            (
                *python,
                "-m",
                "compileall",
                "-q",
                "claude-code",
                "subagents_configs",
                "scripts",
                "tests",
            ),
        ),
        (
            "backend gate",
            (
                *python,
                "-m",
                "unittest",
                "tests.test_validation_backend.BackendIntegrationTests",
                "tests.test_validation_smoke",
                "-v",
            ),
        ),
        ("git diff check", ("git", "diff", "--check")),
        ("clean checkout", ("git", "status", "--short")),
    )


def main(argv: Sequence[str] = ()) -> int:
    arguments = tuple(argv)
    if arguments:
        print("canonical repository validator accepts no arguments", file=sys.stderr)
        return 2

    repo_root = SCRIPT_PATH.resolve().parents[1]
    try:
        temporary_parent = "/private/tmp" if Path("/private/tmp").is_dir() else None
        with tempfile.TemporaryDirectory(
            prefix="subagents-validation-", dir=temporary_parent
        ) as temporary:
            validation_root = Path(temporary)
            environment = _environment(validation_root)
            for label, command in _checks():
                check_environment = dict(environment)
                check_environment["VALIDATION_SMOKE_MODE"] = (
                    "required" if label == "backend gate" else "optional"
                )
                result, output = _run(command, env=check_environment, cwd=repo_root)
                if result != 0:
                    print(f"validation failed: {label}", file=sys.stderr)
                    return 1
                if label == "clean checkout":
                    if output:
                        print(
                            "validation failed: checkout is not clean", file=sys.stderr
                        )
                        return 1
    except (OSError, RuntimeError):
        print("validation failed: private validation environment", file=sys.stderr)
        return 1
    print("repository validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(tuple(sys.argv[1:])))
