#!/usr/bin/env python3
"""Run the repository's one canonical, read-only validation sequence."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from hashlib import sha256
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
_BACKEND_PROBE = (
    "import os,stat\n"
    "from pathlib import Path\n"
    "marker=Path(os.environ['TMPDIR']).joinpath('validator-backend-marker')\n"
    "marker.write_text('ok')\n"
    "marker.chmod(0o600)\n"
    "if stat.S_IMODE(marker.stat().st_mode) != 0o600: raise SystemExit(12)\n"
)


def _fixed_executable(path: Path, *, label: str, root_owned: bool) -> Path:
    """Return a fixed, non-link executable or fail closed."""

    if not path.is_absolute() or path != path.resolve(strict=False):
        raise OSError(f"unsafe {label}")
    item = os.lstat(path)
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise OSError(f"unsafe {label}")
    owners = {0} if root_owned else {os.getuid()}
    if item.st_uid not in owners:
        raise OSError(f"unsafe {label}")
    if stat.S_IMODE(item.st_mode) & 0o022:
        raise OSError(f"unsafe {label}")
    if not item.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise OSError(f"unsafe {label}")
    return path


def _fixed_tools() -> tuple[Path, Path, Path, Path]:
    """Resolve tools from reviewed absolute locations, never from PATH."""

    python = _fixed_executable(
        Path(sys.executable), label="Python interpreter", root_owned=False
    )
    ruff = _fixed_executable(
        python.parent / "ruff", label="Ruff executable", root_owned=False
    )
    shell = _fixed_executable(Path("/bin/sh"), label="shell", root_owned=True)
    git = None
    for candidate in (Path("/usr/bin/git"), Path("/bin/git")):
        try:
            git = _fixed_executable(candidate, label="git", root_owned=True)
        except OSError:
            continue
        break
    if git is None:
        raise OSError("no reviewed git executable")
    return python, ruff, shell, git


def _run(
    argv: Sequence[str], *, env: dict[str, str], cwd: Path
) -> tuple[int, str, str]:
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
        return 126, "", ""
    return completed.returncode, completed.stdout, completed.stderr


def _diagnostic(label: str, status: str, stdout: str, stderr: str) -> str:
    def metadata(value: str) -> tuple[int, str]:
        encoded = value.encode("utf-8", errors="replace")
        return len(encoded), sha256(encoded).hexdigest()

    stdout_bytes, stdout_digest = metadata(stdout)
    stderr_bytes, stderr_digest = metadata(stderr)
    return (
        f"validation failed: {label}; status={status}; "
        f"stdout-bytes={stdout_bytes}; stdout-sha256={stdout_digest}; "
        f"stderr-bytes={stderr_bytes}; stderr-sha256={stderr_digest}"
    )


def _status(code: int) -> str:
    return f"exit-{code}" if code >= 0 else f"signal-{abs(code)}"


def _environment(root: Path) -> dict[str, str]:
    home = root / "home"
    tmp = root / "tmp"
    cache = root / "cache"
    config = root / "config"
    pycache = root / "pycache"
    ruff_cache = root / "ruff-cache"
    for directory in (home, tmp, cache, config, pycache, ruff_cache):
        directory.mkdir(mode=0o700)
    environment = {
        key: os.environ[key]
        for key in ("CI", "LANG", "LC_ALL", "VALIDATION_SYSTEM_PYTHON")
        if key in os.environ
    }
    environment.update(
        {
            "HOME": str(home),
            # This is a fixed child PATH for test helpers, not tool discovery:
            # every validator-owned executable is resolved by _fixed_tools().
            "PATH": os.pathsep.join(
                (str(Path(sys.executable).parent), "/usr/bin", "/bin")
            ),
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


def _checks(
    tools: tuple[Path, Path, Path, Path],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    python, ruff, shell, git = (str(item) for item in tools)
    return (
        ("catalog validation", (python, "scripts/validate-catalogs.py")),
        (
            "unit test discovery",
            (
                python,
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
            (ruff, "check", "claude-code", "subagents_configs", "scripts", "tests"),
        ),
        (
            "Ruff format",
            (
                ruff,
                "format",
                "--check",
                "claude-code",
                "subagents_configs",
                "scripts",
                "tests",
            ),
        ),
        ("shell syntax", (shell, "-n", *_SHELL_FILES)),
        (
            "compileall",
            (
                python,
                "-m",
                "compileall",
                "-q",
                "claude-code",
                "subagents_configs",
                "scripts",
                "tests",
            ),
        ),
        ("backend gate", ()),
        ("git diff check", (git, "diff", "--check")),
        ("clean checkout", (git, "status", "--short")),
    )


def _backend_gate(repo_root: Path, *, env: dict[str, str]) -> tuple[int, str, str]:
    """Run one direct isolated probe and require typed backend evidence."""

    inherited = dict(os.environ)
    try:
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        from scripts.validation_isolation.runner import (
            _trusted_system_interpreter,
            run_isolated,
        )

        os.environ.clear()
        os.environ.update(env)
        python = _trusted_system_interpreter(
            sys.platform, env.get("VALIDATION_SYSTEM_PYTHON")
        )
        result = run_isolated(
            (str(python), "-c", _BACKEND_PROBE), repo_root, sys.platform
        )
    except (ImportError, OSError, RuntimeError, ValueError, TimeoutError):
        return 125, "", ""
    finally:
        os.environ.clear()
        os.environ.update(inherited)
    if result.returncode == 0 and "probe=passed" in result.evidence:
        return 0, result.stdout, result.stderr
    return result.returncode or 1, result.stdout, result.stderr


def main(argv: Sequence[str] = ()) -> int:
    arguments = tuple(argv)
    if arguments:
        print("canonical repository validator accepts no arguments", file=sys.stderr)
        return 2

    repo_root = SCRIPT_PATH.resolve().parents[1]
    try:
        tools = _fixed_tools()
        temporary_parent = "/private/tmp" if Path("/private/tmp").is_dir() else None
        with tempfile.TemporaryDirectory(
            prefix="subagents-validation-", dir=temporary_parent
        ) as temporary:
            validation_root = Path(temporary)
            environment = _environment(validation_root)
            for label, command in _checks(tools):
                check_environment = dict(environment)
                check_environment["VALIDATION_SMOKE_MODE"] = (
                    "required" if label == "backend gate" else "optional"
                )
                if label == "backend gate":
                    result, stdout, stderr = _backend_gate(
                        repo_root, env=check_environment
                    )
                else:
                    result, stdout, stderr = _run(
                        command, env=check_environment, cwd=repo_root
                    )
                if result != 0:
                    print(
                        _diagnostic(label, _status(result), stdout, stderr),
                        file=sys.stderr,
                    )
                    return 1
                if label == "clean checkout" and stdout:
                    print(_diagnostic(label, "dirty", stdout, stderr), file=sys.stderr)
                    return 1
    except (OSError, RuntimeError):
        print(
            _diagnostic("private validation environment", "blocked", "", ""),
            file=sys.stderr,
        )
        return 1
    print("repository validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(tuple(sys.argv[1:])))
