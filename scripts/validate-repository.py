#!/usr/bin/env python3
"""Run the repository's one canonical, read-only validation sequence."""

from __future__ import annotations

import os
import re
import selectors
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path
from time import monotonic

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
_CAPTURE_LIMIT = 8192
_DIRECT_CHECK_TIMEOUT = 900.0
_UNIT_DIAGNOSTIC_MAX_ITEMS = 8
_UNIT_DIAGNOSTIC_MAX_ITEM_LENGTH = 160
_UNIT_HEADER = re.compile(
    r"^(?P<kind>FAIL|ERROR): (?P<test>test[A-Za-z0-9_]*) "
    r"\((?P<scope>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\)"
    r"(?: \([ -~]{1,160}\))?$"
)
_UNIT_REASON = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Failure))(?::.*)?$"
)


class _StreamCapture:
    """Bounded displayed bytes plus complete stream accounting."""

    __slots__ = ("byte_count", "sha256", "text")

    def __init__(self, text: str, byte_count: int, digest: str) -> None:
        self.text = text
        self.byte_count = byte_count
        self.sha256 = digest


class _CheckResult:
    __slots__ = ("returncode", "stderr", "stdout")

    def __init__(
        self, returncode: int, stdout: _StreamCapture, stderr: _StreamCapture
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _StreamAccumulator:
    def __init__(self) -> None:
        self._captured = bytearray()
        self._byte_count = 0
        self._digest = sha256()

    def feed(self, chunk: bytes) -> None:
        self._byte_count += len(chunk)
        self._digest.update(chunk)
        remaining = _CAPTURE_LIMIT - len(self._captured)
        if remaining > 0:
            self._captured.extend(chunk[:remaining])

    def finish(self) -> _StreamCapture:
        # Ignoring an incomplete final UTF-8 sequence keeps the displayed
        # representation no larger than the byte capture cap.
        return _StreamCapture(
            bytes(self._captured).decode("utf-8", errors="ignore"),
            self._byte_count,
            self._digest.hexdigest(),
        )


def _stream_from_text(value: str) -> _StreamCapture:
    accumulator = _StreamAccumulator()
    accumulator.feed(value.encode("utf-8", errors="replace"))
    return accumulator.finish()


def _result(returncode: int, stdout: str = "", stderr: str = "") -> _CheckResult:
    return _CheckResult(
        returncode, _stream_from_text(stdout), _stream_from_text(stderr)
    )


def _coerce_result(value: object) -> _CheckResult:
    """Keep test seams typed while accepting the former tuple seam."""

    if isinstance(value, _CheckResult):
        return value
    if isinstance(value, tuple) and len(value) == 3:
        return _result(value[0], value[1], value[2])
    raise TypeError("invalid validation result")


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


def _fixed_candidate(
    candidates: Sequence[Path], *, label: str, root_owned: bool
) -> Path:
    """Select the first reviewed candidate that passes all trust checks."""

    for candidate in candidates:
        try:
            return _fixed_executable(candidate, label=label, root_owned=root_owned)
        except OSError:
            continue
    raise OSError(f"no reviewed {label} executable")


def _fixed_tools() -> tuple[Path, Path, Path, Path]:
    """Resolve tools from reviewed absolute locations, never from PATH."""

    python = _fixed_executable(
        Path(sys.executable), label="Python interpreter", root_owned=False
    )
    ruff = _fixed_executable(
        python.parent / "ruff", label="Ruff executable", root_owned=False
    )
    shell = _fixed_candidate(
        (Path("/usr/bin/dash"), Path("/bin/sh")),
        label="shell",
        root_owned=True,
    )
    git = _fixed_candidate(
        (Path("/usr/bin/git"), Path("/bin/git")),
        label="git",
        root_owned=True,
    )
    return python, ruff, shell, git


def _run(argv: Sequence[str], *, env: dict[str, str], cwd: Path) -> _CheckResult:
    try:
        process = subprocess.Popen(  # noqa: S603
            list(argv),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
        )
    except OSError:
        return _result(126)

    stdout = _StreamAccumulator()
    stderr = _StreamAccumulator()
    streams = ((process.stdout, stdout), (process.stderr, stderr))
    selector = selectors.DefaultSelector()
    read_failed = False
    timed_out = False
    reaped = False
    for stream, accumulator in streams:
        if stream is None:
            read_failed = True
            continue
        selector.register(stream, selectors.EVENT_READ, accumulator)
    deadline = monotonic() + _DIRECT_CHECK_TIMEOUT
    try:
        while selector.get_map():
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
                if process.poll() is None:
                    process.kill()
                break
            events = selector.select(remaining)
            if not events:
                continue
            for key, _ in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except OSError:
                    read_failed = True
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if chunk:
                    key.data.feed(chunk)
                else:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
    finally:
        if not timed_out:
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
            else:
                try:
                    # EOF only says that both captured streams are closed; the
                    # child may still be completing.  Observe its exit within
                    # the same overall deadline before classifying a timeout.
                    process.wait(timeout=remaining)
                    reaped = True
                except subprocess.TimeoutExpired:
                    timed_out = True
        if timed_out and process.poll() is None:
            process.kill()
        selector.close()
        if not reaped:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream, _ in streams:
            if stream is not None and not stream.closed:
                stream.close()
    if read_failed:
        returncode = 126
    elif timed_out:
        returncode = 124
    else:
        returncode = process.returncode
    return _CheckResult(returncode, stdout.finish(), stderr.finish())


def _unit_diagnostic(result: _CheckResult) -> str:
    """Extract only bounded, stable unittest failure context."""

    failures: list[str] = []
    reasons: list[str] = []
    current = False
    for line in (result.stdout.text + "\n" + result.stderr.text).splitlines():
        header = _UNIT_HEADER.fullmatch(line)
        if header is not None:
            item = (
                f"{header.group('kind')}:{header.group('test')} "
                f"({header.group('scope')})"
            )
            if item not in failures and len(failures) < _UNIT_DIAGNOSTIC_MAX_ITEMS:
                failures.append(item[:_UNIT_DIAGNOSTIC_MAX_ITEM_LENGTH])
            current = True
            continue
        if not current:
            continue
        reason = _UNIT_REASON.fullmatch(line)
        if reason is None:
            continue
        category = (
            "assertion"
            if reason.group("name").rsplit(".", 1)[-1] == "AssertionError"
            else "exception"
        )
        if category not in reasons:
            reasons.append(category)

    fields = []
    if failures:
        fields.append("unit-failures=" + ",".join(failures))
    if reasons:
        fields.append("unit-reasons=" + ",".join(reasons))
    return "; ".join(fields)


def _diagnostic(label: str, status: str, result: _CheckResult) -> str:
    diagnostic = (
        f"validation failed: {label}; status={status}; "
        f"stdout-bytes={result.stdout.byte_count}; "
        f"stdout-sha256={result.stdout.sha256}; "
        f"stderr-bytes={result.stderr.byte_count}; "
        f"stderr-sha256={result.stderr.sha256}"
    )
    if label == "unit test discovery":
        details = _unit_diagnostic(result)
        if details:
            diagnostic += "; " + details
    return diagnostic


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
        key: os.environ[key] for key in ("CI", "LANG", "LC_ALL") if key in os.environ
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


def _backend_gate(repo_root: Path, *, env: dict[str, str]) -> _CheckResult:
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
        return _result(125)
    finally:
        os.environ.clear()
        os.environ.update(inherited)
    if result.returncode == 0 and "probe=passed" in result.evidence:
        return _result(0, result.stdout, result.stderr)
    return _result(result.returncode or 1, result.stdout, result.stderr)


def main(argv: Sequence[str] = ()) -> int:
    arguments = tuple(argv)
    if arguments:
        print("canonical repository validator accepts no arguments", file=sys.stderr)
        return 2

    repo_root = SCRIPT_PATH.resolve().parents[1]
    try:
        tools = _fixed_tools()
    except (OSError, RuntimeError):
        print(
            _diagnostic("fixed tool gate", "blocked", _result(1)),
            file=sys.stderr,
        )
        return 1
    try:
        configured_system_python = os.environ.get("VALIDATION_SYSTEM_PYTHON")
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
                    if configured_system_python is not None:
                        check_environment["VALIDATION_SYSTEM_PYTHON"] = (
                            configured_system_python
                        )
                    result = _coerce_result(
                        _backend_gate(repo_root, env=check_environment)
                    )
                else:
                    result = _coerce_result(
                        _run(command, env=check_environment, cwd=repo_root)
                    )
                if result.returncode != 0:
                    print(
                        _diagnostic(label, _status(result.returncode), result),
                        file=sys.stderr,
                    )
                    return 1
                if label == "clean checkout" and result.stdout.byte_count:
                    print(_diagnostic(label, "dirty", result), file=sys.stderr)
                    return 1
    except (OSError, RuntimeError):
        print(
            _diagnostic("private validation environment", "blocked", _result(1)),
            file=sys.stderr,
        )
        return 1
    print("repository validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(tuple(sys.argv[1:])))
