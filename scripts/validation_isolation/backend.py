"""Fixed, fail-closed process isolation backends."""

from __future__ import annotations

import os
import re
import socket
import stat
import subprocess
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypeAlias
from urllib.parse import unquote

from .environment import SAFE_ENV_KEYS
from .errors import ValidationIsolationError


@dataclass(frozen=True)
class BackendSpec:
    name: Literal["macos", "linux"]
    launcher: Path
    python_executable: Path
    launcher_identity: tuple[int, int] | None = field(default=None, repr=False)
    python_identity: tuple[int, int] | None = field(default=None, repr=False)


MAX_PROBE_SECONDS = 5.0
MAX_PROBE_OUTPUT = 8192
_MARKER_CONTENT = b"ok"
_TRUSTED_SYSTEM_PREFIXES = (
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
)
_SECRET_COMPONENTS = frozenset(
    {
        ".aws",
        ".config",
        ".env",
        ".ssh",
        "credential",
        "credentials",
        "id_rsa",
        "key",
        "keys",
        "passwd",
        "password",
        "secret",
        "secrets",
        "shadow",
        "socket",
        "sockets",
        "token",
        "tokens",
    }
)
ProcessRunner: TypeAlias = Callable[
    [Sequence[str], Path, Mapping[str, str], float | None],
    subprocess.CompletedProcess[str],
]


@dataclass(frozen=True)
class PrivateRootIdentity:
    """No-follow identity contract for a private host root at launch."""

    path: Path
    device: int
    inode: int
    owner: int
    nlink: int
    mode: int


def run_process(
    argv: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    timeout: float | None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        list(argv),
        cwd=cwd,
        env=dict(env),
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _regular_executable(path: Path, label: str, *, root_owned: bool) -> Path:
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts[1:]):
        raise ValidationIsolationError(f"{label} must be an absolute path")
    try:
        if path.resolve(strict=True) != path:
            raise ValidationIsolationError(f"{label} is not canonical")
    except ValidationIsolationError:
        raise
    except (OSError, RuntimeError) as exc:
        raise ValidationIsolationError(f"{label} is unavailable") from exc
    current = Path(path.anchor)
    allowed_owners = {0}
    if not root_owned and hasattr(os, "getuid"):
        allowed_owners.add(os.getuid())
    for component in path.parts[1:-1]:
        current /= component
        try:
            parent = os.lstat(current)
        except OSError as exc:
            raise ValidationIsolationError(
                f"{label} has an unsafe parent directory"
            ) from exc
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid not in allowed_owners
            or stat.S_IMODE(parent.st_mode) & 0o022
            or not parent.st_mode & stat.S_IXUSR
        ):
            raise ValidationIsolationError(f"{label} has an unsafe parent directory")
    current /= path.name
    try:
        item = os.lstat(current)
    except OSError as exc:
        raise ValidationIsolationError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise ValidationIsolationError(f"{label} is not a regular file")
    if not item.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise ValidationIsolationError(f"{label} is not executable")
    if stat.S_IMODE(item.st_mode) & 0o022:
        raise ValidationIsolationError(f"{label} is writable by group or other")
    if item.st_uid not in allowed_owners:
        raise ValidationIsolationError(f"{label} is not root-owned")
    return path


def _identity(path: Path, label: str, *, root_owned: bool) -> tuple[int, int]:
    _regular_executable(path, label, root_owned=root_owned)
    item = os.lstat(path)
    return item.st_dev, item.st_ino


def verify_backend(backend: BackendSpec) -> None:
    launcher_identity = _identity(backend.launcher, "sandbox launcher", root_owned=True)
    python_identity = _identity(
        backend.python_executable, "validation interpreter", root_owned=False
    )
    if (
        getattr(backend, "launcher_identity", None) is not None
        and launcher_identity != backend.launcher_identity
    ):
        raise ValidationIsolationError("sandbox launcher changed before launch")
    if (
        getattr(backend, "python_identity", None) is not None
        and python_identity != backend.python_identity
    ):
        raise ValidationIsolationError("validation interpreter changed before launch")


def run_verified_process(
    backend: BackendSpec,
    argv: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    timeout: float | None,
    process_runner: ProcessRunner = run_process,
    private_roots: tuple[PrivateRootIdentity, ...] = (),
) -> subprocess.CompletedProcess[str]:
    """Verify fixed executable identities at the final process boundary."""

    verify_backend(backend)
    for expected in private_roots:
        try:
            current = _private_directory(expected.path, "private isolation root")
        except ValidationIsolationError as exc:
            raise ValidationIsolationError(
                "private isolation root changed before launch"
            ) from exc
        if current != expected:
            raise ValidationIsolationError(
                "private isolation root changed before launch"
            )
    return process_runner(argv, cwd, env, timeout)


def select_backend(
    platform_name: str,
    sandbox_exec: Path,
    bwrap: Path | None,
    python_executable: Path,
) -> BackendSpec:
    python = _regular_executable(
        python_executable, "validation interpreter", root_owned=False
    )
    if platform_name == "darwin":
        _validate_trusted_interpreter(python, "macOS")
        if sandbox_exec != Path("/usr/bin/sandbox-exec"):
            raise ValidationIsolationError("macOS requires /usr/bin/sandbox-exec")
        launcher = _regular_executable(sandbox_exec, "sandbox-exec", root_owned=True)
        return BackendSpec(
            "macos",
            launcher,
            python,
            _identity(launcher, "sandbox-exec", root_owned=True),
            _identity(python, "validation interpreter", root_owned=False),
        )
    if platform_name == "linux":
        _validate_trusted_interpreter(python, "Linux")
        if bwrap not in (Path("/usr/bin/bwrap"), Path("/bin/bwrap")):
            raise ValidationIsolationError(
                "Linux requires /usr/bin/bwrap or /bin/bwrap"
            )
        launcher = _regular_executable(bwrap, "Bubblewrap", root_owned=True)
        return BackendSpec(
            "linux",
            launcher,
            python,
            _identity(launcher, "Bubblewrap", root_owned=True),
            _identity(python, "validation interpreter", root_owned=False),
        )
    raise ValidationIsolationError(f"unsupported validation platform: {platform_name}")


def _profile_path(path: Path) -> str:
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts[1:]):
        raise ValidationIsolationError("sandbox path is unsafe")
    value = str(path)
    if any(
        character == '"'
        or character == "\\"
        or ord(character) < 0x20
        or ord(character) == 0x7F
        for character in value
    ):
        raise ValidationIsolationError("sandbox path contains unsafe Seatbelt syntax")
    return value


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _validate_trusted_interpreter(path: Path, platform_name: str) -> None:
    """Allow interpreters only from fixed, root-controlled system prefixes."""

    _regular_executable(path, "validation interpreter", root_owned=False)
    if platform_name == "macOS":
        allowed = (
            Path("/usr/bin"),
            Path("/System/Library/Frameworks/Python.framework"),
        )
    else:
        allowed = (Path("/usr/bin"), Path("/bin"), Path("/sbin"))
    if not any(_is_within(path, prefix) for prefix in allowed):
        raise ValidationIsolationError(
            f"{platform_name} validation interpreter is outside trusted system roots"
        )
    for prefix in allowed:
        if _is_within(path, prefix) and prefix.exists():
            _validate_system_directory(prefix, f"{platform_name} interpreter root")
            return
    raise ValidationIsolationError("validation interpreter root is unavailable")


def _validate_system_directory(path: Path, label: str) -> Path:
    """Validate a fixed directory without following user-controlled aliases."""

    if not path.is_absolute() or any(part in (".", "..") for part in path.parts[1:]):
        raise ValidationIsolationError(f"{label} must be an absolute canonical path")
    try:
        canonical = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValidationIsolationError(f"{label} is unavailable") from exc
    if canonical != path:
        raise ValidationIsolationError(f"{label} is not canonical")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            item = os.lstat(current)
        except OSError as exc:
            raise ValidationIsolationError(f"{label} is unavailable") from exc
        if (
            stat.S_ISLNK(item.st_mode)
            or not stat.S_ISDIR(item.st_mode)
            or item.st_uid != 0
            or stat.S_IMODE(item.st_mode) & 0o022
            or not item.st_mode & stat.S_IXUSR
        ):
            raise ValidationIsolationError(f"{label} is unsafe")
    return path


def _validate_private_directory(path: Path, temp_root: Path, label: str) -> None:
    if not _is_within(path, temp_root):
        raise ValidationIsolationError(f"{label} is outside the private temporary root")
    try:
        canonical = path.resolve(strict=True)
        item = os.lstat(path)
    except (OSError, RuntimeError) as exc:
        raise ValidationIsolationError(f"{label} is unavailable") from exc
    canonical_alias = path.parts[1:2] == ("var",) and canonical == Path(
        "/private/var", *path.parts[2:]
    )
    if (
        (canonical != path and not canonical_alias)
        or stat.S_ISLNK(item.st_mode)
        or not stat.S_ISDIR(item.st_mode)
    ):
        raise ValidationIsolationError(f"{label} is unsafe")
    owner = os.getuid() if hasattr(os, "getuid") else item.st_uid
    if item.st_uid not in (0, owner) or stat.S_IMODE(item.st_mode) != 0o700:
        raise ValidationIsolationError(f"{label} is not private")


def _validate_child_environment(env: Mapping[str, str], temp_root: Path) -> None:
    if set(env) != SAFE_ENV_KEYS or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in env.items()
    ):
        raise ValidationIsolationError("validation environment is not the approved set")
    expected = {
        "CI": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    for key, value in expected.items():
        if env[key] != value:
            raise ValidationIsolationError("validation environment has an unsafe value")
    for key in ("HOME", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"):
        _validate_private_directory(Path(env[key]), temp_root, key)
    if not env["PATH"]:
        raise ValidationIsolationError("validation PATH is empty")
    for entry in env["PATH"].split(os.pathsep):
        if not entry:
            raise ValidationIsolationError("validation PATH contains an empty entry")
        _validate_system_directory(Path(entry), "validation PATH entry")


def _path_has_untrusted_spelling(path: Path) -> bool:
    """Return whether an existing component is a symlink or traversal alias."""

    if not path.is_absolute() or any(part in (".", "..") for part in path.parts[1:]):
        return True
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            item = os.lstat(current)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if stat.S_ISLNK(item.st_mode):
            return True
    return False


_PATH_ESCAPE = re.compile(
    r"\\(?:"
    r"u([0-9a-fA-F]{4})|"
    r"U([0-9a-fA-F]{8})|"
    r"x([0-9a-fA-F]{2})|"
    r"N\{([^}]+)\}|"
    r"([0-7]{1,3})"
    r")"
)


def _decode_path_escapes(value: str) -> str:
    def decode(match: re.Match[str]) -> str:
        if match.group(4) is not None:
            try:
                codepoint = ord(unicodedata.lookup(match.group(4)))
            except KeyError:
                return match.group(0)
        else:
            digits = (
                match.group(1) or match.group(2) or match.group(3) or match.group(5)
            )
            base = 16 if match.group(1) or match.group(2) or match.group(3) else 8
            codepoint = int(digits, base)
        if codepoint in (0x2E, 0x2F, 0x5C):
            return chr(codepoint)
        return match.group(0)

    return _PATH_ESCAPE.sub(decode, value).replace(r"\/", "/").replace(r"\\", "\\")


def _reject_ambiguous_path_encoding(token: str) -> None:
    """Reject encoded separators/traversal before any path approval decision."""

    value = token
    for _ in range(32):
        decoded = _decode_path_escapes(unquote(value))
        if decoded == value:
            return
        if any(marker in decoded for marker in ("/", "\\", ".")):
            raise ValidationIsolationError(
                "validation command contains encoded path syntax"
            )
        value = decoded
    raise ValidationIsolationError("validation command contains encoded path syntax")


def _absolute_tokens(token: str) -> tuple[str, ...]:
    """Extract filesystem-looking absolute paths from arbitrary argv text."""

    _reject_ambiguous_path_encoding(token)
    candidates: list[str] = []
    terminators = frozenset(" \t\r\n'\"`(){}[]<>,;:")
    index = 0
    while index < len(token):
        if token[index] != "/":
            index += 1
            continue
        end = index + 1
        while end < len(token) and token[end] not in terminators:
            end += 1
        candidate = token[index:end]
        if candidate:
            candidates.append(candidate)
        index = end
    return tuple(dict.fromkeys(candidates))


def _approved_absolute_argument(
    path: Path,
    worktree: Path | None = None,
    home: Path | None = None,
    raw: str | None = None,
) -> None:
    if raw is not None:
        decoded = unquote(raw)
        if decoded != raw and any(marker in decoded for marker in ("/", "..", "\\")):
            raise ValidationIsolationError(
                "validation command contains encoded path syntax"
            )
    if _path_has_untrusted_spelling(path):
        raise ValidationIsolationError(
            "validation command contains a non-canonical path"
        )
    if worktree is not None and _is_within(path, worktree):
        raise ValidationIsolationError("validation command references the worktree")
    home_path = Path.home() if home is None else home
    if _is_within(path, home_path):
        raise ValidationIsolationError(
            "validation command references the home directory"
        )
    components = {part.casefold() for part in path.parts}
    if components & _SECRET_COMPONENTS or any(
        any(word in part.casefold() for word in ("credential", "secret", "socket"))
        for part in path.parts
    ):
        raise ValidationIsolationError("validation command references protected data")
    if path in {Path("/dev/null"), Path("/dev/urandom"), Path("/dev/random")}:
        return
    if not any(_is_within(path, prefix) for prefix in _TRUSTED_SYSTEM_PREFIXES):
        raise ValidationIsolationError(
            "validation command contains an unapproved host path"
        )


def validate_command_argv(
    command: Sequence[str], worktree: Path, home: Path | None = None
) -> tuple[str, ...]:
    """Validate command tokens before any isolation backend is selected."""

    if not command:
        raise ValidationIsolationError("validation command is empty")
    values = tuple(command)
    for index, token in enumerate(values):
        if not isinstance(token, str) or (index == 0 and not token) or "\x00" in token:
            raise ValidationIsolationError(
                "validation command contains an invalid argument"
            )
        for candidate in _absolute_tokens(token):
            _approved_absolute_argument(Path(candidate), worktree, home, candidate)
    return values


def _validate_backend_command(
    command: Sequence[str],
    snapshot_root: Path,
    temp_root: Path,
    approved_executable: Path | None = None,
) -> tuple[str, ...]:
    values = tuple(command)
    if not values:
        raise ValidationIsolationError("validation command is empty")
    for index, token in enumerate(values):
        if not isinstance(token, str) or (index == 0 and not token) or "\x00" in token:
            raise ValidationIsolationError(
                "validation command contains an invalid argument"
            )
        for candidate in _absolute_tokens(token):
            path = Path(candidate)
            if _is_within(path, snapshot_root) or _is_within(path, temp_root):
                if token != candidate:
                    raise ValidationIsolationError(
                        "validation command embeds a host guest path"
                    )
                continue
            if approved_executable is not None and path == approved_executable:
                continue
            if token == _probe_script() and path == Path("/proc/self/ns/net"):
                continue
            _approved_absolute_argument(path, raw=candidate)
    return values


def render_macos_profile(
    snapshot_root: Path, temp_root: Path, python_executable: Path
) -> str:
    _validate_trusted_interpreter(python_executable, "macOS")
    snapshot = _profile_path(snapshot_root)
    temp = _profile_path(temp_root)
    python = _profile_path(python_executable)
    read_roots = {_validate_system_directory(Path("/usr"), "macOS runtime /usr")}
    for system_root in (Path("/bin"), Path("/sbin")):
        if system_root.exists():
            read_roots.add(
                _validate_system_directory(system_root, "macOS runtime prefix")
            )
    framework = Path("/System/Library/Frameworks/Python.framework")
    if _is_within(python_executable, framework) and framework.exists():
        read_roots.add(_validate_system_directory(framework, "macOS Python framework"))
    lines = [
        "(version 1)",
        "(deny default)",
        "(deny network*)",
        "(allow process-exec*)",
        "(allow process-fork)",
        "(allow signal)",
        "(allow sysctl-read)",
        "(deny file-write*)",
    ]
    for root in sorted(read_roots):
        lines.append(f'(allow file-read* (subpath "{_profile_path(Path(root))}"))')
    lines.extend(
        [
            f'(allow file-read* (subpath "{snapshot}"))',
            f'(allow file-read* (subpath "{temp}"))',
            f'(allow file-write* (subpath "{snapshot}"))',
            f'(allow file-write* (subpath "{temp}"))',
            f'(allow process-exec* (literal "{python}"))',
        ]
    )
    return "\n".join(lines) + "\n"


def build_linux_mount_plan(python_executable: Path) -> tuple[Path, ...]:
    """Return fixed, canonical, non-overlapping runtime mount prefixes."""

    _regular_executable(python_executable, "validation interpreter", root_owned=False)
    _validate_trusted_interpreter(python_executable, "Linux")
    mounts: list[Path] = []
    for candidate in _TRUSTED_SYSTEM_PREFIXES:
        if not candidate.exists():
            continue
        mount = _validate_system_directory(candidate, "Linux runtime mount")
        if any(
            mount == other or mount in other.parents or other in mount.parents
            for other in mounts
        ):
            raise ValidationIsolationError("Linux runtime mount prefixes overlap")
        mounts.append(mount)
    if not mounts:
        raise ValidationIsolationError("Linux runtime mount plan is empty")
    return tuple(mounts)


def _existing_mounts(python_executable: Path) -> tuple[Path, ...]:
    return build_linux_mount_plan(python_executable)


def build_backend_argv(
    backend: BackendSpec,
    command: Sequence[str],
    snapshot_root: Path,
    temp_root: Path,
    env: Mapping[str, str],
) -> tuple[str, ...]:
    command = _validate_backend_command(
        command, snapshot_root, temp_root, backend.python_executable
    )
    _validate_child_environment(env, temp_root)
    if backend.name == "macos":
        profile = render_macos_profile(
            snapshot_root, temp_root, backend.python_executable
        )
        return (
            str(backend.launcher),
            "-p",
            profile,
            *command,
        )
    guest_snapshot = Path("/tmp/validation-snapshot")  # noqa: S108
    guest_temp = Path("/tmp/validation-temp")  # noqa: S108

    def guest_path(value: str) -> str:
        path = Path(value)
        for host, guest in ((snapshot_root, guest_snapshot), (temp_root, guest_temp)):
            try:
                relative = path.relative_to(host)
            except ValueError:
                continue
            return str(guest / relative)
        return value

    argv: list[str] = [
        str(backend.launcher),
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",  # noqa: S108 - private mount inside the Bubblewrap namespace
        "--bind",
        str(snapshot_root),
        str(guest_snapshot),
        "--bind",
        str(temp_root),
        str(guest_temp),
    ]
    for mount in _existing_mounts(backend.python_executable):
        argv.extend(("--ro-bind", str(mount), str(mount)))
    for key, value in sorted(env.items()):
        argv.extend(("--setenv", key, guest_path(value)))
    argv.extend(("--chdir", str(guest_snapshot), "--"))
    argv.extend(guest_path(item) for item in command)
    return tuple(argv)


def _private_directory(path: Path, label: str) -> PrivateRootIdentity:
    if not path.is_absolute():
        raise ValidationIsolationError(f"{label} must be absolute")
    try:
        item = os.lstat(path)
    except OSError as exc:
        raise ValidationIsolationError(f"{label} is unavailable") from exc
    owner = os.getuid() if hasattr(os, "getuid") else item.st_uid
    mode = stat.S_IMODE(item.st_mode)
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
        raise ValidationIsolationError(f"{label} is not a directory")
    if item.st_uid not in (0, owner):
        raise ValidationIsolationError(f"{label} has an unsafe owner")
    if item.st_nlink < 2:
        raise ValidationIsolationError(f"{label} has an unsafe link count")
    if mode != 0o700:
        raise ValidationIsolationError(f"{label} is not private")
    return PrivateRootIdentity(
        path=path,
        device=item.st_dev,
        inode=item.st_ino,
        owner=item.st_uid,
        nlink=item.st_nlink,
        mode=mode,
    )


def _probe_script() -> str:
    return (
        "import os,socket,sys\n"
        "marker,port,parent_ns=sys.argv[1:]\n"
        "try:\n"
        " socket.create_connection(('127.0.0.1',int(port)),timeout=0.5)\n"
        "except OSError:\n"
        " pass\n"
        "else:\n"
        " raise SystemExit(17)\n"
        "if parent_ns and os.readlink('/proc/self/ns/net') == parent_ns:\n"
        " raise SystemExit(18)\n"
        "with open(marker,'x',encoding='ascii') as output:\n"
        " output.write('ok')\n"
        " os.fchmod(output.fileno(),0o600)\n"
        " output.flush()\n"
        " os.fsync(output.fileno())\n"
    )


def _marker_stat(item: os.stat_result) -> tuple[int, int, int, int, int]:
    owner = os.getuid() if hasattr(os, "getuid") else item.st_uid
    if (
        not stat.S_ISREG(item.st_mode)
        or item.st_nlink != 1
        or item.st_uid not in (0, owner)
        or stat.S_IMODE(item.st_mode) != 0o600
        or item.st_size != len(_MARKER_CONTENT)
    ):
        raise ValidationIsolationError("validation isolation probe marker is unsafe")
    return item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_size


def _read_probe_marker(marker: Path) -> None:
    """Read a pinned, private marker while detecting replacement races."""

    try:
        before = os.lstat(marker)
        identity = _marker_stat(before)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(marker, flags)
    except (OSError, ValidationIsolationError) as exc:
        raise ValidationIsolationError(
            "validation isolation probe marker is unsafe"
        ) from exc
    try:
        pinned = os.fstat(descriptor)
        if _marker_stat(pinned) != identity:
            raise ValidationIsolationError("validation isolation probe marker changed")
        content = os.read(descriptor, len(_MARKER_CONTENT) + 1)
        after_read = os.fstat(descriptor)
        if _marker_stat(after_read) != identity or content != _MARKER_CONTENT:
            raise ValidationIsolationError(
                "validation isolation probe marker is invalid"
            )
        after = os.lstat(marker)
        if _marker_stat(after) != identity:
            raise ValidationIsolationError("validation isolation probe marker changed")
    except (OSError, ValidationIsolationError) as exc:
        if isinstance(exc, ValidationIsolationError):
            raise
        raise ValidationIsolationError(
            "validation isolation probe marker is unreadable"
        ) from exc
    finally:
        os.close(descriptor)


def probe_backend(
    backend: BackendSpec,
    snapshot_root: Path,
    temp_root: Path,
    env: Mapping[str, str],
    process_runner: ProcessRunner = run_process,
) -> None:
    verify_backend(backend)
    snapshot_identity = _private_directory(snapshot_root, "snapshot")
    temp_identity = _private_directory(temp_root, "validation temporary root")
    marker = temp_root / ".validation-probe-marker"
    try:
        marker.unlink()
    except FileNotFoundError:
        pass
    parent_namespace = ""
    if backend.name == "linux":
        try:
            parent_namespace = os.readlink("/proc/self/ns/net")
        except OSError as exc:
            raise ValidationIsolationError(
                "Linux network namespace is unavailable"
            ) from exc
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
        except OSError as exc:
            raise ValidationIsolationError(
                "loopback probe listener is unavailable"
            ) from exc
        probe_command = (
            str(backend.python_executable),
            "-c",
            _probe_script(),
            str(marker),
            str(listener.getsockname()[1]),
            parent_namespace,
        )
        argv = build_backend_argv(backend, probe_command, snapshot_root, temp_root, env)
        try:
            completed = run_verified_process(
                backend,
                argv,
                snapshot_root,
                env,
                MAX_PROBE_SECONDS,
                process_runner,
                private_roots=(snapshot_identity, temp_identity),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValidationIsolationError("validation isolation probe failed") from exc
    finally:
        listener.close()
    if not isinstance(completed.stdout, str) or not isinstance(completed.stderr, str):
        raise ValidationIsolationError("validation isolation probe output is invalid")
    if (
        len(completed.stdout) > MAX_PROBE_OUTPUT
        or len(completed.stderr) > MAX_PROBE_OUTPUT
    ):
        raise ValidationIsolationError("validation isolation probe output is invalid")
    if completed.returncode != 0:
        raise ValidationIsolationError("validation isolation probe failed")
    _read_probe_marker(marker)
