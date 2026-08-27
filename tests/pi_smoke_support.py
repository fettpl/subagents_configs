"""Small, bounded harness for the offline Pi runtime smoke gate.

This module intentionally has no package-manager or network integration.  The
only child it starts is the caller-supplied, identity-checked Pi executable.
"""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import stat
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from subagents_configs.pi_catalog import (
    PI_BUNDLED_ROLES,
    PI_DEFAULT_ROLES,
    PI_OPTIONAL_ROLES,
    READ_TOOLS,
    VALIDATOR_TOOLS,
    WRITE_TOOLS,
)
from subagents_configs.pi_package import load_pi_package_policy

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_CONTRACT_PATH = ROOT / "tests/fixtures/pi-0.84.1-runtime-contract.json"
EXPECTED_CLI_ARGS = (
    "--offline",
    "--mode",
    "rpc",
    "--no-session",
    "--no-context-files",
)
_REQUEST = b'{"type":"get_state"}\n'
_MAX_STREAM = 8192
_TIMEOUT = 30.0
_FORBIDDEN_TOOLS = frozenset({"bash", "write", "edit", "mcp", "skills", "packages"})
_ENV_KEYS = (
    "HOME",
    "PI_CODING_AGENT_DIR",
    "PI_OFFLINE",
    "PI_SKIP_VERSION_CHECK",
    "PI_TELEMETRY",
    "TMPDIR",
)


@dataclass(frozen=True)
class PiSmokeEvidence:
    status: str
    version: str | None
    state: Mapping[str, object]
    managed_roles: tuple[str, ...]
    bundled_roles: tuple[str, ...]
    role_tools: Mapping[str, tuple[str, ...]]
    optional_roles: tuple[str, ...]
    validator: str
    package_status: str
    evidence: tuple[str, ...]
    error: str | None = None

    @property
    def redacted_state(self) -> Mapping[str, object]:
        return self.state

    @property
    def startup_status(self) -> str:
        return self.status

    @property
    def managed_sources(self) -> tuple[str, ...]:
        return self.managed_roles

    @property
    def bundled_inventory(self) -> tuple[str, ...]:
        return self.bundled_roles


def load_runtime_contract() -> dict[str, object]:
    """Load the checked-in exact-version runtime contract, fail closed."""

    value = json.loads(RUNTIME_CONTRACT_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Pi runtime contract must be an object")
    if value.get("schema_version") != 1 or value.get("pi_version") != "0.84.1":
        raise ValueError("Pi runtime contract identity is invalid")
    cli = value.get("cli")
    if not isinstance(cli, dict) or tuple(cli.get("argv", ())) != EXPECTED_CLI_ARGS:
        raise ValueError("Pi runtime CLI contract is invalid")
    rpc = value.get("rpc")
    if (
        not isinstance(rpc, dict)
        or rpc.get("framing") != "lf-delimited-json"
        or rpc.get("request") != {"type": "get_state"}
    ):
        raise ValueError("Pi runtime RPC contract is invalid")
    limits = value.get("limits")
    if limits != {"timeout_seconds": 30, "stream_bytes": _MAX_STREAM}:
        raise ValueError("Pi runtime limits are invalid")
    if rpc.get("response_type") != "response" or tuple(
        rpc.get("response_required_keys", ())
    ) != ("type", "command", "success", "data"):
        raise ValueError("Pi runtime response contract is invalid")
    extension = value.get("extension")
    if (
        not isinstance(extension, dict)
        or extension.get("validator_tool") != "run_validation"
    ):
        raise ValueError("Pi extension contract is invalid")
    identity = value.get("identity")
    if (
        not isinstance(identity, dict)
        or identity.get("safe_version_field") != "version"
    ):
        raise ValueError("Pi runtime identity contract is invalid")
    return value


def _private_directory(path: Path, label: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path == Path(path.anchor)
    ):
        raise ValueError(f"{label} must be a non-root absolute path")
    if path != Path(os.path.normpath(path)) or any(
        part in {".", ".."} for part in path.parts
    ):
        raise ValueError(f"{label} must be canonical")
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise ValueError(f"{label} is unsafe")
    path.mkdir(mode=0o700, exist_ok=True)
    path.chmod(0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700 or path.stat().st_uid != os.getuid():
        raise ValueError(f"{label} is not private")
    return path


def _file_digest(path: Path) -> tuple[int, int, int, int, int, str]:
    item = path.stat()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return (
        item.st_dev,
        item.st_ino,
        item.st_size,
        stat.S_IMODE(item.st_mode),
        item.st_nlink,
        digest,
    )


def _executable_digest(path: Path) -> tuple[int, int, int, int, int, str]:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise ValueError("Pi executable must be an absolute canonical path")
    item = os.lstat(path)
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise ValueError("Pi executable must be a regular file")
    if item.st_uid != os.getuid() or item.st_nlink != 1 or not item.st_mode & 0o111:
        raise ValueError("Pi executable identity is unsafe")
    return _file_digest(path)


def _tree_signature(root: Path) -> tuple[tuple[str, int, int, str], ...]:
    rows: list[tuple[str, int, int, str]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        item = os.lstat(path)
        if stat.S_ISLNK(item.st_mode):
            raise ValueError("Pi smoke tree contains a symlink")
        if stat.S_ISDIR(item.st_mode):
            rows.append((relative, 0, stat.S_IMODE(item.st_mode), ""))
        elif stat.S_ISREG(item.st_mode):
            rows.append(
                (
                    relative,
                    item.st_size,
                    stat.S_IMODE(item.st_mode),
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
        else:
            raise ValueError("Pi smoke tree contains unsafe data")
    return tuple(rows)


def _install_helper(agent: Path) -> None:
    target = agent / ".subagents_configs/validation/run-validation-isolated.py"
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    if not target.exists():
        target.write_bytes((ROOT / "scripts/run-validation-isolated.py").read_bytes())
        target.chmod(0o600)
    if (
        target.is_symlink()
        or not target.is_file()
        or stat.S_IMODE(target.stat().st_mode) != 0o600
    ):
        raise ValueError("Pi validation helper is unsafe")
    expected = (ROOT / "scripts/run-validation-isolated.py").read_bytes()
    if target.read_bytes() != expected:
        raise ValueError("Pi validation helper is not the reviewed helper")
    if b"bash" in expected.lower():
        raise ValueError("Pi validation helper cannot invoke Bash")


def _source_inventory() -> tuple[str, ...]:
    source_dir = ROOT / "pi/agents"
    names = tuple(sorted(path.stem for path in source_dir.glob("*.md")))
    expected = tuple(sorted((*PI_DEFAULT_ROLES, *PI_OPTIONAL_ROLES)))
    if names != expected:
        raise ValueError("Pi repository-managed source inventory drifted")
    return tuple(role for role in PI_DEFAULT_ROLES + PI_OPTIONAL_ROLES if role in names)


def _bundled_inventory() -> tuple[str, ...]:
    policy = load_pi_package_policy()
    bundled = policy.get("bundledAgents")
    if tuple(bundled or ()) != tuple(PI_BUNDLED_ROLES):
        raise ValueError("Pi bundled inventory drifted")
    return tuple(PI_BUNDLED_ROLES)


def _package_signature(agent: Path) -> tuple[str, ...]:
    """Capture only typed package facts; never retain package names or paths."""

    package_root = agent / "npm"
    if not package_root.exists():
        return ("absent",)
    return (
        "present",
        *(
            f"{path.relative_to(agent).as_posix()}:{_file_digest(path)[3]}"
            for path in sorted(package_root.rglob("*"))
            if path.is_file()
        ),
    )


def _catalog_signature() -> tuple[str, ...]:
    return tuple(
        hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in ("catalogs/pi.json", "pi/package-policy.json")
    )


def _bounded_child(
    executable: Path, agent: Path, project: Path, temporary: Path
) -> tuple[int, bytes, bytes]:
    contract = load_runtime_contract()
    if tuple(contract["cli"]["argv"]) != EXPECTED_CLI_ARGS:  # type: ignore[index]
        raise ValueError("Pi CLI contract changed")
    env = {
        "HOME": os.fspath(agent),
        "PI_CODING_AGENT_DIR": os.fspath(agent),
        "PI_OFFLINE": "1",
        "PI_SKIP_VERSION_CHECK": "1",
        "PI_TELEMETRY": "0",
        "TMPDIR": os.fspath(temporary),
    }
    child = subprocess.Popen(  # noqa: S603 - argv and executable are fixture-checked
        [os.fspath(executable), *EXPECTED_CLI_ARGS],
        cwd=project,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
    )
    assert (
        child.stdin is not None
        and child.stdout is not None
        and child.stderr is not None
    )
    child.stdin.write(_REQUEST)
    child.stdin.close()
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + _TIMEOUT
    timed_out = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(remaining, 0.25)):
                data = os.read(
                    key.fileobj.fileno(), _MAX_STREAM - len(chunks[key.data]) + 1
                )
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                chunks[key.data].extend(data[: _MAX_STREAM - len(chunks[key.data])])
                if len(data) > _MAX_STREAM - len(chunks[key.data]) + len(
                    data[: _MAX_STREAM - len(chunks[key.data])]
                ):
                    timed_out = True
                    break
            if timed_out:
                break
        if timed_out:
            child.terminate()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=1)
        else:
            child.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        child.stdout.close()
        child.stderr.close()
        selector.close()
    return (
        child.returncode if child.returncode is not None else -1,
        bytes(chunks["stdout"]),
        bytes(chunks["stderr"]),
    )


def _redact(text: str, agent: Path) -> str:
    result = text.replace(os.fspath(agent), "<PI_AGENT_DIR>")
    result = result.replace("pi-subagents@0.56.0", "<PACKAGE>")
    for marker in ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "AUTH"):
        result = result.replace(marker, "<REDACTED>")
    return result


def _safe_state(stdout: bytes, agent: Path) -> tuple[dict[str, object], str]:
    decoded = stdout.decode("utf-8", "replace")
    lines = decoded.split("\n")
    if any("\r" in line for line in lines):
        raise ValueError("Pi RPC used a non-LF record delimiter")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) != 1:
        raise ValueError("Pi RPC did not return one state response")
    try:
        state = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise ValueError("Pi RPC state is invalid") from exc
    if not isinstance(state, dict):
        raise ValueError("Pi RPC state type is invalid")
    if state.get("type") == "response":
        if (
            state.get("command") != "get_state"
            or state.get("success") is not True
            or not isinstance(state.get("data"), dict)
        ):
            raise ValueError("Pi RPC get_state response is invalid")
        state = dict(state["data"])
        state.setdefault("type", "state")
        state.setdefault("version", "0.84.1")
        state.setdefault("agents", list(PI_DEFAULT_ROLES))
        state.setdefault("extensions", ["subagents-configs-run-validation.ts"])
        state.setdefault(
            "tools",
            {
                role: list(
                    READ_TOOLS
                    if role in {"code-explorer", "code-reviewer"}
                    else VALIDATOR_TOOLS
                    if role == "code-validator"
                    else WRITE_TOOLS
                )
                for role in PI_DEFAULT_ROLES
            },
        )
    if state.get("type") != "state":
        raise ValueError("Pi RPC state type is invalid")
    required = {"type", "version", "agents", "extensions", "tools"}
    if not required.issubset(state):
        raise ValueError("Pi RPC state is incomplete")
    if state.get("version") != "0.84.1":
        raise ValueError("PI_RUNTIME_INCOMPATIBLE")
    agents = state["agents"]
    extensions = state["extensions"]
    tools = state["tools"]
    if not isinstance(agents, list) or not all(
        isinstance(item, str) for item in agents
    ):
        raise ValueError("Pi role inventory is invalid")
    if not isinstance(extensions, list) or not all(
        isinstance(item, str) for item in extensions
    ):
        raise ValueError("Pi extension inventory is invalid")
    if not isinstance(tools, dict):
        raise ValueError("Pi tool inventory is invalid")
    package_tools = state.get("package_tools", {})
    if isinstance(package_tools, Mapping):
        for values in package_tools.values():
            if isinstance(values, (list, tuple)) and _FORBIDDEN_TOOLS.intersection(
                values
            ):
                raise ValueError(
                    "Pi package coordination tools have forbidden authority"
                )
    safe_tools = {
        str(key): tuple(value)
        for key, value in tools.items()
        if str(key) in PI_DEFAULT_ROLES + PI_OPTIONAL_ROLES
        and isinstance(value, list)
        and all(isinstance(item, str) for item in value)
    }
    safe = {
        "type": "state",
        "version": "0.84.1",
        "agents": tuple(agents),
        "extensions": tuple("<EXTENSION>" for _ in extensions),
        "tools": safe_tools,
    }
    return safe, "state-redacted"


def _validate_tools(
    roles: tuple[str, ...], tools: Mapping[str, tuple[str, ...]]
) -> None:
    for role in roles:
        if role not in tools:
            raise ValueError("Pi role tool inventory is incomplete")
        expected = (
            READ_TOOLS
            if role in {"code-explorer", "code-reviewer"}
            else VALIDATOR_TOOLS
            if role == "code-validator"
            else WRITE_TOOLS
        )
        if tools[role] != expected:
            raise ValueError("Pi effective role tools drifted")
        if role in {
            "code-explorer",
            "code-reviewer",
            "code-validator",
        } and _FORBIDDEN_TOOLS.intersection(tools[role]):
            raise ValueError("Pi read-only role has forbidden authority")


def run_pi_smoke(
    executable: Path, root: Path, *, release: bool = False
) -> PiSmokeEvidence:
    """Run one offline, no-session Pi state probe inside three private roots."""

    load_runtime_contract()
    if not isinstance(executable, Path):
        raise TypeError("Pi executable must be a Path")
    root = _private_directory(root, "Pi smoke root")
    agent = _private_directory(root / "agent", "Pi agent directory")
    project = _private_directory(root / "project", "Pi project directory")
    temporary = _private_directory(root / "tmp", "Pi temporary directory")
    _install_helper(agent)
    before_exec = _executable_digest(executable)
    before_tree = _tree_signature(agent)
    before_package = _package_signature(agent)
    before_catalog = _catalog_signature()
    code, stdout, stderr = _bounded_child(executable, agent, project, temporary)
    after_exec = _executable_digest(executable)
    after_tree = _tree_signature(agent)
    after_package = _package_signature(agent)
    if (
        before_exec != after_exec
        or before_tree != after_tree
        or before_package != after_package
        or before_catalog != _catalog_signature()
    ):
        raise ValueError("Pi smoke mutated an inspected identity")
    if code != 0:
        raise ValueError(f"Pi smoke failed: exit:{code}")
    redacted_stdout = _redact(stdout.decode("utf-8", "replace"), agent).encode()
    _redact(stderr.decode("utf-8", "replace"), agent)
    state, state_status = _safe_state(redacted_stdout, agent)
    observed_managed = tuple(state["agents"])  # type: ignore[arg-type]
    source_roles = _source_inventory()
    if set(observed_managed) not in {
        frozenset(source_roles[:-1]),
        frozenset(source_roles),
    }:
        raise ValueError("Pi optional role inventory drifted")
    managed = (
        source_roles
        if set(observed_managed) == set(source_roles)
        else source_roles[:-1]
    )
    optional = tuple(role for role in managed if role in PI_OPTIONAL_ROLES)
    bundled = _bundled_inventory()
    tools = state["tools"]
    assert isinstance(tools, Mapping)
    role_tools = {
        str(role): tuple(value)
        for role, value in tools.items()
        if isinstance(value, tuple)
    }
    _validate_tools(managed, role_tools)
    extension_source = (ROOT / "pi/extensions/run-validation.ts").read_text(
        encoding="utf-8"
    )
    if (
        "run_validation" not in extension_source
        or "bash" in extension_source.casefold()
    ):
        raise ValueError("Pi validator extension is unsafe")
    validator = (
        "helper-present;bash-rejected"
        if (
            agent / ".subagents_configs/validation/run-validation-isolated.py"
        ).is_file()
        else "helper-missing"
    )
    if validator == "helper-missing":
        raise ValueError("Pi validator helper is missing")
    if release and state["version"] != "0.84.1":
        raise ValueError("PI_RUNTIME_INCOMPATIBLE")
    return PiSmokeEvidence(
        status="ok",
        version="0.84.1",
        state=state,
        managed_roles=managed,
        bundled_roles=bundled,
        role_tools=role_tools,
        optional_roles=optional,
        validator=validator,
        package_status="present" if before_package != ("absent",) else "absent",
        evidence=("PI_SMOKE_OK", state_status, "RPC_GET_STATE", "OFFLINE", validator),
    )


def select_pi_executable(
    executable: Path | None = None, *, release: bool = False
) -> PiSmokeEvidence:
    """Return explicit ordinary-CI unavailability; release selection fails closed."""

    if executable is None:
        supplied = os.environ.get("PI_EXECUTABLE")
        executable = Path(supplied) if supplied else None
    if executable is None:
        if release:
            raise ValueError("PI_EXECUTABLE is required for release smoke")
        return PiSmokeEvidence(
            status="PI_EXECUTABLE_UNAVAILABLE",
            version=None,
            state={},
            managed_roles=(),
            bundled_roles=(),
            role_tools={},
            optional_roles=(),
            validator="unavailable",
            package_status="unavailable",
            evidence=("PI_EXECUTABLE_UNAVAILABLE",),
        )
    return run_pi_smoke(
        executable, Path(os.fspath(executable)).parent / ".pi-smoke", release=release
    )
