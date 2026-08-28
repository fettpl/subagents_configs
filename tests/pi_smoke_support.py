"""Small, bounded harness for the offline Pi runtime smoke gate.

This module intentionally has no package-manager or network integration.  The
only child it starts is the caller-supplied, identity-checked Pi executable.
"""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from subagents_configs.pi_catalog import (
    PI_BUNDLED_ROLES,
    PI_DEFAULT_ROLES,
    PI_OPTIONAL_ROLES,
    PUSHER_TOOLS,
    READ_TOOLS,
    VALIDATOR_TOOLS,
    WRITE_TOOLS,
    render_pi_source,
    validate_pi_agent,
)
from subagents_configs.pi_effective import inspect_effective_catalog
from subagents_configs.pi_package import (
    inspect_pi_package_state,
    load_pi_package_policy,
    pi_package_policy_hash,
)

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
_REVIEWED_EXTENSIONS = ("subagents-configs-run-validation.ts",)
_RESPONSE_KEYS = ("type", "command", "success", "data")
_RESPONSE_DATA_REQUIRED = (
    "model",
    "thinkingLevel",
    "isStreaming",
    "isCompacting",
    "steeringMode",
    "followUpMode",
    "sessionFile",
    "sessionId",
    "autoCompactionEnabled",
    "messageCount",
    "pendingMessageCount",
)
_RESPONSE_DATA_OPTIONAL = (
    "sessionName",
    "version",
    "agents",
    "extensions",
    "tools",
    "packages",
    "package_tools",
)
_VALIDATOR_REQUEST = ("--", "bash", "-c", "pi-smoke-forbidden")
_EXPECTED_RELEASE_SMOKE_EVIDENCE = (
    "PI_SMOKE_OK",
    "state-redacted",
    "PI_VERSION_0.84.1",
    "RPC_GET_STATE",
    "OFFLINE",
    "helper-present;bash-rejected",
    "VALIDATOR_HELPER_EXECUTED",
    "BASH_REJECTED",
)
_ENV_KEYS = (
    "HOME",
    "PI_CODING_AGENT_DIR",
    "PI_OFFLINE",
    "PI_SKIP_VERSION_CHECK",
    "PI_TELEMETRY",
    "TMPDIR",
)


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Pi RPC response contains duplicate keys")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"Pi RPC response contains non-standard value: {value}")


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
    sandbox_backend: str | None = None
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
    if tuple(rpc.get("response_data_required_keys", ())) != _RESPONSE_DATA_REQUIRED:
        raise ValueError("Pi runtime response data contract is invalid")
    if tuple(rpc.get("response_data_optional_keys", ())) != _RESPONSE_DATA_OPTIONAL:
        raise ValueError("Pi runtime response data optional contract is invalid")
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
        or tuple(identity.get("version_argv", ())) != ("--offline", "--version")
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
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            item = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(item.st_mode):
            if current == Path("/var") and Path(os.path.realpath(current)) == Path(
                "/private/var"
            ):
                continue
            raise ValueError(f"{label} contains an unsafe ancestor")
        if current != path and not stat.S_ISDIR(item.st_mode):
            raise ValueError(f"{label} contains a non-directory ancestor")
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


def _owned_private_file_digest(path: Path) -> str:
    """Hash an already-selected private file without following its final link."""

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        item = os.fstat(descriptor)
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != os.getuid()
            or item.st_nlink != 1
            or stat.S_IMODE(item.st_mode) & 0o077
        ):
            raise ValueError("Pi release package evidence is unsafe")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (item.st_dev, item.st_ino, item.st_size, item.st_nlink) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_nlink,
        ):
            raise ValueError("Pi release package evidence changed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _executable_digest(path: Path) -> tuple[int, int, int, int, int, str]:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise ValueError("Pi executable must be an absolute canonical path")
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        item = os.lstat(current)
        if stat.S_ISLNK(item.st_mode) and not (
            current == Path("/var")
            and Path(os.path.realpath(current)) == Path("/private/var")
        ):
            raise ValueError("Pi executable identity is unsafe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        item = os.fstat(descriptor)
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != os.getuid()
            or item.st_nlink != 1
            or not item.st_mode & 0o111
            or stat.S_IMODE(item.st_mode) & 0o022
        ):
            raise ValueError("Pi executable identity is unsafe")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (item.st_dev, item.st_ino, item.st_size, item.st_nlink) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_nlink,
        ):
            raise ValueError("Pi executable identity changed")
        return (
            item.st_dev,
            item.st_ino,
            item.st_size,
            stat.S_IMODE(item.st_mode),
            item.st_nlink,
            digest.hexdigest(),
        )
    finally:
        os.close(descriptor)


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
    dependency_dir = target.parent / "validation_isolation"
    dependency_dir.mkdir(mode=0o700, exist_ok=True)
    dependency_dir.chmod(0o700)
    if not target.exists():
        target.write_bytes((ROOT / "scripts/run-validation-isolated.py").read_bytes())
        target.chmod(0o600)
    for source in sorted((ROOT / "scripts/validation_isolation").glob("*.py")):
        dependency = dependency_dir / source.name
        if not dependency.exists():
            dependency.write_bytes(source.read_bytes())
            dependency.chmod(0o600)
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
    expected_dependencies = tuple(
        source.name
        for source in sorted((ROOT / "scripts/validation_isolation").glob("*.py"))
    )
    if (
        tuple(path.name for path in sorted(dependency_dir.glob("*.py")))
        != expected_dependencies
    ):
        raise ValueError("Pi validation helper dependencies are incomplete")
    for source in sorted((ROOT / "scripts/validation_isolation").glob("*.py")):
        dependency = dependency_dir / source.name
        if dependency.read_bytes() != source.read_bytes():
            raise ValueError("Pi validation helper dependency is not reviewed")


def _source_inventory() -> tuple[str, ...]:
    source_dir = ROOT / "pi/agents"
    names = tuple(sorted(path.stem for path in source_dir.glob("*.md")))
    expected = tuple(sorted((*PI_DEFAULT_ROLES, *PI_OPTIONAL_ROLES)))
    if names != expected:
        raise ValueError("Pi repository-managed source inventory drifted")
    return tuple(role for role in PI_DEFAULT_ROLES + PI_OPTIONAL_ROLES if role in names)


def _install_extension(agent: Path) -> None:
    # Validate the conventional loader directory with lstat before selecting
    # any target below it; a symlink here could redirect the write outside the
    # private Pi home.
    extension_dir = _private_directory(agent / "extensions", "Pi extension directory")
    target = extension_dir / "subagents-configs-run-validation.ts"
    source = ROOT / "pi/extensions/run-validation.ts"
    if not target.exists():
        target.write_bytes(source.read_bytes())
        target.chmod(0o600)
    if (
        target.is_symlink()
        or not target.is_file()
        or stat.S_IMODE(target.stat().st_mode) != 0o600
        or target.read_bytes() != source.read_bytes()
    ):
        raise ValueError("Pi validator extension is not reviewed")


def _extension_inventory(agent: Path) -> tuple[str, ...]:
    extension_dir = agent / "extensions"
    names: list[str] = []
    for path in sorted(extension_dir.glob("*.ts")):
        item = os.lstat(path)
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
            raise ValueError("Pi extension inventory is unsafe")
        names.append(path.name)
    result = tuple(names)
    if result != _REVIEWED_EXTENSIONS:
        raise ValueError("Pi ambient or unreviewed extension discovered")
    return result


def _repository_signature() -> tuple[tuple[str, str], ...]:
    paths = [
        *(ROOT / "pi/agents").glob("*.md"),
        ROOT / "pi/extensions/run-validation.ts",
        ROOT / "scripts/run-validation-isolated.py",
        *((ROOT / "scripts/validation_isolation").glob("*.py")),
    ]
    return tuple(
        (
            path.relative_to(ROOT).as_posix(),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(paths)
    )


def _rendered_catalog(agent: Path) -> dict[str, object]:
    rendered: dict[str, object] = {}
    for role in (*PI_DEFAULT_ROLES, *PI_OPTIONAL_ROLES):
        source = ROOT / "pi/agents" / f"{role}.md"
        source_bytes = source.read_bytes()
        if role == "code-validator":
            source_bytes = render_pi_source(source_bytes, agent_dir=agent)
            rendered[role] = validate_pi_agent(
                role, source_bytes, allow_rendered_extension=True
            )
        else:
            rendered[role] = validate_pi_agent(role, source_bytes)
    return rendered


def _bundled_inventory() -> tuple[str, ...]:
    policy = load_pi_package_policy()
    bundled = policy.get("bundledAgents")
    if tuple(bundled or ()) != tuple(PI_BUNDLED_ROLES):
        raise ValueError("Pi bundled inventory drifted")
    return tuple(PI_BUNDLED_ROLES)


def _package_evidence(agent: Path):
    try:
        return inspect_pi_package_state(agent)
    except (OSError, ValueError, RuntimeError) as exc:
        raise ValueError("Pi installed package evidence is invalid") from exc


def _check_effective_catalog(agent: Path, project: Path, package) -> None:
    rendered = _rendered_catalog(agent)
    result = inspect_effective_catalog(
        agent,
        rendered,
        package,
        project_root=project,
    )
    if result.conflicts:
        raise ValueError("Pi effective discovery has unreviewed authority")


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


def _smoke_environment(agent: Path, temporary: Path) -> dict[str, str]:
    return {
        "HOME": os.fspath(agent),
        "PI_CODING_AGENT_DIR": os.fspath(agent),
        "PI_OFFLINE": "1",
        "PI_SKIP_VERSION_CHECK": "1",
        "PI_TELEMETRY": "0",
        "TMPDIR": os.fspath(temporary),
    }


def _bounded_process(
    argv: tuple[str, ...],
    request: bytes,
    *,
    cwd: Path,
    env: Mapping[str, str],
) -> tuple[int, bytes, bytes]:
    env = {str(key): str(value) for key, value in env.items() if str(key) in _ENV_KEYS}
    child = subprocess.Popen(  # noqa: S603 - argv and executable are fixture-checked
        list(argv),
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
        start_new_session=True,
    )
    assert (
        child.stdin is not None
        and child.stdout is not None
        and child.stderr is not None
    )
    if request:
        child.stdin.write(request)
    child.stdin.close()
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + _TIMEOUT
    timed_out = False

    def terminate_group() -> None:
        def group_exists() -> bool:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                return False
            except OSError:
                return True
            return True

        try:
            os.killpg(child.pid, signal.SIGTERM)
        except OSError:
            if child.poll() is None:
                child.terminate()
        try:
            child.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
        if group_exists():
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except OSError:
                if child.poll() is None:
                    child.kill()
        try:
            child.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass

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
                if len(data) > _MAX_STREAM - len(chunks[key.data]):
                    timed_out = True
                    break
            if timed_out:
                break
        if timed_out:
            terminate_group()
        else:
            try:
                child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                terminate_group()
    finally:
        if child.poll() is None:
            terminate_group()
        child.stdout.close()
        child.stderr.close()
        selector.close()
    return (
        child.returncode if child.returncode is not None else -1,
        bytes(chunks["stdout"]),
        bytes(chunks["stderr"]),
    )


def _bounded_child(
    executable: Path, agent: Path, project: Path, temporary: Path
) -> tuple[int, bytes, bytes]:
    contract = load_runtime_contract()
    if tuple(contract["cli"]["argv"]) != EXPECTED_CLI_ARGS:  # type: ignore[index]
        raise ValueError("Pi CLI contract changed")
    _executable_digest(executable)
    return _bounded_process(
        (os.fspath(executable), *EXPECTED_CLI_ARGS),
        _REQUEST,
        cwd=project,
        env=_smoke_environment(agent, temporary),
    )


def _probe_version(
    executable: Path, agent: Path, project: Path, temporary: Path
) -> str:
    contract = load_runtime_contract()
    identity = contract["identity"]
    if not isinstance(identity, dict):
        raise ValueError("Pi runtime identity contract is invalid")
    version_argv = tuple(identity["version_argv"])
    if version_argv != ("--offline", "--version"):
        raise ValueError("Pi version probe argv is not reviewed")
    _executable_digest(executable)
    code, stdout, _stderr = _bounded_process(
        (os.fspath(executable), *version_argv),
        b"",
        cwd=project,
        env=_smoke_environment(agent, temporary),
    )
    value = _redact(stdout.decode("utf-8", "replace"), agent)
    if code != 0 or value != "0.84.1\n":
        raise ValueError("PI_RUNTIME_INCOMPATIBLE")
    return "0.84.1"


def _run_validator_helper(agent: Path, project: Path, temporary: Path) -> None:
    helper = agent / ".subagents_configs/validation/run-validation-isolated.py"
    argv = (sys.executable, "-B", os.fspath(helper), *_VALIDATOR_REQUEST)
    code, stdout, stderr = _bounded_process(
        argv,
        b"",
        cwd=project,
        env=_smoke_environment(agent, temporary),
    )
    redacted = _redact((stdout + stderr).decode("utf-8", "replace"), agent)
    if code == 0 or "validation shell execution is not allowed" not in redacted:
        raise ValueError("Pi validator Bash denial failed")


def _require_release_package(package) -> None:
    """Require the complete installed-package evidence for release probes."""

    if (
        package.status != "exact"
        or not package.exact_pinned_entry
        or not package.package_identity_valid
        or package.installed_lock_path is None
        or package.installed_lock_root_hash is None
        or package.package_manifest_path is None
        or package.manifest_hash is None
    ):
        raise ValueError("PI_PACKAGE_INCOMPATIBLE")
    for path, mode in (
        (package.installed_lock_path, 0o600),
        (package.package_manifest_path, 0o600),
    ):
        item = os.lstat(path)
        if (
            stat.S_ISLNK(item.st_mode)
            or not stat.S_ISREG(item.st_mode)
            or item.st_uid != os.getuid()
            or item.st_nlink != 1
            or stat.S_IMODE(item.st_mode) != mode
        ):
            raise ValueError("PI_PACKAGE_INCOMPATIBLE")
    policy = load_pi_package_policy()
    if package.manifest_hash != policy.get("packageJsonSha256"):
        raise ValueError("PI_PACKAGE_INCOMPATIBLE")


def build_release_evidence(
    executable: Path,
    root: Path,
    smoke: PiSmokeEvidence,
    *,
    backend: str,
) -> dict[str, object]:
    """Build the complete safe release record from one successful smoke.

    The record contains only the hashes and reviewed identifiers consumed by
    the release transition predicate.  Paths, process output, credentials,
    and Pi state are intentionally excluded.
    """

    if (
        not isinstance(smoke, PiSmokeEvidence)
        or smoke.status != "ok"
        or smoke.version != "0.84.1"
        or smoke.package_status != "exact"
        or smoke.sandbox_backend != backend
        or not isinstance(backend, str)
    ):
        raise ValueError("PI_RELEASE_EVIDENCE_INCOMPLETE")
    if type(smoke.evidence) is not tuple or smoke.evidence != (
        _EXPECTED_RELEASE_SMOKE_EVIDENCE
    ):
        raise ValueError("PI_RELEASE_EVIDENCE_INCOMPLETE")
    if sys.platform == "linux":
        platform = "linux"
        if backend != "bubblewrap":
            raise ValueError("PI_RELEASE_BACKEND_INVALID")
    elif sys.platform == "darwin":
        platform = "macos"
        if backend != "sandbox-exec":
            raise ValueError("PI_RELEASE_BACKEND_INVALID")
    else:
        raise ValueError("PI_RELEASE_PLATFORM_UNSUPPORTED")

    if not isinstance(executable, Path) or not isinstance(root, Path):
        raise TypeError("Pi release paths must be Path values")
    root = _private_directory(root, "Pi smoke root")
    agent = _private_directory(root / "agent", "Pi agent directory")
    package = _package_evidence(agent)
    _require_release_package(package)
    policy = load_pi_package_policy()
    executable_hash = _executable_digest(executable)[-1]
    return {
        "schema_version": 1,
        "status": "ok",
        "pi_version": "0.84.1",
        "pi_executable_sha256": executable_hash,
        "package_source": policy["source"],
        "package_version": policy["version"],
        "package_policy_sha256": pi_package_policy_hash(),
        "upstream_commit": policy["upstreamCommit"],
        "dist_integrity": policy["distIntegrity"],
        "package_manifest_sha256": package.manifest_hash,
        "package_lock_sha256": _owned_private_file_digest(package.installed_lock_path),
        "platform": platform,
        "backend": backend,
        "smoke_evidence": list(smoke.evidence),
    }


def _redact(text: str, agent: Path) -> str:
    result = text.replace(os.fspath(agent), "<PI_AGENT_DIR>")
    result = result.replace("pi-subagents@0.56.0", "<PACKAGE>")
    for marker in ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "AUTH"):
        result = result.replace(marker, "<REDACTED>")
    return result


def _safe_state(
    stdout: bytes, agent: Path, version: str
) -> tuple[dict[str, object], str]:
    decoded = stdout.decode("utf-8", "replace")
    lines = decoded.split("\n")
    if any("\r" in line for line in lines):
        raise ValueError("Pi RPC used a non-LF record delimiter")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) != 1:
        raise ValueError("Pi RPC did not return one state response")
    try:
        state = json.loads(
            lines[0],
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Pi RPC state is invalid") from exc
    if not isinstance(state, dict):
        raise ValueError("Pi RPC state type is invalid")
    if set(state) != set(_RESPONSE_KEYS):
        raise ValueError("Pi RPC response keys are not reviewed")
    if (
        state.get("type") != "response"
        or state.get("command") != "get_state"
        or state.get("success") is not True
        or not isinstance(state.get("data"), dict)
    ):
        raise ValueError("Pi RPC get_state response is invalid")
    data = state["data"]
    assert isinstance(data, dict)
    data_keys = set(data)
    allowed_data_keys = set(_RESPONSE_DATA_REQUIRED) | set(_RESPONSE_DATA_OPTIONAL)
    if not set(_RESPONSE_DATA_REQUIRED).issubset(data_keys) or not data_keys.issubset(
        allowed_data_keys
    ):
        raise ValueError("Pi RPC response data keys are not reviewed")
    if (
        not (data.get("model") is None or isinstance(data.get("model"), Mapping))
        or type(data.get("thinkingLevel")) is not str
        or type(data.get("isStreaming")) is not bool
        or type(data.get("isCompacting")) is not bool
        or type(data.get("steeringMode")) is not str
        or type(data.get("followUpMode")) is not str
        or not (data.get("sessionFile") is None or type(data.get("sessionFile")) is str)
        or type(data.get("sessionId")) is not str
        or type(data.get("autoCompactionEnabled")) is not bool
        or type(data.get("messageCount")) is not int
        or type(data.get("pendingMessageCount")) is not int
        or data.get("messageCount", 0) < 0
        or data.get("pendingMessageCount", 0) < 0
    ):
        raise ValueError("Pi RPC response data values are invalid")
    if "version" in data and data.get("version") != "0.84.1":
        raise ValueError("PI_RUNTIME_INCOMPATIBLE")
    agents = data.get("agents", [])
    extensions = data.get("extensions", [])
    tools = data.get("tools", {})
    if (
        not isinstance(agents, list)
        or not agents
        or not all(isinstance(item, str) and item for item in agents)
        or len(agents) != len(set(agents))
    ):
        raise ValueError("Pi role inventory is invalid")
    if not isinstance(extensions, list) or not all(
        isinstance(item, str) and item for item in extensions
    ):
        raise ValueError("Pi extension inventory is invalid")
    if not isinstance(tools, dict):
        raise ValueError("Pi tool inventory is invalid")
    if tuple(extensions) != _REVIEWED_EXTENSIONS:
        raise ValueError("Pi ambient or unreviewed extension discovered")
    known_roles = set(PI_DEFAULT_ROLES + PI_OPTIONAL_ROLES)
    if not tools or set(tools) - known_roles:
        raise ValueError("Pi tool inventory contains an unreviewed role")
    if any(
        not isinstance(role, str)
        or not isinstance(values, list)
        or not all(isinstance(item, str) and item for item in values)
        for role, values in tools.items()
    ):
        raise ValueError("Pi tool inventory is malformed")
    if "package_tools" in data:
        package_tools = data["package_tools"]
        if not isinstance(package_tools, Mapping):
            raise ValueError("Pi package coordination tools are malformed")
        for key, values in package_tools.items():
            if (
                not isinstance(key, str)
                or not key
                or not isinstance(values, list)
                or not values
                or not all(isinstance(item, str) for item in values)
                or not all(item for item in values)
            ):
                raise ValueError("Pi package coordination tools are malformed")
            if any(item.casefold() in _FORBIDDEN_TOOLS for item in values):
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
        "version": data.get("version", version),
        "agents": tuple(agents),
        "extensions": _REVIEWED_EXTENSIONS,
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
            else PUSHER_TOOLS
            if role == "commit-pusher"
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
    if release:
        # This release path is intentionally closed until a reviewed wrapper
        # executes the Pi child through a verified Bubblewrap/Seatbelt backend
        # and supplies the matching sandbox proof to the evidence builder.
        raise ValueError("PI_RELEASE_SANDBOX_UNAVAILABLE")
    root = _private_directory(root, "Pi smoke root")
    agent = _private_directory(root / "agent", "Pi agent directory")
    project = _private_directory(root / "project", "Pi project directory")
    temporary = _private_directory(root / "tmp", "Pi temporary directory")
    _install_helper(agent)
    _install_extension(agent)
    source_roles = _source_inventory()
    _extension_inventory(agent)
    bundled = _bundled_inventory()
    package_before_evidence = _package_evidence(agent)
    _check_effective_catalog(agent, project, package_before_evidence)
    before_exec = _executable_digest(executable)
    before_tree = _tree_signature(agent)
    before_package = _package_signature(agent)
    before_catalog = _catalog_signature()
    before_repository = _repository_signature()
    if release:
        _require_release_package(package_before_evidence)
        if _package_evidence(agent) != package_before_evidence:
            raise ValueError("PI_PACKAGE_INCOMPATIBLE")
    version = _probe_version(executable, agent, project, temporary)
    code, stdout, stderr = _bounded_child(executable, agent, project, temporary)
    after_exec = _executable_digest(executable)
    after_tree = _tree_signature(agent)
    after_package = _package_signature(agent)
    after_repository = _repository_signature()
    if (
        before_exec != after_exec
        or before_tree != after_tree
        or before_package != after_package
        or before_catalog != _catalog_signature()
        or before_repository != after_repository
    ):
        raise ValueError("Pi smoke mutated an inspected identity")
    if code != 0:
        raise ValueError(f"Pi smoke failed: exit:{code}")
    package_after_evidence = _package_evidence(agent)
    if package_before_evidence != package_after_evidence:
        raise ValueError("Pi installed package identity changed")
    _check_effective_catalog(agent, project, package_after_evidence)
    _run_validator_helper(agent, project, temporary)
    helper_tree = _tree_signature(agent)
    helper_package = _package_signature(agent)
    helper_repository = _repository_signature()
    helper_catalog = _catalog_signature()
    if (
        before_tree != helper_tree
        or before_package != helper_package
        or before_repository != helper_repository
        or before_catalog != helper_catalog
        or before_exec != _executable_digest(executable)
        or package_after_evidence != _package_evidence(agent)
    ):
        raise ValueError("Pi validator mutated an inspected identity")
    redacted_stdout = _redact(stdout.decode("utf-8", "replace"), agent).encode()
    _redact(stderr.decode("utf-8", "replace"), agent)
    state, state_status = _safe_state(redacted_stdout, agent, version)
    observed_managed = tuple(state["agents"])  # type: ignore[arg-type]
    if observed_managed and set(observed_managed) not in {
        frozenset(source_roles[:-1]),
        frozenset(source_roles),
    }:
        raise ValueError("Pi optional role inventory drifted")
    managed = (
        source_roles
        if set(observed_managed) == set(source_roles)
        else source_roles[:-1]
    )
    state["agents"] = managed
    optional = tuple(role for role in managed if role in PI_OPTIONAL_ROLES)
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
    if release and version != "0.84.1":
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
        package_status=package_after_evidence.status,
        evidence=(
            "PI_SMOKE_OK",
            state_status,
            "PI_VERSION_0.84.1",
            "RPC_GET_STATE",
            "OFFLINE",
            validator,
            "VALIDATOR_HELPER_EXECUTED",
            "BASH_REJECTED",
        ),
    )


def select_pi_executable(
    executable: Path | None = None,
    root: Path | None = None,
    *,
    release: bool = False,
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
    if root is None:
        raise ValueError("disposable private Pi smoke root is required")
    return run_pi_smoke(executable, root, release=release)
