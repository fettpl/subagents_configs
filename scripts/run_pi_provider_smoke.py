#!/usr/bin/env python3
"""Run the separately authorized, bounded Pi provider smoke.

This is a release-owner command, not a CI check.  It starts only an absolute,
reviewed Pi executable supplied by the caller.  No package manager, direct
network client, shell, session, project context, or transcript is used here;
the separately authorized Pi provider boundary may make its own provider call.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import signal
import stat
import sys
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from subagents_configs import filesystem
from subagents_configs.errors import TransactionError

EXPECTED_PI_VERSION = "0.84.1"
PACKAGE_SOURCE = "npm:pi-subagents@0.56.0"
EXPECTED_RESPONSE = "PI_PROVIDER_SMOKE_OK"
_PROMPT = "PI provider compatibility check\n"
_MAX_STREAM = 8192
_TIMEOUT_SECONDS = 30.0
_FIXED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
_RUNTIME_CONTRACT = (
    Path(__file__).resolve().parents[1]
    / "tests/fixtures/pi-0.84.1-runtime-contract.json"
)
_RPC_REQUEST = {"type": "prompt", "prompt": _PROMPT}
_MAX_MODEL_LENGTH = 256
_MAX_CREDENTIAL_LENGTH = 4096

# Provider names and credential variables are reviewed policy, not arbitrary
# environment passthrough.  Values are copied only for the selected provider.
PROVIDER_CREDENTIALS: Mapping[str, tuple[str, ...]] = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "google": ("GOOGLE_API_KEY", "GEMINI_API_KEY"),
    "openai": ("OPENAI_API_KEY",),
}


class ProviderSmokeError(ValueError):
    """A safe error code that never contains child output or credentials."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _strict_json(value: bytes, code: str) -> object:
    def duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ProviderSmokeError(code)
            result[key] = item
        return result

    try:
        return json.loads(
            value.decode("utf-8"),
            object_pairs_hook=duplicate_keys,
            parse_constant=lambda _constant: (_ for _ in ()).throw(
                ProviderSmokeError(code)
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderSmokeError(code) from exc


def _runtime_rpc_contract() -> dict[str, object]:
    try:
        raw = _RUNTIME_CONTRACT.read_bytes()
    except OSError as exc:
        raise ProviderSmokeError("RPC_CONTRACT_INVALID") from exc
    value = _strict_json(raw, "RPC_CONTRACT_INVALID")
    if not isinstance(value, dict):
        raise ProviderSmokeError("RPC_CONTRACT_INVALID")
    rpc = value.get("rpc")
    if (
        set(value)
        != {
            "schema_version",
            "pi_version",
            "cli",
            "rpc",
            "limits",
            "extension",
            "identity",
        }
        or not isinstance(value.get("cli"), dict)
        or not isinstance(value.get("limits"), dict)
        or not isinstance(value.get("extension"), dict)
        or not isinstance(value.get("identity"), dict)
        or value.get("schema_version") != 1
        or value.get("pi_version") != EXPECTED_PI_VERSION
        or not isinstance(rpc, dict)
        or rpc.get("framing") != "lf-delimited-json"
        or tuple(rpc.get("response_required_keys", ()))
        != ("type", "command", "success", "data")
        or rpc.get("response_type") != "response"
        or rpc.get("provider_request") != _RPC_REQUEST
        or tuple(rpc.get("provider_response_data_keys", ())) != ("text",)
    ):
        raise ProviderSmokeError("RPC_CONTRACT_INVALID")
    return rpc


def _executable_identity(path: Path) -> tuple[int, int, int, int, int, str]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProviderSmokeError("PI_EXECUTABLE_NOT_ABSOLUTE")
    if path != Path(os.path.normpath(path)):
        raise ProviderSmokeError("PI_EXECUTABLE_NOT_CANONICAL")
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        try:
            item = os.lstat(current)
        except OSError as exc:
            raise ProviderSmokeError("PI_EXECUTABLE_UNAVAILABLE") from exc
        if stat.S_ISLNK(item.st_mode) and not (
            current == Path("/var")
            and Path(os.path.realpath(current)) == Path("/private/var")
        ):
            raise ProviderSmokeError("PI_EXECUTABLE_IDENTITY_UNSAFE")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProviderSmokeError("PI_EXECUTABLE_UNAVAILABLE") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or not opened.st_mode & 0o111
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            raise ProviderSmokeError("PI_EXECUTABLE_IDENTITY_UNSAFE")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_nlink) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_nlink,
        ):
            raise ProviderSmokeError("PI_EXECUTABLE_CHANGED")
        return (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            stat.S_IMODE(opened.st_mode),
            opened.st_nlink,
            digest.hexdigest(),
        )
    finally:
        os.close(descriptor)


def _assert_executable_identity(
    path: Path, expected: tuple[int, int, int, int, int, str]
) -> None:
    if _executable_identity(path) != expected:
        raise ProviderSmokeError("PI_EXECUTABLE_CHANGED")


def _canonical_executable(path: Path) -> Path:
    _executable_identity(path)
    return path


def _private_output(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProviderSmokeError("OUTPUT_NOT_PRIVATE")
    if path == Path(path.anchor) or path != Path(os.path.normpath(path)):
        raise ProviderSmokeError("OUTPUT_NOT_PRIVATE")
    parent = path.parent
    current = Path(path.anchor)
    for component in parent.parts[1:]:
        current /= component
        try:
            item = os.lstat(current)
        except OSError as exc:
            raise ProviderSmokeError("OUTPUT_NOT_PRIVATE") from exc
        if stat.S_ISLNK(item.st_mode):
            if current != Path("/var") or Path(os.path.realpath(current)) != Path(
                "/private/var"
            ):
                raise ProviderSmokeError("OUTPUT_NOT_PRIVATE")
    resolved_parent = Path(os.path.realpath(parent))
    try:
        parent_item = os.lstat(resolved_parent)
    except OSError as exc:
        raise ProviderSmokeError("OUTPUT_NOT_PRIVATE") from exc
    parent_is_private = (
        parent_item.st_uid == os.getuid()
        and not stat.S_IMODE(parent_item.st_mode) & 0o077
    )
    # macOS's documented temporary directory is root-owned and sticky.  The
    # result file itself remains owner-only and is created without clobbering.
    parent_is_private_tmp = (
        parent == Path("/private/tmp")
        and parent_item.st_uid == 0
        and stat.S_IMODE(parent_item.st_mode) == 0o1777
    )
    if (
        stat.S_ISLNK(parent_item.st_mode)
        or not stat.S_ISDIR(parent_item.st_mode)
        or not (parent_is_private or parent_is_private_tmp)
    ):
        raise ProviderSmokeError("OUTPUT_NOT_PRIVATE")
    if path != resolved_parent / path.name:
        path = resolved_parent / path.name
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        return path
    except OSError as exc:
        raise ProviderSmokeError("OUTPUT_NOT_PRIVATE") from exc
    if (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != os.getuid()
        or existing.st_nlink != 1
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise ProviderSmokeError("OUTPUT_NOT_PRIVATE")
    raise ProviderSmokeError("OUTPUT_ALREADY_EXISTS")


def _provider_and_credentials(
    model: str, environ: Mapping[str, str]
) -> tuple[str, dict[str, str]]:
    if (
        not isinstance(model, str)
        or model.count("/") != 1
        or not model
        or len(model) > _MAX_MODEL_LENGTH
    ):
        raise ProviderSmokeError("MODEL_INVALID")
    provider, model_id = model.split("/", 1)
    if not provider or not model_id or any(ord(char) < 32 for char in model):
        raise ProviderSmokeError("MODEL_INVALID")
    names = PROVIDER_CREDENTIALS.get(provider.casefold())
    if names is None:
        raise ProviderSmokeError("PROVIDER_NOT_REVIEWED")
    credentials: dict[str, str] = {}
    for name in names:
        value = environ.get(name)
        if value:
            if (
                type(value) is not str
                or len(value) > _MAX_CREDENTIAL_LENGTH
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                raise ProviderSmokeError("CREDENTIAL_INVALID")
            credentials[name] = value
    if not credentials:
        raise ProviderSmokeError("CREDENTIAL_MISSING")
    return provider.casefold(), credentials


def _terminate_process(child: object) -> None:
    import subprocess

    if not isinstance(child, subprocess.Popen):
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except OSError:
        if child.poll() is None:
            try:
                child.terminate()
            except OSError:
                pass
    try:
        child.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except OSError:
            try:
                child.kill()
            except OSError:
                pass
        try:
            child.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass


def _bounded_child(
    argv: tuple[str, ...],
    input_bytes: bytes,
    env: Mapping[str, str],
    *,
    executable: Path,
    identity: tuple[int, int, int, int, int, str],
) -> tuple[int, bytes, bytes]:
    import subprocess

    # The caller's identity is checked before Popen as well as immediately
    # after it.  The descriptor is reopened with O_NOFOLLOW on every check;
    # any replacement is therefore rejected even if a prior probe was safe.
    _assert_executable_identity(executable, identity)
    try:
        child = subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise ProviderSmokeError("PI_EXECUTION_FAILED") from exc
    if child.stdin is None or child.stdout is None or child.stderr is None:
        _terminate_process(child)
        raise ProviderSmokeError("PI_EXECUTION_FAILED")
    try:
        _assert_executable_identity(executable, identity)
        child.stdin.write(input_bytes)
        child.stdin.close()
        streams = selectors.DefaultSelector()
        streams.register(child.stdout, selectors.EVENT_READ, "stdout")
        streams.register(child.stderr, selectors.EVENT_READ, "stderr")
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + _TIMEOUT_SECONDS
        while child.poll() is None or streams.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process(child)
                raise ProviderSmokeError("PI_TIMEOUT")
            for key, _ in streams.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, _MAX_STREAM + 1)
                if not chunk:
                    streams.unregister(key.fileobj)
                    continue
                data = captured[key.data]
                if len(data) + len(chunk) > _MAX_STREAM:
                    _terminate_process(child)
                    raise ProviderSmokeError("PI_OUTPUT_LIMIT")
                data.extend(chunk)
        streams.close()
        code = child.returncode
        if code is None:
            raise ProviderSmokeError("PI_EXECUTION_FAILED")
        try:
            _assert_executable_identity(executable, identity)
        except ProviderSmokeError:
            _terminate_process(child)
            raise
        child.stdout.close()
        child.stderr.close()
        _terminate_process(child)
        return code, bytes(captured["stdout"]), bytes(captured["stderr"])
    finally:
        if child.poll() is None:
            _terminate_process(child)
        if child.stdout is not None:
            child.stdout.close()
        if child.stderr is not None:
            child.stderr.close()


def _version(executable: Path, env: Mapping[str, str]) -> str:
    identity = _executable_identity(executable)
    code, stdout, _stderr = _bounded_child(
        (str(executable), "--offline", "--version"),
        b"",
        env,
        executable=executable,
        identity=identity,
    )
    if code != 0:
        raise ProviderSmokeError("PI_VERSION_UNAVAILABLE")
    version = stdout.decode("utf-8", errors="strict").strip()
    if version != EXPECTED_PI_VERSION:
        raise ProviderSmokeError("PI_VERSION_MISMATCH")
    return version


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def run_provider_smoke(
    pi_executable: Path,
    model: str,
    output: Path,
    *,
    authorize_provider_smoke: bool = False,
    environ: Mapping[str, str] | None = None,
    interactive: bool | None = None,
) -> dict[str, object]:
    """Run one fixed prompt and write only a safe result object."""

    if not authorize_provider_smoke:
        raise ProviderSmokeError("AUTHORIZATION_REQUIRED")
    if interactive is None:
        interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
    if not interactive:
        raise ProviderSmokeError("INTERACTIVE_REQUIRED")
    executable = _canonical_executable(pi_executable)
    safe_output = _private_output(output)
    source_environment = os.environ if environ is None else environ
    _provider, credentials = _provider_and_credentials(model, source_environment)
    child_environment = {
        "PATH": _FIXED_PATH,
        "PI_SKIP_VERSION_CHECK": "1",
        "PI_TELEMETRY": "0",
        **credentials,
    }
    version = _version(executable, {**child_environment, "PI_OFFLINE": "1"})
    rpc = _runtime_rpc_contract()
    started = _timestamp()
    argv = (
        str(executable),
        "--mode",
        "rpc",
        "--no-session",
        "--no-context-files",
        "--no-tools",
        "--no-project-context",
        "--no-telemetry",
        "--no-update-check",
        "--model",
        model,
    )
    identity = _executable_identity(executable)
    code, stdout, _stderr = _bounded_child(
        argv,
        (
            json.dumps(_RPC_REQUEST, ensure_ascii=True, separators=(",", ":")) + "\n"
        ).encode("utf-8"),
        child_environment,
        executable=executable,
        identity=identity,
    )
    response_hash_match = False
    if code == 0:
        if b"\r" in stdout or stdout.count(b"\n") != 1:
            raise ProviderSmokeError("RPC_INVALID")
        response = _strict_json(stdout.rstrip(b"\n"), "RPC_INVALID")
        if not isinstance(response, dict):
            raise ProviderSmokeError("RPC_INVALID")
        required = tuple(rpc["response_required_keys"])
        if set(response) != set(required):
            raise ProviderSmokeError("RPC_INVALID")
        data = response.get("data")
        if (
            response.get("type") != rpc["response_type"]
            or response.get("command") != "prompt"
            or response.get("success") is not True
            or not isinstance(data, dict)
            or set(data) != {"text"}
            or type(data.get("text")) is not str
        ):
            raise ProviderSmokeError("RPC_INVALID")
        response_hash_match = (
            hashlib.sha256(data["text"].encode("utf-8")).hexdigest()
            == hashlib.sha256(EXPECTED_RESPONSE.encode("utf-8")).hexdigest()
        )
    ended = _timestamp()
    result: dict[str, object] = {
        "schema_version": 1,
        "pi_version": version,
        "package_source": PACKAGE_SOURCE,
        "model": model,
        "started_at": started,
        "ended_at": ended,
        "status": (
            "ok"
            if code == 0 and response_hash_match
            else "process_failed"
            if code != 0
            else "response_mismatch"
        ),
        "exit_code": code,
        "response_hash_match": response_hash_match,
    }
    try:
        payload = (
            json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        with filesystem.expected_atomic_identity(None):
            filesystem.atomic_write(safe_output, payload, mode=0o600)
    except FileExistsError as exc:
        raise ProviderSmokeError("OUTPUT_ALREADY_EXISTS") from exc
    except TransactionError as exc:
        raise ProviderSmokeError("OUTPUT_ALREADY_EXISTS") from exc
    except ProviderSmokeError:
        raise
    except ValueError as exc:
        raise ProviderSmokeError("OUTPUT_WRITE_FAILED") from exc
    except OSError as exc:
        raise ProviderSmokeError("OUTPUT_WRITE_FAILED") from exc
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--authorize-provider-smoke", action="store_true")
    parser.add_argument("--pi-executable", required=True, type=Path)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        run_provider_smoke(
            args.pi_executable,
            args.model,
            args.output,
            authorize_provider_smoke=args.authorize_provider_smoke,
        )
    except ProviderSmokeError as exc:
        print(f"provider smoke failed: {exc.code}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
