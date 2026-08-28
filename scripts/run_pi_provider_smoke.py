#!/usr/bin/env python3
"""Run the separately authorized, bounded Pi provider smoke.

This is a release-owner command, not a CI check.  It starts only an absolute,
reviewed Pi executable supplied by the caller.  No package manager, network
client, shell, session, project context, or transcript is used here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import stat
import sys
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

EXPECTED_PI_VERSION = "0.84.1"
PACKAGE_SOURCE = "npm:pi-subagents@0.56.0"
EXPECTED_RESPONSE = "PI_PROVIDER_SMOKE_OK"
_PROMPT = "PI provider compatibility check\n"
_MAX_STREAM = 8192
_TIMEOUT_SECONDS = 30.0
_FIXED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"

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


def _canonical_executable(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProviderSmokeError("PI_EXECUTABLE_NOT_ABSOLUTE")
    if path != Path(os.path.normpath(path)):
        raise ProviderSmokeError("PI_EXECUTABLE_NOT_CANONICAL")
    try:
        item = os.lstat(path)
    except OSError as exc:
        raise ProviderSmokeError("PI_EXECUTABLE_UNAVAILABLE") from exc
    if (
        stat.S_ISLNK(item.st_mode)
        or not stat.S_ISREG(item.st_mode)
        or item.st_uid != os.getuid()
        or item.st_nlink != 1
        or not item.st_mode & 0o111
    ):
        raise ProviderSmokeError("PI_EXECUTABLE_IDENTITY_UNSAFE")
    return path


def _private_output(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProviderSmokeError("OUTPUT_NOT_PRIVATE")
    if path == Path(path.anchor) or path != Path(os.path.normpath(path)):
        raise ProviderSmokeError("OUTPUT_NOT_PRIVATE")
    parent = path.parent
    try:
        parent_item = os.lstat(parent)
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
    if not isinstance(model, str) or model.count("/") != 1:
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
            credentials[name] = value
    if not credentials:
        raise ProviderSmokeError("CREDENTIAL_MISSING")
    return provider.casefold(), credentials


def _bounded_child(
    argv: tuple[str, ...], input_bytes: bytes, env: Mapping[str, str]
) -> tuple[int, bytes, bytes]:
    import subprocess

    try:
        child = subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            shell=False,
            close_fds=True,
        )
    except OSError as exc:
        raise ProviderSmokeError("PI_EXECUTION_FAILED") from exc
    if child.stdin is None or child.stdout is None or child.stderr is None:
        child.kill()
        child.wait()
        raise ProviderSmokeError("PI_EXECUTION_FAILED")
    try:
        child.stdin.write(input_bytes)
        child.stdin.close()
        streams = selectors.DefaultSelector()
        streams.register(child.stdout, selectors.EVENT_READ, "stdout")
        streams.register(child.stderr, selectors.EVENT_READ, "stderr")
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + _TIMEOUT_SECONDS
        overflow = False
        while streams.get_map() and time.monotonic() < deadline:
            for key, _ in streams.select(max(0.0, deadline - time.monotonic())):
                chunk = os.read(key.fd, _MAX_STREAM + 1)
                if not chunk:
                    streams.unregister(key.fileobj)
                    continue
                data = captured[key.data]
                if len(data) + len(chunk) > _MAX_STREAM:
                    overflow = True
                    child.kill()
                    streams.close()
                    child.wait()
                    raise ProviderSmokeError("PI_OUTPUT_LIMIT")
                data.extend(chunk)
        streams.close()
        if streams.get_map():
            child.kill()
            child.wait()
            raise ProviderSmokeError("PI_TIMEOUT")
        code = child.wait()
        if overflow:
            raise ProviderSmokeError("PI_OUTPUT_LIMIT")
        child.stdout.close()
        child.stderr.close()
        return code, bytes(captured["stdout"]), bytes(captured["stderr"])
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        if child.stdout is not None:
            child.stdout.close()
        if child.stderr is not None:
            child.stderr.close()


def _version(executable: Path, env: Mapping[str, str]) -> str:
    code, stdout, _stderr = _bounded_child(
        (str(executable), "--offline", "--version"), b"", env
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
        "PI_OFFLINE": "1",
        "PI_SKIP_VERSION_CHECK": "1",
        "PI_TELEMETRY": "0",
        **credentials,
    }
    version = _version(executable, child_environment)
    started = _timestamp()
    argv = (
        str(executable),
        "--offline",
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
    code, stdout, _stderr = _bounded_child(
        argv, _PROMPT.encode("utf-8"), child_environment
    )
    response_hash_match = (
        hashlib.sha256(stdout.strip()).hexdigest()
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
        "status": ("ok" if code == 0 and response_hash_match else "response_mismatch"),
        "exit_code": code,
        "response_hash_match": response_hash_match,
    }
    try:
        payload = (
            json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        descriptor = os.open(
            safe_output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        safe_output.chmod(0o600)
    except FileExistsError as exc:
        raise ProviderSmokeError("OUTPUT_ALREADY_EXISTS") from exc
    except OSError as exc:
        raise ProviderSmokeError("OUTPUT_WRITE_FAILED") from exc
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
