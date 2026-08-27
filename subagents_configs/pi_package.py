"""Fail-closed verification and lifecycle helpers for the reviewed Pi package.

This module deliberately knows only Pi's official package commands.  It never
invokes a package manager, a shell, a package installer script, or a fallback
removal command.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from . import filesystem
from .errors import PiPackageError, TransactionError
from .models import DesiredFile, IdentityEvidence

PACKAGE_POLICY_PATH = Path(__file__).resolve().parents[1] / "pi/package-policy.json"
_PACKAGE_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "tests/fixtures/pi-subagents-0.56.0-package.json"
)
_LOCK_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "tests/fixtures/pi-subagents-0.56.0-package-lock.json"
)
_PACKAGE_SOURCE = "npm:pi-subagents@0.56.0"
_REMOVE_SOURCE = "npm:pi-subagents"
_PACKAGE_NAME = "pi-subagents"
_PACKAGE_VERSION = "0.56.0"
_PI_VERSION = "0.84.1"
_MAX_OUTPUT = 4096
_COMMAND_TIMEOUT = 20
_SYSTEM_TMP = Path(os.sep) / "tmp"
_FORBIDDEN_EXECUTABLE_NAMES = frozenset({"npm", "npx", "node", "git", "install.mjs"})
_RECEIPT_RELATIVE = Path(".subagents_configs/pi-package-receipt.json")
_ALLOWED_ENV = {
    "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
    "PI_TELEMETRY": "0",
    "PI_SKIP_VERSION_CHECK": "1",
    "GIT_TERMINAL_PROMPT": "0",
}
_RUNTIME_PROOF = object()
_EXPECTED_AGENT_IDENTITY_UNSET = object()
_SAFE_CONFIG_KEYS = frozenset(
    {
        "toolDescriptionMode",
        "inlineToolDisplay",
        "mainWindowRenderer",
        "foregroundDetachShortcut",
        "orcaProgressTabs",
        "asyncByDefault",
        "fleetView",
        "fleetViewPlacement",
        "fleetKeybindings",
        "asyncWidget",
        "waitTool",
        "resultScanLogging",
        "forceTopLevelAsync",
        "intercomBridge",
    }
)
_UNSAFE_CONFIG_FRAGMENTS = (
    "tool",
    "agent",
    "role",
    "override",
    "extension",
    "skill",
    "alias",
    "model",
    "thinking",
    "range",
    "authority",
    "permission",
    "provider",
    "source",
    "manager",
    "registry",
    "command",
    "path",
    "binary",
    "hook",
)


@dataclass(frozen=True)
class PiRuntimeEvidence:
    executable: Path
    version: str | None
    device: int
    inode: int
    mode: int
    sha256: str
    help_has_install: bool
    help_has_remove: bool
    help_has_offline: bool
    _proof: object | None = field(default=None, repr=False, compare=False)
    _size: int | None = field(default=None, repr=False, compare=False)
    _nlink: int | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class PiPackageEvidence:
    settings_path: Path
    settings_hash: str | None
    package_entries: tuple[str, ...]
    status: Literal["absent", "exact", "conflict"]
    exact_pinned_entry: bool
    installed_lock_path: Path | None
    installed_lock_root_hash: str | None
    package_manifest_path: Path | None
    manifest_hash: str | None
    package_identity_valid: bool


@dataclass(frozen=True)
class _PiPackageSnapshot:
    """Private package evidence, including the store identity race proof."""

    evidence: PiPackageEvidence
    package_store_identity: tuple[int, int, int, int, int] | None


@dataclass(frozen=True)
class PiPackageReceipt:
    schema_version: Literal[1]
    operation: Literal["install", "remove", "none"]
    source: str
    remove_source: str
    settings_before_hash: str | None
    settings_after_hash: str | None
    package_manifest_hash: str
    package_policy_hash: str
    created_exact_entry: bool


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _read_json_bytes(
    path: Path, label: str, *, private: bool = False
) -> tuple[dict[str, object], str]:
    """Read one JSON file through a pinned descriptor and return its hash.

    The pre/post lstat checks only enforce the owner and final mode; the bytes,
    size, inode, link count, and mode are bound to the descriptor evidence from
    ``filesystem.read_bytes_with_evidence``.  This keeps all managed reads
    descriptor-relative while retaining the public six-field evidence API.
    """

    path = _filesystem_path(path, label)
    try:
        item = os.lstat(path)
    except FileNotFoundError as exc:
        raise ValueError(f"{label} is missing") from exc
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise ValueError(f"{label} is not a regular file")
    if (
        item.st_nlink != 1
        or item.st_uid != os.getuid()
        or (private and stat.S_IMODE(item.st_mode) != 0o600)
    ):
        raise ValueError(f"{label} has unsafe identity or mode")
    try:
        evidence, raw = filesystem.read_bytes_with_evidence(path, label)
    except FileNotFoundError as exc:
        raise ValueError(f"{label} is missing") from exc
    except (OSError, ValueError, TransactionError) as exc:
        raise ValueError(f"{label} cannot be read safely") from exc
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} identity changed") from exc
    if (
        (
            evidence.device,
            evidence.inode,
            evidence.size,
            evidence.nlink,
            evidence.mode,
        )
        != (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_nlink,
            stat.S_IMODE(item.st_mode),
        )
        or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_nlink,
            stat.S_IMODE(after.st_mode),
        )
        != (
            evidence.device,
            evidence.inode,
            evidence.size,
            evidence.nlink,
            evidence.mode,
        )
        or after.st_uid != os.getuid()
    ):
        raise ValueError(f"{label} identity changed")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"{label} is malformed") from exc
    if type(value) is not dict:
        raise ValueError(f"{label} must be an object")
    return value, evidence.sha256


def _read_json(path: Path, label: str, *, private: bool = False) -> dict[str, object]:
    value, _ = _read_json_bytes(path, label, private=private)
    return value


def _sha256(path: Path) -> str:
    path = _filesystem_path(path, "hashed file")
    try:
        evidence, _ = filesystem.read_bytes_with_evidence(path, "hashed file")
    except (OSError, ValueError, TransactionError) as exc:
        raise ValueError("file hash unavailable") from exc
    if evidence.nlink != 1:
        raise ValueError("file hash target has unsafe link count")
    return evidence.sha256


def _hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _check_policy(policy: Mapping[str, object], path: Path) -> Mapping[str, object]:
    expected = {
        "source",
        "removeSource",
        "name",
        "version",
        "testedPiVersion",
        "upstreamCommit",
        "distIntegrity",
        "packageJsonSha256",
        "packageLockSha256",
        "type",
        "pi",
        "dependencies",
        "peerDependencies",
        "bundledAgents",
        "forbiddenLifecycleScripts",
    }
    if set(policy) != expected:
        raise ValueError("Pi package policy schema changed")
    fixed = {
        "source": _PACKAGE_SOURCE,
        "removeSource": _REMOVE_SOURCE,
        "name": _PACKAGE_NAME,
        "version": _PACKAGE_VERSION,
        "testedPiVersion": _PI_VERSION,
        "upstreamCommit": "a0e2b9e31de5970215a567e20e2d781bbbddf235",
        "distIntegrity": (
            "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
        ),
        "packageJsonSha256": (
            "e35c5acf7f2c75fcfd182b1eaa67f8485abc5ea81ac63598ef8ad637d3e788be"
        ),
        "packageLockSha256": (
            "76b359ad4a8ecf20892d169ba5cce7892a54d8217024b115bff9262c5a1d4f04"
        ),
        "type": "module",
    }
    for key, value in fixed.items():
        if policy.get(key) != value:
            raise ValueError("Pi package policy identity drifted")
    pi = policy["pi"]
    if type(pi) is not dict or pi != {
        "extensions": ["./index.ts"],
        "skills": ["./skills"],
        "prompts": ["./prompts"],
    }:
        raise ValueError("Pi package policy entrypoint drifted")
    dependencies = {
        "acorn": "8.18.0",
        "jiti": "2.7.0",
        "typebox": "1.1.38",
        "yaml": "2.8.3",
    }
    peers = {
        "@earendil-works/pi-agent-core": "*",
        "@earendil-works/pi-ai": ">=0.80.0",
        "@earendil-works/pi-coding-agent": "*",
        "@earendil-works/pi-tui": "*",
    }
    if policy["dependencies"] != dependencies or policy["peerDependencies"] != peers:
        raise ValueError("Pi package dependency policy drifted")
    if policy["bundledAgents"] != [
        "delegate",
        "oracle",
        "researcher",
        "reviewer",
        "scout",
        "worker",
    ]:
        raise ValueError("Pi bundled inventory drifted")
    if policy["forbiddenLifecycleScripts"] != [
        "preinstall",
        "install",
        "postinstall",
        "prepare",
    ]:
        raise ValueError("Pi lifecycle policy drifted")
    if (
        _sha256(_PACKAGE_FIXTURE) != policy["packageJsonSha256"]
        or _sha256(_LOCK_FIXTURE) != policy["packageLockSha256"]
    ):
        raise ValueError("reviewed Pi provenance fixture hash mismatch")
    package = _read_json(_PACKAGE_FIXTURE, "upstream package fixture")
    lock = _read_json(_LOCK_FIXTURE, "upstream lock fixture")
    if (
        package.get("name") != _PACKAGE_NAME
        or package.get("version") != _PACKAGE_VERSION
    ):
        raise ValueError("upstream package fixture identity mismatch")
    root = lock.get("packages")
    if type(root) is not dict or type(root.get("")) is not dict:
        raise ValueError("upstream lock fixture root missing")
    scripts = package.get("scripts")
    if type(scripts) is not dict or any(
        key in scripts for key in policy["forbiddenLifecycleScripts"]
    ):
        raise ValueError("upstream package fixture has forbidden lifecycle script")
    return MappingProxyType(dict(policy))


def load_pi_package_policy(path: Path = PACKAGE_POLICY_PATH) -> Mapping[str, object]:
    """Load and verify the reviewed policy and its immutable provenance bytes."""

    if not isinstance(path, Path) or path.is_symlink() or not path.is_absolute():
        raise ValueError("policy path must be an absolute regular file")
    return _check_policy(_read_json(path, "Pi package policy"), path)


def _reviewed_policy_hash() -> str:
    load_pi_package_policy(PACKAGE_POLICY_PATH)
    return _sha256(PACKAGE_POLICY_PATH)


def pi_package_policy_hash() -> str:
    """Return the hash of the currently reviewed Pi package policy."""

    return _reviewed_policy_hash()


def _revalidate_reviewed_policy(expected_hash: str) -> None:
    if _reviewed_policy_hash() != expected_hash:
        raise ValueError("Pi package policy changed during command")


def _lexical_absolute(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    raw = os.fspath(path)
    if (
        "\\" in raw
        or "\x00" in raw
        or any(ord(char) < 32 or ord(char) == 127 for char in raw)
    ):
        raise ValueError(f"{label} contains unsafe characters")
    normalized = Path(os.path.normpath(raw))
    if raw != os.fspath(normalized) or ".." in path.parts or "." in path.parts:
        raise ValueError(f"{label} must be lexically normalized")
    return path


def _check_components(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            item = os.lstat(current)
        except FileNotFoundError:
            break
        # macOS commonly exposes the private temporary root through /var ->
        # /private/var.  It is a trusted system prefix, while links below it
        # remain rejected.
        if stat.S_ISLNK(item.st_mode):
            if current == Path("/var"):
                continue
            raise ValueError(f"{label} contains a symlink")
        if current != path and not stat.S_ISDIR(item.st_mode):
            raise ValueError(f"{label} contains a non-directory component")


def _filesystem_path(path: Path, label: str) -> Path:
    """Canonicalize only macOS's trusted ``/var`` compatibility link.

    The descriptor helpers intentionally open every component with
    ``O_NOFOLLOW``.  macOS presents temporary directories below ``/var`` as a
    system link to ``/private/var``; spell that one known link canonically
    after checking that its target is exactly the system target.  No
    user-controlled link is ever resolved here.
    """

    _lexical_absolute(path, label)
    _check_components(path, label)
    raw = os.fspath(path)
    if raw == "/var" or raw.startswith("/var/"):
        try:
            item = os.lstat("/var")
            target = os.readlink("/var") if stat.S_ISLNK(item.st_mode) else None
        except OSError as exc:
            raise ValueError(f"{label} system prefix cannot be inspected") from exc
        if target is not None:
            if target not in {"/private/var", "private/var"}:
                raise ValueError(f"{label} contains an untrusted system link")
            return Path("/private" + raw)
    return path


def _validate_agent_dir(agent_dir: Path) -> Path:
    result = _lexical_absolute(agent_dir, "agent directory")
    _check_components(result, "agent directory")
    try:
        item = os.lstat(result)
    except FileNotFoundError:
        return result
    if not stat.S_ISDIR(item.st_mode):
        raise ValueError("agent directory is unsafe")
    if item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) & 0o077:
        raise ValueError("agent directory must be owner-private")
    return result


def _executable_identity(path: Path) -> tuple[os.stat_result, str]:
    path = _filesystem_path(path, "Pi executable")
    if path.name.casefold() in _FORBIDDEN_EXECUTABLE_NAMES:
        raise ValueError("Pi executable name is not allowed")
    try:
        item = os.lstat(path)
    except OSError as exc:
        raise ValueError("Pi executable cannot be inspected") from exc
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise ValueError("Pi executable must be a regular file")
    if (
        item.st_uid != os.getuid()
        or item.st_nlink != 1
        or not item.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    ):
        raise ValueError("Pi executable identity is unsafe")
    descriptor: int | None = None
    try:
        descriptor = filesystem._open_regular_read(path, "Pi executable")
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(item.st_mode)
        ):
            raise ValueError("Pi executable identity is unsafe")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 65536):
            digest.update(chunk)
    except OSError as exc:
        raise ValueError("Pi executable cannot be hashed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_nlink,
        stat.S_IMODE(opened.st_mode),
    ) != (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_nlink,
        stat.S_IMODE(item.st_mode),
    ):
        raise ValueError("Pi executable identity changed")
    return item, digest.hexdigest()


def _executable_identity_tuple(
    item: os.stat_result, digest: str
) -> tuple[int, int, int, int, int, str]:
    return (
        item.st_dev,
        item.st_ino,
        stat.S_IMODE(item.st_mode),
        item.st_size,
        item.st_nlink,
        digest,
    )


def _expected_executable_identity(
    expected: PiRuntimeEvidence | tuple[int, int, int, int, int, str],
) -> tuple[int, int, int, int, int, str]:
    if isinstance(expected, PiRuntimeEvidence):
        if expected._size is None or expected._nlink is None:
            raise ValueError("expected Pi executable evidence is incomplete")
        return (
            expected.device,
            expected.inode,
            expected.mode,
            expected._size,
            expected._nlink,
            expected.sha256,
        )
    if (
        type(expected) is not tuple
        or len(expected) != 6
        or any(type(value) is not int for value in expected[:5])
        or type(expected[5]) is not str
    ):
        raise TypeError("expected Pi executable evidence has the wrong type")
    return expected


def _agent_directory_identity(path: Path) -> tuple[int, int, int, int, int] | None:
    path = _filesystem_path(path, "Pi agent directory")
    try:
        item = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(item.st_mode):
        raise ValueError("Pi agent directory is not a directory")
    if item.st_uid != os.getuid():
        raise ValueError("Pi agent directory identity is unsafe")
    if stat.S_IMODE(item.st_mode) & 0o077:
        raise ValueError("Pi agent directory must be owner-private")
    return (
        item.st_dev,
        item.st_ino,
        stat.S_IMODE(item.st_mode),
        item.st_uid,
        item.st_nlink,
    )


def _require_existing_agent_directory(
    agent_dir: Path, *, error_code: str
) -> tuple[Path, tuple[int, int, int, int, int]]:
    """Validate that a spawn target is an existing owner-private directory."""

    try:
        normalized = _validate_agent_dir(agent_dir)
        identity = _agent_directory_identity(normalized)
    except (OSError, ValueError) as exc:
        raise PiPackageError(error_code) from exc
    if identity is None:
        raise PiPackageError(error_code)
    return normalized, identity


def _agent_directory_matches(
    actual: tuple[int, int, int, int, int] | None,
    expected: tuple[int, int, int, int, int] | None,
    *,
    allow_new_children: bool,
    allow_removed_children: bool = False,
) -> bool:
    if actual is None or expected is None:
        return actual == expected
    if actual[:4] != expected[:4]:
        return False
    if allow_new_children:
        return actual[4] >= expected[4]
    if allow_removed_children:
        return actual[4] <= expected[4]
    return actual[4] == expected[4]


def _safe_env(agent_dir: Path, npm_config_userconfig: Path) -> dict[str, str]:
    env = dict(_ALLOWED_ENV)
    env["PI_CODING_AGENT_DIR"] = os.fspath(agent_dir)
    env["NPM_CONFIG_USERCONFIG"] = os.fspath(npm_config_userconfig)
    return env


def _sanitize_output(value: str) -> str:
    """Bound and redact untrusted child output before it leaves this module."""

    # Keep output useful only for internal exact parsing; callers receive no
    # raw child text.  Redaction is deliberately conservative and handles
    # URLs, absolute paths, assignment-looking secrets, ANSI, and controls.
    value = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))", "", value)
    value = re.sub(r"(?i)\b(?:https?|ftp|file)://[^\s]+", "<redacted-url>", value)
    value = re.sub(
        r"\b[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|AUTH|PROXY)?\s*=\s*[^\s]+",
        "<redacted-assignment>",
        value,
        flags=re.IGNORECASE,
    )
    value = re.sub(
        r"(?<![A-Za-z0-9_])(?:/[^\s]+|~[/\\][^\s]+)",
        "<redacted-path>",
        value,
    )
    value = re.sub(
        r"(?i)\b(?:npm|npx|node|git)(?:\.js)?\b",
        "<redacted-program>",
        value,
    )
    value = "".join(
        char if char in "\n\t\r" or ord(char) >= 32 else "?" for char in value
    )
    encoded = value.encode("utf-8", "replace")[:_MAX_OUTPUT]
    return encoded.decode("utf-8", "replace")


def _before_bounded_spawn(_argv: tuple[str, ...], _agent_dir: Path) -> None:
    """Test seam immediately before the final executable/home identity proofs."""


def _before_package_evidence(_argv: tuple[str, ...], _agent_dir: Path) -> None:
    """Test seam after executable/home proofs and before package evidence."""


def _create_private_npm_config(working_directory: Path) -> Path:
    """Create the empty, private npm config used by every Pi child."""

    path = working_directory / ".npmrc"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        item = os.fstat(descriptor)
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != os.getuid()
            or item.st_nlink != 1
            or stat.S_IMODE(item.st_mode) != 0o600
        ):
            raise PiPackageError("PI_PACKAGE_COMMAND")
    except OSError as exc:
        raise PiPackageError("PI_PACKAGE_COMMAND") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return path


def _working_directory_identity(path: Path) -> tuple[int, int, int, int]:
    try:
        item = os.lstat(path)
    except OSError as exc:
        raise PiPackageError("Pi command working directory is unsafe") from exc
    if (
        not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.getuid()
        or stat.S_IMODE(item.st_mode) != 0o700
    ):
        raise PiPackageError("Pi command working directory is unsafe")
    return item.st_dev, item.st_ino, stat.S_IMODE(item.st_mode), item.st_uid


def _fixed_tmp_root() -> Path:
    """Return the fixed OS temporary root without honoring TMPDIR."""

    try:
        item = os.lstat(_SYSTEM_TMP)
    except OSError as exc:
        raise PiPackageError("Pi command working directory is unsafe") from exc
    if stat.S_ISLNK(item.st_mode):
        try:
            target = os.readlink(_SYSTEM_TMP)
        except OSError as exc:
            raise PiPackageError("Pi command working directory is unsafe") from exc
        if target not in {"/private/tmp", "private/tmp"}:
            raise PiPackageError("Pi command working directory is unsafe")
        return Path("/private/tmp")
    if not stat.S_ISDIR(item.st_mode):
        raise PiPackageError("Pi command working directory is unsafe")
    return _SYSTEM_TMP


def _cleanup_working_directory(
    path: Path, expected: tuple[int, int, int, int] | None
) -> None:
    """Remove only the owned temporary directory through pinned descriptors."""

    if expected is None:
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd: int | None = None
    directory_fd: int | None = None
    try:
        parent_fd = os.open(path.parent, flags)
        entry = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(entry.st_mode)
            or (entry.st_dev, entry.st_ino, stat.S_IMODE(entry.st_mode), entry.st_uid)
            != expected
        ):
            raise PiPackageError("Pi command working directory cleanup failed")
        directory_fd = os.open(path.name, flags, dir_fd=parent_fd)
        opened = os.fstat(directory_fd)
        if (
            opened.st_dev,
            opened.st_ino,
            stat.S_IMODE(opened.st_mode),
            opened.st_uid,
        ) != expected:
            raise PiPackageError("Pi command working directory cleanup failed")
        for name in os.listdir(directory_fd):
            child = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(child.st_mode):
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    child_opened = os.fstat(child_fd)
                    if (
                        child_opened.st_dev,
                        child_opened.st_ino,
                        stat.S_IMODE(child_opened.st_mode),
                        child_opened.st_uid,
                    ) != (
                        child.st_dev,
                        child.st_ino,
                        stat.S_IMODE(child.st_mode),
                        child.st_uid,
                    ):
                        raise PiPackageError(
                            "Pi command working directory cleanup failed"
                        )
                    _cleanup_directory_fd(child_fd)
                finally:
                    os.close(child_fd)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    current.st_dev,
                    current.st_ino,
                    stat.S_IMODE(current.st_mode),
                    current.st_uid,
                ) != (
                    child.st_dev,
                    child.st_ino,
                    stat.S_IMODE(child.st_mode),
                    child.st_uid,
                ):
                    raise PiPackageError("Pi command working directory cleanup failed")
                os.rmdir(name, dir_fd=directory_fd)
            else:
                if not stat.S_ISLNK(child.st_mode) and stat.S_ISREG(child.st_mode):
                    opened_child = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=directory_fd,
                    )
                    try:
                        child_opened = os.fstat(opened_child)
                        if (
                            child_opened.st_dev,
                            child_opened.st_ino,
                            child_opened.st_size,
                            child_opened.st_nlink,
                            stat.S_IMODE(child_opened.st_mode),
                            child_opened.st_uid,
                        ) != (
                            child.st_dev,
                            child.st_ino,
                            child.st_size,
                            child.st_nlink,
                            stat.S_IMODE(child.st_mode),
                            child.st_uid,
                        ):
                            raise PiPackageError(
                                "Pi command working directory cleanup failed"
                            )
                    finally:
                        os.close(opened_child)
                os.unlink(name, dir_fd=directory_fd)
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            current.st_dev,
            current.st_ino,
            stat.S_IMODE(current.st_mode),
            current.st_uid,
        ) != expected:
            raise PiPackageError("Pi command working directory cleanup failed")
        os.rmdir(path.name, dir_fd=parent_fd)
    except PiPackageError:
        raise
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        raise PiPackageError("Pi command working directory cleanup failed") from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _cleanup_directory_fd(directory_fd: int) -> None:
    for name in os.listdir(directory_fd):
        child = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(child.st_mode):
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            child_fd = os.open(name, flags, dir_fd=directory_fd)
            try:
                child_opened = os.fstat(child_fd)
                if (
                    child_opened.st_dev,
                    child_opened.st_ino,
                    stat.S_IMODE(child_opened.st_mode),
                    child_opened.st_uid,
                ) != (
                    child.st_dev,
                    child.st_ino,
                    stat.S_IMODE(child.st_mode),
                    child.st_uid,
                ):
                    raise PiPackageError("Pi command working directory cleanup failed")
                _cleanup_directory_fd(child_fd)
            finally:
                os.close(child_fd)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                current.st_dev,
                current.st_ino,
                stat.S_IMODE(current.st_mode),
                current.st_uid,
            ) != (
                child.st_dev,
                child.st_ino,
                stat.S_IMODE(child.st_mode),
                child.st_uid,
            ):
                raise PiPackageError("Pi command working directory cleanup failed")
            os.rmdir(name, dir_fd=directory_fd)
        else:
            if not stat.S_ISLNK(child.st_mode) and stat.S_ISREG(child.st_mode):
                opened_child = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    child_opened = os.fstat(opened_child)
                    if (
                        child_opened.st_dev,
                        child_opened.st_ino,
                        child_opened.st_size,
                        child_opened.st_nlink,
                        stat.S_IMODE(child_opened.st_mode),
                        child_opened.st_uid,
                    ) != (
                        child.st_dev,
                        child.st_ino,
                        child.st_size,
                        child.st_nlink,
                        stat.S_IMODE(child.st_mode),
                        child.st_uid,
                    ):
                        raise PiPackageError(
                            "Pi command working directory cleanup failed"
                        )
                finally:
                    os.close(opened_child)
            os.unlink(name, dir_fd=directory_fd)


def _bounded_spawn(
    argv: tuple[str, ...],
    *,
    agent_dir: Path,
    expected_executable: PiRuntimeEvidence
    | tuple[int, int, int, int, int, str]
    | None = None,
    expected_agent_dir: tuple[int, int, int, int, int] | object | None = (
        _EXPECTED_AGENT_IDENTITY_UNSET
    ),
    expected_package: _PiPackageSnapshot | None = None,
) -> tuple[int, str, str]:
    if (
        not isinstance(argv, tuple)
        or not argv
        or any(type(argument) is not str for argument in argv)
        or not Path(argv[0]).is_absolute()
        or Path(argv[0]).name.casefold() in _FORBIDDEN_EXECUTABLE_NAMES
    ):
        raise ValueError("Pi command executable must be absolute")
    allowed_tail = {
        ("--offline", "--version"),
        ("--offline", "--help"),
        ("install", _PACKAGE_SOURCE),
        ("remove", _REMOVE_SOURCE),
    }
    if argv[1:] not in allowed_tail:
        raise PiPackageError("Pi package command is not allowlisted")
    # Do not let a poisoned TMPDIR or process cwd select where an untrusted
    # Pi process runs.  ``/tmp`` is the fixed OS temporary root (on macOS it
    # is the system-owned compatibility link to ``/private/tmp``).
    working_directory: Path | None = None
    working_directory_identity: tuple[int, int, int, int] | None = None
    npm_config_userconfig: Path | None = None
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        working_directory = Path(
            tempfile.mkdtemp(prefix="pi-check-", dir=_fixed_tmp_root())
        )
        working_directory.chmod(0o700)
        working_directory_identity = _working_directory_identity(working_directory)
        npm_config_userconfig = _create_private_npm_config(working_directory)
        _before_bounded_spawn(argv, agent_dir)
        # Revalidate executable and agent directory immediately before
        # handing them to the child. The package evidence comparison must be
        # the final validation operation, so a package/settings/lock/manifest
        # or store mutation after these proofs is still caught before Popen.
        try:
            current_executable, current_hash = _executable_identity(Path(argv[0]))
        except ValueError as exc:
            if expected_executable is not None:
                raise PiPackageError("Pi executable identity changed") from exc
            raise
        if expected_executable is not None and _executable_identity_tuple(
            current_executable, current_hash
        ) != _expected_executable_identity(expected_executable):
            raise PiPackageError("Pi executable identity changed")
        try:
            current_agent_dir = _agent_directory_identity(agent_dir)
        except ValueError as exc:
            raise PiPackageError("PI_PACKAGE_CONFLICT") from exc
        if current_agent_dir is None:
            raise PiPackageError("PI_PACKAGE_CONFLICT")
        if (
            expected_agent_dir is not _EXPECTED_AGENT_IDENTITY_UNSET
            and not _agent_directory_matches(
                current_agent_dir, expected_agent_dir, allow_new_children=False
            )
        ):
            raise PiPackageError("PI_PACKAGE_CONFLICT")
        _before_package_evidence(argv, agent_dir)
        if expected_package is not None:
            try:
                current_package = _inspect_pi_package_state_snapshot(agent_dir)
            except (OSError, ValueError, TransactionError) as exc:
                raise PiPackageError("PI_PACKAGE_CONFLICT") from exc
            if current_package != expected_package:
                raise PiPackageError("PI_PACKAGE_CONFLICT")
        process = subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_directory,
            env=_safe_env(agent_dir, npm_config_userconfig),
            shell=False,
            close_fds=True,
            start_new_session=True,
            umask=0o077,
        )
        selector = selectors.DefaultSelector()
        if process.stdout is None or process.stderr is None:
            process.kill()
            process.wait()
            raise PiPackageError("Pi command pipes are unavailable")
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = time.monotonic() + _COMMAND_TIMEOUT
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise PiPackageError("Pi command timed out")
            for key, _ in selector.select(min(0.2, remaining)):
                data = os.read(key.fileobj.fileno(), 1024)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                target = chunks[key.data]
                if len(target) < _MAX_OUTPUT:
                    target.extend(data[: _MAX_OUTPUT - len(target)])
            if process.poll() is not None and not selector.get_map():
                break
        try:
            code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise PiPackageError("Pi command timed out") from exc
    except OSError as exc:
        raise PiPackageError("Pi command could not start") from exc
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                process.wait()
        if selector is not None:
            selector.close()
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        if working_directory is not None:
            primary_exception = sys.exc_info()[0] is not None
            try:
                _cleanup_working_directory(
                    working_directory, working_directory_identity
                )
            except BaseException as exc:
                if not primary_exception:
                    raise PiPackageError(
                        "Pi command working directory cleanup failed"
                    ) from exc
    if process is None:
        raise PiPackageError("Pi command could not start")
    if expected_executable is not None:
        try:
            final_executable, final_hash = _executable_identity(Path(argv[0]))
        except ValueError as exc:
            raise PiPackageError("Pi executable identity changed") from exc
        if _executable_identity_tuple(
            final_executable, final_hash
        ) != _expected_executable_identity(expected_executable):
            raise PiPackageError("Pi executable identity changed")
    if expected_agent_dir is not _EXPECTED_AGENT_IDENTITY_UNSET:
        try:
            final_agent_dir = _agent_directory_identity(agent_dir)
        except ValueError as exc:
            raise PiPackageError("Pi agent directory identity changed") from exc
        if not _agent_directory_matches(
            final_agent_dir,
            expected_agent_dir,
            allow_new_children=argv[1:] == ("install", _PACKAGE_SOURCE),
            allow_removed_children=argv[1:] == ("remove", _REMOVE_SOURCE),
        ):
            raise PiPackageError("Pi agent directory identity changed")
    return (
        code,
        _sanitize_output(bytes(chunks["stdout"]).decode("utf-8", "replace")),
        _sanitize_output(bytes(chunks["stderr"]).decode("utf-8", "replace")),
    )


def validate_pi_executable(
    path: Path, *, agent_dir: Path, execute: bool
) -> PiRuntimeEvidence:
    """Validate executable identity and, optionally, exact maintained runtime facts."""

    if type(execute) is not bool:
        raise TypeError("execute must be a bool")
    if execute:
        normalized_agent, expected_agent_dir = _require_existing_agent_directory(
            agent_dir, error_code="PI_RUNTIME_INCOMPATIBLE"
        )
    else:
        normalized_agent = _validate_agent_dir(agent_dir)
        expected_agent_dir = _agent_directory_identity(normalized_agent)
    item, digest = _executable_identity(path)
    version: str | None = None
    has_install = has_remove = has_offline = False
    if execute:
        before, before_hash = _executable_identity(path)
        try:
            code, stdout, _ = _bounded_spawn(
                (os.fspath(path), "--offline", "--version"),
                agent_dir=normalized_agent,
                expected_executable=_executable_identity_tuple(before, before_hash),
                expected_agent_dir=expected_agent_dir,
            )
        except ValueError as exc:
            raise PiPackageError("Pi runtime executable identity changed") from exc
        except PiPackageError as exc:
            raise PiPackageError("PI_RUNTIME_INCOMPATIBLE") from exc
        after, after_hash = _executable_identity(path)
        if (before.st_dev, before.st_ino, before_hash) != (
            after.st_dev,
            after.st_ino,
            after_hash,
        ) or code != 0:
            raise PiPackageError("Pi runtime version probe failed")
        if stdout.strip() != _PI_VERSION:
            raise PiPackageError("Pi runtime version is incompatible")
        version = _PI_VERSION
        before, before_hash = _executable_identity(path)
        try:
            code, stdout, _ = _bounded_spawn(
                (os.fspath(path), "--offline", "--help"),
                agent_dir=normalized_agent,
                expected_executable=_executable_identity_tuple(before, before_hash),
                expected_agent_dir=expected_agent_dir,
            )
        except ValueError as exc:
            raise PiPackageError("Pi runtime executable identity changed") from exc
        except PiPackageError as exc:
            raise PiPackageError("PI_RUNTIME_INCOMPATIBLE") from exc
        after, after_hash = _executable_identity(path)
        if (before.st_dev, before.st_ino, before_hash) != (
            after.st_dev,
            after.st_ino,
            after_hash,
        ) or code != 0:
            raise PiPackageError("Pi runtime help probe failed")
        lowered = stdout.casefold()
        tokens = set(
            re.findall(
                r"(?<![a-z0-9_-])(?:--?[a-z0-9][a-z0-9_-]*|[a-z0-9][a-z0-9_-]*)",
                lowered,
            )
        )
        if tokens & {"--install", "--remove", "--offline"}:
            raise PiPackageError("Pi runtime command contract is incomplete")
        has_install, has_remove, has_offline = (
            "install" in tokens,
            "remove" in tokens,
            "offline" in tokens,
        )
        if not (has_install and has_remove and has_offline):
            raise PiPackageError("Pi runtime command contract is incomplete")
    final_item, final_hash = _executable_identity(path)
    if execute:
        item, digest = final_item, final_hash
    return PiRuntimeEvidence(
        path,
        version,
        item.st_dev,
        item.st_ino,
        stat.S_IMODE(item.st_mode),
        digest,
        has_install,
        has_remove,
        has_offline,
        _RUNTIME_PROOF,
        final_item.st_size,
        final_item.st_nlink,
    )


def _settings_data(agent_dir: Path) -> tuple[Path, str | None, tuple[str, ...]]:
    path = agent_dir / "settings.json"
    _check_components(path, "Pi settings")
    try:
        os.lstat(path)
    except FileNotFoundError:
        return path, None, ()
    value, settings_hash = _read_json_bytes(path, "Pi settings", private=True)
    _reject_unsafe_settings(value)
    packages = value.get("packages", [])
    if type(packages) is not list or any(type(entry) is not str for entry in packages):
        raise ValueError("Pi package entries must be strings")
    if len(set(packages)) != len(packages):
        raise ValueError("Pi package entries must not be duplicated")
    if "npmCommand" in value:
        raise ValueError("custom package command is not allowed")
    return path, settings_hash, tuple(packages)


def _reject_unsafe_settings(value: object) -> None:
    """Reject every setting key capable of widening managed authority."""

    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            if type(raw_key) is not str:
                raise ValueError("Pi settings keys must be strings")
            lowered = raw_key.casefold()
            if any(fragment in lowered for fragment in _UNSAFE_CONFIG_FRAGMENTS):
                raise ValueError("Pi settings widen the managed contract")
            _reject_unsafe_settings(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_unsafe_settings(nested)


def _check_private_directories(agent_dir: Path, path: Path, label: str) -> None:
    """Bind every existing managed parent directory to private ownership."""

    try:
        relative = path.relative_to(agent_dir)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the Pi home") from exc
    current = agent_dir
    for component in relative.parts[:-1]:
        current /= component
        try:
            item = os.lstat(current)
        except FileNotFoundError:
            break
        if (
            stat.S_ISLNK(item.st_mode)
            or not stat.S_ISDIR(item.st_mode)
            or item.st_uid != os.getuid()
            or stat.S_IMODE(item.st_mode) != 0o700
        ):
            raise ValueError(f"{label} parent directory is unsafe")


def _inspect_optional_config(agent_dir: Path) -> None:
    path = agent_dir / "extensions/subagent/config.json"
    _check_private_directories(agent_dir, path, "Pi extension config")
    _check_components(path, "Pi extension config")
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    value = _read_json(path, "Pi extension config", private=True)
    unknown = set(value) - _SAFE_CONFIG_KEYS
    if unknown:
        raise ValueError("Pi extension config contains unknown authority")
    if any(
        type(item) not in {str, bool, int, float} or item is None
        for item in value.values()
    ):
        raise ValueError("Pi extension config value is not a safe scalar")


def _inspect_package_store(
    agent_dir: Path,
) -> tuple[int, int, int, int, int] | None:
    path = agent_dir / "npm"
    _check_components(path, "Pi package store")
    try:
        item = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
        raise ValueError("Pi package store is not a directory")
    if item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o700:
        raise ValueError("Pi package store is not owner-private")
    return (
        item.st_dev,
        item.st_ino,
        stat.S_IMODE(item.st_mode),
        item.st_uid,
        item.st_nlink,
    )


def _inspect_package_directory(agent_dir: Path) -> bool:
    """Return whether the managed package directory exists, fail closed if unsafe."""

    path = agent_dir / "npm/node_modules/pi-subagents"
    _check_private_directories(agent_dir, path, "installed Pi package directory")
    _check_components(path, "installed Pi package directory")
    try:
        item = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
        raise ValueError("installed Pi package directory is unsafe")
    if item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o700:
        raise ValueError("installed Pi package directory is not owner-private")
    return True


def _reject_nested_package_locks(agent_dir: Path) -> None:
    """Reject package-lock evidence anywhere below the private node_modules tree."""

    root = agent_dir / "npm/node_modules"
    _check_private_directories(agent_dir, root / "placeholder", "nested package lock")
    pinned_root = _filesystem_path(root, "nested package lock")
    try:
        with filesystem._pinned_directory(
            pinned_root, "nested package lock"
        ) as root_fd:
            _assert_nested_directory_private(os.fstat(root_fd), "node_modules store")
            _scan_nested_package_locks_fd(root_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError("node_modules store cannot be inspected") from exc


def _assert_nested_directory_private(item: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.getuid()
        or item.st_nlink < 1
        or stat.S_IMODE(item.st_mode) != 0o700
    ):
        raise ValueError(f"{label} is not owner-private")


def _scan_nested_package_locks_fd(directory_fd: int) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            name = entry.name
            child = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if name == "package-lock.json":
                raise ValueError("nested package lock is not installed evidence")
            if stat.S_ISLNK(child.st_mode):
                raise ValueError("node_modules store contains a symlink")
            if stat.S_ISDIR(child.st_mode):
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if (
                        opened.st_dev,
                        opened.st_ino,
                        stat.S_IMODE(opened.st_mode),
                        opened.st_uid,
                        opened.st_nlink,
                    ) != (
                        child.st_dev,
                        child.st_ino,
                        stat.S_IMODE(child.st_mode),
                        child.st_uid,
                        child.st_nlink,
                    ):
                        raise ValueError("node_modules directory identity changed")
                    _assert_nested_directory_private(opened, "node_modules directory")
                    _scan_nested_package_locks_fd(child_fd)
                finally:
                    os.close(child_fd)
                continue
            if (
                not stat.S_ISREG(child.st_mode)
                or child.st_uid != os.getuid()
                or child.st_nlink != 1
                or stat.S_IMODE(child.st_mode) & 0o077
            ):
                raise ValueError("node_modules store contains an unsafe file")


def _installed_manifest(agent_dir: Path) -> tuple[Path, str | None, bool]:
    path = agent_dir / "npm/node_modules/pi-subagents/package.json"
    _check_private_directories(agent_dir, path, "installed Pi package manifest")
    _check_components(path, "installed Pi package manifest")
    try:
        os.lstat(path)
    except FileNotFoundError:
        return path, None, False
    manifest, manifest_hash = _read_json_bytes(
        path, "installed Pi package manifest", private=True
    )
    policy = load_pi_package_policy()
    exact = (
        manifest.get("name") == policy["name"]
        and manifest.get("version") == policy["version"]
        and manifest.get("type") == policy["type"]
        and manifest.get("pi") == policy["pi"]
        and manifest.get("dependencies") == policy["dependencies"]
        and manifest.get("peerDependencies") == policy["peerDependencies"]
        and type(manifest.get("scripts", {})) is dict
        and not any(
            key in manifest.get("scripts", {})
            for key in policy["forbiddenLifecycleScripts"]
        )
        and manifest_hash == policy["packageJsonSha256"]
    )
    return path, manifest_hash, exact


def _installed_lock(
    agent_dir: Path,
) -> tuple[Path, str | None, bool, bool]:
    _reject_nested_package_locks(agent_dir)
    path = agent_dir / "npm/package-lock.json"
    _check_private_directories(agent_dir, path, "installed Pi package lock")
    _check_components(path, "installed Pi package lock")
    try:
        os.lstat(path)
    except FileNotFoundError:
        return path, None, False, False
    lock, _lock_hash = _read_json_bytes(path, "installed Pi package lock", private=True)
    packages = lock.get("packages")
    root = packages.get("") if type(packages) is dict else None
    if type(root) is not dict:
        return path, None, False, True
    dependencies = root.get("dependencies")
    entry = dependencies.get(_PACKAGE_NAME) if type(dependencies) is dict else None
    installed = packages.get("node_modules/pi-subagents")
    exact = (
        lock.get("lockfileVersion") == 3
        and lock.get("name") == _PACKAGE_NAME
        and lock.get("version") == _PACKAGE_VERSION
        and (entry == _PACKAGE_VERSION or entry == _PACKAGE_SOURCE)
        and type(installed) is dict
        and installed.get("version") == _PACKAGE_VERSION
        and installed.get("integrity")
        == (
            "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
        )
    )
    nested_lock = agent_dir / "npm/node_modules/pi-subagents/package-lock.json"
    _check_components(nested_lock, "nested Pi package lock")
    try:
        nested = os.lstat(nested_lock)
    except FileNotFoundError:
        nested = None
    if nested is not None:
        raise ValueError("nested package lock is not installed evidence")
    root_hash = _hash_bytes(
        json.dumps(root, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return path, root_hash, exact, True


def _is_pi_identity(entry: str) -> bool:
    """Classify package specs that could select the managed Pi package."""

    if type(entry) is not str:
        return False
    # Package specs may be npm aliases, ranges, file/path specs, or git
    # references.  Match the package as a component, never as a substring of
    # an unrelated package such as ``my-pi-subagents-tools``.
    return (
        re.search(
            rf"(?:^|[@/:]){re.escape(_PACKAGE_NAME)}(?:$|[@/:?#.])",
            entry.casefold(),
        )
        is not None
    )


def _inspect_pi_package_state_snapshot(agent_dir: Path) -> _PiPackageSnapshot:
    normalized = _validate_agent_dir(agent_dir)
    _inspect_optional_config(normalized)
    package_store_identity = _inspect_package_store(normalized)
    package_directory_present = _inspect_package_directory(normalized)
    settings_path, settings_hash, entries = _settings_data(normalized)
    lock_path, lock_hash, lock_exact, lock_present = _installed_lock(normalized)
    manifest_path, manifest_hash, manifest_exact = _installed_manifest(normalized)
    target_entries = tuple(entry for entry in entries if _is_pi_identity(entry))
    exact_count = sum(entry == _PACKAGE_SOURCE for entry in target_entries)
    wrong_target = any(entry != _PACKAGE_SOURCE for entry in target_entries)
    exact_entry = exact_count == 1 and not wrong_target
    if wrong_target or exact_count > 1:
        status: Literal["absent", "exact", "conflict"] = "conflict"
    elif (
        not target_entries
        and not lock_present
        and manifest_hash is None
        and not package_directory_present
    ):
        status = "absent"
    elif exact_entry and lock_exact and manifest_exact:
        status = "exact"
    else:
        status = "conflict"
    return _PiPackageSnapshot(
        PiPackageEvidence(
            settings_path,
            settings_hash,
            entries,
            status,
            exact_entry,
            lock_path if lock_present else None,
            lock_hash,
            manifest_path if manifest_hash else None,
            manifest_hash,
            manifest_exact,
        ),
        package_store_identity,
    )


def inspect_pi_package_state(agent_dir: Path) -> PiPackageEvidence:
    """Return the stable public package contract without race-only internals."""

    return _inspect_pi_package_state_snapshot(agent_dir).evidence


def _receipt_path(agent_dir: Path) -> Path:
    normalized = _validate_agent_dir(agent_dir)
    path = normalized / _RECEIPT_RELATIVE
    # Validate user-controlled receipt parents before selecting the descriptor
    # spelling used by the filesystem CAS helpers.
    _check_private_directories(normalized, path, "Pi package receipt")
    _check_components(path, "Pi package receipt")
    return _filesystem_path(path, "Pi package receipt")


def _receipt_filesystem_path(agent_dir: Path) -> Path:
    """Return the already-validated descriptor spelling for a receipt."""

    return _receipt_path(agent_dir)


def _hash_field(value: object, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if (
        type(value) is not str
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError("receipt hash is invalid")
    return value


def _receipt_from_mapping(raw: Mapping[str, object]) -> PiPackageReceipt:
    fields = {
        "schema_version",
        "operation",
        "source",
        "remove_source",
        "settings_before_hash",
        "settings_after_hash",
        "package_manifest_hash",
        "package_policy_hash",
        "created_exact_entry",
    }
    if (
        set(raw) != fields
        or type(raw.get("schema_version")) is not int
        or raw.get("schema_version") != 1
        or raw.get("source") != _PACKAGE_SOURCE
        or raw.get("remove_source") != _REMOVE_SOURCE
    ):
        raise ValueError("Pi receipt schema is invalid")
    operation = raw.get("operation")
    if operation != "install":
        raise ValueError("Pi receipt operation is invalid")
    if raw.get("created_exact_entry") is not True:
        raise ValueError("Pi receipt ownership is invalid")
    before = _hash_field(raw.get("settings_before_hash"), optional=True)
    after = _hash_field(raw.get("settings_after_hash"), optional=True)
    manifest = _hash_field(raw.get("package_manifest_hash"))
    policy = _hash_field(raw.get("package_policy_hash"))
    return PiPackageReceipt(
        1,
        operation,
        _PACKAGE_SOURCE,
        _REMOVE_SOURCE,
        before,
        after,
        manifest,
        policy,
        raw["created_exact_entry"],
    )


def load_pi_package_receipt(agent_dir: Path) -> PiPackageReceipt | None:
    path = _receipt_path(agent_dir)
    try:
        os.lstat(path)
    except FileNotFoundError:
        return None
    return _receipt_from_mapping(_read_json(path, "Pi package receipt", private=True))


def validate_pi_package_receipt(
    agent_dir: Path,
    evidence: PiPackageEvidence,
    *,
    require_current: bool = True,
) -> PiPackageReceipt | None:
    """Validate durable ownership evidence against the current package state.

    Planning uses this read-only contract before constructing an optional
    removal phase.  Keeping the policy/hash checks here prevents callers from
    accidentally treating a merely parseable receipt as proof of ownership.
    """

    if type(evidence) is not PiPackageEvidence:
        raise TypeError("Pi package evidence has the wrong type")
    receipt = load_pi_package_receipt(agent_dir)
    if receipt is None:
        return None
    try:
        policy_hash = _reviewed_policy_hash()
    except (OSError, ValueError, TransactionError) as exc:
        raise PiPackageError("Pi package policy is invalid") from exc
    valid = (
        receipt.operation == "install"
        and receipt.source == _PACKAGE_SOURCE
        and receipt.remove_source == _REMOVE_SOURCE
        and receipt.created_exact_entry
        and receipt.package_policy_hash == policy_hash
        and evidence.status == "exact"
        and receipt.package_manifest_hash == evidence.manifest_hash
        and receipt.settings_after_hash == evidence.settings_hash
    )
    if require_current and not valid:
        raise PiPackageError("Pi receipt does not prove current package ownership")
    return receipt if valid else None


def _durable_receipt_evidence(
    agent_dir: Path, expected_receipt: PiPackageReceipt
) -> IdentityEvidence:
    """Capture the exact private receipt identity held across a command."""

    path = _receipt_filesystem_path(agent_dir)
    try:
        evidence, content = filesystem.read_bytes_with_evidence(
            path, "Pi package receipt"
        )
        decoded = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs)
        if (
            type(decoded) is not dict
            or _receipt_from_mapping(decoded) != expected_receipt
        ):
            raise ValueError("Pi receipt content changed")
    except (OSError, UnicodeError, json.JSONDecodeError, TransactionError) as exc:
        raise ValueError("Pi receipt cannot be read safely") from exc
    try:
        item = os.lstat(path)
    except OSError as exc:
        raise ValueError("Pi receipt identity changed") from exc
    if (
        item.st_uid != os.getuid()
        or item.st_nlink != 1
        or stat.S_IMODE(item.st_mode) != 0o600
        or (item.st_dev, item.st_ino, item.st_size, item.st_nlink)
        != (evidence.device, evidence.inode, evidence.size, evidence.nlink)
    ):
        raise ValueError("Pi receipt identity is unsafe")
    return evidence


def store_pi_package_receipt(
    agent_dir: Path,
    receipt: PiPackageReceipt,
    *,
    expected_evidence: PiPackageEvidence | None = None,
) -> None:
    if type(receipt) is not PiPackageReceipt:
        raise TypeError("receipt has the wrong type")
    if receipt.operation != "install":
        raise ValueError("only an install receipt can be stored")
    if not receipt.created_exact_entry:
        raise ValueError("receipt must prove a newly created exact entry")
    if (
        expected_evidence is not None
        and type(expected_evidence) is not PiPackageEvidence
    ):
        raise TypeError("expected package evidence has the wrong type")
    _receipt_from_mapping(
        {
            "schema_version": receipt.schema_version,
            "operation": receipt.operation,
            "source": receipt.source,
            "remove_source": receipt.remove_source,
            "settings_before_hash": receipt.settings_before_hash,
            "settings_after_hash": receipt.settings_after_hash,
            "package_manifest_hash": receipt.package_manifest_hash,
            "package_policy_hash": receipt.package_policy_hash,
            "created_exact_entry": receipt.created_exact_entry,
        }
    )
    normalized = _validate_agent_dir(agent_dir)
    receipt_path = _receipt_filesystem_path(normalized)
    parent = receipt_path.parent
    created_receipt_evidence: IdentityEvidence | None = None
    try:
        if expected_evidence is not None:
            current = inspect_pi_package_state(normalized)
            if current != expected_evidence:
                raise ValueError("Pi package evidence changed before receipt")
            if (
                current.status != "exact"
                or not current.package_identity_valid
                or receipt.settings_after_hash != current.settings_hash
                or receipt.package_manifest_hash != current.manifest_hash
            ):
                raise ValueError("Pi receipt does not match package evidence")
        filesystem.ensure_private_directory(parent)
        payload = {
            "schema_version": receipt.schema_version,
            "operation": receipt.operation,
            "source": receipt.source,
            "remove_source": receipt.remove_source,
            "settings_before_hash": receipt.settings_before_hash,
            "settings_after_hash": receipt.settings_after_hash,
            "package_manifest_hash": receipt.package_manifest_hash,
            "package_policy_hash": receipt.package_policy_hash,
            "created_exact_entry": receipt.created_exact_entry,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        created_receipt_evidence = filesystem.safe_mutate(
            receipt_path, None, DesiredFile(encoded, mode=0o600)
        )
        if created_receipt_evidence is None:
            raise ValueError("Pi receipt create postcondition is unavailable")
        if load_pi_package_receipt(normalized) != receipt:
            raise ValueError("Pi receipt postcondition could not be proved")
        if expected_evidence is not None:
            current = inspect_pi_package_state(normalized)
            if current != expected_evidence:
                raise ValueError("Pi package evidence changed after receipt")
    except (OSError, ValueError, TransactionError) as exc:
        if created_receipt_evidence is not None:
            try:
                filesystem.safe_mutate(
                    receipt_path, created_receipt_evidence, None
                )
            except (OSError, ValueError, TransactionError):
                # Preserve any concurrent replacement; CAS only removes the
                # exact receipt identity created by this call.
                pass
        raise PiPackageError("Pi receipt cannot be stored") from exc


def build_pi_install_argv(executable: Path) -> tuple[str, ...]:
    _lexical_absolute(executable, "Pi executable")
    return (os.fspath(executable), "install", _PACKAGE_SOURCE)


def build_pi_remove_argv(executable: Path) -> tuple[str, ...]:
    _lexical_absolute(executable, "Pi executable")
    return (os.fspath(executable), "remove", _REMOVE_SOURCE)


pi_install_argv = build_pi_install_argv
pi_remove_argv = build_pi_remove_argv


def _same_runtime_identity(
    expected: PiRuntimeEvidence, agent_dir: Path
) -> PiRuntimeEvidence:
    try:
        current = validate_pi_executable(
            expected.executable, agent_dir=agent_dir, execute=False
        )
    except (OSError, ValueError) as exc:
        raise PiPackageError("Pi executable identity changed") from exc
    if (
        current.device,
        current.inode,
        current.mode,
        current.sha256,
        current._size,
        current._nlink,
    ) != (
        expected.device,
        expected.inode,
        expected.mode,
        expected.sha256,
        expected._size,
        expected._nlink,
    ):
        raise PiPackageError("Pi executable identity changed")
    return current


def _trusted_runtime_identity(
    expected: PiRuntimeEvidence, agent_dir: Path
) -> PiRuntimeEvidence:
    if (
        expected._proof is not _RUNTIME_PROOF
        or expected.version != _PI_VERSION
        or not expected.help_has_install
        or not expected.help_has_remove
        or not expected.help_has_offline
    ):
        raise PiPackageError("PI_RUNTIME_INCOMPATIBLE")
    return _same_runtime_identity(expected, agent_dir)


def _run_command(
    argv: tuple[str, ...],
    agent_dir: Path,
    expected: PiRuntimeEvidence,
    *,
    expected_agent_dir: tuple[int, int, int, int, int] | object | None = (
        _EXPECTED_AGENT_IDENTITY_UNSET
    ),
    expected_package: _PiPackageSnapshot | None = None,
) -> None:
    if (
        not isinstance(argv, tuple)
        or not argv
        or argv[0] != os.fspath(expected.executable)
    ):
        raise PiPackageError("Pi package command is not allowlisted")
    if argv[1:] not in {
        ("install", _PACKAGE_SOURCE),
        ("remove", _REMOVE_SOURCE),
    }:
        raise PiPackageError("Pi package command is not allowlisted")
    _trusted_runtime_identity(expected, agent_dir)
    try:
        code, _, _ = _bounded_spawn(
            argv,
            agent_dir=agent_dir,
            expected_executable=expected,
            expected_agent_dir=expected_agent_dir,
            expected_package=expected_package,
        )
    except ValueError as exc:
        raise PiPackageError("Pi executable identity changed") from exc
    _same_runtime_identity(expected, agent_dir)
    if code != 0:
        raise PiPackageError("Pi package command failed")
    if expected_agent_dir is not _EXPECTED_AGENT_IDENTITY_UNSET:
        try:
            current_agent_dir = _agent_directory_identity(agent_dir)
        except ValueError as exc:
            raise PiPackageError("Pi agent directory identity changed") from exc
        if not _agent_directory_matches(
            current_agent_dir,
            expected_agent_dir,
            allow_new_children=argv[1:] == ("install", _PACKAGE_SOURCE),
            allow_removed_children=argv[1:] == ("remove", _REMOVE_SOURCE),
        ):
            raise PiPackageError("Pi agent directory identity changed")


def install_pi_package_external(
    executable: PiRuntimeEvidence,
    agent_dir: Path,
    consent_third_party_code: bool,
    consent_network: bool,
) -> PiPackageReceipt:
    """Install and verify the reviewed package without writing a receipt.

    The explicit no-receipt primitive lets the orchestrator establish the
    external package boundary before recording ownership and applying local
    repository files.  The returned receipt contains only verified hashes and
    can be persisted by the caller after the phase succeeds.
    """
    if (
        type(executable) is not PiRuntimeEvidence
        or type(consent_third_party_code) is not bool
        or type(consent_network) is not bool
    ):
        raise TypeError("Pi install arguments are invalid")
    if not (consent_third_party_code and consent_network):
        raise PiPackageError("both Pi installation consents are required")
    try:
        policy_hash = _reviewed_policy_hash()
    except (OSError, ValueError, TransactionError) as exc:
        raise PiPackageError("Pi package policy is invalid") from exc
    normalized, expected_agent_dir = _require_existing_agent_directory(
        agent_dir, error_code="PI_PACKAGE_CONFLICT"
    )
    _trusted_runtime_identity(executable, normalized)
    try:
        before_snapshot = _inspect_pi_package_state_snapshot(normalized)
        before = before_snapshot.evidence
    except ValueError as exc:
        raise PiPackageError("Pi package state conflicts with policy") from exc
    try:
        existing_receipt = load_pi_package_receipt(normalized)
    except ValueError as exc:
        raise PiPackageError("Pi receipt is invalid") from exc
    if before.status == "exact":
        if existing_receipt is not None and (
            existing_receipt.operation != "install"
            or not existing_receipt.created_exact_entry
            or existing_receipt.source != _PACKAGE_SOURCE
            or existing_receipt.remove_source != _REMOVE_SOURCE
            or existing_receipt.package_policy_hash != policy_hash
            or existing_receipt.package_manifest_hash != before.manifest_hash
            or existing_receipt.settings_after_hash != before.settings_hash
        ):
            raise PiPackageError("stale Pi receipt conflicts with package state")
        return PiPackageReceipt(
            1,
            "none",
            _PACKAGE_SOURCE,
            _REMOVE_SOURCE,
            before.settings_hash,
            before.settings_hash,
            before.manifest_hash or "0" * 64,
            policy_hash,
            False,
        )
    if existing_receipt is not None:
        raise PiPackageError("stale Pi receipt blocks package installation")
    if before.status != "absent":
        raise PiPackageError("Pi package state conflicts with policy")
    _run_command(
        build_pi_install_argv(executable.executable),
        normalized,
        executable,
        expected_agent_dir=expected_agent_dir,
        expected_package=before_snapshot,
    )
    try:
        _revalidate_reviewed_policy(policy_hash)
    except (OSError, ValueError, TransactionError) as exc:
        raise PiPackageError("Pi package policy changed during install") from exc
    try:
        after = inspect_pi_package_state(normalized)
    except ValueError as exc:
        raise PiPackageError("Pi package verification failed after install") from exc
    if after.status != "exact" or not after.manifest_hash:
        raise PiPackageError("Pi package verification failed after install")
    receipt = PiPackageReceipt(
        1,
        "install",
        _PACKAGE_SOURCE,
        _REMOVE_SOURCE,
        before.settings_hash,
        after.settings_hash,
        after.manifest_hash,
        policy_hash,
        True,
    )
    return receipt


def install_pi_package(
    executable: PiRuntimeEvidence,
    agent_dir: Path,
    consent_third_party_code: bool,
    consent_network: bool,
) -> PiPackageReceipt:
    """Install the reviewed package and persist its ownership receipt.

    This keeps the original package-unit API intact.  Explicit phase-aware
    callers should use :func:`install_pi_package_external` instead.
    """

    receipt = install_pi_package_external(
        executable,
        agent_dir,
        consent_third_party_code,
        consent_network,
    )
    if receipt.operation == "install":
        store_pi_package_receipt(agent_dir, receipt)
    return receipt


def remove_pi_package(
    executable: PiRuntimeEvidence, agent_dir: Path, receipt: PiPackageReceipt
) -> PiPackageReceipt:
    if (
        type(executable) is not PiRuntimeEvidence
        or type(receipt) is not PiPackageReceipt
    ):
        raise TypeError("Pi removal arguments are invalid")
    try:
        policy_hash = _reviewed_policy_hash()
    except (OSError, ValueError, TransactionError) as exc:
        raise PiPackageError("Pi package policy is invalid") from exc
    normalized, expected_agent_dir = _require_existing_agent_directory(
        agent_dir, error_code="PI_PACKAGE_CONFLICT"
    )
    _trusted_runtime_identity(executable, normalized)
    try:
        stored = load_pi_package_receipt(normalized)
    except ValueError as exc:
        raise PiPackageError("Pi receipt is invalid") from exc
    if stored != receipt:
        raise PiPackageError("Pi receipt does not match durable ownership evidence")
    try:
        current_snapshot = _inspect_pi_package_state_snapshot(normalized)
        current = current_snapshot.evidence
    except ValueError as exc:
        raise PiPackageError("Pi package state conflicts with policy") from exc
    if (
        receipt.operation != "install"
        or not receipt.created_exact_entry
        or receipt.source != _PACKAGE_SOURCE
        or receipt.remove_source != _REMOVE_SOURCE
        or receipt.package_policy_hash != policy_hash
        or receipt.settings_after_hash != current.settings_hash
        or receipt.package_manifest_hash != current.manifest_hash
        or current.status != "exact"
    ):
        raise PiPackageError("Pi receipt does not prove package ownership")
    try:
        expected_receipt = _durable_receipt_evidence(normalized, receipt)
    except (OSError, ValueError, TransactionError) as exc:
        raise PiPackageError("Pi receipt cannot be removed") from exc
    _run_command(
        build_pi_remove_argv(executable.executable),
        normalized,
        executable,
        expected_agent_dir=expected_agent_dir,
        expected_package=current_snapshot,
    )
    try:
        _revalidate_reviewed_policy(policy_hash)
    except (OSError, ValueError, TransactionError) as exc:
        raise PiPackageError("Pi package policy changed during removal") from exc
    try:
        after = inspect_pi_package_state(normalized)
    except ValueError as exc:
        raise PiPackageError("Pi package removal was not verified") from exc
    if after.status != "absent":
        raise PiPackageError("Pi package removal was not verified")
    path = _receipt_filesystem_path(normalized)
    try:
        filesystem.safe_mutate(path, expected_receipt, None)
    except (OSError, ValueError, TransactionError) as exc:
        raise PiPackageError("Pi receipt cannot be removed") from exc
    return PiPackageReceipt(
        1,
        "remove",
        _PACKAGE_SOURCE,
        _REMOVE_SOURCE,
        receipt.settings_before_hash,
        receipt.settings_after_hash,
        receipt.package_manifest_hash,
        receipt.package_policy_hash,
        True,
    )
