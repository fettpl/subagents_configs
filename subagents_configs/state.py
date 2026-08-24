"""Strict, metadata-only manifest and transaction-journal state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from . import filesystem
from .locks import IdentityEvidence, capture_evidence
from .models import (
    Journal,
    JournalOperation,
    Manifest,
    ManifestEntry,
    Target,
    TargetDescriptor,
)
from .paths import (
    assert_contained,
    assert_safe_home,
    assert_safe_managed_path,
    lstat_existing,
    normalized_absolute,
    strict_relative_path,
)

SCHEMA_VERSION = 2
_OWNERSHIPS = {"created", "replaced", "preexisting"}
_ACTIONS = {
    "create",
    "replace",
    "remove",
    "restore",
    "write-block",
    "remove-block",
    "write-manifest",
}
_STATUSES = {
    "planned",
    "applying",
    "applied",
    "rollback-planned",
    "rolled-back",
    "ambiguous",
}
_ROLLBACK_STATUSES = {"not-started", "in-progress", "complete", "incomplete"}
_BLOCKS = {
    Target.CODEX: {"routing-codex", "codex-multi-agent-v2"},
    Target.OPENCODE: {"routing-opencode"},
    Target.CLAUDE_CODE: {"routing-claude-code"},
}

_MANIFEST_KEYS = {"schema_version", "target", "entries"}
_ENTRY_KEYS = {
    "identifier",
    "relative_path",
    "installed_hash",
    "installed_mode",
    "ownership",
    "backup_path",
    "backup_hash",
    "original_mode",
    "managed_block_id",
    "installed_block_hash",
    "unresolved_reason",
}
_JOURNAL_KEYS = {
    "schema_version",
    "transaction_id",
    "target",
    "participants",
    "operation",
    "operations",
    "rollback_status",
}
_OPERATION_KEYS = {
    "operation_id",
    "identifier",
    "action",
    "expected_before_hash",
    "expected_after_hash",
    "expected_before_mode",
    "expected_after_mode",
    "backup_path",
    "backup_hash",
    "status",
}
_EVIDENCE_KEYS = {"device", "inode", "size", "nlink", "mode", "sha256"}
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _dict(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = expected - actual
        unknown = actual - expected
        detail = []
        if missing:
            detail.append(f"missing {sorted(missing)}")
        if unknown:
            detail.append(f"unknown {sorted(unknown)}")
        raise ValueError(f"invalid {label} fields ({'; '.join(detail)})")
    return value


def _schema(value: object) -> int:
    if type(value) is not int or value not in {1, SCHEMA_VERSION}:
        raise ValueError("unsupported schema_version")
    return value


def _evidence(value: object, field: str) -> IdentityEvidence | None:
    if value is None:
        return None
    item = _dict(value, _EVIDENCE_KEYS, field)
    numeric = ("device", "inode", "size", "nlink", "mode")
    for key in numeric:
        if type(item[key]) is not int or item[key] < 0:
            raise ValueError(f"{field}.{key} must be a non-negative integer")
    mode = item["mode"]
    if mode > 0o777:
        raise ValueError(f"{field}.mode is invalid")
    digest = _hash(item["sha256"], f"{field}.sha256")
    return IdentityEvidence(
        item["device"], item["inode"], item["size"], item["nlink"], mode, digest
    )


def _evidence_json(value: IdentityEvidence | None) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "device": value.device,
        "inode": value.inode,
        "size": value.size,
        "nlink": value.nlink,
        "mode": value.mode,
        "sha256": value.sha256,
    }


def _target(value: object, descriptor: TargetDescriptor) -> Target:
    if type(value) is not str:
        raise ValueError("target must be a string")
    try:
        target = Target(value)
    except ValueError as exc:
        raise ValueError(f"unsupported target: {value!r}") from exc
    if target is not descriptor.target:
        raise ValueError("state target does not match descriptor")
    return target


def _string(value: object, field: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        raise ValueError(f"{field} must be a string")
    if "\x00" in value:
        raise ValueError(f"{field} contains NUL")
    return value


def _safe_id(value: object, field: str) -> str:
    value = _string(value, field)
    if _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{field} must match [A-Za-z0-9][A-Za-z0-9._-]{{0,127}}")
    return value


def _hash(value: object, field: str) -> str:
    value = _string(value, field)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def _optional_hash(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _hash(value, field)


def _mode(value: object, field: str, *, installed: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= 0o777:
        raise ValueError(f"{field} must be an integer mode from 000 through 777")
    if installed and value & ~0o600:
        raise ValueError("installed_mode must not grant group or other access")
    return value


def _optional_mode(value: object, field: str) -> int | None:
    if value is None:
        return None
    return _mode(value, field)


def _relative(value: object, field: str) -> str:
    try:
        return strict_relative_path(_string(value, field)).as_posix()
    except ValueError as exc:
        raise ValueError(f"invalid {field}") from exc


def _supported_identifiers(descriptor: TargetDescriptor) -> dict[str, str]:
    identifiers: dict[str, str] = {}
    destination_owner: dict[str, str] = {}
    seen_all_source_identifiers: set[str] = set()
    seen_source_destinations: set[str] = set()

    def add(identifier: str, destination: str, owner: str) -> None:
        previous_owner = destination_owner.get(destination)
        if previous_owner is not None and previous_owner != owner:
            raise ValueError("descriptor aliases collide on one destination")
        destination_owner[destination] = owner
        previous_destination = identifiers.get(identifier)
        if previous_destination is not None and previous_destination != destination:
            raise ValueError("descriptor identifier aliases collide")
        identifiers[identifier] = destination

    for source in descriptor.sources:
        if source.identifier in seen_all_source_identifiers:
            raise ValueError("descriptor contains a repeated identifier")
        seen_all_source_identifiers.add(source.identifier)
        if source.destination is None:
            continue
        destination = source.destination.as_posix()
        if destination in seen_source_destinations:
            raise ValueError("descriptor contains a repeated destination")
        seen_source_destinations.add(destination)
        add(source.identifier, destination, source.identifier)
        add(destination, destination, source.identifier)
    for block_id in _BLOCKS[descriptor.target]:
        destination = descriptor.global_filename
        if block_id == "codex-multi-agent-v2":
            if descriptor.config_filename is None:
                continue
            destination = descriptor.config_filename
        add(block_id, destination, block_id)
        add(destination, destination, block_id)
    return identifiers


def _backup(
    home: Path, backup_path: object, backup_hash: object, *, verify: bool = True
) -> tuple[str | None, str | None]:
    if backup_path is None and backup_hash is None:
        return None, None
    if backup_path is None or backup_hash is None:
        raise ValueError("backup_path and backup_hash must be supplied together")
    relative = _relative(backup_path, "backup_path")
    parts = PurePosixPath(relative).parts
    if len(parts) != 2 or parts[0] != "backups":
        raise ValueError("backup_path must be a flat file below backups/")
    digest = _hash(backup_hash, "backup_hash")
    if not verify:
        return relative, digest
    absolute_home = normalized_absolute(home)
    state_dir = absolute_home / ".subagents_configs"
    absolute = state_dir / relative
    assert_contained(absolute_home, absolute)
    assert_safe_managed_path(absolute_home, absolute, "backup")
    backups_dir = state_dir / "backups"
    backups_stat = lstat_existing(backups_dir, "backup directory")
    if backups_stat is not None:
        if not stat.S_ISDIR(backups_stat.st_mode):
            raise ValueError("backup directory must be a directory")
        if stat.S_IMODE(backups_stat.st_mode) & ~0o700:
            raise ValueError("backup directory must be private")
    backup_stat = lstat_existing(absolute, "backup")
    if backup_stat is not None and stat.S_IMODE(backup_stat.st_mode) & ~0o600:
        raise ValueError("backup files must be private")
    try:
        actual = _sha256_backup(absolute)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise ValueError("referenced backup is unavailable") from exc
    if actual != digest:
        raise ValueError("referenced backup hash does not match")
    return relative, digest


def _sha256_backup(path: Path) -> str:
    """Hash a backup through a pinned parent fd with an opened-file mode check."""

    absolute = normalized_absolute(path)
    with filesystem._pinned_directory(absolute.parent, "backup") as parent_fd:
        filesystem._after_parent_pin("backup-read", absolute.parent)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute.name, flags, dir_fd=parent_fd)
        try:
            result = os.fstat(descriptor)
            if not stat.S_ISREG(result.st_mode):
                raise ValueError("backup must be a regular file")
            if stat.S_IMODE(result.st_mode) & ~0o600:
                raise ValueError("backup files must be private")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(descriptor)


def _entry(
    raw: object,
    descriptor: TargetDescriptor,
    home: Path,
    *,
    verify_backups: bool = True,
) -> ManifestEntry:
    value = _dict(raw, _ENTRY_KEYS, "manifest entry")
    identifiers = _supported_identifiers(descriptor)
    identifier = _string(value["identifier"], "identifier")
    if identifier not in identifiers:
        raise ValueError(f"identifier is not managed by {descriptor.target.value}")
    relative_path = _relative(value["relative_path"], "relative_path")
    if relative_path != identifiers[identifier]:
        raise ValueError("relative_path does not match managed identifier")
    installed_hash = _hash(value["installed_hash"], "installed_hash")
    installed_mode = _mode(value["installed_mode"], "installed_mode", installed=True)
    ownership = value["ownership"]
    if type(ownership) is not str or ownership not in _OWNERSHIPS:
        raise ValueError("invalid ownership")
    managed_block_id = value["managed_block_id"]
    if managed_block_id is not None:
        managed_block_id = _string(managed_block_id, "managed_block_id")
        if managed_block_id not in _BLOCKS[descriptor.target]:
            raise ValueError("unsupported managed block id")
        if identifier != managed_block_id:
            raise ValueError("managed block id does not match identifier")
    backup_path, backup_hash = _backup(
        home,
        value["backup_path"],
        value["backup_hash"],
        verify=verify_backups,
    )
    original_mode = _optional_mode(value["original_mode"], "original_mode")
    if ownership == "replaced":
        if backup_path is None or original_mode is None:
            raise ValueError("replaced entries require backup and original_mode")
    elif ownership == "created":
        if backup_path is not None or original_mode is not None:
            raise ValueError("created entries cannot restore prior state")
    elif ownership == "preexisting":
        if backup_path is not None:
            raise ValueError("preexisting entries cannot have a backup")
        if managed_block_id is not None and original_mode is None:
            raise ValueError("preexisting managed files require original_mode")
        if managed_block_id is None and original_mode is not None:
            raise ValueError("preexisting entries do not restore original_mode")

    installed_block_hash = _optional_hash(
        value["installed_block_hash"], "installed_block_hash"
    )
    if (managed_block_id is None) != (installed_block_hash is None):
        raise ValueError("managed block hash and id must be supplied together")
    unresolved_reason = value["unresolved_reason"]
    if unresolved_reason is not None:
        unresolved_reason = _string(unresolved_reason, "unresolved_reason")
    return ManifestEntry(
        identifier=identifier,
        relative_path=relative_path,
        installed_hash=installed_hash,
        installed_mode=installed_mode,
        ownership=ownership,
        backup_path=backup_path,
        backup_hash=backup_hash,
        original_mode=original_mode,
        managed_block_id=managed_block_id,
        installed_block_hash=installed_block_hash,
        unresolved_reason=unresolved_reason,
    )


def decode_manifest(raw: object, descriptor: TargetDescriptor, home: Path) -> Manifest:
    return _decode_manifest(raw, descriptor, home, verify_backups=True)


def _decode_manifest(
    raw: object,
    descriptor: TargetDescriptor,
    home: Path,
    *,
    verify_backups: bool,
) -> Manifest:
    value = _dict(raw, _MANIFEST_KEYS, "manifest")
    schema_version = _schema(value["schema_version"])
    target = _target(value["target"], descriptor)
    if type(value["entries"]) is not list:
        raise ValueError("manifest entries must be an array")
    entries = tuple(
        _entry(item, descriptor, home, verify_backups=verify_backups)
        for item in value["entries"]
    )
    identifiers = [entry.identifier for entry in entries]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("manifest contains duplicate identifiers")
    allowed = _supported_identifiers(descriptor)
    destinations = [allowed[entry.identifier] for entry in entries]
    if len(destinations) != len(set(destinations)):
        raise ValueError("manifest contains duplicate canonical destinations")
    return Manifest(schema_version, target, entries)


def _operation(
    raw: object,
    descriptor: TargetDescriptor,
    home: Path,
    *,
    schema_version: int = SCHEMA_VERSION,
    verify_backups: bool = True,
) -> JournalOperation:
    expected_keys = _OPERATION_KEYS | {
        "expected_before_evidence",
        "expected_after_evidence",
    }
    value = _dict(
        raw,
        expected_keys if schema_version >= 2 else _OPERATION_KEYS,
        "journal operation",
    )
    operation_id = _safe_id(value["operation_id"], "operation_id")
    identifier = _string(value["identifier"], "identifier")
    allowed = _supported_identifiers(descriptor)
    if identifier != "state/manifest" and identifier not in allowed:
        raise ValueError("journal identifier is not managed")
    action = value["action"]
    if type(action) is not str or action not in _ACTIONS:
        raise ValueError("invalid journal action")
    if action == "write-manifest" and identifier != "state/manifest":
        raise ValueError("write-manifest requires state/manifest")
    if identifier == "state/manifest" and action != "write-manifest":
        raise ValueError("state/manifest only supports write-manifest")
    is_block = any(
        identifier == block_id
        or allowed.get(identifier)
        == (
            descriptor.config_filename
            if block_id == "codex-multi-agent-v2"
            else descriptor.global_filename
        )
        for block_id in _BLOCKS[descriptor.target]
    )
    if action in {"write-block", "remove-block"} and not is_block:
        raise ValueError("block actions require a managed block identifier")
    if is_block and action not in {"write-block", "remove-block"}:
        raise ValueError("managed block identifiers require a block action")
    before_hash = _optional_hash(value["expected_before_hash"], "expected_before_hash")
    after_hash = _optional_hash(value["expected_after_hash"], "expected_after_hash")
    before_mode = _optional_mode(value["expected_before_mode"], "expected_before_mode")
    after_mode = _optional_mode(value["expected_after_mode"], "expected_after_mode")
    before_identity = (
        _evidence(value["expected_before_evidence"], "expected_before_evidence")
        if schema_version >= 2
        else None
    )
    after_identity = (
        _evidence(value["expected_after_evidence"], "expected_after_evidence")
        if schema_version >= 2
        else None
    )
    if schema_version >= 2:
        if (before_hash is None) != (before_identity is None):
            raise ValueError("before hash and identity evidence must agree")
        if after_identity is not None and after_hash is None:
            raise ValueError("after identity evidence requires after hash")
        if before_identity is not None and (
            before_hash != before_identity.sha256 or before_mode != before_identity.mode
        ):
            raise ValueError("before identity evidence disagrees with hash/mode")
        if after_identity is not None and (
            after_hash != after_identity.sha256 or after_mode != after_identity.mode
        ):
            raise ValueError("after identity evidence disagrees with hash/mode")
    before_evidence = (before_hash is not None, before_mode is not None)
    after_evidence = (after_hash is not None, after_mode is not None)
    if before_evidence[0] != before_evidence[1]:
        raise ValueError("expected-before hash and mode must be supplied together")
    if after_evidence[0] != after_evidence[1]:
        raise ValueError("expected-after hash and mode must be supplied together")
    backup_path, backup_hash = _backup(
        home,
        value["backup_path"],
        value["backup_hash"],
        verify=verify_backups,
    )
    has_before = before_hash is not None
    has_after = after_hash is not None
    has_backup = backup_path is not None
    same_evidence = (
        has_before
        and has_after
        and before_hash == after_hash
        and before_mode == after_mode
    )
    if action == "create":
        valid = not has_before and has_after and not has_backup
    elif action == "replace":
        valid = has_before and has_after and has_backup
    elif action == "remove":
        valid = has_before and not has_after and has_backup
    elif action == "restore":
        valid = has_before and has_after and has_backup
    elif action == "write-block":
        if not has_before:
            valid = has_after and not has_backup
        elif same_evidence:
            valid = has_after and not has_backup
        else:
            valid = has_after and has_backup
    elif action == "remove-block":
        valid = has_before
        if same_evidence:
            valid = not has_backup
        else:
            valid = has_backup
    else:  # write-manifest
        if not has_before:
            valid = has_after and not has_backup
        elif same_evidence:
            valid = not has_backup
        else:
            valid = has_backup
    if not valid:
        raise ValueError("journal action has ambiguous rollback evidence")
    requires_reverse_backup = (
        action in {"replace", "remove", "restore"}
        or (action == "write-block" and has_before and not same_evidence)
        or (action == "remove-block" and not same_evidence)
        or (action == "write-manifest" and has_before and not same_evidence)
    )
    if requires_reverse_backup and backup_hash != before_hash:
        raise ValueError("backup hash must match expected-before hash")
    if action in {"create", "replace", "write-block", "write-manifest"}:
        if after_mode is not None and after_mode & ~0o600:
            raise ValueError(
                "installed journal mode must not grant group or other access"
            )
    status = value["status"]
    if type(status) is not str or status not in _STATUSES:
        raise ValueError("invalid journal operation status")
    return JournalOperation(
        operation_id=operation_id,
        identifier=identifier,
        action=action,
        expected_before_hash=before_hash,
        expected_after_hash=after_hash,
        expected_before_mode=before_mode,
        expected_after_mode=after_mode,
        backup_path=backup_path,
        backup_hash=backup_hash,
        status=status,
        expected_before_evidence=before_identity,
        expected_after_evidence=after_identity,
    )


def decode_journal(raw: object, descriptor: TargetDescriptor, home: Path) -> Journal:
    return _decode_journal(raw, descriptor, home, verify_backups=True)


def _decode_journal(
    raw: object,
    descriptor: TargetDescriptor,
    home: Path,
    *,
    verify_backups: bool,
) -> Journal:
    value = _dict(raw, _JOURNAL_KEYS, "journal")
    schema_version = _schema(value["schema_version"])
    transaction_id = _safe_id(value["transaction_id"], "transaction_id")
    target = _target(value["target"], descriptor)
    if type(value["participants"]) is not list:
        raise ValueError("journal participants must be an array")
    participants: list[Target] = []
    for item in value["participants"]:
        if type(item) is not str:
            raise ValueError("journal participants must be target names")
        try:
            participant = Target(item)
        except ValueError as exc:
            raise ValueError("journal contains unsupported participant") from exc
        if participant in participants:
            raise ValueError("journal contains duplicate participant")
        participants.append(participant)
    if target not in participants:
        raise ValueError("journal target must be a participant")
    operation = value["operation"]
    if type(operation) is not str or operation not in {"install", "uninstall"}:
        raise ValueError("invalid journal operation")
    if type(value["operations"]) is not list:
        raise ValueError("journal operations must be an array")
    operations = tuple(
        _operation(
            item,
            descriptor,
            home,
            schema_version=schema_version,
            verify_backups=verify_backups,
        )
        for item in value["operations"]
    )
    operation_ids = [item.operation_id for item in operations]
    if len(operation_ids) != len(set(operation_ids)):
        raise ValueError("journal contains duplicate operation IDs")
    allowed = _supported_identifiers(descriptor)
    canonical_paths = [
        (
            "state/manifest"
            if item.identifier == "state/manifest"
            else allowed[item.identifier]
        )
        for item in operations
    ]
    if len(canonical_paths) != len(set(canonical_paths)):
        raise ValueError("journal contains duplicate canonical destinations")
    rollback_status = value["rollback_status"]
    if type(rollback_status) is not str or rollback_status not in _ROLLBACK_STATUSES:
        raise ValueError("invalid rollback status")
    return Journal(
        schema_version,
        transaction_id,
        target,
        tuple(participants),
        operation,
        operations,
        rollback_status,
    )


def _entry_json(entry: ManifestEntry) -> dict[str, object]:
    return {
        "identifier": entry.identifier,
        "relative_path": entry.relative_path,
        "installed_hash": entry.installed_hash,
        "installed_mode": entry.installed_mode,
        "ownership": entry.ownership,
        "backup_path": entry.backup_path,
        "backup_hash": entry.backup_hash,
        "original_mode": entry.original_mode,
        "managed_block_id": entry.managed_block_id,
        "installed_block_hash": entry.installed_block_hash,
        "unresolved_reason": entry.unresolved_reason,
    }


def encode_manifest(manifest: Manifest) -> bytes:
    if type(manifest) is not Manifest:
        raise TypeError("manifest must be a Manifest")
    if type(manifest.entries) is not tuple or any(
        type(entry) is not ManifestEntry for entry in manifest.entries
    ):
        raise ValueError("manifest entries must be a tuple of ManifestEntry")
    if type(manifest.target) is not Target:
        raise ValueError("manifest target must be a Target")
    value = {
        "schema_version": manifest.schema_version,
        "target": manifest.target.value,
        "entries": [_entry_json(entry) for entry in manifest.entries],
    }
    from .targets import descriptor_for

    _decode_manifest(
        value,
        descriptor_for(manifest.target),
        Path("."),
        verify_backups=False,
    )
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _operation_json(operation: JournalOperation) -> dict[str, object]:
    value = {
        "operation_id": operation.operation_id,
        "identifier": operation.identifier,
        "action": operation.action,
        "expected_before_hash": operation.expected_before_hash,
        "expected_after_hash": operation.expected_after_hash,
        "expected_before_mode": operation.expected_before_mode,
        "expected_after_mode": operation.expected_after_mode,
        "backup_path": operation.backup_path,
        "backup_hash": operation.backup_hash,
        "status": operation.status,
    }
    return value


def encode_journal(journal: Journal) -> bytes:
    if type(journal) is not Journal:
        raise TypeError("journal must be a Journal")
    if type(journal.participants) is not tuple or any(
        type(target) is not Target for target in journal.participants
    ):
        raise ValueError("journal participants must be a tuple of Target")
    if type(journal.operations) is not tuple or any(
        type(operation) is not JournalOperation for operation in journal.operations
    ):
        raise ValueError("journal operations must be a tuple of JournalOperation")
    if type(journal.target) is not Target:
        raise ValueError("journal target must be a Target")
    value = {
        "schema_version": journal.schema_version,
        "transaction_id": journal.transaction_id,
        "target": journal.target.value,
        "participants": [target.value for target in journal.participants],
        "operation": journal.operation,
        "operations": [_operation_json(operation) for operation in journal.operations],
        "rollback_status": journal.rollback_status,
    }
    if journal.schema_version >= 2:
        for operation_value, operation in zip(
            value["operations"], journal.operations, strict=True
        ):
            operation_value["expected_before_evidence"] = _evidence_json(
                operation.expected_before_evidence
            )
            operation_value["expected_after_evidence"] = _evidence_json(
                operation.expected_after_evidence
            )
    from .targets import descriptor_for

    _decode_journal(
        value,
        descriptor_for(journal.target),
        Path("."),
        verify_backups=False,
    )
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _reject_duplicate_pairs(pairs: list[tuple[object, object]]) -> dict[object, object]:
    value: dict[object, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def _read_state_file_fd(parent_fd: int, name: str) -> object:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError("cannot open state file") from exc
    try:
        result = os.fstat(descriptor)
        if not stat.S_ISREG(result.st_mode):
            raise ValueError("state file must be a regular file")
        if stat.S_IMODE(result.st_mode) & ~0o600:
            raise ValueError("state file must be private")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    try:
        return json.loads(
            b"".join(chunks),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed state JSON; manual recovery is required") from exc


def _fd_stat(parent_fd: int, name: str, label: str) -> os.stat_result | None:
    try:
        result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(result.st_mode):
        raise ValueError(f"{label} must not be a symlink")
    return result


def _fd_names(parent_fd: int, label: str) -> list[str]:
    try:
        with os.scandir(parent_fd) as entries:
            return sorted(entry.name for entry in entries)
    except OSError as exc:
        raise ValueError(f"cannot inspect {label}") from exc


def _open_private_directory(parent_fd: int, name: str, label: str) -> int:
    result = _fd_stat(parent_fd, name, label)
    if result is None:
        raise ValueError(f"missing {label}")
    if not stat.S_ISDIR(result.st_mode):
        raise ValueError(f"{label} must be a directory")
    if stat.S_IMODE(result.st_mode) & ~0o700:
        raise ValueError(f"{label} must be private")
    try:
        descriptor = filesystem._open_directory_component(name, parent_fd, label)
    except OSError as exc:
        raise ValueError(f"cannot open {label}") from exc
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or stat.S_IMODE(opened.st_mode) & ~0o700:
        os.close(descriptor)
        raise ValueError(f"{label} changed during inspection")
    return descriptor


def _inventory_backups_fd(backups_fd: int, backups: Path) -> None:
    filesystem._after_parent_pin("state-inventory-backups", backups)
    for name in _fd_names(backups_fd, "backup directory"):
        _relative(f"backups/{name}", "backup path")
        result = _fd_stat(backups_fd, name, "backup")
        if result is None or not stat.S_ISREG(result.st_mode):
            raise ValueError("backups may contain only regular files")
        if stat.S_IMODE(result.st_mode) & ~0o600:
            raise ValueError("backup files must be private")


def _runtime_files(descriptor: TargetDescriptor) -> set[tuple[str, ...]]:
    files: set[tuple[str, ...]] = set()
    for source in descriptor.sources:
        if source.kind != "validation-runtime" or source.destination is None:
            continue
        parts = source.destination.parts
        if len(parts) < 3 or parts[:2] != (".subagents_configs", "validation"):
            raise ValueError("validation runtime destination is outside state")
        files.add(tuple(parts[2:]))
    return files


def _inventory_runtime_fd(
    directory_fd: int,
    relative: tuple[str, ...],
    allowed_files: set[tuple[str, ...]],
) -> None:
    for name in _fd_names(directory_fd, "validation directory"):
        candidate = (*relative, name)
        result = _fd_stat(directory_fd, name, "validation path")
        if result is None:
            raise ValueError("validation path disappeared")
        if candidate in allowed_files:
            if not stat.S_ISREG(result.st_mode):
                raise ValueError("validation runtime file must be regular")
            if stat.S_IMODE(result.st_mode) & ~0o600:
                raise ValueError("validation runtime file must be private")
            continue
        if any(path[: len(candidate)] == candidate for path in allowed_files):
            if not stat.S_ISDIR(result.st_mode):
                raise ValueError("validation runtime parent must be a directory")
            child_fd = _open_private_directory(
                directory_fd, name, "validation runtime directory"
            )
            try:
                _inventory_runtime_fd(child_fd, candidate, allowed_files)
            finally:
                os.close(child_fd)
            continue
        raise ValueError(f"unknown validation runtime path: {'/'.join(candidate)}")


def _inventory_state_fd(
    state_fd: int, state_dir: Path, descriptor: TargetDescriptor
) -> None:
    allowed_runtime = _runtime_files(descriptor)
    filesystem._after_parent_pin("state-inventory", state_dir)
    names = set(_fd_names(state_fd, "state directory"))
    allowed = {"manifest.json", "journal.json", "backups", "validation"}
    unknown = names - allowed
    if unknown:
        raise ValueError(f"unknown state entries: {sorted(unknown)}")
    for name in ("manifest.json", "journal.json"):
        result = _fd_stat(state_fd, name, "state file")
        if result is None:
            continue
        if not stat.S_ISREG(result.st_mode):
            raise ValueError("state file must be a regular file")
        if stat.S_IMODE(result.st_mode) & ~0o600:
            raise ValueError("state file must be private")
    if "backups" in names:
        backups_fd = _open_private_directory(state_fd, "backups", "backup directory")
        try:
            _inventory_backups_fd(backups_fd, state_dir / "backups")
        finally:
            os.close(backups_fd)
    if "validation" in names:
        validation_fd = _open_private_directory(
            state_fd, "validation", "validation directory"
        )
        try:
            _inventory_runtime_fd(validation_fd, tuple(), allowed_runtime)
        finally:
            os.close(validation_fd)


def _read_state_files(
    home: Path, descriptor: TargetDescriptor
) -> dict[str, object | None]:
    home = normalized_absolute(home)
    assert_safe_home(home)
    state_dir = home / ".subagents_configs"
    state_stat = lstat_existing(state_dir, "state directory")
    if state_stat is None:
        return {"manifest.json": None, "journal.json": None}
    if not stat.S_ISDIR(state_stat.st_mode):
        raise ValueError("state directory must be a directory")
    if stat.S_IMODE(state_stat.st_mode) & 0o077:
        raise ValueError("state directory must be private")
    with filesystem._pinned_directory(state_dir, "state directory") as state_fd:
        _inventory_state_fd(state_fd, state_dir, descriptor)
        state_names = set(_fd_names(state_fd, "state directory"))
        result = {
            name: (
                _read_state_file_fd(state_fd, name)
                if _fd_stat(state_fd, name, "state file") is not None
                else None
            )
            for name in ("manifest.json", "journal.json")
        }
    if (
        result["manifest.json"] is None
        and result["journal.json"] is None
        and not state_names.intersection({"backups", "validation"})
    ):
        raise ValueError("unknown or unsafe .subagents_configs state")
    return result


def load_manifest(home: Path, descriptor: TargetDescriptor) -> Manifest | None:
    try:
        raw = _read_state_files(home, descriptor)
        if raw["manifest.json"] is None:
            manifest = None
        elif (
            isinstance(raw["manifest.json"], dict)
            and raw["manifest.json"].get("schema_version") == 1
        ):
            manifest = migrate_manifest_schema(raw["manifest.json"], descriptor, home)
        else:
            manifest = decode_manifest(raw["manifest.json"], descriptor, home)
        if raw["journal.json"] is not None:
            if (
                isinstance(raw["journal.json"], dict)
                and raw["journal.json"].get("schema_version") == 1
            ):
                inspect_legacy_journal(raw["journal.json"], descriptor, home)
            else:
                decode_journal(raw["journal.json"], descriptor, home)
        return manifest
    except ValueError as exc:
        raise ValueError(
            f"unsafe or legacy manifest state; manual recovery is required: {exc}"
        ) from exc


def load_journal(home: Path, descriptor: TargetDescriptor) -> Journal | None:
    try:
        raw = _read_state_files(home, descriptor)
        if raw["journal.json"] is None:
            journal = None
        elif (
            isinstance(raw["journal.json"], dict)
            and raw["journal.json"].get("schema_version") == 1
        ):
            inspect_legacy_journal(raw["journal.json"], descriptor, home)
            journal = None
        else:
            journal = decode_journal(raw["journal.json"], descriptor, home)
        if raw["manifest.json"] is not None:
            if (
                isinstance(raw["manifest.json"], dict)
                and raw["manifest.json"].get("schema_version") == 1
            ):
                migrate_manifest_schema(raw["manifest.json"], descriptor, home)
            else:
                decode_manifest(raw["manifest.json"], descriptor, home)
        return journal
    except ValueError as exc:
        raise ValueError(
            f"unsafe or legacy journal state; manual recovery is required: {exc}"
        ) from exc


@dataclass(frozen=True)
class LegacyJournalEvidence:
    """Metadata that can be shown to an operator without becoming a Journal."""

    transaction_id: str
    target: Target
    operation_count: int
    rollback_status: str


def migrate_manifest_schema(
    raw: object, descriptor: TargetDescriptor, home: Path
) -> Manifest:
    """Migrate a v1 manifest after proving every live entry exactly."""

    if type(raw) is not dict or raw.get("schema_version") != 1:
        raise ValueError("manifest migration requires schema version 1")
    legacy = _decode_manifest(raw, descriptor, home, verify_backups=True)
    for entry in legacy.entries:
        candidate = normalized_absolute(home / PurePosixPath(entry.relative_path))
        evidence = capture_evidence(candidate, f"legacy manifest {entry.identifier}")
        if (
            evidence is None
            or evidence.sha256 != entry.installed_hash
            or evidence.mode != entry.installed_mode
        ):
            raise ValueError("legacy manifest live evidence does not match")
    return Manifest(SCHEMA_VERSION, legacy.target, legacy.entries)


def inspect_legacy_journal(
    raw: object, descriptor: TargetDescriptor, home: Path
) -> LegacyJournalEvidence:
    """Inspect v1 journal metadata; pending v1 journals require manual recovery."""

    if type(raw) is not dict or raw.get("schema_version") != 1:
        raise ValueError("legacy journal inspection requires schema version 1")
    journal = _decode_journal(raw, descriptor, home, verify_backups=False)
    if not journal.operations:
        raise ValueError("legacy journal has no operations")
    evidence = LegacyJournalEvidence(
        journal.transaction_id,
        journal.target,
        len(journal.operations),
        journal.rollback_status,
    )
    if journal.rollback_status != "complete" or any(
        operation.status not in {"applied", "rolled-back"}
        for operation in journal.operations
    ):
        from .transaction import IncompleteRollbackError

        raise IncompleteRollbackError(
            "schema-v1 pending journal is inspect-only; manual recovery is required"
        )
    return evidence
