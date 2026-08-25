"""Journaled execution, rollback, and recovery for validated transaction plans."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal, Protocol

from . import filesystem
from .errors import TransactionError
from .locks import (
    IdentityEvidence,
    capture_evidence,
    homes_locked,
    locked_target_homes,
)
from .models import Journal, JournalOperation, Target
from .paths import assert_contained, assert_safe_home, assert_safe_managed_path
from .planning import PlannedOperation, TargetPlan, TransactionPlan
from .state import encode_journal, load_journal
from .targets import descriptor_for


class FailureInjector(Protocol):
    def before_operation(self, operation_id: str) -> None: ...


class IncompleteRollbackError(TransactionError):
    """Raised when rollback cannot prove the prior state."""


class TransactionPreparationError(TransactionError):
    """Raised when transaction metadata cannot be prepared durably."""


DirectoryIdentity = tuple[int, int, int, int]
ArtifactIdentity = IdentityEvidence | DirectoryIdentity


@dataclass(frozen=True)
class OwnedArtifact:
    """A preparation artifact with the identity captured at creation time."""

    path: Path
    kind: Literal["directory", "backup", "journal"]
    identity: ArtifactIdentity | None = None


@dataclass(frozen=True)
class PreparedEvidence:
    """Read-only evidence bound to one planned operation."""

    target: Target
    identifier: str
    before: IdentityEvidence | None
    before_content: bytes | None = None
    backups: tuple[tuple[Path, bytes | None, IdentityEvidence | None], ...] = ()


class _Prepared:
    def __init__(self, plan: TransactionPlan, transaction_id: str):
        self.plan = plan
        self.nonce = transaction_id
        self.transaction_id = transaction_id
        self.journals: dict[Target, Journal] = {}
        self.operations: dict[Target, tuple[PlannedOperation, ...]] = {}
        self.operation_ids: dict[tuple[Target, str], str] = {}
        self.backups: dict[tuple[Target, str], tuple[str, str]] = {}
        self.owned: list[OwnedArtifact] = []
        self.before_contents: dict[tuple[Target, str], bytes | None] = {}
        self.backup_contents: dict[Path, bytes | None] = {}
        self.backup_evidence: dict[Path, IdentityEvidence | None] = {}
        self.journal_evidence: dict[Target, IdentityEvidence] = {}


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _state(home: Path) -> Path:
    return home / ".subagents_configs"


def _manifest_path(home: Path) -> Path:
    return _state(home) / "manifest.json"


def _journal_path(home: Path) -> Path:
    return _state(home) / "journal.json"


def _canonical_participant_order(participants: tuple[Target, ...]) -> None:
    order = {Target.CODEX: 0, Target.OPENCODE: 1, Target.CLAUDE_CODE: 2}
    if not participants or len(set(participants)) != len(participants):
        raise ValueError("journal participants must be unique")
    if tuple(sorted(participants, key=order.__getitem__)) != participants:
        raise ValueError("journal participants are not in descriptor order")


def _journal_commitment_record(journal: Journal) -> dict[str, object]:
    descriptor = descriptor_for(journal.target)
    return {
        "target": journal.target.value,
        "participants": [target.value for target in journal.participants],
        "operation": journal.operation,
        "operations": [
            {
                "operation_id": operation.operation_id,
                "identifier": _identifier_relative(descriptor, operation.identifier),
                "canonical_path": _identifier_relative(
                    descriptor, operation.identifier
                ),
                "action": operation.action,
                "expected_before_hash": operation.expected_before_hash,
                "expected_after_hash": operation.expected_after_hash,
                "expected_before_mode": operation.expected_before_mode,
                "expected_after_mode": operation.expected_after_mode,
                "backup_path": operation.backup_path,
                "backup_hash": operation.backup_hash,
            }
            for operation in journal.operations
        ],
    }


def _committed_transaction_id(nonce: str, journals: tuple[Journal, ...]) -> str:
    return f"{nonce}-{_commitment_digest(journals)}"


def _commitment_digest(journals: tuple[Journal, ...]) -> str:
    payload = json.dumps(
        [_journal_commitment_record(journal) for journal in journals],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return _digest(payload)


def _commitment_path(home: Path, nonce: str) -> Path:
    return _state(home) / "backups" / f"commitment-{nonce}"


def _read_commitment_marker(home: Path, nonce: str) -> str:
    marker = _commitment_path(home, nonce)
    try:
        descriptor = filesystem._open_regular_read(marker, "transaction commitment")
    except FileNotFoundError as exc:
        raise ValueError("transaction commitment marker is missing") from exc
    try:
        content = os.read(descriptor, 4096)
        if os.read(descriptor, 1):
            raise ValueError("transaction commitment marker is too large")
        mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
    finally:
        os.close(descriptor)
    if mode != 0o600:
        raise ValueError("transaction commitment marker is invalid")
    try:
        marker_nonce, marker_digest = content.decode().split(":", 1)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("transaction commitment marker is invalid") from exc
    if (
        marker_nonce != nonce
        or len(marker_nonce) != 32
        or any(char not in "0123456789abcdef" for char in marker_nonce)
        or len(marker_digest) != 64
        or any(char not in "0123456789abcdef" for char in marker_digest)
    ):
        raise ValueError("transaction commitment marker is invalid")
    return marker_digest


def _validate_journal_operation_order(journal: Journal) -> None:
    descriptor = descriptor_for(journal.target)
    if not journal.operations:
        raise ValueError("transaction journal has no operations")
    canonical: list[tuple[bool, str, str, JournalOperation]] = []
    seen_relative: set[str] = set()
    for index, operation in enumerate(journal.operations):
        relative = _identifier_relative(descriptor, operation.identifier)
        if relative is None:
            raise ValueError("journal identifier is not managed")
        if relative in seen_relative:
            raise ValueError("journal operation paths are not unique")
        seen_relative.add(relative)
        if operation.operation_id != _operation_id(
            journal.target, index, operation.identifier
        ):
            raise ValueError("journal operation ID is not stable")
        canonical.append(
            (
                operation.identifier == "state/manifest",
                relative,
                operation.identifier,
                operation,
            )
        )
    expected = sorted(canonical, key=lambda item: item[:3])
    if [item[3] for item in canonical] != [item[3] for item in expected]:
        raise ValueError("journal operations are not in canonical order")
    if journal.operations[-1].identifier != "state/manifest":
        raise ValueError("journal manifest operation is not last")
    if (
        sum(
            operation.identifier == "state/manifest" for operation in journal.operations
        )
        != 1
    ):
        raise ValueError("journal must contain one manifest operation")


def _validate_transaction_commitment(
    journals: tuple[Journal, ...], homes: Mapping[Target, Path] | None = None
) -> None:
    if not journals:
        raise ValueError("transaction has no participant journals")
    participants = journals[0].participants
    _canonical_participant_order(participants)
    if tuple(journal.target for journal in journals) != participants:
        raise ValueError("transaction journals are not in participant order")
    if any(
        journal.participants != participants
        or journal.operation != journals[0].operation
        or journal.transaction_id != journals[0].transaction_id
        for journal in journals
    ):
        raise ValueError("transaction journals disagree")
    try:
        nonce, digest = journals[0].transaction_id.rsplit("-", 1)
    except ValueError as exc:
        raise ValueError("journal transaction commitment is missing") from exc
    if len(nonce) != 32 or any(char not in "0123456789abcdef" for char in nonce):
        raise ValueError("journal transaction nonce is invalid")
    for journal in journals:
        _validate_journal_operation_order(journal)
    expected = _committed_transaction_id(nonce, journals)
    if digest != expected.rsplit("-", 1)[1]:
        raise ValueError("journal transaction commitment does not match")
    if homes is not None:
        if set(homes) != set(participants):
            raise ValueError("transaction commitment homes are incomplete")
        for target in participants:
            if _read_commitment_marker(homes[target], nonce) != digest:
                raise ValueError("transaction commitment marker does not match")


def _transaction_backup_path(nonce: str, target: Target, operation_id: str) -> str:
    name = hashlib.sha256(
        f"transaction:{nonce}:{target.value}:{operation_id}".encode()
    ).hexdigest()
    return f"backups/{name}"


def _identifier_relative(descriptor, identifier: str) -> str | None:
    if identifier == "state/manifest":
        return ".subagents_configs/manifest.json"
    for source in descriptor.sources:
        if identifier in {
            source.identifier,
            source.destination.as_posix() if source.destination else None,
        }:
            return source.destination.as_posix() if source.destination else None
    for setting in descriptor.managed_settings:
        if identifier in {setting.identifier, setting.relative_path.as_posix()}:
            return setting.relative_path.as_posix()
    global_aliases = {
        descriptor.global_filename: descriptor.global_filename,
    }
    if descriptor.config_filename is not None:
        global_aliases[descriptor.config_filename] = descriptor.config_filename
    if identifier in global_aliases:
        return global_aliases[identifier]
    return {
        "routing-codex": descriptor.global_filename,
        "routing-opencode": descriptor.global_filename,
        "routing-claude-code": descriptor.global_filename,
        "codex-multi-agent-v2": descriptor.config_filename,
    }.get(identifier)


def _canonical_path(target_plan: TargetPlan, operation: PlannedOperation) -> Path:
    descriptor = descriptor_for(target_plan.target)
    relative = _identifier_relative(descriptor, operation.identifier)
    if relative is None:
        raise ValueError(f"unknown managed identifier: {operation.identifier}")
    candidate = target_plan.home / relative
    assert_contained(target_plan.home, candidate)
    assert_safe_managed_path(target_plan.home, candidate, operation.identifier)
    return candidate


def _read_regular(path: Path) -> tuple[bytes, int] | None:
    try:
        descriptor = filesystem._open_regular_read(path, "transaction target")
    except FileNotFoundError:
        return None
    try:
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        result = os.fstat(descriptor)
        if stat.S_IMODE(result.st_mode) < 0:
            raise ValueError("invalid transaction target mode")
        return b"".join(chunks), stat.S_IMODE(result.st_mode)
    finally:
        os.close(descriptor)


def _check_evidence(
    path: Path,
    expected_hash: str | None,
    expected_mode: int | None,
    *,
    present: bool,
    expected_identity: IdentityEvidence | None = None,
) -> bytes | None:
    if expected_identity is not None:
        current_identity = capture_evidence(path, "transaction target")
        if current_identity != expected_identity:
            raise TransactionError(f"transaction target identity changed: {path}")
        if (
            expected_hash != current_identity.sha256
            or expected_mode != current_identity.mode
        ):
            raise TransactionError(f"transaction target evidence disagrees: {path}")
        if not present:
            return None
        current = _read_regular(path)
        return current[0] if current is not None else None
    if expected_hash is not None:
        raise TransactionError("transaction target lacks identity evidence")
    current = _read_regular(path)
    if not present:
        if current is not None:
            raise ValueError(f"expected absent transaction target exists: {path}")
        return None
    if current is None:
        raise ValueError(f"expected transaction target is absent: {path}")
    content, mode = current
    if expected_hash is None or expected_mode is None:
        raise ValueError("present transaction state lacks hash/mode evidence")
    if _digest(content) != expected_hash or mode != expected_mode:
        raise ValueError(f"transaction target changed before apply: {path}")
    return content


def _validate_operation(target_plan: TargetPlan, operation: PlannedOperation) -> Path:
    if operation.target is not target_plan.target:
        raise ValueError("operation target does not match target plan")
    if type(operation.identifier) is not str or not operation.identifier:
        raise ValueError("operation identifier must be non-empty")
    if type(operation.content) is not bytes and operation.content is not None:
        raise ValueError("operation content must be bytes or None")
    if type(operation.backup_required) is not bool:
        raise ValueError("backup_required must be a bool")
    if operation.expected_after_hash is not None:
        if (
            operation.content is None
            or _digest(operation.content) != operation.expected_after_hash
        ):
            raise ValueError("operation content does not match expected-after hash")
    elif operation.content is not None:
        raise ValueError("absent after-state cannot carry content")
    if (
        operation.expected_after_hash is None
        and operation.expected_after_mode is not None
    ):
        raise ValueError("absent after-state cannot carry a mode")
    if (
        operation.expected_after_hash is not None
        and operation.expected_after_mode is None
    ):
        raise ValueError("present after-state requires a mode")
    if (
        operation.expected_after_mode is not None
        and operation.action not in {"restore", "remove-block"}
        and operation.expected_after_mode
        & ~(
            0o700
            if descriptor_for(target_plan.target).target is Target.CLAUDE_CODE
            and operation.identifier == "claude/code-validator-command-gate"
            else 0o600
        )
    ):
        raise ValueError("managed after-state must be private")
    if (operation.expected_before_hash is None) != (
        operation.expected_before_mode is None
    ):
        raise ValueError("before hash and mode must be supplied together")
    actions = {
        "create",
        "replace",
        "restore",
        "write-block",
        "remove",
        "remove-block",
        "write-manifest",
    }
    if operation.action not in actions:
        raise ValueError("unsupported transaction action")
    before = operation.expected_before_hash is not None
    after = operation.expected_after_hash is not None
    if operation.action == "create" and (before or not after):
        raise ValueError("create action has invalid before/after evidence")
    if operation.action in {"replace", "restore"} and (not before or not after):
        raise ValueError("replacement action has invalid before/after evidence")
    if operation.action == "remove" and (not before or after):
        raise ValueError("remove action has invalid before/after evidence")
    if operation.action == "remove-block" and not before:
        raise ValueError("remove-block action has invalid before evidence")
    if operation.action == "write-block" and not after:
        raise ValueError("write action requires an after-state")
    descriptor = descriptor_for(target_plan.target)
    canonical = _canonical_path(target_plan, operation)
    expected_relative = canonical.relative_to(target_plan.home).as_posix()
    if operation.relative_path != expected_relative:
        raise ValueError("operation relative_path does not match its identifier")
    if operation.action in {"write-block", "remove-block"}:
        if (
            operation.managed_block_id is None
            or _identifier_relative(descriptor, operation.managed_block_id)
            != expected_relative
        ):
            raise ValueError("block operation has mismatched managed_block_id")
    elif operation.managed_block_id is not None:
        raise ValueError("non-block operation cannot carry managed_block_id")
    if operation.ownership not in {None, "created", "replaced", "preexisting"}:
        raise ValueError("operation has invalid ownership")
    if operation.action == "create" and operation.ownership != "created":
        raise ValueError("create operation must own a created entry")
    if operation.action == "restore" and operation.ownership != "replaced":
        raise ValueError("restore operation must restore a replaced entry")
    if operation.action == "remove" and operation.ownership != "created":
        raise ValueError("remove operation must remove a created entry")
    if operation.action == "write-manifest" and operation.ownership is not None:
        raise ValueError("manifest operation cannot carry file ownership")
    return canonical


def _validate_manifest_linkage(target_plan: TargetPlan) -> None:
    manifest = target_plan.resulting_manifest
    if manifest is None:
        manifest_operations = [
            operation
            for operation in target_plan.operations
            if operation.action == "write-manifest"
        ]
        if not target_plan.operations:
            if manifest_operations:
                raise ValueError("empty plan has a manifest operation")
            return
        if len(manifest_operations) != 1:
            raise ValueError("absent resulting manifest requires one operation")
        manifest_operation = manifest_operations[0]
        if (
            manifest_operation.content is not None
            or manifest_operation.expected_after_hash is not None
            or manifest_operation.expected_after_mode is not None
        ):
            raise ValueError("absent resulting manifest has present evidence")
        if any(
            operation.action not in {"write-manifest", "restore", "remove-block"}
            and operation.expected_after_hash is not None
            for operation in target_plan.operations
        ):
            raise ValueError("absent resulting manifest has retained entries")
        return
    if manifest.target is not target_plan.target:
        raise ValueError("resulting manifest target does not match target plan")
    backup_paths: set[str] = set()
    entries = {entry.identifier: entry for entry in manifest.entries}
    descriptor = descriptor_for(target_plan.target)
    operations = {
        _identifier_relative(descriptor, operation.identifier): operation
        for operation in target_plan.operations
        if operation.action != "write-manifest"
    }
    from .state import load_manifest

    prior_manifest = load_manifest(target_plan.home, descriptor_for(target_plan.target))
    prior_entries = (
        {entry.identifier: entry for entry in prior_manifest.entries}
        if prior_manifest is not None
        else {}
    )
    for entry in manifest.entries:
        if entry.backup_path is not None:
            if entry.backup_path in backup_paths:
                raise ValueError("manifest backup paths must be unique")
            backup_paths.add(entry.backup_path)
        operation = operations.get(entry.relative_path)
        if operation is not None:
            if operation.expected_after_hash != entry.installed_hash:
                raise ValueError("manifest installed hash does not match operation")
            if operation.expected_after_mode != entry.installed_mode:
                raise ValueError("manifest installed mode does not match operation")
            if (
                operation.ownership is not None
                and operation.ownership != entry.ownership
            ):
                raise ValueError("manifest ownership does not match operation")
            if operation.ownership is None and operation.action not in {
                "write-block",
                "remove-block",
            }:
                raise ValueError("manifest ownership is missing for file operation")
            if operation.action == "write-block":
                expected_ownership = (
                    "created"
                    if operation.expected_before_hash is None
                    else operation.ownership or "replaced"
                )
                if entry.ownership != expected_ownership:
                    raise ValueError("manifest block ownership does not match")
            if entry.managed_block_id != operation.managed_block_id or (
                operation.managed_block_id is not None
                and _identifier_relative(descriptor, operation.managed_block_id)
                != entry.relative_path
            ):
                raise ValueError("manifest block metadata does not match operation")
            if (
                entry.managed_setting_id is not None
                and operation.managed_block_id is not None
            ):
                raise ValueError("setting-owned entry cannot also be a block entry")
        setting_ids = {item.identifier for item in descriptor.managed_settings}
        if entry.identifier in setting_ids:
            if entry.managed_setting_id != entry.identifier:
                raise ValueError("manifest setting metadata does not match operation")
        if (
            operation is not None
            and entry.managed_block_id is not None
            and operation.content is not None
        ):
            from .planning import _block_from_file

            block = _block_from_file(operation.content, entry.managed_block_id)
            if block is None or block.sha256 != entry.installed_block_hash:
                raise ValueError("manifest block hash does not match operation")
        relative = _identifier_relative(descriptor, entry.identifier)
        if relative is None or relative != entry.relative_path:
            raise ValueError("manifest entry path does not match its identifier")
        if entry.backup_path is not None:
            backup = _state(target_plan.home) / entry.backup_path
            assert_contained(target_plan.home, backup)
            assert_safe_managed_path(target_plan.home, backup, "manifest backup")
            current_backup = _read_regular(backup)
            prior_entry = prior_entries.get(entry.identifier)
            retained_prior_backup = (
                prior_entry is not None
                and prior_entry.ownership == "replaced"
                and prior_entry.backup_path == entry.backup_path
                and prior_entry.backup_hash == entry.backup_hash
                and prior_entry.original_mode == entry.original_mode
            )
            if current_backup is not None:
                if current_backup[1] & ~0o600:
                    raise ValueError("manifest backup is not private")
                if _digest(current_backup[0]) != entry.backup_hash:
                    raise ValueError("manifest backup hash does not match")
                if (
                    operation is not None
                    and not retained_prior_backup
                    and (
                        operation.expected_before_hash != entry.backup_hash
                        or operation.expected_before_mode != entry.original_mode
                    )
                ):
                    raise ValueError(
                        "manifest backup is not linked to operation before-state"
                    )
            elif operation is None:
                raise ValueError("manifest backup is missing")
            elif (
                operation.expected_before_hash != entry.backup_hash
                or operation.expected_before_mode != entry.original_mode
            ):
                raise ValueError(
                    "manifest backup is not linked to operation before-state"
                )
            elif operation.action not in {"replace", "write-block"}:
                raise ValueError("manifest backup action is invalid")
        elif entry.ownership == "replaced":
            raise ValueError("replaced manifest entry requires backup metadata")
        prior_entry = prior_entries.get(entry.identifier)
        if operation is None and entry.unresolved_reason is not None:
            if prior_entry is None or prior_entry.relative_path != entry.relative_path:
                raise ValueError("unresolved manifest entry is not retained")
            comparable = replace(entry, unresolved_reason=None)
            prior_comparable = replace(prior_entry, unresolved_reason=None)
            if comparable != prior_comparable:
                raise ValueError("unresolved manifest entry metadata was altered")
            continue
        if operation is None and prior_entry is not None and entry != prior_entry:
            raise ValueError("unchanged manifest entry metadata was altered")
        if entry.managed_block_id is not None:
            path = target_plan.home / entry.relative_path
            current = _read_regular(path)
            if current is None:
                if operation is None:
                    raise ValueError("manifest block target is missing")
            else:
                if operation is None and (
                    _digest(current[0]) != entry.installed_hash
                    or current[1] != entry.installed_mode
                ):
                    raise ValueError("unchanged manifest block target does not match")
                from .planning import _block_from_file

                block = _block_from_file(current[0], entry.managed_block_id)
                if block is None or block.sha256 != entry.installed_block_hash:
                    if operation is None:
                        raise ValueError(
                            "manifest block hash does not match current state"
                        )
        elif operation is None:
            path = target_plan.home / entry.relative_path
            current = _read_regular(path)
            if current is None:
                raise ValueError("manifest entry target is missing")
            if (
                _digest(current[0]) != entry.installed_hash
                or current[1] != entry.installed_mode
            ):
                raise ValueError(
                    "manifest entry does not match unchanged current state"
                )
    manifest_operations = [
        operation
        for operation in target_plan.operations
        if operation.identifier == "state/manifest"
    ]
    if not target_plan.operations:
        return
    if len(manifest_operations) != 1:
        raise ValueError("resulting manifest requires exactly one manifest operation")
    manifest_operation = manifest_operations[0]
    from .state import encode_manifest

    manifest_bytes = encode_manifest(manifest)
    if (
        manifest_operation.content != manifest_bytes
        or manifest_operation.expected_after_hash != _digest(manifest_bytes)
        or manifest_operation.expected_after_mode != 0o600
    ):
        raise ValueError("manifest operation is not linked to resulting manifest")
    if {entry.relative_path for entry in entries.values()} != {
        operation.relative_path
        for operation in target_plan.operations
        if operation.action
        not in {"write-manifest", "remove", "remove-block", "restore"}
        and operation.expected_after_hash is not None
    } | {
        entry.relative_path
        for entry in entries.values()
        if entry.relative_path not in operations
    }:
        raise ValueError("manifest entries and operation after-states do not match")


def _validate_plan(plan: TransactionPlan) -> None:
    if type(plan) is not TransactionPlan or plan.operation not in {
        "install",
        "uninstall",
    }:
        raise ValueError("invalid transaction plan")
    if not plan.targets:
        raise ValueError("transaction plan has no targets")
    seen_targets: set[Target] = set()
    seen_homes: set[Path] = set()
    target_order = {
        target: index
        for index, target in enumerate(
            (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE)
        )
    }
    previous_order = -1
    for target_plan in plan.targets:
        if type(target_plan) is not TargetPlan:
            raise ValueError("transaction plan contains an invalid target plan")
        if target_plan.target in seen_targets:
            raise ValueError("transaction plan contains duplicate targets")
        if target_order.get(target_plan.target, -1) <= previous_order:
            raise ValueError("transaction targets are not in descriptor order")
        previous_order = target_order[target_plan.target]
        seen_targets.add(target_plan.target)
        if not isinstance(target_plan.home, Path):
            raise ValueError("target plan home must be a Path")
        home = target_plan.home
        assert_safe_home(home)
        if load_journal(home, descriptor_for(target_plan.target)) is not None:
            raise ValueError("existing transaction journal blocks apply")
        normalized = home.absolute().resolve(strict=False)
        if normalized in seen_homes:
            raise ValueError("transaction homes must be distinct")
        seen_homes.add(normalized)
        if plan.operation == "install" and target_plan.conflicts:
            raise ValueError(
                f"transaction plan contains conflicts for {target_plan.target.value}"
            )
        seen_paths: set[Path] = set()
        seen_identifiers: set[str] = set()
        for operation in target_plan.operations:
            path = _validate_operation(target_plan, operation)
            if path in seen_paths or operation.identifier in seen_identifiers:
                raise ValueError("transaction plan contains duplicate operation target")
            seen_paths.add(path)
            seen_identifiers.add(operation.identifier)
        manifests = [
            item for item in target_plan.operations if item.action == "write-manifest"
        ]
        if len(manifests) > 1:
            raise ValueError("target has duplicate manifest operations")
        if manifests and target_plan.resulting_manifest is not None:
            from .state import encode_manifest

            if manifests[0].content != encode_manifest(target_plan.resulting_manifest):
                raise ValueError("manifest operation content does not match plan")
        if plan.operation == "uninstall":
            resulting_entries = (
                target_plan.resulting_manifest.entries
                if target_plan.resulting_manifest is not None
                else ()
            )
            unresolved = tuple(
                entry
                for entry in resulting_entries
                if entry.unresolved_reason is not None
            )
            reasons = tuple(sorted(entry.unresolved_reason for entry in unresolved))
            conflicts = tuple(sorted(target_plan.conflicts))
            if reasons != conflicts or any(
                type(reason) is not str or not reason for reason in conflicts
            ):
                raise ValueError("uninstall conflicts do not match unresolved entries")
            operation_paths = {
                _identifier_relative(
                    descriptor_for(target_plan.target), operation.identifier
                )
                for operation in target_plan.operations
                if operation.action != "write-manifest"
            }
            if any(entry.relative_path in operation_paths for entry in unresolved):
                raise ValueError("uninstall targets an unresolved manifest entry")
        _validate_manifest_linkage(target_plan)


def _operation_id(target: Target, ordinal: int, identifier: str) -> str:
    relative = _identifier_relative(descriptor_for(target), identifier) or identifier
    safe = "".join(
        char if char.isalnum() or char in "._-" else "-" for char in relative
    )
    return f"{target.value}-{ordinal:04d}-{safe}"[:128]


def _manifest_entry_for_operation(target_plan: TargetPlan, operation: PlannedOperation):
    if target_plan.resulting_manifest is None:
        return None
    relative = _identifier_relative(
        descriptor_for(target_plan.target), operation.identifier
    )
    return next(
        (
            item
            for item in target_plan.resulting_manifest.entries
            if item.relative_path == relative
        ),
        None,
    )


def _ensure_permanent_backup(
    prepared: _Prepared,
    target_plan: TargetPlan,
    operation: PlannedOperation,
    path: Path,
) -> None:
    if operation.expected_before_hash is None:
        return
    entry = _manifest_entry_for_operation(target_plan, operation)
    if entry is None or entry.ownership != "replaced":
        return
    if entry.backup_path is None or entry.backup_hash is None:
        raise ValueError("replaced manifest entry lacks permanent backup")
    destination = _state(target_plan.home) / entry.backup_path
    existing_content = prepared.backup_contents.get(destination)
    existing_identity = prepared.backup_evidence.get(destination)
    if existing_identity is None:
        before_content = prepared.before_contents.get(
            (target_plan.target, operation.relative_path)
        )
        if before_content is None:
            raise TransactionPreparationError("backup source evidence is missing")
        if operation.expected_before_hash != entry.backup_hash:
            raise TransactionPreparationError(
                "permanent backup does not match before-state"
            )
        identity = filesystem.exclusive_write(destination, before_content, 0o600)
        _record_owned(prepared.owned, destination, "backup", identity)
        prepared.backup_evidence[destination] = identity
        prepared.backup_contents[destination] = before_content
        return
    if existing_content is None or existing_identity is None:
        raise ValueError("permanent backup hash does not match manifest")


def _transaction_backup(
    prepared: _Prepared,
    target_plan: TargetPlan,
    operation: PlannedOperation,
    operation_id: str,
    path: Path,
) -> tuple[str, str] | None:
    if operation.expected_before_hash is None:
        return None
    if (
        operation.expected_before_hash == operation.expected_after_hash
        and operation.expected_before_mode == operation.expected_after_mode
    ):
        return None
    key = (target_plan.target, operation.relative_path)
    if key in prepared.backups:
        return prepared.backups[key]
    relative = _transaction_backup_path(
        prepared.nonce, target_plan.target, operation_id
    )
    destination = _state(target_plan.home) / relative
    before_content = prepared.before_contents.get(key)
    if before_content is None:
        raise TransactionPreparationError(
            "transaction backup source evidence is missing"
        )
    digest = operation.expected_before_hash
    if digest is None:
        raise TransactionPreparationError(
            "transaction backup source evidence is missing"
        )
    try:
        identity = filesystem.exclusive_write(destination, before_content, 0o600)
    except FileExistsError as exc:
        raise TransactionPreparationError("transaction backup already exists") from exc
    _record_owned(prepared.owned, destination, "backup", identity)
    prepared.backup_evidence[destination] = identity
    prepared.backup_contents[destination] = before_content
    prepared.backups[key] = (relative, digest)
    return relative, digest


def _journal_operation(
    prepared: _Prepared,
    target_plan: TargetPlan,
    operation: PlannedOperation,
    ordinal: int,
    path: Path,
) -> JournalOperation:
    operation_id = _operation_id(target_plan.target, ordinal, operation.identifier)
    prepared.operation_ids[(target_plan.target, operation.identifier)] = operation_id
    _ensure_permanent_backup(prepared, target_plan, operation, path)
    backup = _transaction_backup(prepared, target_plan, operation, operation_id, path)
    before_identity = operation.expected_before_evidence
    if operation.expected_before_hash is not None and before_identity is None:
        raise TransactionError("transaction journal target lacks identity evidence")
    return JournalOperation(
        operation_id,
        operation.identifier,
        operation.action,
        operation.expected_before_hash,
        operation.expected_after_hash,
        operation.expected_before_mode,
        operation.expected_after_mode,
        backup[0] if backup else None,
        backup[1] if backup else None,
        "planned",
        before_identity,
        operation.expected_after_evidence,
    )


def _write_journal(home: Path, journal: Journal) -> IdentityEvidence:
    identity = filesystem.atomic_write(
        _journal_path(home), encode_journal(journal), 0o600
    )
    if not isinstance(identity, IdentityEvidence):
        identity = capture_evidence(_journal_path(home), "written journal")
    if identity is None:
        raise TransactionPreparationError("written journal is missing")
    return identity


def _journal_with_status(journal: Journal, status: str) -> Journal:
    rollback_status = journal.rollback_status
    operation_status = status
    if status == "complete":
        rollback_status = "complete"
        operation_status = "applied"
    return replace(
        journal,
        operations=tuple(
            replace(operation, status=operation_status)
            for operation in journal.operations
        ),
        rollback_status=rollback_status,
    )


def _journal_for_plan(plan: TransactionPlan, transaction_id: str) -> Journal:
    nonce = hashlib.sha256(transaction_id.encode()).hexdigest()[:32]
    target_plan = plan.targets[0]
    ordered = tuple(
        sorted(
            target_plan.operations,
            key=lambda item: (
                item.action == "write-manifest",
                item.relative_path,
                item.identifier,
            ),
        )
    )

    def current_identity(operation: PlannedOperation) -> IdentityEvidence | None:
        path = _canonical_path(target_plan, operation)
        if not path.parent.exists():
            return None
        try:
            return capture_evidence(path, "journal plan target")
        except FileNotFoundError:
            return None

    operations = tuple(
        JournalOperation(
            _operation_id(target_plan.target, index, operation.identifier),
            operation.identifier,
            operation.action,
            operation.expected_before_hash,
            operation.expected_after_hash,
            operation.expected_before_mode,
            operation.expected_after_mode,
            None,
            None,
            "planned",
            operation.expected_before_evidence
            if operation.expected_before_evidence is not None
            else current_identity(operation)
            if operation.expected_before_hash is not None
            else None,
            operation.expected_after_evidence
            if operation.expected_after_evidence is not None
            else current_identity(operation)
            if operation.expected_after_hash is not None
            and operation.expected_before_hash is None
            else None,
        )
        for index, operation in enumerate(ordered)
    )
    journal = Journal(
        2,
        transaction_id,
        target_plan.target,
        tuple(item.target for item in plan.targets),
        plan.operation,
        operations,
        "not-started",
    )
    journal = replace(
        journal, transaction_id=_committed_transaction_id(nonce, (journal,))
    )
    filesystem.ensure_private_directory(_state(target_plan.home) / "backups")
    filesystem.exclusive_write(
        _commitment_path(target_plan.home, nonce),
        f"{nonce}:{journal.transaction_id.rsplit('-', 1)[1]}".encode(),
        0o600,
    )
    return journal


def _commit_prepared_transaction(prepared: _Prepared) -> None:
    journals = tuple(
        prepared.journals[target_plan.target] for target_plan in prepared.plan.targets
    )
    transaction_id = _committed_transaction_id(prepared.nonce, journals)
    prepared.transaction_id = transaction_id
    for target_plan in prepared.plan.targets:
        prepared.journals[target_plan.target] = replace(
            prepared.journals[target_plan.target], transaction_id=transaction_id
        )


def _write_commitment_markers(prepared: _Prepared) -> None:
    journals = tuple(
        prepared.journals[target_plan.target] for target_plan in prepared.plan.targets
    )
    digest = _commitment_digest(journals)
    for target_plan in prepared.plan.targets:
        marker = _commitment_path(target_plan.home, prepared.nonce)
        identity = filesystem.exclusive_write(
            marker,
            f"{prepared.nonce}:{digest}".encode(),
            0o600,
        )
        _record_owned(prepared.owned, marker, "journal", identity)


def _capture_artifact_identity(
    path: Path, kind: Literal["directory", "backup", "journal"]
) -> ArtifactIdentity | None:
    """Capture a no-follow identity suitable for preparation cleanup."""

    try:
        item = path.lstat()
    except FileNotFoundError:
        return None
    if kind == "directory":
        if not stat.S_ISDIR(item.st_mode):
            raise TransactionPreparationError("prepared directory identity is invalid")
        return (item.st_dev, item.st_ino, item.st_nlink, stat.S_IMODE(item.st_mode))
    if not stat.S_ISREG(item.st_mode):
        raise TransactionPreparationError("prepared file identity is invalid")
    return capture_evidence(path, "prepared artifact")


def _record_owned(
    owned: list[OwnedArtifact],
    path: Path,
    kind: Literal["directory", "backup", "journal"],
    identity: ArtifactIdentity | None = None,
) -> ArtifactIdentity:
    if identity is None:
        identity = _capture_artifact_identity(path, kind)
    if identity is None:
        raise TransactionPreparationError("prepared artifact disappeared")
    owned.append(OwnedArtifact(path, kind, identity))
    return identity


def _ensure_owned_directory(
    path: Path, owned: list[OwnedArtifact], *, private: bool = False
) -> None:
    """Create a directory chain and record only components created by us."""

    created = filesystem.ensure_directory(path, private=private) or ()
    for created_path, identity in created:
        _record_owned(owned, created_path, "directory", identity)


def _cleanup_preparation(owned: Sequence[OwnedArtifact]) -> None:
    """Remove exactly the artifacts created by preparation, newest first."""

    for artifact in reversed(tuple(owned)):
        if artifact.identity is None:
            continue
        try:
            if artifact.kind == "directory":
                if not isinstance(artifact.identity, tuple):
                    continue
                filesystem.remove_owned_directory(artifact.path, artifact.identity)
                continue
            current = capture_evidence(artifact.path, "preparation cleanup")
            if current != artifact.identity:
                continue
            filesystem.compare_and_swap(artifact.path, current, None, None, "unlink")
        except (FileNotFoundError, OSError, TransactionError, ValueError):
            # Cleanup is fail-closed: a missing or replaced path is retained.
            continue


def _collect_readonly_evidence(
    plan: TransactionPlan,
) -> tuple[PreparedEvidence, ...]:
    """Validate every operation without creating any filesystem artifact."""

    _validate_plan(plan)
    evidence: list[PreparedEvidence] = []
    for target_plan in plan.targets:
        for operation in target_plan.operations:
            path = _canonical_path(target_plan, operation)
            try:
                before = capture_evidence(path, "transaction precondition")
            except FileNotFoundError:
                before = None
            before_content = _check_evidence(
                path,
                operation.expected_before_hash,
                operation.expected_before_mode,
                present=operation.expected_before_hash is not None,
                expected_identity=before,
            )
            if operation.expected_before_hash is not None and before is None:
                raise TransactionError(
                    "transaction precondition lacks identity evidence"
                )
            backup_records: list[
                tuple[Path, bytes | None, IdentityEvidence | None]
            ] = []
            entry = _manifest_entry_for_operation(target_plan, operation)
            if entry is not None and entry.backup_path is not None:
                backup_path = _state(target_plan.home) / entry.backup_path
                try:
                    backup = _read_regular(backup_path)
                except FileNotFoundError:
                    backup = None
                try:
                    backup_identity = capture_evidence(backup_path, "backup evidence")
                except FileNotFoundError:
                    backup_identity = None
                if backup is not None:
                    if (
                        backup[1] & ~0o600
                        or entry.backup_hash is None
                        or _digest(backup[0]) != entry.backup_hash
                    ):
                        raise TransactionError("backup evidence is invalid")
                elif (
                    operation.expected_before_hash != entry.backup_hash
                    or entry.backup_hash is None
                ):
                    raise TransactionError("backup evidence is invalid")
                backup_records.append(
                    (
                        backup_path,
                        backup[0] if backup is not None else None,
                        backup_identity,
                    )
                )
            evidence.append(
                PreparedEvidence(
                    target_plan.target,
                    operation.identifier,
                    before,
                    before_content,
                    tuple(backup_records),
                )
            )
    return tuple(evidence)


def _prepare(
    plan: TransactionPlan,
    evidence: tuple[PreparedEvidence, ...] | None = None,
) -> _Prepared:
    """Create transaction metadata only after complete read-only evidence."""

    if evidence is None:
        evidence = _collect_readonly_evidence(plan)
    _validate_plan(plan)
    evidence_by_operation = {(item.target, item.identifier): item for item in evidence}
    prepared = _Prepared(plan, secrets.token_hex(16))
    participants = tuple(item.target for item in plan.targets)
    prepared_operations: dict[Target, tuple[PlannedOperation, ...]] = {}
    try:
        for target_plan in plan.targets:
            _ensure_owned_directory(
                _state(target_plan.home), prepared.owned, private=True
            )
            _ensure_owned_directory(
                _state(target_plan.home) / "backups", prepared.owned, private=True
            )
            validated_operations: list[PlannedOperation] = []
            for operation in target_plan.operations:
                item = evidence_by_operation.get(
                    (target_plan.target, operation.identifier)
                )
                if item is None:
                    raise TransactionPreparationError("prepared evidence is incomplete")
                prepared.before_contents[
                    (target_plan.target, operation.relative_path)
                ] = item.before_content
                for backup_path, backup_content, backup_identity in item.backups:
                    prepared.backup_contents[backup_path] = backup_content
                    prepared.backup_evidence[backup_path] = backup_identity
                validated_operations.append(
                    replace(operation, expected_before_evidence=item.before)
                )
                path = _canonical_path(target_plan, operation)
                parent = path.parent
                if parent != target_plan.home:
                    private_parent = (
                        parent == _state(target_plan.home)
                        or _state(target_plan.home) in parent.parents
                    )
                    _ensure_owned_directory(
                        parent, prepared.owned, private=private_parent
                    )
            prepared_operations[target_plan.target] = tuple(validated_operations)
            filesystem.sync_directory(target_plan.home)
            filesystem.sync_directory(_state(target_plan.home))
            filesystem.sync_directory(_state(target_plan.home) / "backups")
        for target_plan in plan.targets:
            ordered = sorted(
                prepared_operations[target_plan.target],
                key=lambda item: (
                    item.action == "write-manifest",
                    item.relative_path,
                    item.identifier,
                ),
            )
            prepared.operations[target_plan.target] = tuple(ordered)
            journal_operations = tuple(
                _journal_operation(
                    prepared,
                    target_plan,
                    operation,
                    index,
                    _canonical_path(target_plan, operation),
                )
                for index, operation in enumerate(ordered)
            )
            prepared.journals[target_plan.target] = Journal(
                2,
                prepared.transaction_id,
                target_plan.target,
                participants,
                plan.operation,
                journal_operations,
                "not-started",
            )
        _write_commitment_markers(prepared)
        _commit_prepared_transaction(prepared)
        for target_plan in plan.targets:
            journal_path = _journal_path(target_plan.home)
            journal_identity: IdentityEvidence | None = None
            try:
                journal_identity = _write_journal(
                    target_plan.home, prepared.journals[target_plan.target]
                )
            finally:
                if journal_identity is not None and not any(
                    item.path == journal_path for item in prepared.owned
                ):
                    _record_owned(
                        prepared.owned, journal_path, "journal", journal_identity
                    )
                    prepared.journal_evidence[target_plan.target] = journal_identity
    except BaseException as primary:
        _cleanup_preparation(prepared.owned)
        if not isinstance(primary, Exception):
            raise
        raise TransactionPreparationError("transaction preparation failed") from primary
    return prepared


def _update_operation(
    prepared: _Prepared, target: Target, index: int, status: str
) -> None:
    journal = prepared.journals[target]
    operations = tuple(
        replace(operation, status=status) if position == index else operation
        for position, operation in enumerate(journal.operations)
    )
    journal = replace(journal, operations=operations)
    prepared.journals[target] = journal
    target_plan = next(item for item in prepared.plan.targets if item.target is target)
    prepared.journal_evidence[target] = _write_journal(target_plan.home, journal)


def _apply_operation(
    target_plan: TargetPlan, operation: PlannedOperation
) -> IdentityEvidence | None:
    path = _canonical_path(target_plan, operation)
    before_identity = operation.expected_before_evidence
    if operation.expected_before_hash is not None and before_identity is None:
        raise TransactionError("transaction target lacks prepared identity evidence")
    if operation.expected_after_hash is None:
        result = filesystem.compare_and_swap(
            path, before_identity, None, None, "unlink"
        )
    else:
        write_mode = (
            0o600
            if operation.action in {"restore", "remove-block"}
            else operation.expected_after_mode or 0o600
        )
        result = filesystem.compare_and_swap(
            path,
            before_identity,
            operation.content or b"",
            operation.expected_after_mode or write_mode,
            "create" if operation.expected_before_hash is None else "replace",
        )
    _check_evidence(
        path,
        operation.expected_after_hash,
        operation.expected_after_mode,
        present=operation.expected_after_hash is not None,
        expected_identity=result,
    )
    return result


def _backup_bytes(home: Path, journal_operation: JournalOperation) -> bytes:
    if journal_operation.backup_path is None or journal_operation.backup_hash is None:
        raise IncompleteRollbackError("rollback backup evidence is missing")
    path = _state(home) / journal_operation.backup_path
    data = _read_regular(path)
    if (
        data is None
        or data[1] & ~0o600
        or _digest(data[0]) != journal_operation.backup_hash
    ):
        raise IncompleteRollbackError("rollback backup is missing or changed")
    return data[0]


def _reverse_operation(
    target_plan: TargetPlan, journal_operation: JournalOperation
) -> IdentityEvidence | None:
    operation = next(
        item
        for item in target_plan.operations
        if item.relative_path
        == _identifier_relative(
            descriptor_for(target_plan.target), journal_operation.identifier
        )
    )
    path = _canonical_path(target_plan, operation)
    current = _read_regular(path)
    current_hash = _digest(current[0]) if current else None
    current_mode = current[1] if current else None
    current_identity = capture_evidence(path, "rollback target")
    expected_before_identity = journal_operation.expected_before_evidence
    expected_after_identity = journal_operation.expected_after_evidence
    if (
        current_hash == operation.expected_before_hash
        and current_mode == operation.expected_before_mode
        and current_identity == expected_before_identity
    ):
        return current_identity
    if (
        current_hash != operation.expected_after_hash
        or current_mode != operation.expected_after_mode
        or current_identity != expected_after_identity
    ):
        raise IncompleteRollbackError(
            f"ambiguous rollback state for {operation.identifier}"
        )
    before_identity = journal_operation.expected_after_evidence
    if operation.expected_after_hash is not None and before_identity is None:
        raise IncompleteRollbackError("rollback target lacks after identity evidence")
    if operation.expected_before_hash is None:
        filesystem.compare_and_swap(path, before_identity, None, None, "unlink")
    else:
        before = _backup_bytes(target_plan.home, journal_operation)
        filesystem.compare_and_swap(
            path,
            before_identity,
            before,
            operation.expected_before_mode or 0o600,
            "replace",
        )
    result = capture_evidence(path, "rollback target")
    _check_evidence(
        path,
        operation.expected_before_hash,
        operation.expected_before_mode,
        present=operation.expected_before_hash is not None,
        expected_identity=result,
    )
    return result


def _sync_and_remove_journal(
    home: Path,
    journal: Journal,
    *,
    journal_evidence: IdentityEvidence | None,
    backup_evidence: Mapping[Path, IdentityEvidence | None] | None = None,
) -> None:
    path = _journal_path(home)
    if journal_evidence is None:
        raise TransactionError("journal cleanup lacks validated identity evidence")
    backup_evidence = backup_evidence or {}
    try:
        current = capture_evidence(path, "journal cleanup")
    except FileNotFoundError as exc:
        raise TransactionError("journal disappeared before cleanup") from exc
    if current != journal_evidence:
        raise TransactionError("journal identity changed before cleanup")
    payload = encode_journal(journal)
    filesystem.compare_and_swap(path, journal_evidence, None, None, "unlink")

    def restore() -> None:
        try:
            filesystem.compare_and_swap(path, None, payload, 0o600, "create")
            filesystem.sync_directory(_state(home))
        except BaseException as exc:
            raise TransactionError("journal restoration could not be proved") from exc

    try:
        filesystem.sync_directory(_state(home))
    except BaseException as exc:
        try:
            restore()
        except TransactionError:
            raise
        raise TransactionError("journal directory synchronization failed") from exc
    try:
        for operation in journal.operations:
            if operation.backup_path is None:
                continue
            backup = _state(home) / operation.backup_path
            if backup not in backup_evidence or backup_evidence[backup] is None:
                raise TransactionError(
                    "backup cleanup lacks validated identity evidence"
                )
            backup_identity = backup_evidence[backup]
            current_backup = capture_evidence(backup, "backup cleanup")
            if current_backup != backup_identity:
                raise TransactionError("backup identity changed before cleanup")
            filesystem.compare_and_swap(backup, backup_identity, None, None, "unlink")
        filesystem.sync_directory(_state(home) / "backups")
    except BaseException as exc:
        try:
            restore()
        except TransactionError:
            raise
        raise TransactionError("journal cleanup could not be proved") from exc


def _validated_journal_evidence(
    home: Path,
    journal: Journal,
    *,
    journal_identity: IdentityEvidence,
) -> tuple[IdentityEvidence, dict[Path, IdentityEvidence]]:
    """Capture backup identities while retaining the loaded journal identity."""

    backups: dict[Path, IdentityEvidence] = {}
    for operation in journal.operations:
        if operation.backup_path is None:
            continue
        backup_path = _state(home) / operation.backup_path
        identity = capture_evidence(backup_path, "validated backup")
        if identity is None:
            raise IncompleteRollbackError("validated rollback backup is missing")
        data = _read_regular(backup_path)
        if (
            data is None
            or data[1] & ~0o600
            or operation.backup_hash is None
            or _digest(data[0]) != operation.backup_hash
        ):
            raise IncompleteRollbackError("validated rollback backup is invalid")
        backups[backup_path] = identity
    return journal_identity, backups


def _rollback(prepared: _Prepared, primary: BaseException) -> None:
    rollback_error: BaseException | None = None
    for target_plan in prepared.plan.targets:
        journal = prepared.journals[target_plan.target]
        journal = replace(journal, rollback_status="in-progress")
        prepared.journals[target_plan.target] = journal
        try:
            prepared.journal_evidence[target_plan.target] = _write_journal(
                target_plan.home, journal
            )
        except BaseException as exc:
            rollback_error = rollback_error or exc
    for target_plan in reversed(prepared.plan.targets):
        journal = prepared.journals[target_plan.target]
        for index in reversed(range(len(journal.operations))):
            operation = journal.operations[index]
            if operation.status not in {"applying", "applied"}:
                continue
            try:
                restored_identity = _reverse_operation(target_plan, operation)
                journal = prepared.journals[target_plan.target]
                prepared.journals[target_plan.target] = replace(
                    journal,
                    operations=tuple(
                        replace(item, expected_before_evidence=restored_identity)
                        if position == index
                        else item
                        for position, item in enumerate(journal.operations)
                    ),
                )
                _update_operation(prepared, target_plan.target, index, "rolled-back")
            except BaseException as exc:
                rollback_error = rollback_error or exc
                try:
                    _update_operation(prepared, target_plan.target, index, "ambiguous")
                except BaseException as status_error:
                    rollback_error = rollback_error or status_error
    for target_plan in prepared.plan.targets:
        journal = prepared.journals[target_plan.target]
        incomplete = any(
            operation.status == "ambiguous" for operation in journal.operations
        )
        journal = replace(
            journal,
            operations=(
                tuple(
                    replace(operation, status="rolled-back")
                    for operation in journal.operations
                )
                if not incomplete
                else journal.operations
            ),
            rollback_status="incomplete" if incomplete else "complete",
        )
        prepared.journals[target_plan.target] = journal
        try:
            prepared.journal_evidence[target_plan.target] = _write_journal(
                target_plan.home, journal
            )
        except BaseException as exc:
            rollback_error = rollback_error or exc
    if rollback_error is None:
        try:
            for target_plan in prepared.plan.targets:
                _sync_and_remove_journal(
                    target_plan.home,
                    prepared.journals[target_plan.target],
                    journal_evidence=prepared.journal_evidence.get(target_plan.target),
                    backup_evidence=prepared.backup_evidence,
                )
        except BaseException as cleanup_error:
            if not isinstance(primary, Exception):
                primary.add_note("rollback completed but journal cleanup failed")
                raise primary from cleanup_error
            error = IncompleteRollbackError(
                "transaction failed and rolled back, but journal cleanup failed"
            )
            error.cleanup_only = True
            raise error from primary
        if not isinstance(primary, Exception):
            raise primary
        raise TransactionError("transaction failed and rolled back") from primary
    if not isinstance(primary, Exception):
        primary.add_note("rollback incomplete")
        raise primary from rollback_error
    raise IncompleteRollbackError(
        "transaction failed; rollback incomplete"
    ) from primary


def _apply_transaction_unlocked(
    plan: TransactionPlan,
    failure_injector: FailureInjector | None = None,
) -> None:
    _validate_plan(plan)
    if all(not target_plan.operations for target_plan in plan.targets):
        return
    readonly_evidence = _collect_readonly_evidence(plan)
    prepared = _prepare(plan, readonly_evidence)
    try:
        for target_plan in prepared.plan.targets:
            operations = prepared.operations[target_plan.target]
            for index, operation in enumerate(operations):
                _update_operation(prepared, target_plan.target, index, "applying")
                journal_operation = prepared.journals[target_plan.target].operations[
                    index
                ]
                _check_evidence(
                    _canonical_path(target_plan, operation),
                    operation.expected_before_hash,
                    operation.expected_before_mode,
                    present=operation.expected_before_hash is not None,
                    expected_identity=operation.expected_before_evidence,
                )
                if failure_injector is not None:
                    failure_injector.before_operation(journal_operation.operation_id)
                after_identity = _apply_operation(target_plan, operation)
                if after_identity is not None or operation.expected_after_hash is None:
                    journal = prepared.journals[target_plan.target]
                    updated = tuple(
                        replace(
                            item,
                            expected_after_evidence=after_identity,
                        )
                        if position == index
                        else item
                        for position, item in enumerate(journal.operations)
                    )
                    prepared.journals[target_plan.target] = replace(
                        journal, operations=updated
                    )
                _update_operation(prepared, target_plan.target, index, "applied")
        for target_plan in prepared.plan.targets:
            journal = replace(
                prepared.journals[target_plan.target], rollback_status="complete"
            )
            prepared.journals[target_plan.target] = journal
            prepared.journal_evidence[target_plan.target] = _write_journal(
                target_plan.home, journal
            )
    except BaseException as primary:
        _rollback(prepared, primary)
    for target_plan in prepared.plan.targets:
        try:
            _sync_and_remove_journal(
                target_plan.home,
                prepared.journals[target_plan.target],
                journal_evidence=prepared.journal_evidence.get(target_plan.target),
                backup_evidence=prepared.backup_evidence,
            )
        except BaseException as primary:
            raise TransactionError(
                "transaction committed but journal cleanup failed"
            ) from primary


def apply_transaction(
    plan: TransactionPlan,
    failure_injector: FailureInjector | None = None,
) -> None:
    """Apply one plan while holding every participant's persistent lock."""

    _validate_plan(plan)
    homes = {target_plan.target: target_plan.home for target_plan in plan.targets}
    if homes_locked(homes):
        _apply_transaction_unlocked(plan, failure_injector)
        return
    targets = tuple(target_plan.target for target_plan in plan.targets)
    with locked_target_homes(homes, targets):
        _apply_transaction_unlocked(plan, failure_injector)


def _verify_manifest_entries(home: Path, descriptor, manifest) -> None:
    backup_paths: set[str] = set()
    for entry in manifest.entries:
        if entry.backup_path is not None:
            if entry.backup_path in backup_paths:
                raise IncompleteRollbackError("manifest backup paths are aliased")
            backup_paths.add(entry.backup_path)
        relative = _identifier_relative(descriptor, entry.identifier)
        if relative != entry.relative_path:
            raise IncompleteRollbackError("manifest identifier/path mismatch")
        if entry.unresolved_reason is not None:
            continue
        path = home / entry.relative_path
        current = _read_regular(path)
        if current is None:
            raise IncompleteRollbackError("manifest entry target is missing")
        if (
            _digest(current[0]) != entry.installed_hash
            or current[1] != entry.installed_mode
        ):
            raise IncompleteRollbackError("manifest entry target drifted")
        if entry.managed_block_id is not None:
            from .planning import _block_from_file

            block = _block_from_file(current[0], entry.managed_block_id)
            if block is None or block.sha256 != entry.installed_block_hash:
                raise IncompleteRollbackError("manifest managed block drifted")


def _verify_complete_journal(
    home: Path,
    descriptor,
    journal: Journal,
    all_journals: tuple[Journal, ...] | None = None,
) -> None:
    if journal.operation not in {"install", "uninstall"}:
        raise IncompleteRollbackError("complete journal has the wrong operation")
    journals = all_journals or (journal,)
    try:
        _validate_transaction_commitment(journals)
    except ValueError as exc:
        raise IncompleteRollbackError("complete journal commitment is invalid") from exc
    if not journal.operations or any(
        operation.status != "applied" for operation in journal.operations
    ):
        raise IncompleteRollbackError("complete journal has unapplied operations")
    manifest_operations = [
        operation
        for operation in journal.operations
        if operation.identifier == "state/manifest"
    ]
    if (
        len(manifest_operations) != 1
        or journal.operations[-1].identifier != "state/manifest"
    ):
        raise IncompleteRollbackError(
            "complete journal lacks a last manifest operation"
        )
    for index, operation in enumerate(journal.operations):
        if operation.operation_id != _operation_id(
            journal.target, index, operation.identifier
        ):
            raise IncompleteRollbackError("complete journal operation order is invalid")
        path = _path_for_journal_operation(home, descriptor, operation)
        try:
            _check_evidence(
                path,
                operation.expected_after_hash,
                operation.expected_after_mode,
                present=operation.expected_after_hash is not None,
                expected_identity=operation.expected_after_evidence,
            )
        except (TransactionError, ValueError) as exc:
            raise IncompleteRollbackError(
                "complete journal target identity evidence is invalid"
            ) from exc
    manifest_operation = manifest_operations[0]
    from .state import load_manifest

    manifest = load_manifest(home, descriptor)
    manifest_bytes = _read_regular(_manifest_path(home))
    if manifest_operation.expected_after_hash is None:
        if manifest_bytes is not None or manifest is not None:
            raise IncompleteRollbackError("complete journal manifest should be absent")
    else:
        if (
            manifest_bytes is None
            or _digest(manifest_bytes[0]) != manifest_operation.expected_after_hash
            or manifest_bytes[1] != manifest_operation.expected_after_mode
            or manifest is None
        ):
            raise IncompleteRollbackError(
                "complete journal manifest evidence is invalid"
            )
        _verify_manifest_entries(home, descriptor, manifest)


def _verify_rollback_complete_journal(
    home: Path,
    descriptor,
    journal: Journal,
    all_journals: tuple[Journal, ...] | None = None,
) -> None:
    if not journal.operations or any(
        operation.status != "rolled-back" for operation in journal.operations
    ):
        raise IncompleteRollbackError("rollback-complete journal has open operations")
    try:
        _validate_transaction_commitment(all_journals or (journal,))
    except ValueError as exc:
        raise IncompleteRollbackError("rollback journal commitment is invalid") from exc
    for operation in journal.operations:
        path = _path_for_journal_operation(home, descriptor, operation)
        try:
            _check_evidence(
                path,
                operation.expected_before_hash,
                operation.expected_before_mode,
                present=operation.expected_before_hash is not None,
                expected_identity=operation.expected_before_evidence,
            )
        except (TransactionError, ValueError) as exc:
            raise IncompleteRollbackError(
                "rollback journal target identity evidence is invalid"
            ) from exc


def _recover_single(home: Path, descriptor) -> None:
    journal_path = _journal_path(home)
    loaded_identity = capture_evidence(journal_path, "recovery journal")
    journal = load_journal(home, descriptor)
    if journal is None:
        if loaded_identity is not None:
            raise IncompleteRollbackError("recovery journal disappeared")
        return
    if capture_evidence(journal_path, "recovery journal") != loaded_identity:
        raise IncompleteRollbackError("recovery journal changed during validation")
    if len(journal.participants) != 1:
        participants = ", ".join(item.value for item in journal.participants)
        raise ValueError(
            f"multi-participant recovery requires all homes: {participants}"
        )
    if journal.rollback_status == "incomplete" or any(
        operation.status == "ambiguous" for operation in journal.operations
    ):
        raise IncompleteRollbackError(
            "journal records an ambiguous or incomplete rollback; "
            "manual recovery is required"
        )
    if journal.rollback_status == "complete":
        if all(operation.status == "rolled-back" for operation in journal.operations):
            _verify_rollback_complete_journal(home, descriptor, journal)
        else:
            _verify_complete_journal(home, descriptor, journal)
        journal_identity, backup_evidence = _validated_journal_evidence(
            home, journal, journal_identity=loaded_identity
        )
        _sync_and_remove_journal(
            home,
            journal,
            journal_evidence=journal_identity,
            backup_evidence=backup_evidence,
        )
        return
    target_plan = TargetPlan(
        descriptor.target,
        home,
        tuple(
            _planned_from_journal(descriptor, operation)
            for operation in journal.operations
        ),
        None,
        (),
    )
    errors: list[str] = []
    for operation in reversed(journal.operations):
        if operation.status not in {"applying", "applied"}:
            if operation.status == "planned":
                path = _path_for_journal_operation(home, descriptor, operation)
                try:
                    _check_evidence(
                        path,
                        operation.expected_before_hash,
                        operation.expected_before_mode,
                        present=operation.expected_before_hash is not None,
                        expected_identity=operation.expected_before_evidence,
                    )
                except (TransactionError, ValueError):
                    errors.append("planned journal evidence is invalid")
            continue
        try:
            _reverse_operation(target_plan, operation)
        except IncompleteRollbackError:
            errors.append("rollback operation evidence is invalid")
    if errors:
        raise IncompleteRollbackError("; ".join(errors))
    journal_identity, backup_evidence = _validated_journal_evidence(
        home, journal, journal_identity=loaded_identity
    )
    _sync_and_remove_journal(
        home,
        journal,
        journal_evidence=journal_identity,
        backup_evidence=backup_evidence,
    )


def _recover_participants(homes: Mapping[Target, Path]) -> None:
    """Recover one logical transaction after exact participant resolution."""

    if not isinstance(homes, Mapping) or not homes:
        raise ValueError("participant homes must be a non-empty mapping")
    journals: dict[Target, Journal] = {}
    journal_evidence: dict[Target, IdentityEvidence] = {}
    backup_evidence_by_target: dict[Target, dict[Path, IdentityEvidence]] = {}
    descriptors = {target: descriptor_for(target) for target in homes}
    for target, home in homes.items():
        if not isinstance(target, Target) or not isinstance(home, Path):
            raise ValueError("participant mapping has invalid key or home")
        loaded_identity = capture_evidence(_journal_path(home), "participant journal")
        journal = load_journal(home, descriptors[target])
        if journal is None:
            raise ValueError(f"missing participant journal for {target.value}")
        validated_identity = capture_evidence(
            _journal_path(home), "participant journal"
        )
        if loaded_identity is None or validated_identity != loaded_identity:
            raise IncompleteRollbackError(
                "participant journal changed during validation"
            )
        journals[target] = journal
        journal_evidence[target] = loaded_identity
        _, backup_evidence_by_target[target] = _validated_journal_evidence(
            home, journal, journal_identity=loaded_identity
        )
    first = next(iter(journals.values()))
    participants = first.participants
    _canonical_participant_order(participants)
    if set(homes) != set(participants) or tuple(homes) != participants:
        raise ValueError("participant mapping does not exactly match journal set")
    for target in participants:
        journal = journals.get(target)
        if journal is None:
            raise ValueError("participant journal set is incomplete")
        if (
            journal.transaction_id != first.transaction_id
            or journal.operation != first.operation
            or journal.participants != participants
            or journal.target is not target
        ):
            raise IncompleteRollbackError("participant journals disagree")
    ordered_journals = tuple(journals[target] for target in participants)
    try:
        _validate_transaction_commitment(ordered_journals, homes)
    except ValueError as exc:
        raise IncompleteRollbackError(
            "participant journal commitment is invalid"
        ) from exc
    if all(journal.rollback_status == "complete" for journal in journals.values()):
        statuses = {
            operation.status
            for journal in journals.values()
            for operation in journal.operations
        }
        if statuses == {"rolled-back"}:
            for target in participants:
                _verify_rollback_complete_journal(
                    homes[target],
                    descriptors[target],
                    journals[target],
                    ordered_journals,
                )
        elif statuses == {"applied"}:
            for target in participants:
                _verify_complete_journal(
                    homes[target],
                    descriptors[target],
                    journals[target],
                    ordered_journals,
                )
        else:
            raise IncompleteRollbackError(
                "participant journals have mixed final states"
            )
        for target in participants:
            _sync_and_remove_journal(
                homes[target],
                journals[target],
                journal_evidence=journal_evidence[target],
                backup_evidence=backup_evidence_by_target[target],
            )
        return
    if any(journal.rollback_status == "complete" for journal in journals.values()):
        raise ValueError("participant journals have mixed completion status")
    target_plans = {
        target: TargetPlan(
            target,
            homes[target],
            tuple(
                _planned_from_journal(descriptors[target], operation)
                for operation in journals[target].operations
            ),
            None,
            (),
        )
        for target in participants
    }
    # Prove every current state before changing any journal. This is the
    # coordinator's zero-write boundary for missing or ambiguous participants.
    for target in participants:
        journal = journals[target]
        for operation in journal.operations:
            path = _path_for_journal_operation(
                homes[target], descriptors[target], operation
            )
            if operation.status in {"applying", "applied"}:
                current = _read_regular(path)
                current_hash = _digest(current[0]) if current else None
                current_mode = current[1] if current else None
                before = (
                    current_hash == operation.expected_before_hash
                    and current_mode == operation.expected_before_mode
                )
                after = (
                    current_hash == operation.expected_after_hash
                    and current_mode == operation.expected_after_mode
                )
                current_identity = capture_evidence(path, "participant recovery target")
                before = (
                    before and current_identity == operation.expected_before_evidence
                )
                after = after and current_identity == operation.expected_after_evidence
                if not before and not after:
                    raise IncompleteRollbackError(
                        f"ambiguous participant state for {operation.identifier}"
                    )
                if after and operation.expected_before_hash is not None:
                    _backup_bytes(homes[target], operation)
            elif operation.status == "planned":
                _check_evidence(
                    path,
                    operation.expected_before_hash,
                    operation.expected_before_mode,
                    present=operation.expected_before_hash is not None,
                    expected_identity=operation.expected_before_evidence,
                )
            else:
                raise IncompleteRollbackError(
                    "participant journal has ambiguous status"
                )
    try:
        for target in participants:
            journal = replace(journals[target], rollback_status="in-progress")
            journals[target] = journal
            journal_evidence[target] = _write_journal(homes[target], journal)
        for target in reversed(participants):
            journal = journals[target]
            for index in reversed(range(len(journal.operations))):
                operation = journal.operations[index]
                if operation.status not in {"applying", "applied"}:
                    continue
                restored_identity = _reverse_operation(target_plans[target], operation)
                journal = replace(
                    journal,
                    operations=tuple(
                        replace(item, status="rolled-back")
                        if position == index
                        else item
                        for position, item in enumerate(journal.operations)
                    ),
                )
                journal = replace(
                    journal,
                    operations=tuple(
                        replace(item, expected_before_evidence=restored_identity)
                        if position == index
                        else item
                        for position, item in enumerate(journal.operations)
                    ),
                )
                journals[target] = journal
                journal_evidence[target] = _write_journal(homes[target], journal)
        for target in participants:
            journal = replace(
                journals[target],
                operations=tuple(
                    replace(item, status="rolled-back")
                    for item in journals[target].operations
                ),
                rollback_status="complete",
            )
            journals[target] = journal
            journal_evidence[target] = _write_journal(homes[target], journal)
        for target in participants:
            _sync_and_remove_journal(
                homes[target],
                journals[target],
                journal_evidence=journal_evidence[target],
                backup_evidence=backup_evidence_by_target[target],
            )
    except BaseException as primary:
        if not isinstance(primary, Exception):
            primary.add_note("participant rollback incomplete")
            raise primary
        raise IncompleteRollbackError("participant rollback incomplete") from primary


def _path_for_journal_operation(
    home: Path, descriptor, operation: JournalOperation
) -> Path:
    target_plan = TargetPlan(descriptor.target, home, (), None, ())
    planned = _planned_from_journal(descriptor, operation)
    return _canonical_path(target_plan, planned)


def _planned_from_journal(descriptor, operation: JournalOperation) -> PlannedOperation:
    relative = _identifier_relative(descriptor, operation.identifier)
    if relative is None:
        raise ValueError(f"journal identifier is not managed: {operation.identifier}")
    return PlannedOperation(
        descriptor.target,
        operation.identifier,
        operation.action,
        relative,
        operation.expected_before_hash,
        operation.expected_after_hash,
        operation.expected_before_mode,
        operation.expected_after_mode,
        None,
        None,
        operation.backup_path is not None,
        operation.identifier
        if operation.action in {"write-block", "remove-block"}
        else None,
        operation.expected_before_evidence,
        operation.expected_after_evidence,
    )


def recover_incomplete_journal(home: Path, descriptor) -> None:
    if descriptor.target not in {Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE}:
        raise ValueError("unsupported target descriptor")
    assert_safe_home(home)
    journal = load_journal(home, descriptor)
    if journal is None:
        return
    if len(journal.participants) != 1:
        participants = ", ".join(item.value for item in journal.participants)
        raise ValueError(
            f"multi-participant recovery requires all homes: {participants}"
        )
    _recover_participants({descriptor.target: home})


# Private seams used by transaction tests and by the future multi-home
# recovery coordinator. They intentionally do not expand the public API.
encode_journal = encode_journal
