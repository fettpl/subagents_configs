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
from .blocks import inspect_managed_block
from .errors import TransactionError
from .locks import (
    IdentityEvidence,
    homes_locked,
    locked_target_homes,
)
from .locks import (
    capture_evidence as _capture_evidence,
)
from .models import (
    COMMITMENT_ANCHOR_COUNT,
    COMMITMENT_ANCHOR_SIZE,
    Journal,
    JournalOperation,
    Target,
)
from .paths import assert_contained, assert_safe_home, assert_safe_managed_path
from .planning import PlannedOperation, TargetPlan, TransactionPlan
from .state import encode_journal
from .state import load_journal as _load_journal
from .targets import descriptor_for, registry_target_order


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
    kind: Literal["directory", "backup", "journal", "anchor"]
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
    order = {target: index for index, target in enumerate(registry_target_order())}
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
                **(
                    {
                        "backup_identity_evidence": _identity_record(
                            operation.backup_identity_evidence
                        )
                    }
                    if operation.backup_identity_evidence is not None
                    else {}
                ),
            }
            for operation in journal.operations
        ],
        **(
            {
                "commitment_anchor_structures": [
                    _identity_structure_record(item)
                    for item in journal.cleanup_commitment_evidence
                ]
            }
            if journal.schema_version >= 3
            else {}
        ),
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


def _identity_record(evidence: IdentityEvidence | None) -> dict[str, object] | None:
    if evidence is None:
        return None
    return {
        "device": evidence.device,
        "inode": evidence.inode,
        "size": evidence.size,
        "nlink": evidence.nlink,
        "mode": evidence.mode,
        "sha256": evidence.sha256,
    }


def _identity_structure_record(evidence: IdentityEvidence) -> dict[str, int]:
    return {
        "device": evidence.device,
        "inode": evidence.inode,
        "size": evidence.size,
        "nlink": evidence.nlink,
        "mode": evidence.mode,
    }


def _same_identity_structure(left: IdentityEvidence, right: IdentityEvidence) -> bool:
    return _identity_structure_record(left) == _identity_structure_record(right)


def _cleanup_journal_record(journal: Journal) -> dict[str, object]:
    if journal.schema_version < 3 or journal.rollback_status != "cleanup":
        raise ValueError("cleanup participant digest requires a cleanup journal")
    if any(
        (operation.backup_path is None) != (operation.cleanup_backup_evidence is None)
        for operation in journal.operations
    ):
        raise ValueError("cleanup participant digest lacks full backup evidence")
    return {
        "schema_version": journal.schema_version,
        "transaction_id": journal.transaction_id,
        "target": journal.target.value,
        "participants": [target.value for target in journal.participants],
        "operation": journal.operation,
        "rollback_status": journal.rollback_status,
        "operations": [
            {
                **record,
                "status": operation.status,
                "expected_before_evidence": _identity_record(
                    operation.expected_before_evidence
                ),
                "expected_after_evidence": _identity_record(
                    operation.expected_after_evidence
                ),
                "cleanup_backup_evidence": _identity_record(
                    operation.cleanup_backup_evidence
                ),
            }
            for record, operation in zip(
                _journal_commitment_record(journal)["operations"],
                journal.operations,
                strict=True,
            )
        ],
        # The full anchor digest is derived from the canonical root payload,
        # which itself binds these participant records.  Only the structural
        # projection is included here to avoid a recursive hash definition.
        "commitment_anchor_structures": [
            _identity_structure_record(item)
            for item in journal.cleanup_commitment_evidence
        ],
    }


def _cleanup_participant_digests(journals: tuple[Journal, ...]) -> tuple[str, ...]:
    return tuple(
        _digest(
            json.dumps(
                _cleanup_journal_record(journal),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
        for journal in journals
    )


def _cleanup_group_digest(participant_digests: tuple[str, ...]) -> str:
    return _digest(
        json.dumps(
            list(participant_digests), sort_keys=True, separators=(",", ":")
        ).encode()
    )


def _commitment_path(home: Path, nonce: str) -> Path:
    return _state(home) / "backups" / f"commitment-{nonce}"


def _commitment_anchor_path(home: Path, nonce: str, slot: int) -> Path:
    if slot == 0:
        return _commitment_path(home, nonce)
    if slot not in {1, 2}:
        raise ValueError("transaction commitment anchor slot is invalid")
    suffix = "progress-a" if slot == 1 else "progress-b"
    return _state(home) / "backups" / f"commitment-{nonce}-{suffix}"


def _fixed_commitment_payload(record: dict[str, object]) -> bytes:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > COMMITMENT_ANCHOR_SIZE:
        raise ValueError("commitment root payload is too large")
    return encoded + b" " * (COMMITMENT_ANCHOR_SIZE - len(encoded))


def _base_commitment_payload(journal: Journal) -> bytes:
    nonce, transaction_digest = journal.transaction_id.rsplit("-", 1)
    return _fixed_commitment_payload(
        {
            "domain": "subagents-configs/transaction-root/v1",
            "nonce": nonce,
            "transaction_digest": transaction_digest,
            "participants": [target.value for target in journal.participants],
            "anchor_structures": [
                _identity_structure_record(item)
                for item in journal.cleanup_commitment_evidence
            ],
        }
    )


def _progress_journal_record(journal: Journal) -> dict[str, object]:
    """Canonical dynamic evidence protected by alternating progress roots."""

    return {
        "transaction_id": journal.transaction_id,
        "target": journal.target.value,
        "participants": [target.value for target in journal.participants],
        "operation": journal.operation,
        "operations": [
            {
                **record,
                "status": operation.status,
                "expected_before_evidence": _identity_record(
                    operation.expected_before_evidence
                ),
                "expected_after_evidence": _identity_record(
                    operation.expected_after_evidence
                ),
            }
            for record, operation in zip(
                _journal_commitment_record(journal)["operations"],
                journal.operations,
                strict=True,
            )
        ],
        "commitment_anchor_structures": [
            _identity_structure_record(item)
            for item in journal.cleanup_commitment_evidence
        ],
    }


def _progress_journal_digest(journal: Journal) -> str:
    return _digest(
        json.dumps(
            _progress_journal_record(journal),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )


def _progress_root_payload(journal: Journal, sequence: int) -> bytes:
    if type(sequence) is not int or sequence < 0:
        raise ValueError("progress root sequence is invalid")
    return _fixed_commitment_payload(
        {
            "domain": "subagents-configs/progress-root/v1",
            "transaction_id": journal.transaction_id,
            "target": journal.target.value,
            "participants": [target.value for target in journal.participants],
            "sequence": sequence,
            "journal_digest": _progress_journal_digest(journal),
            "anchor_structures": [
                _identity_structure_record(item)
                for item in journal.cleanup_commitment_evidence
            ],
        }
    )


def _progress_sequence(content: bytes, journal: Journal) -> int | None:
    """Return a sequence only for one exact canonical progress-root payload."""

    envelope = _progress_envelope(content, journal)
    if envelope is None:
        return None
    sequence, _journal_digest = envelope
    try:
        expected = _progress_root_payload(journal, sequence)
    except (TypeError, ValueError):
        return None
    return sequence if content == expected else None


def _progress_envelope(content: bytes, journal: Journal) -> tuple[int, str] | None:
    """Validate a fixed progress envelope without trusting its journal digest."""

    try:
        decoded = json.loads(content.rstrip(b" "))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if type(decoded) is not dict or set(decoded) != {
        "domain",
        "transaction_id",
        "target",
        "participants",
        "sequence",
        "journal_digest",
        "anchor_structures",
    }:
        return None
    sequence = decoded.get("sequence")
    journal_digest = decoded.get("journal_digest")
    if (
        type(sequence) is not int
        or sequence < 0
        or type(journal_digest) is not str
        or len(journal_digest) != 64
        or any(char not in "0123456789abcdef" for char in journal_digest)
        or decoded.get("domain") != "subagents-configs/progress-root/v1"
        or decoded.get("transaction_id") != journal.transaction_id
        or decoded.get("target") != journal.target.value
        or decoded.get("participants")
        != [target.value for target in journal.participants]
        or decoded.get("anchor_structures")
        != [
            _identity_structure_record(item)
            for item in journal.cleanup_commitment_evidence
        ]
    ):
        return None
    try:
        canonical = _fixed_commitment_payload(decoded)
    except ValueError:
        return None
    return (sequence, journal_digest) if content == canonical else None


def _matching_target_identity(
    home: Path,
    journal: Journal,
    operation: JournalOperation,
    *,
    before: bool,
) -> tuple[bool, IdentityEvidence | None]:
    """Capture one exact target state used to derive a possible next root."""

    relative = _identifier_relative(
        descriptor_for(journal.target), operation.identifier
    )
    if relative is None:
        return False, None
    path = home / relative
    assert_contained(home, path)
    assert_safe_managed_path(home, path, operation.identifier)
    expected_hash = (
        operation.expected_before_hash if before else operation.expected_after_hash
    )
    expected_mode = (
        operation.expected_before_mode if before else operation.expected_after_mode
    )
    try:
        evidence, _content = filesystem.read_bytes_with_evidence(
            path, "transaction progress target"
        )
    except FileNotFoundError:
        return expected_hash is None and expected_mode is None, None
    return (
        evidence.sha256 == expected_hash and evidence.mode == expected_mode,
        evidence,
    )


def _possible_next_progress_journals(
    home: Path, journal: Journal
) -> dict[str, Journal]:
    """Derive exact one-step journals that may durably trail an ahead root."""

    candidates: dict[str, Journal] = {}

    def add_candidate(candidate: Journal) -> None:
        candidates[_progress_journal_digest(candidate)] = candidate

    def add_operation(
        index: int,
        status: str,
        *,
        expected_before_evidence: IdentityEvidence | object | None = _EVIDENCE_UNSET,
        expected_after_evidence: IdentityEvidence | object | None = _EVIDENCE_UNSET,
    ) -> None:
        operations = tuple(
            replace(
                operation,
                status=status,
                **(
                    {"expected_before_evidence": expected_before_evidence}
                    if expected_before_evidence is not _EVIDENCE_UNSET
                    else {}
                ),
                **(
                    {"expected_after_evidence": expected_after_evidence}
                    if expected_after_evidence is not _EVIDENCE_UNSET
                    else {}
                ),
            )
            if position == index
            else operation
            for position, operation in enumerate(journal.operations)
        )
        add_candidate(replace(journal, operations=operations))

    for index, operation in enumerate(journal.operations):
        if operation.status == "planned":
            add_operation(index, "applying")
        if operation.status not in {"applying", "applied"}:
            continue
        matches_after, after_identity = _matching_target_identity(
            home, journal, operation, before=False
        )
        if operation.status == "applying" and matches_after:
            add_operation(index, "applied", expected_after_evidence=after_identity)
        matches_before, before_identity = _matching_target_identity(
            home, journal, operation, before=True
        )
        if matches_before:
            add_operation(
                index, "rolled-back", expected_before_evidence=before_identity
            )
        add_operation(index, "ambiguous")
    if all(
        operation.status in {"planned", "rolled-back"}
        for operation in journal.operations
    ) and any(operation.status == "planned" for operation in journal.operations):
        add_candidate(
            replace(
                journal,
                operations=tuple(
                    replace(operation, status="rolled-back")
                    for operation in journal.operations
                ),
            )
        )
    return candidates


def _cleanup_root_payload(journal: Journal) -> bytes:
    nonce, transaction_digest = journal.transaction_id.rsplit("-", 1)
    participant_digests = journal.cleanup_participant_digests
    return _fixed_commitment_payload(
        {
            "domain": "subagents-configs/cleanup-root/v1",
            "nonce": nonce,
            "transaction_digest": transaction_digest,
            "participant_digests": list(participant_digests),
            "group_digest": _cleanup_group_digest(participant_digests),
            "participants": [target.value for target in journal.participants],
            "anchor_structures": [
                _identity_structure_record(item)
                for item in journal.cleanup_commitment_evidence
            ],
        }
    )


def _participant_anchor_evidence(
    journal: Journal, position: int
) -> tuple[IdentityEvidence, ...]:
    start = position * COMMITMENT_ANCHOR_COUNT
    stop = start + COMMITMENT_ANCHOR_COUNT
    evidence = journal.cleanup_commitment_evidence[start:stop]
    if len(evidence) != COMMITMENT_ANCHOR_COUNT:
        raise ValueError("transaction commitment anchor evidence is incomplete")
    return evidence


def _read_commitment_anchors(
    home: Path,
    journal: Journal,
    position: int,
    *,
    require_cleanup_root: bool,
) -> tuple[tuple[IdentityEvidence, ...], Journal | None]:
    nonce, _transaction_digest = journal.transaction_id.rsplit("-", 1)
    expected_evidence = _participant_anchor_evidence(journal, position)
    base_payload = _base_commitment_payload(journal)
    cleanup_payload = _cleanup_root_payload(journal)
    observed: list[IdentityEvidence] = []
    contents: list[bytes] = []
    for slot, expected in enumerate(expected_evidence):
        marker = _commitment_anchor_path(home, nonce, slot)
        try:
            evidence, content = filesystem.read_bytes_with_evidence(
                marker, "transaction commitment anchor"
            )
        except FileNotFoundError as exc:
            raise ValueError("transaction commitment anchor is missing") from exc
        if (
            not _same_identity_structure(evidence, expected)
            or evidence.nlink != 1
            or evidence.mode != 0o600
            or evidence.size != COMMITMENT_ANCHOR_SIZE
        ):
            raise ValueError("transaction commitment anchor is invalid")
        if slot == 0 and (evidence != expected or content != base_payload):
            raise ValueError("retained transaction root is invalid")
        observed.append(evidence)
        contents.append(content)
    progress_sequences = {
        slot: sequence
        for slot in (1, 2)
        if observed[slot] == expected_evidence[slot]
        and (sequence := _progress_sequence(contents[slot], journal)) is not None
    }
    progress_slots = tuple(progress_sequences)
    if not progress_slots:
        raise ValueError("transaction progress root is invalid")
    current_sequence = max(progress_sequences.values())
    ahead_journal: Journal | None = None
    for slot in (1, 2):
        if observed[slot] == expected_evidence[slot]:
            continue
        ahead = _progress_envelope(contents[slot], journal)
        if ahead is not None:
            ahead_sequence, ahead_digest = ahead
            candidate = _possible_next_progress_journals(home, journal).get(
                ahead_digest
            )
            if (
                ahead_sequence != current_sequence + 1
                or candidate is None
                or ahead_journal is not None
            ):
                raise ValueError("transaction progress anchor evidence changed")
            anchor_evidence = list(candidate.cleanup_commitment_evidence)
            start = position * COMMITMENT_ANCHOR_COUNT
            anchor_evidence[start : start + COMMITMENT_ANCHOR_COUNT] = observed
            ahead_journal = replace(
                candidate, cleanup_commitment_evidence=tuple(anchor_evidence)
            )
    if require_cleanup_root:
        cleanup_slots = tuple(
            slot for slot in (1, 2) if contents[slot] == cleanup_payload
        )
        if len(cleanup_slots) != 1 or len(progress_slots) != 1:
            raise ValueError("cleanup commitment root is invalid")
        if any(observed[slot] != expected_evidence[slot] for slot in (1, 2)):
            raise ValueError("cleanup anchor evidence changed")
    return tuple(observed), ahead_journal


def _read_missing_cleanup_participant_anchors(
    home: Path, journal: Journal, position: int
) -> tuple[IdentityEvidence, ...]:
    """Validate a missing participant's roots from surviving cleanup evidence."""

    nonce = journal.transaction_id.rsplit("-", 1)[0]
    expected = _participant_anchor_evidence(journal, position)
    base_payload = _base_commitment_payload(journal)
    cleanup_payload = _cleanup_root_payload(journal)
    observed: list[IdentityEvidence] = []
    contents: list[bytes] = []
    for slot, item in enumerate(expected):
        marker = _commitment_anchor_path(home, nonce, slot)
        evidence, content = filesystem.read_bytes_with_evidence(
            marker, "missing participant commitment anchor"
        )
        if (
            evidence != item
            or evidence.nlink != 1
            or evidence.mode != 0o600
            or evidence.size != COMMITMENT_ANCHOR_SIZE
        ):
            raise ValueError("missing participant commitment anchor changed")
        observed.append(evidence)
        contents.append(content)
    if contents[0] != base_payload:
        raise ValueError("missing participant base root is invalid")
    if sum(content == cleanup_payload for content in contents[1:]) != 1:
        raise ValueError("missing participant cleanup root is invalid")
    return tuple(observed)


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
    journals: tuple[Journal, ...],
    homes: Mapping[Target, Path] | None = None,
    *,
    allow_unsealed_complete: bool = False,
) -> tuple[Journal, ...]:
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
    if not allow_unsealed_complete and any(
        journal.rollback_status == "complete" for journal in journals
    ):
        raise ValueError("unsealed complete journal is not recoverable")
    expected_anchor_count = len(participants) * COMMITMENT_ANCHOR_COUNT
    if any(
        len(journal.cleanup_commitment_evidence) != expected_anchor_count
        or any(
            item.nlink != 1 or item.mode != 0o600 or item.size != COMMITMENT_ANCHOR_SIZE
            for item in journal.cleanup_commitment_evidence
        )
        for journal in journals
    ):
        raise ValueError("transaction commitment anchor evidence is incomplete")
    first_structures = tuple(
        _identity_structure_record(item)
        for item in journals[0].cleanup_commitment_evidence
    )
    if any(
        tuple(
            _identity_structure_record(item)
            for item in journal.cleanup_commitment_evidence
        )
        != first_structures
        for journal in journals
    ):
        raise ValueError("transaction commitment anchor structures disagree")
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
    materialized = list(journals)
    if homes is not None:
        if set(homes) != set(participants):
            raise ValueError("transaction commitment homes are incomplete")
        for position, target in enumerate(participants):
            _observed, ahead_journal = _read_commitment_anchors(
                homes[target],
                journals[position],
                position,
                require_cleanup_root=journals[position].rollback_status == "cleanup",
            )
            if ahead_journal is not None:
                materialized[position] = ahead_journal
    return tuple(materialized)


def validate_transaction_commitment(
    journals: tuple[Journal, ...], homes: Mapping[Target, Path] | None = None
) -> tuple[Journal, ...]:
    """Validate a participant commitment without exposing internal helpers."""
    return _validate_transaction_commitment(journals, homes)


def _validate_cleanup_survivors(
    journals: tuple[Journal, ...], homes: Mapping[Target, Path]
) -> tuple[Target, ...]:
    """Validate the only state in which participant journals may be absent."""

    if not journals:
        raise ValueError("cleanup survivor set is empty")
    first = journals[0]
    participants = first.participants
    _canonical_participant_order(participants)
    if set(homes) != set(participants) or tuple(homes) != participants:
        raise ValueError("cleanup survivor homes do not match participants")
    survivor_targets = tuple(journal.target for journal in journals)
    if len(set(survivor_targets)) != len(survivor_targets) or any(
        target not in participants for target in survivor_targets
    ):
        raise ValueError("cleanup survivor targets are invalid")
    if tuple(target for target in participants if target in survivor_targets) != (
        survivor_targets
    ):
        raise ValueError("cleanup survivors are not in participant order")
    final_statuses = {
        operation.status for journal in journals for operation in journal.operations
    }
    if final_statuses not in ({"applied"}, {"rolled-back"}):
        raise ValueError("cleanup survivors do not share one final state")
    if any(
        journal.schema_version < 3
        or journal.rollback_status != "cleanup"
        or journal.transaction_id != first.transaction_id
        or journal.operation != first.operation
        or journal.participants != participants
        for journal in journals
    ):
        raise ValueError("cleanup survivors disagree")
    group_digests = first.cleanup_participant_digests
    if len(group_digests) != len(participants) or any(
        journal.cleanup_participant_digests != group_digests for journal in journals
    ):
        raise ValueError("cleanup survivor participant evidence disagrees")
    commitment_evidence = first.cleanup_commitment_evidence
    if len(commitment_evidence) != len(participants) * COMMITMENT_ANCHOR_COUNT or any(
        journal.cleanup_commitment_evidence != commitment_evidence
        for journal in journals
    ):
        raise ValueError("cleanup survivor marker evidence disagrees")
    for journal in journals:
        position = participants.index(journal.target)
        if _cleanup_participant_digests((journal,))[0] != group_digests[position]:
            raise ValueError("cleanup survivor content commitment changed")
    for journal in journals:
        _validate_journal_operation_order(journal)
    journals_by_target = {journal.target: journal for journal in journals}
    for position, target in enumerate(participants):
        local = journals_by_target.get(target)
        if local is None:
            _read_missing_cleanup_participant_anchors(homes[target], first, position)
        else:
            _read_commitment_anchors(
                homes[target], local, position, require_cleanup_root=True
            )
    return tuple(target for target in participants if target not in survivor_targets)


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
            operation is not None
            and entry.managed_block_id is not None
            and operation.content is not None
        ):
            block = inspect_managed_block(operation.content, entry.managed_block_id)
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
                block = inspect_managed_block(current[0], entry.managed_block_id)
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
        target: index for index, target in enumerate(registry_target_order())
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
    backup_identity = (
        prepared.backup_evidence.get(_state(target_plan.home) / backup[0])
        if backup is not None
        else None
    )
    if backup is not None and backup_identity is None:
        raise TransactionPreparationError("transaction backup identity is missing")
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
        backup_identity_evidence=backup_identity,
    )


def _write_journal(
    home: Path,
    journal: Journal,
    *,
    expected_before: IdentityEvidence | None = None,
) -> IdentityEvidence:
    """Create or CAS-update a journal while preserving concurrent evidence."""

    path = _journal_path(home)
    with filesystem.expected_atomic_identity(expected_before):
        identity = filesystem.atomic_write(path, encode_journal(journal), 0o600)
    if not isinstance(identity, IdentityEvidence):
        identity = capture_evidence(path, "written journal")
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
        3,
        transaction_id,
        target_plan.target,
        tuple(item.target for item in plan.targets),
        plan.operation,
        operations,
        "not-started",
    )
    filesystem.ensure_private_directory(_state(target_plan.home) / "backups")
    anchors = tuple(
        filesystem.exclusive_write(
            _commitment_anchor_path(target_plan.home, nonce, slot),
            b"\x00" * COMMITMENT_ANCHOR_SIZE,
            0o600,
        )
        for slot in range(COMMITMENT_ANCHOR_COUNT)
    )
    journal = replace(journal, cleanup_commitment_evidence=anchors)
    journal = replace(
        journal, transaction_id=_committed_transaction_id(nonce, (journal,))
    )
    base_payload = _base_commitment_payload(journal)
    sealed = tuple(
        filesystem.rewrite_regular_in_place(
            _commitment_anchor_path(target_plan.home, nonce, slot),
            anchors[slot],
            base_payload if slot == 0 else _progress_root_payload(journal, 0),
            "transaction commitment anchor",
        )
        for slot in range(COMMITMENT_ANCHOR_COUNT)
    )
    return replace(journal, cleanup_commitment_evidence=sealed)


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


def _create_commitment_anchors(prepared: _Prepared) -> None:
    evidence: list[IdentityEvidence] = []
    for target_plan in prepared.plan.targets:
        for slot in range(COMMITMENT_ANCHOR_COUNT):
            marker = _commitment_anchor_path(target_plan.home, prepared.nonce, slot)
            identity = filesystem.exclusive_write(
                marker, b"\x00" * COMMITMENT_ANCHOR_SIZE, 0o600
            )
            _record_owned(prepared.owned, marker, "anchor", identity)
            evidence.append(identity)
    anchors = tuple(evidence)
    for target_plan in prepared.plan.targets:
        journal = prepared.journals[target_plan.target]
        prepared.journals[target_plan.target] = replace(
            journal, cleanup_commitment_evidence=anchors
        )


def _seal_transaction_commitment(prepared: _Prepared) -> None:
    first = prepared.journals[prepared.plan.targets[0].target]
    base_payload = _base_commitment_payload(first)
    sealed: list[IdentityEvidence] = []
    position = 0
    for target_plan in prepared.plan.targets:
        for slot in range(COMMITMENT_ANCHOR_COUNT):
            expected = first.cleanup_commitment_evidence[position]
            marker = _commitment_anchor_path(target_plan.home, prepared.nonce, slot)
            journal = prepared.journals[target_plan.target]
            sealed_identity = filesystem.rewrite_regular_in_place(
                marker,
                expected,
                base_payload if slot == 0 else _progress_root_payload(journal, 0),
                "transaction commitment anchor",
            )
            sealed.append(sealed_identity)
            _record_owned(prepared.owned, marker, "anchor", sealed_identity)
            position += 1
    sealed_evidence = tuple(sealed)
    for target_plan in prepared.plan.targets:
        journal = prepared.journals[target_plan.target]
        prepared.journals[target_plan.target] = replace(
            journal, cleanup_commitment_evidence=sealed_evidence
        )


def _capture_artifact_identity(
    path: Path, kind: Literal["directory", "backup", "journal", "anchor"]
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
    kind: Literal["directory", "backup", "journal", "anchor"],
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
            if artifact.kind == "anchor":
                if (
                    not isinstance(current, IdentityEvidence)
                    or not isinstance(artifact.identity, IdentityEvidence)
                    or not _same_identity_structure(current, artifact.identity)
                ):
                    continue
            elif current != artifact.identity:
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
                3,
                prepared.transaction_id,
                target_plan.target,
                participants,
                plan.operation,
                journal_operations,
                "not-started",
            )
        _create_commitment_anchors(prepared)
        _commit_prepared_transaction(prepared)
        _seal_transaction_commitment(prepared)
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


def _write_progress_journal(
    home: Path,
    current_journal: Journal,
    next_journal: Journal,
    *,
    expected_before: IdentityEvidence,
) -> tuple[Journal, IdentityEvidence]:
    """Durably bind dynamic operation evidence before replacing its journal."""

    if (
        current_journal.target is not next_journal.target
        or current_journal.transaction_id != next_journal.transaction_id
        or current_journal.participants != next_journal.participants
        or current_journal.operation != next_journal.operation
        or len(current_journal.operations) != len(next_journal.operations)
    ):
        raise TransactionError("progress journal transition is invalid")
    position = current_journal.participants.index(current_journal.target)
    try:
        _read_commitment_anchors(
            home, current_journal, position, require_cleanup_root=False
        )
    except ValueError as exc:
        raise TransactionError("transaction progress evidence is invalid") from exc
    nonce = current_journal.transaction_id.rsplit("-", 1)[0]
    expected_anchors = _participant_anchor_evidence(current_journal, position)
    snapshots: dict[int, tuple[IdentityEvidence, bytes, int | None]] = {}
    for slot in (1, 2):
        marker = _commitment_anchor_path(home, nonce, slot)
        evidence, content = filesystem.read_bytes_with_evidence(
            marker, "transaction progress anchor"
        )
        if (
            not _same_identity_structure(evidence, expected_anchors[slot])
            or evidence.nlink != 1
            or evidence.mode != 0o600
            or evidence.size != COMMITMENT_ANCHOR_SIZE
        ):
            raise TransactionError("transaction progress anchor changed")
        snapshots[slot] = (
            evidence,
            content,
            _progress_sequence(content, current_journal),
        )
    sequences = {
        slot: item[2]
        for slot, item in snapshots.items()
        if item[2] is not None and item[0] == expected_anchors[slot]
    }
    if not sequences:
        raise TransactionError("transaction progress root is missing")
    current_sequence = max(sequence for sequence in sequences.values())
    active_slots = {
        slot for slot, sequence in sequences.items() if sequence == current_sequence
    }
    slot_to_write = (
        1
        if active_slots == {1, 2}
        else next(slot for slot in (1, 2) if slot not in active_slots)
    )
    marker = _commitment_anchor_path(home, nonce, slot_to_write)
    before, _content, _sequence = snapshots[slot_to_write]
    payload = _progress_root_payload(next_journal, current_sequence + 1)
    try:
        written_evidence = filesystem.rewrite_regular_in_place(
            marker,
            before,
            payload,
            "transaction progress anchor",
        )
    except Exception as exc:
        try:
            written_evidence, content = filesystem.read_bytes_with_evidence(
                marker, "transaction progress anchor"
            )
        except Exception as validation_error:
            raise TransactionError(
                "progress root write could not be proved"
            ) from validation_error
        if (
            not _same_identity_structure(
                written_evidence, expected_anchors[slot_to_write]
            )
            or content != payload
        ):
            raise TransactionError("progress root write could not be proved") from exc
    filesystem.sync_directory(_state(home) / "backups")
    anchor_evidence = list(next_journal.cleanup_commitment_evidence)
    start = position * COMMITMENT_ANCHOR_COUNT
    for slot, (evidence, _content, _sequence) in snapshots.items():
        anchor_evidence[start + slot] = (
            written_evidence if slot == slot_to_write else evidence
        )
    bound_journal = replace(
        next_journal, cleanup_commitment_evidence=tuple(anchor_evidence)
    )
    journal_identity = _write_journal(
        home, bound_journal, expected_before=expected_before
    )
    return bound_journal, journal_identity


_EVIDENCE_UNSET = object()


def _update_operation(
    prepared: _Prepared,
    target: Target,
    index: int,
    status: str,
    *,
    expected_before_evidence: IdentityEvidence | object | None = _EVIDENCE_UNSET,
    expected_after_evidence: IdentityEvidence | object | None = _EVIDENCE_UNSET,
) -> None:
    current_journal = prepared.journals[target]
    operations = tuple(
        replace(
            operation,
            status=status,
            **(
                {"expected_before_evidence": expected_before_evidence}
                if expected_before_evidence is not _EVIDENCE_UNSET
                else {}
            ),
            **(
                {"expected_after_evidence": expected_after_evidence}
                if expected_after_evidence is not _EVIDENCE_UNSET
                else {}
            ),
        )
        if position == index
        else operation
        for position, operation in enumerate(current_journal.operations)
    )
    journal = replace(current_journal, operations=operations)
    target_plan = next(item for item in prepared.plan.targets if item.target is target)
    current = prepared.journal_evidence.get(target)
    if current is None:
        raise TransactionError("journal update lacks current identity evidence")
    journal, next_evidence = _write_progress_journal(
        target_plan.home,
        current_journal,
        journal,
        expected_before=current,
    )
    prepared.journals[target] = journal
    prepared.journal_evidence[target] = next_evidence


def _bind_all_operation_statuses(
    prepared: _Prepared, target_plan: TargetPlan, status: str
) -> None:
    """Persist one progress-bound bulk status transition for cleanup staging."""

    target = target_plan.target
    current_journal = prepared.journals[target]
    journal = replace(
        current_journal,
        operations=tuple(
            replace(operation, status=status)
            for operation in current_journal.operations
        ),
    )
    if journal.operations == current_journal.operations:
        return
    current = prepared.journal_evidence.get(target)
    if current is None:
        raise TransactionError("journal update lacks current identity evidence")
    journal, next_evidence = _write_progress_journal(
        target_plan.home,
        current_journal,
        journal,
        expected_before=current,
    )
    prepared.journals[target] = journal
    prepared.journal_evidence[target] = next_evidence


def _apply_operation(
    target_plan: TargetPlan, operation: PlannedOperation
) -> IdentityEvidence | None:
    path = _canonical_path(target_plan, operation)
    before_identity = operation.expected_before_evidence
    if operation.expected_before_hash is not None and before_identity is None:
        raise TransactionError("transaction target lacks prepared identity evidence")
    # Planning evidence is never trusted across the mutation boundary.  Take
    # a fresh descriptor-relative capture immediately before CAS, including
    # create operations where the expected state is absence.
    current_identity = capture_evidence(path, "transaction mutation")
    if current_identity != before_identity:
        raise TransactionError(f"transaction target identity changed: {path}")
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
            "create" if before_identity is None else "replace",
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


def _prepare_journal_cleanup(
    home: Path,
    journal: Journal,
    *,
    journal_evidence: IdentityEvidence | None,
    backup_evidence: Mapping[Path, IdentityEvidence | None] | None = None,
) -> tuple[Journal, IdentityEvidence]:
    path = _journal_path(home)
    if journal_evidence is None:
        raise TransactionError("journal cleanup lacks validated identity evidence")
    backup_evidence = backup_evidence or {}
    current = capture_evidence(path, "journal cleanup")
    if current != journal_evidence:
        raise TransactionError("journal identity changed before cleanup")

    if journal.rollback_status not in {"complete", "cleanup"} or {
        operation.status for operation in journal.operations
    } not in ({"applied"}, {"rolled-back"}):
        raise TransactionError("journal is not in a cleanup-safe final state")
    if journal.schema_version < 3 and any(
        operation.backup_path is not None for operation in journal.operations
    ):
        raise TransactionError(
            "legacy journal backup identity cannot be proved for cleanup"
        )

    cleanup_evidence: dict[Path, IdentityEvidence] = {}
    for operation in journal.operations:
        if operation.backup_path is None:
            continue
        backup = _state(home) / operation.backup_path
        current_backup = capture_evidence(backup, "backup cleanup")
        if journal.rollback_status == "cleanup" and current_backup is None:
            continue
        if (
            current_backup is None
            or (
                journal.rollback_status == "cleanup"
                and current_backup != operation.cleanup_backup_evidence
            )
            or (
                journal.rollback_status == "complete"
                and (
                    backup not in backup_evidence
                    or backup_evidence[backup] is None
                    or current_backup != backup_evidence[backup]
                    or current_backup != operation.backup_identity_evidence
                )
            )
        ):
            raise TransactionError("backup cleanup lacks validated identity evidence")
        backup_identity = current_backup
        snapshot_identity, _content = filesystem.read_bytes_with_evidence(
            backup, "backup cleanup snapshot"
        )
        if (
            snapshot_identity != backup_identity
            or operation.backup_hash is None
            or snapshot_identity.sha256 != operation.backup_hash
            or snapshot_identity.nlink != 1
            or snapshot_identity.mode & ~0o600
        ):
            raise TransactionError("backup cleanup snapshot is invalid")
        cleanup_evidence[backup] = snapshot_identity

    cleanup_operations = tuple(
        replace(
            operation,
            cleanup_backup_evidence=(
                operation.cleanup_backup_evidence
                if journal.rollback_status == "cleanup"
                and operation.backup_path is not None
                else cleanup_evidence[_state(home) / operation.backup_path]
                if operation.backup_path is not None
                else None
            ),
        )
        for operation in journal.operations
    )

    candidate = replace(
        journal,
        schema_version=3,
        operations=cleanup_operations,
        rollback_status="cleanup",
        cleanup_participant_digests=(),
    )
    return candidate, journal_evidence


def _transition_commitment_anchor_slot(
    homes: Mapping[Target, Path],
    journals: tuple[Journal, ...],
) -> tuple[IdentityEvidence, ...]:
    """Write one cleanup root while retaining base and latest progress roots."""

    journal = journals[0]
    nonce, _digest_value = journal.transaction_id.rsplit("-", 1)
    base_payload = _base_commitment_payload(journal)
    cleanup_payload = _cleanup_root_payload(journal)
    observed_all: list[IdentityEvidence] = []
    for position, target in enumerate(journal.participants):
        local_journal = journals[position]
        expected_anchors = _participant_anchor_evidence(journal, position)
        observed_anchors: list[tuple[IdentityEvidence, bytes]] = []
        for slot, expected in enumerate(expected_anchors):
            marker = _commitment_anchor_path(homes[target], nonce, slot)
            evidence, content = filesystem.read_bytes_with_evidence(
                marker, "transaction commitment anchor"
            )
            if (
                not _same_identity_structure(evidence, expected)
                or evidence.nlink != 1
                or evidence.mode != 0o600
                or evidence.size != COMMITMENT_ANCHOR_SIZE
            ):
                raise TransactionError("transaction commitment anchor changed")
            observed_anchors.append((evidence, content))
        base_evidence, base_content = observed_anchors[0]
        if base_content != base_payload or base_evidence != expected_anchors[0]:
            raise TransactionError("retained transaction root is invalid")
        sequences = {
            slot: sequence
            for slot in (1, 2)
            if (
                sequence := _progress_sequence(observed_anchors[slot][1], local_journal)
            )
            is not None
        }
        if not sequences:
            raise TransactionError("transaction progress root is missing")
        current_sequence = max(sequences.values())
        active_slots = {
            slot for slot, sequence in sequences.items() if sequence == current_sequence
        }
        slot_to_write = (
            1
            if active_slots == {1, 2}
            else next(slot for slot in (1, 2) if slot not in active_slots)
        )
        marker = _commitment_anchor_path(homes[target], nonce, slot_to_write)
        selected_evidence, selected_content = observed_anchors[slot_to_write]
        if selected_content != cleanup_payload:
            try:
                selected_evidence = filesystem.rewrite_regular_in_place(
                    marker,
                    selected_evidence,
                    cleanup_payload,
                    "transaction commitment anchor",
                )
            except Exception as exc:
                try:
                    selected_evidence, content = filesystem.read_bytes_with_evidence(
                        marker, "transaction commitment anchor"
                    )
                except Exception as validation_error:
                    raise TransactionError(
                        "commitment root write could not be proved"
                    ) from validation_error
                if (
                    not _same_identity_structure(
                        selected_evidence, expected_anchors[slot_to_write]
                    )
                    or content != cleanup_payload
                ):
                    raise TransactionError(
                        "commitment root write could not be proved"
                    ) from exc
            filesystem.sync_directory(_state(homes[target]) / "backups")
            observed_anchors[slot_to_write] = (selected_evidence, cleanup_payload)
        observed_all.extend(evidence for evidence, _content in observed_anchors)
    return tuple(observed_all)


def _stage_cleanup_group(
    homes: Mapping[Target, Path],
    journals: tuple[Journal, ...],
    *,
    journal_evidence: Mapping[Target, IdentityEvidence],
    backup_evidence: Mapping[Target, Mapping[Path, IdentityEvidence | None]],
) -> tuple[dict[Target, Journal], dict[Target, IdentityEvidence]]:
    """Persist all cleanup journals and group markers before any unlink."""

    _validate_transaction_commitment(journals, homes, allow_unsealed_complete=True)
    participants = journals[0].participants
    if tuple(journal.target for journal in journals) != participants:
        raise TransactionError("cleanup journals are not in participant order")
    candidates: dict[Target, Journal] = {}
    identities: dict[Target, IdentityEvidence] = {}
    for journal in journals:
        candidate, identity = _prepare_journal_cleanup(
            homes[journal.target],
            journal,
            journal_evidence=journal_evidence.get(journal.target),
            backup_evidence=backup_evidence.get(journal.target),
        )
        candidates[journal.target] = candidate
        identities[journal.target] = identity
    ordered_candidates = tuple(candidates[target] for target in participants)
    group_digests = _cleanup_participant_digests(ordered_candidates)
    candidates = {
        target: replace(candidate, cleanup_participant_digests=group_digests)
        for target, candidate in candidates.items()
    }
    existing_cleanup = tuple(
        journal for journal in journals if journal.rollback_status == "cleanup"
    )
    if existing_cleanup:
        final_evidence = existing_cleanup[0].cleanup_commitment_evidence
        if any(
            journal.cleanup_participant_digests != group_digests
            or journal.cleanup_commitment_evidence != final_evidence
            for journal in existing_cleanup
        ):
            raise TransactionError("cleanup group evidence is inconsistent")
        # A cleanup journal is persisted only after every participant root is
        # durable.  Therefore a retry may adopt its full evidence only after
        # all roots match it exactly; it must never self-rehash changed state.
        try:
            for position, target in enumerate(participants):
                representative = replace(
                    candidates[target],
                    cleanup_commitment_evidence=final_evidence,
                )
                _read_commitment_anchors(
                    homes[target],
                    representative,
                    position,
                    require_cleanup_root=True,
                )
        except ValueError as exc:
            raise TransactionError("cleanup commitment evidence is invalid") from exc
    else:
        final_evidence = _transition_commitment_anchor_slot(
            homes, tuple(candidates[target] for target in participants)
        )
    candidates = {
        target: replace(candidate, cleanup_commitment_evidence=final_evidence)
        for target, candidate in candidates.items()
    }
    # Every cleanup root is durable before the first cleanup journal. Once a
    # journal exists, exact root/evidence validation above makes retries
    # fail-closed instead of treating a rewrite as an interrupted transition.
    for target in participants:
        identities[target] = _write_journal(
            homes[target], candidates[target], expected_before=identities[target]
        )
    return candidates, identities


def _stage_journal_cleanup(
    home: Path,
    journal: Journal,
    *,
    journal_evidence: IdentityEvidence | None,
    backup_evidence: Mapping[Path, IdentityEvidence | None] | None = None,
) -> tuple[Journal, IdentityEvidence]:
    if journal.participants != (journal.target,):
        raise TransactionError("group cleanup must be staged atomically")
    if journal_evidence is None:
        raise TransactionError("journal cleanup lacks validated identity evidence")
    staged, identities = _stage_cleanup_group(
        {journal.target: home},
        (journal,),
        journal_evidence={journal.target: journal_evidence},
        backup_evidence={journal.target: backup_evidence or {}},
    )
    return staged[journal.target], identities[journal.target]


def _sync_and_remove_journal(
    home: Path,
    journal: Journal,
    *,
    journal_evidence: IdentityEvidence | None,
    backup_evidence: Mapping[Path, IdentityEvidence | None] | None = None,
) -> Journal:
    path = _journal_path(home)
    if journal.rollback_status == "cleanup":
        if journal_evidence is None or capture_evidence(path, "journal cleanup") != (
            journal_evidence
        ):
            raise TransactionError("journal identity changed before cleanup")
        position = journal.participants.index(journal.target)
        if (
            len(journal.cleanup_participant_digests) != len(journal.participants)
            or _cleanup_participant_digests((journal,))[0]
            != journal.cleanup_participant_digests[position]
            or len(journal.cleanup_commitment_evidence)
            != len(journal.participants) * COMMITMENT_ANCHOR_COUNT
        ):
            raise TransactionError("cleanup group evidence is inconsistent")
        try:
            _read_commitment_anchors(home, journal, position, require_cleanup_root=True)
        except ValueError as exc:
            raise TransactionError("cleanup commitment is invalid") from exc
    else:
        journal, journal_evidence = _stage_journal_cleanup(
            home,
            journal,
            journal_evidence=journal_evidence,
            backup_evidence=backup_evidence,
        )
    cleanup_payload = encode_journal(journal)

    for operation in journal.operations:
        if operation.backup_path is None:
            continue
        backup = _state(home) / operation.backup_path
        backup_identity = operation.cleanup_backup_evidence
        if backup_identity is None:
            raise TransactionError("cleanup backup identity is missing")
        current_backup = capture_evidence(backup, "backup cleanup")
        if current_backup is None:
            continue
        if current_backup != backup_identity:
            raise TransactionError("backup identity changed before cleanup")
        snapshot_identity, content = filesystem.read_bytes_with_evidence(
            backup, "backup cleanup snapshot"
        )
        if snapshot_identity != backup_identity or _digest(content) != (
            operation.backup_hash
        ):
            raise TransactionError("backup cleanup snapshot is invalid")
        try:
            filesystem.compare_and_swap(backup, backup_identity, None, None, "unlink")
        except Exception as exc:
            after = capture_evidence(backup, "backup cleanup interruption")
            if after is not None and after != backup_identity:
                raise TransactionError(
                    "backup identity changed during cleanup"
                ) from exc
            # Whether CAS failed before or after unlink, the cleanup journal
            # makes the state resumable.  Do not pretend the attempt passed.
            raise TransactionError("backup cleanup was interrupted") from exc
    try:
        filesystem.sync_directory(_state(home) / "backups")
    except Exception as exc:
        raise TransactionError("backup directory synchronization failed") from exc

    def restore_cleanup_journal() -> None:
        try:
            replacement = capture_evidence(path, "journal cleanup restoration")
            if replacement is not None:
                if replacement != journal_evidence:
                    raise TransactionError(
                        "journal replacement blocks cleanup restoration"
                    )
                return
            restored = filesystem.compare_and_swap(
                path, None, cleanup_payload, 0o600, "create"
            )
            if restored is None or restored.sha256 != _digest(cleanup_payload):
                raise TransactionError("journal cleanup restoration is invalid")
            filesystem.sync_directory(_state(home))
        except Exception as exc:
            raise TransactionError("journal restoration could not be proved") from exc

    try:
        filesystem.compare_and_swap(path, journal_evidence, None, None, "unlink")
    except Exception as exc:
        after = capture_evidence(path, "journal cleanup interruption")
        if after is not None and after != journal_evidence:
            raise TransactionError("journal identity changed during cleanup") from exc
        if after is None:
            restore_cleanup_journal()
        raise TransactionError("journal cleanup was interrupted") from exc
    try:
        filesystem.sync_directory(_state(home))
    except Exception as exc:
        restore_cleanup_journal()
        raise TransactionError("journal directory synchronization failed") from exc
    return journal


def _remove_cleanup_commitment_markers(
    homes: Mapping[Target, Path], journals: tuple[Journal, ...]
) -> None:
    """Best-effort removal after every participant journal is already absent."""

    if not journals:
        return
    first = journals[0]
    participants = first.participants
    if (
        set(homes) != set(participants)
        or len(first.cleanup_commitment_evidence)
        != len(participants) * COMMITMENT_ANCHOR_COUNT
    ):
        return
    try:
        if any(
            capture_evidence(_journal_path(homes[target]), "final journal cleanup")
            is not None
            for target in participants
        ):
            return
    except (OSError, TransactionError, ValueError):
        return
    nonce = first.transaction_id.rsplit("-", 1)[0]
    for position, target in enumerate(participants):
        for slot, expected in enumerate(_participant_anchor_evidence(first, position)):
            marker = _commitment_anchor_path(homes[target], nonce, slot)
            try:
                current = capture_evidence(marker, "final cleanup commitment")
                if current != expected:
                    continue
                filesystem.compare_and_swap(marker, expected, None, None, "unlink")
                filesystem.sync_directory(_state(homes[target]) / "backups")
            except (OSError, TransactionError, ValueError):
                # The commitment roots are no longer recovery-critical after
                # every participant journal is absent. Retain unproved files.
                continue


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
            if journal.rollback_status == "cleanup":
                continue
            raise IncompleteRollbackError("validated rollback backup is missing")
        if (
            journal.schema_version >= 3
            and identity != operation.backup_identity_evidence
        ):
            raise IncompleteRollbackError("validated backup identity changed")
        if (
            journal.rollback_status == "cleanup"
            and identity != operation.cleanup_backup_evidence
        ):
            raise IncompleteRollbackError("validated cleanup backup identity changed")
        snapshot_identity, content = filesystem.read_bytes_with_evidence(
            backup_path, "validated backup"
        )
        if (
            snapshot_identity != identity
            or identity.nlink != 1
            or identity.mode & ~0o600
            or operation.backup_hash is None
            or _digest(content) != operation.backup_hash
        ):
            raise IncompleteRollbackError("validated rollback backup is invalid")
        backups[backup_path] = identity
    return journal_identity, backups


def _stage_prepared_cleanup(prepared: _Prepared) -> None:
    """Durably stage every participant before any group evidence is removed."""

    participants = tuple(target_plan.target for target_plan in prepared.plan.targets)
    staged, identities = _stage_cleanup_group(
        {target_plan.target: target_plan.home for target_plan in prepared.plan.targets},
        tuple(prepared.journals[target] for target in participants),
        journal_evidence=prepared.journal_evidence,
        backup_evidence={target: prepared.backup_evidence for target in participants},
    )
    prepared.journals.update(staged)
    prepared.journal_evidence.update(identities)


def _rollback(prepared: _Prepared, primary: BaseException) -> None:
    rollback_error: BaseException | None = None
    for target_plan in prepared.plan.targets:
        journal = prepared.journals[target_plan.target]
        journal = replace(journal, rollback_status="in-progress")
        prepared.journals[target_plan.target] = journal
        try:
            current = prepared.journal_evidence.get(target_plan.target)
            if current is None:
                raise TransactionError("journal update lacks current identity evidence")
            prepared.journal_evidence[target_plan.target] = _write_journal(
                target_plan.home, journal, expected_before=current
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
                _update_operation(
                    prepared,
                    target_plan.target,
                    index,
                    "rolled-back",
                    expected_before_evidence=restored_identity,
                )
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
        if not incomplete:
            try:
                _bind_all_operation_statuses(prepared, target_plan, "rolled-back")
            except BaseException as exc:
                rollback_error = rollback_error or exc
                incomplete = True
        journal = prepared.journals[target_plan.target]
        journal = replace(
            journal,
            rollback_status="incomplete" if incomplete else "complete",
        )
        prepared.journals[target_plan.target] = journal
    if rollback_error is None:
        try:
            _stage_prepared_cleanup(prepared)
            for target_plan in prepared.plan.targets:
                _sync_and_remove_journal(
                    target_plan.home,
                    prepared.journals[target_plan.target],
                    journal_evidence=prepared.journal_evidence.get(target_plan.target),
                    backup_evidence=prepared.backup_evidence,
                )
            _remove_cleanup_commitment_markers(
                {
                    target_plan.target: target_plan.home
                    for target_plan in prepared.plan.targets
                },
                tuple(
                    prepared.journals[target_plan.target]
                    for target_plan in prepared.plan.targets
                ),
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
                _update_operation(
                    prepared,
                    target_plan.target,
                    index,
                    "applied",
                    expected_after_evidence=after_identity,
                )
        for target_plan in prepared.plan.targets:
            journal = replace(
                prepared.journals[target_plan.target], rollback_status="complete"
            )
            prepared.journals[target_plan.target] = journal
    except BaseException as primary:
        _rollback(prepared, primary)
    try:
        _stage_prepared_cleanup(prepared)
    except BaseException as primary:
        raise TransactionError(
            "transaction committed but journal cleanup staging failed"
        ) from primary
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
    _remove_cleanup_commitment_markers(
        {target_plan.target: target_plan.home for target_plan in prepared.plan.targets},
        tuple(
            prepared.journals[target_plan.target]
            for target_plan in prepared.plan.targets
        ),
    )


def apply_transaction(
    plan: TransactionPlan,
    *,
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
            block = inspect_managed_block(current[0], entry.managed_block_id)
            if block is None or block.sha256 != entry.installed_block_hash:
                raise IncompleteRollbackError("manifest managed block drifted")


def _verify_complete_journal(
    home: Path,
    descriptor,
    journal: Journal,
    all_journals: tuple[Journal, ...] | None = None,
    *,
    commitment_validated: bool = False,
) -> None:
    if journal.operation not in {"install", "uninstall"}:
        raise IncompleteRollbackError("complete journal has the wrong operation")
    journals = all_journals or (journal,)
    if not commitment_validated:
        try:
            _validate_transaction_commitment(journals)
        except ValueError as exc:
            raise IncompleteRollbackError(
                "complete journal commitment is invalid"
            ) from exc
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
    *,
    commitment_validated: bool = False,
) -> None:
    if not journal.operations or any(
        operation.status != "rolled-back" for operation in journal.operations
    ):
        raise IncompleteRollbackError("rollback-complete journal has open operations")
    if not commitment_validated:
        try:
            _validate_transaction_commitment(all_journals or (journal,))
        except ValueError as exc:
            raise IncompleteRollbackError(
                "rollback journal commitment is invalid"
            ) from exc
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
    if journal.rollback_status in {"complete", "cleanup"}:
        if all(operation.status == "rolled-back" for operation in journal.operations):
            _verify_rollback_complete_journal(home, descriptor, journal)
        else:
            _verify_complete_journal(home, descriptor, journal)
        journal_identity, backup_evidence = _validated_journal_evidence(
            home, journal, journal_identity=loaded_identity
        )
        cleanup_journal = _sync_and_remove_journal(
            home,
            journal,
            journal_evidence=journal_identity,
            backup_evidence=backup_evidence,
        )
        _remove_cleanup_commitment_markers({journal.target: home}, (cleanup_journal,))
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
            if operation.status in {"planned", "rolled-back"}:
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
                    errors.append("pre-rollback journal evidence is invalid")
            else:
                errors.append("journal operation status is ambiguous")
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
    cleanup_journal = _sync_and_remove_journal(
        home,
        journal,
        journal_evidence=journal_identity,
        backup_evidence=backup_evidence,
    )
    _remove_cleanup_commitment_markers({journal.target: home}, (cleanup_journal,))


def _recover_participants(homes: Mapping[Target, Path]) -> None:
    """Compatibility forwarder to the recovery module implementation."""
    from .recovery import recover_participants_impl

    recover_participants_impl(homes)


def _path_for_journal_operation(
    home: Path, descriptor, operation: JournalOperation
) -> Path:
    """Compatibility forwarder for the recovery path seam."""
    from .recovery import path_for_journal_operation

    return path_for_journal_operation(home, descriptor, operation)


def _planned_from_journal(descriptor, operation: JournalOperation) -> PlannedOperation:
    """Compatibility forwarder for recovery journal decoding."""
    from .recovery import planned_from_journal

    return planned_from_journal(descriptor, operation)


def recover_incomplete_journal(home: Path, descriptor) -> None:
    if descriptor.target not in set(registry_target_order()):
        raise ValueError("unsupported target descriptor")
    assert_safe_home(home)
    with locked_target_homes({descriptor.target: home}, (descriptor.target,)):
        journal = load_journal(home, descriptor)
        if journal is None:
            return
        if len(journal.participants) != 1:
            participants = ", ".join(item.value for item in journal.participants)
            raise ValueError(
                f"multi-participant recovery requires all homes: {participants}"
            )
        _recover_participants({descriptor.target: home})


def recover_participants(homes: Mapping[Target, Path]) -> None:
    """Public participant recovery adapter used by the recovery module."""
    from .recovery import recover_transaction

    targets = tuple(
        target
        for target in registry_target_order()
        if isinstance(homes, Mapping) and target in homes
    )
    recover_transaction(homes, targets)


# Recovery helpers are public implementation seams so the recovery module can
# own participant orchestration without importing transaction-private names.
def digest(content: bytes) -> str:
    return _digest(content)


def journal_path(home: Path) -> Path:
    return _journal_path(home)


def canonical_participant_order(participants: tuple[Target, ...]) -> None:
    return _canonical_participant_order(participants)


def identifier_relative(descriptor, identifier: str) -> str | None:
    return _identifier_relative(descriptor, identifier)


def canonical_path(target_plan: TargetPlan, operation: PlannedOperation) -> Path:
    return _canonical_path(target_plan, operation)


def read_regular(path: Path):
    return _read_regular(path)


def check_evidence(path: Path, expected_hash, expected_mode, **kwargs):
    return _check_evidence(path, expected_hash, expected_mode, **kwargs)


def write_journal(
    home: Path,
    journal: Journal,
    *,
    expected_before: IdentityEvidence | None = None,
):
    return _write_journal(home, journal, expected_before=expected_before)


def write_progress_journal(
    home: Path,
    current_journal: Journal,
    next_journal: Journal,
    *,
    expected_before: IdentityEvidence,
):
    return _write_progress_journal(
        home,
        current_journal,
        next_journal,
        expected_before=expected_before,
    )


def backup_bytes(home: Path, journal_operation: JournalOperation) -> bytes:
    return _backup_bytes(home, journal_operation)


def reverse_operation(target_plan: TargetPlan, operation: JournalOperation):
    return _reverse_operation(target_plan, operation)


def sync_and_remove_journal(home: Path, journal: Journal, **kwargs):
    return _sync_and_remove_journal(home, journal, **kwargs)


def remove_cleanup_commitment_markers(
    homes: Mapping[Target, Path], journals: tuple[Journal, ...]
) -> None:
    _remove_cleanup_commitment_markers(homes, journals)


def stage_journal_cleanup(home: Path, journal: Journal, **kwargs):
    return _stage_journal_cleanup(home, journal, **kwargs)


def stage_cleanup_group(
    homes: Mapping[Target, Path], journals: tuple[Journal, ...], **kwargs
):
    return _stage_cleanup_group(homes, journals, **kwargs)


def cleanup_participant_digests(journals: tuple[Journal, ...]) -> tuple[str, ...]:
    return _cleanup_participant_digests(journals)


def validate_cleanup_survivors(
    journals: tuple[Journal, ...], homes: Mapping[Target, Path]
) -> tuple[Target, ...]:
    return _validate_cleanup_survivors(journals, homes)


def validated_journal_evidence(home: Path, journal: Journal, **kwargs):
    return _validated_journal_evidence(home, journal, **kwargs)


def verify_complete_journal(
    home: Path, descriptor, journal: Journal, all_journals=None, **kwargs
):
    return _verify_complete_journal(home, descriptor, journal, all_journals, **kwargs)


def verify_rollback_complete_journal(
    home: Path, descriptor, journal: Journal, all_journals, **kwargs
):
    return _verify_rollback_complete_journal(
        home, descriptor, journal, all_journals, **kwargs
    )


def capture_evidence(path: Path, label: str):
    return _capture_evidence(path, label)


def load_journal(home: Path, descriptor):
    return _load_journal(home, descriptor)
