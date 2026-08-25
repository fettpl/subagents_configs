"""Journal-group recovery implementation and public seam."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

from .locks import locked_target_homes
from .models import Journal, JournalOperation, Target
from .planning import PlannedOperation, TargetPlan
from .targets import descriptor_for, registry_target_order
from .transaction import (
    IncompleteRollbackError,
    backup_bytes,
    canonical_participant_order,
    canonical_path,
    capture_evidence,
    check_evidence,
    digest,
    identifier_relative,
    journal_path,
    load_journal,
    read_regular,
    reverse_operation,
    sync_and_remove_journal,
    validate_transaction_commitment,
    validated_journal_evidence,
    verify_complete_journal,
    verify_rollback_complete_journal,
    write_journal,
)


def recover_participants_impl(homes: Mapping[Target, Path]) -> None:
    """Recover one logical transaction after exact participant resolution."""
    if not isinstance(homes, Mapping) or not homes:
        raise ValueError("participant homes must be a non-empty mapping")
    journals: dict[Target, Journal] = {}
    journal_evidence = {}
    backup_evidence_by_target = {}
    descriptors = {target: descriptor_for(target) for target in homes}
    for target, home in homes.items():
        if not isinstance(target, Target) or not isinstance(home, Path):
            raise ValueError("participant mapping has invalid key or home")
        loaded_identity = capture_evidence(journal_path(home), "participant journal")
        journal = load_journal(home, descriptors[target])
        if journal is None:
            raise ValueError(f"missing participant journal for {target.value}")
        validated_identity = capture_evidence(journal_path(home), "participant journal")
        if loaded_identity is None or validated_identity != loaded_identity:
            raise IncompleteRollbackError(
                "participant journal changed during validation"
            )
        journals[target] = journal
        journal_evidence[target] = loaded_identity
        _, backup_evidence_by_target[target] = validated_journal_evidence(
            home, journal, journal_identity=loaded_identity
        )
    first = next(iter(journals.values()))
    participants = first.participants
    canonical_participant_order(participants)
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
        validate_transaction_commitment(ordered_journals, homes)
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
                verify_rollback_complete_journal(
                    homes[target],
                    descriptors[target],
                    journals[target],
                    ordered_journals,
                )
        elif statuses == {"applied"}:
            for target in participants:
                verify_complete_journal(
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
            sync_and_remove_journal(
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
                planned_from_journal(descriptors[target], operation)
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
            path = path_for_journal_operation(
                homes[target], descriptors[target], operation
            )
            if operation.status in {"applying", "applied"}:
                current = read_regular(path)
                current_hash = digest(current[0]) if current else None
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
                    backup_bytes(homes[target], operation)
            elif operation.status == "planned":
                check_evidence(
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
            journal_evidence[target] = write_journal(homes[target], journal)
        for target in reversed(participants):
            journal = journals[target]
            for index in reversed(range(len(journal.operations))):
                operation = journal.operations[index]
                if operation.status not in {"applying", "applied"}:
                    continue
                restored_identity = reverse_operation(target_plans[target], operation)
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
                journal_evidence[target] = write_journal(homes[target], journal)
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
            journal_evidence[target] = write_journal(homes[target], journal)
        for target in participants:
            sync_and_remove_journal(
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


def path_for_journal_operation(
    home: Path, descriptor, operation: JournalOperation
) -> Path:
    target_plan = TargetPlan(descriptor.target, home, (), None, ())
    planned = planned_from_journal(descriptor, operation)
    return canonical_path(target_plan, planned)


def planned_from_journal(descriptor, operation: JournalOperation) -> PlannedOperation:
    relative = identifier_relative(descriptor, operation.identifier)
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


def recover_transaction(
    homes: Mapping[Target, Path], targets: tuple[Target, ...]
) -> None:
    """Recover exactly the requested participant set under canonical locks."""
    if not isinstance(homes, Mapping) or not isinstance(targets, tuple) or not targets:
        raise ValueError("recovery requires participant homes and targets")
    if (
        tuple(target for target in registry_target_order() if target in targets)
        != targets
    ):
        raise ValueError("recovery targets must use canonical registry order")
    if set(homes) != set(targets):
        raise ValueError("recovery homes must exactly match targets")
    if any(
        not isinstance(target, Target) or not isinstance(home, Path)
        for target, home in homes.items()
    ):
        raise ValueError("recovery participant mapping is invalid")
    with locked_target_homes(homes, targets):
        recover_participants_impl(homes)


__all__ = ["recover_participants_impl", "recover_transaction"]
