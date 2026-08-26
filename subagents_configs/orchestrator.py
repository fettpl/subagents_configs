"""Public command-line orchestration for the multi-client installer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal, TextIO

from . import filesystem
from .cli import parse_request
from .compatibility import (
    CompatibilityPreflightError,
    validate_request_compatibility,
)
from .diagnostics import DiagnosticCode, emit_diagnostic
from .errors import CliError, ValidationBlockedError
from .locks import locked_target_homes
from .models import Journal, Request, Target
from .paths import normalized_absolute
from .planning import (
    RecoverySummary,
    TargetPlan,
    TransactionPlan,
    preflight_install,
    preflight_uninstall,
    render_plan,
    render_plan_json,
    validate_request_shape,
)
from .recovery import recover_transaction
from .state import load_journal
from .targets import descriptor_for
from .transaction import (
    FailureInjector,
    IncompleteRollbackError,
    TransactionError,
    apply_transaction,
    validate_cleanup_survivors,
    validate_transaction_commitment,
)

EXIT_SUCCESS = 0
EXIT_CLI_ERROR = 2
EXIT_PREFLIGHT_ERROR = 3
EXIT_MANAGED_CONFLICT = 4
EXIT_APPLY_ERROR = 5
EXIT_INCOMPLETE_ROLLBACK = 6
EXIT_UNRESOLVED_UNINSTALL = 7
EXIT_BLOCKED_VALIDATION = 8

# Public aliases make the status contract easier for embedding callers to use.
EXIT_USAGE = EXIT_CLI_ERROR
EXIT_PREFLIGHT = EXIT_PREFLIGHT_ERROR
EXIT_APPLY_FAILURE = EXIT_APPLY_ERROR
EXIT_ROLLBACK_INCOMPLETE = EXIT_INCOMPLETE_ROLLBACK
EXIT_UNRESOLVED = EXIT_UNRESOLVED_UNINSTALL
EXIT_VALIDATION_BLOCKED = EXIT_BLOCKED_VALIDATION

HELP_TEXT = {
    "install": (
        "Usage: install.sh (--target TARGET ... | --all) [OPTIONS]\n"
        "\n"
        "Install the selected roles, routing source, and private validation runtime.\n"
        "Targets: codex, opencode, claude-code, pi; --all selects the first three.\n"
        "Defaults: homes use TARGET-specific environment variables, then HOME;\n"
        "CLI --home TARGET=PATH overrides environment/default homes.\n"
        "Default install excludes commit-pusher and does not edit global instructions\n"
        "or Codex config, enable network access, execute installed content, or write\n"
        "outside selected homes. --include-commit-pusher opts that role in;\n"
        "--enable-global-routing opts in one managed routing block;\n"
        "--enable-codex-multi-agent opts in the Codex TOML feature block.\n"
        "--profile PATH loads a strict local JSON/TOML request; explicit CLI\n"
        "targets, homes, booleans, dry-run, and format values take precedence.\n"
        "Installed files are home/agents/<role>, the private\n"
        "home/.subagents_configs/validation runtime, and only opted-in managed\n"
        "AGENTS.md/CLAUDE.md or Codex config blocks.\n"
        "--dry-run prints normalized homes and exact effects without any writes;\n"
        "--format json selects the versioned structured dry-run output.\n"
        "--client-version TARGET=VERSION supplies caller-owned version evidence;\n"
        "absent versions use the maintained tested matrix row.\n"
        "Pi is explicit-only; --pi-executable and both consent flags authorize\n"
        "later Pi package work, while --dry-run reports missing consent safely.\n"
        "Options: --target TARGET, --all, --home TARGET=PATH, --profile PATH,\n"
        "         --enable-global-routing/--no-global-routing,\n"
        "         --enable-codex-multi-agent/--no-codex-multi-agent,\n"
        "         --include-commit-pusher/--no-commit-pusher,\n"
        "         --client-version TARGET=VERSION, --pi-executable PATH,\n"
        "         --consent-third-party-code, --consent-network,\n"
        "         --dry-run/--no-dry-run,\n"
        "         --format text|json, --help\n"
    ),
    "uninstall": (
        "Usage: uninstall.sh (--target TARGET ... | --all) [OPTIONS]\n"
        "\n"
        "Conservatively remove exact managed files/blocks and restore proven backups.\n"
        "Targets: codex, opencode, claude-code, pi; --all selects the first three.\n"
        "Defaults: homes use TARGET-specific environment variables, then HOME;\n"
        "CLI --home TARGET=PATH overrides environment/default homes.\n"
        "Unresolved, changed, missing, unsafe, or preexisting entries are retained\n"
        "and reported; validation runtime and private backup evidence are retained.\n"
        "Managed files are home/agents/<role> and opted-in AGENTS.md/CLAUDE.md or\n"
        "Codex config blocks; no unrelated files are removed.\n"
        "Uninstall never accepts install-only routing, Codex, or role options.\n"
        "--dry-run prints normalized homes and exact effects without any writes;\n"
        "--format json selects the versioned structured dry-run output.\n"
        "--profile PATH loads a strict local JSON/TOML request; explicit CLI\n"
        "targets, homes, booleans, dry-run, and format values take precedence.\n"
        "--client-version TARGET=VERSION supplies caller-owned version evidence;\n"
        "absent versions use the maintained tested matrix row.\n"
        "Pi package removal is explicit and requires --target pi.\n"
        "Options: --target TARGET, --all, --home TARGET=PATH, --profile PATH,\n"
        "         --client-version TARGET=VERSION, --pi-executable PATH,\n"
        "         --remove-pi-package, --dry-run/--no-dry-run,\n"
        "         --format text|json, --help\n"
    ),
}


def _write_output(stream: TextIO, text: str) -> bool:
    """Write output without allowing a broken caller stream to escape."""

    try:
        stream.write(text)
    except Exception:
        return False
    return True


def _emit(
    stderr: TextIO,
    code: DiagnosticCode,
    *,
    operation: str,
    phase: str,
    status: str,
    targets: Sequence[Target] = (),
    homes: Sequence[Path] = (),
    reasons: tuple[str, ...] = (),
) -> bool:
    """Emit a typed diagnostic using only normalized, safe context."""

    target_names = tuple(target.value for target in targets)
    home_names = tuple(str(home) for home in homes)
    return emit_diagnostic(
        stderr,
        code,
        target_names,
        home_names,
        operation,
        phase,
        status,
        reasons,
    )


def _emit_request(
    stderr: TextIO,
    request: Request,
    code: DiagnosticCode,
    *,
    phase: str,
    status: str,
    reasons: tuple[str, ...] = (),
) -> bool:
    return _emit(
        stderr,
        code,
        operation=request.operation,
        phase=phase,
        status=status,
        targets=request.targets,
        homes=tuple(request.homes[target] for target in request.targets),
        reasons=reasons,
    )


def _compatibility_output(
    stdout: TextIO,
    request: Request,
    failure: CompatibilityPreflightError,
) -> bool:
    """Render bounded compatibility reasons for a failed dry-run."""

    if request.dry_run_format == "json":
        import json

        rendered = (
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": request.operation,
                    "compatibility": {
                        "target": failure.target,
                        "supported": False,
                        "reasons": list(failure.result.reasons),
                        **(
                            {"required_consents": ["third-party-code", "network"]}
                            if failure.target == Target.PI.value
                            and request.operation == "install"
                            else {}
                        ),
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
    else:
        rendered = (
            f"compatibility: target={failure.target} supported=false "
            f"reasons={','.join(failure.result.reasons)}\n"
        )
        if failure.target == Target.PI.value and request.operation == "install":
            rendered = (
                rendered.rstrip("\n") + " required_consents=third-party-code,network\n"
            )
    return _write_output(stdout, rendered)


def _handle_compatibility_failure(
    request: Request,
    failure: CompatibilityPreflightError,
    *,
    stdout: TextIO | None,
    stderr: TextIO,
) -> int:
    if stdout is not None and request.dry_run:
        _compatibility_output(stdout, request, failure)
    _emit_request(
        stderr,
        request,
        DiagnosticCode.PREFLIGHT_REJECTED,
        phase="preflight",
        status="rejected",
        reasons=failure.result.reasons,
    )
    return EXIT_PREFLIGHT_ERROR


def _journal_groups(
    request: Request,
) -> tuple[tuple[dict[Target, Path], tuple[Journal, ...]], ...]:
    """Read and validate every selected journal before any recovery write."""

    journals: dict[Target, Journal] = {}
    homes = {
        target: normalized_absolute(request.homes[target]) for target in request.targets
    }
    for target in request.targets:
        journal = load_journal(homes[target], descriptor_for(target))
        if journal is not None:
            journals[target] = journal
    if not journals:
        return ()

    groups: list[tuple[dict[Target, Path], tuple[Journal, ...]]] = []
    by_transaction: dict[str, dict[Target, Journal]] = {}
    for target, journal in journals.items():
        by_transaction.setdefault(journal.transaction_id, {})[target] = journal
    for transaction_journals in by_transaction.values():
        anchor = next(iter(transaction_journals.values()))
        journal = anchor
        participants = journal.participants
        if not participants:
            raise ValueError("journal has no participants")
        if any(target not in homes for target in participants):
            names = ", ".join(target.value for target in participants)
            raise ValueError(
                f"recovery requires selected homes for participants: {names}"
            )
        group_homes = {target: homes[target] for target in participants}
        if set(transaction_journals) != set(participants):
            missing = set(participants) - set(transaction_journals)
            if missing:
                if any(target in journals for target in missing):
                    raise ValueError("cleanup participant transaction IDs disagree")
                survivors = tuple(
                    transaction_journals[target]
                    for target in participants
                    if target in transaction_journals
                )
                validate_cleanup_survivors(survivors, group_homes)
                groups.append((group_homes, survivors))
                continue
            raise ValueError("recovery participant journal mapping is not exact")
        group_journals: list[Journal] = []
        for target in participants:
            participant = journals.get(target)
            if participant is None:
                raise ValueError(f"missing participant journal for {target.value}")
            group_journals.append(participant)
        ordered = tuple(group_journals)
        ordered = validate_transaction_commitment(ordered, group_homes)
        groups.append((group_homes, ordered))
    return tuple(groups)


def _recovery_action(journals: tuple[Journal, ...]) -> str:
    """Classify a validated pending group as cleanup or rollback."""

    statuses = {
        operation.status for journal in journals for operation in journal.operations
    }
    complete = all(
        journal.rollback_status in {"complete", "cleanup"} for journal in journals
    )
    if complete and statuses in ({"applied"}, {"rolled-back"}):
        return "cleanup"
    return "rollback"


def _recover_groups(
    groups: tuple[tuple[dict[Target, Path], tuple[Journal, ...]], ...],
) -> None:
    for homes, _journals in groups:
        recover_transaction(homes, tuple(homes))


def _plan(request: Request, repo_root: Path) -> TransactionPlan:
    if request.operation == "install":
        return preflight_install(repo_root, request)
    return preflight_uninstall(repo_root, request)


class ConcurrentDryRunChangeError(RuntimeError):
    """Raised when the two lock-free dry-run evidence collections disagree."""


def _evidence_fingerprint(value: object) -> tuple[object, ...] | None:
    fields = ("device", "inode", "size", "nlink", "mode", "sha256")
    if not all(hasattr(value, field) for field in fields):
        return None
    return tuple(getattr(value, field) for field in fields)


def _plan_fingerprint(plan: TransactionPlan) -> tuple[object, ...]:
    targets = []
    for target in plan.targets:
        operations = []
        for operation in target.operations:
            operations.append(
                (
                    operation.target.value,
                    operation.identifier,
                    operation.action,
                    operation.relative_path,
                    operation.expected_before_hash,
                    operation.expected_after_hash,
                    operation.expected_before_mode,
                    operation.expected_after_mode,
                    operation.ownership,
                    _evidence_fingerprint(operation.expected_before_evidence),
                    _evidence_fingerprint(operation.expected_after_evidence),
                )
            )
        targets.append(
            (
                target.target.value,
                str(normalized_absolute(target.home)),
                tuple(operations),
                tuple(target.conflicts),
            )
        )
    sources = tuple(
        (item.identifier, item.kind, item.format, item.source_hash)
        for item in plan.sources
    )
    return (plan.operation, tuple(targets), sources)


def _state_fingerprint(request: Request) -> tuple[object, ...]:
    """Capture existing state/journal identities without creating substrates."""

    records = []
    for target in request.targets:
        home = normalized_absolute(request.homes[target])
        state_dir = home / ".subagents_configs"
        state_identity = (
            filesystem.capture_evidence(state_dir / "manifest.json", "dry-run manifest")
            if (state_dir / "manifest.json").exists()
            else None
        )
        journal_identity = (
            filesystem.capture_evidence(state_dir / "journal.json", "dry-run journal")
            if (state_dir / "journal.json").exists()
            else None
        )
        records.append(
            (
                target.value,
                _evidence_fingerprint(state_identity),
                _evidence_fingerprint(journal_identity),
            )
        )
    return tuple(records)


def _recovery_fingerprint(
    groups: tuple[tuple[dict[Target, Path], tuple[Journal, ...]], ...],
) -> tuple[object, ...]:
    records = []
    for homes, journals in groups:
        for journal in journals:
            records.append(
                (
                    journal.target.value,
                    str(normalized_absolute(homes[journal.target])),
                    journal.transaction_id,
                    journal.operation,
                    tuple(journal.participants),
                    journal.rollback_status,
                    tuple(
                        (
                            operation.operation_id,
                            operation.identifier,
                            operation.action,
                            operation.status,
                            operation.expected_before_hash,
                            operation.expected_after_hash,
                            operation.expected_before_mode,
                            operation.expected_after_mode,
                            _evidence_fingerprint(operation.expected_before_evidence),
                            _evidence_fingerprint(operation.expected_after_evidence),
                            _evidence_fingerprint(operation.backup_identity_evidence),
                            _evidence_fingerprint(operation.cleanup_backup_evidence),
                        )
                        for operation in journal.operations
                    ),
                    journal.cleanup_participant_digests,
                    tuple(
                        _evidence_fingerprint(item)
                        for item in journal.cleanup_commitment_evidence
                    ),
                )
            )
    return tuple(records)


def _collect_stable_dry_run_evidence(
    request: Request, repo_root: Path | None = None
) -> tuple[TransactionPlan, tuple[object, ...]]:
    """Collect complete read-only planning evidence twice without acquiring locks."""

    root = Path(__file__).parents[1] if repo_root is None else repo_root
    first_groups = _journal_groups(request)
    first_state = _state_fingerprint(request)
    if first_groups:
        first = TransactionPlan(
            request.operation,
            tuple(
                TargetPlan(
                    target,
                    normalized_absolute(request.homes[target]),
                    (),
                    None,
                    (),
                )
                for target in request.targets
            ),
            recovery=_recovery_summary(first_groups),
        )
    else:
        first = _plan(request, root)
    second_groups = _journal_groups(request)
    second = (
        TransactionPlan(
            request.operation,
            tuple(
                TargetPlan(
                    target,
                    normalized_absolute(request.homes[target]),
                    (),
                    None,
                    (),
                )
                for target in request.targets
            ),
            recovery=_recovery_summary(second_groups),
        )
        if second_groups
        else _plan(request, root)
    )

    second_state = _state_fingerprint(request)
    recovery_fingerprint = _recovery_fingerprint(first_groups)
    plan_fingerprint = _plan_fingerprint(first)
    if (
        first_state != second_state
        or recovery_fingerprint != _recovery_fingerprint(second_groups)
        or plan_fingerprint != _plan_fingerprint(second)
    ):
        raise ConcurrentDryRunChangeError("dry-run evidence changed")
    return first, (first_state, recovery_fingerprint, plan_fingerprint)


def collect_stable_dry_run_evidence(
    request: Request, repo_root: Path | None = None
) -> TransactionPlan:
    """Collect complete read-only planning evidence twice without acquiring locks."""

    plan, _fingerprint = _collect_stable_dry_run_evidence(request, repo_root)
    return plan


def _recovery_summary(
    groups: tuple[tuple[dict[Target, Path], tuple[Journal, ...]], ...],
) -> RecoverySummary:
    if not groups:
        return RecoverySummary()
    participants: list[Target] = []
    homes: list[Path] = []
    identifiers: list[str] = []
    actions: set[str] = set()
    manual_resolution = False
    for group_homes, journals in groups:
        actions.add(_recovery_action(journals))
        for journal in journals:
            if journal.target not in participants:
                participants.append(journal.target)
            homes.append(group_homes[journal.target])
            identifiers.extend(
                operation.operation_id for operation in journal.operations
            )
            manual_resolution = (
                manual_resolution
                or journal.rollback_status in {"incomplete"}
                or any(
                    operation.status == "ambiguous" for operation in journal.operations
                )
            )
    action = next(iter(sorted(actions))) if len(actions) == 1 else "rollback"
    return RecoverySummary(
        required=True,
        action=action,
        participants=tuple(participants),
        homes=tuple(homes),
        journal_identifiers=tuple(identifiers),
        manual_resolution=manual_resolution,
    )


def _run_mutating_locked(
    request: Request,
    *,
    repo_root: Path,
    stdout: TextIO,
    stderr: TextIO,
    failure_injector: FailureInjector | None,
) -> int:
    """Run recovery, planning, preparation, apply, and cleanup in one lock scope."""

    try:
        validate_request_compatibility(request)
    except CompatibilityPreflightError as failure:
        return _handle_compatibility_failure(
            request, failure, stdout=stdout, stderr=stderr
        )
    except (ValueError, OSError):
        _emit_request(
            stderr,
            request,
            DiagnosticCode.PREFLIGHT_REJECTED,
            phase="preflight",
            status="rejected",
        )
        return EXIT_PREFLIGHT_ERROR

    homes = {
        target: normalized_absolute(request.homes[target]) for target in request.targets
    }
    primary_status: int | None = None

    def _finish(status: int) -> int:
        nonlocal primary_status
        primary_status = status
        return status

    try:
        with locked_target_homes(homes, request.targets):
            try:
                groups = _journal_groups(request)
            except (ValueError, OSError):
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.VALIDATION_BLOCKED,
                    phase="recovery",
                    status="blocked",
                )
                return _finish(EXIT_BLOCKED_VALIDATION)
            except Exception:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.VALIDATION_BLOCKED,
                    phase="recovery",
                    status="blocked",
                )
                return _finish(EXIT_BLOCKED_VALIDATION)
            try:
                _recover_groups(groups)
            except IncompleteRollbackError:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.RECOVERY_INCOMPLETE,
                    phase="recovery",
                    status="incomplete",
                )
                return _finish(EXIT_INCOMPLETE_ROLLBACK)
            except (ValueError, OSError, TransactionError, RuntimeError):
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.VALIDATION_BLOCKED,
                    phase="recovery",
                    status="blocked",
                )
                return _finish(EXIT_BLOCKED_VALIDATION)
            except Exception:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.APPLY_AMBIGUOUS,
                    phase="recovery",
                    status="ambiguous",
                )
                return _finish(EXIT_INCOMPLETE_ROLLBACK)
            try:
                plan = _plan(request, repo_root)
            except CompatibilityPreflightError as failure:
                return _finish(
                    _handle_compatibility_failure(
                        request, failure, stdout=stdout, stderr=stderr
                    )
                )
            except ValidationBlockedError:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.VALIDATION_BLOCKED,
                    phase="validation",
                    status="blocked",
                )
                return _finish(EXIT_BLOCKED_VALIDATION)
            except ValueError:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.PREFLIGHT_REJECTED,
                    phase="preflight",
                    status="rejected",
                )
                return _finish(EXIT_PREFLIGHT_ERROR)
            except RuntimeError:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.VALIDATION_BLOCKED,
                    phase="validation",
                    status="blocked",
                )
                return _finish(EXIT_BLOCKED_VALIDATION)
            except OSError:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.PREFLIGHT_REJECTED,
                    phase="preflight",
                    status="rejected",
                )
                return _finish(EXIT_PREFLIGHT_ERROR)
            except Exception:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.PREFLIGHT_REJECTED,
                    phase="preflight",
                    status="rejected",
                )
                return _finish(EXIT_PREFLIGHT_ERROR)
            try:
                rendered = render_plan(plan)
                if not _write_output(stdout, rendered):
                    raise OSError("preflight output unavailable")
                has_conflicts = any(target.conflicts for target in plan.targets)
            except Exception:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.OUTPUT_FAILED,
                    phase="output",
                    status="failed",
                )
                return _finish(EXIT_PREFLIGHT_ERROR)
            if request.operation == "install" and has_conflicts:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.MANAGED_CONFLICT,
                    phase="preflight",
                    status="conflict",
                )
                return _finish(EXIT_MANAGED_CONFLICT)
            try:
                apply_transaction(plan, failure_injector=failure_injector)
            except IncompleteRollbackError:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.APPLY_AMBIGUOUS,
                    phase="apply",
                    status="ambiguous",
                )
                return _finish(EXIT_INCOMPLETE_ROLLBACK)
            except (TransactionError, OSError, ValueError):
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.APPLY_ROLLED_BACK,
                    phase="apply",
                    status="rolled-back",
                )
                return _finish(EXIT_APPLY_ERROR)
            except Exception:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.APPLY_ROLLED_BACK,
                    phase="apply",
                    status="rolled-back",
                )
                return _finish(EXIT_APPLY_ERROR)
            try:
                has_conflicts = any(target.conflicts for target in plan.targets)
                if request.operation == "uninstall" and has_conflicts:
                    for target in plan.targets:
                        for conflict in target.conflicts:
                            del conflict
                            if not emit_diagnostic(
                                stdout,
                                DiagnosticCode.UNRESOLVED_UNINSTALL,
                                (target.target.value,),
                                (str(target.home),),
                                request.operation,
                                "output",
                                "unresolved",
                            ):
                                raise OSError("unresolved output unavailable")
                    return _finish(EXIT_UNRESOLVED_UNINSTALL)
            except Exception:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.OUTPUT_FAILED,
                    phase="output",
                    status="failed",
                )
                return _finish(EXIT_PREFLIGHT_ERROR)
            return _finish(EXIT_SUCCESS)
    except (ValueError, OSError):
        if primary_status is not None:
            return primary_status
        _emit_request(
            stderr,
            request,
            DiagnosticCode.VALIDATION_BLOCKED,
            phase="recovery",
            status="blocked",
        )
        return EXIT_BLOCKED_VALIDATION
    except Exception:
        if primary_status is not None:
            return primary_status
        _emit_request(
            stderr,
            request,
            DiagnosticCode.VALIDATION_BLOCKED,
            phase="recovery",
            status="blocked",
        )
        return EXIT_BLOCKED_VALIDATION


def run(
    operation: Literal["install", "uninstall"],
    argv: Sequence[str],
    *,
    repo_root: Path,
    environ: Mapping[str, str],
    stdout: TextIO,
    stderr: TextIO,
    failure_injector: FailureInjector | None = None,
) -> int:
    """Parse, recover, preflight, render, and optionally apply one operation."""

    if operation not in HELP_TEXT:
        _emit(
            stderr,
            DiagnosticCode.CLI_INVALID,
            operation=operation,
            phase="cli",
            status="invalid",
        )
        return EXIT_CLI_ERROR
    if len(argv) == 1 and argv[0] == "--help":
        if not _write_output(stdout, HELP_TEXT[operation]):
            _emit(
                stderr,
                DiagnosticCode.OUTPUT_FAILED,
                operation=operation,
                phase="output",
                status="failed",
            )
            return EXIT_PREFLIGHT_ERROR
        return EXIT_SUCCESS
    try:
        request = parse_request(operation, argv, environ)
    except CliError:
        _emit(
            stderr,
            DiagnosticCode.CLI_INVALID,
            operation=operation,
            phase="cli",
            status="invalid",
        )
        return EXIT_CLI_ERROR
    except ValueError:
        _emit(
            stderr,
            DiagnosticCode.PREFLIGHT_REJECTED,
            operation=operation,
            phase="preflight",
            status="rejected",
        )
        return EXIT_PREFLIGHT_ERROR
    except Exception:
        _emit(
            stderr,
            DiagnosticCode.CLI_INVALID,
            operation=operation,
            phase="cli",
            status="invalid",
        )
        return EXIT_CLI_ERROR

    try:
        validate_request_shape(request, operation)
    except (TypeError, ValueError):
        _emit(
            stderr,
            DiagnosticCode.PREFLIGHT_REJECTED,
            operation=operation,
            phase="preflight",
            status="rejected",
        )
        return EXIT_PREFLIGHT_ERROR

    if not request.dry_run:
        return _run_mutating_locked(
            request,
            repo_root=repo_root,
            stdout=stdout,
            stderr=stderr,
            failure_injector=failure_injector,
        )

    # Compatibility is the first read-only preflight fact for both dry-run
    # renderers; do not inspect recovery state before an incompatible request
    # has been rejected.
    try:
        validate_request_compatibility(request)
    except CompatibilityPreflightError as failure:
        return _handle_compatibility_failure(
            request, failure, stdout=stdout, stderr=stderr
        )
    except (ValueError, OSError):
        _emit_request(
            stderr,
            request,
            DiagnosticCode.PREFLIGHT_REJECTED,
            phase="preflight",
            status="rejected",
        )
        return EXIT_PREFLIGHT_ERROR

    if request.dry_run_format == "json":
        try:
            plan, fingerprint = _collect_stable_dry_run_evidence(request, repo_root)
        except CompatibilityPreflightError as failure:
            return _handle_compatibility_failure(
                request, failure, stdout=stdout, stderr=stderr
            )
        except ConcurrentDryRunChangeError:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.PREFLIGHT_CONCURRENT_CHANGE,
                phase="preflight",
                status="rejected",
            )
            return EXIT_PREFLIGHT_ERROR
        except ValidationBlockedError:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.VALIDATION_BLOCKED,
                phase="validation",
                status="blocked",
            )
            return EXIT_BLOCKED_VALIDATION
        except ValueError:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.PREFLIGHT_REJECTED,
                phase="preflight",
                status="rejected",
            )
            return EXIT_PREFLIGHT_ERROR
        except (RuntimeError, OSError):
            _emit_request(
                stderr,
                request,
                DiagnosticCode.PREFLIGHT_REJECTED,
                phase="preflight",
                status="rejected",
            )
            return EXIT_PREFLIGHT_ERROR
        except Exception:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.PREFLIGHT_REJECTED,
                phase="preflight",
                status="rejected",
            )
            return EXIT_PREFLIGHT_ERROR
        try:
            rendered = render_plan_json(plan).decode("utf-8")
        except Exception:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.OUTPUT_FAILED,
                phase="output",
                status="failed",
            )
            return EXIT_PREFLIGHT_ERROR
        try:
            _post_render_plan, post_fingerprint = _collect_stable_dry_run_evidence(
                request, repo_root
            )
            if post_fingerprint != fingerprint:
                raise ConcurrentDryRunChangeError(
                    "dry-run evidence changed after render"
                )
        except ConcurrentDryRunChangeError:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.PREFLIGHT_CONCURRENT_CHANGE,
                phase="preflight",
                status="rejected",
            )
            return EXIT_PREFLIGHT_ERROR
        except Exception:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.PREFLIGHT_CONCURRENT_CHANGE,
                phase="preflight",
                status="rejected",
            )
            return EXIT_PREFLIGHT_ERROR
        try:
            if not _write_output(stdout, rendered):
                raise OSError("structured output unavailable")
            has_conflicts = any(target.conflicts for target in plan.targets)
        except Exception:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.OUTPUT_FAILED,
                phase="output",
                status="failed",
            )
            return EXIT_PREFLIGHT_ERROR
        if request.operation == "install" and has_conflicts:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.MANAGED_CONFLICT,
                phase="preflight",
                status="conflict",
            )
            return EXIT_MANAGED_CONFLICT
        return EXIT_SUCCESS

    try:
        groups = _journal_groups(request)
    except (ValueError, OSError):
        _emit_request(
            stderr,
            request,
            DiagnosticCode.VALIDATION_BLOCKED,
            phase="recovery",
            status="blocked",
        )
        return EXIT_BLOCKED_VALIDATION
    except Exception:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.VALIDATION_BLOCKED,
            phase="recovery",
            status="blocked",
        )
        return EXIT_BLOCKED_VALIDATION

    if groups and request.dry_run:
        if request.dry_run_format == "json":
            try:
                recovery = _recovery_summary(groups)
                plan = TransactionPlan(
                    request.operation,
                    tuple(
                        TargetPlan(
                            target,
                            normalized_absolute(request.homes[target]),
                            (),
                            None,
                            (),
                        )
                        for target in request.targets
                    ),
                )
                rendered = render_plan_json(plan, recovery=recovery).decode("utf-8")
                if not _write_output(stdout, rendered):
                    raise OSError("recovery output unavailable")
            except Exception:
                _emit_request(
                    stderr,
                    request,
                    DiagnosticCode.OUTPUT_FAILED,
                    phase="output",
                    status="failed",
                )
                return EXIT_PREFLIGHT_ERROR
            return EXIT_SUCCESS
        try:
            for homes, journals in groups:
                del journals
                for target in homes:
                    if not emit_diagnostic(
                        stdout,
                        DiagnosticCode.RECOVERY_REQUIRED,
                        (target.value,),
                        (str(homes[target]),),
                        request.operation,
                        "recovery",
                        "required",
                    ):
                        raise OSError("recovery output unavailable")
        except Exception:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.OUTPUT_FAILED,
                phase="output",
                status="failed",
            )
            return EXIT_PREFLIGHT_ERROR
        return EXIT_SUCCESS

    try:
        _recover_groups(groups)
    except IncompleteRollbackError:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.RECOVERY_INCOMPLETE,
            phase="recovery",
            status="incomplete",
        )
        return EXIT_INCOMPLETE_ROLLBACK
    except (ValueError, OSError, TransactionError, RuntimeError):
        _emit_request(
            stderr,
            request,
            DiagnosticCode.VALIDATION_BLOCKED,
            phase="recovery",
            status="blocked",
        )
        return EXIT_BLOCKED_VALIDATION
    except Exception:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.APPLY_AMBIGUOUS,
            phase="recovery",
            status="ambiguous",
        )
        return EXIT_INCOMPLETE_ROLLBACK

    try:
        if request.dry_run_format == "json":
            plan = collect_stable_dry_run_evidence(request, repo_root)
        else:
            plan = _plan(request, repo_root)
    except CompatibilityPreflightError as failure:
        return _handle_compatibility_failure(
            request, failure, stdout=stdout, stderr=stderr
        )
    except ConcurrentDryRunChangeError:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.PREFLIGHT_CONCURRENT_CHANGE,
            phase="preflight",
            status="rejected",
        )
        return EXIT_PREFLIGHT_ERROR
    except ValidationBlockedError:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.VALIDATION_BLOCKED,
            phase="validation",
            status="blocked",
        )
        return EXIT_BLOCKED_VALIDATION
    except ValueError:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.PREFLIGHT_REJECTED,
            phase="preflight",
            status="rejected",
        )
        return EXIT_PREFLIGHT_ERROR
    except RuntimeError:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.VALIDATION_BLOCKED,
            phase="validation",
            status="blocked",
        )
        return EXIT_BLOCKED_VALIDATION
    except OSError:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.PREFLIGHT_REJECTED,
            phase="preflight",
            status="rejected",
        )
        return EXIT_PREFLIGHT_ERROR
    except Exception:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.PREFLIGHT_REJECTED,
            phase="preflight",
            status="rejected",
        )
        return EXIT_PREFLIGHT_ERROR

    try:
        if request.dry_run_format == "json":
            rendered = render_plan_json(plan).decode("utf-8")
        else:
            rendered = render_plan(plan)
    except Exception:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.OUTPUT_FAILED,
            phase="output",
            status="failed",
        )
        return EXIT_PREFLIGHT_ERROR
    if not _write_output(stdout, rendered):
        _emit_request(
            stderr,
            request,
            DiagnosticCode.OUTPUT_FAILED,
            phase="output",
            status="failed",
        )
        return EXIT_PREFLIGHT_ERROR
    try:
        has_conflicts = any(target.conflicts for target in plan.targets)
    except Exception:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.OUTPUT_FAILED,
            phase="output",
            status="failed",
        )
        return EXIT_PREFLIGHT_ERROR
    if request.operation == "install" and has_conflicts:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.MANAGED_CONFLICT,
            phase="preflight",
            status="conflict",
        )
        return EXIT_MANAGED_CONFLICT
    if request.dry_run:
        return EXIT_SUCCESS

    try:
        apply_transaction(plan, failure_injector=failure_injector)
    except IncompleteRollbackError:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.APPLY_AMBIGUOUS,
            phase="apply",
            status="ambiguous",
        )
        return EXIT_INCOMPLETE_ROLLBACK
    except (TransactionError, OSError, ValueError):
        _emit_request(
            stderr,
            request,
            DiagnosticCode.APPLY_ROLLED_BACK,
            phase="apply",
            status="rolled-back",
        )
        return EXIT_APPLY_ERROR
    except Exception:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.APPLY_ROLLED_BACK,
            phase="apply",
            status="rolled-back",
        )
        return EXIT_APPLY_ERROR

    try:
        has_conflicts = any(target.conflicts for target in plan.targets)
    except Exception:
        _emit_request(
            stderr,
            request,
            DiagnosticCode.OUTPUT_FAILED,
            phase="output",
            status="failed",
        )
        return EXIT_PREFLIGHT_ERROR
    if request.operation == "uninstall" and has_conflicts:
        try:
            for target in plan.targets:
                for conflict in target.conflicts:
                    del conflict
                    if not emit_diagnostic(
                        stdout,
                        DiagnosticCode.UNRESOLVED_UNINSTALL,
                        (target.target.value,),
                        (str(target.home),),
                        request.operation,
                        "output",
                        "unresolved",
                    ):
                        raise OSError("unresolved output unavailable")
        except Exception:
            _emit_request(
                stderr,
                request,
                DiagnosticCode.OUTPUT_FAILED,
                phase="output",
                status="failed",
            )
        return EXIT_UNRESOLVED_UNINSTALL
    return EXIT_SUCCESS
