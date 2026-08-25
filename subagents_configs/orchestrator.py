"""Public command-line orchestration for the multi-client installer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal, TextIO

from .cli import parse_request
from .diagnostics import DiagnosticCode, emit_diagnostic
from .errors import CliError, ValidationBlockedError
from .locks import locked_target_homes
from .models import Journal, Request, Target
from .paths import normalized_absolute
from .planning import (
    TransactionPlan,
    preflight_install,
    preflight_uninstall,
    render_plan,
)
from .recovery import recover_transaction
from .state import load_journal
from .targets import descriptor_for
from .transaction import (
    FailureInjector,
    IncompleteRollbackError,
    TransactionError,
    apply_transaction,
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
        "Targets: codex, opencode, claude-code; --all selects all three.\n"
        "Defaults: homes use TARGET-specific environment variables, then HOME;\n"
        "CLI --home TARGET=PATH overrides environment/default homes.\n"
        "Default install excludes commit-pusher and does not edit global instructions\n"
        "or Codex config, enable network access, execute installed content, or write\n"
        "outside selected homes. --include-commit-pusher opts that role in;\n"
        "--enable-global-routing opts in one managed routing block;\n"
        "--enable-codex-multi-agent opts in the Codex TOML feature block.\n"
        "Installed files are home/agents/<role>, the private\n"
        "home/.subagents_configs/validation runtime, and only opted-in managed\n"
        "AGENTS.md/CLAUDE.md or Codex config blocks.\n"
        "--dry-run prints normalized homes and exact effects without any writes.\n"
        "Options: --target TARGET, --all, --home TARGET=PATH,\n"
        "         --enable-global-routing, --enable-codex-multi-agent,\n"
        "         --include-commit-pusher, --dry-run, --help\n"
    ),
    "uninstall": (
        "Usage: uninstall.sh (--target TARGET ... | --all) [OPTIONS]\n"
        "\n"
        "Conservatively remove exact managed files/blocks and restore proven backups.\n"
        "Targets: codex, opencode, claude-code; --all selects all three.\n"
        "Defaults: homes use TARGET-specific environment variables, then HOME;\n"
        "CLI --home TARGET=PATH overrides environment/default homes.\n"
        "Unresolved, changed, missing, unsafe, or preexisting entries are retained\n"
        "and reported; validation runtime and private backup evidence are retained.\n"
        "Managed files are home/agents/<role> and opted-in AGENTS.md/CLAUDE.md or\n"
        "Codex config blocks; no unrelated files are removed.\n"
        "Uninstall never accepts install-only routing, Codex, or role options.\n"
        "--dry-run prints normalized homes and exact effects without any writes.\n"
        "Options: --target TARGET, --all, --home TARGET=PATH, --dry-run, --help\n"
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
    )


def _emit_request(
    stderr: TextIO,
    request: Request,
    code: DiagnosticCode,
    *,
    phase: str,
    status: str,
) -> bool:
    return _emit(
        stderr,
        code,
        operation=request.operation,
        phase=phase,
        status=status,
        targets=request.targets,
        homes=tuple(request.homes[target] for target in request.targets),
    )


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
        if set(transaction_journals) != set(participants):
            missing = set(participants) - set(transaction_journals)
            if missing:
                names = ", ".join(
                    target.value
                    for target in sorted(missing, key=lambda item: item.value)
                )
                raise ValueError(
                    f"recovery participant journals are incomplete: {names}"
                )
            raise ValueError("recovery participant journal mapping is not exact")
        group_homes = {target: homes[target] for target in participants}
        group_journals: list[Journal] = []
        for target in participants:
            participant = journals.get(target)
            if participant is None:
                raise ValueError(f"missing participant journal for {target.value}")
            group_journals.append(participant)
        ordered = tuple(group_journals)
        validate_transaction_commitment(ordered, group_homes)
        groups.append((group_homes, ordered))
    return tuple(groups)


def _recovery_action(journals: tuple[Journal, ...]) -> str:
    """Classify a validated pending group as cleanup or rollback."""

    statuses = {
        operation.status for journal in journals for operation in journal.operations
    }
    complete = all(journal.rollback_status == "complete" for journal in journals)
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


def _run_mutating_locked(
    request: Request,
    *,
    repo_root: Path,
    stdout: TextIO,
    stderr: TextIO,
    failure_injector: FailureInjector | None,
) -> int:
    """Run recovery, planning, preparation, apply, and cleanup in one lock scope."""

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
    except Exception:
        _emit(
            stderr,
            DiagnosticCode.CLI_INVALID,
            operation=operation,
            phase="cli",
            status="invalid",
        )
        return EXIT_CLI_ERROR

    if not request.dry_run:
        return _run_mutating_locked(
            request,
            repo_root=repo_root,
            stdout=stdout,
            stderr=stderr,
            failure_injector=failure_injector,
        )

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
        plan = _plan(request, repo_root)
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
