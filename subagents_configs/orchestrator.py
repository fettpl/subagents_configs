"""Public command-line orchestration for the multi-client installer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal, TextIO

from .cli import parse_request
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
from .state import load_journal
from .targets import descriptor_for
from .transaction import (
    FailureInjector,
    IncompleteRollbackError,
    TransactionError,
    _recover_participants,
    _validate_transaction_commitment,
    apply_transaction,
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


def _print_error(
    stderr: TextIO,
    prefix: str,
    error: BaseException | None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Emit only a fixed diagnostic; exception text is never user output."""

    del error, environ
    return _write_output(stderr, f"error: {prefix}\n")


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
        _validate_transaction_commitment(ordered, group_homes)
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
        _recover_participants(homes)


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
    try:
        with locked_target_homes(homes, request.targets):
            try:
                groups = _journal_groups(request)
            except (ValueError, OSError):
                _print_error(stderr, "recovery validation blocked", None)
                return EXIT_BLOCKED_VALIDATION
            except Exception:
                _print_error(stderr, "recovery validation blocked", None)
                return EXIT_BLOCKED_VALIDATION
            try:
                _recover_groups(groups)
            except IncompleteRollbackError:
                _print_error(
                    stderr,
                    "recovery is incomplete; manual recovery is required",
                    None,
                )
                return EXIT_INCOMPLETE_ROLLBACK
            except (ValueError, OSError, TransactionError, RuntimeError):
                _print_error(
                    stderr, "recovery failed: recovery operation blocked", None
                )
                return EXIT_BLOCKED_VALIDATION
            except Exception:
                _print_error(
                    stderr, "recovery failed; rollback status is unknown", None
                )
                return EXIT_INCOMPLETE_ROLLBACK
            try:
                plan = _plan(request, repo_root)
            except ValidationBlockedError:
                _print_error(
                    stderr, "validation blocked: source validation failed", None
                )
                return EXIT_BLOCKED_VALIDATION
            except ValueError:
                _print_error(stderr, "preflight rejected", None)
                return EXIT_PREFLIGHT_ERROR
            except RuntimeError:
                _print_error(
                    stderr, "validation blocked: source validation failed", None
                )
                return EXIT_BLOCKED_VALIDATION
            except OSError:
                _print_error(stderr, "preflight rejected", None)
                return EXIT_PREFLIGHT_ERROR
            except Exception:
                _print_error(stderr, "preflight rejected: unexpected failure", None)
                return EXIT_PREFLIGHT_ERROR
            try:
                rendered = render_plan(plan)
                if not _write_output(stdout, rendered):
                    raise OSError("preflight output unavailable")
                has_conflicts = any(target.conflicts for target in plan.targets)
            except Exception:
                _print_error(stderr, "preflight output failed", None)
                return EXIT_PREFLIGHT_ERROR
            if request.operation == "install" and has_conflicts:
                try:
                    conflicted = ", ".join(
                        target.target.value
                        for target in plan.targets
                        if target.conflicts
                    )
                    _write_output(
                        stderr, f"error: managed conflict: targets={conflicted}\n"
                    )
                except Exception:
                    _write_output(stderr, "error: managed conflict\n")
                return EXIT_MANAGED_CONFLICT
            try:
                apply_transaction(plan, failure_injector=failure_injector)
            except IncompleteRollbackError:
                _print_error(stderr, "apply failed; rollback incomplete", None)
                return EXIT_INCOMPLETE_ROLLBACK
            except (TransactionError, OSError, ValueError):
                _print_error(stderr, "apply failed; rollback completed", None)
                return EXIT_APPLY_ERROR
            except Exception:
                _print_error(stderr, "apply failed; rollback completed", None)
                return EXIT_APPLY_ERROR
            try:
                has_conflicts = any(target.conflicts for target in plan.targets)
                if request.operation == "uninstall" and has_conflicts:
                    for target in plan.targets:
                        for conflict in target.conflicts:
                            if not _write_output(
                                stdout,
                                (
                                    f"unresolved: target={target.target.value} "
                                    f"{conflict}\n"
                                ),
                            ):
                                raise OSError("unresolved output unavailable")
                    return EXIT_UNRESOLVED_UNINSTALL
            except Exception:
                _print_error(stderr, "unresolved output failed", None)
                return EXIT_PREFLIGHT_ERROR
            return EXIT_SUCCESS
    except (ValueError, OSError):
        _print_error(stderr, "recovery validation blocked", None)
        return EXIT_BLOCKED_VALIDATION
    except Exception:
        _print_error(stderr, "recovery validation blocked", None)
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
        _print_error(stderr, "unsupported operation", None)
        return EXIT_CLI_ERROR
    if len(argv) == 1 and argv[0] == "--help":
        if not _write_output(stdout, HELP_TEXT[operation]):
            _print_error(stderr, "help output failed", None)
            return EXIT_PREFLIGHT_ERROR
        return EXIT_SUCCESS
    try:
        request = parse_request(operation, argv, environ)
    except CliError:
        _print_error(stderr, "invalid command line: invalid arguments", None)
        return EXIT_CLI_ERROR
    except Exception:
        _print_error(stderr, "invalid command line: unexpected failure", None)
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
        _print_error(stderr, "recovery validation blocked", None)
        return EXIT_BLOCKED_VALIDATION
    except Exception:
        _print_error(
            stderr,
            "recovery validation blocked: unexpected failure",
            None,
        )
        return EXIT_BLOCKED_VALIDATION

    if groups and request.dry_run:
        try:
            for homes, journals in groups:
                participants = ", ".join(target.value for target in homes)
                for target, home in homes.items():
                    line = (
                        f"recovery required: target={target.value} home={home} "
                        f"action={_recovery_action(journals)} "
                        f"transaction={journals[0].transaction_id} "
                        f"participants={participants}\n"
                    )
                    if not _write_output(stdout, line):
                        raise OSError("recovery output unavailable")
        except Exception:
            _print_error(stderr, "recovery output failed", None)
            return EXIT_PREFLIGHT_ERROR
        return EXIT_SUCCESS

    try:
        _recover_groups(groups)
    except IncompleteRollbackError:
        _print_error(
            stderr,
            "recovery is incomplete; manual recovery is required",
            None,
        )
        return EXIT_INCOMPLETE_ROLLBACK
    except (ValueError, OSError, TransactionError, RuntimeError):
        _print_error(stderr, "recovery failed: recovery operation blocked", None)
        return EXIT_BLOCKED_VALIDATION
    except Exception:
        _print_error(
            stderr,
            "recovery failed; rollback status is unknown",
            RuntimeError("unexpected failure"),
        )
        return EXIT_INCOMPLETE_ROLLBACK

    try:
        plan = _plan(request, repo_root)
    except ValidationBlockedError:
        _print_error(stderr, "validation blocked: source validation failed", None)
        return EXIT_BLOCKED_VALIDATION
    except ValueError:
        _print_error(stderr, "preflight rejected", None)
        return EXIT_PREFLIGHT_ERROR
    except RuntimeError:
        _print_error(stderr, "validation blocked: source validation failed", None)
        return EXIT_BLOCKED_VALIDATION
    except OSError:
        _print_error(stderr, "preflight rejected", None)
        return EXIT_PREFLIGHT_ERROR
    except Exception:
        _print_error(stderr, "preflight rejected: unexpected failure", None)
        return EXIT_PREFLIGHT_ERROR

    try:
        rendered = render_plan(plan)
    except Exception:
        _print_error(stderr, "preflight output failed", None)
        return EXIT_PREFLIGHT_ERROR
    if not _write_output(stdout, rendered):
        _print_error(stderr, "preflight output failed", None)
        return EXIT_PREFLIGHT_ERROR
    try:
        has_conflicts = any(target.conflicts for target in plan.targets)
    except Exception:
        _print_error(stderr, "preflight output failed", None)
        return EXIT_PREFLIGHT_ERROR
    if request.operation == "install" and has_conflicts:
        try:
            conflicted = ", ".join(
                target.target.value for target in plan.targets if target.conflicts
            )
            conflict_line = f"error: managed conflict: targets={conflicted}\n"
        except Exception:
            conflict_line = "error: managed conflict\n"
        _write_output(stderr, conflict_line)
        return EXIT_MANAGED_CONFLICT
    if request.dry_run:
        return EXIT_SUCCESS

    try:
        apply_transaction(plan, failure_injector=failure_injector)
    except IncompleteRollbackError:
        _print_error(stderr, "apply failed; rollback incomplete", None)
        return EXIT_INCOMPLETE_ROLLBACK
    except (TransactionError, OSError, ValueError):
        _print_error(stderr, "apply failed; rollback completed", None)
        return EXIT_APPLY_ERROR
    except Exception:
        _print_error(stderr, "apply failed; rollback completed", None)
        return EXIT_APPLY_ERROR

    try:
        has_conflicts = any(target.conflicts for target in plan.targets)
    except Exception:
        _print_error(stderr, "unresolved output failed", None)
        return EXIT_PREFLIGHT_ERROR
    if request.operation == "uninstall" and has_conflicts:
        try:
            for target in plan.targets:
                for conflict in target.conflicts:
                    line = f"unresolved: target={target.target.value} {conflict}\n"
                    if not _write_output(stdout, line):
                        raise OSError("unresolved output unavailable")
        except Exception:
            _print_error(stderr, "unresolved output failed", None)
        return EXIT_UNRESOLVED_UNINSTALL
    return EXIT_SUCCESS
