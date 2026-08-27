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
from .errors import (
    CliError,
    PiPackageError,
    ValidationBlockedError,
    sanitize_pi_context,
)
from .locks import locked_target_homes
from .models import Journal, PiExternalPlan, PiInstallPlan, Request, Target
from .paths import normalized_absolute
from .pi_package import (
    PiPackageEvidence,
    PiPackageReceipt,
    PiRuntimeEvidence,
    inspect_pi_package_state,
    inspect_pi_package_store_identity,
    install_pi_package_external,
    load_pi_package_policy,
    pi_package_policy_hash,
    store_pi_package_receipt,
    validate_pi_executable,
    validate_pi_package_receipt,
    validate_pi_version_evidence,
)
from .pi_package import remove_pi_package as _remove_pi_package
from .planning import (
    RecoverySummary,
    TargetPlan,
    TransactionPlan,
    preflight_install,
    preflight_uninstall,
    render_plan,
    render_plan_json,
    validate_project_root,
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


def _plan(request: Request, repo_root: Path) -> TransactionPlan | PiInstallPlan:
    if request.operation == "install":
        # The command's explicit repository root is also its project-resource
        # discovery root.  Passing it through keeps Pi planning independent of
        # ambient cwd while preserving the existing embedding seam, where
        # callers can invoke ``preflight_install(..., project_root=...)``
        # directly with a different validated project root.
        return preflight_install(repo_root, request, project_root=repo_root)
    return preflight_uninstall(repo_root, request)


def install_pi_package(
    executable: Path | PiRuntimeEvidence,
    agent_dir: Path,
    consent_third_party_code: bool,
    consent_network: bool,
) -> PiPackageReceipt:
    """Run the external Pi install phase without recording ownership.

    ``PiExternalPlan`` intentionally carries the executable path as a public
    plan value.  Convert it to trusted runtime evidence at the execution
    boundary, then use the no-receipt package primitive.  Keeping this small
    seam in the orchestrator also gives tests a precise phase-injection point.
    """

    runtime = executable
    if type(runtime) is not PiRuntimeEvidence:
        if not isinstance(runtime, Path):
            raise PiPackageError("PI_EXECUTABLE_INVALID")
        try:
            runtime = validate_pi_executable(runtime, agent_dir=agent_dir, execute=True)
        except PiPackageError:
            raise
        except (OSError, ValueError, RuntimeError) as exc:
            raise PiPackageError("PI_EXECUTABLE_INVALID") from exc
    return install_pi_package_external(
        runtime,
        agent_dir,
        consent_third_party_code,
        consent_network,
    )


def verify_pi_install_postcondition(
    external: PiExternalPlan, receipt: PiPackageReceipt
) -> None:
    """Re-check package, policy inventory, and project-root postconditions.

    This is intentionally the small Plan 1 contract.  Effective project
    discovery and override analysis belongs to the later effective-catalog
    phase; here we only prove that the reviewed package and bundled inventory
    still match the pinned policy before ownership becomes durable.
    """

    if type(external) is not PiExternalPlan or type(receipt) is not PiPackageReceipt:
        raise TypeError("Pi install postcondition arguments are invalid")
    evidence = inspect_pi_package_state(external.agent_dir)
    verify_pi_package_postcondition(external, evidence)
    policy = load_pi_package_policy()
    source = policy.get("source")
    remove_source = policy.get("removeSource")
    if (
        type(source) is not str
        or type(remove_source) is not str
        or receipt.operation != "install"
        or not receipt.created_exact_entry
        or receipt.source != source
        or receipt.remove_source != remove_source
        or receipt.package_policy_hash != pi_package_policy_hash()
        or receipt.settings_before_hash != external.before.settings_hash
        or receipt.settings_after_hash != evidence.settings_hash
        or receipt.package_manifest_hash != evidence.manifest_hash
    ):
        raise ValueError("Pi package receipt postcondition is invalid")


def verify_pi_package_postcondition(
    external: PiExternalPlan, package: PiPackageEvidence
) -> None:
    """Prove the reviewed Pi package is still exact before local apply."""

    if type(external) is not PiExternalPlan or type(package) is not PiPackageEvidence:
        raise TypeError("Pi package postcondition arguments are invalid")
    if validate_project_root(external.project_root) != external.project_root:
        raise ValueError("Pi project root changed during package phase")
    policy = load_pi_package_policy()
    from .pi_catalog import PI_BUNDLED_ROLES

    if policy.get("bundledAgents") != list(PI_BUNDLED_ROLES):
        raise ValueError("Pi bundled inventory policy is invalid")
    if package.status != "exact" or not package.package_identity_valid:
        raise ValueError("Pi package postcondition is not exact")


def _rendered_pi_contracts(plan: TransactionPlan) -> Mapping[str, object]:
    """Parse the rendered Pi agent bytes supplied to the effective evaluator."""

    from .pi_catalog import PI_DEFAULT_ROLES, PI_OPTIONAL_ROLES, validate_pi_agent

    roles = frozenset(PI_DEFAULT_ROLES + PI_OPTIONAL_ROLES)
    rendered: dict[str, object] = {}
    for target_plan in plan.targets:
        if target_plan.target is not Target.PI:
            continue
        for operation in target_plan.operations:
            if operation.identifier not in roles or operation.content is None:
                continue
            rendered[operation.identifier] = validate_pi_agent(
                operation.identifier,
                operation.content,
                allow_rendered_extension=True,
            )
    # A clean reinstall may have no file operations at all.  Planning retains
    # validated, rendered source bytes as private in-memory evidence so the
    # effective evaluator still receives the complete contract set.
    for source in plan.sources:
        if source.identifier not in roles or source.content is None:
            continue
        rendered.setdefault(
            source.identifier,
            validate_pi_agent(
                source.identifier,
                source.content,
                allow_rendered_extension=True,
            ),
        )
    if not rendered:
        raise ValueError("Pi rendered contract evidence is unavailable")
    return rendered


def verify_pi_effective_postcondition(
    external: PiExternalPlan,
    local_plan: TransactionPlan,
    package: PiPackageEvidence,
) -> None:
    """Evaluate Pi's effective catalog before taking package ownership.

    Task 5 owns the evaluator. Until that module is present, this seam is
    deliberately fail-closed: a package receipt and local repository apply
    must never proceed on the assumption that effective discovery was safe.
    """

    if type(external) is not PiExternalPlan or type(package) is not PiPackageEvidence:
        raise TypeError("Pi effective postcondition arguments are invalid")
    if type(local_plan) is not TransactionPlan:
        raise TypeError("Pi effective local plan is invalid")
    try:
        from .pi_effective import inspect_effective_catalog
    except (ImportError, AttributeError) as exc:
        raise ValueError("Pi effective catalog evaluator is unavailable") from exc
    if validate_project_root(external.project_root) != external.project_root:
        raise ValueError("Pi project root changed during effective verification")
    try:
        result = inspect_effective_catalog(
            external.agent_dir,
            _rendered_pi_contracts(local_plan),
            package,
            project_root=external.project_root,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("Pi effective catalog verification failed") from exc
    conflicts = getattr(result, "conflicts", None)
    if type(conflicts) is not tuple or conflicts:
        raise ValueError("Pi effective catalog verification found conflicts")


def remove_pi_package(
    executable: Path | PiRuntimeEvidence,
    agent_dir: Path,
    receipt: PiPackageReceipt,
) -> PiPackageReceipt:
    """Run explicit Pi package removal after the local phase succeeds."""

    runtime = executable
    if type(runtime) is not PiRuntimeEvidence:
        if not isinstance(runtime, Path):
            raise PiPackageError("PI_EXECUTABLE_INVALID")
        try:
            runtime = validate_pi_executable(runtime, agent_dir=agent_dir, execute=True)
        except PiPackageError:
            raise
        except (OSError, ValueError, RuntimeError) as exc:
            raise PiPackageError("PI_EXECUTABLE_INVALID") from exc
    return _remove_pi_package(runtime, agent_dir, receipt)


def _external_plan(plan: object) -> object | None:
    """Return a Pi external phase only for the typed composite install plan."""

    if not isinstance(plan, PiInstallPlan):
        return None
    if not isinstance(plan.external, PiExternalPlan):
        raise TypeError("Pi external plan is invalid")
    return plan.external


def _local_plan(plan: object) -> TransactionPlan:
    """Unwrap the repository transaction from a composite Pi plan."""

    local = plan.local if isinstance(plan, PiInstallPlan) else plan
    if not isinstance(local, TransactionPlan):
        raise TypeError("local transaction plan is invalid")
    return local


def _pi_phase_failure(
    request: Request,
    stderr: TextIO,
    *,
    phase: str,
    code: str | None = None,
    safe_identifier: str = "pi-subagents",
) -> int:
    """Emit one stable Pi code without exception or child output."""

    selected = code or "PI_PACKAGE_PHASE_FAILED"
    try:
        context = sanitize_pi_context(
            selected,
            target="pi",
            phase=phase,
            safe_identifier=safe_identifier,
            normalized_home="home-1",
        )
        diagnostic_code = DiagnosticCode(selected)
    except (TypeError, ValueError):
        context = {
            "target": "pi",
            "phase": phase,
            "identifier": "unknown",
            "home": "home-1",
        }
        diagnostic_code = DiagnosticCode.PI_PACKAGE_PHASE_FAILED
    emit_diagnostic(
        stderr,
        diagnostic_code,
        (context["target"],),
        (context["home"],),
        request.operation,
        context["phase"],
        "failed",
    )
    return EXIT_PREFLIGHT_ERROR if phase == "preflight" else EXIT_APPLY_ERROR


def _pi_code(exc: BaseException, *, fallback: str) -> str:
    """Map private Pi exceptions to the public fixed code vocabulary."""

    code = getattr(exc, "code", None)
    code = {
        "PI_PACKAGE_CONFLICT": "PI_PACKAGE_DRIFT",
        "PI_PACKAGE_COMMAND": "PI_PACKAGE_PHASE_FAILED",
    }.get(code, code)
    if code in {item.value for item in DiagnosticCode if item.name.startswith("PI_")}:
        return code
    return fallback


class ConcurrentDryRunChangeError(RuntimeError):
    """Raised when the two lock-free dry-run evidence collections disagree."""


def _evidence_fingerprint(value: object) -> tuple[object, ...] | None:
    fields = ("device", "inode", "size", "nlink", "mode", "sha256")
    if not all(hasattr(value, field) for field in fields):
        return None
    return tuple(getattr(value, field) for field in fields)


def _external_fingerprint(plan: object) -> tuple[object, ...] | None:
    """Capture only stable, non-content Pi package evidence for dry runs."""

    if not isinstance(plan, PiInstallPlan):
        return None
    external = plan.external
    before = external.before
    # The public evidence intentionally omits race-only package-store data;
    # include the private identity proof in the dry-run comparison so an
    # equivalent directory replacement cannot pass as unchanged.
    store_identity = inspect_pi_package_store_identity(external.agent_dir)
    receipt = external.removal_receipt
    receipt_fingerprint = None
    if receipt is not None:
        receipt_fingerprint = (
            receipt.operation,
            receipt.source,
            receipt.remove_source,
            receipt.settings_before_hash,
            receipt.settings_after_hash,
            receipt.package_manifest_hash,
            receipt.package_policy_hash,
            receipt.created_exact_entry,
        )
    return (
        external.action,
        str(normalized_absolute(external.agent_dir)),
        str(normalized_absolute(external.project_root)),
        external.package_source,
        before.status,
        before.exact_pinned_entry,
        before.settings_hash,
        before.installed_lock_root_hash,
        before.manifest_hash,
        before.package_identity_valid,
        store_identity,
        receipt_fingerprint,
    )


def _plan_fingerprint(plan: object) -> tuple[object, ...]:
    composite = plan
    plan = _local_plan(plan)
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
    return (plan.operation, tuple(targets), sources, _external_fingerprint(composite))


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
) -> tuple[TransactionPlan | PiInstallPlan, tuple[object, ...]]:
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
) -> TransactionPlan | PiInstallPlan:
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
            except PiPackageError as exc:
                return _finish(
                    _pi_phase_failure(
                        request,
                        stderr,
                        phase="preflight",
                        code=_pi_code(exc, fallback="PI_PACKAGE_DRIFT"),
                    )
                )
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
                local_plan = _local_plan(plan)
                rendered = render_plan(local_plan)
                if not _write_output(stdout, rendered):
                    raise OSError("preflight output unavailable")
                has_conflicts = any(target.conflicts for target in local_plan.targets)
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

            external = _external_plan(plan)
            if request.operation == "install" and external is not None:
                action = getattr(external, "action", None)
                if action == "install" and not (
                    request.consent_third_party_code and request.consent_network
                ):
                    return _finish(
                        _pi_phase_failure(
                            request, stderr, phase="package", code="PI_CONSENT_REQUIRED"
                        )
                    )
                if action == "none":
                    try:
                        # An exact package still requires fresh executable
                        # evidence before repository-owned changes are applied.
                        validate_pi_executable(
                            external.executable,
                            agent_dir=external.agent_dir,
                            execute=True,
                        )
                    except PiPackageError as exc:
                        return _finish(
                            _pi_phase_failure(
                                request,
                                stderr,
                                phase="package",
                                code=_pi_code(exc, fallback="PI_RUNTIME_INCOMPATIBLE"),
                            )
                        )
                    except (OSError, ValueError, RuntimeError):
                        return _finish(
                            _pi_phase_failure(
                                request,
                                stderr,
                                phase="package",
                                code="PI_EXECUTABLE_INVALID",
                            )
                        )
                try:
                    if action == "install":
                        receipt = install_pi_package(
                            external.executable,
                            external.agent_dir,
                            request.consent_third_party_code,
                            request.consent_network,
                        )
                    elif action == "none":
                        receipt = None
                    else:
                        return _finish(
                            _pi_phase_failure(
                                request,
                                stderr,
                                phase="package",
                                code="PI_PACKAGE_DRIFT",
                            )
                        )
                except PiPackageError as exc:
                    return _finish(
                        _pi_phase_failure(
                            request,
                            stderr,
                            phase="package",
                            code=_pi_code(exc, fallback="PI_PACKAGE_PHASE_FAILED"),
                        )
                    )
                except (OSError, ValueError, RuntimeError):
                    return _finish(
                        _pi_phase_failure(
                            request,
                            stderr,
                            phase="package",
                            code="PI_PACKAGE_PHASE_FAILED",
                        )
                    )
                try:
                    if receipt is not None:
                        verify_pi_install_postcondition(external, receipt)
                    package = inspect_pi_package_state(external.agent_dir)
                    verify_pi_package_postcondition(external, package)
                except (OSError, ValueError, RuntimeError):
                    return _finish(
                        _pi_phase_failure(
                            request,
                            stderr,
                            phase="package",
                            code="PI_PACKAGE_DRIFT",
                        )
                    )
                try:
                    verify_pi_effective_postcondition(external, local_plan, package)
                except ValueError as exc:
                    code = (
                        "PI_CATALOG_CONFLICT"
                        if "conflict" in str(exc).casefold()
                        else "PI_CATALOG_PHASE_FAILED"
                    )
                    return _finish(
                        _pi_phase_failure(request, stderr, phase="catalog", code=code)
                    )
                except (OSError, RuntimeError):
                    return _finish(
                        _pi_phase_failure(
                            request,
                            stderr,
                            phase="catalog",
                            code="PI_CATALOG_PHASE_FAILED",
                        )
                    )
                if action == "install":
                    try:
                        # Ownership becomes durable only after all external
                        # postconditions have succeeded and remains outside the
                        # local journal.
                        store_pi_package_receipt(
                            external.agent_dir,
                            receipt,
                            expected_evidence=package,
                        )
                        package = inspect_pi_package_state(external.agent_dir)
                        verify_pi_package_postcondition(external, package)
                        if (
                            validate_pi_package_receipt(
                                external.agent_dir, package, require_current=True
                            )
                            != receipt
                        ):
                            raise ValueError(
                                "Pi package receipt postcondition is not durable"
                            )
                    except (OSError, ValueError, RuntimeError):
                        return _finish(
                            _pi_phase_failure(
                                request,
                                stderr,
                                phase="package",
                                code="PI_RECEIPT_INVALID",
                            )
                        )
            try:
                apply_transaction(local_plan, failure_injector=failure_injector)
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
                has_conflicts = any(target.conflicts for target in local_plan.targets)
                if request.operation == "uninstall" and has_conflicts:
                    for target in local_plan.targets:
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

            if (
                request.operation == "uninstall"
                and external is not None
                and getattr(external, "action", None) == "remove"
            ):
                receipt = getattr(external, "removal_receipt", None)
                if type(receipt) is not PiPackageReceipt:
                    return _finish(
                        _pi_phase_failure(
                            request,
                            stderr,
                            phase="package",
                            code="PI_PACKAGE_PHASE_FAILED",
                        )
                    )
                try:
                    remove_pi_package(
                        external.executable,
                        external.agent_dir,
                        receipt,
                    )
                except Exception:
                    # Local files have already been committed.  Preserve the
                    # package and receipt when optional removal fails.
                    return _finish(
                        _pi_phase_failure(
                            request,
                            stderr,
                            phase="package",
                            code="PI_PACKAGE_PHASE_FAILED",
                        )
                    )
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

    if Target.PI in request.targets and Target.PI.value in request.client_versions:
        try:
            validate_pi_version_evidence(request.client_versions[Target.PI.value])
        except (PiPackageError, ValueError, RuntimeError):
            return _pi_phase_failure(
                request,
                stderr,
                phase="preflight",
                code="PI_RUNTIME_INCOMPATIBLE",
            )

    # Preserve the recovery validator's fail-closed classification before the
    # lock-free double collection.  In particular, unsafe home links are a
    # blocked validation state, not a generic planning rejection.
    try:
        _journal_groups(request)
    except (ValueError, OSError):
        _emit_request(
            stderr,
            request,
            DiagnosticCode.VALIDATION_BLOCKED,
            phase="recovery",
            status="blocked",
        )
        return EXIT_BLOCKED_VALIDATION

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
    except PiPackageError as exc:
        return _pi_phase_failure(
            request,
            stderr,
            phase="preflight",
            code=_pi_code(exc, fallback="PI_PACKAGE_DRIFT"),
        )
    except (ValueError, RuntimeError, OSError):
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

    runtime_evidence = (
        "caller-supplied"
        if Target.PI.value in request.client_versions
        else "maintained-matrix-only"
    )
    if _local_plan(plan).recovery.required and request.dry_run_format == "text":
        try:
            recovery = _local_plan(plan).recovery
            for target, home in zip(recovery.participants, recovery.homes, strict=True):
                if not emit_diagnostic(
                    stdout,
                    DiagnosticCode.RECOVERY_REQUIRED,
                    (target.value,),
                    (str(home),),
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
        if request.dry_run_format == "json":
            if Target.PI in request.targets:
                rendered = render_plan_json(
                    plan, runtime_version_evidence=runtime_evidence
                ).decode("utf-8")
            else:
                rendered = render_plan_json(plan).decode("utf-8")
        else:
            if Target.PI in request.targets:
                rendered = render_plan(plan, runtime_version_evidence=runtime_evidence)
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
    try:
        _post_render_plan, post_fingerprint = _collect_stable_dry_run_evidence(
            request, repo_root
        )
        if post_fingerprint != fingerprint:
            raise ConcurrentDryRunChangeError("dry-run evidence changed after render")
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
            raise OSError("dry-run output unavailable")
        has_conflicts = any(target.conflicts for target in _local_plan(plan).targets)
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
