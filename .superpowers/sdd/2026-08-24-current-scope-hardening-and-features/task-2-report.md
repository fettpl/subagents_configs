# Task 2 self-review — zero-write preparation and lock lifetime

Status: complete

Commit: `fix: separate preflight evidence from transaction preparation` (this task commit)

## RED / GREEN evidence

- RED: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation tests.test_planning -v`
  - observed missing `_collect_readonly_evidence` and preparation/cleanup behavior failures.
- GREEN: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation tests.test_planning tests.test_full_install_matrix tests.test_cli_integration -v`
  - 69 tests passed.
- Full suite: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q`
  - 377 tests passed.
- Static checks: `.venv/bin/ruff check subagents_configs tests`, `.venv/bin/ruff format --check subagents_configs tests`, and `git diff --check` passed.

## Changed files

- `subagents_configs/transaction.py`
- `subagents_configs/orchestrator.py`
- `subagents_configs/locks.py`
- `tests/test_transaction_preparation.py`
- `tests/test_full_install_matrix.py`

## Requirement mapping

- Read-only preflight is represented by `_collect_readonly_evidence`; all operation identity checks complete before `_prepare` creates state, backup, managed-parent, commitment, or journal artifacts.
- Preparation tracks immutable `OwnedArtifact` records with creation identity and removes only matching artifacts in reverse order. Persistent lock anchors are not owned or cleaned by preparation.
- Non-dry orchestration holds all selected target locks through journal discovery, recovery, planning, preparation, apply/rollback, and journal cleanup. Nested transaction calls reuse only a context holding every requested home.
- Journal and backup removal uses six-field evidence through compare-and-swap and retains journal evidence when synchronization or cleanup cannot be proved.
- Cleanup-only failures retain the primary operation diagnostic class/status boundary; raw cleanup exception text is not emitted.
- Existing Task 1 schema-v2 and six-field CAS contracts remain in use.
- Strict matrix snapshots explicitly include only the persistent lock anchor as synchronization substrate; no preparation state is accepted after read-only failure.

## Self-review

- Failure paths were exercised at late evidence validation, journal preparation, operation injection, rollback, and cleanup synchronization points.
- Cleanup is fail-closed for missing, changed, symlinked, or attacker-replaced artifacts; pre-existing state/backups and unrelated files remain untouched.
- The mutating orchestration path is intentionally separate from the existing dry-run path; no Task 9 double-evidence behavior was introduced.
- No Pi, network, package-manager, service, telemetry, or unrelated target behavior was added.

## Concerns / follow-up

- The existing transaction diagnostic exception strings retain internal exception chaining for callers/tests, while CLI output remains fixed and sanitized. A later diagnostics task can centralize the typed public rendering without changing this transaction boundary.
- The task adds three focused tests, bringing discovery from the 374-test baseline to 377 tests.
