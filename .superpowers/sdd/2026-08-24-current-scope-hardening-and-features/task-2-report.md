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

## Fix round 1/5 — identity-bound cleanup and late-read boundary

Status: complete

Commit: `fix: bind cleanup to validated transaction identities` (final fix-round commit)

### RED / GREEN evidence

- RED (adversarial cleanup tests):
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation tests.test_planning -v`
  initially exposed journal cleanup lacking the required identity argument and directory replacement being treated as installer-owned.
- RED (write-identity regression):
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation tests.test_transaction_install -q`
  observed 70 tests with 56 `OSError: [Errno 9] Bad file descriptor` errors after attempting to read write-only descriptors, plus two cascading cleanup/preparation failures.
- GREEN focused transaction suites:
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation tests.test_transaction_install -q`
  — 70 tests passed.
- GREEN exact brief suite:
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation tests.test_planning tests.test_full_install_matrix tests.test_cli_integration -v`
  — 75 tests passed.
- GREEN full discovery:
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q`
  — 383 tests passed.
- Static checks passed: `.venv/bin/ruff check subagents_configs tests`, `.venv/bin/ruff format --check subagents_configs tests`, and `git diff --check`.

### Changed files in this fix round

- `subagents_configs/filesystem.py`
- `subagents_configs/transaction.py`
- `tests/test_transaction_preparation.py`
- `tests/test_transaction_install.py`
- `tests/test_full_install_matrix.py`

### Requirement mapping

- Journal cleanup now requires validated `IdentityEvidence` for the journal and every referenced backup, verifies identity immediately before unlink, and fails closed for missing/replaced/changed artifacts.
- Journal restoration after unlink or directory-sync failure uses expected-absence CAS only; an attacker-created replacement is never overwritten. Fixed typed diagnostics preserve the primary failure and avoid raw underlying exception interpolation.
- Read-only evidence captures source bytes, backup bytes, validation, identity, and derived backup inputs before `_prepare`; `_transaction_backup` consumes those precomputed bytes and performs no late source/backup read.
- Directory ownership records only exact identities returned from this invocation’s directory creation; cleanup checks identity and removes in reverse order, never claiming a concurrent/pre-existing replacement.
- Write primitives return exact identity evidence from the still-open descriptor using known payload bytes, avoiding a post-close capture race. Preparation records returned marker/journal identities directly; uncertain post-replace writes are retained as recovery evidence.
- `OwnedArtifact.identity` uses the concrete `IdentityEvidence | DirectoryIdentity` union. Task 1 six-field CAS/schema contracts, persistent lock anchors, lock lifetime, dry-run boundary, and strict matrix snapshots remain unchanged.

### Self-review

- Added adversarial coverage for replaced/missing journals and backups, restoration replacement races, directory ownership races, and late backup-read zero-write behavior.
- Recovery, rollback, apply, and cleanup callers thread the identity captured at validation or write time. Cleanup-only errors remain typed and cannot replace the primary sanitized diagnostic.
- The post-replace journal-write failure test now asserts the safe outcome: a journal whose exact identity was not returned is retained rather than guessed at and deleted.
- No Task 9 strict dry-run, Pi, network, package-manager, service, telemetry, or unrelated behavior was added.

### Concerns

- A write wrapper that reports failure after replacement without returning identity intentionally leaves its journal for recovery; this is the fail-closed behavior required when cleanup ownership cannot be proved.
- Existing internal exceptions remain chained for debugging, while public CLI diagnostics stay fixed and sanitized.

## Fix round 2/5 — recovery authority, precomputed derivations, and directory detach

Status: complete

Commit: `fix: preserve validated recovery identities and atomic cleanup` (final fix-round commit)

### RED / GREEN evidence

- RED recovery race:
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation.TransactionPreparationTests.test_recovery_keeps_replacement_after_validation_before_cleanup -v`
  failed because `_recover_single` recaptured a replacement journal as fresh cleanup authority and did not raise.
- RED digest boundary:
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation.TransactionPreparationTests.test_prepare_consumes_precomputed_backup_derivations -v`
  failed with `AssertionError: backup digest computed after preparation` from `_ensure_permanent_backup`.
- RED directory race:
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation.TransactionPreparationTests.test_directory_cleanup_preserves_replacement_during_atomic_detach -v`
  failed because pathname `rmdir` removed the replacement.
- GREEN focused suite:
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation tests.test_planning tests.test_full_install_matrix tests.test_cli_integration -q`
  — 79 tests passed.
- GREEN full discovery:
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q`
  — 387 tests passed.
- Static checks passed: `.venv/bin/ruff check subagents_configs tests`, `.venv/bin/ruff format --check subagents_configs tests`, and `git diff --check`.

### Changed files in this fix round

- `subagents_configs/filesystem.py`
- `subagents_configs/transaction.py`
- `tests/test_transaction_preparation.py`

### Requirement mapping

- Single-home recovery now carries the initial journal identity captured before/after load through verification and cleanup; participant recovery does the same for every mapping entry. Fresh journal recapture cannot authorize deletion after validation.
- Backup digest checks and backup-source derivations are completed in `_collect_readonly_evidence`; `_prepare`, `_ensure_permanent_backup`, and `_transaction_backup` consume expected/precomputed values without post-artifact digest computation.
- Directory cleanup opens and verifies the exact directory identity, atomically detaches it to an unpredictable descriptor-relative quarantine name, verifies the detached identity, and only then removes it. A replacement at the managed path remains intact.
- Added adversarial tests for single-home and participant journal replacement races, late derivation guards, and replacement during directory cleanup. Existing lock lifetime, six-field CAS/schema, dry-run boundary, and strict matrix behavior remain intact.

### Self-review and concerns

- Recovery retains the attacker replacement and raises a typed cleanup error; participant cleanup cannot use a post-validation journal identity.
- The quarantine path is random and descriptor-relative; if detach identity or removal cannot be proved, cleanup restores when safe or leaves evidence in place.
- No Task 9 strict dry-run, Pi, network, or unrelated behavior was added.
