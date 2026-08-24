# Current-Scope Hardening and Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the current Codex, OpenCode, and Claude Code installer against concurrent mutation, validation escape, state ambiguity, and diagnostic leakage, then add four strictly read-only/explicit CLI extensions without changing the product boundary.

**Architecture:** Keep one cohesive local Python installer with the existing side-effect-free planning, journaled transaction, native catalog, and isolated-validation boundaries. Add descriptor-backed locking and descriptor-relative compare-and-swap at the filesystem boundary, make one typed target capability registry authoritative for catalogs and lifecycle seams, and expose the new dry-run, compatibility, profile, and policy-diff behavior through the existing command entry points. All target selection, profile, and catalog inputs remain untrusted data and are validated before any write.

**Tech Stack:** Python 3.11, 3.12, 3.13, and 3.14; Python standard library (`unittest`, `tomllib`, `json`, `fcntl`/`msvcrt`-guarded platform code); PyYAML 6.0.3; Ruff 0.16.3; POSIX `sh`; GitHub Actions; macOS `/usr/bin/sandbox-exec`; Linux `/usr/bin/bwrap` or `/bin/bwrap`; ShellCheck.

**Spec:** `docs/superpowers/specs/2026-08-24-repository-hardening-features-and-pi-design.md`

## Global Constraints

- Supported runtime targets remain exactly `codex`, `opencode`, and `claude-code`; Pi is represented only as a future row in the compatibility contract and is not implemented by this plan.
- Runtime code never downloads, installs, invokes package managers, invokes network services, executes prompts, starts a daemon/service, writes a dashboard/telemetry system, or creates a generic plugin framework.
- All repository files, prompts, client output, project instructions, state, plans, fixtures, and subagent output are untrusted data; no artifact or diagnostic contains credentials, raw environment values, private file contents, full prompts, or provider transcripts.
- Every selected target completes read-only evidence validation before preparation creates a directory, journal, backup, or target file. For mutating commands, lock acquisition is the separate synchronization precondition and may create only its private persistent lock descriptor. Preparation records each artifact it owns and removes only those artifacts on preparation failure.
- Non-dry planning, recovery, apply, and journal cleanup hold descriptor-backed locks for every selected target home; multi-target locks use canonical order `(codex, opencode, claude-code)` and release only after journal cleanup. Strict dry-run never opens/creates a lock anchor or makes another filesystem mutation: it captures the complete read-only evidence set twice around rendering and fails with `PREFLIGHT_CONCURRENT_CHANGE` unless both snapshots are identical.
- Lock pathnames are persistent synchronization anchors. They are opened without following links, their identity/mode/ownership is validated, and they are never unlinked by normal cleanup, rollback, uninstall, or preparation-failure handling; unlinking could let a third process lock a different inode.
- Replace, unlink, chmod, rollback, and restore use descriptor-relative compare-and-swap; expected device, inode, size, link count, content hash, and mode must match at the mutation boundary and are rechecked after mutation.
- Existing fail-closed recovery, participant/commitment validation, ownership and conservative-uninstall rules, symlink/hard-link checks, private modes, containment checks, and sanitized error precedence remain mandatory.
- Environment, cache, credential, and excluded path names compare with `casefold()`; this includes mixed-case `.env`, `.env.*`, `.envrc`, cache directories, and credential-store paths.
- Real Bubblewrap and Seatbelt smoke tests prove network denial, host-read denial, snapshot reads, private temporary writes, child status propagation, and checkout immutability; unsupported or unverified backends fail closed.
- The Claude Code validator has a technical `PreToolUse` command gate; prompt wording is never treated as enforcement. Explorer/reviewer/validator permissions are explicitly negative-tested for every target and role.
- The target capability registry is authoritative for descriptor order, source formats, parsers, semantic validators, global-instruction behavior, optional blocks, runtime sources, and external lifecycle capabilities. Generated native catalogs remain checked in and reproducibly validated.
- State schema compatibility is defined and tested before schema version 2 is written. Hostile persisted state is decoded strictly; v1 is read/migrated only under exact evidence, unsupported versions fail closed, and no migration copies private content into metadata.
- Dependency requirement files use reviewed artifact hashes for every supported Python/platform artifact. Runtime and developer bootstraps are separate; runtime never installs dependencies.
- The canonical repository validation entry point uses fixed argv, never installs dependencies, and is invoked by contributor docs, CI, and release docs. CI runs equivalent coverage once, retains private homes/backend checks, and enforces a clean checkout.
- Diagnostics use typed stable codes and fixed safe context. They never print exception text, secret-bearing paths, package-manager output, environment values, raw source paths, or private contents.
- Every task uses stdlib `unittest`, writes failing tests first, runs focused tests and the relevant full suite, runs static/format checks and `git diff --check`, and ends with a reviewable commit containing only task files.
- Documentation and generated/catalog contract tests change in the same task as the behavior they describe; a later documentation task may consolidate prose but may not leave an earlier behavior commit undocumented.
- No task changes remotes, credentials, branch protection, publication settings, or release hosting. A license and private vulnerability channel are documented as release prerequisites, not configured through runtime code.
- This plan does not choose a license for the owner. Public redistribution remains technically and procedurally blocked until the owner separately approves exact license text and its SPDX identifier.

## File Map

Files are listed before the tasks so each reviewer can identify the intended boundary.

### Create

- `subagents_configs/locks.py` — descriptor-backed per-home lock acquisition and canonical multi-target ordering.
- `subagents_configs/diagnostics.py` — stable diagnostic codes, safe context schemas, and redacted rendering.
- `subagents_configs/state_schema.py`, `subagents_configs/recovery.py` — strict state codecs/migrations and the public recovery seam extracted from oversized modules without changing entry points.
- `subagents_configs/compatibility.py` — read-only client capability contract and maintained matrix loader.
- `subagents_configs/profiles.py` — strict JSON/TOML profile schema, validation, and request merge.
- `subagents_configs/catalog_policy.py` — normalized catalog snapshots and policy-diff report generation.
- `claude-code/hooks/code-validator-pretooluse.py` — target-native Claude `PreToolUse` technical command gate.
- `catalogs/codex.json`, `catalogs/opencode.json`, `catalogs/claude-code.json` — checked-in normalized catalog projections generated from the canonical registry.
- `catalogs/client-compatibility.json` — tested Codex/OpenCode/Claude matrix plus an explicitly unsupported Pi row.
- `requirements-runtime.lock`, `requirements-dev.lock` — hash-checked requirement sets for supported artifacts.
- `scripts/validate-repository.py` — canonical non-installing contributor/CI/release validation entry point.
- `scripts/generate-catalogs.py` — deterministic catalog renderer with explicit write and check modes.
- `scripts/bootstrap-developer.sh` — explicit developer-only bootstrap using pinned requirement files.
- `AGENTS.md` — repository-local contributor/agent guidance for trust boundaries, temporary homes, validation, and publication authorization.
- `docs/STATE_SCHEMA.md` — normative compatibility matrix for manifest/journal schema versions and migration/recovery behavior.
- `tests/test_locks.py`, `tests/test_diagnostics.py`, `tests/test_state_migrations.py`, `tests/test_validation_smoke.py`, `tests/test_claude_command_gate.py`, `tests/test_capabilities.py`, `tests/test_profiles.py`, `tests/test_compatibility.py`, `tests/test_policy_diff.py`, `tests/test_repository_validation.py` — focused contract/regression suites.

### Modify

- `subagents_configs/models.py`, `state.py`, `filesystem.py`, `transaction.py`, `orchestrator.py` — identity evidence, schema v2 migration, locking, CAS, preparation ownership, recovery, and public seams.
- `subagents_configs/targets.py`, `formats.py`, `planning.py`, `cli.py`, `__main__.py` — canonical capability registry, rendered-catalog validation, profiles, JSON dry-run, compatibility, and policy-diff dispatch.
- `scripts/validation_isolation/backend.py`, `environment.py`, `git_snapshot.py`, `runner.py`, `cli.py` — case-insensitive filters, cleanup precedence, and real backend evidence.
- `agents/*.toml`, `opencode/agents/*.md`, `claude-code/agents/*.md`, `rules/*.md`, `templates/*` — generated catalog/policy updates and explicit negative permissions; Claude validator hook configuration is added only through the managed target settings seam.
- `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, `.github/workflows/ci.yml` — hash-lock includes, Python 3.11–3.14 matrix, one validation invocation, macOS Seatbelt gate, and confined cache output.
- `README.md`, `SECURITY.md`, `docs/RELEASING.md` — bootstrap, trust boundary, recovery, dry-run, exit codes, compatibility prerequisites, license, private reporting, and client/backend support.

### Test/verification targets

- Existing `tests/test_transaction_install.py`, `tests/test_transaction_uninstall.py`, `tests/test_full_install_matrix.py`, `tests/test_planning.py`, `tests/test_state.py`, `tests/test_catalogs.py`, `tests/test_routing_policy.py`, `tests/test_cli.py`, `tests/test_cli_integration.py`, `tests/test_ci.py`, `tests/test_security_static.py`, and `tests/test_validation_*.py` receive focused additions in the same task as each behavior.
- `scripts/validate-catalogs.py`, `scripts/validate-repository.py`, `ruff`, `shellcheck`, `sh -n`, `compileall`, and the full `unittest` discovery suite are the final verification surfaces.

---

### Task 1: Lock, identity evidence, and state-schema migration boundary (SEC-01)

**Files:**
- Create: `subagents_configs/locks.py`, `docs/STATE_SCHEMA.md`, `tests/test_locks.py`, `tests/test_state_migrations.py`
- Modify: `subagents_configs/models.py`, `subagents_configs/state.py`, `subagents_configs/filesystem.py`, `subagents_configs/transaction.py`, `tests/test_transaction_install.py`, `tests/test_transaction_uninstall.py`, `tests/test_state.py`

**Interfaces:**
- Produces `IdentityEvidence(device: int, inode: int, size: int, nlink: int, mode: int, sha256: str)`, `capture_evidence(path: Path, label: str) -> IdentityEvidence | None`, `compare_and_swap(path: Path, before: IdentityEvidence | None, after_content: bytes | None, after_mode: int | None, action: Literal["create", "replace", "unlink", "chmod"]) -> IdentityEvidence | None`, and `locked_target_homes(homes: Mapping[Target, Path], targets: Sequence[Target]) -> ContextManager[None]`.
- Produces schema-v2 journal fields `expected_before_evidence` and `expected_after_evidence`, each either `null` or an object with exactly `device`, `inode`, `size`, `nlink`, `mode`, and `sha256`. `docs/STATE_SCHEMA.md` defines: v0 reject; v1 completed manifests migrate only under live evidence; v1 pending journals are inspect-only/manual recovery; v2 read/write; versions greater than 2 reject.
- Consumes existing `PlannedOperation`, `JournalOperation`, `Manifest`, and `Target` types; v1 state can be read only through an explicit migration path, never silently treated as v2 evidence.

- [ ] **Step 1: Write the RED lock/CAS and migration tests.**

  Add tests with `TemporaryDirectory()` that open two lock contexts and assert the second blocks until the first releases, that `(opencode, codex)` is rejected while `(codex, opencode)` succeeds, and that a file replacement fails after changing only inode, mode, size, nlink, or hash. Add JSON fixtures for schema 1, schema 2, schema 0, and schema 3; assert v1 manifests migrate only when exact hash/mode/path evidence is present, pending v1 journals are blocked for manual recovery, and unknown keys/types are rejected.

  ```python
  with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
      evidence = capture_evidence(home / "agents/code-explorer.toml", "target")
      with self.assertRaises(TransactionError):
          compare_and_swap(path, replace(evidence, inode=evidence.inode + 1), b"x", 0o600, "replace")
  self.assertEqual(migrate_state_schema(raw_v1, descriptor, home).schema_version, 2)
  ```

- [ ] **Step 2: Run the focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_locks tests.test_state_migrations -v`

  Expected: import/signature failures for the new lock/evidence interfaces and failures showing current hash/mode-only mutation accepts an inode or link-count change.

- [ ] **Step 3: Implement descriptor-backed locks and descriptor-relative evidence.**

  In `locks.py`, open `<home>/.subagents_configs.lock` with `O_NOFOLLOW|O_CREAT`, mode `0600`, acquire `fcntl.flock(LOCK_EX)` on POSIX, and keep the descriptor alive for the context. Sort requested targets by `DESCRIPTOR_ORDER`; reject duplicate/missing homes before opening any lock. In `filesystem.py`, open the parent directory with no-follow flags, `fstat` the target descriptor, hash bytes from that descriptor, and use `os.replace`/`os.unlink`/`os.fchmod` through the pinned parent only after all six evidence fields match. Return a fresh post-mutation `IdentityEvidence` and fail closed on any mismatch or replacement race.

- [ ] **Step 4: Add strict schema-v2 encoding/decoding and thread evidence through transactions.**

  Define `SCHEMA_VERSION = 2`, exact evidence JSON keys, `migrate_manifest_schema(raw, descriptor, home) -> Manifest`, and `inspect_legacy_journal(raw, descriptor, home) -> LegacyJournalEvidence`. Schema 1 manifests migrate by re-reading the managed path and proving stored hash/mode before writing v2; schema 1 journals never become `Journal`, remain diagnostic evidence only, and raise `IncompleteRollbackError` before mutation because they lack device/inode evidence. Update `_journal_operation`, `_planned_from_journal`, `_check_evidence`, `_apply_operation`, `_reverse_operation`, complete-journal verification, and participant recovery to call `compare_and_swap` with both before and after evidence. Do not put file bytes in the migration or journal, and keep `docs/STATE_SCHEMA.md` synchronized with executable fixture tests.

- [ ] **Step 5: Run the focused transaction suite and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_locks tests.test_state_migrations tests.test_state tests.test_transaction_install tests.test_transaction_uninstall -v`

  Expected: PASS with changed identity races returning the existing fail-closed transaction status, and no state file containing private content. Run `ruff check subagents_configs tests`, `ruff format --check subagents_configs tests`, and `git diff --check`; commit `fix: serialize transactions and require identity evidence`.

### Task 2: Zero-write preflight, preparation ownership, and cleanup-only failures (SEC-01, TEST-03)

**Files:**
- Create: `tests/test_transaction_preparation.py`
- Modify: `subagents_configs/transaction.py`, `subagents_configs/planning.py`, `subagents_configs/orchestrator.py`, `tests/test_planning.py`, `tests/test_full_install_matrix.py`, `tests/test_cli_integration.py`

**Interfaces:**
- Produces `_collect_readonly_evidence(plan: TransactionPlan) -> tuple[PreparedEvidence, ...]`, `_prepare(plan: TransactionPlan, evidence: tuple[PreparedEvidence, ...]) -> _Prepared`, and `_cleanup_preparation(owned: Sequence[OwnedArtifact]) -> None` where `OwnedArtifact(path: Path, kind: Literal["directory", "backup", "journal"])` is immutable. Lock anchors are owned by `locks.py`, persist across commands, and are never preparation artifacts.
- For non-dry install/uninstall, `run()` holds `locked_target_homes` from journal discovery through preflight, apply, recovery, and `_sync_and_remove_journal`; the strict dry-run branch added in Task 9 never calls the lock API and instead uses its double-collection stability check. No caller imports private transaction helpers across module boundaries after Task 5.

- [ ] **Step 1: Write failing zero-write and cleanup tests.**

  Add a failure injector for the final source, corrupt late manifest, missing participant, and journal-write failure. Snapshot every selected home after acquiring/validating its persistent lock anchor and assert the managed snapshot is unchanged when read-only evidence fails. For journal preparation failure, assert only newly created state/backups/journals disappear, while the lock anchor, a pre-existing state directory, unrelated file, and user backup remain byte-for-byte unchanged. Add a cleanup failure test asserting the primary sanitized diagnostic wins and the cleanup failure is represented only by the typed status.

  ```python
  before = tree_snapshot(home)
  status = run("install", argv, repo_root=repo, environ={}, stdout=out, stderr=err)
  self.assertEqual(status, EXIT_BLOCKED_VALIDATION)
  self.assertEqual(before, tree_snapshot(home))
  ```

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation tests.test_planning -v`

  Expected: failures show `_prepare` creates state/backups before all evidence is complete and journal-cleanup errors can replace the primary error.

- [ ] **Step 3: Split preparation into an explicit read-only and mutation phase.**

  Implement `_collect_readonly_evidence` to load all journals/manifests, validate participants/commitments, read every source, resolve every destination, capture identity evidence, and compute backups without creating directories. Only after it returns successfully may `_prepare` create private state directories, backups, commitment markers, and journals. Append each successful creation to `owned`; on preparation failure call `_cleanup_preparation` in reverse order and unlink only artifacts whose identity is still the recorded created identity.

- [ ] **Step 4: Hold locks through recovery and cleanup and preserve diagnostic precedence.**

  Wrap `_journal_groups`, `_recover_groups`, `_plan`, `apply_transaction`, and journal removal in one lock context per selected home. Make `_sync_and_remove_journal` use CAS evidence before unlinking journals/backups and keep the journal if directory sync or cleanup fails. Map primary operation failures to `TransactionPreparationError`, `IncompleteRollbackError`, or `TransactionError` without concatenating raw exception messages.

- [ ] **Step 5: Verify all transaction paths and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_transaction_preparation tests.test_planning tests.test_full_install_matrix tests.test_cli_integration -v`

  Expected: PASS for all seven target combinations, failure positions, recovery participants, zero-write preflight, and cleanup-only failure precedence. Run `ruff check subagents_configs tests`, `ruff format --check subagents_configs tests`, and `git diff --check`; commit `fix: separate preflight evidence from transaction preparation`.

### Task 3: Validation isolation, case-insensitive inventory, and real backend gates (SEC-02, TEST-01)

**Files:**
- Create: `tests/test_validation_smoke.py`
- Modify: `scripts/validation_isolation/backend.py`, `scripts/validation_isolation/environment.py`, `scripts/validation_isolation/git_snapshot.py`, `scripts/validation_isolation/runner.py`, `scripts/validation_isolation/cli.py`, `tests/test_validation_backend.py`, `tests/test_validation_git_snapshot.py`, `tests/test_validation_environment.py`, `tests/test_validation_runner.py`, `.github/workflows/ci.yml`

**Interfaces:**
- `is_protected_component(name: str) -> bool` and `is_excluded_relative_path(path: PurePosixPath) -> bool` are shared by tracked and untracked inventory filters and compare every component with `casefold()`.
- `run_isolated(command: Sequence[str], start_dir: Path, platform_name: str, process_runner: ProcessRunner = run_process) -> ValidationResult` keeps its current return type and must report only bounded output/evidence.
- `probe_backend(backend: BackendSpec, snapshot_root: Path, temp_root: Path, env: Mapping[str, str], process_runner: ProcessRunner = run_process) -> None` remains the real backend contract; no fake backend is accepted as a platform gate.
- `cleanup_validation_root(root: Path, *, primary: ValidationFailure | None) -> CleanupResult` never replaces a primary failure and exposes only a stable sanitized cleanup code.

- [ ] **Step 1: Write failing mixed-case and real-smoke tests.**

  In a real temporary Git repository, create tracked and untracked `CrEdEnTiAlS.JSON`, `.ENV.PROD`, `.EnVrC`, `.CaChE`, `.RuFf_CaChE`, `.CoNfIg/Gh/HoStS.YmL`, and a benign tracked ignored source file. Assert only the secret/cache paths are excluded and the tracked benign file remains. Add backend smoke assertions for network connection denial, `/etc/hosts` host-read denial, snapshot file read success, private temp-file creation with mode `0600`, child exit code `23`, and post-run checkout identity/status unchanged. Patch validation-root cleanup to fail both after a successful child and after a primary child/backend failure; assert checkout immutability, bounded typed cleanup reporting, and primary-error precedence.

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_validation_git_snapshot tests.test_validation_runner tests.test_validation_smoke -v`

  Expected: mixed-case protected names are currently included and the real smoke suite is either absent or does not assert all six isolation properties.

- [ ] **Step 3: Implement one casefolded path policy and source-aware inventory.**

  Keep tracked and non-ignored-untracked inventories separate: tracked paths are never removed merely because `.gitignore` matches them; explicit credential/cache/environment policies apply to both. Preserve NUL parsing, canonical traversal, symlink/special-file rejection, deterministic ordering, and `assert_checkout_unchanged`. Use `part.casefold()` for `.env`, `.env.*`, `.envrc`, `credentials.json`, `.npmrc`, `.pypirc`, `.netrc`, private-key names, credential stores, and cache components.

- [ ] **Step 4: Make real Bubblewrap and Seatbelt smoke execution a CI/release gate.**

  Add a Linux job that locates only `/usr/bin/bwrap` or `/bin/bwrap` and runs `tests.test_validation_smoke`; a macOS job locates only `/usr/bin/sandbox-exec` and runs the same assertions through the Seatbelt profile. If the fixed backend or ShellCheck is unavailable, exit nonzero rather than selecting an unsandboxed fallback. Keep the existing `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPYCACHEPREFIX`, private `HOME`/client homes, and checkout-cleanliness checks below the job-local temporary root.

- [ ] **Step 5: Verify isolation and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_validation_backend tests.test_validation_environment tests.test_validation_git_snapshot tests.test_validation_runner tests.test_validation_smoke -v`

  Expected: PASS on a host with the fixed backend; on an unsupported host the explicit fail-closed selector test passes and no child command starts. Run `ruff check scripts tests`, `ruff format --check scripts tests`, `sh -n ./*.sh`, and `git diff --check`; commit `fix: enforce casefolded validation isolation policy`.

### Task 4: Claude technical command gate and semantic-negative coverage (SEC-03, TEST-02)

**Files:**
- Create: `claude-code/hooks/code-validator-pretooluse.py`, `tests/test_claude_command_gate.py`
- Modify: `claude-code/agents/code-validator.md`, `subagents_configs/models.py`, `subagents_configs/targets.py`, `subagents_configs/formats.py`, `subagents_configs/planning.py`, `subagents_configs/state.py`, `tests/test_catalogs.py`, `tests/test_full_install_matrix.py`, `tests/test_security_static.py`, `README.md`

**Interfaces:**
- `parse_pretooluse_event(raw: bytes) -> PreToolUseEvent` accepts only JSON with `tool_name: "Bash"` and `tool_input.command: str`; unknown keys, non-string command, NUL, newline, shell operators, redirects, assignments, command substitution, pipelines, and chained commands are rejected.
- `validate_validator_command(command: str, helper: str) -> tuple[str, ...]` returns exactly `(python3, helper, "--", *argv)` with no shell syntax; `hook_main(stdin: BinaryIO, stdout: TextIO, stderr: TextIO) -> int` returns `0` only for this shape and `2` for malformed input.
- `validate_agent_semantics()` receives explicit per-role permission maps and rejects omission or broadening, including unknown role names, models, tools, permission modes, helper paths, body contracts, and optional-role inventory.

- [ ] **Step 1: Write failing gate and semantic-negative tests.**

  Feed the hook valid `python3 /abs/helper -- unittest tests/test_x.py`, then reject `bash -c`, `python3 /abs/helper`, `python3 /abs/helper --; touch x`, `python3 /abs/helper -- >x`, `env X=1 python3 /abs/helper -- unittest tests/test_x.py`, and `python3 /abs/helper -- ../../secret`. Mutate every catalog role one field at a time: model, tool, permission, rule order, helper path, body phrase, role name, and optional-role inventory. Assert `validate_source_inventory` rejects each mutation before any plan is returned.

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_claude_command_gate tests.test_catalogs tests.test_security_static -v`

  Expected: the current Claude validator Bash allowance accepts at least one forbidden command and the negative catalog mutations are not all rejected.

- [ ] **Step 3: Implement the fixed-argv hook and managed Claude configuration seam.**

  Use `shlex.split` only after rejecting control characters and shell metacharacters; require the first token to be `python3`, the second to equal the rendered absolute helper, the third to be `--`, and pass the remaining tokens as data. Add a target-specific managed `settings.json` hook block with exact shape:

  ```json
  {"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/absolute/.subagents_configs/validation/code-validator-pretooluse.py"}]}]}}
  ```

  Register source identifier `claude/code-validator-command-gate` with repository source `claude-code/hooks/code-validator-pretooluse.py` and destination `.subagents_configs/claude-hooks/code-validator-pretooluse.py`. Add a typed managed-JSON setting spec for the exact hook entry, include both file and setting ownership in plans/manifests, preserve unrelated settings, reject a conflicting existing hook rather than replacing it, and uninstall only an unchanged repository-owned hook file/entry. Claude necessarily exposes its Bash tool to this role so `PreToolUse` can run; the semantic policy treats unrestricted Bash as denied and the hook's one fixed helper argv shape as the only effective validation-command authority.

- [ ] **Step 4: Make catalog semantics exhaustive and generated-contract tested.**

  Define per-target expected maps for model, effort, tools, permissions, syntax, helper path, body concepts, role names, and optional `commit-pusher`. Check exact dictionary key order where the native client is order-sensitive; require catch-all deny before validator helper allow. Add generated catalog fixtures and assert a missing negative permission, extra tool, reordered rule, or absent optional role fails closed.

- [ ] **Step 5: Verify and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_claude_command_gate tests.test_catalogs tests.test_routing_policy tests.test_security_static tests.test_full_install_matrix -v`

  Expected: PASS with direct Claude validator Bash denied, only the fixed helper shape accepted, and all semantic-negative mutations blocked. Run `python scripts/validate-catalogs.py`, Ruff, `python -m compileall -q claude-code scripts subagents_configs tests`, and `git diff --check`; commit `fix: gate Claude validator commands technically`.

### Task 5: Canonical capability registry, typed lifecycle domain, and public seams (COR-01)

**Files:**
- Create: `subagents_configs/state_schema.py`, `subagents_configs/recovery.py`, `scripts/generate-catalogs.py`, `tests/test_capabilities.py`, `catalogs/codex.json`, `catalogs/opencode.json`, `catalogs/claude-code.json`
- Modify: `subagents_configs/models.py`, `subagents_configs/targets.py`, `subagents_configs/formats.py`, `subagents_configs/planning.py`, `subagents_configs/state.py`, `subagents_configs/transaction.py`, `subagents_configs/blocks.py`, `scripts/validate-catalogs.py`, `tests/test_targets.py`, `tests/test_catalogs.py`, `tests/test_state.py`

**Interfaces:**
- Define `TargetCapability(target: Target, order: int, include_in_all: bool, agent_directory: PurePosixPath, source_format: Literal["toml", "yaml-frontmatter"], parser: ParserName, semantic_validator: ValidatorName, global_instruction: GlobalInstructionSpec, optional_blocks: tuple[ManagedBlockSpec, ...], runtime_sources: tuple[SourceSpec, ...], lifecycle_capabilities: frozenset[LifecycleCapability], external_lifecycle: ExternalLifecycleSpec | None)`. Current targets set `include_in_all=True` and `external_lifecycle=None`; Plan 2 can add Pi with `include_in_all=False` without another registry.
- Extend `SourceSpec.kind` with `command-gate` and `target-extension`, and `SourceSpec.source_format` with `typescript` and `json`; current targets use `command-gate` only for the Claude hook, while the TypeScript variant is deliberately unused until Plan 2.
- Define concrete validated constructors: `FileAction.create(identifier: str, relative_path: PurePosixPath, desired: DesiredFile) -> FileAction`, `FileAction.replace(identifier: str, relative_path: PurePosixPath, expected: IdentityEvidence, desired: DesiredFile, backup: BackupSpec) -> FileAction`, `FileAction.remove(identifier: str, relative_path: PurePosixPath, expected: IdentityEvidence) -> FileAction`, `FileAction.restore(identifier: str, relative_path: PurePosixPath, expected: IdentityEvidence, backup: BackupSpec) -> FileAction`, `BlockAction.write(identifier: str, relative_path: PurePosixPath, expected: IdentityEvidence | None, block: ManagedBlock) -> BlockAction`, and `BlockAction.remove(identifier: str, relative_path: PurePosixPath, expected: IdentityEvidence, block: ManagedBlock) -> BlockAction`. Decoding hostile persisted strings remains strict and returns `LifecycleAction` only through `decode_lifecycle_action(raw: Mapping[str, object]) -> LifecycleAction`.
- Public seams are `capability_for(target: Target) -> TargetCapability`, `targets_for_request(explicit: tuple[Target, ...], include_all: bool) -> tuple[Target, ...]`, `load_state(home, descriptor)`, `inspect_managed_block(content, block_id)`, `safe_mutate(path, expected, desired)`, `apply_transaction(plan: TransactionPlan, *, failure_injector: FailureInjector | None = None) -> None`, `recover_transaction(homes: Mapping[Target, Path], targets: tuple[Target, ...]) -> None`, and `validate_lifecycle(request, descriptor)`; callers no longer import underscored helpers across these module boundaries.

- [ ] **Step 1: Write failing registry/seam tests.**

  Assert `capability_for()` is the only source of descriptor order and that every target has exactly one `include_in_all` decision, parser, semantic validator, global-instruction spec, runtime inventory, optional-block set, and external-lifecycle value. Assert `targets_for_request((), True)` returns the three current targets and derives that result only from the registry. Assert all `LifecycleAction` constructors reject missing evidence, invalid ownership/action pairs, and unknown persisted fields; assert imports from public seams work while direct cross-module private imports are detected by an AST test.

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_capabilities tests.test_targets tests.test_catalogs -v`

  Expected: duplicate descriptor facts and private helper imports are currently observable, and normalized catalog files do not exist.

- [ ] **Step 3: Implement the authoritative registry and typed variants.**

  Move all target facts into `CAPABILITIES: tuple[TargetCapability, ...]` ordered by `order`; derive `DESCRIPTORS`, `DESCRIPTOR_ORDER`, selected sources, parser dispatch, semantic validator dispatch, global block IDs, runtime files, and external lifecycle names from it. Make `LifecycleAction` a tagged union with constructors that validate action/ownership/evidence combinations before a transaction plan can contain it.

- [ ] **Step 4: Split only at proven seams and generate checked-in catalog projections.**

  Keep `__main__.py`, `scripts/manage-subagents-configs.py`, and `scripts/validate-catalogs.py` as cohesive entry points. Move strict state codecs/migrations to `state_schema.py` and journal-group recovery to `recovery.py`; leave small public forwarding imports in `state.py`/`transaction.py` so callers migrate without a flag day. Define one shared role-policy table, then render native per-target model, effort, tool, permission, and syntax overlays from that table. `python scripts/generate-catalogs.py --write` writes deterministic projections and `python scripts/generate-catalogs.py --check` renders in memory, compares byte-for-byte with checked-in JSON, and exits nonzero on drift. Generate each `catalogs/<target>.json` with canonical role/source/overlay/policy hashes and validate it by re-reading the native TOML/YAML/Markdown source; reject a generated diff or duplicate destination during validation.

- [ ] **Step 5: Verify and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_capabilities tests.test_targets tests.test_catalogs tests.test_state tests.test_blocks tests.test_filesystem tests.test_transaction_install tests.test_transaction_uninstall -v`

  Expected: PASS with every caller using public seams and generated catalogs reproducible from the registry. Run `python scripts/generate-catalogs.py --check`, `python scripts/validate-catalogs.py`, Ruff, compileall, and `git diff --check`; commit `refactor: centralize target capabilities and lifecycle types`.

### Task 6: Hash/inventory reuse and CI test consolidation (PERF-01, PERF-02, PERF-03)

**Files:**
- Create: `tests/test_performance_contracts.py`
- Modify: `subagents_configs/filesystem.py`, `subagents_configs/planning.py`, `subagents_configs/transaction.py`, `scripts/validation_isolation/git_snapshot.py`, `.github/workflows/ci.yml`, `tests/test_full_install_matrix.py`, `tests/test_ci.py`

**Interfaces:**
- `CommandCache` is an immutable-scope object created by `preflight_*`: `read_bytes(path, evidence) -> bytes`, `hash_bytes(content) -> str`, and `inventory_state(home, descriptor) -> StateInventory`; it is discarded at command end and never reused across mutation boundaries.
- `ValidatedSource.content` is the single source byte buffer for a planning command; `source_hash(source: ValidatedSource, cache: CommandCache) -> str` must not reread the file.

- [ ] **Step 1: Write measurable RED tests.**

  Patch the filesystem read/hash seams with counters and assert duplicate destination hashing is one read per command, already-read instruction/config bytes are reused during planning, and a second install command rebuilds the cache. Assert inventory is reused before a single operation but a changed identity immediately before the next write causes CAS failure. Parse CI and assert each equivalent unittest discovery pattern appears once.

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_performance_contracts tests.test_ci tests.test_full_install_matrix -v`

  Expected: current planning performs duplicate reads/hashes and CI invokes overlapping test suites.

- [ ] **Step 3: Implement scoped caches without weakening final checks.**

  Thread one `CommandCache` through `validate_source_inventory`, `_target_install`, `_target_uninstall`, and manifest rendering. Cache `(device, inode, size, nlink, mode, hash, bytes)` only until the next mutation boundary; call `capture_evidence` and `compare_and_swap` immediately before every write, unlink, chmod, rollback, and restore regardless of cached values.

- [ ] **Step 4: Remove duplicate CI invocations while retaining diagnostics.**

  Remove overlapping discovery/focused invocations from the existing workflow while preserving the current commands and diagnostic labels. Add a CI contract test describing the final single-entrypoint shape; Task 8 creates `scripts/validate-repository.py` and replaces these temporary calls with that one canonical invocation.

- [ ] **Step 5: Verify and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_performance_contracts tests.test_ci tests.test_full_install_matrix tests.test_planning -v`

  Expected: counter assertions pass, CAS still catches final identity changes, and the workflow has equivalent coverage once. Run Ruff, `git diff --check`, and commit `perf: reuse validated planning evidence safely`.

### Task 7: Stable diagnostics, recovery documentation, compatibility prerequisites, license decision gate, and private reporting (SEC-04)

**Files:**
- Create: `subagents_configs/diagnostics.py`, `tests/test_diagnostics.py`
- Modify: `subagents_configs/errors.py`, `subagents_configs/orchestrator.py`, `README.md`, `SECURITY.md`, `docs/RELEASING.md`, `tests/test_cli_integration.py`, `tests/test_docs.py`, `tests/test_readme_contract.py`

**Interfaces:**
- `DiagnosticCode` is an enum containing `CLI_INVALID`, `PREFLIGHT_REJECTED`, `VALIDATION_BLOCKED`, `RECOVERY_REQUIRED`, `RECOVERY_INCOMPLETE`, `APPLY_ROLLED_BACK`, `APPLY_AMBIGUOUS`, `MANAGED_CONFLICT`, `UNRESOLVED_UNINSTALL`, and `OUTPUT_FAILED`.
- `SafeContext(targets: tuple[str, ...], homes: tuple[str, ...], operation: str, phase: str, status: str)`, `Diagnostic(code: DiagnosticCode, context: SafeContext)`, and `render_diagnostic(diagnostic: Diagnostic) -> str` expose only fixed fields; no exception or environment mapping is accepted by the renderer.

- [ ] **Step 1: Write failing diagnostic/documentation tests.**

  Patch each phase with exceptions containing synthetic credentials, multiline payloads, raw paths, and environment values; assert output is the fixed code/context format and contains none of those values. Add document assertions for exact participant homes, recovery replay, dry-run semantics, exit codes 0/2/3/4/5/6/7/8, and manual-resolution boundaries. Assert `SECURITY.md` names a private GitHub Security Advisory URL, release documentation blocks public redistribution while `LICENSE` is absent, and no test or documentation claims that this plan selected a license for the owner.

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_diagnostics tests.test_cli_integration tests.test_docs tests.test_readme_contract -v`

  Expected: current fixed prefixes do not provide typed codes/context and the docs still claim no private reporting channel/license.

- [ ] **Step 3: Implement typed diagnostics and safe precedence.**

  Replace `_print_error(stderr, prefix, error, environ)` with `emit_diagnostic(stderr, DiagnosticCode, targets, homes, operation, phase, status)`. Map every existing exception branch to one enum code; sort targets canonically; render only normalized target names, normalized home labels, operation, phase, and status. Keep the primary error code when cleanup fails and return the established exit constants unchanged.

- [ ] **Step 4: Document recovery and prerequisites in the same change.**

  Add README sections that show `uninstall.sh --all --home codex=/srv/example/codex-home --home opencode=/srv/example/opencode-home --home claude-code=/srv/example/claude-home` for exact participant replay, explain journal/backup retention and manual-resolution conditions, and give dry-run JSON/text examples without contents. State tested prerequisites as a maintained matrix: Python 3.11–3.14, POSIX shell, Linux fixed Bubblewrap or macOS `/usr/bin/sandbox-exec`, and client version values recorded by the compatibility check. Make `SECURITY.md` direct vulnerability reports to `https://github.com/fettpl/subagents_configs/security/advisories/new` with a no-secrets/no-transcripts rule. Add an explicit owner-only release gate: implementation pauses before public redistribution until the owner separately approves exact license text/SPDX identifier; adding `LICENSE` is then a dedicated reviewed documentation commit, not an assumption in this plan.

- [ ] **Step 5: Verify and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_diagnostics tests.test_cli_integration tests.test_docs tests.test_readme_contract -v`

  Expected: fixed safe diagnostics and documentation contract tests pass; no sensitive fixture value is emitted. Run Ruff, `git diff --check`, and commit `docs: establish safe diagnostics and release prerequisites`.

### Task 8: Hash-locked dependencies, Python matrix, bootstrap, and canonical validation entry point (TEST-03)

**Files:**
- Create: `requirements-runtime.lock`, `requirements-dev.lock`, `scripts/validate-repository.py`, `scripts/bootstrap-developer.sh`, `AGENTS.md`, `tests/test_repository_validation.py`
- Modify: `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, `.github/workflows/ci.yml`, `README.md`, `docs/RELEASING.md`, `tests/test_ci.py`, `tests/test_wrappers.py`

**Interfaces:**
- `scripts/validate-repository.py` accepts no arguments (`argv == ()`), performs no install/download, and returns `0` only after catalog validation, unittest discovery, Ruff, format, shell syntax, compileall, backend gate, and clean-tree checks; unexpected argv returns `2` before repository reads.
- `scripts/bootstrap-developer.sh` accepts no arguments, creates `.venv` only after checking `python3 --version` is 3.11–3.14, and runs `python -m pip install --require-hashes --requirement requirements-dev.lock`; it is never imported or called by runtime code.
- Lock files use `--require-hashes`, exact versions, and the complete reviewed `sha256:<64 lowercase hex>` set for every wheel/sdist artifact allowed by each Python/platform selector; the test compares the full expected artifact filename/tag/hash inventory, rejects missing or extra hashes, rejects un-hashed lines/floating ranges/unsupported interpreters, and performs clean `pip install --require-hashes` jobs on every supported CI platform/Python pair.

- [ ] **Step 1: Write failing lock/bootstrap/entry-point tests.**

  Parse requirement files and assert PyYAML 6.0.3 and Ruff 0.16.3 are exact, each supported wheel/sdist filename and platform tag has exactly its reviewed 64-hex hashes with no unreviewed extra artifact, and runtime/developer files are distinct. Invoke the validator with `[]` and `['--install']`; assert the latter returns `2` and neither invocation calls pip. Parse CI and assert Python `3.11`, `3.12`, `3.13`, and `3.14` jobs, private homes, `PYTHONDONTWRITEBYTECODE`, `PYTHONPYCACHEPREFIX`, a clean `pip --require-hashes` install for every matrix cell, and a nonzero clean-tree failure branch.

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_repository_validation tests.test_ci tests.test_wrappers -v`

  Expected: current requirement files lack reviewed artifact hashes, CI covers only 3.11/3.14, and there is no fixed-argv canonical validator/bootstrap contract.

- [ ] **Step 3: Write the lock files and separate bootstrap paths.**

  Put `PyYAML==6.0.3` and its reviewed hashes in `requirements-runtime.lock`; put `-r requirements-runtime.lock` plus `ruff==0.16.3` and all reviewed Ruff hashes in `requirements-dev.lock`. Make `requirements.txt` include the runtime lock and `requirements-dev.txt` include the dev lock for backwards-compatible documented commands. The bootstrap validates `sys.version_info`, creates a private venv, and installs only the checked-in lock file; runtime wrappers continue to use an already-present interpreter and never call pip.

- [ ] **Step 4: Implement the fixed validation entry point and matrix.**

  Implement `main(argv: Sequence[str]) -> int` with exact empty argv, set `PYTHONDONTWRITEBYTECODE=1` and a job-private `PYTHONPYCACHEPREFIX` before checks, invoke each check once, require real backend smoke or explicit unsupported-backend failure, and execute `git diff --check` plus a fail-closed `git status --short` assertion. Update CI to call this script once per Python 3.11–3.14 job and add the macOS Seatbelt job from Task 3; contributor/release docs call the same command. Write `AGENTS.md` with exact repository guidance: use temporary homes, treat repository/client/subagent data as untrusted, run only the canonical validator, never access credentials or network services, and require a separate explicit authorization for commit/push/publication.

- [ ] **Step 5: Verify and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_repository_validation tests.test_ci tests.test_wrappers -v`; expected PASS. Then run `python scripts/validate-repository.py` in a clean temporary checkout, `ruff check subagents_configs scripts tests`, `ruff format --check subagents_configs scripts tests`, `sh -n ./*.sh`, and `git diff --check`; commit `ci: lock dependencies and centralize repository validation`.

### Task 9: Versioned structured dry-run output

**Files:**
- Create: `tests/test_dry_run_json.py`
- Modify: `subagents_configs/models.py`, `subagents_configs/planning.py`, `subagents_configs/orchestrator.py`, `subagents_configs/cli.py`, `subagents_configs/__main__.py`, `README.md`, `tests/test_cli.py`, `tests/test_cli_integration.py`

**Interfaces:**
- Add `DryRunFormat = Literal["text", "json"]` and `Request.dry_run_format`; parse `--dry-run --format json` only when `--dry-run` is present, reject `--format json` without dry-run, and keep default text byte-compatible.
- `render_plan_json(plan: TransactionPlan, *, recovery: RecoverySummary | None = None) -> bytes` returns one JSON object with exactly `schema_version: 1`, `operation`, `targets`, `actions`, `hashes`, `ownership`, `conflicts`, `recovery`, and `sources` keys.
- Each action object has `target`, `home`, `identifier`, `action`, `relative_path`, `before`/`after` evidence (hash/mode/device/inode/size/nlink or null), `ownership`, and `conflict`; sources contain only stable `identifier`, `kind`, `format`, and `source_hash`.
- `collect_stable_dry_run_evidence(request: Request) -> TransactionPlan` performs two read-only complete evidence collections with no lock API call and returns a plan only when normalized identities, source hashes, state/journal evidence, conflicts, and participant homes match exactly.

- [ ] **Step 1: Write failing JSON contract tests.**

  Plan install/uninstall for all seven target combinations with `--dry-run --format json`; parse JSON and assert stable key sets, canonical target order, normalized home paths, action hashes/evidence, ownership, conflicts, recovery participants, and safe source identifiers. Assert no content bytes, prompts, environment values, credential-looking names, or exception strings occur. Assert default `--dry-run` output remains the existing text format. Patch the lock API to fail if called, start with no lock anchor, and assert dry-run leaves it absent; when the second evidence collection changes one source/state/target identity, assert `PREFLIGHT_CONCURRENT_CHANGE` and no output plan.

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_dry_run_json tests.test_cli tests.test_cli_integration -v`

  Expected: parser rejects the new format flag and no structured renderer exists.

- [ ] **Step 3: Implement the strict schema and renderer.**

  Build JSON from `TransactionPlan` and typed recovery summaries only; sort targets by descriptor order and actions by `(target, relative_path, identifier)`, convert `Path` to normalized safe strings, and omit all content. Set `recovery.required` when a validated pending journal exists, include exact participants/homes/journal identifiers, and set `manual_resolution` only for incomplete/ambiguous recovery. Implement the double-collection stability check through the same read-only evidence functions used by locked non-dry planning; never call `locked_target_homes` from the dry-run branch.

- [ ] **Step 4: Wire CLI output without changing normal text.**

  Parse `--format` with `allow_abbrev=False`, require value `text` or `json`, and reject JSON for non-dry-run operations before source reads. In `run`, render the selected format after preflight and before apply; JSON conflicts and exit code behavior remain identical to text. JSON rendering failures use `OUTPUT_FAILED` and never expose the rendering exception.

- [ ] **Step 5: Verify and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_dry_run_json tests.test_cli tests.test_cli_integration tests.test_full_install_matrix -v`

  Expected: structured contract passes for every target combination, default text is unchanged, dry-run creates no lock/filesystem/state/journal/backup mutation, and a concurrent evidence change fails closed. Run Ruff and `git diff --check`; commit `feat: add versioned structured dry-run output`.

### Task 10: Read-only client compatibility contract and maintained matrix

**Files:**
- Create: `subagents_configs/compatibility.py`, `catalogs/client-compatibility.json`, `tests/test_compatibility.py`
- Modify: `subagents_configs/models.py`, `subagents_configs/targets.py`, `subagents_configs/cli.py`, `subagents_configs/planning.py`, `subagents_configs/orchestrator.py`, `README.md`, `SECURITY.md`, `docs/RELEASING.md`, `tests/test_cli_integration.py`, `tests/test_docs.py`

**Interfaces:**
- `CompatibilityTarget = Literal["codex", "opencode", "claude-code", "pi"]` is a matrix identity independent of the runtime `Target` enum, allowing Plan 1 to publish a fail-closed future Pi row without registering Pi as an install target.
- `ClientCompatibility(target: CompatibilityTarget, supported: bool, format_version: str, features: frozenset[str], minimum_client_version: str | None, tested_client_version: str | None, tested_python: tuple[str, ...], supported_platforms: tuple[Literal["linux", "macos"], ...], tested_os_backends: tuple[str, ...], package_source: str | None, scope: Literal["user"] | None)` is strict JSON data; current rows use `supported=True` and `package_source=None`, while the Plan 1 Pi row uses `supported=False`, `tested_client_version=None`, `package_source=None`, and no claimed platform. `CompatibilityResult(supported: bool, reasons: tuple[str, ...])` is immutable.
- `validate_client_compatibility(capability: TargetCapability, client: ClientCompatibility, *, requested_features: frozenset[str]) -> CompatibilityResult` is read-only and never executes prompts or broadens permissions.
- `load_compatibility_matrix(path: Path) -> tuple[ClientCompatibility, ...]` rejects unknown keys, duplicate target rows, empty/non-semver version fields, missing target feature declarations, and a Pi row with `supported: true`.

- [ ] **Step 1: Write failing matrix and adapter tests.**

  Add rows for Codex, OpenCode, and Claude Code with the formats/features already emitted by the repository plus a Pi row marked unsupported. Assert the compatibility-only Pi identity does not create `Target.PI`, a descriptor, a selectable target, or any install path. Assert unsupported format/features return reasons without filesystem writes, prompts, network, or package-manager calls; assert requested optional blocks are checked against the row before planning.

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_compatibility tests.test_cli_integration -v`

  Expected: no matrix loader or adapter result exists.

- [ ] **Step 3: Implement strict read-only adapters.**

  Load only the checked-in matrix and capability registry. Resolve current runtime targets to their `CompatibilityTarget` string; the unsupported Pi row remains queryable only by the read-only matrix/report path. `validate_client_compatibility` compares support status, target format, required features, platform/scope, optional package identity, and optional client version strings using `packaging`-free numeric dotted comparison (`tuple(int(part) for part in version.split("."))` after strict semver validation); it returns fixed reason codes such as `target_unsupported`, `format_unsupported`, `feature_unsupported`, `platform_unsupported`, `scope_unsupported`, `package_unsupported`, or `client_version_too_old` and never invokes a client or reads an environment variable.

- [ ] **Step 4: Add explicit compatibility checking to dry-run/install preflight.**

  Add `--client-version TARGET=VERSION` as a read-only fact supplied by the caller; absent versions use the maintained tested row without probing. Before any target write, compare requested format/features and expose compatibility reasons in text/JSON dry-run; a failed result returns `EXIT_PREFLIGHT_ERROR` with a typed diagnostic. Document how release owners update the matrix from separately authorized `client --version` evidence.

- [ ] **Step 5: Verify and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_compatibility tests.test_cli tests.test_cli_integration tests.test_docs -v`

  Expected: all adapter negatives fail closed, Pi remains unsupported, and no prompt/network/package code is reachable. Run `python scripts/validate-catalogs.py`, Ruff, and `git diff --check`; commit `feat: add read-only client compatibility contract`.

### Task 11: Strict declarative install profiles

**Files:**
- Create: `subagents_configs/profiles.py`, `tests/test_profiles.py`
- Modify: `subagents_configs/cli.py`, `subagents_configs/planning.py`, `subagents_configs/models.py`, `subagents_configs/orchestrator.py`, `README.md`, `tests/test_cli.py`, `tests/test_cli_integration.py`

**Interfaces:**
- `ProfileRequest(schema_version: Literal[1], operation: Literal["install", "uninstall"], targets: tuple[Target, ...], homes: Mapping[Target, Path], options: ProfileOptions)` is immutable; `load_profile(path: Path) -> ProfileRequest` accepts `.json` or `.toml` only.
- Exact profile schema is `{ "schema_version": 1, "operation": "install", "targets": ["codex"], "homes": {"codex": "/absolute/home"}, "options": {"enable_global_routing": false, "enable_codex_multi_agent": false, "include_commit_pusher": false, "dry_run": true, "dry_run_format": "text"} }`; TOML uses the same field names/tables.
- `merge_profile_with_cli(profile: ProfileRequest, argv: Sequence[str], environ: Mapping[str, str]) -> Request` applies documented precedence: explicit CLI target/all, `--home`, paired positive/negative booleans, `--dry-run`/`--no-dry-run`, and `--format` override profile fields; absent CLI values retain profile values; profile and CLI cannot select conflicting operations. Add exact negative forms `--no-global-routing`, `--no-codex-multi-agent`, and `--no-commit-pusher` alongside the existing positive flags.

- [ ] **Step 1: Write failing profile tests.**

  Test JSON and TOML success, unknown top-level/nested keys, duplicate JSON keys, duplicate targets/homes, both `targets` and `all`, non-absolute/traversal/symlink/credential-looking paths, credentials in arbitrary keys/values, invalid booleans, unsupported operation, and both directions of CLI override precedence. Assert each explicit `--no-*` turns off a profile `true`, each positive flag turns on a profile `false`, absence retains the profile value, and `--profile` is rejected for uninstall when the profile operation is install.

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_profiles tests.test_cli tests.test_cli_integration -v`

  Expected: parser has no `--profile` option and no strict profile schema.

- [ ] **Step 3: Implement strict JSON/TOML loading.**

  Parse JSON with an `object_pairs_hook` that rejects duplicate keys; parse TOML with `tomllib.loads`. Require exact key sets, `type(value) is bool` for booleans, target enum values, one of `text/json`, no credentials/secret/token/password/private-key key fragments, no NUL/control characters, and absolute lexical paths with no `.`/`..`; defer no-follow filesystem checks to preflight.

- [ ] **Step 4: Merge profile values before request validation and document precedence.**

  Add `--profile PATH` and the paired negative flags to the existing parser using an explicit tri-state (`None`, `True`, `False`) during parsing. Merge `None` from the CLI as “retain profile”, and merge either boolean as authoritative; run the existing duplicate/target/home/flag validation after merging. Never allow a profile to enable a target, role, global route, or model authority not represented by existing `Request` fields.

- [ ] **Step 5: Verify and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_profiles tests.test_cli tests.test_cli_integration tests.test_planning -v`

  Expected: every hostile profile fails before repository/home reads, safe profiles merge deterministically, and CLI values win. Run Ruff and `git diff --check`; commit `feat: support strict declarative install profiles`.

### Task 12: Catalog policy change reports

**Files:**
- Create: `subagents_configs/catalog_policy.py`, `tests/test_policy_diff.py`
- Modify: `scripts/manage-subagents-configs.py`, `subagents_configs/__main__.py`, `subagents_configs/targets.py`, `scripts/validate-catalogs.py`, `README.md`, `docs/RELEASING.md`

**Interfaces:**
- `NormalizedCatalog(target: Target, revision: str, roles: tuple[RolePolicy, ...], destinations: tuple[DestinationPolicy, ...], source_hashes: Mapping[str, str])` is loaded from checked-in generated catalogs or an explicit local revision path.
- `PolicyChange(kind: Literal["role","model","tool","permission","destination","source_hash","authority"], target: Target, role: str | None, before: str | None, after: str | None, authority_broadening: bool)` and `PolicyChangeReport(from_revision: str, to_revision: str, changes: tuple[PolicyChange, ...])` are immutable. `AuthorityCapability` is a normalized enum containing filesystem read/write, shell execution, network, credentials, external-directory, MCP, extension, package, skill, publication, and repository-history capabilities; native fields map to these enums before comparison.
- `compare_catalogs(before: NormalizedCatalog, after: NormalizedCatalog) -> PolicyChangeReport` is read-only; `render_policy_report(report: PolicyChangeReport, format: Literal["text","json"]) -> str` emits only identifiers, hashes, and normalized policy values.

- [ ] **Step 1: Write failing diff tests.**

  Compare two temporary normalized catalogs with one change each to role name, model, tool, permission, destination, source hash, and every `AuthorityCapability`. Assert every change kind is reported, every added capability—including shell, external-directory, MCP, extension, package, skill, publication, and repository-history authority—is marked `authority_broadening=True`, removals are not, output is deterministic, and source contents/private paths never appear.

- [ ] **Step 2: Run focused tests and verify RED.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_policy_diff -v`

  Expected: no policy-diff command or typed report exists.

- [ ] **Step 3: Implement normalized catalog loading and comparison.**

  Require exact normalized catalog keys, lowercase SHA-256 source hashes, canonical target/role order, and explicit sets for model/effort/tools/permissions/destinations. Compare maps by `(target, role)` and emit sorted `PolicyChange` records. Map each target-native permission/tool/lifecycle field to the closed `AuthorityCapability` enum, reject unknown native fields, and classify any set addition as broadening rather than relying on substring matching.

- [ ] **Step 4: Add the read-only command and docs.**

  Dispatch the concrete forms `python scripts/manage-subagents-configs.py policy-diff --from catalogs/revisions/before --to catalogs/revisions/after --format json` and `python -m subagents_configs policy-diff --from catalogs/revisions/before --to catalogs/revisions/after --format text` without invoking install/uninstall or reading target homes. Reject missing/ambiguous paths and unknown flags before reads. Document the command as a local, non-mutating review gate used before catalog publication.

- [ ] **Step 5: Verify and commit.**

  Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_policy_diff tests.test_capabilities tests.test_catalogs -v`

  Expected: all seven policy dimensions and authority flags are reported deterministically with no writes. Run `python scripts/validate-catalogs.py`, Ruff, and `git diff --check`; commit `feat: report catalog policy changes`.

## Final Verification and Traceability

- [ ] Run the pinned developer bootstrap only in a disposable developer environment, then record exact `python --version`, `ruff --version`, `shellcheck --version`, client `--version` values, backend paths/versions, and catalog/package metadata without recording environment values, credentials, prompts, or transcripts.
- [ ] In a clean checkout, run `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v`; expected: every test passes, including real Bubblewrap/Seatbelt smoke where the corresponding fixed backend exists and explicit fail-closed tests elsewhere.
- [ ] Run `python scripts/validate-repository.py`; expected: catalog generation/validation, all tests, Ruff, format, ShellCheck, shell syntax, compileall, backend gate, `git diff --check`, and clean-tree assertion pass without installing or downloading anything.
- [ ] Re-run hostile identity races, late-source/late-journal zero-write failures, mixed-case credential/cache inventory, validator Bash denial, profile unknown-key/unsafe-path rejection, JSON dry-run redaction, compatibility mismatch, and authority-broadening policy diff fixtures.
- [ ] For the Plan 1 branch only, review the complete diff from revision `5264e39700e69e774f6c0895a1be0a9b96419ec1` through the final Plan 1 commit; verify no Pi package/install/network code, service, daemon, dashboard, generic plugin framework, secrets, raw environment values, or unrelated files were introduced. Plan 2 has a separate, explicitly authorized Pi package boundary and is not evaluated by this Plan 1-only assertion.

Requirement traceability:

| Spec requirement/finding | Covered by |
| --- | --- |
| SEC-01: per-home descriptor locks, canonical order, CAS identity checks, read-only evidence boundary, owned preparation cleanup | Tasks 1–2 |
| SEC-02: case-insensitive excluded names, real Bubblewrap/Seatbelt denial and immutability | Task 3 |
| SEC-03: technical Claude validator command gate | Task 4 |
| SEC-04: typed safe diagnostics, recovery/manual boundaries, private reporting, license/prerequisites | Task 7 |
| COR-01: authoritative target capability/catalog registry and public module seams | Task 5 |
| TEST-01: real backend smoke coverage and macOS/Linux gates | Task 3 and Task 8 |
| TEST-02: semantic-negative coverage for models, permissions, tools, ordering, paths, bodies, roles, and optional inventory | Task 4 |
| TEST-03: cleanup-only failures, fixed validation entry point, full CI/clean-tree checks | Tasks 2 and 8 |
| Consolidated hashing, state inventory, instruction/config reads, and duplicate CI invocations | Task 6 |
| Reviewed dependency hashes and Python 3.11/3.12/3.13/3.14 support | Task 8 |
| Runtime/developer bootstrap separation and no-install validation command | Task 8 |
| State compatibility matrix and migration before schema v2 | Task 1 |
| Recovery replay, exact participants/homes, dry-run output, exit codes, manual resolution | Tasks 2, 7, and 9 |
| Client compatibility contract for Codex/OpenCode/Claude and later Pi row without Pi implementation | Task 10 |
| Versioned structured JSON dry-run | Task 9 |
| Strict declarative JSON/TOML install profiles and explicit CLI precedence | Task 11 |
| Read-only catalog policy diff for role/model/tool/permission/destination/source-hash/authority changes | Task 12 |
| Single-component scope, fail-closed behavior, no runtime network/download/install, generated catalog validation, documentation co-change | Global constraints and Tasks 4–12 |

Audit-ID coverage (no row may be removed during execution):

| IDs | Required outcome | Covered by |
| --- | --- | --- |
| C-01, C-02, C-03, C-04 | Persistent per-home locking, mutation-boundary CAS, zero-write preflight/preparation cleanup, and preservation of every existing fail-closed transaction invariant | Tasks 1–2 |
| C-05, C-06, C-07, C-10 | Casefolded exclusions, real Bubblewrap/Seatbelt evidence, Linux/macOS gates, and validation cleanup-only failure precedence | Task 3 |
| C-08, C-09 | Owned Claude command gate and full per-target/per-role semantic-negative matrix | Task 4 |
| C-11, C-12, C-13, C-14, C-15 | One extensible capability registry, typed lifecycle variants, public seams, seam-based module splits, and reproducible canonical policy/catalog generation | Task 5 |
| C-16, C-17, C-18 | Eliminate duplicate hashing, safely reuse state/source evidence, and remove duplicate CI execution | Task 6 |
| C-24, C-25, C-26, C-27 | Safe diagnostics, recovery/prerequisite docs, private reporting, and owner-controlled license/publication gate | Task 7 |
| C-19, C-20, C-21, C-22, C-23 | Complete reviewed dependency hashes, Python 3.11–3.14, one non-installing validator, separate bootstraps, and repository-local agent/contributor guidance | Task 8 |
| C-28 | Normative v0/v1/v2/future state matrix and safe migration before schema 2 | Task 1 |
| C-29 | TDD, focused/full/static verification, clean-tree enforcement, documentation co-change, and reviewable commits | Global Constraints and Final Verification |
| N-01 | Versioned JSON dry-run | Task 9 |
| N-02 | Read-only client compatibility adapters and maintained matrix | Task 10 |
| N-03 | Strict JSON/TOML install profiles with two-way explicit CLI precedence | Task 11 |
| N-04 | Catalog/revision policy reports with closed-set authority broadening detection | Task 12 |

Approved execution mode: **Subagent-Driven**. Dispatch a fresh `gpt-5.6-luna` subagent with high reasoning effort for each task, complete the prescribed review checkpoint before dispatching the next task, and do not start Plan 2 until the Plan 1 prerequisite gate passes.
