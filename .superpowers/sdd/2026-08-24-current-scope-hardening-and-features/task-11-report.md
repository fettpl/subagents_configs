# Task 11 implementation report

Implementation commit (before adding this report): `550b9a0`

## Changed files

- `subagents_configs/profiles.py`: strict JSON/TOML decoding, hostile-data rejection, immutable profile merge, and explicit CLI precedence.
- `subagents_configs/models.py`: immutable `ProfileOptions` and `ProfileRequest` models.
- `subagents_configs/cli.py`: `--profile`, tri-state positive/negative flags, and public parser seams.
- `subagents_configs/orchestrator.py`: help text for profiles and paired flags.
- `README.md`: profile schema, hostile examples, and precedence contract.
- `tests/test_profiles.py`: real JSON/TOML, duplicate/hostile input, immutability, precedence, operation conflict, and preflight coverage.
- `tests/test_security_static.py`: exact active-Python inventory entry for the new production module.

The static-inventory change is directly required because the repository rejects
unlisted active Python modules; it does not broaden runtime targets or scan
scope.

## Requirement mapping

- Exact v1 schema: closed top-level/options keys, exact bool types, supported target/order, operation, format, and home mapping checks.
- Safety: duplicate JSON/TOML data, credential-like fragments, controls/NUL, unsupported/all targets, non-absolute/traversal/noncanonical homes, and profile symlink files fail closed.
- Models: frozen dataclasses and mapping-proxy homes prevent post-load mutation.
- CLI: `--profile`, paired `--no-global-routing`, `--no-codex-multi-agent`, `--no-commit-pusher`, and `--no-dry-run`; absence retains profile values and explicit values override in both directions.
- Merge: explicit targets/`--all`, homes, booleans, dry-run, and format are merged into the existing `Request`; operation and install-only feature conflicts remain rejected; existing compatibility/preflight paths are reused by orchestration.
- Scope: no Pi target, package/client execution, network, environment capture, or authority-bearing profile fields were added.

## TDD evidence

- RED: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_profiles -v` failed at import with `ModuleNotFoundError: No module named 'subagents_configs.profiles'`.
- GREEN: focused profile/CLI/integration/planning run passed 76 tests.
- REFACTOR: public CLI seams removed prohibited private cross-module imports; Ruff and static architecture checks passed.

## Verification evidence

- Focused: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_profiles tests.test_cli tests.test_cli_integration tests.test_planning -v` — 76 passed.
- Full: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py'` — 520 passed, 1 skipped.
- Catalogs: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/validate-catalogs.py` — passed.
- Ruff: `ruff check subagents_configs tests/test_profiles.py` and `ruff format --check subagents_configs tests/test_profiles.py` — passed.
- Compile: `PYTHONPYCACHEPREFIX=<private temporary cache> .venv/bin/python -m compileall -q subagents_configs scripts tests` — passed.
- Shell: `shellcheck` and `bash -n` over all repository shell entrypoints — passed.
- `git diff --check` — passed before commit.
- Canonical `.venv/bin/python scripts/validate-repository.py` — repository
  checks reached the fixed backend gate, which returned `exit-125` with zero
  stdout/stderr bytes in this environment; no profile-specific check failed.

## Concerns

Existing no-follow preflight behavior intentionally maps a symlinked home in
dry-run recovery inspection to the repository's bounded validation-blocked
status. Profiles do not resolve or follow those paths; the existing preflight
checks remain authoritative.

The fixed backend-gate availability result above remains the only incomplete
verification item and should be rerun in an environment with the required
backend before release-owner validation.

## Review round 1 fixes

Review-round base: `7ef6f5a`.

- Extracted public pure `validate_request_shape` from planner invariants;
  profile merge and orchestrator invoke it before compatibility, recovery,
  locks, repository, or home reads, while preflight delegates to it.
- Closed direct `ProfileRequest` canonical target, absolute/canonical home,
  and normalized-distinctness invariants.
- Sensitive-fragment matching now case-folds and removes separators, covering
  `privatekey`, `private-key`, `private_key`, and `private key` in keys/values.
- Added the production-path duplicate-normalized-home zero-read regression,
  hostile TOML parity, direct-model, precedence, and paired-flag tests.

Review-round focused verification:

- Profile, CLI, integration, planning, capability, and static suites — 104 passed.
- Full unittest discovery — 525 passed, 1 skipped.
- Ruff check/format, catalog validation, compileall, shell syntax/ShellCheck,
  and `git diff --check` rerun after fixes — passed.
