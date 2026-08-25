# Task 9 report — versioned structured dry-run output

## Changed files

- `tests/test_dry_run_json.py`: RED/GREEN contract coverage for parsing,
  schema safety, all seven target combinations, lock absence, and concurrent
  evidence rejection.
- `subagents_configs/models.py`: `DryRunFormat` and the request format field.
- `subagents_configs/cli.py`: strict `--format text|json` parsing and the
  JSON-only-with-dry-run rule.
- `subagents_configs/planning.py`: stable source metadata, recovery summary,
  deterministic JSON renderer, typed evidence reduction, and format validation.
- `subagents_configs/orchestrator.py`: lock-free double evidence collection,
  state/journal/recovery fingerprints, post-render recapture, structured
  output/error handling, and the `PREFLIGHT_CONCURRENT_CHANGE` diagnostic.
- `subagents_configs/diagnostics.py`: concurrent-change diagnostic code.
- `README.md`: structured dry-run CLI and schema documentation.

## Requirement mapping

| Requirement | Implementation/evidence |
| --- | --- |
| Versioned schema with exact top-level keys | `render_plan_json()` emits schema version `1` and exactly `schema_version`, `operation`, `targets`, `actions`, `hashes`, `ownership`, `conflicts`, `recovery`, and `sources`. |
| Content/path/exception sanitization | JSON uses hashes, modes, identity fields, safe identifiers, relative managed paths, and normalized selected homes; it never serializes operation content, source paths, or exception text. |
| Canonical ordering | Targets use the capability registry order; actions sort by target order, relative path, and identifier; source records have deterministic field ordering. |
| CLI contract and text compatibility | `--format` is parsed with abbreviation disabled; JSON without `--dry-run` is rejected before source planning; text remains the existing renderer. |
| Lock-free stable evidence | JSON dry-run collects journals/state and a complete plan twice without `locked_target_homes`; normalized homes, plan identities/hashes/conflicts, source hashes, state/journal identity, and recovery participants are compared both before and after in-memory rendering. |
| Fail-closed concurrent change | A mismatch returns `PREFLIGHT_CONCURRENT_CHANGE` and writes no plan output. |
| Recovery/conflicts/output failures | Structured recovery includes validated participants, normalized homes, journal operation IDs, action, and manual-resolution state; conflicts and rendering failures use existing bounded diagnostics. |
| No dry-run mutation | Focused tests snapshot repository/home trees and fail if the lock API is called. |

## TDD evidence

Initial RED command:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_dry_run_json tests.test_cli tests.test_cli_integration -v
```

The initial run failed during test import with `ImportError: cannot import
name 'render_plan_json' from subagents_configs.planning`; existing CLI and
integration tests still ran green. The implementation was then added and the
 same focused command passed. Subsequent focused contract tests covered all
 seven target combinations and the lock/concurrent-change cases.

Review-round RED regression:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_dry_run_json.StructuredDryRunContractTests.test_source_change_during_json_render_fails_before_output -v
```

Before the fix this failed with `AssertionError: 0 != 3`: a renderer-side
source mutation returned status 0 and emitted a plan. The fix performs a new
complete lock-free collection after in-memory rendering and compares the
state/journal/source/recovery/plan fingerprint before writing stdout. The
regression and added state/journal mutation tests now pass.

## Verification evidence

- Review-focused: `tests.test_dry_run_json tests.test_cli tests.test_cli_integration tests.test_full_install_matrix` — 53 tests passed.
- Full discovery: `PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/private/tmp/subagents-configs-pycache .venv/bin/python -m unittest discover -s tests` — 490 tests passed, 1 skipped.
- Catalogs: `.venv/bin/python scripts/validate-catalogs.py` — passed.
- Ruff: `.venv/bin/python -m ruff check subagents_configs scripts tests` — passed.
- Ruff format: `.venv/bin/python -m ruff format --check subagents_configs scripts tests` — 67 files already formatted.
- Compile: `compileall` over `subagents_configs`, `scripts`, and `tests` with an external private cache — passed.
- Shell syntax/ShellCheck (where available), YAML parse, and `git diff --check` — passed.
- Canonical validator: `.venv/bin/python scripts/validate-repository.py` was run as required but failed at the environment-dependent backend gate with bounded `status=exit-125` and empty stdout/stderr. No repository changes or fallback behavior were introduced.

## Commit

Implementation commit SHA: `9aa9ff9`.

Subject: `feat: add versioned structured dry-run output`

Review-fix commit SHA: `146a0ee`.

Subject: `fix: close Task 9 review gaps`

## Residual concerns

The canonical validator's fixed backend smoke gate is unavailable in this
environment (`exit-125`); the full unit suite, catalog validator, static
checks, and compile/syntax checks pass. The controller should rerun the
canonical validator in its supported backend environment.
