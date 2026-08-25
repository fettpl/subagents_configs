# Task 10 handoff — read-only client compatibility contract

## Scope and changed files

Implemented only Task 10 on `feat/client-compatibility`:

- `subagents_configs/compatibility.py` — immutable matrix rows/results, strict
  JSON loader, fixed reason codes, numeric semver comparison, request feature
  mapping, and read-only preflight.
- `catalogs/client-compatibility.json` — Codex/OpenCode/Claude Code supported
  rows plus the unsupported compatibility-only future Pi row.
- `tests/test_compatibility.py` — RED/GREEN contract tests, loader negatives,
  no-write dry-run checks, Pi identity boundary, and CLI version parsing.
- `subagents_configs/models.py`, `cli.py`, `planning.py`, `orchestrator.py`,
  `diagnostics.py`, `scripts/validate-catalogs.py`, and package exports — typed
  caller version fact, preflight integration, bounded typed reasons, and
  matrix validation.
- `README.md`, `SECURITY.md`, `docs/RELEASING.md`, `tests/test_docs.py`, and
  `tests/test_security_static.py` — compatibility maintenance and trust-boundary
  documentation/tests.

## Requirement mapping

| Requirement | Evidence |
| --- | --- |
| Runtime targets remain exactly Codex/OpenCode/Claude Code | `Target` and `CAPABILITIES` are unchanged; `tests.test_targets` and `tests.test_compatibility.test_unsupported_pi_is_queryable_without_runtime_registration` pass. |
| Compatibility-only Pi row | Matrix row is `supported: false`, has no tested/minimum client version, package source, platform, or scope; loader rejects any supported future row. |
| Strict immutable loader | Exact row/envelope keys, duplicate JSON keys/rows/list members, types, required features, strict versions, platform/scope/package constraints are validated. |
| Read-only adapter | `validate_client_compatibility` performs only typed comparisons; no client, environment, network, filesystem write, or package-manager call is reachable. |
| Caller `--client-version` | Parser accepts only selected `TARGET=X.Y.Z`, rejects duplicate/unselected/unsafe/invalid values, and preserves absent-version maintained-row semantics. |
| Fail-closed preflight | Compatibility runs before dry-run recovery inspection and before mutating lock/recovery/planning; text/JSON failures expose only fixed reasons and return exit 3. |
| Task 9 compatibility | Successful JSON dry-run schema remains unchanged; compatibility failure output is a separate typed compatibility payload. |

## TDD evidence

- RED: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_compatibility tests.test_cli_integration -v` failed during collection with `ModuleNotFoundError: No module named 'subagents_configs.compatibility'`; existing CLI integration tests passed.
- GREEN: focused compatibility/CLI/docs tests pass after the minimal contract implementation; the final focused run covered 56 tests and passed.
- REFACTOR: Ruff/format cleanup, package exports, strict direct dataclass validation, and duplicate-key handling were completed with tests remaining green.

## Verification evidence

- Focused Task 10 command: 56 tests passed.
- Full unittest discovery: 504 tests passed, 1 expected optional smoke skip.
- `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/validate-catalogs.py`: passed.
- Ruff check and format check over `subagents_configs scripts tests`: passed.
- External-cache `compileall`: passed.
- Shell `sh -n` checks for all wrappers: passed.
- YAML syntax check: passed.
- `git diff --check`: passed.
- Canonical `.venv/bin/python scripts/validate-repository.py`: bounded fail-closed result `backend gate; status=exit-125` with zero-byte output because this host lacks an available fixed isolation backend. No Task 10 test failed.

## No-Pi-runtime proof

The runtime `Target` enum, capability registry, descriptor registry, parser
dispatch, target selection, planning, transaction, and install/uninstall paths
contain no Pi entry. The Pi identity exists only in the compatibility module
and checked-in matrix/reporting path. Static security inventory and target
boundary tests pass, and no package/network/client execution code was added.

## Commit and concerns

- Implementation commit SHA: `8ced302` (`feat: add read-only client compatibility contract`).
- Concern: canonical repository validation remains unavailable on this host due
  to the fixed backend gate (`exit-125`); rerun on a host with the reviewed
  Bubblewrap or Seatbelt backend before publication.
- No push, publication, package installation, network access, or external
  coordination was performed.
