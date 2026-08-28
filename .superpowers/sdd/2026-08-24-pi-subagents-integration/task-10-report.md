# Task 10 report — documentation, compatibility, and trust boundary

Date: 2026-08-28
Branch: `feat/pi-task10-docs-compatibility`
Baseline: `17cbcb2a68e2eca4206600edb3d79033b80769ac`

## Result

Updated the Pi-facing README, security policy, release checklist, and
compatibility projection. Added contract tests for provenance, exact runtime
and package pins, consent/dry-run behavior, model/provider inheritance,
managed-versus-bundled inventories, ownership and uninstall boundaries,
redacted diagnostics, release evidence, and JSON-to-Markdown compatibility
projection parity.

The checked-in machine-readable Pi row was already exactly the required
unreleased boundary (`supported: false`, `status: "unreleased"`, with no
version/package/platform/scope claims). It was deliberately left unchanged;
the human projection documents intended Pi 0.84.1/package evidence without
turning it into a support claim. Task 11 remains the sole support transition.

## Verification

All commands were offline and did not run Pi, provider smoke, npm/package
installation, or network operations.

| Command | Result |
| --- | --- |
| `PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python -m unittest tests.test_readme_contract tests.test_docs tests.test_compatibility -v` | PASS — 45 tests. |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_docs tests.test_compatibility -v` | PASS — 34 tests (initial dependency-light probe). |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_readme_contract.ReadmeContractTests.test_pi_provenance_lifecycle_and_trust_boundary_are_documented tests.test_readme_contract.ReadmeContractTests.test_pi_commands_and_ownership_are_exact -v` | PASS — 2 tests (initial dependency-light probe). |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_readme_contract tests.test_docs tests.test_compatibility -v` | Initial partial probe under system Python: documentation/compatibility assertions pass, but the existing parsed-agent test could not import unavailable PyYAML. |
| `PYTHONDONTWRITEBYTECODE=1 python3 -c 'import ast; ...'` (three changed Python tests) | PASS — all files parse. |
| `PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python scripts/validate-catalogs.py` | PASS — catalog validation passed. |
| `python3 scripts/validate-repository.py` | Blocked before repository checks by the environment fixed-tool gate (`status=blocked`, no child output). |
| `/Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/ruff check tests/test_readme_contract.py tests/test_docs.py tests/test_compatibility.py` | PASS — all checks passed. |
| `/Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/ruff format --check tests/test_readme_contract.py tests/test_docs.py tests/test_compatibility.py` | PASS — 3 files already formatted. |
| `git diff --check` | PASS. |

## Changed files

- `README.md` — Pi provenance, commands, consent, package/lifecycle, model/provider, inventories, ownership, uninstall, offline, and OS boundary.
- `SECURITY.md` — third-party execution boundary, drift/receipt handling, redacted diagnostics, provider/credential exclusion, no automatic package rollback, and fail-closed platform wording.
- `docs/COMPATIBILITY.md` — canonical seven-column projection with intended Pi evidence and explicit unreleased boundary.
- `docs/RELEASING.md` — Task 11-only release gate, exact package/runtime evidence, integrity/dependency/lifecycle review, smoke and manual governance.
- `tests/test_readme_contract.py` — README contracts.
- `tests/test_docs.py` — SECURITY/RELEASING contracts.
- `tests/test_compatibility.py` — projection parity and unreleased-row contracts.

## Remaining risks

- The canonical repository validator could not run because this environment's
  fixed tool gate is blocked.
- The worktree-local `.venv` symlink/environment is absent; verification used
  the shared pinned repository venv supplied by the parent, without installing
  dependencies.
- Pi remains intentionally unreleased and unsupported until Task 11 completes
  its mandatory isolated real-Pi smoke and owner-approved release transition.

Implementation commit: `63517b0` (`docs: publish pi compatibility and trust boundary`)
The verification table was updated after that commit when the parent supplied
the shared pinned venv; this report-only update is intentionally separate from
the implementation commit.

## Review round 1 follow-up

Added a complete compatibility-table projection contract. Every displayed
column for Codex, OpenCode, Claude Code, and Pi is now checked against parsed
matrix rows, canonical target descriptors/capabilities, and the reviewed Pi
package policy. Existing projection and Pi-boundary assertions remain intact;
no documentation or catalog content changed.

Verification:

- `PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python -m unittest tests.test_compatibility tests.test_docs -v` — PASS (35 tests).
- `/Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/ruff check tests/test_compatibility.py` — PASS.
- `/Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/ruff format --check tests/test_compatibility.py` — PASS.
- `git diff --check` — PASS.

Review-round-1 follow-up commit: `b63f4da` (`test: enforce full compatibility projection parity`)
