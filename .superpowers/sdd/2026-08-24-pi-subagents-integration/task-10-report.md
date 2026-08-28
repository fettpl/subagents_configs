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
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_readme_contract tests.test_docs tests.test_compatibility -v` | Blocked: `.venv/bin/python` is absent in this checkout. |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_docs tests.test_compatibility -v` | PASS — 34 tests. |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_readme_contract.ReadmeContractTests.test_pi_provenance_lifecycle_and_trust_boundary_are_documented tests.test_readme_contract.ReadmeContractTests.test_pi_commands_and_ownership_are_exact -v` | PASS — 2 tests. |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_readme_contract tests.test_docs tests.test_compatibility -v` | Partial under system Python: documentation/compatibility assertions pass, but the existing parsed-agent test cannot import unavailable PyYAML. |
| `PYTHONDONTWRITEBYTECODE=1 python3 -c 'import ast; ...'` (three changed Python tests) | PASS — all files parse. |
| `python3 scripts/validate-catalogs.py` | Blocked: PyYAML is unavailable for OpenCode source validation. |
| `python3 scripts/validate-repository.py` | Blocked before repository checks by the environment fixed-tool gate (`status=blocked`, no child output). |
| `ruff check ...` / `ruff format --check ...` | Not run: Ruff is not installed in this checkout. |
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

- The full focused command and catalog validator require the repository's
  PyYAML-enabled `.venv`, which was not present; no dependency was installed.
- The canonical repository validator could not run because this environment's
  fixed tool gate is blocked.
- Ruff is unavailable, so its checks must be run by the parent/release gate in
  the normal pinned developer environment.
- Pi remains intentionally unreleased and unsupported until Task 11 completes
  its mandatory isolated real-Pi smoke and owner-approved release transition.

Commit: pending
