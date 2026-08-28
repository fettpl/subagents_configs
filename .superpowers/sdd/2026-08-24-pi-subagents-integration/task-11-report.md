# Task 11 implementation report

## Result

Task 11 CI/release contracts are implemented on `feat/pi-task11-release-integration`.
The canonical compatibility matrix remains truthful: Pi is still
`supported: false` and `status: "unreleased"` because this environment has no
externally supplied exact Pi 0.84.1 executable or real-Pi release evidence.

## Changes

- Ordinary CI now runs the checked-in Pi catalog/package/effective/integration
  contracts, the explicit unavailable smoke selector, catalog validation, Ruff
  check/format, compileall, and existing shell checks without invoking Pi,
  providers, or package installation for Pi.
- A manual `workflow_dispatch` `pi-release` job requires an externally supplied
  absolute, regular, owner-only executable, verifies exact Pi 0.84.1, and runs
  the complete `PiReleaseSmokeTests` suite. Missing or mismatched evidence
  fails closed.
- `scripts/run_pi_provider_smoke.py` is a separate authorized-only command.
  It validates a reviewed provider/credential allowlist, uses fixed offline
  and disabled-context arguments, bounds child output, and emits only the
  versioned safe result schema. It never records credentials, environment,
  prompt, response, or transcript and never invokes a package manager or
  network client.
- Compatibility gained a side-effect-free release-only predicate requiring
  exact successful smoke/package evidence and all release gates; no support
  transition is performed.
- Release and compatibility documentation now describe exact evidence fields,
  provider authorization, safe-result handling, and the unreleased boundary.

## Verification

The following passed with the canonical interpreter:

```text
scripts/validate-catalogs.py
877 discovered tests (OK; 1 skipped)
PiSmokeTests.test_selector_reports_explicit_unavailable
ruff check subagents_configs scripts tests
ruff format --check subagents_configs scripts tests
sh -n ./*.sh
shellcheck install.sh uninstall.sh install-codex.sh uninstall-codex.sh install-opencode.sh uninstall-opencode.sh install-claude-code.sh uninstall-claude-code.sh
python -m compileall -q subagents_configs scripts tests
git diff --check
```

Provider tests use only fake executables and synthetic credentials. No real Pi,
provider, network, package installation, or support-evidence synthesis was
performed.

## Review round 1 follow-up

All 11 review findings are covered by the current implementation and
adversarial tests:

- provider children use a bounded selector loop, a private process group, and
  group termination; EOF cannot bypass the deadline and descendants are
  cleaned up;
- executable identity is owner-only, rejects group/other writes, and is
  rechecked around every version/provider spawn;
- provider result publication uses the no-follow, descriptor-bound atomic
  writer with file and parent-directory durability and no path-based chmod;
- the live provider child uses the reviewed LF-delimited JSON RPC contract,
  fixed disabled-authority flags, and only the selected provider's bounded,
  control-free credential strings;
- the release workflow bootstraps the hash-locked environment and invokes the
  supplied executable through `release=True` before the full release suite;
- compatibility transition input is a sealed, exact schema rather than the
  prior caller-controlled partial mapping;
- the required hyphenated provider script and release helper are direct
  executable entrypoints, with repository-import tests; and
- static security tests reject direct network-client imports with adversarial
  `urllib`, `requests`, `http.client`, and `socket` fixtures.

The canonical venv verification after the follow-up passed:

```text
PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python scripts/validate-catalogs.py — passed
PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v — 891 passed, 1 skipped
PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python -m unittest tests.test_pi_smoke.PiSmokeTests.test_selector_reports_explicit_unavailable -v — passed
/Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/ruff check subagents_configs scripts tests — passed
/Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/ruff format --check subagents_configs scripts tests — passed (87 files)
sh -n ./*.sh — passed
shellcheck install.sh uninstall.sh install-codex.sh uninstall-codex.sh install-opencode.sh uninstall-opencode.sh install-claude-code.sh uninstall-claude-code.sh — passed
PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python -m compileall -q subagents_configs scripts tests — passed
git diff --check — passed
```

The direct provider entrypoint was verified first as a failing `126`
permission-denied invocation, then as a passing executable invocation after
the mode fix. No real Pi, provider, network, package installation, or
download was performed.

## Review round 2 follow-up

The final five review findings were resolved with regression coverage: process
groups are escalated to `SIGKILL` even after a leader exits; the manual gate
requires a trusted pre-provisioned release runner; complete safe smoke facts
are bound to the release-transition proof; provider argv are fixture-validated;
and the release helper writes bounded safe evidence rather than reducing it to
an `OK` line. Pi remains source-unreleased because no external real-Pi evidence
was supplied.

Fresh ordinary verification on the complete follow-up diff:

```text
PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q — 894 passed, 1 skipped
PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python -m unittest tests.test_pi_provider_smoke tests.test_ci tests.test_compatibility tests.test_pi_smoke tests.test_security_static -q — 105 passed
PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python scripts/validate-catalogs.py — passed
/Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/ruff check subagents_configs scripts tests — passed
/Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/ruff format --check subagents_configs scripts tests — passed
sh -n ./*.sh; shellcheck install.sh uninstall.sh install-codex.sh uninstall-codex.sh install-opencode.sh uninstall-opencode.sh install-claude-code.sh uninstall-claude-code.sh; PYTHONDONTWRITEBYTECODE=1 /Users/pawel/Documents/GitHub/subagents_configs/.venv/bin/python -m compileall -q subagents_configs scripts tests; git diff --check — passed
```

The printed release-evidence objects above were generated solely by fake test
executables and contain only the explicitly safe schema fields.
