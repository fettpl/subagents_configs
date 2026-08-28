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
