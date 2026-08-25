# Task 3 report — validation isolation, casefolded inventory, and real backend gates

Status: complete
Commit: final `HEAD` (`fix: enforce casefolded validation isolation policy`)

## TDD record

- RED: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_validation_git_snapshot tests.test_validation_runner tests.test_validation_smoke -v` failed on mixed-case `.ENV.PROD` inventory inclusion and missing `CleanupResult`/`cleanup_validation_root` interfaces.
- GREEN: the same focused suite passed after implementing the shared policy, typed cleanup result, and probe/smoke coverage (the local fixed Seatbelt host is unavailable for execution and is explicitly skipped by the smoke test).

## Changed files

- `scripts/validation_isolation/git_snapshot.py`: added shared `casefold()` protected-component/path policy and applied it to tracked and non-ignored-untracked inventory parsing; removed raw Git diagnostics/path values from public errors.
- `scripts/validation_isolation/backend.py`: extended the real probe with `/etc/hosts` denial and snapshot-read checks while preserving fixed backend and command-boundary validation.
- `scripts/validation_isolation/runner.py`: added bounded typed `ValidationFailure`/`CleanupResult`, cleanup precedence, and the typed process-runner interface.
- `scripts/validation_isolation/cli.py`: sanitized generic failure output at the CLI boundary.
- `scripts/validation_isolation/environment.py`: documented and retained the source-environment isolation contract.
- `tests/test_validation_smoke.py`: added mixed-case inventory, cleanup precedence/redaction, and real fixed-backend six-property smoke coverage.
- `.github/workflows/ci.yml`: runs Linux and macOS matrix entries with fixed backend and `/usr/bin/shellcheck` fail-closed checks; no runtime backend/tool installation or unsandboxed fallback.

## Requirement mapping

- SEC-02: one casefolded explicit credential/environment/cache policy; tracked ignored benign source remains visible; NUL parsing, canonical traversal, symlink/special rejection, deterministic ordering, and checkout identity checks remain intact.
- TEST-01: real backend probe covers network denial, `/etc/hosts` denial, snapshot read, private `0600` marker, namespace separation, and requested child exit `23`; cleanup failure is bounded/typed and never replaces primary failure.
- CI gates select only `/usr/bin/bwrap`/`/bin/bwrap` or `/usr/bin/sandbox-exec`, and fail closed when fixed backend or `/usr/bin/shellcheck` is unavailable.

## Self-review and concerns

- No fake process runner is used by the real smoke assertion; fake runners remain confined to existing unit seams.
- The current development host exposes `/usr/bin/sandbox-exec` but denies Seatbelt application, so the real smoke test reports an explicit host execution skip locally. CI fixed-backend selection remains fail-closed.
- CI keeps the existing Python 3.11/3.14 matrix and private job-local homes/cache roots.

## Verification

- Focused: 73 tests passed, 1 explicit unsupported-host smoke skip.
- Full discovery: 392 tests passed, 1 explicit unsupported-host smoke skip.
- `ruff check scripts tests`: passed.
- `ruff format --check scripts tests`: passed.
- `sh -n ./*.sh`: passed.
- `git diff --check`: passed.

## Fix round 1/5

Status: complete (review findings addressed)

### TDD record

- RED: the new cleanup-precedence tests failed because cleanup replaced successful/nonzero child results and probe failures; cleanup results lacked a stable primary-presence flag; the real smoke broadly skipped a present-but-denied backend.
- GREEN: focused validation suite passed with cleanup status evidence, fixed probe diagnostics, child nonzero `23` preservation, and required/optional smoke modes.

### Changes and review mapping

- `run_isolated` now establishes the primary exception/result before cleanup. Backend/probe failures are fixed bounded diagnostics and win over cleanup; successful and nonzero child results remain observable with `cleanup=<code>` evidence.
- `CleanupResult` exposes only `code` and `primary_present`; arbitrary primary messages are not a public cleanup field.
- Local smoke mode defaults to optional for hosts that cannot apply Seatbelt; CI exports `VALIDATION_SMOKE_MODE=required`, so a present-but-unusable fixed backend fails the job rather than skipping.
- The benign tracked smoke fixture is added only after asserting `.gitignore` matches it, using force-add to retain it as tracked source.

### Fix-round verification

- Focused: 76 tests passed, 1 explicit local optional smoke skip.
- Full discovery: 395 tests passed, 1 explicit local optional smoke skip.
- `ruff check scripts tests`: passed.
- `ruff format --check scripts tests`: passed.
- `sh -n ./*.sh`: passed.
- `git diff --check`: passed.
