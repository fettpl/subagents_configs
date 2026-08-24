# Re-review Hardening Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every security and CI gap confirmed by the 2026-08-24 re-review while preserving the existing installer, transaction, and multi-client contracts.

**Architecture:** Keep the existing catalog parser, preflight planner, validation snapshot helper, and CI workflow boundaries. Tighten each boundary independently with behavioral regression tests: explicit OpenCode permissions, safe post-render validation, source-aware snapshot filtering, and temporary-only Python bytecode in CI.

**Tech Stack:** Python 3.11/3.14 standard library, PyYAML, POSIX shell, Ruff, ShellCheck, GitHub Actions.

**Spec:** `/Users/pawel/Downloads/PROMPT_GPT-5.6-SOL_HARDEN_SUBAGENTS_CONFIGS.md`, plus the confirmed findings in the 2026-08-24 re-review.

## Global Constraints

- Use strict test-first RED/GREEN cycles and record both commands and outcomes in the task report.
- Do not weaken fail-closed validation, no-network enforcement, symlink protections, atomic transactions, manifest validation, or conservative uninstall behavior.
- Do not add network downloads, new runtime dependencies, `eval`, `shell=True`, or shell command-string execution.
- Preserve support for selecting Codex, OpenCode, Claude Code, or any combination; Pi remains excluded.
- `commit-pusher` and global routing remain explicit opt-ins.
- All tests and reproduction fixtures must use temporary directories and must not touch real client homes.
- Each task must commit only its scoped files and must not push, merge, rebase, amend, reset, or clean.

---

### Task 1: Enforce OpenCode Role Permissions

**Files:**
- Modify: `opencode/agents/code-explorer.md`
- Modify: `opencode/agents/code-reviewer.md`
- Modify: `opencode/agents/code-validator.md`
- Modify: `subagents_configs/formats.py`
- Modify: `tests/test_catalogs.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: OpenCode Markdown frontmatter parsed by `validate_yaml_agent()` and checked by `validate_agent_semantics()`.
- Produces: explicit deny-by-default read-role permissions and a validator whose only permitted shell shape invokes the rendered isolated helper.

- [ ] **Step 1: Write failing behavioral catalog tests**

Add tests proving that explorer/reviewer explicitly deny `edit`, `bash`, `external_directory`, `webfetch`, `websearch`, `task`, and `skill`; that validator explicitly denies editing, web tools, task, and skill; and that validator `bash` permissions deny `*` before narrowly allowing only `python3 {{VALIDATION_HELPER}} -- ...` invocation patterns. Add negative semantic tests showing that a missing validator permission block, omitted `websearch`, or a broad validator bash allow is rejected.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 /private/tmp/subagents-configs-venv/bin/python -m unittest tests.test_catalogs -v`

Expected: failures identify the currently missing validator permissions and missing `websearch`/`skill` denies.

- [ ] **Step 3: Implement the minimal permission and semantic-validation changes**

Use current official OpenCode `permission` syntax. The validator must not receive a general-purpose shell allowance: catch-all bash denial precedes only exact helper invocation patterns containing `{{VALIDATION_HELPER}}`; all dedicated network, edit, delegation, skill, and external-directory capabilities are denied except the minimum external path needed to invoke the helper. Semantic validation must fail closed on absent or broadened protected permissions.

- [ ] **Step 4: Update the README policy matrix/explanation from parsed catalog facts**

Document the explicit OpenCode permission boundary and retain a clear statement that parent/session policy can further restrict roles but must never be broadened by these files.

- [ ] **Step 5: Verify GREEN and commit**

Run the focused catalog tests, `scripts/validate-catalogs.py`, Ruff check/format, and `git diff --check`.

Commit message: `fix: enforce OpenCode validator permissions`

---

### Task 2: Validate Fully Rendered Agent Configurations

**Files:**
- Modify: `subagents_configs/planning.py`
- Modify: `subagents_configs/formats.py` only if a reusable rendered-source validator is required
- Modify: `tests/test_planning.py`
- Modify: `tests/test_full_install_matrix.py` if an installed-file parse assertion belongs in the matrix

**Interfaces:**
- Consumes: `ValidatedSource`, target home paths, and `{{VALIDATION_HELPER}}` substitution.
- Produces: `bytes` that have been parsed and semantically validated after substitution, or a preflight error before any target write.

- [ ] **Step 1: Write failing hostile-path regression tests**

Add tests using a Codex home containing `\"\"\"` and client homes containing newline/control characters. Assert that `preflight_install()` rejects them without operations or filesystem mutation. Add an install-matrix assertion that every rendered Codex TOML and OpenCode/Claude YAML-frontmatter agent remains parseable after a normal path with spaces is substituted.

- [ ] **Step 2: Run focused tests and verify RED**

Run the exact new `tests.test_planning` selectors. The triple-quote case must fail because preflight currently accepts content that `tomllib` rejects.

- [ ] **Step 3: Implement safe rendering and post-render validation**

Reject path characters that can terminate or structurally inject into TOML/YAML/Markdown prompt contexts, while preserving ordinary absolute paths including spaces and Unicode. After replacement, parse the complete rendered agent using its declared format and re-run semantic validation before returning bytes to the plan. Never repair malformed output after planning and never write before this check passes.

- [ ] **Step 4: Verify GREEN and commit**

Run focused planning/install-matrix tests, catalog validation, Ruff, and `git diff --check`.

Commit message: `fix: validate rendered agent configurations`

---

### Task 3: Make Validation Snapshots Secret-Safe and Complete

**Files:**
- Modify: `scripts/validation_isolation/git_snapshot.py`
- Modify: `tests/test_validation_git_snapshot.py`
- Modify: `README.md`
- Modify: `SECURITY.md` if the threat-model wording needs the same qualification

**Interfaces:**
- Consumes: Git tracked inventory and non-ignored untracked inventory.
- Produces: deterministic snapshot paths that include tracked changes even when `.gitignore` matches them, exclude common credential-bearing paths such as `credentials.json`, and retain existing traversal/symlink/special-file rejection.

- [ ] **Step 1: Write failing inventory tests**

Add a real temporary Git repository test proving `credentials.json`, `.npmrc`, `.pypirc`, `.netrc`, private-key names, and credential-store paths are excluded whether tracked or untracked. Change the tracked-ignored test to require a benign tracked ignored file to remain included. Retain tests proving ignored untracked files, `.env*`, caches, `.git`, symlinks, and special files are excluded or rejected.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 /private/tmp/subagents-configs-venv/bin/python -m unittest tests.test_validation_git_snapshot -v`

Expected: `credentials.json` is currently included and a benign tracked ignored file is currently omitted.

- [ ] **Step 3: Implement source-aware inventory filtering**

Inventory tracked and non-ignored untracked paths separately. Do not subtract tracked paths merely because `.gitignore` matches them. Apply explicit common-secret exclusions to both inventories, and apply cache/ignored-untracked exclusions without hiding benign tracked source changes. Keep NUL-delimited parsing, canonical path checks, deterministic ordering, and fail-closed behavior.

- [ ] **Step 4: Make documentation precise**

Replace the absolute README claim that all secrets are absent with the exact enforced exclusions and state that users must not commit secrets under unrecognized names. Do not weaken the guarantee for environment-secret filtering or network isolation.

- [ ] **Step 5: Verify GREEN and commit**

Run focused snapshot/environment/runner tests, Ruff, and `git diff --check`.

Commit message: `fix: harden validation snapshot inventory`

---

### Task 4: Keep CI Writes Inside Its Temporary Root

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/test_ci.py`

**Interfaces:**
- Consumes: the existing `ci_root` temporary directory and repository quality commands.
- Produces: CI checks whose Python bytecode/cache writes are redirected below `ci_root`, followed by an enforced clean-checkout assertion.

- [ ] **Step 1: Write failing CI contract tests**

Require the workflow to set `PYTHONDONTWRITEBYTECODE=1` and `PYTHONPYCACHEPREFIX` below `ci_root` before Python repository commands, and require a final command that exits nonzero when tracked or untracked checkout state changed. Ensure `git status` is not merely informational.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 /private/tmp/subagents-configs-venv/bin/python -m unittest tests.test_ci -v`

Expected: failures identify missing bytecode redirection and missing enforced cleanliness.

- [ ] **Step 3: Update the workflow minimally**

Create/chmod the redirected pycache directory under `ci_root`, export both Python variables, retain `compileall` as a syntax check, and replace the informational final status with a fail-closed clean-tree check that reports differences before exiting.

- [ ] **Step 4: Verify GREEN and commit**

Run `tests.test_ci`, YAML parsing, Ruff for the test, ShellCheck-equivalent shell syntax review of the workflow block where practical, and `git diff --check`.

Commit message: `fix: confine CI-generated files to temp`

---

### Final Verification

- [ ] Run all 346+ unit and integration tests with `PYTHONDONTWRITEBYTECODE=1`.
- [ ] Run catalog validation, real backend integration, Ruff check/format, ShellCheck, POSIX shell syntax, redirected `compileall`, and `git diff --check`.
- [ ] Re-run the hostile-home and `credentials.json` reproductions.
- [ ] Confirm the worktree is clean and review the complete range from `5f7b8ca` to final HEAD for security, correctness, documentation accuracy, and scope.
