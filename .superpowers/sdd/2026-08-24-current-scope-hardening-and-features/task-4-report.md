# Task 4 report — Claude technical command gate and catalog semantics

Status: complete
Commit: planned `fix: gate Claude validator commands technically`

## TDD record

- RED: the focused gate test could not load the absent
  `claude-code/hooks/code-validator-pretooluse.py`; the pre-existing catalog
  policy also did not reject the mutated Claude validator authority.
- GREEN: the focused gate, catalog, routing, static-security, and full-matrix
  suite passes after adding the standalone gate, managed settings lifecycle,
  and exhaustive target/role semantic checks.

## Changed files

- `claude-code/hooks/code-validator-pretooluse.py`: standalone standard-library
  Claude `PreToolUse` parser and fixed-argv validator. It emits only the fixed
  denial diagnostic and never executes a command.
- `claude-code/agents/code-validator.md` and `README.md`: document the
  technical hook boundary and its non-executing, fixed-helper contract.
- `subagents_configs/models.py` and `subagents_configs/targets.py`: add typed
  command-gate and managed-JSON-setting descriptors for Claude.
- `subagents_configs/formats.py`: enforce model, tool, permission, rule-order,
  helper, body, role, and optional-role catalog contracts.
- `subagents_configs/planning.py`: preserve unrelated `settings.json` keys,
  reject conflicting Bash hooks, and record file/setting ownership and
  evidence.
- `subagents_configs/state.py` and `subagents_configs/transaction.py`: decode,
  validate, inventory, install, rollback, and uninstall command-gate files and
  setting-owned entries conservatively.
- `tests/helpers.py`, `tests/test_full_install_matrix.py`, and
  `tests/test_security_static.py`: include the managed hook in isolated source,
  lifecycle, mode, and static inventories.
- `tests/test_claude_command_gate.py`: parser, hostile-input, no-execution,
  conflict, preservation, ownership, and lifecycle coverage.

## Requirement mapping

- SEC-03: Claude validator Bash is exposed only for the managed `PreToolUse`
  seam; the hook accepts exactly `python3 <absolute-helper> -- <safe argv>` and
  treats all event/command data as hostile.
- TEST-02: source inventories fail closed on catalog authority broadening,
  missing semantics, helper drift, body-contract drift, role drift, and
  optional-role inventory changes.
- Lifecycle: unrelated settings survive installation; conflicting Bash hooks
  fail before writes; only unchanged repository-owned hook files/settings are
  removed on uninstall.

## Self-review and concerns

- The hook uses only Python standard-library parsing/path utilities and has no
  subprocess, shell, network, credential, dynamic-import, or package behavior.
- The installer does not construct or execute a validation command; it only
  renders the installed hook path into the managed settings entry.
- The command-gate file is intentionally owner-private executable (`0700`);
  all other managed files remain `0600`.
- Task 5 registry/generator work and Pi behavior are intentionally absent.

## Verification

- Focused: 52 tests passed.
- Full discovery: 404 tests passed, 1 explicit unsupported-host validation
  smoke skip.
- `scripts/validate-catalogs.py`: passed.
- Ruff check and format check: passed.
- Python compileall: passed.
- `git diff --check`: passed.

## Fix round 1/5 — controller review closure

Status: complete
Commit: pending `fix: scope Claude command gate to validator agent`

### TDD record

- RED: the new realistic-event and post-`--` attack cases failed against the
  two-key parser and permissive argv validator; the old settings lifecycle did
  not prove role scope; and syntax-only command-gate validation accepted a
  mutated unconditional allow source.
- GREEN: the revised focused suite passes after moving the hook into validator
  agent frontmatter, removing global settings ownership, hardening the parser
  and argv contract, and adding semantic source/catalog checks.

### Review mapping

- Claude `PreToolUse` is now rendered only in `code-validator` frontmatter with
  the deterministic absolute installed hook path. Global `settings.json`
  managed-setting models, planning, state, transaction, and lifecycle logic
  were removed. The installed executable hook file remains managed normally.
- Hook input requires the realistic common event fields, validates documented
  optional fields and `agent_type`, rejects duplicate/unknown/type changes,
  and keeps fixed diagnostics/no execution.
- Post-helper argv rejects shells, launchers, interpreters, absolute or
  executable paths, assignments, traversal, glob, and tilde expansion while
  retaining finite validation command data.
- Command-gate source validation now checks AST imports/calls, required
  parser/validator/hook symbols, fixed statuses, policy constants, and the
  non-executing validation path.
- YAML duplicate/unknown frontmatter, OpenCode permission maps/order, and
  Claude role-scoped hook/tool contracts are fail-closed and mutation-tested.
- README describes role-scoped enforcement; active Ruff/format checks include
  `claude-code`.

### Fix-round verification

- Focused: 55 tests passed.
- Full discovery: 407 tests passed, 1 explicit unsupported-host validation
  smoke skip.
- `scripts/validate-catalogs.py`: passed.
- Ruff check and format check over `claude-code subagents_configs scripts tests`:
  passed.
- Compileall over `claude-code subagents_configs scripts tests`: passed.
- `git diff --check`: passed.

### Concerns

- Claude installations on versions without agent-frontmatter hooks must be
  rejected by future compatibility validation rather than silently falling
  back to a global hook; no global authority-changing fallback is retained.
