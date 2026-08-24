# Secure Multi-Client Subagent Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a secure, fail-closed distribution and transactional installer for Codex, OpenCode, and Claude Code subagents, with isolated validation, complete documentation, and least-privilege CI.

**Architecture:** Native role catalogs and routing policies are validated by a shared Python 3.11+ engine before any target is touched. The engine plans every selected target in memory, applies per-file atomic operations through a journal, and rolls the whole logical transaction back on failure. A separately installable validation helper snapshots the active Git worktree and runs argv-only commands behind a probed macOS `sandbox-exec` or Linux Bubblewrap boundary.

**Tech Stack:** POSIX `sh`, Python 3.11+, `tomllib`, PyYAML 6.0.3, standard-library `unittest`, Ruff 0.16.3, ShellCheck, GitHub Actions, macOS `/usr/bin/sandbox-exec`, Linux `bwrap`.

**Spec:** `docs/superpowers/specs/2026-08-20-secure-multi-client-subagent-distribution-design.md`

**Version references:** [PyYAML 6.0.3](https://pypi.org/project/PyYAML/),
[Ruff 0.16.3](https://pypi.org/project/ruff/),
[actions/checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1),
and [actions/setup-python v7.0.0](https://github.com/actions/setup-python/releases/tag/v7.0.0).

## Global Constraints

- Supported targets are exactly `codex`, `opencode`, and `claude-code`; Pi and `pi-coding-agent` are out of scope.
- Runtime requires POSIX `sh` and Python 3.11 or newer.
- OpenCode and Claude Code operations require PyYAML 6.0.3; Codex-only operations must not import or require PyYAML.
- Installers never download code or dependencies, invoke `sudo`, or modify system files.
- A command without `--target` or `--all` is an error before any write.
- Global routing, Codex multi-agent configuration, and `commit-pusher` are opt-in only.
- Every selected target passes a complete read-only preflight before the first selected target is modified.
- Existing homes, managed path components, sources, targets, state, journals, manifests, and backups must not be symlinks.
- Managed directories use modes no broader than `0700`; managed files, state, journals, manifests, and backups use modes no broader than `0600`.
- State contains identifiers, paths, hashes, ownership, and status only; it never contains prior private file contents in JSON, Base64, or another encoding.
- Validation accepts only `python3 scripts/run-validation-isolated.py -- COMMAND ARG...`, builds the child environment from empty state, and has no unsandboxed fallback.
- macOS validation requires a successful `sandbox-exec` probe; Linux validation requires a successful Bubblewrap probe; all other platforms fail closed.
- Implementation and verification must not commit, push, open a PR, modify remotes, alter credentials, or change repository-host settings.
- The normal per-task “commit” step is replaced by a status/diff checkpoint because the user explicitly prohibited commits.

---

## File Structure

### Shared installer package

- Create `subagents_configs/__init__.py` — package version and exported target names.
- Create `subagents_configs/__main__.py` — module entry point.
- Create `subagents_configs/errors.py` — concise typed operational errors.
- Create `subagents_configs/models.py` — immutable request, descriptor, plan, manifest, and journal models.
- Create `subagents_configs/cli.py` — exact option parsing, target expansion, home precedence, and help rendering.
- Create `subagents_configs/targets.py` — static, repository-controlled target descriptors and exact source inventories.
- Create `subagents_configs/formats.py` — TOML/YAML parsing and role-policy invariants.
- Create `subagents_configs/paths.py` — containment, `lstat`, file-type, and symlink checks.
- Create `subagents_configs/filesystem.py` — hashes, private directories, exclusive backups, atomic writes, and directory sync.
- Create `subagents_configs/state.py` — strict manifest/journal decoding and encoding.
- Create `subagents_configs/blocks.py` — unique managed-block inspection, insertion, and exact removal.
- Create `subagents_configs/planning.py` — side-effect-free cross-target install/uninstall planning.
- Create `subagents_configs/transaction.py` — journaled apply, rollback, and recovery.
- Create `subagents_configs/orchestrator.py` — recovery, preflight, plan display, dry-run, apply, and exit handling.
- Create `scripts/manage-subagents-configs.py` — thin repository entry point that imports the fixed package from the repository root.
- Create `scripts/validate-catalogs.py` — read-only catalog/routing validator using `targets.py` and `formats.py`.

### Native distributions

- Modify the six `agents/*.toml` Codex definitions.
- Create six `opencode/agents/*.md` definitions.
- Create six `claude-code/agents/*.md` definitions.
- Modify `rules/SUBAGENT_ROUTING.md` for Codex.
- Create `rules/OPENCODE_SUBAGENT_ROUTING.md` and `rules/CLAUDE_SUBAGENT_ROUTING.md`.
- Modify `templates/AGENTS.md.template` into a project-only Codex template.
- Create `templates/opencode/AGENTS.md.template` and `templates/claude-code/CLAUDE.md.template`.

### Isolated validation

- Create `scripts/run-validation-isolated.py` — thin executable entry point.
- Create `scripts/validation_isolation/__init__.py` — public helper exports.
- Create `scripts/validation_isolation/errors.py` — snapshot, backend, and mutation errors.
- Create `scripts/validation_isolation/models.py` — immutable snapshot/backend/result models and process protocols.
- Create `scripts/validation_isolation/git_snapshot.py` — Git inventory, snapshot copying, fingerprinting, and mutation detection.
- Create `scripts/validation_isolation/environment.py` — exact child environment and private directories.
- Create `scripts/validation_isolation/backend.py` — backend selection, sandbox argv construction, and technical probe.
- Create `scripts/validation_isolation/runner.py` — isolated orchestration and bounded evidence.
- Create `scripts/validation_isolation/cli.py` — exact `--` parsing and exit codes.

The installer copies the launcher plus this package to
`<target-home>/.subagents_configs/validation/`. Agent sources contain the
literal `{{VALIDATION_HELPER}}`; planning replaces it with the normalized
installed launcher path before hashing and writing the role definition.

### Wrappers, tests, documentation, and CI

- Modify `install.sh`, `uninstall.sh`, `install-opencode.sh`, and `uninstall-opencode.sh`.
- Create `install-codex.sh`, `uninstall-codex.sh`, `install-claude-code.sh`, and `uninstall-claude-code.sh`.
- Create `tests/__init__.py` and focused `tests/test_*.py` modules named in the tasks below.
- Create `requirements.txt`, `requirements-dev.txt`, and `pyproject.toml`.
- Rewrite `README.md`; create `SECURITY.md` and `docs/RELEASING.md`.
- Create `.github/workflows/ci.yml`.

---

### Task 1: Test Harness, Domain Models, and CLI Normalization

**Files:**

- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Create: `pyproject.toml`
- Create: `subagents_configs/__init__.py`
- Create: `subagents_configs/errors.py`
- Create: `subagents_configs/models.py`
- Create: `subagents_configs/targets.py`
- Create: `subagents_configs/cli.py`
- Create: `tests/__init__.py`
- Create: `tests/helpers.py`
- Test: `tests/test_cli.py`
- Test: `tests/test_targets.py`

**Interfaces:**

- Produces:

```python
class Target(str, enum.Enum):
    CODEX = "codex"
    OPENCODE = "opencode"
    CLAUDE_CODE = "claude-code"

@dataclass(frozen=True)
class Request:
    operation: Literal["install", "uninstall"]
    targets: tuple[Target, ...]
    homes: Mapping[Target, Path]
    enable_global_routing: bool
    enable_codex_multi_agent: bool
    include_commit_pusher: bool
    dry_run: bool

@dataclass(frozen=True)
class SourceSpec:
    identifier: str
    source: PurePosixPath
    destination: PurePosixPath | None
    kind: Literal["agent", "routing-source", "project-template", "validation-runtime"]
    source_format: Literal["toml", "yaml-frontmatter", "markdown", "python"]
    optional_role: Literal["commit-pusher"] | None = None

@dataclass(frozen=True)
class TargetDescriptor:
    target: Target
    environment_variable: str
    default_home: str
    global_filename: str
    config_filename: str | None
    sources: tuple[SourceSpec, ...]

def parse_request(
    operation: Literal["install", "uninstall"],
    argv: Sequence[str],
    environ: Mapping[str, str],
) -> Request: ...

def descriptor_for(target: Target) -> TargetDescriptor: ...
def selected_sources(
    descriptor: TargetDescriptor,
    include_commit_pusher: bool,
) -> tuple[SourceSpec, ...]: ...
```

- Later tasks consume `Request`, `SourceSpec`, `TargetDescriptor`, and the exact descriptor order `(codex, opencode, claude-code)`.

Agent and validation-runtime sources have managed destinations. Routing and
project-template sources have `destination=None`: they are always validated,
but routing content is written only inside an opted-in managed block and
project templates are never installed globally.

- [ ] **Step 1: Add exact dependency and formatter configuration**

`requirements.txt`:

```text
PyYAML==6.0.3
```

`requirements-dev.txt`:

```text
-r requirements.txt
ruff==0.16.3
```

Configure Ruff in `pyproject.toml` with `target-version = "py311"`,
`line-length = 88`, `extend-exclude = [".git"]`, and lint selections
`E`, `F`, `I`, `B`, `UP`, `S`, and `RUF`. Per-file ignores may allow only
`S101` in `tests/**/*.py`.

- [ ] **Step 2: Write failing CLI and descriptor tests**

Create tests with these exact cases:

```python
class CliTests(unittest.TestCase):
    def test_requires_target(self): ...
    def test_all_expands_in_descriptor_order(self): ...
    def test_rejects_all_mixed_with_target(self): ...
    def test_rejects_repeated_target(self): ...
    def test_rejects_duplicate_home(self): ...
    def test_rejects_home_for_unselected_target(self): ...
    def test_rejects_unknown_option(self): ...
    def test_cli_home_overrides_environment(self): ...
    def test_environment_home_overrides_default(self): ...
    def test_codex_multi_agent_requires_codex(self): ...
    def test_uninstall_rejects_install_only_options(self): ...

class TargetTests(unittest.TestCase):
    def test_supported_targets_are_exact(self): ...
    def test_each_inventory_is_nonempty_and_unique(self): ...
    def test_commit_pusher_is_excluded_by_default(self): ...
    def test_commit_pusher_is_selected_explicitly(self): ...
    def test_no_descriptor_mentions_pi(self): ...
```

Use `tempfile.TemporaryDirectory()` and pass an explicit environment mapping;
never read or write the process's real home.

- [ ] **Step 3: Run tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_cli tests.test_targets -v
```

Expected: import failures for the not-yet-created package interfaces.

- [ ] **Step 4: Implement the minimal models, descriptors, and parser**

Use `argparse` without abbreviation. Reject duplicate options before building
`Request`. Resolve home precedence as CLI `--home TARGET=PATH`, then the target
environment variable, then `Path.home()` plus the documented default suffix.
Call `expanduser()` but defer filesystem resolution and safety checks to Task 3.
Uninstall accepts only selection, home, and dry-run options.

- [ ] **Step 5: Run focused tests and record a no-commit checkpoint**

Run:

```sh
python3 -m unittest tests.test_cli tests.test_targets -v
git diff --check
git status --short
```

Expected: focused tests pass; status lists only intentional task files. Do not
stage or commit them.

---

### Task 2: Native Role Catalogs, Routing, and Semantic Validation

**Files:**

- Modify: `agents/code-explorer.toml`
- Modify: `agents/code-reviewer.toml`
- Modify: `agents/code-validator.toml`
- Modify: `agents/quick-implementer.toml`
- Modify: `agents/implementer.toml`
- Modify: `agents/commit-pusher.toml`
- Create: `opencode/agents/*.md` for the same six role names
- Create: `claude-code/agents/*.md` for the same six role names
- Modify: `rules/SUBAGENT_ROUTING.md`
- Create: `rules/OPENCODE_SUBAGENT_ROUTING.md`
- Create: `rules/CLAUDE_SUBAGENT_ROUTING.md`
- Modify: `templates/AGENTS.md.template`
- Create: `templates/opencode/AGENTS.md.template`
- Create: `templates/claude-code/CLAUDE.md.template`
- Create: `subagents_configs/formats.py`
- Create: `scripts/validate-catalogs.py`
- Test: `tests/test_catalogs.py`
- Test: `tests/test_routing_policy.py`

**Interfaces:**

- Consumes: `Target`, `SourceSpec`, `TargetDescriptor`, and `selected_sources()` from Task 1.
- Produces:

```python
@dataclass(frozen=True)
class ValidatedSource:
    spec: SourceSpec
    content: bytes
    sha256: str
    parsed: Mapping[str, object] | None

def validate_toml_agent(path: Path, content: bytes) -> Mapping[str, object]: ...
def validate_yaml_agent(path: Path, content: bytes) -> Mapping[str, object]: ...
def validate_agent_semantics(
    target: Target,
    role: str,
    parsed: Mapping[str, object],
    body: str,
) -> None: ...
def validate_source_inventory(
    repo_root: Path,
    target: Target,
    specs: Sequence[SourceSpec],
) -> tuple[ValidatedSource, ...]: ...
def validate_all_catalogs(repo_root: Path) -> None: ...
```

- [ ] **Step 1: Write failing catalog and routing tests**

Require exact inventories containing the six names `code-explorer`,
`code-reviewer`, `code-validator`, `quick-implementer`, `implementer`, and
`commit-pusher`. Tests must parse full TOML and full YAML frontmatter with
`yaml.safe_load`, reject unknown or duplicate roles, reject source symlinks,
and assert all of these invariants:

```python
def test_codex_catalog_parses_and_has_exact_inventory(): ...
def test_opencode_catalog_parses_and_has_exact_inventory(): ...
def test_claude_catalog_parses_and_has_exact_inventory(): ...
def test_no_active_source_contains_gpt_5_4_mini(): ...
def test_codex_explorer_and_reviewer_are_read_only(): ...
def test_opencode_read_roles_deny_edit_bash_external_directory_webfetch_task(): ...
def test_claude_read_roles_allow_only_read_grep_glob_in_plan_mode(): ...
def test_no_role_declares_write_bypass_or_network_escalation(): ...
def test_validator_models_are_luna_luna_and_inherit(): ...
def test_validator_requires_literal_helper_placeholder(): ...
def test_reviewer_contains_complete_p0_to_p3_workflow_and_verdicts(): ...
def test_commit_pusher_requires_separate_commit_and_push_request(): ...
def test_codex_catalog_validation_does_not_import_yaml(): ...
def test_yaml_target_without_pyyaml_fails_concisely(): ...
def test_routing_files_contain_full_trust_and_least_privilege_policy(): ...
def test_routing_files_and_templates_have_no_absolute_import(): ...
def test_templates_are_project_only_and_contain_real_policy_text(): ...
```

- [ ] **Step 2: Run tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_catalogs tests.test_routing_policy -v
```

Expected failures: missing OpenCode/Claude sources, stale validator model,
writable Codex commit-pusher, skill-dependent reviewer, cost-first routing,
and the absolute template import.

- [ ] **Step 3: Implement native role definitions and policy files**

Use these exact permission shapes:

```toml
# Codex explorer and reviewer
sandbox_mode = "read-only"
```

```yaml
# OpenCode explorer and reviewer frontmatter fragment
mode: subagent
permission:
  edit: deny
  bash: deny
  external_directory: deny
  webfetch: deny
  task: deny
```

```yaml
# Claude Code explorer and reviewer frontmatter fragment
tools: Read, Grep, Glob
model: inherit
permissionMode: plan
```

Codex and OpenCode validators use `gpt-5.6-luna` and
`openai/gpt-5.6-luna`; Claude uses `model: inherit`. Remove every role-local
`workspace-write`, `acceptEdits`, `bypassPermissions`, or network grant.
Every validator body must say it runs only through `{{VALIDATION_HELPER}}`,
refuses direct validation, and fails closed without a verified backend.
Every reviewer must embed its full review process and must not depend on a
named skill. Keep `commit-pusher` behavior restrictive even though it is not
installed by default.

Replace cost-first routing with the approved semantic policy. Each routing
file and project-only template must contain the actual policy text, including
untrusted repository/tool data, technical read-only enforcement, hook
inspection, network/credential/external-file restrictions, separate Git
publication authorization, least privilege, and independent verification of
security-sensitive decisions.

- [ ] **Step 4: Implement lazy native-format validation**

Use `tomllib.loads()` for Codex. Import `yaml` inside `validate_yaml_agent()`
only. Parse the bytes between the opening and closing `---` lines with
`yaml.safe_load()` and require a mapping. `validate_source_inventory()` accepts
an explicit descriptor-derived sequence and must reject a missing, empty,
symlinked, non-regular, malformed, or semantically unsafe source before
returning any `ValidatedSource`. `validate_all_catalogs()` passes agent,
routing-source, and project-template specs; planning later passes the complete
selected inventory including validation runtime files.

The CLI in `scripts/validate-catalogs.py` calls `validate_all_catalogs()` and
prints only a concise target/path error on failure.

- [ ] **Step 5: Run focused validation and record a no-commit checkpoint**

Run:

```sh
python3 scripts/validate-catalogs.py
python3 -m unittest tests.test_catalogs tests.test_routing_policy -v
git diff --check
git status --short
```

Expected: every native catalog and policy test passes. Do not stage or commit.

---

### Task 3: Safe Path and Atomic Filesystem Primitives

**Files:**

- Create: `subagents_configs/paths.py`
- Create: `subagents_configs/filesystem.py`
- Test: `tests/test_paths.py`
- Test: `tests/test_filesystem.py`

**Interfaces:**

```python
def normalized_absolute(path: Path) -> Path: ...
def strict_relative_path(value: str) -> PurePosixPath: ...
def lstat_existing(path: Path, label: str) -> os.stat_result | None: ...
def assert_contained(home: Path, candidate: Path) -> None: ...
def assert_safe_home(home: Path) -> None: ...
def assert_safe_managed_path(home: Path, candidate: Path, label: str) -> None: ...

def sha256_bytes(content: bytes) -> str: ...
def sha256_file(path: Path) -> str: ...
def ensure_private_directory(path: Path) -> None: ...
def atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None: ...
def exclusive_backup(source: Path, destination: Path) -> str: ...
def unlink_regular(path: Path) -> None: ...
```

- [ ] **Step 1: Write failing path and filesystem tests**

Create exact cases for symlink homes, intermediate components, target files,
global instructions, configs, manifests, journals, backups, absolute state
paths, `..` traversal, normalized containment, non-regular files, modes,
exclusive backup creation, atomic replacement, and failure cleanup:

```python
def test_rejects_symlink_home(): ...
def test_rejects_symlink_managed_component(): ...
def test_rejects_symlink_target_file(): ...
def test_rejects_absolute_and_parent_traversing_state_paths(): ...
def test_rejects_normalized_path_outside_home(): ...
def test_private_directories_are_0700(): ...
def test_atomic_write_uses_0600_and_replaces_complete_bytes(): ...
def test_atomic_write_fsyncs_file_and_parent_directory(): ...
def test_atomic_write_removes_same_directory_temp_on_failure(): ...
def test_backup_is_exclusive_0600_hash_verified_and_never_follows_symlinks(): ...
```

- [ ] **Step 2: Run tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_paths tests.test_filesystem -v
```

Expected: missing-module failures.

- [ ] **Step 3: Implement minimal safe primitives**

Use `os.lstat()` on every existing path component. Accept only real
directories for homes/components and regular files for managed files. Build
relative paths from `PurePosixPath`, rejecting empty components, `.`, `..`,
absolute roots, and platform separators not represented by `/`.

`atomic_write()` must create a random same-directory file with
`os.open(O_CREAT | O_EXCL | O_WRONLY, 0o600)`, write all bytes, `fsync`,
`chmod`, close, call `os.replace`, and sync the parent directory where
supported. `exclusive_backup()` uses the same safe creation pattern and
returns the SHA-256 digest. Neither helper follows a symlink.

- [ ] **Step 4: Run focused tests and record a no-commit checkpoint**

Run:

```sh
python3 -m unittest tests.test_paths tests.test_filesystem -v
git diff --check
git status --short
```

Expected: focused tests pass. Do not stage or commit.

---

### Task 4: Strict State Schemas and Managed Blocks

**Files:**

- Extend: `subagents_configs/models.py`
- Create: `subagents_configs/state.py`
- Create: `subagents_configs/blocks.py`
- Test: `tests/test_state.py`
- Test: `tests/test_blocks.py`

**Interfaces:**

```python
Ownership = Literal["created", "replaced", "preexisting"]

@dataclass(frozen=True)
class ManifestEntry:
    identifier: str
    relative_path: str
    installed_hash: str
    installed_mode: int
    ownership: Ownership
    backup_path: str | None
    backup_hash: str | None
    original_mode: int | None
    managed_block_id: str | None
    installed_block_hash: str | None
    unresolved_reason: str | None

@dataclass(frozen=True)
class Manifest:
    schema_version: int
    target: Target
    entries: tuple[ManifestEntry, ...]

@dataclass(frozen=True)
class JournalOperation:
    operation_id: str
    identifier: str
    action: str
    expected_before_hash: str | None
    expected_after_hash: str | None
    expected_before_mode: int | None
    expected_after_mode: int | None
    backup_path: str | None
    backup_hash: str | None
    status: Literal["planned", "applying", "applied", "rollback-planned", "rolled-back", "ambiguous"]

@dataclass(frozen=True)
class Journal:
    schema_version: int
    transaction_id: str
    target: Target
    participants: tuple[Target, ...]
    operation: Literal["install", "uninstall"]
    operations: tuple[JournalOperation, ...]
    rollback_status: Literal["not-started", "in-progress", "complete", "incomplete"]

def load_manifest(home: Path, descriptor: TargetDescriptor) -> Manifest | None: ...
def load_journal(home: Path, descriptor: TargetDescriptor) -> Journal | None: ...
def decode_manifest(raw: object, descriptor: TargetDescriptor, home: Path) -> Manifest: ...
def decode_journal(raw: object, descriptor: TargetDescriptor, home: Path) -> Journal: ...
def encode_manifest(manifest: Manifest) -> bytes: ...
def encode_journal(journal: Journal) -> bytes: ...

@dataclass(frozen=True)
class ManagedBlock:
    block_id: str
    begin_marker: bytes
    end_marker: bytes
    content: bytes
    sha256: str

def render_managed_block(block_id: str, body: bytes) -> ManagedBlock: ...
def insert_or_replace_block(original: bytes, block: ManagedBlock) -> bytes: ...
def remove_exact_block(original: bytes, block: ManagedBlock) -> tuple[bytes, bool]: ...
```

- [ ] **Step 1: Write failing schema and block tests**

Cover exact schema round trips and rejection of wrong types, missing fields,
unknown fields, duplicate identifiers, mismatched target names, absolute or
traversing paths, descriptor-external identifiers, invalid ownership/backup
pairings, missing or hash-mismatched backups, and symlinked state.

Validate modes as integers from `0o000` through `0o777`. `installed_mode` must
be no broader than `0o600`; `original_mode` is required only for replaced files
and managed user files whose original mode must be restored.

Require every journal in one transaction to carry the same ordered participant
list and transaction ID. Reject duplicate/unknown participants and a journal
whose own target is absent from that list; never store participant home paths.

Block tests must reject duplicate, nested, unbalanced, or ambiguous markers;
verify one insertion/replacement; remove an unchanged block while preserving
surrounding bytes; and preserve changed/missing blocks as unresolved.

Assert encoded state has no `before`, `content`, `base64`, or prior file bytes.

- [ ] **Step 2: Run tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_state tests.test_blocks -v
```

Expected: missing state and block interfaces.

- [ ] **Step 3: Implement exact schemas and block parser**

Use `schema_version = 1`. Reject every key outside the exact allowed key set.
Store manifest at `<home>/.subagents_configs/manifest.json`, journal at
`<home>/.subagents_configs/journal.json`, and backups under the relative
`backups/` directory. Validate a referenced backup's containment, regular-file
type, and hash before returning state.

Manifest identifiers must come from descriptor-managed agent/runtime files or
the exact target block IDs. Journal identifiers may additionally use the one
reserved internal identifier `state/manifest`; no state payload may introduce
another destination or operation name.

Treat an existing `.subagents_configs/` directory without a valid current
manifest or journal as an unsafe unknown state. Do not reinterpret malformed
JSON as an empty installation.

Use target-specific marker IDs `routing-codex`, `routing-opencode`,
`routing-claude-code`, and `codex-multi-agent-v2`. A block is removable only
when its exact bytes hash to the recorded `installed_block_hash`.

- [ ] **Step 4: Run focused tests and record a no-commit checkpoint**

Run:

```sh
python3 -m unittest tests.test_state tests.test_blocks -v
git diff --check
git status --short
```

Expected: focused tests pass. Do not stage or commit.

---

### Task 5: Side-Effect-Free Cross-Target Planning

**Files:**

- Create: `subagents_configs/planning.py`
- Test: `tests/test_planning.py`

**Interfaces:**

```python
@dataclass(frozen=True)
class PlannedOperation:
    target: Target
    identifier: str
    action: Literal["create", "replace", "remove", "restore", "write-block", "remove-block", "write-manifest"]
    relative_path: str
    expected_before_hash: str | None
    expected_after_hash: str | None
    expected_before_mode: int | None
    expected_after_mode: int | None
    content: bytes | None
    ownership: Ownership | None
    backup_required: bool
    managed_block_id: str | None

@dataclass(frozen=True)
class TargetPlan:
    target: Target
    home: Path
    operations: tuple[PlannedOperation, ...]
    resulting_manifest: Manifest | None
    conflicts: tuple[str, ...]

@dataclass(frozen=True)
class TransactionPlan:
    operation: Literal["install", "uninstall"]
    targets: tuple[TargetPlan, ...]

def preflight_install(repo_root: Path, request: Request) -> TransactionPlan: ...
def preflight_uninstall(repo_root: Path, request: Request) -> TransactionPlan: ...
def render_plan(plan: TransactionPlan) -> str: ...
```

- [ ] **Step 1: Write failing planning tests**

Use complete temporary source inventories and target homes from
`tests/helpers.py`. Until Tasks 9–10 create the repository's real helper,
fixtures must include the exact launcher and `validation_isolation/*.py`
descriptor paths as regular test files. Cover all seven nonempty target selections, default versus
explicit `commit-pusher`, default versus opted-in global routing, Codex feature
block creation and existing-table/type-collision behavior, normalized path
display, identical reinstall, replacement backup planning, managed drift,
stale exact cleanup, and dry-run plan rendering.

The identical reinstall test must preserve the original ownership and backup
metadata without rewriting bytes or creating a backup. Stale cleanup tests
must remove a still-exact prior `created` file, restore a still-exact prior
`replaced` file from its verified backup, and preserve any drifted stale file.
Selecting a YAML target without PyYAML must fail the complete cross-target
preflight with zero writes; a Codex-only plan must succeed under an import hook
that raises if `yaml` is requested.

An identical pre-existing destination is accepted only when its mode is no
broader than `0600`; otherwise planning reports a conflict rather than silently
changing an unowned file. Replacements and managed-block writes install mode
`0600`, record the prior mode, and restore it during rollback or final uninstall.
Directories created by the package are `0700`; existing non-state target
directories are required to be real directories but are not silently chmodded.

Add two zero-write assertions: corrupt a late Claude YAML source after valid
Codex/OpenCode setup, and corrupt a late target manifest. Snapshot every temp
home before calling preflight and assert byte-for-byte equality afterward.

Add `test_recognized_legacy_codex_manifest_converts_only_after_exact_path_and_hash_validation`
and `test_malformed_or_unknown_legacy_state_blocks_with_zero_writes`. No legacy
OpenCode state is treated as successfully managed.

- [ ] **Step 2: Run tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_planning -v
```

Expected: missing planning interfaces.

- [ ] **Step 3: Implement complete read-only preflight**

For every selected target, in descriptor order:

1. normalize and contain the home;
2. recover no state yet, but reject any existing journal until Task 6 handles it;
3. validate the exact agent, routing, project-template, validation-launcher,
   validation-package, and selected role source inventory;
4. render `{{VALIDATION_HELPER}}` to
   `<home>/.subagents_configs/validation/run-validation-isolated.py`;
5. parse every existing relevant config and proposed result;
6. `lstat` every existing managed path and state reference;
7. load and strictly validate state and backups;
8. compute target operations, ownership, hashes, backups, managed blocks,
   stale cleanup, conflicts, and resulting manifest in memory.

Do not call `mkdir`, `open` for writing, `atomic_write`, `exclusive_backup`,
or a temp-file API from planning. Sort operations by target descriptor order
then normalized relative path. Return a plan only after all selected targets
finish preflight.

- [ ] **Step 4: Run focused tests and record a no-commit checkpoint**

Run:

```sh
python3 -m unittest tests.test_planning -v
git diff --check
git status --short
```

Expected: every planning and zero-write test passes. Do not stage or commit.

---

### Task 6: Journaled Install Apply, Rollback, and Recovery

**Files:**

- Create: `subagents_configs/transaction.py`
- Test: `tests/test_transaction_install.py`

**Interfaces:**

```python
class FailureInjector(Protocol):
    def before_operation(self, operation_id: str) -> None: ...

def apply_transaction(
    plan: TransactionPlan,
    failure_injector: FailureInjector | None = None,
) -> None: ...

def recover_incomplete_journal(
    home: Path,
    descriptor: TargetDescriptor,
) -> None: ...
```

`FailureInjector` is imported directly by tests. It must never be selected by
a CLI option or environment variable.

- [ ] **Step 1: Write failing install transaction tests**

Cover private state creation, backup creation, agent/helper/global/config
writes, manifest write last, deterministic order, no-op idempotent reinstall,
mode enforcement, journal transitions, mid-target failure rollback, later
target failure rollback of earlier homes, failed rollback preservation,
hash-proven recovery, ambiguous recovery refusal, and the guarantee that
backups are never deleted automatically.

Add `test_success_syncs_all_manifests_marks_all_journals_complete_then_removes_journals`
and `test_recovery_of_complete_matching_journals_only_cleans_journal_files`.

Add a multi-target interruption test that later selects only one participant;
recovery must report the full required participant set and perform zero writes.
Recovery proceeds only when every participant home resolves from the new CLI
request and all journals agree on transaction ID, operation, and participant
order.

Use an injected counter that raises before a chosen operation. Assert the
command never reports success when any operation or rollback is incomplete.

- [ ] **Step 2: Run tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_transaction_install -v
```

Expected: missing transaction implementation.

- [ ] **Step 3: Implement journaled apply and reverse rollback**

After successful preflight, create each required state/backup directory with
`0700`, then write and sync a `0600` journal for every selected target before
the first managed target file is mutated. If preparing any journal fails,
reverse already-created transaction state or retain a validated recoverable
journal; do not start an agent, routing, config, or manifest write. Persist
status before and after every operation with `atomic_write()`. Create and hash
backups before replacement. Apply operations in plan order and write each
target manifest only after its managed file operations succeed.

After every target manifest is synced, mark every participant journal complete,
sync those writes, then unlink the complete journal files and sync their parent
directories. A crash between these steps is recovered as successful completion
only when all participant journals and manifest hashes prove that every planned
operation completed; otherwise recovery rolls back.

On failure, mark rollback in progress and reverse every completed operation
across all target plans. Restore only when current and backup hashes prove the
expected state. Mark any mismatch `ambiguous`, retain journal plus backups,
and raise an incomplete-rollback error. Recovery validates the journal and
descriptor again and completes only hash-proven reverse operations.

- [ ] **Step 4: Run focused tests and record a no-commit checkpoint**

Run:

```sh
python3 -m unittest tests.test_transaction_install -v
git diff --check
git status --short
```

Expected: install, rollback, and recovery tests pass. Do not stage or commit.

---

### Task 7: Conservative Uninstall and Unresolved State

**Files:**

- Extend: `subagents_configs/planning.py`
- Extend: `subagents_configs/transaction.py`
- Test: `tests/test_transaction_uninstall.py`

**Interfaces:**

- Consumes `preflight_uninstall()`, `apply_transaction()`, strict state, and
  exact managed-block functions.
- Produces conservative uninstall behavior through the existing interfaces;
  no second removal engine is introduced.

- [ ] **Step 1: Write failing uninstall tests**

Create cases for removing unchanged `created` files, restoring exact
`replaced` files, preserving `preexisting` files, preserving modified/missing
files, preserving changed/missing managed blocks, retaining an exact unresolved
reason, atomically reducing the manifest, removing the manifest only when
empty, mid-uninstall rollback, cross-target uninstall rollback, and dry-run
with zero writes.

Exercise routing blocks in `AGENTS.md`/`CLAUDE.md` and the optional Codex
`config.toml` feature block separately: exact blocks are removed, surrounding
bytes are preserved, and a changed or missing block remains unresolved.

Also reject symlinked targets/backups/state and backup hash mismatches before
the first uninstall write.

- [ ] **Step 2: Run tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_transaction_uninstall -v
```

Expected: uninstall plans either do not exist or violate preservation rules.

- [ ] **Step 3: Implement uninstall through the shared planner/executor**

Plan `remove` only for exact unchanged `created` bytes. Plan `restore` only
when both installed target and backup hashes match. Convert `preexisting`,
modified, missing, unsafe, ambiguous, and changed-block cases into retained
manifest entries with concise reasons. After apply, write the reduced manifest
atomically or remove only an empty manifest; never delete the state directory
or backups automatically.

- [ ] **Step 4: Run focused tests and record a no-commit checkpoint**

Run:

```sh
python3 -m unittest tests.test_transaction_uninstall -v
git diff --check
git status --short
```

Expected: conservative uninstall tests pass. Do not stage or commit.

---

### Task 8: Orchestration, Dry-Run, Help, and POSIX Wrappers

**Files:**

- Create: `subagents_configs/orchestrator.py`
- Create: `subagents_configs/__main__.py`
- Create: `scripts/manage-subagents-configs.py`
- Modify: `install.sh`
- Modify: `uninstall.sh`
- Create: `install-codex.sh`
- Create: `uninstall-codex.sh`
- Modify: `install-opencode.sh`
- Modify: `uninstall-opencode.sh`
- Create: `install-claude-code.sh`
- Create: `uninstall-claude-code.sh`
- Test: `tests/test_wrappers.py`
- Test: `tests/test_cli_integration.py`

**Interfaces:**

```python
def run(
    operation: Literal["install", "uninstall"],
    argv: Sequence[str],
    *,
    repo_root: Path,
    environ: Mapping[str, str],
    stdout: TextIO,
    stderr: TextIO,
    failure_injector: FailureInjector | None = None,
) -> int: ...
```

- [ ] **Step 1: Write failing wrapper and end-to-end CLI tests**

Test exact help, missing target, invalid options, target/home precedence,
single and multi-target install/uninstall, `--all`, dry-run zero writes,
normalized home display, default opt-outs, all explicit opt-ins, compatibility
wrappers selecting exactly one target, argv preservation, exit codes, and
concise errors.

Require distinct concise diagnostics and nonzero statuses for preflight
rejection, managed conflict, apply failure with successful rollback, apply
failure with incomplete rollback, unresolved uninstall state, and blocked
validation. Diagnostics name the target and safe path but never dump contents.

Static wrapper tests must reject embedded Python, `eval`, `sh -c`, download
commands, `sudo`, missing `umask 077`, and a missing final `exec`.
They must also prove wrappers replace inherited `PATH`, use Python isolated mode
`-I`, and that the thin Python entry point rejects Python older than 3.11
before importing the engine package.

- [ ] **Step 2: Run tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_wrappers tests.test_cli_integration -v
```

Expected: missing orchestration and wrapper behavior.

- [ ] **Step 3: Implement orchestration and thin wrappers**

The generic wrappers must have this structure and no embedded engine logic:

```sh
#!/bin/sh
set -eu
umask 077
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
export PATH
exec python3 -I "$SCRIPT_DIR/scripts/manage-subagents-configs.py" install "$@"
```

Use `uninstall` in the generic uninstaller. Compatibility wrappers resolve
their own directory and execute the corresponding generic wrapper with a
fixed `--target codex`, `--target opencode`, or `--target claude-code` before
unchanged user arguments.

`scripts/manage-subagents-configs.py` uses only Python-3.9-compatible syntax
until it checks `sys.version_info >= (3, 11)`. On failure it prints the version
floor and exits before inserting the fixed repository root into `sys.path` or
importing `subagents_configs`; on success, isolated mode has already ignored
`PYTHONPATH`, user-site packages, and user-controlled imports from the caller's
working directory.

`run()` parses selection first, loads and validates every selected target's
journal, builds one cross-target recovery plan, and only then performs any
recovery write. A dry-run reports required recovery and makes no change. After
recovery, it builds a fresh complete operation plan, prints normalized homes
and exact effects, returns after printing for dry-run, and otherwise applies
once. Return success only after every requested target and manifest completes.

- [ ] **Step 4: Run focused tests, ShellCheck, and a no-commit checkpoint**

Run:

```sh
python3 -m unittest tests.test_wrappers tests.test_cli_integration -v
shellcheck install.sh uninstall.sh install-codex.sh uninstall-codex.sh install-opencode.sh uninstall-opencode.sh install-claude-code.sh uninstall-claude-code.sh
git diff --check
git status --short
```

Expected: focused CLI tests and ShellCheck pass. Do not stage or commit.

---

### Task 9: Git Snapshot and Exact Child Environment

**Files:**

- Create: `scripts/validation_isolation/__init__.py`
- Create: `scripts/validation_isolation/errors.py`
- Create: `scripts/validation_isolation/models.py`
- Create: `scripts/validation_isolation/git_snapshot.py`
- Create: `scripts/validation_isolation/environment.py`
- Create: `tests/validation_isolated_test_support.py`
- Test: `tests/test_validation_git_snapshot.py`
- Test: `tests/test_validation_environment.py`

**Interfaces:**

```python
@dataclass(frozen=True)
class SnapshotFile:
    relative_path: PurePosixPath
    exists: bool
    sha256: str | None
    mode: int | None

@dataclass(frozen=True)
class CheckoutState:
    git_status: bytes
    files: tuple[SnapshotFile, ...]

@dataclass(frozen=True)
class GitSnapshot:
    worktree: Path
    snapshot_root: Path
    before: CheckoutState

GitRunner = Callable[[Sequence[str], Path], subprocess.CompletedProcess[bytes]]

def locate_worktree(start: Path, git_runner: GitRunner = run_git) -> Path: ...
def list_source_paths(worktree: Path, git_runner: GitRunner = run_git) -> tuple[PurePosixPath, ...]: ...
def capture_checkout_state(worktree: Path, git_runner: GitRunner = run_git) -> CheckoutState: ...
def create_snapshot(worktree: Path, destination: Path, git_runner: GitRunner = run_git) -> GitSnapshot: ...
def assert_checkout_unchanged(snapshot: GitSnapshot, git_runner: GitRunner = run_git) -> None: ...

def build_child_environment(
    source_env: Mapping[str, str],
    temp_root: Path,
    executable_dirs: Sequence[Path],
) -> dict[str, str]: ...
```

- [ ] **Step 1: Write failing real-Git snapshot and environment tests**

Use a real temporary Git repository. Cover tracked/modified/nonignored
untracked inclusion; ignored, `.git`, `.env`, `.env.*`, `.envrc`, cache,
`node_modules`, and outside-worktree exclusion; deleted tracked absence;
symlink rejection; executable-bit preservation; private modes; and fatal
content, mode, status, new-file, and deletion mutations.

Environment tests start with proxy variables, `SSH_AUTH_SOCK`, cloud/package
credentials, API keys, and names containing `TOKEN`, `SECRET`, `PASSWORD`,
`CREDENTIAL`, or `KEY`, and assert that the result is exactly these keys:

```python
SAFE_ENV_KEYS = frozenset({
    "CI", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM",
    "GIT_TERMINAL_PROMPT", "HOME", "LANG", "LC_ALL", "PATH",
    "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
})
```

Add `test_git_runner_uses_fixed_usr_bin_git_not_inherited_path`; the real
runner invokes `/usr/bin/git` and fails closed when it is absent or unsafe.

- [ ] **Step 2: Run tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_validation_git_snapshot tests.test_validation_environment -v
```

Expected: missing validation-isolation modules.

- [ ] **Step 3: Implement the snapshot and allowlist**

Inventory with NUL-delimited
`git ls-files --cached --others --exclude-standard -z`; use
`git status --porcelain=v1 -z --untracked-files=all` for status. Filter missing
tracked paths from copying while retaining their absence in the fingerprint.
`lstat` every existing component and reject all symlinks. Create directories
`0700`; copy regular files as `0600 | (source_mode & 0o111)` without `.git` or
history.

Build the child environment from `{}`. Set `CI=1`, deterministic locale,
private `HOME`/cache/config/tmp directories, sanitized executable directories,
`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, and
`GIT_TERMINAL_PROMPT=0`. Do not copy any `source_env` value.

- [ ] **Step 4: Run focused tests and record a no-commit checkpoint**

Run:

```sh
python3 -m unittest tests.test_validation_git_snapshot tests.test_validation_environment -v
git diff --check
git status --short
```

Expected: snapshot and environment tests pass. Do not stage or commit.

---

### Task 10: Fail-Closed Isolation Backends and Validation CLI

**Files:**

- Create: `scripts/validation_isolation/backend.py`
- Create: `scripts/validation_isolation/runner.py`
- Create: `scripts/validation_isolation/cli.py`
- Create: `scripts/run-validation-isolated.py`
- Test: `tests/test_validation_backend.py`
- Test: `tests/test_validation_runner.py`
- Test: `tests/test_validation_cli.py`

**Interfaces:**

```python
@dataclass(frozen=True)
class BackendSpec:
    name: Literal["macos", "linux"]
    launcher: Path
    python_executable: Path

@dataclass(frozen=True)
class ValidationResult:
    returncode: int
    stdout: str
    stderr: str
    evidence: tuple[str, ...]

ProcessRunner = Callable[[Sequence[str], Path, Mapping[str, str], float | None], subprocess.CompletedProcess[str]]

def select_backend(platform_name: str, sandbox_exec: Path, bwrap: Path | None, python_executable: Path) -> BackendSpec: ...
def render_macos_profile(snapshot_root: Path, temp_root: Path, python_executable: Path) -> str: ...
def build_backend_argv(backend: BackendSpec, command: Sequence[str], snapshot_root: Path, temp_root: Path, env: Mapping[str, str]) -> tuple[str, ...]: ...
def probe_backend(backend: BackendSpec, snapshot_root: Path, temp_root: Path, env: Mapping[str, str], process_runner: ProcessRunner = run_process) -> None: ...
def run_isolated(command: Sequence[str], start_dir: Path, platform_name: str, process_runner: ProcessRunner = run_process) -> ValidationResult: ...
def parse_command(argv: Sequence[str]) -> tuple[str, ...]: ...
def main(argv: Sequence[str] | None = None) -> int: ...
```

- [ ] **Step 1: Write failing backend, runner, and CLI tests**

Test unsupported platforms, missing/non-executable backends, macOS profile
network denial and private writes, Linux `--unshare-net`, `--die-with-parent`,
`--new-session`, `--clearenv`, writable private snapshot/temp mounts,
read-only system mounts, failed process/marker/network probes, and absence of an
unsandboxed argv.

Runner/CLI tests cover exact `--` requirements, empty commands, argv boundary
preservation, snapshot cwd, probe-before-command ordering, nonzero child status,
post-run source mutation failure, bounded output, checkout preservation, and
exit codes: usage `2`, blocked/mutation `1`, otherwise the child status.
Add `test_backend_selection_ignores_inherited_path`: backend discovery accepts
only `/usr/bin/sandbox-exec` on macOS and `/usr/bin/bwrap` or `/bin/bwrap` on
Linux, with `lstat` regular-file, ownership, and executable-mode checks.

- [ ] **Step 2: Run tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_validation_backend tests.test_validation_runner tests.test_validation_cli -v
```

Expected: missing backend, runner, and CLI behavior.

- [ ] **Step 3: Implement platform isolation and technical probes**

macOS uses `/usr/bin/sandbox-exec` with `(deny network*)`, default-deny file
writes, and write allowances only for the snapshot and private temp tree.
Linux uses `bwrap` with an unshared network namespace, a private writable
snapshot, private tmp, `/proc`, `/dev`, and only required system paths mounted
read-only. Backend and Git discovery never consult inherited `PATH`. Resolve
`sys.executable` to an absolute regular executable and mount its required
system prefix read-only on Linux. Never mount or pass the original worktree.

The probe must launch the wrapped interpreter, write a private marker, and
attempt to reach a parent loopback listener. The Linux child must also have a
different network namespace identity where `/proc` exposes it. Successful
connection, missing marker, same Linux namespace, timeout, launch failure, or
nonzero probe blocks execution.

Every process call must be equivalent to:

```python
subprocess.run(
    list(argv),
    cwd=cwd,
    env=dict(env),
    shell=False,
    capture_output=True,
    text=True,
    timeout=timeout,
)
```

`run_isolated()` always fingerprints the source checkout again in `finally`,
including after child failure. Truncate stdout/stderr into bounded evidence.
The entry point imports `validation_isolation.cli.main` only.

- [ ] **Step 4: Run focused tests and real available-backend checks**

Run:

```sh
python3 -m unittest tests.test_validation_backend tests.test_validation_runner tests.test_validation_cli -v
python3 -m unittest tests.test_validation_backend.BackendIntegrationTests -v
git diff --check
git status --short
```

The real network-denial assertion runs when the platform backend passes its
probe. An absent or unusable backend must instead pass an explicit fail-closed
assertion and must never trigger an unsandboxed fallback. Do not stage or
commit.

---

### Task 11: Full Security Regression and Behavioral Matrix

**Files:**

- Create: `tests/test_full_install_matrix.py`
- Create: `tests/test_security_static.py`
- Extend: `tests/helpers.py`

**Interfaces:**

- Consumes every public interface and wrapper from Tasks 1–10.
- Produces the complete regression matrix required by the approved spec.

- [ ] **Step 1: Write the cross-cutting tests before filling any uncovered behavior**

`test_full_install_matrix.py` must execute all seven nonempty target
combinations in private temp homes; check default and opt-in file lists;
perform install/reinstall/uninstall; exercise corrupt late sources/state;
inject mid-install and mid-uninstall failures; verify cross-target rollback;
and assert original user files, changed blocks, unresolved manifests, modes,
backups, and journals match their contracts.

`test_security_static.py` must scan executable sources separately from policy
prose and reject `eval`, `shell=True`, `os.system`, `sh -c`, remote
download-and-execute patterns, `sudo`, stale `gpt-5.4-mini`, active Pi source
or CLI target, absolute routing imports, incomplete inventories, and wrapper
drift. It must also prove no test activates a failure injector through an
environment variable or public CLI option.

- [ ] **Step 2: Run the new matrix and observe any red cases**

Run:

```sh
python3 -m unittest tests.test_full_install_matrix tests.test_security_static -v
```

Expected: any cross-cutting implementation gaps not exposed by focused tests.

- [ ] **Step 3: Make only the minimal production corrections exposed by the matrix**

Correct the responsible Task 1–10 module without weakening an assertion,
skipping an available security check, adding an unsandboxed fallback, or
changing the approved contract. Add a focused regression test beside the
owning module for every corrected defect, then keep the matrix assertion.

- [ ] **Step 4: Run all implementation tests and record a no-commit checkpoint**

Run:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/validate-catalogs.py
git diff --check
git status --short
```

Expected: all implementation tests pass. Do not stage or commit.

---

### Task 12: Complete README, Security/Release Guidance, and Least-Privilege CI

**Files:**

- Rewrite: `README.md`
- Create: `SECURITY.md`
- Create: `docs/RELEASING.md`
- Create: `.github/workflows/ci.yml`
- Create: `tests/test_readme_contract.py`
- Create: `tests/test_docs.py`
- Create: `tests/test_ci.py`

**Interfaces:**

- Documentation is tested against `parse_request()`, target descriptors, and
  exact manifest/helper destinations rather than maintaining an unrelated list.
- CI invokes only repository scripts and commands already exercised locally.

- [ ] **Step 1: Write failing documentation and CI contract tests**

Require README to cover: three-target support and explicit Pi exclusion; six
roles and target model behavior; exact default/opt-in installed files;
single/multiple/all-target examples; every option and home precedence;
normalized path display; safe defaults; project-only setup; prompt/tool trust;
hook inspection; snapshot/environment/backend limitations; no sudo/download;
pinned reviewed installation; manifests/backups/journals/rollback/recovery;
dry-run; conservative uninstall; format status; and unresolved license choice.

Require `SECURITY.md` to cover supported versions, the honest absence of a
configured private vulnerability channel, advice not to disclose sensitive
details publicly, and threats involving prompts, commands/hooks, secrets,
network, external files, symlinks/state, and Git publication.

Require `docs/RELEASING.md` to make protected `main`, required CI, one review,
signed commits/tags, SHA-256 artifacts, and pinned installation explicit manual
owner actions. Require CI top-level `permissions: contents: read`, no secret
references, private target homes, full tests/parse/Ruff/ShellCheck/diff/static
checks, real Linux isolation when available, and fail-closed backend tests.

- [ ] **Step 2: Run documentation/CI tests and verify the red state**

Run:

```sh
python3 -m unittest tests.test_readme_contract tests.test_docs tests.test_ci -v
```

Expected: missing or stale docs/workflow failures.

- [ ] **Step 3: Rewrite documentation and add pinned CI**

README examples must include these exact parseable commands:

```sh
./install.sh --target codex
./install.sh --target opencode --home opencode=/tmp/opencode
./install.sh --target claude-code
./install.sh --target codex --target opencode --target claude-code
./install.sh --all --dry-run
./uninstall.sh --target codex --dry-run
```

Use these immutable action pins in `.github/workflows/ci.yml`:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      persist-credentials: false
  - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
    with:
      python-version: "3.11"
```

Use a Python matrix for 3.11 and 3.14. Install pinned Python developer
dependencies, detect the runner's existing `bwrap` and ShellCheck executables,
set all three target-home variables to job-private temporary paths, and run the
exact final commands below. The real Linux backend test runs when `bwrap` is
usable; missing/unusable backend tests always run and must fail closed. Do not
invoke `sudo`, reference `${{ secrets.* }}`, or grant write permissions.

- [ ] **Step 4: Run the complete fresh verification suite**

Run:

```sh
python3 -m pip install --requirement requirements-dev.txt
python3 scripts/validate-catalogs.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
ruff check subagents_configs scripts tests
ruff format --check subagents_configs scripts tests
shellcheck install.sh uninstall.sh install-codex.sh uninstall-codex.sh install-opencode.sh uninstall-opencode.sh install-claude-code.sh uninstall-claude-code.sh
python3 -m compileall -q subagents_configs scripts tests
git diff --check
rg -n 'shell=True|eval\(|os\.system|sh -c' subagents_configs scripts tests install*.sh uninstall*.sh
git status --short --branch
```

Expected: dependency installation succeeds; catalogs, all tests, Ruff,
ShellCheck, compileall, and diff checks pass; prohibited-execution scan returns
no executable-source matches; Git status shows only intentional uncommitted
implementation files.

- [ ] **Step 5: Perform manual security and spec coverage review without committing**

Read every spec section and map it to a passing test or documentation section.
Inspect the entire diff for private content, unrelated changes, weakened
controls, stale claims, Pi support, state content leakage, and operations
outside the selected homes. Record remaining platform/hosting/license risks for
the final response. Do not stage, commit, push, or modify remote state.
