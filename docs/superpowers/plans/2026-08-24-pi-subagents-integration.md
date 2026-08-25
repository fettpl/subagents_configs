# Pi Subagents Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicitly authorized, user-scope Pi support backed by the pinned `npm:pi-subagents@0.56.0` package while preserving the repository’s least-privilege, fail-closed, dry-run, and conservative-uninstall guarantees.

**Architecture:** Extend the approved capability registry with a Pi descriptor whose target is explicit and excluded from `--all`. A read-only pre-package phase validates the absolute Pi executable fact, `PI_CODING_AGENT_DIR`, settings/config conflicts, existing-package status, and repository sources. A non-dry install then verifies exact Pi 0.84.1, runs the separately owned official `pi install`, verifies the installed manifest/bundled/effective contract, and writes a minimal durable ownership receipt before repository-managed Markdown agents, validator extension, and runtime files enter the existing descriptor-backed transaction. Package contents/state never become local journal operations, so a post-install or catalog failure leaves the extension installed and reports the precise phase boundary.

**Tech Stack:** Python 3.11–3.14, standard-library `unittest`, `tomllib`, PyYAML 6.0.3, POSIX `sh`, TypeScript loaded by Pi’s extension runtime, exact tested Pi 0.84.1, `npm:pi-subagents@0.56.0`, Pi’s official `pi install`/`pi remove` commands, Ruff 0.16.3, ShellCheck, GitHub Actions, macOS/Linux.

**Spec:** `docs/superpowers/specs/2026-08-24-repository-hardening-features-and-pi-design.md`

## Global Constraints

- Plan 2 starts only after Plan 1 has delivered the authoritative capability registry and descriptor-backed transaction work; Pi must consume those seams rather than bypassing them.
- Pi is selected only by explicit `--target pi`; `--all` remains exactly Codex, OpenCode, and Claude Code and never invokes Pi, npm, Node, network, or third-party code.
- The first supported package is exactly `npm:pi-subagents@0.56.0`; changing it requires a reviewed source, package inventory, dependency, compatibility, and release-note change.
- User-scope support follows `PI_CODING_AGENT_DIR`, defaulting to `~/.pi/agent`; project scope is not implemented.
- Non-dry package installation requires explicit `--consent-third-party-code` and `--consent-network`, exact package identity, an absolute verified Pi executable whose identity is rechecked at each spawn, exact tested Pi 0.84.1 compatibility evidence, and safe read-only inspection of settings/package state. Dry-run does not ask for consent because it executes no third-party code or network action; it reports the consents that a later real install would require.
- The installer invokes only Pi’s official package command. It never invokes `npx pi-subagents`, `install.mjs`, `git clone`, `git pull`, npm directly, or recursive-removal fallbacks.
- Pi dry-run performs no Pi, npm, Node, package-manager, network, lock-anchor, temporary-file, settings, package-store, state, journal, backup, or catalog mutation and does not execute the Pi binary. It reuses Plan 1's double-collection read-only stability check and fails if evidence changes during planning.
- Pi package registration and repository-managed role installation are separate phases and ownership domains; pre-package conflict checks, official package install, post-package identity/effective-runtime verification, and local catalog apply are explicit phase boundaries. No code claims atomic rollback across Pi/npm and the repository journal.
- If package installation succeeds and catalog installation fails, the extension remains installed, evidence is preserved, and the phase boundary is reported; automatic package removal is forbidden.
- A successful package install is followed by a strict mode-`0600` durable ownership receipt outside the local transaction journal. Normal uninstall removes only unchanged repository-owned Pi role/runtime files. Extension removal requires a separate explicit operation and exact receipt/settings/manifest evidence that this installer created the same pinned package entry; pre-existing or drifted package state is preserved. After that proof, the official removal argv is `(pi, "remove", "npm:pi-subagents")`, because Pi removes npm packages by unversioned identity.
- Exactly five Pi roles install by default: `code-explorer`, `code-reviewer`, `code-validator`, `quick-implementer`, and `implementer`; `commit-pusher` is source-only unless the existing explicit optional-role flag is supplied.
- Pi roles retain the repository role names and do not alias to `scout`, `reviewer`, or `worker`.
- `code-explorer` and `code-reviewer` receive only `read`, `grep`, `find`, and `ls`; they receive no Bash, write, edit, MCP, ambient extension, alias, package, or inherited-skill authority.
- `code-validator` receives no Bash and uses only the Pi-native `run_validation` tool, which invokes the existing isolated Python helper through fixed argv with a mandatory `--` boundary.
- `quick-implementer` and `implementer` receive explicit read/write/Bash lists; commit, push, credential, network, and scope restrictions remain visible and the parent session retains final authority.
- `commit-pusher` retains separate explicit commit-and-push authorization, no-force-push, and no-credential-change requirements.
- Pi roles inherit the active parent model. For `pi-subagents@0.56.0`, the valid native representation is omission of the `model` frontmatter key; normalized policy reports this as `model: inherit`. No Codex/OpenCode model identifier, `thinking`, fallback model, or explicit mapping is introduced in the first release. Such mappings require a later compatibility-matrix change backed by live registry evidence.
- The third-party bundled inventory (`scout`, `researcher`, `worker`, `reviewer`, `oracle`, `delegate`) remains visibly separate from the repository-managed inventory. Exactly five repository roles install by default and `commit-pusher` is the sixth only by opt-in; tests never misreport bundled roles as repository roles.
- Effective discovery, collisions, overrides, tools, extensions, skills, model, thinking, context inheritance, and source identity are validated; user settings never silently widen a repository-managed role.
- Optional Pi global routing is absent by default and, when explicitly enabled through the existing routing opt-in, uses one managed block in global `APPEND_SYSTEM.md` under the selected Pi home.
- Repository and package metadata, prompts, client output, diagnostics, state, and tests are untrusted data; no artifact records credentials, raw environment values, private file contents, full prompts, provider transcripts, or unredacted package-manager output.
- Windows remains fail-closed and unsupported until a separate approved design, with a behavioral selection/lifecycle test. Offline real Pi smoke with exact Pi 0.84.1 is mandatory before claiming/releasing Pi support. Provider smoke is optional supplementary evidence, separately authorized and never run by default; it becomes mandatory only for a release claim that explicitly includes live provider interoperability, and it never records credentials or full transcripts.
- Every task uses TDD, focused tests, the relevant full suite, static checks, clean-tree verification, and a reviewable commit; no task weakens fail-closed behavior or automatically rolls back Pi-owned package state.
- Documentation and catalog/compatibility contract tests change in the same task as behavior; intermediate docs label Pi as unreleased until the mandatory Task 11 release gate passes.

---

## Prerequisite gate from Plan 1

Do not start Task 1 until the current-scope hardening plan has landed and its review confirms these exact seams:

```python
# subagents_configs/targets.py
@dataclass(frozen=True)
class TargetCapability:
    target: Target
    order: int
    include_in_all: bool
    agent_directory: PurePosixPath
    source_format: Literal["toml", "yaml-frontmatter"]
    parser: ParserName
    semantic_validator: ValidatorName
    global_instruction: GlobalInstructionSpec
    optional_blocks: tuple[ManagedBlockSpec, ...]
    runtime_sources: tuple[SourceSpec, ...]
    lifecycle_capabilities: frozenset[LifecycleCapability]
    external_lifecycle: ExternalLifecycleSpec | None
```

The exact public selection signatures are `capability_for(target: Target) -> TargetCapability` and `targets_for_request(explicit: tuple[Target, ...], include_all: bool) -> tuple[Target, ...]`.

```python
# subagents_configs/transaction.py
def apply_transaction(plan: TransactionPlan, *, failure_injector: FailureInjector | None = None) -> None:
    """Apply an already validated local transaction while target locks are held."""

def recover_transaction(homes: Mapping[Target, Path], targets: tuple[Target, ...]) -> None:
    """Recover the exact selected participant set through the public recovery seam."""
```

Plan 1 must also expose `SourceSpec.kind` variants `command-gate`/`target-extension`, `SourceSpec.source_format` variants `typescript`/`json`, and `locked_target_homes(homes, targets)` from `subagents_configs.locks`. The registry must make `include_in_all=False` and `external_lifecycle` independently representable for Pi. Mutating transactions must already serialize non-dry planning/recovery/apply/journal cleanup with persistent descriptor-backed locks, canonical multi-target order, descriptor-relative compare-and-swap evidence, and preparation-owned cleanup; strict dry-run must instead use Plan 1's lock-free double-collection evidence check and make zero writes. Run these exact prerequisite checks before proceeding:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_targets tests.test_cli tests.test_planning tests.test_transaction_install tests.test_transaction_uninstall -v
```

Expected: PASS with no Pi-specific implementation in this plan yet; a missing registry or transaction seam is a prerequisite failure, not a reason to add a Pi bypass here.

## File map

Files created by this plan:

- `pi/agents/code-explorer.md`, `pi/agents/code-reviewer.md`, `pi/agents/code-validator.md`, `pi/agents/quick-implementer.md`, `pi/agents/implementer.md`, `pi/agents/commit-pusher.md`: Pi-native Markdown agents with YAML frontmatter and preserved repository role names.
- `pi/extensions/run-validation.ts`: target-scoped Pi extension that registers the validator’s `run_validation` tool without Bash.
- `pi/package-policy.json`: reviewed identity, manifest, dependency, lifecycle, and compatibility expectations for `pi-subagents` 0.56.0.
- `tests/fixtures/pi-subagents-0.56.0-package.json`, `tests/fixtures/pi-subagents-0.56.0-package-lock.json`: reviewed upstream metadata/provenance fixtures pinned by policy hashes.
- `rules/PI_SUBAGENT_ROUTING.md`: Pi-native routing source used only by the explicit global-routing opt-in.
- `subagents_configs/pi_catalog.py`: Pi source parsing, placeholder rendering, native semantic validation, and effective catalog contracts.
- `subagents_configs/pi_package.py`: absolute executable/runtime checks, consent, no-follow settings/package evidence, durable receipt codec, official Pi package commands, and bounded redacted subprocess results.
- `subagents_configs/pi_effective.py`: collision, override, discovery, and effective-contract evaluation.
- `tests/test_pi_catalog.py`, `tests/test_pi_package.py`, `tests/test_pi_effective.py`, `tests/test_pi_integration.py`, `tests/test_pi_smoke.py`, `tests/pi_smoke_support.py`: unit, negative, failure-injection, concurrency, and isolated real-Pi coverage.
- `tests/test_pi_provider_smoke.py`: no-credential tests for the release-only provider-smoke authorization, argv, redaction, and safe evidence schema.
- `catalogs/pi.json`: deterministic normalized Pi catalog projection consumed by validation and policy-diff without reading a user home or invoking Pi.
- `docs/COMPATIBILITY.md`: human-readable projection of the maintained Codex/OpenCode/Claude/Pi compatibility matrix including the exact Pi/package pins and runtime evidence fields.
- `scripts/run-pi-provider-smoke.py`: optional, explicitly authorized provider-evidence command with fixed prompt/argv, bounded result schema, and no transcript persistence; it is a gate only for claims of live provider interoperability.

Files modified by this plan:

- `subagents_configs/models.py`, `subagents_configs/targets.py`, `subagents_configs/cli.py`, `subagents_configs/locks.py`: Pi target, request consent/executable/home fields, registry-backed explicit target selection, and direct reuse of Plan 1's persistent lock API.
- `subagents_configs/formats.py`, `subagents_configs/planning.py`, `subagents_configs/orchestrator.py`, `subagents_configs/transaction.py`, `subagents_configs/state.py`, `subagents_configs/errors.py`: Pi source/lifecycle validation, separate external phase, safe diagnostics, manifest/state identity, and phase-boundary handling.
- `catalogs/client-compatibility.json`, `subagents_configs/compatibility.py`, `tests/test_compatibility.py`: transition the predeclared Pi row from unsupported to exact tested Pi 0.84.1/package 0.56.0 support without weakening other client rows.
- `subagents_configs/profiles.py`, `tests/test_profiles.py`: allow profile defaults for an explicitly CLI-selected Pi target while forbidding profiles from selecting Pi, storing consents, or authorizing package lifecycle.
- `subagents_configs/catalog_policy.py`, `scripts/generate-catalogs.py`, `scripts/validate-catalogs.py`, `tests/test_policy_diff.py`: generate, validate, and compare the Pi projection through Plan 1's read-only catalog-policy feature.
- `tests/test_targets.py`, `tests/test_cli.py`, `tests/test_catalogs.py`, `tests/test_planning.py`, `tests/test_transaction_install.py`, `tests/test_transaction_uninstall.py`, `tests/test_readme_contract.py`, `tests/test_docs.py`, `tests/test_security_static.py`, `tests/test_ci.py`: existing contracts extended for Pi and the package/phase boundary.
- `README.md`, `SECURITY.md`, `docs/RELEASING.md`, `.github/workflows/ci.yml`: user trust boundary, exact paths/commands/consent, release evidence, and opt-in smoke wiring.

Files tested without modification:

- Existing native catalogs under `agents/`, `opencode/agents/`, `claude-code/agents/` and existing validation helper files under `scripts/` are parsed as unchanged Plan 1 sources and are included in mixed-target and `--all` regression tests.

---

### Task 1: Register Pi as an explicit, non-`--all` target

**Files:**
- Create: `docs/COMPATIBILITY.md`
- Modify: `subagents_configs/models.py`
- Modify: `subagents_configs/targets.py`
- Modify: `subagents_configs/cli.py`
- Modify: `subagents_configs/planning.py`
- Modify: `subagents_configs/orchestrator.py`
- Modify: `subagents_configs/compatibility.py`
- Modify: `subagents_configs/profiles.py`
- Modify: `catalogs/client-compatibility.json`
- Modify: `tests/test_targets.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_planning.py`
- Modify: `tests/test_compatibility.py`
- Modify: `tests/test_profiles.py`
- Modify: `README.md`
- Modify: `tests/test_readme_contract.py`

**Interfaces:**
- Consumes: Plan 1 `TargetCapability`, `capability_for()`, `targets_for_request()`, `locked_target_homes()`, and client-compatibility seams from the prerequisite gate.
- Produces: `Target.PI`, a Pi `TargetDescriptor`, and a `Request` carrying `pi_executable: Path | None`, `pi_agent_dir: Path | None`, `consent_third_party_code: bool`, `consent_network: bool`, and `remove_pi_package: bool`; `--all` still returns only `(CODEX, OPENCODE, CLAUDE_CODE)`.

- [ ] **Step 1: Write RED target and parser tests**

Add these exact tests:

```python
def test_pi_is_explicit_but_not_in_all(self):
    self.assertEqual(parse_request("install", ["--all"], ENV).targets,
                     (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE))
    request = parse_request("install", ["--target", "pi",
                                         "--pi-executable", "/opt/pi",
                                         "--consent-third-party-code",
                                         "--consent-network"], ENV)
    self.assertEqual(request.targets, (Target.PI,))

def test_pi_home_uses_explicit_home_then_environment_then_default(self):
    self.assertEqual(parse_request("install", ["--target", "pi",
        "--pi-executable", "/opt/pi", "--consent-third-party-code",
        "--consent-network"], {**ENV, "PI_CODING_AGENT_DIR": "/tmp/pi"}).homes[Target.PI],
        Path("/tmp/pi"))

def test_pi_install_rejects_missing_consents_or_relative_executable(self):
    for argv in (("--target", "pi", "--pi-executable", "/opt/pi"),
                 ("--target", "pi", "--pi-executable", "pi",
                  "--consent-third-party-code", "--consent-network")):
        with self.assertRaises(CliError):
            parse_request("install", list(argv), ENV)
```

Change the consent test to apply only when `dry_run` is false. Add `test_pi_dry_run_does_not_require_or_record_consent`, which accepts an absolute Pi executable without either consent and reports both required consents in the plan. Also assert that consent flags, `--pi-executable`, and `--remove-pi-package` are rejected for non-Pi targets; uninstall accepts no package-removal request unless Pi is explicitly selected; and `platform_name="win32"` rejects Pi before executable/settings/package reads.

Add profile integration tests proving that a profile containing `targets = ["pi"]` cannot select Pi by itself, while explicit CLI `--target pi` may consume matching safe profile defaults such as the Pi home, global-routing opt-in, and optional-role choice. The profile schema must reject Pi executable paths, consent booleans, package-removal flags, or any other external-lifecycle authority; those values remain CLI-only, and a non-dry install still requires the two live consent flags.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_targets tests.test_cli tests.test_planning tests.test_profiles -v`

Expected: FAIL because `Target.PI`, Pi request fields, Pi descriptor, consent flags, the non-`--all` registry entry, and Pi-safe profile merge rules do not exist; all pre-existing non-Pi tests remain green.

- [ ] **Step 3: Implement the registry-backed target and exact request validation**

Add `PI = "pi"` to `Target`; add a descriptor with `environment_variable="PI_CODING_AGENT_DIR"`, `default_home="~/.pi/agent"`, `global_filename="APPEND_SYSTEM.md"`, `config_filename=None`, Pi source directory `pi/agents`, `.md` agent suffix, routing source `rules/PI_SUBAGENT_ROUTING.md`, and runtime/extension sources. Do not append Pi to the `include_in_all` set. Parse `--pi-executable`, `--consent-third-party-code`, `--consent-network`, and `--remove-pi-package` with duplicate rejection. Require both consent flags only for non-dry Pi install, require an absolute executable string before any runtime invocation, reject project-scope paths, and preserve precedence `--home pi=PATH > PI_CODING_AGENT_DIR > ~/.pi/agent`. Keep all non-Pi requests byte-for-byte compatible in rendered text.

Extend Plan 1's profile merge only at the existing request seam: the CLI must contain explicit `--target pi` before a profile may contribute Pi-safe defaults, and the profile parser rejects external lifecycle/consent/executable fields as unknown. Neither `--all` nor a profile target list may introduce Pi.

Use these signatures:

```python
@dataclass(frozen=True)
class Request:
    operation: Literal["install", "uninstall"]
    targets: tuple[Target, ...]
    homes: Mapping[Target, Path]
    enable_global_routing: bool
    enable_codex_multi_agent: bool
    include_commit_pusher: bool
    dry_run: bool
    dry_run_format: Literal["text", "json"]
    pi_executable: Path | None
    pi_agent_dir: Path | None
    consent_third_party_code: bool
    consent_network: bool
    remove_pi_package: bool

def _validate_pi_request(request: Request) -> None:
    """Raise CliError before source reads or filesystem mutation."""
```

Require both consents only when `request.operation == "install" and not request.dry_run`; dry-run still requires an absolute lexical executable fact but never executes it. Change the Plan 1 compatibility-only Pi row to `supported: true` only with `tested_client_version == "0.84.1"`, `minimum_client_version == "0.84.1"`, `package_source == "npm:pi-subagents@0.56.0"`, `supported_platforms == ["linux", "macos"]`, `scope == "user"`, and all required Pi format/features. The row's `CompatibilityTarget` string now maps to the newly registered `Target.PI`. In dry-run, validate a caller-supplied Plan 1 `--client-version pi=VERSION` when present; otherwise report `runtime_version_evidence="maintained-matrix-only"` and never claim the executable was probed. Non-dry preflight must execute the identity-checked Pi binary and prove exact 0.84.1. Unknown supplied/observed versions, Windows, project scope, or a different package source fail read-only compatibility preflight.

Create the first generated `docs/COMPATIBILITY.md` projection and add a README development-status note in the same task. It must state that the target exists for implementation/testing but is not release-ready until Tasks 2–11, especially mandatory real-Pi smoke, pass; no intermediate commit may imply supported production use.

- [ ] **Step 4: Run GREEN, catalog/transaction regressions, and commit**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_targets tests.test_cli tests.test_planning tests.test_compatibility tests.test_profiles tests.test_transaction_install tests.test_transaction_uninstall -v`

Expected: PASS; `--all` has exactly three targets, explicit `--target pi` has one target, and no test observes a Pi write or external command yet.

Commit: `git add subagents_configs/models.py subagents_configs/targets.py subagents_configs/cli.py subagents_configs/planning.py subagents_configs/orchestrator.py subagents_configs/compatibility.py subagents_configs/profiles.py catalogs/client-compatibility.json docs/COMPATIBILITY.md README.md tests/test_targets.py tests/test_cli.py tests/test_planning.py tests/test_compatibility.py tests/test_profiles.py tests/test_readme_contract.py && git commit -m "feat: register explicit pi target"`

---

### Task 2: Define and verify the pinned Pi package contract

**Files:**
- Create: `pi/package-policy.json`
- Create: `tests/fixtures/pi-subagents-0.56.0-package.json`
- Create: `tests/fixtures/pi-subagents-0.56.0-package-lock.json`
- Create: `subagents_configs/pi_package.py`
- Create: `tests/test_pi_package.py`
- Modify: `subagents_configs/errors.py`
- Modify: `tests/test_security_static.py`

**Interfaces:**
- Consumes: `Request.pi_executable`, `Request.pi_agent_dir`, the selected Pi descriptor, and the package policy JSON.
- Produces: `PiRuntimeEvidence`, `PiPackageEvidence`, `PiPackageReceipt`, strict receipt load/store functions, executable identity validation, package inspection, installation, and removal; every subprocess uses an argv tuple and a sanitized result.

- [ ] **Step 1: Write failing package-policy and command-boundary tests**

Create a temporary executable Python fixture that records argv and `PI_CODING_AGENT_DIR`, returns `0.84.1` for `--version`, advertises `install`, `remove`, and `--offline` in `--help`, and mutates only a fixture settings file when the exact official command is received. Test the policy schema against this exact reviewed JSON shape, derived from upstream tag `v0.56.0` (peeled commit `a0e2b9e31de5970215a567e20e2d781bbbddf235`), npm registry metadata, and the tag's package files:

```json
{
  "source": "npm:pi-subagents@0.56.0",
  "removeSource": "npm:pi-subagents",
  "name": "pi-subagents",
  "version": "0.56.0",
  "testedPiVersion": "0.84.1",
  "upstreamCommit": "a0e2b9e31de5970215a567e20e2d781bbbddf235",
  "distIntegrity": "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ==",
  "packageJsonSha256": "e35c5acf7f2c75fcfd182b1eaa67f8485abc5ea81ac63598ef8ad637d3e788be",
  "packageLockSha256": "76b359ad4a8ecf20892d169ba5cce7892a54d8217024b115bff9262c5a1d4f04",
  "type": "module",
  "pi": {"extensions": ["./index.ts"], "skills": ["./skills"], "prompts": ["./prompts"]},
  "dependencies": {"acorn": "8.18.0", "jiti": "2.7.0", "typebox": "1.1.38", "yaml": "2.8.3"},
  "peerDependencies": {"@earendil-works/pi-agent-core": "*", "@earendil-works/pi-ai": ">=0.80.0", "@earendil-works/pi-coding-agent": "*", "@earendil-works/pi-tui": "*"},
  "bundledAgents": ["delegate", "oracle", "researcher", "reviewer", "scout", "worker"],
  "forbiddenLifecycleScripts": ["preinstall", "install", "postinstall", "prepare"]
}
```

Check in the reviewed upstream `package.json` and package-lock root inventory as test fixtures and prove their hashes before deriving policy assertions; fabricated fixture-only evidence is insufficient. Assert that the command builder returns exactly `(pi, "install", "npm:pi-subagents@0.56.0")` and removal returns exactly `(pi, "remove", "npm:pi-subagents")`. The AST/static test forbids executable argv/program names `npm`, `npx`, `node`, `git`, shell APIs, `install.mjs`, and recursive removal while explicitly allowing the inert package-identity string prefix `npm:`. Test wrong name/version, missing manifest fields, dependency or bundled-agent drift, lifecycle scripts, wrong Pi version output, non-absolute path, symlink, directory, executable identity replacement, and non-executable fixtures as failures.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_package tests.test_security_static -v`

Expected: FAIL because the policy file/module/commands do not exist; existing static security tests remain green.

- [ ] **Step 3: Implement policy parsing, executable evidence, and bounded subprocesses**

Implement these concrete types and functions:

```python
@dataclass(frozen=True)
class PiRuntimeEvidence:
    executable: Path
    version: str | None
    device: int
    inode: int
    mode: int
    sha256: str
    help_has_install: bool
    help_has_remove: bool
    help_has_offline: bool

@dataclass(frozen=True)
class PiPackageEvidence:
    settings_path: Path
    settings_hash: str | None
    package_entries: tuple[str, ...]
    status: Literal["absent", "exact", "conflict"]
    exact_pinned_entry: bool
    package_manifest_path: Path | None
    manifest_hash: str | None
    package_identity_valid: bool

@dataclass(frozen=True)
class PiPackageReceipt:
    schema_version: Literal[1]
    operation: Literal["install", "remove", "none"]
    source: str
    remove_source: str
    settings_before_hash: str | None
    settings_after_hash: str | None
    package_manifest_hash: str
    package_policy_hash: str
    created_exact_entry: bool
```

The concrete public functions are `validate_pi_executable(path: Path, execute: bool) -> PiRuntimeEvidence`, `inspect_pi_package_state(agent_dir: Path) -> PiPackageEvidence`, `load_pi_package_receipt(agent_dir: Path) -> PiPackageReceipt | None`, `store_pi_package_receipt(agent_dir: Path, receipt: PiPackageReceipt) -> None`, `install_pi_package(executable: PiRuntimeEvidence, agent_dir: Path, consent_third_party_code: bool, consent_network: bool) -> PiPackageReceipt`, and `remove_pi_package(executable: PiRuntimeEvidence, agent_dir: Path, receipt: PiPackageReceipt) -> PiPackageReceipt`.

For `execute=False`, validate only absolute lexical form, no-follow `lstat` regular-file type, execute mode, and executable identity/hash; never spawn Pi. For `execute=True`, revalidate that identity immediately before and after `(str(path), "--offline", "--version")` and `(str(path), "--offline", "--help")`, with `PI_CODING_AGENT_DIR` set to the normalized agent directory and a fixed environment allowlist. Parse version output only as exact `0.84.1`; map every other value to `PI_RUNTIME_INCOMPATIBLE`. Capture at most 4096 bytes, redact paths, environment-looking assignments, URLs, tokens, and package-manager output, and expose only typed diagnostic code/context.

Read `<agent_dir>/settings.json`, `<agent_dir>/extensions/subagent/config.json` when present, the package-store directory, `package.json`, and package lock through no-follow, regular-file/directory, containment, owner, private-mode, and descriptor-identity checks. Reject object-form package entries, duplicate package identities, project settings, custom `npmCommand`, package/agent overrides that widen managed roles, and any unsafe path. Resolve only `<agent_dir>/npm/node_modules/pi-subagents/package.json` and its lock evidence without recursive search. Verify every policy field, exact source provenance/hash, bundled inventory, and absence of lifecycle keys.

Run the official install from an empty private working directory with an allowlisted environment containing only the required system path, `PI_CODING_AGENT_DIR`, `PI_TELEMETRY=0`, `PI_SKIP_VERSION_CHECK=1`, `GIT_TERMINAL_PROMPT=0`, and an empty npm user-config path; do not inherit proxy/auth/token variables or the user's npm configuration. Package installation may run only after both consent booleans are true and pre-package state is `absent`; an existing exact pin is a non-owned no-op. After a successful install and post-install verification, atomically persist `<agent_dir>/.subagents_configs/pi-package-receipt.json` at mode `0600` under the persistent target lock. If receipt persistence fails, preserve the package, skip local catalog mutation, and report manual recovery. Package removal requires that durable receipt, exact settings/manifest/policy hashes, and a single pinned entry; keep the receipt on failure and remove it only after Pi proves successful removal.

- [ ] **Step 4: Run GREEN and static checks**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_package tests.test_security_static -v` and `ruff check subagents_configs/pi_package.py tests/test_pi_package.py`.

Expected: PASS; fake command logs contain only `pi --offline --version`, `pi --offline --help`, exact `pi install`, or exact `pi remove`, and no test invokes npm, npx, Node, `install.mjs`, git, or a shell.

- [ ] **Step 5: Commit**

Run `git diff --check`, then commit: `git add pi/package-policy.json tests/fixtures/pi-subagents-0.56.0-package.json tests/fixtures/pi-subagents-0.56.0-package-lock.json subagents_configs/pi_package.py subagents_configs/errors.py tests/test_pi_package.py tests/test_security_static.py && git commit -m "feat: verify pinned pi package contract"`.

---

### Task 3: Add the six Pi-native role sources and `run_validation` extension

**Files:**
- Create: `pi/agents/code-explorer.md`
- Create: `pi/agents/code-reviewer.md`
- Create: `pi/agents/code-validator.md`
- Create: `pi/agents/quick-implementer.md`
- Create: `pi/agents/implementer.md`
- Create: `pi/agents/commit-pusher.md`
- Create: `pi/extensions/run-validation.ts`
- Create: `rules/PI_SUBAGENT_ROUTING.md`
- Create: `subagents_configs/pi_catalog.py`
- Create: `tests/test_pi_catalog.py`
- Modify: `subagents_configs/targets.py`
- Modify: `subagents_configs/formats.py`
- Modify: `tests/test_catalogs.py`

**Interfaces:**
- Consumes: Pi descriptor source specs and `PI_CODING_AGENT_DIR`-derived placeholder values.
- Produces: `validate_pi_agent(role: str, content: bytes) -> PiAgentContract`, `render_pi_source(source: bytes, *, agent_dir: Path) -> bytes`, `PI_DEFAULT_ROLES`, `PI_OPTIONAL_ROLES`, and a target-scoped TypeScript tool named exactly `run_validation`.

- [ ] **Step 1: Write failing native catalog tests**

Add tests that parse each Markdown frontmatter document and assert these exact contracts:

```python
READ_TOOLS = ("read", "grep", "find", "ls")
WRITE_TOOLS = ("read", "grep", "find", "ls", "write", "edit", "bash")
VALIDATOR_TOOLS = ("read", "grep", "find", "ls", "run_validation")
PUSHER_TOOLS = ("read", "grep", "find", "ls", "bash")

for role in PI_DEFAULT_ROLES + PI_OPTIONAL_ROLES:
    assert frontmatter["name"] == role
    assert "model" not in frontmatter
    assert "thinking" not in frontmatter
    assert "fallbackModels" not in frontmatter
    assert normalize_model_policy(frontmatter) == "inherit"
    assert frontmatter["inheritProjectContext"] is False
    assert frontmatter["inheritSkills"] is False
```

Assert explorer/reviewer tools equal `READ_TOOLS`, validator tools equal `VALIDATOR_TOOLS` and contain no `bash`, quick/implementer tools equal `WRITE_TOOLS`, and commit-pusher tools equal `PUSHER_TOOLS`. Require an explicit empty `extensions` field and empty `skills` for every role. Validator alone has `subagentOnlyExtensions: {{PI_VALIDATION_EXTENSION}}`; no other role may declare `subagentOnlyExtensions`. Reject aliases, MCP entries, package names, inherited project context/skills, explicit model/fallback IDs, and any thinking value. Assert the repository-managed default inventory is five and optional inventory contains only `commit-pusher`; separately assert the reviewed third-party bundled inventory is exactly `delegate`, `oracle`, `researcher`, `reviewer`, `scout`, and `worker`.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_catalog tests.test_catalogs -v`

Expected: FAIL because the Pi directory, sources, parser, and target-specific validator do not exist; existing three-target catalog assertions remain green.

- [ ] **Step 3: Implement exact frontmatter and target artifact**

Write each agent with frontmatter containing `name`, a nonempty `description`, `systemPromptMode: replace`, `inheritProjectContext: false`, `inheritSkills: false`, explicit `tools`, and explicit empty `skills`/`extensions`. Omit `model`, `fallbackModels`, and `thinking`; pinned `pi-subagents@0.56.0` treats the absent model as parent-session inheritance, and tests normalize it to `inherit`. Put the rendered validator path only in `subagentOnlyExtensions`. Keep existing repository role contracts visible in the body: explorer/reviewer are read-only and never implement; validator refuses direct Bash and runs checks only through `run_validation`; implementers state parent scope, no credential changes, no network/publication without authorization; commit-pusher requires separate requests for `git commit` and `git push`, never force-pushes, and never changes credentials. Write `rules/PI_SUBAGENT_ROUTING.md` from the shared safe routing policy and test that it is absent unless the existing global-routing opt-in is selected.

Implement `pi/extensions/run-validation.ts` with this fixed behavior:

```typescript
const args = [helperPath, "--", ...params.argv];
const child = spawn("python3", args, {
  cwd: process.cwd(),
  env: { PATH: "/usr/bin:/bin", PI_CODING_AGENT_DIR: agentDir },
  shell: false,
  stdio: ["ignore", "pipe", "pipe"],
});
```

Register `run_validation` through `pi.registerTool` with `Type.Object({ argv: Type.Array(Type.String(), { minItems: 1, maxItems: 64 }) })`; reject empty strings and control characters, enforce a 900-second timeout, cap combined output at 8192 bytes, redact paths/environment/token-like values, return exit status plus safe bounded output, and return a typed failure when `PI_CODING_AGENT_DIR` or the helper is not absolute, regular, and contained. The only child argv is `python3`, the normalized helper, `--`, and user command arguments; no Bash, `exec`, `eval`, shell string, npm, or network client is present.

- [ ] **Step 4: Validate native and TypeScript contracts**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/validate-catalogs.py`, `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_catalog tests.test_catalogs -v`, and `ruff check subagents_configs/pi_catalog.py tests/test_pi_catalog.py`. In the mandatory exact-Pi release environment, load `pi/extensions/run-validation.ts` with Pi 0.84.1's real extension loader in an isolated home before the full smoke; a parse/import/tool-registration failure blocks the release.

Expected: PASS; the repository parser accepts all six Pi sources, rejects a validator with Bash or without its sole `subagentOnlyExtensions` provider, rejects an explorer with any extension provider, validates the routing source, and static text checks find no secrets, full prompts, or forbidden execution fallbacks. The exact-Pi loader registers only `run_validation` from the target extension and exits without a provider call.

- [ ] **Step 5: Commit**

Run `git diff --check`, then commit: `git add pi/agents pi/extensions/run-validation.ts rules/PI_SUBAGENT_ROUTING.md subagents_configs/pi_catalog.py subagents_configs/targets.py subagents_configs/formats.py tests/test_pi_catalog.py tests/test_catalogs.py && git commit -m "feat: add pi native role catalog"`.

---

### Task 4: Render Pi sources and plan the two ownership phases

**Files:**
- Modify: `subagents_configs/models.py`
- Modify: `subagents_configs/planning.py`
- Modify: `subagents_configs/orchestrator.py`
- Modify: `subagents_configs/transaction.py`
- Modify: `subagents_configs/state.py`
- Modify: `subagents_configs/pi_catalog.py`
- Modify: `subagents_configs/pi_package.py`
- Create: `tests/test_pi_integration.py`
- Modify: `tests/test_planning.py`
- Modify: `tests/test_transaction_install.py`

**Interfaces:**
- Consumes: validated Pi package evidence/catalog contracts and Plan 1 descriptor-relative transaction APIs.
- Produces: a `TransactionPlan` containing only repository-owned Pi files plus a separate `PiExternalPlan`; package actions and the durable receipt are never local journal operations.

- [ ] **Step 1: Write RED phase-boundary tests**

Add tests using an absolute fake Pi executable and temporary `PI_CODING_AGENT_DIR` that assert `preflight_install()` returns exactly five repository catalog writes, one validator extension write, and the validation runtime writes, while `external_plan.package_source == "npm:pi-subagents@0.56.0"` is a separate field. Cover absent-package and exact-pre-existing-package paths. For absent state, assert the order is pre-package conflict check → official install → post-package manifest/bundled/effective verification → durable receipt → local catalog apply. Inject post-package verification, receipt-write, and local catalog failures; assert the package/settings remain installed, the receipt exists only when it was durably written, the local journal contains only repository operations, the phase-specific error is sanitized, and no remove command is recorded. Inject package-install failure and assert zero receipt/local writes.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_integration tests.test_planning tests.test_transaction_install -v`

Expected: FAIL because `PiExternalPlan` and phase orchestration do not exist; existing transaction tests remain green.

- [ ] **Step 3: Implement typed phase plans and safe rendering**

Add these exact dataclasses:

```python
@dataclass(frozen=True)
class PiExternalPlan:
    action: Literal["install", "remove", "none"]
    executable: Path
    agent_dir: Path
    package_source: str
    before: PiPackageEvidence
    consent_third_party_code: bool
    consent_network: bool
    removal_receipt: PiPackageReceipt | None

@dataclass(frozen=True)
class PiInstallPlan:
    local: TransactionPlan
    external: PiExternalPlan
```

Render `{{PI_VALIDATION_EXTENSION}}` to `<agent_dir>/extensions/subagents-configs-run-validation.ts` only after `normalized_absolute`, containment, regular-source, and final source identity checks. Keep `PiExternalPlan` and the receipt outside `PlannedOperation` and `JournalOperation`. Under Plan 1's persistent Pi-home lock, the orchestrator must execute: all pre-package read-only source/settings/config/collision checks; official external install only when state is absent; post-package manifest, package-policy, bundled-inventory, and effective-contract verification; durable receipt creation only for a newly created exact entry; then local `apply_transaction`. An exact pre-existing pin skips installation, creates no ownership receipt, and remains preserved on later uninstall. On any post-install/local failure, preserve external state and receipt evidence and raise a sanitized phase-boundary error. For normal uninstall execute the local transaction first and never remove the package; for `--remove-pi-package`, remove only after local success and only through exact durable receipt/hash evidence. A package failure never starts the local transaction.

- [ ] **Step 4: Verify phase behavior, idempotency, and no journal leakage**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_integration tests.test_planning tests.test_transaction_install -v` and `ruff check subagents_configs/{planning,orchestrator,transaction,state,pi_catalog,pi_package}.py tests/test_pi_integration.py`.

Expected: PASS; a pinned existing package produces `action="none"`, repeated local installs produce no writes, package state is absent from journals/manifests, and a local failure never triggers package removal.

- [ ] **Step 5: Commit**

Run `git diff --check`, then commit: `git add subagents_configs/models.py subagents_configs/planning.py subagents_configs/orchestrator.py subagents_configs/transaction.py subagents_configs/state.py subagents_configs/pi_catalog.py subagents_configs/pi_package.py tests/test_pi_integration.py tests/test_planning.py tests/test_transaction_install.py && git commit -m "feat: separate pi package and catalog phases"`.

---

### Task 5: Enforce effective discovery, collision, override, and source contracts

**Files:**
- Create: `subagents_configs/pi_effective.py`
- Create: `tests/test_pi_effective.py`
- Create: `catalogs/pi.json`
- Modify: `subagents_configs/planning.py`
- Modify: `subagents_configs/pi_catalog.py`
- Modify: `subagents_configs/catalog_policy.py`
- Modify: `scripts/generate-catalogs.py`
- Modify: `scripts/validate-catalogs.py`
- Modify: `tests/test_pi_catalog.py`
- Modify: `tests/test_catalogs.py`
- Modify: `tests/test_policy_diff.py`

**Interfaces:**
- Consumes: rendered `PiAgentContract` values, strict Pi settings JSON, package manifest metadata, and the selected user-scope agent directory.
- Produces: `PiEffectiveCatalog`, `PiConflict`, and `inspect_effective_catalog(agent_dir: Path, rendered: Mapping[str, PiAgentContract], package: PiPackageEvidence) -> PiEffectiveCatalog`.

- [ ] **Step 1: Write RED effective-contract tests**

Test each failure independently with temporary settings/config and agent files: an existing unmanaged `agents/code-explorer.md`; duplicate/object-form `packages` entries; an unpinned `npm:pi-subagents`; a second package identity; custom `npmCommand`; `subagents.agentOverrides.code-explorer.tools` containing `bash`; overrides for `extensions`, `subagentOnlyExtensions`, `skills`, `model`, `fallbackModels`, `thinking`, `inheritSkills`, or `inheritProjectContext`; aliases equal to a managed role; a package manifest whose discovered names collide; and a user/project ambient extension or project agent that would widen a managed role. Assert each returns a `PiConflict(kind, role, source_id, field, safe_value, observed_value)` with redacted values and no mutation. Add catalog-policy RED tests that require a deterministic `catalogs/pi.json` and report Pi role, tool, extension, package, destination, source-hash, and authority broadening without reading a user home or running Pi.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_effective tests.test_pi_catalog tests.test_catalogs tests.test_policy_diff -v`

Expected: FAIL because effective discovery and conflict evaluation do not exist.

- [ ] **Step 3: Implement strict effective evaluation**

Use these exact structures:

```python
@dataclass(frozen=True)
class PiConflict:
    kind: Literal["path-collision", "package-drift", "override", "alias", "ambient-extension", "discovery"]
    role: str | None
    source_id: str
    field: str
    safe_value: str
    observed_value: str

@dataclass(frozen=True)
class PiEffectiveCatalog:
    managed_roles: tuple[str, ...]
    bundled_roles: tuple[str, ...]
    optional_managed_roles: tuple[str, ...]
    conflicts: tuple[PiConflict, ...]
    source_hashes: Mapping[str, str]
```

The public evaluator is `inspect_effective_catalog(agent_dir: Path, rendered: Mapping[str, PiAgentContract], package: PiPackageEvidence) -> PiEffectiveCatalog`.

Parse `settings.json` and package config strictly and inspect `packages`, `npmCommand`, `subagents.agentOverrides`, `subagents.defaultExtensions`, `extensions`, `skills`, aliases, project-resource discovery, and package inventory. Before installation, accept only `absent` or one exact pin; after installation require one exact pin. Require no project settings/project agents in the selected working directory and no unmanaged managed-role path. Treat any override that changes a protected field as a conflict; inherited parent model is allowed only when the role omits `model`, and the first release rejects every explicit model/fallback/thinking value. Require exact source identity/hash for every rendered file. Keep the six reviewed bundled roles in `bundled_roles`, never in `managed_roles`, and fail closed before directory creation when any unreviewed bundled role appears.

Extend the canonical generator so `python scripts/generate-catalogs.py --write --target pi` renders `catalogs/pi.json` from the authoritative Pi capability, repository role/routing/extension sources, and `pi/package-policy.json`; `--check --target pi` compares it byte-for-byte. Extend normalized policy loading so Pi package and extension authority maps to the existing closed `AuthorityCapability` enum. Policy diff remains a local read-only operation over explicit revision/catalog paths and never inspects `PI_CODING_AGENT_DIR`, executes Pi, or invokes package/network code.

- [ ] **Step 4: Verify negative and positive contracts**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_effective tests.test_pi_catalog tests.test_catalogs tests.test_policy_diff -v`, `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_targets tests.test_cli tests.test_planning -v`, and `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/generate-catalogs.py --check --target pi`.

Expected: PASS; clean settings yield five managed roles plus the separately identified six bundled roles, `commit-pusher` is absent unless selected, all collision/override cases report a safe conflict, and no conflict output contains the observed raw settings value. Effective tool evidence distinguishes the declared resource/process allowlist from pinned package-internal coordination plumbing; any internal tool with filesystem, shell, network, credential, extension, package, skill, or MCP authority is a release-blocking conflict. The Pi projection is reproducible and policy diff flags every added Pi authority while performing zero target-home reads and zero external commands.

- [ ] **Step 5: Commit**

Run `git diff --check`, then commit: `git add subagents_configs/pi_effective.py subagents_configs/planning.py subagents_configs/pi_catalog.py subagents_configs/catalog_policy.py scripts/generate-catalogs.py scripts/validate-catalogs.py catalogs/pi.json tests/test_pi_effective.py tests/test_pi_catalog.py tests/test_catalogs.py tests/test_policy_diff.py && git commit -m "feat: validate effective pi role contracts"`.

---

### Task 6: Implement strict Pi dry-run, consent, diagnostics, and recovery boundaries

**Files:**
- Modify: `subagents_configs/orchestrator.py`
- Modify: `subagents_configs/planning.py`
- Modify: `subagents_configs/pi_package.py`
- Modify: `subagents_configs/errors.py`
- Modify: `tests/test_pi_integration.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_readme_contract.py`

**Interfaces:**
- Consumes: `PiInstallPlan`, typed Plan 1 diagnostic codes, package/effective evidence, and fixed request consent fields.
- Produces: safe text/JSON plan output with operation, target/home, package source, phase, ownership, and recovery fields but no package-manager output, credentials, raw environment, private contents, or full prompts.

- [ ] **Step 1: Write RED dry-run/diagnostic tests**

Snapshot a temporary Pi home, fake executable log, settings, package store, receipt path, lock path, and repository tree. Call `run("install", ["--target", "pi", "--dry-run", "--pi-executable", str(fake_pi.resolve())], env=isolated_env, stdout=stdout, stderr=stderr)` without consent flags; assert the fake executable and lock APIs are never called, all bytes/modes/links are unchanged, no lock/directory/journal/backup/temp/receipt exists, and output contains only `pi`, normalized home, `npm:pi-subagents@0.56.0`, five managed role identifiers, `external-package-phase`, `runtime_version_evidence="maintained-matrix-only"`, and the two consents required for a later real install. Repeat with `--client-version pi=0.84.1` and assert `runtime_version_evidence="caller-supplied"`; reject any other supplied version without execution. Inject a change between the two evidence collections and assert `PREFLIGHT_CONCURRENT_CHANGE` with zero writes. Add non-dry failures for missing consent, missing executable, wrong observed executable version, package drift, malformed settings, and injected stderr containing `API_KEY=`, a private path, or a URL; assert only stable diagnostic codes and fixed safe context are emitted.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_integration tests.test_cli tests.test_readme_contract -v`

Expected: FAIL because dry-run currently reaches no Pi-aware path and diagnostics do not have Pi codes/phase fields.

- [ ] **Step 3: Implement fail-closed output and phase handling**

Add stable codes `PI_CONSENT_REQUIRED`, `PI_EXECUTABLE_INVALID`, `PI_RUNTIME_INCOMPATIBLE`, `PI_SETTINGS_INVALID`, `PI_PACKAGE_DRIFT`, `PI_RECEIPT_INVALID`, `PI_CATALOG_CONFLICT`, `PI_PACKAGE_PHASE_FAILED`, `PI_CATALOG_PHASE_FAILED`, and `PI_UNINSTALL_PRESERVED`. Add `sanitize_pi_context(code, *, target, phase, safe_identifier, normalized_home) -> Mapping[str, str]` that allows only target, phase, role/source identifier, package source, and normalized home label; never interpolate exception text or child output. In `orchestrator.run`, branch after Plan 1's lock-free double-collection read-only Pi preflight for `dry_run`, render the versioned JSON/text plan with either the caller-supplied compatibility fact or `runtime_version_evidence="maintained-matrix-only"`, and return without calling the lock API, `validate_pi_executable(execute=True)`, receipt stores, package installation/removal, Node, npm, filesystem preparation, or journal cleanup. Require both consent flags only in non-dry install immediately before package phase, and preserve package/receipt state on every later error.

- [ ] **Step 4: Verify exact dry-run and sanitized failures**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_integration tests.test_cli tests.test_readme_contract -v`, then `ruff check subagents_configs/{orchestrator,planning,pi_package,errors}.py tests/test_pi_integration.py tests/test_cli.py`.

Expected: PASS; dry-run makes zero lock/external calls and zero filesystem writes, labels maintained-matrix versus caller-supplied version evidence without claiming a probe, fails on concurrent evidence drift, missing consent fails before any package command, wrong executable/package/settings evidence fails closed, and diagnostic output contains no secret-like value or raw third-party output.

- [ ] **Step 5: Commit**

Run `git diff --check`, then commit: `git add subagents_configs/orchestrator.py subagents_configs/planning.py subagents_configs/pi_package.py subagents_configs/errors.py tests/test_pi_integration.py tests/test_cli.py tests/test_readme_contract.py && git commit -m "feat: make pi dry run and diagnostics fail closed"`.

---

### Task 7: Prove conservative uninstall, drift handling, and failure recovery

**Files:**
- Modify: `subagents_configs/planning.py`
- Modify: `subagents_configs/orchestrator.py`
- Modify: `subagents_configs/transaction.py`
- Modify: `subagents_configs/state.py`
- Modify: `tests/test_pi_integration.py`
- Modify: `tests/test_transaction_uninstall.py`

**Interfaces:**
- Consumes: repository manifest ownership entries, Pi external receipts, Plan 1 CAS/lock/recovery APIs, and exact settings/package evidence.
- Produces: conservative Pi uninstall with no package removal by default, exact optional package removal, and preserved evidence after partial failure.

- [ ] **Step 1: Write RED uninstall/recovery tests**

Cover these exact cases: unchanged created role/runtime files are removed; changed, missing, symlinked, hard-linked, or pre-existing files remain unresolved; routing is absent by default; an unchanged opt-in Pi `APPEND_SYSTEM.md` managed block is removed while a changed block remains unresolved; default uninstall leaves the pinned package, receipt, and settings unchanged; `--remove-pi-package` refuses missing/hostile receipts, pre-existing, drifted, duplicate, or settings/manifest/policy-hash-mismatched package entries; successful explicit removal invokes only `pi remove npm:pi-subagents` and removes the receipt after post-removal verification; package removal failure after local success reports `PI_PACKAGE_PHASE_FAILED` without recreating files or deleting the receipt; local failure after package install never invokes remove; interrupted local transaction recovers only through the existing journal and persistent lock path.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_integration tests.test_transaction_uninstall -v`

Expected: FAIL for package ownership/receipt assertions and Pi-specific phase recovery; existing non-Pi uninstall tests remain green.

- [ ] **Step 3: Implement exact ownership and recovery rules**

Persist only safe manifest evidence for Pi repository files: identifier, relative path, installed hash/mode, ownership, managed block hash, and backup metadata. Persist the separate strict receipt with only schema/source/remove-source, settings before/after hashes, package manifest hash, package-policy hash, and `created_exact_entry`; never persist package contents or raw settings. Require `created_exact_entry is True`, `receipt.settings_after_hash == current.settings_hash`, exactly one `npm:pi-subagents@0.56.0` entry, and exact package manifest/policy identity/hash before optional removal. Use Plan 1's `locked_target_homes` around planning, package evidence, official Pi commands, receipt mutation, local apply, recovery, and journal cleanup. On every package/catalog boundary error, preserve the external package and repository/receipt evidence and return the phase-specific diagnostic; never delete a package store directory recursively.

- [ ] **Step 4: Verify recovery, drift, and idempotency**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_integration tests.test_transaction_uninstall tests.test_transaction_install -v`.

Expected: PASS; no unsafe or drifted file/package state is removed, exact ownership is required for extension removal, journal recovery remains fail-closed, repeated install/uninstall is idempotent, and package state is never automatically rolled back.

- [ ] **Step 5: Commit**

Run `git diff --check`, then commit: `git add subagents_configs/planning.py subagents_configs/orchestrator.py subagents_configs/transaction.py subagents_configs/state.py tests/test_pi_integration.py tests/test_transaction_uninstall.py && git commit -m "fix: preserve pi ownership and recovery evidence"`.

---

### Task 8: Add offline, concurrency, drift, and failure-injection coverage

**Files:**
- Modify: `tests/test_pi_integration.py`
- Modify: `tests/test_pi_package.py`
- Modify: `tests/test_transaction_install.py`
- Modify: `tests/test_transaction_uninstall.py`

**Interfaces:**
- Consumes: `PiInstallPlan`, official-command fixture, descriptor-backed locks, and `FailureInjector.before_operation()`.
- Produces: deterministic regression coverage for the entire external/local boundary without real credentials or provider calls.

- [ ] **Step 1: Write the failure matrix**

Add named tests `test_offline_dry_run_never_spawns_pi`, `test_missing_executable_fails_before_preparation`, `test_wrong_runtime_version_fails_before_package_command`, `test_windows_fails_before_pi_lifecycle`, `test_custom_npm_command_is_rejected`, `test_settings_drift_preserves_package`, `test_package_drift_preserves_settings`, `test_catalog_collision_after_package_install_preserves_package`, `test_receipt_failure_preserves_package_and_skips_catalog`, `test_package_command_failure_has_zero_local_writes`, `test_concurrent_same_home_install_has_one_effective_package_entry`, and `test_uninstall_package_removal_requires_exact_receipt`. The fake Pi must record argv/env only in a temp file and must never receive credentials, proxy values, npm user configuration, or caller HOME.

- [ ] **Step 2: Run the failure matrix and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_integration tests.test_pi_package tests.test_transaction_install tests.test_transaction_uninstall -v`

Expected: any missing Pi boundary behavior is reported by a named failure; there is no broad skip for missing evidence.

- [ ] **Step 3: Add deterministic injection and lock assertions**

Extend the test-only injector with `before_external(phase: Literal["package-install", "catalog-apply", "package-remove"]) -> None` and inject at each boundary. Run two `ThreadPoolExecutor(max_workers=2)` calls against the same temporary Pi home; assert both acquire the descriptor lock, one official install is effective, settings contains one exact pinned entry, and both return either a no-op or successful idempotent plan. Assert distinct homes can proceed concurrently and multi-target locks use registry order.

- [ ] **Step 4: Verify full relevant suites and static constraints**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_integration tests.test_pi_package tests.test_transaction_install tests.test_transaction_uninstall tests.test_full_install_matrix -v`, `ruff check subagents_configs scripts tests`, and `git diff --check`.

Expected: PASS; all offline/idempotency/drift/concurrency/failure-injection cases pass, no fixture writes outside its temporary root, and static checks reject direct npm/npx/git/shell fallbacks.

- [ ] **Step 5: Commit**

Commit: `git add tests/test_pi_integration.py tests/test_pi_package.py tests/test_transaction_install.py tests/test_transaction_uninstall.py && git commit -m "test: cover pi lifecycle boundaries"`.

---

### Task 9: Add isolated real-Pi smoke evidence

**Files:**
- Create: `tests/test_pi_smoke.py`
- Create: `tests/pi_smoke_support.py`
- Create: `tests/fixtures/pi-0.84.1-runtime-contract.json`
- Modify: `tests/test_security_static.py`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: a user-supplied absolute `PI_EXECUTABLE`, disposable `PI_CODING_AGENT_DIR`, installed Pi catalog/package, and the target-scoped `run_validation` extension.
- Produces: real Pi startup/discovery/role/tool evidence with no credentials, provider calls, full transcripts, or writes outside temporary homes.

- [ ] **Step 1: Write RED real-smoke harness tests and the reviewed runtime fixture**

Derive and check in `pi-0.84.1-runtime-contract.json` from the exact Pi 0.84.1 source/release: supported CLI argv, LF-delimited RPC `get_state` request/response key sets, extension loader contract, and safe version identity. Write tests that require `run_pi_smoke(executable: Path, root: Path) -> PiSmokeEvidence` to create `root/agent`, `root/project`, and `root/tmp` with mode `0700`, set only `HOME`, `PI_CODING_AGENT_DIR`, `PI_OFFLINE=1`, `PI_SKIP_VERSION_CHECK=1`, `PI_TELEMETRY=0`, and `TMPDIR`, then run Pi using only argv and RPC framing validated by that fixture. Assert startup status, redacted state, exact five/six repository-managed source inventory, separately reviewed six-role bundled inventory, and no package/catalog mutation during inspection. Add canaries that prove explorer/reviewer effective resource/process tools exclude `bash`, write/edit, MCP, skills, ambient extensions, and packages; prove any package-internal coordination tool has no such authority; require the validator extension to run the installed isolated Python helper while rejecting Bash; and verify optional `commit-pusher` absence/presence. Use a deterministic fake executable for these RED contract tests; do not implement the harness in this step.

- [ ] **Step 2: Run the focused contract tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_smoke.PiSmokeContractTests -v`

Expected: FAIL because `run_pi_smoke`, bounded RPC execution, evidence parsing, and the explicit unavailable selector do not exist yet. Existing non-Pi tests remain green.

- [ ] **Step 3: Implement bounded real-smoke execution**

Build the subprocess argv from the checked contract, which for exact Pi 0.84.1 is `[str(executable), "--offline", "--mode", "rpc", "--no-session", "--no-context-files"]`; write only the fixture-validated `get_state` request, enforce a 30-second timeout, terminate/kill only this child, cap each stream at 8192 bytes, and pass all output through the same redactor. Recheck executable and installed package identities before and after. Do not pass auth variables, inherit the caller environment, invoke a provider, send a model prompt, or record the RPC transcript. A missing/unsupported backend produces an explicit ordinary-CI evidence result but fails the release test.

- [ ] **Step 4: Verify smoke and CI policy**

Run the fake-executable contract suite, then for ordinary CI run `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_smoke.PiSmokeTests.test_selector_reports_explicit_unavailable -v`; it must pass only with a safe `PI_EXECUTABLE_UNAVAILABLE` evidence line and no silent skip, which is sufficient for ordinary CI but never release evidence. For the mandatory release path, run `PI_EXECUTABLE=/absolute/path/to/pi-0.84.1 PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_smoke.PiReleaseSmokeTests tests.test_security_static -v`; it rejects absent executables and every version other than 0.84.1. Run `ruff check tests/test_pi_smoke.py tests/pi_smoke_support.py`, `ruff format --check tests/test_pi_smoke.py tests/pi_smoke_support.py`, and `git diff --check`.

Expected: PASS with bounded/redacted evidence; the normal CI job never downloads or installs Pi, while the macOS/Linux release workflow must provide exact Pi 0.84.1 and run the real smoke suite before support can be claimed.

- [ ] **Step 5: Commit**

Commit: `git add tests/test_pi_smoke.py tests/pi_smoke_support.py tests/fixtures/pi-0.84.1-runtime-contract.json tests/test_security_static.py .github/workflows/ci.yml && git commit -m "test: add isolated pi smoke evidence"`.

---

### Task 10: Update README, SECURITY, RELEASING, and compatibility matrix

**Files:**
- Modify: `docs/COMPATIBILITY.md`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `docs/RELEASING.md`
- Modify: `catalogs/client-compatibility.json`
- Modify: `tests/test_readme_contract.py`
- Modify: `tests/test_docs.py`
- Modify: `tests/test_compatibility.py`

**Interfaces:**
- Consumes: final parsed descriptors, `pi/package-policy.json`, diagnostic codes, and smoke/release evidence fields.
- Produces: documentation that names exact Pi trust, paths, package command/pin, consent, phase boundary, model/provider behavior, uninstall ownership, offline/dry-run behavior, and OS support.

- [ ] **Step 1: Write failing documentation contract tests**

Extend README tests to require the Mario Zechner project lineage and current Earendil Works maintenance, Nico Bailon's separately authored third-party package boundary, `pi` in the supported-target matrix, `PI_CODING_AGENT_DIR`, `~/.pi/agent`, exact Pi 0.84.1, `npm:pi-subagents@0.56.0`, `--consent-third-party-code`, `--consent-network`, `--pi-executable`, `--remove-pi-package`, explicit `--target pi`, `--all` exclusion, `APPEND_SYSTEM.md`, `run_validation`, semantic model inheritance by omitted frontmatter, five/default plus optional managed role inventory, separate bundled inventory, no Bash validator, non-atomic package/catalog boundary, no `npx`/`install.mjs`/git fallback, and Windows fail-closed wording. Require SECURITY topics for third-party package execution, settings/config/package/receipt drift, redacted diagnostics, no automatic package rollback, and provider/credential exclusion. Require RELEASING topics for package source commit/integrity/manifest/dependency/lifecycle review, exact Pi and Python/OS versions, mandatory isolated real-Pi smoke, release-note update on pin changes, and manual consent/publication.

- [ ] **Step 2: Run documentation tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_readme_contract tests.test_docs -v`

Expected: FAIL because current docs explicitly say Pi is unsupported and do not document the new lifecycle.

- [ ] **Step 3: Write the exact documentation and matrix**

Update the canonical `catalogs/client-compatibility.json` Pi row to exact tested support and render `docs/COMPATIBILITY.md` from it with columns `Client`, `Supported scope`, `Home variable/default`, `Native format`, `Runtime/package evidence`, `Validation backends`, `Unsupported scope`; a contract test rejects drift between JSON and Markdown. The Pi row must say exact Pi 0.84.1, `PI_CODING_AGENT_DIR`/`~/.pi/agent`, Markdown agents plus TypeScript extension, `pi --offline --version`/`--help`, package `npm:pi-subagents@0.56.0`, package peer `@earendil-works/pi-ai >=0.80.0`, macOS/Linux only, and Windows fail-closed. README must show the exact commands:

```sh
./install.sh --target pi --pi-executable /absolute/path/to/pi \
  --consent-third-party-code --consent-network
./install.sh --target pi --dry-run --pi-executable /absolute/path/to/pi
./uninstall.sh --target pi --dry-run --home pi=/tmp/pi-agent
./uninstall.sh --target pi --home pi=/absolute/path/to/pi-agent \
  --pi-executable /absolute/path/to/pi --remove-pi-package
```

State that dry-run neither requires consent nor executes the executable, non-dry package install requires both consents, `--all` excludes Pi, and Pi inherits the parent model/provider by omitting native model/thinking fields. Document the bundled-versus-managed inventories, separate provider-smoke authorization, and exact path ownership: repository-owned `agents/*.md`, `extensions/subagents-configs-run-validation.ts`, `.subagents_configs/validation/**`, optional `APPEND_SYSTEM.md` managed block, and `.subagents_configs/pi-package-receipt.json`; inspected but Pi-owned `settings.json`, `extensions/subagent/config.json`, and `npm/node_modules/pi-subagents/**`. Package removal is never part of normal uninstall, uses unversioned `npm:pi-subagents` only after exact pinned receipt evidence, preserves drift, and keeps the receipt on failure.

- [ ] **Step 4: Verify docs from parsed facts and commit**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_readme_contract tests.test_docs tests.test_compatibility -v`, `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/validate-catalogs.py`, and `git diff --check`.

Expected: PASS; docs state the supported boundary exactly and do not claim package atomicity, prompt-only enforcement, real-provider testing, or Windows support.

- [ ] **Step 5: Commit**

Commit: `git add catalogs/client-compatibility.json docs/COMPATIBILITY.md README.md SECURITY.md docs/RELEASING.md tests/test_compatibility.py tests/test_readme_contract.py tests/test_docs.py && git commit -m "docs: publish pi compatibility and trust boundary"`.

---

### Task 11: Complete CI/release integration and final verification

**Files:**
- Create: `scripts/run-pi-provider-smoke.py`
- Create: `tests/test_pi_provider_smoke.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/RELEASING.md`
- Modify: `tests/test_ci.py`
- Modify: `tests/test_security_static.py`

**Interfaces:**
- Consumes: all Pi tests/catalogs, pinned Python requirements, compatibility matrix, and explicit real-Pi smoke evidence mode.
- Produces: reproducible CI commands that do not install Pi by default and a release gate that records exact safe versions/evidence.

- [ ] **Step 1: Write failing CI/release contract tests**

Require the workflow to run `tests.test_pi_catalog`, `tests.test_pi_package`, `tests.test_pi_effective`, `tests.test_pi_integration`, and the explicit-unavailable smoke selector; require static scans for executable `npm`/`npx`, `install.mjs`, `git clone`, `git pull`, recursive removal, shell execution, and direct network clients without rejecting inert `npm:` identities. Require the release workflow to make exact Pi 0.84.1 real smoke mandatory. Require release documentation to record `python --version`, Pi `--version`/`--help`, package source commit/dist integrity/manifest/dependency/lifecycle hashes, OS/backend, ShellCheck, and smoke result without secrets.

- [ ] **Step 2: Run CI contract tests and verify RED**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_ci tests.test_security_static tests.test_pi_provider_smoke -v`

Expected: FAIL until the new Pi selectors, forbidden-fallback scans, and evidence fields are wired.

- [ ] **Step 3: Implement no-network default CI and opt-in release smoke**

Keep ordinary CI limited to checked-in source/package-policy metadata, Python tests, catalog validation, Ruff, format, ShellCheck, compileall, and explicit-unavailable real-smoke behavior. Add a release job that requires an absolute identity-checked `PI_EXECUTABLE`, rejects every version except 0.84.1, and must pass `PiReleaseSmokeTests`; unavailable evidence fails this job.

Implement `scripts/run-pi-provider-smoke.py` as a separate release-only command accepting exact flags `--authorize-provider-smoke --pi-executable ABSOLUTE --model PROVIDER/ID --output SAFE_JSON_PATH`. It refuses missing authorization, non-0.84.1 Pi, non-private output paths, and non-interactive environments; sends one fixed non-sensitive prompt whose expected answer is the constant `PI_PROVIDER_SMOKE_OK`; inherits only the credential variables required by the explicitly selected provider through a reviewed provider allowlist; disables tools, sessions, project context, telemetry, and update checks; caps stdout/stderr; writes only schema version, Pi/package/model identifiers, start/end status, exit code, and response-hash match. It never writes the prompt, response, credentials, environment, or transcript. Unit tests use a fake executable and synthetic credentials. The real provider command remains a separately approved manual action, never runs in ordinary CI, and is not required for the base Pi support claim; if release notes claim live provider interoperability, this command and safe result become mandatory.

Update release instructions to record package policy SHA-256, source provenance, manifest/dependency/lifecycle checks, Pi runtime evidence, Python/OS/backend versions, and mandatory offline real-Pi smoke. Record the separately authorized provider-smoke safe JSON result only when that optional command was run or when release notes claim live provider interoperability; in every case exclude credentials, raw env values, prompts, responses, and transcripts.

- [ ] **Step 4: Run full verification**

Run exactly:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/validate-catalogs.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_smoke.PiSmokeTests.test_selector_reports_explicit_unavailable -v
ruff check subagents_configs scripts tests
ruff format --check subagents_configs scripts tests
sh -n ./*.sh
shellcheck install.sh uninstall.sh install-codex.sh uninstall-codex.sh install-opencode.sh uninstall-opencode.sh install-claude-code.sh uninstall-claude-code.sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q subagents_configs scripts tests
git diff --check
test -z "$(git status --short)"
```

Expected: every ordinary-CI command exits 0, the selector reports explicit unavailable evidence when no Pi executable is supplied, and the explicit status assertion proves cleanup. Before release/support claims, additionally run `PI_EXECUTABLE=/absolute/path/to/pi-0.84.1 .venv/bin/python -m unittest tests.test_pi_smoke.PiReleaseSmokeTests -v`; unavailable or wrong-version results fail. Provider smoke is omitted for the base support claim. When separately authorized—or required by a live-provider interoperability claim—record exact release inputs and run `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/run-pi-provider-smoke.py --authorize-provider-smoke --pi-executable /absolute/path/to/pi-0.84.1 --model PROVIDER/ID --output /private/tmp/pi-provider-smoke.json`; record only that bounded safe JSON artifact.

- [ ] **Step 5: Review and commit the final integration**

Inspect the complete diff for the one-component/no-service boundary, exact `--all` behavior, explicit consent, package/catalog phase ownership, no automatic Pi package rollback, redaction, fail-closed errors, and documentation parity. Commit: `git add scripts/run-pi-provider-smoke.py tests/test_pi_provider_smoke.py .github/workflows/ci.yml docs/RELEASING.md tests/test_ci.py tests/test_security_static.py && git commit -m "ci: verify pi integration contracts"`.

---

## Final verification and coverage matrix

The implementer must repeat the full verification commands from Task 11, inspect `git status --short`, and verify that only the approved plan-task files changed. The final review must include the Plan 1 prerequisite commits and confirm that Pi did not bypass capability-registry order, descriptor-relative mutation, lock acquisition, state decoding, recovery, or diagnostic redaction.

| Pi specification requirement | Plan task(s) |
| --- | --- |
| Pi is Mario Zechner's project lineage now maintained by Earendil Works, with separately authored third-party `pi-subagents` trust boundary | 2, 10 |
| Explicit `--target pi`; `--all` never reaches Pi/network/install/code | 1, 6, 11 |
| Exact pin `npm:pi-subagents@0.56.0`; reviewed changes for later versions | 2, 10, 11 |
| Official Pi package command only; no npx/install.mjs/git fallback/recursive removal | 2, 8, 11 |
| User scope via `PI_CODING_AGENT_DIR`, default `~/.pi/agent`; project deferred | 1, 5, 10 |
| Absolute verified Pi executable and compatible runtime evidence | 2, 6, 9, 10 |
| Explicit third-party-code and network consent | 1, 2, 6, 10 |
| Safe existing settings/package inspection | 2, 5, 6, 7 |
| Package/catalog separate phases and ownership | 4, 6, 7, 8 |
| Successful package + failed catalog preserves package and evidence | 4, 6, 7, 8 |
| No atomic rollback claim across Pi/npm and repository journal | 4, 7, 10 |
| Normal uninstall removes only unchanged repository-owned files | 4, 7, 8 |
| Extension removal explicit and exact pinned-entry evidence required | 2, 7, 8 |
| Five default roles; commit-pusher explicit opt-in | 3, 5, 9, 10 |
| Repository role names preserved; no scout/reviewer/worker aliases | 3, 5 |
| Explorer/reviewer exact read-only allowlist and no ambient authority | 3, 5, 9 |
| Validator has no Bash and uses Pi-native `run_validation` | 3, 9, 10 |
| `run_validation` fixed argv and mandatory `--` to isolated Python helper | 3, 9 |
| Implementer explicit read/write/Bash lists and visible scope restrictions | 3, 10 |
| Commit-pusher separate commit/push, no force-push/credential changes | 3, 10 |
| Parent-model inheritance via omitted native model field; no copied identifiers; explicit model/thinking rejected in the first release | 3, 5, 9, 10 |
| Effective discovery/collision/override/tools/extensions/skills/model/thinking/context/source checks | 5, 6, 9 |
| User settings cannot silently widen managed roles | 5, 6, 10 |
| Optional global routing uses managed Pi `APPEND_SYSTEM.md` block and is absent by default | 1, 7, 10 |
| Strict Pi dry-run with no Pi/npm/Node/network/temp/settings/package/catalog mutation | 6, 8, 10 |
| Static identity/version/manifest/dependency/lifecycle checks | 2, 11 |
| Offline, missing executable, wrong version, drift, collision, idempotency, partial failure, uninstall, concurrency tests | 2, 5, 7, 8, 9 |
| No real credentials/full transcripts; bounded/redacted diagnostics | 2, 6, 9, 10, 11 |
| Isolated real Pi smoke for discovery, inventory, canaries, validator denial/helper, optional role | 9, 11 |
| Real provider smoke is separate explicitly authorized release evidence | 9, 10, 11 |
| README trust boundary/paths/pin/consent/phase/offline/model/uninstall/OS docs | 10 |
| SECURITY trust boundary, package lifecycle, drift, redaction, no rollback docs | 10 |
| RELEASING evidence, compatibility, package review, release-note/pin governance | 10, 11 |
| macOS/Linux support and Windows fail-closed | 9, 10, 11 |
| One-component/no-service boundary and no generic plugin framework | Global Constraints, 3, 4, 11 |

Plan 1 feature integration retained for Pi:

| Plan 1 feature | Pi extension point | Covered by |
| --- | --- | --- |
| N-01 versioned JSON/text dry-run | Pi emits the same versioned plan schema and remains non-executing/non-mutating | Task 6 |
| N-02 client compatibility matrix | The predeclared unsupported row transitions to exact Pi/runtime/package/platform/scope evidence | Tasks 1, 10–11 |
| N-03 declarative profiles | A profile may contribute safe defaults only after explicit CLI `--target pi`; it cannot store consent or package authority | Task 1 |
| N-04 catalog policy diff | Deterministic `catalogs/pi.json` generation and closed-enum package/extension authority comparison | Task 5 |

Audit-ID coverage (no row may be removed during execution):

| IDs | Required outcome | Covered by |
| --- | --- | --- |
| P-01, P-03, P-04 | Correct Pi/package authorship boundary, exact package/upstream/integrity pin, official install plus evidence-gated unversioned official removal, and forbidden fallback checks | Tasks 2, 10, 11 |
| P-02, P-05, P-06 | Explicit non-`--all` target, user scope only, exact Pi 0.84.1 executable identity, consents for real install, and safe settings/config/package inspection | Tasks 1–2, 6, 8 |
| P-07, P-08, P-09 | Explicit pre-package/install/post-package/receipt/catalog phases, preserved partial success, conservative local uninstall, and separately authorized receipt-backed package removal | Tasks 4, 6–8 |
| P-10 | Strict non-executing/non-mutating Pi dry-run without consent requirement | Tasks 1, 6, 8 |
| P-11, P-12, P-13 | Target-specific Markdown sources, exact five-plus-optional managed inventory, separately verified bundled inventory, and preserved repository role names | Tasks 3, 5, 9 |
| P-14, P-15, P-16, P-17 | Exact read-only resource/process allowlists, validator-only child extension and fixed isolated helper, explicit writer tools, and optional commit-pusher authority | Tasks 3, 5, 9 |
| P-18 | Parent model inheritance represented by omitted native fields; explicit model/fallback/thinking mappings fail closed | Tasks 3, 5, 9–10 |
| P-19, P-20 | Effective discovery/collision/override/config/package/context/source enforcement and opt-in managed Pi routing | Tasks 3, 5, 7, 9–10 |
| P-21, P-22 | Provenance/static package contract and full no-credential lifecycle/failure/concurrency/Windows matrix | Tasks 2, 8, 11 |
| P-23 | Mandatory exact-Pi isolated release smoke with managed/bundled inventory, canaries, validator denial/helper, and bounded evidence | Tasks 9, 11 |
| P-24 | Separate explicitly authorized provider-smoke command and safe evidence schema | Task 11 |
| P-25 | Complete README/SECURITY/RELEASING/compatibility documentation and Windows fail-closed behavior | Tasks 1, 10–11 |
| P-26 | Hard Plan 1 registry/lock/CAS/recovery prerequisites and permanent Pi exclusion from implicit `--all` | Prerequisite Gate and Task 1 |
| P-27 | TDD, focused/full/static checks, mandatory release evidence, clean-tree assertion, documentation co-change, and reviewable commits | Global Constraints and Task 11 |

Approved execution mode: **Subagent-Driven**. Dispatch a fresh `gpt-5.6-luna` subagent with high reasoning effort for each task and complete the prescribed review checkpoint before the next task. Start this plan only after Plan 1's prerequisite gate passes.
