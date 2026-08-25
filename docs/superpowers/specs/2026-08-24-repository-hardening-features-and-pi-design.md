# Repository Hardening, Natural Extensions, and Pi Support Design

## Status and source

This design records the repository audit and Pi integration architecture approved
on 2026-08-24 at revision `5264e39700e69e774f6c0895a1be0a9b96419ec1`.
It extends the existing secure multi-client distribution design without weakening
its least-privilege, fail-closed, explicit-authorization, or conservative-uninstall
guarantees.

Implementation is split into exactly two plans:

1. harden and extend the current Codex, OpenCode, and Claude Code product;
2. add explicitly gated Pi support through the third-party `pi-subagents` package.

Pi implementation begins only after the target-capability and transaction-safety
work required from the first plan is complete.

## Product boundary

The repository remains one cohesive local tool. It does not gain a service,
daemon, dashboard, telemetry pipeline, remote control plane, or generic plugin
framework. New modules and target-native artifacts are allowed only when they
separate existing responsibilities or enforce a supported harness boundary.

All repository content, package metadata, prompts, client output, project
instructions, and subagent output remain untrusted data. No diagnostic, state
record, plan, or test artifact may contain credential values, raw environment
values, private file contents, full prompts, or provider transcripts.

## Plan 1 requirements: current-scope hardening

### Transaction safety

- Serialize planning, recovery, apply, and journal cleanup with a descriptor-backed
  lock for every selected target home. Acquire multi-target locks in canonical
  target order and release them only after journal cleanup.
- Replace check-then-mutate operations with descriptor-relative compare-and-swap
  semantics. Expected device, inode, content hash, and mode must still match at the
  mutation boundary for replace, unlink, chmod, rollback, and restore.
- Finish all read-only evidence checks before preparation creates directories or
  backups. Track preparation-owned artifacts and clean only those artifacts if
  journal preparation fails.
- Preserve existing fail-closed recovery, participant, commitment, ownership,
  symlink, hard-link, mode, and containment checks.

### Validation isolation and permissions

- Compare environment, cache, credential, and excluded path names
  case-insensitively, including mixed-case `.env`, `.env.*`, `.envrc`, and cache
  directory variants.
- Add real Bubblewrap and Seatbelt smoke coverage that executes the selected
  backend and proves network denial, host-read denial, snapshot reads, private
  temporary writes, child status propagation, and checkout immutability.
- Add a macOS CI or release gate for the real Seatbelt smoke suite. Linux retains
  its real Bubblewrap gate. Unsupported backends continue to fail closed.
- Replace Claude Code validator's unrestricted Bash boundary with a technical
  command gate, using a reviewed `PreToolUse` hook or a narrower native mechanism.
  Prompt text alone is not enforcement.
- Add semantic-negative tests for every target and role, including models,
  permissions, tools, rule ordering, helper paths, body contracts, role names, and
  optional-role inventory.
- Add cleanup-only failure tests for validation isolation and preserve sanitized
  error precedence.

### Architecture and catalog maintenance

- Make one target capability registry authoritative for order, formats, parser,
  semantic validator, global instruction behavior, optional configuration blocks,
  runtime sources, and external lifecycle capabilities.
- Represent lifecycle actions and ownership combinations with validated
  constructors or typed variants while retaining strict decoding of hostile
  persisted state.
- Expose stable module seams for managed blocks, state loading, safe filesystem
  mutation, transaction recovery, and validation lifecycle ownership; callers
  must stop importing private helpers across module boundaries.
- Split oversized transaction/state/validation modules only along those proven
  seams. The command-line entry points and installed validation helper remain
  single cohesive interfaces.
- Define shared role policy once and render native target catalogs with explicit
  per-target model, effort, tool, permission, and syntax overlays. Generated
  catalogs remain checked into the repository and reproducibly validated.

### Tests, performance, dependencies, and contributor experience

- Consolidate duplicate destination hashing without removing final identity,
  content, mode, link-count, size, or replacement checks.
- Reuse validated state inventory within a command only inside explicit mutation
  boundaries; revalidate immediately before writes.
- Reuse already-read instruction/config bytes during planning and remove duplicate
  CI test invocations while retaining equivalent coverage and useful diagnostics.
- Lock Python dependencies with reviewed artifact hashes for every supported
  platform and Python version.
- Test Python 3.11, 3.12, 3.13, and 3.14 or narrow the published support contract.
- Create one non-installing validation entry point used by contributors, CI, and
  release documentation. It must use fixed argv, never install dependencies, and
  preserve CI's private environment and backend checks.
- Document separate runtime and developer bootstraps using the pinned requirement
  files. Add repository-local contributor/agent guidance for trust boundaries,
  validation, temporary homes, and publication authorization.
- Introduce typed stable diagnostic codes with fixed safe context; never expose raw
  exceptions, secret-bearing paths, package-manager output, or environment values.
- Document recovery replay, exact multi-target participants/homes, dry-run output,
  exit codes, and manual-resolution boundaries.
- Establish a private vulnerability-reporting path and block public redistribution
  until the repository owner separately chooses and approves a license. The plan
  must not select a license on the owner's behalf. Publish tested Python, OS
  backend, and client compatibility prerequisites.
- Define and test a state schema compatibility matrix and migration mechanism
  before introducing schema version 2.

## Plan 1 requirements: natural feature expansion

The following four features are mandatory and remain inside the existing CLI:

1. **Versioned structured dry-run:** an opt-in JSON output containing schema
   version, operation, normalized targets/homes, actions, hashes, ownership,
   conflicts, recovery requirements, and safe source identifiers. Default text
   output remains compatible.
2. **Client compatibility contract:** read-only target adapters validate supported
   format/features and optional client versions without executing prompts or
   broadening authority. A maintained matrix covers Codex, OpenCode, Claude Code,
   and later Pi.
3. **Declarative install profiles:** a strict local JSON or TOML request schema
   maps to the existing request model. Unknown keys, credentials, ambiguous
   precedence, duplicate homes, and unsafe paths are rejected. Explicit CLI values
   override profile values according to one documented precedence rule.
4. **Catalog policy change reports:** a read-only command compares normalized
   catalogs or revisions and reports role, model, tool, permission, destination,
   source-hash, and authority changes. Authority broadening is highlighted.

## Plan 2 requirements: Pi support

### Trust and lifecycle model

- Pi is the Mario Zechner coding-agent lineage now maintained under Earendil
  Works. `pi-subagents` is a separately authored third-party package and executes
  inside Pi with the user's authority.
- Pi is selected only by explicit `--target pi`. Existing `--all` must not trigger
  network access, package installation, or third-party code execution.
- The first supported package is exactly `npm:pi-subagents@0.56.0`. A later version
  requires an explicit reviewed source change, package inventory review, dependency
  review, compatibility evidence, and release-note update.
- The installer uses only Pi's official package command. It never invokes
  `npx pi-subagents`, the package's `install.mjs`, `git clone`, `git pull`, or a
  recursive removal fallback.
- User-scope support is the first release and follows `PI_CODING_AGENT_DIR`, whose
  default is `~/.pi/agent`. Project scope is deferred until its trust, working-tree,
  and ownership semantics receive a separate approved design.
- Package installation requires explicit third-party-code and network consent,
  exact package identity, an absolute verified Pi executable, compatible Pi
  runtime evidence, and safe inspection of existing settings/package state.
- Pi package registration and repository-managed role installation are distinct
  phases and ownership domains. Read-only checks run before the package command;
  the installed package is then verified before local catalog mutation. The
  product never claims atomic rollback across Pi/npm and the repository
  transaction journal.
- If package installation succeeds and catalog installation fails, leave the
  extension installed, preserve evidence, and report the phase boundary. Never
  run automatic package removal as rollback.
- A successful package install creates a strict, minimal, durable ownership receipt
  outside the repository transaction journal. Normal uninstall removes only
  unchanged repository-owned Pi role/runtime files. Removing the extension
  requires a separate explicit operation, that receipt, and exact evidence that
  this installer created the same pinned package entry; pre-existing or drifted
  package state is preserved. The official removal command uses Pi's unversioned
  npm package identity only after the versioned entry has been proven.
- Pi dry-run performs no Pi, npm, Node, package-manager, network, lock-anchor,
  temporary-file, settings, package-store, state, journal, backup, or catalog
  mutation. It uses two complete read-only evidence collections and fails closed
  if they differ; it never probes the executable. A caller-supplied version fact
  is validated when present, otherwise output labels the version as maintained-
  matrix-only evidence rather than observed runtime evidence.

### Pi catalog

- Source files live in a target-specific repository directory and install as
  Markdown/YAML-frontmatter user agents below the selected Pi home.
- Exactly five roles install by default. `commit-pusher` remains source-only and is
  installed only through the existing explicit optional-role flag.
- Preserve the repository role names; do not alias them to the extension's bundled
  `scout`, `reviewer`, or `worker` names.
- `code-explorer` and `code-reviewer` receive an exact read-only tool allowlist and
  no Bash, write, edit, MCP, ambient extension, alias, package, or inherited-skill
  authority.
- `code-validator` receives no Bash. A small Pi-native, target-scoped
  `run_validation` tool invokes the existing isolated Python helper through fixed
  argv and the mandatory `--` boundary. This is a Pi target artifact, not a
  service or independent product.
- `quick-implementer` and `implementer` receive explicit read/write/Bash tool lists.
  Their commit, push, credential, network, and scope restrictions remain visible,
  with the parent session retaining the final authority boundary.
- `commit-pusher` stays absent by default and retains its separate explicit
  commit-and-push authorization, no-force-push, no-credential-change contract.
- Start with inherited parent-model behavior; for `pi-subagents@0.56.0` this means
  omitting the `model` frontmatter key and normalizing that absence to the policy
  value `inherit`. Do not copy Codex/OpenCode identifiers. Thinking levels and
  explicit model mappings are rejected in the first release and require a later
  reviewed compatibility-matrix change backed by live registry evidence.
- The pinned package's bundled agents and the repository-managed roles are separate
  inventories. Exactly five repository roles install by default and the optional
  `commit-pusher` is sixth; bundled `scout`, `researcher`, `worker`, `reviewer`,
  `oracle`, and `delegate` roles are verified as third-party package inventory and
  are never relabeled as repository roles.
- Validate effective discovery, collisions, overrides, tools, extensions, skills,
  model, thinking, context inheritance, and source identity. User settings must not
  silently widen a repository-managed role without a reported conflict.
- Pi global routing, if enabled, uses the existing explicit global-routing opt-in
  and a managed block in the Pi global instruction file. It is absent by default.

### Pi verification and documentation

- Add static package identity/version/manifest/dependency/lifecycle checks.
- Add dry-run, offline, missing executable, wrong version, settings drift, package
  drift, collision, idempotency, partial-phase failure, uninstall, and concurrency
  tests without real credentials.
- Add real Pi smoke tests in isolated temporary homes for discovery, exact role
  inventory, read-only write canaries, validator Bash denial, helper execution,
  optional role absence/presence, and bounded/redacted diagnostics.
- Real provider smoke tests are optional supplementary evidence, separately
  authorized and absent from ordinary CI; they become mandatory only when release
  notes claim live provider interoperability and never record credentials or full
  transcripts.
- Pi extends the four Plan 1 feature seams rather than creating parallel tooling:
  it uses the same versioned dry-run schema and compatibility matrix, contributes a
  deterministic normalized catalog to policy diff, and accepts profile defaults
  only after an explicit CLI `--target pi`. Profiles cannot store Pi executable,
  consent, or package-removal authority.
- README, SECURITY.md, and RELEASING.md must document the Pi trust boundary,
  supported versions, exact managed paths, package pin, consent, non-atomic phase
  boundary, offline/dry-run behavior, model/provider behavior, uninstall ownership,
  and macOS/Linux support. Windows remains fail-closed until separately designed.

## Global acceptance

- Every task follows test-driven development and ends with focused tests, the full
  relevant suite, static checks, clean-tree verification, and a reviewable commit.
- No task weakens fail-closed behavior to make a test, platform, or client pass.
- Documentation and generated/catalog contract tests change in the same task as
  the behavior they describe.
- Final verification uses pinned developer dependencies and records exact Python,
  client, Pi, package, backend, and ShellCheck versions without recording secrets.
