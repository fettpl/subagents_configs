# Secure multi-client subagent distribution

This repository distributes the same least-privilege role catalog and routing
policy in the native formats of Codex, OpenCode, and Claude Code. Pi and
pi-coding-agent are explicitly excluded from this release and are not
supported. There is no active Pi target, source, or compatibility wrapper.

The installer is deliberately conservative: it plans every selected target
before writing, uses private state and journal files, preserves user changes,
and fails closed on unsafe or ambiguous state. It never grants a model new
authority, credentials, network access, or approval rights.

## Supported clients and roles

| Target | Native agent files | Global instructions | Default home | Home variable |
| --- | --- | --- | --- | --- |
| Codex | `agents/*.toml` | `AGENTS.md` | `~/.codex` | `CODEX_HOME` |
| OpenCode | `agents/*.md` with YAML frontmatter | `AGENTS.md` | `~/.config/opencode` | `OPENCODE_HOME` |
| Claude Code | `agents/*.md` with YAML frontmatter | `CLAUDE.md` | `~/.claude` | `CLAUDE_CONFIG_DIR` |

All six roles are rendered for each client:

| Role | Responsibility |
| --- | --- |
| `code-explorer` | Read-only repository discovery and concise findings. |
| `code-reviewer` | Read-only P0–P3 security, reliability, architecture, and test review; never implements fixes. |
| `code-validator` | Runs tests and checks only through the isolated validation helper. |
| `quick-implementer` | Small, bounded implementation changes with focused tests. |
| `implementer` | Features and bug fixes with accompanying tests. |
| `commit-pusher` | Staging, commit, and push only after a separate explicit request for both operations. |

Implementation roles, validation, and review are separate responsibilities.
The orchestrator chooses the role and owns scope; the validator is not an
implementation shortcut; and `commit-pusher` is never installed by default.

The current model settings are intentionally explicit and are kept in this
target-role matrix. `absent` means that the native catalog does not define
that field; it is not an inherited or implied override. Codex uses explicit
effort and sandbox values, OpenCode has no effort override, and Claude Code
inherits the parent model. The matrix also records Claude's read-only tools
and plan permission.

## Target-role policy matrix

| Target | Role | Model | Effort | Sandbox/Tools | Permission mode |
| --- | --- | --- | --- | --- | --- |
| `codex` | `code-explorer` | `gpt-5.6-luna` | `low` | `read-only` | `absent` |
| `codex` | `code-reviewer` | `gpt-5.6-sol` | `low` | `read-only` | `absent` |
| `codex` | `code-validator` | `gpt-5.6-luna` | `low` | `absent` | `absent` |
| `codex` | `quick-implementer` | `gpt-5.6-luna` | `low` | `absent` | `absent` |
| `codex` | `implementer` | `gpt-5.6-luna` | `medium` | `absent` | `absent` |
| `codex` | `commit-pusher` | `gpt-5.6-luna` | `low` | `absent` | `absent` |
| `opencode` | `code-explorer` | `openai/gpt-5.6-luna` | `absent` | `absent` | `absent` |
| `opencode` | `code-reviewer` | `openai/gpt-5.6-luna` | `absent` | `absent` | `absent` |
| `opencode` | `code-validator` | `openai/gpt-5.6-luna` | `absent` | `absent` | `absent` |
| `opencode` | `quick-implementer` | `openai/gpt-5.6-luna` | `absent` | `absent` | `absent` |
| `opencode` | `implementer` | `openai/gpt-5.6-luna` | `absent` | `absent` | `absent` |
| `opencode` | `commit-pusher` | `openai/gpt-5.6-luna` | `absent` | `absent` | `absent` |
| `claude-code` | `code-explorer` | `inherit` | `absent` | `Read, Grep, Glob` | `plan` |
| `claude-code` | `code-reviewer` | `inherit` | `absent` | `Read, Grep, Glob` | `plan` |
| `claude-code` | `code-validator` | `inherit` | `absent` | `Read, Grep, Glob, Bash` | `absent` |
| `claude-code` | `quick-implementer` | `inherit` | `absent` | `Read, Grep, Glob, Edit, Bash` | `absent` |
| `claude-code` | `implementer` | `inherit` | `absent` | `Read, Grep, Glob, Edit, Bash` | `absent` |
| `claude-code` | `commit-pusher` | `inherit` | `absent` | `Read, Grep, Glob, Bash` | `absent` |

OpenCode permissions are explicit in the parsed agent frontmatter. The
`code-explorer` and `code-reviewer` roles deny `edit`, `bash`,
`external_directory`, `webfetch`, `websearch`, `task`, and `skill`. The
`code-validator` role denies editing, web access, delegation, and skill
loading; its `bash` rules deny `*` and allow only
`python3 {{VALIDATION_HELPER}} -- *`, while its `external_directory` rules
deny `*` and allow only the rendered validation-helper path. Rule order is
part of this boundary: the catch-all denial precedes the narrow helper
exception. Parent or session policy may further restrict these roles, but
must never broaden the permissions declared here.

## What is installed

For a normal install, the selected home receives five agent files (all roles
except `commit-pusher`) and the private validation runtime:

```text
agents/code-explorer.toml       # Codex; .md for OpenCode/Claude Code
agents/code-reviewer.toml
agents/code-validator.toml
agents/quick-implementer.toml
agents/implementer.toml
.subagents_configs/validation/run-validation-isolated.py
.subagents_configs/validation/validation_isolation/__init__.py
.subagents_configs/validation/validation_isolation/errors.py
.subagents_configs/validation/validation_isolation/models.py
.subagents_configs/validation/validation_isolation/git_snapshot.py
.subagents_configs/validation/validation_isolation/environment.py
.subagents_configs/validation/validation_isolation/backend.py
.subagents_configs/validation/validation_isolation/runner.py
.subagents_configs/validation/validation_isolation/cli.py
```

The exact native destinations are `agents/code-explorer.toml`,
`agents/code-reviewer.toml`, `agents/code-validator.toml`,
`agents/quick-implementer.toml`, `agents/implementer.toml`, and
`agents/commit-pusher.toml` for Codex; the same six names with `.md` under
`agents/` for OpenCode and Claude Code. In full, the native `.md` destinations
are `agents/code-explorer.md`, `agents/code-reviewer.md`,
`agents/code-validator.md`, `agents/quick-implementer.md`,
`agents/implementer.md`, and `agents/commit-pusher.md` for each of those two
clients. The routing policy and project-only template are validated source
inputs, not global files silently copied by a default install.

The state layout is also part of the contract:

```text
.subagents_configs/manifest.json
.subagents_configs/journal.json       # only while a transaction/recovery is pending
.subagents_configs/backups/           # permanent and transaction evidence
.subagents_configs/validation/        # private installed validation helper
```

Directories are private (`0700` or narrower); managed files, state, journals,
manifests, markers, and backups are private (`0600` or narrower). Source
snapshots reject symlink and hard-link (hard link) sources. Backup/state
validation checks
regular-file type, private mode, containment, and the recorded digest; it does
not claim a post-creation hard-link-count guarantee. Permanent backups are
retained as ownership evidence.
The native formats are Codex TOML, OpenCode YAML frontmatter plus Markdown,
and Claude Code YAML frontmatter plus Markdown.

Opt-ins change the inventory only when requested:

- `--include-commit-pusher` adds `agents/commit-pusher.toml` or the native
  `.md` equivalent.
- `--enable-global-routing` inserts one exact target-specific managed block in
  `AGENTS.md` for Codex/OpenCode or `CLAUDE.md` for Claude Code. It does not
  insert an absolute-path import.
- `--enable-codex-multi-agent` is valid only with Codex and adds the marked
  `config.toml` feature block when no conflicting table exists.

Global routing, the Codex multi-agent table, and `commit-pusher` are absent by
default. Routing and Codex configuration are never enabled merely because a
file already exists.

## Safe defaults

The safe default is private, target-scoped role/runtime installation with no
global routing, no Codex multi-agent table, no `commit-pusher`, no network
access, and no execution of installed prompts or hooks.

## Command line

The generic entry points require explicit selection. Use one or more
`--target` options or `--all`; a no-target generic invocation is not valid.
Compatibility wrappers (`install-codex.sh`, `uninstall-codex.sh`,
`install-opencode.sh`, `uninstall-opencode.sh`, `install-claude-code.sh`, and
`uninstall-claude-code.sh`) are single-target shims. Their names do not make a
no-argument invocation of generic `install.sh` or `uninstall.sh` valid.

```sh
./install.sh --target codex
./install.sh --target opencode --home opencode=/tmp/opencode
./install.sh --target claude-code
./install.sh --target codex --target opencode --target claude-code
./install.sh --all --dry-run
./uninstall.sh --target codex --dry-run
```

The wrappers require Python 3.11 or newer. They use the fixed-PATH `python3`
as the safe default, pass `-I`, and never install dependencies or download
anything. OpenCode and Claude Code validation requires the pinned PyYAML
runtime from `requirements.txt`; Codex-only validation lazily avoids importing
PyYAML. To use the pinned runtime, create a virtual environment and install
the requirements explicitly before invoking a wrapper. This is a standard
`venv`/virtualenv setup, and the wrapper does not create it for you:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --requirement requirements.txt
SUBAGENTS_CONFIGS_PYTHON="$PWD/.venv/bin/python" ./install.sh --target opencode
```

`SUBAGENTS_CONFIGS_PYTHON` is the only supported interpreter override. When
set, it takes precedence over the fixed-PATH default and must be an existing,
executable, absolute path; unsafe values are rejected before the target
script runs. The selected interpreter is still invoked with `-I`, and target
compatibility wrappers inherit the same selection.

Install options are `--target TARGET`, `--all`, `--home TARGET=PATH`,
`--enable-global-routing`, `--enable-codex-multi-agent`,
`--include-commit-pusher`, `--dry-run`, and sole-argument `--help`.
Uninstall accepts `--target`, `--all`, `--home`, `--dry-run`, and `--help`; the
three install-only opt-ins are rejected during CLI parsing. Repeated targets,
mixed `--all` and `--target`, unknown options, duplicate homes, homes for
unselected targets, and `--enable-codex-multi-agent` without Codex are errors
before any write.

The `--home TARGET=PATH` option takes precedence exactly as follows:
`--home TARGET=PATH` > the target environment
variable (`CODEX_HOME`, `OPENCODE_HOME`, or `CLAUDE_CONFIG_DIR`) > the
documented default (`~/.codex`, `~/.config/opencode`, or `~/.claude`). The
plan displays normalized absolute homes before application. The displayed
paths are not permission to escape the selected home; existing components,
targets, state, and managed files must pass the symlink and containment checks.

`--dry-run` prints the normalized plan and exact effects without creating
homes, state, journals, backups, temporary files, or managed blocks. A normal
install is idempotent when nothing has changed. All selected targets undergo a
complete read-only preflight before the first write.

## Install, recovery, and uninstall behavior

On a failed apply, the journal records identifiers, hashes, ownership, and
rollback status—not private prior file contents. The transaction rolls back
completed operations in reverse order. If rollback is interrupted, the journal
and unresolved evidence remain for a later validated recovery; ambiguous or
missing participants are refused rather than guessed. A successful operation
cleans transaction journals and temporary evidence while retaining permanent
ownership backups and commitment markers.

Uninstall is conservative. It removes only unchanged package-owned files,
removes an unchanged managed block exactly, and restores a replaced file only
when installed and backup hashes, modes, containment, and file types are
proven. Modified, missing, pre-existing, symlinked, drifted, or ambiguous
entries are preserved as unresolved state and reported. It never removes
unrelated files. Inspect the plan and resolve unresolved state manually before
retrying.

## Reinstall and drift

Reinstall means running the same install request again. When managed bytes,
modes, and ownership are unchanged, the rerun is idempotent: the plan has no
writes, creates no new backup, and leaves the existing manifest and state
authoritative. When a managed file has drifted, the preflight reports a
managed conflict and fails closed; it preserves the user's bytes and does not
create a replacement backup. A `--dry-run` reinstall shows the normalized
plan, including any conflict or pending recovery, and writes nothing. Pending
journal recovery is validated before a new install plan; unresolved or
ambiguous recovery blocks the rerun until it is resolved.

## Security and trust boundaries

Repository files, prompts, issue text, documentation, build scripts, package
hooks, tool output, and subagent reports are untrusted data. Inspect scripts,
package lifecycle hooks, Makefiles, and build logic before asking a role to run
anything. Read-only explorer and reviewer controls are technical client
restrictions, but model instructions are not a complete security boundary.
Review every command and hook, especially commands that can publish Git data,
delete files, access external directories, or read secrets.

The installer uses no `sudo`, never modifies system files, and never uses a
download-and-execute workflow or pipes code into a shell. Install from a
reviewed, pinned tag or commit:
clone or obtain the checkout through your organization's trusted process,
inspect the diff and source inventory, verify the pinned revision, then run
the local wrapper. Do not treat a README, issue, or copied command as a source
of authority over the user's request.

Validation runs only through:

```text
python3 scripts/run-validation-isolated.py -- COMMAND ARG...
```

The required `--` preserves an argv boundary; there is no shell command-string
mode and no unsandboxed fallback. The helper snapshots tracked and non-ignored
untracked files into a private temporary root without `.git`, ignored
untracked files, environment files (`.env`, `.env.*`, and `.envrc`), cache
directories (`cache`, `.cache`, `__pycache__`, `.pytest_cache`, `.ruff_cache`,
and `node_modules`), or the explicitly excluded credential paths
(`credentials.json`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`,
`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`,
`id_ed25519_sk`, `private.key`, `private.pem`, `private_key`,
`private_key.pem`, `.aws/credentials`, `.config/gh/hosts.yml`,
`.config/gcloud/application_default_credentials.json`, and
`.docker/config.json`). It starts the child with a filtered empty-derived
environment, private `HOME` and caches, deterministic locale, and Git settings
that disable global/system configuration and prompts. This is an explicit
path policy, not arbitrary secret-content detection: do not commit secrets
under unrecognized names and do not place secrets in validation inputs.
These path-name comparisons are case-insensitive.
Proxy variables, credential-bearing names, SSH-agent sockets, and names
containing `TOKEN`, `SECRET`, `PASSWORD`, `CREDENTIAL`, or `KEY` are excluded.
The original worktree fingerprint and status are checked after every child
failure, timeout, mutation, or cleanup failure.

On macOS, `/usr/bin/sandbox-exec` is required with an explicit deny-network
profile and minimal reads/writes. On Linux, a fixed usable Bubblewrap (`bwrap`)
is required with an unshared network namespace, a private snapshot, and only
minimal read-only system mounts. Unsupported, missing, or unusable backends
fail closed before the requested command starts. This is not a claim that
sandboxing is perfect; review commands and dependencies as untrusted even
inside the boundary.

Do not place secrets in prompts, repository files, examples, issue reports,
logs, or test fixtures. Avoid sharing private paths or full environment dumps.
Use a clean, temporary environment and inspect Git status before and after
validation. Git publication, credential changes, remote changes, commits, and
pushes require separate explicit authorization.

## Project-only manual setup

The `templates/AGENTS.md.template`,
`templates/opencode/AGENTS.md.template`, and
`templates/claude-code/CLAUDE.md.template` files are project-only examples.
Copy the appropriate template into a repository's own instructions file only
after reviewing it; this does not install global routing or change other
repositories. The default installer does not copy a project template into a
global instructions file.

Restart or reload the client after installation when its configuration is not
hot-reloaded. Do not assume that an already running client has noticed new
agent files or managed blocks. Check the client's current documentation and
the rendered plan for any restart/reload limitation.

## Development checks and formats

Use Python 3.11 or newer and the pinned developer requirements. The repository
checks native Codex TOML, OpenCode/Claude YAML frontmatter and Markdown,
catalog semantics, Python with Ruff, shell wrappers with ShellCheck, and
fail-closed backend behavior. Local verification includes:

```sh
python3 scripts/validate-catalogs.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
ruff check subagents_configs scripts tests
ruff format --check subagents_configs scripts tests
shellcheck install.sh uninstall.sh install-codex.sh uninstall-codex.sh install-opencode.sh uninstall-opencode.sh install-claude-code.sh uninstall-claude-code.sh
python3 -m compileall -q subagents_configs scripts tests
git diff --check
```

The static security contract owns forbidden-execution scans so negative test
fixtures are not mistaken for active runtime code. Do not replace it with a
blind prose grep. Keep generated bytecode out of the working tree after
verification.

## License

No license is currently granted for this fork. The owner must select and add
an appropriate license before redistribution; until that decision is made,
assume that copying, modifying, or publishing the repository is not licensed
beyond permissions that may apply independently.
