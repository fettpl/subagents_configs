# Client compatibility

The canonical compatibility source is
[`catalogs/client-compatibility.json`](../catalogs/client-compatibility.json).
This Markdown table is its human-readable projection; the machine-readable
Pi row remains `supported: false` and `status: "unreleased"` until Task 11.

| Client | Supported scope | Home variable/default | Native format | Runtime/package evidence | Validation backends | Unsupported scope |
| --- | --- | --- | --- | --- | --- | --- |
| codex | released / supported | `CODEX_HOME` / `~/.codex` | TOML agents plus Markdown routing | maintained client row; no package | linux/macOS: bwrap / sandbox-exec | Pi-only lifecycle and package features |
| opencode | released / supported | `OPENCODE_HOME` / `~/.config/opencode` | YAML frontmatter plus Markdown | maintained client row; no package | linux/macOS: bwrap / sandbox-exec | Pi-only lifecycle and package features |
| claude-code | released / supported | `CLAUDE_CONFIG_DIR` / `~/.claude` | YAML frontmatter plus Markdown | maintained client row; no package | linux/macOS: bwrap / sandbox-exec | Pi-only lifecycle and package features |
| pi | unreleased / unsupported | `PI_CODING_AGENT_DIR` / `~/.pi/agent` | Markdown agents plus TypeScript extension | intended evidence boundary: Pi 0.84.1; `pi --offline --version` / `pi --help`; `npm:pi-subagents@0.56.0`; peer `@earendil-works/pi-ai >=0.80.0` | macOS/Linux: isolated offline real-Pi smoke required by Task 11 | Windows fail-closed; project scope and live provider smoke are not supported claims |

The Pi row is explicit so selection and reporting can be validated without
implying a release. Its intended user home is resolved in this order:
explicit `--home pi=PATH`, an explicitly selected profile
`target_defaults.pi.home`, `PI_CODING_AGENT_DIR`, then `~/.pi/agent`.
Profiles cannot select Pi, and `--all` excludes it. Pi is not supported on
Windows; unsupported or unusable platform backends fail closed.

Pi follows the project lineage of Mario Zechner's Pi coding agent, currently
maintained by Earendil Works. `pi-subagents` is a separately authored
third-party package by Nico Bailon, so its source, package manifest,
dependencies, lifecycle scripts, and integrity are a separate trust boundary.
The exact first-release package pin is `npm:pi-subagents@0.56.0`, with the
reviewed peer `@earendil-works/pi-ai >=0.80.0`; later pins require a new review.

Task 11 is the sole support transition. It must complete the mandatory
isolated real-Pi smoke for exact Pi 0.84.1 and the complete release gate before
the JSON row may change to `supported: true`. A provider smoke is optional,
separately authorized release evidence and is never implied by this row.
The release-only transition predicate requires successful exact-version smoke,
exact package evidence, the complete bounded evidence markers, and every other
release gate; it has no side effects and cannot change this checked-in row.
