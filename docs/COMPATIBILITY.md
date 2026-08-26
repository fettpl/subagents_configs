# Client compatibility

This repository currently maintains native installation support for Codex,
OpenCode, and Claude Code. Pi is registered as an explicit-only target so its
selection and safety boundaries can be developed incrementally; it is not yet
released or supported for installation.

| Target | Status | Selection | Home | Environment variable |
| --- | --- | --- | --- | --- |
| Codex | supported | `--target codex`, `--all` | `~/.codex` | `CODEX_HOME` |
| OpenCode | supported | `--target opencode`, `--all` | `~/.config/opencode` | `OPENCODE_HOME` |
| Claude Code | supported | `--target claude-code`, `--all` | `~/.claude` | `CLAUDE_CONFIG_DIR` |
| Pi | unreleased / unsupported | `--target pi` only | `~/.pi/agent` | `PI_CODING_AGENT_DIR` |

Pi is intentionally absent from `--all`; its future global instruction file is
`APPEND_SYSTEM.md`. Its home is resolved in this order:
an explicit `--home pi=PATH` > `target_defaults.pi.home` >
`PI_CODING_AGENT_DIR` > `~/.pi/agent`.
Every Pi install, including `--dry-run`, requires an explicit lexically
absolute `--pi-executable`; dry-run reports the compatibility boundary and
never executes it. The Pi executable and third-party/network consents are explicit CLI authority;
profiles may provide only a safe Pi home default and may not select Pi.

The checked-in machine-readable source is
[`catalogs/client-compatibility.json`](../catalogs/client-compatibility.json).
The Pi row must remain `supported: false` until later tasks provide exact
runtime/package evidence and release-owner approval.

The remaining Pi work is intentionally staged across Tasks 2–11: source and
role rendering, planning, external package lifecycle, transaction/recovery
boundaries, catalogs, documentation and CI, followed by a release transition.
Task 11 requires mandatory isolated real-Pi smoke evidence for the pinned
`pi-coding-agent` and `pi-subagents` versions before the compatibility row can
be marked supported.
