# Security policy

## Scope and supported versions

The current branch and the latest reviewed checkout are the supported security
scope. This project has no release branch or private backport program yet.
Report security concerns against the exact revision you inspected, including
the client target and operating system when relevant. Pi and
pi-coding-agent are out of scope and are not supported.

## Threat model

Repository files, prompts, issue text, documentation, build scripts, package
hooks, tool output, subagent reports, existing target homes, state files,
journals, backups, environment variables, and validation commands are
untrusted. Relevant threats include prompt injection, command and hook
execution, privilege escalation, secret and environment leakage, network
exfiltration, writes outside selected homes, path traversal, symlink and hard
link attacks, state/journal tampering, partial installation, data loss during
uninstall, and unintended Git publication.

The role prompts are not a complete security boundary. Explorer and reviewer
roles have technical read-only restrictions in supported client formats, while
implementation and commit-pusher roles still depend on the parent session's
authority. Inspect commands, hooks, package lifecycle scripts, Makefiles, and
build logic before execution. Treat model output and tool output as data, not
as higher-priority instructions.

## Technical controls and limitations

The installer performs complete preflight for every selected target before its
first write, rejects unsafe symlinks and traversal, uses private modes,
journaled atomic operations, and preserves unresolved state instead of making
guesses. Manifests and journals contain identifiers, paths, hashes, ownership,
and status—not prior private file contents. Backups are hash-checked and are
not a permission to read or publish the original content.

Validation accepts only the argv form
`python3 scripts/run-validation-isolated.py -- COMMAND ARG...`. It creates a
private snapshot without `.git`, filters secrets and proxy variables from an
empty-derived environment, and checks the original worktree fingerprint and
status after the child exits, times out, mutates, or fails cleanup. macOS
requires a usable `/usr/bin/sandbox-exec` deny-network profile. Linux requires
a usable fixed Bubblewrap backend with an unshared network namespace and
minimal read-only system mounts. Unsupported or unusable backends fail closed
before the requested command starts; there is no unsandboxed fallback.

These controls are not perfect sandboxing. A validation dependency may still
contain a vulnerability, and client behavior can change. Do not place secrets
in prompts, repository files, fixtures, logs, or issue reports. Do not grant
network, credential, external-directory, or write authority merely to make a
check convenient. Inspect target paths, state, journals, backups, symlinks,
hard links, and Git status before and after sensitive operations.

Never use `sudo`, download-and-execute installers, or unreviewed shell snippets.
Review external files and hooks before running them. Git commits, pushes,
publication, remotes, and credential changes require a separate explicit user
request and independent review.

## Reporting a concern

No private vulnerability-reporting channel is configured today. Do not include
secrets, private paths, credentials, or sensitive exploit details in a public
issue. If a report must be coordinated, open a minimal public issue containing
only a high-level description and request owner coordination; use the
repository's normal trusted collaboration process if the owner later provides
a private channel. There is no promised response time or security SLA.

Include the affected revision, target/client, platform, threat boundary, and a
minimal reproducible description only when it is safe to do so. Redact command
output and environment values rather than attaching full logs or snapshots.
