# Security policy

## Scope and supported versions

The current branch and the latest reviewed checkout are the supported security
scope. This project has no release branch or private backport program yet.
Report security concerns against the exact revision you inspected, including
the client target and operating system when relevant. Pi and
pi-coding-agent are out of scope and are not supported.

The checked-in client compatibility matrix is read-only policy data. The
unsupported Pi row is an identity for reporting only: it creates no runtime
target, descriptor, parser, selector, package command, network path, platform
claim, or version claim. Compatibility preflight checks native format,
declared features, platform, user scope, package identity, and an optional
caller-supplied numeric client version without executing a client or reading
environment variables. Missing version evidence uses the maintained tested
row and never probes the host. Matrix updates require separate release-owner
authorization and separately reviewed read-only client-version evidence.

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
guesses. Alternating durable progress records bind operation statuses and full
before/after file identities before their journal transitions. Manifests and
journals contain identifiers, paths, hashes, ownership,
and status—not prior private file contents. Backups are hash-checked and are
not a permission to read or publish the original content.

Validation accepts only the argv form
`python3 scripts/run-validation-isolated.py -- COMMAND ARG...`. It creates a
private snapshot without `.git`, ignored untracked files, environment files
(`.env`, `.env.*`, and `.envrc`), cache directories (`cache`, `.cache`,
`__pycache__`, `.pytest_cache`, `.ruff_cache`, and `node_modules`), and the
explicitly excluded credential paths (`credentials.json`, `.npmrc`, `.pypirc`,
`.netrc`, `.git-credentials`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ecdsa_sk`,
`id_ed25519`, `id_ed25519_sk`, `private.key`, `private.pem`, `private_key`,
`private_key.pem`, and the credential-store paths `.aws/credentials`,
`.config/gh/hosts.yml`,
`.config/gcloud/application_default_credentials.json`, and
`.docker/config.json`). It filters secrets and proxy variables from an
empty-derived environment, and checks the original worktree fingerprint and
status after the child exits, times out, mutates, or fails cleanup. macOS
requires a usable `/usr/bin/sandbox-exec` deny-network profile. Linux requires
a usable fixed Bubblewrap backend with an unshared network namespace and
minimal read-only system mounts. Unsupported or unusable backends fail closed
before the requested command starts; there is no unsandboxed fallback.

The snapshot credential policy is an explicit path policy, not arbitrary
secret-content detection; do not commit secrets under unrecognized names or
place them in validation inputs. These path-name comparisons are
case-insensitive. Descriptor-relative pinning and before/after evidence detect
swaps around mutations, and persistent locks serialize cooperative installer
clients. Transaction cleanup uses durable local journals, full file-identity
evidence, a retained base record, and a separately staged cleanup record. These
controls make interrupted cleanup resumable and reject malformed state,
hardlinks, inode replacements, and internally inconsistent journal/anchor
rewrites. They are local crash- and consistency-evidence, not an authenticated
append-only store: a same-UID actor that can coordinate rewriting a journal,
the affected target or backup state, and the mutable progress or cleanup
anchors needed for an accepted crash-boundary state can construct a different
self-consistent history without rewriting every anchor.
Preventing that stronger attack requires an external key, TPM, privileged
service, or other trust boundary that this project does not possess. Rewrites
that do not form a complete accepted crash-boundary state fail closed.
Cross-home cleanup is resumable, not atomic. If a same-UID actor deletes every
participant journal, restart has no trusted fact that distinguishes completed
cleanup from coordinated deletion; unproved orphan anchors are preserved
rather than interpreted or removed.

However, a non-cooperative actor able to race the parent can swap the
final pathname after the final evidence proof and immediately before the
trusted `unlink`/`rmdir` primitive. Python/POSIX offers no portable
inode-conditional `unlink`/`rmdir`; in that residual window, the primitive may
remove a replacement or otherwise unowned final entry selected by the swapped
pathname. This is a limitation of the accepted final filesystem primitive; it
does not remove the other containment, no-following, ownership, or evidence
checks. These controls are not perfect sandboxing. A validation dependency may
still contain a vulnerability, and client behavior can change. Do not place
secrets in prompts, repository files, fixtures, logs, or issue reports. Do not
grant network, credential, external-directory, or write authority merely to
make a check convenient. Inspect target paths, state, journals, backups, symlinks,
hard links, and Git status before and after sensitive operations.

Never use `sudo`, download-and-execute installers, or unreviewed shell snippets.
Review external files and hooks before running them. Git commits, pushes,
publication, remotes, and credential changes require a separate explicit user
request and independent review.

## Reporting a concern

Report vulnerabilities through the private GitHub Security Advisory channel:
https://github.com/fettpl/subagents_configs/security/advisories/new

Reports must contain no secrets and no transcripts; do not include credentials,
private paths, or sensitive exploit payloads. Provide only the minimum safe reproduction,
affected revision, target/client, platform, and threat boundary. There is no
promised response time or security SLA.

Include the affected revision, target/client, platform, threat boundary, and a
minimal reproducible description only when it is safe to do so. Redact command
output and environment values rather than attaching full logs or snapshots.
