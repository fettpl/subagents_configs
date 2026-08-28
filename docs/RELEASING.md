# Manual release checklist

Every item in this document is a manual owner action. This repository does not
automate publication, branch protection, signing, release creation, or changes
to hosting settings.

## Governance before a release

- Keep protected `main` and require CI to pass; required CI is a release gate.
- Require at least one independent review of the complete diff, including
  security and documentation changes.
- Block public redistribution until the owner separately approves the exact license text and SPDX identifier. This task does not select a license or add
  `LICENSE`; adding `LICENSE` is a dedicated, separately reviewed
  documentation commit after that approval.
- Configure and verify the private security advisory channel and publish its
  handling policy manually.
- The security channel is the private GitHub Security Advisory URL recorded in
  `SECURITY.md`; do not move vulnerability reports to public issues.
- Decide the version and write release notes that identify supported clients,
  limitations, migration concerns, and verification evidence.

## Client compatibility matrix maintenance

Updating `catalogs/client-compatibility.json` is a separately authorized,
read-only release-owner action. Record client version evidence obtained from a
reviewed `client --version` invocation outside the installer; do not add a
runtime probe or package-manager check. For each supported Codex, OpenCode, or
Claude Code row, independently review the exact native format, required and
optional features, Linux/macOS platform evidence, user scope, and package
identity (currently none). Keep the compatibility-only Pi row unsupported and
without platform, package, or version claims in the machine matrix until a
separate Pi task is authorized; the human projection may describe the intended
evidence boundary without turning it into a support claim. Update the matrix and README/SECURITY wording together, then run
the focused compatibility tests, full unittest discovery, catalog validation,
Ruff, compile checks, shell/YAML checks, and `git diff --check`. Release notes
must state whether a client version was caller-supplied or derived from the
maintained tested row; they must never imply that installation probed a client.

Branch protection, required checks, review rules, signing policy, and security
channel setup are hosting/owner decisions. Do not attempt to configure them
from this task.

## Pi release gate (Task 11 only)

Task 10 publishes documentation and the explicit unreleased compatibility row;
it does not transition Pi to support. Only Task 11 may transition Pi to
supported and change the canonical row
after every gate below passes and an owner approves publication.

Before any Pi release, review the exact `pi/package-policy.json` source commit
and package policy, the upstream provenance, package name/version, SHA-512 distribution integrity,
package JSON SHA-256, lock SHA-256, manifest, dependency versions, peer
dependencies, and forbidden lifecycle-script list. The first intended package
is `npm:pi-subagents@0.56.0`, tested against exact Pi 0.84.1 and peer
`@earendil-works/pi-ai >=0.80.0`. A pin change requires a fresh source commit,
integrity, manifest, dependency, lifecycle, compatibility, and release-note
review; release notes must call out the changed pin and evidence.

The release gate records Python 3.11, Python 3.12, Python 3.13, and Python 3.14,
the exact Pi version, operating system and backend (macOS/Linux only), and the package-policy
identifiers. It must run the mandatory isolated real-Pi smoke in offline mode,
including discovery, managed and bundled inventories, canaries, validator
denial/helper behavior, and cleanup evidence. An unavailable or wrong-version
executable is a release failure, not support evidence. Windows remains
fail-closed and unsupported.

For the release record, preserve the literal command outputs for `python
--version`, `pi --offline --version`, and `pi --help` only after reviewing them
for secrets. Also record the exact package-policy SHA-256, upstream source
commit, distribution SHA-512 integrity, package-manifest and lock-file
SHA-256 values, manifest/dependency/lifecycle checks, operating system,
isolation backend, ShellCheck version, and the bounded real-Pi smoke result.
The real-Pi smoke must use the externally supplied absolute executable for
exact Pi 0.84.1 and the complete `PiReleaseSmokeTests` suite. Never substitute
an installed package-manager binary, `npx`, an install script, a source clone,
or a network probe when evidence is unavailable.

Provider smoke is optional and separate from the base Pi support claim. If it
is run, or if release notes claim live provider interoperability, it requires
separate manual consent and explicit provider-smoke authorization. Record only
the reviewed bounded safe result; never record credentials, raw environment
values, prompts, responses, or transcripts.

The separately authorized command is:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/run_pi_provider_smoke.py \
  --authorize-provider-smoke \
  --pi-executable /absolute/path/to/pi-0.84.1 \
  --model PROVIDER/ID \
  --output /private/tmp/pi-provider-smoke.json
```

Run it only from an interactive terminal with a reviewed provider credential
allowlist. The JSON artifact contains schema/version/package/model
identifiers, start/end status, exit code, and a response-hash match; it does
not contain the prompt, response, credentials, environment, or transcript.
Treat a missing, non-private, non-interactive, unreviewed-provider, or
wrong-version input as a release failure. Provider smoke is never run by
ordinary CI and is not required for the base Pi support claim.

Normal package/catalog work is not atomic and does not imply automatic package
rollback. Package removal is a separate manual action using the unversioned
`npm:pi-subagents` command only after exact pinned receipt evidence. The owner
must manually inspect the complete diff, approve third-party execution and
publication, obtain independent security/documentation review, and sign the
commit/tag before changing `supported: false` to `supported: true`.

## Clean-tree verification

On a clean tree and trusted checkout at the candidate revision, manually inspect the
diff and run the pinned developer environment. Do not use real Codex,
OpenCode, or Claude homes. Bootstrap once, then run exactly the canonical
validator:

```sh
scripts/bootstrap-developer.sh
.venv/bin/python scripts/validate-repository.py
```

Confirm that no generated bytecode, private data, credentials, ignored build
output, or unintended file mode changes remain. Check the complete `git
status`, source inventory, native TOML/YAML-frontmatter/Markdown formats, and
the fail-closed behavior when a usable isolation backend is absent. Record the
exact revision and tool versions in the release notes.

Reproducible verification means using the hash-locked `requirements-dev.lock`,
a clean checkout, deterministic temporary homes, and the canonical validator
from the preceding bootstrap-and-validation block.

## Catalog policy review gate

Before publication, compare the candidate generated catalog revision with the
previous reviewed revision using the standalone local command:

```sh
python scripts/manage-subagents-configs.py policy-diff \
  --from catalogs/revisions/before \
  --to catalogs/revisions/after \
  --format json
```

This is a read-only review gate. It accepts only strict normalized snapshots,
requires matching target sets and coherent revision identifiers, and never
reads client homes, environment settings, credentials, or source contents.
Inspect every reported role/model/tool/permission/destination/source-hash and
authority change. Any authority broadening requires separate owner approval;
the command itself does not publish, install, uninstall, or modify files.
Generated catalog hashes are checked against their canonical metadata, role
overlay hashes, and source inventory hash. The shared `policy_sha256` input
cannot be reconstructed from one catalog because it includes the generator's
full role-policy table; its value is nevertheless cryptographically bound by
the verified top-level catalog hash and remains covered by the generator check.

The validator performs no installation, download, network access, or
credential access. Bootstrap a developer environment only with
`scripts/bootstrap-developer.sh`; runtime wrappers never install packages.
It does not mean that client behavior, operating-system sandboxing, or
third-party dependencies are permanently identical.

## Signed source and artifacts

The owner must manually create a signed commit and signed tag (annotated) for
the approved revision. Verify the tag and commit locally before release. Do
not use `--no-verify`, force-push, or rewrite the reviewed history.

Generate release artifacts from the clean tagged checkout. Generate SHA-256
checksums for every artifact, verify each checksum from a separate clean read,
and publish the artifacts and checksum file through the owner's approved
channel. Publish the tag, version, release notes, supported Python/client
versions, and known macOS/Linux backend limitations together.

## Installation guidance

Release notes must show installation from the reviewed immutable tag or commit,
after a manual diff and checksum review. The pinned checkout workflow must not
download and execute an unreviewed script, use `sudo`, modify system files, or
silently grant network or credential access. Document the exact target options,
safe defaults, opt-ins, and client restart/reload limitations.

## What is intentionally not automated

This task does not push branches, publish releases, upload artifacts, change
remotes, configure branch protection, create required checks, create signing
keys, select a license, or create a private vulnerability-reporting channel.
Those are manual owner actions requiring their own authorization and review.
