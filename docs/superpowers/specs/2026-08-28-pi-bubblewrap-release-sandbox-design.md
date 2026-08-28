# Pi Bubblewrap Release Sandbox Design

## Purpose

Turn the existing fail-closed Pi release boundary into a real, offline release
smoke on a dedicated Linux runner. The change proves that the caller-supplied
exact Pi 0.84.1 executable runs through Bubblewrap with no network, no ambient
home/configuration, bounded process lifetime, and only the private smoke
inputs it needs. It does not make Pi supported or released, run a provider, or
automate package acquisition.

## Scope and non-goals

- The sole release platform is Linux x64 with Bubblewrap. macOS Seatbelt and
  Windows are outside this change and remain fail-closed.
- The smoke is offline. Live provider validation, credentials, prompts,
  transcripts, and provider network access remain a separately authorized
  feature.
- The workflow never downloads Pi or `pi-subagents`. A separately authorized,
  one-time provisioning step uses the official exact Pi command
  `pi install npm:pi-subagents@0.56.0` on an ephemeral Linux machine with no
  repository checkout, credentials, or pre-existing user home. It first builds
  that exact Pi CLI from its retained registry tarball using the official
  `npm install -g --ignore-scripts` procedure in a separate private prefix,
  then creates one empty private `0700` home/`PI_CODING_AGENT_DIR` for the
  extension command. Both reviewed actions run with a clean environment, unset
  proxy/registry overrides, TLS only, and egress
  restricted by a process-independent default-deny firewall/egress gateway and
  controlled DNS/TLS allowlist to the reviewed npm registry endpoint. The owner
  preserves the gateway/DNS audit digest and rejects any additional hostname,
  address, or protocol. That explicit
  network/third-party-code consent preserves the downloaded tarball, verifies
  its pinned SHA-512 `distIntegrity`, and produces inspected receipt, manifest,
  lock, and package tree evidence. The release workflow itself is completely
offline after the pinned protected-main checkout. That control-plane checkout
is the sole allowed repository fetch; the Pi/probe execution and every
post-checkout release step have no package, registry, provider, or other
network operation.
- This change produces evidence only. The compatibility row stays
  `unreleased` and `supported: false`; a later owner-reviewed release change
  is the only transition point.

## Chosen architecture

Create a dedicated `scripts/pi_release_isolation` package instead of widening
`scripts/validation_isolation`. The generic validator is intentionally tied to
a checked-out snapshot and a fixed Python command contract. A Pi release child
needs a different trusted executable/runtime closure and three mutable private
guest directories, so sharing its public command builder would blur those
authority boundaries.

`scripts/pi_release_isolation` has a deliberately small public import surface:

```python
@dataclass(frozen=True)
class PiReleaseSandbox:
    launcher: Path
    executable: Path
    runtime_root: Path
    smoke_root: Path
    evidence_output: Path
    launcher_identity: PathIdentity
    executable_identity: PathIdentity
    runtime_identity: RuntimeClosureIdentity
    package_identity: PackageClosureIdentity
    smoke_identity: SmokeRootIdentity
    evidence_parent_identity: PathIdentity

prepare_release_sandbox(executable: Path, runtime_root: Path, smoke_root: Path, evidence_output: Path) -> PiReleaseSandbox
verify_release_sandbox(sandbox: PiReleaseSandbox) -> None
```

`SandboxProof`, the probe, Bubblewrap argv builders, and the two release
operations are private package internals. The existing Pi smoke integration is
their only caller. It receives a prepared sandbox, creates the proof itself,
and can request only the fixed version and the fixed `_REQUEST` RPC operation;
no caller can provide an alternate command, standard input, timeout,
environment, or process runner. A proof is an opaque module-private capability
whose constructor and operation-state registry are inaccessible outside the
module. It binds the nonce marker, launcher/executable/runtime/package/smoke
identities, and a transaction nonce. It permits version once then RPC once,
expires at the transaction deadline, and is consumed before the launcher exits;
cross-sandbox, stale, forged, or replayed proof use fails closed.

The preparation phase validates canonical absolute paths with no symlinks,
root-owned non-group/world-writable Bubblewrap and runtime ancestors, a
runner-owned private (`0700`) smoke root, and a regular executable with stable
device/inode identity. `PI_RUNTIME_ROOT`, `PI_SMOKE_ROOT`, and the evidence
output parent must be canonically pairwise disjoint. The exact Pi 0.84.1
runtime comes from the owner-reviewed `runtime` object in
`pi/package-policy.json`, which is already catalog-bound source/provenance for
`@earendil-works/pi-coding-agent@0.84.1` (CLI `dist/cli.js`), its
preserved npm tarball, the upstream `v0.84.1` shrinkwrap, and Node `>=22.19.0`.
The exact registry SHA-512 integrity and canonical runtime closure digest are
captured during the authorized provisioning step; no placeholder or guessed
digest is accepted. The catalog and evidence use a stable *artifact* closure
digest: the canonical serialization of sorted relative paths, entry type,
approved mode, size, and regular-file content SHA-256, explicitly excluding
device and inode. Device/inode values remain runtime-local identities used
only to detect substitution after the rootfs is mounted. The artifact digest,
entrypoint, Node ABI, and rootfs closure digest must match before the rootfs is
accepted. `PI_RUNTIME_ROOT` is a canonical root-owned,
non-group/world-writable minimal root filesystem: it contains Pi, Node, its
loader/libraries, only the fixed paths required by their reviewed shebang, and
an immutable `/opt/pi-subagents` tree. Provisioning derives that tree directly
from the retained pinned tarball and a reviewed complete file-digest contract;
it is the exact code later overlaid read-only at guest
`/pi-smoke/agent/npm/node_modules/pi-subagents`, while the Pi-owned lock and
settings evidence stays in the private smoke root. The closure tree is
directories or regular files only, has no symlinks or hard links, and is
snapshotted as sorted relative paths with device, inode, mode, size, and
SHA-256 for every regular file, while its separately calculated portable
artifact digest omits device/inode. A separate `PackageClosureIdentity` identifies
the `/opt/pi-subagents` subtree. Both complete signatures are rechecked before
and after every child launch. Pi is only accepted as a reviewed direct
executable or exact `#!/usr/bin/env node` script; the rootfs then supplies only
its own `/usr/bin/env` and `/bin/node` with guest `PATH=/bin`.

The global npm `pi` link is never copied into the rootfs. Provisioning
verifies the exact package under the private npm prefix, copies its reviewed
runtime closure into the rootfs, and materializes a regular, root-owned
`bin/pi` from the reviewed `dist/cli.js` entrypoint. The policy records both
that materialized entrypoint SHA-256 and the complete rootfs SHA-256; host
`PI_EXECUTABLE` must be exactly `PI_RUNTIME_ROOT/bin/pi` and match both before
launch. The closure contains no symlink and the launcher cannot resolve outside
the rootfs.

Because the unprivileged user namespace maps the release runner rather than
host root, the runtime policy also fixes usable read modes: directories are
`0755`, executable files are `0755`, and non-executable files are `0644`.
Root-owned `0600` files are prohibited in the rootfs; no setuid, setgid, or
file capability is allowed.

On Linux the launcher constructs its own fixed Bubblewrap argv. The rootfs must
contain empty root-owned mountpoint directories `/proc`, `/dev`, `/tmp`,
`/pi-smoke`, and probe-only `/pi-proof`; the builder verifies them before
launch. It starts with
an empty root (`--tmpfs /`) and mounts the complete reviewed runtime root only
at guest `/`; it never exposes the host root or host `/usr`, `/etc`, `/home`,
`/run`, `/var`, sockets, checkout, or credentials. It adds `--die-with-parent`,
`--new-session`, `--unshare-user`, `--unshare-net`, `--unshare-pid`,
`--unshare-ipc`, `--uid 0`, `--gid 0`, `--cap-drop ALL`, `--clearenv`, private
`/proc`, `/dev`, and `/tmp`; it binds only `agent`,
`project`, and `tmp` below the private smoke root read/write at pre-created
guest paths, sets `--chdir /pi-smoke/project`, then overlays the immutable
runtime package tree read-only at the one expected package path within `agent`.
It supplies only the existing smoke
environment with fixed guest values `HOME=/pi-smoke/agent`,
`PI_CODING_AGENT_DIR=/pi-smoke/agent`, `TMPDIR=/pi-smoke/tmp`, `PI_OFFLINE=1`,
`PI_SKIP_VERSION_CHECK=1`, `PI_TELEMETRY=0`, and `PATH=/bin`; no host `HOME` is
forwarded. The host process uses
`close_fds=True`, passes no descriptors other than standard pipes, and ensures
the parent listener, output, lock, and runner descriptors cannot reach Pi.

The probe has a separate command contract from Pi. The host writes a fixed,
hash-checked Node probe script under the private guest tmp directory and starts
only the verified guest `/bin/node` with that script, a random nonce, a parent
loopback port, and the parent network-namespace identifier. Before launch, the
parent creates an exclusive `0600` nonce sentinel in a newly-created `0700`
directory below its own canonical home, validates it no-follow, and creates the
listener. Its absolute path is passed only as an opaque argument to the fixed
probe, is never mounted, logged, or included in evidence, and is removed after
the probe. The probe alone receives a fourth private `0700` host proof
directory over the rootfs's required empty `0755` `/pi-proof` mountpoint; it
atomically creates the marker there. Pi's two later argv variants receive only
that empty rootfs mountpoint and never bind the host proof directory, so Pi
cannot read, replace, or replay the marker. The distinct sentinel and proof directories must be
canonically pairwise disjoint from each other, `PI_RUNTIME_ROOT`,
`PI_SMOKE_ROOT`, and the evidence parent; creation or revalidation failure
blocks the release. The probe must attempt the listener, fail to connect, fail
to read the sentinel, observe a different namespace, and atomically create a
`0600` marker containing the nonce. No public command API accepts arbitrary
argv, stdin, timeout, process runner, or environment.

## Evidence and control flow

1. The separately authorized provisioning machine builds the exact Pi CLI in
   its private prefix, then runs the official exact Pi extension-install
   command with network and third-party-code consent, and saves reviewed
   package evidence in a private disposable smoke root. It is destroyed before
   the offline release workflow starts.
2. The `pi-release` workflow requires protected `main`, the dedicated
   `self-hosted`, `linux`, `x64`, `pi-release` runner, and absolute values for
   `PI_EXECUTABLE`, `PI_RUNTIME_ROOT`, `PI_SMOKE_ROOT`,
   `PI_RELEASE_EVIDENCE_OUTPUT`, and `PI_RELEASE_BACKEND=bubblewrap`. It uses
   only the runner-provisioned, root-owned Python 3.13 interpreter and never
   calls the dependency bootstrapper, pip, or a network client. Preflight
   proves the unprivileged user-namespace Bubblewrap feature set with the exact
   user/PID/network/IPC flags before Pi is allowed to start.
3. An unmocked release-runner integration test first creates a disposable
   harmless smoke root and exercises the real builder/probe through Bubblewrap
   and the supplied rootfs; a missing backend or mountpoint is a failure, not a
   skip. The test is selected only when the release workflow sets the exact
   `PI_RELEASE_INTEGRATION=required` gate; absent that gate it is intentionally
   not collected by ordinary CI, while any value other than `required` on a
   `pi-release` runner fails preflight. `prepare_release_sandbox()` then validates identities and the private
   `_probe_release_sandbox()` issues an internal `SandboxProof` only after the
   distinct namespace, denied loopback, denied sentinel, writable guest temp,
   and private no-follow nonce marker checks pass. Probe output is bounded and
   never released as evidence.
4. Private `_run_verified_release_smoke(executable, root, sandbox)` sends both
   the offline version command and the JSON-RPC state command through the
   release launcher and returns an opaque `_SealedReleaseSmoke`; the public
   `run_pi_smoke(..., release=True)` may expose only its ordinary
   `PiSmokeEvidence` view.
   The existing bounded-output, timeout, executable/package/catalog identity,
   role/tool, and validator-helper checks remain in force. Before Pi starts,
   the immutable package-tree manifest must equal the exact package manifest
   recorded under the smoke root, so the read-only code overlay and lock
   evidence describe the same extension. The validator helper retains its own
   existing isolation boundary; it does not gain the Pi runtime's mounts or
   environment.
5. Only private `write_release_evidence(_SealedReleaseSmoke)` can consume the
   sealed transaction after revalidating the runtime/package closures,
   proof-marker identity/content, and sealed evidence-parent identity. It adds
   `SANDBOX_VERIFIED` and backend `bubblewrap` to its `PiSmokeEvidence` view,
   atomically creates the sealed output path itself, consumes the proof, and
   rejects forged/replayed smoke objects. `validate_pi_release_evidence()` then requires the marker and
   matching Linux/Bubblewrap combination. The version-2, bounded, path-free record also
carries SHA-256 commitments for the runtime closure, package tree,
Bubblewrap binary, and transaction proof binding, plus the checked-out Git
commit; it is written atomically at mode `0600`.

## Failure model

Any unsafe identity, mutable/symlinked closure entry, unsupported launcher or
shebang, missing Linux namespace support, probe failure, network reachability,
unreadable/replaceable proof marker, timeout, output overflow, nonzero child
exit, package drift, malformed Pi RPC response, failed proof revalidation, or
surviving descendant raises a fixed failure before a release record is written.
The wrapper makes no unsandboxed fallback, no automatic package install/removal
inside the release workflow, and no compatibility transition.

The child process is PID 1 in its own PID namespace. Timeout, output overflow,
and normal completion terminate its process group, wait briefly, then use
SIGKILL if needed. The outer launcher must be reaped and observed exited before
return; only that exit tears down the private PID namespace. An adversarial
`setsid()`/double-fork test proves that no release-owned descendant can create a
post-run marker. Cleanup failure or an unreaped outer launcher is itself a
release failure.

## Verification

Unit tests use controlled internal process seams to assert the exact argv,
empty rootfs, private mounts, environment allowlist, closed inherited-FD set,
identity rechecks, opaque-proof lifecycle, marker checks, PID-namespace
cleanup, durable evidence bindings, and every denial path without executing
external Pi. Ordinary Linux CI keeps only the generic real isolation probe and
the deterministic unit contracts. The exact new-builder integration probe and
Pi rootfs smoke are explicitly owner-only `pi-release` gates: they require the
root-owned runtime and AppArmor/user-namespace policy that hosted PR workers
must never provision. They run unmocked and fail, rather than skip, on the
dedicated manual trusted runner with Pi 0.84.1 and reviewed package evidence.

Before considering a release transition, run the ordinary full suite, catalog
validation, Ruff, compile checks, shell syntax/ShellCheck, and the dedicated
real release workflow. An owner then reviews the bounded evidence and complete
diff. Provider smoke is explicitly excluded from this release gate.

## Owner-controlled provisioning prerequisite

Before any implementation task that edits `pi/package-policy.json`, provision
first on an ephemeral, non-shared Linux machine without credentials and create
an owner-signed, path-free `pi-runtime-provisioning-manifest-v1` plus an
immutable, content-addressed transfer bundle. The manifest records the Pi and
extension registry integrities, shrinkwrap hash, materialized `bin/pi` hash,
portable runtime/package-tree closure digests, Node ABI, receipt/lock/manifest
hashes, and egress-audit digest; the bundle contains only the reviewed tarballs
and derived runtime inputs. Transfer the bundle to the separate offline runner
by owner-controlled offline media and verify every recorded digest before use.
Do not begin Task 1 or invent policy fields unless that manifest is available:
its reviewed values are copied verbatim into the catalog-bound `runtime` object
and `installedTreeSha256` in the same Task-1 policy/catalog commit.

Provision by using an ephemeral, non-shared Linux machine without credentials:
after recording the owner's network and third-party-code consent, use a clean
environment with process-independent default-deny firewall/egress-gateway and
controlled DNS/TLS allowlists only to the reviewed registry endpoint to build
Pi from the retained `@earendil-works/pi-coding-agent@0.84.1` tarball with the
official `npm install -g --ignore-scripts` procedure in a private prefix.
Verify its shrinkwrap and exact registry integrity, then create a separate
empty private `0700` `HOME`/`PI_CODING_AGENT_DIR` and run the official exact Pi
0.84.1 package command to install `pi-subagents@0.56.0`. Retain the extension
tarball, verify its pinned `distIntegrity`, inspect the resulting
receipt/manifest/lock, and build the reviewed digest-checked package tree;
retain a path-free digest of the gateway/DNS audit showing no other egress, then
destroy the provisioning machine. On the separate release runner, build
the Pi rootfs solely from the exact artifact and hashes in the catalog-bound
`pi/package-policy.json` runtime object, verify its closure and Node ABI, install root-owned
fixed Bubblewrap with the documented unprivileged user-namespace/AppArmor
policy; a policy refusal must make the real Bubblewrap preflight fail. Create
the immutable rootfs including that package tree. Preinstall
the root-owned Python 3.13 interpreter used by the release job; no pip or
dependency bootstrap occurs there. Set the five repository variables, ensuring
the output parent is a private canonical directory disjoint from runtime and
smoke roots and the destination does not exist. Use workflow concurrency one
for `pi-release`, manually dispatch protected `main`, inspect bounded evidence
for correctness and absence of secrets, then destroy the disposable smoke root.
None of these operational steps alter the repository compatibility claim.
