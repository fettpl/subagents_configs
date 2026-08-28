# Pi Bubblewrap Release Sandbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the intentional Pi release-sandbox refusal with a verified, offline Bubblewrap release launcher for the exact Pi 0.84.1 smoke.

**Architecture:** Add a dedicated `scripts/pi_release_isolation` package that owns Linux-only Pi runtime closure validation, fixed Bubblewrap argv construction, sandbox probing, and process-group cleanup. Inject its typed launcher into the existing Pi smoke harness so only verified release calls receive `SANDBOX_VERIFIED`; ordinary CI stays unavailable and the compatibility row remains unreleased.

**Tech Stack:** Python 3.13 on the dedicated release stage, Bubblewrap, Linux user namespaces/AppArmor, existing `unittest`, existing Pi 0.84.1 runtime fixture, GitHub Actions, Ruff, ShellCheck.

**Spec:** `docs/superpowers/specs/2026-08-28-pi-bubblewrap-release-sandbox-design.md`

## Global Constraints

- Support only a dedicated Linux x64 Bubblewrap release runner; macOS and Windows remain fail-closed.
- Never download Pi or `pi-subagents` in CI. A separately authorized, disposable provisioning machine builds the reviewed Pi CLI from its registry tarball via official `npm install -g --ignore-scripts` in a private prefix, then runs the official exact Pi `install npm:pi-subagents@0.56.0` command in a separate private home, with network and third-party-code consent, an independently enforced default-deny firewall/egress gateway, controlled DNS/TLS registry allowlist, and retained path-free audit digest; only inspected immutable runtime/package artifacts and evidence reach the offline release runner. “Offline” begins after the pinned protected-main checkout, which is the sole allowed control-plane repository fetch; Pi/probe and all later release steps must make no network request.
- Require `PI_EXECUTABLE`, `PI_RUNTIME_ROOT`, `PI_SMOKE_ROOT`, and `PI_RELEASE_EVIDENCE_OUTPUT` to be absolute and identity-checked; require `PI_RELEASE_BACKEND` to equal the enum value `bubblewrap`.
- `PI_RUNTIME_ROOT`, `PI_SMOKE_ROOT`, and the evidence-output parent must be canonically pairwise disjoint; the output destination must not exist. Bubblewrap must be canonical `/usr/bin/bwrap` or `/bin/bwrap`, root-owned and non-group/world-writable, and is rechecked before every child launch.
- The runtime closure must be a root-owned, canonical minimal rootfs, non-group/world-writable, directories or regular files only, with no symlinks and regular-file link count exactly one. It must contain root-owned empty mountpoints `/proc`, `/dev`, `/tmp`, `/pi-smoke`, and probe-only `/pi-proof`, plus immutable `/opt/pi-subagents`. To work under an unprivileged user namespace, require directories `0755`, executable files `0755`, and data files `0644`; reject root-only, setuid, setgid, or file-capability entries. Snapshot relative path, device, inode, owner, mode, size, and SHA-256 for every regular file and revalidate the complete local identity signature before every child. Separately calculate the catalog/evidence portable artifact digest from sorted relative paths, type, approved mode, size, and regular-file content SHA-256, excluding device/inode; it must equal the policy digest.
- The smoke root, `agent`, `project`, and `tmp` are existing runner-owned `0700` directories; no other host writable path is mounted.
- The fixed release argv starts with `--tmpfs /`, mounts the complete reviewed runtime root read-only at guest `/`, then mounts `/proc`, `/dev`, `/tmp`, and the three guest smoke subdirectories in that order, and sets `--chdir /pi-smoke/project`. It uses `--die-with-parent`, `--new-session`, `--unshare-user`, `--unshare-net`, `--unshare-pid`, `--unshare-ipc`, `--uid 0`, `--gid 0`, `--cap-drop ALL`, and `--clearenv`. It overlays `/opt/pi-subagents` read-only at guest `/pi-smoke/agent/npm/node_modules/pi-subagents`, binds no other host path, and never mounts host `/usr`, `/etc`, `/home`, `/run`, `/var`, sockets, checkout, or credentials.
- After `--clearenv`, set only guest `HOME=/pi-smoke/agent`, `PI_CODING_AGENT_DIR=/pi-smoke/agent`, `TMPDIR=/pi-smoke/tmp`, `PI_OFFLINE=1`, `PI_SKIP_VERSION_CHECK=1`, `PI_TELEMETRY=0`, and `PATH=/bin`; do not forward host HOME, credentials, package-manager configuration, arbitrary PATH entries, prompts, responses, or transcripts. Use `close_fds=True` and allow no inherited descriptors beyond standard pipes.
- The probe uses only the immutable rootfs Node interpreter and a hash-checked fixed guest script. The rootfs supplies an empty `/pi-proof` mountpoint; only the probe overlays it with a temporary private proof bind, which Pi never receives. It must prove a distinct network namespace, attempted-and-denied parent loopback, host-home sentinel denial, writable guest temp, and a private no-follow nonce marker before Pi starts. Its private proof and sentinel directories are canonically pairwise disjoint from each other, runtime, smoke, and evidence-output parents.
- Version and JSON-RPC Pi calls use the same release launcher and an internal, stateful `SandboxProof`; public calls cannot select argv, stdin, timeout, runner, or environment. The runner accepts the reviewed `_REQUEST` only. The runtime/package closures and proof marker are revalidated after every child and before evidence. Timeout, overflow, normal completion, and errors terminate and reap the outer PID namespace; cleanup failure blocks evidence.
- `SANDBOX_VERIFIED` is emitted only after the real probe, post-child proof revalidation, and a matching Linux/Bubblewrap check in `validate_pi_release_evidence()`. The version-2 evidence record includes path-free commitments for runtime/package closures, Bubblewrap, proof binding, and repository commit. No unsandboxed fallback, support transition, or provider smoke is permitted.
- `PiReleaseBackendIntegrationTests` is selected exclusively by `PI_RELEASE_INTEGRATION=required`: ordinary CI does not collect it, while the dedicated `pi-release` preflight rejects missing or any other value and therefore cannot skip the real test.
- Before Task 1, an owner must produce an owner-signed, path-free `pi-runtime-provisioning-manifest-v1` and a content-addressed immutable transfer bundle on the authorized disposable provisioning machine. The manifest contains exact Pi/extension registry integrities, Pi shrinkwrap hash, materialized `bin/pi` hash, Node ABI, portable runtime/package-tree closure digests, receipt/lock/manifest hashes, and egress-audit digest. Its values are reviewed and copied verbatim into `pi/package-policy.json`/generated `catalogs/pi.json` in the Task-1 commit; no Task-1 implementation starts without it, and the bundle is verified on the offline release runner after owner-controlled offline transfer.

---

### Mandatory preflight: provision reviewed Pi inputs before Task 1

This is an external owner operation, not a repository implementation task. On a
disposable, non-shared provisioning machine without repository checkout,
credentials, or a pre-existing user home, record the owner's explicit consent
to network and third-party code. Build the exact Pi CLI from its retained
tarball in a private prefix with official `npm install -g --ignore-scripts`,
then create a separate empty private `0700` `HOME`/`PI_CODING_AGENT_DIR` and
run the official exact Pi command `pi install npm:pi-subagents@0.56.0` with a
clean environment and no proxy/registry overrides. Enforce egress outside the
process with a default-deny firewall/egress gateway plus controlled DNS and TLS
allowlists limited to the reviewed registry endpoint; retain a path-free audit
digest and reject every extra hostname, address, or protocol. Preserve and
verify the extension tarball's pinned integrity and Pi runtime
tarball/shrinkwrap provenance; inspect the receipt, manifest, lock, and
portable package-tree digest. Create and owner-sign the path-free
`pi-runtime-provisioning-manifest-v1` and immutable content-addressed transfer
bundle containing only reviewed tarballs and derived runtime inputs. Transfer
it by owner-controlled offline media to the separate runner and verify all
manifest digests. Only then may Task 1 copy those exact values verbatim into
the catalog-bound `runtime` object and `installedTreeSha256` in
`pi/package-policy.json`; otherwise stop with no placeholder values. Destroy
the provisioning machine once transfer verification is complete.

Expected: an owner-reviewed manifest and verified immutable bundle exist before
the first Task-1 policy/catalog edit; this preflight changes no repository file
by itself.

---

### Task 1: Define Pi release-sandbox identities and immutable runtime closure checks

**Files:**

- Create: `scripts/pi_release_isolation/__init__.py`
- Create: `scripts/pi_release_isolation/errors.py`
- Create: `scripts/pi_release_isolation/models.py`
- Create: `scripts/pi_release_isolation/identity.py`
- Modify: `pi/package-policy.json`
- Modify: `subagents_configs/pi_package.py`
- Modify: `tests/test_pi_package.py`
- Modify: `catalogs/pi.json`
- Modify: `tests/test_catalogs.py`
- Create: `tests/test_pi_release_isolation.py`

**Interfaces:**

- Consumes: `Path`, `os.lstat`, and existing private-root conventions in `tests/pi_smoke_support.py`.
- Produces: `PiReleaseSandbox`, `PathIdentity`, `RuntimeClosureIdentity`, `PackageClosureIdentity`, `SmokeRootIdentity`, `PiReleaseIsolationError`, `prepare_release_sandbox(executable: Path, runtime_root: Path, smoke_root: Path, evidence_output: Path) -> PiReleaseSandbox`, and `verify_release_sandbox(sandbox: PiReleaseSandbox) -> None`.

- [ ] **Step 1: Write failing identity-contract tests**

```python
def test_prepare_rejects_a_runtime_symlink_and_writable_runtime_file(self):
    root = self.make_private_root()
    runtime = self.make_root_owned_like_runtime(root / "runtime")
    executable = self.make_pi(runtime / "bin/pi")
    output = self.make_private_output(root / "evidence/pi.json")
    (runtime / "node_modules/link").symlink_to(runtime / "bin/pi")
    with self.assertRaisesRegex(PiReleaseIsolationError, "RUNTIME_UNSAFE"):
        prepare_release_sandbox(executable, runtime, root, output)

    (runtime / "node_modules/link").unlink()
    mutable = runtime / "node_modules/entry.js"
    mutable.write_text("x", encoding="utf-8")
    mutable.chmod(0o664)
    with self.assertRaisesRegex(PiReleaseIsolationError, "RUNTIME_UNSAFE"):
        prepare_release_sandbox(executable, runtime, root, output)
```

Add cases for relative paths, noncanonical launcher/executable/runtime paths, a non-private smoke root, pairwise-overlapping runtime/smoke/output parents, a group/world-writable `bwrap`, an executable outside the runtime root, a missing rootfs mountpoint, a rootfs shell/interpreter escape, an unsafe/mismatched immutable package tree, a changed device/inode, and in-place runtime or package content replacement after preparation. Patch identity helpers rather than requiring root ownership in unit tests.

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_release_isolation.PiReleaseIdentityTests tests.test_pi_package tests.test_catalogs -v`

Expected: FAIL because `scripts.pi_release_isolation` and `prepare_release_sandbox` do not exist.

- [ ] **Step 3: Implement minimal typed identity module**

```python
@dataclass(frozen=True)
class PathIdentity:
    path: Path
    device: int
    inode: int
    mode: int
    owner: int
    sha256: str | None

@dataclass(frozen=True)
class RuntimeEntry:
    relative_path: PurePosixPath
    device: int
    inode: int
    owner: int
    mode: int
    size: int
    sha256: str | None

@dataclass(frozen=True)
class RuntimeClosureIdentity:
    root: PathIdentity
    entries: tuple[RuntimeEntry, ...]
    artifact_sha256: str  # portable content/path/mode digest; no device/inode

@dataclass(frozen=True)
class PackageClosureIdentity:
    root: PathIdentity
    entries: tuple[RuntimeEntry, ...]
    artifact_sha256: str  # portable content/path/mode digest; no device/inode

@dataclass(frozen=True)
class SmokeRootIdentity:
    root: PathIdentity
    agent: PathIdentity
    project: PathIdentity
    temporary: PathIdentity

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

class PiReleaseIsolationError(ValueError):
    pass
```

Extend `subagents_configs/pi_package.py` and `tests/test_pi_package.py` before editing the policy, using only values from the approved `pi-runtime-provisioning-manifest-v1`: add a strict catalog-bound `runtime` object and canonical `installedTreeSha256` to `pi/package-policy.json`, with non-placeholder provenance for `@earendil-works/pi-coding-agent@0.84.1`, registry tarball integrity, upstream shrinkwrap hash, Node `>=22.19.0`, package entrypoint `dist/cli.js`, its materialized regular `bin/pi` SHA-256, portable canonical rootfs closure digest, and the complete extension-tree digest. The portable closure algorithm serializes sorted relative path, entry type, approved mode, size, and regular-file SHA-256, never device/inode; `RuntimeEntry` device/inode remain only local replacement detection. Regenerate `catalogs/pi.json` with `scripts/generate-catalogs.py` and add catalog regression tests so the changed source hash is intentional. Then implement no-follow `lstat` validation for every path component. Canonicalize the trusted `/bin` to `/usr/bin` alias before accepting Bubblewrap; require the launcher, executable, every runtime ancestor, and every runtime entry to be root-owned and immutable to group/other. Require host `PI_EXECUTABLE` to be exactly `PI_RUNTIME_ROOT/bin/pi`, a regular `nlink == 1` file materialized from the verified private-prefix `dist/cli.js` rather than npm's global `pi` symlink, and compare its digest and the full closure to the runtime policy. Require exact rootfs mountpoint directories `/proc`, `/dev`, `/tmp`, `/pi-smoke`, and `/pi-proof`, and an immutable `/opt/pi-subagents` package closure. Recursively reject symlinks/special files/hard-linked regular runtime/package files, snapshot sorted local identity signatures, calculate portable artifact closure digests, and compare the package artifact digest to `installedTreeSha256`. Tests must reject a different entrypoint, materialized-executable digest, rootfs digest, absent, guessed, or mismatched runtime/policy fields. Require pre-created private `agent`, `project`, and `tmp` child identities in addition to smoke root, and a private existing evidence parent that is pairwise disjoint while the destination itself does not exist. `verify_release_sandbox()` repeats validation and compares all identities/signatures, raising only fixed tokens: `BWRAP_UNSAFE`, `PI_EXECUTABLE_UNSAFE`, `RUNTIME_UNSAFE`, `PACKAGE_UNSAFE`, and `SMOKE_ROOT_UNSAFE`.

- [ ] **Step 4: Run focused test to verify it passes**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_release_isolation.PiReleaseIdentityTests -v`

Expected: PASS; unsafe identity permutations raise a fixed error before any child process is invoked.

- [ ] **Step 5: Run formatting and commit**

Run: `.venv/bin/python scripts/generate-catalogs.py --write`

Run: `.venv/bin/python scripts/generate-catalogs.py --check`

Run: `.venv/bin/ruff check subagents_configs/pi_package.py scripts/pi_release_isolation tests/test_pi_package.py tests/test_catalogs.py tests/test_pi_release_isolation.py`

Run: `.venv/bin/ruff format --check subagents_configs/pi_package.py scripts/pi_release_isolation tests/test_pi_package.py tests/test_catalogs.py tests/test_pi_release_isolation.py`

Run: `git diff --check`

Commit only `pi/package-policy.json`, `catalogs/pi.json`, `subagents_configs/pi_package.py`, `scripts/pi_release_isolation`, `tests/test_pi_package.py`, `tests/test_catalogs.py`, and `tests/test_pi_release_isolation.py` with `feat: validate Pi release sandbox identities`.

Expected: checks pass and the commit contains only Task 1 files.

### Task 2: Build and prove the fixed Linux Bubblewrap boundary

**Files:**

- Modify: `scripts/pi_release_isolation/models.py`
- Create: `scripts/pi_release_isolation/backend.py`
- Modify: `scripts/pi_release_isolation/__init__.py`
- Modify: `tests/test_pi_release_isolation.py`

**Interfaces:**

- Consumes: `PiReleaseSandbox` and `verify_release_sandbox()` from Task 1.
- Produces: internal `_build_pi_argv(sandbox: PiReleaseSandbox, operation: Literal["version", "rpc"]) -> tuple[str, ...]`, internal `_build_probe_argv(sandbox: PiReleaseSandbox, probe: ProbeInput) -> tuple[str, ...]`, and internal `_probe_release_sandbox(sandbox: PiReleaseSandbox) -> SandboxProof`. `ProbeInput` is factory-only and contains the fixed-script path/digest, listener port, parent network-namespace identifier, sentinel `PathIdentity`, private proof-root identity, and nonce digest. `SandboxProof` is factory-only and contains the no-follow marker identity/content digest, runtime/package/launcher/executable/smoke identities, transaction deadline, and an opaque registry token/state; only the module registry can consume version then RPC once.

- [ ] **Step 1: Write failing fixed-argv and probe tests**

```python
def test_linux_argv_has_no_network_or_ambient_host_mounts(self):
    argv = _build_pi_argv(self.sandbox, "version")
    self.assertIn("--unshare-net", argv)
    self.assertIn("--unshare-user", argv)
    self.assertIn("--cap-drop", argv)
    self.assertIn("--clearenv", argv)
    self.assertIn("--die-with-parent", argv)
    self.assertNotIn(str(Path.home()), argv)
    self.assertNotIn("/var/run/docker.sock", argv)
    self.assertIn("--tmpfs", argv)
    self.assertEqual(argv[argv.index("--tmpfs") + 1], "/")
    self.assertEqual(argv[argv.index("--chdir") + 1], "/pi-smoke/project")

def test_probe_rejects_reachable_loopback_or_missing_private_marker(self):
    with patch("scripts.pi_release_isolation.backend._run_bounded_bwrap", self.loopback_reachable):
        with self.assertRaisesRegex(PiReleaseIsolationError, "SANDBOX_PROBE_FAILED"):
            _probe_release_sandbox(self.sandbox)
```

Add assertions that the runtime root contains the five required mountpoints, including an empty `/pi-proof`, and is the only rootfs mount; `agent`, `project`, and `tmp` are the only writable guest binds for Pi; the probe alone overlays its distinct private proof root at `/pi-proof`; and the immutable package tree is overlaid read-only at the one expected agent path. Assert that proof and sentinel directories are pairwise disjoint from each other, runtime, smoke, and evidence parents. Assert no host `/usr`, `/etc`, `/home`, `/run`, `/var`, socket, inherited FD, or unexpected guest mount appears in argv; unapproved environment keys are rejected; unsafe Pi tails are rejected; and probe marker replacement, symlink, mode change, nonce mismatch, cross-sandbox proof, forged proof, stale proof, and replayed proof are rejected. Add adversarial probe cases for parent loopback reachability, parent namespace reuse, and a detached `setsid()` descendant. Patch the internal process seam only; the public API must not accept a caller-provided runner.

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_release_isolation.PiReleaseBackendTests -v`

Expected: FAIL because the fixed argv builder and probe do not exist.

- [ ] **Step 3: Implement Bubblewrap builder and probe**

Implement a Linux-only builder with two closed command paths. `_build_pi_argv()` accepts only `version` or `rpc` and maps them to the exact reviewed Pi argv from `tests/fixtures/pi-0.84.1-runtime-contract.json`; RPC always writes the fixed `_REQUEST` internally. `_build_probe_argv()` accepts only a host-created `ProbeInput` whose script digest, nonce digest, listener port, parent namespace, sentinel, and proof root were produced by the internal probe factory; it starts only the reviewed rootfs `/bin/node` and guest probe path. Begin each Bubblewrap argv with `--tmpfs /`, mount `runtime_root` read-only at guest `/`, then mount private `/proc`, `/dev`, `/tmp`, and the three pre-created guest smoke paths in that order, and set `--chdir /pi-smoke/project`. The immutable rootfs must provide an empty `/pi-proof` mountpoint. Overlay `runtime_root/opt/pi-subagents` read-only at guest `/pi-smoke/agent/npm/node_modules/pi-subagents`; the probe variant additionally binds the private proof root over `/pi-proof`, while Pi variants retain only the empty rootfs directory. Add `--unshare-user --uid 0 --gid 0 --cap-drop ALL --unshare-net --unshare-pid --unshare-ipc --new-session --die-with-parent --clearenv`. The only guest executable paths are rootfs Pi, `/bin/node`, and rootfs `/usr/bin/env` used by Pi's exact reviewed shebang. Spawn Bubblewrap only with `close_fds=True`, an empty `pass_fds`, and the three bounded standard streams.

Implement the probe as a fixed hash-checked Node script created under private host tmp before launch. The parent creates a listener plus an exclusive `0600` nonce sentinel in a newly-created `0700` canonical directory below its own home; it validates the sentinel no-follow, passes its path only to the fixed probe, removes it afterwards, and never writes its path to evidence or logs. The script must attempt the listener, fail to connect, fail to read the sentinel, compare `/proc/self/ns/net` with the supplied parent namespace, create a fresh exclusive `0600` marker containing its nonce under `/pi-proof`, and exit nonzero if any condition fails. Read that host marker with `O_NOFOLLOW`, verify regular file, `nlink == 1`, owner, exact `0600`, content, and stable identity. Create the opaque proof through the module-private factory, binding its one-time operation state, marker, closures, executable, launcher, and smoke identities. Raise `SANDBOX_PROBE_FAILED` for every probe failure.

- [ ] **Step 4: Run focused test to verify it passes**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_release_isolation.PiReleaseBackendTests -v`

Expected: PASS. Ordinary Linux CI retains only deterministic unit contracts and the existing generic real isolation probe. The exact runtime-root smoke and unmocked real-builder probe are explicitly owner-only manual trusted-runner gates because ordinary CI has no approved root-owned Pi rootfs or AppArmor policy; they must fail, never skip, when `pi-release` runs them.

- [ ] **Step 5: Run formatting and commit**

Run: `.venv/bin/ruff check scripts/pi_release_isolation tests/test_pi_release_isolation.py`

Run: `.venv/bin/ruff format --check scripts/pi_release_isolation tests/test_pi_release_isolation.py`

Run: `git diff --check`

Commit only `scripts/pi_release_isolation` and `tests/test_pi_release_isolation.py` with `feat: add verified Bubblewrap Pi release boundary`.

Expected: checks pass and the commit contains only Task 2 files.

### Task 3: Route release Pi commands through the verified launcher and bind evidence

**Files:**

- Modify: `scripts/pi_release_isolation/backend.py`
- Create: `scripts/pi_release_isolation/runner.py`
- Modify: `scripts/pi_release_isolation/__init__.py`
- Modify: `subagents_configs/compatibility.py`
- Modify: `tests/pi_smoke_support.py`
- Modify: `tests/test_pi_smoke.py`
- Modify: `tests/test_pi_release_isolation.py`
- Modify: `tests/test_compatibility.py`
- Modify: `scripts/run-pi-release-smoke.py`
- Modify: `tests/test_pi_provider_smoke.py`

**Interfaces:**

- Consumes: Task 2's probe and argv builder plus existing `PiSmokeEvidence`, release-record schema, and atomic-write helper.
- Produces: private closed `ReleasePiCommandRunner` operations for only `version` and `rpc`, private `_run_verified_release_smoke(executable: Path, root: Path, sandbox: PiReleaseSandbox) -> _SealedReleaseSmoke`, private `write_release_evidence(sealed: _SealedReleaseSmoke) -> dict[str, object]`, `run_pi_smoke(executable: Path, root: Path, *, release: bool = False, sandbox: PiReleaseSandbox | None = None) -> PiSmokeEvidence`, `select_pi_executable(executable: Path | None = None, root: Path | None = None, *, release: bool = False, sandbox: PiReleaseSandbox | None = None) -> PiSmokeEvidence`, and records whose `smoke_evidence` contains `SANDBOX_VERIFIED`.

- [ ] **Step 1: Write failing release-path tests**

```python
def test_release_smoke_routes_pi_calls_through_the_verified_runner(self):
    sandbox = self.verified_fake_sandbox()
    with patch("tests.pi_smoke_support.ReleasePiCommandRunner") as runner:
        evidence = run_pi_smoke(
            self.executable, self.root, release=True, sandbox=sandbox
        )
    self.assertEqual(runner.call_count, 1)
    self.assertEqual(runner.return_value.run_version.call_count, 1)
    self.assertEqual(runner.return_value.run_rpc.call_count, 1)
    self.assertEqual(evidence.sandbox_backend, "bubblewrap")
    self.assertIn("SANDBOX_VERIFIED", evidence.evidence)

def test_public_smoke_evidence_cannot_construct_a_release_record(self):
    smoke = replace(self.successful_smoke, evidence=("PI_SMOKE_OK",))
    with self.assertRaisesRegex(ValueError, "PI_RELEASE_EVIDENCE_INCOMPLETE"):
        write_release_evidence(smoke)  # type: ignore[arg-type]

def test_release_record_rejects_missing_sandbox_commitments(self):
    record = self.make_verified_release_record()
    del record["runtime_closure_sha256"]
    with self.assertRaisesRegex(ValueError, "Pi release evidence schema"):
        validate_pi_release_evidence(record)
```

Add release tests for wrong or missing `PI_RUNTIME_ROOT`, probe failure before version invocation, command identity drift between version and RPC calls, overflow/timeout/term-resistant descendant cleanup, outer-launcher unreaped failure, an absent marker, an inaccessible Pi proof directory, a failing exact package/tree check, a manifest mismatch between the immutable package tree and the smoke-root lock evidence, and no inherited listener/secret descriptor. Change tests that expect `PI_RELEASE_SANDBOX_UNAVAILABLE` to expect `PI_RELEASE_SANDBOX_REQUIRED` when no prepared sandbox is passed. Add compatibility tests proving that `SANDBOX_VERIFIED` is mandatory; the four path-free sandbox commitments are mandatory 64-character hashes; `repository_commit` is a mandatory 40-character Git SHA; and a release record is accepted only for `platform == "linux"` and `backend == "bubblewrap"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_smoke.PiReleaseSmokeTests tests.test_pi_provider_smoke.PiProviderSmokeTests -v`

Expected: FAIL because release smoke still raises `PI_RELEASE_SANDBOX_UNAVAILABLE`, and evidence/compatibility validation do not require the marker and Linux/Bubblewrap pair.

- [ ] **Step 3: Implement release-only command runner**

Create `ReleasePiCommandRunner` in `runner.py`. Its only callable operations are `run_version()` and parameterless `run_rpc()`: neither accepts caller-controlled argv, standard input, timeout, environment, or process runner. Each operation first asks the private proof registry to authorize the required next state, calls `verify_release_sandbox()` immediately before invocation, builds the fixed Bubblewrap argv, starts the launcher with a new session and closed inherited descriptors, streams the fixed/bounded input and stdout/stderr with the existing 30-second/8192-byte bounds, and unconditionally kills/waits its process group after every completion or failure. It reaps and confirms exit of the outer Bubblewrap process before returning; it returns only bounded bytes and fixed errors.

Refactor `_probe_version()` and `_bounded_child()` to accept a narrow command-runner protocol. Ordinary smoke continues to pass the existing direct runner. Private `_run_verified_release_smoke()` requires a prepared sandbox, calls private `_probe_release_sandbox()` before starting Pi, routes both commands through `ReleasePiCommandRunner`, reuses every existing identity/package/catalog/validator check, and additionally requires the immutable package-tree manifest to equal the exact smoke-root package evidence before Pi starts. It returns a module-sealed `_SealedReleaseSmoke` bound to the proof, `PiSmokeEvidence`, all four commitments, repository commit, and `evidence_parent_identity`; public `run_pi_smoke(..., release=True)` returns only that sealed result's smoke-evidence view. `write_release_evidence(sealed)` alone revalidates the proof marker plus complete runtime/package closures and evidence parent, appends `SANDBOX_VERIFIED`, builds and validates the record, atomically writes its sealed output path at `0600`, consumes the proof/result, and deletes the private proof directory. Any forged, stale, cross-sandbox, or replayed smoke/result fails before a record exists.

Update `subagents_configs/compatibility.py` together with the private sealed writer to schema version 2: require the exact ordered evidence tuple with `SANDBOX_VERIFIED`, Linux/Bubblewrap, four path-free SHA-256 commitments named `runtime_closure_sha256`, `package_tree_sha256`, `bubblewrap_sha256`, and `sandbox_proof_sha256`, plus a path-free 40-character `repository_commit`. Extend the sealed binding calculation and `PiReleaseEvidence` fields, reject the old schema, and update `tests/test_compatibility.py` accordingly. `scripts/run-pi-release-smoke.py` obtains a clean checked-out `HEAD` commit internally, requires `PI_RUNTIME_ROOT`, validates the new output path, passes it into `prepare_release_sandbox()` for pairwise-disjoint identity checks, obtains `_SealedReleaseSmoke`, and calls its private evidence writer; it must not format, validate, or atomically write evidence itself. It emits only fixed release failure text on unsafe input. Update provider-smoke release-entrypoint tests for the required environment variable without authorizing provider execution.

- [ ] **Step 4: Run focused test to verify it passes**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_smoke.PiReleaseSmokeTests tests.test_pi_provider_smoke.PiProviderSmokeTests tests.test_pi_release_isolation tests.test_compatibility -v`

Expected: PASS; ordinary Pi selector remains unavailable, release calls are sandbox-only, and the compatibility transition remains false.

- [ ] **Step 5: Run formatting and commit**

Run: `.venv/bin/ruff check subagents_configs/compatibility.py scripts/pi_release_isolation scripts/run-pi-release-smoke.py tests/pi_smoke_support.py tests/test_pi_smoke.py tests/test_pi_provider_smoke.py tests/test_compatibility.py`

Run: `.venv/bin/ruff format --check subagents_configs/compatibility.py scripts/pi_release_isolation scripts/run-pi-release-smoke.py tests/pi_smoke_support.py tests/test_pi_smoke.py tests/test_pi_provider_smoke.py tests/test_compatibility.py`

Run: `git diff --check`

Commit only `subagents_configs/compatibility.py`, `scripts/pi_release_isolation`, `scripts/run-pi-release-smoke.py`, `tests/pi_smoke_support.py`, `tests/test_pi_smoke.py`, `tests/test_pi_provider_smoke.py`, and `tests/test_compatibility.py` with `feat: run Pi release smoke inside verified sandbox`.

Expected: checks pass and the commit contains only Task 3 files.

### Task 4: Harden the manual release workflow and release-owner documentation

**Files:**

- Modify: `.github/workflows/ci.yml`
- Modify: `docs/RELEASING.md`
- Modify: `README.md`
- Modify: `tests/test_ci.py`
- Modify: `tests/test_pi_provider_smoke.py`
- Modify: `tests/test_readme_contract.py`
- Modify: `tests/test_compatibility.py`
- Create: `tests/test_releasing_contract.py`

**Interfaces:**

- Consumes: Task 3's `PI_RUNTIME_ROOT` requirement and `SANDBOX_VERIFIED` evidence contract.
- Produces: a manual-only release job that fails closed before Pi execution when runner/runtime inputs are unsafe, uses no dependency bootstrap after checkout, and documentation that correctly states the offline evidence boundary.

- [ ] **Step 1: Write failing workflow and documentation contract tests**

```python
def test_release_entrypoint_requires_runtime_root_before_selection(self):
    result = self.run_release_entrypoint({
        "PI_EXECUTABLE": "/opt/pi-runtime/bin/pi",
        "PI_SMOKE_ROOT": "/private/pi-smoke",
        "PI_RELEASE_EVIDENCE_OUTPUT": "/private/evidence/pi.json",
        "PI_RELEASE_BACKEND": "bubblewrap",
    })
    self.assertEqual(result.returncode, 2)
    self.assertEqual(result.stdout, "PI_RUNTIME_ROOT_UNAVAILABLE\n")
```

Extend `tests/test_ci.py` workflow contract tests to require the fifth repository variable, root-owned closure and executable validation, all mandatory rootfs mountpoints and immutable package-tree overlay, a fresh output path pairwise disjoint from smoke/runtime roots, a single-release concurrency group, exactly one pinned protected-main `actions/checkout` control-plane fetch, self-hosted Linux x64 `pi-release` labels, user/PID/network/IPC namespace preflight that fails under the runner's owner-managed AppArmor policy, root-owned Python 3.13, the unmocked real-builder integration test, and no provider variables. Require that after checkout `pi-release` never invokes `bootstrap-developer.sh`, `pip`, npm, `setup-python`, or another network/bootstrap step. Create `tests/test_releasing_contract.py` to parse the Pi release-gate section and require `offline after checkout`, `Bubblewrap`, `SANDBOX_VERIFIED`, `PI_RUNTIME_ROOT`, `unreleased`, Python 3.13, exact-runtime provenance, and the statement that package acquisition/provider smoke are outside this workflow. Keep `tests/test_readme_contract.py` limited to README's user-facing boundary claims.

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_provider_smoke tests.test_readme_contract tests.test_releasing_contract tests.test_compatibility -v`

Expected: FAIL because workflow and entrypoint have no runtime-root contract and docs describe the old intentional block.

- [ ] **Step 3: Implement workflow and documentation changes**

Add `PI_RUNTIME_ROOT: ${{ vars.PI_RUNTIME_ROOT }}` and the literal `PI_RELEASE_INTEGRATION: required` to `pi-release`. In preflight, require the latter exact value (missing or any other value fails), require a canonical absolute root-owned non-group/world-writable directory, recursively reject symlinks/special files/group/world-writable entries, require its exact `/proc`, `/dev`, `/tmp`, `/pi-smoke`, `/pi-proof`, and `/opt/pi-subagents` layout, and require the root-owned immutable `PI_EXECUTABLE` inside it. Require a private canonical output parent pairwise disjoint from runtime and smoke roots, and reject a pre-existing output destination. Verify a root-owned canonical `/usr/bin/python3.13` (or fixed resolved system equivalent) and invoke it directly; remove the release job's dependency bootstrap entirely. Run the exact Bubblewrap user/PID/network/IPC/capability preflight in the runner's owner-managed AppArmor context and fail on refusal, then run the unmocked `PiReleaseBackendIntegrationTests` under the exact required gate before the real smoke. Add a concurrency group of one for `pi-release`. Keep `PI_RELEASE_BACKEND` exactly `bubblewrap`. Do not add a network step, pip, Node download, npm command, secrets, Docker, macOS runner, provider job, or release matrix.

Replace old wrapper-unavailable wording in `docs/RELEASING.md` with the runner provisioning and evidence review procedure from the approved spec: exact Pi runtime provenance, Node >=22.19.0, reviewed extension tarball/tree, clean one-time private provisioning home, offline release Python 3.13, Bubblewrap user-namespace/AppArmor preflight, rootfs, read-only package overlay, schema-v2 evidence, and evidence deletion. State that the manual stage runs only on Linux with Python 3.13 and Bubblewrap; remove the obsolete macOS `sandbox-exec` alternative. Update README only to describe the offline manual evidence gate and separate network-consented user installation; retain `Pi (unreleased)` and `supported: false`. Do not modify the machine compatibility row or transition predicate.

- [ ] **Step 4: Run focused test to verify it passes**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.test_pi_provider_smoke tests.test_readme_contract tests.test_releasing_contract tests.test_compatibility -v`

Expected: PASS; missing runtime root fails before Pi selection, docs describe the real gate, and Pi remains unsupported.

- [ ] **Step 5: Run full verification and commit**

Run: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -q`

Run: `.venv/bin/python scripts/validate-catalogs.py`

Run: `.venv/bin/ruff check subagents_configs scripts tests`

Run: `.venv/bin/ruff format --check subagents_configs scripts tests`

Run: `.venv/bin/python -m compileall -q subagents_configs scripts tests`

Run: `sh -n ./*.sh`

Run: `shellcheck install.sh uninstall.sh install-codex.sh uninstall-codex.sh install-opencode.sh uninstall-opencode.sh install-claude-code.sh uninstall-claude-code.sh`

Run: `git diff --check`

Run: `git status --short`

Commit only `.github/workflows/ci.yml`, `README.md`, `docs/RELEASING.md`, `tests/test_ci.py`, `tests/test_pi_provider_smoke.py`, `tests/test_readme_contract.py`, `tests/test_releasing_contract.py`, and `tests/test_compatibility.py` with `ci: require verified Bubblewrap Pi release sandbox`.

Expected: all checks pass, the tree is clean before staging, and the commit does not transition Pi support.

### Task 5: Review, merge, prepare the runner, and perform the owner-only evidence run

**Files:**

- Modify: `docs/RELEASING.md` only if a reviewer identifies a factual omission in the documented runner procedure.

**Interfaces:**

- Consumes: merged Tasks 1–4 and the immutable Pi 0.84.1 runtime/package evidence prepared by the mandatory preflight.
- Produces: a reviewed, bounded `0600` release evidence file; it does not produce a support transition.

- [ ] **Step 1: Perform two independent code reviews**

Ask one reviewer to examine mounts, environment, executable/runtime identity, process cleanup, and evidence leakage. Ask another to examine runner labels, variables, actual Bubblewrap invocation, test coverage, and documentation. Give each the final diff and test commands; require categorized findings and no implementation changes.

- [ ] **Step 2: Address review findings with a fresh task-specific agent**

For every Critical or Important finding, write a failing regression test first, verify it fails, implement only that fix, re-run the focused suite, and obtain a follow-up review. Do not treat simulated evidence or a self-hashed record as release evidence.

- [ ] **Step 3: Create, verify, and merge the implementation PR**

Run Task 4 verification, push the branch, create a PR describing the offline-only scope and deliberate unsupported Pi status, wait for required CI, merge only when green, and verify the post-merge `main` pipeline is green.

- [ ] **Step 4: Prepare the dedicated runner from the verified transfer bundle**

After the merged code is available, on the separate disposable non-shared Linux
x64 runner, verify every digest in the mandatory-preflight transfer manifest;
do not acquire a package or contact the network. Install and verify root-owned
fixed Bubblewrap with unprivileged user namespaces, the required UID/GID
mapping, and an owner-managed AppArmor policy that permits this exact
invocation. The actual preflight must fail if that policy refuses it. Build the
immutable root-owned Pi 0.84.1/Node >=22.19.0 runtime closure solely from the
verified bundle and catalog-bound policy, including the checked package tree;
prepare a private `0700` smoke root containing the reviewed lock/settings
evidence, a root-owned Python 3.13 interpreter, and a private output parent.
Configure only `PI_EXECUTABLE`, `PI_RUNTIME_ROOT`, `PI_SMOKE_ROOT`,
`PI_RELEASE_EVIDENCE_OUTPUT`, and `PI_RELEASE_BACKEND=bubblewrap` as repository
variables; set literal workflow-only `PI_RELEASE_INTEGRATION=required`, never a
repository variable.

- [ ] **Step 5: Manually dispatch and review the offline evidence run**

Dispatch protected-main `workflow_dispatch` after quality passes. Confirm the release job emits a bounded `0600` schema-v2 record containing exact Pi/package hashes, runtime/package/Bubblewrap/proof commitments, repository commit, `backend: bubblewrap`, and `SANDBOX_VERIFIED`; inspect it for absence of secrets, paths, prompts, responses, and transcripts. Destroy the disposable smoke root and proof directory after review. Keep Pi unsupported until a separate owner-approved transition commit; do not run provider smoke in this task.
