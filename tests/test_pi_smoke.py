"""Offline Pi smoke contracts and release-only selection tests."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tests.pi_smoke_support import (
    EXPECTED_CLI_ARGS,
    PiSmokeEvidence,
    _bounded_process,
    _safe_state,
    load_runtime_contract,
    run_pi_smoke,
    select_pi_executable,
)

ROOT = Path(__file__).resolve().parents[1]
_UNSET = object()


def _write_fake_pi(
    path: Path,
    *,
    version: str = "0.84.1",
    response_type: str = "response",
    extensions: list[str] | None = None,
    package_tools: object = _UNSET,
    include_pusher: bool = False,
) -> Path:
    agents = [
        "code-explorer",
        "code-reviewer",
        "code-validator",
        "quick-implementer",
        "implementer",
    ]
    if include_pusher:
        agents.append("commit-pusher")
    tools = {
        "code-explorer": ["read", "grep", "find", "ls"],
        "code-reviewer": ["read", "grep", "find", "ls"],
        "code-validator": ["read", "grep", "find", "ls", "run_validation"],
        "quick-implementer": ["read", "grep", "find", "ls", "write", "edit", "bash"],
        "implementer": ["read", "grep", "find", "ls", "write", "edit", "bash"],
    }
    if include_pusher:
        tools["commit-pusher"] = ["read", "grep", "find", "ls", "bash"]
    extension_list = (
        ["subagents-configs-run-validation.ts"] if extensions is None else extensions
    )
    package_fragment = (
        "" if package_tools is _UNSET else f', "package_tools": {package_tools!r}'
    )
    script = f"""#!{sys.executable}
import json
import os
import sys

if sys.argv[1:] == ["--offline", "--version"]:
    print({version!r}, flush=True)
    raise SystemExit(0)
if sys.argv[1:] != {list(EXPECTED_CLI_ARGS)!r}:
    raise SystemExit(41)
line = sys.stdin.readline()
if json.loads(line) != {{"type": "get_state"}}:
    raise SystemExit(42)
print(json.dumps({{
    "type": {response_type!r},
    "command": "get_state",
    "success": True,
    "data": {{
        "model": None, "thinkingLevel": "medium", "isStreaming": False,
        "isCompacting": False, "steeringMode": "all",
        "followUpMode": "one-at-a-time", "sessionFile": None,
        "sessionId": "redacted", "autoCompactionEnabled": True,
        "messageCount": 0, "pendingMessageCount": 0,
        "version": {version!r}, "agents": {agents!r},
        "extensions": {extension_list!r}, "tools": {tools!r}{package_fragment}
    }}
}}), flush=True)
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o700)
    return path


class PiSmokeContractTests(unittest.TestCase):
    def test_reviewed_fixture_pins_safe_rpc_and_limits(self):
        contract = load_runtime_contract()
        self.assertEqual(contract["pi_version"], "0.84.1")
        self.assertEqual(tuple(contract["cli"]["argv"]), EXPECTED_CLI_ARGS)
        self.assertEqual(contract["rpc"]["request"], {"type": "get_state"})
        self.assertEqual(contract["rpc"]["framing"], "lf-delimited-json")
        self.assertEqual(
            contract["limits"], {"timeout_seconds": 30, "stream_bytes": 8192}
        )

    def test_run_pi_smoke_uses_private_roots_and_redacted_bounded_evidence(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-contract-") as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(root / "pi")
            evidence = run_pi_smoke(executable, root)
            self.assertIsInstance(evidence, PiSmokeEvidence)
            self.assertEqual(evidence.status, "ok")
            self.assertEqual(evidence.version, "0.84.1")
            self.assertEqual(
                evidence.managed_roles,
                (
                    "code-explorer",
                    "code-reviewer",
                    "code-validator",
                    "quick-implementer",
                    "implementer",
                ),
            )
            self.assertEqual(
                evidence.bundled_roles,
                (
                    "delegate",
                    "oracle",
                    "researcher",
                    "reviewer",
                    "scout",
                    "worker",
                ),
            )
            for name in ("agent", "project", "tmp"):
                self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o700)
            self.assertIn("PI_SMOKE_OK", evidence.evidence)
            self.assertNotIn(str(root), repr(evidence))
            self.assertNotIn("pi-subagents@0.56.0", repr(evidence))
            self.assertIn("VALIDATOR_HELPER_EXECUTED", evidence.evidence)
            self.assertIn("BASH_REJECTED", evidence.evidence)

    def test_smoke_environment_is_minimal_and_no_credentials_are_forwarded(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-env-") as temporary:
            root = Path(temporary)
            log = root / "tmp/env.json"
            executable = _write_fake_pi(root / "pi")
            source = executable.read_text(encoding="utf-8")
            source = source.replace(
                "line = sys.stdin.readline()",
                'Path = __import__("pathlib").Path\n'
                f"Path({str(log)!r}).write_text(json.dumps(dict(os.environ)))\n"
                "line = sys.stdin.readline()",
            )
            executable.write_text(source, encoding="utf-8")
            executable.chmod(0o700)
            os.environ["PI_SMOKE_TEST_SECRET"] = "must-not-forward"  # noqa: S105
            try:
                run_pi_smoke(executable, root)
            finally:
                os.environ.pop("PI_SMOKE_TEST_SECRET", None)
            observed = json.loads(log.read_text(encoding="utf-8"))
            self.assertTrue(
                set(observed).issubset(
                    {
                        "HOME",
                        "PI_CODING_AGENT_DIR",
                        "PI_OFFLINE",
                        "PI_SKIP_VERSION_CHECK",
                        "PI_TELEMETRY",
                        "TMPDIR",
                        # Python may synthesize these locale values at startup.
                        "LC_CTYPE",
                        "__CF_USER_TEXT_ENCODING",
                    }
                )
            )
            self.assertNotIn("PI_SMOKE_TEST_SECRET", observed)

    def test_stream_overflow_terminates_the_child_at_the_bound(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-stream-") as temporary:
            root = Path(temporary)
            executable = root / "flood"
            executable.write_text(
                f"#!{sys.executable}\n"
                "import sys, time\n"
                "sys.stdout.write('x' * 9000)\n"
                "sys.stdout.flush()\n"
                "time.sleep(2)\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            started = time.monotonic()
            code, stdout, _stderr = _bounded_process(
                (str(executable),),
                b"",
                cwd=root,
                env={"HOME": str(root)},
            )
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.5)
            self.assertNotEqual(code, 0)
            self.assertLessEqual(len(stdout), 8192)

    def test_direct_state_frame_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-rpc-") as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(root / "pi", response_type="state")
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, root)

    def test_missing_reviewed_response_data_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-rpc-data-") as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(root / "pi")
            source = executable.read_text(encoding="utf-8")
            source = source.replace('"model": None, ', "")
            executable.write_text(source, encoding="utf-8")
            executable.chmod(0o700)
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, root)

    def test_malformed_response_data_types_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-rpc-types-") as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(root / "pi")
            source = executable.read_text(encoding="utf-8")
            source = source.replace('"isStreaming": False', '"isStreaming": "false"')
            executable.write_text(source, encoding="utf-8")
            executable.chmod(0o700)
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, root)

    def test_duplicate_json_response_keys_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-rpc-duplicate-") as temporary:
            with self.assertRaises(ValueError):
                _safe_state(
                    b'{"type":"response","type":"response"}\n',
                    Path(temporary),
                    "0.84.1",
                )

    def test_ambient_extension_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-extension-") as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(
                root / "pi",
                extensions=["subagents-configs-run-validation.ts", "ambient.ts"],
            )
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, root)

    def test_symlinked_extension_directory_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory(
            prefix="pi-smoke-extension-link-"
        ) as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(root / "pi")
            agent = root / "agent"
            agent.mkdir(mode=0o700)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            (agent / "extensions").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, root)
            self.assertFalse((outside / "subagents-configs-run-validation.ts").exists())

    def test_malformed_package_tools_are_rejected(self):
        malformed = (None, [], {"delegate": "bash"}, {"delegate": ["read", 1]})
        for payload in malformed:
            with self.subTest(payload=payload):
                with tempfile.TemporaryDirectory(
                    prefix="pi-smoke-package-tools-"
                ) as temporary:
                    root = Path(temporary)
                    executable = _write_fake_pi(root / "pi", package_tools=payload)
                    with self.assertRaises(ValueError):
                        run_pi_smoke(executable, root)

    def test_optional_commit_pusher_uses_pusher_tools(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-pusher-") as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(root / "pi", include_pusher=True)
            evidence = run_pi_smoke(executable, root)
            self.assertEqual(evidence.optional_roles, ("commit-pusher",))

    def test_selector_with_executable_requires_disposable_root(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-selector-") as temporary:
            executable = _write_fake_pi(Path(temporary) / "pi")
            with self.assertRaises(ValueError):
                select_pi_executable(executable)

    def test_root_ancestor_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-ancestor-") as temporary:
            parent = Path(temporary) / "real"
            parent.mkdir(mode=0o700)
            link = Path(temporary) / "link"
            link.symlink_to(parent, target_is_directory=True)
            executable = _write_fake_pi(parent / "pi")
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, link / "root")

    def test_selector_emits_explicit_unavailable_evidence(self):
        evidence = select_pi_executable(None)
        print(evidence.evidence[0])
        self.assertEqual(evidence.evidence, ("PI_EXECUTABLE_UNAVAILABLE",))


class PiSmokeTests(unittest.TestCase):
    def test_selector_reports_explicit_unavailable(self):
        evidence = select_pi_executable(None)
        print(evidence.evidence[0])
        self.assertEqual(evidence.status, "PI_EXECUTABLE_UNAVAILABLE")
        self.assertIn("PI_EXECUTABLE_UNAVAILABLE", evidence.evidence)


class PiReleaseSmokeTests(unittest.TestCase):
    @staticmethod
    def _write_exact_package(agent: Path) -> None:
        package = agent / "npm/node_modules/pi-subagents"
        package.mkdir(mode=0o700, parents=True)
        (agent / "npm").chmod(0o700)
        (agent / "npm/node_modules").chmod(0o700)
        shutil.copyfile(
            ROOT / "tests/fixtures/pi-subagents-0.56.0-package.json",
            package / "package.json",
        )
        (package / "package.json").chmod(0o600)
        lock = {
            "name": "pi-subagents",
            "version": "0.56.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"pi-subagents": "0.56.0"}},
                "node_modules/pi-subagents": {
                    "version": "0.56.0",
                    "integrity": (
                        "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+"
                        "W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
                    ),
                },
            },
        }
        (agent / "npm/package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
        (agent / "npm/package-lock.json").chmod(0o600)
        (agent / "settings.json").write_text(
            json.dumps({"packages": ["npm:pi-subagents@0.56.0"]}), encoding="utf-8"
        )
        (agent / "settings.json").chmod(0o600)

    def test_release_selector_rejects_missing_executable(self):
        with self.assertRaises(ValueError):
            select_pi_executable(None, release=True)

    def test_release_selector_rejects_wrong_version(self):
        with tempfile.TemporaryDirectory(prefix="pi-release-contract-") as temporary:
            executable = _write_fake_pi(Path(temporary) / "pi", version="0.84.0")
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, Path(temporary), release=True)

    def test_release_rejects_absent_installed_package(self):
        with tempfile.TemporaryDirectory(prefix="pi-release-no-package-") as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(root / "pi")
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, root, release=True)

    def test_release_requires_exact_installed_package_evidence(self):
        with tempfile.TemporaryDirectory(prefix="pi-release-package-") as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(root / "pi")
            (root / "agent").mkdir(mode=0o700)
            self._write_exact_package(root / "agent")
            evidence = run_pi_smoke(executable, root, release=True)
            self.assertEqual(evidence.package_status, "exact")

    def test_unreviewed_effective_tool_role_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-tools-") as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(root / "pi")
            source = executable.read_text(encoding="utf-8")
            source = source.replace(
                "'implementer': ['read', 'grep', 'find', 'ls', 'write', 'edit', "
                "'bash']",
                "'implementer': ['read', 'grep', 'find', 'ls', 'write', 'edit', "
                "'bash'],\n"
                "        'ambient': ['bash']",
            )
            executable.write_text(source, encoding="utf-8")
            executable.chmod(0o700)
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, root)

    def test_missing_effective_extension_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pi-smoke-no-extension-") as temporary:
            root = Path(temporary)
            executable = _write_fake_pi(root / "pi", extensions=[])
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, root)


if __name__ == "__main__":
    unittest.main()
