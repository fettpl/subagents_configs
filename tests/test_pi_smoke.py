"""Offline Pi smoke contracts and release-only selection tests."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from tests.pi_smoke_support import (
    EXPECTED_CLI_ARGS,
    PiSmokeEvidence,
    load_runtime_contract,
    run_pi_smoke,
    select_pi_executable,
)

ROOT = Path(__file__).resolve().parents[1]


def _write_fake_pi(path: Path, *, version: str = "0.84.1") -> Path:
    script = f"""#!{sys.executable}
import json
import os
import sys

if sys.argv[1:] != {list(EXPECTED_CLI_ARGS)!r}:
    raise SystemExit(41)
line = sys.stdin.readline()
if json.loads(line) != {{"type": "get_state"}}:
    raise SystemExit(42)
print(json.dumps({{
    "type": "state",
    "version": {version!r},
    "agents": ["code-explorer", "code-reviewer", "code-validator", "quick-implementer",
               "implementer"],
    "extensions": ["subagents-configs-run-validation.ts"],
    "tools": {{
        "code-explorer": ["read", "grep", "find", "ls"],
        "code-reviewer": ["read", "grep", "find", "ls"],
        "code-validator": ["read", "grep", "find", "ls", "run_validation"],
        "quick-implementer": ["read", "grep", "find", "ls", "write", "edit", "bash"],
        "implementer": ["read", "grep", "find", "ls", "write", "edit", "bash"]
    }},
    "packages": ["pi-subagents@0.56.0"]
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


class PiSmokeTests(unittest.TestCase):
    def test_selector_reports_explicit_unavailable(self):
        evidence = select_pi_executable(None)
        self.assertEqual(evidence.status, "PI_EXECUTABLE_UNAVAILABLE")
        self.assertIn("PI_EXECUTABLE_UNAVAILABLE", evidence.evidence)


class PiReleaseSmokeTests(unittest.TestCase):
    def test_release_selector_rejects_missing_executable(self):
        with self.assertRaises(ValueError):
            select_pi_executable(None, release=True)

    def test_release_selector_rejects_wrong_version(self):
        with tempfile.TemporaryDirectory(prefix="pi-release-contract-") as temporary:
            executable = _write_fake_pi(Path(temporary) / "pi", version="0.84.0")
            with self.assertRaises(ValueError):
                run_pi_smoke(executable, Path(temporary), release=True)


if __name__ == "__main__":
    unittest.main()
