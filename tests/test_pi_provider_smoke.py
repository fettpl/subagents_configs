from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.run_pi_provider_smoke import (
    EXPECTED_RESPONSE,
    PROVIDER_CREDENTIALS,
    ProviderSmokeError,
    run_provider_smoke,
)


def _write_fake(path: Path, *, response: str = EXPECTED_RESPONSE) -> Path:
    expected_prompt = "PI provider compatibility check\n"
    path.write_text(
        f"#!{sys.executable}\n"
        "import json\n"
        "import os\n"
        "import sys\n"
        "if sys.argv[1:] == ['--offline', '--version']:\n"
        "    print('0.84.1', flush=True)\n"
        "    raise SystemExit(0)\n"
        "if '--model' not in sys.argv or '--no-tools' not in sys.argv:\n"
        "    raise SystemExit(41)\n"
        "if os.environ.get('OPENAI_API_KEY') != 'synthetic-provider-key':\n"
        "    raise SystemExit(42)\n"
        "prompt = sys.stdin.read()\n"
        f"if prompt != {expected_prompt!r}:\n"
        "    raise SystemExit(43)\n"
        f"print({response!r}, end='', flush=True)\n",
        encoding="utf-8",
    )
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return path


class PiProviderSmokeTests(unittest.TestCase):
    def test_authorized_fake_smoke_writes_only_safe_bounded_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-smoke-") as raw:
            root = Path(raw)
            executable = _write_fake(root / "pi")
            output = root / "result.json"
            with patch.dict(
                os.environ,
                {"OPENAI_API_KEY": "synthetic-provider-key", "UNRELATED": "secret"},
                clear=False,
            ):
                result = run_provider_smoke(
                    executable,
                    "openai/gpt-test",
                    output,
                    authorize_provider_smoke=True,
                    interactive=True,
                )
            self.assertEqual(result["status"], "ok")
            self.assertTrue(result["response_hash_match"])
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["pi_version"], "0.84.1")
            self.assertEqual(result["package_source"], "npm:pi-subagents@0.56.0")
            self.assertEqual(
                set(result),
                {
                    "schema_version",
                    "pi_version",
                    "package_source",
                    "model",
                    "started_at",
                    "ended_at",
                    "status",
                    "exit_code",
                    "response_hash_match",
                },
            )
            self.assertNotIn("PI provider compatibility check", output.read_text())
            self.assertNotIn("synthetic-provider-key", output.read_text())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_missing_authorization_fails_before_starting_executable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-auth-") as raw:
            root = Path(raw)
            executable = _write_fake(root / "pi")
            with self.assertRaisesRegex(ProviderSmokeError, "AUTHORIZATION_REQUIRED"):
                run_provider_smoke(
                    executable,
                    "openai/gpt-test",
                    root / "result.json",
                    interactive=True,
                )

    def test_unknown_provider_and_missing_credential_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-provider-") as raw:
            root = Path(raw)
            executable = _write_fake(root / "pi")
            with self.assertRaisesRegex(ProviderSmokeError, "PROVIDER_NOT_REVIEWED"):
                run_provider_smoke(
                    executable,
                    "unknown/model",
                    root / "result.json",
                    authorize_provider_smoke=True,
                    interactive=True,
                )
            with (
                patch.dict(os.environ, {}, clear=True),
                self.assertRaisesRegex(ProviderSmokeError, "CREDENTIAL_MISSING"),
            ):
                run_provider_smoke(
                    executable,
                    "openai/gpt-test",
                    root / "result.json",
                    authorize_provider_smoke=True,
                    interactive=True,
                )

    def test_noninteractive_and_nonprivate_output_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-path-") as raw:
            root = Path(raw)
            executable = _write_fake(root / "pi")
            with self.assertRaisesRegex(ProviderSmokeError, "INTERACTIVE_REQUIRED"):
                run_provider_smoke(
                    executable,
                    "openai/gpt-test",
                    root / "result.json",
                    authorize_provider_smoke=True,
                    interactive=False,
                )
            with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-provider-key"}):
                public = root / "public"
                public.mkdir(mode=0o755)
                with self.assertRaisesRegex(ProviderSmokeError, "OUTPUT_NOT_PRIVATE"):
                    run_provider_smoke(
                        executable,
                        "openai/gpt-test",
                        public / "result.json",
                        authorize_provider_smoke=True,
                        interactive=True,
                    )

    def test_wrong_pi_version_and_unexpected_response_are_failures(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-failure-") as raw:
            root = Path(raw)
            wrong = root / "wrong"
            wrong.write_text(f"#!{sys.executable}\nprint('0.84.0')\n", encoding="utf-8")
            wrong.chmod(0o700)
            with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-provider-key"}):
                with self.assertRaisesRegex(ProviderSmokeError, "PI_VERSION_MISMATCH"):
                    run_provider_smoke(
                        wrong,
                        "openai/gpt-test",
                        root / "wrong.json",
                        authorize_provider_smoke=True,
                        interactive=True,
                    )
                executable = _write_fake(root / "pi", response="not-the-answer")
                result = run_provider_smoke(
                    executable,
                    "openai/gpt-test",
                    root / "mismatch.json",
                    authorize_provider_smoke=True,
                    interactive=True,
                )
            self.assertEqual(result["status"], "response_mismatch")
            self.assertFalse(result["response_hash_match"])
            self.assertEqual(result["exit_code"], 0)


class PiProviderSmokeStaticTests(unittest.TestCase):
    def test_provider_allowlist_contains_only_credential_names(self) -> None:
        self.assertTrue(PROVIDER_CREDENTIALS)
        for provider, variables in PROVIDER_CREDENTIALS.items():
            self.assertRegex(provider, r"^[a-z0-9-]+$")
            for variable in variables:
                self.assertRegex(variable, r"^[A-Z][A-Z0-9_]+$")


if __name__ == "__main__":
    unittest.main()
