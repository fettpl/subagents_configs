from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.run_pi_provider_smoke import (
    EXPECTED_RESPONSE,
    PROVIDER_CREDENTIALS,
    ProviderSmokeError,
    run_provider_smoke,
)


def _write_fake(
    path: Path,
    *,
    response: str = EXPECTED_RESPONSE,
    behavior: str = "normal",
    marker: Path | None = None,
) -> Path:
    expected_prompt = "PI provider compatibility check\n"
    marker_literal = repr(str(marker))
    descendant_code = f"import time; time.sleep(1); open({marker_literal}, 'w').close()"
    resistant_code = (
        "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"open({(str(marker) + '.ready')!r}, 'w').close(); "
        f"time.sleep(0.8); open({marker_literal}, 'w').close()"
    )
    path.write_text(
        f"#!{sys.executable}\n"
        "import json\n"
        "import os\n"
        "import sys\n"
        "import time\n"
        "if sys.argv[1:] == ['--offline', '--version']:\n"
        "    print('0.84.1', flush=True)\n"
        f"    if {behavior!r} == 'replace':\n"
        "        from pathlib import Path\n"
        "        Path(sys.argv[0]).write_text('#!/bin/sh\\nexit 99\\n')\n"
        "    raise SystemExit(0)\n"
        "if '--model' not in sys.argv or '--no-tools' not in sys.argv:\n"
        "    raise SystemExit(41)\n"
        "if os.environ.get('OPENAI_API_KEY') != 'synthetic-provider-key':\n"
        "    raise SystemExit(42)\n"
        "request = json.loads(sys.stdin.readline())\n"
        f"if request != {{'type': 'prompt', 'prompt': {expected_prompt!r}}}:\n"
        "    raise SystemExit(43)\n"
        f"if {behavior!r} == 'close-pipes':\n"
        "    os.close(sys.stdout.fileno())\n"
        "    os.close(sys.stderr.fileno())\n"
        "    time.sleep(3)\n"
        f"if {behavior!r} == 'descendant':\n"
        "    import subprocess\n"
        f"    subprocess.Popen([sys.executable, '-c', {descendant_code!r}])\n"
        "    os.close(sys.stdout.fileno())\n"
        "    os.close(sys.stderr.fileno())\n"
        "    time.sleep(3)\n"
        f"if {behavior!r} == 'leader-exits-term-resistant':\n"
        "    import signal\n"
        "    import subprocess\n"
        f"    resistant = {resistant_code!r}\n"
        "    subprocess.Popen([sys.executable, '-c', resistant])\n"
        f"    print(json.dumps({{'type': 'response', 'command': 'prompt', "
        f"'success': True, 'data': {{'text': {response!r}}}}}), flush=True)\n"
        "    time.sleep(0.5)\n"
        "    os.close(sys.stdout.fileno())\n"
        "    os.close(sys.stderr.fileno())\n"
        "    raise SystemExit(0)\n"
        f"if {behavior!r} == 'bad-rpc':\n"
        '    print(\'{"type":"response","type":"response"}\', flush=True)\n'
        "    raise SystemExit(0)\n"
        "print(json.dumps({"
        f"'type': 'response', 'command': 'prompt', 'success': True, "
        f"'data': {{'text': {response!r}}}"
        "}), flush=True)\n"
        f"if {behavior!r} == 'marker':\n"
        f"    open({marker_literal}, 'w').close()\n",
        encoding="utf-8",
    )
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return path


def _release_evidence() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "ok",
        "pi_version": "0.84.1",
        "pi_executable_sha256": "a" * 64,
        "package_source": "npm:pi-subagents@0.56.0",
        "package_version": "0.56.0",
        "package_policy_sha256": (
            "d0f902d54cda2f073215701b4c04a38480c29ef1a8a7f6e3d4981d70657e4722"
        ),
        "upstream_commit": "a0e2b9e31de5970215a567e20e2d781bbbddf235",
        "dist_integrity": (
            "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+"
            "W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
        ),
        "package_manifest_sha256": "b" * 64,
        "package_lock_sha256": "c" * 64,
        "platform": "linux",
        "backend": "bubblewrap",
        "smoke_evidence": [
            "PI_SMOKE_OK",
            "VALIDATOR_HELPER_EXECUTED",
            "BASH_REJECTED",
        ],
    }


class PiProviderSmokeTests(unittest.TestCase):
    def test_provider_rpc_request_and_response_keys_are_fixture_validated(self) -> None:
        contract = json.loads(
            (
                Path(__file__).parents[1]
                / "tests/fixtures/pi-0.84.1-runtime-contract.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            contract["rpc"]["provider_request"],
            {"type": "prompt", "prompt": "PI provider compatibility check\n"},
        )
        self.assertEqual(contract["rpc"]["provider_response_data_keys"], ["text"])

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

    def test_provider_smoke_uses_live_authorized_json_rpc_without_offline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-live-") as raw:
            root = Path(raw)
            executable = _write_fake(root / "pi")
            output = root / "result.json"
            observed = root / "argv-env.json"
            source = executable.read_text(encoding="utf-8")
            source = source.replace(
                "request = json.loads(sys.stdin.readline())",
                f"open({str(observed)!r}, 'w').write("
                "json.dumps({'argv': sys.argv[1:], 'env': dict(os.environ)}))\n"
                "request = json.loads(sys.stdin.readline())",
            )
            executable.write_text(source, encoding="utf-8")
            executable.chmod(0o700)
            with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-provider-key"}):
                result = run_provider_smoke(
                    executable,
                    "openai/gpt-test",
                    output,
                    authorize_provider_smoke=True,
                    interactive=True,
                )
            observed_data = __import__("json").loads(observed.read_text())
            self.assertNotIn("--offline", observed_data["argv"])
            contract = json.loads(
                (
                    Path(__file__).parents[1]
                    / "tests/fixtures/pi-0.84.1-runtime-contract.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                tuple(observed_data["argv"]),
                tuple(
                    "openai/gpt-test" if argument == "<MODEL>" else argument
                    for argument in contract["rpc"]["provider_argv"]
                ),
            )
            self.assertTrue(
                set(observed_data["env"]).issubset(
                    {
                        "PATH",
                        "PI_SKIP_VERSION_CHECK",
                        "PI_TELEMETRY",
                        "OPENAI_API_KEY",
                        "LC_CTYPE",
                        "__CF_USER_TEXT_ENCODING",
                    }
                )
            )
            self.assertTrue(
                {
                    "PATH",
                    "PI_SKIP_VERSION_CHECK",
                    "PI_TELEMETRY",
                    "OPENAI_API_KEY",
                }.issubset(observed_data["env"])
            )
            self.assertEqual(result["status"], "ok")

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

    def test_invalid_credential_mapping_fails_before_executable_start(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-credential-") as raw:
            root = Path(raw)
            executable = _write_fake(root / "pi")
            with self.assertRaisesRegex(ProviderSmokeError, "CREDENTIAL_INVALID"):
                run_provider_smoke(
                    executable,
                    "openai/gpt-test",
                    root / "result.json",
                    authorize_provider_smoke=True,
                    environ={"OPENAI_API_KEY": 42},  # type: ignore[dict-item]
                    interactive=True,
                )
            self.assertFalse((root / "result.json").exists())
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
                public.chmod(0o755)
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

    def test_eof_child_is_killed_at_deadline_and_descendants_do_not_survive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-timeout-") as raw:
            root = Path(raw)
            with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-provider-key"}):
                close_pipes = _write_fake(root / "close-pipes", behavior="close-pipes")
                started = time.monotonic()
                with patch("scripts.run_pi_provider_smoke._TIMEOUT_SECONDS", 0.2):
                    with self.assertRaisesRegex(ProviderSmokeError, "PI_TIMEOUT"):
                        run_provider_smoke(
                            close_pipes,
                            "openai/gpt-test",
                            root / "closed.json",
                            authorize_provider_smoke=True,
                            interactive=True,
                        )
                self.assertLess(time.monotonic() - started, 2)
                marker = root / "descendant-marker"
                descendant = _write_fake(
                    root / "descendant", behavior="descendant", marker=marker
                )
                with patch("scripts.run_pi_provider_smoke._TIMEOUT_SECONDS", 0.2):
                    with self.assertRaisesRegex(ProviderSmokeError, "PI_TIMEOUT"):
                        run_provider_smoke(
                            descendant,
                            "openai/gpt-test",
                            root / "descendant.json",
                            authorize_provider_smoke=True,
                            interactive=True,
                        )
                time.sleep(1.2)
                self.assertFalse(marker.exists())

    def test_term_resistant_descendant_is_killed_after_leader_exits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-term-resistant-") as raw:
            root = Path(raw)
            marker = root / "term-resistant-marker"
            executable = _write_fake(
                root / "pi",
                behavior="leader-exits-term-resistant",
                marker=marker,
            )
            with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-provider-key"}):
                with patch("scripts.run_pi_provider_smoke._TIMEOUT_SECONDS", 0.8):
                    with self.assertRaisesRegex(ProviderSmokeError, "PI_TIMEOUT"):
                        run_provider_smoke(
                            executable,
                            "openai/gpt-test",
                            root / "result.json",
                            authorize_provider_smoke=True,
                            interactive=True,
                        )
            self.assertTrue((root / "term-resistant-marker.ready").exists())
            time.sleep(1.4)
            self.assertFalse(marker.exists())

    def test_executable_identity_rejects_writable_and_replaced_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-identity-") as raw:
            root = Path(raw)
            writable = _write_fake(root / "writable")
            writable.chmod(0o702)
            with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-provider-key"}):
                with self.assertRaisesRegex(
                    ProviderSmokeError, "PI_EXECUTABLE_IDENTITY_UNSAFE"
                ):
                    run_provider_smoke(
                        writable,
                        "openai/gpt-test",
                        root / "writable.json",
                        authorize_provider_smoke=True,
                        interactive=True,
                    )
                replaced = _write_fake(root / "replaced", behavior="replace")
                with self.assertRaisesRegex(
                    ProviderSmokeError, "PI_EXECUTABLE_CHANGED"
                ):
                    run_provider_smoke(
                        replaced,
                        "openai/gpt-test",
                        root / "replaced.json",
                        authorize_provider_smoke=True,
                        interactive=True,
                    )

    def test_output_publish_rejects_symlink_and_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-output-") as raw:
            root = Path(raw)
            executable = _write_fake(root / "pi")
            victim = root / "victim"
            victim.write_text("keep", encoding="utf-8")
            output_link = root / "link.json"
            output_link.symlink_to(victim)
            with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-provider-key"}):
                with self.assertRaisesRegex(ProviderSmokeError, "OUTPUT_NOT_PRIVATE"):
                    run_provider_smoke(
                        executable,
                        "openai/gpt-test",
                        output_link,
                        authorize_provider_smoke=True,
                        interactive=True,
                    )
                output = root / "result.json"
                output.write_text("keep", encoding="utf-8")
                output.chmod(0o600)
                with self.assertRaisesRegex(
                    ProviderSmokeError, "OUTPUT_ALREADY_EXISTS"
                ):
                    run_provider_smoke(
                        executable,
                        "openai/gpt-test",
                        output,
                        authorize_provider_smoke=True,
                        interactive=True,
                    )

    def test_provider_response_must_match_reviewed_json_rpc_fixture(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-rpc-") as raw:
            root = Path(raw)
            executable = _write_fake(root / "pi", behavior="bad-rpc")
            with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-provider-key"}):
                with self.assertRaisesRegex(ProviderSmokeError, "RPC_INVALID"):
                    run_provider_smoke(
                        executable,
                        "openai/gpt-test",
                        root / "result.json",
                        authorize_provider_smoke=True,
                        interactive=True,
                    )
            self.assertFalse((root / "result.json").exists())

    def test_model_identifier_is_bounded_before_provider_start(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pi-provider-model-") as raw:
            root = Path(raw)
            executable = _write_fake(root / "pi")
            with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-provider-key"}):
                with self.assertRaisesRegex(ProviderSmokeError, "MODEL_INVALID"):
                    run_provider_smoke(
                        executable,
                        "openai/" + "x" * 256,
                        root / "result.json",
                        authorize_provider_smoke=True,
                        interactive=True,
                    )

    def test_public_hyphenated_entrypoint_is_present(self) -> None:
        self.assertTrue(
            Path(__file__)
            .parents[1]
            .joinpath("scripts/run-pi-provider-smoke.py")
            .is_file()
        )

    def test_public_entrypoint_resolves_repository_imports_when_run_directly(
        self,
    ) -> None:
        script = Path(__file__).parents[1] / "scripts/run-pi-provider-smoke.py"
        result = subprocess.run(  # noqa: S603 - fixed repository script and argv
            [sys.executable, str(script), "--help"],
            cwd=Path("/"),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

    def test_public_entrypoint_is_directly_executable(self) -> None:
        script = Path(__file__).parents[1] / "scripts/run-pi-provider-smoke.py"
        result = subprocess.run(  # noqa: S603 - fixed repository script and argv
            [str(script), "--help"],
            cwd=Path("/"),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")

    def test_release_entrypoint_requests_release_selector_and_package_proof(
        self,
    ) -> None:
        script = Path(__file__).parents[1] / "scripts/run-pi-release-smoke.py"
        spec = importlib.util.spec_from_file_location("pi_release_smoke", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        evidence = SimpleNamespace(status="ok", version="0.84.1")
        with tempfile.TemporaryDirectory(prefix="pi-release-selector-") as raw:
            output = Path(raw) / "release-evidence.json"
            with patch.dict(
                os.environ,
                {
                    "PI_EXECUTABLE": "/private/var/pi-0.84.1",
                    "PI_SMOKE_ROOT": "/private/var/pi-release-root",
                    "PI_RELEASE_EVIDENCE_OUTPUT": str(output),
                    "PI_RELEASE_BACKEND": "bubblewrap",
                },
                clear=True,
            ):
                with (
                    patch.object(
                        module,
                        "select_pi_executable",
                        return_value=evidence,
                    ) as selector,
                    patch.object(
                        module,
                        "build_release_evidence",
                        return_value=_release_evidence(),
                    ),
                ):
                    self.assertEqual(module.main(), 0)
        selector.assert_called_once_with(
            Path("/private/var/pi-0.84.1"),
            Path("/private/var/pi-release-root"),
            release=True,
        )

    def test_release_entrypoint_records_complete_safe_evidence(self) -> None:
        script = Path(__file__).parents[1] / "scripts/run-pi-release-smoke.py"
        spec = importlib.util.spec_from_file_location("pi_release_evidence", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        evidence = _release_evidence()
        with tempfile.TemporaryDirectory(prefix="pi-release-evidence-") as raw:
            root = Path(raw)
            output = root / "release-evidence.json"
            with patch.dict(
                os.environ,
                {
                    "PI_EXECUTABLE": "/private/var/pi-0.84.1",
                    "PI_SMOKE_ROOT": "/private/var/pi-release-root",
                    "PI_RELEASE_EVIDENCE_OUTPUT": str(output),
                    "PI_RELEASE_BACKEND": "bubblewrap",
                },
                clear=True,
            ):
                with (
                    patch.object(
                        module,
                        "select_pi_executable",
                        return_value=SimpleNamespace(status="ok", version="0.84.1"),
                    ),
                    patch.object(
                        module, "build_release_evidence", return_value=evidence
                    ),
                ):
                    self.assertEqual(module.main(), 0)
            recorded = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(recorded, evidence)
            self.assertEqual(set(recorded), set(evidence))
            self.assertNotIn("PI_EXECUTABLE", recorded)
            self.assertNotIn("PI_SMOKE_ROOT", recorded)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_release_entrypoint_resolves_repository_imports_when_run_directly(
        self,
    ) -> None:
        script = Path(__file__).parents[1] / "scripts/run-pi-release-smoke.py"
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(  # noqa: S603 - fixed repository script and argv
            [sys.executable, str(script)],
            cwd=Path("/"),
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "PI_EXECUTABLE_UNAVAILABLE\n")
        self.assertEqual(result.stderr, "")


class PiProviderSmokeStaticTests(unittest.TestCase):
    def test_provider_allowlist_contains_only_credential_names(self) -> None:
        self.assertTrue(PROVIDER_CREDENTIALS)
        for provider, variables in PROVIDER_CREDENTIALS.items():
            self.assertRegex(provider, r"^[a-z0-9-]+$")
            for variable in variables:
                self.assertRegex(variable, r"^[A-Z][A-Z0-9_]+$")


if __name__ == "__main__":
    unittest.main()
