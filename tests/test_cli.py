import tempfile
import unittest
from pathlib import Path

from subagents_configs.cli import parse_request
from subagents_configs.errors import CliError
from subagents_configs.models import Target
from subagents_configs.orchestrator import HELP_TEXT
from tests.helpers import environment


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.environ = environment(self.root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def assertInvalid(self, argv: list[str], operation: str = "install") -> None:
        with self.assertRaises(CliError):
            parse_request(operation, argv, self.environ)

    def test_requires_target(self):
        self.assertInvalid([])

    def test_all_expands_in_descriptor_order(self):
        request = parse_request("install", ["--all"], self.environ)
        self.assertEqual(
            request.targets,
            (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE),
        )

    def test_pi_is_explicit_but_not_in_all(self):
        request = parse_request(
            "install",
            [
                "--target",
                "pi",
                "--pi-executable",
                "/opt/pi",
                "--consent-third-party-code",
                "--consent-network",
            ],
            self.environ,
        )
        self.assertEqual(request.targets, (Target.PI,))

    def test_pi_home_uses_explicit_home_then_environment_then_default(self):
        request = parse_request(
            "install",
            [
                "--target",
                "pi",
                "--pi-executable",
                "/opt/pi",
                "--consent-third-party-code",
                "--consent-network",
            ],
            {**self.environ, "PI_CODING_AGENT_DIR": "/tmp/pi"},  # noqa: S108
        )
        self.assertEqual(request.homes[Target.PI], Path("/tmp/pi"))  # noqa: S108

    def test_pi_install_rejects_missing_consents_or_relative_executable(self):
        for argv in (
            ("--target", "pi", "--pi-executable", "/opt/pi"),
            ("--target", "pi", "--pi-executable", "~/pi", "--dry-run"),
            (
                "--target",
                "pi",
                "--pi-executable",
                "pi",
                "--consent-third-party-code",
                "--consent-network",
            ),
        ):
            with self.subTest(argv=argv):
                self.assertInvalid(list(argv))

    def test_pi_dry_run_does_not_require_or_record_consent(self):
        request = parse_request(
            "install",
            ["--target", "pi", "--pi-executable", "/opt/pi", "--dry-run"],
            self.environ,
        )
        self.assertEqual(request.targets, (Target.PI,))
        self.assertFalse(request.consent_third_party_code)
        self.assertFalse(request.consent_network)
        with_consents = parse_request(
            "install",
            [
                "--target",
                "pi",
                "--pi-executable",
                "/opt/pi",
                "--consent-third-party-code",
                "--consent-network",
                "--dry-run",
            ],
            self.environ,
        )
        self.assertFalse(with_consents.consent_third_party_code)
        self.assertFalse(with_consents.consent_network)

    def test_pi_only_flags_rejected_for_non_pi_targets(self):
        for option in (
            "--pi-executable",
            "--consent-third-party-code",
            "--consent-network",
            "--remove-pi-package",
        ):
            with self.subTest(option=option):
                argv = ["--target", "codex", option]
                if option == "--pi-executable":
                    argv.append("/opt/pi")
                self.assertInvalid(argv)

    def test_uninstall_rejects_pi_package_removal_without_pi(self):
        self.assertInvalid(["--target", "codex", "--remove-pi-package"], "uninstall")

    def test_pi_rejected_on_windows_before_settings_reads(self):
        with self.assertRaises(CliError):
            parse_request(
                "install",
                ["--target", "pi", "--pi-executable", "/opt/pi", "--dry-run"],
                self.environ,
                platform_name="win32",
            )

    def test_pi_uninstall_accepts_executable_only_with_package_removal(self):
        request = parse_request(
            "uninstall",
            [
                "--target",
                "pi",
                "--pi-executable",
                "/opt/pi",
                "--remove-pi-package",
            ],
            self.environ,
        )
        self.assertTrue(request.remove_pi_package)

    def test_help_lists_pi_options_by_operation(self):
        self.assertIn("--pi-executable", HELP_TEXT["install"])
        self.assertIn("--consent-network", HELP_TEXT["install"])
        self.assertNotIn("--remove-pi-package", HELP_TEXT["install"])
        self.assertIn("--pi-executable", HELP_TEXT["uninstall"])
        self.assertIn("--remove-pi-package", HELP_TEXT["uninstall"])

    def test_pi_ignores_poisoned_platform_environment(self):
        request = parse_request(
            "install",
            ["--target", "pi", "--pi-executable", "/opt/pi", "--dry-run"],
            {**self.environ, "platform_name": "win32"},
            platform_name="linux",
        )
        self.assertEqual(request.targets, (Target.PI,))

    def test_rejects_all_mixed_with_target(self):
        self.assertInvalid(["--all", "--target", "codex"])

    def test_rejects_repeated_target(self):
        self.assertInvalid(["--target", "codex", "--target", "codex"])

    def test_rejects_duplicate_home(self):
        self.assertInvalid(
            ["--target", "codex", "--home", "codex=/a", "--home", "codex=/b"]
        )

    def test_rejects_home_for_unselected_target(self):
        self.assertInvalid(["--target", "codex", "--home", "opencode=/tmp/o"])

    def test_rejects_unknown_option(self):
        self.assertInvalid(["--target", "codex", "--unknown"])

    def test_cli_home_overrides_environment(self):
        request = parse_request(
            "install",
            ["--target", "codex", "--home", "codex=~/explicit"],
            {**self.environ, "CODEX_HOME": "/from-env"},
        )
        self.assertEqual(request.homes[Target.CODEX], self.root / "explicit")

    def test_environment_home_overrides_default(self):
        request = parse_request(
            "install",
            ["--target", "codex"],
            {**self.environ, "CODEX_HOME": "/from-env"},
        )
        self.assertEqual(request.homes[Target.CODEX], Path("/from-env"))

    def test_codex_multi_agent_requires_codex(self):
        self.assertInvalid(["--target", "opencode", "--enable-codex-multi-agent"])

    def test_uninstall_rejects_install_only_options(self):
        for option in (
            "--enable-global-routing",
            "--enable-codex-multi-agent",
            "--include-commit-pusher",
        ):
            self.assertInvalid(["--target", "codex", option], "uninstall")


if __name__ == "__main__":
    unittest.main()
