import tempfile
import unittest
from pathlib import Path

from subagents_configs.cli import parse_request
from subagents_configs.errors import CliError
from subagents_configs.models import Target
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
