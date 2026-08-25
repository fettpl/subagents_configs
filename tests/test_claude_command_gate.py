import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from subagents_configs.formats import validate_source_inventory
from subagents_configs.models import SourceSpec, Target
from subagents_configs.planning import preflight_install
from subagents_configs.state import load_manifest
from subagents_configs.targets import descriptor_for
from subagents_configs.transaction import apply_transaction
from tests.helpers import planning_repository, planning_request, private_tempdir

ROOT = Path(__file__).resolve().parents[1]
HOOK_PATH = ROOT / "claude-code/hooks/code-validator-pretooluse.py"


def _hook_module():
    spec = importlib.util.spec_from_file_location("claude_command_gate", HOOK_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load command gate")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ClaudeCommandGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hook = _hook_module()

    def _event(self, command):
        return json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": command}}
        ).encode()

    def test_parser_accepts_only_bash_command_events(self):
        event = self.hook.parse_pretooluse_event(
            self._event("python3 /abs/helper -- unittest tests/test_x.py")
        )
        self.assertEqual(event.tool_name, "Bash")
        self.assertEqual(
            event.command, "python3 /abs/helper -- unittest tests/test_x.py"
        )

    def test_parser_rejects_unknown_keys_duplicate_keys_and_invalid_utf8(self):
        for raw in (
            b'{"tool_name":"Bash","tool_input":{"command":"x"},"extra":1}',
            b'{"tool_name":"Bash","tool_input":{"command":"x","extra":1}}',
            b'{"tool_name":"Bash","tool_name":"Bash","tool_input":{"command":"x"}}',
            b"\xff",
            self._event("python3 /abs/helper -- unittest\ntests/test_x.py"),
            self._event("python3 /abs/helper -- unittest\x00tests/test_x.py"),
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    self.hook.parse_pretooluse_event(raw)

    def test_validator_command_returns_fixed_argv_for_safe_data(self):
        self.assertEqual(
            self.hook.validate_validator_command(
                "python3 /abs/helper -- unittest tests/test_x.py", "/abs/helper"
            ),
            ("python3", "/abs/helper", "--", "unittest", "tests/test_x.py"),
        )

    def test_validator_command_rejects_shell_authority_and_unsafe_paths(self):
        commands = (
            "bash -c 'touch x'",
            "python3 /abs/helper",
            "python3 /abs/helper --; touch x",
            "python3 /abs/helper -- >x",
            "env X=1 python3 /abs/helper -- unittest tests/test_x.py",
            "python3 /abs/helper -- ../../secret",
            "python3 /abs/../helper -- unittest tests/test_x.py",
            "python3 /abs/helper -- $(touch x)",
            "python3 /abs/helper -- unittest\ntests/test_x.py",
        )
        for command in commands:
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    self.hook.validate_validator_command(command, "/abs/helper")

    def test_hook_main_never_executes_and_returns_bounded_status(self):
        valid = self._event(
            f"python3 {self.hook.VALIDATION_HELPER} -- unittest tests/test_x.py"
        )
        with patch.object(self.hook, "subprocess", create=True) as subprocess:
            stdout, stderr = io.StringIO(), io.StringIO()
            self.assertEqual(self.hook.hook_main(io.BytesIO(valid), stdout, stderr), 0)
            subprocess.assert_not_called()
        stdout, stderr = io.StringIO(), io.StringIO()
        self.assertEqual(
            self.hook.hook_main(io.BytesIO(self._event("bash -c id")), stdout, stderr),
            2,
        )
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "validation command denied\n")

    def test_claude_catalog_rejects_bash_allow_without_gate(self):
        source = ROOT / "claude-code/agents/code-validator.md"
        content = source.read_bytes().replace(b"only through", b"directly through", 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / source.name).write_bytes(content)
            spec = SourceSpec(
                identifier="code-validator",
                source=Path(source.name),
                destination=None,
                kind="agent",
                source_format="yaml-frontmatter",
            )
            with self.assertRaises(ValueError):
                validate_source_inventory(root, Target.CLAUDE_CODE, (spec,))

    def test_claude_install_preserves_unrelated_settings_and_records_ownership(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            repository = planning_repository(root)
            home = root / "claude-home"
            home.mkdir(mode=0o700)
            settings = home / "settings.json"
            settings.write_text('{"theme":"dark"}\n', encoding="utf-8")
            settings.chmod(0o600)
            plan = preflight_install(
                repository,
                planning_request("install", {Target.CLAUDE_CODE: home}),
            )
            apply_transaction(plan)
            rendered = json.loads(settings.read_text(encoding="utf-8"))
            self.assertEqual(rendered["theme"], "dark")
            self.assertEqual(rendered["hooks"]["PreToolUse"][0]["matcher"], "Bash")
            manifest = load_manifest(home, descriptor_for(Target.CLAUDE_CODE))
            setting = next(
                item for item in manifest.entries if item.managed_setting_id is not None
            )
            self.assertEqual(
                setting.identifier, "claude/code-validator-command-gate/settings"
            )

    def test_claude_install_rejects_conflicting_bash_hook_without_writes(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            repository = planning_repository(root)
            home = root / "claude-home"
            home.mkdir(mode=0o700)
            settings = home / "settings.json"
            settings.write_text(
                '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[]}]}}\n',
                encoding="utf-8",
            )
            settings.chmod(0o600)
            before = settings.read_bytes()
            with self.assertRaises(ValueError):
                preflight_install(
                    repository,
                    planning_request("install", {Target.CLAUDE_CODE: home}),
                )
            self.assertEqual(settings.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
