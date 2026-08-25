import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from subagents_configs.errors import ValidationBlockedError
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
            {
                "session_id": "session-1",
                "cwd": "/workspace/project",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "tool_use_id": "tool-1",
                "agent_type": "code-validator",
                "prompt_id": "prompt-1",
                "effort": {"level": "medium"},
                "permission_mode": "auto",
            }
        ).encode()

    def test_parser_accepts_only_bash_command_events(self):
        event = self.hook.parse_pretooluse_event(
            json.dumps(
                {
                    "session_id": "session-1",
                    "cwd": "/workspace/project",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {
                        "command": "python3 /abs/helper -- unittest tests/test_x.py",
                        "description": "run focused tests",
                        "timeout": 120000,
                        "run_in_background": False,
                    },
                    "tool_use_id": "tool-1",
                    "permission_mode": "default",
                    "agent_id": "agent-1",
                    "agent_type": "code-validator",
                }
            ).encode()
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
        valid = json.loads(self._event("python3 /abs/helper -- unittest").decode())
        for key, value in (
            ("session_id", 1),
            ("cwd", 1),
            ("hook_event_name", "PostToolUse"),
            ("tool_use_id", 1),
            ("permission_mode", 1),
            ("agent_id", 1),
            ("agent_type", "implementer"),
            ("permission_mode", "unsafe"),
            ("effort", "maximum"),
            ("prompt_id", "bad\nvalue"),
        ):
            invalid = dict(valid)
            invalid[key] = value
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    self.hook.parse_pretooluse_event(json.dumps(invalid).encode())
        duplicate = (
            b'{"session_id":"s","cwd":"/w","hook_event_name":"PreToolUse",'
            b'"tool_name":"Bash","tool_input":{"command":"python3 /abs/helper -- x"},'
            b'"tool_use_id":"t","agent_type":"code-validator",'
            b'"agent_type":"code-validator"}'
        )
        with self.assertRaises(ValueError):
            self.hook.parse_pretooluse_event(duplicate)
        for effort in (
            {},
            {"level": "medium", "extra": "nope"},
            {"level": 1},
            {"level": "maximum"},
            {"level": "medium\nunsafe"},
        ):
            malformed_effort = json.loads(
                self._event("python3 /abs/helper -- unittest").decode()
            )
            malformed_effort["effort"] = effort
            with self.subTest(effort=effort):
                with self.assertRaises(ValueError):
                    self.hook.parse_pretooluse_event(
                        json.dumps(malformed_effort).encode()
                    )
        malformed_input = json.loads(
            self._event("python3 /abs/helper -- unittest").decode()
        )
        malformed_input["tool_input"]["timeout"] = True
        with self.assertRaises(ValueError):
            self.hook.parse_pretooluse_event(json.dumps(malformed_input).encode())

    def test_validator_command_returns_fixed_argv_for_safe_data(self):
        for command in (
            "python3 /abs/helper -- unittest tests/test_x.py",
            "python3 /abs/helper -- pytest tests/test_x.py",
            "python3 /abs/helper -- ruff check subagents_configs",
            "python3 /abs/helper -- python3 -m unittest discover -s tests",
            "python3 /abs/helper -- python3 -m compileall -q subagents_configs",
            "python3 /abs/helper -- shellcheck install.sh",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    self.hook.validate_validator_command(command, "/abs/helper")[0:3],
                    ("python3", "/abs/helper", "--"),
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
            "python3 /abs/helper -- bash -c id",
            "python3 /abs/helper -- sh -c id",
            "python3 /abs/helper -- env X=1 unittest tests/test_x.py",
            "python3 /abs/helper -- python3 -c id",
            "python3 /abs/helper -- python3.14 -c id",
            "python3 /abs/helper -- /bin/echo unsafe",
            "python3 /abs/helper -- ./echo unsafe",
            "python3 /abs/helper -- unittest *.py",
            "python3 /abs/helper -- unittest tests/?.py",
            "python3 /abs/helper -- unittest ~/tests.py",
            "python3 /abs/helper -- xargs unittest tests/test_x.py",
            "python3 /abs/helper -- rm tests/test_x.py",
            "python3 /abs/helper -- curl https://example.test",
            "python3 /abs/helper -- git status",
            "python3 /abs/helper -- sed -n 1p tests/test_x.py",
            "python3 /abs/helper -- busybox sh",
            "python3 /abs/helper -- python3 -c id",
            "python3 /abs/helper -- python3 -m pip install x",
            "python3 /abs/helper -- unknown-tool tests/test_x.py",
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

    def test_catalog_rejects_command_gate_that_allows_unconditionally(self):
        source = ROOT / "claude-code/hooks/code-validator-pretooluse.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / source.name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source.read_bytes().replace(b"return 2", b"return 0", 1))
            spec = SourceSpec(
                identifier="claude/code-validator-command-gate",
                source=Path(source.name),
                destination=Path(".subagents_configs/claude-hooks/hook.py"),
                kind="command-gate",
                source_format="python",
            )
            with self.assertRaises(ValueError):
                validate_source_inventory(root, Target.CLAUDE_CODE, (spec,))

    def test_claude_install_scopes_hook_to_validator_agent_only(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            repository = planning_repository(root)
            home = root / "home with $ and (spaces)"
            home.mkdir(mode=0o700)
            plan = preflight_install(
                repository,
                planning_request("install", {Target.CLAUDE_CODE: home}),
            )
            apply_transaction(plan)
            validator = (home / "agents/code-validator.md").read_text()
            self.assertIn("PreToolUse:", validator)
            self.assertIn("args: []", validator)
            self.assertIn(
                str(
                    home
                    / ".subagents_configs/claude-hooks/code-validator-pretooluse.py"
                ),
                validator,
            )
            self.assertFalse((home / "settings.json").exists())
            for role in (
                "code-explorer",
                "code-reviewer",
                "quick-implementer",
                "implementer",
            ):
                rendered = (home / f"agents/{role}.md").read_text()
                self.assertNotIn("PreToolUse:", rendered)
                if role in {"quick-implementer", "implementer"}:
                    self.assertIn("tools: Read, Grep, Glob, Edit, Bash", rendered)
            self.assertTrue(
                (
                    home
                    / ".subagents_configs/claude-hooks/code-validator-pretooluse.py"
                ).exists()
            )
            manifest = load_manifest(home, descriptor_for(Target.CLAUDE_CODE))
            self.assertIsNotNone(manifest)

    def test_claude_frontmatter_rejects_conflicting_hook_without_writes(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            repository = planning_repository(root)
            home = root / "claude-home"
            home.mkdir(mode=0o700)
            source = repository / "claude-code/agents/code-validator.md"
            source.write_bytes(
                source.read_bytes().replace(b"type: command", b"type: prompt")
            )
            with self.assertRaises(ValidationBlockedError):
                preflight_install(
                    repository,
                    planning_request("install", {Target.CLAUDE_CODE: home}),
                )
            self.assertFalse(home.joinpath("agents").exists())


if __name__ == "__main__":
    unittest.main()
