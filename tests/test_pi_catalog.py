"""Tests for the repository-owned Pi-native role catalog.

These tests intentionally exercise the small public surface promised by the Pi
catalog task.  They do not invoke Pi, npm, Node, a provider, or the network.
"""

from __future__ import annotations

import importlib
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PI_AGENTS = ROOT / "pi" / "agents"

READ_TOOLS = ("read", "grep", "find", "ls")
WRITE_TOOLS = ("read", "grep", "find", "ls", "write", "edit", "bash")
VALIDATOR_TOOLS = ("read", "grep", "find", "ls", "run_validation")
PUSHER_TOOLS = ("read", "grep", "find", "ls", "bash")

EXPECTED_DEFAULT_ROLES = (
    "code-explorer",
    "code-reviewer",
    "code-validator",
    "quick-implementer",
    "implementer",
)
EXPECTED_OPTIONAL_ROLES = ("commit-pusher",)
EXPECTED_BUNDLED_ROLES = (
    "delegate",
    "oracle",
    "researcher",
    "reviewer",
    "scout",
    "worker",
)


def _parse_frontmatter(path: Path) -> tuple[dict[str, object], str]:
    yaml = importlib.import_module("yaml")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        raise AssertionError(f"missing Pi frontmatter: {path}")
    try:
        closing = lines.index("---", 1)
    except ValueError as exc:
        raise AssertionError(f"missing Pi frontmatter terminator: {path}") from exc
    parsed = yaml.safe_load("\n".join(lines[1:closing]))
    if not isinstance(parsed, dict):
        raise AssertionError(f"Pi frontmatter is not a mapping: {path}")
    return parsed, "\n".join(lines[closing + 1 :])


def _with_frontmatter(parsed: dict[str, object], body: str = "safe body\n") -> bytes:
    yaml = importlib.import_module("yaml")
    return ("---\n" + yaml.safe_dump(parsed, sort_keys=False) + "---\n" + body).encode(
        "utf-8"
    )


def _as_tuple(value: object) -> tuple[object, ...]:
    """Normalize Pi's list or comma-separated frontmatter forms for assertions."""
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple)):
        return tuple(value)
    raise AssertionError(f"expected a Pi sequence, got {type(value).__name__}")


class PiCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = importlib.import_module("subagents_configs.pi_catalog")

    def test_pi_role_inventory_is_exact_and_separates_bundled_roles(self):
        self.assertEqual(self.catalog.PI_DEFAULT_ROLES, EXPECTED_DEFAULT_ROLES)
        self.assertEqual(self.catalog.PI_OPTIONAL_ROLES, EXPECTED_OPTIONAL_ROLES)
        self.assertEqual(
            tuple(
                sorted(self.catalog.PI_DEFAULT_ROLES + self.catalog.PI_OPTIONAL_ROLES)
            ),
            tuple(path.stem for path in sorted(PI_AGENTS.glob("*.md"))),
        )
        self.assertEqual(tuple(self.catalog.PI_BUNDLED_ROLES), EXPECTED_BUNDLED_ROLES)
        self.assertNotIn("scout", self.catalog.PI_DEFAULT_ROLES)
        self.assertNotIn("worker", self.catalog.PI_DEFAULT_ROLES)

    def test_each_pi_agent_has_exact_native_frontmatter_contract(self):
        for role in EXPECTED_DEFAULT_ROLES + EXPECTED_OPTIONAL_ROLES:
            with self.subTest(role=role):
                path = PI_AGENTS / f"{role}.md"
                frontmatter, body = _parse_frontmatter(path)
                self.assertEqual(frontmatter["name"], role)
                self.assertIsInstance(frontmatter["description"], str)
                self.assertTrue(frontmatter["description"].strip())
                self.assertEqual(frontmatter["systemPromptMode"], "replace")
                self.assertIs(frontmatter["inheritProjectContext"], False)
                self.assertIs(frontmatter["inheritSkills"], False)
                self.assertEqual(_as_tuple(frontmatter["skills"]), ())
                self.assertEqual(_as_tuple(frontmatter["extensions"]), ())
                self.assertNotIn("model", frontmatter)
                self.assertNotIn("thinking", frontmatter)
                self.assertNotIn("fallbackModels", frontmatter)
                self.assertEqual(
                    self.catalog.normalize_model_policy(frontmatter), "inherit"
                )
                self.assertTrue(body.strip())

                if role == "code-validator":
                    self.assertEqual(
                        _as_tuple(frontmatter["subagentOnlyExtensions"]),
                        ("{{PI_VALIDATION_EXTENSION}}",),
                    )
                    self.assertEqual(_as_tuple(frontmatter["tools"]), VALIDATOR_TOOLS)
                else:
                    self.assertNotIn("subagentOnlyExtensions", frontmatter)
                    expected = (
                        READ_TOOLS
                        if role in {"code-explorer", "code-reviewer"}
                        else WRITE_TOOLS
                        if role in {"quick-implementer", "implementer"}
                        else PUSHER_TOOLS
                    )
                    self.assertEqual(_as_tuple(frontmatter["tools"]), expected)

                lowered_body = body.lower()
                if role in {"code-explorer", "code-reviewer"}:
                    self.assertIn("read-only", lowered_body)
                    self.assertIn("never implement", lowered_body)
                elif role == "code-validator":
                    self.assertIn("run_validation", body)
                    self.assertIn("fails closed", lowered_body)
                elif role in {"quick-implementer", "implementer"}:
                    self.assertIn("parent", lowered_body)
                    self.assertIn("credential", lowered_body)
                    self.assertIn("network", lowered_body)
                else:
                    self.assertIn("both a commit and a push", lowered_body)
                    self.assertIn("never force-push", lowered_body)

    def test_pi_agent_parser_accepts_all_six_authoritative_sources(self):
        for role in EXPECTED_DEFAULT_ROLES + EXPECTED_OPTIONAL_ROLES:
            with self.subTest(role=role):
                contract = self.catalog.validate_pi_agent(
                    role, (PI_AGENTS / f"{role}.md").read_bytes()
                )
                identity = getattr(contract, "role", getattr(contract, "name", None))
                self.assertEqual(identity, role)

    def test_pi_validator_is_the_only_role_allowed_an_extension_provider(self):
        validator, _ = _parse_frontmatter(PI_AGENTS / "code-validator.md")
        self.assertEqual(
            _as_tuple(validator["subagentOnlyExtensions"]),
            ("{{PI_VALIDATION_EXTENSION}}",),
        )
        for role in EXPECTED_DEFAULT_ROLES + EXPECTED_OPTIONAL_ROLES:
            if role != "code-validator":
                frontmatter, body = _parse_frontmatter(PI_AGENTS / f"{role}.md")
                mutated = dict(frontmatter)
                mutated["subagentOnlyExtensions"] = "{{PI_VALIDATION_EXTENSION}}"
                with self.subTest(role=role):
                    with self.assertRaises(ValueError):
                        self.catalog.validate_pi_agent(
                            role, _with_frontmatter(mutated, body)
                        )

    def test_pi_agent_parser_rejects_unsafe_authority_mutations(self):
        mutations: tuple[tuple[str, object], ...] = (
            ("tools", ["read", "bash"]),
            ("inheritProjectContext", True),
            ("inheritSkills", True),
            ("skills", ["ambient-skill"]),
            ("extensions", ["ambient-extension"]),
            ("model", "gpt-5.6-luna"),
            ("thinking", "high"),
            ("fallbackModels", ["other-model"]),
            ("aliases", ["code-explorer"]),
            ("mcp", {"docs": {}}),
            ("package", "npm:untrusted@1.0.0"),
        )
        for field, value in mutations:
            source_frontmatter, body = _parse_frontmatter(
                PI_AGENTS / "code-explorer.md"
            )
            source_frontmatter[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.catalog.validate_pi_agent(
                        "code-explorer", _with_frontmatter(source_frontmatter, body)
                    )

    def test_pi_parser_rejects_validator_tool_or_extension_mutations(self):
        source_frontmatter, body = _parse_frontmatter(PI_AGENTS / "code-validator.md")
        mutations = (
            ("tools", [*VALIDATOR_TOOLS, "bash"]),
            ("subagentOnlyExtensions", ["{{PI_VALIDATION_EXTENSION}}"]),
            ("subagentOnlyExtensions", "./unsafe-extension.ts"),
        )
        for field, value in mutations:
            mutated = dict(source_frontmatter)
            mutated[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    self.catalog.validate_pi_agent(
                        "code-validator", _with_frontmatter(mutated, body)
                    )

    def test_render_pi_source_replaces_only_the_safe_absolute_extension_path(self):
        source = (PI_AGENTS / "code-validator.md").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            agent_dir = Path(temporary) / "pi-agent"
            rendered = self.catalog.render_pi_source(source, agent_dir=agent_dir)
        rendered_text = rendered.decode("utf-8")
        expected = str(agent_dir / "extensions" / "subagents-configs-run-validation.ts")
        self.assertIn(expected, rendered_text)
        self.assertNotIn("{{PI_VALIDATION_EXTENSION}}", rendered_text)
        self.assertNotIn("{{VALIDATION_HELPER}}", rendered_text)

    def test_render_pi_source_requires_keyword_only_agent_directory(self):
        source = (PI_AGENTS / "code-validator.md").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(TypeError):
                self.catalog.render_pi_source(source, Path(temporary) / "pi-agent")

    def test_pi_extension_source_digest_rejects_arbitrary_code_additions(self):
        from subagents_configs import formats

        extension = ROOT / "pi" / "extensions" / "run-validation.ts"
        mutated = extension.read_bytes() + b"\nconst attackerControlled = true;\n"
        with self.assertRaisesRegex(ValueError, "digest"):
            formats._validate_pi_extension_source(mutated, extension)

    def test_render_pi_source_rejects_relative_or_unsafe_agent_directories(self):
        source = (PI_AGENTS / "code-validator.md").read_bytes()
        unsafe_paths = (
            Path("relative/pi-agent"),
            Path("/tmp/pi-agent/../other"),  # noqa: S108
            Path("/tmp/pi-agent\nwith-control"),  # noqa: S108
            Path('/tmp/pi-agent"quoted'),  # noqa: S108
        )
        for agent_dir in unsafe_paths:
            with self.subTest(agent_dir=agent_dir):
                with self.assertRaises(ValueError):
                    self.catalog.render_pi_source(source, agent_dir=agent_dir)

    def test_pi_extension_registers_only_target_scoped_run_validation_tool(self):
        extension = ROOT / "pi" / "extensions" / "run-validation.ts"
        text = extension.read_text(encoding="utf-8")
        self.assertIn("registerTool", text)
        self.assertIn('"run_validation"', text)
        self.assertIn("Type.Object", text)
        self.assertIn("Type.Array(Type.String()", text)
        self.assertIn('spawn("python3", args,', text)
        self.assertIn("shell: false", text)
        self.assertNotRegex(text, r"\b(?:npm|npx)\b")
        self.assertNotRegex(text, r"\b(?:eval|exec)\s*\(")
        self.assertNotIn("shell: true", text)


if __name__ == "__main__":
    unittest.main()
