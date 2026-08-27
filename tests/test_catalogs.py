import importlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from subagents_configs.models import SourceSpec, Target

ROOT = Path(__file__).resolve().parents[1]
ROLES = {
    "code-explorer",
    "code-reviewer",
    "code-validator",
    "quick-implementer",
    "implementer",
    "commit-pusher",
}


def _yaml_frontmatter(path: Path):
    yaml = importlib.import_module("yaml")
    lines = path.read_text().splitlines()
    if not lines or lines[0].strip() != "---":
        raise AssertionError(f"missing frontmatter: {path}")
    end = lines[1:].index("---") + 1
    return yaml.safe_load("\n".join(lines[1:end])), "\n".join(lines[end + 1 :])


class CatalogTests(unittest.TestCase):
    def _temporary_agent_specs(self, target, sources):
        """Build explicit temporary source specs for semantic negative cases."""
        repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, repo, ignore_errors=True)
        specs = []
        for index, (identifier, content) in enumerate(sources):
            filename = f"agent-{index}.md"
            (repo / filename).write_text(content)
            specs.append(
                SourceSpec(
                    identifier=identifier,
                    source=PurePosixPath(filename),
                    destination=None,
                    kind="agent",
                    source_format="yaml-frontmatter"
                    if target is not Target.CODEX
                    else "toml",
                )
            )
        return repo, tuple(specs)

    def test_codex_catalog_parses_and_has_exact_inventory(self):
        import tomllib

        actual = set()
        for path in sorted((ROOT / "agents").glob("*.toml")):
            parsed = tomllib.loads(path.read_text())
            self.assertIn("name", parsed)
            actual.add(parsed["name"])
        self.assertEqual(actual, ROLES)

    def test_pi_catalog_has_exact_repository_inventory_and_extension_source(self):
        from subagents_configs import formats
        from subagents_configs.targets import descriptor_for, selected_sources

        descriptor = descriptor_for(Target.PI)
        sources = selected_sources(descriptor, include_commit_pusher=True)
        default_sources = selected_sources(descriptor, include_commit_pusher=False)
        self.assertEqual(
            tuple(
                source.identifier
                for source in default_sources
                if source.kind == "agent"
            ),
            (
                "code-explorer",
                "code-reviewer",
                "code-validator",
                "quick-implementer",
                "implementer",
            ),
        )
        self.assertNotIn(
            "commit-pusher",
            [source.identifier for source in default_sources],
        )
        agent_sources = tuple(source for source in sources if source.kind == "agent")
        self.assertEqual(
            tuple(source.identifier for source in agent_sources),
            (
                "code-explorer",
                "code-reviewer",
                "code-validator",
                "quick-implementer",
                "implementer",
                "commit-pusher",
            ),
        )
        self.assertEqual(
            tuple(source.source for source in agent_sources),
            tuple(
                PurePosixPath("pi/agents") / f"{role}.md"
                for role in (
                    "code-explorer",
                    "code-reviewer",
                    "code-validator",
                    "quick-implementer",
                    "implementer",
                    "commit-pusher",
                )
            ),
        )
        self.assertTrue(
            all(source.source_format == "markdown" for source in agent_sources)
        )
        extension_sources = tuple(
            source for source in sources if source.kind == "target-extension"
        )
        self.assertEqual(len(extension_sources), 1)
        extension = extension_sources[0]
        self.assertEqual(
            extension.source, PurePosixPath("pi/extensions/run-validation.ts")
        )
        self.assertEqual(
            extension.destination,
            PurePosixPath("extensions/subagents-configs-run-validation.ts"),
        )
        self.assertEqual(extension.source_format, "typescript")
        routing_sources = tuple(
            source for source in sources if source.kind == "routing-source"
        )
        self.assertEqual(len(routing_sources), 1)
        self.assertEqual(
            routing_sources[0].source,
            PurePosixPath("rules/PI_SUBAGENT_ROUTING.md"),
        )
        self.assertEqual(routing_sources[0].source_format, "markdown")

        validated = formats.validate_source_inventory(
            ROOT,
            Target.PI,
            sources,
            require_commit_pusher=True,
        )
        self.assertEqual(
            {item.spec.identifier for item in validated},
            {
                "code-explorer",
                "code-reviewer",
                "code-validator",
                "quick-implementer",
                "implementer",
                "commit-pusher",
                extension.identifier,
                "routing",
                *(
                    source.identifier
                    for source in sources
                    if source.kind == "validation-runtime"
                ),
            },
        )

    def test_opencode_catalog_parses_and_has_exact_inventory(self):
        actual = set()
        for path in sorted((ROOT / "opencode" / "agents").glob("*.md")):
            parsed, body = _yaml_frontmatter(path)
            self.assertIsInstance(parsed, dict)
            self.assertTrue(body.strip())
            actual.add(parsed["name"])
        self.assertEqual(actual, ROLES)

    def test_claude_catalog_parses_and_has_exact_inventory(self):
        actual = set()
        for path in sorted((ROOT / "claude-code" / "agents").glob("*.md")):
            parsed, body = _yaml_frontmatter(path)
            self.assertIsInstance(parsed, dict)
            self.assertTrue(body.strip())
            actual.add(parsed["name"])
        self.assertEqual(actual, ROLES)

    def test_no_active_source_contains_gpt_5_4_mini(self):
        directories = (
            ROOT / "agents",
            ROOT / "opencode" / "agents",
            ROOT / "claude-code" / "agents",
        )
        for directory in directories:
            for path in directory.glob("*"):
                self.assertNotIn("gpt-5.4-mini", path.read_text())

    def test_codex_explorer_and_reviewer_are_read_only(self):
        import tomllib

        for role in ("code-explorer", "code-reviewer"):
            parsed = tomllib.loads((ROOT / "agents" / f"{role}.toml").read_text())
            self.assertEqual(parsed["sandbox_mode"], "read-only")

    def test_codex_semantics_reject_unknown_authority_and_benign_fields(self):
        import tomllib

        from subagents_configs import formats

        parsed = tomllib.loads((ROOT / "agents/code-explorer.toml").read_text())
        for field, value in {
            "approval_policy": "never",
            "permissions": {},
            "display_color": "blue",
        }.items():
            candidate = dict(parsed)
            candidate[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    ValueError, "unknown codex agent frontmatter field"
                ):
                    formats.validate_agent_semantics(
                        Target.CODEX,
                        "code-explorer",
                        candidate,
                        "read-only body",
                    )

    def test_codex_semantics_rejects_unsupported_config_fields_even_when_empty(self):
        import tomllib

        from subagents_configs import formats

        parsed = tomllib.loads((ROOT / "agents/code-explorer.toml").read_text())
        unsupported = {
            "mcp_servers": ({}, {"docs": {}}),
            "skills": ({}, {"config": []}),
            "nickname_candidates": ([], ["Scout"]),
            "permissions": ({}, {"workspace": "allow"}),
            "hooks": ({}, {"after_turn": []}),
            "features": ({}, {"multi_agent": True}),
            "model_provider": ("openai", {"name": "openai"}),
            "review_model": ("gpt-5.6-luna", ["gpt-5.6-luna"]),
        }
        for field, values in unsupported.items():
            for value in values:
                candidate = dict(parsed)
                candidate[field] = value
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(
                        ValueError, "unknown codex agent frontmatter field"
                    ):
                        formats.validate_agent_semantics(
                            Target.CODEX,
                            "code-explorer",
                            candidate,
                            "read-only body",
                        )

    def test_codex_semantics_rejects_non_string_catalog_fields(self):
        import tomllib

        from subagents_configs import formats

        parsed = tomllib.loads((ROOT / "agents/code-explorer.toml").read_text())
        invalid_types = {
            "description": False,
            "developer_instructions": True,
            "model": {"name": "gpt-5.6-luna"},
            "model_reasoning_effort": ["low"],
            "sandbox_mode": False,
        }
        for field, value in invalid_types.items():
            candidate = dict(parsed)
            candidate[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    ValueError, "Codex agent field must be a string"
                ):
                    formats.validate_agent_semantics(
                        Target.CODEX,
                        "code-explorer",
                        candidate,
                        "read-only body",
                    )

    def test_codex_semantics_requires_description_and_instructions(self):
        import tomllib

        from subagents_configs import formats

        parsed = tomllib.loads((ROOT / "agents/code-explorer.toml").read_text())
        for field in ("description", "developer_instructions"):
            candidate = dict(parsed)
            del candidate[field]
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    ValueError, "Codex agent field is required"
                ):
                    formats.validate_agent_semantics(
                        Target.CODEX,
                        "code-explorer",
                        candidate,
                        "read-only body",
                    )

    def test_codex_semantics_rejects_empty_required_fields(self):
        import tomllib

        from subagents_configs import formats

        parsed = tomllib.loads((ROOT / "agents/code-explorer.toml").read_text())
        for field in ("description", "developer_instructions"):
            for value in ("", " \t\n"):
                candidate = dict(parsed)
                candidate[field] = value
                with self.subTest(field=field, value=repr(value)):
                    with self.assertRaisesRegex(
                        ValueError, "Codex agent field must be non-empty"
                    ):
                        formats.validate_agent_semantics(
                            Target.CODEX,
                            "code-explorer",
                            candidate,
                            "read-only body",
                        )

    def test_codex_semantics_accepts_exact_catalog_agent_fields(self):
        import tomllib

        from subagents_configs import formats

        for path in sorted((ROOT / "agents").glob("*.toml")):
            parsed = tomllib.loads(path.read_text())
            formats.validate_agent_semantics(
                Target.CODEX,
                parsed["name"],
                parsed,
                path.read_text(),
            )

    def test_opencode_read_roles_deny_edit_bash_external_directory_webfetch_task(self):
        for role in ("code-explorer", "code-reviewer"):
            parsed, _ = _yaml_frontmatter(ROOT / "opencode" / "agents" / f"{role}.md")
            self.assertEqual(parsed["mode"], "subagent")
            self.assertEqual(
                parsed["permission"],
                {
                    "edit": "deny",
                    "bash": "deny",
                    "external_directory": "deny",
                    "webfetch": "deny",
                    "websearch": "deny",
                    "task": "deny",
                    "skill": "deny",
                },
            )

    def test_opencode_validator_allows_only_isolated_helper_bash(self):
        parsed, _ = _yaml_frontmatter(
            ROOT / "opencode" / "agents" / "code-validator.md"
        )
        self.assertEqual(
            parsed["permission"],
            {
                "edit": "deny",
                "webfetch": "deny",
                "websearch": "deny",
                "task": "deny",
                "skill": "deny",
                "external_directory": {
                    "*": "deny",
                    "{{VALIDATION_HELPER}}": "allow",
                },
                "bash": {
                    "*": "deny",
                    "python3 {{VALIDATION_HELPER}} -- *": "allow",
                },
            },
        )
        self.assertEqual(
            list(parsed["permission"]["bash"]),
            ["*", "python3 {{VALIDATION_HELPER}} -- *"],
        )

    def test_claude_read_roles_allow_only_read_grep_glob_in_plan_mode(self):
        for role in ("code-explorer", "code-reviewer"):
            parsed, _ = _yaml_frontmatter(
                ROOT / "claude-code" / "agents" / f"{role}.md"
            )
            self.assertEqual(parsed["tools"], "Read, Grep, Glob")
            self.assertEqual(parsed["permissionMode"], "plan")

    def test_no_role_declares_write_bypass_or_network_escalation(self):
        import tomllib

        for path in (ROOT / "agents").glob("*.toml"):
            parsed = tomllib.loads(path.read_text())
            self.assertNotIn(
                parsed.get("sandbox_mode"),
                {"workspace-write", "acceptEdits", "bypassPermissions"},
            )
            self.assertNotEqual(parsed.get("network_access"), True)
        directories = (ROOT / "opencode" / "agents", ROOT / "claude-code" / "agents")
        for directory in directories:
            for path in directory.glob("*"):
                text = path.read_text()
                self.assertNotIn("acceptEdits", text)
                self.assertNotIn("bypassPermissions", text)

    def test_validator_models_are_luna_luna_and_inherit(self):
        import tomllib

        codex = tomllib.loads((ROOT / "agents" / "code-validator.toml").read_text())
        self.assertEqual(codex["model"], "gpt-5.6-luna")
        opencode, _ = _yaml_frontmatter(
            ROOT / "opencode" / "agents" / "code-validator.md"
        )
        claude, _ = _yaml_frontmatter(
            ROOT / "claude-code" / "agents" / "code-validator.md"
        )
        self.assertEqual(opencode["model"], "openai/gpt-5.6-luna")
        self.assertEqual(claude["model"], "inherit")

    def test_validator_requires_literal_helper_placeholder(self):
        for path in (
            ROOT / "agents" / "code-validator.toml",
            ROOT / "opencode" / "agents" / "code-validator.md",
            ROOT / "claude-code" / "agents" / "code-validator.md",
        ):
            text = path.read_text()
            self.assertIn("{{VALIDATION_HELPER}}", text)
            self.assertIn("only through", text.lower())
            self.assertIn("refuse", text.lower())
            self.assertIn("fails closed", text.lower())

    def test_reviewer_contains_complete_p0_to_p3_workflow_and_verdicts(self):
        for path in (
            ROOT / "agents" / "code-reviewer.toml",
            ROOT / "opencode" / "agents" / "code-reviewer.md",
            ROOT / "claude-code" / "agents" / "code-reviewer.md",
        ):
            text = path.read_text()
            terms = (
                "P0",
                "P1",
                "P2",
                "P3",
                "security",
                "reliability",
                "path:line",
                "APPROVE",
                "REQUEST_CHANGES",
                "COMMENT",
            )
            for term in terms:
                self.assertIn(term, text)
            self.assertNotIn("$code-review", text)

    def test_commit_pusher_requires_separate_commit_and_push_request(self):
        for path in (
            ROOT / "agents" / "commit-pusher.toml",
            ROOT / "opencode" / "agents" / "commit-pusher.md",
            ROOT / "claude-code" / "agents" / "commit-pusher.md",
        ):
            text = path.read_text().lower()
            self.assertIn("both a commit and a push", text)
            self.assertIn("separate explicit", text)
            self.assertIn("never force-push", text)

    def test_codex_catalog_validation_does_not_import_yaml(self):
        formats = importlib.import_module("subagents_configs.formats")
        from unittest import mock

        from subagents_configs.models import Target
        from subagents_configs.targets import descriptor_for, selected_sources

        with mock.patch.dict(sys.modules, {"yaml": None}):
            descriptor = descriptor_for(Target.CODEX)
            specs = tuple(
                spec
                for spec in selected_sources(descriptor, include_commit_pusher=True)
                if spec.kind in {"agent", "routing-source", "project-template"}
            )
            formats.validate_source_inventory(ROOT, Target.CODEX, specs)

    def test_yaml_target_without_pyyaml_fails_concisely(self):
        formats = importlib.import_module("subagents_configs.formats")
        path = ROOT / "opencode" / "agents" / "code-explorer.md"
        from unittest import mock

        with mock.patch.dict(sys.modules, {"yaml": None}):
            with self.assertRaisesRegex(RuntimeError, "PyYAML"):
                formats.validate_yaml_agent(path, path.read_bytes())

    def test_inventory_rejects_symlink(self):
        formats = importlib.import_module("subagents_configs.formats")
        from subagents_configs.models import SourceSpec

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "real.toml").write_text('name = "code-explorer"\n')
            (repo / "link.toml").symlink_to(repo / "real.toml")
            source = SourceSpec(
                identifier="code-explorer",
                source=PurePosixPath("link.toml"),
                destination=None,
                kind="agent",
                source_format="toml",
            )
            with self.assertRaises(ValueError):
                formats.validate_source_inventory(repo, Target.CODEX, (source,))

    def test_inventory_rejects_unknown_parsed_role(self):
        formats = importlib.import_module("subagents_configs.formats")
        content = "---\nname: unknown-role\nmode: subagent\n---\nbody\n"
        repo, specs = self._temporary_agent_specs(
            Target.OPENCODE, (("unknown-role", content),)
        )
        with self.assertRaisesRegex(ValueError, "unknown role"):
            formats.validate_source_inventory(repo, Target.OPENCODE, specs)

    def test_inventory_rejects_duplicate_parsed_role_names(self):
        formats = importlib.import_module("subagents_configs.formats")
        permission = (
            "permission:\n  edit: deny\n  bash: deny\n  "
            "external_directory: deny\n  webfetch: deny\n  websearch: deny\n  "
            "task: deny\n  skill: deny\n"
        )
        first = f"---\nname: code-explorer\nmode: subagent\n{permission}---\nbody\n"
        second = f"---\nname: code-explorer\nmode: subagent\n{permission}---\nbody\n"
        repo, specs = self._temporary_agent_specs(
            Target.OPENCODE,
            (("code-explorer", first), ("code-reviewer", second)),
        )
        with self.assertRaisesRegex(ValueError, "duplicate parsed role"):
            formats.validate_source_inventory(repo, Target.OPENCODE, specs)

    def test_opencode_rejects_nested_permission_allow_escalation(self):
        formats = importlib.import_module("subagents_configs.formats")
        content = (
            "---\nname: quick-implementer\nmode: subagent\n"
            "permission:\n  edit: allow\n---\nbody\n"
        )
        repo, specs = self._temporary_agent_specs(
            Target.OPENCODE, (("quick-implementer", content),)
        )
        with self.assertRaisesRegex(ValueError, "unsafe permission"):
            formats.validate_source_inventory(repo, Target.OPENCODE, specs)

    def test_opencode_validator_requires_permission_block(self):
        formats = importlib.import_module("subagents_configs.formats")
        content = (
            "---\nname: code-validator\nmodel: openai/gpt-5.6-luna\n---\n"
            "Run only through {{VALIDATION_HELPER}}. Refuses direct validation "
            "and fails closed without a verified backend.\n"
        )
        repo, specs = self._temporary_agent_specs(
            Target.OPENCODE, (("code-validator", content),)
        )
        with self.assertRaisesRegex(ValueError, "unsafe validator permissions"):
            formats.validate_source_inventory(repo, Target.OPENCODE, specs)

    def test_opencode_validator_requires_websearch_deny(self):
        formats = importlib.import_module("subagents_configs.formats")
        permission = (
            "permission:\n"
            "  edit: deny\n"
            "  webfetch: deny\n"
            "  task: deny\n"
            "  skill: deny\n"
            "  external_directory:\n"
            "    '*': deny\n"
            "    '{{VALIDATION_HELPER}}': allow\n"
            "  bash:\n"
            "    '*': deny\n"
            "    'python3 {{VALIDATION_HELPER}} -- *': allow\n"
        )
        content = (
            "---\nname: code-validator\nmodel: openai/gpt-5.6-luna\n"
            f"{permission}---\n"
            "Run only through {{VALIDATION_HELPER}}. Refuses direct validation "
            "and fails closed without a verified backend.\n"
        )
        repo, specs = self._temporary_agent_specs(
            Target.OPENCODE, (("code-validator", content),)
        )
        with self.assertRaisesRegex(ValueError, "unsafe validator permissions"):
            formats.validate_source_inventory(repo, Target.OPENCODE, specs)

    def test_opencode_validator_rejects_broad_bash_allow(self):
        formats = importlib.import_module("subagents_configs.formats")
        permission = (
            "permission:\n"
            "  edit: deny\n"
            "  webfetch: deny\n"
            "  websearch: deny\n"
            "  task: deny\n"
            "  skill: deny\n"
            "  external_directory:\n"
            "    '*': deny\n"
            "    '{{VALIDATION_HELPER}}': allow\n"
            "  bash: allow\n"
        )
        content = (
            "---\nname: code-validator\nmodel: openai/gpt-5.6-luna\n"
            f"{permission}---\n"
            "Run only through {{VALIDATION_HELPER}}. Refuses direct validation "
            "and fails closed without a verified backend.\n"
        )
        repo, specs = self._temporary_agent_specs(
            Target.OPENCODE, (("code-validator", content),)
        )
        with self.assertRaisesRegex(ValueError, "unsafe validator permissions"):
            formats.validate_source_inventory(repo, Target.OPENCODE, specs)

    def test_claude_rejects_network_and_write_tool_escalation(self):
        formats = importlib.import_module("subagents_configs.formats")
        content = (
            "---\nname: quick-implementer\ntools: Read, Bash, WebFetch, WebSearch\n"
            "model: inherit\n---\nbody\n"
        )
        repo, specs = self._temporary_agent_specs(
            Target.CLAUDE_CODE, (("quick-implementer", content),)
        )
        with self.assertRaisesRegex(ValueError, "unsafe tool"):
            formats.validate_source_inventory(repo, Target.CLAUDE_CODE, specs)

    def test_yaml_catalog_rejects_duplicate_and_unknown_frontmatter(self):
        formats = importlib.import_module("subagents_configs.formats")
        duplicate = (
            "---\nname: code-explorer\nname: code-reviewer\nmode: subagent\n---\nbody\n"
        )
        unknown = "---\nname: code-explorer\nsurprise: true\n---\nbody\n"
        for content in (duplicate, unknown):
            repo, specs = self._temporary_agent_specs(
                Target.OPENCODE, (("code-explorer", content),)
            )
            with self.subTest(content=content):
                with self.assertRaises(ValueError):
                    formats.validate_source_inventory(repo, Target.OPENCODE, specs)

    def test_opencode_permission_order_and_unknown_key_fail_closed(self):
        formats = importlib.import_module("subagents_configs.formats")
        source = ROOT / "opencode/agents/code-explorer.md"
        content = source.read_text()
        mutations = (
            content.replace("  edit: deny\n  bash: deny", "  bash: deny\n  edit: deny"),
            content.replace("  skill: deny", "  skill: deny\n  mystery: deny"),
        )
        for mutated in mutations:
            repo, specs = self._temporary_agent_specs(
                Target.OPENCODE, (("code-explorer", mutated),)
            )
            with self.subTest(mutated=mutated):
                with self.assertRaises(ValueError):
                    formats.validate_source_inventory(repo, Target.OPENCODE, specs)


if __name__ == "__main__":
    unittest.main()
