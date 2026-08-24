from __future__ import annotations

import shlex
import tomllib
import unittest
from pathlib import Path

from subagents_configs.cli import _parser, parse_request
from subagents_configs.models import Target
from subagents_configs.targets import DESCRIPTOR_ORDER, descriptor_for, selected_sources

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def _frontmatter(path: Path) -> dict[str, object]:
    import yaml

    lines = path.read_text(encoding="utf-8").splitlines()
    end = lines[1:].index("---") + 1
    return yaml.safe_load("\n".join(lines[1:end]))


def _parsed_agent(target: Target, role: str) -> dict[str, object]:
    descriptor = descriptor_for(target)
    source = next(
        source
        for source in descriptor.sources
        if source.identifier == role and source.kind == "agent"
    )
    path = ROOT / source.source
    if source.source_format == "toml":
        return tomllib.loads(path.read_text(encoding="utf-8"))
    return _frontmatter(path)


def _policy_table(text: str) -> dict[tuple[str, str], dict[str, str]]:
    heading = "## Target-role policy matrix"
    start = text.index(heading) + len(heading)
    remainder = text[start:]
    next_heading = remainder.find("\n## ")
    section = remainder if next_heading == -1 else remainder[:next_heading]
    rows = [
        line.strip()
        for line in section.splitlines()
        if line.strip().startswith("|") and line.count("|") >= 6
    ]
    if len(rows) < 2:
        raise AssertionError("target-role policy matrix is missing its data rows")
    headers = [cell.strip().lower() for cell in rows[0].strip("|").split("|")]
    expected_headers = [
        "target",
        "role",
        "model",
        "effort",
        "sandbox/tools",
        "permission mode",
    ]
    if headers != expected_headers:
        raise AssertionError(f"unexpected target-role policy headers: {headers!r}")

    def clean(cell: str) -> str:
        value = cell.strip()
        return value[1:-1] if value.startswith("`") and value.endswith("`") else value

    result: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows[1:]:
        if set(row.replace("|", "").replace("-", "").replace(":", "").strip()) == set():
            continue
        cells = [clean(cell) for cell in row.strip("|").split("|")]
        if len(cells) != len(headers):
            raise AssertionError(f"malformed target-role policy row: {row!r}")
        data = dict(zip(headers, cells, strict=True))
        key = (data["target"], data["role"])
        if key in result:
            raise AssertionError(f"duplicate target-role policy row: {key!r}")
        result[key] = data
    return result


def _catalog_policy(target: Target, role: str) -> dict[str, str]:
    parsed = _parsed_agent(target, role)

    def value(name: str) -> str:
        raw = parsed.get(name)
        if raw is None:
            return "absent"
        if isinstance(raw, list):
            return ", ".join(str(item) for item in raw)
        return str(raw)

    return {
        "target": target.value,
        "role": role,
        "model": value("model"),
        "effort": (
            value("model_reasoning_effort")
            if target is Target.CODEX
            else value("variant")
        ),
        "sandbox/tools": (
            value("sandbox_mode") if target is Target.CODEX else value("tools")
        ),
        "permission mode": value("permissionMode"),
    }


class ReadmeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = README.read_text(encoding="utf-8")
        cls.lower = cls.text.lower()

    def test_readme_is_standalone_and_names_supported_targets_and_pi_exclusion(self):
        for target in DESCRIPTOR_ORDER:
            self.assertIn(target.value, self.lower)
            descriptor = descriptor_for(target)
            self.assertIn(descriptor.environment_variable, self.text)
            self.assertIn(descriptor.default_home, self.text)
            self.assertIn(descriptor.global_filename, self.text)
        self.assertIn("pi", self.lower)
        self.assertIn("pi-coding-agent", self.lower)
        self.assertRegex(
            self.lower,
            r"pi(?:-coding-agent)?[^.\n]{0,80}(?:excluded|out of scope|not supported)",
        )
        active_text = "\n".join(
            source.source.as_posix()
            for target in DESCRIPTOR_ORDER
            for source in descriptor_for(target).sources
        )
        self.assertNotIn("pi", active_text.lower())
        self.assertFalse(list(ROOT.glob("*pi*.sh")))

    def test_role_and_target_model_facts_are_derived_from_catalog(self):
        roles = {
            source.identifier
            for target in DESCRIPTOR_ORDER
            for source in descriptor_for(target).sources
            if source.kind == "agent"
        }
        for role in sorted(roles):
            self.assertIn(role, self.lower)
        self.assertIn("read-only", self.lower)
        self.assertIn("validation", self.lower)
        self.assertIn("review", self.lower)
        self.assertRegex(self.lower, r"commit-pusher.{0,120}explicit")

        expected = {
            (target.value, role): _catalog_policy(target, role)
            for target in DESCRIPTOR_ORDER
            for role in sorted(roles)
        }
        actual = _policy_table(self.text)
        self.assertEqual(set(actual), set(expected))
        self.assertEqual(actual, expected)
        self.assertEqual(
            {actual[(Target.OPENCODE.value, role)]["effort"] for role in roles},
            {"absent"},
        )
        self.assertEqual(
            {actual[(Target.CLAUDE_CODE.value, role)]["model"] for role in roles},
            {"inherit"},
        )
        for role in ("code-explorer", "code-reviewer"):
            self.assertEqual(
                actual[(Target.CLAUDE_CODE.value, role)]["permission mode"],
                "plan",
            )
        self.assertNotIn("gpt-5.4-mini", self.lower)

    def test_default_and_opt_in_inventory_comes_from_descriptors(self):
        for target in DESCRIPTOR_ORDER:
            descriptor = descriptor_for(target)
            default_sources = selected_sources(descriptor, include_commit_pusher=False)
            selected_ids = {source.identifier for source in default_sources}
            self.assertNotIn("commit-pusher", selected_ids)
            self.assertIn("commit-pusher", self.lower)
            for source in default_sources:
                if source.destination is not None:
                    self.assertIn(source.destination.as_posix(), self.text)
            optional = next(
                source
                for source in descriptor.sources
                if source.identifier == "commit-pusher"
            )
            self.assertIsNotNone(optional.destination)
            self.assertIn(optional.destination.as_posix(), self.text)
            if descriptor.config_filename:
                self.assertIn(descriptor.config_filename, self.text)
        for path in (
            ".subagents_configs/manifest.json",
            ".subagents_configs/journal.json",
            ".subagents_configs/backups",
            ".subagents_configs/validation",
        ):
            self.assertIn(path, self.text)
        self.assertIn("toml", self.lower)
        self.assertIn("yaml frontmatter", self.lower)
        self.assertIn("markdown", self.lower)

    def test_required_examples_parse_through_the_real_cli(self):
        examples = (
            "./install.sh --target codex",
            "./install.sh --target opencode --home opencode=/tmp/opencode",
            "./install.sh --target claude-code",
            "./install.sh --target codex --target opencode --target claude-code",
            "./install.sh --all --dry-run",
            "./uninstall.sh --target codex --dry-run",
        )
        environment = {
            "HOME": "readme-contract/home",
            "CODEX_HOME": "readme-contract/codex",
            "OPENCODE_HOME": "readme-contract/opencode",
            "CLAUDE_CONFIG_DIR": "readme-contract/claude",
        }
        for example in examples:
            self.assertIn(example, self.text)
            argv = shlex.split(example)[1:]
            operation = "uninstall" if example.startswith("./uninstall") else "install"
            parse_request(operation, argv, environment)

        valid_shapes = (
            ("install", ("--target", "codex", "--enable-global-routing")),
            (
                "install",
                (
                    "--target",
                    "codex",
                    "--enable-codex-multi-agent",
                    "--include-commit-pusher",
                    "--home",
                    "codex=/tmp/readme-contract-codex",
                    "--dry-run",
                ),
            ),
            (
                "install",
                ("--all", "--home", "opencode=/tmp/readme-contract-opencode"),
            ),
            ("uninstall", ("--all", "--dry-run")),
        )
        for operation, argv in valid_shapes:
            parse_request(operation, argv, environment)

    def test_every_public_option_and_precedence_rule_is_documented(self):
        options = {
            option for action in _parser()._actions for option in action.option_strings
        }
        options.add("--help")
        for option in sorted(options):
            self.assertIn(option, self.text)
        self.assertRegex(self.lower, r"--home.{0,120}(?:overrides|precedence)")
        self.assertIn("CODEX_HOME", self.text)
        self.assertIn("OPENCODE_HOME", self.text)
        self.assertIn("CLAUDE_CONFIG_DIR", self.text)
        self.assertIn("normalized", self.lower)
        self.assertIn("display", self.lower)
        self.assertIn("install-only", self.lower)

    def test_reinstall_contract_is_explicit(self):
        heading = "## Reinstall and drift"
        self.assertIn(heading, self.text)
        start = self.text.index(heading) + len(heading)
        remainder = self.text[start:]
        next_heading = remainder.find("\n## ")
        section = remainder if next_heading == -1 else remainder[:next_heading]
        lower = section.lower()
        for anchor in ("reinstall", "unchanged", "backup", "manifest", "state"):
            self.assertIn(anchor, lower)
        self.assertRegex(lower, r"no\s+writes")
        self.assertIn("drift", lower)
        self.assertIn("conflict", lower)
        self.assertRegex(lower, r"fail(?:s|ed)? closed|refus(?:e|es|ed)")
        self.assertIn("dry-run", lower)
        self.assertRegex(lower, r"recovery|journal")

    def test_safety_lifecycle_and_manual_setup_topics_are_present(self):
        topics = (
            "safe default",
            "prompt",
            "hook",
            "secret",
            "symlink",
            "hard link",
            "journal",
            "rollback",
            "recovery",
            "dry-run",
            "uninstall",
            "unresolved",
            "project-only",
            "restart",
            "reload",
            "sandbox",
            "bwrap",
            "sandbox-exec",
            "no unsandboxed fallback",
            "sudo",
            "download-and-execute",
            "pinned",
            "git",
            "license",
        )
        for topic in topics:
            self.assertIn(topic, self.lower)
        self.assertRegex(
            self.lower, r"no license[^.\n]{0,120}(?:selected|granted|decision)"
        )
        self.assertIn("global routing", self.lower)
        self.assertIn("multi-agent", self.lower)
        self.assertIn("commit-pusher", self.lower)


if __name__ == "__main__":
    unittest.main()
