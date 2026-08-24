import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_FILES = (
    ROOT / "rules" / "SUBAGENT_ROUTING.md",
    ROOT / "rules" / "OPENCODE_SUBAGENT_ROUTING.md",
    ROOT / "rules" / "CLAUDE_SUBAGENT_ROUTING.md",
)
TEMPLATES = (
    ROOT / "templates" / "AGENTS.md.template",
    ROOT / "templates" / "opencode" / "AGENTS.md.template",
    ROOT / "templates" / "claude-code" / "CLAUDE.md.template",
)


class RoutingPolicyTests(unittest.TestCase):
    def test_routing_files_contain_full_trust_and_least_privilege_policy(self):
        required = (
            "untrusted data",
            "read-only",
            "package hooks",
            "network services",
            "credentials",
            "outside the active workspace",
            "commit, push, publish",
            "least privilege",
            "security-sensitive",
        )
        for path in POLICY_FILES:
            text = path.read_text().lower()
            for term in required:
                self.assertIn(term.lower(), text, f"{term} missing from {path}")
            self.assertNotIn("optimize monetary cost", text)

    def test_routing_files_and_templates_have_no_absolute_import(self):
        for path in (*POLICY_FILES, *TEMPLATES):
            self.assertNotIn("@/absolute/path", path.read_text())

    def test_templates_are_project_only_and_contain_real_policy_text(self):
        for path in TEMPLATES:
            text = path.read_text().lower()
            self.assertIn("project", text)
            self.assertIn("untrusted data", text)
            self.assertIn("read-only", text)
            self.assertIn("credentials", text)
            self.assertIn("security-sensitive", text)
            self.assertIn("does not affect other repositories", text)


if __name__ == "__main__":
    unittest.main()
