from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DocumentationContractTests(unittest.TestCase):
    def test_security_guidance_is_honest_and_covers_threat_model(self):
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        lower = text.lower()
        for topic in (
            "supported",
            "current branch",
            "threat model",
            "prompt injection",
            "commands",
            "hooks",
            "secrets",
            "environment",
            "network",
            "external files",
            "symlink",
            "hard link",
            "state",
            "journal",
            "git",
            "publication",
            "fail closed",
        ):
            self.assertIn(topic, lower)
        self.assertIn(
            "https://github.com/fettpl/subagents_configs/security/advisories/new",
            text,
        )
        self.assertRegex(
            lower, r"no[- ]secrets.*no[- ]transcripts|no[- ]transcripts.*no[- ]secrets"
        )
        self.assertRegex(lower, r"do not|don't.{0,100}(?:secret|sensitive|exploit)")
        self.assertNotIn("mailto:", lower)
        self.assertNotIn("security@", lower)
        self.assertIn("not perfect", lower)

    def test_release_guidance_keeps_governance_manual(self):
        text = (ROOT / "docs" / "RELEASING.md").read_text(encoding="utf-8")
        lower = text.lower()
        for topic in (
            "manual owner action",
            "protected `main`",
            "required ci",
            "independent review",
            "signed commit",
            "signed tag",
            "version",
            "release notes",
            "sha-256",
            "artifact",
            "pinned",
            "license",
            "security channel",
            "clean tree",
            "reproducible",
        ):
            self.assertIn(topic, lower)
        self.assertRegex(lower, r"do not automate|never automate|manual")
        self.assertIn("push", lower)
        self.assertIn("publish", lower)
        self.assertIn("branch protection", lower)
        self.assertIn("public redistribution", lower)
        self.assertIn("owner", lower)
        self.assertIn("spdx", lower)
        self.assertIn("exact license text", lower)
        self.assertNotIn("license selected", lower)
        self.assertFalse((ROOT / "LICENSE").exists())

    def test_release_and_agent_guidance_uses_bootstrap_interpreter_for_validator(self):
        expected = ".venv/bin/python scripts/validate-repository.py"
        for path in (
            ROOT / "docs" / "RELEASING.md",
            ROOT / "README.md",
            ROOT / "AGENTS.md",
        ):
            text = path.read_text(encoding="utf-8")
            self.assertIn(expected, text)
            self.assertNotIn("python3 scripts/validate-repository.py", text)


if __name__ == "__main__":
    unittest.main()
