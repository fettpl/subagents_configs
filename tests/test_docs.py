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
        self.assertRegex(
            lower,
            r"no private (?:vulnerability|security).{0,100}(?:channel|configured)",
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


if __name__ == "__main__":
    unittest.main()
