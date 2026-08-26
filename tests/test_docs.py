from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DocumentationContractTests(unittest.TestCase):
    def test_client_compatibility_guidance_is_read_only_and_pi_fail_closed(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8").lower()
        releasing = (ROOT / "docs" / "RELEASING.md").read_text(encoding="utf-8").lower()
        for text in (readme, security, releasing):
            self.assertIn("client compatibility", text)
            self.assertIn("read-only", text)
            self.assertIn("maintained", text)
        for phrase in (
            "client-version target=version",
            "target_unsupported",
            "format_unsupported",
            "feature_unsupported",
            "platform_unsupported",
            "scope_unsupported",
            "package_unsupported",
            "client_version_too_old",
            "compatibility-only `pi` row",
            "without probing",
        ):
            self.assertIn(phrase, readme)
        self.assertIn("without platform, package, or version claims", releasing)

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

    def test_snapshot_and_environment_credential_boundaries_are_explicit(self):
        text = " ".join(
            (ROOT / "README.md").read_text(encoding="utf-8").lower().split()
        )

        self.assertIn(
            "proxy and credential-bearing environment variables are filtered from the child environment",
            text,
        )
        self.assertIn(
            "snapshot exclusions are limited to the explicit credential paths listed above",
            text,
        )
        self.assertIn(
            "`token`, `secret`, `password`, `credential`, or `key` substrings are not generically detected",
            text,
        )

    def test_security_guidance_discloses_final_name_primitive_race(self):
        lower = " ".join(
            (ROOT / "SECURITY.md").read_text(encoding="utf-8").lower().split()
        )

        for phrase in (
            "descriptor-relative pinning and before/after evidence detect swaps",
            "persistent locks serialize cooperative installer clients",
            "python/posix offers no portable inode-conditional `unlink`/`rmdir`",
            "an adversary swapping the final pathname in the tiny window inside a trusted `unlink`/`rmdir`",
            "an unowned entry to be removed or overwritten",
        ):
            self.assertIn(phrase, lower)

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
