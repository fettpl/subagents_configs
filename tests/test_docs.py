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
        validation = text.split("validation runs only through:", 1)[1].split(
            "on macos,", 1
        )[0]

        for token in (
            "snapshot exclusions",
            "explicit credential paths",
            "not generically detected",
            "credential-bearing environment variables",
            "filtered",
            "child environment",
        ):
            self.assertIn(token, validation)
        self.assertRegex(
            validation,
            r"snapshot exclusions.{0,100}explicit credential paths",
        )
        self.assertRegex(
            validation,
            r"proxy.{0,100}credential-bearing environment variables"
            r".{0,100}filtered.{0,100}child environment",
        )
        self.assertRegex(
            validation,
            r"`token`.{0,80}`secret`.{0,80}`password`"
            r".{0,80}`credential`.{0,80}`key`.{0,80}not generically detected",
        )
        self.assertNotRegex(validation, r"names containing.{0,100}excluded")

    def test_security_guidance_discloses_final_name_primitive_race(self):
        text = " ".join(
            (ROOT / "SECURITY.md").read_text(encoding="utf-8").lower().split()
        )
        technical = text.split("## technical controls and limitations", 1)[1].split(
            "## reporting a concern", 1
        )[0]

        for token in (
            "descriptor-relative pinning",
            "before/after evidence",
            "persistent locks",
            "cooperative installer clients",
            "python/posix",
            "inode-conditional `unlink`/`rmdir`",
            "non-cooperative actor",
            "race the parent",
            "final evidence proof",
            "immediately before",
            "trusted `unlink`/`rmdir` primitive",
            "replacement",
            "unowned final entry",
        ):
            self.assertIn(token, technical)
        self.assertRegex(
            technical,
            r"non-cooperative actor.{0,100}race the parent",
        )
        self.assertRegex(
            technical,
            r"after the final evidence proof.{0,100}"
            r"immediately before the trusted `unlink`/`rmdir` primitive",
        )
        self.assertRegex(
            technical,
            r"(?:may|could) remove.{0,100}(?:replacement|unowned final entry)",
        )
        self.assertNotRegex(technical, r"`unlink`/`rmdir`.{0,100}overwrite")

    def test_cleanup_evidence_boundary_does_not_claim_local_authenticity(self):
        security = " ".join(
            (ROOT / "SECURITY.md").read_text(encoding="utf-8").lower().split()
        )
        schema = " ".join(
            (ROOT / "docs" / "STATE_SCHEMA.md")
            .read_text(encoding="utf-8")
            .lower()
            .split()
        )
        for text in (security, schema):
            for token in (
                "same-uid actor",
                "self-consistent",
                "external key",
                "tpm",
                "privileged service",
                "without rewriting every anchor",
            ):
                self.assertIn(token, text)
            self.assertRegex(text, r"fail[- ]closed")
        self.assertIn("not an authenticated append-only store", security)
        self.assertIn("not an append-only trust service", schema)

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

    def test_pi_security_boundary_covers_package_drift_diagnostics_and_providers(self):
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8").lower()
        for phrase in (
            "third-party package",
            "package execution",
            "settings",
            "config",
            "package",
            "receipt",
            "drift",
            "redacted diagnostics",
            "no automatic package rollback",
            "provider",
            "credential",
            "pi-subagents",
            "pi 0.84.1",
            "npm:pi-subagents@0.56.0",
            "non-atomic",
            "windows",
            "fail-closed",
        ):
            self.assertIn(phrase, text, phrase)
        self.assertRegex(
            text,
            r"provider.{0,160}(?:credential|secret).{0,160}(?:exclude|omit|never)",
        )
        self.assertRegex(
            text, r"diagnostic.{0,120}(?:redact|safe).{0,120}(?:path|output|secret)"
        )

    def test_pi_release_gate_documents_evidence_and_manual_governance(self):
        text = (ROOT / "docs" / "RELEASING.md").read_text(encoding="utf-8").lower()
        for phrase in (
            "pi-subagents",
            "0.56.0",
            "0.84.1",
            "package policy",
            "source commit",
            "integrity",
            "manifest",
            "dependency",
            "lifecycle",
            "python 3.11",
            "python 3.14",
            "macos",
            "linux",
            "mandatory isolated real-pi smoke",
            "offline",
            "release-note",
            "pin change",
            "manual consent",
            "publication",
            "provider smoke",
        ):
            self.assertIn(phrase, text, phrase)
        self.assertRegex(text, r"only task 11.{0,160}(?:supported|transition)")
        self.assertRegex(
            text, r"provider smoke.{0,160}(?:separate|explicitly authorized)"
        )


if __name__ == "__main__":
    unittest.main()
