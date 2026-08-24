from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class CiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.text)
        cls.steps = [
            step
            for job in cls.workflow.get("jobs", {}).values()
            for step in job.get("steps", [])
        ]

    @staticmethod
    def _unsafe_mutations(text: str) -> list[str]:
        violations = []
        lower = text.lower()
        if "contents: write" in lower:
            violations.append("write permission")
        if "persist-credentials: true" in lower:
            violations.append("persisted credentials")
        if re.search(r"\$\{\{\s*secrets\.", text):
            violations.append("secret reference")
        if re.search(r"\bsudo\b", lower):
            violations.append("sudo")
        if re.search(r"pip[^\n]*(?:bwrap|shellcheck)", lower):
            violations.append("tool installation")
        for line in text.splitlines():
            if "uses:" in line and not re.search(r"uses:\s+[^@\s]+@[0-9a-f]{40}", line):
                violations.append("unpinned action")
        return violations

    def test_workflow_is_read_only_and_actions_are_immutable(self):
        self.assertEqual(self._unsafe_mutations(self.text), [])
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertNotIn("contents: write", self.text.lower())
        self.assertNotRegex(self.text, r"\$\{\{\s*secrets\.")
        self.assertNotRegex(self.text.lower(), r"\bsudo\b|curl[^\n]*\|\s*(?:sh|bash)")
        actions = [step["uses"] for step in self.steps if "uses" in step]
        self.assertEqual(
            actions,
            [
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            ],
        )
        checkout = next(
            step
            for step in self.steps
            if step.get("uses", "").startswith("actions/checkout@")
        )
        self.assertIs(checkout["with"]["persist-credentials"], False)

    def test_python_matrix_and_job_private_target_homes_are_explicit(self):
        matrix = next(
            job["strategy"]["matrix"]
            for job in self.workflow["jobs"].values()
            if "strategy" in job
        )
        self.assertEqual(
            {str(version) for version in matrix["python-version"]}, {"3.11", "3.14"}
        )
        setup = next(
            step
            for step in self.steps
            if step.get("uses", "").startswith("actions/setup-python@")
        )
        self.assertEqual(
            setup["with"]["python-version"], "${{ matrix.python-version }}"
        )
        for variable in (
            "HOME",
            "CODEX_HOME",
            "OPENCODE_HOME",
            "CLAUDE_CONFIG_DIR",
            "TMPDIR",
        ):
            self.assertRegex(self.text, rf"\b{variable}=")
        self.assertIn("mktemp -d", self.text)
        self.assertIn("umask 077", self.text)

    def test_ci_uses_only_pinned_dependencies_existing_tools_and_local_checks(self):
        self.assertIn(
            "python -m pip install --requirement requirements-dev.txt", self.text
        )
        self.assertNotRegex(self.text.lower(), r"\b(?:brew|apt(?:-get)?|apk|yum|dnf)\b")
        for fixed_tool in ("/usr/bin/bwrap", "/bin/bwrap", "/usr/bin/shellcheck"):
            self.assertIn(fixed_tool, self.text)
        self.assertRegex(
            self.text, r"(?:test|if)\s+.*(?:-x|command -v).*(?:bwrap|shellcheck)"
        )
        for command in (
            "scripts/validate-catalogs.py",
            "tests.test_readme_contract",
            "tests.test_docs",
            "tests.test_ci",
            "tests.test_security_static",
            "tests.test_validation_backend.BackendIntegrationTests",
            "unittest discover -s tests -p 'test_*.py'",
            "ruff check subagents_configs scripts tests",
            "ruff format --check subagents_configs scripts tests",
            "shellcheck",
            "compileall -q subagents_configs scripts tests",
            "git diff --check",
        ):
            self.assertIn(command, self.text)
        self.assertIn("install.sh", self.text)
        self.assertIn("uninstall.sh", self.text)
        for wrapper in (
            "install.sh",
            "uninstall.sh",
            "install-codex.sh",
            "uninstall-codex.sh",
            "install-opencode.sh",
            "uninstall-opencode.sh",
            "install-claude-code.sh",
            "uninstall-claude-code.sh",
        ):
            self.assertIn(wrapper, self.text)
        self.assertRegex(self.text, r"fail[- ]closed|unavailable|unusable")
        self.assertNotRegex(self.text.lower(), r"pip[^\n]*(?:bwrap|shellcheck)|wget")

    def test_action_lines_are_all_sha_pinned(self):
        for line in self.text.splitlines():
            if "uses:" in line:
                self.assertRegex(line, r"uses:\s+[^@\s]+@[0-9a-f]{40}")

    def test_negative_ci_mutations_trigger_contract_guards(self):
        mutations = (
            self.text.replace("contents: read", "contents: write", 1),
            self.text.replace(
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/checkout@v7.0.1",
                1,
            ),
            self.text.replace(
                "persist-credentials: false", "persist-credentials: true", 1
            ),
            self.text.replace(
                "python -m pip install --requirement requirements-dev.txt",
                "python -m pip install bwrap",
                1,
            ),
            f"{self.text}\nrun: sudo true\nrun: ${{{{ secrets.TOKEN }}}}\n",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-80:]):
                self.assertTrue(self._unsafe_mutations(mutation))


if __name__ == "__main__":
    unittest.main()
