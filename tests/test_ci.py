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
        allowed_linux_provisioning = re.compile(
            r"(?ms)^      - name: Provision Ubuntu bubblewrap\n"
            r"        if: matrix\.os == ['\"]ubuntu-24\.04['\"]\n"
            r"        shell: bash\n"
            r"        run: \|\n"
            r"          set -euo pipefail\n"
            r"          sudo apt-get update\n"
            r"          sudo apt-get install --yes --no-install-recommends "
            r"bubblewrap=0\.9\.0-1ubuntu0\.1 "
            r"apparmor=4\.0\.1really4\.0\.1-0ubuntu0\.24\.04\.7 "
            r"apparmor-profiles=4\.0\.1really4\.0\.1-0ubuntu0\.24\.04\.7\n"
            r"          profile_source=/usr/share/apparmor/extra-profiles/"
            r"bwrap-userns-restrict\n"
            r"          parser=/usr/sbin/apparmor_parser\n"
            r"          if ! test -f \"\$profile_source\" \|\| ! test \"\$\(realpath "
            r"\"\$profile_source\"\)\" = \"\$profile_source\" \|\| ! test "
            r"\"\$\(stat -c '%u' "
            r"\"\$profile_source\"\)\" = 0; then\n"
            r"            echo \"AppArmor profile source is unavailable or unsafe\"\n"
            r"            exit 1\n"
            r"          fi\n"
            r"          profile_mode=\"\$\(stat -c '%a' \"\$profile_source\"\)\"\n"
            r"          test \"\$\(\(8#\$profile_mode & 8#022\)\)\" -eq 0\n"
            r"          if ! test -f \"\$parser\" \|\| ! test -x \"\$parser\" "
            r"\|\| ! test "
            r"\"\$\(realpath \"\$parser\"\)\" = \"\$parser\" \|\| ! test "
            r"\"\$\(stat -c '%u' "
            r"\"\$parser\"\)\" = 0; then\n"
            r"            echo \"AppArmor parser is unavailable or unsafe\"\n"
            r"            exit 1\n"
            r"          fi\n"
            r"          parser_mode=\"\$\(stat -c '%a' \"\$parser\"\)\"\n"
            r"          test \"\$\(\(8#\$parser_mode & 8#022\)\)\" -eq 0\n"
            r"          sudo install --owner=root --group=root --mode=0644 "
            r"\"\$profile_source\" /etc/apparmor.d/bwrap-userns-restrict\n"
            r"          test -f /etc/apparmor.d/bwrap-userns-restrict\n"
            r"          test \"\$\(realpath "
            r"/etc/apparmor.d/bwrap-userns-restrict\)\" = "
            r"/etc/apparmor.d/bwrap-userns-restrict\n"
            r"          test \"\$\(stat -c '%u:%g' /etc/apparmor.d/"
            r"bwrap-userns-restrict\)\" = 0:0\n"
            r"          test \"\$\(stat -c '%a' /etc/apparmor.d/"
            r"bwrap-userns-restrict\)\" = 644\n"
            r"          sudo /usr/sbin/apparmor_parser --replace "
            r"/etc/apparmor.d/bwrap-userns-restrict\n"
        )
        sanitized, provisioning_count = allowed_linux_provisioning.subn("", text)
        sanitized_lower = sanitized.lower()
        if provisioning_count != 1:
            violations.append("unsafe Ubuntu bubblewrap provisioning")
        if "contents: write" in lower:
            violations.append("write permission")
        if "persist-credentials: true" in lower:
            violations.append("persisted credentials")
        if re.search(r"\$\{\{\s*secrets\.", text):
            violations.append("secret reference")
        if re.search(r"\bsudo\b", sanitized_lower):
            violations.append("sudo")
        if re.search(r"\b(?:apt(?:-get)?|apk|brew|dnf|yum)\b", sanitized_lower):
            violations.append("package manager")
        if re.search(r"pip[^\n]*(?:bwrap|shellcheck)", sanitized_lower):
            violations.append("tool installation")
        for required_mode_check in (
            'test "$((8#$tool_mode & 8#022))" -eq 0',
            'test "$((8#$sandbox_mode & 8#022))" -eq 0',
            'test "$((8#$shellcheck_mode & 8#022))" -eq 0',
        ):
            if required_mode_check not in text:
                violations.append("missing fixed-tool mode check")
        for line in text.splitlines():
            if "uses:" in line and not re.search(r"uses:\s+[^@\s]+@[0-9a-f]{40}", line):
                violations.append("unpinned action")
        return violations

    def test_workflow_is_read_only_and_actions_are_immutable(self):
        self.assertEqual(self._unsafe_mutations(self.text), [])
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertNotIn("contents: write", self.text.lower())
        self.assertNotRegex(self.text, r"\$\{\{\s*secrets\.")
        self.assertNotRegex(self.text.lower(), r"curl[^\n]*\|\s*(?:sh|bash)")
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

    def test_runner_matrix_is_pinned_to_supported_images(self):
        matrix = next(
            job["strategy"]["matrix"]
            for job in self.workflow["jobs"].values()
            if "strategy" in job
        )
        self.assertEqual(set(matrix["os"]), {"ubuntu-24.04", "macos-15"})

    def test_ubuntu_bubblewrap_provisioning_is_one_exact_linux_step(self):
        provisioning = [
            step
            for step in self.steps
            if step.get("name") == "Provision Ubuntu bubblewrap"
        ]
        self.assertEqual(len(provisioning), 1)
        step = provisioning[0]
        self.assertEqual(step["if"], "matrix.os == 'ubuntu-24.04'")
        self.assertEqual(
            step["run"],
            "set -euo pipefail\n"
            "sudo apt-get update\n"
            "sudo apt-get install --yes --no-install-recommends "
            "bubblewrap=0.9.0-1ubuntu0.1 "
            "apparmor=4.0.1really4.0.1-0ubuntu0.24.04.7 "
            "apparmor-profiles=4.0.1really4.0.1-0ubuntu0.24.04.7\n"
            "profile_source=/usr/share/apparmor/extra-profiles/"
            "bwrap-userns-restrict\n"
            "parser=/usr/sbin/apparmor_parser\n"
            'if ! test -f "$profile_source" || ! test "$(realpath '
            '"$profile_source")" = "$profile_source" || ! test "$(stat -c \'%u\' '
            '"$profile_source")" = 0; then\n'
            '  echo "AppArmor profile source is unavailable or unsafe"\n'
            "  exit 1\n"
            "fi\n"
            'profile_mode="$(stat -c \'%a\' "$profile_source")"\n'
            'test "$((8#$profile_mode & 8#022))" -eq 0\n'
            'if ! test -f "$parser" || ! test -x "$parser" || ! test "$(realpath '
            '"$parser")" = "$parser" || ! test '
            '"$(stat -c \'%u\' "$parser")" = 0; then\n'
            '  echo "AppArmor parser is unavailable or unsafe"\n'
            "  exit 1\n"
            "fi\n"
            'parser_mode="$(stat -c \'%a\' "$parser")"\n'
            'test "$((8#$parser_mode & 8#022))" -eq 0\n'
            "sudo install --owner=root --group=root --mode=0644 "
            '"$profile_source" /etc/apparmor.d/bwrap-userns-restrict\n'
            "test -f /etc/apparmor.d/bwrap-userns-restrict\n"
            'test "$(realpath /etc/apparmor.d/bwrap-userns-restrict)" = '
            "/etc/apparmor.d/bwrap-userns-restrict\n"
            "test \"$(stat -c '%u:%g' /etc/apparmor.d/bwrap-userns-restrict)\" = 0:0\n"
            "test \"$(stat -c '%a' /etc/apparmor.d/bwrap-userns-restrict)\" = 644\n"
            "sudo /usr/sbin/apparmor_parser --replace "
            "/etc/apparmor.d/bwrap-userns-restrict\n",
        )
        self.assertEqual(
            self.text.count("sudo apt-get update"),
            1,
        )
        self.assertEqual(
            self.text.count(
                "sudo apt-get install --yes --no-install-recommends "
                "bubblewrap=0.9.0-1ubuntu0.1"
            ),
            1,
        )

    def test_ci_uses_only_pinned_dependencies_existing_tools_and_local_checks(self):
        self.assertIn(
            "python -m pip install --requirement requirements-dev.txt", self.text
        )
        self.assertNotRegex(self.text.lower(), r"\b(?:brew|apk|yum|dnf)\b")
        self.assertIn("sudo apt-get update", self.text)
        self.assertIn(
            "sudo apt-get install --yes --no-install-recommends "
            "bubblewrap=0.9.0-1ubuntu0.1 "
            "apparmor=4.0.1really4.0.1-0ubuntu0.24.04.7 "
            "apparmor-profiles=4.0.1really4.0.1-0ubuntu0.24.04.7",
            self.text,
        )
        self.assertNotIn("0ubuntu0.24.04.5", self.text)
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
            "ruff check claude-code subagents_configs scripts tests",
            "ruff format --check claude-code subagents_configs scripts tests",
            "shellcheck",
            "compileall -q claude-code subagents_configs scripts tests",
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

    def test_fixed_backend_and_shellcheck_candidates_are_regular_canonical_files(self):
        self.assertIn('test -f "$candidate"', self.text)
        self.assertIn('test "$(realpath "$candidate")" = "$candidate"', self.text)
        self.assertIn(
            "test -f /usr/bin/sandbox-exec && test -x /usr/bin/sandbox-exec",
            self.text,
        )
        self.assertIn(
            'test "$(realpath /usr/bin/sandbox-exec)" = /usr/bin/sandbox-exec',
            self.text,
        )
        self.assertIn(
            "test -f /usr/bin/shellcheck && test -x /usr/bin/shellcheck",
            self.text,
        )
        self.assertIn('test "$(stat -c \'%u\' "$candidate")" = 0', self.text)
        self.assertIn("test \"$(stat -c '%u' /usr/bin/shellcheck)\" = 0", self.text)
        self.assertIn("test \"$(stat -f '%u' /usr/bin/sandbox-exec)\" = 0", self.text)

    def test_fixed_tools_reject_group_or_other_writable_modes(self):
        self.assertEqual(
            self.text.count('test "$((8#$tool_mode & 8#022))" -eq 0'),
            1,
        )
        self.assertEqual(
            self.text.count('test "$((8#$sandbox_mode & 8#022))" -eq 0'),
            1,
        )
        self.assertEqual(
            self.text.count('test "$((8#$shellcheck_mode & 8#022))" -eq 0'),
            1,
        )

    def test_validation_smoke_uses_exact_system_interpreters_per_os(self):
        self.assertIn("export VALIDATION_SYSTEM_PYTHON=/usr/bin/python3.12", self.text)
        self.assertIn(
            "export VALIDATION_SYSTEM_PYTHON=/Library/Developer/CommandLineTools/"
            "Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9\n",
            self.text,
        )
        self.assertIn(
            'if test "${{ matrix.os }}" = "ubuntu-24.04"; then\n'
            "            export VALIDATION_SYSTEM_PYTHON=/usr/bin/python3.12\n"
            "          else\n"
            "            export VALIDATION_SYSTEM_PYTHON=/Library/Developer/"
            "CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/"
            "bin/python3.9\n"
            "          fi",
            self.text,
        )

    def test_shellcheck_is_required_and_executed_only_in_ubuntu_jobs(self):
        ubuntu_gates = re.finditer(
            r"if test \"\$\{\{ matrix\.os \}\}\" = \"ubuntu-24\.04\"; then"
            r"(?P<body>[\s\S]*?)\n          fi",
            self.text,
        )
        body = next(
            (
                match.group("body")
                for match in ubuntu_gates
                if "shellcheck" in match.group("body")
            ),
            None,
        )
        self.assertIsNotNone(body)
        self.assertIn("ShellCheck is unavailable", body)
        self.assertIn('"$shellcheck" install.sh', body)
        self.assertEqual(self.text.count('"$shellcheck" install.sh'), 1)
        self.assertIn("VALIDATION_SMOKE_MODE=required", self.text)

    def test_action_lines_are_all_sha_pinned(self):
        for line in self.text.splitlines():
            if "uses:" in line:
                self.assertRegex(line, r"uses:\s+[^@\s]+@[0-9a-f]{40}")

    def test_python_bytecode_writes_are_confined_to_ci_root(self):
        self.assertRegex(
            self.text,
            r'mkdir -p "\$ci_root/[^"\n]*pycache[^"\n]*"',
        )
        self.assertRegex(
            self.text,
            r'chmod 700[^\n]*"\$ci_root/[^"\n]*pycache[^"\n]*"',
        )
        self.assertRegex(
            self.text,
            r'export PYTHONDONTWRITEBYTECODE="?1"?',
        )
        self.assertRegex(
            self.text,
            r'export PYTHONPYCACHEPREFIX="\$ci_root/[^"\n]*"',
        )

    def test_ruff_cache_writes_are_confined_to_ci_root(self):
        self.assertRegex(
            self.text,
            r'mkdir -p "\$ci_root/[^"\n]*ruff[^"\n]*"',
        )
        self.assertRegex(
            self.text,
            r'chmod 700[^\n]*"\$ci_root/[^"\n]*ruff[^"\n]*"',
        )
        self.assertRegex(
            self.text,
            r'export RUFF_CACHE_DIR="\$ci_root/[^"\n]*"',
        )

    def test_checkout_cleanliness_is_enforced_fail_closed(self):
        self.assertRegex(
            self.text,
            r'if\s+test\s+-n\s+"\$checkout_status";\s+then',
        )
        self.assertRegex(
            self.text,
            r"git status --short[\s\S]*?exit 1",
        )

    def test_checkout_status_errors_fail_closed(self):
        self.assertRegex(
            self.text,
            r'if\s+!\s+checkout_status="\$\(git status --short\)";\s+then',
        )
        self.assertRegex(
            self.text,
            r'checkout_status="\$\(git status --short\)"[\s\S]*?exit 1',
        )

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
            self.text.replace("8#$tool_mode & 8#022", "8#$tool_mode & 8#000", 1),
            self.text.replace(
                "python -m pip install --requirement requirements-dev.txt",
                "python -m pip install bwrap",
                1,
            ),
            f"{self.text}\nrun: sudo true\n",
            f"{self.text}\nrun: apt-get install shellcheck\n",
            f"{self.text}\nrun: brew install shellcheck\n",
            self.text.replace(
                "          sudo /usr/sbin/apparmor_parser --replace "
                "/etc/apparmor.d/bwrap-userns-restrict\n",
                "",
                1,
            ),
            self.text.replace(
                "          sudo /usr/sbin/apparmor_parser --replace "
                "/etc/apparmor.d/bwrap-userns-restrict\n",
                "          sudo sysctl -w "
                "kernel.apparmor_restrict_unprivileged_userns=0\n"
                "          sudo /usr/sbin/apparmor_parser --replace "
                "/etc/apparmor.d/bwrap-userns-restrict\n",
                1,
            ),
            self.text.replace(
                "apparmor=4.0.1really4.0.1-0ubuntu0.24.04.7",
                "apparmor=4.0.1really4.0.1-0ubuntu0.24.04.5",
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-80:]):
                self.assertTrue(self._unsafe_mutations(mutation))


if __name__ == "__main__":
    unittest.main()
