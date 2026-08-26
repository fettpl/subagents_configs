from __future__ import annotations

import ast
import re
import stat
import unittest
from pathlib import Path

from subagents_configs.models import Target
from subagents_configs.targets import DESCRIPTOR_ORDER, descriptor_for
from tests.helpers import private_tempdir, real_repository

REPOSITORY = real_repository()
WRAPPERS = (
    "install.sh",
    "uninstall.sh",
    "install-codex.sh",
    "uninstall-codex.sh",
    "install-opencode.sh",
    "uninstall-opencode.sh",
    "install-claude-code.sh",
    "uninstall-claude-code.sh",
)
ACTIVE_PYTHON = tuple(
    sorted(
        (
            *((REPOSITORY / "subagents_configs").rglob("*.py")),
            *(REPOSITORY / "scripts/validation_isolation").rglob("*.py"),
            REPOSITORY / "scripts/run-validation-isolated.py",
            REPOSITORY / "scripts/manage-subagents-configs.py",
            REPOSITORY / "scripts/generate-catalogs.py",
            REPOSITORY / "scripts/validate-catalogs.py",
            REPOSITORY / "claude-code/hooks/code-validator-pretooluse.py",
        ),
        key=lambda path: path.as_posix(),
    )
)
EXPECTED_ACTIVE_PYTHON = frozenset(
    REPOSITORY / relative
    for relative in (
        "subagents_configs/__init__.py",
        "subagents_configs/__main__.py",
        "subagents_configs/blocks.py",
        "subagents_configs/compatibility.py",
        "subagents_configs/cli.py",
        "subagents_configs/catalog_policy.py",
        "subagents_configs/diagnostics.py",
        "subagents_configs/errors.py",
        "subagents_configs/filesystem.py",
        "subagents_configs/formats.py",
        "subagents_configs/locks.py",
        "subagents_configs/models.py",
        "subagents_configs/orchestrator.py",
        "subagents_configs/paths.py",
        "subagents_configs/planning.py",
        "subagents_configs/profiles.py",
        "subagents_configs/recovery.py",
        "subagents_configs/state.py",
        "subagents_configs/state_schema.py",
        "subagents_configs/targets.py",
        "subagents_configs/transaction.py",
        "scripts/manage-subagents-configs.py",
        "scripts/generate-catalogs.py",
        "scripts/validate-catalogs.py",
        "scripts/run-validation-isolated.py",
        "scripts/validation_isolation/__init__.py",
        "scripts/validation_isolation/backend.py",
        "scripts/validation_isolation/cli.py",
        "scripts/validation_isolation/environment.py",
        "scripts/validation_isolation/errors.py",
        "scripts/validation_isolation/git_snapshot.py",
        "scripts/validation_isolation/models.py",
        "scripts/validation_isolation/runner.py",
        "claude-code/hooks/code-validator-pretooluse.py",
    )
)


def _tree_calls(path: Path) -> list[ast.Call]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _call_name(node: ast.Call) -> str:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        parts: list[str] = []
        current: ast.AST | None = function
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name in {"os", "subprocess"}:
                    aliases[imported.asname or imported.name] = imported.name
        elif isinstance(node, ast.ImportFrom) and node.module in {"os", "subprocess"}:
            for imported in node.names:
                if imported.name != "*":
                    aliases[imported.asname or imported.name] = (
                        f"{node.module}.{imported.name}"
                    )
    return aliases


def _canonical_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _canonical_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _shell_argv(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, (ast.List, ast.Tuple)):
            continue
        values = [_string_value(value) for value in child.elts]
        for index in range(len(values) - 1):
            first, second = values[index], values[index + 1]
            if first in {"sh", "bash", "/bin/sh", "/bin/bash"} and second == "-c":
                return True
    return False


def _looks_like_failure_injection(value: str) -> bool:
    return bool(re.search(r"failure[-_ ]?inject", value, re.IGNORECASE))


def _security_issues_from_source(source: str) -> list[str]:
    tree = ast.parse(source)
    aliases = _import_aliases(tree)
    issues: list[str] = []
    dangerous_calls = {
        "eval",
        "exec",
        "os.system",
        "os.popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        name = _canonical_name(call.func, aliases)
        if name in dangerous_calls:
            issues.append(f"dynamic execution: {name}")
        if name in {"os.getenv", "os.environ.get"}:
            issues.append(f"ambient failure-injection lookup: {name}")
        if name == "os.putenv":
            issues.append("ambient failure-injection mutation: os.putenv")
        if name.endswith(".get") and call.args:
            value = _string_value(call.args[0])
            if value is not None and _looks_like_failure_injection(value):
                issues.append("mapping failure-injection lookup")
        if name.startswith("subprocess."):
            for keyword in call.keywords:
                if keyword.arg == "shell":
                    if not (
                        isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is False
                    ):
                        issues.append("subprocess shell mode")
            if _shell_argv(call):
                issues.append("shell -c argv")
    if re.search(
        r"(?:^|[\"' (/:])(?:/[^\s\"']*/)?(?:sh|bash)\s+-c(?:$|[\s\"'])", source
    ):
        issues.append("shell -c command string")
    if re.search(r"\b(?:curl|wget)\b[^\n|]*\|", source):
        issues.append("remote pipe")
    if re.search(r"\bsudo\b", source):
        issues.append("privilege escalation")
    if "gpt-5.4-mini" in source:
        issues.append("stale model")
    if re.search(r"pi-coding-agent|(^|[^a-z])pi([^a-z]|$)", source.casefold()):
        issues.append("removed Pi client")
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            base = _canonical_name(node.value, aliases)
            key = _string_value(node.slice)
            if (
                base == "os.environ"
                and key is not None
                and _looks_like_failure_injection(key)
            ):
                issues.append("environment failure-injection lookup")
            if key is not None and _looks_like_failure_injection(key):
                if isinstance(node.ctx, ast.Store):
                    issues.append("mapping failure-injection mutation")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.search(r"--failure[-_]inject|FAILURE[-_]INJECTOR", node.value):
                issues.append("public failure-injection name")
    return issues


def _wrapper_issues_from_source(
    source: str, expected_lines: tuple[str, ...] | None = None
) -> list[str]:
    lines = tuple(source.splitlines())
    issues: list[str] = []
    if len(lines) < 11:
        issues.append("wrapper shape")
    if sum(line.startswith("exec ") for line in lines) != 1:
        issues.append("wrapper exec count")
    if not lines or not lines[-1].startswith("exec "):
        issues.append("wrapper must terminate in exec")
    if re.search(r"\beval\b|\b(?:sh|bash)\s+-c\b|\bsudo\b|python(?:3)?\s+-c", source):
        issues.append("wrapper dynamic execution")
    if "failure_injector" in source or re.search(
        r"gpt-5\.4-mini|pi-coding-agent|(^|[^a-z])pi([^a-z]|$)",
        source.casefold(),
    ):
        issues.append("wrapper stale or removed client")
    if expected_lines is not None and lines != expected_lines:
        issues.append("wrapper is not an approved thin shape")
    return issues


def _expected_wrapper_lines(relative: str) -> tuple[str, ...]:
    if relative in {"install.sh", "uninstall.sh"}:
        operation = relative.removesuffix(".sh")
        final = (
            f'exec "$PYTHON" -I "$SCRIPT_DIR/scripts/manage-subagents-configs.py" '
            f'{operation} "$@"'
        )
        return (
            "#!/bin/sh",
            "set -eu",
            "umask 077",
            "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            "export PATH",
            'if [ -L "$0" ]; then',
            '    echo "error: wrapper invocation must not be a symlink" >&2',
            "    exit 2",
            "fi",
            'SCRIPT_DIR=$(CDPATH=\'\' cd -- "$(dirname -- "$0")" && pwd -P)',
            'if [ "${SUBAGENTS_CONFIGS_PYTHON+x}" = x ]; then',
            "    PYTHON=$SUBAGENTS_CONFIGS_PYTHON",
            '    case "$PYTHON" in',
            "        /*) ;;",
            '        *) echo "error: SUBAGENTS_CONFIGS_PYTHON must be an '
            'absolute path" >&2; exit 2 ;;',
            "    esac",
            '    if [ ! -f "$PYTHON" ] || [ ! -x "$PYTHON" ]; then',
            '        echo "error: SUBAGENTS_CONFIGS_PYTHON must name an '
            'executable file" >&2',
            "        exit 2",
            "    fi",
            "else",
            "    PYTHON=python3",
            "fi",
            final,
        )
    else:
        operation, target = relative.removesuffix(".sh").split("-", 1)
        final = f'exec "$SCRIPT_DIR/{operation}.sh" --target {target} "$@"'
    return (
        "#!/bin/sh",
        "set -eu",
        "umask 077",
        "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        "export PATH",
        'if [ -L "$0" ]; then',
        '    echo "error: wrapper invocation must not be a symlink" >&2',
        "    exit 2",
        "fi",
        'SCRIPT_DIR=$(CDPATH=\'\' cd -- "$(dirname -- "$0")" && pwd -P)',
        final,
    )


class StaticSecurityTests(unittest.TestCase):
    def test_active_python_inventory_is_exact_and_nonempty(self):
        self.assertTrue(ACTIVE_PYTHON)
        self.assertEqual(set(ACTIVE_PYTHON), EXPECTED_ACTIVE_PYTHON)
        self.assertTrue(all(path.is_file() for path in ACTIVE_PYTHON))

    def test_negative_mutation_fixtures_trigger_each_static_guard(self):
        fixtures = {
            "shell-alias.py": "import subprocess as sp\nsp.run(['bash', '-c', 'x'])\n",
            "popen-alias.py": (
                "import os as operating_system\noperating_system.popen('x')\n"
            ),
            "shell-string.py": "command = 'sh -c echo unsafe'\n",
            "env-getenv.py": "import os\nos.getenv('FAILURE_INJECTOR')\n",
            "env-environ-get.py": "import os\nos.environ.get('FAILURE_INJECTOR')\n",
            "env-subscript.py": "import os\nos.environ['FAILURE_INJECTOR'] = 'x'\n",
            "env-putenv.py": "import os\nos.putenv('FAILURE_INJECTOR', 'x')\n",
            "mapping-get.py": "settings = {}\nsettings.get('failure_injector')\n",
            "mapping-subscript.py": (
                "settings = {}\nsettings['failure_injector'] = 'x'\n"
            ),
            "public-option.py": "parser.add_argument('--failure-injector')\n",
        }
        with private_tempdir() as directory:
            for name, source in fixtures.items():
                with self.subTest(fixture=name):
                    path = Path(directory) / name
                    path.write_text(source, encoding="utf-8")
                    expected_issue = {
                        "shell-alias.py": "shell -c argv",
                        "popen-alias.py": "dynamic execution: os.popen",
                        "shell-string.py": "shell -c command string",
                        "env-getenv.py": (
                            "ambient failure-injection lookup: os.getenv"
                        ),
                        "env-environ-get.py": (
                            "ambient failure-injection lookup: os.environ.get"
                        ),
                        "env-subscript.py": "environment failure-injection lookup",
                        "env-putenv.py": (
                            "ambient failure-injection mutation: os.putenv"
                        ),
                        "mapping-get.py": "mapping failure-injection lookup",
                        "mapping-subscript.py": "mapping failure-injection mutation",
                        "public-option.py": "public failure-injection name",
                    }[name]
                    self.assertIn(expected_issue, _security_issues_from_source(source))
            wrapper = Path(directory) / "wrapper.sh"
            wrapper.write_text(
                "#!/bin/sh\nset -eu\npython3 -c 'print(1)'\n",
                encoding="utf-8",
            )
            self.assertTrue(_wrapper_issues_from_source(wrapper.read_text()))

    def test_active_python_has_no_dynamic_shell_or_remote_execution_constructs(self):
        self.assertTrue(ACTIVE_PYTHON)
        self.assertEqual(set(ACTIVE_PYTHON), EXPECTED_ACTIVE_PYTHON)
        for path in ACTIVE_PYTHON:
            with self.subTest(path=path.relative_to(REPOSITORY)):
                source = path.read_text(encoding="utf-8")
                self.assertEqual(_security_issues_from_source(source), [])

    def test_negative_fixture_and_policy_prose_are_outside_executable_scan_scope(self):
        with private_tempdir() as directory:
            fixture = Path(directory) / "negative-fixture.py"
            fixture.write_text('eval("fixture")\n', encoding="utf-8")
            self.assertNotIn(fixture, ACTIVE_PYTHON)
            self.assertEqual(
                len(
                    [
                        call
                        for call in _tree_calls(fixture)
                        if _call_name(call) == "eval"
                    ]
                ),
                1,
            )
        policy = REPOSITORY / "rules/SUBAGENT_ROUTING.md"
        self.assertTrue(policy.is_file())
        self.assertNotIn(policy, ACTIVE_PYTHON)

    def test_native_and_validation_inventories_are_complete_and_non_pi(self):
        expected_roles = {
            "code-explorer",
            "code-reviewer",
            "code-validator",
            "quick-implementer",
            "implementer",
            "commit-pusher",
        }
        for target in DESCRIPTOR_ORDER:
            descriptor = descriptor_for(target)
            source_directory = {
                Target.CODEX: REPOSITORY / "agents",
                Target.OPENCODE: REPOSITORY / "opencode/agents",
                Target.CLAUDE_CODE: REPOSITORY / "claude-code/agents",
            }[target]
            suffix = ".toml" if target is Target.CODEX else ".md"
            self.assertEqual(
                {path.stem for path in source_directory.glob(f"*{suffix}")},
                expected_roles,
            )
            runtime_sources = {
                source.source.as_posix()
                for source in descriptor.sources
                if source.kind == "validation-runtime"
            }
            runtime_files = {
                path.relative_to(REPOSITORY).as_posix()
                for path in (REPOSITORY / "scripts/validation_isolation").glob("*.py")
            }
            runtime_files.add("scripts/run-validation-isolated.py")
            self.assertEqual(runtime_sources, runtime_files)
            self.assertNotIn("pi-coding-agent", " ".join(runtime_sources).casefold())
            self.assertNotIn(
                "pi", {source.identifier.casefold() for source in descriptor.sources}
            )

    def test_wrappers_are_private_fixed_path_thin_delegators(self):
        for relative in WRAPPERS:
            path = REPOSITORY / relative
            with self.subTest(wrapper=relative):
                self.assertTrue(path.is_file())
                self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o022, 0)
                source = path.read_text(encoding="utf-8")
                expected = _expected_wrapper_lines(relative)
                self.assertEqual(
                    _wrapper_issues_from_source(source, expected),
                    [],
                )
                self.assertRegex(source, r"(?m)^umask 077$")
                self.assertRegex(
                    source, r"(?m)^PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin$"
                )
                self.assertIn("export PATH", source)
                self.assertIn('if [ -L "$0" ]', source)
                self.assertIn("CDPATH='' cd --", source)
                self.assertNotRegex(source, r"\beval\b|\bsh\s+-c\b|\bsudo\b")
                self.assertNotIn("failure_injector", source)
                self.assertNotRegex(source, r"python(?:3)?\s+-c")
                self.assertRegex(source, r"(?m)^exec .+$")
                if relative in {"install.sh", "uninstall.sh"}:
                    self.assertIn("SUBAGENTS_CONFIGS_PYTHON", source)
                    self.assertIn("PYTHON=python3", source)
                    self.assertIn(
                        'exec "$PYTHON" -I '
                        '"$SCRIPT_DIR/scripts/manage-subagents-configs.py"',
                        source,
                    )
                else:
                    base = (
                        "install.sh"
                        if relative.startswith("install-")
                        else "uninstall.sh"
                    )
                    self.assertIn(f'"$SCRIPT_DIR/{base}"', source)

    def test_failure_injector_is_only_a_direct_python_dependency(self):
        cli_source = (REPOSITORY / "subagents_configs/cli.py").read_text(
            encoding="utf-8"
        )
        entry_source = (REPOSITORY / "scripts/manage-subagents-configs.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("failure_injector", cli_source)
        self.assertNotIn("failure_injector", entry_source)
        self.assertNotRegex(cli_source, r"FAILURE_INJECTOR|failure-injector")
        self.assertNotRegex(entry_source, r"FAILURE_INJECTOR|failure-injector")
        for path in ACTIVE_PYTHON:
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("os.getenv", source)
            self.assertNotIn("os.environ.get", source)
            self.assertFalse(
                any(
                    "failure-injection" in issue
                    or "environment failure-injection" in issue
                    for issue in _security_issues_from_source(source)
                )
            )

    def test_routing_sources_have_no_stale_or_removed_client(self):
        for path in sorted((REPOSITORY / "rules").glob("*.md")):
            source = path.read_text(encoding="utf-8").casefold()
            with self.subTest(path=path.name):
                self.assertNotIn("gpt-5.4-mini", source)
                self.assertNotIn("pi-coding-agent", source)
                self.assertNotRegex(source, r"\bpi\s+agent\b")


if __name__ == "__main__":
    unittest.main()
