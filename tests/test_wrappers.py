import json
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
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


class WrapperTests(unittest.TestCase):
    def test_every_wrapper_is_thin_private_and_executable(self):
        for name in WRAPPERS:
            path = ROOT / name
            self.assertTrue(path.exists(), name)
            self.assertTrue(path.stat().st_mode & stat.S_IXUSR, name)
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("#!/bin/sh\nset -eu\numask 077\n"), name)
            self.assertNotIn("python3 - <<", text, name)
            self.assertNotIn("eval ", text, name)
            self.assertNotIn("sh -c", text, name)
            self.assertNotRegex(text, r"\b(curl|wget|sudo)\b")
            self.assertIn("PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", text)
            self.assertIn("export PATH", text)
            self.assertIn("CDPATH='' cd --", text)
            self.assertIn("pwd -P", text)
            self.assertRegex(text, r"(?m)^exec .+\"\$@\"$")
            subprocess.run(["sh", "-n", str(path)], check=True)  # noqa: S603, S607

    def test_compatibility_wrappers_select_one_target_and_preserve_argv(self):
        expected = {
            "install-codex.sh": ("install.sh", "codex"),
            "uninstall-codex.sh": ("uninstall.sh", "codex"),
            "install-opencode.sh": ("install.sh", "opencode"),
            "uninstall-opencode.sh": ("uninstall.sh", "opencode"),
            "install-claude-code.sh": ("install.sh", "claude-code"),
            "uninstall-claude-code.sh": ("uninstall.sh", "claude-code"),
        }
        for name, (generic, target) in expected.items():
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn(f'exec "$SCRIPT_DIR/{generic}" --target {target} "$@"', text)

    def test_generic_wrappers_use_isolated_python_and_fixed_path(self):
        for name, operation in (
            ("install.sh", "install"),
            ("uninstall.sh", "uninstall"),
        ):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn(
                f'exec python3 -I "$SCRIPT_DIR/scripts/manage-subagents-configs.py" '
                f'{operation} "$@"',
                text,
            )

    def test_fixed_path_is_set_before_dirname_and_fake_python_is_ignored(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            fake_dir = Path(directory)
            (fake_dir / "dirname").write_text(
                "#!/bin/sh\nprintf '%%s\\n' dirname-ran > %s\nexit 91\n"
                % (fake_dir / "dirname-marker"),
                encoding="utf-8",
            )
            (fake_dir / "python3").write_text(
                "#!/bin/sh\nprintf '%%s\\n' python-ran > %s\nexit 92\n"
                % (fake_dir / "python-marker"),
                encoding="utf-8",
            )
            (fake_dir / "dirname").chmod(0o700)
            (fake_dir / "python3").chmod(0o700)
            result = subprocess.run(  # noqa: S603
                [str(ROOT / "install.sh"), "--help"],
                env={"PATH": str(fake_dir)},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((fake_dir / "dirname-marker").exists())
            self.assertFalse((fake_dir / "python-marker").exists())

    def test_compatibility_file_symlink_fails_closed_without_adjacent_script(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            sandbox = Path(directory)
            marker = sandbox / "marker"
            (sandbox / "install.sh").write_text(
                f"#!/bin/sh\nprintf x > {marker}\n", encoding="utf-8"
            )
            (sandbox / "install.sh").chmod(0o700)
            alias = sandbox / "install-codex.sh"
            alias.symlink_to(ROOT / "install-codex.sh")
            result = subprocess.run(  # noqa: S603
                [str(alias), "--help"], capture_output=True, text=True, timeout=10
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_directory_symlink_resolves_to_physical_repository(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            alias_dir = Path(directory) / "repo-link"
            alias_dir.symlink_to(ROOT, target_is_directory=True)
            result = subprocess.run(  # noqa: S603
                [str(alias_dir / "install.sh"), "--help"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Usage: install.sh", result.stdout)

    def test_every_wrapper_real_subprocess_preserves_complex_argv(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            sandbox = Path(directory)
            for path in ROOT.glob("*.sh"):
                shutil.copy2(path, sandbox / path.name)
                (sandbox / path.name).chmod(0o700)
            script = sandbox / "scripts/manage-subagents-configs.py"
            script.parent.mkdir()
            script.write_text(
                "import json, os, sys\n"
                "with open(os.environ['CAPTURE'], 'w') as handle:\n"
                "    json.dump(sys.argv[1:], handle)\n",
                encoding="utf-8",
            )
            capture = sandbox / "argv.json"
            weird = ["value with spaces", "glob[*]?", "--leading-dash"]
            for wrapper in WRAPPERS:
                capture.unlink(missing_ok=True)
                operation = "install" if wrapper.startswith("install") else "uninstall"
                result = subprocess.run(  # noqa: S603
                    [str(sandbox / wrapper), *weird],
                    env={"CAPTURE": str(capture)},
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, (wrapper, result.stderr))
                captured = json.loads(capture.read_text(encoding="utf-8"))
                self.assertEqual(captured[0], operation)
                if wrapper in {"install.sh", "uninstall.sh"}:
                    self.assertEqual(captured[1:], weird)
                else:
                    target = wrapper.removeprefix(operation + "-").removesuffix(".sh")
                    self.assertEqual(captured[1:3], ["--target", target])
                    self.assertEqual(captured[3:], weird)


class EntryPointTests(unittest.TestCase):
    def test_script_refuses_old_python_before_engine_import(self):
        source = (ROOT / "scripts/manage-subagents-configs.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("sys.version_info", source)
        self.assertIn("(3, 11)", source)
        self.assertLess(
            source.index("sys.version_info"), source.index("from subagents_configs")
        )

    def test_old_python_guard_executes_before_path_mutation_or_engine_import(self):
        source = ROOT / "scripts/manage-subagents-configs.py"
        original_path = list(sys.path)
        old_version = (3, 10, 0)
        original_import = __import__

        def import_trap(name, *args, **kwargs):
            if name.startswith("subagents_configs"):
                raise AssertionError("engine import attempted")
            return original_import(name, *args, **kwargs)

        from io import StringIO

        with (
            patch.object(sys, "version_info", old_version),
            patch("builtins.__import__", side_effect=import_trap) as importer,
            patch.object(sys, "stderr", StringIO()),
        ):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_path(str(source), run_name="__main__")
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(sys.path, original_path)
        self.assertFalse(
            any(
                call.args and str(call.args[0]).startswith("subagents_configs")
                for call in importer.call_args_list
            )
        )

    def test_module_entry_supports_help_and_invalid_operation(self):
        help_result = subprocess.run(
            [sys.executable, "-m", "subagents_configs", "install", "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("Usage: install.sh", help_result.stdout)
        invalid_result = subprocess.run(
            [sys.executable, "-m", "subagents_configs"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(invalid_result.returncode, 2)
