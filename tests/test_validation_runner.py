from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.validation_isolated_test_support import (
    make_repository,
    system_executable,
    trusted_parent_tempdir,
)


def _system_launcher() -> Path:
    return system_executable("true")


def _system_python() -> Path:
    return system_executable("python3")


class RunnerTests(unittest.TestCase):
    def test_trusted_executable_directories_are_canonical_and_skip_aliases(self):
        from scripts.validation_isolation.runner import _trusted_executable_dirs

        directories = _trusted_executable_dirs(_system_python())
        self.assertTrue(directories)
        for directory in directories:
            self.assertEqual(directory, directory.resolve(strict=True))
        for candidate in (Path("/usr/bin"), Path("/bin")):
            if candidate.exists() and candidate.resolve(strict=True) != candidate:
                self.assertNotIn(candidate, directories)

    def test_runs_probe_before_child_and_preserves_argv_boundary(self):
        from scripts.validation_isolation.runner import run_isolated

        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            calls = []

            def process_runner(argv, cwd, env, timeout):
                calls.append((tuple(argv), cwd, dict(env), timeout))
                return subprocess.CompletedProcess(argv, 0, "ok\n", "")

            with (
                patch(
                    "scripts.validation_isolation.runner.locate_worktree",
                    return_value=repository,
                ),
                patch("scripts.validation_isolation.runner.select_backend") as select,
            ):
                select.return_value = type(
                    "Backend",
                    (),
                    {
                        "name": "macos",
                        "launcher": _system_launcher(),
                        "python_executable": _system_python(),
                    },
                )()
                with patch("scripts.validation_isolation.runner.probe_backend"):
                    result = run_isolated(
                        ("python3", "-c", "print('a b')", "--"),
                        repository,
                        "darwin",
                        process_runner,
                    )

            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "ok\n")
            self.assertEqual(len(calls), 1)
            self.assertIn("print('a b')", calls[0][0])
            self.assertEqual(calls[0][1].name, "snapshot")

    def test_child_failure_is_returned_with_bounded_output(self):
        from scripts.validation_isolation.runner import run_isolated

        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            huge = "x" * 100_000

            def process_runner(argv, cwd, env, timeout):
                del cwd, env, timeout
                return subprocess.CompletedProcess(argv, 23, huge, huge)

            with (
                patch("scripts.validation_isolation.runner.select_backend") as select,
                patch("scripts.validation_isolation.runner.probe_backend"),
            ):
                select.return_value = type(
                    "Backend",
                    (),
                    {
                        "name": "macos",
                        "launcher": _system_launcher(),
                        "python_executable": _system_python(),
                    },
                )()
                result = run_isolated(("false",), repository, "darwin", process_runner)

            self.assertEqual(result.returncode, 23)
            self.assertLessEqual(len(result.stdout), 8192)
            self.assertLessEqual(len(result.stderr), 8192)

    def test_non_string_child_output_is_blocked_without_payload(self):
        from scripts.validation_isolation.runner import run_isolated

        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            with (
                patch("scripts.validation_isolation.runner.select_backend") as select,
                patch("scripts.validation_isolation.runner.probe_backend"),
            ):
                select.return_value = type(
                    "Backend",
                    (),
                    {
                        "name": "macos",
                        "launcher": _system_launcher(),
                        "python_executable": _system_python(),
                    },
                )()
                with self.assertRaisesRegex(ValueError, "output is invalid") as raised:
                    run_isolated(
                        ("false",),
                        repository,
                        "darwin",
                        lambda *args: subprocess.CompletedProcess(
                            args[0], 0, b"SECRET", ""
                        ),
                    )
            self.assertNotIn("SECRET", str(raised.exception))

    def test_runner_passes_raw_sys_executable_to_trust_validation(self):
        from scripts.validation_isolation import runner

        with trusted_parent_tempdir() as temporary:
            root = Path(temporary).resolve()
            repository = make_repository(root)
            real = root / "trusted-python"
            real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            real.chmod(0o755)
            link = root / "python-link"
            link.symlink_to(real)
            with (
                patch.object(runner.sys, "executable", str(link)),
                patch.object(
                    runner,
                    "build_child_environment",
                    return_value={"PATH": "/usr/bin"},
                ),
                patch.object(runner, "probe_backend"),
                patch.object(
                    runner,
                    "select_backend",
                    wraps=__import__(
                        "scripts.validation_isolation.backend",
                        fromlist=["select_backend"],
                    ).select_backend,
                ) as select,
            ):
                with self.assertRaisesRegex(ValueError, "canonical|symlink"):
                    runner.run_isolated(("false",), repository, "darwin")
            self.assertEqual(select.call_args.args[3], link)

    def test_requested_launch_rechecks_identity_after_argv_construction(self):
        from scripts.validation_isolation import backend as backend_module
        from scripts.validation_isolation import runner

        with trusted_parent_tempdir() as temporary:
            root = Path(temporary).resolve()
            repository = make_repository(root)
            interpreter = root / "python"
            interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            interpreter.chmod(0o755)
            launcher = _system_launcher()
            interpreter_item = os.lstat(interpreter)
            launcher_item = os.lstat(launcher)
            spec = backend_module.BackendSpec(
                "macos",
                launcher,
                interpreter,
                (launcher_item.st_dev, launcher_item.st_ino),
                (interpreter_item.st_dev, interpreter_item.st_ino),
            )
            replacement = root / "replacement"
            replacement.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            replacement.chmod(0o755)
            calls = []
            real_build = runner.build_backend_argv

            def build_then_replace(*args, **kwargs):
                result = real_build(*args, **kwargs)
                interpreter.unlink()
                replacement.rename(interpreter)
                return result

            with (
                patch.object(runner.sys, "executable", str(_system_python())),
                patch.object(runner, "select_backend", return_value=spec),
                patch.object(runner, "probe_backend"),
                patch(
                    "scripts.validation_isolation.backend._validate_trusted_interpreter"
                ),
                patch.object(
                    runner, "build_backend_argv", side_effect=build_then_replace
                ),
            ):
                with self.assertRaisesRegex(ValueError, "changed"):
                    runner.run_isolated(
                        ("false",),
                        repository,
                        "darwin",
                        lambda *args: calls.append(args),
                    )
            self.assertEqual(calls, [])

    def test_requested_launch_rejects_private_root_replacement(self):
        from scripts.validation_isolation import backend as backend_module
        from scripts.validation_isolation import runner

        with trusted_parent_tempdir() as temporary:
            root = Path(temporary).resolve()
            repository = make_repository(root)
            interpreter = root / "python"
            interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            interpreter.chmod(0o755)
            launcher = _system_launcher()
            interpreter_item = os.lstat(interpreter)
            launcher_item = os.lstat(launcher)
            spec = backend_module.BackendSpec(
                "macos",
                launcher,
                interpreter,
                (launcher_item.st_dev, launcher_item.st_ino),
                (interpreter_item.st_dev, interpreter_item.st_ino),
            )
            real_build = runner.build_backend_argv
            calls = []

            def run_once(target_name):
                def build_then_replace(backend, command, snapshot, temp, env):
                    result = real_build(backend, command, snapshot, temp, env)
                    target = snapshot if target_name == "snapshot" else temp
                    displaced = target.with_name(f"{target.name}-displaced")
                    target.rename(displaced)
                    target.mkdir(mode=0o700)
                    return result

                with (
                    patch.object(runner.sys, "executable", str(_system_python())),
                    patch.object(runner, "select_backend", return_value=spec),
                    patch.object(runner, "probe_backend"),
                    patch(
                        "scripts.validation_isolation.backend._validate_trusted_interpreter"
                    ),
                    patch.object(
                        runner, "build_backend_argv", side_effect=build_then_replace
                    ),
                ):
                    with self.assertRaisesRegex(ValueError, "root changed"):
                        runner.run_isolated(
                            ("false",), repository, "darwin", process_runner
                        )

            def process_runner(*args):
                calls.append(args)
                return subprocess.CompletedProcess(args[0], 0, "", "")

            for target_name in ("snapshot", "temp"):
                with self.subTest(target=target_name):
                    run_once(target_name)
            self.assertEqual(calls, [])

    def test_source_mutation_is_checked_even_after_child_failure(self):
        from scripts.validation_isolation.runner import run_isolated

        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))

            def process_runner(argv, cwd, env, timeout):
                del cwd, env, timeout
                (repository / "tracked.txt").write_text("mutated\n", encoding="utf-8")
                return subprocess.CompletedProcess(argv, 9, "", "failed")

            with (
                patch("scripts.validation_isolation.runner.select_backend") as select,
                patch("scripts.validation_isolation.runner.probe_backend"),
            ):
                select.return_value = type(
                    "Backend",
                    (),
                    {
                        "name": "macos",
                        "launcher": _system_launcher(),
                        "python_executable": _system_python(),
                    },
                )()
                with self.assertRaises(ValueError):
                    run_isolated(("false",), repository, "darwin", process_runner)

    def test_probe_failure_blocks_child(self):
        from scripts.validation_isolation.runner import run_isolated

        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            child_calls = []

            def process_runner(*args, **kwargs):
                child_calls.append((args, kwargs))
                return subprocess.CompletedProcess((), 0, "", "")

            with (
                patch("scripts.validation_isolation.runner.select_backend") as select,
                patch(
                    "scripts.validation_isolation.runner.probe_backend",
                    side_effect=ValueError("blocked"),
                ),
            ):
                select.return_value = type(
                    "Backend",
                    (),
                    {
                        "name": "macos",
                        "launcher": _system_launcher(),
                        "python_executable": _system_python(),
                    },
                )()
                with self.assertRaises(ValueError):
                    run_isolated(("false",), repository, "darwin", process_runner)
            self.assertEqual(child_calls, [])

    def test_timeout_is_sanitized_and_cleanup_runs(self):
        from scripts.validation_isolation.runner import run_isolated

        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            cleanup = []

            def process_runner(argv, cwd, env, timeout):
                del cwd, env, timeout
                raise subprocess.TimeoutExpired(
                    argv, 1, output="SECRET", stderr="SECRET"
                )

            with (
                patch("scripts.validation_isolation.runner.select_backend") as select,
                patch("scripts.validation_isolation.runner.probe_backend"),
                patch(
                    "scripts.validation_isolation.runner.shutil.rmtree",
                    side_effect=lambda path, ignore_errors: cleanup.append(
                        (path, ignore_errors)
                    ),
                ),
            ):
                select.return_value = type(
                    "Backend",
                    (),
                    {
                        "name": "macos",
                        "launcher": _system_launcher(),
                        "python_executable": _system_python(),
                    },
                )()
                with self.assertRaisesRegex(ValueError, "timed out") as raised:
                    run_isolated(("false",), repository, "darwin", process_runner)
            self.assertNotIn("SECRET", str(raised.exception))
            self.assertEqual(len(cleanup), 1)

    def test_mutation_error_overrides_child_and_cleanup_error(self):
        from scripts.validation_isolation.runner import run_isolated

        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            with (
                patch("scripts.validation_isolation.runner.select_backend") as select,
                patch("scripts.validation_isolation.runner.probe_backend"),
                patch(
                    "scripts.validation_isolation.runner.assert_checkout_unchanged",
                    side_effect=ValueError("mutation"),
                ),
                patch(
                    "scripts.validation_isolation.runner.shutil.rmtree",
                    side_effect=OSError("cleanup secret"),
                ) as cleanup,
            ):
                select.return_value = type(
                    "Backend",
                    (),
                    {
                        "name": "macos",
                        "launcher": _system_launcher(),
                        "python_executable": _system_python(),
                    },
                )()
                with self.assertRaisesRegex(ValueError, "mutation"):
                    run_isolated(
                        ("false",),
                        repository,
                        "darwin",
                        lambda *args: subprocess.CompletedProcess(args[0], 9, "", ""),
                    )
            cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
