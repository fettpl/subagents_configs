from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from tests.validation_isolated_test_support import git, make_repository


def _fixed_backend_path() -> Path | None:
    candidates = (
        (Path("/usr/bin/bwrap"), Path("/bin/bwrap"))
        if sys.platform.startswith("linux")
        else (Path("/usr/bin/sandbox-exec"),)
    )
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            item = os.lstat(candidate)
        except (OSError, RuntimeError):
            continue
        if (
            resolved == candidate
            and stat.S_ISREG(item.st_mode)
            and item.st_uid == 0
            and stat.S_IMODE(item.st_mode) & 0o022 == 0
            and item.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ):
            return candidate
    return None


class ValidationInventorySmokeTests(unittest.TestCase):
    def test_casefolded_policy_excludes_mixed_case_secrets_and_caches(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            gitignore = repository / ".gitignore"
            gitignore.write_text(
                gitignore.read_text(encoding="utf-8") + "ignored-source.py\n",
                encoding="utf-8",
            )
            git(repository, "add", ".gitignore")
            git(repository, "commit", "--quiet", "-m", "ignore benign fixture")
            tracked = (
                "CrEdEnTiAlS.JSON",
                ".ENV.PROD",
                ".EnVrC",
                ".CaChE/item",
                ".RuFf_CaChE/item",
                ".CoNfIg/Gh/HoStS.YmL",
            )
            for name in tracked:
                path = repository / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("secret\n", encoding="utf-8")
            benign = repository / "ignored-source.py"
            benign.write_text("print('tracked')\n", encoding="utf-8")
            self.assertEqual(
                git(
                    repository, "check-ignore", "--quiet", "ignored-source.py"
                ).returncode,
                0,
            )
            git(
                repository,
                "add",
                "--all",
                "-f",
                *tracked,
                str(benign.relative_to(repository)),
            )
            git(repository, "commit", "--quiet", "-m", "mixed-case")

            untracked = repository / ".CoNfIg" / "source.py"
            untracked.write_text("source\n", encoding="utf-8")

            from scripts.validation_isolation.git_snapshot import list_source_paths

            paths = list_source_paths(repository)
            self.assertIn(PurePosixPath("ignored-source.py"), paths)
            self.assertIn(PurePosixPath(".CoNfIg/source.py"), paths)
            for name in tracked:
                self.assertNotIn(PurePosixPath(name), paths)


class ValidationCleanupContractTests(unittest.TestCase):
    def test_cleanup_failure_is_typed_and_never_replaces_primary_failure(self):
        from scripts.validation_isolation.runner import (
            CleanupResult,
            ValidationFailure,
            cleanup_validation_root,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir(mode=0o700)
            primary = ValidationFailure(
                "child_failed", "child output is not public evidence"
            )
            with patch(
                "scripts.validation_isolation.runner.shutil.rmtree",
                side_effect=OSError("secret path and credentials"),
            ):
                result = cleanup_validation_root(root, primary=primary)

            self.assertIsInstance(result, CleanupResult)
            self.assertEqual(result.code, "cleanup_failed")
            self.assertTrue(result.primary_present)
            self.assertNotIn("secret", repr(result).lower())
            self.assertNotIn("credentials", repr(result).lower())

    def test_cleanup_success_reports_stable_code(self):
        from scripts.validation_isolation.runner import cleanup_validation_root

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir(mode=0o700)
            result = cleanup_validation_root(root, primary=None)
            self.assertEqual(result.code, "cleaned")
            self.assertFalse(result.primary_present)

    def test_cleanup_rejects_validation_root_substitution(self):
        from scripts.validation_isolation.runner import (
            CleanupRootIdentity,
            cleanup_validation_root,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir(mode=0o700)
            identity = CleanupRootIdentity.from_path(root)
            displaced = root.with_name("root-displaced")
            root.rename(displaced)
            root.mkdir(mode=0o700)
            result = cleanup_validation_root(
                root, primary=None, expected_identity=identity
            )
            self.assertEqual(result.code, "cleanup_root_changed")
            self.assertTrue(root.exists())
            self.assertTrue(displaced.exists())

    def test_cleanup_quarantines_pinned_root_before_deleting_under_race(self):
        from scripts.validation_isolation import runner

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir(mode=0o700)
            (root / "original").write_text("original", encoding="utf-8")
            identity = runner.CleanupRootIdentity.from_path(root)
            displaced = root.with_name("root-displaced")
            raced = False
            real_rename = os.rename

            def swap_before_cleanup(source, destination):
                nonlocal raced
                if Path(source) == root and not raced:
                    real_rename(root, displaced)
                    root.mkdir(mode=0o700)
                    (root / "replacement").write_text(
                        "replacement", encoding="utf-8"
                    )
                    raced = True
                return real_rename(source, destination)

            with patch.object(
                runner.os, "rename", side_effect=swap_before_cleanup
            ):
                result = runner.cleanup_validation_root(
                    root, primary=None, expected_identity=identity
                )

            self.assertEqual(result.code, "cleanup_root_changed")
            self.assertTrue((root / "replacement").exists())
            self.assertTrue((displaced / "original").exists())


class RunnerCleanupPrecedenceTests(unittest.TestCase):
    @staticmethod
    def _backend():
        return type(
            "Backend",
            (),
            {
                "name": "macos",
                "launcher": Path("/usr/bin/true"),
                "python_executable": Path("/usr/bin/python3"),
            },
        )()

    def _run_with_cleanup_failure(
        self, child_returncode, *, probe_error=None, expect_cleanup_error=False
    ):
        from scripts.validation_isolation import runner

        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            process_calls = []
            cleanup_primary = []

            def process_runner(argv, cwd, env, timeout):
                del cwd, env, timeout
                process_calls.append(tuple(argv))
                return subprocess.CompletedProcess(argv, child_returncode, "", "")

            def cleanup_validation_root(root, *, primary, expected_identity):
                del root, expected_identity
                cleanup_primary.append(primary)
                return runner.CleanupResult("cleanup_failed", primary is not None)

            with (
                patch.object(runner, "select_backend", return_value=self._backend()),
                patch.object(runner, "verify_backend"),
                patch.object(runner, "probe_backend", side_effect=probe_error),
                patch.object(runner, "build_backend_argv", return_value=("sandbox",)),
                patch.object(
                    runner,
                    "run_verified_process",
                    side_effect=lambda *args, **kwargs: process_runner(
                        args[1], args[2], args[3], args[4]
                    ),
                ),
                patch.object(
                    runner,
                    "cleanup_validation_root",
                    side_effect=cleanup_validation_root,
                ),
            ):
                if probe_error is None:
                    if expect_cleanup_error:
                        with self.assertRaisesRegex(
                            runner.ValidationIsolationError,
                            "validation cleanup failed",
                        ) as raised:
                            runner.run_isolated(
                                ("false",), repository, "darwin", process_runner
                            )
                        result = raised.exception
                    else:
                        result = runner.run_isolated(
                            ("false",), repository, "darwin", process_runner
                        )
                else:
                    with self.assertRaisesRegex(
                        ValueError, "validation isolation probe failed"
                    ):
                        runner.run_isolated(
                            ("false",), repository, "darwin", process_runner
                        )
                    result = None
            return result, process_calls, cleanup_primary

    def test_successful_child_reports_typed_cleanup_failure(self):
        from scripts.validation_isolation import runner

        result, process_calls, cleanup_primary = self._run_with_cleanup_failure(
            0, expect_cleanup_error=True
        )
        self.assertIsInstance(result, runner.ValidationIsolationError)
        self.assertEqual(result.cleanup.code, "cleanup_failed")
        self.assertFalse(result.cleanup.primary_present)
        self.assertEqual(len(process_calls), 1)
        self.assertEqual(cleanup_primary, [None])

    def test_nonzero_child_result_wins_over_cleanup_failure(self):
        result, process_calls, cleanup_primary = self._run_with_cleanup_failure(23)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.returncode, 23)
        self.assertIn("cleanup=cleanup_failed", result.evidence)
        self.assertIsNotNone(result.cleanup)
        assert result.cleanup is not None
        self.assertEqual(result.cleanup.code, "cleanup_failed")
        self.assertEqual(len(process_calls), 1)
        self.assertEqual(len(cleanup_primary), 1)
        self.assertIsNotNone(cleanup_primary[0])

    def test_backend_failure_wins_over_cleanup_failure_and_child_never_starts(self):
        result, process_calls, cleanup_primary = self._run_with_cleanup_failure(
            0, probe_error=ValueError("backend credentials and raw diagnostics")
        )
        self.assertIsNone(result)
        self.assertEqual(process_calls, [])
        self.assertEqual(len(cleanup_primary), 1)
        self.assertIsNotNone(cleanup_primary[0])

    def test_timeout_primary_wins_over_cleanup_failure(self):
        from scripts.validation_isolation import runner

        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            timeout = subprocess.TimeoutExpired(("false",), 1)
            with (
                patch.object(runner, "select_backend", return_value=self._backend()),
                patch.object(runner, "verify_backend"),
                patch.object(runner, "probe_backend"),
                patch.object(runner, "build_backend_argv", return_value=("sandbox",)),
                patch.object(runner, "run_verified_process", side_effect=timeout),
                patch.object(
                    runner,
                    "cleanup_validation_root",
                    return_value=runner.CleanupResult("cleanup_failed", True),
                ),
            ):
                with self.assertRaisesRegex(
                    runner.ValidationIsolationError, "validation command timed out"
                ):
                    runner.run_isolated(("false",), repository, "darwin")


class RealValidationSmokeTests(unittest.TestCase):
    def test_optional_mode_skips_before_backend_selection(self):
        with (
            patch.dict(os.environ, {"VALIDATION_SMOKE_MODE": "optional"}),
            patch.object(
                sys.modules[__name__],
                "_fixed_backend_path",
                return_value=Path("/usr/bin/bwrap"),
            ),
            patch(
                "scripts.validation_isolation.runner.run_isolated",
                side_effect=AssertionError("backend must not run in optional mode"),
            ),
        ):
            with self.assertRaises(unittest.SkipTest):
                self.test_fixed_backend_enforces_smoke_properties_with_real_probe_evidence()

    def test_required_mode_does_not_skip_missing_backend(self):
        with (
            patch.dict(os.environ, {"VALIDATION_SMOKE_MODE": "required"}),
            patch.object(
                sys.modules[__name__], "_fixed_backend_path", return_value=None
            ),
        ):
            with self.assertRaises(AssertionError):
                self.test_fixed_backend_enforces_smoke_properties_with_real_probe_evidence()

    def test_fixed_backend_enforces_smoke_properties_with_real_probe_evidence(self):
        mode = os.environ.get("VALIDATION_SMOKE_MODE", "optional")
        if mode == "optional":
            self.skipTest(
                "optional smoke mode is covered by the canonical backend gate"
            )
        backend_path = _fixed_backend_path()
        if backend_path is None:
            self.fail("required fixed validation backend is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            child = (
                "import os,stat\n"
                "from pathlib import Path\n"
                "try: Path(bytes([47]).decode()+'etc'+bytes([47]).decode()+'hosts')"
                ".read_bytes()\n"
                "except OSError: pass\n"
                "else: raise SystemExit(12)\n"
                "if Path.cwd().joinpath('tracked.txt').read_text() != 'tracked\\n':"
                " raise SystemExit(13)\n"
                "marker=Path(os.environ['TMPDIR']).joinpath('smoke-marker')\n"
                "marker.write_text('ok')\n"
                "marker.chmod(0o600)\n"
                "if stat.S_IMODE(marker.stat().st_mode) != 0o600:"
                " raise SystemExit(14)\n"
                "raise SystemExit(23)\n"
            )
            from scripts.validation_isolation.runner import run_isolated

            configured = os.environ.get("VALIDATION_SYSTEM_PYTHON")
            interpreter = Path(configured or "/usr/bin/python3")
            if configured is not None:
                self.assertTrue(interpreter.is_absolute())
                self.assertEqual(interpreter.resolve(strict=True), interpreter)
            smoke_command = (str(interpreter), "-c", child)

            try:
                with patch(
                    "scripts.validation_isolation.runner.sys.executable",
                    str(interpreter),
                ):
                    result = run_isolated(smoke_command, repository, sys.platform)
            except (OSError, RuntimeError, ValueError):
                raise
            self.assertEqual(result.returncode, 23)
            self.assertLessEqual(len(result.stdout), 8192)
            self.assertLessEqual(len(result.stderr), 8192)
            self.assertIn("probe=passed", result.evidence)


if __name__ == "__main__":
    unittest.main()
