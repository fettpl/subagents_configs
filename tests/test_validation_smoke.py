from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from tests.validation_isolated_test_support import git, make_repository


class ValidationInventorySmokeTests(unittest.TestCase):
    def test_casefolded_policy_excludes_mixed_case_secrets_and_caches(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
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
            self.assertIs(result.primary, primary)
            self.assertNotIn("secret", repr(result).lower())
            self.assertNotIn("credentials", repr(result).lower())

    def test_cleanup_success_reports_stable_code(self):
        from scripts.validation_isolation.runner import cleanup_validation_root

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir(mode=0o700)
            result = cleanup_validation_root(root, primary=None)
            self.assertEqual(result.code, "cleaned")
            self.assertIsNone(result.primary)


class RealValidationSmokeTests(unittest.TestCase):
    @unittest.skipUnless(
        (Path("/usr/bin/bwrap").is_file() or Path("/bin/bwrap").is_file())
        if sys.platform.startswith("linux")
        else Path("/usr/bin/sandbox-exec").is_file(),
        "fixed validation backend is unavailable",
    )
    def test_fixed_backend_enforces_six_smoke_properties(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            child = (
                "import os,socket,stat,sys\n"
                "from pathlib import Path\n"
                "try:\n"
                " socket.create_connection(('127.0.0.1',9),timeout=.2)\n"
                "except OSError: pass\n"
                "else: raise SystemExit(11)\n"
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

            try:
                with patch(
                    "scripts.validation_isolation.runner.sys.executable",
                    "/usr/bin/python3",
                ):
                    result = run_isolated(
                        ("python3", "-c", child), repository, sys.platform
                    )
            except (OSError, RuntimeError, ValueError) as exc:
                self.skipTest(f"fixed backend cannot execute in this host: {exc}")
            self.assertEqual(result.returncode, 23)
            self.assertLessEqual(len(result.stdout), 8192)
            self.assertLessEqual(len(result.stderr), 8192)
            self.assertIn("probe=passed", result.evidence)


if __name__ == "__main__":
    unittest.main()
