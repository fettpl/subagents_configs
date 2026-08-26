from __future__ import annotations

import subprocess
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch


class ValidationCliTests(unittest.TestCase):
    def test_requires_separator_and_nonempty_command(self):
        from scripts.validation_isolation.cli import parse_command

        for argv in ((), ("python3",), ("--",), ("python3", "--", "echo")):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                parse_command(argv)

    def test_preserves_command_argv_after_separator(self):
        from scripts.validation_isolation.cli import parse_command

        self.assertEqual(
            parse_command(("--", "python3", "-c", "a b", "--")),
            ("python3", "-c", "a b", "--"),
        )

    def test_usage_is_two_and_blocked_is_one(self):
        from scripts.validation_isolation import cli

        self.assertEqual(cli.main(["--"]), 2)
        with patch.object(cli, "run_isolated", side_effect=ValueError("blocked")):
            self.assertEqual(cli.main(["--", "false"]), 1)

    def test_success_or_child_status_is_returned(self):
        from scripts.validation_isolation import cli
        from scripts.validation_isolation.runner import ValidationResult

        with patch.object(
            cli, "run_isolated", return_value=ValidationResult(0, "", "", ())
        ) as run:
            self.assertEqual(cli.main(["--", "echo", "hello"]), 0)
            run.assert_called_once()
        with patch.object(
            cli, "run_isolated", return_value=ValidationResult(17, "", "", ())
        ) as run:
            self.assertEqual(cli.main(["--", "false"]), 17)
            run.assert_called_once()

    def test_timeout_is_blocked_without_payload_or_traceback(self):
        from scripts.validation_isolation import cli

        output = StringIO()
        timeout = subprocess.TimeoutExpired(
            ("false",), 1, output="SECRET", stderr="SECRET"
        )
        with patch.object(cli, "run_isolated", side_effect=timeout):
            with redirect_stderr(output):
                self.assertEqual(cli.main(["--", "false"]), 1)
        self.assertNotIn("SECRET", output.getvalue())
        self.assertNotIn("TimeoutExpired", output.getvalue())

    def test_cleanup_failure_is_sanitized_and_nonzero(self):
        from scripts.validation_isolation import cli
        from scripts.validation_isolation.runner import (
            CleanupResult,
            ValidationCleanupError,
        )

        output = StringIO()
        failure = ValidationCleanupError(
            CleanupResult("cleanup_failed", primary_present=False)
        )
        with patch.object(cli, "run_isolated", side_effect=failure):
            with redirect_stderr(output):
                self.assertEqual(cli.main(["--", "false"]), 1)
        self.assertEqual(output.getvalue(), "validation blocked: validation failed\n")
        self.assertNotIn("cleanup_failed", output.getvalue())

    def test_entrypoint_checks_python_version_before_newer_import(self):
        import ast
        import runpy
        import sys

        entrypoint = (
            Path(__file__).parents[1] / "scripts" / "run-validation-isolated.py"
        )
        source = entrypoint.read_text(encoding="utf-8")
        ast.parse(source, filename=str(entrypoint), feature_version=(3, 9))
        output = StringIO()
        with patch.object(sys, "version_info", (3, 10, 0)):
            with redirect_stderr(output):
                with self.assertRaises(SystemExit) as raised:
                    runpy.run_path(str(entrypoint), run_name="__main__")
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(
            output.getvalue(), "validation helper requires Python 3.11 or newer\n"
        )


if __name__ == "__main__":
    unittest.main()
