import io
import itertools
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from subagents_configs.cli import parse_request
from subagents_configs.errors import CliError, ValidationBlockedError
from subagents_configs.models import Journal, JournalOperation, Target
from subagents_configs.orchestrator import (
    EXIT_APPLY_ERROR,
    EXIT_BLOCKED_VALIDATION,
    EXIT_CLI_ERROR,
    EXIT_INCOMPLETE_ROLLBACK,
    EXIT_MANAGED_CONFLICT,
    EXIT_PREFLIGHT_ERROR,
    EXIT_SUCCESS,
    HELP_TEXT,
    run,
)
from subagents_configs.planning import TargetPlan, TransactionPlan
from subagents_configs.transaction import IncompleteRollbackError, TransactionError
from tests.helpers import planning_repository


class FailingWriter:
    def __init__(self, message="YAML_OUTPUT_SECRET=writer-leak"):
        self.message = message

    def write(self, _text):
        raise OSError(self.message)


class CliIntegrationTests(unittest.TestCase):
    def test_all_seven_target_combinations_and_all_are_plannable(self):
        targets = (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE)
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            root = Path(directory)
            repo = planning_repository(root)
            for size in (1, 2, 3):
                for selected in itertools.combinations(targets, size):
                    homes = {
                        target: root / f"{target.value}-{size}" for target in selected
                    }
                    argv = [
                        item
                        for target in selected
                        for item in ("--target", target.value)
                    ]
                    for target in selected:
                        argv += ["--home", f"{target.value}={homes[target]}"]
                    argv.append("--dry-run")
                    out, err = io.StringIO(), io.StringIO()
                    status = run(
                        "install",
                        argv,
                        repo_root=repo,
                        environ={"HOME": str(root)},
                        stdout=out,
                        stderr=err,
                    )
                    self.assertEqual(status, EXIT_SUCCESS, (selected, err.getvalue()))
                    self.assertEqual(err.getvalue(), "")
                    for target in selected:
                        self.assertIn(f"target: {target.value} home=", out.getvalue())
            out, err = io.StringIO(), io.StringIO()
            all_argv = ["--all"]
            for target, suffix in (
                (Target.CODEX, "all-codex"),
                (Target.OPENCODE, "all-opencode"),
                (Target.CLAUDE_CODE, "all-claude"),
            ):
                all_argv += ["--home", f"{target.value}={root / suffix}"]
            all_argv.append("--dry-run")
            status = run(
                "install",
                all_argv,
                repo_root=repo,
                environ={"HOME": str(root)},
                stdout=out,
                stderr=err,
            )
            self.assertEqual(status, EXIT_SUCCESS, err.getvalue())
            self.assertEqual(err.getvalue(), "")

    def test_install_opt_ins_are_visible_and_uninstall_rejects_them(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            root = Path(directory)
            repo = planning_repository(root)
            home = root / "codex"
            argv = [
                "--target",
                "codex",
                "--home",
                f"codex={home}",
                "--enable-global-routing",
                "--enable-codex-multi-agent",
                "--include-commit-pusher",
                "--dry-run",
            ]
            out, err = io.StringIO(), io.StringIO()
            self.assertEqual(
                run(
                    "install", argv, repo_root=repo, environ={}, stdout=out, stderr=err
                ),
                EXIT_SUCCESS,
            )
            self.assertIn("commit-pusher", out.getvalue())
            self.assertIn("routing-codex", out.getvalue())
            self.assertIn("codex-multi-agent-v2", out.getvalue())
            out, err = io.StringIO(), io.StringIO()
            self.assertEqual(
                run(
                    "uninstall",
                    [
                        "--target",
                        "codex",
                        "--home",
                        f"codex={home}",
                        "--include-commit-pusher",
                    ],
                    repo_root=repo,
                    environ={},
                    stdout=out,
                    stderr=err,
                ),
                EXIT_CLI_ERROR,
            )

    def test_help_is_stable_and_does_not_read_repository_or_homes(self):
        out, err = io.StringIO(), io.StringIO()
        with patch("subagents_configs.orchestrator.preflight_install") as preflight:
            status = run(
                "install",
                ["--help"],
                repo_root=Path("/does/not/exist"),
                environ={},
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, EXIT_SUCCESS)
        self.assertEqual(out.getvalue(), HELP_TEXT["install"])
        self.assertEqual(err.getvalue(), "")
        preflight.assert_not_called()

    def test_help_is_only_valid_as_the_sole_argument(self):
        for argv in (
            ["--help", "--help"],
            ["--help", "--unknown"],
            ["--help", "--target", "unknown"],
        ):
            out, err = io.StringIO(), io.StringIO()
            status = run(
                "install",
                argv,
                repo_root=Path("/private/tmp"),
                environ={"HOME": "/private/tmp"},
                stdout=out,
                stderr=err,
            )
            self.assertEqual(status, EXIT_CLI_ERROR)
            self.assertEqual(out.getvalue(), "")
            self.assertTrue(err.getvalue().startswith("error: invalid command line:"))

    def test_malformed_source_is_blocked_validation(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            root = Path(directory)
            repo = planning_repository(root)
            (repo / "agents/code-explorer.toml").write_text(
                "name = [\n", encoding="utf-8"
            )
            out, err = io.StringIO(), io.StringIO()
            status = run(
                "install",
                ["--target", "codex", "--home", f"codex={root / 'home'}", "--dry-run"],
                repo_root=repo,
                environ={},
                stdout=out,
                stderr=err,
            )
            self.assertEqual(status, EXIT_BLOCKED_VALIDATION)
            self.assertTrue(err.getvalue().startswith("error: validation blocked:"))

    def test_diagnostics_redact_sensitive_and_payload_values(self):
        out, err = io.StringIO(), io.StringIO()
        secret = "super-secret-token"  # noqa: S105
        environ = {"HOME": "/private/tmp", "TOKEN": secret, "PASSWORD": "pass-value"}
        message = (
            f"TOKEN={secret} password=pass-value bare={secret} "
            "payload={'bytes': b'private'}\nnext"
        )
        with patch(
            "subagents_configs.orchestrator._plan", side_effect=RuntimeError(message)
        ):
            status = run(
                "install",
                ["--target", "codex", "--home", "codex=/private/tmp/task8"],
                repo_root=Path("/private/tmp"),
                environ=environ,
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, EXIT_BLOCKED_VALIDATION)
        self.assertNotIn(secret, err.getvalue())
        self.assertNotIn("pass-value", err.getvalue())
        self.assertNotIn("private", err.getvalue())
        self.assertNotIn("\nnext", err.getvalue())

    def test_diagnostics_fail_closed_for_multiline_payloads_and_secret_keys(self):
        messages = (
            "payload={'secret': 'SYNTHETIC_SECRET'\n, 'other': 'LEAK'}",
            "bytes=b'SYNTHETIC_SECRET\nMORE'",
            "AWS_SECRET_ACCESS_KEY=aws-value OPENAI_API_KEY=openai-value "
            "DATABASE_PASSWORD=db-value PRIVATE_KEY=private-value "
            "GITHUB_TOKEN=github-value",
        )
        for message in messages:
            out, err = io.StringIO(), io.StringIO()
            with patch(
                "subagents_configs.orchestrator._plan",
                side_effect=RuntimeError(message),
            ):
                status = run(
                    "install",
                    ["--target", "codex", "--home", "codex=/private/tmp/task8"],
                    repo_root=Path("/private/tmp"),
                    environ={},
                    stdout=out,
                    stderr=err,
                )
            self.assertEqual(status, EXIT_BLOCKED_VALIDATION)
            for value in (
                "SYNTHETIC_SECRET",
                "LEAK",
                "MORE",
                "aws-value",
                "openai-value",
                "db-value",
                "private-value",
                "github-value",
            ):
                self.assertNotIn(value, err.getvalue())

    def test_unexpected_preflight_exception_uses_fixed_diagnostic(self):
        out, err = io.StringIO(), io.StringIO()
        with patch(
            "subagents_configs.orchestrator._plan",
            side_effect=Exception("yaml payload: SYNTHETIC_YAML_SECRET"),
        ):
            status = run(
                "install",
                ["--target", "codex", "--home", "codex=/private/tmp/task8"],
                repo_root=Path("/private/tmp"),
                environ={},
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, EXIT_PREFLIGHT_ERROR)
        self.assertEqual(
            err.getvalue(), "error: preflight rejected: unexpected failure\n"
        )
        self.assertNotIn("SYNTHETIC_YAML_SECRET", err.getvalue())

    def test_unexpected_recovery_exception_returns_safe_incomplete_status(self):
        out, err = io.StringIO(), io.StringIO()
        with (
            patch(
                "subagents_configs.orchestrator._journal_groups",
                return_value=(({}, ()),),
            ),
            patch(
                "subagents_configs.orchestrator._recover_groups",
                side_effect=Exception("YAML_SECRET=leak"),
            ),
        ):
            status = run(
                "install",
                ["--target", "codex", "--home", "codex=/private/tmp/task8"],
                repo_root=Path("/private/tmp"),
                environ={},
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, EXIT_INCOMPLETE_ROLLBACK)
        self.assertEqual(
            err.getvalue(),
            "error: recovery failed; rollback status is unknown\n",
        )
        self.assertNotIn("YAML_SECRET", err.getvalue())

    def test_known_failure_diagnostics_are_fixed_across_preflight_recovery_apply(self):
        payloads = (
            "yaml payload: SYNTHETIC_SECRET",
            "bytes=b'SYNTHETIC_SECRET'\nsecond line",
        )
        request_args = ["--target", "codex", "--home", "codex=/private/tmp/task8"]
        clean_plan = TransactionPlan(
            "install",
            (TargetPlan(Target.CODEX, Path("/private/tmp/task8"), (), None, ()),),
        )
        for payload in payloads:
            for failure in (ValueError(payload), OSError(payload)):
                out, err = io.StringIO(), io.StringIO()
                with patch("subagents_configs.orchestrator._plan", side_effect=failure):
                    status = run(
                        "install",
                        request_args,
                        repo_root=Path("/private/tmp"),
                        environ={},
                        stdout=out,
                        stderr=err,
                    )
                self.assertEqual(status, EXIT_PREFLIGHT_ERROR)
                self.assertNotIn("SYNTHETIC_SECRET", err.getvalue())
                self.assertNotIn("Traceback", err.getvalue())

            for failure, expected in (
                (IncompleteRollbackError(payload), EXIT_INCOMPLETE_ROLLBACK),
                (TransactionError(payload), EXIT_BLOCKED_VALIDATION),
                (RuntimeError(payload), EXIT_BLOCKED_VALIDATION),
                (ValueError(payload), EXIT_BLOCKED_VALIDATION),
                (OSError(payload), EXIT_BLOCKED_VALIDATION),
            ):
                out, err = io.StringIO(), io.StringIO()
                with (
                    patch(
                        "subagents_configs.orchestrator._journal_groups",
                        return_value=(({}, ()),),
                    ),
                    patch(
                        "subagents_configs.orchestrator._recover_groups",
                        side_effect=failure,
                    ),
                ):
                    status = run(
                        "install",
                        request_args,
                        repo_root=Path("/private/tmp"),
                        environ={},
                        stdout=out,
                        stderr=err,
                    )
                self.assertEqual(status, expected)
                self.assertNotIn("SYNTHETIC_SECRET", err.getvalue())
                self.assertNotIn("Traceback", err.getvalue())

            for failure, expected in (
                (IncompleteRollbackError(payload), EXIT_INCOMPLETE_ROLLBACK),
                (TransactionError(payload), EXIT_APPLY_ERROR),
                (OSError(payload), EXIT_APPLY_ERROR),
                (ValueError(payload), EXIT_APPLY_ERROR),
            ):
                out, err = io.StringIO(), io.StringIO()
                with (
                    patch(
                        "subagents_configs.orchestrator._plan", return_value=clean_plan
                    ),
                    patch(
                        "subagents_configs.orchestrator.apply_transaction",
                        side_effect=failure,
                    ),
                ):
                    status = run(
                        "install",
                        request_args,
                        repo_root=Path("/private/tmp"),
                        environ={},
                        stdout=out,
                        stderr=err,
                    )
                self.assertEqual(status, expected)
                self.assertNotIn("SYNTHETIC_SECRET", err.getvalue())
                self.assertNotIn("Traceback", err.getvalue())

    def test_unexpected_parse_and_journal_failures_are_stable(self):
        request_args = ["--target", "codex", "--home", "codex=/private/tmp/task8"]
        for name, target, expected in (
            ("parse_request", "parse", EXIT_CLI_ERROR),
            ("_journal_groups", "journal", EXIT_BLOCKED_VALIDATION),
        ):
            out, err = io.StringIO(), io.StringIO()
            with patch(
                f"subagents_configs.orchestrator.{name}",
                side_effect=Exception(f"YAML_SECRET={target}-leak"),
            ):
                status = run(
                    "install",
                    request_args,
                    repo_root=Path("/private/tmp"),
                    environ={},
                    stdout=out,
                    stderr=err,
                )
            self.assertEqual(status, expected)
            self.assertNotIn("YAML_SECRET", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())

    def test_render_and_output_failures_are_stable_and_sanitized(self):
        request_args = ["--target", "codex", "--home", "codex=/private/tmp/task8"]
        clean_plan = TransactionPlan(
            "install",
            (TargetPlan(Target.CODEX, Path("/private/tmp/task8"), (), None, ()),),
        )
        out, err = io.StringIO(), io.StringIO()
        with (
            patch("subagents_configs.orchestrator._plan", return_value=clean_plan),
            patch(
                "subagents_configs.orchestrator.render_plan",
                side_effect=Exception("YAML_SECRET=render-leak"),
            ),
        ):
            status = run(
                "install",
                request_args,
                repo_root=Path("/private/tmp"),
                environ={},
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, EXIT_PREFLIGHT_ERROR)
        self.assertNotIn("YAML_SECRET", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

        with patch("subagents_configs.orchestrator._plan", return_value=clean_plan):
            status = run(
                "install",
                request_args,
                repo_root=Path("/private/tmp"),
                environ={},
                stdout=FailingWriter(),
                stderr=err,
            )
        self.assertEqual(status, EXIT_PREFLIGHT_ERROR)
        self.assertNotIn("YAML_OUTPUT_SECRET", err.getvalue())

        class BrokenPlan:
            @property
            def targets(self):
                raise Exception("YAML_SECRET=targets-leak")

        out, err = io.StringIO(), io.StringIO()
        with (
            patch("subagents_configs.orchestrator._plan", return_value=BrokenPlan()),
            patch("subagents_configs.orchestrator.render_plan", return_value="plan\n"),
        ):
            status = run(
                "install",
                request_args,
                repo_root=Path("/private/tmp"),
                environ={},
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, EXIT_PREFLIGHT_ERROR)
        self.assertNotIn("YAML_SECRET", err.getvalue())

        with patch(
            "subagents_configs.orchestrator._plan",
            side_effect=ValueError("YAML_SECRET=stderr-leak"),
        ):
            status = run(
                "install",
                request_args,
                repo_root=Path("/private/tmp"),
                environ={},
                stdout=io.StringIO(),
                stderr=FailingWriter(),
            )
        self.assertEqual(status, EXIT_PREFLIGHT_ERROR)

    def test_yaml_parser_diagnostic_does_not_echo_source_secret(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            root = Path(directory)
            repo = planning_repository(root)
            (repo / "opencode/agents/code-explorer.md").write_text(
                "---\nname: code-explorer\npermission: [\n"
                "SYNTHETIC_YAML_SECRET\n---\nunsafe body\n",
                encoding="utf-8",
            )
            out, err = io.StringIO(), io.StringIO()
            status = run(
                "install",
                [
                    "--target",
                    "opencode",
                    "--home",
                    f"opencode={root / 'home'}",
                    "--dry-run",
                ],
                repo_root=repo,
                environ={},
                stdout=out,
                stderr=err,
            )
            self.assertEqual(status, EXIT_BLOCKED_VALIDATION)
            self.assertNotIn("SYNTHETIC_YAML_SECRET", err.getvalue())

    def test_pending_recovery_dry_run_labels_cleanup_and_rollback(self):
        def journal(status, operation_status):
            operation = JournalOperation(
                "codex-0000-agents-code-explorer.toml",
                "code-explorer",
                "create",
                None,
                "a" * 64,
                None,
                0o600,
                None,
                None,
                operation_status,
            )
            return Journal(
                1,
                "a" * 32 + "-" + "b" * 64,
                Target.CODEX,
                (Target.CODEX,),
                "install",
                (operation,),
                status,
            )

        for journal_status, operation_status, action in (
            ("complete", "applied", "cleanup"),
            ("in-progress", "applying", "rollback"),
        ):
            out, err = io.StringIO(), io.StringIO()
            group = (
                {Target.CODEX: Path("/private/tmp/task8-home")},
                (journal(journal_status, operation_status),),
            )
            with (
                patch(
                    "subagents_configs.orchestrator._journal_groups",
                    return_value=(group,),
                ),
                patch("subagents_configs.orchestrator._recover_groups") as recover,
                patch("subagents_configs.orchestrator.preflight_install") as preflight,
            ):
                status = run(
                    "install",
                    [
                        "--target",
                        "codex",
                        "--home",
                        "codex=/private/tmp/task8-home",
                        "--dry-run",
                    ],
                    repo_root=Path("/private/tmp"),
                    environ={},
                    stdout=out,
                    stderr=err,
                )
            self.assertEqual(status, EXIT_SUCCESS)
            self.assertIn(f"action={action}", out.getvalue())
            self.assertNotIn("rollback-or-cleanup", out.getvalue())
            recover.assert_not_called()
            preflight.assert_not_called()

    def test_missing_participant_blocks_all_selected_recovery_writes(self):
        journal = Journal(
            1,
            "a" * 32 + "-" + "b" * 64,
            Target.CODEX,
            (Target.CODEX, Target.OPENCODE),
            "install",
            (),
            "not-started",
        )
        request = ["--target", "codex", "--target", "opencode"]
        with (
            patch(
                "subagents_configs.orchestrator.load_journal",
                side_effect=lambda home, descriptor: (
                    journal if descriptor.target is Target.CODEX else None
                ),
            ),
            patch("subagents_configs.orchestrator._recover_groups") as recover,
            patch("subagents_configs.orchestrator._plan") as preflight,
        ):
            out, err = io.StringIO(), io.StringIO()
            status = run(
                "install",
                request,
                repo_root=Path("/private/tmp"),
                environ={"HOME": "/private/tmp"},
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, EXIT_BLOCKED_VALIDATION)
        recover.assert_not_called()
        preflight.assert_not_called()
        self.assertEqual(out.getvalue(), "")

    def test_status_mapping_conflict_apply_rollback_and_blocked_validation(self):
        home = Path("/private/tmp/task8-status-home")
        request_args = ["--target", "codex", "--home", f"codex={home}"]
        conflict_plan = TransactionPlan(
            "install", (TargetPlan(Target.CODEX, home, (), None, ("drift",)),)
        )
        with (
            patch("subagents_configs.orchestrator._plan", return_value=conflict_plan),
            patch("subagents_configs.orchestrator.apply_transaction") as apply,
        ):
            out, err = io.StringIO(), io.StringIO()
            status = run(
                "install",
                request_args,
                repo_root=Path("/private/tmp"),
                environ={},
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, EXIT_MANAGED_CONFLICT)
        apply.assert_not_called()

        clean_plan = TransactionPlan(
            "install", (TargetPlan(Target.CODEX, home, (), None, ()),)
        )
        for failure, expected in (
            (RuntimeError("TOKEN=hidden"), EXIT_APPLY_ERROR),
            (
                IncompleteRollbackError("rollback evidence unavailable"),
                EXIT_INCOMPLETE_ROLLBACK,
            ),
        ):
            with (
                patch("subagents_configs.orchestrator._plan", return_value=clean_plan),
                patch(
                    "subagents_configs.orchestrator.apply_transaction",
                    side_effect=failure,
                ) as apply,
            ):
                out, err = io.StringIO(), io.StringIO()
                status = run(
                    "install",
                    request_args,
                    repo_root=Path("/private/tmp"),
                    environ={},
                    stdout=out,
                    stderr=err,
                )
            self.assertEqual(status, expected)
            apply.assert_called_once()

        with patch(
            "subagents_configs.orchestrator._plan",
            side_effect=ValidationBlockedError("source blocked"),
        ):
            out, err = io.StringIO(), io.StringIO()
            status = run(
                "install",
                request_args,
                repo_root=Path("/private/tmp"),
                environ={},
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, EXIT_BLOCKED_VALIDATION)

        with patch(
            "subagents_configs.orchestrator._plan",
            side_effect=ValueError("validation wording is ordinary preflight"),
        ):
            out, err = io.StringIO(), io.StringIO()
            status = run(
                "install",
                request_args,
                repo_root=Path("/private/tmp"),
                environ={},
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, EXIT_PREFLIGHT_ERROR)

    def test_unresolved_uninstall_applies_once_and_injector_is_not_cli_selectable(self):
        home = Path("/private/tmp/task8-unresolved-home")
        plan = TransactionPlan(
            "uninstall", (TargetPlan(Target.CODEX, home, (), None, ("drift",)),)
        )
        with (
            patch("subagents_configs.orchestrator._plan", return_value=plan),
            patch("subagents_configs.orchestrator.apply_transaction") as apply,
        ):
            out, err = io.StringIO(), io.StringIO()
            status = run(
                "uninstall",
                ["--target", "codex", "--home", f"codex={home}"],
                repo_root=Path("/private/tmp"),
                environ={"FAILURE_INJECTOR": "yes"},
                stdout=out,
                stderr=err,
            )
        self.assertEqual(status, 7)
        apply.assert_called_once()
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(
            run(
                "install",
                ["--target", "codex", "--failure-injector", "x"],
                repo_root=Path("/private/tmp"),
                environ={},
                stdout=out,
                stderr=err,
            ),
            EXIT_CLI_ERROR,
        )

    def test_invalid_and_missing_selection_have_cli_error_status(self):
        with self.assertRaises(CliError):
            parse_request("install", [], {"HOME": "/private/tmp"})
        out, err = io.StringIO(), io.StringIO()
        status = run(
            "install",
            ["--target", "unknown"],
            repo_root=Path("/private/tmp"),
            environ={"HOME": "/private/tmp"},
            stdout=out,
            stderr=err,
        )
        self.assertNotEqual(status, EXIT_SUCCESS)
        self.assertTrue(err.getvalue().startswith("error: "))
        self.assertNotIn("Traceback", err.getvalue())

    def test_install_dry_run_does_not_write_fixture_or_home(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repo = planning_repository(root)
            home = root / "codex-home"
            before = sorted(
                (path.relative_to(root), path.stat().st_mode, path.read_bytes())
                for path in root.rglob("*")
                if path.is_file()
            )
            out, err = io.StringIO(), io.StringIO()
            status = run(
                "install",
                ["--target", "codex", "--home", f"codex={home}", "--dry-run"],
                repo_root=repo,
                environ={"HOME": str(root)},
                stdout=out,
                stderr=err,
            )
            after = sorted(
                (path.relative_to(root), path.stat().st_mode, path.read_bytes())
                for path in root.rglob("*")
                if path.is_file()
            )
            self.assertEqual(status, EXIT_SUCCESS)
            self.assertEqual(before, after)
            self.assertFalse(home.exists())
            self.assertIn("target: codex home=", out.getvalue())
            self.assertEqual(err.getvalue(), "")

    def test_install_then_uninstall_uses_shared_transaction_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repo = planning_repository(root)
            home = root / "codex-home"
            args = ["--target", "codex", "--home", f"codex={home}"]
            out, err = io.StringIO(), io.StringIO()
            self.assertEqual(
                run(
                    "install", args, repo_root=repo, environ={}, stdout=out, stderr=err
                ),
                EXIT_SUCCESS,
            )
            self.assertTrue((home / "agents/code-explorer.toml").exists())
            out, err = io.StringIO(), io.StringIO()
            self.assertEqual(
                run(
                    "uninstall",
                    args,
                    repo_root=repo,
                    environ={},
                    stdout=out,
                    stderr=err,
                ),
                EXIT_SUCCESS,
            )
            self.assertFalse((home / "agents/code-explorer.toml").exists())


if __name__ == "__main__":
    unittest.main()
