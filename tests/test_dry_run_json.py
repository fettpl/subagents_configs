import io
import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from subagents_configs.cli import parse_request
from subagents_configs.errors import CliError
from subagents_configs.models import Journal, JournalOperation, Request, Target
from subagents_configs.orchestrator import run
from subagents_configs.planning import render_plan_json
from tests.helpers import planning_repository, private_tempdir, tree_snapshot


class StructuredDryRunContractTests(unittest.TestCase):
    def test_parser_accepts_json_only_for_dry_run(self):
        with private_tempdir() as directory:
            home = Path(directory) / "home"
            request = parse_request(
                "install",
                [
                    "--target",
                    "codex",
                    "--home",
                    f"codex={home}",
                    "--dry-run",
                    "--format",
                    "json",
                ],
                {"HOME": str(directory)},
            )
            self.assertEqual(request.dry_run_format, "json")

            with self.assertRaises(CliError):
                parse_request(
                    "install",
                    [
                        "--target",
                        "codex",
                        "--home",
                        f"codex={home}",
                        "--format",
                        "json",
                    ],
                    {"HOME": str(directory)},
                )

    def test_json_renderer_has_versioned_safe_schema(self):
        with private_tempdir() as directory:
            root = Path(directory)
            repo = planning_repository(root)
            home = root / "home"
            from subagents_configs.planning import preflight_install

            request = Request(
                "install",
                (Target.CODEX,),
                {Target.CODEX: home},
                False,
                False,
                False,
                True,
                "json",
            )
            plan = preflight_install(repo, request)
            payload = json.loads(render_plan_json(plan))
            self.assertEqual(
                set(payload),
                {
                    "schema_version",
                    "operation",
                    "targets",
                    "actions",
                    "hashes",
                    "ownership",
                    "conflicts",
                    "recovery",
                    "sources",
                },
            )
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["operation"], "install")
            encoded = json.dumps(payload, sort_keys=True)
            self.assertNotIn("{{VALIDATION_HELPER}}", encoded)
            self.assertNotIn("content", encoded)

    def test_default_request_retains_text_format(self):
        request = Request(
            "install",
            (Target.CODEX,),
            {Target.CODEX: Path("codex-home")},
            False,
            False,
            False,
            True,
        )
        self.assertEqual(request.dry_run_format, "text")

    def test_every_target_combination_has_canonical_json_order_and_no_content(self):
        with private_tempdir() as directory:
            root = Path(directory).resolve()
            repo = planning_repository(root)
            targets = (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE)
            for mask in range(1, 8):
                selected = tuple(
                    target
                    for index, target in enumerate(targets)
                    if mask & (1 << index)
                )
                homes = {target: root / f"home-{target.value}" for target in selected}
                from subagents_configs.orchestrator import run

                for operation in ("install", "uninstall"):
                    out, err = io.StringIO(), io.StringIO()
                    before = tree_snapshot(root)
                    status = run(
                        operation,
                        [
                            *(
                                item
                                for target in selected
                                for item in ("--target", target.value)
                            ),
                            *(
                                item
                                for target in selected
                                for item in (
                                    "--home",
                                    f"{target.value}={homes[target]}",
                                )
                            ),
                            "--dry-run",
                            "--format",
                            "json",
                        ],
                        repo_root=repo,
                        environ={"HOME": str(root)},
                        stdout=out,
                        stderr=err,
                    )
                    payload = json.loads(out.getvalue())
                    self.assertEqual(status, 0)
                    self.assertEqual(err.getvalue(), "")
                    self.assertEqual(
                        [item["target"] for item in payload["targets"]],
                        [target.value for target in selected],
                    )
                    self.assertEqual(tree_snapshot(root), before)
                    encoded = out.getvalue()
                    self.assertNotIn("content", encoded)
                    self.assertNotIn("{{VALIDATION_HELPER}}", encoded)
                    self.assertNotIn("SECRET", encoded)

    def test_json_pending_recovery_contains_validated_metadata(self):
        with private_tempdir() as directory:
            root = Path(directory).resolve()
            repo = planning_repository(root)
            home = root / "home"
            operation = JournalOperation(
                "codex-op",
                "code-explorer",
                "create",
                None,
                "a" * 64,
                None,
                0o600,
                None,
                None,
                "applied",
            )
            journal = Journal(
                2,
                "transaction-id",
                Target.CODEX,
                (Target.CODEX,),
                "install",
                (operation,),
                "complete",
            )
            groups = (({Target.CODEX: home}, (journal,)),)
            out, err = io.StringIO(), io.StringIO()
            with patch(
                "subagents_configs.orchestrator._journal_groups",
                return_value=groups,
            ):
                status = run(
                    "install",
                    [
                        "--target",
                        "codex",
                        "--home",
                        f"codex={home}",
                        "--dry-run",
                        "--format",
                        "json",
                    ],
                    repo_root=repo,
                    environ={"HOME": str(root)},
                    stdout=out,
                    stderr=err,
                )
            payload = json.loads(out.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(err.getvalue(), "")
            self.assertEqual(payload["recovery"]["required"], True)
            self.assertEqual(payload["recovery"]["participants"], ["codex"])
            self.assertEqual(payload["recovery"]["journal_identifiers"], ["codex-op"])
            self.assertEqual(payload["recovery"]["homes"], [str(home)])

    def test_json_conflict_has_existing_exit_status_and_safe_payload(self):
        with private_tempdir() as directory:
            root = Path(directory).resolve()
            repo = planning_repository(root)
            home = root / "home"
            destination = home / "agents" / "code-explorer.toml"
            destination.parent.mkdir(parents=True)
            destination.write_bytes(
                (repo / "agents" / "code-explorer.toml").read_bytes()
            )
            destination.chmod(0o644)
            out, err = io.StringIO(), io.StringIO()
            status = run(
                "install",
                [
                    "--target",
                    "codex",
                    "--home",
                    f"codex={home}",
                    "--dry-run",
                    "--format",
                    "json",
                ],
                repo_root=repo,
                environ={"HOME": str(root)},
                stdout=out,
                stderr=err,
            )
            payload = json.loads(out.getvalue())
            self.assertEqual(status, 4)
            self.assertTrue(payload["conflicts"])
            self.assertIn("MANAGED_CONFLICT", err.getvalue())
            self.assertNotIn(str(repo), out.getvalue())

    def test_json_output_failure_is_sanitized(self):
        with private_tempdir() as directory:
            root = Path(directory).resolve()
            repo = planning_repository(root)
            out, err = io.StringIO(), io.StringIO()
            with patch(
                "subagents_configs.orchestrator.render_plan_json",
                side_effect=RuntimeError("JSON_RENDER_SECRET"),
            ):
                status = run(
                    "install",
                    [
                        "--target",
                        "codex",
                        "--home",
                        f"codex={root / 'home'}",
                        "--dry-run",
                        "--format",
                        "json",
                    ],
                    repo_root=repo,
                    environ={"HOME": str(root)},
                    stdout=out,
                    stderr=err,
                )
            self.assertEqual(status, 3)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("OUTPUT_FAILED", err.getvalue())
            self.assertNotIn("JSON_RENDER_SECRET", err.getvalue())

    def test_state_and_journal_identity_change_during_render_fails_closed(self):
        for state_name in ("manifest.json", "journal.json"):
            with self.subTest(state_name=state_name), private_tempdir() as directory:
                root = Path(directory).resolve()
                repo = planning_repository(root)
                state_dir = root / "home" / ".subagents_configs"
                original = b"{}\n"
                from subagents_configs.planning import render_plan_json as real_render

                def mutate_during_render(
                    plan,
                    state_dir=state_dir,
                    state_name=state_name,
                    original=original,
                ):
                    state_dir.mkdir(mode=0o700, parents=True)
                    (state_dir / state_name).write_bytes(original)
                    return real_render(plan)

                out, err = io.StringIO(), io.StringIO()
                try:
                    with patch(
                        "subagents_configs.orchestrator.render_plan_json",
                        side_effect=mutate_during_render,
                    ):
                        status = run(
                            "install",
                            [
                                "--target",
                                "codex",
                                "--home",
                                f"codex={root / 'home'}",
                                "--dry-run",
                                "--format",
                                "json",
                            ],
                            repo_root=repo,
                            environ={"HOME": str(root)},
                            stdout=out,
                            stderr=err,
                        )
                finally:
                    if (state_dir / state_name).exists():
                        (state_dir / state_name).unlink()
                    if state_dir.exists():
                        state_dir.rmdir()
                self.assertEqual(status, 3)
                self.assertEqual(out.getvalue(), "")
                self.assertIn("PREFLIGHT_CONCURRENT_CHANGE", err.getvalue())

    def test_structured_dry_run_never_calls_lock_api(self):
        with private_tempdir() as directory:
            root = Path(directory).resolve()
            repo = planning_repository(root)
            from subagents_configs.orchestrator import run

            with patch(
                "subagents_configs.orchestrator.locked_target_homes",
                side_effect=AssertionError("dry-run lock API called"),
            ):
                out, err = io.StringIO(), io.StringIO()
                status = run(
                    "install",
                    [
                        "--target",
                        "codex",
                        "--home",
                        f"codex={root / 'home'}",
                        "--dry-run",
                        "--format",
                        "json",
                    ],
                    repo_root=repo,
                    environ={"HOME": str(root)},
                    stdout=out,
                    stderr=err,
                )
            self.assertEqual(status, 0)
            self.assertEqual(err.getvalue(), "")

    def test_concurrent_second_collection_fails_without_plan_output(self):
        with private_tempdir() as directory:
            root = Path(directory).resolve()
            repo = planning_repository(root)
            from subagents_configs.planning import preflight_install

            request = Request(
                "install",
                (Target.CODEX,),
                {Target.CODEX: root / "home"},
                False,
                False,
                False,
                True,
                "json",
            )
            first = preflight_install(repo, request)
            second = replace(
                first,
                targets=tuple(
                    replace(item, conflicts=("changed",)) for item in first.targets
                ),
            )
            out, err = io.StringIO(), io.StringIO()
            with patch(
                "subagents_configs.orchestrator._plan", side_effect=(first, second)
            ):
                status = run(
                    "install",
                    [
                        "--target",
                        "codex",
                        "--home",
                        f"codex={root / 'home'}",
                        "--dry-run",
                        "--format",
                        "json",
                    ],
                    repo_root=repo,
                    environ={"HOME": str(root)},
                    stdout=out,
                    stderr=err,
                )
            self.assertEqual(status, 3)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("PREFLIGHT_CONCURRENT_CHANGE", err.getvalue())

    def test_source_change_during_json_render_fails_before_output(self):
        with private_tempdir() as directory:
            root = Path(directory).resolve()
            repo = planning_repository(root)
            source = repo / "agents" / "code-explorer.toml"
            original = source.read_bytes()
            from subagents_configs.planning import render_plan_json as real_render

            def mutate_during_render(plan):
                source.write_bytes(original + b"\nRENDER_RACE")
                return real_render(plan)

            out, err = io.StringIO(), io.StringIO()
            try:
                with patch(
                    "subagents_configs.orchestrator.render_plan_json",
                    side_effect=mutate_during_render,
                ):
                    status = run(
                        "install",
                        [
                            "--target",
                            "codex",
                            "--home",
                            f"codex={root / 'home'}",
                            "--dry-run",
                            "--format",
                            "json",
                        ],
                        repo_root=repo,
                        environ={"HOME": str(root)},
                        stdout=out,
                        stderr=err,
                    )
            finally:
                source.write_bytes(original)
            self.assertEqual(status, 3)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("PREFLIGHT_CONCURRENT_CHANGE", err.getvalue())


if __name__ == "__main__":
    unittest.main()
