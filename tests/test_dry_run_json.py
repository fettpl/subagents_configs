import io
import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from subagents_configs.cli import parse_request
from subagents_configs.errors import CliError
from subagents_configs.models import Request, Target
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

                out, err = io.StringIO(), io.StringIO()
                before = tree_snapshot(root)
                status = run(
                    "install",
                    [
                        *(
                            item
                            for target in selected
                            for item in ("--target", target.value)
                        ),
                        *(
                            item
                            for target in selected
                            for item in ("--home", f"{target.value}={homes[target]}")
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


if __name__ == "__main__":
    unittest.main()
