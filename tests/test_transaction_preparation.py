import io
import unittest
from pathlib import Path
from unittest.mock import patch

from subagents_configs import transaction
from subagents_configs.models import Target
from subagents_configs.orchestrator import EXIT_INCOMPLETE_ROLLBACK, run
from subagents_configs.planning import preflight_install
from tests.helpers import (
    planning_repository,
    planning_request,
    private_tempdir,
    tree_snapshot,
)


class _FailAtFirstOperation:
    def before_operation(self, _operation_id):
        raise RuntimeError("injected operation failure")


class TransactionPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = private_tempdir()
        self.root = Path(self.temporary.name)
        self.repository = planning_repository(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_readonly_evidence_failure_writes_nothing_after_lock(self):
        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        marker = home / "keep.txt"
        marker.write_bytes(b"keep\n")
        marker.chmod(0o640)
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        )
        calls = 0

        def fail_late(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == len(plan.targets[0].operations):
                raise transaction.TransactionError("late evidence failure")
            return original(*args, **kwargs)

        original = transaction._check_evidence
        with transaction.locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
            locked_before = tree_snapshot(home)
            with patch.object(transaction, "_check_evidence", side_effect=fail_late):
                with self.assertRaises(transaction.TransactionError):
                    transaction._collect_readonly_evidence(plan)
            self.assertEqual(locked_before, tree_snapshot(home))

    def test_preparation_failure_cleans_only_new_identity_bound_artifacts(self):
        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        state = home / ".subagents_configs"
        backups = state / "backups"
        backups.mkdir(mode=0o700, parents=True)
        state.chmod(0o700)
        (backups / "user-backup").write_bytes(b"user backup\n")
        (backups / "user-backup").chmod(0o600)
        unrelated = home / "unrelated.txt"
        unrelated.write_bytes(b"unrelated\n")
        unrelated.chmod(0o640)
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        )
        with transaction.locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
            before = tree_snapshot(home)
            evidence = transaction._collect_readonly_evidence(plan)
            with patch.object(
                transaction,
                "_write_journal",
                side_effect=OSError("journal write failed"),
            ):
                with self.assertRaises(transaction.TransactionPreparationError):
                    transaction._prepare(plan, evidence)
            self.assertEqual(before, tree_snapshot(home))
        self.assertTrue((backups / "user-backup").exists())
        self.assertTrue(unrelated.exists())

    def test_cleanup_failure_does_not_replace_primary_apply_status(self):
        home = self.root / "codex-home"
        plan_argv = ["--target", "codex", "--home", f"codex={home}"]
        out, err = io.StringIO(), io.StringIO()
        with patch.object(
            transaction,
            "_sync_and_remove_journal",
            side_effect=OSError("cleanup-only failure"),
        ):
            status = run(
                "install",
                plan_argv,
                repo_root=self.repository,
                environ={"HOME": str(self.root)},
                stdout=out,
                stderr=err,
                failure_injector=_FailAtFirstOperation(),
            )
        self.assertEqual(status, EXIT_INCOMPLETE_ROLLBACK)
        self.assertEqual(err.getvalue(), "error: apply failed; rollback incomplete\n")
        self.assertNotIn("cleanup-only failure", err.getvalue())


if __name__ == "__main__":
    unittest.main()
