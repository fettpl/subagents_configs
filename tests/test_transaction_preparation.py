import io
import os
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from subagents_configs import transaction
from subagents_configs.models import Target
from subagents_configs.orchestrator import EXIT_INCOMPLETE_ROLLBACK, run
from subagents_configs.planning import preflight_install
from subagents_configs.state import encode_journal
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

    def _prepared(self, home, *, preexisting=False):
        if preexisting:
            destination = home / "agents/code-explorer.toml"
            destination.parent.mkdir(parents=True)
            destination.write_bytes(b"user bytes\n")
            destination.chmod(0o640)
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        )
        with transaction.locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
            evidence = transaction._collect_readonly_evidence(plan)
            return transaction._prepare(plan, evidence)

    def test_journal_replacement_after_validation_is_retained(self):
        home = self.root / "codex-home"
        prepared = self._prepared(home)
        journal = prepared.journals[Target.CODEX]
        path = home / ".subagents_configs/journal.json"
        expected = transaction.capture_evidence(path, "test journal")
        replacement = replace(journal, transaction_id="attacker-replacement")
        path.write_bytes(encode_journal(replacement))
        path.chmod(0o600)
        with self.assertRaises(transaction.TransactionError):
            transaction._sync_and_remove_journal(
                home, journal, journal_evidence=expected
            )
        self.assertEqual(path.read_bytes(), encode_journal(replacement))

    def test_backup_replacement_after_validation_is_retained_with_journal(self):
        home = self.root / "codex-home"
        prepared = self._prepared(home, preexisting=True)
        journal = prepared.journals[Target.CODEX]
        operation = next(
            item for item in journal.operations if item.backup_path is not None
        )
        journal_path = home / ".subagents_configs/journal.json"
        journal_evidence = transaction.capture_evidence(journal_path, "test journal")
        backup_path = home / ".subagents_configs" / operation.backup_path
        backup_evidence = transaction.capture_evidence(backup_path, "test backup")
        backup_path.write_bytes(b"attacker backup\n")
        backup_path.chmod(0o600)
        with self.assertRaises(transaction.TransactionError):
            transaction._sync_and_remove_journal(
                home,
                journal,
                journal_evidence=journal_evidence,
                backup_evidence={backup_path: backup_evidence},
            )
        self.assertTrue(journal_path.exists())
        self.assertEqual(backup_path.read_bytes(), b"attacker backup\n")

    def test_missing_journal_or_backup_fails_closed(self):
        home = self.root / "codex-home"
        prepared = self._prepared(home, preexisting=True)
        journal = prepared.journals[Target.CODEX]
        journal_path = home / ".subagents_configs/journal.json"
        journal_evidence = transaction.capture_evidence(journal_path, "test journal")
        operation = next(
            item for item in journal.operations if item.backup_path is not None
        )
        backup_path = home / ".subagents_configs" / operation.backup_path
        backup_evidence = transaction.capture_evidence(backup_path, "test backup")
        journal_path.unlink()
        with self.assertRaises(transaction.TransactionError):
            transaction._sync_and_remove_journal(
                home,
                journal,
                journal_evidence=journal_evidence,
                backup_evidence={backup_path: backup_evidence},
            )
        journal_path.write_bytes(encode_journal(journal))
        journal_path.chmod(0o600)
        journal_evidence = transaction.capture_evidence(journal_path, "test journal")
        backup_path.unlink()
        with self.assertRaises(transaction.TransactionError):
            transaction._sync_and_remove_journal(
                home,
                journal,
                journal_evidence=journal_evidence,
                backup_evidence={backup_path: backup_evidence},
            )
        self.assertTrue(journal_path.exists())

    def test_journal_restore_does_not_overwrite_replacement(self):
        home = self.root / "codex-home"
        prepared = self._prepared(home)
        journal = prepared.journals[Target.CODEX]
        journal_path = home / ".subagents_configs/journal.json"
        expected = transaction.capture_evidence(journal_path, "test journal")
        real_cas = transaction.filesystem.compare_and_swap

        def race(path, before, content, mode, action):
            if action == "unlink":
                result = real_cas(path, before, content, mode, action)
                journal_path.write_bytes(b"attacker replacement\n")
                journal_path.chmod(0o600)
                return result
            return real_cas(path, before, content, mode, action)

        with (
            patch.object(transaction.filesystem, "compare_and_swap", side_effect=race),
            patch.object(
                transaction.filesystem,
                "sync_directory",
                side_effect=[OSError("sync failure"), None],
            ),
        ):
            with self.assertRaises(transaction.TransactionError):
                transaction._sync_and_remove_journal(
                    home, journal, journal_evidence=expected
                )
        self.assertEqual(journal_path.read_bytes(), b"attacker replacement\n")

    def test_directory_identity_race_is_not_recorded_for_cleanup(self):
        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        target = home / "agents"
        owned = []
        real_ensure = transaction.filesystem.ensure_directory

        def race(path, *, private=False):
            created = real_ensure(path, private=private)
            if Path(path) == target:
                replacement = target.with_name("agents-replacement")
                replacement.mkdir(mode=0o700)
                os.replace(replacement, target)
            return created

        with patch.object(transaction.filesystem, "ensure_directory", side_effect=race):
            transaction._ensure_owned_directory(target, owned)
        transaction._cleanup_preparation(owned)
        self.assertTrue(target.is_dir())

    def test_late_backup_read_fails_before_preparation_writes(self):
        home = self.root / "codex-home"
        destination = home / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"user bytes\n")
        destination.chmod(0o640)
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        )
        before = tree_snapshot(home)
        with transaction.locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
            with patch.object(
                transaction,
                "_read_regular",
                side_effect=OSError("late backup read"),
            ):
                with self.assertRaises(OSError):
                    transaction._collect_readonly_evidence(plan)
            self.assertEqual(
                before | {".subagents_configs.lock": ("file", 0o600, b"")},
                tree_snapshot(home),
            )

    def test_recovery_keeps_replacement_after_validation_before_cleanup(self):
        from subagents_configs.targets import descriptor_for

        home = self.root / "codex-home"
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        )
        with patch.object(transaction, "_sync_and_remove_journal"):
            transaction.apply_transaction(plan)
        journal_path = home / ".subagents_configs/journal.json"
        real_verify = transaction._verify_complete_journal

        def verify_then_replace(home, descriptor, journal, all_journals=None):
            result = real_verify(home, descriptor, journal, all_journals)
            journal_path.write_bytes(b"attacker journal replacement\n")
            journal_path.chmod(0o600)
            return result

        with patch.object(
            transaction, "_verify_complete_journal", side_effect=verify_then_replace
        ):
            with self.assertRaises(transaction.TransactionError):
                transaction._recover_single(home, descriptor_for(Target.CODEX))
        self.assertEqual(journal_path.read_bytes(), b"attacker journal replacement\n")

    def test_single_recovery_rejects_journal_disappearing_after_initial_capture(self):
        from subagents_configs.targets import descriptor_for

        home = self.root / "codex-home"
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        )
        with patch.object(transaction, "_sync_and_remove_journal"):
            transaction.apply_transaction(plan)
        with patch.object(transaction, "load_journal", return_value=None):
            with self.assertRaises(transaction.IncompleteRollbackError) as error:
                transaction._recover_single(home, descriptor_for(Target.CODEX))
        self.assertEqual(str(error.exception), "recovery journal disappeared")

    def test_participant_recovery_keeps_replacement_after_validation(self):
        homes = {
            Target.CODEX: self.root / "codex-home",
            Target.OPENCODE: self.root / "opencode-home",
        }
        plan = preflight_install(
            self.repository,
            planning_request("install", homes),
        )
        with patch.object(transaction, "_sync_and_remove_journal"):
            transaction.apply_transaction(plan)
        replaced_path = homes[Target.OPENCODE] / ".subagents_configs/journal.json"
        real_verify = transaction._verify_complete_journal

        def verify_then_replace(home, descriptor, journal, all_journals=None):
            result = real_verify(home, descriptor, journal, all_journals)
            if descriptor.target is Target.OPENCODE:
                replaced_path.write_bytes(b"attacker participant journal\n")
                replaced_path.chmod(0o600)
            return result

        with patch.object(
            transaction, "_verify_complete_journal", side_effect=verify_then_replace
        ):
            with self.assertRaises(transaction.TransactionError):
                transaction._recover_participants(homes)
        self.assertEqual(replaced_path.read_bytes(), b"attacker participant journal\n")

    def test_prepare_consumes_precomputed_backup_derivations(self):
        home = self.root / "codex-home"
        destination = home / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        before_content = b"user bytes\n"
        destination.write_bytes(before_content)
        destination.chmod(0o640)
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        )
        with transaction.locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
            evidence = transaction._collect_readonly_evidence(plan)
            real_digest = transaction._digest

            def fail_after_first_artifact(content):
                if content == before_content and (home / ".subagents_configs").exists():
                    raise AssertionError("backup digest computed after preparation")
                return real_digest(content)

            with patch.object(
                transaction, "_digest", side_effect=fail_after_first_artifact
            ):
                prepared = transaction._prepare(plan, evidence)
        self.assertTrue(prepared.journals[Target.CODEX].operations)

    def test_directory_cleanup_preserves_replacement_during_atomic_detach(self):
        home = self.root / "codex-home"
        home.mkdir(mode=0o700)
        target = home / "owned-directory"
        owned: list[transaction.OwnedArtifact] = []
        transaction._ensure_owned_directory(target, owned)
        real_rename = os.rename

        def replace_after_detach(source, destination, *args, **kwargs):
            result = real_rename(source, destination, *args, **kwargs)
            if Path(source).name == target.name:
                target.mkdir(mode=0o700)
            return result

        with patch.object(os, "rename", side_effect=replace_after_detach):
            transaction._cleanup_preparation(owned)
        self.assertTrue(target.is_dir())


if __name__ == "__main__":
    unittest.main()
