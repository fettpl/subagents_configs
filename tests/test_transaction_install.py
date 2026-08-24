import hashlib
import json
import os
import stat
import unittest
from pathlib import Path
from unittest.mock import patch

from subagents_configs.models import Journal, Manifest, Target
from subagents_configs.planning import preflight_install
from subagents_configs.state import (
    encode_journal,
    encode_manifest,
    load_journal,
    load_manifest,
)
from subagents_configs.targets import descriptor_for
from tests.helpers import planning_repository, planning_request, private_tempdir


class _FailBefore:
    def __init__(self, operation_id):
        self.operation_id = operation_id
        self.seen = []

    def before_operation(self, operation_id):
        self.seen.append(operation_id)
        if operation_id == self.operation_id or operation_id.endswith(
            f"-{self.operation_id}"
        ):
            raise RuntimeError("injected failure")


class TransactionInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = private_tempdir()
        self.root = Path(self.temporary.name)
        self.repository = planning_repository(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def _home(self, target=Target.CODEX):
        return self.root / f"home-{target.value}"

    def _plan(self, *targets, **options):
        if any(target is not Target.CODEX for target in targets):
            try:
                import yaml  # noqa: F401
            except ModuleNotFoundError:
                self.skipTest("PyYAML is required for YAML target transaction fixtures")
        homes = {target: self._home(target) for target in targets}
        return preflight_install(
            self.repository,
            planning_request("install", homes, targets=targets, **options),
        )

    def _apply_leaving_journals(self, plan):
        from subagents_configs import transaction

        with patch.object(transaction, "_sync_and_remove_journal"):
            transaction.apply_transaction(plan)

    def test_apply_creates_private_state_files_and_managed_files(self):
        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX)
        apply_transaction(plan)
        home = self._home()
        state = home / ".subagents_configs"
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((state / "manifest.json").stat().st_mode), 0o600)
        self.assertIsNone(load_journal(home, descriptor_for(Target.CODEX)))
        managed = home / "agents/code-explorer.toml"
        self.assertEqual(stat.S_IMODE(managed.stat().st_mode), 0o600)
        self.assertEqual(
            managed.read_bytes(),
            (self.repository / "agents/code-explorer.toml").read_bytes(),
        )

    def test_all_journals_exist_before_first_managed_write_and_manifests_are_last(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        events = []
        original_atomic = transaction.filesystem.atomic_write
        original_compare_and_swap = transaction.filesystem.compare_and_swap

        def record(path, content, mode=0o600):
            events.append(
                ("write", Path(path).relative_to(self.root).as_posix(), content)
            )
            original_atomic(path, content, mode)

        def record_compare_and_swap(path, before, content, mode, action):
            events.append(
                ("write", Path(path).relative_to(self.root).as_posix(), content)
            )
            return original_compare_and_swap(path, before, content, mode, action)

        transaction.filesystem.atomic_write = record
        transaction.filesystem.compare_and_swap = record_compare_and_swap
        try:
            transaction.apply_transaction(plan)
        finally:
            transaction.filesystem.atomic_write = original_atomic
            transaction.filesystem.compare_and_swap = original_compare_and_swap
        first_managed = next(
            i
            for i, event in enumerate(events)
            if ".subagents_configs/" not in event[1]
            or event[1].endswith("manifest.json")
        )
        journal_writes = [
            i for i, event in enumerate(events) if event[1].endswith("journal.json")
        ]
        self.assertEqual(len(journal_writes[:2]), 2)
        self.assertTrue(all(index < first_managed for index in journal_writes[:2]))
        manifest_writes = [
            i for i, event in enumerate(events) if event[1].endswith("manifest.json")
        ]
        self.assertTrue(manifest_writes)
        self.assertTrue(all(index > first_managed for index in manifest_writes))

    def test_failure_in_later_target_rolls_back_every_home_and_preserves_backups(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        operation = next(
            item
            for item in plan.targets[1].operations
            if item.identifier == "code-explorer"
        )
        ordered = sorted(
            plan.targets[1].operations,
            key=lambda item: (
                item.action == "write-manifest",
                item.relative_path,
                item.identifier,
            ),
        )
        operation_id = transaction._operation_id(
            Target.OPENCODE, ordered.index(operation), operation.identifier
        )
        with self.assertRaises(RuntimeError):
            apply_transaction(plan, _FailBefore(operation_id))
        for target in (Target.CODEX, Target.OPENCODE):
            home = self._home(target)
            self.assertFalse((home / "agents/code-explorer.toml").exists())
            self.assertFalse((home / ".subagents_configs/manifest.json").exists())
            self.assertFalse((home / ".subagents_configs/journal.json").exists())

    def test_injector_order_is_global_descriptor_then_path_order(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        seen = []

        class Recorder:
            def before_operation(self, operation_id):
                seen.append(operation_id)

        apply_transaction(plan, Recorder())
        expected = []
        for target_plan in plan.targets:
            operations = sorted(
                target_plan.operations,
                key=lambda item: (
                    item.action == "write-manifest",
                    item.relative_path,
                    item.identifier,
                ),
            )
            expected.extend(
                transaction._operation_id(
                    target_plan.target, index, operation.identifier
                )
                for index, operation in enumerate(operations)
            )
        self.assertEqual(seen, expected)

    def test_status_is_persisted_before_and_after_operation(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX)
        writes = []
        original = transaction.filesystem.atomic_write

        def record(path, content, mode=0o600):
            if Path(path).name == "journal.json":
                payload = json.loads(content)
                writes.append(tuple(item["status"] for item in payload["operations"]))
            original(path, content, mode)

        transaction.filesystem.atomic_write = record
        try:
            apply_transaction(plan)
        finally:
            transaction.filesystem.atomic_write = original
        self.assertTrue(any("applying" in statuses for statuses in writes))
        self.assertTrue(any("applied" in statuses for statuses in writes))

    def test_noop_reinstall_does_not_rewrite_managed_files_or_create_backups(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        transaction.apply_transaction(plan)
        home = self._home()
        managed = home / "agents/code-explorer.toml"
        before = managed.stat().st_mtime_ns
        second = self._plan(Target.CODEX)
        self.assertFalse(
            [
                op
                for op in second.targets[0].operations
                if op.identifier == "code-explorer"
            ]
        )
        transaction.apply_transaction(second)
        self.assertEqual(managed.stat().st_mtime_ns, before)
        backups = home / ".subagents_configs/backups"
        self.assertTrue(backups.exists())
        self.assertTrue(
            any(item.name.startswith("commitment-") for item in backups.iterdir())
        )

    def test_replacement_backup_is_persisted_at_manifest_reference(self):
        from subagents_configs import transaction

        home = self._home()
        destination = home / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        original = b"user-owned agent\n"
        destination.write_bytes(original)
        destination.chmod(0o640)
        plan = self._plan(Target.CODEX)
        transaction.apply_transaction(plan)
        manifest = load_manifest(home, descriptor_for(Target.CODEX))
        entry = next(
            item for item in manifest.entries if item.identifier == "code-explorer"
        )
        self.assertEqual(entry.ownership, "replaced")
        backup = home / ".subagents_configs" / entry.backup_path
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_committed_transaction_cleans_temporary_backups_only(self):
        from subagents_configs import transaction

        home = self._home()
        destination = home / "AGENTS.md"
        destination.parent.mkdir(parents=True)
        original = b"user routing\n"
        destination.write_bytes(original)
        destination.chmod(0o640)
        transaction.apply_transaction(
            self._plan(Target.CODEX, enable_global_routing=True)
        )
        manifest = load_manifest(home, descriptor_for(Target.CODEX))
        self.assertIsNotNone(manifest)
        permanent = {
            f".subagents_configs/{entry.backup_path}"
            for entry in manifest.entries
            if entry.backup_path is not None
        }
        backups = {
            path.relative_to(home).as_posix()
            for path in (home / ".subagents_configs/backups").iterdir()
            if path.is_file()
        }
        commitments = {path for path in backups if path not in permanent}
        self.assertEqual(len(commitments), 1)
        self.assertEqual(backups, permanent | commitments)
        backup = home / next(iter(permanent))
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_regular_update_backup_and_uninstall_restore_user_bytes(
        self,
    ):
        from subagents_configs import transaction
        from subagents_configs.planning import preflight_uninstall
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        destination = home / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        original = b"user original bytes\n"
        destination.write_bytes(original)
        destination.chmod(0o644)
        apply_transaction(self._plan(Target.CODEX))
        first_installed = destination.read_bytes()
        source = self.repository / "agents/code-explorer.toml"
        source.write_bytes(source.read_bytes() + b"\n# second installed\n")
        second = self._plan(Target.CODEX)
        with patch.object(transaction, "_sync_and_remove_journal"):
            apply_transaction(second)
        self.assertNotEqual(destination.read_bytes(), first_installed)
        journal = load_journal(home, descriptor_for(Target.CODEX))
        journal_operation = next(
            item for item in journal.operations if item.identifier == "code-explorer"
        )
        manifest = load_manifest(home, descriptor_for(Target.CODEX))
        entry = next(
            item for item in manifest.entries if item.identifier == "code-explorer"
        )
        permanent_backup = home / ".subagents_configs" / entry.backup_path
        self.assertEqual(permanent_backup.read_bytes(), original)
        transaction_backup = home / ".subagents_configs" / journal_operation.backup_path
        self.assertNotEqual(journal_operation.backup_path, entry.backup_path)
        self.assertEqual(transaction_backup.read_bytes(), first_installed)
        transaction.recover_incomplete_journal(home, descriptor_for(Target.CODEX))
        uninstall = preflight_uninstall(
            self.repository,
            planning_request(
                "uninstall", {Target.CODEX: home}, targets=(Target.CODEX,)
            ),
        )
        apply_transaction(uninstall)
        self.assertEqual(destination.read_bytes(), original)

    def test_second_regular_update_rollback_restores_immediate_previous_bytes(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        destination = home / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"user original bytes\n")
        destination.chmod(0o600)
        apply_transaction(self._plan(Target.CODEX))
        previous = destination.read_bytes()
        source = self.repository / "agents/code-explorer.toml"
        source.write_bytes(source.read_bytes() + b"\n# second installed\n")
        second = self._plan(Target.CODEX)
        manifest_operation = next(
            item
            for item in second.targets[0].operations
            if item.identifier == "state/manifest"
        )
        manifest_index = sorted(
            second.targets[0].operations,
            key=lambda item: (
                item.action == "write-manifest",
                item.relative_path,
                item.identifier,
            ),
        ).index(manifest_operation)

        class FailAtManifest:
            def before_operation(self, operation_id):
                if operation_id == transaction._operation_id(
                    Target.CODEX, manifest_index, "state/manifest"
                ):
                    raise RuntimeError("manifest failure")

        with self.assertRaises(RuntimeError):
            apply_transaction(second, FailAtManifest())
        self.assertEqual(destination.read_bytes(), previous)

    def test_block_update_backup_and_uninstall_restore_user_bytes(
        self,
    ):
        from subagents_configs import transaction
        from subagents_configs.planning import preflight_uninstall
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        destination = home / "AGENTS.md"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"user original routing\n")
        destination.chmod(0o600)
        apply_transaction(self._plan(Target.CODEX, enable_global_routing=True))
        first_installed = destination.read_bytes()
        source = self.repository / "rules/SUBAGENT_ROUTING.md"
        source.write_bytes(source.read_bytes() + b"\n# second routing\n")
        second = self._plan(Target.CODEX, enable_global_routing=True)
        with patch.object(transaction, "_sync_and_remove_journal"):
            apply_transaction(second)
        self.assertNotEqual(destination.read_bytes(), first_installed)
        journal = load_journal(home, descriptor_for(Target.CODEX))
        journal_operation = next(
            item for item in journal.operations if item.identifier == "routing-codex"
        )
        manifest = load_manifest(home, descriptor_for(Target.CODEX))
        entry = next(
            item for item in manifest.entries if item.identifier == "routing-codex"
        )
        permanent_backup = home / ".subagents_configs" / entry.backup_path
        self.assertEqual(permanent_backup.read_bytes(), b"user original routing\n")
        transaction_backup = home / ".subagents_configs" / journal_operation.backup_path
        self.assertNotEqual(journal_operation.backup_path, entry.backup_path)
        self.assertEqual(transaction_backup.read_bytes(), first_installed)
        transaction.recover_incomplete_journal(home, descriptor_for(Target.CODEX))
        uninstall = preflight_uninstall(
            self.repository,
            planning_request(
                "uninstall", {Target.CODEX: home}, targets=(Target.CODEX,)
            ),
        )
        apply_transaction(uninstall)
        self.assertEqual(destination.read_bytes(), b"user original routing\n")

    def test_second_block_update_rollback_restores_immediate_previous_bytes(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        destination = home / "AGENTS.md"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"user original routing\n")
        destination.chmod(0o600)
        apply_transaction(self._plan(Target.CODEX, enable_global_routing=True))
        previous = destination.read_bytes()
        source = self.repository / "rules/SUBAGENT_ROUTING.md"
        source.write_bytes(source.read_bytes() + b"\n# second routing\n")
        second = self._plan(Target.CODEX, enable_global_routing=True)
        manifest_operation = next(
            item
            for item in second.targets[0].operations
            if item.identifier == "state/manifest"
        )
        manifest_index = sorted(
            second.targets[0].operations,
            key=lambda item: (
                item.action == "write-manifest",
                item.relative_path,
                item.identifier,
            ),
        ).index(manifest_operation)

        class FailAtManifest:
            def before_operation(self, operation_id):
                if operation_id == transaction._operation_id(
                    Target.CODEX, manifest_index, "state/manifest"
                ):
                    raise RuntimeError("manifest failure")

        with self.assertRaises(RuntimeError):
            apply_transaction(second, FailAtManifest())
        self.assertEqual(destination.read_bytes(), previous)

    def test_install_then_uninstall_applies_and_removes_final_manifest(self):
        from subagents_configs.planning import preflight_uninstall
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        apply_transaction(self._plan(Target.CODEX))
        uninstall = preflight_uninstall(
            self.repository,
            planning_request(
                "uninstall", {Target.CODEX: home}, targets=(Target.CODEX,)
            ),
        )
        apply_transaction(uninstall)
        self.assertFalse((home / ".subagents_configs/manifest.json").exists())
        self.assertFalse((home / "agents/code-explorer.toml").exists())
        self.assertIsNone(load_manifest(home, descriptor_for(Target.CODEX)))

    def test_mid_uninstall_failure_rolls_back_to_installed_manifest_and_files(self):
        from subagents_configs import transaction
        from subagents_configs.planning import preflight_uninstall
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        apply_transaction(self._plan(Target.CODEX))
        before_manifest = (home / ".subagents_configs/manifest.json").read_bytes()
        before_agent = (home / "agents/code-explorer.toml").read_bytes()
        uninstall = preflight_uninstall(
            self.repository,
            planning_request(
                "uninstall", {Target.CODEX: home}, targets=(Target.CODEX,)
            ),
        )
        manifest_operation = next(
            item
            for item in uninstall.targets[0].operations
            if item.identifier == "state/manifest"
        )
        manifest_index = sorted(
            uninstall.targets[0].operations,
            key=lambda item: (
                item.action == "write-manifest",
                item.relative_path,
                item.identifier,
            ),
        ).index(manifest_operation)

        class FailAtManifest:
            def before_operation(self, operation_id):
                if operation_id == transaction._operation_id(
                    Target.CODEX, manifest_index, "state/manifest"
                ):
                    raise RuntimeError("manifest failure")

        with self.assertRaises(RuntimeError):
            apply_transaction(uninstall, FailAtManifest())
        self.assertEqual(
            (home / ".subagents_configs/manifest.json").read_bytes(), before_manifest
        )
        self.assertEqual(
            (home / "agents/code-explorer.toml").read_bytes(), before_agent
        )

    def test_complete_uninstall_journal_recovers_and_cleans(self):
        from subagents_configs import transaction
        from subagents_configs.planning import preflight_uninstall
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        apply_transaction(self._plan(Target.CODEX))
        uninstall = preflight_uninstall(
            self.repository,
            planning_request(
                "uninstall", {Target.CODEX: home}, targets=(Target.CODEX,)
            ),
        )
        self._apply_leaving_journals(uninstall)
        self.assertTrue((home / ".subagents_configs/journal.json").exists())
        transaction.recover_incomplete_journal(home, descriptor_for(Target.CODEX))
        self.assertFalse((home / ".subagents_configs/journal.json").exists())

    def _uninstall_with_drifted_preexisting_entry(self):
        from subagents_configs.planning import preflight_uninstall
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        source = self.repository / "agents/code-explorer.toml"
        destination = home / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o600)
        apply_transaction(self._plan(Target.CODEX))
        destination.write_bytes(b"user retained bytes\n")
        destination.chmod(0o600)
        uninstall = preflight_uninstall(
            self.repository,
            planning_request(
                "uninstall", {Target.CODEX: home}, targets=(Target.CODEX,)
            ),
        )
        return home, destination, uninstall

    def _uninstall_with_drifted_replaced_entry(self):
        from subagents_configs.planning import preflight_uninstall
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        destination = home / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"user original bytes\n")
        destination.chmod(0o600)
        apply_transaction(self._plan(Target.CODEX))
        destination.write_bytes(b"user drifted bytes\n")
        destination.chmod(0o600)
        uninstall = preflight_uninstall(
            self.repository,
            planning_request(
                "uninstall", {Target.CODEX: home}, targets=(Target.CODEX,)
            ),
        )
        return home, destination, uninstall

    def test_uninstall_keeps_drifted_unresolved_entry_and_removes_resolvable_entries(
        self,
    ):
        from subagents_configs.transaction import apply_transaction

        home, destination, uninstall = self._uninstall_with_drifted_preexisting_entry()
        self.assertTrue(uninstall.targets[0].conflicts)
        unresolved = [
            entry
            for entry in uninstall.targets[0].resulting_manifest.entries
            if entry.unresolved_reason is not None
        ]
        self.assertEqual(
            tuple(sorted(entry.unresolved_reason for entry in unresolved)),
            tuple(sorted(uninstall.targets[0].conflicts)),
        )
        apply_transaction(uninstall)
        self.assertEqual(destination.read_bytes(), b"user retained bytes\n")
        self.assertFalse((home / "agents/code-reviewer.toml").exists())
        manifest = load_manifest(home, descriptor_for(Target.CODEX))
        self.assertEqual(
            {entry.relative_path for entry in manifest.entries},
            {"agents/code-explorer.toml"},
        )

    def test_uninstall_arbitrary_conflict_is_rejected_before_writes(self):
        from dataclasses import replace

        from subagents_configs import transaction

        _home, destination, uninstall = self._uninstall_with_drifted_preexisting_entry()
        altered = replace(uninstall.targets[0], conflicts=("arbitrary conflict",))
        with self.assertRaises(ValueError):
            transaction.apply_transaction(replace(uninstall, targets=(altered,)))
        self.assertEqual(destination.read_bytes(), b"user retained bytes\n")

    def test_uninstall_operation_targeting_unresolved_entry_is_rejected(self):
        from dataclasses import replace

        from subagents_configs import transaction

        _home, destination, uninstall = self._uninstall_with_drifted_preexisting_entry()
        unresolved = next(
            entry
            for entry in uninstall.targets[0].resulting_manifest.entries
            if entry.unresolved_reason is not None
        )
        injected = replace(
            uninstall.targets[0].operations[0],
            identifier=unresolved.identifier,
            relative_path=unresolved.relative_path,
        )
        altered = replace(
            uninstall.targets[0],
            operations=(injected, *uninstall.targets[0].operations[1:]),
        )
        with self.assertRaises(ValueError):
            transaction.apply_transaction(replace(uninstall, targets=(altered,)))
        self.assertEqual(destination.read_bytes(), b"user retained bytes\n")

    def test_unresolved_uninstall_entries_must_match_prior_manifest_exactly(self):
        from dataclasses import replace

        from subagents_configs import transaction

        _home, destination, uninstall = self._uninstall_with_drifted_replaced_entry()
        target_plan = uninstall.targets[0]
        retained = next(
            entry
            for entry in target_plan.resulting_manifest.entries
            if entry.unresolved_reason is not None
        )
        fabricated = replace(
            retained,
            identifier="routing-codex",
            relative_path="AGENTS.md",
            installed_hash="0" * 64,
            ownership="preexisting",
            backup_path=None,
            backup_hash=None,
            original_mode=None,
            managed_block_id=None,
            installed_block_hash=None,
            unresolved_reason="fabricated unresolved entry",
        )
        cases = [
            ("missing-prior", fabricated, "fabricated unresolved entry"),
            (
                "alias-identifier",
                replace(retained, identifier=retained.relative_path),
                retained.unresolved_reason,
            ),
            (
                "installed-hash",
                replace(retained, installed_hash="0" * 64),
                retained.unresolved_reason,
            ),
            (
                "installed-mode",
                replace(retained, installed_mode=0o400),
                retained.unresolved_reason,
            ),
            (
                "ownership",
                replace(
                    retained,
                    ownership="preexisting",
                    backup_path=None,
                    backup_hash=None,
                    original_mode=None,
                ),
                retained.unresolved_reason,
            ),
            (
                "backup-path",
                replace(
                    retained,
                    backup_path="backups/fabricated",
                    backup_hash="0" * 64,
                ),
                retained.unresolved_reason,
            ),
            (
                "backup-hash",
                replace(
                    retained,
                    backup_path="backups/fabricated",
                    backup_hash="0" * 64,
                ),
                retained.unresolved_reason,
            ),
            (
                "original-mode",
                replace(retained, original_mode=0o400),
                retained.unresolved_reason,
            ),
        ]
        for label, altered_entry, reason in cases:
            with self.subTest(label=label):
                entries = tuple(
                    altered_entry if entry is retained else entry
                    for entry in target_plan.resulting_manifest.entries
                )
                resulting = replace(target_plan.resulting_manifest, entries=entries)
                manifest_bytes = encode_manifest(resulting)
                operations = tuple(
                    replace(
                        operation,
                        content=manifest_bytes,
                        expected_after_hash=hashlib.sha256(manifest_bytes).hexdigest(),
                    )
                    if operation.identifier == "state/manifest"
                    else operation
                    for operation in target_plan.operations
                )
                altered_target = replace(
                    target_plan,
                    operations=operations,
                    resulting_manifest=resulting,
                    conflicts=tuple(sorted({*target_plan.conflicts, reason})),
                )
                with self.assertRaises(ValueError):
                    transaction.apply_transaction(
                        replace(uninstall, targets=(altered_target,))
                    )
                self.assertEqual(destination.read_bytes(), b"user drifted bytes\n")

    def test_complete_reduced_manifest_recovery_skips_unresolved_current_drift(self):
        from subagents_configs import transaction

        home, destination, uninstall = self._uninstall_with_drifted_preexisting_entry()
        self._apply_leaving_journals(uninstall)
        destination.write_bytes(b"user changed after uninstall\n")
        destination.chmod(0o600)
        transaction.recover_incomplete_journal(home, descriptor_for(Target.CODEX))
        self.assertEqual(destination.read_bytes(), b"user changed after uninstall\n")
        self.assertFalse((home / ".subagents_configs/journal.json").exists())

    def test_mid_uninstall_failure_rolls_back_while_retaining_unresolved_entry(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        home, destination, uninstall = self._uninstall_with_drifted_preexisting_entry()
        manifest_operation = next(
            item
            for item in uninstall.targets[0].operations
            if item.identifier == "state/manifest"
        )
        ordered = sorted(
            uninstall.targets[0].operations,
            key=lambda item: (
                item.action == "write-manifest",
                item.relative_path,
                item.identifier,
            ),
        )
        manifest_index = ordered.index(manifest_operation)

        class FailAtManifest:
            def before_operation(self, operation_id):
                if operation_id == transaction._operation_id(
                    Target.CODEX, manifest_index, "state/manifest"
                ):
                    raise RuntimeError("manifest failure")

        with self.assertRaises(RuntimeError):
            apply_transaction(uninstall, FailAtManifest())
        self.assertEqual(destination.read_bytes(), b"user retained bytes\n")
        self.assertTrue((home / "agents/code-reviewer.toml").exists())
        self.assertFalse((home / ".subagents_configs/journal.json").exists())

    def test_routing_and_codex_feature_blocks_are_applied_before_manifest(self):
        from subagents_configs import transaction

        plan = self._plan(
            Target.CODEX,
            enable_global_routing=True,
            enable_codex_multi_agent=True,
        )
        transaction.apply_transaction(plan)
        home = self._home()
        self.assertIn(
            b"BEGIN SUBAGENTS_CONFIGS routing-codex", (home / "AGENTS.md").read_bytes()
        )
        self.assertIn(
            b"BEGIN SUBAGENTS_CONFIGS codex-multi-agent-v2",
            (home / "config.toml").read_bytes(),
        )
        self.assertIsNotNone(load_manifest(home, descriptor_for(Target.CODEX)))

    def test_hash_tampering_is_rejected_before_any_write(self):
        from dataclasses import replace

        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX)
        operation = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "code-explorer"
        )
        tampered = replace(operation, expected_after_hash="0" * 64)
        target_plan = replace(
            plan.targets[0], operations=(tampered, *plan.targets[0].operations[1:])
        )
        with self.assertRaises(ValueError):
            apply_transaction(replace(plan, targets=(target_plan,)))
        self.assertFalse(self._home().exists())

    def test_destination_alias_plan_links_to_canonical_manifest_entry(self):
        from dataclasses import replace

        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX)
        operation = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "code-explorer"
        )
        alias = replace(operation, identifier=operation.relative_path)
        target_plan = replace(
            plan.targets[0],
            operations=tuple(
                alias if item.identifier == operation.identifier else item
                for item in plan.targets[0].operations
            ),
        )
        apply_transaction(replace(plan, targets=(target_plan,)))
        self.assertTrue((self._home() / "agents/code-explorer.toml").exists())

    def test_destination_alias_collision_is_rejected_by_canonical_path(self):
        from dataclasses import replace

        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX)
        first = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "code-explorer"
        )
        second = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "code-reviewer"
        )
        altered = replace(second, identifier=first.relative_path)
        target_plan = replace(
            plan.targets[0],
            operations=tuple(
                altered if item.identifier == second.identifier else item
                for item in plan.targets[0].operations
            ),
        )
        with self.assertRaises(ValueError):
            apply_transaction(replace(plan, targets=(target_plan,)))

    def test_destination_alias_plan_links_canonical_managed_block(self):
        from dataclasses import replace

        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX, enable_global_routing=True)
        operation = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "routing-codex"
        )
        alias = replace(operation, identifier="AGENTS.md")
        target_plan = replace(
            plan.targets[0],
            operations=tuple(
                alias if item.identifier == operation.identifier else item
                for item in plan.targets[0].operations
            ),
        )
        apply_transaction(replace(plan, targets=(target_plan,)))
        self.assertIn(
            b"BEGIN SUBAGENTS_CONFIGS routing-codex",
            (self._home() / "AGENTS.md").read_bytes(),
        )

    def test_manifest_entry_tampering_is_rejected_before_directory_creation(self):
        from dataclasses import replace

        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        destination = home / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"user-owned bytes\n")
        destination.chmod(0o600)
        plan = self._plan(Target.CODEX)
        manifest = plan.targets[0].resulting_manifest
        entry = next(
            item for item in manifest.entries if item.identifier == "code-explorer"
        )
        tampered_entry = replace(entry, installed_hash="0" * 64)
        tampered_manifest = replace(
            manifest,
            entries=tuple(
                tampered_entry if item.identifier == entry.identifier else item
                for item in manifest.entries
            ),
        )
        manifest_bytes = encode_manifest(tampered_manifest)
        manifest_operation = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "state/manifest"
        )
        tampered_operation = replace(
            manifest_operation,
            content=manifest_bytes,
            expected_after_hash=hashlib.sha256(manifest_bytes).hexdigest(),
        )
        tampered_target = replace(
            plan.targets[0],
            operations=tuple(
                tampered_operation if item.identifier == "state/manifest" else item
                for item in plan.targets[0].operations
            ),
            resulting_manifest=tampered_manifest,
        )
        with patch.object(transaction.filesystem, "ensure_directory") as ensure:
            with self.assertRaises(ValueError):
                apply_transaction(replace(plan, targets=(tampered_target,)))
        ensure.assert_not_called()
        self.assertFalse((home / ".subagents_configs").exists())

    def test_manifest_backup_aliasing_is_rejected_before_directory_creation(self):
        from dataclasses import replace

        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        home = self._home()
        for name, content in (
            ("code-explorer.toml", b"old explorer\n"),
            ("code-reviewer.toml", b"old reviewer\n"),
        ):
            destination = home / "agents" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            destination.chmod(0o600)
        plan = self._plan(Target.CODEX)
        manifest = plan.targets[0].resulting_manifest
        first = next(
            item for item in manifest.entries if item.identifier == "code-explorer"
        )
        second = next(
            item for item in manifest.entries if item.identifier == "code-reviewer"
        )
        aliased = replace(
            manifest,
            entries=tuple(
                replace(
                    item, backup_path=first.backup_path, backup_hash=first.backup_hash
                )
                if item.identifier == second.identifier
                else item
                for item in manifest.entries
            ),
        )
        manifest_bytes = encode_manifest(aliased)
        operation = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "state/manifest"
        )
        operation = replace(
            operation,
            content=manifest_bytes,
            expected_after_hash=hashlib.sha256(manifest_bytes).hexdigest(),
        )
        target = replace(
            plan.targets[0],
            operations=tuple(
                operation if item.identifier == "state/manifest" else item
                for item in plan.targets[0].operations
            ),
            resulting_manifest=aliased,
        )
        with patch.object(transaction.filesystem, "ensure_directory") as ensure:
            with self.assertRaises(ValueError):
                apply_transaction(replace(plan, targets=(target,)))
        ensure.assert_not_called()

    def test_replaced_block_manifest_cannot_drop_before_state_backup_linkage(self):
        from dataclasses import replace

        from subagents_configs.transaction import apply_transaction

        home = self._home()
        destination = home / "AGENTS.md"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"user routing content\n")
        destination.chmod(0o600)
        plan = self._plan(Target.CODEX, enable_global_routing=True)
        manifest = plan.targets[0].resulting_manifest
        entry = next(
            item for item in manifest.entries if item.identifier == "routing-codex"
        )
        tampered_entry = replace(
            entry,
            ownership="created",
            backup_path=None,
            backup_hash=None,
            original_mode=None,
        )
        tampered_manifest = replace(
            manifest,
            entries=tuple(
                tampered_entry if item.identifier == entry.identifier else item
                for item in manifest.entries
            ),
        )
        manifest_bytes = encode_manifest(tampered_manifest)
        manifest_operation = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "state/manifest"
        )
        tampered_operation = replace(
            manifest_operation,
            content=manifest_bytes,
            expected_after_hash=hashlib.sha256(manifest_bytes).hexdigest(),
        )
        target_plan = replace(
            plan.targets[0],
            operations=tuple(
                tampered_operation if item.identifier == "state/manifest" else item
                for item in plan.targets[0].operations
            ),
            resulting_manifest=tampered_manifest,
        )
        with self.assertRaises(ValueError):
            apply_transaction(replace(plan, targets=(target_plan,)))

    def test_complete_empty_journal_is_preserved_and_rejected(self):
        from subagents_configs import transaction

        home = self._home()
        transaction.filesystem.ensure_private_directory(home / ".subagents_configs")
        journal = Journal(
            1,
            "empty-complete",
            Target.CODEX,
            (Target.CODEX,),
            "install",
            (),
            "complete",
        )
        journal_path = home / ".subagents_configs/journal.json"
        journal_path.write_bytes(encode_journal(journal))
        journal_path.chmod(0o600)
        with self.assertRaises((transaction.IncompleteRollbackError, ValueError)):
            transaction.recover_incomplete_journal(home, descriptor_for(Target.CODEX))
        self.assertTrue(journal_path.exists())

    def test_noop_apply_does_not_create_a_journal(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        transaction.apply_transaction(plan)
        noop = self._plan(Target.CODEX)
        with patch.object(transaction, "_write_journal") as write_journal:
            transaction.apply_transaction(noop)
        write_journal.assert_not_called()

    def test_successful_transaction_leaves_durable_external_commitment_marker(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        self._apply_leaving_journals(plan)
        journal = load_journal(self._home(), descriptor_for(Target.CODEX))
        nonce, digest = journal.transaction_id.rsplit("-", 1)
        marker = self._home() / ".subagents_configs/backups" / f"commitment-{nonce}"
        self.assertEqual(marker.read_bytes(), f"{nonce}:{digest}".encode())
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        transaction.recover_incomplete_journal(
            self._home(), descriptor_for(Target.CODEX)
        )
        self.assertFalse((self._home() / ".subagents_configs/journal.json").exists())
        self.assertTrue(marker.exists())

    def test_recovery_rejects_self_rehashed_sparse_journal_and_preserves_marker(self):
        from dataclasses import replace

        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        self._apply_leaving_journals(plan)
        home = self._home()
        journal = load_journal(home, descriptor_for(Target.CODEX))
        nonce, _ = journal.transaction_id.rsplit("-", 1)
        altered = replace(journal, operations=journal.operations[1:])
        altered = replace(
            altered,
            transaction_id=transaction._committed_transaction_id(nonce, (altered,)),
        )
        (home / ".subagents_configs/journal.json").write_bytes(encode_journal(altered))
        with self.assertRaises((transaction.IncompleteRollbackError, ValueError)):
            transaction.recover_incomplete_journal(home, descriptor_for(Target.CODEX))
        self.assertTrue((home / ".subagents_configs/journal.json").exists())
        self.assertTrue(
            (home / ".subagents_configs/backups" / f"commitment-{nonce}").exists()
        )

    def test_recovery_rejects_missing_or_unsafe_commitment_marker(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        self._apply_leaving_journals(plan)
        home = self._home()
        journal = load_journal(home, descriptor_for(Target.CODEX))
        nonce, _ = journal.transaction_id.rsplit("-", 1)
        marker = home / ".subagents_configs/backups" / f"commitment-{nonce}"
        marker.unlink()
        with self.assertRaises((transaction.IncompleteRollbackError, ValueError)):
            transaction.recover_incomplete_journal(home, descriptor_for(Target.CODEX))
        self.assertTrue((home / ".subagents_configs/journal.json").exists())

        marker.write_bytes(b"0" * 64)
        marker.chmod(0o644)
        with self.assertRaises((transaction.IncompleteRollbackError, ValueError)):
            transaction.recover_incomplete_journal(home, descriptor_for(Target.CODEX))
        self.assertTrue((home / ".subagents_configs/journal.json").exists())

    def test_recovery_rejects_commitment_marker_symlink(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        self._apply_leaving_journals(plan)
        home = self._home()
        journal = load_journal(home, descriptor_for(Target.CODEX))
        nonce, _ = journal.transaction_id.rsplit("-", 1)
        marker = home / ".subagents_configs/backups" / f"commitment-{nonce}"
        outside = self.root / "marker-target"
        outside.write_bytes(b"0" * 64)
        marker.unlink()
        marker.symlink_to(outside)
        with self.assertRaises((transaction.IncompleteRollbackError, ValueError)):
            transaction.recover_incomplete_journal(home, descriptor_for(Target.CODEX))
        self.assertTrue((home / ".subagents_configs/journal.json").exists())

    def test_multi_home_recovery_rejects_swapped_commitment_markers(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        self._apply_leaving_journals(plan)
        homes = [self._home(Target.CODEX), self._home(Target.OPENCODE)]
        journals = [
            load_journal(home, descriptor_for(target))
            for home, target in zip(homes, (Target.CODEX, Target.OPENCODE), strict=True)
        ]
        markers = [
            home
            / ".subagents_configs/backups"
            / f"commitment-{journal.transaction_id.split('-', 1)[0]}"
            for home, journal in zip(homes, journals, strict=True)
        ]
        first = markers[0].read_bytes()
        markers[0].write_bytes(markers[1].read_bytes())
        markers[1].write_bytes(first)
        markers[0].write_bytes(b"0" * 32 + b":" + first.split(b":", 1)[1])
        with self.assertRaises(transaction.IncompleteRollbackError):
            transaction._recover_participants(
                {Target.CODEX: homes[0], Target.OPENCODE: homes[1]}
            )
        for home in homes:
            self.assertTrue((home / ".subagents_configs/journal.json").exists())

    def test_participant_journal_preparation_failure_cleans_partial_journals(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        real_write = transaction._write_journal
        calls = 0

        def fail_second(home, journal):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("journal fsync failed")
            return real_write(home, journal)

        with patch.object(transaction, "_write_journal", fail_second):
            with self.assertRaises(transaction.TransactionPreparationError):
                apply_transaction(plan)
        for target in (Target.CODEX, Target.OPENCODE):
            self.assertFalse(
                (self._home(target) / ".subagents_configs/journal.json").exists()
            )

    def test_post_replace_journal_failure_also_cleans_every_installed_journal(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        real_atomic = transaction.filesystem.atomic_write
        journal_calls = 0

        def fail_after_replace(path, content, mode=0o600):
            nonlocal journal_calls
            if Path(path).name == "journal.json":
                journal_calls += 1
                real_atomic(path, content, mode)
                if journal_calls == 2:
                    raise OSError("post-replace journal sync failed")
                return
            return real_atomic(path, content, mode)

        with patch.object(transaction.filesystem, "atomic_write", fail_after_replace):
            with self.assertRaises(transaction.TransactionPreparationError):
                apply_transaction(plan)
        for target in (Target.CODEX, Target.OPENCODE):
            self.assertFalse(
                (self._home(target) / ".subagents_configs/journal.json").exists()
            )

    def test_injected_baseexception_rolls_back_then_reraises_primary(self):
        from subagents_configs.transaction import apply_transaction

        class StopNow:
            def before_operation(self, operation_id):
                raise KeyboardInterrupt(operation_id)

        plan = self._plan(Target.CODEX)
        with self.assertRaises(KeyboardInterrupt):
            apply_transaction(plan, StopNow())
        self.assertFalse((self._home() / "agents/code-explorer.toml").exists())

    def test_system_exit_with_incomplete_rollback_preserves_primary_type_and_evidence(
        self,
    ):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX)
        operations = sorted(
            (
                item
                for item in plan.targets[0].operations
                if item.action != "write-manifest"
            ),
            key=lambda item: (item.relative_path, item.identifier),
        )
        drifted = self._home() / operations[0].relative_path
        stop_id = transaction._operation_id(Target.CODEX, 1, operations[1].identifier)

        class StopAfterDrift:
            def before_operation(self, operation_id):
                if operation_id == stop_id:
                    drifted.parent.mkdir(parents=True, exist_ok=True)
                    drifted.write_bytes(b"concurrent drift")
                    drifted.chmod(0o600)
                    raise SystemExit("stop now")

        with self.assertRaises(SystemExit):
            apply_transaction(plan, StopAfterDrift())
        self.assertTrue((self._home() / ".subagents_configs/journal.json").exists())

    def test_exact_mapping_coordinator_rejects_participant_disagreement_without_writes(
        self,
    ):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        transaction._prepare(plan)
        other_home = self._home(Target.OPENCODE)
        other_journal = load_journal(other_home, descriptor_for(Target.OPENCODE))
        altered = transaction.replace(other_journal, transaction_id="different-id")
        transaction.filesystem.atomic_write(
            other_home / ".subagents_configs/journal.json", encode_journal(altered)
        )
        with patch.object(transaction.filesystem, "atomic_write") as write:
            with self.assertRaises(transaction.IncompleteRollbackError):
                transaction._recover_participants(
                    {
                        Target.CODEX: self._home(Target.CODEX),
                        Target.OPENCODE: other_home,
                    }
                )
        write.assert_not_called()

    def test_exact_mapping_coordinator_verifies_and_cleans_all_complete_journals(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        with patch.object(transaction, "_sync_and_remove_journal"):
            transaction.apply_transaction(plan)
        homes = {
            Target.CODEX: self._home(Target.CODEX),
            Target.OPENCODE: self._home(Target.OPENCODE),
        }
        transaction._recover_participants(homes)
        for home in homes.values():
            self.assertFalse((home / ".subagents_configs/journal.json").exists())

    def test_runtime_and_claude_managed_writes_are_applied(self):
        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX, Target.CLAUDE_CODE)
        apply_transaction(plan)
        self.assertTrue(
            (self._home(Target.CLAUDE_CODE) / "agents/code-explorer.md").exists()
        )
        self.assertTrue(
            (
                self._home(Target.CLAUDE_CODE)
                / ".subagents_configs/validation/run-validation-isolated.py"
            ).exists()
        )

    def test_rollback_failure_preserves_journal_and_verified_backup(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        runtime = (
            self._home() / ".subagents_configs/validation/run-validation-isolated.py"
        )
        runtime.parent.mkdir(parents=True)
        (self._home() / ".subagents_configs").chmod(0o700)
        runtime.parent.chmod(0o700)
        runtime.write_bytes(b"user runtime bytes\n")
        runtime.chmod(0o600)
        (self._home() / ".subagents_configs/manifest.json").write_bytes(
            encode_manifest(Manifest(1, Target.CODEX, ()))
        )
        (self._home() / ".subagents_configs/manifest.json").chmod(0o600)
        plan = self._plan(Target.CODEX)
        calls = 0

        class DriftThenFail:
            def before_operation(self, operation_id):
                nonlocal calls
                calls += 1
                if calls == 2:
                    runtime.write_bytes(b"concurrent drift\n")
                    raise RuntimeError("injected later failure")

        with self.assertRaises(transaction.IncompleteRollbackError):
            apply_transaction(plan, DriftThenFail())
        self.assertTrue((self._home() / ".subagents_configs/journal.json").exists())
        backups = list((self._home() / ".subagents_configs/backups").iterdir())
        self.assertTrue(backups)

    def test_cleanup_failure_is_chained_and_journal_is_preserved(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX)

        class FailBefore:
            def before_operation(self, operation_id):
                raise RuntimeError("primary failure")

        with patch.object(
            transaction, "_sync_and_remove_journal", side_effect=OSError("cleanup")
        ):
            with self.assertRaises(transaction.IncompleteRollbackError) as error:
                apply_transaction(plan, FailBefore())
        self.assertIn("primary failure", str(error.exception))
        self.assertIn("cleanup", str(error.exception))
        self.assertTrue((self._home() / ".subagents_configs/journal.json").exists())

    def test_environment_cannot_activate_a_failure_injector(self):
        from subagents_configs.transaction import apply_transaction

        plan = self._plan(Target.CODEX)
        with patch.dict(
            os.environ,
            {"SUBAGENTS_CONFIGS_FAILURE_INJECTOR": "raise-everything"},
        ):
            apply_transaction(plan)

    def test_recovery_accepts_canonical_destination_alias(self):
        from dataclasses import replace

        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        self._apply_leaving_journals(plan)
        operation = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "code-explorer"
        )
        state = self._home() / ".subagents_configs"
        journal = load_journal(self._home(), descriptor_for(Target.CODEX))
        nonce, _digest = journal.transaction_id.rsplit("-", 1)
        alias_operation = replace(
            next(
                item
                for item in journal.operations
                if item.identifier == "code-explorer"
            ),
            identifier=operation.relative_path,
            operation_id=transaction._operation_id(
                Target.CODEX,
                next(
                    index
                    for index, item in enumerate(journal.operations)
                    if item.identifier == operation.identifier
                ),
                operation.relative_path,
            ),
            status="applied",
        )
        journal = replace(
            journal,
            operations=tuple(
                alias_operation if item.identifier == operation.identifier else item
                for item in journal.operations
            ),
        )
        journal = replace(
            journal,
            transaction_id=transaction._committed_transaction_id(nonce, (journal,)),
        )
        transaction.filesystem.atomic_write(
            state / "journal.json", encode_journal(journal)
        )
        transaction.recover_incomplete_journal(
            self._home(), descriptor_for(Target.CODEX)
        )
        self.assertTrue((self._home() / operation.relative_path).exists())
        self.assertFalse((self._home() / ".subagents_configs/journal.json").exists())

    def test_recovery_of_single_target_interrupted_operation_rolls_back(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        target_plan = plan.targets[0]
        operation = next(
            item
            for item in target_plan.operations
            if item.identifier == "code-explorer"
        )
        ordered = sorted(
            target_plan.operations,
            key=lambda item: (
                item.action == "write-manifest",
                item.relative_path,
                item.identifier,
            ),
        )
        operation_index = ordered.index(operation)
        transaction.filesystem.ensure_private_directory(
            self._home() / ".subagents_configs"
        )
        transaction.filesystem.ensure_private_directory(self._home() / "agents")
        transaction.filesystem.atomic_write(
            self._home() / "agents" / "code-explorer.toml",
            operation.content or b"",
            operation.expected_after_mode or 0o600,
        )
        journal = transaction._journal_for_plan(plan, "recovery-test")
        journal = transaction.replace(
            journal,
            operations=tuple(
                transaction.replace(
                    item, status="applied" if i == operation_index else "planned"
                )
                for i, item in enumerate(journal.operations)
            ),
        )
        transaction.filesystem.atomic_write(
            self._home() / ".subagents_configs/journal.json",
            transaction.encode_journal(journal),
        )
        journal_path = self._home() / ".subagents_configs/journal.json"
        transaction.recover_incomplete_journal(
            self._home(), descriptor_for(Target.CODEX)
        )
        self.assertFalse(journal_path.exists())
        self.assertFalse((self._home() / "agents/code-explorer.toml").exists())

    def test_complete_matching_journal_recovery_only_cleans_journal(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        with patch.object(transaction, "_sync_and_remove_journal"):
            transaction.apply_transaction(plan)
        home = self._home()
        descriptor = descriptor_for(Target.CODEX)
        before = (home / "agents/code-explorer.toml").read_bytes()
        transaction.recover_incomplete_journal(home, descriptor)
        self.assertFalse((home / ".subagents_configs/journal.json").exists())
        self.assertEqual((home / "agents/code-explorer.toml").read_bytes(), before)

    def test_journal_cleanup_recreates_unlinked_journal_when_state_sync_fails(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        self._apply_leaving_journals(plan)
        home = self._home()
        descriptor = descriptor_for(Target.CODEX)
        with patch.object(
            transaction.filesystem,
            "sync_directory",
            side_effect=[OSError("state fsync failed"), None],
        ):
            with self.assertRaises(OSError):
                transaction.recover_incomplete_journal(home, descriptor)
        self.assertTrue((home / ".subagents_configs/journal.json").exists())
        transaction.recover_incomplete_journal(home, descriptor)
        self.assertFalse((home / ".subagents_configs/journal.json").exists())

    def test_journal_cleanup_reports_recreation_failure_after_unlink(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        self._apply_leaving_journals(plan)
        home = self._home()
        descriptor = descriptor_for(Target.CODEX)
        with (
            patch.object(
                transaction.filesystem,
                "sync_directory",
                side_effect=OSError("state fsync failed"),
            ),
            patch.object(
                transaction.filesystem,
                "atomic_write",
                side_effect=OSError("journal recreate failed"),
            ),
        ):
            with self.assertRaises(transaction.TransactionError) as error:
                transaction.recover_incomplete_journal(home, descriptor)
        self.assertIn("state fsync failed", str(error.exception))
        self.assertIn("journal recreate failed", str(error.exception))

    def test_complete_recovery_rejects_sparse_journal_with_original_transaction_id(
        self,
    ):
        from dataclasses import replace

        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        self._apply_leaving_journals(plan)
        home = self._home()
        descriptor = descriptor_for(Target.CODEX)
        journal = load_journal(home, descriptor)
        operations = [
            item for item in journal.operations if item.identifier != "state/manifest"
        ]
        omitted = operations.pop(0)
        del omitted
        operations.append(
            next(
                item
                for item in journal.operations
                if item.identifier == "state/manifest"
            )
        )
        operations = tuple(
            replace(
                item,
                operation_id=transaction._operation_id(
                    journal.target, index, item.identifier
                ),
            )
            for index, item in enumerate(operations)
        )
        altered = replace(journal, operations=operations)
        transaction.filesystem.atomic_write(
            home / ".subagents_configs/journal.json", encode_journal(altered)
        )
        with self.assertRaises(transaction.IncompleteRollbackError):
            transaction.recover_incomplete_journal(home, descriptor)
        self.assertTrue((home / ".subagents_configs/journal.json").exists())

    def test_complete_recovery_rejects_reordered_journal_with_original_transaction_id(
        self,
    ):
        from dataclasses import replace

        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        self._apply_leaving_journals(plan)
        home = self._home()
        descriptor = descriptor_for(Target.CODEX)
        journal = load_journal(home, descriptor)
        managed = [
            item for item in journal.operations if item.identifier != "state/manifest"
        ]
        managed[0], managed[1] = managed[1], managed[0]
        operations = tuple(
            replace(
                item,
                operation_id=transaction._operation_id(
                    journal.target, index, item.identifier
                ),
            )
            for index, item in enumerate((*managed, journal.operations[-1]))
        )
        altered = replace(journal, operations=operations)
        transaction.filesystem.atomic_write(
            home / ".subagents_configs/journal.json", encode_journal(altered)
        )
        with self.assertRaises(transaction.IncompleteRollbackError):
            transaction.recover_incomplete_journal(home, descriptor)
        self.assertTrue((home / ".subagents_configs/journal.json").exists())

    def test_complete_recovery_rejects_duplicate_operation_with_original_transaction_id(
        self,
    ):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        self._apply_leaving_journals(plan)
        home = self._home()
        journal_path = home / ".subagents_configs/journal.json"
        raw = json.loads(journal_path.read_text())
        raw["operations"].insert(1, raw["operations"][0].copy())
        journal_path.write_text(
            json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n"
        )
        journal_path.chmod(0o600)
        with self.assertRaises(ValueError):
            transaction.recover_incomplete_journal(home, descriptor_for(Target.CODEX))
        self.assertTrue(journal_path.exists())

    def test_multi_home_recovery_rejects_sparse_journal_before_cleaning_any_home(self):
        from dataclasses import replace

        from subagents_configs import transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        self._apply_leaving_journals(plan)
        homes = {
            Target.CODEX: self._home(Target.CODEX),
            Target.OPENCODE: self._home(Target.OPENCODE),
        }
        descriptor = descriptor_for(Target.OPENCODE)
        journal = load_journal(homes[Target.OPENCODE], descriptor)
        managed = [
            item for item in journal.operations if item.identifier != "state/manifest"
        ]
        managed.pop(0)
        operations = tuple(
            replace(
                item,
                operation_id=transaction._operation_id(
                    journal.target, index, item.identifier
                ),
            )
            for index, item in enumerate((*managed, journal.operations[-1]))
        )
        transaction.filesystem.atomic_write(
            homes[Target.OPENCODE] / ".subagents_configs/journal.json",
            encode_journal(replace(journal, operations=operations)),
        )
        with self.assertRaises(transaction.IncompleteRollbackError):
            transaction._recover_participants(homes)
        for home in homes.values():
            self.assertTrue((home / ".subagents_configs/journal.json").exists())

    def test_multi_home_recovery_rejects_self_rehashed_sparse_journal(self):
        from dataclasses import replace

        from subagents_configs import transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        self._apply_leaving_journals(plan)
        homes = {
            Target.CODEX: self._home(Target.CODEX),
            Target.OPENCODE: self._home(Target.OPENCODE),
        }
        journals = {
            target: load_journal(home, descriptor_for(target))
            for target, home in homes.items()
        }
        altered = replace(
            journals[Target.OPENCODE],
            operations=journals[Target.OPENCODE].operations[1:],
        )
        nonce, _ = journals[Target.CODEX].transaction_id.rsplit("-", 1)
        altered_id = transaction._committed_transaction_id(
            nonce, (journals[Target.CODEX], altered)
        )
        transaction.filesystem.atomic_write(
            homes[Target.OPENCODE] / ".subagents_configs/journal.json",
            encode_journal(replace(altered, transaction_id=altered_id)),
        )
        with self.assertRaises(transaction.IncompleteRollbackError):
            transaction._recover_participants(homes)
        for home in homes.values():
            self.assertTrue((home / ".subagents_configs/journal.json").exists())

    def test_multi_home_recovery_rejects_reversed_descriptor_order_without_writes(self):
        from dataclasses import replace

        from subagents_configs import transaction

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        self._apply_leaving_journals(plan)
        homes = {
            Target.CODEX: self._home(Target.CODEX),
            Target.OPENCODE: self._home(Target.OPENCODE),
        }
        for target, home in homes.items():
            descriptor = descriptor_for(target)
            journal = load_journal(home, descriptor)
            transaction.filesystem.atomic_write(
                home / ".subagents_configs/journal.json",
                encode_journal(
                    replace(
                        journal,
                        participants=(Target.OPENCODE, Target.CODEX),
                    )
                ),
            )
        reversed_homes = {
            Target.OPENCODE: homes[Target.OPENCODE],
            Target.CODEX: homes[Target.CODEX],
        }
        with self.assertRaises(ValueError):
            transaction._recover_participants(reversed_homes)
        for home in homes.values():
            self.assertTrue((home / ".subagents_configs/journal.json").exists())

    def test_ambiguous_recovery_preserves_journal_and_raises(self):
        from subagents_configs import transaction

        plan = self._plan(Target.CODEX)
        operation = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "code-explorer"
        )
        ordered = sorted(
            plan.targets[0].operations,
            key=lambda item: (
                item.action == "write-manifest",
                item.relative_path,
                item.identifier,
            ),
        )
        operation_index = ordered.index(operation)
        transaction.filesystem.ensure_private_directory(
            self._home() / ".subagents_configs"
        )
        journal = transaction._journal_for_plan(plan, "recovery-test")
        journal = transaction.replace(
            journal,
            operations=tuple(
                transaction.replace(
                    item, status="applied" if i == operation_index else "planned"
                )
                for i, item in enumerate(journal.operations)
            ),
        )
        transaction.filesystem.atomic_write(
            self._home() / ".subagents_configs/journal.json",
            transaction.encode_journal(journal),
        )
        managed = self._home() / "agents/code-explorer.toml"
        managed.parent.mkdir(parents=True, exist_ok=True)
        managed.write_bytes(b"user drift")
        managed.chmod(0o600)
        with self.assertRaises(transaction.IncompleteRollbackError):
            transaction.recover_incomplete_journal(
                self._home(), descriptor_for(Target.CODEX)
            )
        self.assertTrue((self._home() / ".subagents_configs/journal.json").exists())

    def test_multi_target_single_home_recovery_refuses_with_required_participants(self):
        from subagents_configs import transaction
        from subagents_configs.transaction import recover_incomplete_journal

        plan = self._plan(Target.CODEX, Target.OPENCODE)
        transaction._prepare(plan)
        with self.assertRaises(ValueError) as recovery_error:
            recover_incomplete_journal(self._home(), descriptor_for(Target.CODEX))
        self.assertIn("codex", str(recovery_error.exception))
        self.assertIn("opencode", str(recovery_error.exception))
        self.assertTrue((self._home() / ".subagents_configs/journal.json").exists())


if __name__ == "__main__":
    unittest.main()
