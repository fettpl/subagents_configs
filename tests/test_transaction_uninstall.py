import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from subagents_configs import filesystem
from subagents_configs.blocks import _markers
from subagents_configs.models import Target
from subagents_configs.planning import preflight_install, preflight_uninstall
from subagents_configs.state import load_journal, load_manifest
from subagents_configs.targets import descriptor_for
from subagents_configs.transaction import (
    IncompleteRollbackError,
    TransactionError,
    apply_transaction,
)
from tests.helpers import planning_repository, planning_request


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            dir="/private/tmp" if Path("/private/tmp").is_dir() else None
        )
        self.root = Path(self.temporary.name)
        self.repository = planning_repository(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def _home(self, target=Target.CODEX):
        return self.root / f"home-{target.value}"

    def _install(self, target=Target.CODEX, **options):
        home = self._home(target)
        plan = preflight_install(
            self.repository,
            planning_request("install", {target: home}, **options),
        )
        apply_transaction(plan)
        return home

    def _uninstall_plan(self, home, target=Target.CODEX, *, dry_run=False):
        return preflight_uninstall(
            self.repository,
            planning_request("uninstall", {target: home}, dry_run=dry_run),
        )

    def _snapshot_tree(self, root):
        snapshot = []
        for directory, names, files in os.walk(root, followlinks=False):
            current = Path(directory)
            for name in sorted((*names, *files)):
                path = current / name
                relative = path.relative_to(root).as_posix()
                result = os.lstat(path)
                mode = stat.S_IMODE(result.st_mode)
                if stat.S_ISLNK(result.st_mode):
                    value = ("symlink", mode, os.readlink(path))
                elif stat.S_ISREG(result.st_mode):
                    value = ("file", mode, path.read_bytes())
                elif stat.S_ISDIR(result.st_mode):
                    value = ("directory", mode, None)
                else:
                    value = ("other", mode, None)
                snapshot.append((relative, value))
        return tuple(snapshot)

    def test_created_file_is_removed_and_manifest_is_removed(self):
        home = self._install()
        destination = home / "agents/code-explorer.toml"
        self.assertTrue(destination.exists())

        plan = self._uninstall_plan(home)
        operation = next(
            item
            for item in plan.targets[0].operations
            if item.identifier == "code-explorer"
        )
        self.assertEqual(operation.action, "remove")
        apply_transaction(plan)

        self.assertFalse(destination.exists())
        self.assertFalse((home / ".subagents_configs/manifest.json").exists())
        self.assertTrue((home / ".subagents_configs").is_dir())
        self.assertTrue((home / ".subagents_configs/backups").is_dir())

    def test_uninstall_failure_injector_preserves_the_installed_tree(self):
        home = self._install()
        before = self._snapshot_tree(home)
        plan = self._uninstall_plan(home)

        class FailBeforeUninstall:
            def before_operation(self, _operation_id):
                raise RuntimeError("injected uninstall failure")

        with self.assertRaises((RuntimeError, TransactionError)):
            apply_transaction(plan, failure_injector=FailBeforeUninstall())
        self.assertEqual(self._snapshot_tree(home), before)

    def test_replaced_file_is_restored_with_original_bytes_and_mode(self):
        home = self._home()
        destination = home / "agents/code-explorer.toml"
        original = b"user-owned agent\n"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(original)
        destination.chmod(0o644)

        install = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        )
        apply_transaction(install)
        uninstall = self._uninstall_plan(home)
        operation = next(
            item
            for item in uninstall.targets[0].operations
            if item.identifier == "code-explorer"
        )
        self.assertEqual(operation.action, "restore")
        apply_transaction(uninstall)

        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o644)

    def test_preexisting_file_is_retained_as_unresolved(self):
        home = self._home()
        destination = home / "agents/code-explorer.toml"
        content = (self.repository / "agents/code-explorer.toml").read_bytes()
        destination.parent.mkdir(parents=True)
        destination.write_bytes(content)
        destination.chmod(0o600)
        self._install()

        before = destination.read_bytes()
        plan = self._uninstall_plan(home)
        entry = next(
            item
            for item in plan.targets[0].resulting_manifest.entries
            if item.identifier == "code-explorer"
        )
        self.assertEqual(entry.ownership, "preexisting")
        self.assertIsNotNone(entry.unresolved_reason)
        self.assertFalse(
            any(
                item.identifier == "code-explorer"
                for item in plan.targets[0].operations
            )
        )
        apply_transaction(plan)
        self.assertEqual(destination.read_bytes(), before)
        self.assertIsNotNone(load_manifest(home, descriptor_for(Target.CODEX)))

    def test_modified_and_missing_files_are_retained_with_reasons(self):
        home = self._install()
        modified = home / "agents/code-explorer.toml"
        modified.write_bytes(b"user changed\n")
        missing = home / "agents/code-reviewer.toml"
        missing.unlink()

        plan = self._uninstall_plan(home).targets[0]
        modified_entry = next(
            item
            for item in plan.resulting_manifest.entries
            if item.identifier == "code-explorer"
        )
        missing_entry = next(
            item
            for item in plan.resulting_manifest.entries
            if item.identifier == "code-reviewer"
        )
        self.assertIn("drifted", modified_entry.unresolved_reason or "")
        self.assertIn("missing", missing_entry.unresolved_reason or "")
        apply_transaction(self._uninstall_plan(home))
        self.assertEqual(modified.read_bytes(), b"user changed\n")
        self.assertFalse(missing.exists())

    def test_routing_block_removal_preserves_surrounding_edits(self):
        home = self._install(enable_global_routing=True)
        instructions = home / "AGENTS.md"
        current = instructions.read_bytes()
        instructions.write_bytes(b"user prefix\n" + current + b"user suffix\n")

        plan = self._uninstall_plan(home).targets[0]
        routing = next(
            item for item in plan.operations if item.identifier == "routing-codex"
        )
        self.assertEqual(routing.action, "remove-block")
        apply_transaction(self._uninstall_plan(home))

        self.assertEqual(instructions.read_bytes(), b"user prefix\nuser suffix\n")

    def test_created_block_file_keeps_new_user_content(self):
        home = self._install(enable_global_routing=True)
        instructions = home / "AGENTS.md"
        current = instructions.read_bytes()
        instructions.write_bytes(b"user prefix\n" + current + b"user suffix\n")

        apply_transaction(self._uninstall_plan(home))
        self.assertEqual(instructions.read_bytes(), b"user prefix\nuser suffix\n")

    def test_replaced_block_does_not_clobber_surrounding_user_edits(self):
        home = self._home()
        instructions = home / "AGENTS.md"
        instructions.parent.mkdir(parents=True)
        instructions.write_bytes(b"old prefix\nold suffix\n")
        instructions.chmod(0o644)
        self._install(enable_global_routing=True)

        installed = instructions.read_bytes()
        instructions.write_bytes(b"new prefix\n" + installed + b"new suffix\n")
        instructions.chmod(0o600)
        plan = self._uninstall_plan(home).targets[0]
        routing = next(
            item for item in plan.operations if item.identifier == "routing-codex"
        )
        self.assertEqual(routing.action, "remove-block")
        apply_transaction(self._uninstall_plan(home))

        self.assertEqual(
            instructions.read_bytes(),
            b"new prefix\nold prefix\nold suffix\nnew suffix\n",
        )
        self.assertEqual(stat.S_IMODE(instructions.stat().st_mode), 0o644)

    def test_replaced_block_without_surrounding_edits_restores_backup(self):
        home = self._home()
        instructions = home / "AGENTS.md"
        original = b"original instructions\n"
        instructions.parent.mkdir(parents=True)
        instructions.write_bytes(original)
        instructions.chmod(0o644)
        self._install(enable_global_routing=True)

        plan = self._uninstall_plan(home).targets[0]
        operation = next(
            item for item in plan.operations if item.identifier == "routing-codex"
        )
        self.assertEqual(operation.action, "remove-block")
        apply_transaction(self._uninstall_plan(home))
        self.assertEqual(instructions.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(instructions.stat().st_mode), 0o644)

    def test_replaced_block_with_empty_edited_surrounding_keeps_empty_file(self):
        for target in (Target.CODEX, Target.OPENCODE):
            with self.subTest(target=target):
                home = self._home(target)
                filename = "AGENTS.md"
                instructions = home / filename
                instructions.parent.mkdir(parents=True)
                instructions.write_bytes(b"old surrounding bytes\n")
                instructions.chmod(0o644)
                options = {"enable_global_routing": True}
                install = preflight_install(
                    self.repository,
                    planning_request("install", {target: home}, **options),
                )
                apply_transaction(install)
                installed = instructions.read_bytes()
                begin, _end = _markers(f"routing-{target.value}")
                block_start = installed.index(begin)
                instructions.write_bytes(installed[block_start:])
                instructions.chmod(0o600)

                uninstall = self._uninstall_plan(home, target)
                operation = next(
                    item
                    for item in uninstall.targets[0].operations
                    if item.identifier == f"routing-{target.value}"
                )
                self.assertIsNotNone(operation.expected_after_hash)
                self.assertEqual(operation.content, b"")
                self.assertEqual(operation.expected_after_mode, 0o644)
                apply_transaction(uninstall)

                self.assertTrue(instructions.exists())
                self.assertEqual(instructions.read_bytes(), b"")
                self.assertEqual(stat.S_IMODE(instructions.stat().st_mode), 0o644)

    def test_changed_managed_block_is_retained_unresolved(self):
        home = self._install(enable_global_routing=True)
        instructions = home / "AGENTS.md"
        current = instructions.read_bytes().replace(
            b"Custom subagents", b"Changed subagents", 1
        )
        instructions.write_bytes(current)

        plan = self._uninstall_plan(home).targets[0]
        entry = next(
            item
            for item in plan.resulting_manifest.entries
            if item.identifier == "routing-codex"
        )
        self.assertIn("changed", entry.unresolved_reason or "")
        self.assertFalse(
            any(item.identifier == "routing-codex" for item in plan.operations)
        )
        apply_transaction(self._uninstall_plan(home))
        self.assertEqual(instructions.read_bytes(), current)

    def test_unsafe_managed_block_retains_block_specific_reason_and_metadata(self):
        for kind in ("symlink", "non-regular"):
            with self.subTest(kind=kind):
                home = self.root / f"home-unsafe-block-{kind}"
                self._install_at_with_routing(home)
                instructions = home / "AGENTS.md"
                prior_manifest = load_manifest(home, descriptor_for(Target.CODEX))
                prior = next(
                    item
                    for item in prior_manifest.entries
                    if item.identifier == "routing-codex"
                )
                if kind == "symlink":
                    outside = self.root / f"outside-{kind}.md"
                    outside.write_bytes(b"outside\n")
                    instructions.unlink()
                    instructions.symlink_to(outside)
                else:
                    instructions.unlink()
                    instructions.mkdir()

                plan = self._uninstall_plan(home).targets[0]
                retained = next(
                    item
                    for item in plan.resulting_manifest.entries
                    if item.identifier == "routing-codex"
                )
                self.assertEqual(
                    retained.__class__(
                        **{**retained.__dict__, "unresolved_reason": None}
                    ),
                    prior,
                )
                self.assertIn("routing-codex", retained.unresolved_reason or "")
                self.assertIn("unsafe", retained.unresolved_reason or "")

    def _install_at_with_routing(self, home):
        apply_transaction(
            preflight_install(
                self.repository,
                planning_request(
                    "install",
                    {Target.CODEX: home},
                    enable_global_routing=True,
                ),
            )
        )

    def test_missing_or_ambiguous_managed_block_is_retained(self):
        for index, replacement in enumerate(
            (b"user removed block\n", b"# BEGIN SUBAGENTS_CONFIGS routing-codex\n")
        ):
            with self.subTest(replacement=replacement):
                home = self.root / f"home-block-{index}"
                apply_transaction(
                    preflight_install(
                        self.repository,
                        planning_request(
                            "install",
                            {Target.CODEX: home},
                            enable_global_routing=True,
                        ),
                    )
                )
                instructions = home / "AGENTS.md"
                instructions.write_bytes(replacement)
                plan = self._uninstall_plan(home).targets[0]
                entry = next(
                    item
                    for item in plan.resulting_manifest.entries
                    if item.identifier == "routing-codex"
                )
                self.assertIsNotNone(entry.unresolved_reason)
                self.assertFalse(
                    any(item.identifier == "routing-codex" for item in plan.operations)
                )
                apply_transaction(self._uninstall_plan(home))
                self.assertEqual(instructions.read_bytes(), replacement)

    def test_codex_feature_block_and_all_routing_filenames_are_independent(self):
        for target, filename, block_id, option in (
            (
                Target.CODEX,
                "AGENTS.md",
                "routing-codex",
                {"enable_global_routing": True, "enable_codex_multi_agent": True},
            ),
            (
                Target.OPENCODE,
                "AGENTS.md",
                "routing-opencode",
                {"enable_global_routing": True},
            ),
            (
                Target.CLAUDE_CODE,
                "CLAUDE.md",
                "routing-claude-code",
                {"enable_global_routing": True},
            ),
        ):
            with self.subTest(target=target):
                home = self._install(target, **option)
                plan = self._uninstall_plan(home, target).targets[0]
                identifiers = {item.identifier for item in plan.operations}
                self.assertIn(block_id, identifiers)
                if target is Target.CODEX:
                    self.assertIn("codex-multi-agent-v2", identifiers)
                apply_transaction(self._uninstall_plan(home, target))
                self.assertFalse((home / ".subagents_configs/manifest.json").exists())
                self.assertFalse((home / filename).exists())

    def test_symlink_target_is_retained_and_backup_mismatch_fails_before_writes(self):
        home = self._install()
        destination = home / "agents/code-explorer.toml"
        outside = self.root / "outside.toml"
        outside.write_bytes(b"outside\n")
        destination.unlink()
        destination.symlink_to(outside)
        before = outside.read_bytes()
        plan = self._uninstall_plan(home).targets[0]
        retained = next(
            item
            for item in plan.resulting_manifest.entries
            if item.identifier == "code-explorer"
        )
        self.assertIn("unsafe", retained.unresolved_reason or "")
        apply_transaction(self._uninstall_plan(home))
        self.assertEqual(outside.read_bytes(), before)
        destination.unlink()

        home = self.root / "home-codex-backup"
        replacement = home / "agents/code-explorer.toml"
        replacement.parent.mkdir(parents=True, exist_ok=True)
        replacement.write_bytes(b"before install\n")
        replacement.chmod(0o600)
        apply_transaction(
            preflight_install(
                self.repository, planning_request("install", {Target.CODEX: home})
            )
        )
        manifest = load_manifest(home, descriptor_for(Target.CODEX))
        replaced = next(
            item for item in manifest.entries if item.identifier == "code-explorer"
        )
        backup = home / ".subagents_configs" / replaced.backup_path
        backup.write_bytes(b"tampered backup\n")
        with self.assertRaises(ValueError):
            self._uninstall_plan(home)

    def test_hard_linked_created_file_is_retained_as_unresolved(self):
        """Uninstall must not unlink an inode still owned by another name."""

        home = self._install()
        destination = home / "agents/code-explorer.toml"
        linked = self.root / "user-preserved-agent.toml"
        os.link(destination, linked)

        plan = self._uninstall_plan(home).targets[0]
        self.assertIsNotNone(plan.resulting_manifest)
        retained = next(
            item
            for item in plan.resulting_manifest.entries
            if item.identifier == "code-explorer"
        )
        self.assertIsNotNone(retained.unresolved_reason)
        self.assertFalse(
            any(item.identifier == "code-explorer" for item in plan.operations)
        )
        apply_transaction(self._uninstall_plan(home))
        self.assertTrue(destination.exists())
        self.assertEqual(destination.read_bytes(), linked.read_bytes())

    def test_uninstall_preflight_is_read_only_and_keeps_runtime_and_backups(self):
        home = self._home()
        apply_transaction(
            preflight_install(
                self.repository, planning_request("install", {Target.CODEX: home})
            )
        )
        state = home / ".subagents_configs"
        before = {
            path.relative_to(home): (
                path.read_bytes() if path.is_file() else None,
                stat.S_IMODE(path.stat().st_mode),
            )
            for path in state.rglob("*")
            if path.is_file()
        }
        plan = self._uninstall_plan(home)
        self.assertTrue(plan.targets[0].operations)
        after = {
            path.relative_to(home): (
                path.read_bytes() if path.is_file() else None,
                stat.S_IMODE(path.stat().st_mode),
            )
            for path in state.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        apply_transaction(plan)
        self.assertTrue((state / "validation").is_dir())
        self.assertTrue((state / "backups").is_dir())

    def test_dry_run_preflight_preserves_tree_bytes_modes_and_links(self):
        home = self._install(enable_global_routing=True)
        outside = self.root / "outside.txt"
        outside.write_bytes(b"outside\n")
        link = home / "user-link"
        link.symlink_to(outside)
        before = self._snapshot_tree(home)
        self._uninstall_plan(home, dry_run=True)
        self.assertEqual(self._snapshot_tree(home), before)

    def test_unsafe_state_and_backup_entries_fail_preflight_without_writes(self):
        scenarios = (
            "state-symlink",
            "backup-symlink",
            "backup-directory",
            "backup-hash",
            "backup-mode",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                home = self._home() / scenario
                if scenario == "state-symlink":
                    home.parent.mkdir(mode=0o700)
                    installed = self._install_at(home)
                    state = installed / ".subagents_configs"
                    real_state = self.root / f"real-state-{scenario}"
                    state.rename(real_state)
                    state.symlink_to(real_state, target_is_directory=True)
                    target_before = (
                        installed / "agents/code-explorer.toml"
                    ).read_bytes()
                    with self.assertRaises(ValueError):
                        self._uninstall_plan(installed)
                    self.assertEqual(
                        (installed / "agents/code-explorer.toml").read_bytes(),
                        target_before,
                    )
                    continue
                installed = self._install_replaced_at(home)
                manifest = load_manifest(installed, descriptor_for(Target.CODEX))
                entry = next(
                    item
                    for item in manifest.entries
                    if item.identifier == "code-explorer"
                )
                backup = installed / ".subagents_configs" / entry.backup_path
                outside = self.root / f"outside-{scenario}"
                outside.write_bytes(b"outside backup\n")
                if scenario == "backup-symlink":
                    backup.unlink()
                    backup.symlink_to(outside)
                elif scenario == "backup-directory":
                    backup.unlink()
                    backup.mkdir()
                elif scenario == "backup-hash":
                    backup.write_bytes(b"tampered backup\n")
                else:
                    backup.chmod(0o644)
                target_before = (installed / "agents/code-explorer.toml").read_bytes()
                with self.assertRaises(ValueError):
                    self._uninstall_plan(installed)
                self.assertEqual(
                    (installed / "agents/code-explorer.toml").read_bytes(),
                    target_before,
                )

    def _install_at(self, home):
        apply_transaction(
            preflight_install(
                self.repository,
                planning_request("install", {Target.CODEX: home}),
            )
        )
        return home

    def _install_replaced_at(self, home, *, mode=0o600):
        destination = home / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"original bytes\n")
        destination.chmod(mode)
        return self._install_at(home)

    def test_post_preflight_backup_drift_is_rejected_before_target_mutation(self):
        for index, drift in enumerate(("hash", "mode")):
            with self.subTest(drift=drift):
                home = self._install_replaced_at(
                    self._home() / f"post-preflight-{index}"
                )
                uninstall = self._uninstall_plan(home)
                manifest = load_manifest(home, descriptor_for(Target.CODEX))
                entry = next(
                    item
                    for item in manifest.entries
                    if item.identifier == "code-explorer"
                )
                backup = home / ".subagents_configs" / entry.backup_path
                target = home / "agents/code-explorer.toml"
                target_before = target.read_bytes()
                if drift == "hash":
                    backup.write_bytes(b"changed after preflight\n")
                else:
                    backup.chmod(0o644)
                with self.assertRaises(ValueError):
                    apply_transaction(uninstall)
                self.assertEqual(target.read_bytes(), target_before)

    def test_mid_target_uninstall_failure_rolls_back_global_reverse_order(self):
        codex_home = self._install(Target.CODEX)
        opencode_home = self._install(Target.OPENCODE)
        codex_target = codex_home / "agents/code-explorer.toml"
        opencode_target = opencode_home / "agents/code-explorer.md"
        codex_before = codex_target.read_bytes()
        opencode_before = opencode_target.read_bytes()
        plan = preflight_uninstall(
            self.repository,
            planning_request(
                "uninstall",
                {Target.CODEX: codex_home, Target.OPENCODE: opencode_home},
                targets=(Target.CODEX, Target.OPENCODE),
            ),
        )

        class FailAfterOneOpenCodeMutation:
            def __init__(self):
                self.open_code_calls = 0

            def before_operation(self, operation_id):
                if operation_id.startswith("opencode-"):
                    self.open_code_calls += 1
                    if self.open_code_calls == 2:
                        raise RuntimeError("mid-target failure")

        with self.assertRaises(RuntimeError):
            apply_transaction(plan, failure_injector=FailAfterOneOpenCodeMutation())
        self.assertEqual(codex_target.read_bytes(), codex_before)
        self.assertEqual(opencode_target.read_bytes(), opencode_before)

    def test_interrupted_broad_restore_mode_retains_ambiguous_journal(self):
        home = self._install_replaced_at(self._home() / "mode-interrupt", mode=0o644)
        target = home / "agents/code-explorer.toml"
        uninstall = self._uninstall_plan(home)
        unrelated = home / "unrelated.txt"
        unrelated.write_bytes(b"keep me\n")

        original_compare_and_swap = filesystem.compare_and_swap

        def fail_broad_mode(path, before, content, mode, action):
            if mode == 0o644:
                # Simulate content replacement completing before the broad
                # restore mode reaches disk, then interrupt the operation.
                original_compare_and_swap(path, before, content, 0o600, action)
                raise OSError("mode application interrupted")
            return original_compare_and_swap(path, before, content, mode, action)

        with patch(
            "subagents_configs.transaction.filesystem.compare_and_swap",
            fail_broad_mode,
        ):
            with self.assertRaises(IncompleteRollbackError):
                apply_transaction(uninstall)
        self.assertTrue((home / ".subagents_configs/journal.json").exists())
        self.assertEqual(target.read_bytes(), b"original bytes\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(unrelated.read_bytes(), b"keep me\n")
        self.assertIsNotNone(load_journal(home, descriptor_for(Target.CODEX)))

    def test_cross_target_uninstall_failure_rolls_back_earlier_target(self):
        codex_home = self._install(Target.CODEX)
        opencode_home = self._install(Target.OPENCODE)
        codex_file = codex_home / "agents/code-explorer.toml"
        opencode_file = opencode_home / "agents/code-explorer.md"
        codex_before = codex_file.read_bytes()
        opencode_before = opencode_file.read_bytes()
        plan = preflight_uninstall(
            self.repository,
            planning_request(
                "uninstall",
                {Target.CODEX: codex_home, Target.OPENCODE: opencode_home},
                targets=(Target.CODEX, Target.OPENCODE),
            ),
        )

        class FailOpenCode:
            def before_operation(self, operation_id):
                if operation_id.startswith("opencode-"):
                    raise RuntimeError("late target failure")

        with self.assertRaises(RuntimeError):
            apply_transaction(plan, failure_injector=FailOpenCode())
        self.assertEqual(codex_file.read_bytes(), codex_before)
        self.assertEqual(opencode_file.read_bytes(), opencode_before)


if __name__ == "__main__":
    unittest.main()
