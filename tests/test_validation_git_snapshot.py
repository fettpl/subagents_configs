from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from tests.validation_isolated_test_support import git, make_repository


class GitSnapshotTests(unittest.TestCase):
    def test_inventory_includes_tracked_modified_and_nonignored_untracked_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            (repository / "tracked.txt").write_text("modified\n", encoding="utf-8")
            (repository / "new.txt").write_text("new\n", encoding="utf-8")
            (repository / "ignored.txt").write_text("ignored\n", encoding="utf-8")
            (repository / ".env").write_text("secret\n", encoding="utf-8")
            (repository / ".env.local").write_text("secret\n", encoding="utf-8")
            (repository / ".envrc").write_text("secret\n", encoding="utf-8")
            (repository / "cache").mkdir()
            (repository / "cache" / "item").write_text("cache\n", encoding="utf-8")
            (repository / "node_modules").mkdir()
            (repository / "node_modules" / "item").write_text(
                "dependency\n", encoding="utf-8"
            )

            from scripts.validation_isolation.git_snapshot import list_source_paths

            self.assertEqual(
                list_source_paths(repository),
                (
                    PurePosixPath(".gitignore"),
                    PurePosixPath("new.txt"),
                    PurePosixPath("script.sh"),
                    PurePosixPath("tracked.txt"),
                ),
            )

    def test_deleted_tracked_file_is_in_fingerprint_as_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            (repository / "tracked.txt").unlink()

            from scripts.validation_isolation.git_snapshot import capture_checkout_state

            state = capture_checkout_state(repository)
            deleted = next(
                file
                for file in state.files
                if file.relative_path == PurePosixPath("tracked.txt")
            )
            self.assertFalse(deleted.exists)
            self.assertIsNone(deleted.sha256)
            self.assertIsNone(deleted.mode)

    def test_tracked_ignored_source_file_is_included(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            tracked_ignored = repository / "ignored.txt"
            tracked_ignored.write_text("tracked ignored\n", encoding="utf-8")
            git(repository, "add", "--all", "-f", "ignored.txt")
            git(repository, "commit", "--quiet", "-m", "ignored")

            from scripts.validation_isolation.git_snapshot import list_source_paths

            self.assertIn(
                PurePosixPath("ignored.txt"), list_source_paths(repository)
            )

    def test_common_credential_paths_are_excluded_when_tracked_or_untracked(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            credential_paths = (
                "credentials.json",
                ".npmrc",
                ".pypirc",
                ".netrc",
                "id_rsa",
                "private.key",
                ".aws/credentials",
                ".docker/config.json",
                ".git-credentials",
            )
            for path in credential_paths:
                tracked = repository / "tracked" / path
                tracked.parent.mkdir(parents=True, exist_ok=True)
                tracked.write_text("credential\n", encoding="utf-8")
                untracked = repository / "untracked" / path
                untracked.parent.mkdir(parents=True, exist_ok=True)
                untracked.write_text("credential\n", encoding="utf-8")
            git(repository, "add", "--all", "-f", "tracked")
            git(repository, "commit", "--quiet", "-m", "credentials")

            from scripts.validation_isolation.git_snapshot import list_source_paths

            paths = list_source_paths(repository)
            self.assertNotIn(PurePosixPath("tracked/credentials.json"), paths)
            self.assertNotIn(PurePosixPath("untracked/credentials.json"), paths)
            for path in credential_paths:
                self.assertNotIn(PurePosixPath("tracked", path), paths)
                self.assertNotIn(PurePosixPath("untracked", path), paths)

    def test_deleted_tracked_parent_is_in_fingerprint_as_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            nested = repository / "nested"
            nested.mkdir()
            (nested / "tracked.txt").write_text("nested\n", encoding="utf-8")
            git(repository, "add", "--all")
            git(repository, "commit", "--quiet", "-m", "nested")
            (nested / "tracked.txt").unlink()
            nested.rmdir()

            from scripts.validation_isolation.git_snapshot import capture_checkout_state

            state = capture_checkout_state(repository)
            deleted = next(
                file
                for file in state.files
                if file.relative_path == PurePosixPath("nested/tracked.txt")
            )
            self.assertFalse(deleted.exists)

    def test_snapshot_excludes_git_and_has_private_modes_and_executable_bits(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            destination = Path(temporary) / "snapshot"

            from scripts.validation_isolation.git_snapshot import create_snapshot

            snapshot = create_snapshot(repository, destination)
            self.assertFalse((snapshot.snapshot_root / ".git").exists())
            self.assertEqual(stat.S_IMODE(snapshot.snapshot_root.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((destination / "tracked.txt").stat().st_mode), 0o600
            )
            self.assertEqual(
                stat.S_IMODE((destination / "script.sh").stat().st_mode), 0o711
            )

    def test_symlink_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            (repository / "link").symlink_to(repository / "tracked.txt")
            git(repository, "add", "--all")

            from scripts.validation_isolation.git_snapshot import create_snapshot

            with self.assertRaises(ValueError):
                create_snapshot(repository, Path(temporary) / "snapshot")

    def test_nested_symlink_and_special_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            (repository / "linked").mkdir()
            outside = Path(temporary) / "outside"
            outside.mkdir()
            (repository / "linked").rmdir()
            (repository / "linked").symlink_to(outside, target_is_directory=True)
            (outside / "escape.txt").write_text("escape\n", encoding="utf-8")
            git(repository, "add", "--all")

            from scripts.validation_isolation.git_snapshot import create_snapshot

            with self.assertRaises(ValueError):
                create_snapshot(repository, Path(temporary) / "snapshot")

    def test_checkout_mutations_are_fatal(self):
        mutations = ("content", "mode", "new", "deletion", "status")
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                repository = make_repository(Path(temporary))
                from scripts.validation_isolation.git_snapshot import (
                    assert_checkout_unchanged,
                    create_snapshot,
                )

                snapshot = create_snapshot(repository, Path(temporary) / "snapshot")
                if mutation == "content":
                    (repository / "tracked.txt").write_text(
                        "changed\n", encoding="utf-8"
                    )
                elif mutation == "mode":
                    os.chmod(repository / "tracked.txt", 0o755)  # noqa: S103
                elif mutation == "new":
                    (repository / "appeared.txt").write_text(
                        "appeared\n", encoding="utf-8"
                    )
                elif mutation == "deletion":
                    (repository / "tracked.txt").unlink()
                else:
                    git(repository, "status", "--short")
                    (repository / "tracked.txt").write_text(
                        "status\n", encoding="utf-8"
                    )
                with self.assertRaises(ValueError):
                    assert_checkout_unchanged(snapshot)

    def test_paths_are_sorted_and_outside_files_are_not_copied(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            outside = Path(temporary) / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            destination = Path(temporary) / "snapshot"

            from scripts.validation_isolation.git_snapshot import create_snapshot

            snapshot = create_snapshot(repository, destination)
            paths = tuple(file.relative_path for file in snapshot.before.files)
            self.assertEqual(paths, tuple(sorted(paths)))
            self.assertFalse((destination / "outside.txt").exists())

    def test_destination_overlap_and_preexisting_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            from scripts.validation_isolation.git_snapshot import create_snapshot

            with self.subTest("overlap"):
                with self.assertRaises(ValueError):
                    create_snapshot(repository, repository / "nested-snapshot")
            with self.subTest("symlink"):
                outside = Path(temporary) / "outside"
                outside.mkdir()
                destination = Path(temporary) / "snapshot"
                destination.symlink_to(outside, target_is_directory=True)
                with self.assertRaises(ValueError):
                    create_snapshot(repository, destination)

    def test_git_runner_uses_fixed_usr_bin_git_not_inherited_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            fake_git = fake_bin / "git"
            fake_git.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            os.chmod(fake_git, 0o755)  # noqa: S103

            from scripts.validation_isolation.git_snapshot import run_git

            with patch.dict(os.environ, {"PATH": str(fake_bin)}, clear=False):
                result = run_git(("status", "--short"), repository)
            self.assertEqual(result.returncode, 0)

    def test_unsafe_trusted_git_fails_closed_without_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            from scripts.validation_isolation import git_snapshot

            with patch.object(
                git_snapshot, "GIT_EXECUTABLE", Path(temporary) / "missing"
            ):
                with self.assertRaises(ValueError):
                    git_snapshot.run_git(("status", "--short"), repository)

    def test_repository_fsmonitor_helper_is_never_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            marker = Path(temporary) / "fsmonitor-marker"
            helper = Path(temporary) / "fsmonitor-helper"
            helper.write_text(
                f"#!/bin/sh\nprintf x > {marker}\nexit 0\n", encoding="utf-8"
            )
            os.chmod(helper, 0o700)
            git(repository, "config", "core.fsmonitor", str(helper))

            from scripts.validation_isolation.git_snapshot import run_git

            result = run_git(("status", "--porcelain=v1", "-z"), repository)
            self.assertEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_git_runner_neutralizes_local_helpers_and_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            from scripts.validation_isolation import git_snapshot

            captured = {}

            def fake_run(command, **kwargs):
                captured["command"] = command
                captured["kwargs"] = kwargs
                return subprocess.CompletedProcess(command, 0, b"", b"")

            with patch.object(git_snapshot.subprocess, "run", fake_run):
                git_snapshot.run_git(("status", "-z"), repository)
            command = captured["command"]
            self.assertEqual(command[0], "/usr/bin/git")
            self.assertIn("core.fsmonitor=false", command)
            self.assertIn("core.hooksPath=/dev/null", command)
            self.assertIn("core.pager=cat", command)
            self.assertIn("credential.helper=", command)
            self.assertEqual(captured["kwargs"]["shell"], False)
            self.assertEqual(captured["kwargs"]["env"]["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(captured["kwargs"]["env"]["GIT_OPTIONAL_LOCKS"], "0")

    def test_locate_worktree_rejects_unrelated_and_noncanonical_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = make_repository(root)
            unrelated = root / "unrelated"
            unrelated.mkdir()

            from scripts.validation_isolation.git_snapshot import locate_worktree

            def unrelated_runner(arguments, cwd):
                del arguments, cwd
                return subprocess.CompletedProcess(
                    (), 0, stdout=f"{unrelated}\n".encode(), stderr=b""
                )

            with self.assertRaises(ValueError):
                locate_worktree(repository, unrelated_runner)

            noncanonical = f"{repository}/child/../"

            def noncanonical_runner(arguments, cwd):
                del arguments, cwd
                return subprocess.CompletedProcess(
                    (), 0, stdout=f"{noncanonical}\n".encode(), stderr=b""
                )

            with self.assertRaises(ValueError):
                locate_worktree(repository, noncanonical_runner)

    def test_capture_rejects_ordinary_source_root_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = make_repository(root)
            replacement = root / "replacement"
            replacement.mkdir()
            (replacement / ".gitignore").write_text("", encoding="utf-8")
            (replacement / "tracked.txt").write_text("attacker\n", encoding="utf-8")
            (replacement / "script.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            displaced = root / "displaced"

            from scripts.validation_isolation import git_snapshot

            original_open = git_snapshot._open_directory
            swapped = False

            def swap_once(path, label):
                nonlocal swapped
                if not swapped and path == repository:
                    repository.rename(displaced)
                    replacement.rename(repository)
                    swapped = True
                return original_open(path, label)

            with patch.object(git_snapshot, "_open_directory", swap_once):
                with self.assertRaises(ValueError):
                    git_snapshot.capture_checkout_state(repository)

    def test_capture_rejects_ordinary_nested_ancestor_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = make_repository(root)
            nested = repository / "nested"
            nested.mkdir()
            (nested / "tracked.txt").write_text("trusted\n", encoding="utf-8")
            git(repository, "add", "nested/tracked.txt")
            git(repository, "commit", "--quiet", "-m", "nested")
            replacement = root / "replacement"
            replacement.mkdir()
            (replacement / "tracked.txt").write_text("attacker\n", encoding="utf-8")
            displaced = root / "displaced-nested"

            from scripts.validation_isolation import git_snapshot

            original_open = git_snapshot._open_relative_directory
            swapped = False

            def swap_once(root_descriptor, components, label, expected=None):
                nonlocal swapped
                if not swapped and tuple(components) == ("nested",):
                    nested.rename(displaced)
                    replacement.rename(nested)
                    swapped = True
                    return original_open(root_descriptor, components, label, expected)
                return original_open(root_descriptor, components, label, expected)

            with patch.object(git_snapshot, "_open_relative_directory", swap_once):
                with self.assertRaises(ValueError):
                    git_snapshot.capture_checkout_state(repository)

    def test_capture_rejects_preopen_ancestor_disappearance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = make_repository(root)
            nested = repository / "nested"
            nested.mkdir()
            (nested / "tracked.txt").write_text("trusted\n", encoding="utf-8")
            git(repository, "add", "nested/tracked.txt")
            git(repository, "commit", "--quiet", "-m", "nested")
            displaced = root / "displaced-nested"

            from scripts.validation_isolation import git_snapshot

            original_open = git_snapshot._open_relative_directory
            swapped = False

            def disappear_once(root_descriptor, components, label, expected=None):
                nonlocal swapped
                if not swapped and tuple(components) == ("nested",):
                    nested.rename(displaced)
                    swapped = True
                return original_open(root_descriptor, components, label, expected)

            with patch.object(git_snapshot, "_open_relative_directory", disappear_once):
                with self.assertRaises(ValueError):
                    git_snapshot.capture_checkout_state(repository)

    def test_source_hard_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            os.link(repository / "tracked.txt", repository / "hardlink.txt")
            git(repository, "add", "hardlink.txt")

            from scripts.validation_isolation.git_snapshot import capture_checkout_state

            with self.assertRaises(ValueError):
                capture_checkout_state(repository)

    def test_destination_final_file_replacement_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = make_repository(root)
            destination = root / "snapshot"
            from scripts.validation_isolation import git_snapshot

            real_fsync = os.fsync
            replaced = False

            def replace_after_write(descriptor):
                nonlocal replaced
                result = real_fsync(descriptor)
                if not replaced and stat.S_ISREG(os.fstat(descriptor).st_mode):
                    target = destination / "tracked.txt"
                    if target.exists():
                        replacement = root / "replacement.txt"
                        replacement.write_text("attacker\n", encoding="utf-8")
                        os.replace(replacement, target)
                        replaced = True
                return result

            with patch.object(git_snapshot.os, "fsync", replace_after_write):
                with self.assertRaises(ValueError):
                    git_snapshot.create_snapshot(repository, destination)

    def test_duplicate_excluded_inventory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))

            from scripts.validation_isolation.git_snapshot import list_source_paths

            def fake_runner(arguments, cwd):
                del cwd
                if arguments[:2] == ("ls-files", "--cached"):
                    if "--ignored" in arguments:
                        output = b""
                    else:
                        output = b".env\0.env\0"
                    return subprocess.CompletedProcess((), 0, output, b"")
                return subprocess.CompletedProcess((), 0, b"", b"")

            with self.assertRaises(ValueError):
                list_source_paths(repository, fake_runner)

    def test_failed_ignored_inventory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))

            from scripts.validation_isolation.git_snapshot import list_source_paths

            def failed_runner(arguments, cwd):
                del cwd
                if "--ignored" in arguments:
                    return subprocess.CompletedProcess(
                        (), 1, b"ignored.txt\0", b"inventory failed"
                    )
                if arguments[0] == "ls-files":
                    return subprocess.CompletedProcess(
                        (), 0, b".gitignore\0tracked.txt\0", b""
                    )
                return subprocess.CompletedProcess((), 0, b"", b"")

            with self.assertRaises(ValueError):
                list_source_paths(repository, failed_runner)

    def test_destination_creation_replacement_mode_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = make_repository(root)
            destination = root / "snapshot"
            replacement = root / "replacement-destination"

            from scripts.validation_isolation import git_snapshot

            original_prepare = git_snapshot._prepare_destination

            def replace_after_create(path, worktree):
                original_prepare(path, worktree)
                path.rename(replacement)
                os.chmod(replacement, 0o755)  # noqa: S103
                replacement.rename(path)
                return git_snapshot._pin_directory(path, "snapshot destination")

            with patch.object(
                git_snapshot, "_prepare_destination", replace_after_create
            ):
                with self.assertRaises(ValueError):
                    git_snapshot.create_snapshot(repository, destination)

    def test_destination_replacement_after_first_final_check_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = make_repository(root)
            destination = root / "snapshot"

            from scripts.validation_isolation import git_snapshot

            original_check = git_snapshot._check_relative_directory
            replaced = False

            def replace_after_destination_parent(
                root_descriptor, components, expected_descriptor, label, expected=None
            ):
                nonlocal replaced
                result = original_check(
                    root_descriptor,
                    components,
                    expected_descriptor,
                    label,
                    expected,
                )
                if label == "snapshot parent" and not replaced:
                    target = destination / "tracked.txt"
                    if not target.exists():
                        return result
                    replacement = root / "replacement.txt"
                    replacement.write_text("attacker\n", encoding="utf-8")
                    os.replace(replacement, target)
                    replaced = True
                return result

            with patch.object(
                git_snapshot,
                "_check_relative_directory",
                replace_after_destination_parent,
            ):
                with self.assertRaises(ValueError):
                    git_snapshot.create_snapshot(repository, destination)


if __name__ == "__main__":
    unittest.main()
