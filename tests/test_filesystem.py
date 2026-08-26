import errno
import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from subagents_configs import filesystem
from subagents_configs.errors import TransactionError
from subagents_configs.filesystem import (
    atomic_write,
    capture_evidence,
    compare_and_swap,
    ensure_private_directory,
    exclusive_backup,
    sha256_bytes,
    sha256_file,
    unlink_regular,
)

TEMP_DIR = "/private/tmp" if Path("/private/tmp").is_dir() else None


class FilesystemTests(unittest.TestCase):
    def test_quarantine_evidence_failure_removes_only_created_link(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"original")
            path.chmod(0o600)
            before = capture_evidence(path, "target")
            real_evidence = filesystem._evidence_from_descriptor

            def fail_quarantine(descriptor, label, **kwargs):
                if label == "CAS quarantine link":
                    raise OSError("injected quarantine evidence failure")
                return real_evidence(descriptor, label, **kwargs)

            with patch.object(filesystem, "_evidence_from_descriptor", fail_quarantine):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, before, b"installer bytes", 0o600, "replace")
            self.assertEqual(path.read_bytes(), b"original")
            self.assertEqual(list(root.glob(".managed.cas-*")), [])

    def test_quarantine_open_failure_removes_only_created_link(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"original")
            path.chmod(0o600)
            before = capture_evidence(path, "target")
            real_open = filesystem.os.open

            def fail_quarantine_open(name, flags, *args, **kwargs):
                if isinstance(name, str) and Path(name).name.startswith(
                    ".managed.cas-"
                ):
                    raise OSError("injected quarantine open failure")
                return real_open(name, flags, *args, **kwargs)

            with patch.object(filesystem.os, "open", side_effect=fail_quarantine_open):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, before, b"installer bytes", 0o600, "replace")
            self.assertEqual(path.read_bytes(), b"original")
            self.assertEqual(list(root.glob(".managed.cas-*")), [])

    def test_replacement_target_appearance_preserves_original_and_attacker(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"original")
            path.chmod(0o600)
            before = capture_evidence(path, "target")
            real_link = filesystem._link_no_replace

            def target_appears(parent_fd, source, target):
                if source.startswith(".managed.tmp-"):
                    path.write_bytes(b"attacker replacement")
                    path.chmod(0o600)
                return real_link(parent_fd, source, target)

            with patch.object(
                filesystem, "_link_no_replace", side_effect=target_appears
            ):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, before, b"installer bytes", 0o600, "replace")
            self.assertEqual(path.read_bytes(), b"attacker replacement")
            self.assertEqual(list(root.glob(".managed.cas-*")), [])

    def test_quarantine_cleanup_has_no_target_appearance_gap(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"original")
            path.chmod(0o600)
            before = capture_evidence(path, "target")
            real_remove = filesystem._remove_owned_quarantine

            def appear_after_cleanup(parent_fd, quarantine, expected):
                result = real_remove(parent_fd, quarantine, expected)
                if not path.exists():
                    path.write_bytes(b"attacker replacement")
                    path.chmod(0o600)
                return result

            with patch.object(
                filesystem,
                "_remove_owned_quarantine",
                side_effect=appear_after_cleanup,
            ):
                result = compare_and_swap(
                    path, before, b"installer bytes", 0o600, "replace"
                )
            self.assertEqual(result.sha256, sha256_bytes(b"installer bytes"))
            self.assertEqual(path.read_bytes(), b"installer bytes")
            self.assertEqual(list(root.glob(".managed.cas-*")), [])

    def test_quarantine_cleanup_error_after_removal_returns_proven_install(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"original")
            path.chmod(0o600)
            before = capture_evidence(path, "target")
            real_remove = filesystem._remove_owned_quarantine

            def remove_then_raise(parent_fd, quarantine, expected):
                real_remove(parent_fd, quarantine, expected)
                raise OSError("injected post-removal error")

            with patch.object(
                filesystem,
                "_remove_owned_quarantine",
                side_effect=remove_then_raise,
            ):
                result = compare_and_swap(
                    path, before, b"installer bytes", 0o600, "replace"
                )
            self.assertEqual(result.sha256, sha256_bytes(b"installer bytes"))
            self.assertEqual(path.read_bytes(), b"installer bytes")
            self.assertEqual(list(root.glob(".managed.cas-*")), [])

    def test_quarantine_boundary_swap_never_overwrites_unowned_entry(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"original")
            path.chmod(0o600)
            before = capture_evidence(path, "target")

            def swap_reserved(_parent, _target, quarantine):
                if quarantine.exists():
                    quarantine.unlink()
                quarantine.write_bytes(b"unowned replacement")
                quarantine.chmod(0o600)

            with patch.object(
                filesystem,
                "_before_quarantine_mutation",
                swap_reserved,
                create=True,
            ):
                with (
                    patch.object(
                        filesystem,
                        "_quarantine_path",
                        return_value=root / ".managed.cas-race",
                    ),
                    self.assertRaises(TransactionError),
                ):
                    compare_and_swap(path, before, b"installer bytes", 0o600, "replace")
            self.assertEqual(path.read_bytes(), b"original")
            self.assertEqual(
                next(iter(root.glob(".managed.cas-*"))).read_bytes(),
                b"unowned replacement",
            )

    def test_create_rejects_same_inode_hardlink_count_race_in_final_evidence(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"

            def add_hardlink(_parent, target):
                os.link(target, target.with_name("same-inode-link"))

            with patch.object(
                filesystem,
                "_before_final_target_evidence",
                add_hardlink,
                create=True,
            ):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, None, b"installer bytes", 0o600, "create")
            self.assertEqual(path.read_bytes(), b"installer bytes")
            self.assertTrue((root / "same-inode-link").exists())

    def test_quarantine_collision_preserves_unowned_entry(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"original")
            path.chmod(0o600)
            before = capture_evidence(path, "target")
            collision = root / ".managed.cas-collision"
            collision.write_bytes(b"unowned quarantine")
            collision.chmod(0o600)

            with patch.object(filesystem, "_quarantine_path", return_value=collision):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, before, b"installer bytes", 0o600, "replace")
            self.assertEqual(path.read_bytes(), b"original")
            self.assertEqual(collision.read_bytes(), b"unowned quarantine")

    def test_failed_cas_cleanup_preserves_same_content_different_inode_temp(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"

            def create_target(_parent):
                path.write_bytes(b"installer bytes")
                path.chmod(0o600)

            def replace_temp(_parent, temporary_path):
                replacement = temporary_path.with_name("replacement-temp")
                replacement.write_bytes(b"installer bytes")
                replacement.chmod(0o600)
                temporary_path.unlink()
                replacement.rename(temporary_path)

            with (
                patch.object(
                    filesystem,
                    "_before_create_mutation",
                    create_target,
                    create=True,
                ),
                patch.object(
                    filesystem,
                    "_before_failed_temp_cleanup",
                    replace_temp,
                    create=True,
                ),
            ):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, None, b"installer bytes", 0o600, "create")
            self.assertEqual(path.read_bytes(), b"installer bytes")
            self.assertEqual(
                len(list(root.glob(".managed.tmp-*"))),
                1,
                "same-content replacement temp must not be unlinked",
            )

    def test_create_rejects_same_content_mode_replacement_inode_after_link(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"

            def replace_after_link(_parent, target, _temporary):
                replacement = target.with_name("replacement-target")
                replacement.write_bytes(b"installer bytes")
                replacement.chmod(0o600)
                target.unlink()
                replacement.rename(target)

            with patch.object(
                filesystem, "_after_create_link", replace_after_link, create=True
            ):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, None, b"installer bytes", 0o600, "create")
            self.assertEqual(path.read_bytes(), b"installer bytes")

    def test_temp_unlink_boundary_preserves_same_content_replacement(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"

            def replace_temp(_parent, temporary_path):
                replacement = temporary_path.with_name("replacement-temp")
                replacement.write_bytes(b"installer bytes")
                replacement.chmod(0o600)
                temporary_path.unlink()
                replacement.rename(temporary_path)

            with patch.object(filesystem, "_before_temp_unlink_mutation", replace_temp):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, None, b"installer bytes", 0o600, "create")
            self.assertEqual(path.read_bytes(), b"installer bytes")
            self.assertEqual(len(list(root.glob(".managed.tmp-*"))), 1)

    def test_create_race_preserves_late_target_and_fails(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"

            def attacker_before_create(_parent):
                path.write_bytes(b"user create race")
                path.chmod(0o600)

            with patch.object(
                filesystem, "_before_create_mutation", attacker_before_create
            ):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, None, b"installer bytes", 0o600, "create")
            self.assertEqual(path.read_bytes(), b"user create race")

    def test_replace_race_preserves_late_target_and_fails(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"original")
            path.chmod(0o600)
            before = capture_evidence(path, "target")

            def attacker_before_replace(_parent):
                path.unlink()
                path.write_bytes(b"user replace race")
                path.chmod(0o600)

            with patch.object(
                filesystem, "_before_replace_mutation", attacker_before_replace
            ):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, before, b"installer bytes", 0o600, "replace")
            self.assertEqual(path.read_bytes(), b"user replace race")

    def test_unlink_race_preserves_late_target_and_fails(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"original")
            path.chmod(0o600)
            before = capture_evidence(path, "target")

            def attacker_before_unlink(_parent):
                path.unlink()
                path.write_bytes(b"user unlink race")
                path.chmod(0o600)

            with patch.object(
                filesystem, "_before_unlink_mutation", attacker_before_unlink
            ):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, before, None, None, "unlink")
            self.assertEqual(path.read_bytes(), b"user unlink race")

    def test_chmod_race_preserves_late_target_and_fails(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"original")
            path.chmod(0o600)
            before = capture_evidence(path, "target")

            def attacker_before_chmod(_parent):
                path.unlink()
                path.write_bytes(b"user chmod race")
                path.chmod(0o640)

            with patch.object(
                filesystem, "_before_chmod_mutation", attacker_before_chmod
            ):
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, before, None, 0o644, "chmod")
            self.assertEqual(path.read_bytes(), b"user chmod race")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_hash_helpers_match_sha256(self):
        content = b"known bytes\x00"
        expected = hashlib.sha256(content).hexdigest()
        self.assertEqual(sha256_bytes(content), expected)
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            path = Path(temporary) / "content"
            path.write_bytes(content)
            self.assertEqual(sha256_file(path), expected)

    def test_private_directories_are_0700(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            path = Path(temporary) / "state" / "nested"
            ensure_private_directory(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            ensure_private_directory(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_private_directory_does_not_chmod_existing_user_directory(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            path = Path(temporary) / "state"
            path.mkdir(mode=0o755)
            path.chmod(0o755)
            with self.assertRaises(ValueError):
                ensure_private_directory(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)

    def test_private_directory_rejects_symlink(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            link = root / "state"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                ensure_private_directory(link)

    def test_all_helpers_reject_intermediate_symlink_ancestors(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (outside / "source").write_bytes(b"outside")
            (outside / "victim").write_bytes(b"must survive")
            link = root / "linked-parent"
            link.symlink_to(outside, target_is_directory=True)

            with self.assertRaises(ValueError):
                sha256_file(link / "source")
            with self.assertRaises(ValueError):
                exclusive_backup(link / "source", root / "backup")
            source = root / "source"
            source.write_bytes(b"inside")
            with self.assertRaises(ValueError):
                exclusive_backup(source, link / "backup")
            with self.assertRaises(ValueError):
                unlink_regular(link / "victim")
            with self.assertRaises(ValueError):
                atomic_write(link / "new", b"must not escape")
            with self.assertRaises(ValueError):
                ensure_private_directory(link / "new-directory")
            self.assertEqual((outside / "victim").read_bytes(), b"must survive")

    def test_atomic_write_uses_0600_and_replaces_complete_bytes(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_bytes(b"old")
            atomic_write(path, b"new complete bytes")
            self.assertEqual(path.read_bytes(), b"new complete bytes")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(list(Path(temporary).glob(".manifest.json.tmp-*")), [])

    def test_atomic_write_fsyncs_file_and_parent_directory(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            path = Path(temporary) / "journal"
            events = []
            real_fsync = os.fsync
            real_replace = os.replace

            def observed_fsync(fd):
                events.append(("fsync", stat.S_ISDIR(os.fstat(fd).st_mode), fd))
                return real_fsync(fd)

            def observed_replace(*args, **kwargs):
                events.append(
                    (
                        "replace",
                        kwargs.get("src_dir_fd"),
                        kwargs.get("dst_dir_fd"),
                    )
                )
                return real_replace(*args, **kwargs)

            with (
                patch("subagents_configs.filesystem.os.fsync", observed_fsync),
                patch("subagents_configs.filesystem.os.replace", observed_replace),
            ):
                atomic_write(path, b"journal")
            file_fsync = next(
                index
                for index, event in enumerate(events)
                if event[0] == "fsync" and not event[1]
            )
            replace = next(
                index for index, event in enumerate(events) if event[0] == "replace"
            )
            parent_fsync = next(
                index
                for index, event in enumerate(events)
                if event[0] == "fsync" and event[1]
            )
            self.assertLess(file_fsync, replace)
            self.assertLess(replace, parent_fsync)
            self.assertEqual(events[replace][2], events[parent_fsync][2])
            self.assertEqual(path.read_bytes(), b"journal")

    def test_atomic_write_fails_closed_on_temp_entry_substitution(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"old managed bytes")
            outside = root / "outside"
            outside.write_bytes(b"outside bytes must remain")
            real_replace = os.replace

            def substitute_temp_before_replace(src, dst, **kwargs):
                parent_fd = kwargs["src_dir_fd"]
                os.unlink(src, dir_fd=parent_fd)
                os.symlink(outside, src, dir_fd=parent_fd)
                return real_replace(src, dst, **kwargs)

            with patch(
                "subagents_configs.filesystem.os.replace",
                substitute_temp_before_replace,
            ):
                with self.assertRaisesRegex(ValueError, "temporary"):
                    atomic_write(path, b"attacker bytes")
            self.assertEqual(outside.read_bytes(), b"outside bytes must remain")
            self.assertTrue(path.is_symlink())
            self.assertEqual(path.resolve(), outside)

    def test_atomic_write_preserves_concurrent_regular_file_on_identity_mismatch(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "managed"
            path.write_bytes(b"old managed bytes")
            real_replace = os.replace

            def replace_then_concurrent_write(src, dst, **kwargs):
                result = real_replace(src, dst, **kwargs)
                parent_fd = kwargs["dst_dir_fd"]
                os.unlink(dst, dir_fd=parent_fd)
                descriptor = os.open(
                    dst, os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=parent_fd
                )
                try:
                    os.write(descriptor, b"concurrent user bytes")
                finally:
                    os.close(descriptor)
                return result

            with patch(
                "subagents_configs.filesystem.os.replace",
                replace_then_concurrent_write,
            ):
                with self.assertRaisesRegex(ValueError, "temporary"):
                    atomic_write(path, b"installer bytes")
            self.assertEqual(path.read_bytes(), b"concurrent user bytes")

    def test_directory_fsync_ignores_only_supported_portability_errors(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            path = Path(temporary) / "journal"
            real_fsync = os.fsync

            for unsupported_errno in {
                errno.EINVAL,
                errno.ENOTSUP,
                errno.EOPNOTSUPP,
            }:

                def unsupported_directory_fsync(fd, error=unsupported_errno):
                    if stat.S_ISDIR(os.fstat(fd).st_mode):
                        raise OSError(error, "directory fsync unsupported")
                    return real_fsync(fd)

                with patch(
                    "subagents_configs.filesystem.os.fsync",
                    unsupported_directory_fsync,
                ):
                    atomic_write(path, b"journal")
                self.assertEqual(path.read_bytes(), b"journal")

            def unrelated_directory_fsync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError(errno.EPERM, "directory fsync denied")
                return real_fsync(fd)

            with patch(
                "subagents_configs.filesystem.os.fsync",
                unrelated_directory_fsync,
            ):
                with self.assertRaisesRegex(OSError, "directory fsync denied"):
                    atomic_write(path, b"must report sync failure")
            self.assertEqual(path.read_bytes(), b"must report sync failure")

    def test_parent_swap_after_pin_cannot_redirect_operations(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (outside / "target").write_bytes(b"outside target")
            (outside / "source").write_bytes(b"outside source")
            watched = root / "watched"
            watched.mkdir()
            (watched / "target").write_bytes(b"old")
            (watched / "source").write_bytes(b"inside source")
            detached = root / "detached"
            swapped = False

            def swap_parent(operation, parent):
                nonlocal swapped
                if parent == watched and not swapped:
                    watched.rename(detached)
                    watched.symlink_to(outside, target_is_directory=True)
                    swapped = True

            with patch("subagents_configs.filesystem._after_parent_pin", swap_parent):
                self.assertEqual(
                    sha256_file(watched / "source"),
                    sha256_bytes(b"inside source"),
                )
            self.assertEqual((outside / "source").read_bytes(), b"outside source")
            watched.unlink()
            detached.rename(watched)

            swapped = False
            with patch("subagents_configs.filesystem._after_parent_pin", swap_parent):
                atomic_write(watched / "target", b"new inside")
            self.assertEqual((outside / "target").read_bytes(), b"outside target")
            self.assertEqual((detached / "target").read_bytes(), b"new inside")

            watched.unlink()
            detached.rename(watched)
            backup_source = root / "backup-source"
            backup_source.write_bytes(b"backup source")
            swapped = False
            with patch("subagents_configs.filesystem._after_parent_pin", swap_parent):
                exclusive_backup(backup_source, watched / "backup")
            self.assertFalse((outside / "backup").exists())
            self.assertEqual((detached / "backup").read_bytes(), b"backup source")

            watched.unlink()
            detached.rename(watched)
            (watched / "victim").write_bytes(b"inside victim")
            swapped = False
            with patch("subagents_configs.filesystem._after_parent_pin", swap_parent):
                unlink_regular(watched / "victim")
            self.assertEqual((outside / "victim").exists(), False)
            self.assertFalse((detached / "victim").exists())

            watched.unlink()
            detached.rename(watched)
            swapped = False
            with patch("subagents_configs.filesystem._after_parent_pin", swap_parent):
                ensure_private_directory(watched / "new-directory")
            self.assertFalse((outside / "new-directory").exists())
            self.assertEqual(
                stat.S_IMODE((detached / "new-directory").stat().st_mode),
                0o700,
            )

    def test_atomic_write_removes_same_directory_temp_on_failure(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            path = Path(temporary) / "manifest"
            with patch(
                "subagents_configs.filesystem.os.replace",
                side_effect=OSError("replace failed"),
            ):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    atomic_write(path, b"bytes")
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(temporary).glob(".manifest.tmp-*")), [])

    def test_atomic_write_rejects_symlink_target(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            real = root / "real"
            real.write_bytes(b"outside")
            path = root / "manifest"
            path.symlink_to(real)
            with self.assertRaises(ValueError):
                atomic_write(path, b"must not follow")
            self.assertEqual(real.read_bytes(), b"outside")

    def test_backup_is_exclusive_0600_hash_verified_and_never_follows_symlinks(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            source = root / "source"
            content = b"backup content"
            source.write_bytes(content)
            destination = root / "backup"
            digest = exclusive_backup(source, destination)
            self.assertEqual(digest, hashlib.sha256(content).hexdigest())
            self.assertEqual(destination.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                exclusive_backup(source, destination)

            source_link = root / "source-link"
            source_link.symlink_to(source)
            with self.assertRaises(ValueError):
                exclusive_backup(source_link, root / "other-backup")
            destination_link = root / "destination-link"
            destination_link.symlink_to(root / "not-created")
            with self.assertRaises(FileExistsError):
                exclusive_backup(source, destination_link)
            self.assertFalse((root / "not-created").exists())

    def test_backup_failure_removes_only_created_destination(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"source")
            destination = root / "backup"
            with patch(
                "subagents_configs.filesystem.os.fsync",
                side_effect=OSError("sync failed"),
            ):
                with self.assertRaisesRegex(OSError, "sync failed"):
                    exclusive_backup(source, destination)
            self.assertFalse(destination.exists())

    def test_backup_fchmods_before_file_fsync_and_parent_fsync(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "backups" / "backup"
            source.write_bytes(b"backup")
            destination.parent.mkdir()
            events = []
            real_fchmod = os.fchmod
            real_fsync = os.fsync

            def observed_fchmod(fd, mode):
                events.append(("chmod", fd, mode))
                return real_fchmod(fd, mode)

            def observed_fsync(fd):
                events.append(("fsync", fd, stat.S_ISDIR(os.fstat(fd).st_mode)))
                return real_fsync(fd)

            with (
                patch("subagents_configs.filesystem.os.fchmod", observed_fchmod),
                patch("subagents_configs.filesystem.os.fsync", observed_fsync),
            ):
                exclusive_backup(source, destination)
            chmod = next(
                index for index, event in enumerate(events) if event[0] == "chmod"
            )
            fsyncs = [
                (index, event)
                for index, event in enumerate(events)
                if event[0] == "fsync"
            ]
            file_fsync = next(index for index, event in fsyncs if not event[2])
            parent_fsync = next(index for index, event in fsyncs if event[2])
            self.assertLess(chmod, file_fsync)
            self.assertLess(file_fsync, parent_fsync)
            self.assertNotEqual(fsyncs[0][1][1], fsyncs[-1][1][1])

    def test_unlink_regular_is_safe_and_idempotent(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            path = root / "file"
            path.write_bytes(b"x")
            unlink_regular(path)
            unlink_regular(path)
            link = root / "link"
            link.symlink_to(root / "other")
            with self.assertRaises(ValueError):
                unlink_regular(link)


if __name__ == "__main__":
    unittest.main()
