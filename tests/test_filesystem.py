import errno
import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from subagents_configs.filesystem import (
    atomic_write,
    ensure_private_directory,
    exclusive_backup,
    sha256_bytes,
    sha256_file,
    unlink_regular,
)

TEMP_DIR = "/private/tmp" if Path("/private/tmp").is_dir() else None


class FilesystemTests(unittest.TestCase):
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
