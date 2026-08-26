import asyncio
import errno
import os
import stat
import subprocess
import sys
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import subagents_configs.locks as locks
from subagents_configs import filesystem, recovery
from subagents_configs.locks import (
    capture_evidence,
    compare_and_swap,
    homes_locked,
    lock_held,
    locked_target_homes,
)
from subagents_configs.models import Target
from subagents_configs.transaction import TransactionError
from tests.helpers import private_tempdir


class LockAndEvidenceTests(unittest.TestCase):
    def test_inherited_asyncio_and_thread_contexts_cannot_claim_released_lease(self):
        with private_tempdir() as temporary:
            home = Path(temporary) / "home"

            async def exercise():
                released = asyncio.Event()

                async def child_task():
                    await released.wait()
                    return lock_held(), homes_locked({Target.CODEX: home})

                thread_gate = threading.Event()

                def child_thread():
                    thread_gate.wait(2)
                    return lock_held(), homes_locked({Target.CODEX: home})

                with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                    task = asyncio.create_task(child_task())
                    thread = asyncio.create_task(asyncio.to_thread(child_thread))
                    await asyncio.sleep(0)
                released.set()
                thread_gate.set()
                return await task, await thread

            self.assertEqual(
                asyncio.run(exercise()),
                ((False, False), (False, False)),
            )

    def test_recovery_reuses_the_live_outer_lock_without_deadlock(self):
        with private_tempdir() as temporary:
            home = Path(temporary) / "home"
            entered = threading.Event()

            def recovery_body(_homes):
                self.assertTrue(lock_held())
                entered.set()

            def run_recovery():
                with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                    with patch.object(
                        recovery, "recover_participants_impl", recovery_body
                    ):
                        recovery.recover_transaction(
                            {Target.CODEX: home}, (Target.CODEX,)
                        )

            thread = threading.Thread(target=run_recovery)
            thread.start()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertTrue(entered.is_set())

    def test_ensure_directory_checks_every_existing_component_against_home_lease(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                detached = root / "detached"
                home.rename(detached)
                home.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    filesystem.ensure_private_directory(home / "nested")
                self.assertFalse((home / "nested").exists())

    def test_absent_final_home_is_created_but_missing_ancestors_are_not(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            parent = root / "existing"
            parent.mkdir(mode=0o700)
            home = parent / "home"
            with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                self.assertTrue(home.is_dir())
                self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)
                self.assertTrue((home / ".subagents_configs.lock").is_file())
            missing = root / "missing" / "nested" / "home"
            with self.assertRaises(ValueError):
                with locked_target_homes({Target.CODEX: missing}, (Target.CODEX,)):
                    pass
            self.assertFalse((root / "missing").exists())

    def test_absent_home_swap_after_mkdir_fails_before_lock_creation(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            home = parent / "home"

            def swap(_home):
                home.mkdir(mode=0o700)

            with patch("subagents_configs.locks._after_home_mkdir", swap):
                with self.assertRaises(ValueError):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            self.assertFalse((home / ".subagents_configs.lock").exists())
            self.assertEqual(
                [entry.name for entry in parent.iterdir() if ".tmp-" in entry.name],
                [],
            )

    def test_absent_home_swap_after_publication_fails_before_lock_creation(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            home = parent / "home"

            def swap(_home):
                home.rmdir()
                home.mkdir(mode=0o700)

            with patch("subagents_configs.locks._after_home_publish", swap):
                with self.assertRaises(ValueError):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            self.assertTrue(home.is_dir())
            self.assertFalse((home / ".subagents_configs.lock").exists())
            self.assertEqual(
                [entry.name for entry in parent.iterdir() if ".tmp-" in entry.name],
                [],
            )

    def test_absent_home_publication_unavailable_fails_without_temp_leak(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            home = parent / "home"

            with patch(
                "subagents_configs.locks._rename_noreplace",
                side_effect=ValueError("exclusive home publication is unavailable"),
            ):
                with self.assertRaisesRegex(
                    ValueError, "exclusive home publication is unavailable"
                ):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            self.assertFalse(home.exists())
            self.assertEqual(
                [entry.name for entry in parent.iterdir() if ".tmp-" in entry.name],
                [],
            )

    def test_absent_home_temp_open_failure_cleans_owned_temp(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            home = parent / "home"
            real_open = locks.os.open

            def fail_temp_open(path, *args, **kwargs):
                if isinstance(path, str) and path.startswith(".home.tmp-"):
                    raise OSError(errno.EIO, "injected temporary open failure")
                return real_open(path, *args, **kwargs)

            with patch.object(locks.os, "open", side_effect=fail_temp_open):
                with self.assertRaisesRegex(OSError, "temporary open failure"):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            self.assertEqual(
                [entry.name for entry in parent.iterdir() if ".tmp-" in entry.name],
                [],
            )

    def test_absent_home_temp_open_replacement_is_preserved(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            home = parent / "home"
            replacement = parent / "replacement"
            replacement.mkdir(mode=0o700)
            real_open = locks.os.open

            def fail_after_replacement(path, *args, **kwargs):
                if isinstance(path, str) and path.startswith(".home.tmp-"):
                    temporary_entry = next(
                        entry for entry in parent.iterdir() if ".tmp-" in entry.name
                    )
                    temporary_entry.rmdir()
                    temporary_entry.symlink_to(replacement, target_is_directory=True)
                    raise OSError(errno.EIO, "injected temporary open failure")
                return real_open(path, *args, **kwargs)

            with patch.object(locks.os, "open", side_effect=fail_after_replacement):
                with self.assertRaisesRegex(OSError, "temporary open failure"):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            temporary_entries = [
                entry for entry in parent.iterdir() if ".tmp-" in entry.name
            ]
            self.assertEqual(len(temporary_entries), 1)
            self.assertTrue(temporary_entries[0].is_symlink())
            self.assertEqual(temporary_entries[0].resolve(), replacement)

    def test_absent_home_temp_real_directory_swap_before_open_fails_closed(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            home = parent / "home"
            real_open = locks.os.open
            swapped = False

            def swap_before_open(path, *args, **kwargs):
                nonlocal swapped
                if isinstance(path, str) and path.startswith(".home.tmp-"):
                    temporary_entry = next(
                        entry for entry in parent.iterdir() if ".tmp-" in entry.name
                    )
                    temporary_entry.rmdir()
                    temporary_entry.mkdir(mode=0o700)
                    swapped = True
                return real_open(path, *args, **kwargs)

            with patch.object(locks.os, "open", side_effect=swap_before_open):
                with self.assertRaises(ValueError):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            self.assertTrue(swapped)
            self.assertFalse(home.exists())
            temporary_entries = [
                entry for entry in parent.iterdir() if ".tmp-" in entry.name
            ]
            self.assertEqual(len(temporary_entries), 1)
            self.assertTrue(temporary_entries[0].is_dir())

    def test_absent_home_temp_same_inode_with_new_ctime_fails_closed(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            home = parent / "home"
            real_open = locks.os.open
            real_fstat = locks.os.fstat
            original_binding = None
            swapped = False
            forced = False

            def swap_before_open(path, *args, **kwargs):
                nonlocal swapped
                if isinstance(path, str) and path.startswith(".home.tmp-"):
                    temporary_entry = next(
                        entry for entry in parent.iterdir() if ".tmp-" in entry.name
                    )
                    temporary_entry.rmdir()
                    temporary_entry.mkdir(mode=0o700)
                    swapped = True
                return real_open(path, *args, **kwargs)

            def same_inode_new_ctime(descriptor):
                nonlocal forced, original_binding
                result = real_fstat(descriptor)
                if not swapped or forced:
                    return result
                forced = True
                return SimpleNamespace(
                    st_dev=original_binding[0],
                    st_ino=original_binding[1],
                    st_ctime_ns=original_binding[2] + 1,
                    st_mode=result.st_mode,
                    st_uid=result.st_uid,
                )

            real_binding = locks._directory_binding

            def capture_original(result):
                nonlocal original_binding
                binding = real_binding(result)
                if original_binding is None:
                    original_binding = binding
                return binding

            with (
                patch.object(locks.os, "open", side_effect=swap_before_open),
                patch.object(locks.os, "fstat", side_effect=same_inode_new_ctime),
                patch.object(locks, "_directory_binding", side_effect=capture_original),
            ):
                with self.assertRaises(ValueError):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            self.assertTrue(swapped)
            self.assertTrue(forced)
            self.assertFalse(home.exists())
            temporary_entries = [
                entry for entry in parent.iterdir() if ".tmp-" in entry.name
            ]
            self.assertEqual(len(temporary_entries), 1)
            self.assertTrue(temporary_entries[0].is_dir())

    def test_absent_home_post_publish_stat_failure_cleans_published_home(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            home = parent / "home"
            real_stat = locks.os.stat
            home_stat_calls = 0

            def fail_first_post_publish_stat(path, *args, **kwargs):
                nonlocal home_stat_calls
                if path == "home":
                    home_stat_calls += 1
                    if home_stat_calls == 2:
                        raise OSError(errno.EIO, "injected post-publish stat failure")
                return real_stat(path, *args, **kwargs)

            with patch.object(
                locks.os, "stat", side_effect=fail_first_post_publish_stat
            ):
                with self.assertRaisesRegex(OSError, "post-publish stat failure"):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            self.assertEqual(home_stat_calls, 3)
            self.assertFalse(home.exists())
            self.assertEqual(
                [entry for entry in parent.iterdir() if ".tmp-" in entry.name], []
            )

    def test_home_and_ancestor_symlinks_are_rejected_without_redirected_lock(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir(mode=0o700)
            home_link = root / "home"
            home_link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                with locked_target_homes({Target.CODEX: home_link}, (Target.CODEX,)):
                    pass
            ancestor_link = root / "linked-parent"
            ancestor_link.symlink_to(root, target_is_directory=True)
            nested = ancestor_link / "new-home"
            with self.assertRaises(ValueError):
                with locked_target_homes({Target.CODEX: nested}, (Target.CODEX,)):
                    pass
            self.assertFalse((root / "new-home" / ".subagents_configs.lock").exists())

    def test_ancestor_real_directory_swap_between_validation_and_open_fails(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            anchor = root / "anchor"
            anchor.mkdir(mode=0o700)
            home = anchor / "home"

            def swap(_home):
                detached = root / "detached-anchor"
                anchor.rename(detached)
                anchor.mkdir(mode=0o700)

            with patch("subagents_configs.locks._after_home_validation", swap):
                with self.assertRaises(ValueError):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            self.assertFalse((anchor / "home").exists())
            self.assertFalse((root / "detached-anchor" / "home").exists())

    def test_replacing_locked_home_with_real_directory_fails_before_write(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                detached = root / "detached"
                home.rename(detached)
                home.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    filesystem.atomic_write(home / "managed", b"must not write")
                self.assertFalse((home / "managed").exists())
                self.assertFalse((detached / "managed").exists())

    def test_home_swap_after_parent_pin_fails_closed(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            swapped = False

            def swap(_operation, parent):
                nonlocal swapped
                if parent == home and not swapped:
                    detached = root / "detached"
                    home.rename(detached)
                    home.mkdir(mode=0o700)
                    swapped = True

            with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                with patch.object(filesystem, "_after_parent_pin", swap):
                    with self.assertRaises(ValueError):
                        filesystem.atomic_write(home / "managed", b"must not write")
            self.assertFalse((home / "managed").exists())

    def test_second_lock_waits_until_first_releases(self):
        with private_tempdir() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            acquired = threading.Event()
            release = threading.Event()

            def holder():
                with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                    acquired.set()
                    release.wait(2)

            thread = threading.Thread(target=holder)
            thread.start()
            self.assertTrue(acquired.wait(2))
            contender_acquired = threading.Event()

            def contender():
                with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                    contender_acquired.set()

            contender_thread = threading.Thread(target=contender)
            contender_thread.start()
            self.assertFalse(contender_acquired.wait(0.1))
            release.set()
            thread.join(2)
            contender_thread.join(2)
            self.assertTrue(contender_acquired.is_set())

    def test_replaced_persistent_anchor_rejects_second_context(self):
        with private_tempdir() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            result = []
            with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                anchor = home / ".subagents_configs.lock"
                detached = home / ".detached-lock"
                anchor.rename(detached)
                anchor.write_bytes(b"")
                anchor.chmod(0o600)

                def contender():
                    try:
                        with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                            result.append("entered")
                    except ValueError:
                        result.append("rejected")

                thread = threading.Thread(target=contender)
                thread.start()
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(result, ["rejected"])
                self.assertTrue(anchor.is_file())
                self.assertTrue(detached.is_file())

    def test_replaced_persistent_anchor_blocks_independent_process(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            ready = root / "ready"
            gate = root / "gate"
            entered = root / "entered"
            script = """
import sys
import time
from pathlib import Path
from subagents_configs.locks import locked_target_homes
from subagents_configs.models import Target

home, ready, gate, entered = map(Path, sys.argv[1:])
ready.write_text("ready")
while not gate.exists():
    time.sleep(0.01)
with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
    entered.write_text("entered")
"""
            with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                process = subprocess.Popen(  # noqa: S603
                    [
                        sys.executable,
                        "-c",
                        script,
                        str(home),
                        str(ready),
                        str(gate),
                        str(entered),
                    ]
                )
                try:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists())
                    anchor = home / ".subagents_configs.lock"
                    detached = home / ".detached-lock"
                    anchor.rename(detached)
                    anchor.write_bytes(b"")
                    anchor.chmod(0o600)
                    gate.write_text("go")
                    time.sleep(0.5)
                    self.assertFalse(entered.exists())
                finally:
                    process.terminate()
                    process.wait(timeout=5)
            self.assertTrue((home / ".subagents_configs.lock").is_file())
            self.assertTrue((home / ".detached-lock").is_file())

    def test_cleanup_closes_home_descriptor_when_unlock_fails(self):
        with private_tempdir() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            real_flock = locks.fcntl.flock
            real_close = locks.os.close
            flock_calls = []
            close_calls = []
            cleanup_close_calls = []
            unlocks = 0

            def flaky_flock(descriptor, operation):
                nonlocal unlocks
                flock_calls.append((descriptor, operation))
                result = real_flock(descriptor, operation)
                if operation == locks.fcntl.LOCK_UN:
                    unlocks += 1
                    if unlocks == 2:
                        raise OSError("injected home unlock failure")
                return result

            def recording_close(descriptor):
                close_calls.append(descriptor)
                if unlocks:
                    cleanup_close_calls.append(descriptor)
                return real_close(descriptor)

            with (
                patch.object(locks.fcntl, "flock", side_effect=flaky_flock),
                patch.object(locks.os, "close", side_effect=recording_close),
            ):
                with self.assertRaisesRegex(OSError, "home unlock failure"):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            home_descriptor = flock_calls[0][0]
            anchor_descriptor = flock_calls[1][0]
            self.assertIn(home_descriptor, cleanup_close_calls)
            self.assertIn(anchor_descriptor, cleanup_close_calls)
            self.assertGreaterEqual(len(close_calls), 2)
            with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                pass

    def test_acquisition_cleanup_releases_all_descriptors_when_unlock_fails(self):
        with private_tempdir() as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            real_identity_check = locks._lock_anchor_path_identity
            real_flock = locks.fcntl.flock
            real_close = locks.os.close
            flock_calls = []
            close_calls = []
            unlocks = 0
            identity_checks = 0

            def fail_identity_check(home_descriptor, anchor_identity):
                nonlocal identity_checks
                identity_checks += 1
                if identity_checks == 3:
                    raise ValueError("primary anchor identity failure")
                return real_identity_check(home_descriptor, anchor_identity)

            def flaky_flock(descriptor, operation):
                nonlocal unlocks
                flock_calls.append((descriptor, operation))
                result = real_flock(descriptor, operation)
                if operation == locks.fcntl.LOCK_UN:
                    unlocks += 1
                    if unlocks == 1:
                        raise OSError("injected anchor unlock failure")
                return result

            def recording_close(descriptor):
                if unlocks:
                    close_calls.append(descriptor)
                return real_close(descriptor)

            with (
                patch.object(
                    locks, "_lock_anchor_path_identity", side_effect=fail_identity_check
                ),
                patch.object(locks.fcntl, "flock", side_effect=flaky_flock),
                patch.object(locks.os, "close", side_effect=recording_close),
            ):
                with self.assertRaisesRegex(ValueError, "primary anchor identity"):
                    with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                        pass
            self.assertIn(flock_calls[0][0], close_calls)
            self.assertIn(flock_calls[1][0], close_calls)
            with locked_target_homes({Target.CODEX: home}, (Target.CODEX,)):
                pass

    def test_failed_close_retries_when_original_descriptor_remains_open(self):
        with private_tempdir() as temporary:
            path = Path(temporary) / "descriptor"
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            real_close = locks.os.close
            attempts = 0

            def fail_once(fd):
                nonlocal attempts
                if fd == descriptor and attempts == 0:
                    attempts += 1
                    raise OSError(errno.EIO, "injected close failure")
                return real_close(fd)

            with patch.object(locks.os, "close", side_effect=fail_once):
                errors = locks._unlock_and_close(descriptor, False)
            self.assertEqual(attempts, 1)
            self.assertEqual(len(errors), 1)
            with self.assertRaises(OSError) as error:
                locks.fcntl.fcntl(descriptor, locks.fcntl.F_GETFD)
            self.assertEqual(error.exception.errno, errno.EBADF)

    def test_failed_close_does_not_close_reused_descriptor_after_eintr(self):
        with private_tempdir() as temporary:
            path = Path(temporary) / "descriptor"
            replacement = Path(temporary) / "replacement"
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            real_close = locks.os.close
            replacement_descriptor = None

            def close_then_reuse(fd):
                nonlocal replacement_descriptor
                if fd == descriptor and replacement_descriptor is None:
                    real_close(fd)
                    replacement_descriptor = os.open(
                        replacement, os.O_RDWR | os.O_CREAT, 0o600
                    )
                    raise OSError(errno.EINTR, "simulated completed close")
                return real_close(fd)

            with patch.object(locks.os, "close", side_effect=close_then_reuse):
                errors = locks._unlock_and_close(descriptor, False)
            assert replacement_descriptor is not None
            self.assertEqual(len(errors), 1)
            self.assertGreaterEqual(
                locks.fcntl.fcntl(replacement_descriptor, locks.fcntl.F_GETFD), 0
            )
            real_close(replacement_descriptor)

    def test_lock_rejects_noncanonical_or_duplicate_target_sequences(self):
        with private_tempdir() as temporary:
            homes = {
                Target.CODEX: Path(temporary) / "codex",
                Target.OPENCODE: Path(temporary) / "opencode",
            }
            for home in homes.values():
                home.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                with locked_target_homes(homes, (Target.OPENCODE, Target.CODEX)):
                    pass
            with self.assertRaises(ValueError):
                with locked_target_homes(homes, (Target.CODEX, Target.CODEX)):
                    pass

    def test_nested_lock_rejects_swapped_target_home_bindings(self):
        with private_tempdir() as temporary:
            homes = {
                Target.CODEX: Path(temporary) / "codex",
                Target.OPENCODE: Path(temporary) / "opencode",
            }
            for home in homes.values():
                home.mkdir(mode=0o700)
            swapped = {
                Target.CODEX: homes[Target.OPENCODE],
                Target.OPENCODE: homes[Target.CODEX],
            }
            with locked_target_homes(homes, (Target.CODEX, Target.OPENCODE)):
                self.assertTrue(homes_locked(homes))
                self.assertFalse(homes_locked(swapped))
                with self.assertRaises(ValueError):
                    with locked_target_homes(swapped, (Target.CODEX, Target.OPENCODE)):
                        pass

    def test_compare_and_swap_rejects_each_identity_field_change(self):
        with private_tempdir() as temporary:
            path = Path(temporary) / "managed"
            path.write_bytes(b"before")
            path.chmod(0o600)
            evidence = capture_evidence(path, "target")
            self.assertIsNotNone(evidence)
            assert evidence is not None
            mutations = (
                replace(evidence, device=evidence.device + 1),
                replace(evidence, inode=evidence.inode + 1),
                replace(evidence, size=evidence.size + 1),
                replace(evidence, nlink=evidence.nlink + 1),
                replace(evidence, mode=0o400),
                replace(evidence, sha256="0" * 64),
            )
            for changed in mutations:
                with self.assertRaises(TransactionError):
                    compare_and_swap(path, changed, b"after", 0o600, "replace")
            self.assertEqual(path.read_bytes(), b"before")


if __name__ == "__main__":
    unittest.main()
