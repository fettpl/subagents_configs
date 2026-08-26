import asyncio
import stat
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

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
