import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from subagents_configs.locks import (
    capture_evidence,
    compare_and_swap,
    locked_target_homes,
)
from subagents_configs.models import Target
from subagents_configs.transaction import TransactionError


class LockAndEvidenceTests(unittest.TestCase):
    def test_second_lock_waits_until_first_releases(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
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
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
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
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
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
