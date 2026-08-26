import stat
import unittest
from pathlib import Path

from tests.helpers import (
    private_tempdir,
    replace_file_with_same_content_new_inode,
)


class HelperTests(unittest.TestCase):
    def test_same_content_replacement_has_new_inode_and_preserves_file(self):
        with private_tempdir() as directory:
            root = Path(directory)
            target = root / "managed-file"
            target.write_bytes(b"same content\n")
            target.chmod(0o640)
            before = target.stat(follow_symlinks=False)

            replace_file_with_same_content_new_inode(target)

            after = target.stat(follow_symlinks=False)
            self.assertNotEqual(
                (after.st_dev, after.st_ino),
                (before.st_dev, before.st_ino),
            )
            self.assertEqual(target.read_bytes(), b"same content\n")
            self.assertEqual(stat.S_IMODE(after.st_mode), 0o640)
            self.assertEqual(tuple(root.iterdir()), (target,))
