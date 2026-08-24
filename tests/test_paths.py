import os
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from subagents_configs.paths import (
    assert_contained,
    assert_safe_home,
    assert_safe_managed_path,
    lstat_existing,
    normalized_absolute,
    strict_relative_path,
)

TEMP_DIR = "/private/tmp" if Path("/private/tmp").is_dir() else None


class PathSafetyTests(unittest.TestCase):
    def test_normalized_absolute_is_lexical(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            link = root / "link"
            link.symlink_to(root / "missing")
            self.assertEqual(normalized_absolute(link / ".."), root)

    def test_rejects_symlink_home(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            home = root / "home"
            home.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                assert_safe_home(home)

    def test_rejects_symlink_managed_component(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir()
            (home / "agents").symlink_to(root / "elsewhere", target_is_directory=True)
            with self.assertRaises(ValueError):
                assert_safe_managed_path(home, home / "agents" / "role.toml", "agent")

    def test_rejects_symlink_target_file(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir()
            target = home / "AGENTS.md"
            target.symlink_to(root / "outside")
            with self.assertRaises(ValueError):
                assert_safe_managed_path(home, target, "global instructions")

    def test_rejects_absolute_and_parent_traversing_state_paths(self):
        values = (
            "",
            "/state.json",
            "../state.json",
            "state/../x",
            "state//x",
            "./x",
            "x/",
            "x\\y",
            "C:/x",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                strict_relative_path(value)

    def test_strict_relative_path_returns_posix_path(self):
        self.assertEqual(
            strict_relative_path("state/journal.json"),
            PurePosixPath("state/journal.json"),
        )

    def test_rejects_normalized_path_outside_home(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            home = Path(temporary) / "home"
            home.mkdir()
            with self.assertRaises(ValueError):
                assert_contained(home, home / "state" / ".." / ".." / "outside")

    def test_accepts_missing_managed_target_but_checks_existing_parent_types(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            home = Path(temporary) / "home"
            home.mkdir()
            assert_safe_managed_path(home, home / "agents" / "role.toml", "agent")
            (home / "not-a-directory").write_bytes(b"x")
            with self.assertRaises(ValueError):
                assert_safe_managed_path(
                    home, home / "not-a-directory" / "role.toml", "agent"
                )

    def test_lstat_existing_distinguishes_missing_without_following_links(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            root = Path(temporary)
            self.assertIsNone(lstat_existing(root / "missing", "missing"))
            link = root / "link"
            link.symlink_to(root / "missing")
            with self.assertRaises(ValueError):
                lstat_existing(link, "link")

    def test_rejects_non_directory_home(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            home = Path(temporary) / "home"
            home.write_bytes(b"not a directory")
            with self.assertRaises(ValueError):
                assert_safe_home(home)

    def test_rejects_non_regular_managed_target(self):
        with tempfile.TemporaryDirectory(dir=TEMP_DIR) as temporary:
            home = Path(temporary) / "home"
            home.mkdir()
            target = home / "journal"
            os.mkfifo(target)
            with self.assertRaises(ValueError):
                assert_safe_managed_path(home, target, "journal")


if __name__ == "__main__":
    unittest.main()
