from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

SAFE_ENV_KEYS = frozenset(
    {
        "CI",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
    }
)


class ChildEnvironmentTests(unittest.TestCase):
    def test_environment_is_exact_allowlist_and_has_private_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "bin"
            executable.mkdir(mode=0o700)
            source = {
                "PATH": "/attacker/bin",
                "HTTP_PROXY": "http://proxy.invalid",
                "SSH_AUTH_SOCK": "agent-socket",
                "AWS_SECRET_ACCESS_KEY": "secret",
                "NPM_TOKEN": "token",
                "SERVICE_PASSWORD": "password",
                "DEPLOY_CREDENTIAL": "credential",
                "PUBLIC_KEY": "key",
                "ARBITRARY": "arbitrary",
            }

            from scripts.validation_isolation.environment import build_child_environment

            environment = build_child_environment(
                source, root, (executable, executable)
            )
            self.assertEqual(set(environment), SAFE_ENV_KEYS)
            self.assertEqual(environment["CI"], "1")
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(environment["LANG"], "C.UTF-8")
            self.assertEqual(environment["LC_ALL"], "C.UTF-8")
            self.assertEqual(environment["PATH"], str(executable.resolve()))
            for key in ("HOME", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"):
                path = Path(environment[key])
                self.assertTrue(path.is_dir())
                self.assertEqual(path.parent, root)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertNotIn("secret", environment.values())
            self.assertNotIn("token", environment.values())

    def test_rejects_unsafe_executable_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o700)
            os.chmod(unsafe, 0o777)  # noqa: S103

            from scripts.validation_isolation.environment import build_child_environment

            with self.assertRaises(ValueError):
                build_child_environment({}, root, (unsafe,))

    def test_rejects_empty_executable_directory_list(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                from scripts.validation_isolation.environment import (
                    build_child_environment,
                )

                build_child_environment({}, Path(temporary), ())

    def test_rejects_relative_and_symlink_executable_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)

            from scripts.validation_isolation.environment import build_child_environment

            with self.assertRaises(ValueError):
                build_child_environment({}, root, (Path("relative"),))
            with self.assertRaises(ValueError):
                build_child_environment({}, root, (link,))

    def test_rejects_traversal_in_executable_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "bin"
            executable.mkdir(mode=0o700)

            from scripts.validation_isolation.environment import build_child_environment

            with self.assertRaises(ValueError):
                build_child_environment({}, root, (Path(f"{root}/child/../bin"),))

    def test_rejects_temp_root_aliasing_and_unsafe_existing_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing_home = root / "home"
            existing_home.mkdir(mode=0o755)
            executable = root / "bin"
            executable.mkdir(mode=0o700)

            from scripts.validation_isolation.environment import build_child_environment

            with self.assertRaises(ValueError):
                build_child_environment({}, root, (executable,))


if __name__ == "__main__":
    unittest.main()
