from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.validation_isolated_test_support import make_repository, system_executable

MACOS_SANDBOX = Path("/usr/bin/sandbox-exec")


def _system_launcher() -> Path:
    return system_executable("true")


def _system_python() -> Path:
    return system_executable("python3")


def _executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(path, 0o755)  # noqa: S103
    return path


def _environment(temp: Path) -> dict[str, str]:
    directories = {}
    for name in ("home", "tmp", "cache", "config"):
        path = temp / name
        path.mkdir(mode=0o700, exist_ok=True)
        directories[name] = path
    return {
        "CI": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(directories["home"]),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin",
        "TMPDIR": str(directories["tmp"]),
        "XDG_CACHE_HOME": str(directories["cache"]),
        "XDG_CONFIG_HOME": str(directories["config"]),
    }


class BackendSelectionTests(unittest.TestCase):
    @unittest.skipUnless(
        MACOS_SANDBOX.exists() and MACOS_SANDBOX.resolve(strict=True) == MACOS_SANDBOX,
        "macOS sandbox-exec is unavailable",
    )
    def test_selects_only_fixed_macos_launcher(self):
        from scripts.validation_isolation.backend import select_backend

        backend = select_backend("darwin", MACOS_SANDBOX, None, _system_python())
        self.assertEqual(backend.name, "macos")
        self.assertEqual(backend.launcher, MACOS_SANDBOX)

    def test_selects_only_fixed_linux_launcher(self):
        from scripts.validation_isolation.backend import select_backend

        for launcher in (Path("/usr/bin/bwrap"), Path("/bin/bwrap")):
            with self.subTest(launcher=launcher):
                if not launcher.exists() or launcher.resolve(strict=True) != launcher:
                    continue
                backend = select_backend(
                    "linux",
                    MACOS_SANDBOX,
                    launcher,
                    _system_python(),
                )
                self.assertEqual(backend.name, "linux")
                self.assertEqual(backend.launcher, launcher)

    def test_rejects_unsupported_or_unusable_backend(self):
        from scripts.validation_isolation.backend import select_backend

        with self.assertRaises(ValueError):
            select_backend("win32", MACOS_SANDBOX, None, _system_python())
        with self.assertRaises(ValueError):
            select_backend(
                "darwin", Path("/invalid/sandbox-exec"), None, _system_python()
            )
        with self.assertRaises(ValueError):
            select_backend(
                "linux",
                MACOS_SANDBOX,
                Path("/invalid/bwrap"),
                _system_python(),
            )

    def test_backend_selection_ignores_inherited_path(self):
        from scripts.validation_isolation.backend import select_backend

        with tempfile.TemporaryDirectory() as temporary:
            fake = _executable(Path(temporary) / "sandbox-exec")
            with patch.dict(os.environ, {"PATH": temporary}, clear=False):
                with self.assertRaises(ValueError):
                    select_backend("darwin", fake, None, _system_python())


class BackendArgumentTests(unittest.TestCase):
    def test_rejects_python_separator_encodings_at_both_command_boundaries(self):
        from scripts.validation_isolation.backend import (
            BackendSpec,
            build_backend_argv,
            validate_command_argv,
        )

        spellings = (r"\057", r"\U0000002F", r"\N{SOLIDUS}")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            worktree = root / "worktree"
            home = root / "home"
            temp = root / "temp"
            worktree.mkdir(mode=0o700)
            home.mkdir(mode=0o700)
            temp.mkdir(mode=0o700)
            protected = (
                ("worktree", worktree / "secret.txt"),
                ("home", home / "private.txt"),
                ("socket", home / "run" / "socket"),
                ("credential", home / ".ssh" / "id_rsa"),
            )
            backend = BackendSpec("macos", _system_launcher(), _system_python())
            for spelling in spellings:
                for name, path in protected:
                    encoded = str(path).replace("/", spelling)
                    for token in (
                        f"--input={encoded}",
                        f"prefix{encoded}",
                        f'open("{encoded}")',
                        f'{{"path":"{encoded}"}}',
                    ):
                        with self.subTest(
                            boundary="early", spelling=spelling, name=name, token=token
                        ):
                            with self.assertRaises(ValueError):
                                validate_command_argv(
                                    ("python3", token), worktree, home
                                )
                        with self.subTest(
                            boundary="backend",
                            spelling=spelling,
                            name=name,
                            token=token,
                        ):
                            with self.assertRaises(ValueError):
                                build_backend_argv(
                                    backend,
                                    ("python3", token),
                                    worktree,
                                    temp,
                                    _environment(temp),
                                )

            validate_command_argv((str(_system_python()), "/dev/null"), worktree, home)
            build_backend_argv(
                backend,
                (str(worktree / "guest.py"),),
                worktree,
                temp,
                _environment(temp),
            )

    def test_macos_profile_rejects_seatbelt_syntax_in_every_path(self):
        from scripts.validation_isolation.backend import render_macos_profile

        unsafe_values = ('quote"', "back\\slash", "line\nfeed", "control\x1f")
        for unsafe in unsafe_values:
            with self.subTest(path="snapshot", unsafe=repr(unsafe)):
                with self.assertRaises(ValueError):
                    render_macos_profile(
                        Path("/private/tmp") / unsafe,
                        Path("/private/tmp/temp"),
                        _system_python(),
                    )
            with self.subTest(path="temp", unsafe=repr(unsafe)):
                with self.assertRaises(ValueError):
                    render_macos_profile(
                        Path("/private/tmp/snapshot"),
                        Path("/private/tmp") / unsafe,
                        _system_python(),
                    )
            with self.subTest(path="python", unsafe=repr(unsafe)):
                with self.assertRaises(ValueError):
                    render_macos_profile(
                        Path("/private/tmp/snapshot"),
                        Path("/private/tmp/temp"),
                        Path("/usr/bin") / unsafe,
                    )

    def test_macos_profile_denies_network_and_limits_writes(self):
        from scripts.validation_isolation.backend import render_macos_profile

        profile = render_macos_profile(
            Path("/private/tmp/snapshot"),
            Path("/private/tmp/temp"),
            _system_python(),
        )
        self.assertIn("(deny network*)", profile)
        self.assertIn("/private/tmp/snapshot", profile)
        self.assertIn("/private/tmp/temp", profile)
        self.assertIn("(deny file-write*)", profile)
        self.assertNotIn("/Users/pawel/Documents/GitHub", profile)
        self.assertNotIn('(subpath "/")', profile)
        for optional_root in (Path("/bin"), Path("/sbin")):
            if (
                optional_root.exists()
                and optional_root.resolve(strict=True) != optional_root
            ):
                self.assertNotIn(f'(subpath "{optional_root}")', profile)

    def test_macos_profile_rejects_custom_home_interpreter_and_broad_reads(self):
        from scripts.validation_isolation.backend import render_macos_profile

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "home").mkdir()
            custom = _executable(root / "home" / "python")
            with self.assertRaises(ValueError):
                render_macos_profile(root / "snapshot", root / "temp", custom)
        profile = render_macos_profile(
            Path("/private/tmp/snapshot"),
            Path("/private/tmp/temp"),
            _system_python(),
        )
        for broad in ("/etc", "/Library", "/System", "/Users", "/home"):
            self.assertNotIn(f'(subpath "{broad}")', profile)

    def test_linux_argv_has_namespace_clearenv_and_private_mounts(self):
        from scripts.validation_isolation.backend import BackendSpec, build_backend_argv

        backend = BackendSpec("linux", Path("/usr/bin/bwrap"), _system_python())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            snapshot = root / "snapshot"
            temp = root / "temp"
            snapshot.mkdir(mode=0o700)
            temp.mkdir(mode=0o700)
            argv = build_backend_argv(
                backend,
                ("python3", "-m", "unittest"),
                snapshot,
                temp,
                _environment(temp),
            )
        self.assertEqual(argv[0], "/usr/bin/bwrap")
        for option in (
            "--unshare-net",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ):
            self.assertIn(option, argv)
        self.assertIn(str(snapshot), argv)
        self.assertIn(str(temp), argv)
        self.assertIn("--ro-bind", argv)
        self.assertNotIn("/Users/pawel/Documents/GitHub/subagents_configs", argv)

    def test_linux_mount_plan_is_canonical_minimal_and_no_custom_prefix(self):
        from scripts.validation_isolation.backend import build_linux_mount_plan

        mounts = build_linux_mount_plan(_system_python())
        for index, mount in enumerate(mounts):
            self.assertEqual(mount, mount.resolve(strict=True))
            self.assertNotIn(mount.parts[1:2], (("Users",), ("home",)))
            for other in mounts[index + 1 :]:
                self.assertNotIn(mount, other.parents)
                self.assertNotIn(other, mount.parents)
        for optional_root in (
            Path("/bin"),
            Path("/sbin"),
            Path("/lib"),
            Path("/lib64"),
        ):
            if (
                optional_root.exists()
                and optional_root.resolve(strict=True) != optional_root
            ):
                self.assertNotIn(optional_root, mounts)
        self.assertNotIn(Path("/etc"), mounts)
        with self.assertRaises(ValueError):
            build_linux_mount_plan(Path("/Users/pawel/python"))

    def test_backend_rejects_arbitrary_environment_mapping_and_values(self):
        from scripts.validation_isolation.backend import BackendSpec, build_backend_argv

        backend = BackendSpec("macos", _system_launcher(), _system_python())
        with self.assertRaises(ValueError):
            build_backend_argv(
                backend,
                ("/usr/bin/true",),
                Path("/private/tmp/snapshot"),
                Path("/private/tmp/temp"),
                {"PATH": "/usr/bin"},
            )

    def test_command_argv_rejects_host_and_secret_paths_but_allows_system(self):
        from scripts.validation_isolation.backend import validate_command_argv

        worktree = Path("/Users/pawel/Documents/GitHub/project")
        self.assertEqual(
            validate_command_argv(("/usr/bin/true", "--help"), worktree),
            ("/usr/bin/true", "--help"),
        )
        rejected = (
            str(worktree / "tracked.txt"),
            str(Path.home()),
            "/tmp/agent.sock",  # noqa: S108
            "--config=/Users/pawel/.ssh/id_rsa",
            "--x=/etc/credentials",
        )
        for value in rejected:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_command_argv(("/usr/bin/true", value), worktree)

    def test_command_argv_rejects_embedded_protected_paths_and_encoded_aliases(self):
        from scripts.validation_isolation.backend import validate_command_argv

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            worktree = root / "worktree"
            home = root / "home"
            worktree.mkdir()
            home.mkdir()
            worktree_secret = f"{worktree}/secret"
            home_secret = f"{home}/.ssh/id_rsa"
            encoded_worktree = "%2F" + str(worktree).lstrip("/").replace("/", "%2F")
            encoded_home = "%2F" + str(home).lstrip("/").replace("/", "%2F")
            escaped_worktree = "\\u002f".join(str(worktree).split("/"))
            escaped_home = "\\u002f".join(str(home).split("/"))
            rejected = (
                f"open('{worktree_secret}')",
                f'{{"path":"{worktree_secret}"}}',
                f'"{worktree_secret}"',
                f"echo {worktree_secret},",
                f"-I{worktree_secret}",
                f"--socket{home_secret}",
                f"prefix{worktree_secret}",
                f"open('{home_secret}')",
                f"open('{worktree}/./secret')",
                f"open('{worktree}/%2e%2e/secret')",
                f"open('{encoded_worktree}%2Fsecret')",
                f"open('{encoded_home.replace('%', '%25')}%252F.ssh%252Fid_rsa')",
                f"open('{escaped_home}\\u002f.ssh\\u002fid_rsa')",
                f"open('{escaped_worktree.replace('u002f', 'x2f')}\\x2fsecret')",
            )
            for value in rejected:
                with self.subTest(value=value):
                    with self.assertRaises(ValueError):
                        validate_command_argv(("python3", "-c", value), worktree, home)
            self.assertEqual(
                validate_command_argv(
                    ("/usr/bin/true", "--system=/usr/bin/true"), worktree, home
                ),
                ("/usr/bin/true", "--system=/usr/bin/true"),
            )

    def test_backend_argv_rejects_embedded_unapproved_host_paths(self):
        from scripts.validation_isolation.backend import BackendSpec, build_backend_argv

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            worktree = root / "worktree"
            snapshot = root / "snapshot"
            temp = root / "temp"
            worktree.mkdir()
            snapshot.mkdir(mode=0o700)
            temp.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                build_backend_argv(
                    BackendSpec("macos", _system_launcher(), _system_python()),
                    ("python3", "-c", f"open('{worktree}/secret')"),
                    snapshot,
                    temp,
                    _environment(temp),
                )

    def test_process_probe_requires_marker_and_network_denial(self):
        from scripts.validation_isolation.backend import (
            BackendSpec,
            probe_backend,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            snapshot = root / "snapshot"
            temp = root / "temp"
            snapshot.mkdir(mode=0o700)
            temp.mkdir(mode=0o700)
            backend = BackendSpec("macos", _system_launcher(), _system_python())

            def failed_runner(*args, **kwargs):
                del args, kwargs
                return subprocess.CompletedProcess((), 1, "", "probe failed")

            with self.assertRaises(ValueError):
                probe_backend(
                    backend, snapshot, temp, _environment(temp), failed_runner
                )

    def test_probe_script_flushes_and_fsyncs_marker(self):
        from scripts.validation_isolation.backend import _probe_script

        script = _probe_script()
        self.assertIn("output.flush()", script)
        self.assertIn("os.fsync(output.fileno())", script)

    def test_probe_rejects_non_string_output_without_payload(self):
        from scripts.validation_isolation.backend import BackendSpec, probe_backend

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            temp = root / "temp"
            snapshot.mkdir(mode=0o700)
            temp.mkdir(mode=0o700)
            completed = subprocess.CompletedProcess((), 0, b"SECRET", "")

            class Listener:
                def bind(self, address):
                    del address

                def listen(self, backlog):
                    del backlog

                def getsockname(self):
                    return ("127.0.0.1", 12345)

                def close(self):
                    pass

            with patch(
                "scripts.validation_isolation.backend.socket.socket",
                return_value=Listener(),
            ):
                with self.assertRaisesRegex(ValueError, "probe output") as raised:
                    probe_backend(
                        BackendSpec("macos", _system_launcher(), _system_python()),
                        snapshot,
                        temp,
                        _environment(temp),
                        lambda *args: completed,
                    )
            self.assertNotIn("SECRET", str(raised.exception))

    def test_probe_rejects_oversized_output_without_payload(self):
        from scripts.validation_isolation.backend import BackendSpec, probe_backend

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            temp = root / "temp"
            snapshot.mkdir(mode=0o700)
            temp.mkdir(mode=0o700)
            completed = subprocess.CompletedProcess((), 0, "S" * 9000, "")
            with patch(
                "scripts.validation_isolation.backend.socket.socket",
                return_value=type(
                    "Listener",
                    (),
                    {
                        "bind": lambda self, address: None,
                        "listen": lambda self, backlog: None,
                        "getsockname": lambda self: ("127.0.0.1", 12345),
                        "close": lambda self: None,
                    },
                )(),
            ):
                with self.assertRaisesRegex(ValueError, "probe output"):
                    probe_backend(
                        BackendSpec("macos", _system_launcher(), _system_python()),
                        snapshot,
                        temp,
                        _environment(temp),
                        lambda *args: completed,
                    )

    def test_probe_marker_is_no_follow_private_regular_and_exact(self):
        from scripts.validation_isolation import backend
        from scripts.validation_isolation.backend import _read_probe_marker

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            marker = root / "marker"
            marker.write_text("ok", encoding="ascii")
            marker.chmod(0o600)
            self.assertIsNone(_read_probe_marker(marker))
            marker.unlink()
            target = root / "target"
            target.write_text("ok", encoding="ascii")
            target.chmod(0o600)
            marker.symlink_to(target)
            with self.assertRaises(ValueError):
                _read_probe_marker(marker)
            marker.unlink()
            marker.write_text("ok", encoding="ascii")
            marker.chmod(0o600)
            replacement = root / "replacement"
            replacement.write_text("ok", encoding="ascii")
            replacement.chmod(0o600)
            original_lstat = backend.os.lstat
            calls = 0

            def report_replacement(path):
                nonlocal calls
                item = original_lstat(path)
                if Path(path) == marker:
                    calls += 1
                    if calls == 2:
                        return original_lstat(replacement)
                return item

            with patch.object(backend.os, "lstat", side_effect=report_replacement):
                with self.assertRaisesRegex(ValueError, "changed"):
                    _read_probe_marker(marker)


class BackendPathValidationTests(unittest.TestCase):
    def test_rejects_symlink_parent(self):
        from scripts.validation_isolation.backend import _regular_executable

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            executable = _executable(real / "python")
            with self.assertRaises(ValueError):
                _regular_executable(
                    link / executable.name, "interpreter", root_owned=False
                )

    def test_rejects_unsafe_parent_mode(self):
        from scripts.validation_isolation.backend import _regular_executable

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "unsafe"
            parent.mkdir(mode=0o700)
            os.chmod(parent, 0o777)  # noqa: S103
            with self.assertRaises(ValueError):
                _regular_executable(
                    _executable(parent / "python"), "interpreter", root_owned=False
                )

    def test_rejects_unexpected_owner(self):
        from scripts.validation_isolation import backend

        with tempfile.TemporaryDirectory() as temporary:
            executable = _executable(Path(temporary) / "python")
            original_lstat = backend.os.lstat

            def fake_lstat(path):
                item = original_lstat(path)
                if Path(path) == executable:
                    values = list(item)
                    values[4] = 99999
                    return os.stat_result(values)
                return item

            with patch.object(backend.os, "lstat", side_effect=fake_lstat):
                with self.assertRaises(ValueError):
                    backend._regular_executable(
                        executable, "interpreter", root_owned=False
                    )

    def test_backend_identity_change_is_rejected_before_launch(self):
        from scripts.validation_isolation.backend import BackendSpec, verify_backend

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            interpreter = _executable(root / "python")
            launcher = _system_launcher()
            interpreter_item = os.lstat(interpreter)
            launcher_item = os.lstat(launcher)
            backend = BackendSpec(
                "macos",
                launcher,
                interpreter,
                (launcher_item.st_dev, launcher_item.st_ino),
                (interpreter_item.st_dev, interpreter_item.st_ino),
            )
            replacement = _executable(root / "replacement")
            interpreter.unlink()
            replacement.rename(interpreter)
            with self.assertRaisesRegex(ValueError, "changed"):
                verify_backend(backend)

    def test_symlinked_interpreter_spelling_is_rejected(self):
        from scripts.validation_isolation.backend import select_backend

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = _executable(root / "python")
            link = root / "python-link"
            link.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "canonical|symlink"):
                select_backend("darwin", MACOS_SANDBOX, None, link)

    def test_probe_final_launch_check_rejects_replacement(self):
        from scripts.validation_isolation import backend

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            interpreter = _executable(root / "python")
            launcher = _system_launcher()
            interpreter_item = os.lstat(interpreter)
            launcher_item = os.lstat(launcher)
            spec = backend.BackendSpec(
                "macos",
                launcher,
                interpreter,
                (launcher_item.st_dev, launcher_item.st_ino),
                (interpreter_item.st_dev, interpreter_item.st_ino),
            )
            snapshot = root / "snapshot"
            temp = root / "temp"
            snapshot.mkdir(mode=0o700)
            temp.mkdir(mode=0o700)
            replacement = _executable(root / "replacement")
            calls = []

            class Listener:
                def bind(self, address):
                    del address

                def listen(self, backlog):
                    del backlog

                def getsockname(self):
                    return ("127.0.0.1", 12345)

                def close(self):
                    pass

            real_build = backend.build_backend_argv

            def build_then_replace(*args, **kwargs):
                result = real_build(*args, **kwargs)
                interpreter.unlink()
                replacement.rename(interpreter)
                return result

            with (
                patch.object(backend.socket, "socket", return_value=Listener()),
                patch.object(backend, "_validate_trusted_interpreter"),
                patch.object(
                    backend, "build_backend_argv", side_effect=build_then_replace
                ),
            ):
                with self.assertRaisesRegex(ValueError, "changed"):
                    backend.probe_backend(
                        spec,
                        snapshot,
                        temp,
                        _environment(temp),
                        lambda *args: subprocess.CompletedProcess(args[0], 0, "", ""),
                    )
            self.assertEqual(calls, [])

    def test_probe_final_launch_rejects_private_root_replacement(self):
        from scripts.validation_isolation import backend

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            interpreter = _executable(root / "python")
            launcher = _system_launcher()
            launcher_item = os.lstat(launcher)
            interpreter_item = os.lstat(interpreter)
            spec = backend.BackendSpec(
                "macos",
                launcher,
                interpreter,
                (launcher_item.st_dev, launcher_item.st_ino),
                (interpreter_item.st_dev, interpreter_item.st_ino),
            )
            for target_name in ("snapshot", "temp"):
                with self.subTest(target=target_name):
                    snapshot = root / f"{target_name}-snapshot"
                    temp = root / f"{target_name}-temp"
                    snapshot.mkdir(mode=0o700)
                    temp.mkdir(mode=0o700)
                    calls = []

                    class Listener:
                        def bind(self, address):
                            del address

                        def listen(self, backlog):
                            del backlog

                        def getsockname(self):
                            return ("127.0.0.1", 12345)

                        def close(self):
                            pass

                    real_build = backend.build_backend_argv

                    def build_then_replace(
                        *args,
                        _real_build=real_build,
                        _snapshot=snapshot,
                        _temp=temp,
                        _target_name=target_name,
                        **kwargs,
                    ):
                        result = _real_build(*args, **kwargs)
                        target = _snapshot if _target_name == "snapshot" else _temp
                        displaced = root / f"{_target_name}-displaced"
                        target.rename(displaced)
                        target.mkdir(mode=0o700)
                        return result

                    with (
                        patch.object(backend.socket, "socket", return_value=Listener()),
                        patch.object(backend, "_validate_trusted_interpreter"),
                        patch.object(
                            backend,
                            "build_backend_argv",
                            side_effect=build_then_replace,
                        ),
                    ):
                        with self.assertRaisesRegex(ValueError, "root changed"):

                            def sentinel(*args, _calls=calls):
                                _calls.append(args)

                            backend.probe_backend(
                                spec,
                                snapshot,
                                temp,
                                _environment(temp),
                                sentinel,
                            )
                    self.assertEqual(calls, [])


class BackendIntegrationTests(unittest.TestCase):
    def test_real_backend_or_explicit_fail_closed_without_fallback(self):
        from scripts.validation_isolation import runner

        platform_name = "darwin" if sys.platform == "darwin" else "linux"
        with tempfile.TemporaryDirectory() as temporary:
            repository = make_repository(Path(temporary))
            calls: list[tuple[str, ...]] = []
            requested_child_marker = Path(temporary) / "requested-child-marker"
            selected = []
            real_select = runner.select_backend

            def select_and_capture(*args, **kwargs):
                backend = real_select(*args, **kwargs)
                selected.append(backend)
                return backend

            def sentinel(argv, cwd, env, timeout):
                del cwd, env, timeout
                captured = tuple(argv)
                calls.append(captured)
                is_probe = any(
                    isinstance(item, str) and "marker,port,parent_ns" in item
                    for item in captured
                )
                if not is_probe:
                    requested_child_marker.write_text("child\n", encoding="utf-8")
                return subprocess.CompletedProcess(
                    captured, 17 if is_probe else 0, "", ""
                )

            try:
                runner.run_isolated(
                    ("python3", "-c", "print('bounded')"),
                    repository,
                    platform_name,
                    sentinel,
                )
            except ValueError:
                pass
            if not selected:
                self.assertEqual(calls, [])
            else:
                launcher = str(selected[0].launcher)
                for call in calls:
                    self.assertEqual(call[0], launcher)
                    self.assertNotIn(str(repository), call)
                probe_calls = [
                    call
                    for call in calls
                    if any("marker,port,parent_ns" in item for item in call)
                ]
                requested_calls = [
                    call
                    for call in calls
                    if not any("marker,port,parent_ns" in item for item in call)
                ]
                self.assertEqual(calls, probe_calls)
                self.assertEqual(requested_calls, [])
            self.assertFalse(requested_child_marker.exists())


if __name__ == "__main__":
    unittest.main()
