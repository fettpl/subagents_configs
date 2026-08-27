from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path
from unittest import mock

from subagents_configs.errors import PiPackageError
from subagents_configs.pi_package import (
    PACKAGE_POLICY_PATH,
    PiPackageEvidence,
    PiPackageReceipt,
    _bounded_spawn,
    _sanitize_output,
    build_pi_install_argv,
    build_pi_remove_argv,
    inspect_pi_package_state,
    install_pi_package,
    load_pi_package_policy,
    load_pi_package_receipt,
    remove_pi_package,
    store_pi_package_receipt,
    validate_pi_executable,
)


class PiPackageContractTests(unittest.TestCase):
    def test_package_evidence_public_shape_excludes_private_store_race_identity(self):
        self.assertEqual(
            tuple(field.name for field in fields(PiPackageEvidence)),
            (
                "settings_path",
                "settings_hash",
                "package_entries",
                "status",
                "exact_pinned_entry",
                "installed_lock_path",
                "installed_lock_root_hash",
                "package_manifest_path",
                "manifest_hash",
                "package_identity_valid",
            ),
        )

    @staticmethod
    def _receipt() -> PiPackageReceipt:
        return PiPackageReceipt(
            schema_version=1,
            operation="install",
            source="npm:pi-subagents@0.56.0",
            remove_source="npm:pi-subagents",
            settings_before_hash=None,
            settings_after_hash="a" * 64,
            package_manifest_hash="b" * 64,
            package_policy_hash="c" * 64,
            created_exact_entry=True,
        )

    @staticmethod
    def _write_probe_executable(path: Path) -> Path:
        path.write_text(
            "#!/bin/sh\n"
            'case "$1 $2" in\n'
            "  \"--offline --version\") printf '0.84.1\\n' ;;\n"
            "  \"--offline --help\") printf 'install remove offline\\n' ;;\n"
            "  *) exit 0 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        path.chmod(0o700)
        return path

    @staticmethod
    def _write_exact_package(home: Path) -> None:
        package = home / "npm/node_modules/pi-subagents"
        package.mkdir(parents=True)
        (home / "npm").chmod(0o700)
        (home / "npm/node_modules").chmod(0o700)
        package.chmod(0o700)
        fixture_root = Path(__file__).parent / "fixtures"
        shutil.copyfile(
            fixture_root / "pi-subagents-0.56.0-package.json",
            package / "package.json",
        )
        (package / "package.json").chmod(0o600)
        (home / "npm/package-lock.json").write_text(
            json.dumps(
                {
                    "name": "pi-subagents",
                    "version": "0.56.0",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"pi-subagents": "0.56.0"}},
                        "node_modules/pi-subagents": {
                            "version": "0.56.0",
                            "integrity": (
                                "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+"
                                "W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
                            ),
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        (home / "npm/package-lock.json").chmod(0o600)
        (home / "settings.json").write_text(
            json.dumps({"packages": ["npm:pi-subagents@0.56.0"]}),
            encoding="utf-8",
        )
        (home / "settings.json").chmod(0o600)

    def test_reviewed_policy_matches_exact_contract(self):
        policy = load_pi_package_policy(PACKAGE_POLICY_PATH)
        self.assertEqual(policy["source"], "npm:pi-subagents@0.56.0")
        self.assertEqual(policy["removeSource"], "npm:pi-subagents")
        self.assertEqual(policy["name"], "pi-subagents")
        self.assertEqual(policy["version"], "0.56.0")
        self.assertEqual(policy["testedPiVersion"], "0.84.1")
        self.assertEqual(
            policy["upstreamCommit"],
            "a0e2b9e31de5970215a567e20e2d781bbbddf235",
        )
        self.assertEqual(
            policy["distIntegrity"],
            "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ==",
        )
        self.assertEqual(
            policy["dependencies"],
            {
                "acorn": "8.18.0",
                "jiti": "2.7.0",
                "typebox": "1.1.38",
                "yaml": "2.8.3",
            },
        )
        self.assertEqual(
            policy["bundledAgents"],
            ["delegate", "oracle", "researcher", "reviewer", "scout", "worker"],
        )

    def test_policy_rejects_mutation_of_every_authority_field(self):
        source = json.loads(PACKAGE_POLICY_PATH.read_text(encoding="utf-8"))
        mutations = {
            "source": "npm:other@1",
            "removeSource": "npm:other",
            "name": "other",
            "version": "0.56.1",
            "testedPiVersion": "0.84.2",
            "upstreamCommit": "0" * 40,
            "distIntegrity": "sha512-other",
            "packageJsonSha256": "0" * 64,
            "packageLockSha256": "0" * 64,
            "type": "commonjs",
            "pi": {"extensions": [], "skills": [], "prompts": []},
            "dependencies": {"acorn": "*"},
            "peerDependencies": {},
            "bundledAgents": ["unreviewed"],
            "forbiddenLifecycleScripts": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            for field, value in mutations.items():
                with self.subTest(field=field):
                    mutated = dict(source)
                    mutated[field] = value
                    path.write_text(json.dumps(mutated), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_pi_package_policy(path)
            missing = dict(source)
            del missing["pi"]
            path.write_text(json.dumps(missing), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_pi_package_policy(path)
            extra = dict(source)
            extra["authority"] = "unsafe"
            path.write_text(json.dumps(extra), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_pi_package_policy(path)
            duplicate = json.dumps(source).replace(
                '"source": "npm:pi-subagents@0.56.0"',
                '"source": "npm:pi-subagents@0.56.0", "source": "npm:other@1"',
                1,
            )
            path.write_text(duplicate, encoding="utf-8")
            with self.assertRaises(ValueError):
                load_pi_package_policy(path)

    def test_command_builders_are_official_and_exact(self):
        executable = Path("/opt/pi")
        self.assertEqual(
            build_pi_install_argv(executable),
            ("/opt/pi", "install", "npm:pi-subagents@0.56.0"),
        )
        self.assertEqual(
            build_pi_remove_argv(executable),
            ("/opt/pi", "remove", "npm:pi-subagents"),
        )

    def test_receipt_round_trip_is_strict_and_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            receipt = PiPackageReceipt(
                schema_version=1,
                operation="install",
                source="npm:pi-subagents@0.56.0",
                remove_source="npm:pi-subagents",
                settings_before_hash=None,
                settings_after_hash="a" * 64,
                package_manifest_hash="b" * 64,
                package_policy_hash="c" * 64,
                created_exact_entry=True,
            )
            store_pi_package_receipt(home, receipt)
            path = home / ".subagents_configs/pi-package-receipt.json"
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)
            self.assertEqual(load_pi_package_receipt(home), receipt)
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["unexpected"] = "reject"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_pi_package_receipt(home)

    def test_receipt_parent_mode_blocks_load_and_remove_before_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            self._write_exact_package(home)
            receipt = self._receipt()
            store_pi_package_receipt(home, receipt)
            state = home / ".subagents_configs"
            state.chmod(0o755)
            with self.assertRaises(ValueError):
                load_pi_package_receipt(home)
            executable = self._write_probe_executable(root / "pi")
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)
            with (
                mock.patch(
                    "subagents_configs.pi_package._run_command",
                    side_effect=AssertionError("remove command must not run"),
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                remove_pi_package(runtime, home, receipt)
            self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
            self.assertTrue(
                (home / "npm/node_modules/pi-subagents/package.json").exists()
            )
            self.assertTrue((home / "npm/package-lock.json").exists())
            self.assertTrue(state.exists())

    def test_receipt_codec_rejects_malformed_duplicate_and_unsafe_variants(self):
        valid = {
            "schema_version": 1,
            "operation": "install",
            "source": "npm:pi-subagents@0.56.0",
            "remove_source": "npm:pi-subagents",
            "settings_before_hash": None,
            "settings_after_hash": "a" * 64,
            "package_manifest_hash": "b" * 64,
            "package_policy_hash": "c" * 64,
            "created_exact_entry": True,
        }
        mutations = {
            "missing": {key: value for key, value in valid.items() if key != "source"},
            "wrong-type": {**valid, "schema_version": "1"},
            "wrong-hash": {**valid, "package_policy_hash": "not-a-hash"},
            "wrong-operation": {**valid, "operation": "remove"},
            "not-owned": {**valid, "created_exact_entry": False},
        }
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            state = home / ".subagents_configs"
            state.mkdir(mode=0o700)
            path = state / "pi-package-receipt.json"
            for name, payload in mutations.items():
                with self.subTest(name=name):
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    path.chmod(0o600)
                    with self.assertRaises(ValueError):
                        load_pi_package_receipt(home)
            path.write_text("{", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                load_pi_package_receipt(home)
            duplicate = json.dumps(valid).replace(
                '"schema_version": 1',
                '"schema_version": 1, "schema_version": 1',
                1,
            )
            path.write_text(duplicate, encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                load_pi_package_receipt(home)
            path.write_text(json.dumps(valid), encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                load_pi_package_receipt(home)
            path.chmod(0o600)
            attacker = home / "receipt-copy"
            attacker.write_bytes(path.read_bytes())
            attacker.chmod(0o600)
            path.unlink()
            path.hardlink_to(attacker)
            with self.assertRaises(ValueError):
                load_pi_package_receipt(home)
            path.unlink()
            path.symlink_to(attacker)
            with self.assertRaises(ValueError):
                load_pi_package_receipt(home)

    def test_receipt_codec_rejects_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            state = home / ".subagents_configs"
            outside = home / "outside"
            state.mkdir(mode=0o700)
            outside.mkdir(mode=0o700)
            receipt = self._receipt()
            payload = {
                "schema_version": receipt.schema_version,
                "operation": receipt.operation,
                "source": receipt.source,
                "remove_source": receipt.remove_source,
                "settings_before_hash": receipt.settings_before_hash,
                "settings_after_hash": receipt.settings_after_hash,
                "package_manifest_hash": receipt.package_manifest_hash,
                "package_policy_hash": receipt.package_policy_hash,
                "created_exact_entry": receipt.created_exact_entry,
            }
            (outside / "pi-package-receipt.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
            (outside / "pi-package-receipt.json").chmod(0o600)
            state.rmdir()
            state.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                load_pi_package_receipt(home)

    def test_receipt_create_races_never_overwrite_competing_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            receipt_path = home / ".subagents_configs/pi-package-receipt.json"
            competing = b"competing receipt"

            def compete(_parent):
                receipt_path.parent.mkdir(mode=0o700, exist_ok=True)
                receipt_path.write_bytes(competing)
                receipt_path.chmod(0o600)

            with (
                mock.patch(
                    "subagents_configs.filesystem._before_create_mutation", compete
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                store_pi_package_receipt(home, self._receipt())
            self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
            self.assertEqual(receipt_path.read_bytes(), competing)

    def test_receipt_parent_swap_and_post_link_races_fail_closed(self):
        for race in ("parent", "post-link"):
            with self.subTest(race=race), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                state = home / ".subagents_configs"
                state.mkdir(mode=0o700)
                receipt_path = state / "pi-package-receipt.json"
                outside = home / "outside"
                outside.mkdir(mode=0o700)

                if race == "parent":

                    def swap(
                        _parent,
                        _target,
                        _temporary,
                        state=state,
                        home=home,
                        outside=outside,
                    ):
                        state.rename(home / "state-old")
                        state.symlink_to(outside, target_is_directory=True)

                    hook = swap
                    name = "_after_create_link"
                else:

                    def replace(
                        _parent,
                        _target,
                        _temporary,
                        receipt_path=receipt_path,
                    ):
                        receipt_path.unlink()
                        receipt_path.write_bytes(b"replacement")
                        receipt_path.chmod(0o600)

                    hook = replace
                    name = "_after_create_link"

                with (
                    mock.patch(f"subagents_configs.filesystem.{name}", hook),
                    self.assertRaises(PiPackageError) as raised,
                ):
                    store_pi_package_receipt(home, self._receipt())
                self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
                if race == "parent":
                    self.assertFalse((outside / receipt_path.name).exists())
                    self.assertTrue((home / "state-old" / receipt_path.name).exists())
                else:
                    self.assertEqual(receipt_path.read_bytes(), b"replacement")

    def test_receipt_pre_unlink_replacement_or_hardlink_is_preserved(self):
        from subagents_configs import filesystem

        for kind in ("replacement", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                receipt = self._receipt()
                store_pi_package_receipt(home, receipt)
                path = home / ".subagents_configs/pi-package-receipt.json"
                attacker = home / "attacker"
                attacker.write_bytes(b"attacker")
                attacker.chmod(0o600)
                original = path.read_bytes()

                def replace(_parent, kind=kind, path=path, attacker=attacker):
                    path.unlink()
                    if kind == "hardlink":
                        path.hardlink_to(attacker)
                    else:
                        path.write_bytes(b"replacement")
                        path.chmod(0o600)

                # Use the existing CAS hook: unlink must not follow a
                # replacement or remove a hard-linked attacker target.
                canonical_path = Path(
                    __import__(
                        "subagents_configs.pi_package", fromlist=["_filesystem_path"]
                    )._filesystem_path(path, "receipt")
                )
                identity, _ = filesystem.read_bytes_with_evidence(
                    canonical_path, "receipt"
                )
                with (
                    mock.patch(
                        "subagents_configs.filesystem._before_unlink_mutation",
                        replace,
                    ),
                    self.assertRaises(RuntimeError),
                ):
                    filesystem.safe_mutate(canonical_path, identity, None)
                self.assertTrue(path.exists())
                self.assertEqual(
                    path.read_bytes(),
                    b"attacker" if kind == "hardlink" else b"replacement",
                )
                self.assertNotEqual(path.read_bytes(), original)

    def test_executable_validation_requires_absolute_regular_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "pi"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o700)
            evidence = validate_pi_executable(
                executable, agent_dir=root / "agent", execute=False
            )
            self.assertEqual(evidence.executable, executable)
            hardlink = root / "hardlink-pi"
            hardlink.hardlink_to(executable)
            with self.assertRaises(ValueError):
                validate_pi_executable(
                    hardlink, agent_dir=root / "agent", execute=False
                )
            hardlink.unlink()
            with self.assertRaises(ValueError):
                validate_pi_executable(Path("pi"), agent_dir=root, execute=False)
            executable.chmod(0o600)
            with self.assertRaises(ValueError):
                validate_pi_executable(executable, agent_dir=root, execute=False)
            directory = root / "directory"
            directory.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                validate_pi_executable(directory, agent_dir=root, execute=False)

    def test_runtime_probe_rejects_wrong_version_and_incomplete_help_tokens(self):
        cases = {
            "wrong-version": ("0.84.2", "install remove offline"),
            "missing-install": ("0.84.1", "remove offline"),
            "missing-remove": ("0.84.1", "install offline"),
            "missing-offline": ("0.84.1", "install remove"),
            "substring-only": ("0.84.1", "installer removed offline-mode"),
            "command-flags": ("0.84.1", "--install --remove --offline"),
        }
        for name, (version, help_text) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home = root / "agent"
                home.mkdir(mode=0o700)
                executable = root / "pi"
                executable.write_text(
                    "#!/bin/sh\n"
                    'case "$1 $2" in\n'
                    f"  --offline\\ --version) printf '%s\\n' {version!r} ;;\n"
                    f"  --offline\\ --help) printf '%s\\n' {help_text!r} ;;\n"
                    "  *) exit 2 ;;\n"
                    "esac\n",
                    encoding="utf-8",
                )
                executable.chmod(0o700)
                with self.assertRaises(PiPackageError) as raised:
                    validate_pi_executable(executable, agent_dir=home, execute=True)
                self.assertEqual(raised.exception.code, "PI_RUNTIME_INCOMPATIBLE")

    def test_execute_probe_and_package_commands_require_existing_private_agent_dir(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "spawned"
            executable = root / "pi"
            executable.write_text(
                "#!/bin/sh\n"
                f": > {marker!s}\n"
                'if [ "$1 $2" = "--offline --version" ]; then printf \'0.84.1\\n\'; '
                'elif [ "$1 $2" = "--offline --help" ]; then '
                "printf 'install remove offline\\n'; fi\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            missing = root / "missing-agent"
            with self.assertRaises(PiPackageError) as raised:
                validate_pi_executable(executable, agent_dir=missing, execute=True)
            self.assertEqual(raised.exception.code, "PI_RUNTIME_INCOMPATIBLE")
            self.assertFalse(marker.exists())

            home = root / "agent"
            home.mkdir(mode=0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)
            marker.unlink()
            home.rmdir()
            with self.assertRaises(PiPackageError) as raised:
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            self.assertFalse(marker.exists())

    def test_package_state_is_rechecked_after_preflight_before_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            marker = root / "spawned"
            executable = root / "pi"
            executable.write_text(
                "#!/bin/sh\n"
                'if [ "$1 $2" = "--offline --version" ]; then printf \'0.84.1\\n\'; '
                'elif [ "$1 $2" = "--offline --help" ]; then '
                "printf 'install remove offline\\n'; "
                f'elif [ "$1" = "install" ]; then : > {marker!s}; fi\n',
                encoding="utf-8",
            )
            executable.chmod(0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)

            def mutate_settings(argv, _agent_dir):
                if argv[1:] == ("install", "npm:pi-subagents@0.56.0"):
                    settings = home / "settings.json"
                    settings.write_text('{"packages": []}', encoding="utf-8")
                    settings.chmod(0o600)

            with (
                mock.patch(
                    "subagents_configs.pi_package._before_bounded_spawn",
                    side_effect=mutate_settings,
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            self.assertFalse(marker.exists())

    def test_npm_store_creation_after_preflight_blocks_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            marker = root / "spawned"
            executable = root / "pi"
            executable.write_text(
                "#!/bin/sh\n"
                'case "$1 $2" in\n'
                "  \"--offline --version\") printf '0.84.1\\n' ;;\n"
                "  \"--offline --help\") printf 'install remove offline\\n' ;;\n"
                f'  "install npm:pi-subagents@0.56.0") : > {marker!s} ;;\n'
                "  *) exit 0 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)

            def mutate_store(argv, _agent_dir):
                if argv[1:] == ("install", "npm:pi-subagents@0.56.0"):
                    (home / "npm").mkdir(mode=0o700)

            with (
                mock.patch(
                    "subagents_configs.pi_package._before_bounded_spawn",
                    side_effect=mutate_store,
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            self.assertFalse(marker.exists())

    def test_final_package_evidence_proof_blocks_settings_or_store_mutation(self):
        """Package evidence is compared last, after executable/home proofs."""

        for mutation_name in ("settings", "npm"):
            with (
                self.subTest(mutation=mutation_name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                home = root / "agent"
                home.mkdir(mode=0o700)
                marker = root / "spawned"
                executable = root / "pi"
                executable.write_text(
                    "#!/bin/sh\n"
                    'case "$1 $2" in\n'
                    "  \"--offline --version\") printf '0.84.1\\n' ;;\n"
                    "  \"--offline --help\") printf 'install remove offline\\n' ;;\n"
                    f'  "install npm:pi-subagents@0.56.0") : > {marker!s} ;;\n'
                    "  *) exit 0 ;;\n"
                    "esac\n",
                    encoding="utf-8",
                )
                executable.chmod(0o700)
                runtime = validate_pi_executable(
                    executable, agent_dir=home, execute=True
                )

                def mutate_after_identity_proofs(
                    _argv, _agent_dir, *, mutation_name=mutation_name, home=home
                ):
                    if mutation_name == "settings":
                        settings = home / "settings.json"
                        settings.write_text('{"packages": []}', encoding="utf-8")
                        settings.chmod(0o600)
                    else:
                        (home / "npm").mkdir(mode=0o700)

                with (
                    mock.patch(
                        "subagents_configs.pi_package._before_package_evidence",
                        side_effect=mutate_after_identity_proofs,
                    ),
                    self.assertRaises(PiPackageError) as raised,
                ):
                    install_pi_package(runtime, home, True, True)
                self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
                self.assertFalse(marker.exists())

    def test_child_gets_private_absolute_npm_config_and_cleanup_removes_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            report = root / "report.json"
            executable = root / "pi"
            report_path = repr(str(report))
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, stat\n"
                "config = pathlib.Path(os.environ['NPM_CONFIG_USERCONFIG'])\n"
                "item = config.lstat()\n"
                "json.dump({'config': str(config), 'cwd': os.getcwd(), "
                "'regular': stat.S_ISREG(item.st_mode), "
                "'mode': stat.S_IMODE(item.st_mode), 'nlink': item.st_nlink}, "
                f"pathlib.Path({report_path}).open('w'))\n"
                "print('0.84.1')\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            code, _, _ = _bounded_spawn(
                (str(executable), "--offline", "--version"),
                agent_dir=home,
            )
            self.assertEqual(code, 0)
            observed = json.loads(report.read_text(encoding="utf-8"))
            config = Path(observed["config"])
            self.assertTrue(config.is_absolute())
            self.assertEqual(config.parent, Path(observed["cwd"]))
            self.assertTrue(observed["regular"])
            self.assertEqual(observed["mode"], 0o600)
            self.assertEqual(observed["nlink"], 1)
            self.assertFalse(config.exists())

    def test_runtime_probe_rejects_executable_replacement_during_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            executable = root / "pi"
            replacement = root / "replacement"
            replacement.write_text("#!/bin/sh\nprintf '0.84.1\\n'\n", encoding="utf-8")
            replacement.chmod(0o700)
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, shutil, sys\n"
                f"replacement=pathlib.Path({str(replacement)!r})\n"
                "if sys.argv[1:] == ['--offline', '--version']:\n"
                f" shutil.copyfile(replacement, {str(executable)!r})\n"
                " print('0.84.1')\n"
                "elif sys.argv[1:] == ['--offline', '--help']:\n"
                " print('install remove offline')\n"
                "else: raise SystemExit(2)\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            with self.assertRaises(PiPackageError) as raised:
                validate_pi_executable(executable, agent_dir=home, execute=True)
            self.assertEqual(raised.exception.code, "PI_RUNTIME_INCOMPATIBLE")

    def test_bounded_spawn_rechecks_executable_identity_before_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real-pi"
            real.write_text("#!/bin/sh\nprintf '0.84.1\\n'\n", encoding="utf-8")
            real.chmod(0o700)
            alias = root / "pi"
            alias.symlink_to(real)
            with self.assertRaises(ValueError):
                _bounded_spawn(
                    (str(alias), "--offline", "--version"),
                    agent_dir=root,
                )

    def test_spawn_refuses_executable_replacement_after_trusted_runtime_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            marker = root / "executed-by-replacement"
            executable = root / "pi"
            executable.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "--offline" ] && [ "$2" = "--version" ]; then '
                "printf '0.84.1\\n'\n"
                'elif [ "$1" = "--offline" ] && [ "$2" = "--help" ]; then '
                "printf 'install remove offline\\n'\n"
                f'elif [ "$1" = "install" ] && '
                f'[ "$2" = "npm:pi-subagents@0.56.0" ]; then : > {marker!s}\n'
                "else exit 2; fi\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            replacement = root / "replacement"
            replacement.write_text(f"#!/bin/sh\n: > {marker!s}\n", encoding="utf-8")
            replacement.chmod(0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)

            def replace(argv, _agent_dir):
                if argv[1:] == ("install", "npm:pi-subagents@0.56.0"):
                    executable.write_bytes(replacement.read_bytes())
                    executable.chmod(0o700)

            with (
                mock.patch(
                    "subagents_configs.pi_package._before_bounded_spawn",
                    replace,
                    create=True,
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            self.assertFalse(marker.exists())

    def test_spawn_refuses_agent_directory_swap_before_child_can_write_outside(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            marker = outside / "escaped"
            executable = root / "pi"
            executable.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "--offline" ] && [ "$2" = "--version" ]; then '
                "printf '0.84.1\\n'\n"
                'elif [ "$1" = "--offline" ] && [ "$2" = "--help" ]; then '
                "printf 'install remove offline\\n'\n"
                f'elif [ "$1" = "install" ] && '
                f'[ "$2" = "npm:pi-subagents@0.56.0" ]; then : > {marker!s}\n'
                "else exit 2; fi\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)

            def swap(argv, _agent_dir):
                if argv[1:] == ("install", "npm:pi-subagents@0.56.0"):
                    home.rename(root / "agent-old")
                    home.symlink_to(outside, target_is_directory=True)

            with (
                mock.patch(
                    "subagents_configs.pi_package._before_bounded_spawn",
                    swap,
                    create=True,
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            self.assertFalse(marker.exists())

    def test_final_identity_proof_follows_cwd_preparation_before_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            marker = outside / "escaped"
            executable = root / "pi"
            executable.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "--offline" ] && [ "$2" = "--version" ]; then '
                "printf '0.84.1\\n'\n"
                'elif [ "$1" = "--offline" ] && [ "$2" = "--help" ]; then '
                "printf 'install remove offline\\n'\n"
                "else exit 0; fi\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            replacement = root / "replacement"
            replacement.write_text(f"#!/bin/sh\n: > {marker!s}\n", encoding="utf-8")
            replacement.chmod(0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)
            from subagents_configs import pi_package

            real_mkdtemp = pi_package.tempfile.mkdtemp

            def prepare(*args, **kwargs):
                working = real_mkdtemp(*args, **kwargs)
                executable.write_bytes(replacement.read_bytes())
                executable.chmod(0o700)
                home.rename(root / "agent-old")
                home.symlink_to(outside, target_is_directory=True)
                return working

            with (
                mock.patch(
                    "subagents_configs.pi_package.tempfile.mkdtemp",
                    side_effect=prepare,
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            self.assertFalse(marker.exists())

    def test_child_output_is_bounded_and_redacted_before_return(self):
        raw = (
            "https://secret.invalid/path API_TOKEN=secret /private/user/file "
            "\x1b[31mred\x1b[0m \x00" + "x" * 10000
        )
        sanitized = _sanitize_output(raw)
        self.assertLessEqual(len(sanitized.encode("utf-8")), 4096)
        for forbidden in (
            "secret.invalid",
            "API_TOKEN=secret",
            "/private/user/file",
            "\x1b",
        ):
            self.assertNotIn(forbidden, sanitized)
        self.assertNotIn("\x00", sanitized)

    def test_bounded_spawn_redacts_both_streams_and_caps_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "pi"
            payload = (
                "https://secret.invalid/path API_TOKEN=secret /private/user/file "
                "\x1b[31mred\x1b[0m \x00"
            )
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                f"sys.stdout.write({(payload + 'x' * 10000)!r})\n"
                f"sys.stderr.write({(payload + 'y' * 10000)!r})\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            code, stdout, stderr = _bounded_spawn(
                (str(executable), "--offline", "--version"), agent_dir=root
            )
            self.assertEqual(code, 0)
            for stream in (stdout, stderr):
                self.assertLessEqual(len(stream.encode("utf-8")), 4096)
                for forbidden in (
                    "secret.invalid",
                    "API_TOKEN=secret",
                    "/private/user/file",
                    "\x1b",
                    "\x00",
                ):
                    self.assertNotIn(forbidden, stream)

    def test_bounded_spawn_short_timeout_kills_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "pi"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import os\n"
                "child = os.fork()\n"
                "if child:\n"
                "    os._exit(0)\n"
                "while True:\n"
                "    pass\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            with (
                mock.patch("subagents_configs.pi_package._COMMAND_TIMEOUT", 0.01),
                self.assertRaises(PiPackageError) as raised,
            ):
                _bounded_spawn(
                    (str(executable), "--offline", "--version"), agent_dir=root
                )
            self.assertEqual(raised.exception.code, "PI_PACKAGE_COMMAND")

    def test_bounded_spawn_cleans_child_files_from_private_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "pi"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "Path.cwd().joinpath('leftover').write_text('child')\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            created: list[Path] = []
            from subagents_configs import pi_package

            real_mkdtemp = pi_package.tempfile.mkdtemp

            def record(*args, **kwargs):
                path = Path(real_mkdtemp(*args, **kwargs))
                created.append(path)
                return path

            with mock.patch(
                "subagents_configs.pi_package.tempfile.mkdtemp",
                side_effect=record,
            ):
                code, _, _ = _bounded_spawn(
                    (str(executable), "--offline", "--version"), agent_dir=root
                )
            self.assertEqual(code, 0)
            self.assertEqual(len(created), 1)
            self.assertFalse(created[0].exists())

    def test_bounded_spawn_reports_cleanup_failure_after_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "pi"
            executable.write_text(
                "#!/bin/sh\nprintf 'leftover' > child-file\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            with (
                mock.patch(
                    "subagents_configs.pi_package.os.unlink",
                    side_effect=OSError("cleanup denied"),
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                _bounded_spawn(
                    (str(executable), "--offline", "--version"), agent_dir=root
                )
            self.assertEqual(raised.exception.code, "PI_PACKAGE_COMMAND")

    def test_bounded_spawn_preserves_primary_timeout_when_cleanup_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "pi"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "Path('child-file').write_text('leftover')\n"
                "while True: pass\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            with (
                mock.patch("subagents_configs.pi_package._COMMAND_TIMEOUT", 0.01),
                mock.patch(
                    "subagents_configs.pi_package.os.unlink",
                    side_effect=OSError("cleanup denied"),
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                _bounded_spawn(
                    (str(executable), "--offline", "--version"), agent_dir=root
                )
            self.assertEqual(raised.exception.code, "PI_PACKAGE_COMMAND")

    def test_package_state_is_absent_then_rejects_conflicting_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            absent = inspect_pi_package_state(home)
            self.assertEqual(absent.status, "absent")
            (home / "settings.json").write_text(
                json.dumps({"packages": ["npm:pi-subagents@0.55.0"]}),
                encoding="utf-8",
            )
            (home / "settings.json").chmod(0o600)
            self.assertEqual(inspect_pi_package_state(home).status, "conflict")

    def test_unrelated_only_is_absent_and_exact_plus_wrong_is_conflict(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            settings = home / "settings.json"
            settings.write_text(
                json.dumps({"packages": ["npm:unrelated@1.0.0"]}), encoding="utf-8"
            )
            settings.chmod(0o600)
            self.assertEqual(inspect_pi_package_state(home).status, "absent")
            settings.write_text(
                json.dumps(
                    {
                        "packages": [
                            "npm:pi-subagents@0.56.0",
                            "npm:pi-subagents@^0.56.0",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(inspect_pi_package_state(home).status, "conflict")

    def test_package_entries_reject_duplicate_and_object_forms(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            settings = home / "settings.json"
            cases = (
                ["npm:other@1.0.0", "npm:other@1.0.0"],
                ["npm:pi-subagents@0.56.0", "npm:pi-subagents@0.56.0"],
                [{"name": "npm:pi-subagents@0.56.0"}],
            )
            for packages in cases:
                with self.subTest(packages=packages):
                    settings.write_text(
                        json.dumps({"packages": packages}), encoding="utf-8"
                    )
                    settings.chmod(0o600)
                    with self.assertRaises(ValueError):
                        inspect_pi_package_state(home)

    def test_package_classifier_rejects_every_non_exact_pi_identity(self):
        identities = (
            "npm:pi-subagents",
            "npm:pi-subagents@^0.56.0",
            "npm:alias@npm:pi-subagents@0.56.0",
            "pi-subagents@file:../local",
            "file:../pi-subagents",
            "git+https://example.invalid/pi-subagents.git",
            "github:nicobailon/pi-subagents",
        )
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            for identity in identities:
                (home / "settings.json").write_text(
                    json.dumps({"packages": [identity]}), encoding="utf-8"
                )
                (home / "settings.json").chmod(0o600)
                self.assertEqual(inspect_pi_package_state(home).status, "conflict")

    def test_exact_pi_pin_can_coexist_with_unrelated_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            package_dir = home / "npm/node_modules/pi-subagents"
            package_dir.mkdir(parents=True)
            (home / "npm").chmod(0o700)
            (home / "npm/node_modules").chmod(0o700)
            package_dir.chmod(0o700)
            shutil.copyfile(
                Path(__file__).parent / "fixtures/pi-subagents-0.56.0-package.json",
                package_dir / "package.json",
            )
            (package_dir / "package.json").chmod(0o600)
            (home / "npm/package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "pi-subagents",
                        "version": "0.56.0",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"dependencies": {"pi-subagents": "0.56.0"}},
                            "node_modules/pi-subagents": {
                                "version": "0.56.0",
                                "integrity": (
                                    "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
                                ),
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            (home / "npm/package-lock.json").chmod(0o600)
            (home / "settings.json").write_text(
                json.dumps(
                    {"packages": ["npm:other-package@1.0.0", "npm:pi-subagents@0.56.0"]}
                ),
                encoding="utf-8",
            )
            (home / "settings.json").chmod(0o600)
            self.assertEqual(inspect_pi_package_state(home).status, "exact")

    def test_orphan_pi_package_directory_is_a_conflict_without_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            orphan = home / "npm/node_modules/pi-subagents"
            orphan.mkdir(parents=True, mode=0o700)
            (home / "npm").chmod(0o700)
            (home / "npm/node_modules").chmod(0o700)
            # An empty managed package directory is evidence of an
            # interrupted/foreign install, never an absent package.
            self.assertEqual(inspect_pi_package_state(home).status, "conflict")

    def test_settings_overrides_that_widen_managed_roles_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            cases = {
                "agent-overrides": {"subagents": {"agentOverrides": {}}},
                "extension-authority": {"extensions": {"custom": True}},
                "permission-authority": {"permissions": {"allow": ["x"]}},
                "model-authority": {"model": "unreviewed"},
                "package-command": {"npmCommand": "/opt/attacker/npm"},
                "package-manager": {"packageManager": "pnpm"},
                "registry": {"registry": "https://evil.invalid"},
                "package-registry": {"packageRegistry": "https://evil.invalid"},
                "package-source": {"packageSource": "file:./local"},
                "source-override": {"sourceOverride": "git://evil.invalid"},
                "manager-override": {"managerOverride": "unsafe"},
            }
            for name, extra in cases.items():
                with self.subTest(name=name):
                    (home / "settings.json").write_text(
                        json.dumps({"packages": [], **extra}), encoding="utf-8"
                    )
                    (home / "settings.json").chmod(0o600)
                    with self.assertRaises(ValueError):
                        inspect_pi_package_state(home)

    def test_extension_config_accepts_only_known_scalar_settings(self):
        values = {
            "toolDescriptionMode": "compact",
            "asyncByDefault": True,
            "orcaProgressTabs": 2,
            "resultScanLogging": 0.5,
        }
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            config = home / "extensions/subagent/config.json"
            config.parent.mkdir(parents=True)
            (home / "extensions").chmod(0o700)
            config.parent.chmod(0o700)
            config.write_text(json.dumps(values), encoding="utf-8")
            config.chmod(0o600)
            self.assertEqual(inspect_pi_package_state(home).status, "absent")
            for key, value in {
                "unknownAuthority": True,
                "agentOverride": {},
                "toolDescriptionMode": [],
            }.items():
                with self.subTest(key=key):
                    updated = dict(values)
                    updated[key] = value
                    config.write_text(json.dumps(updated), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        inspect_pi_package_state(home)

    def test_extension_config_rejects_symlink_and_hardlink_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            config = home / "extensions/subagent/config.json"
            config.parent.mkdir(parents=True, mode=0o700)
            (home / "extensions").chmod(0o700)
            config.write_text('{"asyncByDefault": true}', encoding="utf-8")
            config.chmod(0o600)
            source = home / "config-copy"
            for kind in ("symlink", "hardlink"):
                with self.subTest(kind=kind):
                    if config.exists() or config.is_symlink():
                        config.unlink()
                    source.unlink(missing_ok=True)
                    source.write_text('{"asyncByDefault": true}', encoding="utf-8")
                    source.chmod(0o600)
                    if kind == "symlink":
                        config.symlink_to(source)
                    else:
                        config.hardlink_to(source)
                    with self.assertRaises(ValueError):
                        inspect_pi_package_state(home)

    def test_package_state_uses_installed_root_lock_not_provenance_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            npm = home / "npm/node_modules/pi-subagents"
            npm.mkdir(parents=True)
            (home / "npm").chmod(0o700)
            (home / "npm/node_modules").chmod(0o700)
            npm.chmod(0o700)
            shutil.copyfile(
                Path(__file__).parent / "fixtures/pi-subagents-0.56.0-package.json",
                npm / "package.json",
            )
            (npm / "package.json").chmod(0o600)
            (home / "npm/package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "pi-subagents",
                        "version": "0.56.0",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"dependencies": {"pi-subagents": "0.56.0"}},
                            "node_modules/pi-subagents": {
                                "version": "0.56.0",
                                "integrity": (
                                    "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
                                ),
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            (home / "npm/package-lock.json").chmod(0o600)
            (home / "settings.json").write_text(
                json.dumps({"packages": ["npm:pi-subagents@0.56.0"]}), encoding="utf-8"
            )
            (home / "settings.json").chmod(0o600)
            evidence = inspect_pi_package_state(home)
            self.assertEqual(evidence.status, "exact")
            self.assertNotEqual(
                evidence.installed_lock_root_hash,
                "76b359ad4a8ecf20892d169ba5cce7892a54d8217024b115bff9262c5a1d4f04",
            )

    def test_installed_state_drift_table_fails_closed(self):
        fixture = Path(__file__).parent / "fixtures/pi-subagents-0.56.0-package.json"
        integrity = (
            "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+"
            "W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
        )

        def setup(home: Path):
            package = home / "npm/node_modules/pi-subagents"
            package.mkdir(parents=True)
            (home / "npm").chmod(0o700)
            (home / "npm/node_modules").chmod(0o700)
            package.chmod(0o700)
            shutil.copyfile(fixture, package / "package.json")
            (package / "package.json").chmod(0o600)
            lock = {
                "name": "pi-subagents",
                "version": "0.56.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"pi-subagents": "0.56.0"}},
                    "node_modules/pi-subagents": {
                        "version": "0.56.0",
                        "integrity": integrity,
                    },
                },
            }
            (home / "npm/package-lock.json").write_text(
                json.dumps(lock), encoding="utf-8"
            )
            (home / "npm/package-lock.json").chmod(0o600)
            (home / "settings.json").write_text(
                json.dumps({"packages": ["npm:pi-subagents@0.56.0"]}),
                encoding="utf-8",
            )
            (home / "settings.json").chmod(0o600)

        def mutate_settings(home):
            (home / "settings.json").write_text(
                json.dumps(
                    {
                        "packages": ["npm:pi-subagents@0.56.0"],
                        "telemetry": False,
                    }
                ),
                encoding="utf-8",
            )

        def mutate_settings_mode(home):
            (home / "settings.json").chmod(0o644)

        def mutate_manifest_mode(home):
            (home / "npm/node_modules/pi-subagents/package.json").chmod(0o644)

        def mutate_lock_mode(home):
            (home / "npm/package-lock.json").chmod(0o644)

        def mutate_lock_root(home):
            path = home / "npm/package-lock.json"
            raw = json.loads(path.read_text())
            raw["packages"][""]["dependencies"]["pi-subagents"] = "0.55.0"
            path.write_text(json.dumps(raw), encoding="utf-8")

        def mutate_lock_version(home):
            path = home / "npm/package-lock.json"
            raw = json.loads(path.read_text())
            raw["packages"]["node_modules/pi-subagents"]["version"] = "0.55.0"
            path.write_text(json.dumps(raw), encoding="utf-8")

        def mutate_lock_integrity(home):
            path = home / "npm/package-lock.json"
            raw = json.loads(path.read_text())
            raw["packages"]["node_modules/pi-subagents"]["integrity"] = "bad"
            path.write_text(json.dumps(raw), encoding="utf-8")

        def mutate_lock_object_root(home):
            path = home / "npm/package-lock.json"
            raw = json.loads(path.read_text())
            raw["packages"][""]["dependencies"]["pi-subagents"] = {}
            path.write_text(json.dumps(raw), encoding="utf-8")

        def remove_lock(home):
            (home / "npm/package-lock.json").unlink()

        def symlink_lock(home):
            path = home / "npm/package-lock.json"
            source = home / "lock-copy"
            source.write_bytes(path.read_bytes())
            source.chmod(0o600)
            path.unlink()
            path.symlink_to(source)

        def nested_lock(home):
            nested = home / "npm/node_modules/other"
            nested.mkdir(mode=0o700)
            lock = nested / "package-lock.json"
            lock.write_text("{}", encoding="utf-8")
            lock.chmod(0o600)

        def mutate_manifest_dependency(home):
            path = home / "npm/node_modules/pi-subagents/package.json"
            raw = json.loads(path.read_text())
            raw["dependencies"]["acorn"] = "*"
            path.write_text(json.dumps(raw), encoding="utf-8")

        def mutate_manifest_lifecycle(home):
            path = home / "npm/node_modules/pi-subagents/package.json"
            raw = json.loads(path.read_text())
            raw["scripts"]["install"] = "unsafe"
            path.write_text(json.dumps(raw), encoding="utf-8")

        def mutate_manifest_field(field, value):
            def mutation(home, field=field, value=value):
                path = home / "npm/node_modules/pi-subagents/package.json"
                raw = json.loads(path.read_text())
                raw[field] = value
                path.write_text(json.dumps(raw), encoding="utf-8")

            return mutation

        def remove_manifest(home):
            (home / "npm/node_modules/pi-subagents/package.json").unlink()

        def symlink_manifest(home):
            path = home / "npm/node_modules/pi-subagents/package.json"
            source = home / "manifest-copy"
            source.write_bytes(path.read_bytes())
            source.chmod(0o600)
            path.unlink()
            path.symlink_to(source)

        def hardlink_manifest(home):
            path = home / "npm/node_modules/pi-subagents/package.json"
            source = home / "manifest-copy"
            source.write_bytes(path.read_bytes())
            source.chmod(0o600)
            path.unlink()
            path.hardlink_to(source)

        def hardlink_lock(home):
            path = home / "npm/package-lock.json"
            source = home / "lock-copy"
            source.write_bytes(path.read_bytes())
            source.chmod(0o600)
            path.unlink()
            path.hardlink_to(source)

        def symlink_settings(home):
            path = home / "settings.json"
            source = home / "settings-copy"
            source.write_bytes(path.read_bytes())
            source.chmod(0o600)
            path.unlink()
            path.symlink_to(source)

        def hardlink_settings(home):
            path = home / "settings.json"
            source = home / "settings-copy"
            source.write_bytes(path.read_bytes())
            source.chmod(0o600)
            path.unlink()
            path.hardlink_to(source)

        def malformed_settings(home):
            (home / "settings.json").write_text("{", encoding="utf-8")

        def object_settings(home):
            (home / "settings.json").write_text(
                json.dumps({"packages": {"npm:pi-subagents@0.56.0": True}}),
                encoding="utf-8",
            )

        def package_store_mode(home):
            (home / "npm").chmod(0o755)

        def package_store_symlink(home):
            path = home / "npm"
            old = home / "npm-old"
            path.rename(old)
            path.symlink_to(old, target_is_directory=True)

        def ancestor_mode(home):
            (home / "npm/node_modules").chmod(0o755)

        def ancestor_symlink(home):
            path = home / "npm/node_modules"
            old = home / "node_modules-old"
            path.rename(old)
            path.symlink_to(old, target_is_directory=True)

        manifest_mutations = {
            "manifest-name": ("name", "other"),
            "manifest-version": ("version", "0.55.0"),
            "manifest-type": ("type", "commonjs"),
            "manifest-pi": ("pi", {}),
            "manifest-dependencies": ("dependencies", {}),
            "manifest-peers": ("peerDependencies", {}),
            "manifest-scripts": ("scripts", {"test": "changed"}),
        }

        mutations = {
            "settings-hash": mutate_settings,
            "settings-mode": mutate_settings_mode,
            "lock-root": mutate_lock_root,
            "lock-version": mutate_lock_version,
            "lock-integrity": mutate_lock_integrity,
            "lock-object-root": mutate_lock_object_root,
            "lock-mode": mutate_lock_mode,
            "lock-missing": remove_lock,
            "lock-symlink": symlink_lock,
            "nested-unrelated-lock": nested_lock,
            "manifest-dependency": mutate_manifest_dependency,
            "manifest-lifecycle": mutate_manifest_lifecycle,
            "manifest-mode": mutate_manifest_mode,
            "missing-manifest": remove_manifest,
            "symlink-manifest": symlink_manifest,
            "hardlink-manifest": hardlink_manifest,
            "settings-symlink": symlink_settings,
            "settings-hardlink": hardlink_settings,
            "settings-malformed": malformed_settings,
            "settings-object": object_settings,
            "hardlink-lock": hardlink_lock,
            "package-store-mode": package_store_mode,
            "package-store-symlink": package_store_symlink,
            "ancestor-mode": ancestor_mode,
            "ancestor-symlink": ancestor_symlink,
        }
        mutations.update(
            {
                name: mutate_manifest_field(field, value)
                for name, (field, value) in manifest_mutations.items()
            }
        )
        for name, mutation in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                setup(home)
                mutation(home)
                if name == "settings-hash":
                    self.assertEqual(inspect_pi_package_state(home).status, "exact")
                    self.assertNotEqual(
                        inspect_pi_package_state(home).settings_hash,
                        None,
                    )
                elif name in {
                    "settings-mode",
                    "lock-mode",
                    "lock-symlink",
                    "nested-unrelated-lock",
                    "manifest-mode",
                    "symlink-manifest",
                    "hardlink-manifest",
                    "settings-symlink",
                    "settings-hardlink",
                    "settings-malformed",
                    "settings-object",
                    "hardlink-lock",
                    "package-store-mode",
                    "package-store-symlink",
                    "ancestor-mode",
                    "ancestor-symlink",
                }:
                    with self.assertRaises(ValueError):
                        inspect_pi_package_state(home)
                else:
                    self.assertEqual(inspect_pi_package_state(home).status, "conflict")

    def test_nested_lock_scan_does_not_follow_directory_symlink_race(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self._write_exact_package(home)
            child = home / "npm/node_modules/other"
            child.mkdir(mode=0o700)
            outside = home / "outside"
            outside.mkdir(mode=0o700)
            lock = outside / "package-lock.json"
            lock.write_text("{}", encoding="utf-8")
            lock.chmod(0o600)
            old_child = home / "other-old"
            real_stat = os.stat
            swapped = False

            def race(path, *args, **kwargs):
                nonlocal swapped
                result = real_stat(path, *args, **kwargs)
                if (
                    path == "other"
                    and kwargs.get("follow_symlinks") is False
                    and not swapped
                ):
                    swapped = True
                    child.rename(old_child)
                    child.symlink_to(outside, target_is_directory=True)
                return result

            with (
                mock.patch("subagents_configs.pi_package.os.stat", side_effect=race),
                self.assertRaises(ValueError),
            ):
                inspect_pi_package_state(home)
            self.assertTrue(swapped)

    def test_fake_official_commands_receive_sanitized_environment_and_exact_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            log = root / "log.jsonl"
            fixture = (
                Path(__file__).parent / "fixtures/pi-subagents-0.56.0-package.json"
            )
            executable = root / "pi"
            script = (
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                f"log = pathlib.Path({str(log)!r})\n"
                "if sys.argv[1:] == ['--offline', '--version']:\n print('0.84.1')\n"
                "elif sys.argv[1:] == ['--offline', '--help']:\n print('install remove offline')\n"  # noqa: E501
                "elif sys.argv[1:] == ['install', 'npm:pi-subagents@0.56.0']:\n"
                " p=pathlib.Path(os.environ['PI_CODING_AGENT_DIR']); (p/'npm/node_modules/pi-subagents').mkdir(parents=True); (p/'npm').chmod(0o700); (p/'npm/node_modules').chmod(0o700); (p/'npm/node_modules/pi-subagents').chmod(0o700);\n"  # noqa: E501
                " (p/'settings.json').write_text(json.dumps({'packages':['npm:pi-subagents@0.56.0']})); (p/'settings.json').chmod(0o600);\n"  # noqa: E501
                " (p/'npm/package-lock.json').write_text(json.dumps({'name':'pi-subagents','version':'0.56.0','lockfileVersion':3,'packages':{'':{'dependencies':{'pi-subagents':'0.56.0'}},'node_modules/pi-subagents':{'version':'0.56.0','integrity':'sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=='}}}));\n"  # noqa: E501
                f" import shutil; shutil.copyfile({str(fixture)!r}, p/'npm/node_modules/pi-subagents/package.json'); (p/'npm/node_modules/pi-subagents/package.json').chmod(0o600)\n"  # noqa: E501
                "else: raise SystemExit(2)\n"
                "record = {\n"
                " 'argv': sys.argv[1:],\n"
                " 'env': dict(os.environ),\n"
                " 'cwd': os.getcwd(),\n"
                " 'cwd_mode': __import__('stat').S_IMODE(\n"
                "  pathlib.Path.cwd().stat().st_mode),\n"
                " 'cwd_empty': not any(pathlib.Path.cwd().iterdir()),\n"
                "}\n"
                "with log.open('a', encoding='utf-8') as fp:\n"
                " fp.write(json.dumps(record) + '\\n')\n"
            )
            executable.write_text(
                script,
                encoding="utf-8",
            )
            executable.chmod(0o700)
            with mock.patch.dict(
                os.environ,
                {
                    "PI_CODING_AGENT_DIR": "/attacker/home",
                    "HTTP_PROXY": "https://secret.invalid",
                    "HTTPS_PROXY": "https://secret.invalid",
                    "NPM_TOKEN": "secret-token",
                    "AUTH_TOKEN": "secret-auth",
                },
            ):
                runtime = validate_pi_executable(
                    executable, agent_dir=home, execute=True
                )
                receipt = install_pi_package(runtime, home, True, True)
            self.assertTrue(receipt.created_exact_entry)
            invocations = [
                json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                [invocation["argv"] for invocation in invocations],
                [
                    ["--offline", "--version"],
                    ["--offline", "--help"],
                    ["install", "npm:pi-subagents@0.56.0"],
                ],
            )
            expected_env = {
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                "PI_TELEMETRY": "0",
                "PI_SKIP_VERSION_CHECK": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "PI_CODING_AGENT_DIR": str(home),
            }
            platform_env = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
            for invocation in invocations:
                self.assertEqual(
                    {key: invocation["env"].get(key) for key in expected_env},
                    expected_env,
                )
                config = Path(invocation["env"]["NPM_CONFIG_USERCONFIG"])
                self.assertEqual(config, Path(invocation["cwd"]) / ".npmrc")
                self.assertTrue(config.is_absolute())
                self.assertTrue(
                    set(invocation["env"])
                    <= set(expected_env) | platform_env | {"NPM_CONFIG_USERCONFIG"}
                )
                self.assertEqual(invocation["cwd_mode"], 0o700)
                self.assertFalse(invocation["cwd_empty"])
                self.assertNotEqual(Path(invocation["cwd"]), root)

    def test_remove_preserves_receipt_and_uses_exact_argv(self):
        with tempfile.TemporaryDirectory(
            dir=str(Path(tempfile.gettempdir()).resolve())
        ) as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            log = root / "calls.jsonl"
            manifest = (
                Path(__file__).parent / "fixtures/pi-subagents-0.56.0-package.json"
            ).read_text(encoding="utf-8")
            executable = root / "pi"
            script = (
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                f"root=pathlib.Path({str(home)!r}); log=pathlib.Path({str(log)!r})\n"
                "record = {\n"
                " 'argv': sys.argv[1:],\n"
                " 'env': dict(os.environ),\n"
                " 'cwd': os.getcwd(),\n"
                " 'cwd_mode': __import__('stat').S_IMODE(\n"
                "  pathlib.Path.cwd().stat().st_mode),\n"
                " 'cwd_empty': not any(pathlib.Path.cwd().iterdir()),\n"
                "}\n"
                "with log.open('a', encoding='utf-8') as fp:\n"
                " fp.write(json.dumps(record) + '\\n')\n"
                "if sys.argv[1:] == ['--offline', '--version']:\n"
                " print('0.84.1')\n"
                "elif sys.argv[1:] == ['--offline', '--help']:\n"
                " print('install remove offline')\n"
                "elif sys.argv[1:] == ['install','npm:pi-subagents@0.56.0']:\n"
                "  p = root / 'npm/node_modules/pi-subagents'\n"
                "  p.mkdir(parents=True)\n"
                "  (root / 'npm').chmod(0o700)\n"
                "  (root / 'npm/node_modules').chmod(0o700)\n"
                "  p.chmod(0o700)\n"
                f"  (p / 'package.json').write_text({manifest!r}, encoding='utf-8')\n"
                "  (p / 'package.json').chmod(0o600)\n"
                "  settings = {'packages': ['npm:pi-subagents@0.56.0']}\n"
                "  (root / 'settings.json').write_text(json.dumps(settings))\n"
                "  (root / 'settings.json').chmod(0o600)\n"
                "  lock = {'name': 'pi-subagents', 'version': '0.56.0',\n"
                "   'lockfileVersion': 3, 'packages': {\n"
                "    '': {'dependencies': {'pi-subagents': '0.56.0'}},\n"
                "    'node_modules/pi-subagents': {'version': '0.56.0',\n"
                "     'integrity': 'sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+'\n"
                "      'jjwmfNR3El+IfhnaJwZ+W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=='"
                "}}}\n"
                "  (root / 'npm/package-lock.json').write_text(json.dumps(lock))\n"
                "  (root / 'npm/package-lock.json').chmod(0o600)\n"
                "elif sys.argv[1:] == ['remove','npm:pi-subagents']:\n"
                "  if (root/'fail-command').exists(): raise SystemExit(7)\n"
                "  if not (root/'leave-package').exists():\n"
                "    (root / 'settings.json').write_text(\n"
                "        json.dumps({'packages': []}))\n"
                "    (root / 'settings.json').chmod(0o600)\n"
                "    (root / 'npm/package-lock.json').unlink()\n"
                "    (root / 'npm/node_modules/pi-subagents/package.json').unlink()\n"
                "    (root / 'npm/node_modules/pi-subagents').rmdir()\n"
                "    (root / 'npm/node_modules').rmdir()\n"
                "    (root / 'npm').rmdir()\n"
                "else: raise SystemExit(2)\n"
            )
            executable.write_text(
                script,
                encoding="utf-8",
            )
            executable.chmod(0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)
            receipt = install_pi_package(runtime, home, True, True)
            installed_manifest = home / "npm/node_modules/pi-subagents/package.json"
            installed_lock = home / "npm/package-lock.json"
            receipt_path = home / ".subagents_configs/pi-package-receipt.json"

            def assert_preserved():
                self.assertTrue(installed_manifest.exists())
                self.assertTrue(installed_lock.exists())
                self.assertEqual(load_pi_package_receipt(home), receipt)

            def call_count():
                return len(log.read_text(encoding="utf-8").splitlines())

            def snapshot(paths):
                return {
                    path: (
                        path.read_bytes(),
                        stat.S_IMODE(path.lstat().st_mode),
                        path.lstat().st_nlink,
                        path.lstat().st_dev,
                        path.lstat().st_ino,
                    )
                    for path in paths
                }

            def assert_snapshot(expected):
                for path, identity in expected.items():
                    item = path.lstat()
                    self.assertEqual(
                        (
                            path.read_bytes(),
                            stat.S_IMODE(item.st_mode),
                            item.st_nlink,
                            item.st_dev,
                            item.st_ino,
                        ),
                        identity,
                    )

            def remove():
                with mock.patch.dict(
                    os.environ,
                    {
                        "PI_CODING_AGENT_DIR": "/attacker/home",
                        "HTTP_PROXY": "https://secret.invalid",
                        "HTTPS_PROXY": "https://secret.invalid",
                        "NPM_TOKEN": "secret-token",
                        "AUTH_TOKEN": "secret-auth",
                    },
                ):
                    return remove_pi_package(runtime, home, receipt)

            settings_path = home / "settings.json"
            settings_path.write_text(
                json.dumps(
                    {
                        "packages": ["npm:pi-subagents@0.56.0"],
                        "telemetry": False,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(PiPackageError) as raised:
                remove()
            self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
            assert_preserved()
            settings_path.write_text(
                json.dumps({"packages": ["npm:pi-subagents@0.56.0"]}),
                encoding="utf-8",
            )
            settings_path.chmod(0o600)
            installed_manifest.write_text(manifest + "\n", encoding="utf-8")
            with self.assertRaises(PiPackageError) as raised:
                remove()
            self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
            assert_preserved()
            installed_manifest.write_text(manifest, encoding="utf-8")
            installed_manifest.chmod(0o600)
            receipt_path.unlink()
            missing_snapshot = snapshot((installed_manifest, installed_lock))
            before_missing = call_count()
            with self.assertRaises(PiPackageError) as raised:
                remove()
            self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
            self.assertEqual(call_count(), before_missing)
            assert_snapshot(missing_snapshot)
            store_pi_package_receipt(home, receipt)
            receipt_path.write_text("{", encoding="utf-8")
            receipt_path.chmod(0o600)
            malformed_snapshot = snapshot(
                (installed_manifest, installed_lock, receipt_path)
            )
            before_malformed = call_count()
            with self.assertRaises(PiPackageError) as raised:
                remove()
            self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
            self.assertEqual(call_count(), before_malformed)
            assert_snapshot(malformed_snapshot)
            receipt_path.unlink()
            store_pi_package_receipt(home, receipt)
            stale = json.loads(receipt_path.read_text(encoding="utf-8"))
            stale["package_policy_hash"] = "d" * 64
            receipt_path.write_text(json.dumps(stale), encoding="utf-8")
            receipt_path.chmod(0o600)
            stale_snapshot = snapshot(
                (installed_manifest, installed_lock, receipt_path)
            )
            before_stale = call_count()
            with self.assertRaises(PiPackageError) as raised:
                remove()
            self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
            self.assertEqual(call_count(), before_stale)
            assert_snapshot(stale_snapshot)
            receipt_path.unlink()
            store_pi_package_receipt(home, receipt)
            (home / "fail-command").touch(mode=0o600)
            command_snapshot = snapshot(
                (installed_manifest, installed_lock, receipt_path)
            )
            with self.assertRaises(PiPackageError) as raised:
                remove()
            self.assertEqual(raised.exception.code, "PI_PACKAGE_COMMAND")
            assert_preserved()
            assert_snapshot(command_snapshot)
            (home / "fail-command").unlink()
            (home / "leave-package").touch(mode=0o600)
            poststate_snapshot = snapshot(
                (installed_manifest, installed_lock, receipt_path)
            )
            with self.assertRaises(PiPackageError) as raised:
                remove()
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            assert_preserved()
            assert_snapshot(poststate_snapshot)
            (home / "leave-package").unlink()
            original_lock = installed_lock.read_bytes()
            mutated_lock = json.loads(original_lock)
            mutated_lock["packages"][""]["dependencies"]["pi-subagents"] = "0.55.0"
            installed_lock.write_text(json.dumps(mutated_lock), encoding="utf-8")
            installed_lock.chmod(0o600)
            lock_drift_snapshot = snapshot(
                (installed_manifest, installed_lock, receipt_path)
            )
            before_lock_drift = call_count()
            with self.assertRaises(PiPackageError) as raised:
                remove()
            self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
            self.assertEqual(call_count(), before_lock_drift)
            assert_snapshot(lock_drift_snapshot)
            installed_lock.write_bytes(original_lock)
            installed_lock.chmod(0o600)
            removed = remove()
            self.assertEqual(removed.operation, "remove")
            self.assertIsNone(load_pi_package_receipt(home))
            from subagents_configs.models import Target
            from subagents_configs.state import load_state
            from subagents_configs.targets import descriptor_for

            self.assertEqual(load_state(home, descriptor_for(Target.PI)), (None, None))
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(
                [call["argv"] for call in calls[-3:]],
                [
                    ["remove", "npm:pi-subagents"],
                    ["remove", "npm:pi-subagents"],
                    ["remove", "npm:pi-subagents"],
                ],
            )
            expected_env = {
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                "PI_TELEMETRY": "0",
                "PI_SKIP_VERSION_CHECK": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "PI_CODING_AGENT_DIR": str(home),
            }
            platform_env = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
            for call in calls[-3:]:
                self.assertEqual(
                    {key: call["env"].get(key) for key in expected_env},
                    expected_env,
                )
                config = Path(call["env"]["NPM_CONFIG_USERCONFIG"])
                self.assertEqual(config, Path(call["cwd"]) / ".npmrc")
                self.assertTrue(config.is_absolute())
                self.assertTrue(
                    set(call["env"])
                    <= set(expected_env) | platform_env | {"NPM_CONFIG_USERCONFIG"}
                )
                self.assertEqual(call["cwd_mode"], 0o700)
                self.assertFalse(call["cwd_empty"])
                self.assertNotEqual(Path(call["cwd"]), root)

    def test_install_rejects_missing_consent_before_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "install-ran"
            executable = root / "pi"
            executable.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "--offline" ] && [ "$2" = "--version" ]; then '
                "printf '0.84.1\\n'\n"
                'elif [ "$1" = "--offline" ] && [ "$2" = "--help" ]; then '
                "printf 'install remove offline\\n'\n"
                f'elif [ "$1" = "install" ]; then : > {marker!s}\n'
                "else exit 2; fi\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            home = root / "agent"
            home.mkdir(mode=0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)
            with self.assertRaises(PiPackageError) as raised:
                install_pi_package(runtime, home, False, True)
            self.assertEqual(raised.exception.code, "PI_CONSENT_REQUIRED")
            self.assertFalse(marker.exists())

    def test_install_failures_preserve_state_and_leave_no_receipt(self):
        cases = {
            "nonzero": (
                "#!/bin/sh\n"
                'case "$1 $2" in\n'
                "  \"--offline --version\") printf '0.84.1\\n' ;;\n"
                "  \"--offline --help\") printf 'install remove offline\\n' ;;\n"
                "  *) exit 7 ;;\n"
                "esac\n"
            ),
            "wrong-poststate": self._write_probe_executable,
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home = root / "agent"
                home.mkdir(mode=0o700)
                executable = root / "pi"
                if callable(source):
                    source(executable)
                else:
                    executable.write_text(source, encoding="utf-8")
                    executable.chmod(0o700)
                runtime = validate_pi_executable(
                    executable, agent_dir=home, execute=True
                )
                with self.assertRaises(PiPackageError) as raised:
                    install_pi_package(runtime, home, True, True)
                expected_code = (
                    "PI_PACKAGE_COMMAND" if name == "nonzero" else "PI_PACKAGE_CONFLICT"
                )
                self.assertEqual(raised.exception.code, expected_code)
                self.assertIsNone(load_pi_package_receipt(home))
                self.assertFalse((home / "settings.json").exists())
                self.assertFalse((home / "npm").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            runtime = validate_pi_executable(
                self._write_probe_executable(root / "pi"),
                agent_dir=home,
                execute=True,
            )

            def install_state(*_args, **_kwargs):
                self._write_exact_package(home)

            with (
                mock.patch(
                    "subagents_configs.pi_package._run_command",
                    side_effect=install_state,
                ),
                mock.patch(
                    "subagents_configs.pi_package.store_pi_package_receipt",
                    side_effect=PiPackageError("PI_RECEIPT_INVALID"),
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
            self.assertEqual(inspect_pi_package_state(home).status, "exact")
            self.assertIsNone(load_pi_package_receipt(home))

    def test_preexisting_exact_noop_and_stale_receipt_never_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            self._write_exact_package(home)
            runtime = validate_pi_executable(
                self._write_probe_executable(root / "pi"),
                agent_dir=home,
                execute=True,
            )
            with mock.patch(
                "subagents_configs.pi_package._run_command",
                side_effect=AssertionError("preexisting exact package must not spawn"),
            ):
                result = install_pi_package(runtime, home, True, True)
            self.assertEqual(result.operation, "none")
            self.assertIsNone(load_pi_package_receipt(home))

            store_pi_package_receipt(home, self._receipt())
            with (
                mock.patch(
                    "subagents_configs.pi_package._run_command",
                    side_effect=AssertionError("stale receipt must not spawn"),
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_RECEIPT_INVALID")
            self.assertEqual(load_pi_package_receipt(home), self._receipt())

    def test_invalid_policy_is_rejected_before_install_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            marker = root / "install-ran"
            executable = root / "pi"
            executable.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "--offline" ] && [ "$2" = "--version" ]; then '
                "printf '0.84.1\\n'\n"
                'elif [ "$1" = "--offline" ] && [ "$2" = "--help" ]; then '
                "printf 'install remove offline\\n'\n"
                f'elif [ "$1" = "install" ]; then : > {marker!s}\n'
                "else exit 2; fi\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)
            with (
                mock.patch(
                    "subagents_configs.pi_package.load_pi_package_policy",
                    side_effect=ValueError("invalid policy"),
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            self.assertFalse(marker.exists())

    def test_policy_is_revalidated_after_install_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            runtime = validate_pi_executable(
                self._write_probe_executable(root / "pi"),
                agent_dir=home,
                execute=True,
            )
            policy_hash = hashlib.sha256(PACKAGE_POLICY_PATH.read_bytes()).hexdigest()

            def install_state(*_args, **_kwargs):
                self._write_exact_package(home)

            with (
                mock.patch(
                    "subagents_configs.pi_package._reviewed_policy_hash",
                    side_effect=[policy_hash, "d" * 64],
                ),
                mock.patch(
                    "subagents_configs.pi_package._run_command",
                    side_effect=install_state,
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            self.assertEqual(inspect_pi_package_state(home).status, "exact")
            self.assertIsNone(load_pi_package_receipt(home))

    def test_invalid_policy_is_rejected_before_remove_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            marker = root / "remove-ran"
            executable = root / "pi"
            executable.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "--offline" ] && [ "$2" = "--version" ]; then '
                "printf '0.84.1\\n'\n"
                'elif [ "$1" = "--offline" ] && [ "$2" = "--help" ]; then '
                "printf 'install remove offline\\n'\n"
                f'elif [ "$1" = "remove" ]; then : > {marker!s}\n'
                "else exit 2; fi\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)
            with (
                mock.patch(
                    "subagents_configs.pi_package.load_pi_package_policy",
                    side_effect=ValueError("invalid policy"),
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                remove_pi_package(runtime, home, self._receipt())
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            self.assertFalse(marker.exists())

    def test_policy_drift_after_successful_remove_keeps_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            self._write_exact_package(home)
            executable = self._write_probe_executable(root / "pi")
            runtime = validate_pi_executable(executable, agent_dir=home, execute=True)
            evidence = inspect_pi_package_state(home)
            policy_hash = hashlib.sha256(PACKAGE_POLICY_PATH.read_bytes()).hexdigest()
            receipt = PiPackageReceipt(
                1,
                "install",
                "npm:pi-subagents@0.56.0",
                "npm:pi-subagents",
                None,
                evidence.settings_hash,
                evidence.manifest_hash or "0" * 64,
                policy_hash,
                True,
            )
            store_pi_package_receipt(home, receipt)
            with (
                mock.patch(
                    "subagents_configs.pi_package._run_command",
                    return_value=None,
                ) as command,
                mock.patch(
                    "subagents_configs.pi_package._reviewed_policy_hash",
                    side_effect=[policy_hash, "d" * 64],
                ),
                self.assertRaises(PiPackageError) as raised,
            ):
                remove_pi_package(runtime, home, receipt)
            self.assertEqual(raised.exception.code, "PI_PACKAGE_CONFLICT")
            command.assert_called_once()
            self.assertEqual(load_pi_package_receipt(home), receipt)
            self.assertEqual(inspect_pi_package_state(home).status, "exact")

    def test_mutation_rejects_execute_false_or_forged_runtime_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "agent"
            home.mkdir(mode=0o700)
            executable = root / "pi"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o700)
            runtime = validate_pi_executable(executable, agent_dir=home, execute=False)
            with self.assertRaises(PiPackageError) as raised:
                install_pi_package(runtime, home, True, True)
            self.assertEqual(raised.exception.code, "PI_RUNTIME_INCOMPATIBLE")
            forged = type(runtime)(
                executable=runtime.executable,
                version="0.84.1",
                device=runtime.device,
                inode=runtime.inode,
                mode=runtime.mode,
                sha256=runtime.sha256,
                help_has_install=True,
                help_has_remove=True,
                help_has_offline=True,
            )
            with self.assertRaises(PiPackageError) as raised:
                install_pi_package(forged, home, True, True)
            self.assertEqual(raised.exception.code, "PI_RUNTIME_INCOMPATIBLE")


if __name__ == "__main__":
    unittest.main()
