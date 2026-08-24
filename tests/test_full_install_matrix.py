from __future__ import annotations

import hashlib
import io
import itertools
import json
import os
import shutil
import stat
import unittest
from pathlib import Path
from unittest.mock import patch

from subagents_configs import orchestrator
from subagents_configs.locks import locked_target_homes
from subagents_configs.models import Journal, JournalOperation, Target
from subagents_configs.planning import (
    preflight_install,
    preflight_uninstall,
    render_plan,
)
from subagents_configs.state import load_journal, load_manifest
from subagents_configs.targets import DESCRIPTOR_ORDER, descriptor_for
from tests.helpers import (
    planning_request,
    private_tempdir,
    real_repository,
    tree_snapshot,
)
from tests.validation_isolated_test_support import system_executable

TARGETS = DESCRIPTOR_ORDER
COMBINATIONS = tuple(
    combination
    for size in range(1, len(TARGETS) + 1)
    for combination in itertools.combinations(TARGETS, size)
)


class _FailAt:
    def __init__(self, position: int, homes=None):
        self.position = position
        self.calls = 0
        self.homes = homes or {}
        self.snapshots = {}
        self.journals = {}
        self.journal_payloads = {}
        self.manifest_payloads = {}

    def before_operation(self, _operation_id: str) -> None:
        if self.calls == self.position:
            for target, home in self.homes.items():
                self.snapshots[target] = tree_snapshot(home)
                journal = home / ".subagents_configs/journal.json"
                manifest = home / ".subagents_configs/manifest.json"
                if journal.exists():
                    self.journals[target] = load_journal(home, descriptor_for(target))
                    self.journal_payloads[target] = json.loads(
                        journal.read_text(encoding="utf-8")
                    )
                if manifest.exists():
                    self.manifest_payloads[target] = json.loads(
                        manifest.read_text(encoding="utf-8")
                    )
            raise RuntimeError("matrix failure injection")
        self.calls += 1


class FullInstallMatrixTests(unittest.TestCase):
    repository = real_repository()

    def _homes(self, root: Path, selected: tuple[Target, ...]) -> dict[Target, Path]:
        homes = {target: root / "homes" / target.value for target in selected}
        for home in homes.values():
            home.mkdir(mode=0o700, parents=True)
        return homes

    def _argv(
        self,
        selected: tuple[Target, ...],
        homes: dict[Target, Path],
        *options: str,
    ) -> list[str]:
        argv: list[str] = []
        for target in selected:
            argv.extend(("--target", target.value))
        for target in selected:
            argv.extend(("--home", f"{target.value}={homes[target]}"))
        argv.extend(options)
        return argv

    def _run(
        self,
        operation: str,
        argv: list[str],
        root: Path,
        *,
        failure_injector=None,
        repository: Path | None = None,
    ) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        status = orchestrator.run(
            operation,
            argv,
            repo_root=repository or self.repository,
            environ={"HOME": str(root / "ambient")},
            stdout=stdout,
            stderr=stderr,
            failure_injector=failure_injector,
        )
        return status, stdout.getvalue(), stderr.getvalue()

    def _run_with_journal_evidence(
        self,
        operation: str,
        argv: list[str],
        root: Path,
        *,
        repository: Path | None = None,
    ):
        from subagents_configs import transaction

        journals = {}
        real_cleanup = transaction._sync_and_remove_journal

        def capture(home, journal):
            journals[journal.target] = journal
            return real_cleanup(home, journal)

        with patch.object(transaction, "_sync_and_remove_journal", side_effect=capture):
            result = self._run(operation, argv, root, repository=repository)
        return result, journals

    def _expected_commitment_files(self, journals):
        payloads = {
            target: {
                "transaction_id": journal.transaction_id,
                "target": journal.target.value,
                "participants": [
                    participant.value for participant in journal.participants
                ],
                "operation": journal.operation,
                "operations": [
                    {
                        "operation_id": operation.operation_id,
                        "identifier": operation.identifier,
                        "action": operation.action,
                        "expected_before_hash": operation.expected_before_hash,
                        "expected_after_hash": operation.expected_after_hash,
                        "expected_before_mode": operation.expected_before_mode,
                        "expected_after_mode": operation.expected_after_mode,
                        "backup_path": operation.backup_path,
                        "backup_hash": operation.backup_hash,
                    }
                    for operation in journal.operations
                ],
            }
            for target, journal in journals.items()
        }
        return self._expected_commitment_files_from_payloads(payloads)

    def test_rendered_agent_files_remain_parseable_with_home_path_spaces(self):
        from subagents_configs.formats import validate_toml_agent, validate_yaml_agent

        with private_tempdir() as temporary:
            root = Path(temporary)
            selected = TARGETS
            homes = {
                target: root / "homes" / f"{target.value} with spaces-zażółć"
                for target in selected
            }
            plan = preflight_install(
                self.repository,
                planning_request(
                    "install",
                    homes,
                    targets=selected,
                    include_commit_pusher=True,
                ),
            )
            for target_plan in plan.targets:
                for operation in target_plan.operations:
                    if operation.identifier not in {
                        "code-explorer",
                        "code-reviewer",
                        "code-validator",
                        "quick-implementer",
                        "implementer",
                        "commit-pusher",
                    }:
                        continue
                    self.assertIsNotNone(operation.content)
                    if target_plan.target is Target.CODEX:
                        validate_toml_agent(
                            Path(operation.relative_path), operation.content or b""
                        )
                    else:
                        validate_yaml_agent(
                            Path(operation.relative_path), operation.content or b""
                        )

    def test_commitment_oracle_does_not_call_production_digest_helper(self):
        journal = Journal(
            1,
            f"{'0' * 32}-{'1' * 64}",
            Target.CODEX,
            (Target.CODEX,),
            "install",
            (
                JournalOperation(
                    "codex-0000-agents-code-explorer.toml",
                    "code-explorer",
                    "create",
                    None,
                    "a" * 64,
                    None,
                    0o600,
                    None,
                    None,
                    "planned",
                ),
            ),
            "not-started",
        )
        with patch(
            "subagents_configs.transaction._commitment_digest",
            side_effect=AssertionError("commitment oracle called production helper"),
        ):
            evidence = self._expected_commitment_files({Target.CODEX: journal})
        self.assertEqual(
            set(evidence[Target.CODEX]),
            {".subagents_configs/backups/commitment-" + "0" * 32},
        )

    def _journal_relative(self, target: Target, identifier: str) -> str:
        descriptor = descriptor_for(target)
        if identifier == "state/manifest":
            return ".subagents_configs/manifest.json"
        for source in descriptor.sources:
            if identifier in {
                source.identifier,
                source.destination.as_posix() if source.destination else None,
            }:
                self.assertIsNotNone(source.destination)
                return source.destination.as_posix()
        aliases = {
            "routing-codex": descriptor.global_filename,
            "routing-opencode": descriptor.global_filename,
            "routing-claude-code": descriptor.global_filename,
            "codex-multi-agent-v2": descriptor.config_filename,
        }
        self.assertIn(identifier, aliases)
        relative = aliases[identifier]
        self.assertIsNotNone(relative)
        return relative

    def _expected_commitment_files_from_payloads(self, payloads):
        records = []
        ordered_targets = tuple(target for target in TARGETS if target in payloads)
        self.assertTrue(ordered_targets)
        for target in ordered_targets:
            payload = payloads[target]
            records.append(
                {
                    "target": payload["target"],
                    "participants": payload["participants"],
                    "operation": payload["operation"],
                    "operations": [
                        {
                            "operation_id": operation["operation_id"],
                            "identifier": self._journal_relative(
                                target, operation["identifier"]
                            ),
                            "canonical_path": self._journal_relative(
                                target, operation["identifier"]
                            ),
                            "action": operation["action"],
                            "expected_before_hash": operation["expected_before_hash"],
                            "expected_after_hash": operation["expected_after_hash"],
                            "expected_before_mode": operation["expected_before_mode"],
                            "expected_after_mode": operation["expected_after_mode"],
                            "backup_path": operation["backup_path"],
                            "backup_hash": operation["backup_hash"],
                        }
                        for operation in payload["operations"]
                    ],
                }
            )
        digest = hashlib.sha256(
            json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        nonce = payloads[ordered_targets[0]]["transaction_id"].rsplit("-", 1)[0]
        content = f"{nonce}:{digest}".encode()
        return {
            target: {f".subagents_configs/backups/commitment-{nonce}": (content, 0o600)}
            for target in payloads
        }

    def _permanent_backup_evidence(self, manifest, known_contents):
        evidence = {}
        if manifest is None:
            return evidence
        for entry in manifest.entries:
            if entry.backup_path is None:
                continue
            backup_relative = f".subagents_configs/{entry.backup_path}"
            self.assertIn(entry.relative_path, known_contents)
            content = known_contents[entry.relative_path]
            self.assertEqual(hashlib.sha256(content).hexdigest(), entry.backup_hash)
            evidence[backup_relative] = (content, 0o600)
        self.assertTrue(evidence, "permanent backup evidence must be nonempty")
        return evidence

    def _assert_exact_evidence(
        self,
        home: Path,
        expected: dict[str, tuple[bytes, int]],
        *,
        commitment: bool = False,
    ) -> None:
        for relative, (content, mode) in expected.items():
            path = home / relative
            item = path.lstat()
            self.assertTrue(stat.S_ISREG(item.st_mode), relative)
            self.assertEqual(item.st_nlink, 1, relative)
            self.assertEqual(stat.S_IMODE(item.st_mode), mode, relative)
            actual = path.read_bytes()
            self.assertEqual(actual, content, relative)
            self.assertEqual(
                hashlib.sha256(actual).hexdigest(),
                hashlib.sha256(content).hexdigest(),
                relative,
            )
            if commitment:
                nonce, digest = actual.decode("ascii").split(":")
                self.assertEqual(len(nonce), 32, relative)
                self.assertEqual(len(digest), 64, relative)
                self.assertTrue(
                    all(char in "0123456789abcdef" for char in nonce), relative
                )
                self.assertTrue(
                    all(char in "0123456789abcdef" for char in digest), relative
                )

    def _managed_paths(
        self, target: Target, *, include_commit_pusher: bool = False
    ) -> set[str]:
        descriptor = descriptor_for(target)
        paths = {
            source.destination.as_posix()
            for source in descriptor.sources
            if source.destination is not None
            and (include_commit_pusher or source.optional_role != "commit-pusher")
        }
        paths.add(".subagents_configs/manifest.json")
        return paths

    def _expected_default_files(self, target: Target) -> set[str]:
        return self._managed_paths(target)

    def _assert_exact_manifest_files(
        self,
        target: Target,
        home: Path,
        expected: set[str],
    ) -> None:
        self._assert_exact_inventory(home, expected)
        manifest = load_manifest(home, descriptor_for(target))
        self.assertIsNotNone(manifest)
        for entry in manifest.entries:
            item = home / entry.relative_path
            self.assertEqual(
                hashlib.sha256(item.read_bytes()).hexdigest(), entry.installed_hash
            )
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), entry.installed_mode)
            if entry.backup_path is not None:
                backup = home / ".subagents_configs" / entry.backup_path
                backup_item = backup.lstat()
                self.assertTrue(stat.S_ISREG(backup_item.st_mode))
                self.assertEqual(backup_item.st_nlink, 1)
                self.assertEqual(
                    hashlib.sha256(backup.read_bytes()).hexdigest(), entry.backup_hash
                )
                self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def _assert_exact_inventory(self, home: Path, expected: set[str]) -> None:
        expected = {*expected, ".subagents_configs.lock"}
        entries = {
            path.relative_to(home).as_posix(): path.lstat() for path in home.rglob("*")
        }
        self.assertEqual(
            {
                relative
                for relative, item in entries.items()
                if stat.S_ISREG(item.st_mode)
            },
            expected,
        )
        self.assertEqual(
            {
                relative
                for relative, item in entries.items()
                if stat.S_ISLNK(item.st_mode)
            },
            set(),
        )
        self.assertEqual(
            {
                relative
                for relative, item in entries.items()
                if stat.S_ISDIR(item.st_mode)
            },
            {
                ".subagents_configs",
                ".subagents_configs/backups",
                ".subagents_configs/validation",
                ".subagents_configs/validation/validation_isolation",
                "agents",
            },
        )
        lock = home / ".subagents_configs.lock"
        lock_item = lock.lstat()
        self.assertTrue(stat.S_ISREG(lock_item.st_mode))
        self.assertEqual(lock_item.st_nlink, 1)
        self.assertEqual(stat.S_IMODE(lock_item.st_mode), 0o600)

    def _assert_exact_extra_files(
        self,
        home: Path,
        expected: dict[str, tuple[bytes, int]],
    ) -> None:
        for relative, (content, mode) in expected.items():
            path = home / relative
            item = path.lstat()
            self.assertTrue(stat.S_ISREG(item.st_mode), relative)
            self.assertEqual(item.st_nlink, 1, relative)
            self.assertEqual(path.read_bytes(), content, relative)
            self.assertEqual(stat.S_IMODE(item.st_mode), mode, relative)

    def test_all_seven_combinations_real_inventory_lifecycle_and_scope(self):
        """Exercise every nonempty target set against the real source tree."""

        for combination in COMBINATIONS:
            with self.subTest(targets=tuple(target.value for target in combination)):
                with private_tempdir() as directory:
                    root = Path(directory)
                    homes = self._homes(root, combination)
                    user_files: dict[Target, tuple[bytes, int]] = {}
                    for target, home in homes.items():
                        note = home / "user-notes.txt"
                        note.write_bytes(b"user bytes must survive\n")
                        note.chmod(0o640)
                        user_files[target] = (
                            note.read_bytes(),
                            stat.S_IMODE(note.stat().st_mode),
                        )
                    source_before = tree_snapshot(self.repository)

                    argv = self._argv(combination, homes)
                    initial_plan = preflight_install(
                        self.repository,
                        planning_request("install", homes, targets=combination),
                    )
                    self.assertEqual(
                        render_plan(initial_plan),
                        render_plan(
                            preflight_install(
                                self.repository,
                                planning_request("install", homes, targets=combination),
                            )
                        ),
                    )
                    (status, output, error), journals = self._run_with_journal_evidence(
                        "install", argv, root
                    )
                    self.assertEqual(status, orchestrator.EXIT_SUCCESS, error)
                    self.assertEqual(error, "")
                    self.assertEqual(output, render_plan(initial_plan))
                    commitment_files = self._expected_commitment_files(journals)

                    for target, home in homes.items():
                        managed = self._expected_default_files(target)
                        managed |= set(commitment_files[target])
                        self._assert_exact_manifest_files(
                            target, home, managed | {"user-notes.txt"}
                        )
                        self._assert_exact_extra_files(
                            home,
                            {
                                **commitment_files[target],
                                "user-notes.txt": user_files[target],
                            },
                        )
                        self.assertFalse(
                            any("commit-pusher" in path for path in managed)
                        )
                        self.assertFalse(
                            (home / descriptor_for(target).global_filename).exists()
                        )
                        if target is Target.CODEX:
                            self.assertFalse((home / "config.toml").exists())
                        for relative in managed:
                            item = home / relative
                            self.assertEqual(
                                stat.S_IMODE(item.stat().st_mode), 0o600, relative
                            )
                        self.assertEqual(
                            (home / "user-notes.txt").read_bytes(),
                            user_files[target][0],
                        )
                        self.assertEqual(
                            stat.S_IMODE((home / "user-notes.txt").stat().st_mode),
                            user_files[target][1],
                        )

                    installed = tree_snapshot(root)
                    reinstall_plan = preflight_install(
                        self.repository,
                        planning_request("install", homes, targets=combination),
                    )
                    status, _output, error = self._run("install", argv, root)
                    self.assertEqual(status, orchestrator.EXIT_SUCCESS, error)
                    self.assertEqual(_output, render_plan(reinstall_plan))
                    self.assertEqual(tree_snapshot(root), installed)

                    before_dry_run = tree_snapshot(root)
                    dry_plan = preflight_install(
                        self.repository,
                        planning_request(
                            "install", homes, targets=combination, dry_run=True
                        ),
                    )
                    status, output, error = self._run(
                        "install", [*argv, "--dry-run"], root
                    )
                    self.assertEqual(status, orchestrator.EXIT_SUCCESS, error)
                    self.assertEqual(output, render_plan(dry_plan))
                    self.assertEqual(tree_snapshot(root), before_dry_run)

                    status, _output, error = self._run(
                        "uninstall", self._argv(combination, homes), root
                    )
                    self.assertEqual(status, orchestrator.EXIT_SUCCESS, error)
                    self.assertEqual(tree_snapshot(self.repository), source_before)
                    for target, home in homes.items():
                        self.assertEqual(
                            (home / "user-notes.txt").read_bytes(),
                            user_files[target][0],
                        )
                        self.assertEqual(
                            stat.S_IMODE((home / "user-notes.txt").stat().st_mode),
                            user_files[target][1],
                        )
                        self.assertFalse(list((home / "agents").glob("*")))
                        self.assertFalse(
                            (home / ".subagents_configs/manifest.json").exists()
                        )
                        self.assertTrue(
                            (home / ".subagents_configs/validation").is_dir()
                        )

    def test_command_boundary_matrix_rejects_encoded_protected_paths(self):
        from scripts.validation_isolation.backend import (
            BackendSpec,
            build_backend_argv,
            validate_command_argv,
        )

        with private_tempdir() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            home = root / "home"
            temp = root / "temp"
            for path in (worktree, home, temp):
                path.mkdir(mode=0o700)
            environment = {
                "CI": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "HOME": str(home),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin",
                "TMPDIR": str(temp),
                "XDG_CACHE_HOME": str(temp / "cache"),
                "XDG_CONFIG_HOME": str(temp / "config"),
            }
            (temp / "cache").mkdir(mode=0o700)
            (temp / "config").mkdir(mode=0o700)
            backend = BackendSpec(
                "macos", system_executable("true"), system_executable("python3")
            )
            protected = (
                worktree / "secret.txt",
                home / ".ssh" / "id_rsa",
                home / "run" / "socket",
            )
            for spelling in (r"\057", r"\U0000002F", r"\N{SOLIDUS}"):
                for path in protected:
                    encoded = str(path).replace("/", spelling)
                    for token in (f"--path={encoded}", f'open("{encoded}")'):
                        with self.subTest(spelling=spelling, token=token):
                            with self.assertRaises(ValueError):
                                validate_command_argv(
                                    ("python3", token), worktree, home
                                )
                            with self.assertRaises(ValueError):
                                build_backend_argv(
                                    backend,
                                    ("python3", token),
                                    worktree,
                                    temp,
                                    environment,
                                )

    def test_opt_ins_replace_exact_blocks_and_include_optional_role(self):
        for selected in COMBINATIONS:
            with self.subTest(targets=tuple(target.value for target in selected)):
                with private_tempdir() as directory:
                    root = Path(directory)
                    homes = self._homes(root, selected)
                    originals: dict[Target, bytes] = {}
                    for target, home in homes.items():
                        filename = descriptor_for(target).global_filename
                        content = f"before-{target.value}\n\nuser tail\n".encode()
                        destination = home / filename
                        destination.write_bytes(content)
                        destination.chmod(0o640)
                        originals[target] = content
                    options = [
                        "--enable-global-routing",
                        "--include-commit-pusher",
                    ]
                    if Target.CODEX in selected:
                        options.append("--enable-codex-multi-agent")
                    argv = self._argv(selected, homes, *options)
                    initial_plan = preflight_install(
                        self.repository,
                        planning_request(
                            "install",
                            homes,
                            targets=selected,
                            enable_global_routing=True,
                            include_commit_pusher=True,
                            enable_codex_multi_agent=Target.CODEX in selected,
                        ),
                    )
                    self.assertEqual(
                        render_plan(initial_plan),
                        render_plan(
                            preflight_install(
                                self.repository,
                                planning_request(
                                    "install",
                                    homes,
                                    targets=selected,
                                    enable_global_routing=True,
                                    include_commit_pusher=True,
                                    enable_codex_multi_agent=Target.CODEX in selected,
                                ),
                            )
                        ),
                    )
                    (status, output, error), journals = self._run_with_journal_evidence(
                        "install", argv, root
                    )
                    self.assertEqual(status, orchestrator.EXIT_SUCCESS, error)
                    self.assertEqual(output, render_plan(initial_plan))
                    commitment_files_by_target = self._expected_commitment_files(
                        journals
                    )
                    permanent_backups_by_target = {}
                    permanent_evidence_by_target = {}
                    expected_backup_hashes_by_target = {}
                    corruption_checked = False
                    for target, home in homes.items():
                        manifest = load_manifest(home, descriptor_for(target))
                        self.assertIsNotNone(manifest)
                        backup_files = {
                            f".subagents_configs/{entry.backup_path}"
                            for entry in manifest.entries
                            if entry.backup_path is not None
                        }
                        self.assertTrue(backup_files, target)
                        permanent_backups_by_target[target] = backup_files
                        filename = descriptor_for(target).global_filename
                        permanent_evidence_by_target[target] = (
                            self._permanent_backup_evidence(
                                manifest, {filename: originals[target]}
                            )
                        )
                        expected_hash = hashlib.sha256(originals[target]).hexdigest()
                        expected_backup_hashes_by_target[target] = {
                            relative: expected_hash for relative in backup_files
                        }
                        for entry in manifest.entries:
                            if entry.backup_path is not None:
                                self.assertEqual(entry.backup_hash, expected_hash)
                                self.assertEqual(entry.original_mode, 0o640)
                        all_backups = {
                            path.relative_to(home).as_posix()
                            for path in (
                                home / ".subagents_configs" / "backups"
                            ).iterdir()
                            if path.is_file()
                        }
                        commitment_files = set(commitment_files_by_target[target])
                        self.assertTrue(commitment_files, target)
                        self.assertEqual(
                            {
                                path
                                for path in all_backups - backup_files
                                if path.startswith(
                                    ".subagents_configs/backups/commitment-"
                                )
                            },
                            commitment_files,
                        )
                        transaction_backups = (
                            all_backups - backup_files - commitment_files
                        )
                        self.assertEqual(transaction_backups, set())
                        expected = (
                            self._managed_paths(target, include_commit_pusher=True)
                            | {descriptor_for(target).global_filename}
                            | backup_files
                            | commitment_files
                        )
                        if target is Target.CODEX:
                            expected.add("config.toml")
                        self._assert_exact_manifest_files(target, home, expected)
                        self._assert_exact_evidence(
                            home, permanent_evidence_by_target[target]
                        )
                        self._assert_exact_extra_files(
                            home,
                            commitment_files_by_target[target],
                        )
                        filename = descriptor_for(target).global_filename
                        content = (home / filename).read_bytes()
                        self.assertTrue(content.startswith(originals[target]))
                        self.assertIn(
                            f"BEGIN SUBAGENTS_CONFIGS routing-{target.value}".encode(),
                            content,
                        )
                        self.assertTrue(
                            (
                                home
                                / "agents"
                                / (
                                    "commit-pusher.toml"
                                    if target is Target.CODEX
                                    else "commit-pusher.md"
                                )
                            ).is_file()
                        )
                        if not corruption_checked:
                            relative = next(iter(backup_files))
                            corrupted = home / relative
                            corrupted.write_bytes(b"corrupted permanent backup\n")
                            corrupted.chmod(0o600)
                            with self.assertRaises(AssertionError):
                                self._assert_exact_evidence(
                                    home,
                                    {relative: (originals[target], 0o600)},
                                )
                            corrupted.write_bytes(originals[target])
                            corrupted.chmod(0o600)
                            corruption_checked = True
                    if Target.CODEX in selected:
                        self.assertIn(
                            b"BEGIN SUBAGENTS_CONFIGS codex-multi-agent-v2",
                            (homes[Target.CODEX] / "config.toml").read_bytes(),
                        )
                    uninstall_plan = preflight_uninstall(
                        self.repository,
                        planning_request("uninstall", homes, targets=selected),
                    )
                    (uninstall_status, uninstall_output, error), uninstall_journals = (
                        self._run_with_journal_evidence(
                            "uninstall", self._argv(selected, homes), root
                        )
                    )
                    self.assertEqual(uninstall_status, orchestrator.EXIT_SUCCESS, error)
                    self.assertEqual(uninstall_output, render_plan(uninstall_plan))
                    uninstall_commitments = self._expected_commitment_files(
                        uninstall_journals
                    )
                    for target, home in homes.items():
                        filename = descriptor_for(target).global_filename
                        restored = home / filename
                        self.assertEqual(restored.read_bytes(), originals[target])
                        self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o640)
                        self.assertFalse((home / "config.toml").exists())
                        self.assertFalse(
                            (home / ".subagents_configs/manifest.json").exists()
                        )
                        self.assertFalse(
                            (home / ".subagents_configs/journal.json").exists()
                        )
                        runtime = {
                            source.destination.as_posix()
                            for source in descriptor_for(target).sources
                            if source.kind == "validation-runtime"
                            and source.destination is not None
                        }
                        self._assert_exact_inventory(
                            home,
                            runtime
                            | permanent_backups_by_target[target]
                            | set(commitment_files_by_target[target])
                            | set(uninstall_commitments[target])
                            | {filename},
                        )
                        self._assert_exact_extra_files(
                            home,
                            {
                                filename: (originals[target], 0o640),
                                **commitment_files_by_target[target],
                                **uninstall_commitments[target],
                            },
                        )
                        for relative in permanent_backups_by_target[target]:
                            content, expected_mode = permanent_evidence_by_target[
                                target
                            ][relative]
                            expected_hash = expected_backup_hashes_by_target[target][
                                relative
                            ]
                            self.assertEqual(
                                hashlib.sha256(content).hexdigest(), expected_hash
                            )
                            self._assert_exact_evidence(
                                home, {relative: (content, expected_mode)}
                            )
                            self.assertEqual(
                                expected_backup_hashes_by_target[target][relative],
                                hashlib.sha256(originals[target]).hexdigest(),
                            )

    def test_failure_positions_rollback_all_selected_targets_for_install_and_uninstall(
        self,
    ):
        for selected in COMBINATIONS:
            for operation in ("install", "uninstall"):
                for phase in ("early", "middle", "late"):
                    with self.subTest(
                        targets=tuple(target.value for target in selected),
                        operation=operation,
                        phase=phase,
                    ):
                        with private_tempdir() as directory:
                            root = Path(directory)
                            homes = self._homes(root, selected)
                            managed_contents = {}
                            for home in homes.values():
                                note = home / "user-notes.txt"
                                note.write_bytes(b"user bytes must survive\n")
                                note.chmod(0o640)
                                (home / "user-link").symlink_to(note.name)
                            for target, home in homes.items():
                                managed = home / descriptor_for(target).global_filename
                                content = (
                                    f"preexisting managed {target.value}\n".encode()
                                )
                                managed_contents[target] = content
                                managed.write_bytes(content)
                                managed.chmod(0o640)
                            install_argv = self._argv(
                                selected, homes, "--enable-global-routing"
                            )
                            if operation == "uninstall":
                                status, _output, error = self._run(
                                    "install", install_argv, root
                                )
                                self.assertEqual(
                                    status, orchestrator.EXIT_SUCCESS, error
                                )
                            plan_request = planning_request(
                                operation,
                                homes,
                                targets=selected,
                                enable_global_routing=operation == "install",
                            )
                            plan = (
                                preflight_install(self.repository, plan_request)
                                if operation == "install"
                                else preflight_uninstall(self.repository, plan_request)
                            )
                            evidence_manifests = {
                                target_plan.target: target_plan.resulting_manifest
                                for target_plan in plan.targets
                            }
                            if operation == "uninstall":
                                evidence_manifests = {
                                    target: load_manifest(home, descriptor_for(target))
                                    for target, home in homes.items()
                                }
                                self.assertTrue(all(evidence_manifests.values()))
                            operation_count = sum(
                                len(target.operations) for target in plan.targets
                            )
                            position = {
                                "early": 0,
                                "middle": operation_count // 2,
                                "late": max(0, operation_count - 1),
                            }[phase]
                            expected_output = render_plan(plan)
                            before = {
                                target: tree_snapshot(home)
                                for target, home in homes.items()
                            }
                            injector = _FailAt(position, homes)
                            status, output, error = self._run(
                                operation,
                                install_argv
                                if operation == "install"
                                else self._argv(selected, homes),
                                root,
                                failure_injector=injector,
                            )
                            self.assertEqual(status, orchestrator.EXIT_APPLY_ERROR)
                            self.assertEqual(output, expected_output)
                            self.assertEqual(
                                error, "error: apply failed; rollback completed\n"
                            )
                            for target, home in homes.items():
                                after = tree_snapshot(home)
                                backup_prefix = ".subagents_configs/backups/"
                                journal_payload = injector.journal_payloads[target]
                                transaction_backups = {
                                    ".subagents_configs/" + operation["backup_path"]
                                    for operation in journal_payload["operations"]
                                    if operation["backup_path"] is not None
                                }
                                expected_after = dict(before[target])
                                expected_after[".subagents_configs.lock"] = (
                                    "file",
                                    0o600,
                                    b"",
                                )
                                for relative in transaction_backups:
                                    expected_after.pop(relative, None)
                                expected_after.pop(
                                    ".subagents_configs/journal.json", None
                                )
                                marker_evidence = (
                                    self._expected_commitment_files_from_payloads(
                                        injector.journal_payloads
                                    )[target]
                                )
                                permanent_evidence = self._permanent_backup_evidence(
                                    evidence_manifests[target],
                                    {
                                        descriptor_for(
                                            target
                                        ).global_filename: managed_contents[target]
                                    },
                                )
                                expected_after.update(
                                    {
                                        relative: ("file", mode, content)
                                        for relative, (content, mode) in (
                                            marker_evidence | permanent_evidence
                                        ).items()
                                    }
                                )
                                if operation == "install":
                                    validation_runtime_dir = (
                                        ".subagents_configs/validation/"
                                        "validation_isolation"
                                    )
                                    expected_after.update(
                                        {
                                            ".subagents_configs": (
                                                "directory",
                                                0o700,
                                                None,
                                            ),
                                            ".subagents_configs/backups": (
                                                "directory",
                                                0o700,
                                                None,
                                            ),
                                            ".subagents_configs/validation": (
                                                "directory",
                                                0o700,
                                                None,
                                            ),
                                            validation_runtime_dir: (
                                                "directory",
                                                0o700,
                                                None,
                                            ),
                                            "agents": ("directory", 0o700, None),
                                        }
                                    )
                                self.assertEqual(after, expected_after)
                                actual_backups = {
                                    path
                                    for path in after
                                    if path.startswith(backup_prefix)
                                }
                                expected_backups = {
                                    path
                                    for path in expected_after
                                    if path.startswith(backup_prefix)
                                }
                                self.assertEqual(actual_backups, expected_backups)
                                for path in expected_backups:
                                    self.assertEqual(after[path], expected_after[path])
                                for path in transaction_backups:
                                    self.assertNotIn(path, after)
                                self._assert_exact_evidence(
                                    home, marker_evidence, commitment=True
                                )
                                self._assert_exact_evidence(home, permanent_evidence)
                                manifest_payload = injector.manifest_payloads.get(
                                    target
                                )
                                if manifest_payload is not None:
                                    for entry in manifest_payload["entries"]:
                                        if entry["backup_path"] is None:
                                            continue
                                        relative = (
                                            ".subagents_configs/" + entry["backup_path"]
                                        )
                                        self.assertEqual(
                                            hashlib.sha256(
                                                after[relative][2]
                                            ).hexdigest(),
                                            entry["backup_hash"],
                                        )
                                        self.assertEqual(after[relative][1], 0o600)
                                self.assertFalse(
                                    (home / ".subagents_configs/journal.json").exists()
                                )
                                if operation == "install":
                                    self.assertNotIn(
                                        ".subagents_configs/manifest.json", after
                                    )
                                else:
                                    self.assertIn(
                                        ".subagents_configs/manifest.json", after
                                    )

    def test_unresolved_uninstall_preserves_drift_for_all_combinations(self):
        for selected in COMBINATIONS:
            with self.subTest(targets=tuple(target.value for target in selected)):
                with private_tempdir() as directory:
                    root = Path(directory)
                    homes = self._homes(root, selected)
                    safe_files: dict[
                        Target, dict[str, tuple[str, int, bytes | str | None]]
                    ] = {}
                    for target, home in homes.items():
                        note = home / "user-notes.txt"
                        note.write_bytes(b"safe user bytes\n")
                        note.chmod(0o640)
                        link = home / "user-link"
                        link.symlink_to(note.name)
                        safe_files[target] = tree_snapshot(home)
                    status, _output, error = self._run(
                        "install", self._argv(selected, homes), root
                    )
                    self.assertEqual(status, orchestrator.EXIT_SUCCESS, error)
                    drift_target = selected[-1]
                    suffix = ".toml" if drift_target is Target.CODEX else ".md"
                    drifted = homes[drift_target] / "agents" / f"code-explorer{suffix}"
                    drifted.write_bytes(b"user changed managed content\n")
                    drifted.chmod(0o640)
                    expected_plan = preflight_uninstall(
                        self.repository,
                        planning_request("uninstall", homes, targets=selected),
                    )
                    status, output, error = self._run(
                        "uninstall", self._argv(selected, homes), root
                    )
                    self.assertEqual(status, orchestrator.EXIT_UNRESOLVED_UNINSTALL)
                    self.assertTrue(output.startswith(render_plan(expected_plan)))
                    self.assertIn(f"unresolved: target={drift_target.value}", output)
                    self.assertEqual(error, "")
                    self.assertEqual(
                        drifted.read_bytes(), b"user changed managed content\n"
                    )
                    self.assertEqual(stat.S_IMODE(drifted.stat().st_mode), 0o640)
                    manifest = load_manifest(
                        homes[drift_target], descriptor_for(drift_target)
                    )
                    self.assertIsNotNone(manifest)
                    retained = [
                        entry
                        for entry in manifest.entries
                        if entry.relative_path
                        == drifted.relative_to(homes[drift_target]).as_posix()
                    ]
                    self.assertEqual(len(retained), 1)
                    self.assertIsNotNone(retained[0].unresolved_reason)
                    for target, home in homes.items():
                        runtime = {
                            source.destination.as_posix()
                            for source in descriptor_for(target).sources
                            if source.kind == "validation-runtime"
                            and source.destination is not None
                        }
                        backup_files = {
                            path.relative_to(home).as_posix()
                            for path in (
                                home / ".subagents_configs" / "backups"
                            ).iterdir()
                            if path.is_file()
                        }
                        expected_files = runtime | backup_files
                        if target is drift_target:
                            expected_files = expected_files | {
                                ".subagents_configs/manifest.json",
                                drifted.relative_to(home).as_posix(),
                            }
                        expected_files |= {"user-notes.txt", "user-link"}
                        expected_files.add(".subagents_configs.lock")
                        actual_files = {
                            path.relative_to(home).as_posix()
                            for path in home.rglob("*")
                            if path.is_file()
                        }
                        self.assertEqual(actual_files, expected_files)
                        after = tree_snapshot(home)
                        for relative, value in safe_files[target].items():
                            if relative in {"user-notes.txt", "user-link"}:
                                self.assertEqual(after[relative], value)

    def test_corrupt_late_inventory_and_state_fail_closed_without_home_mutation(self):
        for relative in (
            "agents/quick-implementer.toml",
            "scripts/validation_isolation/cli.py",
        ):
            with self.subTest(relative=relative):
                with private_tempdir() as directory:
                    root = Path(directory)
                    repository = root / "repository"
                    shutil.copytree(
                        self.repository,
                        repository,
                        ignore=shutil.ignore_patterns(".git"),
                    )
                    (repository / relative).unlink()
                    homes = self._homes(root, (Target.CODEX,))
                    marker = homes[Target.CODEX] / "user.txt"
                    marker.write_bytes(b"keep\n")
                    with locked_target_homes(homes, (Target.CODEX,)):
                        before = tree_snapshot(homes[Target.CODEX])
                    status, _output, error = self._run(
                        "install",
                        self._argv((Target.CODEX,), homes),
                        root,
                        repository=repository,
                    )
                    self.assertEqual(status, orchestrator.EXIT_BLOCKED_VALIDATION)
                    self.assertIn("validation blocked", error)
                    self.assertEqual(tree_snapshot(homes[Target.CODEX]), before)

        with private_tempdir() as directory:
            root = Path(directory)
            homes = self._homes(root, (Target.CODEX,))
            state = homes[Target.CODEX] / ".subagents_configs"
            state.mkdir(mode=0o700)
            (state / "journal.json").write_bytes(b"{}")
            (state / "journal.json").chmod(0o600)
            with locked_target_homes(homes, (Target.CODEX,)):
                before = tree_snapshot(homes[Target.CODEX])
            status, _output, error = self._run(
                "install", self._argv((Target.CODEX,), homes), root
            )
            self.assertEqual(status, orchestrator.EXIT_BLOCKED_VALIDATION)
            self.assertIn("recovery validation blocked", error)
            self.assertEqual(tree_snapshot(homes[Target.CODEX]), before)

    def test_corrupt_late_inventory_and_recovery_state_cover_all_combinations(self):
        for selected in COMBINATIONS:
            late_target = selected[-1]
            late_descriptor = descriptor_for(late_target)
            late_source = next(
                source.source.as_posix()
                for source in late_descriptor.sources
                if source.identifier == "quick-implementer"
            )
            for relative in (late_source, "scripts/validation_isolation/cli.py"):
                with self.subTest(
                    targets=tuple(target.value for target in selected),
                    relative=relative,
                ):
                    with private_tempdir() as directory:
                        root = Path(directory)
                        repository = root / "repository"
                        shutil.copytree(
                            self.repository,
                            repository,
                            ignore=shutil.ignore_patterns(".git"),
                        )
                        (repository / relative).unlink()
                        homes = self._homes(root, selected)
                        for home in homes.values():
                            (home / "user.txt").write_bytes(b"keep\n")
                            (home / "user.txt").chmod(0o640)
                        with locked_target_homes(homes, selected):
                            before = {
                                target: tree_snapshot(home)
                                for target, home in homes.items()
                            }
                        status, output, error = self._run(
                            "install",
                            self._argv(selected, homes),
                            root,
                            repository=repository,
                        )
                        self.assertEqual(status, orchestrator.EXIT_BLOCKED_VALIDATION)
                        self.assertEqual(output, "")
                        self.assertEqual(
                            error,
                            "error: validation blocked: source validation failed\n",
                        )
                        for target, home in homes.items():
                            self.assertEqual(tree_snapshot(home), before[target])

            with self.subTest(
                targets=tuple(target.value for target in selected), state="journal"
            ):
                with private_tempdir() as directory:
                    root = Path(directory)
                    homes = self._homes(root, selected)
                    state = homes[late_target] / ".subagents_configs"
                    state.mkdir(mode=0o700)
                    journal = state / "journal.json"
                    journal.write_bytes(b"{}")
                    journal.chmod(0o600)
                    with locked_target_homes(homes, selected):
                        before = {
                            target: tree_snapshot(home)
                            for target, home in homes.items()
                        }
                    status, output, error = self._run(
                        "install", self._argv(selected, homes), root
                    )
                    self.assertEqual(status, orchestrator.EXIT_BLOCKED_VALIDATION)
                    self.assertEqual(output, "")
                    self.assertEqual(error, "error: recovery validation blocked\n")
                    for target, home in homes.items():
                        self.assertEqual(tree_snapshot(home), before[target])

        for selected in COMBINATIONS:
            with self.subTest(
                targets=tuple(target.value for target in selected), state="legacy"
            ):
                with private_tempdir() as directory:
                    root = Path(directory)
                    homes = self._homes(root, selected)
                    before = {}
                    for target, home in homes.items():
                        legacy_name = {
                            Target.CODEX: ".subagents_configs-state.json",
                            Target.OPENCODE: ".subagents_configs-opencode-state.json",
                            Target.CLAUDE_CODE: (
                                ".subagents_configs-claude-code-state.json"
                            ),
                        }[target]
                        legacy = home / legacy_name
                        legacy.write_bytes(b"legacy state\n")
                        legacy.chmod(0o600)
                    with locked_target_homes(homes, selected):
                        before = {
                            target: tree_snapshot(home)
                            for target, home in homes.items()
                        }
                    status, output, error = self._run(
                        "install", self._argv(selected, homes), root
                    )
                    self.assertEqual(status, orchestrator.EXIT_PREFLIGHT_ERROR)
                    self.assertEqual(output, "")
                    self.assertIn("preflight rejected", error)
                    for target, home in homes.items():
                        self.assertEqual(tree_snapshot(home), before[target])

            with self.subTest(
                targets=tuple(target.value for target in selected),
                state="contradictory",
            ):
                with private_tempdir() as directory:
                    root = Path(directory)
                    homes = self._homes(root, selected)
                    status, _output, error = self._run(
                        "install", self._argv(selected, homes), root
                    )
                    self.assertEqual(status, orchestrator.EXIT_SUCCESS, error)
                    contradictory_target = selected[-1]
                    manifest_path = (
                        homes[contradictory_target] / ".subagents_configs/manifest.json"
                    )
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["target"] = next(
                        target.value
                        for target in TARGETS
                        if target is not contradictory_target
                    )
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    manifest_path.chmod(0o600)
                    before = {
                        target: tree_snapshot(home) for target, home in homes.items()
                    }
                    status, output, error = self._run(
                        "install", self._argv(selected, homes), root
                    )
                    self.assertEqual(status, orchestrator.EXIT_BLOCKED_VALIDATION)
                    self.assertEqual(output, "")
                    self.assertEqual(error, "error: recovery validation blocked\n")
                    for target, home in homes.items():
                        self.assertEqual(tree_snapshot(home), before[target])

    def test_cross_target_pending_journal_recovery_requires_all_participants(self):
        for selected in COMBINATIONS:
            with self.subTest(targets=tuple(target.value for target in selected)):
                with private_tempdir() as directory:
                    root = Path(directory)
                    homes = self._homes(root, selected)
                    managed_contents = {}
                    for target, home in homes.items():
                        managed = home / descriptor_for(target).global_filename
                        content = (
                            f"recovery preexisting managed {target.value}\n".encode()
                        )
                        managed_contents[target] = content
                        managed.write_bytes(content)
                        managed.chmod(0o640)
                    initial_before = {
                        target: tree_snapshot(home) for target, home in homes.items()
                    }
                    recovery_plan = preflight_install(
                        self.repository,
                        planning_request(
                            "install",
                            homes,
                            targets=selected,
                            enable_global_routing=True,
                        ),
                    )
                    recovery_manifests = {
                        target_plan.target: target_plan.resulting_manifest
                        for target_plan in recovery_plan.targets
                    }
                    injector = _FailAt(1, homes)
                    real_cleanup = (
                        "subagents_configs.transaction._sync_and_remove_journal"
                    )
                    with patch(
                        real_cleanup,
                        side_effect=OSError("leave recovery evidence"),
                    ):
                        status, _output, error = self._run(
                            "install",
                            self._argv(selected, homes, "--enable-global-routing"),
                            root,
                            failure_injector=injector,
                        )
                    self.assertEqual(status, orchestrator.EXIT_INCOMPLETE_ROLLBACK)
                    original_journals = {
                        target: (home / ".subagents_configs/journal.json").read_bytes()
                        for target, home in homes.items()
                    }
                    original_modes = {
                        target: stat.S_IMODE(
                            (home / ".subagents_configs/journal.json").stat().st_mode
                        )
                        for target, home in homes.items()
                    }

                    disagreeing_target = selected[0]
                    disagreeing_path = (
                        homes[disagreeing_target] / ".subagents_configs/journal.json"
                    )
                    disagreeing = json.loads(original_journals[disagreeing_target])
                    if len(selected) == 1:
                        disagreeing["participants"] = []
                    elif len(selected) == len(TARGETS):
                        disagreeing["participants"] = [
                            target.value for target in reversed(selected)
                        ]
                    else:
                        disagreeing["participants"] = [selected[0].value]
                    disagreeing_path.write_text(
                        json.dumps(disagreeing), encoding="utf-8"
                    )
                    disagreeing_path.chmod(0o600)
                    before_disagreeing = {
                        target: tree_snapshot(home) for target, home in homes.items()
                    }
                    status, output, error = self._run(
                        "install", self._argv(selected, homes), root
                    )
                    self.assertEqual(status, orchestrator.EXIT_BLOCKED_VALIDATION)
                    self.assertEqual(output, "")
                    self.assertEqual(error, "error: recovery validation blocked\n")
                    for target, home in homes.items():
                        self.assertEqual(
                            tree_snapshot(home), before_disagreeing[target]
                        )

                    disagreeing_path.write_bytes(original_journals[disagreeing_target])
                    disagreeing_path.chmod(original_modes[disagreeing_target])
                    missing_target = selected[-1]
                    missing_path = (
                        homes[missing_target] / ".subagents_configs/journal.json"
                    )
                    if len(selected) == 1:
                        missing_payload = json.loads(original_journals[missing_target])
                        missing_payload["participants"] = [
                            selected[0].value,
                            next(
                                target for target in TARGETS if target not in selected
                            ).value,
                        ]
                        missing_path.write_text(
                            json.dumps(missing_payload), encoding="utf-8"
                        )
                        missing_path.chmod(0o600)
                    else:
                        missing_path.unlink()
                    before_missing = {
                        target: tree_snapshot(home) for target, home in homes.items()
                    }
                    status, output, error = self._run(
                        "install", self._argv(selected, homes), root
                    )
                    self.assertEqual(status, orchestrator.EXIT_BLOCKED_VALIDATION)
                    self.assertEqual(output, "")
                    self.assertEqual(error, "error: recovery validation blocked\n")
                    for target, home in homes.items():
                        self.assertEqual(tree_snapshot(home), before_missing[target])

                    missing_path.write_bytes(original_journals[missing_target])
                    missing_path.chmod(original_modes[missing_target])
                    before_recovery = {
                        target: tree_snapshot(home) for target, home in homes.items()
                    }
                    for target in selected:
                        self.assertIn(
                            ".subagents_configs/journal.json", before_recovery[target]
                        )
                    marker_evidence_by_target = (
                        self._expected_commitment_files_from_payloads(
                            injector.journal_payloads
                        )
                    )
                    permanent_evidence_by_target = {
                        target: self._permanent_backup_evidence(
                            recovery_manifests[target],
                            {
                                descriptor_for(
                                    target
                                ).global_filename: managed_contents[target]
                            },
                        )
                        for target in selected
                    }
                    transaction_backups_by_target = {
                        target: {
                            ".subagents_configs/" + operation["backup_path"]
                            for operation in injector.journal_payloads[target][
                                "operations"
                            ]
                            if operation["backup_path"] is not None
                        }
                        for target in selected
                    }
                    expected_recovery = {
                        target: dict(initial_before[target]) for target in selected
                    }
                    for target in selected:
                        expected_recovery[target].update(
                            {
                                ".subagents_configs.lock": ("file", 0o600, b""),
                                ".subagents_configs": ("directory", 0o700, None),
                                ".subagents_configs/backups": (
                                    "directory",
                                    0o700,
                                    None,
                                ),
                                ".subagents_configs/validation": (
                                    "directory",
                                    0o700,
                                    None,
                                ),
                                ".subagents_configs/validation/validation_isolation": (
                                    "directory",
                                    0o700,
                                    None,
                                ),
                                "agents": ("directory", 0o700, None),
                            }
                        )
                        expected_recovery[target].update(
                            {
                                relative: ("file", mode, content)
                                for relative, (content, mode) in (
                                    marker_evidence_by_target[target]
                                    | permanent_evidence_by_target[target]
                                ).items()
                            }
                        )
                        expected_recovery[target].pop(
                            ".subagents_configs/journal.json", None
                        )
                        for relative in transaction_backups_by_target[target]:
                            expected_recovery[target].pop(relative, None)
                    groups = orchestrator._journal_groups(
                        planning_request(
                            "install",
                            homes,
                            targets=selected,
                            enable_global_routing=True,
                        )
                    )
                    orchestrator._recover_groups(groups)
                    for target, home in homes.items():
                        self.assertEqual(tree_snapshot(home), expected_recovery[target])
                        self._assert_exact_evidence(
                            home,
                            marker_evidence_by_target[target],
                            commitment=True,
                        )
                        self._assert_exact_evidence(
                            home, permanent_evidence_by_target[target]
                        )
                        self.assertFalse(
                            (home / ".subagents_configs/journal.json").exists()
                        )
                        for relative in transaction_backups_by_target[target]:
                            self.assertFalse((home / relative).exists())
                    status, output, error = self._run(
                        "install",
                        self._argv(selected, homes, "--enable-global-routing"),
                        root,
                    )
                    self.assertEqual(status, orchestrator.EXIT_SUCCESS, error)
                    self.assertTrue(output)
                    self.assertEqual(error, "")
                    for home in homes.values():
                        self.assertFalse(
                            (home / ".subagents_configs/journal.json").exists()
                        )


if __name__ == "__main__":
    unittest.main()
