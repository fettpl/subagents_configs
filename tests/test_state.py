import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from subagents_configs.models import (
    Journal,
    JournalOperation,
    Manifest,
    ManifestEntry,
    SourceSpec,
    Target,
)
from subagents_configs.targets import descriptor_for


class StateTests(unittest.TestCase):
    _TEMP_DIR = "/private/tmp" if Path("/private/tmp").is_dir() else None

    def _entry(self, **overrides):
        value = {
            "identifier": "code-explorer",
            "relative_path": "agents/code-explorer.toml",
            "installed_hash": "a" * 64,
            "installed_mode": 0o600,
            "ownership": "created",
            "backup_path": None,
            "backup_hash": None,
            "original_mode": None,
            "managed_block_id": None,
            "installed_block_hash": None,
            "unresolved_reason": None,
        }
        value.update(overrides)
        return value

    def _manifest(self, **entry_overrides):
        return {
            "schema_version": 2,
            "target": "codex",
            "entries": [self._entry(**entry_overrides)],
        }

    def test_manifest_round_trip_is_deterministic_and_metadata_only(self):
        from subagents_configs.state import decode_manifest, encode_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            manifest = decode_manifest(self._manifest(), descriptor, Path(temporary))
            encoded = encode_manifest(manifest)
        self.assertEqual(encoded, encode_manifest(manifest))
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertNotIn(b"before", encoded)
        self.assertNotIn(b"content", encoded)
        self.assertNotIn(b"base64", encoded)
        self.assertNotIn(b"private prior bytes", encoded)
        self.assertEqual(json.loads(encoded), self._manifest())

    def test_v1_requires_explicit_manifest_migration_and_legacy_journal_inspection(
        self,
    ):
        from subagents_configs.state import (
            decode_journal,
            decode_manifest,
            inspect_legacy_journal,
            migrate_manifest_schema,
        )

        descriptor = descriptor_for(Target.CODEX)
        legacy_manifest = {
            "schema_version": 1,
            "target": "codex",
            "entries": [],
        }
        legacy_journal = self._journal_raw("create", self._journal_operation("create"))
        legacy_journal["schema_version"] = 1
        legacy_journal["rollback_status"] = "complete"
        legacy_journal["operations"][0]["status"] = "applied"
        legacy_journal["operations"][0].pop("expected_before_evidence")
        legacy_journal["operations"][0].pop("expected_after_evidence")
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                decode_manifest(legacy_manifest, descriptor, root)
            with self.assertRaises(ValueError):
                decode_journal(legacy_journal, descriptor, root)
            self.assertEqual(
                migrate_manifest_schema(
                    legacy_manifest, descriptor, root
                ).schema_version,
                2,
            )
            evidence = inspect_legacy_journal(legacy_journal, descriptor, root)
            self.assertEqual(evidence.operation_count, 1)

    def test_manifest_rejects_unknown_fields_and_duplicate_identifiers(self):
        from subagents_configs.state import decode_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            with self.assertRaises(ValueError):
                decode_manifest(
                    {**self._manifest(), "unexpected": True},
                    descriptor,
                    Path(temporary),
                )
            duplicate = self._manifest()
            duplicate["entries"].append(self._entry(relative_path="agents/other.toml"))
            with self.assertRaises(ValueError):
                decode_manifest(duplicate, descriptor, Path(temporary))

    def test_manifest_rejects_unsafe_paths_modes_and_target(self):
        from subagents_configs.state import decode_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            for changes in (
                {"relative_path": "/outside/escape"},
                {"relative_path": "agents/../escape"},
                {"installed_mode": True},
                {"installed_mode": 0o644},
                {"target": "opencode"},
            ):
                raw = self._manifest()
                raw.update({k: v for k, v in changes.items() if k == "target"})
                raw["entries"][0].update(
                    {k: v for k, v in changes.items() if k != "target"}
                )
                with self.assertRaises(ValueError):
                    decode_manifest(raw, descriptor, Path(temporary))

    def test_replaced_entry_requires_verified_backup_and_original_mode(self):
        from subagents_configs.state import decode_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            backup = root / ".subagents_configs" / "backups" / "old"
            backup.parent.mkdir(parents=True, mode=0o700)
            backup.write_bytes(b"old bytes")
            backup.chmod(0o600)
            digest = hashlib.sha256(b"old bytes").hexdigest()
            raw = self._manifest(
                ownership="replaced",
                backup_path="backups/old",
                backup_hash=digest,
                original_mode=0o644,
            )
            from subagents_configs.state import decode_manifest

            manifest = decode_manifest(raw, descriptor, root)
            self.assertEqual(manifest.entries[0].backup_hash, digest)
            for changes in (
                {"backup_path": "backups/old", "backup_hash": None},
                {"backup_path": None, "backup_hash": digest},
                {"backup_path": "backups/missing", "backup_hash": digest},
                {"backup_path": "backups/old", "backup_hash": "b" * 64},
                {"original_mode": None},
            ):
                invalid = self._manifest(
                    ownership="replaced",
                    backup_path="backups/old",
                    backup_hash=digest,
                    original_mode=0o644,
                )
                invalid["entries"][0].update(changes)
                with self.assertRaises(ValueError):
                    decode_manifest(invalid, descriptor, root)

    def test_load_manifest_rejects_symlinked_state_and_returns_none_only_without_state(
        self,
    ):
        from subagents_configs.state import load_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            self.assertIsNone(load_manifest(root, descriptor))
            state = root / ".subagents_configs"
            outside = root / "outside"
            outside.mkdir()
            state.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                load_manifest(root, descriptor)

    def test_journal_round_trip_and_participant_validation(self):
        from subagents_configs.state import decode_journal, encode_journal

        descriptor = descriptor_for(Target.CODEX)
        raw = {
            "schema_version": 2,
            "transaction_id": "tx-1",
            "target": "codex",
            "participants": ["codex", "opencode"],
            "operation": "install",
            "operations": [
                {
                    "operation_id": "op-1",
                    "identifier": "state/manifest",
                    "action": "write-manifest",
                    "expected_before_hash": "a" * 64,
                    "expected_after_hash": "a" * 64,
                    "expected_before_mode": 0o600,
                    "expected_after_mode": 0o600,
                    "backup_path": None,
                    "backup_hash": None,
                    "status": "planned",
                    "expected_before_evidence": {
                        "device": 1,
                        "inode": 1,
                        "size": 1,
                        "nlink": 1,
                        "mode": 0o600,
                        "sha256": "a" * 64,
                    },
                    "expected_after_evidence": {
                        "device": 1,
                        "inode": 1,
                        "size": 1,
                        "nlink": 1,
                        "mode": 0o600,
                        "sha256": "a" * 64,
                    },
                }
            ],
            "rollback_status": "not-started",
        }
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            journal = decode_journal(raw, descriptor, Path(temporary))
        self.assertEqual(json.loads(encode_journal(journal)), raw)
        for changes in (
            {"participants": ["opencode"]},
            {"participants": ["codex", "codex"]},
            {"operations": [{**raw["operations"][0], "action": "chmod"}]},
            {"operations": [{**raw["operations"][0], "identifier": "unknown"}]},
        ):
            invalid = {**raw, **changes}
            with tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(ValueError):
                    decode_journal(invalid, descriptor, Path(temporary))

    def test_encoders_reject_invalid_constructed_dataclasses(self):
        from subagents_configs.state import encode_journal, encode_manifest

        invalid_entry = ManifestEntry(
            identifier="bogus",
            relative_path="../../escape",
            installed_hash="not-a-hash",
            installed_mode=True,
            ownership="created",
            backup_path=None,
            backup_hash=None,
            original_mode=None,
            managed_block_id=None,
            installed_block_hash=None,
            unresolved_reason=None,
        )
        invalid_manifest = Manifest(2, Target.CODEX, (invalid_entry,))
        with self.assertRaises(ValueError):
            encode_manifest(invalid_manifest)

        invalid_operation = JournalOperation(
            operation_id="bad id",
            identifier="unknown",
            action="chmod",
            expected_before_hash="not-a-hash",
            expected_after_hash=None,
            expected_before_mode=True,
            expected_after_mode=0o644,
            backup_path="../outside",
            backup_hash=None,
            status="finished",
        )
        invalid_journal = Journal(
            1,
            "bad/transaction",
            Target.CODEX,
            (Target.CODEX, Target.CODEX),
            "install",
            (invalid_operation,),
            "not-started",
        )
        with self.assertRaises(ValueError):
            encode_journal(invalid_journal)

    def test_journal_action_matrix_enforces_rollback_evidence(self):
        from subagents_configs.state import decode_journal

        digest = "b" * 64
        reverse_hash = hashlib.sha256(b"old").hexdigest()
        operations = {
            "create": {
                "identifier": "code-explorer",
                "expected_before_hash": None,
                "expected_after_hash": digest,
                "expected_before_mode": None,
                "expected_after_mode": 0o600,
                "backup_path": None,
                "backup_hash": None,
            },
            "replace": {
                "identifier": "code-explorer",
                "expected_before_hash": reverse_hash,
                "expected_after_hash": digest,
                "expected_before_mode": 0o644,
                "expected_after_mode": 0o600,
                "backup_path": "backups/old",
                "backup_hash": digest,
            },
            "remove": {
                "identifier": "code-explorer",
                "expected_before_hash": reverse_hash,
                "expected_after_hash": None,
                "expected_before_mode": 0o600,
                "expected_after_mode": None,
                "backup_path": "backups/old",
                "backup_hash": digest,
            },
            "restore": {
                "identifier": "code-explorer",
                "expected_before_hash": reverse_hash,
                "expected_after_hash": digest,
                "expected_before_mode": 0o600,
                "expected_after_mode": 0o644,
                "backup_path": "backups/old",
                "backup_hash": digest,
            },
            "write-block": {
                "identifier": "routing-codex",
                "expected_before_hash": digest,
                "expected_after_hash": digest,
                "expected_before_mode": 0o600,
                "expected_after_mode": 0o600,
                "backup_path": None,
                "backup_hash": None,
            },
            "remove-block": {
                "identifier": "routing-codex",
                "expected_before_hash": digest,
                "expected_after_hash": digest,
                "expected_before_mode": 0o600,
                "expected_after_mode": 0o600,
                "backup_path": None,
                "backup_hash": None,
            },
            "write-manifest": {
                "identifier": "state/manifest",
                "expected_before_hash": digest,
                "expected_after_hash": digest,
                "expected_before_mode": 0o600,
                "expected_after_mode": 0o600,
                "backup_path": None,
                "backup_hash": None,
            },
        }
        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            backup = root / ".subagents_configs" / "backups" / "old"
            backup.parent.mkdir(parents=True, mode=0o700)
            backup.write_bytes(b"old")
            backup.chmod(0o600)
            valid_backup_hash = reverse_hash
            for action, operation in operations.items():
                operation = {**operation, "status": "planned"}
                if operation["backup_path"] is not None:
                    operation["backup_hash"] = valid_backup_hash
                raw = self._journal_raw(action, operation)
                decoded = decode_journal(raw, descriptor, root)
                self.assertEqual(decoded.operations[0].action, action)

            invalid_cases = {
                "create": {"expected_before_hash": "a" * 64},
                "replace": {"backup_path": None, "backup_hash": None},
                "remove": {"expected_after_mode": 0o600},
                "restore": {"backup_path": None, "backup_hash": None},
                "write-block": {"expected_before_mode": None},
                "remove-block": {"expected_after_hash": None},
                "write-manifest": {"backup_path": "backups/old"},
            }
            for action, changes in invalid_cases.items():
                operation = {**operations[action], **changes}
                raw = self._journal_raw(action, operation)
                with self.assertRaises(ValueError):
                    decode_journal(raw, descriptor, root)

    def test_manifest_and_block_journal_lifecycles_allow_absent_sides(self):
        from subagents_configs.state import decode_journal

        descriptor = descriptor_for(Target.CODEX)
        lifecycle_bytes = b"lifecycle before"
        digest = hashlib.sha256(lifecycle_bytes).hexdigest()
        cases = (
            ("write-manifest", "state/manifest", None, digest, None, 0o600),
            ("write-manifest", "state/manifest", digest, digest, 0o600, 0o600),
            ("write-manifest", "state/manifest", digest, None, 0o600, None),
            ("write-block", "routing-codex", None, digest, None, 0o600),
            ("write-block", "routing-codex", digest, digest, 0o600, 0o600),
            ("remove-block", "routing-codex", digest, digest, 0o600, 0o600),
            ("remove-block", "routing-codex", digest, None, 0o600, None),
        )
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            reverse_backup = root / ".subagents_configs" / "backups" / "manifest"
            reverse_backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            reverse_backup.write_bytes(lifecycle_bytes)
            reverse_backup.chmod(0o600)
            for action, identifier, before, after, before_mode, after_mode in cases:
                operation = self._operation(
                    action,
                    identifier,
                    before,
                    after,
                    before_mode,
                    after_mode,
                )
                journal = self._journal_raw(action, operation)
                if action == "remove-block" and after is None:
                    backup = root / ".subagents_configs" / "backups" / "block"
                    backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    backup.write_bytes(lifecycle_bytes)
                    backup.chmod(0o600)
                    operation.update(
                        backup_path="backups/block",
                        backup_hash=hashlib.sha256(lifecycle_bytes).hexdigest(),
                    )
                    journal = self._journal_raw(action, operation)
                if action == "write-manifest" and before is not None and after is None:
                    operation.update(
                        backup_path="backups/manifest",
                        backup_hash=hashlib.sha256(lifecycle_bytes).hexdigest(),
                    )
                    journal = self._journal_raw(action, operation)
                self.assertEqual(
                    decode_journal(journal, descriptor, root).operations[0].action,
                    action,
                )
            invalid = self._journal_raw(
                "write-manifest",
                self._operation(
                    "write-manifest", "state/manifest", None, None, None, None
                ),
            )
            with self.assertRaises(ValueError):
                decode_journal(invalid, descriptor, root)

    def test_mutating_journal_operations_require_reverse_backup_evidence(self):
        from subagents_configs.state import decode_journal

        descriptor = descriptor_for(Target.CODEX)
        backup_bytes = b"actual before bytes"
        digest_before = hashlib.sha256(backup_bytes).hexdigest()
        digest_after = "b" * 64
        backup_hash = hashlib.sha256(backup_bytes).hexdigest()
        cases = (
            (
                "write-manifest",
                "state/manifest",
                None,
                digest_after,
                None,
                0o600,
                False,
                True,
            ),
            (
                "write-manifest",
                "state/manifest",
                digest_before,
                digest_before,
                0o600,
                0o600,
                False,
                True,
            ),
            (
                "write-manifest",
                "state/manifest",
                digest_before,
                digest_after,
                0o600,
                0o600,
                False,
                False,
            ),
            (
                "write-manifest",
                "state/manifest",
                digest_before,
                None,
                0o600,
                None,
                False,
                False,
            ),
            (
                "write-block",
                "routing-codex",
                None,
                digest_after,
                None,
                0o600,
                False,
                True,
            ),
            (
                "write-block",
                "routing-codex",
                digest_before,
                digest_before,
                0o600,
                0o600,
                False,
                True,
            ),
            (
                "write-block",
                "routing-codex",
                digest_before,
                digest_after,
                0o600,
                0o600,
                False,
                False,
            ),
            (
                "remove-block",
                "routing-codex",
                digest_before,
                digest_before,
                0o600,
                0o600,
                False,
                True,
            ),
            (
                "remove-block",
                "routing-codex",
                digest_before,
                digest_after,
                0o600,
                0o600,
                False,
                False,
            ),
            (
                "remove-block",
                "routing-codex",
                digest_before,
                None,
                0o600,
                None,
                False,
                False,
            ),
            ("remove", "code-explorer", digest_before, None, 0o600, None, False, False),
        )
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            backup = root / ".subagents_configs" / "backups" / "reverse"
            backup.parent.mkdir(parents=True, mode=0o700)
            backup.write_bytes(backup_bytes)
            backup.chmod(0o600)
            for (
                action,
                identifier,
                before,
                after,
                before_mode,
                after_mode,
                with_backup,
                valid,
            ) in cases:
                operation = self._operation(
                    action,
                    identifier,
                    before,
                    after,
                    before_mode,
                    after_mode,
                )
                if with_backup:
                    operation.update(
                        backup_path="backups/reverse", backup_hash=backup_hash
                    )
                raw = self._journal_raw(action, operation)
                if valid:
                    decode_journal(raw, descriptor, root)
                else:
                    with self.assertRaises(ValueError):
                        decode_journal(raw, descriptor, root)

            for action, identifier, before, after, before_mode, after_mode in (
                (
                    "write-manifest",
                    "state/manifest",
                    digest_before,
                    digest_after,
                    0o600,
                    0o600,
                ),
                (
                    "write-block",
                    "routing-codex",
                    digest_before,
                    digest_after,
                    0o600,
                    0o600,
                ),
                ("remove-block", "routing-codex", digest_before, None, 0o600, None),
                ("remove", "code-explorer", digest_before, None, 0o600, None),
            ):
                operation = self._operation(
                    action,
                    identifier,
                    before,
                    after,
                    before_mode,
                    after_mode,
                )
                operation.update(backup_path="backups/reverse", backup_hash=backup_hash)
                decode_journal(self._journal_raw(action, operation), descriptor, root)

    def test_required_reverse_backup_hash_matches_expected_before_hash(self):
        from subagents_configs.state import decode_journal

        descriptor = descriptor_for(Target.CODEX)
        before_bytes = b"actual before bytes"
        unrelated_bytes = b"different file bytes"
        before_hash = hashlib.sha256(before_bytes).hexdigest()
        unrelated_hash = hashlib.sha256(unrelated_bytes).hexdigest()
        cases = (
            ("replace", "code-explorer", before_hash, "b" * 64, 0o600, 0o600),
            ("remove", "code-explorer", before_hash, None, 0o600, None),
            ("restore", "code-explorer", before_hash, "b" * 64, 0o600, 0o644),
            ("write-block", "routing-codex", before_hash, "b" * 64, 0o600, 0o600),
            ("remove-block", "routing-codex", before_hash, "b" * 64, 0o600, 0o600),
            ("remove-block", "routing-codex", before_hash, None, 0o600, None),
            ("write-manifest", "state/manifest", before_hash, "b" * 64, 0o600, 0o600),
            ("write-manifest", "state/manifest", before_hash, None, 0o600, None),
        )
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            backups = root / ".subagents_configs" / "backups"
            backups.mkdir(parents=True, mode=0o700)
            matching = backups / "matching"
            matching.write_bytes(before_bytes)
            matching.chmod(0o600)
            mismatch = backups / "mismatch"
            mismatch.write_bytes(unrelated_bytes)
            mismatch.chmod(0o600)
            for action, identifier, before, after, before_mode, after_mode in cases:
                for backup_name, backup_hash, expected in (
                    ("matching", before_hash, True),
                    ("mismatch", unrelated_hash, False),
                ):
                    operation = self._operation(
                        action,
                        identifier,
                        before,
                        after,
                        before_mode,
                        after_mode,
                    )
                    operation.update(
                        backup_path=f"backups/{backup_name}",
                        backup_hash=backup_hash,
                    )
                    raw = self._journal_raw(action, operation)
                    if expected:
                        decode_journal(raw, descriptor, root)
                    else:
                        with self.assertRaises(ValueError):
                            decode_journal(raw, descriptor, root)

    def test_write_block_requires_present_after_state(self):
        from subagents_configs.state import decode_journal

        descriptor = descriptor_for(Target.CODEX)
        before_bytes = b"existing block file"
        before_hash = hashlib.sha256(before_bytes).hexdigest()
        cases = (
            self._operation("write-block", "routing-codex", None, None, None, None),
            {
                **self._operation(
                    "write-block", "routing-codex", before_hash, None, 0o600, None
                ),
                "backup_path": "backups/before-block",
                "backup_hash": before_hash,
            },
        )
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            backup = root / ".subagents_configs" / "backups" / "before-block"
            backup.parent.mkdir(parents=True, mode=0o700)
            backup.write_bytes(before_bytes)
            backup.chmod(0o600)
            for operation in cases:
                with self.assertRaises(ValueError):
                    decode_journal(
                        self._journal_raw("write-block", operation), descriptor, root
                    )

    def test_nested_backup_paths_are_rejected_even_when_parents_are_private(self):
        from subagents_configs.state import decode_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            nested = root / ".subagents_configs" / "backups" / "nested"
            nested.mkdir(parents=True, mode=0o700)
            backup = nested / "old"
            backup.write_bytes(b"old")
            backup.chmod(0o600)
            raw = self._manifest(
                ownership="replaced",
                backup_path="backups/nested/old",
                backup_hash=hashlib.sha256(b"old").hexdigest(),
                original_mode=0o644,
            )
            with self.assertRaises(ValueError):
                decode_manifest(raw, descriptor, root)

    def test_state_parent_swap_after_inventory_reads_only_pinned_directory(self):
        from subagents_configs.state import encode_manifest, load_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            state = root / ".subagents_configs"
            state.mkdir(mode=0o700)
            (state / "manifest.json").write_bytes(
                encode_manifest(Manifest(2, Target.CODEX, tuple()))
            )
            (state / "manifest.json").chmod(0o600)
            alternate = root / "alternate"
            alternate.mkdir(mode=0o700)
            alternate_manifest = alternate / "manifest.json"
            alternate_entry = ManifestEntry(**self._entry())
            alternate_manifest.write_bytes(
                encode_manifest(
                    Manifest(
                        2,
                        Target.CODEX,
                        (alternate_entry,),
                    )
                )
            )
            alternate_manifest.chmod(0o600)
            swapped = False

            def swap_after_inventory(operation, parent):
                nonlocal swapped
                if operation == "state-inventory" and not swapped:
                    state.rename(root / "detached-state")
                    state.symlink_to(alternate, target_is_directory=True)
                    swapped = True

            with patch(
                "subagents_configs.filesystem._after_parent_pin",
                swap_after_inventory,
            ):
                try:
                    loaded = load_manifest(root, descriptor)
                except ValueError:
                    loaded = None
            self.assertTrue(swapped)
            self.assertTrue(loaded is None or loaded.entries == tuple())

    def test_ownership_rules_cover_created_preexisting_and_replaced_blocks(self):
        from subagents_configs.state import decode_manifest

        descriptor = descriptor_for(Target.CODEX)
        block_hash = "b" * 64
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            backups = root / ".subagents_configs" / "backups"
            backups.mkdir(parents=True, mode=0o700)
            (backups / "old").write_bytes(b"old")
            (backups / "old").chmod(0o600)
            backup_hash = hashlib.sha256(b"old").hexdigest()

            self.assertEqual(
                decode_manifest(self._manifest(ownership="created"), descriptor, root)
                .entries[0]
                .original_mode,
                None,
            )
            for changes in (
                {"ownership": "created", "original_mode": 0o644},
                {
                    "ownership": "created",
                    "managed_block_id": "routing-codex",
                    "installed_block_hash": block_hash,
                    "original_mode": 0o644,
                },
                {"ownership": "preexisting", "original_mode": 0o644},
            ):
                with self.assertRaises(ValueError):
                    decode_manifest(self._manifest(**changes), descriptor, root)

            preexisting_block = self._manifest(
                identifier="routing-codex",
                relative_path="AGENTS.md",
                ownership="preexisting",
                original_mode=0o644,
                managed_block_id="routing-codex",
                installed_block_hash=block_hash,
            )
            self.assertEqual(
                decode_manifest(preexisting_block, descriptor, root)
                .entries[0]
                .ownership,
                "preexisting",
            )
            replaced_block = self._manifest(
                identifier="routing-codex",
                relative_path="AGENTS.md",
                ownership="replaced",
                original_mode=0o644,
                managed_block_id="routing-codex",
                installed_block_hash=block_hash,
                backup_path="backups/old",
                backup_hash=backup_hash,
            )
            self.assertEqual(
                decode_manifest(replaced_block, descriptor, root).entries[0].ownership,
                "replaced",
            )

    def test_validation_runtime_subtree_and_retained_backups_are_inventory_safe(self):
        from subagents_configs.state import encode_manifest, load_manifest

        descriptor = descriptor_for(Target.CODEX)
        runtime = next(
            source.destination
            for source in descriptor.sources
            if source.kind == "validation-runtime"
        )
        assert runtime is not None
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            state = root / ".subagents_configs"
            state.mkdir(mode=0o700)
            (state / "manifest.json").write_bytes(
                encode_manifest(Manifest(2, Target.CODEX, tuple()))
            )
            (state / "manifest.json").chmod(0o600)
            relative_runtime = Path(*runtime.parts[1:])
            runtime_file = state / relative_runtime
            runtime_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            runtime_file.write_bytes(b"runtime")
            runtime_file.chmod(0o600)
            retained = state / "backups" / "unreferenced"
            retained.parent.mkdir(mode=0o700)
            retained.write_bytes(b"retained")
            retained.chmod(0o600)
            self.assertIsNotNone(load_manifest(root, descriptor))
            (state / "validation" / "unknown.py").write_bytes(b"unknown")
            (state / "validation" / "unknown.py").chmod(0o600)
            with self.assertRaises(ValueError):
                load_manifest(root, descriptor)

    def test_state_and_backup_files_enforce_0600_ceiling(self):
        from subagents_configs.state import (
            decode_manifest,
            encode_manifest,
            load_manifest,
        )

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            state = root / ".subagents_configs"
            state.mkdir(mode=0o700)
            manifest_path = state / "manifest.json"
            manifest_path.write_bytes(
                encode_manifest(Manifest(2, Target.CODEX, tuple()))
            )
            manifest_path.chmod(0o700)
            with self.assertRaises(ValueError):
                load_manifest(root, descriptor)
            backups = state / "backups"
            backups.mkdir(mode=0o700)
            backup = backups / "old"
            backup.write_bytes(b"old")
            backup.chmod(0o700)
            raw = self._manifest(
                ownership="replaced",
                backup_path="backups/old",
                backup_hash=hashlib.sha256(b"old").hexdigest(),
                original_mode=0o644,
            )
            with self.assertRaises(ValueError):
                decode_manifest(raw, descriptor, root)

    def test_repeated_descriptor_identifier_and_destination_records_fail(self):
        from subagents_configs.state import decode_manifest

        descriptor = descriptor_for(Target.CODEX)
        duplicate = descriptor.sources[0]
        malicious = replace(descriptor, sources=(*descriptor.sources, duplicate))
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            with self.assertRaises(ValueError):
                decode_manifest(self._manifest(), malicious, Path(temporary))

    def test_inventory_parent_swap_uses_descriptor_relative_backup_fd(self):
        from subagents_configs.state import encode_manifest, load_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            state = root / ".subagents_configs"
            state.mkdir(mode=0o700)
            (state / "manifest.json").write_bytes(
                encode_manifest(Manifest(2, Target.CODEX, tuple()))
            )
            (state / "manifest.json").chmod(0o600)
            backups = state / "backups"
            backups.mkdir(mode=0o700)
            (backups / "kept").write_bytes(b"kept")
            (backups / "kept").chmod(0o600)
            outside = root / "outside"
            outside.mkdir()
            (outside / "unknown").write_bytes(b"must not be inspected")
            detached = root / "detached"
            swapped = False

            def swap_after_pin(operation, parent):
                nonlocal swapped
                if operation == "state-inventory-backups" and not swapped:
                    backups.rename(detached)
                    backups.symlink_to(outside, target_is_directory=True)
                    swapped = True

            with patch(
                "subagents_configs.filesystem._after_parent_pin",
                swap_after_pin,
            ):
                self.assertIsNotNone(load_manifest(root, descriptor))
            self.assertTrue(swapped)
            self.assertEqual(
                (outside / "unknown").read_bytes(), b"must not be inspected"
            )

    def test_state_and_operation_ids_use_safe_ascii_grammar(self):
        from subagents_configs.state import decode_journal

        descriptor = descriptor_for(Target.CODEX)
        operation = self._journal_operation("create")
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            for identifier in ("", "a/b", "a b", "a\n", "é", "a" * 129):
                raw = self._journal_raw(
                    "create", {**operation, "operation_id": identifier}
                )
                with self.assertRaises(ValueError):
                    decode_journal(raw, descriptor, Path(temporary))
            for transaction_id in ("", "a/b", "a b", "a\t", "é", "a" * 129):
                raw = self._journal_raw("create", operation)
                raw["transaction_id"] = transaction_id
                with self.assertRaises(ValueError):
                    decode_journal(raw, descriptor, Path(temporary))

    def test_aliases_cannot_duplicate_canonical_destinations_or_descriptor_aliases(
        self,
    ):
        from subagents_configs.state import decode_journal, decode_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            duplicate = self._manifest()
            duplicate["entries"].append(
                self._entry(identifier="agents/code-explorer.toml")
            )
            with self.assertRaises(ValueError):
                decode_manifest(duplicate, descriptor, root)

            journal = self._journal_raw("create", self._journal_operation("create"))
            journal["operations"].append(
                {
                    **journal["operations"][0],
                    "operation_id": "op-2",
                    "identifier": "agents/code-explorer.toml",
                }
            )
            with self.assertRaises(ValueError):
                decode_journal(journal, descriptor, root)

            colliding = replace(
                descriptor,
                sources=(
                    *descriptor.sources,
                    SourceSpec(
                        identifier="alias",
                        source=PurePosixPath("agents/code-explorer.toml"),
                        destination=PurePosixPath("agents/code-explorer.toml"),
                        kind="agent",
                        source_format="toml",
                    ),
                ),
            )
            with self.assertRaises(ValueError):
                decode_manifest(self._manifest(), colliding, root)

    def test_loader_inventories_both_state_files_and_rejects_unknown_or_duplicate_keys(
        self,
    ):
        from subagents_configs.state import encode_manifest, load_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            state = root / ".subagents_configs"
            state.mkdir(mode=0o700)
            (state / "manifest.json").write_bytes(
                encode_manifest(
                    Manifest(
                        2,
                        Target.CODEX,
                        tuple(),
                    )
                )
            )
            (state / "manifest.json").chmod(0o600)
            (state / "extra").write_bytes(b"unknown")
            with self.assertRaises(ValueError):
                load_manifest(root, descriptor)
            (state / "extra").unlink()
            (state / "journal.json").write_bytes(b'{"schema_version": 1,}')
            (state / "journal.json").chmod(0o600)
            with self.assertRaises(ValueError):
                load_manifest(root, descriptor)
            (state / "journal.json").write_bytes(
                b'{"schema_version":1,"schema_version":1,"target":"codex","entries":[]}'
            )
            with self.assertRaises(ValueError):
                load_manifest(root, descriptor)

    def test_rejects_symlinked_backup_reference(self):
        from subagents_configs.state import decode_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            state = root / ".subagents_configs"
            state.mkdir(mode=0o700)
            backups = state / "backups"
            backups.mkdir(mode=0o700)
            outside = root / "outside"
            outside.write_bytes(b"secret")
            (backups / "old").symlink_to(outside)
            raw = self._manifest(
                ownership="replaced",
                backup_path="backups/old",
                backup_hash=hashlib.sha256(b"secret").hexdigest(),
                original_mode=0o644,
            )
            with self.assertRaises(ValueError):
                decode_manifest(raw, descriptor, root)

    def test_backup_hash_read_stays_on_pinned_parent_after_swap(self):
        from subagents_configs.state import decode_manifest

        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir=self._TEMP_DIR) as temporary:
            root = Path(temporary)
            state = root / ".subagents_configs"
            state.mkdir(mode=0o700)
            backups = state / "backups"
            backups.mkdir(mode=0o700)
            (backups / "old").write_bytes(b"inside backup")
            (backups / "old").chmod(0o600)
            outside = root / "outside"
            outside.mkdir()
            (outside / "old").write_bytes(b"outside backup")
            detached = root / "detached"
            swapped = False

            def swap_after_pin(operation, parent):
                nonlocal swapped
                if parent == backups and not swapped:
                    backups.rename(detached)
                    backups.symlink_to(outside, target_is_directory=True)
                    swapped = True

            raw = self._manifest(
                ownership="replaced",
                backup_path="backups/old",
                backup_hash=hashlib.sha256(b"inside backup").hexdigest(),
                original_mode=0o644,
            )
            with patch(
                "subagents_configs.filesystem._after_parent_pin",
                swap_after_pin,
            ):
                decoded = decode_manifest(raw, descriptor, root)
            self.assertEqual(
                decoded.entries[0].backup_hash,
                raw["entries"][0]["backup_hash"],
            )
            self.assertEqual((outside / "old").read_bytes(), b"outside backup")

    def _journal_operation(self, action):
        digest = "b" * 64
        identifier = "routing-codex" if "block" in action else "state/manifest"
        if action in {"create", "remove"}:
            identifier = "code-explorer"
        before_hash = None if action == "create" else "a" * 64
        after_hash = None if action == "remove" else digest
        return {
            "operation_id": "op-1",
            "identifier": identifier,
            "action": action,
            "expected_before_hash": before_hash,
            "expected_after_hash": after_hash,
            "expected_before_mode": None if action == "create" else 0o600,
            "expected_after_mode": None if action == "remove" else 0o600,
            "backup_path": None,
            "backup_hash": None,
            "status": "planned",
            "expected_before_evidence": self._evidence(
                before_hash, None if action == "create" else 0o600
            ),
            "expected_after_evidence": self._evidence(
                after_hash, None if action == "remove" else 0o600
            ),
        }

    @staticmethod
    def _evidence(digest, mode=0o600):
        if digest is None:
            return None
        return {
            "device": 1,
            "inode": 1,
            "size": 1,
            "nlink": 1,
            "mode": mode,
            "sha256": digest,
        }

    def _operation(
        self,
        action,
        identifier,
        before_hash,
        after_hash,
        before_mode,
        after_mode,
    ):
        return {
            "operation_id": "op-1",
            "identifier": identifier,
            "action": action,
            "expected_before_hash": before_hash,
            "expected_after_hash": after_hash,
            "expected_before_mode": before_mode,
            "expected_after_mode": after_mode,
            "backup_path": None,
            "backup_hash": None,
            "status": "planned",
            "expected_before_evidence": self._evidence(before_hash, before_mode),
            "expected_after_evidence": self._evidence(after_hash, after_mode),
        }

    def _journal_raw(self, action, operation):
        operation = {
            **operation,
            "expected_before_evidence": self._evidence(
                operation.get("expected_before_hash"),
                operation.get("expected_before_mode", 0o600),
            ),
            "expected_after_evidence": self._evidence(
                operation.get("expected_after_hash"),
                operation.get("expected_after_mode", 0o600),
            ),
        }
        return {
            "schema_version": 2,
            "transaction_id": "tx-1",
            "target": "codex",
            "participants": ["codex"],
            "operation": "install",
            "operations": [
                {
                    **operation,
                    "operation_id": operation.get("operation_id", "op-1"),
                    "action": action,
                }
            ],
            "rollback_status": "not-started",
        }


if __name__ == "__main__":
    unittest.main()
