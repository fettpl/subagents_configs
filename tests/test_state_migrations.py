import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from subagents_configs.models import Target
from subagents_configs.state import (
    decode_journal,
    decode_manifest,
    encode_journal,
    inspect_legacy_journal,
    migrate_manifest_schema,
)
from subagents_configs.targets import descriptor_for


class StateMigrationTests(unittest.TestCase):
    @staticmethod
    def _v2_journal():
        evidence = {
            "device": 1,
            "inode": 2,
            "size": 3,
            "nlink": 1,
            "mode": 0o600,
            "sha256": "a" * 64,
        }
        return {
            "schema_version": 2,
            "transaction_id": "tx-1",
            "target": "codex",
            "participants": ["codex"],
            "operation": "install",
            "operations": [
                {
                    "operation_id": "op-1",
                    "identifier": "code-explorer",
                    "action": "create",
                    "expected_before_hash": None,
                    "expected_after_hash": "a" * 64,
                    "expected_before_mode": None,
                    "expected_after_mode": 0o600,
                    "expected_before_evidence": None,
                    "expected_after_evidence": evidence,
                    "backup_path": None,
                    "backup_hash": None,
                    "status": "planned",
                }
            ],
            "rollback_status": "not-started",
        }

    def test_schema2_journal_round_trip_preserves_exact_identity_evidence(self):
        raw = self._v2_journal()
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            journal = decode_journal(raw, descriptor_for(Target.CODEX), Path(temporary))
        self.assertEqual(json.loads(encode_journal(journal)), raw)

    def test_schema2_rejects_malformed_identity_evidence_objects(self):
        raw = self._v2_journal()
        evidence = raw["operations"][0]["expected_after_evidence"]
        malformed = (
            {**evidence, "extra": 1},
            {key: value for key, value in evidence.items() if key != "inode"},
            {**evidence, "device": True},
            {**evidence, "device": -1},
            {**evidence, "inode": "2"},
            {**evidence, "inode": -1},
            {**evidence, "size": -1},
            {**evidence, "size": True},
            {**evidence, "nlink": 0},
            {**evidence, "mode": 0o644},
            {**evidence, "sha256": "A" * 64},
            {**evidence, "sha256": "a" * 63},
        )
        descriptor = descriptor_for(Target.CODEX)
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            for item in malformed:
                candidate = {
                    **raw,
                    "operations": [
                        {
                            **raw["operations"][0],
                            "expected_after_evidence": item,
                        }
                    ],
                }
                with self.assertRaises(ValueError):
                    decode_journal(candidate, descriptor, Path(temporary))

    def test_public_decoders_reject_schema_v1_without_explicit_legacy_path(self):
        manifest = {
            "schema_version": 1,
            "target": "codex",
            "entries": [],
        }
        journal = {
            "schema_version": 1,
            "transaction_id": "tx-1",
            "target": "codex",
            "participants": ["codex"],
            "operation": "install",
            "operations": [],
            "rollback_status": "complete",
        }
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            home = Path(temporary)
            descriptor = descriptor_for(Target.CODEX)
            with self.assertRaises(ValueError):
                decode_manifest(manifest, descriptor, home)
            with self.assertRaises(ValueError):
                decode_journal(journal, descriptor, home)

    def test_v1_manifest_migrates_only_when_live_hash_mode_and_path_match(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            home = Path(temporary)
            managed = home / "agents" / "code-explorer.toml"
            managed.parent.mkdir(mode=0o700)
            managed.write_bytes(b"managed")
            managed.chmod(0o600)
            raw = {
                "schema_version": 1,
                "target": "codex",
                "entries": [
                    {
                        "identifier": "code-explorer",
                        "relative_path": "agents/code-explorer.toml",
                        "installed_hash": hashlib.sha256(b"managed").hexdigest(),
                        "installed_mode": 0o600,
                        "ownership": "created",
                        "backup_path": None,
                        "backup_hash": None,
                        "original_mode": None,
                        "managed_block_id": None,
                        "installed_block_hash": None,
                        "unresolved_reason": None,
                    }
                ],
            }
            migrated = migrate_manifest_schema(raw, descriptor_for(Target.CODEX), home)
            self.assertEqual(migrated.schema_version, 2)
            managed.chmod(0o400)
            with self.assertRaises(ValueError):
                migrate_manifest_schema(raw, descriptor_for(Target.CODEX), home)

    def test_v1_pending_journal_is_inspect_only_and_rejected_for_recovery(self):
        raw = {
            "schema_version": 1,
            "transaction_id": "tx-1",
            "target": "codex",
            "participants": ["codex"],
            "operation": "install",
            "operations": [
                {
                    "operation_id": "op-1",
                    "identifier": "state/manifest",
                    "action": "write-manifest",
                    "expected_before_hash": None,
                    "expected_after_hash": "a" * 64,
                    "expected_before_mode": None,
                    "expected_after_mode": 0o600,
                    "backup_path": None,
                    "backup_hash": None,
                    "status": "planned",
                }
            ],
            "rollback_status": "not-started",
        }
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            with self.assertRaisesRegex(RuntimeError, "manual recovery is required"):
                inspect_legacy_journal(
                    raw, descriptor_for(Target.CODEX), Path(temporary)
                )

    def test_v0_and_future_schemas_are_rejected_and_unknown_keys_are_rejected(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            home = Path(temporary)
            for version in (0, 3):
                with self.assertRaises(ValueError):
                    migrate_manifest_schema(
                        {"schema_version": version}, descriptor_for(Target.CODEX), home
                    )
            with self.assertRaises(ValueError):
                migrate_manifest_schema(
                    {"schema_version": 1, "unexpected": True},
                    descriptor_for(Target.CODEX),
                    home,
                )


if __name__ == "__main__":
    unittest.main()
