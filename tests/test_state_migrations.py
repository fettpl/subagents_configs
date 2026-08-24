import hashlib
import tempfile
import unittest
from pathlib import Path

from subagents_configs.models import Target
from subagents_configs.state import (
    inspect_legacy_journal,
    migrate_manifest_schema,
)
from subagents_configs.targets import descriptor_for


class StateMigrationTests(unittest.TestCase):
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
