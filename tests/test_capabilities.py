import hashlib
import unittest
from pathlib import PurePosixPath

from subagents_configs.blocks import inspect_managed_block
from subagents_configs.models import (
    BackupSpec,
    BlockAction,
    DesiredFile,
    FileAction,
    IdentityEvidence,
    LifecycleAction,
    Target,
    decode_lifecycle_action,
)
from subagents_configs.targets import (
    CAPABILITIES,
    capability_for,
    targets_for_request,
)


class CapabilityRegistryTests(unittest.TestCase):
    def test_registry_owns_target_order_and_all_decision(self):
        self.assertEqual(
            tuple(capability.target for capability in CAPABILITIES),
            (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE),
        )
        self.assertEqual(
            tuple(capability.order for capability in CAPABILITIES), (0, 1, 2)
        )
        self.assertTrue(all(capability.include_in_all for capability in CAPABILITIES))
        for capability in CAPABILITIES:
            self.assertIs(capability_for(capability.target), capability)
            self.assertTrue(capability.agent_directory.parts)
            self.assertTrue(capability.runtime_sources)
            self.assertIsNotNone(capability.parser)
            self.assertIsNotNone(capability.semantic_validator)
            self.assertIsNotNone(capability.global_instruction)
            self.assertIsNotNone(capability.optional_blocks)
            self.assertIsNone(capability.external_lifecycle)

    def test_all_selection_is_derived_from_registry(self):
        self.assertEqual(
            targets_for_request((), True),
            (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE),
        )
        self.assertEqual(
            targets_for_request((Target.CLAUDE_CODE, Target.CODEX), False),
            (Target.CODEX, Target.CLAUDE_CODE),
        )

    def test_source_spec_extensions_are_closed_and_pi_is_absent(self):
        allowed_kinds = {
            "agent",
            "routing-source",
            "project-template",
            "validation-runtime",
            "command-gate",
            "target-extension",
        }
        allowed_formats = {
            "toml",
            "yaml-frontmatter",
            "markdown",
            "python",
            "json",
            "typescript",
        }
        for capability in CAPABILITIES:
            for source in (*capability.runtime_sources,):
                self.assertIn(source.kind, allowed_kinds)
                self.assertIn(source.source_format, allowed_formats)
                self.assertNotIn("pi", source.identifier.lower())

    def test_lifecycle_constructors_require_typed_evidence_and_preserve_tags(self):
        desired = DesiredFile(content=b"safe\n", mode=0o600)
        evidence = IdentityEvidence(
            1, 2, 3, 1, 0o600, hashlib.sha256(b"old\n").hexdigest()
        )
        backup = BackupSpec(PurePosixPath("backups/old"), evidence.sha256)
        created = FileAction.create("role", PurePosixPath("agents/role"), desired)
        replaced = FileAction.replace(
            "role", PurePosixPath("agents/role"), evidence, desired, backup
        )
        removed = FileAction.remove("role", PurePosixPath("agents/role"), evidence)
        restored = FileAction.restore(
            "role", PurePosixPath("agents/role"), evidence, backup
        )
        block = inspect_managed_block(
            b"# BEGIN SUBAGENTS_CONFIGS routing-codex\n"
            b"body\n# END SUBAGENTS_CONFIGS routing-codex\n",
            "routing-codex",
        )
        self.assertIsNotNone(block)
        block_write = BlockAction.write(
            "routing-codex", PurePosixPath("AGENTS.md"), evidence, block
        )
        block_remove = BlockAction.remove(
            "routing-codex", PurePosixPath("AGENTS.md"), evidence, block
        )
        for action in (created, replaced, removed, restored, block_write, block_remove):
            self.assertIsInstance(action, LifecycleAction)
            self.assertTrue(action.action)
            self.assertTrue(action.identifier)
        with self.assertRaises((TypeError, ValueError)):
            FileAction.replace(
                "role", PurePosixPath("agents/role"), None, desired, backup
            )
        with self.assertRaises((TypeError, ValueError)):
            BlockAction.remove("routing-codex", PurePosixPath("AGENTS.md"), None, block)

    def test_persisted_lifecycle_decoding_is_strict(self):
        raw = {
            "action": "create",
            "identifier": "role",
            "relative_path": "agents/role",
            "desired": {"content": "c2FmZQo=", "mode": 384},
        }
        action = decode_lifecycle_action(raw)
        self.assertEqual(action.action, "create")
        with self.assertRaises(ValueError):
            decode_lifecycle_action({**raw, "unexpected": True})
        with self.assertRaises(ValueError):
            decode_lifecycle_action({k: v for k, v in raw.items() if k != "desired"})

    def test_named_public_seams_are_importable(self):
        from subagents_configs.filesystem import safe_mutate
        from subagents_configs.planning import validate_lifecycle
        from subagents_configs.recovery import recover_transaction
        from subagents_configs.state import load_state
        from subagents_configs.transaction import apply_transaction

        for seam in (
            safe_mutate,
            validate_lifecycle,
            recover_transaction,
            load_state,
            apply_transaction,
        ):
            self.assertTrue(callable(seam))


if __name__ == "__main__":
    unittest.main()
