import ast
import copy
import hashlib
import inspect
import unittest
from dataclasses import replace
from pathlib import Path, PurePosixPath

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

    def test_registry_mutation_drives_participant_order_and_parser_dispatch(self):
        from unittest.mock import patch

        import subagents_configs.targets as targets_module
        from subagents_configs import formats, transaction
        from subagents_configs.targets import registry_target_order

        reordered = tuple(
            replace(
                capability,
                order={
                    Target.CODEX: 2,
                    Target.OPENCODE: 0,
                    Target.CLAUDE_CODE: 1,
                }[capability.target],
            )
            for capability in CAPABILITIES
        )
        with patch.object(targets_module, "CAPABILITIES", reordered):
            self.assertEqual(
                registry_target_order(),
                (Target.OPENCODE, Target.CLAUDE_CODE, Target.CODEX),
            )
            transaction.canonical_participant_order(
                (Target.OPENCODE, Target.CLAUDE_CODE, Target.CODEX)
            )
            self.assertEqual(formats.parser_for(Target.CODEX), "toml")
            altered = tuple(
                replace(capability, parser="yaml-frontmatter")
                if capability.target is Target.CODEX
                else capability
                for capability in reordered
            )
            with patch.object(targets_module, "CAPABILITIES", altered):
                self.assertEqual(formats.parser_for(Target.CODEX), "yaml-frontmatter")
                with self.assertRaisesRegex(ValueError, "missing opening frontmatter"):
                    formats.validate_rendered_agent(
                        Target.CODEX,
                        "code-explorer",
                        Path("agents/code-explorer.toml"),
                        Path("agents/code-explorer.toml").read_bytes(),
                        str(
                            Path(__file__).resolve().parents[1]
                            / "scripts/run-validation-isolated.py"
                        ),
                    )
            validator_altered = tuple(
                replace(capability, semantic_validator="unsupported")
                if capability.target is Target.CODEX
                else capability
                for capability in reordered
            )
            with patch.object(targets_module, "CAPABILITIES", validator_altered):
                with self.assertRaisesRegex(
                    ValueError, "unsupported semantic validator"
                ):
                    formats.validate_rendered_agent(
                        Target.CODEX,
                        "code-explorer",
                        Path("agents/code-explorer.toml"),
                        Path("agents/code-explorer.toml").read_bytes(),
                        str(
                            Path(__file__).resolve().parents[1]
                            / "scripts/run-validation-isolated.py"
                        ),
                    )

    def test_canonical_role_policy_mutation_rejects_native_divergence(self):
        import tomllib

        from subagents_configs import formats

        parsed = tomllib.loads(
            (
                Path(__file__).resolve().parents[1] / "agents/code-explorer.toml"
            ).read_text()
        )
        original = copy.deepcopy(formats.ROLE_POLICY["codex"])
        try:
            formats.ROLE_POLICY["codex"]["code-explorer"]["overlay"]["model"] = (
                "tampered-model"
            )
            with self.assertRaisesRegex(ValueError, "canonical role policy"):
                formats.validate_agent_semantics(
                    Target.CODEX,
                    "code-explorer",
                    parsed,
                    "read-only body",
                )
        finally:
            formats.ROLE_POLICY["codex"] = original

    def test_native_inventory_uses_registry_validator_dispatch(self):
        from unittest.mock import patch

        import subagents_configs.targets as targets_module
        from subagents_configs import formats
        from subagents_configs.targets import descriptor_for

        spec = next(
            source
            for source in descriptor_for(Target.CODEX).sources
            if source.identifier == "code-explorer"
        )
        altered = tuple(
            replace(capability, semantic_validator="unsupported")
            if capability.target is Target.CODEX
            else capability
            for capability in CAPABILITIES
        )
        with patch.object(targets_module, "CAPABILITIES", altered):
            with self.assertRaisesRegex(ValueError, "unsupported semantic validator"):
                formats.validate_source_inventory(
                    Path(__file__).resolve().parents[1], Target.CODEX, (spec,)
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

    def test_lifecycle_decoder_exhaustively_handles_block_variants(self):
        block = {
            "block_id": "routing-codex",
            "begin_marker": "IyBCRUdJTiBTVUJBR0VOVFNfQ09ORklHUyByb3V0aW5nLWNvZGV4",
            "end_marker": (
                "IyBFTkQgU1VCQUdFTlRTX0NPTkZJR1Mgc m91dGluZy1jb2RleA=="
            ).replace(" ", ""),
            "content": "Ym9keQo=",
            "sha256": hashlib.sha256(
                b"# BEGIN SUBAGENTS_CONFIGS routing-codex\nbody\n"
                b"# END SUBAGENTS_CONFIGS routing-codex\n"
            ).hexdigest(),
        }
        base = {
            "action": "write-block",
            "identifier": "routing-codex",
            "relative_path": "AGENTS.md",
            "expected": None,
            "block": block,
        }
        action = decode_lifecycle_action(base)
        self.assertEqual(action.action, "write-block")
        with self.assertRaises(ValueError):
            decode_lifecycle_action({**base, "block": {**block, "unexpected": True}})
        with self.assertRaises(ValueError):
            decode_lifecycle_action(
                {key: value for key, value in base.items() if key != "block"}
            )

    def test_lifecycle_replace_rejects_untyped_desired_and_backup(self):
        evidence = IdentityEvidence(
            1, 2, 3, 1, 0o600, hashlib.sha256(b"old\n").hexdigest()
        )
        with self.assertRaises((TypeError, ValueError)):
            FileAction.replace(
                "role", PurePosixPath("agents/role"), evidence, object(), object()
            )

    def test_block_constructors_reject_forged_or_mismatched_blocks(self):
        block = inspect_managed_block(
            b"# BEGIN SUBAGENTS_CONFIGS routing-codex\n"
            b"body\n# END SUBAGENTS_CONFIGS routing-codex\n",
            "routing-codex",
        )
        self.assertIsNotNone(block)
        evidence = IdentityEvidence(
            1, 2, 3, 1, 0o600, hashlib.sha256(b"old\n").hexdigest()
        )
        forged = (
            replace(block, block_id="routing-opencode"),
            replace(block, begin_marker=b"# BEGIN forged"),
            replace(block, end_marker=b"# END forged\n"),
            replace(block, content=b"tampered\n"),
            replace(block, sha256="0" * 64),
        )
        for candidate in forged:
            with self.assertRaises((TypeError, ValueError)):
                BlockAction.write(
                    "routing-codex",
                    PurePosixPath("AGENTS.md"),
                    None,
                    candidate,
                )
            with self.assertRaises((TypeError, ValueError)):
                BlockAction.remove(
                    "routing-codex",
                    PurePosixPath("AGENTS.md"),
                    evidence,
                    candidate,
                )

    def test_transaction_failure_injector_is_keyword_only(self):
        from subagents_configs.transaction import apply_transaction

        self.assertEqual(
            inspect.signature(apply_transaction).parameters["failure_injector"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )

    def test_consumers_use_registry_and_no_cross_module_private_imports(self):
        root = Path(__file__).resolve().parents[1] / "subagents_configs"
        for filename in ("cli.py", "planning.py", "formats.py"):
            tree = ast.parse((root / filename).read_text(), filename=filename)
            names = {
                alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
                for alias in node.names
            }
            self.assertNotIn("DESCRIPTOR_ORDER", names, filename)
        for path in root.glob("*.py"):
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and (
                    node.level > 0
                    or (node.module and node.module.startswith("subagents_configs."))
                ):
                    self.assertFalse(
                        any(alias.name.startswith("_") for alias in node.names),
                        str(path),
                    )

    def test_catalog_projection_has_hashes_and_unique_destinations(self):
        root = Path(__file__).resolve().parents[1]
        for target in ("codex", "opencode", "claude-code"):
            import json

            value = json.loads((root / "catalogs" / f"{target}.json").read_text())
            self.assertRegex(value["policy_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(value["source_sha256"], r"^[0-9a-f]{64}$")
            destinations = [
                item["destination"] for item in value["sources"] if item["destination"]
            ]
            self.assertEqual(len(destinations), len(set(destinations)))

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
