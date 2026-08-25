from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from subagents_configs import filesystem, state
from subagents_configs.errors import TransactionError
from subagents_configs.formats import ValidatedSource, validate_source_inventory
from subagents_configs.models import SourceSpec, Target
from subagents_configs.planning import preflight_install, source_hash
from subagents_configs.targets import descriptor_for
from tests.helpers import planning_request, private_tempdir, real_repository

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class PerformanceContractTests(unittest.TestCase):
    repository = real_repository()

    def test_command_cache_reuses_bytes_and_hashes_within_one_command(self):
        with self.subTest("read bytes"):
            with filesystem.CommandCache() as cache:
                path = ROOT / "agents" / "implementer.toml"
                evidence, content = filesystem.read_bytes_with_evidence(path, "test")
                self.assertEqual(cache.read_bytes(path, evidence), content)
                self.assertEqual(cache.read_bytes(path, evidence), content)
                expected = hashlib.sha256(content).hexdigest()
                self.assertEqual(cache.hash_bytes(content), expected)
                self.assertEqual(cache.hash_bytes(content), expected)

    def test_source_hash_uses_validated_source_content_without_rereading(self):
        source = ValidatedSource(
            SourceSpec(
                "example",
                Path("agents/implementer.toml"),
                Path("example.toml"),
                "agent",
                "toml",
            ),
            b"validated source",
            hashlib.sha256(b"validated source").hexdigest(),
            None,
        )
        with (
            filesystem.CommandCache() as cache,
            patch.object(
                filesystem, "sha256_file", side_effect=AssertionError("source reread")
            ),
        ):
            self.assertEqual(source_hash(source, cache), source.sha256)

    def test_regular_reads_and_state_inventory_are_reused_in_scope(self):
        path = ROOT / "agents" / "implementer.toml"
        with (
            filesystem.CommandCache() as cache,
            patch.object(
                filesystem,
                "read_bytes_with_evidence",
                wraps=filesystem.read_bytes_with_evidence,
            ) as reader,
        ):
            first = cache.read_regular(path, "test")
            second = cache.read_cached_regular(path)
            self.assertEqual(first, second)
            self.assertEqual(reader.call_count, 1)

        with (
            filesystem.CommandCache() as cache,
            patch.object(state, "load_state", wraps=state.load_state) as load_state,
        ):
            cache.inventory_state(ROOT, descriptor_for(Target.CODEX))
            cache.inventory_state(ROOT, descriptor_for(Target.CODEX))
            self.assertEqual(load_state.call_count, 1)

    def test_same_size_in_place_rewrite_fails_closed_on_cached_read(self):
        with private_tempdir() as temporary:
            path = Path(temporary) / "source"
            path.write_bytes(b"before")
            with filesystem.CommandCache() as cache:
                self.assertEqual(cache.read_regular(path, "test")[0], b"before")
                path.write_bytes(b"after!")
                with self.assertRaises(TransactionError):
                    cache.read_regular(path, "test")

    def test_source_inventory_reuses_shared_source_read_and_hash_seams(self):
        spec = SourceSpec(
            "runtime",
            Path("scripts/validation_isolation/__init__.py"),
            None,
            "validation-runtime",
            "python",
        )
        with (
            filesystem.CommandCache() as cache,
            patch.object(
                filesystem,
                "read_descriptor_with_evidence",
                wraps=filesystem.read_descriptor_with_evidence,
            ) as reader,
            patch.object(
                filesystem, "sha256_bytes", wraps=filesystem.sha256_bytes
            ) as hasher,
        ):
            validate_source_inventory(
                self.repository, Target.CODEX, (spec,), cache=cache
            )
            validate_source_inventory(
                self.repository, Target.CODEX, (spec,), cache=cache
            )
            self.assertEqual(reader.call_count, 1)
            self.assertEqual(hasher.call_count, 1)

    def test_mutation_after_preflight_fails_before_apply_writes(self):
        with private_tempdir() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            request = planning_request(
                "install", {Target.CODEX: home}, targets=(Target.CODEX,)
            )
            plan = preflight_install(self.repository, request)
            first = plan.targets[0].operations[1]
            destination = home / first.relative_path
            from subagents_configs.transaction import apply_transaction

            class MutateBeforeSecondOperation:
                calls = 0

                def before_operation(self, operation_id):
                    self.calls += 1
                    if self.calls == 1:
                        destination.write_bytes(b"changed before CAS")
                        destination.chmod(0o600)

            with self.assertRaises(TransactionError):
                apply_transaction(plan, failure_injector=MutateBeforeSecondOperation())

    def test_ci_has_one_repository_unittest_discovery_entrypoint(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        yaml.safe_load(text)
        self.assertEqual(
            text.count("python -m unittest discover -s tests -p 'test_*.py'"), 1
        )


if __name__ == "__main__":
    unittest.main()
