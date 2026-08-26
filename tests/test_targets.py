import unittest

from subagents_configs.models import Target
from subagents_configs.targets import (
    CAPABILITIES,
    DESCRIPTORS,
    descriptor_for,
    selected_sources,
    targets_for_request,
)


class TargetTests(unittest.TestCase):
    def test_supported_targets_are_exact(self):
        self.assertEqual(
            tuple(DESCRIPTORS),
            (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE, Target.PI),
        )

    def test_pi_is_explicit_but_not_in_all(self):
        self.assertEqual(
            targets_for_request((), True),
            (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE),
        )
        self.assertEqual(targets_for_request((Target.PI,), False), (Target.PI,))

    def test_pi_descriptor_is_registered_without_later_task_sources(self):
        descriptor = descriptor_for(Target.PI)
        self.assertEqual(descriptor.target, Target.PI)
        self.assertEqual(descriptor.sources, ())
        self.assertEqual(descriptor.environment_variable, "PI_CODING_AGENT_DIR")
        self.assertEqual(descriptor.global_filename, "APPEND_SYSTEM.md")
        capability = next(item for item in CAPABILITIES if item.target is Target.PI)
        self.assertEqual(
            (capability.source_format, capability.parser), ("markdown", "markdown")
        )

    def test_each_inventory_is_nonempty_and_unique(self):
        for descriptor in DESCRIPTORS.values():
            if descriptor.target is Target.PI:
                continue
            self.assertTrue(descriptor.sources)
            identifiers = [source.identifier for source in descriptor.sources]
            self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_commit_pusher_is_excluded_by_default(self):
        for descriptor in DESCRIPTORS.values():
            if descriptor.target is Target.PI:
                continue
            sources = selected_sources(descriptor, include_commit_pusher=False)
            self.assertNotIn("commit-pusher", [s.optional_role for s in sources])

    def test_commit_pusher_is_selected_explicitly(self):
        for descriptor in DESCRIPTORS.values():
            if descriptor.target is Target.PI:
                continue
            sources = selected_sources(descriptor, include_commit_pusher=True)
            self.assertIn("commit-pusher", [s.optional_role for s in sources])

    def test_codex_routing_source_is_markdown(self):
        routing = next(
            source
            for source in descriptor_for(Target.CODEX).sources
            if source.kind == "routing-source"
        )
        self.assertEqual(routing.source_format, "markdown")

    def test_no_descriptor_mentions_pi(self):
        for descriptor in DESCRIPTORS.values():
            if descriptor.target is Target.PI:
                continue
            self.assertNotIn("pi", descriptor.target.value.lower())
            for source in descriptor.sources:
                self.assertNotIn("pi", source.identifier.lower())
                self.assertNotIn("pi", source.source.as_posix().lower())
                if source.destination is not None:
                    self.assertNotIn("pi", source.destination.as_posix().lower())


if __name__ == "__main__":
    unittest.main()
