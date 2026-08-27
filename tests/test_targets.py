import unittest
from pathlib import PurePosixPath

from subagents_configs.models import SourceSpec, Target
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

    def test_pi_descriptor_includes_task3_catalog_and_extension_sources(self):
        descriptor = descriptor_for(Target.PI)
        self.assertEqual(descriptor.target, Target.PI)
        expected = (
                SourceSpec(
                    identifier="code-explorer",
                    source=PurePosixPath("pi/agents/code-explorer.md"),
                    destination=PurePosixPath("agents/code-explorer.md"),
                    kind="agent",
                    source_format="markdown",
                ),
                SourceSpec(
                    identifier="code-reviewer",
                    source=PurePosixPath("pi/agents/code-reviewer.md"),
                    destination=PurePosixPath("agents/code-reviewer.md"),
                    kind="agent",
                    source_format="markdown",
                ),
                SourceSpec(
                    identifier="code-validator",
                    source=PurePosixPath("pi/agents/code-validator.md"),
                    destination=PurePosixPath("agents/code-validator.md"),
                    kind="agent",
                    source_format="markdown",
                ),
                SourceSpec(
                    identifier="quick-implementer",
                    source=PurePosixPath("pi/agents/quick-implementer.md"),
                    destination=PurePosixPath("agents/quick-implementer.md"),
                    kind="agent",
                    source_format="markdown",
                ),
                SourceSpec(
                    identifier="implementer",
                    source=PurePosixPath("pi/agents/implementer.md"),
                    destination=PurePosixPath("agents/implementer.md"),
                    kind="agent",
                    source_format="markdown",
                ),
                SourceSpec(
                    identifier="commit-pusher",
                    source=PurePosixPath("pi/agents/commit-pusher.md"),
                    destination=PurePosixPath("agents/commit-pusher.md"),
                    kind="agent",
                    source_format="markdown",
                    optional_role="commit-pusher",
                ),
                SourceSpec(
                    identifier="pi/run-validation",
                    source=PurePosixPath("pi/extensions/run-validation.ts"),
                    destination=PurePosixPath(
                        "extensions/subagents-configs-run-validation.ts"
                    ),
                    kind="target-extension",
                    source_format="typescript",
                ),
                SourceSpec(
                    identifier="routing",
                    source=PurePosixPath("rules/PI_SUBAGENT_ROUTING.md"),
                    destination=None,
                    kind="routing-source",
                    source_format="markdown",
                ),
        )
        runtime = tuple(
            source
            for source in descriptor.sources
            if source.kind == "validation-runtime"
        )
        self.assertEqual(
            descriptor.sources,
            expected[:-1] + runtime + expected[-1:],
        )
        self.assertEqual(len(runtime), 9)
        self.assertEqual(descriptor.environment_variable, "PI_CODING_AGENT_DIR")
        self.assertEqual(descriptor.global_filename, "APPEND_SYSTEM.md")
        capability = next(item for item in CAPABILITIES if item.target is Target.PI)
        self.assertEqual(
            (capability.source_format, capability.parser), ("markdown", "markdown")
        )

    def test_each_inventory_is_nonempty_and_unique(self):
        for descriptor in DESCRIPTORS.values():
            self.assertTrue(descriptor.sources)
            identifiers = [source.identifier for source in descriptor.sources]
            self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_commit_pusher_is_excluded_by_default(self):
        for descriptor in DESCRIPTORS.values():
            sources = selected_sources(descriptor, include_commit_pusher=False)
            self.assertNotIn("commit-pusher", [s.optional_role for s in sources])

    def test_commit_pusher_is_selected_explicitly(self):
        for descriptor in DESCRIPTORS.values():
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
