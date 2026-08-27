import builtins
import hashlib
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from subagents_configs.blocks import render_managed_block
from subagents_configs.models import (
    Manifest,
    ManifestEntry,
    Request,
    SourceSpec,
    Target,
)
from subagents_configs.state import encode_manifest
from tests.helpers import planning_repository, planning_request


class PlanningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            dir="/private/tmp" if Path("/private/tmp").is_dir() else None
        )
        self.root = Path(self.temporary.name)
        self.repository = planning_repository(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def _homes(self, *targets):
        return {target: self.root / f"home-{target.value}" for target in targets}

    def _write_manifest(self, home, manifest):
        state = home / ".subagents_configs"
        state.mkdir(parents=True, mode=0o700, exist_ok=True)
        state.chmod(0o700)
        path = state / "manifest.json"
        path.write_bytes(encode_manifest(manifest))
        path.chmod(0o600)

    def _manifest_entry(self, identifier, relative_path, content, **changes):
        value = {
            "identifier": identifier,
            "relative_path": relative_path,
            "installed_hash": hashlib.sha256(content).hexdigest(),
            "installed_mode": 0o600,
            "ownership": "created",
            "backup_path": None,
            "backup_hash": None,
            "original_mode": None,
            "managed_block_id": None,
            "installed_block_hash": None,
            "unresolved_reason": None,
        }
        value.update(changes)
        return ManifestEntry(**value)

    def test_all_seven_selections_are_planned_in_descriptor_order(self):
        from subagents_configs.planning import preflight_install

        for selected in (
            (Target.CODEX,),
            (Target.OPENCODE,),
            (Target.CLAUDE_CODE,),
            (Target.CODEX, Target.OPENCODE),
            (Target.CODEX, Target.CLAUDE_CODE),
            (Target.OPENCODE, Target.CLAUDE_CODE),
            (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE),
        ):
            homes = self._homes(*selected)
            plan = preflight_install(
                self.repository,
                planning_request("install", homes, targets=selected),
            )
            self.assertEqual(tuple(target.target for target in plan.targets), selected)
            for target in plan.targets:
                self.assertTrue(target.operations)

    def test_commit_pusher_is_opt_in_and_routing_is_opt_in(self):
        from subagents_configs.planning import preflight_install

        homes = self._homes(Target.CODEX)
        default = preflight_install(
            self.repository, planning_request("install", homes)
        ).targets[0]
        identifiers = {operation.identifier for operation in default.operations}
        self.assertNotIn("commit-pusher", identifiers)
        self.assertNotIn("routing-codex", identifiers)

        opted = preflight_install(
            self.repository,
            planning_request(
                "install",
                homes,
                include_commit_pusher=True,
                enable_global_routing=True,
            ),
        ).targets[0]
        identifiers = {operation.identifier for operation in opted.operations}
        self.assertIn("commit-pusher", identifiers)
        self.assertIn("routing-codex", identifiers)

    def test_codex_feature_block_is_created_and_toml_collisions_fail_closed(self):
        from subagents_configs.planning import preflight_install

        homes = self._homes(Target.CODEX)
        plan = preflight_install(
            self.repository,
            planning_request("install", homes, enable_codex_multi_agent=True),
        )
        config_operation = next(
            operation
            for operation in plan.targets[0].operations
            if operation.identifier == "codex-multi-agent-v2"
        )
        self.assertEqual(config_operation.action, "write-block")
        self.assertNotIn(b"{{", config_operation.content or b"")
        homes[Target.CODEX].mkdir(parents=True)
        (homes[Target.CODEX] / "config.toml").write_text(
            'features = "collision"\n', encoding="utf-8"
        )
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                planning_request("install", homes, enable_codex_multi_agent=True),
            )

    def test_user_codex_feature_table_is_not_silently_accepted(self):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        home.mkdir(parents=True)
        config = home / "config.toml"
        config.write_text(
            '[features.multi_agent_v2]\nuser_key = "keep"\n',
            encoding="utf-8",
        )
        config.chmod(0o600)
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                planning_request(
                    "install", {Target.CODEX: home}, enable_codex_multi_agent=True
                ),
            )

    def test_exact_managed_codex_feature_block_reinstall_is_idempotent(self):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        first = preflight_install(
            self.repository,
            planning_request(
                "install", {Target.CODEX: home}, enable_codex_multi_agent=True
            ),
        ).targets[0]
        operation = next(
            item
            for item in first.operations
            if item.identifier == "codex-multi-agent-v2"
        )
        config = home / "config.toml"
        config.parent.mkdir(parents=True)
        config.write_bytes(operation.content or b"")
        config.chmod(0o600)
        entry = next(
            item
            for item in first.resulting_manifest.entries
            if item.identifier == "codex-multi-agent-v2"
        )
        self._write_manifest(home, Manifest(2, Target.CODEX, (entry,)))
        second = preflight_install(
            self.repository,
            planning_request(
                "install", {Target.CODEX: home}, enable_codex_multi_agent=True
            ),
        ).targets[0]
        self.assertFalse(
            any(item.identifier == "codex-multi-agent-v2" for item in second.operations)
        )
        self.assertFalse(second.conflicts)

    def test_missing_prior_managed_file_is_unresolved_not_recreated(self):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        source = self.repository / "agents/commit-pusher.toml"
        content = source.read_bytes()
        entry = self._manifest_entry(
            "commit-pusher", "agents/commit-pusher.toml", content
        )
        self._write_manifest(home, Manifest(2, Target.CODEX, (entry,)))
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        ).targets[0]
        self.assertFalse(
            any(item.identifier == "commit-pusher" for item in plan.operations)
        )
        preserved = next(
            item
            for item in plan.resulting_manifest.entries
            if item.identifier == "commit-pusher"
        )
        self.assertIn("missing", preserved.unresolved_reason or "")

    def test_preexisting_source_update_is_conflict_without_replacement(self):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        destination = home / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        original = (self.repository / "agents/code-explorer.toml").read_bytes()
        destination.write_bytes(original)
        destination.chmod(0o600)
        first = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        ).targets[0]
        entry = next(
            item
            for item in first.resulting_manifest.entries
            if item.identifier == "code-explorer"
        )
        self._write_manifest(home, Manifest(2, Target.CODEX, (entry,)))
        source = self.repository / "agents/code-explorer.toml"
        try:
            source.write_bytes(original + b"\n# source update\n")
            plan = preflight_install(
                self.repository,
                planning_request("install", {Target.CODEX: home}),
            ).targets[0]
        finally:
            source.write_bytes(original)
        self.assertFalse(
            any(item.identifier == "code-explorer" for item in plan.operations)
        )
        preserved = next(
            item
            for item in plan.resulting_manifest.entries
            if item.identifier == "code-explorer"
        )
        self.assertEqual(preserved.ownership, "preexisting")
        self.assertTrue(plan.conflicts)

    def test_preexisting_managed_block_records_mode_and_uninstall_preserves_it(self):
        from subagents_configs.planning import preflight_install, preflight_uninstall

        home = self._homes(Target.CODEX)[Target.CODEX]
        instructions = home / "AGENTS.md"
        instructions.parent.mkdir(parents=True)
        block = render_managed_block(
            "routing-codex",
            (self.repository / "rules/SUBAGENT_ROUTING.md").read_bytes(),
        )
        instructions.write_bytes(
            block.begin_marker + b"\n" + block.content + block.end_marker + b"\n"
        )
        instructions.chmod(0o600)
        first = preflight_install(
            self.repository,
            planning_request(
                "install", {Target.CODEX: home}, enable_global_routing=True
            ),
        ).targets[0]
        entry = next(
            item
            for item in first.resulting_manifest.entries
            if item.identifier == "routing-codex"
        )
        self.assertEqual(entry.ownership, "preexisting")
        self.assertEqual(entry.original_mode, 0o600)
        self._write_manifest(home, Manifest(2, Target.CODEX, (entry,)))
        uninstall = preflight_uninstall(
            self.repository,
            planning_request("uninstall", {Target.CODEX: home}),
        ).targets[0]
        self.assertFalse(
            any(item.identifier == "routing-codex" for item in uninstall.operations)
        )
        preserved = next(
            item
            for item in uninstall.resulting_manifest.entries
            if item.identifier == "routing-codex"
        )
        self.assertIn(
            "preexisting managed block preserved", preserved.unresolved_reason or ""
        )
        self.assertTrue(
            any(
                "preexisting managed block preserved" in item
                for item in uninstall.conflicts
            )
        )
        encode_manifest(uninstall.resulting_manifest)

        stale_install = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        ).targets[0]
        stale_entry = next(
            item
            for item in stale_install.resulting_manifest.entries
            if item.identifier == "routing-codex"
        )
        self.assertIn(
            "preexisting managed block preserved", stale_entry.unresolved_reason or ""
        )
        self.assertTrue(
            any(
                "preexisting managed block preserved" in item
                for item in stale_install.conflicts
            )
        )
        self.assertFalse(
            any(item.identifier == "routing-codex" for item in stale_install.operations)
        )
        self.assertEqual(
            instructions.read_bytes(),
            block.begin_marker + b"\n" + block.content + block.end_marker + b"\n",
        )
        encode_manifest(stale_install.resulting_manifest)

    def test_request_options_are_exact_booleans_before_source_reads(self):
        from subagents_configs.planning import preflight_install, preflight_uninstall

        values = ("false", "true", 0, 1, [], {})
        for operation, planner in (
            ("install", preflight_install),
            ("uninstall", preflight_uninstall),
        ):
            for field in (
                "enable_global_routing",
                "enable_codex_multi_agent",
                "include_commit_pusher",
                "dry_run",
            ):
                for value in values:
                    options = {
                        "enable_global_routing": False,
                        "enable_codex_multi_agent": False,
                        "include_commit_pusher": False,
                        "dry_run": False,
                    }
                    options[field] = value
                    request = Request(
                        operation,
                        (Target.CODEX,),
                        {Target.CODEX: self.root / "home"},
                        **options,
                    )
                    with self.subTest(operation=operation, field=field, value=value):
                        with patch(
                            "subagents_configs.planning._selected_sources",
                            side_effect=AssertionError("source inventory must not run"),
                        ):
                            with self.assertRaises(ValueError):
                                planner(self.repository, request)

    def test_final_source_symlink_swap_fails_closed(self):
        from subagents_configs.formats import validate_source_inventory
        from subagents_configs.targets import descriptor_for

        source = next(
            item
            for item in descriptor_for(Target.CODEX).sources
            if item.identifier == "code-explorer"
        )
        final = self.repository / source.source
        outside = self.root / "outside-final.toml"
        outside.write_bytes(b"outside bytes")
        original = final.read_bytes()
        swapped = False

        def swap(operation, parent):
            nonlocal swapped
            if operation == "source-read" and parent.name == "agents" and not swapped:
                final.unlink()
                final.symlink_to(outside)
                swapped = True

        try:
            with patch("subagents_configs.filesystem._after_parent_pin", swap):
                with self.assertRaises(ValueError):
                    validate_source_inventory(self.repository, Target.CODEX, (source,))
        finally:
            if final.is_symlink():
                final.unlink()
            final.write_bytes(original)
        self.assertTrue(swapped)
        self.assertNotEqual(final.read_bytes(), outside.read_bytes())

    def test_final_source_regular_replacement_fails_identity_check(self):
        from subagents_configs.formats import validate_source_inventory
        from subagents_configs.targets import descriptor_for

        source = next(
            item
            for item in descriptor_for(Target.CODEX).sources
            if item.identifier == "code-explorer"
        )
        final = self.repository / source.source
        original = final.read_bytes()
        replacement = b"[agent]\nname = 'code-explorer'\n"
        swapped = False

        def swap(operation, parent):
            nonlocal swapped
            if operation == "source-read" and parent.name == "agents" and not swapped:
                final.unlink()
                final.write_bytes(replacement)
                swapped = True

        try:
            with patch("subagents_configs.filesystem._after_parent_pin", swap):
                with self.assertRaises(ValueError):
                    validate_source_inventory(self.repository, Target.CODEX, (source,))
        finally:
            final.write_bytes(original)
        self.assertTrue(swapped)

    def test_source_inventory_rejects_empty_and_nonregular_final_components(self):
        from subagents_configs.formats import validate_source_inventory

        cases = {
            "empty": lambda path: path.write_bytes(b""),
            "directory": lambda path: path.mkdir(),
        }
        if hasattr(os, "mkfifo"):
            cases["fifo"] = os.mkfifo
        for name, create in cases.items():
            with self.subTest(name=name):
                relative = PurePosixPath(f"adversarial-{name}.py")
                path = self.repository / relative
                create(path)
                spec = SourceSpec(
                    f"adversarial-{name}",
                    relative,
                    None,
                    "validation-runtime",
                    "python",
                )
                try:
                    with self.assertRaises(ValueError):
                        validate_source_inventory(
                            self.repository, Target.CODEX, (spec,)
                        )
                finally:
                    if path.is_dir() and not path.is_symlink():
                        path.rmdir()
                    elif path.exists():
                        path.unlink()

    def test_source_descriptor_closes_on_semantic_parse_failure(self):
        from subagents_configs.formats import validate_source_inventory

        relative = PurePosixPath("invalid.py")
        path = self.repository / relative
        path.write_bytes(b"def broken(:\n")
        spec = SourceSpec("invalid", relative, None, "validation-runtime", "python")
        close_calls = []
        real_close = os.close

        def close(descriptor):
            close_calls.append(descriptor)
            return real_close(descriptor)

        try:
            with patch("subagents_configs.formats.os.close", close):
                with self.assertRaises(ValueError):
                    validate_source_inventory(self.repository, Target.CODEX, (spec,))
        finally:
            path.unlink()
        self.assertTrue(close_calls)

    def test_source_destinations_require_canonical_strict_relative_paths(self):
        from subagents_configs.formats import validate_source_inventory

        source = PurePosixPath("scripts/run-validation-isolated.py")
        invalid = ("../escape.py", "agents\\evil.py", "/absolute.py")
        for index, destination in enumerate(invalid):
            with self.subTest(destination=destination):
                spec = SourceSpec(
                    f"invalid-destination-{index}",
                    source,
                    PurePosixPath(destination),
                    "validation-runtime",
                    "python",
                )
                with self.assertRaises(ValueError):
                    validate_source_inventory(self.repository, Target.CODEX, (spec,))

    def test_codex_inline_and_nested_feature_collisions_fail_without_plan_escape(self):
        from subagents_configs.planning import preflight_install

        for content in (
            'features = { multi_agent_v2 = { user = "keep" } }\n',
            '[features.multi_agent_v2.child]\nvalue = "keep"\n',
        ):
            with self.subTest(content=content):
                home = self._homes(Target.CODEX)[Target.CODEX]
                home.mkdir(parents=True, exist_ok=True)
                config = home / "config.toml"
                config.write_text(content, encoding="utf-8")
                before = self._snapshot(home)
                with self.assertRaises(ValueError):
                    preflight_install(
                        self.repository,
                        planning_request(
                            "install",
                            {Target.CODEX: home},
                            enable_codex_multi_agent=True,
                        ),
                    )
                self.assertEqual(before, self._snapshot(home))

    def test_exact_restored_unresolved_regular_entry_clears_reason(self):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        destination = home / "agents/code-explorer.toml"
        source = self.repository / "agents/code-explorer.toml"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o600)
        entry = self._manifest_entry(
            "code-explorer",
            "agents/code-explorer.toml",
            source.read_bytes(),
            unresolved_reason="previous drift",
        )
        self._write_manifest(home, Manifest(2, Target.CODEX, (entry,)))
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        ).targets[0]
        resolved = next(
            item
            for item in plan.resulting_manifest.entries
            if item.identifier == "code-explorer"
        )
        self.assertIsNone(resolved.unresolved_reason)

    def test_exact_restored_unresolved_block_entry_clears_reason(self):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        instructions = home / "AGENTS.md"
        instructions.parent.mkdir(parents=True)
        source_block = render_managed_block(
            "routing-codex",
            (self.repository / "rules/SUBAGENT_ROUTING.md").read_bytes(),
        )
        content = (
            source_block.begin_marker
            + b"\n"
            + source_block.content
            + source_block.end_marker
            + b"\n"
        )
        instructions.write_bytes(content)
        instructions.chmod(0o600)
        entry = self._manifest_entry(
            "routing-codex",
            "AGENTS.md",
            content,
            ownership="created",
            managed_block_id="routing-codex",
            installed_block_hash=source_block.sha256,
            unresolved_reason="previous drift",
        )
        self._write_manifest(home, Manifest(2, Target.CODEX, (entry,)))
        plan = preflight_install(
            self.repository,
            planning_request(
                "install", {Target.CODEX: home}, enable_global_routing=True
            ),
        ).targets[0]
        resolved = next(
            item
            for item in plan.resulting_manifest.entries
            if item.identifier == "routing-codex"
        )
        self.assertIsNone(resolved.unresolved_reason)

    def test_stale_symlink_and_nonregular_paths_are_retained_unresolved(self):
        from subagents_configs.planning import preflight_install

        for kind in ("symlink", "directory"):
            home = self.root / f"home-codex-{kind}"
            target = home / "agents/commit-pusher.toml"
            target.parent.mkdir(parents=True)
            outside = self.root / f"outside-{kind}"
            outside.write_bytes(b"outside")
            if kind == "symlink":
                target.symlink_to(outside)
            else:
                target.mkdir()
            entry = self._manifest_entry(
                "commit-pusher", "agents/commit-pusher.toml", b"managed"
            )
            self._write_manifest(home, Manifest(2, Target.CODEX, (entry,)))
            plan = preflight_install(
                self.repository,
                planning_request("install", {Target.CODEX: home}),
            ).targets[0]
            self.assertFalse(
                any(item.identifier == "commit-pusher" for item in plan.operations)
            )
            self.assertTrue(plan.conflicts)
            self.assertEqual(outside.read_bytes(), b"outside")

    def test_public_request_invariants_reject_bad_homes_and_flags(self):
        from subagents_configs.planning import preflight_install, preflight_uninstall

        codex = self.root / "codex"
        opencode = self.root / "opencode"
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                Request("install", (Target.CODEX,), {}, False, False, False, False),
            )
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                Request(
                    "install",
                    (Target.CODEX,),
                    {Target.CODEX: codex, Target.OPENCODE: opencode},
                    False,
                    False,
                    False,
                    False,
                ),
            )
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                Request(
                    "install",
                    (Target.CODEX, Target.OPENCODE),
                    {Target.CODEX: codex, Target.OPENCODE: codex / "x/.."},
                    False,
                    False,
                    False,
                    False,
                ),
            )
        with self.assertRaises(ValueError):
            preflight_uninstall(
                self.repository,
                Request(
                    "uninstall",
                    (Target.CODEX,),
                    {Target.CODEX: codex},
                    True,
                    False,
                    False,
                    False,
                ),
            )
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                Request(
                    "install",
                    (Target.OPENCODE,),
                    {Target.OPENCODE: opencode},
                    False,
                    True,
                    False,
                    False,
                ),
            )

    def test_placeholder_is_restricted_to_validator_and_home_cannot_retain_token(self):
        from subagents_configs.planning import preflight_install

        reviewer = self.repository / "agents/code-reviewer.toml"
        original = reviewer.read_bytes()
        try:
            reviewer.write_bytes(original + b"\n# {{VALIDATION_HELPER}}\n")
            with self.assertRaises(ValueError):
                preflight_install(
                    self.repository,
                    planning_request("install", self._homes(Target.CODEX)),
                )
        finally:
            reviewer.write_bytes(original)
        token_home = self.root / "home-{{VALIDATION_HELPER}}"
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                planning_request("install", {Target.CODEX: token_home}),
            )

    def test_selected_source_destination_collisions_fail_closed(self):
        from subagents_configs.formats import validate_source_inventory
        from subagents_configs.targets import descriptor_for

        descriptor = descriptor_for(Target.CODEX)
        first = next(
            item for item in descriptor.sources if item.identifier == "code-explorer"
        )
        routing = next(
            item for item in descriptor.sources if item.identifier == "routing"
        )
        duplicate = replace(
            routing,
            identifier="routing-copy",
            destination=first.destination,
        )
        with self.assertRaises(ValueError):
            validate_source_inventory(
                self.repository,
                Target.CODEX,
                (first, duplicate),
            )

        alias = replace(
            routing,
            identifier="routing-alias",
            destination="agents/./code-explorer.toml",
        )
        with self.assertRaises(ValueError):
            validate_source_inventory(
                self.repository,
                Target.CODEX,
                (first, alias),
            )

    def test_source_parent_swap_cannot_put_outside_bytes_in_inventory(self):
        from subagents_configs.formats import validate_source_inventory
        from subagents_configs.targets import descriptor_for

        descriptor = descriptor_for(Target.CODEX)
        source = next(
            item for item in descriptor.sources if item.identifier == "code-explorer"
        )
        agents = self.repository / "agents"
        detached = self.repository / "agents-detached"
        outside = self.repository / "outside-agents"
        outside.mkdir()
        outside_bytes = (
            (agents / "code-explorer.toml")
            .read_bytes()
            .replace(b"Read-only codebase scout", b"OUTSIDE bytes")
        )
        (outside / "code-explorer.toml").write_bytes(outside_bytes)
        swapped = False

        def swap(operation, parent):
            nonlocal swapped
            if operation == "source-read" and parent.name == "agents" and not swapped:
                agents.rename(detached)
                agents.symlink_to(outside, target_is_directory=True)
                swapped = True

        try:
            with patch("subagents_configs.filesystem._after_parent_pin", swap):
                inventory = validate_source_inventory(
                    self.repository, Target.CODEX, (source,)
                )
        finally:
            if agents.is_symlink():
                agents.unlink()
            if detached.exists():
                detached.rename(agents)
        self.assertNotIn(b"OUTSIDE bytes", inventory[0].content)

    def test_validator_placeholder_is_rendered_to_normalized_home(self):
        from subagents_configs.planning import preflight_install

        home = self.root / "nested" / ".." / "codex-home"
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        )
        validator = next(
            operation
            for operation in plan.targets[0].operations
            if operation.identifier == "code-validator"
        )
        expected = str((self.root / "codex-home").resolve())
        self.assertIn(
            f"{expected}/.subagents_configs/validation/run-validation-isolated.py".encode(),
            validator.content or b"",
        )
        self.assertNotIn(b"{{VALIDATION_HELPER}}", validator.content or b"")

    def test_preflight_rejects_codex_home_with_toml_terminating_quotes(
        self,
    ):
        from subagents_configs.planning import preflight_install
        from tests.helpers import tree_snapshot

        home = self.root / 'codex-"""-home'
        before = tree_snapshot(self.root)
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                planning_request("install", {Target.CODEX: home}),
            )
        self.assertEqual(tree_snapshot(self.root), before)

    def test_preflight_rejects_client_homes_with_newline_or_control(
        self,
    ):
        from subagents_configs.planning import preflight_install
        from tests.helpers import tree_snapshot

        for target, home in (
            (Target.OPENCODE, self.root / "opencode-\n-home"),
            (Target.CLAUDE_CODE, self.root / "claude-\x01-home"),
        ):
            before = tree_snapshot(self.root)
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    preflight_install(
                        self.repository,
                        planning_request("install", {target: home}),
                    )
            self.assertEqual(tree_snapshot(self.root), before)

    def test_operations_are_normalized_and_rendering_has_no_content_bytes(self):
        from subagents_configs.planning import preflight_install, render_plan

        home = self.root / "a" / ".." / "display-home"
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        )
        rendered = render_plan(plan)
        self.assertIn(str(self.root / "display-home"), rendered)
        self.assertNotIn("gpt-5.6-luna", rendered)
        self.assertNotIn("{{VALIDATION_HELPER}}", rendered)
        self.assertEqual(
            [operation.relative_path for operation in plan.targets[0].operations],
            sorted(operation.relative_path for operation in plan.targets[0].operations),
        )

    def test_identical_preexisting_reinstall_preserves_metadata_without_operation(self):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        destination = home / "agents" / "code-explorer.toml"
        destination.parent.mkdir(parents=True)
        source = self.repository / "agents/code-explorer.toml"
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o600)
        first = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        ).targets[0]
        entry = next(
            entry
            for entry in first.resulting_manifest.entries
            if entry.identifier == "code-explorer"
        )
        self._write_manifest(
            home,
            Manifest(2, Target.CODEX, (entry,)),
        )
        before = destination.stat()
        second = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        ).targets[0]
        matching = [
            operation
            for operation in second.operations
            if operation.identifier == "code-explorer"
        ]
        self.assertEqual(matching, [])
        self.assertEqual(
            next(
                item
                for item in second.resulting_manifest.entries
                if item.identifier == "code-explorer"
            ),
            entry,
        )
        self.assertEqual(destination.stat().st_mtime_ns, before.st_mtime_ns)

    def test_replacement_requires_backup_and_records_original_mode(self):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        destination = home / "agents" / "code-explorer.toml"
        destination.parent.mkdir(parents=True)
        destination.write_text("different user bytes\n", encoding="utf-8")
        destination.chmod(0o644)
        operation = next(
            operation
            for operation in preflight_install(
                self.repository,
                planning_request("install", {Target.CODEX: home}),
            )
            .targets[0]
            .operations
            if operation.identifier == "code-explorer"
        )
        self.assertEqual(operation.action, "replace")
        self.assertTrue(operation.backup_required)
        self.assertEqual(operation.expected_before_mode, 0o644)
        self.assertEqual(operation.expected_after_mode, 0o600)

    def test_broad_identical_preexisting_mode_is_a_conflict_without_chmod(self):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        destination = home / "agents" / "code-explorer.toml"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(
            (self.repository / "agents/code-explorer.toml").read_bytes()
        )
        destination.chmod(0o644)
        before = destination.stat().st_mode
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        ).targets[0]
        self.assertTrue(any("mode" in conflict for conflict in plan.conflicts))
        self.assertEqual(destination.stat().st_mode, before)

    def test_stale_created_removed_replaced_restored_and_drift_preserved(self):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        created = home / "agents" / "commit-pusher.toml"
        replaced = home / "config.toml"
        stale_drift = home / "AGENTS.md"
        for path in (created, replaced, stale_drift):
            path.parent.mkdir(parents=True, exist_ok=True)
        created_bytes = b"stale created\n"
        replaced_original = b"original user bytes\n"
        created.write_bytes(created_bytes)
        created.chmod(0o600)
        replacement_block = render_managed_block(
            "codex-multi-agent-v2",
            b'tool_namespace = "old"',
        )
        replaced.write_bytes(
            replacement_block.begin_marker
            + b"\n"
            + replacement_block.content
            + replacement_block.end_marker
            + b"\n"
        )
        replaced.chmod(0o600)
        stale_drift.write_bytes(b"user changed\n")
        backup = home / ".subagents_configs/backups/replaced"
        backup.parent.mkdir(parents=True, mode=0o700)
        backup.write_bytes(replaced_original)
        backup.chmod(0o600)
        manifest = Manifest(
            2,
            Target.CODEX,
            (
                self._manifest_entry(
                    "commit-pusher", "agents/commit-pusher.toml", created_bytes
                ),
                self._manifest_entry(
                    "codex-multi-agent-v2",
                    "config.toml",
                    replaced.read_bytes(),
                    ownership="replaced",
                    backup_path="backups/replaced",
                    backup_hash=hashlib.sha256(replaced_original).hexdigest(),
                    original_mode=0o644,
                    managed_block_id="codex-multi-agent-v2",
                    installed_block_hash=replacement_block.sha256,
                ),
                self._manifest_entry(
                    "routing-codex",
                    "AGENTS.md",
                    b"old managed\n",
                    managed_block_id="routing-codex",
                    installed_block_hash="a" * 64,
                ),
            ),
        )
        self._write_manifest(home, manifest)
        plan = preflight_install(
            self.repository,
            planning_request("install", {Target.CODEX: home}),
        ).targets[0]
        self.assertEqual(
            next(
                operation
                for operation in plan.operations
                if operation.identifier == "commit-pusher"
            ).action,
            "remove",
        )
        self.assertEqual(
            next(
                operation
                for operation in plan.operations
                if operation.identifier == "codex-multi-agent-v2"
            ).action,
            "remove-block",
        )
        self.assertTrue(any("drift" in conflict for conflict in plan.conflicts))
        self.assertTrue(
            any(entry.unresolved_reason for entry in plan.resulting_manifest.entries)
        )

    def test_corrupt_late_source_has_zero_writes(self):
        from subagents_configs.planning import preflight_install

        homes = self._homes(Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE)
        snapshots = {target: self._snapshot(home) for target, home in homes.items()}
        late = self.repository / "claude-code/agents/code-validator.md"
        original = late.read_bytes()
        late.write_bytes(b"---\nname: [broken\n---\n")
        try:
            with self.assertRaises(ValueError):
                preflight_install(
                    self.repository,
                    planning_request("install", homes, targets=tuple(homes)),
                )
        finally:
            late.write_bytes(original)
        self.assertEqual(
            snapshots,
            {target: self._snapshot(home) for target, home in homes.items()},
        )

    def test_corrupt_late_manifest_has_zero_writes(self):
        from subagents_configs.planning import preflight_install

        homes = self._homes(Target.CODEX, Target.CLAUDE_CODE)
        state = homes[Target.CLAUDE_CODE] / ".subagents_configs"
        state.mkdir(parents=True, mode=0o700)
        (state / "manifest.json").write_text("{not json\n", encoding="utf-8")
        (state / "manifest.json").chmod(0o600)
        snapshots = {target: self._snapshot(home) for target, home in homes.items()}
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                planning_request("install", homes, targets=tuple(homes)),
            )
        self.assertEqual(
            snapshots,
            {target: self._snapshot(home) for target, home in homes.items()},
        )

    def test_codex_does_not_import_yaml_but_yaml_target_fails_cleanly(self):
        from subagents_configs.planning import preflight_install

        real_import = builtins.__import__

        def no_yaml(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("blocked by test")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", no_yaml):
            preflight_install(
                self.repository,
                planning_request("install", self._homes(Target.CODEX)),
            )
            with self.assertRaises(RuntimeError):
                preflight_install(
                    self.repository,
                    planning_request("install", self._homes(Target.OPENCODE)),
                )

    def test_recognized_legacy_codex_manifest_converts_only_after_exact_path_and_hash_validation(  # noqa: E501
        self,
    ):
        from subagents_configs.planning import preflight_install

        home = self._homes(Target.CODEX)[Target.CODEX]
        home.mkdir(parents=True)
        legacy = home / ".subagents_configs-state.json"
        legacy.write_text('{"files": {}}\n', encoding="utf-8")
        before = self._snapshot(home)
        with self.assertRaisesRegex(ValueError, "manual recovery"):
            preflight_install(
                self.repository,
                planning_request("install", {Target.CODEX: home}),
            )
        self.assertEqual(before, self._snapshot(home))

    def test_symlink_home_and_managed_target_fail_without_writes(self):
        from subagents_configs.planning import preflight_install

        real_home = self._homes(Target.CODEX)[Target.CODEX]
        real_home.mkdir(parents=True)
        link_home = self.root / "linked-home"
        link_home.symlink_to(real_home, target_is_directory=True)
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                planning_request("install", {Target.CODEX: link_home}),
            )
        destination = real_home / "agents" / "code-explorer.toml"
        destination.parent.mkdir(parents=True)
        outside = self.root / "outside"
        outside.write_bytes(b"must remain unchanged")
        destination.symlink_to(outside)
        before = self._snapshot(real_home)
        with self.assertRaises(ValueError):
            preflight_install(
                self.repository,
                planning_request("install", {Target.CODEX: real_home}),
            )
        self.assertEqual(before, self._snapshot(real_home))
        self.assertEqual(outside.read_bytes(), b"must remain unchanged")

    def test_uninstall_plans_exact_created_removal_and_replaced_restore(self):
        from subagents_configs.planning import preflight_uninstall

        home = self._homes(Target.CODEX)[Target.CODEX]
        created = home / "agents/code-explorer.toml"
        replaced = home / "agents/code-reviewer.toml"
        created.parent.mkdir(parents=True)
        created.write_bytes(b"created\n")
        created.chmod(0o600)
        replaced.write_bytes(b"installed\n")
        replaced.chmod(0o600)
        original = b"original\n"
        backup = home / ".subagents_configs/backups/reviewer"
        backup.parent.mkdir(parents=True, mode=0o700)
        backup.write_bytes(original)
        backup.chmod(0o600)
        self._write_manifest(
            home,
            Manifest(
                2,
                Target.CODEX,
                (
                    self._manifest_entry(
                        "code-explorer",
                        "agents/code-explorer.toml",
                        b"created\n",
                    ),
                    self._manifest_entry(
                        "code-reviewer",
                        "agents/code-reviewer.toml",
                        b"installed\n",
                        ownership="replaced",
                        backup_path="backups/reviewer",
                        backup_hash=hashlib.sha256(original).hexdigest(),
                        original_mode=0o644,
                    ),
                ),
            ),
        )
        plan = preflight_uninstall(
            self.repository,
            planning_request(
                "uninstall",
                {Target.CODEX: home},
                targets=(Target.CODEX,),
            ),
        ).targets[0]
        actions = {
            operation.identifier: operation.action for operation in plan.operations
        }
        self.assertEqual(actions["code-explorer"], "remove")
        self.assertEqual(actions["code-reviewer"], "restore")

    def test_direct_pi_request_defers_consent_until_package_phase(self):
        home = self.root / "pi-home"
        request = Request(
            "install",
            (Target.PI,),
            {Target.PI: home},
            False,
            False,
            False,
            False,
            pi_executable=Path("/opt/pi"),
        )
        with patch("subagents_configs.planning.validate_validation_helper"):
            from subagents_configs.planning import validate_request_shape

            validate_request_shape(request, "install")

    def test_direct_pi_request_rejects_non_absolute_executable(self):
        home = self.root / "pi-home"
        request = Request(
            "install",
            (Target.PI,),
            {Target.PI: home},
            False,
            False,
            False,
            True,
            pi_executable=Path("~/pi"),
        )
        with patch("subagents_configs.planning.validate_validation_helper"):
            with self.assertRaises(ValueError):
                from subagents_configs.planning import validate_request_shape

                validate_request_shape(request, "install")

    def test_direct_pi_dry_run_rejects_retained_consent(self):
        request = Request(
            "install",
            (Target.PI,),
            {Target.PI: self.root / "pi-home"},
            False,
            False,
            False,
            True,
            pi_executable=Path("/opt/pi"),
            consent_third_party_code=True,
        )
        with patch("subagents_configs.planning.validate_validation_helper"):
            with self.assertRaises(ValueError):
                from subagents_configs.planning import validate_request_shape

                validate_request_shape(request, "install")

    def test_direct_pi_uninstall_package_removal_requires_executable(self):
        request = Request(
            "uninstall",
            (Target.PI,),
            {Target.PI: self.root / "pi-home"},
            False,
            False,
            False,
            False,
            remove_pi_package=True,
        )
        with patch("subagents_configs.planning.validate_validation_helper"):
            with self.assertRaises(ValueError):
                from subagents_configs.planning import validate_request_shape

                validate_request_shape(request, "uninstall")

    def _snapshot(self, home):
        if not home.exists():
            return None
        result = []
        for path in sorted(home.rglob("*")):
            relative = path.relative_to(home).as_posix()
            mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_symlink():
                result.append((relative, "symlink", os.readlink(path), mode))
            elif path.is_file():
                result.append((relative, "file", path.read_bytes(), mode))
            else:
                result.append((relative, "dir", mode))
        return tuple(result)


if __name__ == "__main__":
    unittest.main()
