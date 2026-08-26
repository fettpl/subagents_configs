import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from subagents_configs.catalog_policy import (
    AuthorityCapability,
    DestinationPolicy,
    NormalizedCatalog,
    PolicyChange,
    PolicyChangeReport,
    RolePolicy,
    authorities_from_native,
    compare_catalogs,
    load_catalog,
    load_revision,
    render_policy_report,
    run_policy_diff,
)
from subagents_configs.models import Target


def catalog(*, roles=(), destinations=(), source_hashes=None, revision="before"):
    return NormalizedCatalog(
        target=Target.CODEX,
        revision=revision,
        roles=tuple(roles),
        destinations=tuple(destinations),
        source_hashes=source_hashes or {"agent": "a" * 64},
    )


class PolicyDiffTests(unittest.TestCase):
    @staticmethod
    def _generated_payload(target="codex"):
        path = Path(__file__).resolve().parents[1] / "catalogs" / f"{target}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _refresh_catalog_hash(payload):
        body = dict(payload)
        body.pop("catalog_sha256", None)
        payload["catalog_sha256"] = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        ).hexdigest()

    def _load_mutated_generated(self, payload):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return load_catalog(path)

    def test_compare_reports_each_policy_dimension(self):
        before_role = RolePolicy(
            target=Target.CODEX,
            role="reviewer",
            model="model-a",
            effort="low",
            tools=frozenset({"read"}),
            permissions=frozenset({"read"}),
            authorities=frozenset({AuthorityCapability.FILESYSTEM_READ}),
        )
        after_role = RolePolicy(
            target=Target.CODEX,
            role="reviewer",
            model="model-b",
            effort="high",
            tools=frozenset({"read", "shell"}),
            permissions=frozenset({"read", "write"}),
            authorities=frozenset(
                {
                    AuthorityCapability.FILESYSTEM_READ,
                    AuthorityCapability.SHELL_EXECUTION,
                }
            ),
        )
        report = compare_catalogs(
            catalog(
                roles=(before_role,),
                destinations=(DestinationPolicy(Target.CODEX, "reviewer", "agents/a"),),
            ),
            catalog(
                revision="after",
                roles=(after_role,),
                destinations=(DestinationPolicy(Target.CODEX, "reviewer", "agents/b"),),
                source_hashes={"agent": "b" * 64},
            ),
        )
        self.assertEqual(
            {change.kind for change in report.changes},
            {"model", "permission", "tool", "destination", "source_hash", "authority"},
        )
        authority = [c for c in report.changes if c.kind == "authority"]
        self.assertEqual(len(authority), 1)
        self.assertTrue(authority[0].authority_broadening)

    def test_every_added_authority_is_broadening_and_removal_is_not(self):
        all_capabilities = frozenset(AuthorityCapability)
        before = RolePolicy(Target.CODEX, "role", authorities=frozenset())
        after = RolePolicy(Target.CODEX, "role", authorities=all_capabilities)
        report = compare_catalogs(
            catalog(roles=(before,)), catalog(roles=(after,), revision="after")
        )
        additions = [c for c in report.changes if c.kind == "authority"]
        self.assertEqual(len(additions), len(all_capabilities))
        self.assertTrue(all(change.authority_broadening for change in additions))
        removal = compare_catalogs(
            catalog(roles=(after,)), catalog(roles=(before,), revision="after")
        )
        self.assertTrue(
            all(
                not c.authority_broadening
                for c in removal.changes
                if c.kind == "authority"
            )
        )

    def test_rendering_is_deterministic_and_redacted(self):
        change = PolicyChange(
            kind="model",
            target=Target.CODEX,
            role="reviewer",
            before="old",
            after="new",
            authority_broadening=False,
        )
        report = PolicyChangeReport("before", "after", (change,))
        text = render_policy_report(report, format="text")
        encoded = render_policy_report(report, format="json")
        self.assertIn("before", text)
        self.assertNotIn("/private/", text)
        self.assertEqual(
            json.loads(encoded),
            {
                "from_revision": "before",
                "to_revision": "after",
                "changes": [
                    {
                        "kind": "model",
                        "target": "codex",
                        "role": "reviewer",
                        "before": "old",
                        "after": "new",
                        "authority_broadening": False,
                    }
                ],
            },
        )

    def test_loader_rejects_unknown_keys_and_symlinks_without_reading_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = {
                "schema_version": 1,
                "revision": "safe",
                "target": "codex",
                "roles": [],
                "destinations": [],
                "source_hashes": {"role": "a" * 64},
            }
            path = root / "catalog.json"
            path.write_text(json.dumps(valid))
            loaded = load_catalog(path)
            self.assertEqual(loaded.revision, "safe")
            path.write_text(json.dumps({**valid, "private": "secret"}))
            with self.assertRaises(ValueError):
                load_catalog(path)

    def test_every_authority_member_has_stable_value_and_addition_is_broadening(self):
        expected = {
            "filesystem-read",
            "filesystem-write",
            "shell-execution",
            "network",
            "credentials",
            "external-directory",
            "mcp",
            "extension",
            "package",
            "skill",
            "publication",
            "repository-history",
        }
        self.assertEqual({item.value for item in AuthorityCapability}, expected)
        before = catalog(roles=(RolePolicy(Target.CODEX, "role"),))
        for capability in AuthorityCapability:
            after_role = RolePolicy(
                Target.CODEX, "role", authorities=frozenset({capability})
            )
            report = compare_catalogs(
                before,
                catalog(roles=(after_role,), revision="after"),
            )
            authority = [item for item in report.changes if item.kind == "authority"]
            self.assertEqual(len(authority), 1)
            self.assertEqual(authority[0].after, capability.value)
            self.assertTrue(authority[0].authority_broadening)

    def test_strict_normalized_schema_rejects_wrong_shapes_and_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = {
                "schema_version": 1,
                "revision": "safe",
                "target": "codex",
                "roles": [
                    {
                        "target": "codex",
                        "role": "reviewer",
                        "model": "model",
                        "effort": "low",
                        "tools": ["read"],
                        "permissions": ["read"],
                        "authorities": ["filesystem-read"],
                    }
                ],
                "destinations": [
                    {
                        "target": "codex",
                        "role": "reviewer",
                        "destination": "agents/reviewer",
                    }
                ],
                "source_hashes": {"reviewer": "a" * 64},
            }
            path = root / "catalog.json"
            path.write_text(json.dumps(valid), encoding="utf-8")
            self.assertEqual(load_catalog(path).roles[0].role, "reviewer")
            for mutation in (
                {**valid, "unexpected": 1},
                {**valid, "schema_version": "1"},
                {**valid, "source_hashes": {"reviewer": "A" * 64}},
                {**valid, "roles": [{**valid["roles"][0], "extra": 1}]},
                {
                    **valid,
                    "roles": [{**valid["roles"][0], "authorities": ["mcp-server"]}],
                },
            ):
                path.write_text(json.dumps(mutation), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_catalog(path)

    def test_native_authority_mapping_is_explicit_and_fail_closed(self):
        self.assertEqual(
            authorities_from_native(
                Target.OPENCODE,
                {"permission": {"bash": "allow", "external_directory": "allow"}},
            ),
            frozenset(
                {
                    AuthorityCapability.SHELL_EXECUTION,
                    AuthorityCapability.EXTERNAL_DIRECTORY,
                }
            ),
        )
        self.assertEqual(
            authorities_from_native(
                Target.CLAUDE_CODE,
                {"tools": "Read, Grep, Bash, MCP, Skill, Edit"},
            ),
            frozenset(
                {
                    AuthorityCapability.FILESYSTEM_READ,
                    AuthorityCapability.FILESYSTEM_WRITE,
                    AuthorityCapability.SHELL_EXECUTION,
                    AuthorityCapability.MCP,
                    AuthorityCapability.SKILL,
                }
            ),
        )
        with self.assertRaises(ValueError):
            authorities_from_native(
                Target.OPENCODE, {"permission": {"mcp-server": "allow"}}
            )
        with self.assertRaises(ValueError):
            authorities_from_native(Target.CODEX, {"unknown_permission": True})

    def test_revision_directory_requires_one_catalog_or_canonical_target_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = {
                "schema_version": 1,
                "revision": "before",
                "target": "codex",
                "roles": [],
                "destinations": [],
                "source_hashes": {},
            }
            (root / "catalog.json").write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(load_revision(root)[0].target, Target.CODEX)
            (root / "extra.json").write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_revision(root)

    def test_render_rejects_untrusted_policy_values_instead_of_leaking_them(self):
        with self.assertRaises(ValueError):
            render_policy_report(
                PolicyChangeReport(
                    "before",
                    "after",
                    (
                        PolicyChange(
                            "model",
                            Target.CODEX,
                            "reviewer",
                            "/private/secret",
                            "safe",
                            False,
                        ),
                    ),
                ),
                format="json",
            )

    def test_loader_rejects_duplicate_keys_members_and_noncanonical_order(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            duplicate_key = (
                '{"schema_version":1,"schema_version":1,"revision":"safe",'
                '"target":"codex","roles":[],"destinations":[],"source_hashes":{}}'
            )
            path.write_text(duplicate_key, encoding="utf-8")
            with self.assertRaises(ValueError):
                load_catalog(path)
            valid = {
                "schema_version": 1,
                "revision": "safe",
                "target": "codex",
                "roles": [],
                "destinations": [],
                "source_hashes": {},
            }
            valid["roles"] = [
                {
                    "target": "codex",
                    "role": "z-role",
                    "model": None,
                    "effort": None,
                    "tools": [],
                    "permissions": [],
                    "authorities": [],
                },
                {
                    "target": "codex",
                    "role": "a-role",
                    "model": None,
                    "effort": None,
                    "tools": [],
                    "permissions": [],
                    "authorities": [],
                },
            ]
            path.write_text(json.dumps(valid), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_catalog(path)
            valid["roles"] = [valid["roles"][0], valid["roles"][0]]
            path.write_text(json.dumps(valid), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_catalog(path)

    def test_loaders_reject_special_files_and_never_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = {
                "schema_version": 1,
                "revision": "safe",
                "target": "codex",
                "roles": [],
                "destinations": [],
                "source_hashes": {},
            }
            path = root / "catalog.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            before = sorted(item.name for item in root.iterdir())
            load_catalog(path)
            self.assertEqual(before, sorted(item.name for item in root.iterdir()))
            fifo = root / "special"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                load_catalog(fifo)
            with self.assertRaises(ValueError):
                load_revision(root)

    def test_native_authority_tables_are_exact_for_each_target(self):
        self.assertEqual(
            authorities_from_native(
                Target.CODEX,
                {"sandbox_mode": "workspace-write", "network_access": True},
            ),
            frozenset(
                {
                    AuthorityCapability.FILESYSTEM_READ,
                    AuthorityCapability.FILESYSTEM_WRITE,
                    AuthorityCapability.NETWORK,
                }
            ),
        )
        self.assertEqual(
            authorities_from_native(
                Target.CLAUDE_CODE,
                {"tools": "Read, Edit, Bash, MCP, Skill", "permissionMode": "plan"},
            ),
            frozenset(
                {
                    AuthorityCapability.FILESYSTEM_READ,
                    AuthorityCapability.FILESYSTEM_WRITE,
                    AuthorityCapability.SHELL_EXECUTION,
                    AuthorityCapability.MCP,
                    AuthorityCapability.SKILL,
                }
            ),
        )
        for target, native in (
            (Target.CODEX, {"sandbox_mode": "unknown"}),
            (Target.CODEX, {"network_access": 1}),
            (Target.OPENCODE, {"permission": {"bash": {"unknown": "allow"}}}),
            (Target.CLAUDE_CODE, {"tools": "Readish"}),
            (Target.CLAUDE_CODE, {"permissionMode": "unknown"}),
        ):
            with (
                self.subTest(target=target, native=native),
                self.assertRaises(ValueError),
            ):
                authorities_from_native(target, native)

    def test_immutable_models_and_source_path_identifiers(self):
        hashes = {"scripts/validator": "a" * 64}
        item = NormalizedCatalog(Target.CODEX, "safe", (), (), hashes)
        hashes["new"] = "b" * 64
        self.assertNotIn("new", item.source_hashes)
        with self.assertRaises(TypeError):
            item.source_hashes["new"] = "b" * 64
        with self.assertRaises((AttributeError, TypeError)):
            item.revision = "changed"
        report = compare_catalogs(
            NormalizedCatalog(
                Target.CODEX, "before", (), (), {"scripts/validator": "a" * 64}
            ),
            NormalizedCatalog(
                Target.CODEX, "after", (), (), {"scripts/validator": "b" * 64}
            ),
        )
        self.assertEqual(report.changes[0].role, "scripts/validator")

    def test_role_and_source_hash_directions_are_reported(self):
        before = catalog(
            roles=(RolePolicy(Target.CODEX, "removed"),),
            source_hashes={"old": "a" * 64},
        )
        after = catalog(
            roles=(RolePolicy(Target.CODEX, "added"),),
            source_hashes={"new": "b" * 64},
            revision="after",
        )
        report = compare_catalogs(before, after)
        self.assertEqual(
            {
                (change.kind, change.role, change.before, change.after)
                for change in report.changes
            },
            {
                ("role", "removed", "removed", None),
                ("role", "added", None, "added"),
                ("source_hash", "old", "a" * 64, None),
                ("source_hash", "new", None, "b" * 64),
            },
        )

    def test_added_and_removed_roles_emit_nested_policy_changes(self):
        populated = RolePolicy(
            Target.CODEX,
            "added",
            model="model-a",
            tools=frozenset({"shell"}),
            permissions=frozenset({"write"}),
            authorities=frozenset(
                {
                    AuthorityCapability.FILESYSTEM_WRITE,
                    AuthorityCapability.SHELL_EXECUTION,
                }
            ),
        )
        empty = RolePolicy(Target.CODEX, "added")
        added = compare_catalogs(
            catalog(roles=()),
            catalog(roles=(populated,), revision="after"),
        )
        removed = compare_catalogs(
            catalog(roles=(populated,)),
            catalog(roles=(empty,), revision="after"),
        )
        self.assertEqual(
            {item.kind for item in added.changes},
            {"role", "model", "tool", "permission", "authority"},
        )
        self.assertEqual(
            {item.after for item in added.changes if item.kind == "authority"},
            {"filesystem-write", "shell-execution"},
        )
        self.assertTrue(
            all(
                item.authority_broadening
                for item in added.changes
                if item.kind == "authority"
            )
        )
        self.assertEqual(
            {item.kind for item in removed.changes},
            {"model", "tool", "permission", "authority"},
        )
        self.assertTrue(
            all(
                not item.authority_broadening
                for item in removed.changes
                if item.kind == "authority"
            )
        )

    def test_policy_change_values_are_kind_specific_and_strict(self):
        invalid = (
            ("model", "agents/model", "safe"),
            ("tool", "agents/tool", None),
            ("permission", "permission with spaces", None),
            ("destination", "agents/../secret", None),
            ("source_hash", "not-a-hash", None),
            ("authority", "unknown-authority", None),
        )
        for kind, before, after in invalid:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                PolicyChange(kind, Target.CODEX, "role", before, after, False)
        with self.assertRaises(ValueError):
            PolicyChange("effort", Target.CODEX, "role", "low", "high", False)

    def test_normalized_catalog_rejects_multiple_destinations_for_one_role(self):
        with self.assertRaises(ValueError):
            NormalizedCatalog(
                Target.CODEX,
                "safe",
                (RolePolicy(Target.CODEX, "role"),),
                (
                    DestinationPolicy(Target.CODEX, "role", "agents/a"),
                    DestinationPolicy(Target.CODEX, "role", "agents/b"),
                ),
                {},
            )

    def test_revision_filename_target_binding_rejects_swapped_catalogs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename, target in (
                ("codex.json", "opencode"),
                ("opencode.json", "codex"),
                ("claude-code.json", "claude-code"),
            ):
                (root / filename).write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "revision": "safe",
                            "target": target,
                            "roles": [],
                            "destinations": [],
                            "source_hashes": {},
                        }
                    ),
                    encoding="utf-8",
                )
            with self.assertRaises(ValueError):
                load_revision(root)

    def test_descriptor_loaders_reject_symlink_races_without_reading_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.json"
            outside.write_text("private-catalog-content", encoding="utf-8")
            link = root / "catalog.json"
            link.symlink_to(outside)
            with self.assertRaises(ValueError):
                load_catalog(link)
            revision = root / "revision"
            revision.mkdir()
            for target in ("codex", "opencode", "claude-code"):
                payload = {
                    "schema_version": 1,
                    "revision": "safe",
                    "target": target,
                    "roles": [],
                    "destinations": [],
                    "source_hashes": {},
                }
                (revision / f"{target}.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )
            swapped = root / "swapped.json"
            swapped.write_text("private-catalog-content", encoding="utf-8")
            (revision / "codex.json").unlink()
            (revision / "codex.json").symlink_to(swapped)
            with self.assertRaises(ValueError):
                load_revision(revision)
            self.assertEqual(
                outside.read_text(encoding="utf-8"), "private-catalog-content"
            )

    def test_generated_catalog_is_normalized_without_reading_sources(self):
        generated = Path(__file__).resolve().parents[1] / "catalogs" / "codex.json"
        loaded = load_catalog(generated)
        self.assertIs(loaded.target, Target.CODEX)
        self.assertEqual(
            loaded.revision,
            "072b9f6c5f7592e0d5de04044de2ff0825ec6f555ef8f2a9cf7e7306b8decb4a",
        )
        self.assertEqual(len(loaded.roles), 6)
        self.assertEqual(
            len(loaded.source_hashes), len(json.loads(generated.read_text())["sources"])
        )

    def test_generated_catalog_rejects_stale_catalog_hash_after_model_mutation(self):
        payload = self._generated_payload()
        payload["roles"][0]["overlay"]["model"] = "gpt-5.6-sol"
        with self.assertRaises(ValueError):
            self._load_mutated_generated(payload)

    def test_generated_catalog_rejects_stale_role_and_source_component_hashes(self):
        role_payload = self._generated_payload()
        role_payload["roles"][0]["policy_sha256"] = "a" * 64
        self._refresh_catalog_hash(role_payload)
        with self.assertRaises(ValueError):
            self._load_mutated_generated(role_payload)

        source_payload = self._generated_payload()
        source_payload["sources"][0]["sha256"] = "b" * 64
        self._refresh_catalog_hash(source_payload)
        with self.assertRaises(ValueError):
            self._load_mutated_generated(source_payload)

    def test_generated_catalog_rejects_unknown_or_changed_lifecycle_capabilities(self):
        for mutation in (
            lambda values: [*values, "package"],
            lambda values: values[:-1],
            lambda values: [*values, values[0]],
            lambda values: list(reversed(values)),
        ):
            with self.subTest(mutation=mutation):
                payload = self._generated_payload()
                payload["lifecycle_capabilities"] = mutation(
                    payload["lifecycle_capabilities"]
                )
                self._refresh_catalog_hash(payload)
                with self.assertRaises(ValueError):
                    self._load_mutated_generated(payload)

    def test_generated_catalog_rejects_duplicate_or_noncanonical_optional_blocks(self):
        original = self._generated_payload()
        mutations = (
            original["optional_blocks"] + [dict(original["optional_blocks"][0])],
            list(reversed(original["optional_blocks"])),
        )
        for optional_blocks in mutations:
            with self.subTest(optional_blocks=optional_blocks):
                payload = self._generated_payload()
                payload["optional_blocks"] = optional_blocks
                self._refresh_catalog_hash(payload)
                with self.assertRaises(ValueError):
                    self._load_mutated_generated(payload)

    def test_all_checked_in_generated_catalogs_normalize(self):
        root = Path(__file__).resolve().parents[1] / "catalogs"
        for target in Target:
            with self.subTest(target=target):
                loaded = load_catalog(root / f"{target.value}.json")
                self.assertIs(loaded.target, target)
                self.assertTrue(loaded.roles)
                self.assertEqual(len(loaded.roles), len(loaded.destinations))

    def test_policy_diff_rejects_duplicate_or_abbreviated_options_before_reads(self):
        missing = Path("/this/path/must/not/be/read")
        for argv in (
            [
                "--from",
                str(missing),
                "--from",
                str(missing),
                "--to",
                str(missing),
                "--format",
                "json",
            ],
            ["--fr", str(missing), "--to", str(missing), "--format", "json"],
            [
                "--from",
                str(missing),
                "--to",
                str(missing),
                "--format",
                "json",
                "--unknown",
            ],
            ["--from", str(missing), "--to", str(missing), "--format", "json", "--"],
            [
                "--from",
                str(missing.parent / ".." / "unsafe"),
                "--to",
                str(missing),
                "--format",
                "json",
            ],
        ):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                run_policy_diff(argv)

    def test_policy_diff_aggregates_matching_target_sets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "before"
            after = root / "after"
            before.mkdir()
            after.mkdir()
            for target in ("codex", "opencode", "claude-code"):
                payload = {
                    "schema_version": 1,
                    "revision": "before",
                    "target": target,
                    "roles": [],
                    "destinations": [],
                    "source_hashes": {},
                }
                (before / f"{target}.json").write_text(json.dumps(payload))
                payload["revision"] = "after"
                (after / f"{target}.json").write_text(json.dumps(payload))
            rendered = run_policy_diff(
                ["--from", str(before), "--to", str(after), "--format", "json"]
            )
            self.assertEqual(
                json.loads(rendered),
                {
                    "from_revision": "before",
                    "to_revision": "after",
                    "reports": [
                        {"target": "claude-code", "changes": []},
                        {"target": "codex", "changes": []},
                        {"target": "opencode", "changes": []},
                    ],
                },
            )

    def test_policy_diff_entrypoints_are_standalone_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "before.json"
            after = root / "after.json"
            payload = {
                "schema_version": 1,
                "revision": "before",
                "target": "codex",
                "roles": [],
                "destinations": [],
                "source_hashes": {},
            }
            before.write_text(json.dumps(payload))
            payload["revision"] = "after"
            after.write_text(json.dumps(payload))
            args = [
                "policy-diff",
                "--from",
                str(before),
                "--to",
                str(after),
                "--format",
                "json",
            ]
            env = {"PATH": os.environ["PATH"], "HOME": str(root / "must-not-be-read")}
            script = (
                Path(__file__).resolve().parents[1]
                / "scripts"
                / "manage-subagents-configs.py"
            )
            result = subprocess.run(  # noqa: S603
                [sys.executable, str(script), *args],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(result.stdout)["reports"],
                [{"target": "codex", "changes": []}],
            )
            result = subprocess.run(  # noqa: S603
                [sys.executable, "-m", "subagents_configs", *args],
                capture_output=True,
                text=True,
                env=env,
                cwd=Path(__file__).resolve().parents[1],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(result.stdout)["reports"],
                [{"target": "codex", "changes": []}],
            )


if __name__ == "__main__":
    unittest.main()
