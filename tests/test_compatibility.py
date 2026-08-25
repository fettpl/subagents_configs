import io
import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from subagents_configs.cli import parse_request
from subagents_configs.compatibility import (
    COMPATIBILITY_TARGETS,
    ClientCompatibility,
    CompatibilityResult,
    load_compatibility_matrix,
    validate_client_compatibility,
)
from subagents_configs.errors import CliError
from subagents_configs.models import Target
from subagents_configs.orchestrator import EXIT_PREFLIGHT_ERROR, run
from subagents_configs.targets import CAPABILITIES, DESCRIPTORS, capability_for
from tests.helpers import environment


def _row(**overrides):
    row = {
        "target": "codex",
        "supported": True,
        "format_version": "toml",
        "features": ["agents", "managed-blocks", "validation-runtime"],
        "minimum_client_version": "1.2.0",
        "tested_client_version": "1.4.0",
        "tested_python": ["3.11", "3.12"],
        "supported_platforms": ["linux", "macos"],
        "tested_os_backends": ["bwrap", "sandbox-exec"],
        "package_source": None,
        "scope": "user",
    }
    row.update(overrides)
    return row


class CompatibilityLoaderTests(unittest.TestCase):
    def test_checked_in_matrix_has_three_runtime_rows_and_unsupported_pi(self):
        rows = load_compatibility_matrix(
            Path(__file__).parents[1] / "catalogs/client-compatibility.json"
        )
        self.assertEqual({row.target for row in rows}, set(COMPATIBILITY_TARGETS))
        self.assertEqual(
            {row.target for row in rows if row.supported},
            {"codex", "opencode", "claude-code"},
        )
        pi = next(row for row in rows if row.target == "pi")
        self.assertFalse(pi.supported)
        self.assertIsNone(pi.tested_client_version)
        self.assertIsNone(pi.package_source)
        self.assertEqual(pi.supported_platforms, ())

    def test_loader_rejects_unknown_keys_duplicate_targets_and_invalid_versions(self):
        cases = (
            ({"extra": True}, "unknown"),
            ({"target": "codex"}, "duplicate"),
            ({"minimum_client_version": "1"}, "semver"),
            ({"tested_client_version": "1.2"}, "semver"),
            ({"features": []}, "feature"),
        )
        for changes, _label in cases:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "matrix.json"
                rows = [
                    _row(),
                    _row(target="opencode", format_version="yaml-frontmatter"),
                ]
                if "target" not in changes:
                    rows[0].update(changes)
                else:
                    rows[1]["target"] = changes["target"]
                path.write_text(json.dumps(rows), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_compatibility_matrix(path)

    def test_loader_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "matrix.json"
            row = json.dumps(_row())[:-1] + ', "target": "codex"}'
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "rows": [json.loads(row)],
                    }
                ).replace('"target": "codex"', '"target": "codex", "target": "codex"'),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_compatibility_matrix(path)

    def test_loader_rejects_supported_pi_and_missing_optional_pi_fields(self):
        for changes in (
            {"target": "pi", "supported": True},
            {"target": "pi", "supported": False, "tested_client_version": "1.0.0"},
            {"target": "pi", "supported": False, "features": ["agents"]},
        ):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "matrix.json"
                row = _row(**changes)
                if changes["target"] == "pi":
                    row["supported_platforms"] = []
                    row["scope"] = None
                    row["package_source"] = None
                path.write_text(json.dumps([row]), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_compatibility_matrix(path)


class CompatibilityAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = load_compatibility_matrix(
            Path(__file__).parents[1] / "catalogs/client-compatibility.json"
        )

    def test_unsupported_pi_is_queryable_without_runtime_registration(self):
        pi = next(row for row in self.rows if row.target == "pi")
        codex = capability_for(Target.CODEX)
        result = validate_client_compatibility(
            codex, pi, requested_features=frozenset()
        )
        self.assertFalse(result.supported)
        self.assertEqual(result.reasons, ("target_unsupported",))
        self.assertNotIn("pi", {target.value for target in Target})
        self.assertNotIn("pi", {target.value for target in DESCRIPTORS})

    def test_current_rows_validate_their_capability_contract(self):
        for capability in CAPABILITIES:
            row = next(
                row for row in self.rows if row.target == capability.target.value
            )
            result = validate_client_compatibility(
                capability,
                row,
                requested_features=frozenset(),
            )
            self.assertTrue(result.supported, result.reasons)
            self.assertEqual(result.reasons, ())

    def test_fixed_reasons_fail_closed_for_contract_fields(self):
        capability = capability_for(Target.CODEX)
        row = next(row for row in self.rows if row.target == "codex")
        mutations = (
            ("format_version", "yaml-frontmatter", "format_unsupported"),
            ("features", frozenset({"not-a-feature"}), "feature_unsupported"),
            ("supported_platforms", ("macos",), "platform_unsupported"),
            ("scope", "user", "scope_unsupported"),
            ("package_source", "npm:wrong", "package_unsupported"),
            ("minimum_client_version", "1.0.0", "client_version_too_old"),
        )
        for field, value, reason in mutations:
            with self.subTest(field=field):
                capability = capability_for(Target.CODEX)
                changed = {field: value}
                if field == "supported_platforms":
                    capability = replace(capability, supported_platforms=("linux",))
                elif field == "scope":
                    capability = replace(capability, scope="project")
                elif field == "package_source":
                    capability = replace(capability, package_source="npm:expected")
                candidate = ClientCompatibility(**{**row.__dict__, **changed})
                result = validate_client_compatibility(
                    capability,
                    candidate,
                    requested_features=frozenset(),
                    client_version="0.9.0",
                )
                self.assertFalse(result.supported)
                self.assertIn(reason, result.reasons)

    def test_optional_requested_features_are_checked(self):
        row = next(row for row in self.rows if row.target == "codex")
        result = validate_client_compatibility(
            capability_for(Target.CODEX),
            row,
            requested_features=frozenset({"feature-not-maintained"}),
        )
        self.assertFalse(result.supported)
        self.assertEqual(result.reasons, ("feature_unsupported",))

    def test_result_is_immutable_and_reasons_are_closed(self):
        result = CompatibilityResult(False, ("target_unsupported",))
        with self.assertRaises(FrozenInstanceError):
            result.supported = True
        with self.assertRaises(ValueError):
            CompatibilityResult(False, ("arbitrary",))

    def test_adapter_is_read_only_and_does_not_read_environment_or_write(self):
        row = next(row for row in self.rows if row.target == "codex")
        capability = capability_for(Target.CODEX)
        with patch(
            "subagents_configs.compatibility.Path.write_text",
            side_effect=AssertionError,
        ):
            result = validate_client_compatibility(
                capability, row, requested_features=frozenset()
            )
        self.assertTrue(result.supported)


class ClientVersionCliTests(unittest.TestCase):
    def test_client_version_is_caller_supplied_and_typed(self):
        request = parse_request(
            "install",
            ["--target", "codex", "--client-version", "codex=1.4.0"],
            environment(Path(tempfile.gettempdir())),
        )
        self.assertEqual(request.client_versions, {"codex": "1.4.0"})

    def test_client_version_rejects_duplicates_unselected_and_invalid_values(self):
        for argv in (
            [
                "--target",
                "codex",
                "--client-version",
                "codex=1.0.0",
                "--client-version",
                "codex=1.1.0",
            ],
            ["--target", "codex", "--client-version", "opencode=1.0.0"],
            ["--target", "codex", "--client-version", "codex=1"],
            ["--target", "codex", "--client-version", "codex=1.0.0\x00"],
        ):
            with self.subTest(argv=argv), self.assertRaises(CliError):
                parse_request("install", argv, environment(Path(tempfile.gettempdir())))

    def test_incompatible_dry_run_returns_fixed_reasons_without_writes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            home = root / "home"
            home.mkdir()
            before = set(root.rglob("*"))
            for format_name in ("text", "json"):
                out, err = io.StringIO(), io.StringIO()
                argv = [
                    "--target",
                    "codex",
                    "--home",
                    f"codex={home}",
                    "--client-version",
                    "codex=0.1.0",
                    "--dry-run",
                ]
                if format_name == "json":
                    argv += ["--format", "json"]
                status = run(
                    "install",
                    argv,
                    repo_root=Path(__file__).parents[1],
                    environ={"HOME": str(root)},
                    stdout=out,
                    stderr=err,
                )
                self.assertEqual(status, EXIT_PREFLIGHT_ERROR)
                self.assertIn("client_version_too_old", out.getvalue())
                self.assertIn("client_version_too_old", err.getvalue())
                if format_name == "json":
                    payload = json.loads(out.getvalue())
                    self.assertEqual(
                        payload["compatibility"]["reasons"], ["client_version_too_old"]
                    )
                self.assertEqual(set(root.rglob("*")), before)


if __name__ == "__main__":
    unittest.main()
