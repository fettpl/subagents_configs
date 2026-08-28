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
    pi_release_transition_allowed,
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
        "status": "released",
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
    def test_loader_requires_exact_v1_object_envelope_and_list_rows(self):
        valid = {"schema_version": 1, "rows": [_row()]}
        cases = (
            [_row()],
            {"schema_version": True, "rows": [_row()]},
            {"schema_version": 1.0, "rows": [_row()]},
            {"schema_version": 1, "rows": tuple([_row()])},
            {"schema_version": 1, "rows": [_row()], "extra": False},
        )
        for raw in cases:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "matrix.json"
                path.write_text(json.dumps(raw), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_compatibility_matrix(path)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "matrix.json"
            path.write_text(json.dumps(valid), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_compatibility_matrix(path)

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
        self.assertEqual(pi.status, "unreleased")

    def test_compatibility_projection_has_canonical_columns_and_pi_boundary(self):
        rows = load_compatibility_matrix(
            Path(__file__).parents[1] / "catalogs/client-compatibility.json"
        )
        text = (Path(__file__).parents[1] / "docs/COMPATIBILITY.md").read_text(
            encoding="utf-8"
        )
        table = ("| Client |" + text.split("| Client |", 1)[1]).split("\n\n", 1)[0]
        lines = [
            line.strip() for line in table.splitlines() if line.strip().startswith("|")
        ]
        self.assertGreaterEqual(len(lines), 2)
        self.assertEqual(
            [cell.strip().lower() for cell in lines[0].strip("|").split("|")],
            [
                "client",
                "supported scope",
                "home variable/default",
                "native format",
                "runtime/package evidence",
                "validation backends",
                "unsupported scope",
            ],
        )
        data = [
            line
            for line in lines[1:]
            if set(line.replace("|", "").replace("-", "").replace(":", "").strip())
        ]
        self.assertEqual(len(data), len(rows))
        for row, line in zip(rows, data, strict=True):
            cells = [cell.strip().lower() for cell in line.strip("|").split("|")]
            self.assertEqual(len(cells), 7)
            self.assertEqual(cells[0], row.target)
            self.assertIn(row.status, cells[1])
            if row.target == "pi":
                self.assertIn("unsupported", cells[1])
                self.assertIn("PI_CODING_AGENT_DIR".lower(), cells[2])
                self.assertIn("~/.pi/agent", cells[2])
                self.assertIn("markdown", cells[3])
                self.assertIn("0.84.1", cells[4])
                self.assertIn("npm:pi-subagents@0.56.0", cells[4])
                self.assertIn("@earendil-works/pi-ai >=0.80.0", cells[4])
                self.assertIn("macos/linux", cells[5])
                self.assertIn("windows", cells[6])

    def test_compatibility_projection_derives_every_column_from_canonical_facts(self):
        root = Path(__file__).parents[1]
        rows = load_compatibility_matrix(root / "catalogs/client-compatibility.json")
        package_policy = json.loads(
            (root / "pi/package-policy.json").read_text(encoding="utf-8")
        )
        text = (root / "docs/COMPATIBILITY.md").read_text(encoding="utf-8")
        table = ("| Client |" + text.split("| Client |", 1)[1]).split("\n\n", 1)[0]
        lines = [
            line.strip() for line in table.splitlines() if line.strip().startswith("|")
        ]
        data = [
            line
            for line in lines[1:]
            if set(line.replace("|", "").replace("-", "").replace(":", "").strip())
        ]

        def clean(cell: str) -> str:
            return cell.strip().lower().replace("`", "")

        def format_name(source_format: str) -> str:
            return {
                "toml": "toml",
                "yaml-frontmatter": "yaml frontmatter",
                "markdown": "markdown",
                "typescript": "typescript",
            }[source_format]

        self.assertEqual(len(data), len(rows))
        for row, line in zip(rows, data, strict=True):
            with self.subTest(target=row.target):
                cells = [clean(cell) for cell in line.strip("|").split("|")]
                self.assertEqual(len(cells), 7)

                target = Target(row.target)
                capability = capability_for(target)
                descriptor = DESCRIPTORS[target]
                self.assertEqual(cells[0], row.target)
                self.assertEqual(row.format_version, capability.source_format)
                self.assertEqual(
                    row.scope,
                    capability.scope if row.supported else None,
                )
                self.assertEqual(
                    cells[1],
                    f"{row.status} / {'supported' if row.supported else 'unsupported'}",
                )
                self.assertEqual(
                    cells[2],
                    f"{descriptor.environment_variable} / "
                    f"{descriptor.default_home}".lower(),
                )

                agent_formats = {
                    source.source_format
                    for source in descriptor.sources
                    if source.kind == "agent"
                }
                self.assertEqual(len(agent_formats), 1)
                agent_format = format_name(next(iter(agent_formats)))
                extension_sources = [
                    source
                    for source in descriptor.sources
                    if source.kind == "target-extension"
                ]
                if extension_sources:
                    self.assertEqual(len(extension_sources), 1)
                    native_format = (
                        f"{agent_format} agents plus "
                        f"{format_name(extension_sources[0].source_format)} extension"
                    )
                else:
                    routing_sources = [
                        source
                        for source in descriptor.sources
                        if source.kind == "routing-source"
                    ]
                    self.assertEqual(len(routing_sources), 1)
                    routing_format = format_name(routing_sources[0].source_format)
                    native_format = (
                        f"{agent_format} plus {routing_format}"
                        if agent_format == "yaml frontmatter"
                        else f"{agent_format} agents plus {routing_format} routing"
                    )
                self.assertEqual(cells[3], native_format)

                if target is Target.PI:
                    peer = package_policy["peerDependencies"]["@earendil-works/pi-ai"]
                    runtime_evidence = (
                        f"intended evidence boundary: pi "
                        f"{package_policy['testedPiVersion']}; pi --offline --"
                        "version / "
                        f"pi --help; {package_policy['source']}; peer "
                        f"@earendil-works/pi-ai {peer}"
                    )
                else:
                    package_evidence = (
                        "no package"
                        if row.package_source is None
                        else f"package {row.package_source}"
                    )
                    runtime_evidence = f"maintained client row; {package_evidence}"
                self.assertEqual(cells[4], runtime_evidence)

                if row.supported:
                    platforms = "/".join(
                        "macOS" if item == "macos" else item
                        for item in row.supported_platforms
                    )
                    backends = " / ".join(row.tested_os_backends)
                    self.assertEqual(cells[5], f"{platforms}: {backends}".lower())
                    self.assertEqual(cells[6], "pi-only lifecycle and package features")
                else:
                    intended_platforms = "/".join(
                        "macOS" if item == "macos" else item
                        for item in reversed(capability.supported_platforms)
                    )
                    self.assertEqual(
                        cells[5],
                        (
                            f"{intended_platforms}: isolated offline real-pi smoke "
                            "required by task 11"
                        ).lower(),
                    )
                    self.assertEqual(
                        cells[6],
                        "windows fail-closed; project scope and live provider smoke "
                        "are not supported claims",
                    )

    def test_pi_row_remains_unreleased_and_unclaimed_in_machine_matrix(self):
        rows = load_compatibility_matrix(
            Path(__file__).parents[1] / "catalogs/client-compatibility.json"
        )
        pi = next(row for row in rows if row.target == "pi")
        self.assertEqual((pi.supported, pi.status), (False, "unreleased"))
        self.assertIsNone(pi.minimum_client_version)
        self.assertIsNone(pi.tested_client_version)
        self.assertIsNone(pi.package_source)
        self.assertEqual(pi.supported_platforms, ())
        self.assertIsNone(pi.scope)

    def test_pi_transition_is_release_only_and_requires_complete_evidence(self):
        evidence = {
            "status": "ok",
            "version": "0.84.1",
            "package_status": "exact",
            "evidence": (
                "PI_SMOKE_OK",
                "VALIDATOR_HELPER_EXECUTED",
                "BASH_REJECTED",
            ),
        }
        self.assertFalse(
            pi_release_transition_allowed(evidence, all_gates_passed=False)
        )
        self.assertTrue(pi_release_transition_allowed(evidence, all_gates_passed=True))
        incomplete = dict(evidence, evidence=("PI_SMOKE_OK",))
        self.assertFalse(
            pi_release_transition_allowed(incomplete, all_gates_passed=True)
        )
        rows = load_compatibility_matrix(
            Path(__file__).parents[1] / "catalogs/client-compatibility.json"
        )
        pi = next(row for row in rows if row.target == "pi")
        self.assertEqual((pi.supported, pi.status), (False, "unreleased"))

    def test_status_is_required_and_closed(self):
        valid = _row(status="released")
        invalid = (
            {**valid, "status": "unreleased"},
            {key: value for key, value in valid.items() if key != "status"},
            {**valid, "status": "preview"},
        )
        for row in invalid:
            with self.subTest(row=row):
                with tempfile.TemporaryDirectory() as raw:
                    path = Path(raw) / "matrix.json"
                    path.write_text(json.dumps({"schema_version": 1, "rows": [row]}))
                    with self.assertRaises(ValueError):
                        load_compatibility_matrix(path)

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
        pi_release_claim = _row(
            target="pi",
            status="released",
            supported=True,
            format_version="markdown",
            features=["agents", "managed-blocks", "validation-runtime"],
            tested_client_version="1.0.0",
            supported_platforms=["linux", "macos"],
            scope="user",
        )
        for changes in (
            {"target": "pi", "status": "released", "supported": True},
            {"target": "pi", "supported": False, "tested_client_version": "1.0.0"},
            {"target": "pi", "supported": False, "features": ["agents"]},
        ):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "matrix.json"
                if changes.get("supported") is True:
                    rows = [
                        _row(),
                        _row(target="opencode", format_version="yaml-frontmatter"),
                        _row(target="claude-code", format_version="yaml-frontmatter"),
                        pi_release_claim,
                    ]
                else:
                    row = _row(**changes)
                    row["supported_platforms"] = []
                    row["scope"] = None
                    row["package_source"] = None
                    rows = [row]
                path.write_text(
                    json.dumps({"schema_version": 1, "rows": rows}),
                    encoding="utf-8",
                )
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
        pi_capability = capability_for(Target.PI)
        result = validate_client_compatibility(
            pi_capability, pi, requested_features=frozenset()
        )
        self.assertFalse(result.supported)
        self.assertEqual(result.reasons, ("target_unsupported",))
        self.assertIn("pi", {target.value for target in Target})
        self.assertIn("pi", {target.value for target in DESCRIPTORS})

    def test_current_rows_validate_their_capability_contract(self):
        for capability in CAPABILITIES:
            if capability.target is Target.PI:
                continue
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

    def test_runtime_registry_declares_explicit_authoritative_features(self):
        expected = {
            Target.CODEX: frozenset(
                {
                    "agents",
                    "managed-blocks",
                    "validation-runtime",
                    "codex-multi-agent-v2",
                }
            ),
            Target.OPENCODE: frozenset(
                {"agents", "managed-blocks", "validation-runtime"}
            ),
            Target.CLAUDE_CODE: frozenset(
                {"agents", "managed-blocks", "validation-runtime", "command-gate"}
            ),
            Target.PI: frozenset({"agents", "managed-blocks", "validation-runtime"}),
        }
        self.assertEqual(
            {
                capability.target: capability.compatibility_features
                for capability in CAPABILITIES
            },
            expected,
        )

    def test_capability_feature_registry_drift_fails_closed(self):
        row = next(row for row in self.rows if row.target == "codex")
        for declared in (frozenset(), frozenset({"agents"}), ["agents"]):
            with self.subTest(declared=declared):
                capability = replace(
                    capability_for(Target.CODEX), compatibility_features=declared
                )
                with self.assertRaises(ValueError):
                    validate_client_compatibility(
                        capability, row, requested_features=frozenset()
                    )

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

    def test_direct_constructor_rejects_duplicate_or_control_tuple_members(self):
        row = next(row for row in self.rows if row.target == "codex")
        for field, value in (
            ("tested_python", ("3.11", "3.11")),
            ("tested_python", ("3.11\n",)),
            ("tested_os_backends", ("bwrap", "bwrap")),
            ("tested_os_backends", ("bwrap\x00",)),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises((TypeError, ValueError)):
                    ClientCompatibility(**{**row.__dict__, field: value})

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

    def test_client_version_rejection_precedes_home_environment_reads(self):
        class ExplodingEnvironment(dict):
            def get(self, key, default=None):
                raise AssertionError(
                    f"environment read before version validation: {key}"
                )

            def __getitem__(self, key):
                raise AssertionError(
                    f"environment read before version validation: {key}"
                )

        environ = ExplodingEnvironment()
        for version in ("codex=1", "opencode=1.0.0"):
            with self.subTest(version=version), self.assertRaises(CliError):
                parse_request(
                    "install",
                    ["--target", "codex", "--client-version", version],
                    environ,
                )

    def test_incompatible_non_dry_install_and_uninstall_do_not_read_pending_recovery(
        self,
    ):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            home = root / "home"
            state = home / ".subagents_configs"
            state.mkdir(parents=True)
            (state / "journal.json").write_text("pending", encoding="utf-8")
            before = {
                path: path.read_bytes() for path in root.rglob("*") if path.is_file()
            }
            for operation in ("install", "uninstall"):
                out, err = io.StringIO(), io.StringIO()
                with patch("subagents_configs.orchestrator._journal_groups") as groups:
                    status = run(
                        operation,
                        [
                            "--target",
                            "codex",
                            "--home",
                            f"codex={home}",
                            "--client-version",
                            "codex=0.1.0",
                        ],
                        repo_root=Path(__file__).parents[1],
                        environ={"HOME": str(root)},
                        stdout=out,
                        stderr=err,
                    )
                self.assertEqual(status, EXIT_PREFLIGHT_ERROR)
                self.assertIn("client_version_too_old", err.getvalue())
                groups.assert_not_called()
                self.assertEqual(
                    before,
                    {
                        path: path.read_bytes()
                        for path in root.rglob("*")
                        if path.is_file()
                    },
                )

    def test_optional_feature_mismatch_fails_before_source_or_home_planning(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            home = root / "home"
            matrix = load_compatibility_matrix(
                Path(__file__).parents[1] / "catalogs/client-compatibility.json"
            )
            changed = tuple(
                replace(row, features=row.features - {"routing-codex"})
                if row.target == "codex"
                else row
                for row in matrix
            )
            out, err = io.StringIO(), io.StringIO()
            with (
                patch(
                    "subagents_configs.compatibility.load_compatibility_matrix",
                    return_value=changed,
                ),
                patch("subagents_configs.planning._selected_sources") as sources,
            ):
                status = run(
                    "install",
                    [
                        "--target",
                        "codex",
                        "--home",
                        f"codex={home}",
                        "--enable-global-routing",
                    ],
                    repo_root=Path(__file__).parents[1],
                    environ={"HOME": str(root)},
                    stdout=out,
                    stderr=err,
                )
            self.assertEqual(status, EXIT_PREFLIGHT_ERROR)
            self.assertIn("feature_unsupported", err.getvalue())
            self.assertEqual(tuple(root.rglob("*")), ())
            sources.assert_not_called()

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

    def test_unsupported_pi_stops_before_sources_writes_or_commands(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            home = root / "pi-home"
            out, err = io.StringIO(), io.StringIO()
            with (
                patch("subagents_configs.planning._selected_sources") as sources,
                patch("subagents_configs.orchestrator.apply_transaction") as apply,
                patch("subagents_configs.orchestrator._journal_groups") as journals,
            ):
                status = run(
                    "install",
                    [
                        "--target",
                        "pi",
                        "--home",
                        f"pi={home}",
                        "--pi-executable",
                        "/opt/pi",
                        "--consent-third-party-code",
                        "--consent-network",
                        "--dry-run",
                    ],
                    repo_root=Path(__file__).parents[1],
                    environ={"HOME": str(root)},
                    stdout=out,
                    stderr=err,
                )
            self.assertEqual(status, EXIT_PREFLIGHT_ERROR)
            self.assertIn("target_unsupported", err.getvalue())
            sources.assert_not_called()
            apply.assert_not_called()
            journals.assert_not_called()
            self.assertFalse(home.exists())

    def test_pi_dry_run_reports_required_consents_without_recording_them(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for format_args in ([], ["--format", "json"]):
                outputs = []
                for extra in ([], ["--consent-third-party-code", "--consent-network"]):
                    out, err = io.StringIO(), io.StringIO()
                    status = run(
                        "install",
                        [
                            "--target",
                            "pi",
                            "--home",
                            f"pi={root / 'pi-home'}",
                            "--pi-executable",
                            "/opt/pi",
                            "--dry-run",
                            *format_args,
                            *extra,
                        ],
                        repo_root=Path(__file__).parents[1],
                        environ={"HOME": str(root)},
                        stdout=out,
                        stderr=err,
                    )
                    self.assertEqual(status, EXIT_PREFLIGHT_ERROR)
                    outputs.append(out.getvalue())
                self.assertEqual(outputs[0], outputs[1])
                if format_args:
                    payload = json.loads(outputs[0])
                    self.assertEqual(
                        payload["compatibility"]["required_consents"],
                        ["third-party-code", "network"],
                    )
                else:
                    self.assertIn(
                        "required_consents=third-party-code,network", outputs[0]
                    )


if __name__ == "__main__":
    unittest.main()
