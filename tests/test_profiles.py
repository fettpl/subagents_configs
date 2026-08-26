import io
import json
import unittest
from pathlib import Path

from subagents_configs.cli import parse_request
from subagents_configs.errors import CliError
from subagents_configs.models import Target
from subagents_configs.orchestrator import (
    EXIT_BLOCKED_VALIDATION,
    EXIT_SUCCESS,
    run,
)
from subagents_configs.profiles import (
    ProfileOptions,
    ProfileRequest,
    load_profile,
    merge_profile_with_cli,
)
from tests.helpers import planning_repository, private_tempdir


def _profile(*, operation="install", options=None, targets=None, homes=None):
    return {
        "schema_version": 1,
        "operation": operation,
        "targets": targets or ["codex"],
        "homes": homes or {"codex": "/var/tmp/profile-codex"},  # noqa: S108
        "options": options
        or {
            "enable_global_routing": True,
            "enable_codex_multi_agent": True,
            "include_commit_pusher": True,
            "dry_run": True,
            "dry_run_format": "json",
        },
    }


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = private_tempdir()
        self.root = Path(self.temp_dir.name)
        self.environ = {"HOME": str(self.root)}

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_json(self, value):
        path = self.root / "profile.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_loads_strict_json_profile_as_immutable_typed_values(self):
        profile = load_profile(self.write_json(_profile()))
        self.assertIsInstance(profile, ProfileRequest)
        self.assertEqual(profile.targets, (Target.CODEX,))
        self.assertEqual(
            profile.homes[Target.CODEX],
            Path("/var/tmp/profile-codex"),  # noqa: S108
        )
        self.assertTrue(profile.options.enable_global_routing)
        with self.assertRaises((AttributeError, TypeError)):
            profile.options.dry_run = False
        with self.assertRaises(TypeError):
            profile.homes[Target.CODEX] = Path("/var/tmp/other")  # noqa: S108

    def test_loads_toml_profile(self):
        path = self.root / "profile.toml"
        path.write_text(
            "schema_version = 1\n"
            'operation = "install"\n'
            'targets = ["codex"]\n\n'
            "[homes]\n"
            'codex = "/var/tmp/profile-codex"\n\n'
            "[options]\n"
            "enable_global_routing = false\n"
            "enable_codex_multi_agent = false\n"
            "include_commit_pusher = false\n"
            "dry_run = true\n"
            'dry_run_format = "text"\n',
            encoding="utf-8",
        )
        profile = load_profile(path)
        self.assertEqual(profile.options.dry_run_format, "text")

    def test_rejects_unknown_keys_and_duplicate_json_keys(self):
        unknown = _profile()
        unknown["unexpected"] = False
        with self.assertRaises(ValueError):
            load_profile(self.write_json(unknown))
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"schema_version":1,"schema_version":1,"operation":"install",'
            '"targets":["codex"],"homes":{"codex":"/var/tmp/x"},"options":{'
            '"enable_global_routing":false,"enable_codex_multi_agent":false,'
            '"include_commit_pusher":false,"dry_run":true,"dry_run_format":"text"}}',
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            load_profile(duplicate)

    def test_rejects_duplicate_targets_homes_all_and_unsafe_values(self):
        for targets in (["codex", "codex"], ["all"]):
            value = _profile(targets=targets)
            with self.assertRaises(ValueError):
                load_profile(self.write_json(value))
        value = _profile(targets=["codex", "opencode"])
        with self.assertRaises(ValueError):
            load_profile(self.write_json(value))
        for home in (
            "relative/home",
            "/var/tmp/../unsafe",  # noqa: S108
            "~/home",
            "/var/tmp/private-key",  # noqa: S108
        ):
            value = _profile(homes={"codex": home})
            with self.assertRaises(ValueError):
                load_profile(self.write_json(value))

    def test_rejects_credentials_controls_and_wrong_exact_types(self):
        for key, value in (
            ("api_token", False),
            ("notes", "secret-value"),
            ("x", "a\x00b"),
        ):
            profile = _profile()
            profile["options"][key] = value
            with self.assertRaises(ValueError):
                load_profile(self.write_json(profile))
        profile = _profile()
        profile["options"]["dry_run"] = 1
        with self.assertRaises(ValueError):
            load_profile(self.write_json(profile))

    def test_cli_boolean_precedence_is_two_way_and_absence_retains_profile(self):
        profile = load_profile(self.write_json(_profile()))
        retained = merge_profile_with_cli(
            profile, ["--profile", str(self.root / "profile.json")], self.environ
        )
        self.assertTrue(retained.enable_global_routing)
        self.assertTrue(retained.enable_codex_multi_agent)
        self.assertTrue(retained.include_commit_pusher)
        self.assertTrue(retained.dry_run)
        turned_off = merge_profile_with_cli(
            profile,
            [
                "--no-global-routing",
                "--no-codex-multi-agent",
                "--no-commit-pusher",
                "--no-dry-run",
            ],
            self.environ,
        )
        self.assertFalse(turned_off.enable_global_routing)
        self.assertFalse(turned_off.enable_codex_multi_agent)
        self.assertFalse(turned_off.include_commit_pusher)
        self.assertFalse(turned_off.dry_run)
        turned_on = merge_profile_with_cli(
            ProfileRequest(
                1,
                "install",
                (Target.CODEX,),
                {Target.CODEX: Path("/var/tmp/profile-codex")},  # noqa: S108
                ProfileOptions(False, False, False, False, "text"),
            ),
            [
                "--enable-global-routing",
                "--enable-codex-multi-agent",
                "--include-commit-pusher",
                "--dry-run",
            ],
            self.environ,
        )
        self.assertTrue(turned_on.enable_global_routing)
        self.assertTrue(turned_on.enable_codex_multi_agent)
        self.assertTrue(turned_on.include_commit_pusher)
        self.assertTrue(turned_on.dry_run)

    def test_profile_and_cli_operations_must_match(self):
        self.write_json(_profile(operation="install"))
        with self.assertRaises(CliError):
            parse_request(
                "uninstall",
                ["--profile", str(self.root / "profile.json")],
                self.environ,
            )

    def test_profile_runs_through_existing_dry_run_preflight(self):
        profile_value = _profile(
            homes={"codex": str(self.root / "codex")},
            options={
                "enable_global_routing": False,
                "enable_codex_multi_agent": False,
                "include_commit_pusher": False,
                "dry_run": True,
                "dry_run_format": "text",
            },
        )
        profile_path = self.write_json(profile_value)
        out, err = io.StringIO(), io.StringIO()
        status = run(
            "install",
            ["--profile", str(profile_path)],
            repo_root=planning_repository(self.root),
            environ=self.environ,
            stdout=out,
            stderr=err,
        )
        self.assertEqual(status, EXIT_SUCCESS, err.getvalue())
        self.assertIn("target: codex", out.getvalue())
        self.assertEqual(err.getvalue(), "")

    def test_profile_symlink_home_is_rejected_by_no_follow_preflight(self):
        target = self.root / "real-home"
        target.mkdir()
        link = self.root / "home-link"
        link.symlink_to(target, target_is_directory=True)
        profile_path = self.write_json(
            _profile(
                homes={"codex": str(link)},
                options={
                    "enable_global_routing": False,
                    "enable_codex_multi_agent": False,
                    "include_commit_pusher": False,
                    "dry_run": True,
                    "dry_run_format": "text",
                },
            )
        )
        out, err = io.StringIO(), io.StringIO()
        status = run(
            "install",
            ["--profile", str(profile_path)],
            repo_root=planning_repository(self.root),
            environ=self.environ,
            stdout=out,
            stderr=err,
        )
        self.assertEqual(status, EXIT_BLOCKED_VALIDATION)
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
