from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from subagents_configs.pi_catalog import PI_DEFAULT_ROLES, validate_pi_agent
from subagents_configs.pi_package import PiPackageEvidence

ROOT = Path(__file__).resolve().parents[1]


def _rendered(agent_dir: Path | None = None) -> dict[str, object]:
    from subagents_configs.pi_catalog import render_pi_source

    return {
        role: validate_pi_agent(
            role,
            render_pi_source(
                (ROOT / "pi/agents" / f"{role}.md").read_bytes(),
                agent_dir=agent_dir,
            )
            if role == "code-validator" and agent_dir is not None
            else (ROOT / "pi/agents" / f"{role}.md").read_bytes(),
            allow_rendered_extension=role == "code-validator" and agent_dir is not None,
        )
        for role in PI_DEFAULT_ROLES
    }


def _package(home: Path, *, entries: tuple[str, ...] = ()) -> PiPackageEvidence:
    return PiPackageEvidence(
        settings_path=home / "settings.json",
        settings_hash=None,
        package_entries=entries,
        status="absent",
        exact_pinned_entry=False,
        installed_lock_path=None,
        installed_lock_root_hash=None,
        package_manifest_path=None,
        manifest_hash=None,
        package_identity_valid=False,
    )


def _project(root: Path) -> Path:
    project = root / "project"
    project.mkdir(mode=0o700, exist_ok=True)
    return project


class EffectiveCatalogTests(unittest.TestCase):
    def test_clean_empty_scope_returns_complete_contract(self):
        from subagents_configs.pi_effective import inspect_effective_catalog

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent_dir = root / "agent"
            agent_dir.mkdir(mode=0o700)
            result = inspect_effective_catalog(
                agent_dir,
                _rendered(agent_dir),
                _package(agent_dir),
                project_root=_project(root),
            )
            self.assertEqual(result.managed_roles, tuple(PI_DEFAULT_ROLES))
            self.assertEqual(
                result.bundled_roles,
                ("delegate", "oracle", "researcher", "reviewer", "scout", "worker"),
            )
            self.assertFalse(result.conflicts)
            self.assertEqual(set(result.source_hashes), set(PI_DEFAULT_ROLES))

    def test_unmanaged_managed_role_path_is_a_redacted_collision(self):
        from subagents_configs.pi_effective import inspect_effective_catalog

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent_dir = root / "agent"
            agent_dir.mkdir(mode=0o700)
            agents = agent_dir / "agents"
            agents.mkdir(mode=0o700)
            (agents / "code-explorer.md").write_text(
                "private settings", encoding="utf-8"
            )
            result = inspect_effective_catalog(
                agent_dir,
                _rendered(agent_dir),
                _package(agent_dir),
                project_root=_project(root),
            )
            self.assertTrue(
                any(item.kind == "path-collision" for item in result.conflicts)
            )
            self.assertNotIn("private settings", repr(result.conflicts))

    def test_package_drift_and_override_are_reported_without_raw_values(self):
        from subagents_configs.pi_effective import inspect_effective_catalog

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent_dir = root / "agent"
            agent_dir.mkdir(mode=0o700)
            (agent_dir / "settings.json").write_text(
                json.dumps(
                    {
                        "packages": ["npm:pi-subagents"],
                        "subagents": {
                            "agentOverrides": {"code-explorer": {"tools": ["bash"]}}
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = inspect_effective_catalog(
                agent_dir,
                _rendered(),
                _package(agent_dir, entries=("npm:pi-subagents",)),
                project_root=_project(root),
            )
            kinds = {item.kind for item in result.conflicts}
            self.assertIn("package-drift", kinds)
            self.assertIn("override", kinds)
            self.assertNotIn("npm:pi-subagents", repr(result.conflicts))
            self.assertNotIn("bash", repr(result.conflicts))

    def test_project_root_must_be_existing_canonical_directory(self):
        from subagents_configs.pi_effective import inspect_effective_catalog

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent_dir = root / "agent"
            agent_dir.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                inspect_effective_catalog(
                    agent_dir,
                    _rendered(),
                    _package(agent_dir),
                    project_root=root / "missing",
                )

    def test_project_root_overlap_with_pi_home_is_rejected_before_scope_discovery(
        self,
    ):
        from subagents_configs.pi_effective import inspect_effective_catalog

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent_dir = root / "agent"
            agent_dir.mkdir(mode=0o700)
            rendered = _rendered(agent_dir)
            package = _package(agent_dir)
            overlapping_roots = (
                agent_dir,
                root,
                agent_dir / "nested-project",
            )
            (agent_dir / ".pi/extensions").mkdir(mode=0o700, parents=True)
            (root / ".pi/extensions").mkdir(mode=0o700, parents=True)
            (agent_dir / "nested-project/.pi/extensions").mkdir(
                mode=0o700, parents=True
            )
            for project_root in overlapping_roots:
                with self.subTest(project_root=project_root):
                    with self.assertRaises(ValueError):
                        inspect_effective_catalog(
                            agent_dir,
                            rendered,
                            package,
                            project_root=project_root,
                        )

    def test_exact_repository_managed_files_are_not_collisions(self):
        from subagents_configs.pi_catalog import render_pi_source
        from subagents_configs.pi_effective import inspect_effective_catalog

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent_dir = root / "agent"
            (agent_dir / "agents").mkdir(mode=0o700, parents=True)
            project = _project(root)
            for role in PI_DEFAULT_ROLES:
                source = (ROOT / "pi/agents" / f"{role}.md").read_bytes()
                if role == "code-validator":
                    source = render_pi_source(source, agent_dir=agent_dir)
                destination = agent_dir / "agents" / f"{role}.md"
                destination.write_bytes(source)
                destination.chmod(0o600)
            result = inspect_effective_catalog(
                agent_dir,
                _rendered(agent_dir),
                _package(agent_dir),
                project_root=project,
            )
            self.assertFalse(
                any(item.kind == "path-collision" for item in result.conflicts)
            )

    def test_pi_project_scope_is_discovered_without_cwd_fallback(self):
        from subagents_configs.pi_effective import inspect_effective_catalog

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent_dir = root / "agent"
            agent_dir.mkdir(mode=0o700)
            project = _project(root)
            (project / ".pi/agents").mkdir(mode=0o700, parents=True)
            (project / ".pi/extensions").mkdir(mode=0o700)
            (project / ".pi/settings.json").write_text("{}", encoding="utf-8")
            result = inspect_effective_catalog(
                agent_dir,
                _rendered(agent_dir),
                _package(agent_dir),
                project_root=project,
            )
            fields = {item.field for item in result.conflicts}
            self.assertTrue(
                {"projectSettings", "projectAgents", "projectExtensions"} <= fields
            )

    def test_manifest_bytes_are_bound_to_supplied_hash_and_parent_is_no_follow(self):
        from subagents_configs.pi_effective import inspect_effective_catalog
        from subagents_configs.pi_package import load_pi_package_policy

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent_dir = root / "agent"
            (agent_dir / "extensions").mkdir(mode=0o700, parents=True)
            manifest = agent_dir / "npm/node_modules/pi-subagents/package.json"
            manifest.parent.mkdir(mode=0o700, parents=True)
            manifest.write_bytes(
                (ROOT / "tests/fixtures/pi-subagents-0.56.0-package.json").read_bytes()
                + b"\n"
            )
            manifest.chmod(0o600)
            package = PiPackageEvidence(
                agent_dir / "settings.json",
                None,
                ("npm:pi-subagents@0.56.0",),
                "exact",
                True,
                None,
                None,
                manifest,
                load_pi_package_policy()["packageJsonSha256"],
                True,
            )
            rendered = _rendered(agent_dir)
            result = inspect_effective_catalog(
                agent_dir, rendered, package, project_root=_project(root)
            )
            self.assertTrue(any(item.field == "manifest" for item in result.conflicts))

            missing_manifest = replace(
                package,
                package_manifest_path=agent_dir
                / "npm/node_modules/pi-subagents/missing.json",
            )
            result = inspect_effective_catalog(
                agent_dir, rendered, missing_manifest, project_root=_project(root)
            )
            self.assertTrue(any(item.field == "manifest" for item in result.conflicts))

            outside = root / "outside"
            outside.mkdir(mode=0o700)
            (outside / "config.json").write_text('{"model":"secret"}', encoding="utf-8")
            extension_link = agent_dir / "extensions"
            extension_link.rmdir()
            extension_link.symlink_to(outside, target_is_directory=True)
            result = inspect_effective_catalog(
                agent_dir, rendered, _package(agent_dir), project_root=_project(root)
            )
            self.assertTrue(any(item.field == "config" for item in result.conflicts))
            self.assertNotIn("secret", repr(result.conflicts))

            manifest.unlink()
            manifest.parent.rmdir()
            outside_manifest = outside / "package"
            outside_manifest.mkdir(mode=0o700)
            (outside_manifest / "package.json").write_bytes(
                (ROOT / "tests/fixtures/pi-subagents-0.56.0-package.json").read_bytes()
            )
            manifest.parent.symlink_to(outside_manifest, target_is_directory=True)
            result = inspect_effective_catalog(
                agent_dir, rendered, package, project_root=_project(root)
            )
            self.assertTrue(any(item.field == "manifest" for item in result.conflicts))
            self.assertNotIn("secret", repr(result.conflicts))


if __name__ == "__main__":
    unittest.main()
