from __future__ import annotations

import json
import tempfile
import unittest
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


class EffectiveCatalogTests(unittest.TestCase):
    def test_clean_empty_scope_returns_complete_contract(self):
        from subagents_configs.pi_effective import inspect_effective_catalog

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent_dir = root / "agent"
            agent_dir.mkdir(mode=0o700)
            result = inspect_effective_catalog(
                agent_dir, _rendered(agent_dir), _package(agent_dir), project_root=root
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
                agent_dir, _rendered(agent_dir), _package(agent_dir), project_root=root
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
                project_root=root,
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


if __name__ == "__main__":
    unittest.main()
