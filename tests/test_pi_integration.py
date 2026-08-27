"""RED integration contracts for the Pi package/catalog phase boundary.

These tests deliberately describe the Plan 1 boundary before its production
implementation exists.  They use only temporary homes and a non-executed fake
Pi executable; a real Pi process, npm, Node, or network must never be needed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from dataclasses import replace
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from subagents_configs.models import Request, Target
from subagents_configs.transaction import apply_transaction
from tests.helpers import planning_repository


class PiIntegrationRedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="subagents-pi-task4-")
        self.root = Path(self.temporary.name).resolve()
        self.repository = planning_repository(self.root)
        real_repository = Path(__file__).parents[1]
        shutil.copytree(real_repository / "pi", self.repository / "pi")
        self.project_root = self.root / "project"
        self.project_root.mkdir(mode=0o700)
        self.home = self.root / "pi-home"
        self.home.mkdir(mode=0o700)
        self.fake_pi = self.root / "pi"
        self.fake_pi.write_text(
            "#!/bin/sh\nexit 0\n",
            encoding="utf-8",
        )
        self.fake_pi.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _request(self, **overrides: object) -> Request:
        values: dict[str, object] = {
            "operation": "install",
            "targets": (Target.PI,),
            "homes": {Target.PI: self.home},
            "enable_global_routing": False,
            "enable_codex_multi_agent": False,
            "include_commit_pusher": False,
            "dry_run": False,
            "pi_executable": self.fake_pi,
            "consent_third_party_code": True,
            "consent_network": True,
            "client_versions": {"pi": "0.84.1"},
        }
        values.update(overrides)
        return Request(**values)  # type: ignore[arg-type]

    def _preflight(self, **overrides: object):
        from subagents_configs.planning import preflight_install

        # Pi is intentionally unreleased until Task 11.  This unit exercises
        # the internal Plan 1 boundary only, so it supplies a successful
        # compatibility fact without weakening the production matrix.
        with patch(
            "subagents_configs.planning.validate_request_compatibility",
            return_value=(),
        ):
            return preflight_install(
                self.repository,
                self._request(**overrides),
                project_root=self.project_root,
            )

    def _write_exact_package(self) -> None:
        self.home.mkdir(mode=0o700, exist_ok=True)
        self.home.chmod(0o700)
        package = self.home / "npm/node_modules/pi-subagents"
        package.mkdir(parents=True, mode=0o700)
        (self.home / "npm/node_modules").chmod(0o700)
        shutil.copyfile(
            Path(__file__).parent / "fixtures/pi-subagents-0.56.0-package.json",
            package / "package.json",
        )
        (package / "package.json").chmod(0o600)
        lock = {
            "name": "pi-subagents",
            "version": "0.56.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"pi-subagents": "0.56.0"}},
                "node_modules/pi-subagents": {
                    "version": "0.56.0",
                    "integrity": (
                        "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+"
                        "W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
                    ),
                },
            },
        }
        npm = self.home / "npm"
        npm.mkdir(mode=0o700, exist_ok=True)
        npm.chmod(0o700)
        (npm / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
        (npm / "package-lock.json").chmod(0o600)
        settings = self.home / "settings.json"
        settings.write_text(
            json.dumps({"packages": ["npm:pi-subagents@0.56.0"]}),
            encoding="utf-8",
        )
        settings.chmod(0o600)

    def _write_valid_receipt(self) -> None:
        from subagents_configs.pi_package import inspect_pi_package_state

        evidence = inspect_pi_package_state(self.home)
        policy_hash = hashlib.sha256(
            (self.repository / "pi/package-policy.json").read_bytes()
        ).hexdigest()
        receipt = {
            "schema_version": 1,
            "operation": "install",
            "source": "npm:pi-subagents@0.56.0",
            "remove_source": "npm:pi-subagents",
            "settings_before_hash": None,
            "settings_after_hash": evidence.settings_hash,
            "package_manifest_hash": evidence.manifest_hash,
            "package_policy_hash": policy_hash,
            "created_exact_entry": True,
        }
        state = self.home / ".subagents_configs"
        state.mkdir(mode=0o700, exist_ok=True)
        state.chmod(0o700)
        path = state / "pi-package-receipt.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        path.chmod(0o600)

    def test_preflight_returns_local_and_external_pi_plans(self) -> None:
        from subagents_configs.models import PiExternalPlan, PiInstallPlan
        from subagents_configs.planning import TransactionPlan

        plan = self._preflight()
        self.assertIsInstance(plan, PiInstallPlan)
        self.assertIsInstance(plan.local, TransactionPlan)
        self.assertIsInstance(plan.external, PiExternalPlan)
        self.assertEqual(plan.external.action, "install")
        self.assertEqual(plan.external.package_source, "npm:pi-subagents@0.56.0")
        self.assertEqual(plan.external.executable, self.fake_pi)
        self.assertEqual(plan.external.agent_dir, self.home)
        self.assertEqual(plan.external.project_root, self.project_root)
        self.assertEqual(plan.external.before.status, "absent")

        operations = plan.local.targets[0].operations
        role_ids = {
            "code-explorer",
            "code-reviewer",
            "code-validator",
            "quick-implementer",
            "implementer",
        }
        self.assertEqual(
            {item.identifier for item in operations if item.identifier in role_ids},
            role_ids,
        )
        self.assertEqual(
            sum(item.identifier == "pi/run-validation" for item in operations), 1
        )
        runtime = {
            item.identifier
            for item in operations
            if item.relative_path.startswith(".subagents_configs/validation/")
        }
        self.assertEqual(len(runtime), 9)
        self.assertNotIn("routing", {item.identifier for item in operations})

    def test_project_root_must_be_explicit_absolute_real_directory(self) -> None:
        from subagents_configs.planning import preflight_install

        invalid_roots = [
            self.root / "missing-project",
            self.root / "project-file",
            Path("relative-project"),
        ]
        invalid_roots[1].write_text("not a directory", encoding="utf-8")
        for invalid in invalid_roots:
            with self.subTest(root=invalid):
                with (
                    patch(
                        "subagents_configs.planning.validate_request_compatibility",
                        return_value=(),
                    ),
                    self.assertRaises((TypeError, ValueError, OSError)),
                ):
                    preflight_install(
                        self.repository,
                        self._request(),
                        project_root=invalid,
                    )

        symlink = self.root / "project-link"
        symlink.symlink_to(self.project_root, target_is_directory=True)
        with (
            patch(
                "subagents_configs.planning.validate_request_compatibility",
                return_value=(),
            ),
            self.assertRaises((TypeError, ValueError, OSError)),
        ):
            preflight_install(
                self.repository,
                self._request(),
                project_root=symlink,
            )

    def test_external_plan_is_not_a_local_or_journal_operation(self) -> None:
        from subagents_configs.models import (
            JournalOperation,
            PiExternalPlan,
            PiInstallPlan,
        )
        from subagents_configs.planning import PlannedOperation

        plan = self._preflight()
        self.assertIsInstance(plan, PiInstallPlan)
        self.assertIsInstance(plan.external, PiExternalPlan)
        self.assertNotIsInstance(plan.external, PlannedOperation)
        self.assertNotIsInstance(plan.external, JournalOperation)
        self.assertNotIn(plan.external, plan.local.targets[0].operations)

    def test_exact_preexisting_package_skips_install_without_ownership_receipt(
        self,
    ) -> None:
        self._write_exact_package()
        plan = self._preflight()
        self.assertEqual(plan.external.action, "none")
        self.assertEqual(plan.external.before.status, "exact")
        self.assertIsNone(plan.external.removal_receipt)
        self.assertFalse(plan.external.consent_third_party_code)
        self.assertFalse(plan.external.consent_network)

    def test_exact_package_none_phase_has_complete_rendered_contracts(self) -> None:
        from subagents_configs import orchestrator

        self._write_exact_package()
        plan = self._preflight()
        rendered = orchestrator._rendered_pi_contracts(plan.local)
        self.assertEqual(
            set(rendered),
            {
                "code-explorer",
                "code-reviewer",
                "code-validator",
                "quick-implementer",
                "implementer",
            },
        )
        orchestrator.verify_pi_effective_postcondition(
            plan.external, plan.local, plan.external.before
        )

    def test_exact_package_with_invalid_receipt_fails_closed_in_planning(self) -> None:
        self._write_exact_package()
        state = self.home / ".subagents_configs"
        state.mkdir(mode=0o700)
        state.chmod(0o700)
        receipt = state / "pi-package-receipt.json"
        receipt.write_text('{"operation":"install"}', encoding="utf-8")
        receipt.chmod(0o600)
        with self.assertRaises(ValueError):
            self._preflight()

    def test_remove_package_builds_typed_external_plan_with_receipt(self) -> None:
        from subagents_configs.models import PiInstallPlan
        from subagents_configs.planning import preflight_uninstall

        self._write_exact_package()
        self._write_valid_receipt()
        request = self._request(
            operation="uninstall",
            remove_pi_package=True,
            consent_third_party_code=False,
            consent_network=False,
        )
        with patch(
            "subagents_configs.planning.validate_request_compatibility",
            return_value=(),
        ):
            plan = preflight_uninstall(self.repository, request)
        self.assertIsInstance(plan, PiInstallPlan)
        self.assertEqual(plan.external.action, "remove")
        self.assertIsNotNone(plan.external.removal_receipt)

    def test_normal_uninstall_never_schedules_package_removal(self) -> None:
        from subagents_configs.planning import TransactionPlan, preflight_uninstall

        self._write_exact_package()
        request = self._request(
            operation="uninstall",
            pi_executable=None,
            remove_pi_package=False,
            consent_third_party_code=False,
            consent_network=False,
        )
        with patch(
            "subagents_configs.planning.validate_request_compatibility",
            return_value=(),
        ):
            plan = preflight_uninstall(self.repository, request)
        self.assertIsInstance(plan, TransactionPlan)

    def test_default_uninstall_preserves_pi_package_receipt_and_settings(self) -> None:
        """Normal uninstall is local-only and leaves external Pi evidence intact."""

        from subagents_configs.models import PiInstallPlan
        from subagents_configs.pi_package import load_pi_package_receipt
        from subagents_configs.planning import preflight_uninstall

        self._write_exact_package()
        self._write_valid_receipt()
        settings = self.home / "settings.json"
        receipt = self.home / ".subagents_configs/pi-package-receipt.json"
        before = (settings.read_bytes(), receipt.read_bytes())
        request = self._request(
            operation="uninstall",
            pi_executable=None,
            remove_pi_package=False,
            consent_third_party_code=False,
            consent_network=False,
        )
        with patch(
            "subagents_configs.planning.validate_request_compatibility",
            return_value=(),
        ):
            plan = preflight_uninstall(self.repository, request)
        self.assertNotIsInstance(plan, PiInstallPlan)
        self.assertEqual((settings.read_bytes(), receipt.read_bytes()), before)
        self.assertIsNotNone(load_pi_package_receipt(self.home))

    def test_package_removal_failure_preserves_receipt_after_local_success(
        self,
    ) -> None:
        """An optional external failure cannot recreate local files or erase proof."""

        from subagents_configs import orchestrator
        from subagents_configs.planning import preflight_install, preflight_uninstall

        self._write_exact_package()
        install_request = self._request(
            consent_third_party_code=False,
            consent_network=False,
        )
        with patch(
            "subagents_configs.planning.validate_request_compatibility",
            return_value=(),
        ):
            install_plan = preflight_install(
                self.repository, install_request, project_root=self.project_root
            )
        apply_transaction(install_plan.local)
        self._write_valid_receipt()
        role = self.home / "agents/code-explorer.md"
        self.assertTrue(role.exists())
        uninstall_request = self._request(
            operation="uninstall",
            remove_pi_package=True,
            consent_third_party_code=False,
            consent_network=False,
        )
        with patch(
            "subagents_configs.planning.validate_request_compatibility",
            return_value=(),
        ):
            uninstall_plan = preflight_uninstall(self.repository, uninstall_request)
        stderr = StringIO()
        with (
            patch.object(
                orchestrator, "validate_request_compatibility", return_value=()
            ),
            patch.object(orchestrator, "_plan", return_value=uninstall_plan),
            patch.object(
                orchestrator,
                "remove_pi_package",
                side_effect=RuntimeError("simulated Pi removal failure"),
            ),
        ):
            status = orchestrator._run_mutating_locked(
                uninstall_request,
                repo_root=self.repository,
                stdout=StringIO(),
                stderr=stderr,
                failure_injector=None,
            )
        self.assertEqual(status, orchestrator.EXIT_APPLY_ERROR)
        self.assertFalse(role.exists())
        self.assertTrue(
            (self.home / ".subagents_configs/pi-package-receipt.json").exists()
        )
        self.assertIn("PI_UNINSTALL_PRESERVED", stderr.getvalue())
        self.assertIsNotNone(uninstall_plan.external.removal_receipt)

    def test_dry_run_fingerprint_accepts_composite_without_raw_package_data(
        self,
    ) -> None:
        from subagents_configs import orchestrator

        plan = self._preflight()
        fingerprint = orchestrator._plan_fingerprint(plan)
        self.assertEqual(fingerprint[0], "install")
        self.assertEqual(fingerprint[-1][0], "install")
        self.assertNotIn("package_entries", repr(fingerprint))

    def test_package_phase_precedes_local_transaction_and_receipt_boundary(
        self,
    ) -> None:
        from subagents_configs import orchestrator

        plan = self._preflight()
        events: list[str] = []

        def package_phase(*_args: object, **_kwargs: object) -> None:
            events.append("package")

        def local_phase(*_args: object, **_kwargs: object) -> None:
            events.append("local")

        with (
            patch.object(
                orchestrator, "validate_request_compatibility", return_value=()
            ),
            patch.object(orchestrator, "_plan", return_value=plan),
            patch.object(orchestrator, "install_pi_package", side_effect=package_phase),
            patch.object(orchestrator, "verify_pi_install_postcondition"),
            patch.object(orchestrator, "verify_pi_effective_postcondition"),
            patch.object(
                orchestrator,
                "verify_pi_package_postcondition",
            ),
            patch.object(
                orchestrator,
                "inspect_pi_package_state",
                return_value=plan.external.before,
            ),
            patch.object(
                orchestrator,
                "validate_pi_package_receipt",
                return_value=None,
            ),
            patch.object(
                orchestrator,
                "store_pi_package_receipt",
                side_effect=lambda *_a, **_k: events.append("receipt"),
            ),
            patch.object(orchestrator, "apply_transaction", side_effect=local_phase),
        ):
            status = orchestrator._run_mutating_locked(
                self._request(),
                repo_root=self.repository,
                stdout=StringIO(),
                stderr=StringIO(),
                failure_injector=None,
            )
        self.assertEqual(status, orchestrator.EXIT_SUCCESS)
        self.assertEqual(events, ["package", "receipt", "local"])

    def test_install_postcondition_checks_reviewed_receipt_identity(self) -> None:
        from subagents_configs import orchestrator
        from subagents_configs.pi_package import (
            PiPackageReceipt,
            inspect_pi_package_state,
            pi_package_policy_hash,
        )

        external = self._preflight().external
        self._write_exact_package()
        evidence = inspect_pi_package_state(self.home)
        receipt = PiPackageReceipt(
            1,
            "install",
            "npm:pi-subagents@0.56.0",
            "npm:pi-subagents",
            external.before.settings_hash,
            evidence.settings_hash,
            evidence.manifest_hash or "",
            pi_package_policy_hash(),
            True,
        )
        orchestrator.verify_pi_install_postcondition(external, receipt)

        for field, value in (
            ("source", "npm:other@1.0.0"),
            ("remove_source", "npm:other"),
            ("package_policy_hash", "0" * 64),
            ("settings_before_hash", "0" * 64),
            ("settings_after_hash", "0" * 64),
            ("package_manifest_hash", "0" * 64),
        ):
            with self.subTest(field=field):
                changed = {
                    "schema_version": receipt.schema_version,
                    "operation": receipt.operation,
                    "source": receipt.source,
                    "remove_source": receipt.remove_source,
                    "settings_before_hash": receipt.settings_before_hash,
                    "settings_after_hash": receipt.settings_after_hash,
                    "package_manifest_hash": receipt.package_manifest_hash,
                    "package_policy_hash": receipt.package_policy_hash,
                    "created_exact_entry": receipt.created_exact_entry,
                }
                changed[field] = value
                with self.assertRaises(ValueError):
                    orchestrator.verify_pi_install_postcondition(
                        external, PiPackageReceipt(**changed)
                    )

    def test_missing_effective_evaluator_blocks_receipt_and_local_apply(self) -> None:
        from subagents_configs import orchestrator

        plan = self._preflight()
        local_calls: list[object] = []
        receipt_calls: list[object] = []
        with (
            patch.object(
                orchestrator, "validate_request_compatibility", return_value=()
            ),
            patch.object(orchestrator, "_plan", return_value=plan),
            patch.object(
                orchestrator,
                "install_pi_package",
                return_value=object(),
            ),
            patch.object(
                orchestrator,
                "verify_pi_install_postcondition",
            ),
            patch.object(
                orchestrator,
                "store_pi_package_receipt",
                side_effect=lambda *_a, **_k: receipt_calls.append(True),
            ),
            patch.object(
                orchestrator,
                "apply_transaction",
                side_effect=lambda *_a, **_k: local_calls.append(True),
            ),
        ):
            status = orchestrator._run_mutating_locked(
                self._request(),
                repo_root=self.repository,
                stdout=StringIO(),
                stderr=StringIO(),
                failure_injector=None,
            )
        self.assertEqual(status, orchestrator.EXIT_APPLY_ERROR)
        self.assertEqual(receipt_calls, [])
        self.assertEqual(local_calls, [])

    def test_preexisting_exact_package_still_requires_effective_verification(
        self,
    ) -> None:
        from subagents_configs import orchestrator

        self._write_exact_package()
        plan = self._preflight()
        self.assertEqual(plan.external.action, "none")
        local_calls: list[object] = []
        with (
            patch.object(
                orchestrator, "validate_request_compatibility", return_value=()
            ),
            patch.object(orchestrator, "_plan", return_value=plan),
            patch.object(orchestrator, "verify_pi_package_postcondition"),
            patch.object(
                orchestrator,
                "verify_pi_effective_postcondition",
                side_effect=ValueError("effective evaluator is unavailable"),
            ),
            patch.object(
                orchestrator,
                "apply_transaction",
                side_effect=lambda *_a, **_k: local_calls.append(True),
            ),
        ):
            status = orchestrator._run_mutating_locked(
                self._request(),
                repo_root=self.repository,
                stdout=StringIO(),
                stderr=StringIO(),
                failure_injector=None,
            )
        self.assertEqual(status, orchestrator.EXIT_APPLY_ERROR)
        self.assertEqual(local_calls, [])

    def test_receipt_storage_rejects_package_evidence_drift(self) -> None:
        from subagents_configs.errors import PiPackageError
        from subagents_configs.pi_package import (
            PiPackageReceipt,
            inspect_pi_package_state,
            pi_package_policy_hash,
            store_pi_package_receipt,
        )

        self._write_exact_package()
        evidence = inspect_pi_package_state(self.home)
        receipt = PiPackageReceipt(
            1,
            "install",
            "npm:pi-subagents@0.56.0",
            "npm:pi-subagents",
            None,
            evidence.settings_hash,
            evidence.manifest_hash or "",
            pi_package_policy_hash(),
            True,
        )
        assert evidence.package_manifest_path is not None
        manifest = evidence.package_manifest_path.read_text(encoding="utf-8")
        evidence.package_manifest_path.write_text(manifest + "\n", encoding="utf-8")
        evidence.package_manifest_path.chmod(0o600)
        with self.assertRaises(PiPackageError):
            store_pi_package_receipt(
                self.home,
                receipt,
                expected_evidence=evidence,
            )
        self.assertFalse(
            (self.home / ".subagents_configs/pi-package-receipt.json").exists()
        )

    def test_unknown_external_action_fails_closed_before_local_apply(self) -> None:
        from subagents_configs import orchestrator

        plan = self._preflight()
        invalid_external = replace(plan.external, action="unexpected")
        invalid_plan = replace(plan, external=invalid_external)
        local_calls: list[object] = []
        with (
            patch.object(
                orchestrator, "validate_request_compatibility", return_value=()
            ),
            patch.object(orchestrator, "_plan", return_value=invalid_plan),
            patch.object(
                orchestrator,
                "apply_transaction",
                side_effect=lambda *_a, **_k: local_calls.append(True),
            ),
        ):
            status = orchestrator._run_mutating_locked(
                self._request(),
                repo_root=self.repository,
                stdout=StringIO(),
                stderr=StringIO(),
                failure_injector=None,
            )
        self.assertEqual(status, orchestrator.EXIT_APPLY_ERROR)
        self.assertEqual(local_calls, [])

    def test_receipt_cleanup_removes_only_own_receipt_after_postwrite_drift(
        self,
    ) -> None:
        from subagents_configs.errors import PiPackageError
        from subagents_configs.pi_package import (
            PiPackageReceipt,
            inspect_pi_package_state,
            pi_package_policy_hash,
            store_pi_package_receipt,
        )

        self._write_exact_package()
        evidence = inspect_pi_package_state(self.home)
        drift = replace(evidence, manifest_hash="0" * 64)
        receipt = PiPackageReceipt(
            1,
            "install",
            "npm:pi-subagents@0.56.0",
            "npm:pi-subagents",
            None,
            evidence.settings_hash,
            evidence.manifest_hash or "",
            pi_package_policy_hash(),
            True,
        )
        with (
            patch(
                "subagents_configs.pi_package.inspect_pi_package_state",
                side_effect=[evidence, drift],
            ),
            self.assertRaises(PiPackageError),
        ):
            store_pi_package_receipt(
                self.home,
                receipt,
                expected_evidence=evidence,
            )
        self.assertFalse(
            (self.home / ".subagents_configs/pi-package-receipt.json").exists()
        )

    def test_package_failure_has_zero_local_operations_and_no_receipt(self) -> None:
        from subagents_configs import orchestrator

        plan = self._preflight()
        local_calls: list[object] = []
        with (
            patch.object(
                orchestrator, "validate_request_compatibility", return_value=()
            ),
            patch.object(orchestrator, "_plan", return_value=plan),
            patch.object(
                orchestrator,
                "install_pi_package",
                side_effect=RuntimeError("third-party output must be sanitized"),
            ),
            patch.object(orchestrator, "verify_pi_install_postcondition"),
            patch.object(orchestrator, "verify_pi_effective_postcondition"),
            patch.object(orchestrator, "store_pi_package_receipt") as store_receipt,
            patch.object(
                orchestrator,
                "apply_transaction",
                side_effect=lambda *_a, **_k: local_calls.append(True),
            ),
        ):
            status = orchestrator._run_mutating_locked(
                self._request(),
                repo_root=self.repository,
                stdout=StringIO(),
                stderr=StringIO(),
                failure_injector=None,
            )
        self.assertNotEqual(status, orchestrator.EXIT_SUCCESS)
        self.assertEqual(local_calls, [])
        store_receipt.assert_not_called()

    def test_local_failure_preserves_external_state_and_never_removes_package(
        self,
    ) -> None:
        from subagents_configs import orchestrator

        plan = self._preflight()
        events: list[str] = []
        with (
            patch.object(
                orchestrator, "validate_request_compatibility", return_value=()
            ),
            patch.object(orchestrator, "_plan", return_value=plan),
            patch.object(
                orchestrator,
                "install_pi_package",
                side_effect=lambda *_a, **_k: events.append("package"),
            ),
            patch.object(orchestrator, "verify_pi_install_postcondition"),
            patch.object(orchestrator, "verify_pi_effective_postcondition"),
            patch.object(
                orchestrator,
                "verify_pi_package_postcondition",
            ),
            patch.object(
                orchestrator,
                "inspect_pi_package_state",
                return_value=plan.external.before,
            ),
            patch.object(
                orchestrator,
                "validate_pi_package_receipt",
                return_value=None,
            ),
            patch.object(
                orchestrator,
                "store_pi_package_receipt",
                side_effect=lambda *_a, **_k: events.append("receipt"),
            ),
            patch.object(
                orchestrator,
                "apply_transaction",
                side_effect=RuntimeError("local failure"),
            ),
            patch.object(orchestrator, "remove_pi_package") as remove_package,
        ):
            status = orchestrator._run_mutating_locked(
                self._request(),
                repo_root=self.repository,
                stdout=StringIO(),
                stderr=StringIO(),
                failure_injector=None,
            )
        self.assertNotEqual(status, orchestrator.EXIT_SUCCESS)
        self.assertEqual(events, ["package", "receipt"])
        remove_package.assert_not_called()

    def test_dry_run_is_lock_free_and_describes_external_pi_phase(self) -> None:
        from subagents_configs import orchestrator

        before = self.home / "before"
        before.write_bytes(b"unchanged")
        stdout, stderr = StringIO(), StringIO()
        with (
            patch.object(
                orchestrator, "validate_request_compatibility", return_value=()
            ),
            patch(
                "subagents_configs.planning.validate_request_compatibility",
                return_value=(),
            ),
            patch.object(
                orchestrator,
                "locked_target_homes",
                side_effect=AssertionError("dry-run must not lock"),
            ),
            patch.object(
                orchestrator,
                "validate_pi_executable",
                side_effect=AssertionError("dry-run must not execute Pi"),
            ),
            patch.object(
                orchestrator,
                "install_pi_package",
                side_effect=AssertionError("dry-run must not install package"),
            ),
            patch.object(
                orchestrator,
                "store_pi_package_receipt",
                side_effect=AssertionError("dry-run must not write receipt"),
            ),
        ):
            status = orchestrator.run(
                "install",
                [
                    "--target",
                    "pi",
                    "--dry-run",
                    "--pi-executable",
                    str(self.fake_pi.resolve()),
                ],
                repo_root=self.repository,
                environ={"HOME": str(self.root), "PI_CODING_AGENT_DIR": str(self.home)},
                stdout=stdout,
                stderr=stderr,
            )
        self.assertEqual(status, orchestrator.EXIT_SUCCESS)
        self.assertEqual(before.read_bytes(), b"unchanged")
        self.assertIn("pi", stdout.getvalue())
        self.assertIn(str(self.home), stdout.getvalue())
        self.assertIn("npm:pi-subagents@0.56.0", stdout.getvalue())
        for role in (
            "code-explorer",
            "code-reviewer",
            "code-validator",
            "quick-implementer",
            "implementer",
        ):
            self.assertIn(role, stdout.getvalue())
        self.assertIn("external-package-phase", stdout.getvalue())
        self.assertIn("maintained-matrix-only", stdout.getvalue())
        self.assertIn("third-party-code", stdout.getvalue())
        self.assertIn("network", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_missing_pi_consent_is_a_stable_package_diagnostic(self) -> None:
        from subagents_configs import orchestrator

        stdout, stderr = StringIO(), StringIO()
        request = self._request(
            consent_third_party_code=False,
            consent_network=False,
        )
        plan = self._preflight()
        with (
            patch.object(
                orchestrator, "validate_request_compatibility", return_value=()
            ),
            patch(
                "subagents_configs.planning.validate_request_compatibility",
                return_value=(),
            ),
            patch.object(orchestrator, "_plan", return_value=plan),
            patch.object(orchestrator, "apply_transaction") as apply,
        ):
            status = orchestrator._run_mutating_locked(
                request,
                repo_root=self.repository,
                stdout=stdout,
                stderr=stderr,
                failure_injector=None,
            )
        self.assertEqual(status, orchestrator.EXIT_APPLY_ERROR)
        self.assertIn("PI_CONSENT_REQUIRED", stderr.getvalue())
        self.assertIn("phase=package", stderr.getvalue())
        apply.assert_not_called()

    def test_public_run_defers_missing_pi_consent_to_package_phase(self) -> None:
        from subagents_configs import orchestrator

        stdout, stderr = StringIO(), StringIO()
        request_plan = self._preflight()
        with (
            patch.object(
                orchestrator,
                "validate_request_compatibility",
                return_value=(),
            ),
            patch(
                "subagents_configs.planning.validate_request_compatibility",
                return_value=(),
            ),
            patch.object(orchestrator, "_plan", return_value=request_plan),
            patch.object(orchestrator, "apply_transaction") as apply,
        ):
            status = orchestrator.run(
                "install",
                [
                    "--target",
                    "pi",
                    "--home",
                    f"pi={self.home}",
                    "--pi-executable",
                    str(self.fake_pi.resolve()),
                ],
                repo_root=self.repository,
                environ={"HOME": str(self.root)},
                stdout=stdout,
                stderr=stderr,
            )
        self.assertEqual(status, orchestrator.EXIT_APPLY_ERROR)
        self.assertIn("PI_CONSENT_REQUIRED", stderr.getvalue())
        self.assertIn("phase=package", stderr.getvalue())
        apply.assert_not_called()

    def test_exact_preexisting_package_validates_runtime_before_local_apply(
        self,
    ) -> None:
        from subagents_configs import orchestrator

        self._write_exact_package()
        plan = self._preflight()
        self.assertEqual(plan.external.action, "none")
        runtime_calls: list[tuple[Path, Path, bool]] = []

        def validate(path: Path, *, agent_dir: Path, execute: bool):
            runtime_calls.append((path, agent_dir, execute))
            raise orchestrator.PiPackageError("PI_RUNTIME_INCOMPATIBLE")

        with (
            patch.object(
                orchestrator, "validate_request_compatibility", return_value=()
            ),
            patch.object(orchestrator, "_plan", return_value=plan),
            patch.object(orchestrator, "validate_pi_executable", side_effect=validate),
            patch.object(orchestrator, "apply_transaction") as apply,
        ):
            status = orchestrator._run_mutating_locked(
                self._request(),
                repo_root=self.repository,
                stdout=StringIO(),
                stderr=StringIO(),
                failure_injector=None,
            )
        self.assertEqual(status, orchestrator.EXIT_APPLY_ERROR)
        self.assertEqual(runtime_calls, [(self.fake_pi, self.home, True)])
        apply.assert_not_called()

    def test_dry_run_detects_package_store_identity_change_between_collections(
        self,
    ) -> None:
        from subagents_configs import orchestrator

        self._write_exact_package()
        plan = self._preflight()
        real_fingerprint = orchestrator._plan_fingerprint
        calls = 0

        def fingerprint(value: object):
            nonlocal calls
            result = real_fingerprint(value)
            calls += 1
            if calls == 1:
                store = self.home / "npm"
                moved = self.root / "moved-npm"
                store.rename(moved)
                store.mkdir(mode=0o700)
                shutil.rmtree(moved)
            return result

        with (
            patch(
                "subagents_configs.planning.validate_request_compatibility",
                return_value=(),
            ),
            patch.object(orchestrator, "_plan", return_value=plan),
            patch.object(orchestrator, "_plan_fingerprint", side_effect=fingerprint),
        ):
            with self.assertRaises(orchestrator.ConcurrentDryRunChangeError):
                orchestrator._collect_stable_dry_run_evidence(
                    self._request(dry_run=False), self.repository
                )

    def test_json_dry_run_labels_caller_owned_runtime_fact(self) -> None:
        from subagents_configs import orchestrator

        stdout, stderr = StringIO(), StringIO()
        with (
            patch.object(
                orchestrator,
                "validate_request_compatibility",
                return_value=(),
            ),
            patch(
                "subagents_configs.planning.validate_request_compatibility",
                return_value=(),
            ),
        ):
            status = orchestrator.run(
                "install",
                [
                    "--target",
                    "pi",
                    "--home",
                    f"pi={self.home}",
                    "--dry-run",
                    "--format",
                    "json",
                    "--pi-executable",
                    str(self.fake_pi.resolve()),
                    "--client-version",
                    "pi=0.84.1",
                ],
                repo_root=self.repository,
                environ={"HOME": str(self.root)},
                stdout=stdout,
                stderr=stderr,
            )
        self.assertEqual(status, orchestrator.EXIT_SUCCESS)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            payload["external"]["runtime_version_evidence"], "caller-supplied"
        )
        self.assertEqual(payload["external"]["phase"], "external-package-phase")
        self.assertEqual(payload["external"]["ownership"], "external")
        self.assertEqual(payload["external"]["recovery"], "preserve-external-state")
        self.assertEqual(stderr.getvalue(), "")

    def test_dry_run_rejects_unmaintained_pi_version_without_execution(self) -> None:
        from subagents_configs import orchestrator

        stdout, stderr = StringIO(), StringIO()
        with (
            patch.object(
                orchestrator,
                "validate_request_compatibility",
                return_value=(),
            ),
            patch.object(
                orchestrator,
                "validate_pi_executable",
                side_effect=AssertionError("version rejection must be preflight-only"),
            ),
            patch(
                "subagents_configs.planning.validate_request_compatibility",
                return_value=(),
            ),
        ):
            status = orchestrator.run(
                "install",
                [
                    "--target",
                    "pi",
                    "--home",
                    f"pi={self.home}",
                    "--dry-run",
                    "--pi-executable",
                    str(self.fake_pi.resolve()),
                    "--client-version",
                    "pi=0.83.0",
                ],
                repo_root=self.repository,
                environ={"HOME": str(self.root)},
                stdout=stdout,
                stderr=stderr,
            )
        self.assertEqual(status, orchestrator.EXIT_PREFLIGHT_ERROR)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("PI_RUNTIME_INCOMPATIBLE", stderr.getvalue())

    def test_pi_context_sanitizer_drops_untrusted_identifier_and_home(self) -> None:
        from subagents_configs.errors import sanitize_pi_context

        context = sanitize_pi_context(
            "PI_PACKAGE_DRIFT",
            target="pi",
            phase="package",
            safe_identifier="API_KEY=private",
            normalized_home="/private/user/home",
        )
        self.assertEqual(context["target"], "pi")
        self.assertEqual(context["phase"], "package")
        self.assertEqual(context["identifier"], "unknown")
        self.assertEqual(context["home"], "home-1")


if __name__ == "__main__":
    unittest.main()
