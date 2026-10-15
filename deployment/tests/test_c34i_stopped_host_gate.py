"""File: deployment/tests/test_c34i_stopped_host_gate.py

Purpose: Validate C34I's root-only, stopped-service, exclusive-lock source
qualification and intentionally disabled final-merge installation gate.
Related: deployment/c34i_stopped_host_gate.py,
deployment/c34g_installed_predecessor_preflight.py,
deployment/state_store_successor_host_migration_runtime.py.

Uses synthetic source/config evidence and mocked host probes. Never calls
sudo, systemd, rootless Docker, installed source, replay, audit or deployment.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import unittest
from unittest.mock import patch

from deployment import c34i_stopped_host_gate as gate
from deployment import c34f_application_generation_evidence as evidence
from deployment import dev_host_provisioning_orchestration as orchestration
from deployment import state_store_successor_host_migration_runtime as runtime
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_broker_service_config import configuration_values as broker_values
from deployment.tests.test_executor_service_config import configuration_values as executor_values


class C34IStoppedHostGateTests(unittest.TestCase):
    """Check root identity, stopped services, unchanged runtime and write HOLD."""

    def setUp(self) -> None:
        """Build only synthetic, mutually consistent canonical configurations."""
        self.executor = DevExecutorServiceConfiguration(
            **executor_values(reviewed_commit=evidence.PREDECESSOR)
        )
        names = (
            "broker_uid", "broker_gid", "executor_uid", "executor_gid",
            "replay_group_gid", "socket_group_gid",
            "runtime_configuration_sha256", "ingress_file_sha256",
        )
        aligned = {name: getattr(self.executor, name) for name in names}
        self.broker = DevBrokerServiceConfiguration(
            **broker_values(
                reviewed_commit=evidence.PREDECESSOR,
                expected_workflow_sha=evidence.C34D_MAIN,
                **aligned,
            )
        )

    def _host_mocks(self, stack: ExitStack):
        """Pin all host interfaces without touching the actual filesystem."""
        acquired = orchestration._ProcessLock((), -1)
        spies = {}
        for key, target, value in (
            ("root", "deployment.state_store_successor_host_migration_runtime._root_identity",
             (0, 0)),
            ("services", "deployment.state_store_successor_host_migration_runtime._service_snapshot",
             (("broker", ("loaded", "inactive", "dead")),)),
            ("runtime", "deployment.state_store_successor_host_migration_runtime._rootless_runtime_signature",
             (1005, 2005, ())),
            ("executor", "deployment.c34i_stopped_host_gate.read_root_dev_executor_configuration",
             self.executor),
            ("broker", "deployment.c34i_stopped_host_gate.read_root_dev_broker_configuration",
             self.broker),
            ("source", "deployment.c34i_stopped_host_gate.predecessor.verify_source",
             None),
            ("configs", "deployment.c34i_stopped_host_gate.predecessor.verify_configs",
             None),
            ("acquire", "deployment.c34i_stopped_host_gate.orchestration._acquire_process_lock",
             acquired),
            ("release", "deployment.c34i_stopped_host_gate.orchestration._release_process_lock",
             None),
        ):
            spies[key] = stack.enter_context(patch(target, return_value=value))
        return spies

    def test_exact_predecessor_yields_non_authorizing_receipt(self):
        """Even a clean stopped host must have migration_ready=False."""
        with ExitStack() as stack:
            spies = self._host_mocks(stack)
            receipt = gate.qualify_c34i_stopped_host_predecessor()
            self.assertEqual(receipt.protected_file_count, 41)
            self.assertTrue(receipt.broker_executor_stopped)
            self.assertTrue(receipt.rootless_runtime_preserved)
            self.assertFalse(receipt.migration_ready)
            self.assertEqual(receipt.expected_workflow_sha, evidence.C34D_MAIN)
            spies["acquire"].assert_called_once_with()
            spies["release"].assert_called_once_with(
                orchestration._ProcessLock((), -1)
            )
            self.assertEqual(spies["source"].call_count, 2)
            self.assertEqual(spies["configs"].call_count, 2)

    def test_preflight_failure_releases_exclusive_lock(self):
        """A stopped-unit check failure must release the acquired lock."""
        with ExitStack() as stack:
            spies = self._host_mocks(stack)
            spies["services"].side_effect = OSError("synthetic private error")
            with self.assertRaises(gate.C34IStoppedHostGateError) as caught:
                gate.qualify_c34i_stopped_host_predecessor()
            self.assertEqual(str(caught.exception), gate._ERROR)
            spies["release"].assert_called_once()

    def test_application_drift_aborts_without_publication(self):
        """A source integrity mismatch cannot pass the stopped-host gate."""
        with ExitStack() as stack:
            spies = self._host_mocks(stack)
            spies["source"].side_effect = ValueError("drift-not-for-logs")
            with self.assertRaises(gate.C34IStoppedHostGateError) as caught:
                gate.qualify_c34i_stopped_host_predecessor()
            self.assertNotIn("drift-not-for-logs", str(caught.exception))
            spies["release"].assert_called_once()

    def test_runtime_change_between_snapshots_aborts(self):
        """Rootless process identity must remain stable throughout inspection."""
        with ExitStack() as stack:
            spies = self._host_mocks(stack)
            spies["runtime"].side_effect = [(1005, 2005, ()), (1005, 3005, ())]
            with self.assertRaises(gate.C34IStoppedHostGateError):
                gate.qualify_c34i_stopped_host_predecessor()
            spies["release"].assert_called_once()

    def test_unexpected_config_workflow_binding_rejected(self):
        """A fabricated source generation or workflow cannot be accepted."""
        with ExitStack() as stack:
            spies = self._host_mocks(stack)
            spies["broker"].return_value = replace(
                self.broker, expected_workflow_sha="f" * 40
            )
            with self.assertRaises(gate.C34IStoppedHostGateError):
                gate.qualify_c34i_stopped_host_predecessor()

    def test_lock_release_failure_fails_closed(self):
        """A missing lock release must never produce a PASS."""
        with ExitStack() as stack:
            spies = self._host_mocks(stack)
            spies["release"].side_effect = OSError("failed release")
            with self.assertRaises(gate.C34IStoppedHostGateError):
                gate.qualify_c34i_stopped_host_predecessor()

    def test_root_gate_rejects_all_draft_and_future_targets(self):
        """Current C34I has no deployable final-main target, by design."""
        for supplied in (
            evidence.C34E_PROPOSAL, evidence.C34D_MAIN, "f" * 40, "", None, 4
        ):
            with self.subTest(target=supplied), self.assertRaises(
                gate.C34IStoppedHostGateError
            ):
                gate.require_final_merge_authority(supplied)

    def test_no_approval_via_forged_receipt(self):
        """No caller-created receipt can turn the blocked installation on."""
        expected = gate.C34IStoppedHostEvidence(
            evidence.PREDECESSOR, evidence.C34D_MAIN, 41,
            True, True, False,
        )
        with self.assertRaises(ValueError):
            replace(expected, migration_ready=True)
        with self.assertRaises(ValueError):
            replace(expected, protected_file_count=40)

    def test_public_surface_has_no_mutating_entrypoint(self):
        """No installer, promoter or root write routine is exported."""
        self.assertEqual(gate.__all__, (
            "C34IStoppedHostGateError",
            "C34IStoppedHostEvidence",
            "require_final_merge_authority",
            "qualify_c34i_stopped_host_predecessor",
        ))


if __name__ == "__main__":
    unittest.main()
