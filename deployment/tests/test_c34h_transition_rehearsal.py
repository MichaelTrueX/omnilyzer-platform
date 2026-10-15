"""File: deployment/tests/test_c34h_transition_rehearsal.py

Purpose: Qualify atomic five-file rehearsal and the exact recovery/rollback
order under synthetic interruption, source drift and invalid stage artifacts.
Related: deployment/c34h_transition_rehearsal.py,
deployment/c34g_migration_authority.py,
deployment/tests/test_c34g_migration_authority.py.

Every test uses an automatically created disposable sandbox, not installed
source, systemd, Docker, root privileges, tokens, replay or production state.
"""

from __future__ import annotations

import os
from pathlib import Path
import unittest
from unittest.mock import patch

from deployment import c34f_application_generation_evidence as evidence
from deployment.c34h_transition_rehearsal import (
    C34HIsolatedRehearsal,
    C34HInjectedInterruption,
    C34HRehearsalError,
)
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_executor_service_config import configuration_values
from deployment.tests.test_broker_service_config import configuration_values as broker_values


def make_rehearsal() -> C34HIsolatedRehearsal:
    """Construct a synthetic aligned predecessor, preserving C34D authority."""
    executor = DevExecutorServiceConfiguration(
        **configuration_values(reviewed_commit=evidence.PREDECESSOR)
    )
    shared = {
        field: getattr(executor, field)
        for field in (
            "broker_uid", "broker_gid", "executor_uid", "executor_gid",
            "replay_group_gid", "socket_group_gid",
            "runtime_configuration_sha256", "ingress_file_sha256",
        )
    }
    broker = DevBrokerServiceConfiguration(
        **broker_values(
            reviewed_commit=evidence.PREDECESSOR,
            expected_workflow_sha=evidence.C34D_MAIN,
            **shared,
        )
    )
    return C34HIsolatedRehearsal(executor=executor, broker=broker)


class C34HIsolatedTests(unittest.TestCase):
    """Prove only the closed five-file migration can be rehearsed."""

    def test_complete_forward_then_reverse(self):
        """All five source/config steps migrate and restore exactly."""
        with make_rehearsal() as rehearsal:
            self.assertEqual(rehearsal.current().completed_steps, 0)
            for count in range(1, 6):
                receipt = rehearsal.advance()
                self.assertEqual(receipt.completed_steps, count)
            self.assertEqual(rehearsal.advance().completed_steps, 5)
            self.assertEqual(rehearsal.current().completed_steps, 5)
            for count in range(4, -1, -1):
                receipt = rehearsal.rollback_one()
                self.assertEqual(receipt.completed_steps, count)
            self.assertEqual(rehearsal.rollback_one().completed_steps, 0)
            self.assertEqual(rehearsal.current().completed_steps, 0)

    def test_each_interruption_stage_can_resume(self):
        """Test create/partial/full-stage/renamed interruptions at each step."""
        for fault in (
            "after_stage_create", "after_half_write",
            "before_replace", "after_replace",
        ):
            with self.subTest(fault=fault), make_rehearsal() as rehearsal:
                for phase in range(5):
                    with self.assertRaises(C34HInjectedInterruption):
                        rehearsal.advance(interrupt=fault)
                    current = rehearsal.current()
                    self.assertIn(current.completed_steps, (phase, phase + 1))
                    if current.completed_steps == phase:
                        result = rehearsal.advance()
                        self.assertEqual(result.completed_steps, phase + 1)
                self.assertEqual(rehearsal.current().completed_steps, 5)
                while rehearsal.current().completed_steps:
                    rehearsal.rollback_one()
                self.assertEqual(rehearsal.current().completed_steps, 0)

    def test_rollback_from_incomplete_forward_stage(self):
        """Delete only the verified pending stage and reverse the prior step."""
        with make_rehearsal() as rehearsal:
            rehearsal.advance()
            with self.assertRaises(C34HInjectedInterruption):
                rehearsal.advance(interrupt="after_half_write")
            self.assertEqual(rehearsal.current().completed_steps, 1)
            receipt = rehearsal.rollback_one()
            self.assertEqual(receipt.completed_steps, 0)
            self.assertEqual(rehearsal.current().completed_steps, 0)

    def test_corrupted_stage_is_not_accepted_or_deleted(self):
        """An unexpected staged payload is a hard HOLD, including rollback."""
        with make_rehearsal() as rehearsal:
            with self.assertRaises(C34HInjectedInterruption):
                rehearsal.advance(interrupt="after_stage_create")
            stage = rehearsal._file(evidence.CHANGED[0]).parent / ".c34h-stage"
            stage.write_bytes(b"UNAPPROVED_STAGE_BYTES")
            with self.assertRaises(C34HRehearsalError):
                rehearsal.advance()
            with self.assertRaises(C34HRehearsalError):
                rehearsal.rollback_one()
            self.assertEqual(rehearsal.current().completed_steps, 0)

    def test_corrupt_installed_blob_blocks_further_changes(self):
        """A modified unrelated one of the 38 protected files stops progress."""
        with make_rehearsal() as rehearsal:
            path = rehearsal._root / "app" / "deployment" / "state.py"
            with open(path, "ab") as out:
                out.write(b"UNAPPROVED_CHANGE")
            with self.assertRaises(C34HRehearsalError):
                rehearsal.advance()

    def test_symlink_source_is_rejected(self):
        """No source symlink may be treated as a valid application file."""
        with make_rehearsal() as rehearsal:
            path = rehearsal._root / "app" / "deployment" / "state.py"
            other = rehearsal._root / "app" / "deployment" / "state_store.py"
            path.unlink()
            path.symlink_to(other)
            with self.assertRaises(C34HRehearsalError):
                rehearsal.advance()

    def test_root_cannot_run_rehearsal(self):
        """Root execution is categorically forbidden even for a private tree."""
        with patch("deployment.c34h_transition_rehearsal.os.geteuid", return_value=0):
            with self.assertRaises(C34HRehearsalError):
                make_rehearsal()

    def test_unknown_interrupt_and_target_rejected(self):
        """No caller-selected destination, interruption type, or operation."""
        with make_rehearsal() as rehearsal:
            with self.assertRaises(C34HRehearsalError):
                rehearsal.advance(interrupt="arbitrary")
            with self.assertRaises(C34HRehearsalError):
                rehearsal._file("/opt/omnilyzer/deployment/app/deployment/broker.py")


if __name__ == "__main__":
    unittest.main()
