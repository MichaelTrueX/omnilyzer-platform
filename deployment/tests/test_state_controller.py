from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from deployment.controller import (
    LIVENESS_PATH,
    READINESS_PATH,
    GateResults,
    authorize_traffic_switch,
    complete_promotion,
    complete_rollback,
    prepare_candidate,
    promotion_plan,
    rollback_plan,
)
from deployment.policy import DeploymentPolicyError
from deployment.state import (
    DEV_STATE_PATH,
    DeploymentState,
    MigrationState,
    load_state,
    verify_migration_history,
    write_state_atomic,
)

from deployment.tests.fixtures import DIGEST, OTHER_DIGEST, TIMESTAMP, request, state


PASSING_GATES = GateResults(True, True, True, True, True)


class DeploymentStateTests(unittest.TestCase):
    def test_valid_blue_green_state_is_accepted(self) -> None:
        current = state(candidate=True)
        self.assertEqual(current.active_slot, "blue")
        self.assertEqual(current.candidate_slot, "green")

    def test_candidate_slot_must_differ_from_active(self) -> None:
        value = state(candidate=True).to_dict()
        value["candidate_slot"] = "blue"
        with self.assertRaises(DeploymentPolicyError):
            DeploymentState.from_dict(value)

    def test_corrupt_or_partial_state_is_rejected(self) -> None:
        values = []
        unknown = state().to_dict()
        unknown["unknown"] = True
        values.append(unknown)
        partial = state().to_dict()
        partial["active_digest"] = None
        values.append(partial)
        malformed = state().to_dict()
        malformed["active_digest"] = "sha256:1234"
        values.append(malformed)
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(DeploymentPolicyError):
                    DeploymentState.from_dict(value)

    def test_atomic_state_round_trip_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            write_state_atomic(path, state())
            self.assertEqual(load_state(path), state())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(str(DEV_STATE_PATH), "/var/lib/omnilyzer/deployment/dev/state.json")

    def test_migration_history_accepts_same_checksum_and_rejects_change(self) -> None:
        history = {"014_additive": "c" * 64}
        self.assertTrue(verify_migration_history("014_additive", "c" * 64, history))
        with self.assertRaisesRegex(DeploymentPolicyError, "checksum changed"):
            verify_migration_history("014_additive", "d" * 64, history)

    def test_migration_state_always_requires_serialized_lock(self) -> None:
        with self.assertRaisesRegex(DeploymentPolicyError, "serialized lock"):
            MigrationState.from_dict({
                "status": "pending", "identity": "014_additive", "checksum": "c" * 64,
                "serialized_lock_required": False,
            })


class PromotionControllerTests(unittest.TestCase):
    def test_blue_green_plan_preserves_required_order(self) -> None:
        plan = promotion_plan(state(), request())
        self.assertEqual(plan.candidate_slot, "green")
        self.assertEqual(plan.exact_image_reference, request().exact_image_reference)
        self.assertLess(plan.steps.index("execute_migration"), plan.steps.index("check_readiness"))
        self.assertLess(plan.steps.index("check_readiness"), plan.steps.index("switch_nginx_traffic"))
        self.assertEqual((LIVENESS_PATH, READINESS_PATH), ("/livez", "/readyz"))

    def test_prepare_candidate_uses_inactive_slot_and_exact_digest(self) -> None:
        prepared = prepare_candidate(state(), request(), "014_additive", "c" * 64)
        self.assertEqual(prepared.candidate_slot, "green")
        self.assertEqual(prepared.candidate_digest, DIGEST)
        self.assertEqual(prepared.migration_state.status, "pending")

    def test_migration_failure_blocks_switch(self) -> None:
        candidate = state(candidate=True)
        candidate = replace(candidate, migration_state=replace(candidate.migration_state, status="failed"))
        with self.assertRaises(DeploymentPolicyError):
            authorize_traffic_switch(candidate, PASSING_GATES)

    def test_readiness_failure_blocks_switch(self) -> None:
        candidate = self._ready_candidate()
        with self.assertRaises(DeploymentPolicyError):
            authorize_traffic_switch(candidate, replace(PASSING_GATES, readiness_passed=False))

    def test_nginx_validation_failure_blocks_switch(self) -> None:
        candidate = self._ready_candidate()
        with self.assertRaises(DeploymentPolicyError):
            authorize_traffic_switch(candidate, replace(PASSING_GATES, nginx_validation_passed=False))

    def test_candidate_failure_leaves_active_state_unchanged(self) -> None:
        candidate = self._ready_candidate()
        before = candidate.canonical_bytes()
        with self.assertRaises(DeploymentPolicyError):
            complete_promotion(
                candidate, replace(PASSING_GATES, application_validation_passed=False),
                updated_at=TIMESTAMP, event_id="failed-switch",
            )
        self.assertEqual(candidate.canonical_bytes(), before)
        self.assertEqual(candidate.active_digest, OTHER_DIGEST)

    def test_success_retains_previous_digest_and_clears_candidate(self) -> None:
        promoted = complete_promotion(
            self._ready_candidate(), PASSING_GATES,
            updated_at="2026-09-07T06:31:00Z", event_id="promotion-success",
        )
        self.assertEqual(promoted.active_digest, DIGEST)
        self.assertEqual(promoted.previous_digest, OTHER_DIGEST)
        self.assertIsNone(promoted.candidate_digest)

    def test_rollback_without_previous_digest_is_rejected(self) -> None:
        with self.assertRaises(DeploymentPolicyError):
            rollback_plan(state(previous=False))

    def test_rollback_uses_retained_digest_without_migration_or_rebuild(self) -> None:
        plan = rollback_plan(state())
        self.assertTrue(plan.exact_image_reference.endswith("@" + "sha256:" + "3" * 64))
        text = " ".join(plan.steps)
        self.assertNotIn("migration", text)
        self.assertNotIn("build", text)
        self.assertNotIn("down", text)

    def test_rollback_retains_replaced_digest_and_schema_state(self) -> None:
        current = state()
        migration = current.migration_state
        rolled_back = complete_rollback(
            current, PASSING_GATES,
            updated_at="2026-09-07T06:32:00Z", event_id="rollback-success",
        )
        self.assertEqual(rolled_back.active_digest, "sha256:" + "3" * 64)
        self.assertEqual(rolled_back.previous_digest, OTHER_DIGEST)
        self.assertEqual(rolled_back.migration_state, migration)

    @staticmethod
    def _ready_candidate() -> DeploymentState:
        candidate = state(candidate=True)
        return replace(candidate, migration_state=replace(candidate.migration_state, status="succeeded"))


if __name__ == "__main__":
    unittest.main()
