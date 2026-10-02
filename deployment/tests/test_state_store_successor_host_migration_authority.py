"""Tests for the pure C33AC host-migration prefix authority."""

from dataclasses import replace
import hashlib
import unittest
from unittest.mock import patch

from deployment import dev_post_c31_application_update as historical
from deployment import executor_service_config as executor_config
from deployment import state_store_successor_host_migration_authority as module
from deployment import state_store_successor_configuration_authority as configuration_authority
from deployment.tests.test_executor_service_config import configuration_values


TARGET_WORKFLOW = "d" * 40


class StateStoreSuccessorHostMigrationAuthorityTests(unittest.TestCase):
    """Require one exact old-to-new prefix order with no mixed authority."""

    def setUp(self) -> None:
        """Build the exact predecessor pair under the historical C17 test pin."""

        values = configuration_values(
            reviewed_commit=module.PREDECESSOR_REVIEWED_COMMIT,
        )
        seed = executor_config.DevExecutorServiceConfiguration(**values)
        historical_seed = replace(
            seed,
            reviewed_commit=historical.PREDECESSOR,
        )
        fixture_hash = hashlib.sha256(
            historical_seed.canonical_bytes()
        ).hexdigest()
        self.pin = patch(
            "deployment.final_configuration_authority.c32d.PREDECESSOR_C17",
            fixture_hash,
        )
        self.pin.start()
        self.addCleanup(self.pin.stop)

        self.old_executor = configuration_authority._predecessor(seed)
        self.old_broker = configuration_authority._predecessor_broker(
            self.old_executor,
            module.PREDECESSOR_WORKFLOW_SHA,
        )
        self.authority = module.DevStateStoreSuccessorHostMigrationAuthority(
            predecessor_executor=self.old_executor,
            predecessor_broker=self.old_broker,
            target_workflow_sha=TARGET_WORKFLOW,
        )
        self.target = self.authority.target_pair()

    def test_exact_four_prefixes_and_operations(self) -> None:
        """Accept only the four ordered old/new host authority combinations."""

        cases = (
            (
                module.PREDECESSOR_REVIEWED_COMMIT,
                self.old_executor,
                self.old_broker,
                "predecessor",
                "replace-state-store",
            ),
            (
                module.TARGET_REVIEWED_COMMIT,
                self.old_executor,
                self.old_broker,
                "application",
                "replace-executor-configuration",
            ),
            (
                module.TARGET_REVIEWED_COMMIT,
                self.target.executor,
                self.old_broker,
                "executor",
                "replace-broker-configuration",
            ),
            (
                module.TARGET_REVIEWED_COMMIT,
                self.target.executor,
                self.target.broker,
                "complete",
                "complete",
            ),
        )
        for app, executor, broker, phase, operation in cases:
            with self.subTest(phase=phase):
                state = self.authority.classify(
                    application_reviewed_commit=app,
                    executor=executor,
                    broker=broker,
                )
                self.assertEqual((state.phase, state.next_operation), (phase, operation))
                self.assertEqual(state.target_workflow_sha, TARGET_WORKFLOW)

    def test_mixed_or_out_of_order_prefixes_fail_closed(self) -> None:
        """Reject every authority mix not represented by the four prefixes."""

        invalid = (
            (
                module.PREDECESSOR_REVIEWED_COMMIT,
                self.target.executor,
                self.old_broker,
            ),
            (
                module.PREDECESSOR_REVIEWED_COMMIT,
                self.old_executor,
                self.target.broker,
            ),
            (
                module.TARGET_REVIEWED_COMMIT,
                self.old_executor,
                self.target.broker,
            ),
            (
                module.TARGET_REVIEWED_COMMIT,
                self.target.executor,
                replace(self.target.broker, expected_workflow_sha="e" * 40),
            ),
        )
        for app, executor, broker in invalid:
            with self.subTest(app=app, executor=executor.reviewed_commit):
                with self.assertRaises(ValueError):
                    self.authority.classify(
                        application_reviewed_commit=app,
                        executor=executor,
                        broker=broker,
                    )

    def test_predecessor_workflow_and_target_workflow_are_independent(self) -> None:
        """Pin the live predecessor while allowing one explicit future workflow."""

        self.assertEqual(
            self.old_broker.expected_workflow_sha,
            module.PREDECESSOR_WORKFLOW_SHA,
        )
        self.assertEqual(
            self.target.broker.expected_workflow_sha,
            TARGET_WORKFLOW,
        )
        with self.assertRaises(ValueError):
            module.DevStateStoreSuccessorHostMigrationAuthority(
                predecessor_executor=self.old_executor,
                predecessor_broker=replace(
                    self.old_broker,
                    expected_workflow_sha="f" * 40,
                ),
                target_workflow_sha=TARGET_WORKFLOW,
            )

    def test_invalid_target_workflow_rejected_without_io(self) -> None:
        """Reject malformed target workflow SHAs during pure construction."""

        for value in (
            "0" * 40,
            "A" * 40,
            "short",
            True,
            module.PREDECESSOR_WORKFLOW_SHA,
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.DevStateStoreSuccessorHostMigrationAuthority(
                    predecessor_executor=self.old_executor,
                    predecessor_broker=self.old_broker,
                    target_workflow_sha=value,
                )


if __name__ == "__main__":
    unittest.main()
