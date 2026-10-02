"""Tests for the pure C33AE executor/broker configuration projection."""

from dataclasses import replace
import hashlib
import unittest
from unittest.mock import patch

from deployment import dev_post_c31_application_update as historical
from deployment import executor_service_config as executor_config
from deployment import state_store_successor_configuration_authority as module
from deployment.tests.test_executor_service_config import configuration_values


WORKFLOW = "b" * 40


class StateStoreSuccessorConfigurationAuthorityTests(unittest.TestCase):
    """Require reviewed-commit-only executor drift and aligned broker authority."""

    def setUp(self) -> None:
        """Build the same exact C32W seed used by predecessor authority tests."""

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
        self.before = module._predecessor(seed)

    def test_executor_changes_only_reviewed_commit(self) -> None:
        """Project only reviewed_commit while retaining all other executor bytes."""

        authority = module.DevStateStoreSuccessorConfigurationAuthority(
            predecessor_configuration=self.before
        )
        after = authority.executor()
        changed = {
            key
            for key in self.before.to_dict()
            if self.before.to_dict()[key] != after.to_dict()[key]
        }
        self.assertEqual(changed, {"reviewed_commit"})
        self.assertEqual(
            after.reviewed_commit,
            module.TARGET_REVIEWED_COMMIT,
        )

    def test_pair_changes_only_reviewed_commit_and_explicit_workflow(self) -> None:
        """Bind one explicit workflow SHA while preserving installation identity."""

        pair = module.DevStateStoreSuccessorConfigurationAuthority(
            predecessor_configuration=self.before
        ).configuration_pair(expected_workflow_sha=WORKFLOW)
        self.assertEqual(
            pair.executor.reviewed_commit,
            module.TARGET_REVIEWED_COMMIT,
        )
        self.assertEqual(
            pair.broker.reviewed_commit,
            module.TARGET_REVIEWED_COMMIT,
        )
        self.assertEqual(pair.broker.expected_workflow_sha, WORKFLOW)
        self.assertEqual(
            module._installation_contract_signature(
                pair.executor.installation_contract()
            ),
            module._installation_contract_signature(
                pair.broker.installation_contract()
            ),
        )

    def test_forged_or_unrelated_predecessors_fail_closed(self) -> None:
        """Reject targets or unrelated commits where predecessor is required."""

        with self.assertRaises(ValueError):
            module.DevStateStoreSuccessorConfigurationAuthority(
                predecessor_configuration=replace(
                    self.before,
                    reviewed_commit="c" * 40,
                )
            )
        target = module.DevStateStoreSuccessorConfigurationAuthority(
            predecessor_configuration=self.before
        ).executor()
        with self.assertRaises(ValueError):
            module.DevStateStoreSuccessorConfigurationAuthority(
                predecessor_configuration=target
            )


if __name__ == "__main__":
    unittest.main()
