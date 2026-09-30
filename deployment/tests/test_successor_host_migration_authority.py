"""C32ZJ pure successor host-migration state-machine tests."""

from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
import builtins
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from deployment import dev_post_c31_application_update as historical
from deployment import final_application_generation as c32w
from deployment import successor_application_generation as generation
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.final_configuration_authority import DevFinalConfigurationAuthority
from deployment.successor_host_migration_authority import (
    DevSuccessorHostMigrationAuthority,
    DevSuccessorHostMigrationState,
)
from deployment.tests.test_executor_service_config import configuration_values


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40


class SuccessorHostMigrationAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        values = configuration_values(reviewed_commit=c32w.TARGET_REVIEWED_COMMIT)
        predecessor = DevExecutorServiceConfiguration(**values)
        historical_seed = replace(
            predecessor, reviewed_commit=historical.PREDECESSOR,
        )
        fixture_hash = hashlib.sha256(
            historical_seed.canonical_bytes(),
        ).hexdigest()
        self.pin = patch(
            "deployment.final_configuration_authority.c32d.PREDECESSOR_C17",
            fixture_hash,
        )
        self.pin.start()
        self.addCleanup(self.pin.stop)
        pair = DevFinalConfigurationAuthority(
            executor_configuration=predecessor,
        ).configuration_pair(expected_workflow_sha=WORKFLOW)
        self.predecessor = pair
        self.authority = DevSuccessorHostMigrationAuthority(
            predecessor_executor=pair.executor,
            predecessor_broker=pair.broker,
        )
        self.successor = self.authority.successor_pair()

    def classify(self, digest, executor, broker):
        return self.authority.classify(
            application_sha256=digest,
            executor=executor,
            broker=broker,
        )

    def test_exact_four_prefixes_and_next_operations(self) -> None:
        cases = (
            (
                generation.PREDECESSOR_DOCKER_SHA256,
                self.predecessor.executor,
                self.predecessor.broker,
                ("c32w", "replace-application"),
            ),
            (
                generation.TARGET_DOCKER_SHA256,
                self.predecessor.executor,
                self.predecessor.broker,
                ("application", "replace-executor-configuration"),
            ),
            (
                generation.TARGET_DOCKER_SHA256,
                self.successor.executor,
                self.predecessor.broker,
                ("executor", "replace-broker-configuration"),
            ),
            (
                generation.TARGET_DOCKER_SHA256,
                self.successor.executor,
                self.successor.broker,
                ("complete", "complete"),
            ),
        )
        for digest, executor, broker, expected in cases:
            with self.subTest(expected=expected):
                state = self.classify(digest, executor, broker)
                self.assertEqual((state.phase, state.next_operation), expected)
                self.assertEqual(state.expected_workflow_sha, WORKFLOW)

    def test_out_of_order_and_mixed_authority_fail_closed(self) -> None:
        cases = (
            (
                generation.PREDECESSOR_DOCKER_SHA256,
                self.successor.executor,
                self.predecessor.broker,
            ),
            (
                generation.PREDECESSOR_DOCKER_SHA256,
                self.predecessor.executor,
                self.successor.broker,
            ),
            (
                generation.TARGET_DOCKER_SHA256,
                self.predecessor.executor,
                self.successor.broker,
            ),
            (
                generation.TARGET_DOCKER_SHA256,
                self.successor.executor,
                replace(self.successor.broker, expected_workflow_sha="b" * 40),
            ),
            ("0" * 64, self.predecessor.executor, self.predecessor.broker),
        )
        for digest, executor, broker in cases:
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                self.classify(digest, executor, broker)

    def test_successor_preserves_workflow_and_changes_only_reviewed_commit(self) -> None:
        before_executor = self.predecessor.executor.to_dict()
        after_executor = self.successor.executor.to_dict()
        before_broker = self.predecessor.broker.to_dict()
        after_broker = self.successor.broker.to_dict()
        self.assertEqual(
            {key for key in before_executor if before_executor[key] != after_executor[key]},
            {"reviewed_commit"},
        )
        self.assertEqual(
            {key for key in before_broker if before_broker[key] != after_broker[key]},
            {"reviewed_commit"},
        )
        self.assertEqual(
            self.successor.broker.expected_workflow_sha,
            self.predecessor.broker.expected_workflow_sha,
        )
        self.assertEqual(
            self.successor.executor.reviewed_commit,
            generation.TARGET_REVIEWED_COMMIT,
        )

    def test_authority_rebuilds_nested_state_and_is_immutable(self) -> None:
        damaged_executor = replace(self.predecessor.executor)
        object.__setattr__(damaged_executor, "_installation", object())
        damaged_broker = replace(self.predecessor.broker)
        object.__setattr__(damaged_broker, "_installation", object())
        rebuilt = DevSuccessorHostMigrationAuthority(
            predecessor_executor=damaged_executor,
            predecessor_broker=damaged_broker,
        )
        self.assertIsNot(
            rebuilt.predecessor_executor.installation_contract(),
            damaged_executor._installation,
        )
        self.assertIsNot(
            rebuilt.predecessor_broker.installation_contract(),
            damaged_broker._installation,
        )
        with self.assertRaises(FrozenInstanceError):
            rebuilt.predecessor_executor = rebuilt.predecessor_executor
        state = rebuilt.classify(
            application_sha256=generation.PREDECESSOR_DOCKER_SHA256,
            executor=rebuilt.predecessor_executor,
            broker=rebuilt.predecessor_broker,
        )
        with self.assertRaises(FrozenInstanceError):
            state.phase = "complete"
        values = {
            "phase": state.phase,
            "next_operation": state.next_operation,
            "application_sha256": state.application_sha256,
            "executor_reviewed_commit": state.executor_reviewed_commit,
            "broker_reviewed_commit": state.broker_reviewed_commit,
            "expected_workflow_sha": state.expected_workflow_sha,
        }
        with self.assertRaises(ValueError):
            DevSuccessorHostMigrationState(
                **(values | {"next_operation": "complete"})
            )
        for field, bad in (
            ("application_sha256", "0" * 64),
            ("executor_reviewed_commit", "A" * 40),
            ("broker_reviewed_commit", "z" * 40),
            ("expected_workflow_sha", "0" * 40),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                DevSuccessorHostMigrationState(**(values | {field: bad}))

    def test_module_is_pure_and_contains_no_mutation_or_activation_surface(self) -> None:
        source = (
            ROOT / "deployment/successor_host_migration_authority.py"
        ).read_text()
        for forbidden in (
            "os.environ", "os.getenv", "subprocess", "socket.socket",
            "systemctl", "docker", "open(", "write(", "replace(",
            "unlink(", "rename", "__main__",
        ):
            self.assertNotIn(forbidden, source)

        blockers = (
            patch.object(builtins, "open", side_effect=AssertionError("file")),
            patch.object(os, "open", side_effect=AssertionError("host")),
            patch.object(os, "getenv", side_effect=AssertionError("environment")),
            patch.object(socket, "socket", side_effect=AssertionError("socket")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
        )
        with ExitStack() as stack:
            for blocker in blockers:
                stack.enter_context(blocker)
            authority = DevSuccessorHostMigrationAuthority(
                predecessor_executor=self.predecessor.executor,
                predecessor_broker=self.predecessor.broker,
            )
            state = authority.classify(
                application_sha256=generation.PREDECESSOR_DOCKER_SHA256,
                executor=self.predecessor.executor,
                broker=self.predecessor.broker,
            )
        self.assertEqual(state.phase, "c32w")


if __name__ == "__main__":
    unittest.main()
