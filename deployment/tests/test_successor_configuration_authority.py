"""C32ZI pure successor executor/broker configuration authority tests."""

from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
import builtins
import hashlib
import inspect
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from deployment import dev_post_c31_application_update as historical
from deployment import final_application_generation as c32w
from deployment import successor_application_generation as generation
from deployment.broker_host_service_contract import DevBrokerHostServiceContract
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.successor_configuration_authority import (
    DevSuccessorConfigurationAuthority,
    DevSuccessorConfigurationPair,
)
from deployment.tests.test_executor_service_config import configuration_values


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40


class SuccessorConfigurationAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        values = configuration_values(reviewed_commit=c32w.TARGET_REVIEWED_COMMIT)
        self.predecessor = DevExecutorServiceConfiguration(**values)
        historical_seed = replace(
            self.predecessor, reviewed_commit=historical.PREDECESSOR,
        )
        fixture_hash = hashlib.sha256(historical_seed.canonical_bytes()).hexdigest()
        self.pin = patch(
            "deployment.final_configuration_authority.c32d.PREDECESSOR_C17",
            fixture_hash,
        )
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def authority(self) -> DevSuccessorConfigurationAuthority:
        return DevSuccessorConfigurationAuthority(
            predecessor_configuration=self.predecessor,
        )

    def test_constructor_requires_exact_c32w_predecessor(self) -> None:
        self.assertEqual(
            generation.PREDECESSOR_REVIEWED_COMMIT,
            c32w.TARGET_REVIEWED_COMMIT,
        )
        self.assertEqual(
            tuple(inspect.signature(DevSuccessorConfigurationAuthority).parameters),
            ("predecessor_configuration",),
        )
        for value in (
            self.predecessor.to_dict(),
            replace(self.predecessor, reviewed_commit=generation.TARGET_REVIEWED_COMMIT),
            replace(self.predecessor, runtime_configuration_sha256="b" * 64),
            object(),
        ):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                DevSuccessorConfigurationAuthority(predecessor_configuration=value)

    def test_executor_changes_only_reviewed_commit(self) -> None:
        successor = self.authority().executor()
        before = self.predecessor.to_dict()
        after = successor.to_dict()
        self.assertEqual(
            {key for key in before if before[key] != after[key]},
            {"reviewed_commit"},
        )
        self.assertEqual(successor.reviewed_commit, generation.TARGET_REVIEWED_COMMIT)
        self.assertEqual(
            successor.runtime_configuration_sha256,
            generation.TARGET_RUNTIME_SHA256,
        )
        self.assertEqual(
            successor.ingress_file_sha256, generation.TARGET_INGRESS_SHA256,
        )
        self.assertEqual(successor.canary_image, self.predecessor.canary_image)

    def test_broker_uses_explicit_workflow_and_successor_commit(self) -> None:
        broker = self.authority().broker_configuration(
            expected_workflow_sha=WORKFLOW,
        )
        self.assertEqual(type(broker), DevBrokerServiceConfiguration)
        self.assertEqual(broker.expected_workflow_sha, WORKFLOW)
        self.assertEqual(broker.reviewed_commit, generation.TARGET_REVIEWED_COMMIT)
        self.assertEqual(
            broker.runtime_configuration_sha256,
            generation.TARGET_RUNTIME_SHA256,
        )
        self.assertEqual(
            broker.ingress_file_sha256, generation.TARGET_INGRESS_SHA256,
        )
        for value in ("0" * 40, "A" * 40, "short", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.authority().broker_configuration(
                    expected_workflow_sha=value,
                )

    def test_pair_is_exactly_aligned_and_nested_state_is_rebuilt(self) -> None:
        pair = self.authority().configuration_pair(
            expected_workflow_sha=WORKFLOW,
        )
        self.assertEqual(type(pair), DevSuccessorConfigurationPair)
        shared = (
            "broker_uid", "broker_gid", "executor_uid", "executor_gid",
            "replay_group_gid", "socket_group_gid", "reviewed_commit",
            "runtime_configuration_sha256", "ingress_file_sha256",
        )
        for name in shared:
            self.assertEqual(getattr(pair.executor, name), getattr(pair.broker, name))
        self.assertEqual(
            pair.executor.installation_contract(),
            pair.broker.installation_contract(),
        )
        host = DevBrokerHostServiceContract(configuration=pair.broker)
        self.assertEqual(
            host.canonical_configuration_bytes(), pair.broker.canonical_bytes(),
        )
        forged = replace(pair.broker)
        object.__setattr__(forged, "_installation", object())
        rebuilt = DevSuccessorConfigurationPair(
            executor=pair.executor, broker=forged,
        )
        self.assertIsNot(
            rebuilt.broker.installation_contract(), forged._installation,
        )
        with self.assertRaises(FrozenInstanceError):
            pair.broker = pair.broker
        with self.assertRaises(ValueError):
            DevSuccessorConfigurationPair(
                executor=replace(
                    pair.executor,
                    reviewed_commit=c32w.TARGET_REVIEWED_COMMIT,
                ),
                broker=pair.broker,
            )

    def test_construction_and_projection_are_pure(self) -> None:
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
            pair = self.authority().configuration_pair(
                expected_workflow_sha=WORKFLOW,
            )
            pair.broker.release_references()
            DevBrokerHostServiceContract(configuration=pair.broker)

    def test_repository_only_boundary_and_generation_binding(self) -> None:
        source = (
            ROOT / "deployment/successor_configuration_authority.py"
        ).read_text()
        for forbidden in (
            "os.environ", "os.getenv", "subprocess", "socket.socket",
            "systemctl", "docker", "__main__", "open(", "write(",
        ):
            self.assertNotIn(forbidden, source)
        pair = self.authority().configuration_pair(
            expected_workflow_sha=WORKFLOW,
        )
        runtime, ingress = pair.broker.release_references()
        self.assertEqual(
            runtime.reviewed_commit, generation.TARGET_REVIEWED_COMMIT,
        )
        self.assertEqual(runtime.sha256, generation.TARGET_RUNTIME_SHA256)
        self.assertEqual(
            ingress.reviewed_commit, generation.TARGET_REVIEWED_COMMIT,
        )
        self.assertEqual(
            tuple(item.sha256 for item in ingress.files),
            generation.TARGET_INGRESS_SHA256,
        )
        self.assertNotEqual(
            pair.executor.reviewed_commit,
            generation.PREDECESSOR_REVIEWED_COMMIT,
        )


if __name__ == "__main__":
    unittest.main()
