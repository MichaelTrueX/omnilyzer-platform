"""C32ZL read-only successor host-migration qualification tests."""

from dataclasses import replace
import hashlib
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
)
import deployment.successor_host_migration_qualification as module
from deployment.tests.test_executor_service_config import configuration_values


WORKFLOW = "a" * 40


class SuccessorHostMigrationQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        predecessor = DevExecutorServiceConfiguration(
            **configuration_values(reviewed_commit=c32w.TARGET_REVIEWED_COMMIT)
        )
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
        self.migration = DevSuccessorHostMigrationAuthority(
            predecessor_executor=pair.executor,
            predecessor_broker=pair.broker,
        )
        self.successor = self.migration.successor_pair()
        self.services = (
            ("omnilyzer-deployment-broker.service", "inactive", "static"),
            ("omnilyzer-deployment-executor.service", "inactive", "static"),
            ("omnilyzer-deployment-executor.socket", "inactive", "disabled"),
        )

    def qualify(self, digest, executor, broker):
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(module, "_systemd_snapshot", return_value=self.services), \
                patch.object(
                    module, "read_root_dev_executor_configuration",
                    return_value=executor,
                ), patch.object(
                    module, "read_root_dev_broker_configuration",
                    return_value=broker,
                ), patch.object(module, "_application_digest", return_value=digest):
            return module.qualify_successor_host_migration()

    def test_all_clean_prefixes_qualify(self) -> None:
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
                evidence = self.qualify(digest, executor, broker)
                self.assertEqual(
                    (evidence.phase, evidence.next_operation), expected,
                )
                self.assertEqual(evidence.expected_workflow_sha, WORKFLOW)

    def test_out_of_order_states_fail_closed(self) -> None:
        for digest, executor, broker in (
            (
                generation.PREDECESSOR_DOCKER_SHA256,
                self.successor.executor,
                self.predecessor.broker,
            ),
            (
                generation.TARGET_DOCKER_SHA256,
                self.predecessor.executor,
                self.successor.broker,
            ),
        ):
            with self.subTest(digest=digest), self.assertRaises(
                module.SuccessorHostMigrationQualificationError,
            ):
                self.qualify(digest, executor, broker)

    def test_installed_workflow_authority_is_preserved_not_caller_supplied(self) -> None:
        rotated_broker = replace(self.predecessor.broker, expected_workflow_sha="b" * 40)
        rotated_authority = DevSuccessorHostMigrationAuthority(
            predecessor_executor=self.predecessor.executor,
            predecessor_broker=rotated_broker,
        )
        rotated_successor = rotated_authority.successor_pair()
        evidence = self.qualify(
            generation.TARGET_DOCKER_SHA256,
            rotated_successor.executor,
            rotated_successor.broker,
        )
        self.assertEqual(evidence.phase, "complete")
        self.assertEqual(evidence.expected_workflow_sha, "b" * 40)

    def test_identity_service_or_second_snapshot_change_fails_closed(self) -> None:
        with patch.object(
            module, "_root_identity", return_value=(1, 0, 0, 0),
        ), self.assertRaises(module.SuccessorHostMigrationQualificationError):
            module.qualify_successor_host_migration()

        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(module, "_systemd_snapshot", side_effect=OSError), \
                self.assertRaises(module.SuccessorHostMigrationQualificationError):
            module.qualify_successor_host_migration()

        first = self.migration.classify(
            application_sha256=generation.PREDECESSOR_DOCKER_SHA256,
            executor=self.predecessor.executor,
            broker=self.predecessor.broker,
        )
        second = self.migration.classify(
            application_sha256=generation.TARGET_DOCKER_SHA256,
            executor=self.predecessor.executor,
            broker=self.predecessor.broker,
        )
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(module, "_systemd_snapshot", return_value=self.services), \
                patch.object(
                    module, "_snapshot",
                    side_effect=[
                        (first, self.predecessor.executor, self.predecessor.broker),
                        (second, self.predecessor.executor, self.predecessor.broker),
                    ],
                ), self.assertRaises(module.SuccessorHostMigrationQualificationError):
            module.qualify_successor_host_migration()

    def test_systemctl_boundary_is_closed_and_exact(self) -> None:
        complete = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=b"inactive\n", stderr=b"",
        )
        with patch.object(module.subprocess, "run", return_value=complete) as run:
            self.assertEqual(
                module._systemctl_property(
                    "omnilyzer-deployment-broker.service", "ActiveState",
                ),
                "inactive",
            )
        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertEqual(
            args[0],
            (
                "/usr/bin/systemctl", "show", "--property=ActiveState",
                "--value", "omnilyzer-deployment-broker.service",
            ),
        )
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["timeout"], 5.0)
        self.assertEqual(
            kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        for stdout, returncode in (
            (b"active\nextra\n", 0),
            (b"", 0),
            (b"inactive\n", 1),
        ):
            with patch.object(
                module.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(
                    args=(), returncode=returncode, stdout=stdout, stderr=b"",
                ),
            ), self.assertRaises(OSError):
                module._systemctl_property(
                    "omnilyzer-deployment-broker.service", "ActiveState",
                )

    def test_module_has_no_mutation_or_activation_surface(self) -> None:
        source = (
            __import__("pathlib").Path(module.__file__).read_text()
        )
        for forbidden in (
            "os.mkdir", "os.chown", "os.chmod", "os.unlink", "os.replace",
            "os.write", "systemctl start", "systemctl stop", "systemctl enable",
            "docker", "socket.socket", "__main__",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
