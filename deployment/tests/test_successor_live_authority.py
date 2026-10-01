"""deployment/tests/test_successor_live_authority.py - C33V tests.

Purpose:
- prove successor workflow authority cannot fall back to historical C32W state;
- prove rotation changes only expected_workflow_sha under the deployment lock;
- preserve C33T rootless and C33U complete-migration authority throughout;
- keep the historical C32ZC edge plan immutable while defining its successor
  continuation.

Links:
- deployment/successor_live_authority.py is the C33V implementation.
- deployment/successor_configuration_authority.py supplies successor pairs.
- deployment/dev_final_broker_resources.py supplies generic protected-file
  primitives only; its historical C32W pair builder is deliberately not used.
"""

from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from deployment import dev_post_c31_application_update as historical
from deployment import final_application_generation as c32w
from deployment import successor_application_generation as generation
from deployment import successor_live_authority as module
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.successor_configuration_authority import (
    DevSuccessorConfigurationAuthority,
)
from deployment.tests.test_executor_service_config import configuration_values
from deployment.tests.test_rootless_docker_fresh_manager_transition import lifecycle


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40
NEXT_WORKFLOW = "b" * 40


class SuccessorLiveAuthorityTests(unittest.TestCase):
    """Exercise C33V qualification, rotation, and successor edge semantics."""

    def setUp(self) -> None:
        """Create one exact C32W predecessor and deterministic successor pairs."""

        values = configuration_values(reviewed_commit=c32w.TARGET_REVIEWED_COMMIT)
        self.predecessor = DevExecutorServiceConfiguration(**values)
        historical_seed = replace(
            self.predecessor,
            reviewed_commit=historical.PREDECESSOR,
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

        authority = DevSuccessorConfigurationAuthority(
            predecessor_configuration=self.predecessor,
        )
        self.current = authority.configuration_pair(
            expected_workflow_sha=WORKFLOW,
        )
        self.next = authority.configuration_pair(
            expected_workflow_sha=NEXT_WORKFLOW,
        )
        self.rootless = lifecycle(
            unit_state=module.c33t._AFTER_UNIT_STATE,
            manager_pid=5000,
            runtime_base=6000,
        )

    def complete_migration(self, workflow: str = WORKFLOW):
        """Return one clean C33U complete-state fixture."""

        return module.c33u.SuccessorHostMigrationRuntimeState(
            "complete",
            "complete",
            None,
            None,
            None,
            workflow,
        )

    def evidence(
        self,
        workflow: str,
        pair,
        *,
        manager_pid: int = 5000,
        runtime_base: int = 6000,
    ) -> module.SuccessorBrokerWorkflowAuthorityEvidence:
        """Build one valid C33V evidence value for rotation tests."""

        runtime = tuple(
            (name, runtime_base + index)
            for index, name in enumerate(module._RUNTIME_NAMES)
        )
        return module.SuccessorBrokerWorkflowAuthorityEvidence(
            reviewed_commit=generation.TARGET_REVIEWED_COMMIT,
            expected_workflow_sha=workflow,
            broker_configuration_sha256=hashlib.sha256(
                pair.broker.canonical_bytes(),
            ).hexdigest(),
            rootless_user_manager_pid=manager_pid,
            rootless_runtime_pids=runtime,
        )

    def test_successor_edge_plan_changes_only_two_historical_tail_checks(self) -> None:
        """Preserve 36 historical edge checks and replace only C32W-specific tail."""

        historical_checks = (
            module.historical_edge.DevBrokerEdgeContract()
            .qualification_plan()
            .checks
        )
        plan = module.SuccessorDevBrokerEdgeQualificationPlan()

        self.assertEqual(len(plan.checks), 38)
        self.assertEqual(plan.checks[:36], historical_checks[:36])
        self.assertEqual(
            plan.checks[36:],
            (
                "successor-application-authority-exact-and-migration-complete",
                "successor-static-resource-authority-otherwise-unchanged",
            ),
        )
        self.assertEqual(
            historical_checks[36:],
            (
                "frozen-c32w-application-authority-unchanged",
                "c32y-static-resource-authority-otherwise-unchanged",
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            plan.status = "complete"

    def test_successor_pair_reconstructs_installed_successor_executor(self) -> None:
        """Derive successor pairs only from an exact installed successor executor."""

        with patch.object(
            module,
            "read_root_dev_executor_configuration",
            return_value=self.current.executor,
        ):
            pair = module._successor_pair(WORKFLOW)
        self.assertEqual(
            pair.executor.canonical_bytes(),
            self.current.executor.canonical_bytes(),
        )
        self.assertEqual(
            pair.broker.canonical_bytes(),
            self.current.broker.canonical_bytes(),
        )

        with patch.object(
            module,
            "read_root_dev_executor_configuration",
            return_value=self.predecessor,
        ), self.assertRaises(OSError):
            module._successor_pair(WORKFLOW)

    def test_resource_qualification_uses_generic_resources_not_c32w_pair(self) -> None:
        """Qualify shared broker resources without invoking historical C32W _pair."""

        class Sigstore:
            def __post_init__(self):
                return None

        with patch.object(
            module.historical_resources,
            "_pair",
            side_effect=AssertionError("historical C32W pair used"),
        ), patch.object(
            module.historical_resources,
            "_authorities",
            return_value=(),
        ), patch.object(
            module.historical_resources,
            "_directory_exists",
            return_value=True,
        ) as directory, patch.object(
            module.historical_resources,
            "_file_state",
            return_value=True,
        ) as config, patch.object(
            module.historical_resources,
            "_installed_unit",
            return_value=True,
        ) as unit, patch.object(
            module.historical_resources,
            "_replay",
        ) as replay, patch.object(
            module.historical_resources.sigstore_installer,
            "_qualify_installed",
            return_value=Sigstore(),
        ) as sigstore:
            host = module._resource_qualification(self.current)

        self.assertEqual(host.configuration.to_dict(), self.current.broker.to_dict())
        self.assertEqual(directory.call_count, 6)
        config.assert_called_once()
        unit.assert_called_once()
        replay.assert_called_once()
        sigstore.assert_called_once_with(self.current.broker)

    def test_read_only_qualification_binds_complete_migration_and_rootless(self) -> None:
        """Require exact successor resources and stable C33T runtime evidence."""

        with patch.object(
            module.c33t,
            "qualify_rootless_docker_fresh_manager_post",
            side_effect=(self.rootless, self.rootless),
        ), patch.object(
            module.c33u,
            "qualify_successor_host_migration_runtime",
            return_value=self.complete_migration(),
        ), patch.object(
            module,
            "_successor_pair",
            return_value=self.current,
        ), patch.object(
            module,
            "read_root_dev_broker_configuration",
            return_value=self.current.broker,
        ), patch.object(
            module,
            "_resource_qualification",
        ) as resources:
            evidence = module._qualify(WORKFLOW)

        self.assertEqual(evidence.reviewed_commit, generation.TARGET_REVIEWED_COMMIT)
        self.assertEqual(evidence.expected_workflow_sha, WORKFLOW)
        self.assertEqual(evidence.rootless_user_manager_pid, 5000)
        self.assertEqual(evidence.rootless_runtime_pids, self.rootless.runtime_pids)
        resources.assert_called_once_with(self.current)

    def test_read_only_qualification_rejects_prefix_or_rootless_drift(self) -> None:
        """Fail closed for incomplete migration state or C33T runtime turnover."""

        incomplete = module.c33u.SuccessorHostMigrationRuntimeState(
            "application",
            "replace-executor-configuration",
            None,
            None,
            None,
            WORKFLOW,
        )
        with patch.object(
            module.c33t,
            "qualify_rootless_docker_fresh_manager_post",
            return_value=self.rootless,
        ), patch.object(
            module.c33u,
            "qualify_successor_host_migration_runtime",
            return_value=incomplete,
        ), self.assertRaises(OSError):
            module._qualify(WORKFLOW)

        zero_stage = type(
            "MalformedCompleteMigration",
            (),
            {
                "phase": "complete",
                "next_operation": "complete",
                "application_stage_length": 0,
                "executor_stage_length": None,
                "broker_stage_length": None,
                "expected_workflow_sha": WORKFLOW,
            },
        )()
        with patch.object(
            module.c33t,
            "qualify_rootless_docker_fresh_manager_post",
            return_value=self.rootless,
        ), patch.object(
            module.c33u,
            "qualify_successor_host_migration_runtime",
            return_value=zero_stage,
        ), self.assertRaises(OSError):
            module._qualify(WORKFLOW)

        changed = lifecycle(
            unit_state=module.c33t._AFTER_UNIT_STATE,
            manager_pid=7000,
            runtime_base=8000,
        )
        with patch.object(
            module.c33t,
            "qualify_rootless_docker_fresh_manager_post",
            side_effect=(self.rootless, changed),
        ), patch.object(
            module.c33u,
            "qualify_successor_host_migration_runtime",
            return_value=self.complete_migration(),
        ), patch.object(
            module,
            "_successor_pair",
            return_value=self.current,
        ), patch.object(
            module,
            "read_root_dev_broker_configuration",
            return_value=self.current.broker,
        ), patch.object(
            module,
            "_resource_qualification",
        ), self.assertRaises(OSError):
            module._qualify(WORKFLOW)

    def test_rotation_changes_only_workflow_authority_and_publishes_once(self) -> None:
        """Use one atomic broker-config replacement and preserve C33T identity."""

        before = self.evidence(WORKFLOW, self.current)
        after = self.evidence(NEXT_WORKFLOW, self.next)
        with patch.object(
            module,
            "_qualify",
            side_effect=(before, after),
        ), patch.object(
            module,
            "_successor_pair",
            side_effect=(self.current, self.next),
        ), patch.object(
            module.historical_resources,
            "_authorities",
            return_value=(),
        ), patch.object(
            module.historical_resources,
            "_temporary_absent",
        ) as temporary, patch.object(
            module.historical_resources,
            "_replace_workflow_configuration",
        ) as publish:
            result = module._rotate_under_lock(WORKFLOW, NEXT_WORKFLOW)

        self.assertEqual(result.old_workflow_sha, WORKFLOW)
        self.assertEqual(result.new_workflow_sha, NEXT_WORKFLOW)
        self.assertEqual(result.operation, "rotated")
        self.assertEqual(
            {
                key
                for key in self.current.broker.to_dict()
                if self.current.broker.to_dict()[key]
                != self.next.broker.to_dict()[key]
            },
            {"expected_workflow_sha"},
        )
        temporary.assert_called_once()
        publish.assert_called_once()

    def test_post_publication_drift_never_retries_or_rolls_back(self) -> None:
        """Reject post-state drift after one publication without a second mutation."""

        before = self.evidence(WORKFLOW, self.current)
        changed = self.evidence(
            NEXT_WORKFLOW,
            self.next,
            manager_pid=7000,
            runtime_base=8000,
        )
        with patch.object(
            module,
            "_qualify",
            side_effect=(before, changed),
        ), patch.object(
            module,
            "_successor_pair",
            side_effect=(self.current, self.next),
        ), patch.object(
            module.historical_resources,
            "_authorities",
            return_value=(),
        ), patch.object(
            module.historical_resources,
            "_temporary_absent",
        ), patch.object(
            module.historical_resources,
            "_replace_workflow_configuration",
        ) as publish, self.assertRaises(OSError):
            module._rotate_under_lock(WORKFLOW, NEXT_WORKFLOW)

        publish.assert_called_once()

    def test_public_rotation_is_root_locked_and_generic_on_failure(self) -> None:
        """Require root and the existing process lock around the one-shot rotation."""

        expected = module.SuccessorBrokerWorkflowRotationEvidence(
            reviewed_commit=generation.TARGET_REVIEWED_COMMIT,
            old_workflow_sha=WORKFLOW,
            new_workflow_sha=NEXT_WORKFLOW,
            old_broker_configuration_sha256="a" * 64,
            new_broker_configuration_sha256="b" * 64,
            rootless_user_manager_pid=5000,
            rootless_runtime_pids=(
                ("rootlesskit", 6000),
                ("dockerd", 6001),
                ("containerd", 6002),
                ("slirp4netns", 6003),
            ),
            operation="rotated",
        )
        lock = module.orchestration._ProcessLock(((7, None, None, ()),), 7)
        with patch.object(
            module.historical_resources,
            "_root",
            return_value=(0, 0, 0, 0),
        ), patch.object(
            module.orchestration,
            "_acquire_process_lock",
            return_value=lock,
        ) as acquire, patch.object(
            module,
            "_rotate_under_lock",
            return_value=expected,
        ) as rotate, patch.object(
            module.orchestration,
            "_release_process_lock",
        ) as release:
            result = module.rotate_successor_broker_workflow_authority(
                current_expected_workflow_sha=WORKFLOW,
                new_expected_workflow_sha=NEXT_WORKFLOW,
            )

        self.assertEqual(result, expected)
        acquire.assert_called_once_with()
        rotate.assert_called_once_with(WORKFLOW, NEXT_WORKFLOW)
        release.assert_called_once_with(lock)

        with patch.object(
            module.historical_resources,
            "_root",
            side_effect=OSError("private"),
        ):
            with self.assertRaises(
                module.SuccessorBrokerWorkflowAuthorityError,
            ) as caught:
                module.rotate_successor_broker_workflow_authority(
                    current_expected_workflow_sha=WORKFLOW,
                    new_expected_workflow_sha=NEXT_WORKFLOW,
                )
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private", str(caught.exception))

    def test_public_qualifier_is_read_only_and_generic_on_failure(self) -> None:
        """Expose only fixed qualification failures and reject malformed SHAs."""

        expected = self.evidence(WORKFLOW, self.current)
        with patch.object(module, "_qualify", return_value=expected) as qualify:
            self.assertEqual(
                module.qualify_successor_broker_workflow_authority(
                    expected_workflow_sha=WORKFLOW,
                ),
                expected,
            )
        qualify.assert_called_once_with(WORKFLOW)

        for value in ("0" * 40, "A" * 40, "short", True):
            with self.subTest(value=value), self.assertRaises(
                module.SuccessorBrokerWorkflowAuthorityError
            ):
                module.qualify_successor_broker_workflow_authority(
                    expected_workflow_sha=value,
                )

    def test_source_has_one_broker_publication_and_no_service_mutation(self) -> None:
        """Keep C33V limited to broker-config authority, never service activation."""

        source = (
            ROOT / "deployment/successor_live_authority.py"
        ).read_text(encoding="utf-8")
        self.assertEqual(source.count("_replace_workflow_configuration("), 1)
        for forbidden in (
            "systemctl start",
            "systemctl restart",
            "systemctl enable",
            "systemctl reload",
            "docker run",
            "docker pull",
            "docker compose",
            "deployment_enabled = True",
            "subprocess.run(",
            "os.replace(",
            "os.unlink(",
            "shell=True",
            "__main__",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
