"""deployment/tests/test_state_store_successor_live_authority.py - C33AQ tests.

Purpose:
- prove post-C33AE workflow rotation accepts only the exact target generation;
- prove projection changes only expected_workflow_sha;
- prove qualification requires the C33AE complete prefix and stable rootless
  runtime authority;
- prove rotation publishes one broker configuration under the deployment lock;
- prove the module is repository-only and has no service/Docker authority.

Links:
- deployment/state_store_successor_live_authority.py implements C33AQ.
- deployment/state_store_successor_configuration_authority.py supplies the
  exact f2ece425... target configuration pair.
- deployment/state_store_successor_host_migration_runtime.py supplies the
  read-only C33AE complete-state qualifier.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from deployment import dev_post_c31_application_update as historical
from deployment import executor_service_config as executor_config
from deployment import state_store_successor_configuration_authority as config
from deployment import state_store_successor_live_authority as module
from deployment.application_source_set import DevApplicationSourceSet
from deployment.tests.test_executor_service_config import configuration_values


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40
NEXT_WORKFLOW = "b" * 40


class StateStoreSuccessorLiveAuthorityTests(unittest.TestCase):
    """Exercise C33AQ exact qualification and workflow-only rotation."""

    def setUp(self) -> None:
        """Build exact C33AE target pairs from the canonical predecessor fixture."""

        values = configuration_values(
            reviewed_commit=config.PREDECESSOR_REVIEWED_COMMIT,
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

        before = config._predecessor(seed)
        authority = config.DevStateStoreSuccessorConfigurationAuthority(
            predecessor_configuration=before,
        )
        self.current = authority.configuration_pair(
            expected_workflow_sha=WORKFLOW,
        )
        self.next = authority.configuration_pair(
            expected_workflow_sha=NEXT_WORKFLOW,
        )
        self.runtime = (
            5000,
            6000,
            (
                ("rootlesskit", 6000),
                ("dockerd", 6001),
                ("containerd", 6002),
                ("slirp4netns", 6003),
            ),
        )

    def complete_state(self, workflow: str = WORKFLOW):
        """Return one clean C33AE complete-state fixture."""

        return module.migration.StateStoreSuccessorHostMigrationRuntimeState(
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
        runtime=None,
    ) -> module.StateStoreSuccessorWorkflowAuthorityEvidence:
        """Build one valid digest-only authority evidence value."""

        runtime = runtime or self.runtime
        return module.StateStoreSuccessorWorkflowAuthorityEvidence(
            reviewed_commit=config.TARGET_REVIEWED_COMMIT,
            expected_workflow_sha=workflow,
            broker_configuration_sha256=hashlib.sha256(
                pair.broker.canonical_bytes()
            ).hexdigest(),
            rootless_user_manager_pid=runtime[0],
            rootless_user_unit_main_pid=runtime[1],
            rootless_runtime_pids=runtime[2],
        )

    def test_installed_pair_accepts_only_exact_target_and_workflow(self) -> None:
        """Reconstruct the exact target pair and reject workflow/config drift."""

        with patch.object(
            module,
            "read_root_dev_executor_configuration",
            return_value=self.current.executor,
        ), patch.object(
            module,
            "read_root_dev_broker_configuration",
            return_value=self.current.broker,
        ):
            pair = module._installed_pair(WORKFLOW)

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
            return_value=self.current.executor,
        ), patch.object(
            module,
            "read_root_dev_broker_configuration",
            return_value=self.current.broker,
        ), self.assertRaises(OSError):
            module._installed_pair(NEXT_WORKFLOW)

        forged_executor = replace(
            self.current.executor,
            reviewed_commit="c" * 40,
        )
        with patch.object(
            module,
            "read_root_dev_executor_configuration",
            return_value=forged_executor,
        ), patch.object(
            module,
            "read_root_dev_broker_configuration",
            return_value=self.current.broker,
        ), self.assertRaises(OSError):
            module._installed_pair(WORKFLOW)

    def test_projection_changes_only_expected_workflow_sha(self) -> None:
        """Project one new workflow SHA without changing executor or other broker fields."""

        projected = module._project_pair(self.current, NEXT_WORKFLOW)
        self.assertEqual(
            projected.executor.canonical_bytes(),
            self.current.executor.canonical_bytes(),
        )
        before = self.current.broker.to_dict()
        after = projected.broker.to_dict()
        self.assertEqual(
            {key for key in before if before[key] != after[key]},
            {"expected_workflow_sha"},
        )
        self.assertEqual(
            projected.broker.canonical_bytes(),
            self.next.broker.canonical_bytes(),
        )
        with self.assertRaises(OSError):
            module._project_pair(self.current, WORKFLOW)

    def test_static_resource_qualification_uses_generic_reviewed_primitives(self) -> None:
        """Qualify target broker resources without invoking historical pair builders."""

        class Sigstore:
            def __post_init__(self):
                return None

        with patch.object(
            module.resources,
            "_authorities",
            return_value=(),
        ), patch.object(
            module.resources,
            "_directory_exists",
            return_value=True,
        ) as directory, patch.object(
            module.resources,
            "_file_state",
            return_value=True,
        ) as file_state, patch.object(
            module.resources,
            "_installed_unit",
            return_value=True,
        ) as unit, patch.object(
            module.resources,
            "_replay",
        ) as replay, patch.object(
            module.resources.sigstore_installer,
            "_qualify_installed",
            return_value=Sigstore(),
        ) as sigstore:
            host = module._resource_qualification(self.current)

        self.assertEqual(
            host.configuration.canonical_bytes(),
            self.current.broker.canonical_bytes(),
        )
        self.assertGreaterEqual(directory.call_count, 1)
        file_state.assert_called_once()
        unit.assert_called_once()
        replay.assert_called_once()
        sigstore.assert_called_once_with(self.current.broker)

    def test_read_only_qualification_requires_complete_prefix_and_stable_runtime(self) -> None:
        """Bind exact current pair/resources to one stable C33AE complete prefix."""

        with patch.object(
            module,
            "_runtime_signature",
            side_effect=(self.runtime, self.runtime),
        ), patch.object(
            module.migration,
            "qualify_state_store_successor_host_migration_runtime",
            return_value=self.complete_state(),
        ) as migration, patch.object(
            module,
            "_installed_pair",
            return_value=self.current,
        ), patch.object(
            module,
            "_resource_qualification",
        ) as resources:
            evidence = module._qualify(WORKFLOW)

        self.assertEqual(
            evidence,
            self.evidence(WORKFLOW, self.current),
        )
        migration.assert_called_once_with(target_workflow_sha=WORKFLOW)
        resources.assert_called_once_with(self.current)

        drifted = (
            self.runtime[0],
            self.runtime[1],
            (
                ("rootlesskit", 6000),
                ("dockerd", 6011),
                ("containerd", 6002),
                ("slirp4netns", 6003),
            ),
        )
        with patch.object(
            module,
            "_runtime_signature",
            side_effect=(self.runtime, drifted),
        ), patch.object(
            module.migration,
            "qualify_state_store_successor_host_migration_runtime",
            return_value=self.complete_state(),
        ), patch.object(
            module,
            "_installed_pair",
            return_value=self.current,
        ), patch.object(
            module,
            "_resource_qualification",
        ), self.assertRaises(OSError):
            module._qualify(WORKFLOW)

        with patch.object(
            module,
            "_runtime_signature",
            return_value=self.runtime,
        ), patch.object(
            module.migration,
            "qualify_state_store_successor_host_migration_runtime",
            return_value=module.migration.StateStoreSuccessorHostMigrationRuntimeState(
                "executor",
                "replace-broker-configuration",
                None,
                None,
                None,
                WORKFLOW,
            ),
        ), self.assertRaises(OSError):
            module._qualify(WORKFLOW)

    def test_rotation_changes_only_workflow_configuration_once(self) -> None:
        """Use the existing atomic primitive once and requalify the new authority."""

        before = self.evidence(WORKFLOW, self.current)
        after = self.evidence(NEXT_WORKFLOW, self.next)
        with patch.object(
            module,
            "_qualify",
            side_effect=(before, after),
        ), patch.object(
            module,
            "_installed_pair",
            return_value=self.current,
        ), patch.object(
            module,
            "_project_pair",
            return_value=self.next,
        ), patch.object(
            module.resources,
            "_authorities",
            return_value=(),
        ) as authorities, patch.object(
            module.resources,
            "_temporary_absent",
        ) as temporary, patch.object(
            module.resources,
            "_replace_workflow_configuration",
        ) as publish:
            result = module._rotate_under_lock(
                WORKFLOW,
                NEXT_WORKFLOW,
            )

        self.assertEqual(result.old_workflow_sha, WORKFLOW)
        self.assertEqual(result.new_workflow_sha, NEXT_WORKFLOW)
        self.assertEqual(result.operation, "rotated")
        self.assertNotEqual(
            result.old_broker_configuration_sha256,
            result.new_broker_configuration_sha256,
        )
        authorities.assert_called_once()
        temporary.assert_called_once()
        publish.assert_called_once()

    def test_public_rotation_is_root_locked_one_shot_and_generic_on_failure(self) -> None:
        """Acquire/release the shared lock exactly once and hide internal failures."""

        expected = module.StateStoreSuccessorWorkflowRotationEvidence(
            reviewed_commit=config.TARGET_REVIEWED_COMMIT,
            old_workflow_sha=WORKFLOW,
            new_workflow_sha=NEXT_WORKFLOW,
            old_broker_configuration_sha256="a" * 64,
            new_broker_configuration_sha256="b" * 64,
            rootless_user_manager_pid=self.runtime[0],
            rootless_user_unit_main_pid=self.runtime[1],
            rootless_runtime_pids=self.runtime[2],
            operation="rotated",
        )
        lock = module.orchestration._ProcessLock(
            ((7, None, None, ()),),
            7,
        )
        with patch.object(
            module.resources,
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
            result = module.rotate_state_store_successor_workflow_authority(
                current_expected_workflow_sha=WORKFLOW,
                new_expected_workflow_sha=NEXT_WORKFLOW,
            )

        self.assertEqual(result, expected)
        acquire.assert_called_once_with()
        rotate.assert_called_once_with(WORKFLOW, NEXT_WORKFLOW)
        release.assert_called_once_with(lock)

        with patch.object(
            module.resources,
            "_root",
            side_effect=OSError("private detail"),
        ):
            with self.assertRaises(
                module.StateStoreSuccessorWorkflowAuthorityError,
            ) as caught:
                module.rotate_state_store_successor_workflow_authority(
                    current_expected_workflow_sha=WORKFLOW,
                    new_expected_workflow_sha=NEXT_WORKFLOW,
                )
        self.assertEqual(str(caught.exception), module._ERROR)
        self.assertNotIn("private detail", str(caught.exception))

    def test_evidence_is_closed_and_binds_rootless_process_relationships(self) -> None:
        """Reject forged target identity, workflow, digest, and PID relationships."""

        evidence = self.evidence(WORKFLOW, self.current)
        with self.assertRaises(FrozenInstanceError):
            evidence.expected_workflow_sha = NEXT_WORKFLOW

        for field, value in (
            ("reviewed_commit", "c" * 40),
            ("expected_workflow_sha", "0" * 40),
            ("broker_configuration_sha256", "z" * 64),
            ("rootless_user_unit_main_pid", 7000),
            ("rootless_user_manager_pid", 6001),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(evidence, **{field: value})

    def test_repository_only_source_has_one_publication_and_no_service_mutation(self) -> None:
        """Keep C33AQ out of installed application and free of service/Docker authority."""

        selected = {
            item.repository_path
            for item in DevApplicationSourceSet().files
        }
        self.assertNotIn(
            "deployment/state_store_successor_live_authority.py",
            selected,
        )

        source = (
            ROOT / "deployment/state_store_successor_live_authority.py"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            source.count("_replace_workflow_configuration("),
            1,
        )
        for forbidden in (
            "systemctl start",
            "systemctl stop",
            "systemctl restart",
            "systemctl enable",
            "systemctl reload",
            "docker run",
            "docker pull",
            "docker compose",
            "subprocess.run(",
            "workflow_dispatch",
            "migrate_state_store_successor_host_step(",
            "__main__",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
