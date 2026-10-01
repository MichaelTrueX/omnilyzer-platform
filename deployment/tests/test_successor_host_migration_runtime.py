"""deployment/tests/test_successor_host_migration_runtime.py - C32ZM tests."""

from contextlib import ExitStack
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
import tempfile
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
from deployment.successor_host_migration_qualification import (
    SuccessorHostMigrationQualificationEvidence,
)
import deployment.successor_host_migration_runtime as module
from deployment.tests.test_executor_service_config import configuration_values


WORKFLOW = "a" * 40


class SuccessorHostMigrationRuntimeTests(unittest.TestCase):
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
        self.authority = DevSuccessorHostMigrationAuthority(
            predecessor_executor=pair.executor,
            predecessor_broker=pair.broker,
        )
        self.successor = self.authority.successor_pair()
        self.services = (
            ("omnilyzer-deployment-broker.service", "inactive", "static"),
            ("omnilyzer-deployment-executor.service", "inactive", "static"),
            ("omnilyzer-deployment-executor.socket", "inactive", "disabled"),
        )

    def inspection(self, phase: str):
        operations = {
            "c32w": "replace-application",
            "application": "replace-executor-configuration",
            "executor": "replace-broker-configuration",
            "complete": "complete",
        }
        executor = (
            self.predecessor.executor
            if phase in ("c32w", "application")
            else self.successor.executor
        )
        broker = (
            self.predecessor.broker
            if phase != "complete"
            else self.successor.broker
        )
        return module._Inspection(
            module.SuccessorHostMigrationRuntimeState(
                phase,
                operations[phase],
                None,
                None,
                None,
                WORKFLOW,
            ),
            executor,
            broker,
            self.authority,
            None,
            None,
            None,
        )
    def test_runtime_state_accepts_only_stage_for_next_operation(self) -> None:
        valid = (
            ("c32w", "replace-application", 1, None, None),
            ("application", "replace-executor-configuration", None, 1, None),
            ("executor", "replace-broker-configuration", None, None, 1),
            ("complete", "complete", None, None, None),
        )
        for phase, operation, app, executor, broker in valid:
            module.SuccessorHostMigrationRuntimeState(
                phase, operation, app, executor, broker, WORKFLOW,
            )
        for args in (
            ("c32w", "complete", None, None, None, WORKFLOW),
            ("c32w", "replace-application", None, 1, None, WORKFLOW),
            ("application", "replace-executor-configuration", 1, None, None, WORKFLOW),
            ("complete", "complete", None, None, 1, WORKFLOW),
            ("unknown", "complete", None, None, None, WORKFLOW),
            ("complete", "complete", None, None, None, "0" * 40),
            ("complete", "complete", None, None, None, "A" * 40),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                module.SuccessorHostMigrationRuntimeState(*args)

    def test_read_only_runtime_qualification_repeats_exact_snapshot(self) -> None:
        inspection = self.inspection("application")
        rootless = object()
        signature = (("rootless", "stable"),)
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(module, "_systemd_snapshot", return_value=self.services), \
                patch.object(module, "_rootless_runtime_evidence", return_value=rootless), \
                patch.object(
                    module, "_rootless_runtime_signature", return_value=signature,
                ), patch.object(
                    module, "_require_rootless_runtime_unchanged",
                ) as rootless_unchanged, patch.object(
                    module, "_inspect", return_value=inspection,
                ) as inspect:
            state = module.qualify_successor_host_migration_runtime()
        self.assertEqual(state.phase, "application")
        self.assertEqual(inspect.call_count, 2)
        self.assertEqual(rootless_unchanged.call_count, 2)
        rootless_unchanged.assert_called_with(signature)

        changed = self.inspection("executor")
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(module, "_systemd_snapshot", return_value=self.services), \
                patch.object(module, "_rootless_runtime_evidence", return_value=rootless), \
                patch.object(
                    module, "_rootless_runtime_signature", return_value=signature,
                ), patch.object(
                    module, "_require_rootless_runtime_unchanged",
                ), patch.object(
                    module, "_inspect", side_effect=(inspection, changed),
                ), self.assertRaises(module.SuccessorHostMigrationRuntimeError):
            module.qualify_successor_host_migration_runtime()

    def test_migrate_under_lock_dispatches_exact_order_and_is_idempotent(self) -> None:
        inspections = tuple(
            self.inspection(phase)
            for phase in ("c32w", "application", "executor", "complete")
        )
        evidence = SuccessorHostMigrationQualificationEvidence(
            "complete",
            "complete",
            generation.TARGET_DOCKER_SHA256,
            generation.TARGET_REVIEWED_COMMIT,
            generation.TARGET_REVIEWED_COMMIT,
            WORKFLOW,
        )
        rootless = object()
        signature = (("rootless", "stable"),)
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(module, "_systemd_snapshot", return_value=self.services), \
                patch.object(module, "_rootless_runtime_evidence", return_value=rootless), \
                patch.object(
                    module, "_rootless_runtime_signature", return_value=signature,
                ), patch.object(
                    module, "_require_rootless_runtime_unchanged",
                ) as rootless_unchanged, patch.object(
                    module, "_inspect", side_effect=inspections,
                ), patch.object(
                    module, "_advance_application",
                ) as app, patch.object(
                    module, "_advance_executor",
                ) as executor, patch.object(
                    module, "_advance_broker",
                ) as broker, patch.object(
                    module, "qualify_successor_host_migration",
                    return_value=evidence,
                ):
            result = module._migrate_under_lock()
        self.assertEqual(result, evidence)
        app.assert_called_once_with(inspections[0])
        executor.assert_called_once_with(inspections[1])
        broker.assert_called_once_with(inspections[2])
        self.assertEqual(rootless_unchanged.call_count, 8)
        rootless_unchanged.assert_called_with(signature)

        complete = self.inspection("complete")
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(module, "_systemd_snapshot", return_value=self.services), \
                patch.object(module, "_rootless_runtime_evidence", return_value=rootless), \
                patch.object(
                    module, "_rootless_runtime_signature", return_value=signature,
                ), patch.object(
                    module, "_require_rootless_runtime_unchanged",
                ) as rootless_unchanged, patch.object(
                    module, "_inspect", return_value=complete,
                ), patch.object(
                    module, "_advance_application",
                ) as app, patch.object(
                    module, "_advance_executor",
                ) as executor, patch.object(
                    module, "_advance_broker",
                ) as broker, patch.object(
                    module, "qualify_successor_host_migration",
                    return_value=evidence,
                ):
            self.assertEqual(module._migrate_under_lock(), evidence)
        app.assert_not_called()
        executor.assert_not_called()
        broker.assert_not_called()
        self.assertEqual(rootless_unchanged.call_count, 2)

    def test_rootless_gate_requires_fresh_manager_state_and_stable_signature(self) -> None:
        """Bind C32ZM to the exact qualified C33T post-state."""

        evidence = type(
            "RootlessEvidence",
            (),
            {"user_unit_state": module.c33t._AFTER_UNIT_STATE},
        )()
        signature = (
            ("user_manager_pid", 647147),
            ("runtime_pids", (1, 2, 3, 4)),
        )
        with patch.object(
            module.c33t,
            "qualify_rootless_docker_fresh_manager_post",
            return_value=evidence,
        ), patch.object(
            module.c33t,
            "_observation_signature",
            return_value=signature,
        ):
            self.assertIs(module._rootless_runtime_evidence(), evidence)
            self.assertEqual(module._rootless_runtime_signature(evidence), signature)
            module._require_rootless_runtime_unchanged(signature)

        bad = type(
            "RootlessEvidence",
            (),
            {"user_unit_state": module.c33t._BEFORE_UNIT_STATE},
        )()
        with patch.object(
            module.c33t,
            "qualify_rootless_docker_fresh_manager_post",
            return_value=bad,
        ), self.assertRaises(OSError):
            module._rootless_runtime_evidence()

        with patch.object(
            module,
            "_rootless_runtime_evidence",
            return_value=evidence,
        ), patch.object(
            module,
            "_rootless_runtime_signature",
            return_value=(("user_manager_pid", 999999),),
        ), self.assertRaises(OSError):
            module._require_rootless_runtime_unchanged(signature)

    def test_rootless_drift_stops_resumable_migration_after_current_step(self) -> None:
        """Never advance another migration phase after C33T runtime drift."""

        first = self.inspection("c32w")
        signature = (("rootless", "stable"),)
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(module, "_systemd_snapshot", return_value=self.services), \
                patch.object(module, "_rootless_runtime_evidence", return_value=object()), \
                patch.object(
                    module, "_rootless_runtime_signature", return_value=signature,
                ), patch.object(
                    module,
                    "_require_rootless_runtime_unchanged",
                    side_effect=(None, OSError()),
                ), patch.object(
                    module, "_inspect", return_value=first,
                ), patch.object(
                    module, "_advance_application",
                ) as app, patch.object(
                    module, "_advance_executor",
                ) as executor, patch.object(
                    module, "_advance_broker",
                ) as broker, self.assertRaises(OSError):
            module._migrate_under_lock()

        app.assert_called_once_with(first)
        executor.assert_not_called()
        broker.assert_not_called()

    def test_public_operation_requires_root_lock_and_release(self) -> None:
        evidence = SuccessorHostMigrationQualificationEvidence(
            "complete",
            "complete",
            generation.TARGET_DOCKER_SHA256,
            generation.TARGET_REVIEWED_COMMIT,
            generation.TARGET_REVIEWED_COMMIT,
            WORKFLOW,
        )
        with patch.object(module, "_root_identity", side_effect=OSError), \
                patch.object(module.orchestration, "_acquire_process_lock") as acquire, \
                self.assertRaises(module.SuccessorHostMigrationRuntimeError):
            module.migrate_successor_host()
        acquire.assert_not_called()

        token = object()
        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(
                    module.orchestration, "_acquire_process_lock",
                    return_value=token,
                ) as acquire, patch.object(
                    module, "_migrate_under_lock", return_value=evidence,
                ), patch.object(
                    module.orchestration, "_release_process_lock",
                ) as release:
            self.assertEqual(module.migrate_successor_host(), evidence)
        acquire.assert_called_once_with()
        release.assert_called_once_with(token)

        with patch.object(module, "_root_identity", return_value=(0, 0, 0, 0)), \
                patch.object(
                    module.orchestration, "_acquire_process_lock",
                    return_value=token,
                ), patch.object(
                    module, "_migrate_under_lock", return_value=evidence,
                ), patch.object(
                    module.orchestration, "_release_process_lock",
                    side_effect=OSError,
                ), self.assertRaises(module.SuccessorHostMigrationRuntimeError):
            module.migrate_successor_host()
    def test_configuration_helper_accepts_only_fixed_paths_and_stages(self) -> None:
        self.assertEqual(
            module._configuration_limit(
                module._EXECUTOR_CONFIG, module._EXECUTOR_STAGE,
            ),
            module.executor_config.MAX_EXECUTOR_SERVICE_CONFIG_BYTES,
        )
        self.assertEqual(
            module._configuration_limit(
                module._BROKER_CONFIG, module._BROKER_STAGE,
            ),
            module.broker_config.MAX_BROKER_SERVICE_CONFIG_BYTES,
        )
        for path, stage in (
            ("/tmp/executor.json", module._EXECUTOR_STAGE),
            (module._EXECUTOR_CONFIG, module._BROKER_STAGE),
            (module._BROKER_CONFIG, ".unexpected"),
        ):
            with self.subTest(path=path, stage=stage), self.assertRaises(OSError):
                module._configuration_limit(path, stage)

    def test_atomic_configuration_replace_resumes_exact_prefix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="task014-c32zm-config-") as temporary:
            root = Path(temporary)
            parent = root / "config"
            parent.mkdir(mode=0o750)
            parent.chmod(0o750)
            destination = parent / "executor.json"
            expected = b'{"generation":"old"}\n'
            target = b'{"generation":"new","authority":"rootless"}\n'
            destination.write_bytes(expected)
            destination.chmod(0o640)
            uid, gid = os.getuid(), os.getgid()
            with patch.object(module, "_CONFIG_UID", uid), \
                    patch.object(module, "_EXECUTOR_CONFIG", str(destination)), \
                    patch.object(module, "_EXECUTOR_STAGE", ".stage"):
                module._write_configuration(
                    str(destination),
                    ".stage",
                    expected,
                    target,
                    gid,
                    None,
                )
            self.assertEqual(destination.read_bytes(), target)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o640)
            self.assertFalse((parent / ".stage").exists())

            destination.write_bytes(expected)
            destination.chmod(0o640)
            stage_path = parent / ".stage"
            stage_path.write_bytes(target[:11])
            stage_path.chmod(0o600)
            directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                stage = module.stage_tools._stage(
                    directory, ".stage", target, 0o640, uid, gid, 0,
                )
            finally:
                os.close(directory)
            with patch.object(module, "_CONFIG_UID", uid), \
                    patch.object(module, "_EXECUTOR_CONFIG", str(destination)), \
                    patch.object(module, "_EXECUTOR_STAGE", ".stage"):
                module._write_configuration(
                    str(destination),
                    ".stage",
                    expected,
                    target,
                    gid,
                    stage,
                )
            self.assertEqual(destination.read_bytes(), target)
            self.assertFalse(stage_path.exists())

    def test_application_stage_is_prefix_resumable_and_switches_only_adapter(self) -> None:
        with tempfile.TemporaryDirectory(prefix="task014-c32zm-app-") as temporary:
            app = Path(temporary) / "app"
            app.mkdir(mode=0o755)
            app.chmod(0o755)
            _manifest, blobs = c32w._reviewed_target()
            for relative, payload in blobs:
                destination = app / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.parent.chmod(0o755)
                destination.write_bytes(payload)
                destination.chmod(0o644)
            for directory in app.rglob("*"):
                if directory.is_dir():
                    directory.chmod(0o755)
            uid, gid = os.getuid(), os.getgid()
            app_status = app.stat()
            self.assertEqual(
                (stat.S_IMODE(app_status.st_mode), app_status.st_uid, app_status.st_gid),
                (0o755, uid, gid),
            )
            with patch.object(module, "_APP_ROOT", str(app)), \
                    patch.object(module, "_APP_UID", uid), \
                    patch.object(module, "_APP_GID", gid):
                digest, stage = module._application_state()
                self.assertEqual(digest, generation.PREDECESSOR_DOCKER_SHA256)
                self.assertIsNone(stage)
                _old, _target, payload = module._application_evidence()
                stage_path = app / "deployment" / module._APP_STAGE
                stage_path.write_bytes(payload[:17])
                stage_path.chmod(0o600)
                digest, stage = module._application_state()
                self.assertEqual(digest, generation.PREDECESSOR_DOCKER_SHA256)
                inspection = module._Inspection(
                    module.SuccessorHostMigrationRuntimeState(
                        "c32w", "replace-application", 17, None, None, WORKFLOW,
                    ),
                    self.predecessor.executor,
                    self.predecessor.broker,
                    self.authority,
                    stage,
                    None,
                    None,
                )
                module._advance_application(inspection)
                digest, stage = module._application_state()
                self.assertEqual(digest, generation.TARGET_DOCKER_SHA256)
                self.assertIsNone(stage)
                self.assertFalse(stage_path.exists())

    def test_module_has_no_install_activation_network_or_cli_surface(self) -> None:
        source = Path(module.__file__).read_text()
        for forbidden in (
            "apt ", "pip install", "docker pull", "docker compose",
            "systemctl start", "systemctl enable", "systemctl unmask",
            "socket.socket", "requests.", "urllib", "__main__",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
