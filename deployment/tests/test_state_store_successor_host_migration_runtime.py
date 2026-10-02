"""Tests for the one-step C33AE root host-migration runtime."""

import ast
import inspect
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from deployment import state_store_successor_application_generation as generation
from deployment import state_store_successor_host_migration_runtime as module
from deployment import successor_application_generation as predecessor_generation


WORKFLOW = "d" * 40


def runtime_state(phase: str) -> module.StateStoreSuccessorHostMigrationRuntimeState:
    """Build one unstaged runtime state for a named migration phase."""

    operations = {
        "predecessor": "replace-state-store",
        "application": "replace-executor-configuration",
        "executor": "replace-broker-configuration",
        "complete": "complete",
    }
    return module.StateStoreSuccessorHostMigrationRuntimeState(
        phase=phase,
        next_operation=operations[phase],
        application_stage_length=None,
        executor_stage_length=None,
        broker_stage_length=None,
        target_workflow_sha=WORKFLOW,
    )


def inspection(phase: str):
    """Build the minimum immutable inspection surface used by step dispatch."""

    return SimpleNamespace(
        state=runtime_state(phase),
        executor=object(),
        broker=object(),
    )


class RuntimeStateTests(unittest.TestCase):
    """Validate staged-prefix shape and exact service lifecycle preconditions."""

    def test_stage_is_allowed_only_for_current_next_operation(self) -> None:
        """Reject stages that belong to a later or earlier migration phase."""

        valid = (
            ("predecessor", 1, None, None),
            ("application", None, 1, None),
            ("executor", None, None, 1),
            ("complete", None, None, None),
        )
        for phase, app, executor, broker in valid:
            with self.subTest(phase=phase):
                state = runtime_state(phase)
                state = module.StateStoreSuccessorHostMigrationRuntimeState(
                    state.phase,
                    state.next_operation,
                    app,
                    executor,
                    broker,
                    WORKFLOW,
                )
                self.assertEqual(state.phase, phase)

        with self.assertRaises(ValueError):
            module.StateStoreSuccessorHostMigrationRuntimeState(
                "application",
                "replace-executor-configuration",
                1,
                None,
                None,
                WORKFLOW,
            )
        for invalid_workflow in ("0" * 40, "A" * 40, "short", True):
            with self.subTest(workflow=invalid_workflow), self.assertRaises(ValueError):
                module.StateStoreSuccessorHostMigrationRuntimeState(
                    "complete",
                    "complete",
                    None,
                    None,
                    None,
                    invalid_workflow,
                )

    def test_service_gate_requires_broker_and_socket_fully_closed(self) -> None:
        """Require a fully closed control-plane without adding service mutation."""

        self.assertEqual(
            module._EXPECTED_UNIT_STATES[
                "omnilyzer-deployment-executor.socket"
            ],
            ("loaded", "inactive", "dead", "disabled", "no"),
        )
        self.assertEqual(
            module._EXPECTED_UNIT_STATES[
                "omnilyzer-deployment-executor.service"
            ],
            ("loaded", "inactive", "dead", "static", "no"),
        )
        self.assertEqual(
            module._EXPECTED_UNIT_STATES[
                "omnilyzer-deployment-broker.service"
            ],
            ("loaded", "inactive", "dead", "static", "no"),
        )


class ReadOnlyQualificationTests(unittest.TestCase):
    """Prove stable double-snapshot qualification before any mutation."""

    def _inspection(self, phase: str):
        """Build one observation with canonical-byte config surfaces."""

        executor = Mock()
        executor.canonical_bytes.return_value = b"executor"
        broker = Mock()
        broker.canonical_bytes.return_value = b"broker"
        return SimpleNamespace(
            state=runtime_state(phase),
            executor=executor,
            broker=broker,
        )

    def test_stable_double_snapshot_passes_and_drift_fails_closed(self) -> None:
        """Repeat all closed authorities and reject a changed second snapshot."""

        current = self._inspection("predecessor")
        persistent = (
            ("deployment_state", "verified-initial"),
            ("replay_database", "verified"),
            ("audit_history", "pristine"),
        )
        services = (("unit", ("closed",)),)
        rootless = (647147, 647159, (("dockerd", 647292),))

        with (
            patch.object(module, "_root_identity", return_value=(0, 0)),
            patch.object(module, "_service_snapshot", return_value=services),
            patch.object(
                module,
                "_rootless_runtime_signature",
                return_value=rootless,
            ),
            patch.object(
                module,
                "_inspect",
                return_value=current,
            ) as inspect_call,
            patch.object(
                module,
                "_persistent_state",
                return_value=persistent,
            ) as persistent_call,
        ):
            result = (
                module.qualify_state_store_successor_host_migration_runtime(
                    target_workflow_sha=WORKFLOW
                )
            )
        self.assertEqual(result, current.state)
        self.assertEqual(inspect_call.call_count, 2)
        self.assertEqual(persistent_call.call_count, 2)

        changed = self._inspection("application")
        with (
            patch.object(module, "_root_identity", return_value=(0, 0)),
            patch.object(module, "_service_snapshot", return_value=services),
            patch.object(
                module,
                "_rootless_runtime_signature",
                return_value=rootless,
            ),
            patch.object(
                module,
                "_inspect",
                side_effect=(current, changed),
            ),
            patch.object(
                module,
                "_persistent_state",
                return_value=persistent,
            ),
            self.assertRaises(
                module.StateStoreSuccessorHostMigrationRuntimeError
            ),
        ):
            module.qualify_state_store_successor_host_migration_runtime(
                target_workflow_sha=WORKFLOW
            )


class OneStepMutationTests(unittest.TestCase):
    """Prove one explicit call can advance no more than one migration prefix."""

    def _run_phase(self, before_phase: str, after_phase: str, expected: str) -> None:
        before = inspection(before_phase)
        after = inspection(after_phase)
        advances = {
            "application": Mock(),
            "executor": Mock(),
            "broker": Mock(),
        }
        with (
            patch.object(module, "_root_identity", return_value=(0, 0)),
            patch.object(module, "_service_snapshot", return_value=(("x", ("y",)),)),
            patch.object(module, "_rootless_runtime_signature", return_value=(1, 2, ())),
            patch.object(module, "_persistent_state", return_value=(
                ("deployment_state", "verified-initial"),
                ("replay_database", "verified"),
                ("audit_history", "pristine"),
            )),
            patch.object(module, "_inspect", side_effect=(before, after)) as inspect_call,
            patch.object(module, "_advance_application", advances["application"]),
            patch.object(module, "_advance_executor", advances["executor"]),
            patch.object(module, "_advance_broker", advances["broker"]),
        ):
            result = module._migrate_under_lock(
                target_workflow_sha=WORKFLOW
            )

        self.assertEqual(result.phase, after_phase)
        self.assertEqual(inspect_call.call_count, 2)
        for name, call in advances.items():
            self.assertEqual(call.call_count, 1 if name == expected else 0)

    def test_each_mutating_phase_dispatches_exactly_one_advance(self) -> None:
        """Advance predecessor, application and executor in separate calls only."""

        for before, after, expected in (
            ("predecessor", "application", "application"),
            ("application", "executor", "executor"),
            ("executor", "complete", "broker"),
        ):
            with self.subTest(before=before):
                self._run_phase(before, after, expected)

    def test_complete_phase_is_noop(self) -> None:
        """A completed host does not repeat any filesystem/config mutation."""

        current = inspection("complete")
        with (
            patch.object(module, "_root_identity", return_value=(0, 0)),
            patch.object(module, "_service_snapshot", return_value=(("x", ("y",)),)),
            patch.object(module, "_rootless_runtime_signature", return_value=(1, 2, ())),
            patch.object(module, "_persistent_state", return_value=(
                ("deployment_state", "verified-initial"),
                ("replay_database", "verified"),
                ("audit_history", "pristine"),
            )),
            patch.object(module, "_inspect", side_effect=(current, current)),
            patch.object(module, "_advance_application") as app,
            patch.object(module, "_advance_executor") as executor,
            patch.object(module, "_advance_broker") as broker,
        ):
            result = module._migrate_under_lock(
                target_workflow_sha=WORKFLOW
            )
        self.assertEqual(result.phase, "complete")
        app.assert_not_called()
        executor.assert_not_called()
        broker.assert_not_called()

    def test_rootless_drift_after_one_step_stops_before_later_prefixes(self) -> None:
        """A changed rootless signature blocks all later migration prefixes."""

        before = inspection("predecessor")
        after = inspection("application")
        stable = (647147, 647159, (("dockerd", 647292),))
        changed = (647147, 647159, (("dockerd", 999999),))
        persistent = (
            ("deployment_state", "verified-initial"),
            ("replay_database", "verified"),
            ("audit_history", "pristine"),
        )
        with (
            patch.object(module, "_root_identity", return_value=(0, 0)),
            patch.object(
                module,
                "_service_snapshot",
                return_value=(("closed", ("exact",)),),
            ),
            patch.object(
                module,
                "_rootless_runtime_signature",
                side_effect=(stable, changed),
            ),
            patch.object(module, "_persistent_state", return_value=persistent),
            patch.object(module, "_inspect", return_value=before),
            patch.object(module, "_advance_application") as application,
            patch.object(module, "_advance_executor") as executor,
            patch.object(module, "_advance_broker") as broker,
            self.assertRaises(OSError),
        ):
            module._migrate_under_lock(target_workflow_sha=WORKFLOW)

        application.assert_called_once_with(before)
        executor.assert_not_called()
        broker.assert_not_called()

    def test_persistent_drift_after_one_step_stops_before_later_prefixes(self) -> None:
        """A changed persistent authority blocks all later migration prefixes."""

        before = inspection("predecessor")
        after = inspection("application")
        persistent = (
            ("deployment_state", "verified-initial"),
            ("replay_database", "verified"),
            ("audit_history", "pristine"),
        )
        with (
            patch.object(module, "_root_identity", return_value=(0, 0)),
            patch.object(
                module,
                "_service_snapshot",
                return_value=(("closed", ("exact",)),),
            ),
            patch.object(
                module,
                "_rootless_runtime_signature",
                return_value=(647147, 647159, (("dockerd", 647292),)),
            ),
            patch.object(
                module,
                "_persistent_state",
                side_effect=(persistent, OSError()),
            ),
            patch.object(module, "_inspect", side_effect=(before, after)),
            patch.object(module, "_advance_application") as application,
            patch.object(module, "_advance_executor") as executor,
            patch.object(module, "_advance_broker") as broker,
            self.assertRaises(OSError),
        ):
            module._migrate_under_lock(target_workflow_sha=WORKFLOW)

        application.assert_called_once_with(before)
        executor.assert_not_called()
        broker.assert_not_called()

    def test_public_mutation_requires_root_process_lock_and_release(self) -> None:
        """Use the shared process lock and release it on success or failure."""

        token = object()
        expected = runtime_state("application")

        with (
            patch.object(module, "_root_identity", side_effect=OSError),
            patch.object(module.orchestration, "_acquire_process_lock") as acquire,
            self.assertRaises(module.StateStoreSuccessorHostMigrationRuntimeError),
        ):
            module.migrate_state_store_successor_host_step(
                target_workflow_sha=WORKFLOW
            )
        acquire.assert_not_called()

        with (
            patch.object(module, "_root_identity", return_value=(0, 0)),
            patch.object(
                module.orchestration,
                "_acquire_process_lock",
                return_value=token,
            ) as acquire,
            patch.object(
                module,
                "_migrate_under_lock",
                return_value=expected,
            ) as migrate,
            patch.object(
                module.orchestration,
                "_release_process_lock",
            ) as release,
        ):
            result = module.migrate_state_store_successor_host_step(
                target_workflow_sha=WORKFLOW
            )
        self.assertEqual(result, expected)
        acquire.assert_called_once_with()
        migrate.assert_called_once_with(target_workflow_sha=WORKFLOW)
        release.assert_called_once_with(token)

        with (
            patch.object(module, "_root_identity", return_value=(0, 0)),
            patch.object(
                module.orchestration,
                "_acquire_process_lock",
                return_value=token,
            ),
            patch.object(module, "_migrate_under_lock", return_value=expected),
            patch.object(
                module.orchestration,
                "_release_process_lock",
                side_effect=OSError,
            ),
            self.assertRaises(module.StateStoreSuccessorHostMigrationRuntimeError),
        ):
            module.migrate_state_store_successor_host_step(
                target_workflow_sha=WORKFLOW
            )

    def test_public_mutation_function_has_no_loop_or_service_command(self) -> None:
        """Prevent a future refactor from reintroducing multi-step auto-advance."""

        for function in (
            module._migrate_under_lock,
            module.migrate_state_store_successor_host_step,
        ):
            source = inspect.getsource(function)
            tree = ast.parse(source)
            self.assertFalse(
                any(
                    isinstance(node, (ast.For, ast.While))
                    for node in ast.walk(tree)
                )
            )
        module_source = inspect.getsource(module)
        for token in (
            "systemctl start",
            "systemctl stop",
            "systemctl restart",
            "docker pull",
            "docker run",
            "tailscale serve",
            "tailscale funnel",
        ):
            self.assertNotIn(token, module_source)



class PrimitiveMutationTests(unittest.TestCase):
    """Exercise exact staged replacements without touching live host paths."""

    def test_configuration_helper_accepts_only_fixed_paths_and_stages(self) -> None:
        """Reject arbitrary configuration destinations and crossed stage names."""

        self.assertEqual(
            module._configuration_limit(
                module._EXECUTOR_CONFIG,
                module._EXECUTOR_STAGE,
            ),
            module.executor_config.MAX_EXECUTOR_SERVICE_CONFIG_BYTES,
        )
        self.assertEqual(
            module._configuration_limit(
                module._BROKER_CONFIG,
                module._BROKER_STAGE,
            ),
            module.broker_config.MAX_BROKER_SERVICE_CONFIG_BYTES,
        )
        for path, stage in (
            ("/tmp/executor.json", module._EXECUTOR_STAGE),
            (module._EXECUTOR_CONFIG, module._BROKER_STAGE),
            (module._BROKER_CONFIG, module._EXECUTOR_STAGE),
            (module._BROKER_CONFIG, ".unexpected"),
        ):
            with self.subTest(path=path, stage=stage), self.assertRaises(OSError):
                module._configuration_limit(path, stage)

    def test_atomic_configuration_replace_resumes_exact_prefix(self) -> None:
        """Publish one canonical config atomically from empty or partial stage."""

        with tempfile.TemporaryDirectory(
            prefix="task014-c33ae-config-"
        ) as temporary:
            parent = Path(temporary) / "config"
            parent.mkdir(mode=0o750)
            parent.chmod(0o750)
            destination = parent / "executor.json"
            expected = b'{"generation":"old"}\n'
            target = b'{"generation":"new","authority":"state-store"}\n'
            destination.write_bytes(expected)
            destination.chmod(0o640)
            uid, gid = os.getuid(), os.getgid()

            with (
                patch.object(module, "_CONFIG_UID", uid),
                patch.object(
                    module,
                    "_EXECUTOR_CONFIG",
                    str(destination),
                ),
                patch.object(module, "_EXECUTOR_STAGE", ".stage"),
            ):
                module._write_configuration(
                    str(destination),
                    ".stage",
                    expected,
                    target,
                    gid,
                    None,
                )
            self.assertEqual(destination.read_bytes(), target)
            self.assertEqual(
                stat.S_IMODE(destination.stat().st_mode),
                0o640,
            )
            self.assertFalse((parent / ".stage").exists())

            destination.write_bytes(expected)
            destination.chmod(0o640)
            stage_path = parent / ".stage"
            stage_path.write_bytes(target[:13])
            stage_path.chmod(0o600)
            directory = os.open(
                parent,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            try:
                stage = module.stage_tools._stage(
                    directory,
                    ".stage",
                    target,
                    0o640,
                    uid,
                    gid,
                    0,
                )
            finally:
                os.close(directory)

            with (
                patch.object(module, "_CONFIG_UID", uid),
                patch.object(
                    module,
                    "_EXECUTOR_CONFIG",
                    str(destination),
                ),
                patch.object(module, "_EXECUTOR_STAGE", ".stage"),
            ):
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

    def test_application_stage_replaces_only_state_store_and_reaches_target(self) -> None:
        """Resume one partial stage and prove the full target manifest afterwards."""

        with tempfile.TemporaryDirectory(
            prefix="task014-c33ae-app-"
        ) as temporary:
            app = Path(temporary) / "app"
            app.mkdir(mode=0o755)
            app.chmod(0o755)
            predecessor, blobs = predecessor_generation._reviewed_target()
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
            before_other = {
                relative: payload
                for relative, payload in blobs
                if relative != "deployment/state_store.py"
            }
            with (
                patch.object(module, "_APP_ROOT", str(app)),
                patch.object(module, "_APP_UID", uid),
                patch.object(module, "_APP_GID", gid),
            ):
                commit, stage = module._application_state()
                self.assertEqual(
                    commit,
                    generation.PREDECESSOR_REVIEWED_COMMIT,
                )
                self.assertIsNone(stage)

                _old, _target, payload = module._application_evidence()
                stage_path = app / "deployment" / module._APP_STAGE
                stage_path.write_bytes(payload[:19])
                stage_path.chmod(0o600)

                commit, stage = module._application_state()
                self.assertEqual(
                    commit,
                    generation.PREDECESSOR_REVIEWED_COMMIT,
                )
                self.assertIsNotNone(stage)

                holder = SimpleNamespace(
                    state=runtime_state("predecessor"),
                    application_stage=stage,
                )
                module._advance_application(holder)

                commit, stage = module._application_state()
                self.assertEqual(
                    commit,
                    generation.TARGET_REVIEWED_COMMIT,
                )
                self.assertIsNone(stage)
                self.assertFalse(stage_path.exists())

            for relative, payload in before_other.items():
                self.assertEqual(
                    (app / relative).read_bytes(),
                    payload,
                    relative,
                )
            self.assertEqual(
                (app / "deployment/state_store.py").read_bytes(),
                dict(generation._reviewed_target()[1])[
                    "deployment/state_store.py"
                ],
            )

if __name__ == "__main__":
    unittest.main()
