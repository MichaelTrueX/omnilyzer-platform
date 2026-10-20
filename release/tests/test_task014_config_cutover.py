"""File: release/tests/test_task014_config_cutover.py

Purpose: Independent offline acceptance of pinned broker/executor config
migration and reversible replacements. Disposable temp roots ONLY; never
access production /etc, systemd, Docker, GitHub workflows, Zot or replay.
Links: release/task014_config_cutover.py,
release/task014_source_cutover.py,
deployment/broker_service_config.py,
deployment/executor_service_config.py.

Sections: synthetic canonical config models, strict pinned transformation,
filesystem staging, two-file failure recovery, and adversarial integrity.
"""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_broker_service_config import (
    configuration_values as broker_values,
)
from deployment.tests.test_executor_service_config import (
    configuration_values as executor_values,
)
from release import task014_config_cutover as module
from release import task014_source_cutover as source_cutover

ROOT = Path(__file__).resolve().parents[2]
HEAD = subprocess.check_output(
    ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
    timeout=5, stderr=subprocess.DEVNULL,
).decode("ascii").strip()


class ConfigCutoverTests(unittest.TestCase):
    """Test real canonical serializers and real os.replace in temporary roots."""

    @classmethod
    def setUpClass(cls) -> None:
        """Construct a reviewed source plan and two mutually consistent models."""
        cls.source = source_cutover.reviewed_plan(ROOT, HEAD)
        broker = broker_values()
        executor = executor_values(**{
            field: broker[field] for field in (
                "broker_uid", "broker_gid", "executor_uid", "executor_gid",
                "replay_group_gid", "socket_group_gid",
                "reviewed_commit", "runtime_configuration_sha256",
                "ingress_file_sha256",
            )
        })
        cls.old_broker = DevBrokerServiceConfiguration(**broker).canonical_bytes()
        cls.old_executor = DevExecutorServiceConfiguration(**executor).canonical_bytes()
        cls.old_broker_sha = hashlib.sha256(cls.old_broker).hexdigest()
        cls.old_executor_sha = hashlib.sha256(cls.old_executor).hexdigest()
        cls.workflow_sha = "e" * 40
        cls.plan = module.reviewed_config_plan(
            broker_previous=cls.old_broker,
            executor_previous=cls.old_executor,
            approved_broker_sha256=cls.old_broker_sha,
            approved_executor_sha256=cls.old_executor_sha,
            source_plan=cls.source,
            reviewed_workflow_sha=cls.workflow_sha,
        )

    def setUp(self) -> None:
        """Place synthetic old configs into a disposable protected test root."""
        temp = tempfile.TemporaryDirectory(prefix="task014-config-offline-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        broker = root / "broker"
        executor = root / "dev"
        broker.mkdir(mode=0o750)
        executor.mkdir(mode=0o750)
        broker.chmod(0o750)
        executor.chmod(0o750)
        self.broker = broker / "dev.json"
        self.executor = executor / "executor.json"
        self.broker.write_bytes(self.old_broker)
        self.executor.write_bytes(self.old_executor)
        self.broker.chmod(0o640)
        self.executor.chmod(0o640)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(module, "BROKER_FILE", self.broker))
        stack.enter_context(patch.object(module, "EXECUTOR_FILE", self.executor))
        stack.enter_context(patch.object(source_cutover, "_require_root"))
        stack.enter_context(patch.object(source_cutover, "_require_quiesced"))
        stack.enter_context(patch.object(
            module, "_is_root_owned",
            side_effect=lambda state, gid: (
                state.st_uid == os.getuid() and state.st_gid == os.getgid()
            ),
        ))
        stack.enter_context(patch.object(module.os, "fchown"))

    def test_exact_authority_only_two_broker_fields_one_executor(self) -> None:
        """Existing identities, image, Cosign and ingresses must not change."""
        import json
        prior_b = json.loads(self.old_broker)
        next_b = json.loads(self.plan.broker_target)
        prior_e = json.loads(self.old_executor)
        next_e = json.loads(self.plan.executor_target)
        changed_b = {key for key in prior_b if prior_b[key] != next_b[key]}
        changed_e = {key for key in prior_e if prior_e[key] != next_e[key]}
        self.assertEqual(changed_b, {"reviewed_commit", "expected_workflow_sha"})
        self.assertEqual(changed_e, {"reviewed_commit"})
        self.assertEqual(next_b["reviewed_commit"], HEAD)
        self.assertEqual(next_e["reviewed_commit"], HEAD)
        self.assertEqual(next_b["expected_workflow_sha"], self.workflow_sha)
        self.assertEqual(len(self.plan.identity()), 4)

    def test_old_sha_pins_cannot_be_guessed_or_omitted(self) -> None:
        """A current config must match independently approved old hashes."""
        for changed in (
            {"approved_broker_sha256": "f" * 64},
            {"approved_executor_sha256": "0" * 64},
            {"approved_broker_sha256": "wrong"},
            {"reviewed_workflow_sha": "refs/heads/main"},
        ):
            arguments = {
                "broker_previous": self.old_broker,
                "executor_previous": self.old_executor,
                "approved_broker_sha256": self.old_broker_sha,
                "approved_executor_sha256": self.old_executor_sha,
                "source_plan": self.source,
                "reviewed_workflow_sha": self.workflow_sha,
            }
            arguments.update(changed)
            with self.subTest(changed=changed):
                with self.assertRaises(module.ConfigurationCutoverHold):
                    module.reviewed_config_plan(**arguments)

    def test_broker_executor_identity_disagreement_rejected(self) -> None:
        """Changing cross-service identities cannot be hidden in migration."""
        incompatible = executor_values(reviewed_commit="d" * 40)
        incompatible_old = DevExecutorServiceConfiguration(
            **incompatible
        ).canonical_bytes()
        with self.assertRaises(module.ConfigurationCutoverHold):
            module.reviewed_config_plan(
                broker_previous=self.old_broker,
                executor_previous=incompatible_old,
                approved_broker_sha256=self.old_broker_sha,
                approved_executor_sha256=hashlib.sha256(incompatible_old).hexdigest(),
                source_plan=self.source,
                reviewed_workflow_sha=self.workflow_sha,
            )

    def test_readonly_preflight_does_not_write(self) -> None:
        """Old exact root/group/mode/canonical bytes are sufficient for HOLD."""
        module.readonly_config_preflight(self.plan)
        self.assertEqual({p.name for p in self.broker.parent.iterdir()}, {"dev.json"})
        self.assertEqual({p.name for p in self.executor.parent.iterdir()},
                         {"executor.json"})

    def test_stage_activate_and_rollback_full_pair(self) -> None:
        """Preserve 0600 backups while replacing 0640 configs and restoring."""
        prepared = module.stage_configurations(self.plan)
        module.activate_configurations(self.plan, prepared)
        self.assertEqual(self.broker.read_bytes(), self.plan.broker_target)
        self.assertEqual(self.executor.read_bytes(), self.plan.executor_target)
        self.assertEqual(self.broker.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.executor.stat().st_mode & 0o777, 0o640)
        self.assertEqual(prepared.broker_backup.read_bytes(), self.old_broker)
        self.assertEqual(prepared.executor_backup.read_bytes(), self.old_executor)
        self.assertEqual(prepared.broker_backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(prepared.executor_backup.stat().st_mode & 0o777, 0o600)
        module.rollback_configurations(self.plan, prepared)
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.executor.read_bytes(), self.old_executor)
        self.assertTrue(prepared.broker_backup.exists())
        self.assertTrue(prepared.executor_backup.exists())

    def test_changes_to_old_source_block_staging(self) -> None:
        """Preflight refuses a drifted config without staging any new file."""
        self.broker.write_bytes(self.old_broker + b" ")
        with self.assertRaises(module.ConfigurationCutoverHold):
            module.stage_configurations(self.plan)
        self.assertEqual({p.name for p in self.broker.parent.iterdir()}, {"dev.json"})

    def test_symlink_or_wrong_mode_denied(self) -> None:
        """Root-only validation checks file objects, not pathname text alone."""
        self.executor.chmod(0o666)
        with self.assertRaises(module.ConfigurationCutoverHold):
            module.readonly_config_preflight(self.plan)
        self.executor.chmod(0o640)
        self.executor.unlink()
        self.executor.symlink_to(self.broker)
        with self.assertRaises(module.ConfigurationCutoverHold):
            module.readonly_config_preflight(self.plan)

    def test_quiescence_required_even_after_staging(self) -> None:
        """Never replace live config while broker or executor socket remains on."""
        staged = module.stage_configurations(self.plan)
        with patch.object(source_cutover, "_require_quiesced",
                          side_effect=source_cutover.CutoverHold):
            with self.assertRaises(source_cutover.CutoverHold):
                module.activate_configurations(self.plan, staged)
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.executor.read_bytes(), self.old_executor)

    def test_second_config_replace_failure_restores_both(self) -> None:
        """Failure after broker is updated must undo it before any service start."""
        staged = module.stage_configurations(self.plan)
        original = module._replace

        def fail_executor_stage(src: Path, dest: Path) -> None:
            """Inject an error only while publishing the executor candidate."""
            if src == staged.executor_candidate and dest == self.executor:
                raise OSError("synthetic executor replace failure")
            original(src, dest)

        with patch.object(module, "_replace", side_effect=fail_executor_stage):
            with self.assertRaises(module.ConfigurationCutoverHold):
                module.activate_configurations(self.plan, staged)
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.executor.read_bytes(), self.old_executor)
        self.assertTrue(staged.broker_backup.exists())
        self.assertTrue(staged.executor_backup.exists())

    def test_tampered_backup_denies_activation(self) -> None:
        """Do not start a two-file replacement without both checked backups."""
        staged = module.stage_configurations(self.plan)
        staged.broker_backup.write_bytes(b"unknown backup")
        with self.assertRaises(module.ConfigurationCutoverHold):
            module.activate_configurations(self.plan, staged)
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.executor.read_bytes(), self.old_executor)

    def test_wrong_staged_path_rejected(self) -> None:
        """No caller-selected rollback stage outside closed config directories."""
        staged = module.stage_configurations(self.plan)
        with self.assertRaises(module.ConfigurationCutoverHold):
            module._checked_stage(Path("/tmp/task014-config-evil"),
                                  self.broker.parent)
        self.assertEqual(staged.broker_candidate.parent, self.broker.parent)

    def test_directory_durability_failure_restores_both(self) -> None:
        """An fsync error after replacement must not leave a mixed pair."""
        staged = module.stage_configurations(self.plan)
        original = module.os.fsync
        calls = [0]

        def once(fd: int) -> None:
            """Inject failure only in first activation directory fsync."""
            calls[0] += 1
            if calls[0] == 1:
                raise OSError("synthetic directory durability failure")
            original(fd)

        with patch.object(module.os, "fsync", side_effect=once):
            with self.assertRaisesRegex(module.ConfigurationCutoverHold, "rolled back"):
                module.activate_configurations(self.plan, staged)
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.executor.read_bytes(), self.old_executor)
        self.assertTrue(staged.broker_backup.exists())
        self.assertTrue(staged.executor_backup.exists())

    def _source_fixture(self) -> tuple[Path, Path]:
        """Add the real 41-file prior generation to disposable test storage."""
        app_parent = self.broker.parent.parent / "deployment"
        app_parent.mkdir(mode=0o755)
        app_parent.chmod(0o755)
        app = app_parent / "app"
        app.mkdir(mode=0o755)
        app.chmod(0o755)
        for path, _hash in self.source.prior_entries:
            raw = source_cutover._git_blob(
                ROOT, source_cutover.PRIOR_SOURCE_SHA, path,
            )
            output = app / path
            output.parent.mkdir(parents=True, exist_ok=True)
            cursor = output.parent
            while cursor != app:
                cursor.chmod(0o755)
                cursor = cursor.parent
            output.write_bytes(raw)
            output.chmod(0o644)
        return app_parent, app

    def test_offline_source_config_pair_full_commit_and_rollback(self) -> None:
        """The two maintenance libraries compose without touching live DEV."""
        app_parent, app = self._source_fixture()
        with (
            patch.object(source_cutover, "APP_PARENT", app_parent),
            patch.object(
                source_cutover, "_required_ownership",
                return_value=(os.getuid(), os.getgid()),
            ),
        ):
            stage_source = source_cutover.prepare_staging(self.source, ROOT)
            stage_configs = module.stage_configurations(self.plan)
            source_cutover.activate_staging(self.source, stage_source)
            module.activate_configurations(self.plan, stage_configs)
            self.assertEqual(source_cutover._observed_tree(app),
                             self.source.target_entries)
            self.assertEqual(self.broker.read_bytes(), self.plan.broker_target)
            self.assertEqual(self.executor.read_bytes(), self.plan.executor_target)
            module.rollback_configurations(self.plan, stage_configs)
            source_cutover.rollback_staging(self.source, stage_source)
            self.assertEqual(source_cutover._observed_tree(app),
                             self.source.prior_entries)
            self.assertEqual(self.broker.read_bytes(), self.old_broker)
            self.assertEqual(self.executor.read_bytes(), self.old_executor)

    def test_config_failure_then_source_rollback_restores_complete_pair(self) -> None:
        """A failed second config update leaves full previous source recoverable."""
        app_parent, app = self._source_fixture()
        with (
            patch.object(source_cutover, "APP_PARENT", app_parent),
            patch.object(
                source_cutover, "_required_ownership",
                return_value=(os.getuid(), os.getgid()),
            ),
        ):
            stage_source = source_cutover.prepare_staging(self.source, ROOT)
            stage_configs = module.stage_configurations(self.plan)
            source_cutover.activate_staging(self.source, stage_source)
            original = module._replace

            def fail_one(src: Path, dest: Path) -> None:
                """Deny executor publication while allowing recovery copies."""
                if src == stage_configs.executor_candidate:
                    raise OSError("synthetic final configuration failure")
                original(src, dest)

            with patch.object(module, "_replace", side_effect=fail_one):
                with self.assertRaisesRegex(module.ConfigurationCutoverHold,
                                            "rolled back"):
                    module.activate_configurations(self.plan, stage_configs)
            source_cutover.rollback_staging(self.source, stage_source)
            self.assertEqual(source_cutover._observed_tree(app),
                             self.source.prior_entries)
            self.assertEqual(self.broker.read_bytes(), self.old_broker)
            self.assertEqual(self.executor.read_bytes(), self.old_executor)

    def test_interrupted_broker_only_publication_recovers_old_pair(self) -> None:
        """Power loss between file swaps must be recoverable without startup."""
        staged = module.stage_configurations(self.plan)
        self.broker.write_bytes(self.plan.broker_target)
        module.recover_interrupted_configurations(self.plan, staged)
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.executor.read_bytes(), self.old_executor)
        self.assertTrue(staged.broker_backup.exists())
        self.assertTrue(staged.executor_backup.exists())

    def test_interrupted_executor_only_publication_recovers_old_pair(self) -> None:
        """Either recognizable mixed pair must be restored from old authority."""
        staged = module.stage_configurations(self.plan)
        self.executor.write_bytes(self.plan.executor_target)
        module.recover_interrupted_configurations(self.plan, staged)
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.executor.read_bytes(), self.old_executor)

    def test_interrupted_unknown_config_refuses_recovery(self) -> None:
        """Recovery cannot overwrite a third, unreviewed configuration."""
        staged = module.stage_configurations(self.plan)
        self.broker.write_bytes(b"unreviewed broker config")
        with self.assertRaisesRegex(module.ConfigurationCutoverHold, "manual recovery"):
            module.recover_interrupted_configurations(self.plan, staged)
        self.assertEqual(self.broker.read_bytes(), b"unreviewed broker config")
        self.assertEqual(self.executor.read_bytes(), self.old_executor)

    def test_already_old_recovery_noop_retains_backup(self) -> None:
        """Recovery is idempotent after a fully completed restoration."""
        staged = module.stage_configurations(self.plan)
        module.recover_interrupted_configurations(self.plan, staged)
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.executor.read_bytes(), self.old_executor)
        self.assertTrue(staged.broker_backup.exists())

    def test_failed_rollback_does_not_claim_success(self) -> None:
        """The operator must know if one config could not be restored."""
        staged = module.stage_configurations(self.plan)
        module.activate_configurations(self.plan, staged)
        original = module._restore_one

        def deny_executor(path: Path, old: bytes, gid: int, mode: int) -> None:
            """Simulate nonrecoverable second restore."""
            if path == self.executor:
                raise OSError("synthetic restore failure")
            original(path, old, gid, mode)

        with patch.object(module, "_restore_one", side_effect=deny_executor):
            with self.assertRaisesRegex(module.ConfigurationCutoverHold,
                                        "manual recovery"):
                module.rollback_configurations(self.plan, staged)
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.executor.read_bytes(), self.plan.executor_target)


if __name__ == "__main__":
    unittest.main()
