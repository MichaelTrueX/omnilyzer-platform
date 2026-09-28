"""C32Y inert, root-only broker-resource plan and no-overwrite primitives."""

from dataclasses import replace
import hashlib
import inspect
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from deployment import dev_final_broker_resources as c32y
from deployment import dev_post_c31_application_update as c32d
from deployment import final_application_generation as frozen
from deployment import dev_final_application_update as c32w
from deployment.broker_host_service_contract import DevBrokerHostServiceContract
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.final_configuration_authority import DevFinalConfigurationAuthority
from deployment.tests.test_executor_service_config import configuration_values
from deployment.tests.test_executor_service_config_loader import status_result


WORKFLOW = "a" * 40


def fixture_pair():
    executor = DevExecutorServiceConfiguration(**configuration_values(
        reviewed_commit=frozen.TARGET_REVIEWED_COMMIT))
    historical = replace(executor, reviewed_commit=c32d.PREDECESSOR)
    digest = hashlib.sha256(historical.canonical_bytes()).hexdigest()
    with patch.object(c32d, "PREDECESSOR_C17", digest):
        pair = DevFinalConfigurationAuthority(
            executor_configuration=executor).configuration_pair(expected_workflow_sha=WORKFLOW)
    return pair, DevBrokerHostServiceContract(configuration=pair.broker)


class BrokerResourcesTests(unittest.TestCase):
    def test_public_signatures_and_historical_pin_are_closed(self):
        self.assertEqual(tuple(inspect.signature(c32y.provision_final_dev_broker_resources).parameters),
                         ("expected_workflow_sha", "reviewed_source_root",
                          "sigstore_staging_directory"))
        self.assertEqual(tuple(inspect.signature(c32y.qualify_final_dev_broker_resources).parameters),
                         ("expected_workflow_sha",))
        pair, _host = fixture_pair()
        with self.assertRaises(ValueError):
            DevFinalConfigurationAuthority(executor_configuration=pair.executor)
        self.assertEqual(c32d.PREDECESSOR_C17,
                         "2da08e1d83ae6baa007ca0f5b8492c7e9df30a6922007095fb129f76fc924762")

    def test_final_config_read_twice_and_predecessor_cannot_reach_authority(self):
        pair, _host = fixture_pair()
        state = c32w.FinalApplicationUpdateState(
            frozen.TARGET_REVIEWED_COMMIT, 16, 16, None, None, True)
        historical = replace(pair.executor, reviewed_commit=c32d.PREDECESSOR)
        with patch.object(c32y, "read_root_dev_executor_configuration", return_value=historical), \
                patch.object(c32y, "DevFinalConfigurationAuthority") as authority:
            with self.assertRaises(OSError):
                c32y._pair(WORKFLOW)
            authority.assert_not_called()
        digest = hashlib.sha256(replace(pair.executor,
            reviewed_commit=c32d.PREDECESSOR).canonical_bytes()).hexdigest()
        with patch.object(c32d, "PREDECESSOR_C17", digest), \
                patch.object(c32y, "read_root_dev_executor_configuration",
                             side_effect=[pair.executor, pair.executor]) as reader, \
                patch.object(c32y.c32w_update, "qualify_final_application_update",
                             return_value=state):
            projected, _host = c32y._pair(WORKFLOW)
        self.assertEqual(projected.broker.expected_workflow_sha, WORKFLOW)
        self.assertEqual(reader.call_count, 2)
        with patch.object(c32d, "PREDECESSOR_C17", digest), \
                patch.object(c32y, "read_root_dev_executor_configuration",
                             side_effect=[pair.executor, historical]), \
                patch.object(c32y.c32w_update, "qualify_final_application_update",
                             return_value=state), self.assertRaises(OSError):
            c32y._pair(WORKFLOW)

    def test_root_requirement_before_lock_or_mutation(self):
        with patch.object(c32y.os, "getuid", return_value=1), \
                patch.object(c32y.lock_runtime, "_acquire_process_lock") as acquire, \
                self.assertRaises(c32y.FinalBrokerResourcesError) as caught:
            c32y.provision_final_dev_broker_resources(
                expected_workflow_sha=WORKFLOW, reviewed_source_root="/reviewed",
                sigstore_staging_directory="/staged")
        acquire.assert_not_called()
        self.assertEqual(str(caught.exception), c32y._ERROR)
        self.assertNotIn("/reviewed", str(caught.exception))

    def test_process_lock_acquire_and_release_fail_closed(self):
        with patch.object(c32y, "_root", return_value=(0, 0, 0, 0)), \
                patch.object(c32y.lock_runtime, "_acquire_process_lock",
                             side_effect=BlockingIOError), \
                patch.object(c32y, "_pair") as pair, \
                self.assertRaises(c32y.FinalBrokerResourcesError):
            c32y.provision_final_dev_broker_resources(
                expected_workflow_sha=WORKFLOW, reviewed_source_root="/reviewed",
                sigstore_staging_directory="/staged")
        pair.assert_not_called()
        lock = c32y.lock_runtime._ProcessLock(((7, None, None, ()),), 7)
        with patch.object(c32y, "_root", return_value=(0, 0, 0, 0)), \
                patch.object(c32y.lock_runtime, "_acquire_process_lock", return_value=lock), \
                patch.object(c32y.lock_runtime, "_release_process_lock",
                             side_effect=OSError), \
                patch.object(c32y, "_pair", side_effect=OSError), \
                self.assertRaises(c32y.FinalBrokerResourcesError):
            c32y.provision_final_dev_broker_resources(
                expected_workflow_sha=WORKFLOW, reviewed_source_root="/reviewed",
                sigstore_staging_directory="/staged")

    def test_ordered_provisioning_uses_shared_lock_and_never_migrates(self):
        pair, host = fixture_pair()
        calls = []
        lock = c32y.lock_runtime._ProcessLock(((7, None, None, ()),), 7)
        class Sigstore:
            operation = "already-installed"
            def __post_init__(self):
                calls.append("sigstore-validated")
        sigstore = Sigstore()
        installed = Mock(sigstore=sigstore)
        installed.operation = "already-installed"
        def record(name, value=None):
            def action(*_args, **_kwargs):
                calls.append(name)
                return value
            return action
        with patch.object(c32y, "_root", side_effect=record("root", (0, 0, 0, 0))), \
                patch.object(c32y.lock_runtime, "_acquire_process_lock",
                             side_effect=record("lock", lock)), \
                patch.object(c32y.lock_runtime, "_release_process_lock",
                             side_effect=record("unlock")), \
                patch.object(c32y, "_pair", side_effect=record("pair", (pair, host))), \
                patch.object(c32y, "_replay", side_effect=record("replay")), \
                patch.object(c32y, "_source_unit", side_effect=record("source", b"unit")), \
                patch.object(c32y, "_authorities", side_effect=record("authorities", ())), \
                patch.object(c32y, "_directory_exists", return_value=False), \
                patch.object(c32y, "_temporary_absent"), \
                patch.object(c32y, "_file_state", return_value=False), \
                patch.object(c32y.host_runtime, "_ensure_directory",
                             side_effect=record("directory", Mock(outcome="created"))), \
                patch.object(c32y.sigstore_installer, "DevSigstoreStaticInstallationEvidence", Sigstore), \
                patch.object(c32y.sigstore_installer, "_install_under_held_process_lock",
                             side_effect=record("sigstore", sigstore)) as installer, \
                patch.object(c32y, "_publish", side_effect=record("publish", "created")), \
                patch.object(c32y, "_qualify", side_effect=record("qualify", installed)), \
                patch.object(c32y, "_evidence", side_effect=record("evidence", installed)), \
                patch.object(c32w, "update_final_application", side_effect=AssertionError):
            result = c32y.provision_final_dev_broker_resources(
                expected_workflow_sha=WORKFLOW, reviewed_source_root="/reviewed",
                sigstore_staging_directory="/staged")
        self.assertIs(result, installed)
        self.assertLess(calls.index("lock"), calls.index("pair"))
        self.assertLess(calls.index("pair"), calls.index("replay"))
        self.assertLess(calls.index("replay"), calls.index("directory"))
        self.assertLess(calls.index("directory"), calls.index("sigstore"))
        self.assertLess(calls.index("sigstore"), calls.index("publish"))
        self.assertLess(calls.index("publish"), calls.index("qualify"))
        self.assertEqual(calls[-1], "unlock")
        installer.assert_called_once_with(staging_directory="/staged",
                                          configuration=pair.broker, held_lock=lock)

    def test_historical_c17_proof_failure_prevents_mutation(self):
        pair, _host = fixture_pair()
        lock = c32y.lock_runtime._ProcessLock(((7, None, None, ()),), 7)
        with patch.object(c32y, "_root", return_value=(0, 0, 0, 0)), \
                patch.object(c32y.lock_runtime, "_acquire_process_lock", return_value=lock), \
                patch.object(c32y.lock_runtime, "_release_process_lock"), \
                patch.object(c32y, "read_root_dev_executor_configuration",
                             return_value=pair.executor), \
                patch.object(c32y, "_source_unit") as source, \
                patch.object(c32y.host_runtime, "_ensure_directory") as directory, \
                self.assertRaises(c32y.FinalBrokerResourcesError):
            c32y.provision_final_dev_broker_resources(
                expected_workflow_sha=WORKFLOW, reviewed_source_root="/reviewed",
                sigstore_staging_directory="/staged")
        source.assert_not_called()
        directory.assert_not_called()

    def test_config_present_without_complete_sigstore_rejected_before_mutation(self):
        pair, host = fixture_pair()
        lock = c32y.lock_runtime._ProcessLock(((7, None, None, ()),), 7)
        with patch.object(c32y, "_root", return_value=(0, 0, 0, 0)), \
                patch.object(c32y.lock_runtime, "_acquire_process_lock", return_value=lock), \
                patch.object(c32y.lock_runtime, "_release_process_lock"), \
                patch.object(c32y, "_pair", return_value=(pair, host)), \
                patch.object(c32y, "_replay"), \
                patch.object(c32y, "_source_unit", return_value=b"unit"), \
                patch.object(c32y, "_authorities", return_value=()), \
                patch.object(c32y, "_directory_exists", return_value=True), \
                patch.object(c32y, "_temporary_absent"), \
                patch.object(c32y, "_file_state", side_effect=[True, False]), \
                patch.object(c32y.sigstore_installer, "_qualify_installed",
                             side_effect=OSError) as sigstore, \
                patch.object(c32y.host_runtime, "_ensure_directory") as directory, \
                self.assertRaises(c32y.FinalBrokerResourcesError):
            c32y.provision_final_dev_broker_resources(
                expected_workflow_sha=WORKFLOW, reviewed_source_root="/reviewed",
                sigstore_staging_directory="/staged")
        sigstore.assert_called_once_with(pair.broker)
        directory.assert_not_called()

    def test_untrusted_source_checkout_rejected_without_host_installation(self):
        pair, host = fixture_pair()
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / host.installed_asset_requirement().source_path
            source.parent.mkdir(parents=True)
            source.write_text("wrong or mutable")
            with self.assertRaises(Exception):
                c32y._source_unit(temporary, host)

    def test_reviewed_unit_source_exact_bytes_and_digest_in_controlled_tree(self):
        _pair, host = fixture_pair()
        source_bytes = Path(host.installed_asset_requirement().source_path).read_bytes()
        self.assertEqual(hashlib.sha256(source_bytes).hexdigest(),
                         host.installed_asset_requirement().sha256)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            unit = directory / "unit"
            unit.write_bytes(source_bytes)
            unit.chmod(0o644)
            original_fstat = os.fstat
            file_status = os.stat(unit)
            directory_status = os.stat(directory)
            fake_file = status_result(file_status.st_mode, file_status.st_ino,
                gid=file_status.st_gid, links=1, size=len(source_bytes), device=file_status.st_dev)
            fake_dir = status_result(directory_status.st_mode, directory_status.st_ino,
                gid=directory_status.st_gid, links=directory_status.st_nlink,
                size=directory_status.st_size, device=directory_status.st_dev)
            def parent(_path, _authorities, owned):
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                owned.append(descriptor)
                return descriptor, "unit", [(descriptor, None, None,
                    c32y.host_runtime._directory_fingerprint(fake_dir))]
            def fstat(descriptor):
                return fake_dir if original_fstat(descriptor).st_ino == directory_status.st_ino else fake_file
            def named(_name, **_kwargs):
                return fake_file
            with patch.object(c32y.host_runtime, "_open_parent", side_effect=parent), \
                    patch.object(c32y.os, "fstat", side_effect=fstat), \
                    patch.object(c32y.os, "stat", side_effect=named):
                self.assertEqual(c32y._source_unit("/reviewed", host), source_bytes)
                unit.write_bytes(source_bytes + b"x")
                with self.assertRaises(OSError):
                    c32y._source_unit("/reviewed", host)
                unit.write_bytes(source_bytes[:-1] + b"x")
                with self.assertRaises(OSError):
                    c32y._source_unit("/reviewed", host)
                unit.unlink()
                unit.symlink_to(directory / "other")
                with self.assertRaises(OSError):
                    c32y._source_unit("/reviewed", host)

    def test_no_replace_publication_and_exact_rerun_in_sandbox(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = "/closed/test.json"
            payload = b'{"schema_version":2}\n'
            uid, gid = os.getuid(), os.getgid()
            def parent(_path, _authorities, owned):
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                owned.append(descriptor)
                return descriptor, "test.json", []
            with patch.object(c32y.host_runtime, "_open_parent", side_effect=parent):
                self.assertEqual(c32y._publish(path, 0o640, uid, gid, payload, ()), "created")
                self.assertEqual((directory / "test.json").read_bytes(), payload)
                self.assertFalse((directory / c32y._TEMPORARY).exists())
                self.assertEqual(c32y._publish(path, 0o640, uid, gid, payload, ()), "unchanged")
                with self.assertRaises(OSError):
                    c32y._publish(path, 0o640, uid, gid, b"different", ())
                self.assertEqual((directory / "test.json").read_bytes(), payload)

    def test_target_race_does_not_overwrite_and_cleans_own_temporary(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def parent(_path, _authorities, owned):
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                owned.append(descriptor)
                return descriptor, "test.json", []
            def competing_link(_source, _target, **_kwargs):
                (directory / "test.json").write_bytes(b"competitor")
                raise FileExistsError
            with patch.object(c32y.host_runtime, "_open_parent", side_effect=parent), \
                    patch.object(c32y.os, "link", side_effect=competing_link), \
                    self.assertRaises(OSError):
                c32y._publish("/closed/test.json", 0o640, os.getuid(), os.getgid(),
                              b"reviewed", ())
            self.assertEqual((directory / "test.json").read_bytes(), b"competitor")
            self.assertFalse((directory / c32y._TEMPORARY).exists())

    def test_unknown_temporary_residue_is_never_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            residue = directory / c32y._TEMPORARY
            residue.write_bytes(b"unrecognized")
            def parent(_path, _authorities, owned):
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                owned.append(descriptor)
                return descriptor, "test.json", []
            with patch.object(c32y.host_runtime, "_open_parent", side_effect=parent), \
                    self.assertRaises(OSError):
                c32y._temporary_absent("/closed/test.json", ())
            self.assertEqual(residue.read_bytes(), b"unrecognized")

    def test_substituted_temporary_is_never_deleted_by_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            residue = directory / c32y._TEMPORARY
            def parent(_path, _authorities, owned):
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                owned.append(descriptor)
                return descriptor, "test.json", []
            def substitute(_source, _target, **_kwargs):
                residue.unlink()
                residue.write_bytes(b"substituted")
                raise OSError
            with patch.object(c32y.host_runtime, "_open_parent", side_effect=parent), \
                    patch.object(c32y.os, "link", side_effect=substitute), \
                    self.assertRaises(OSError):
                c32y._publish("/closed/test.json", 0o640, os.getuid(), os.getgid(),
                              b"reviewed", ())
            self.assertEqual(residue.read_bytes(), b"substituted")
            self.assertFalse((directory / "test.json").exists())

    def test_read_only_qualification_uses_installed_fixed_resources(self):
        pair, host = fixture_pair()
        marker = object()
        with patch.object(c32y, "_pair", return_value=(pair, host)) as derive, \
                patch.object(c32y, "_authorities", return_value=()), \
                patch.object(c32y, "_directory_exists", return_value=True) as directory, \
                patch.object(c32y, "_file_state", return_value=True) as config, \
                patch.object(c32y, "_installed_unit", return_value=True) as unit, \
                patch.object(c32y, "_replay") as replay, \
                patch.object(c32y.sigstore_installer, "_qualify_installed",
                             return_value=marker) as sigstore, \
                patch.object(c32y, "_evidence", return_value=marker):
            self.assertIs(c32y.qualify_final_dev_broker_resources(
                expected_workflow_sha=WORKFLOW), marker)
        derive.assert_called_once_with(WORKFLOW)
        self.assertEqual(directory.call_count, 6)
        self.assertEqual(config.call_count, 1)
        self.assertEqual(unit.call_count, 1)
        replay.assert_called_once_with(host)
        sigstore.assert_called_once_with(pair.broker)

    def test_replay_is_validated_only_and_socket_node_is_not_created(self):
        _pair, host = fixture_pair()
        guard = Mock()
        guard.initialize.side_effect = AssertionError("replay initialization")
        with patch.object(c32y, "SQLiteReplayGuard", return_value=guard) as replay, \
                patch.object(c32y.os, "mkdir", side_effect=AssertionError("socket creation")):
            c32y._replay(host)
        guard.validate.assert_called_once_with()
        guard.initialize.assert_not_called()
        self.assertEqual(replay.call_args.args[0], c32y.PRODUCTION_REPLAY_DATABASE)
        self.assertEqual(replay.call_args.kwargs["expected_directory_uid"], 0)
        self.assertEqual(replay.call_args.kwargs["expected_directory_gid"], host.configuration.replay_group_gid)

    def test_no_host_activities_or_runtime_source_selection(self):
        from deployment.application_source_set import DevApplicationSourceSet
        selected = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertNotIn("deployment/dev_final_broker_resources.py", selected)
        self.assertNotIn("deployment/root_executor_configuration_reader.py", selected)
        source = inspect.getsource(c32y)
        for forbidden in ("systemctl", "daemon-reload", "update_final_application(",
                          "socket.bind", "subprocess.run", "deployment_enabled = True"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(len(selected), 41)


if __name__ == "__main__":
    unittest.main()
