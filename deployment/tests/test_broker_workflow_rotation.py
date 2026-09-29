"""Closed pre-activation C32ZC broker workflow-SHA rotation tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import inspect
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deployment import dev_final_broker_resources as resources
from deployment import dev_post_c31_application_update as c32d
from deployment.broker_host_service_contract import DevBrokerHostServiceContract
from deployment.final_configuration_authority import DevFinalConfigurationAuthority
from deployment.tests.test_dev_final_broker_resources import fixture_pair
from dataclasses import replace

OLD = "a" * 40
NEW = "b" * 40


def pairs():
    old_pair, old_host = fixture_pair()
    historical = replace(old_pair.executor, reviewed_commit=c32d.PREDECESSOR)
    digest = hashlib.sha256(historical.canonical_bytes()).hexdigest()
    with patch.object(c32d, "PREDECESSOR_C17", digest):
        new_pair = DevFinalConfigurationAuthority(
            executor_configuration=old_pair.executor).configuration_pair(
                expected_workflow_sha=NEW)
    return (old_pair, old_host), (new_pair, DevBrokerHostServiceContract(configuration=new_pair.broker))


class BrokerWorkflowRotationTests(unittest.TestCase):
    def test_closed_api_and_digest_only_evidence(self):
        self.assertEqual(tuple(inspect.signature(
            resources.rotate_final_dev_broker_workflow_authority).parameters),
            ("current_expected_workflow_sha", "new_expected_workflow_sha"))
        self.assertEqual(tuple(inspect.signature(
            resources.qualify_final_dev_broker_workflow_authority).parameters),
            ("expected_workflow_sha",))
        evidence = resources.FinalBrokerWorkflowRotationEvidence(
            OLD, NEW, "1" * 64, "2" * 64, "rotated")
        self.assertNotIn("dev.json", repr(evidence))
        with self.assertRaises(FrozenInstanceError):
            evidence.operation = "other"
        for old, new in (("0" * 40, NEW), (OLD.upper(), NEW), (OLD, OLD),
                         (OLD, "z" * 40), (OLD, True)):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                resources.FinalBrokerWorkflowRotationEvidence(
                    old, new, "1" * 64, "2" * 64, "rotated")

    def test_root_and_sha_validation_precede_lock_and_host_access(self):
        with (patch.object(resources.os, "getuid", return_value=1), patch.object(
            resources.lock_runtime, "_acquire_process_lock") as acquire,
            self.assertRaises(resources.FinalBrokerResourcesError)):
            resources.rotate_final_dev_broker_workflow_authority(
                current_expected_workflow_sha=OLD, new_expected_workflow_sha=NEW)
        acquire.assert_not_called()
        for old, new in (("0" * 40, NEW), (OLD, OLD), (OLD.upper(), NEW),
                         (OLD, "z" * 40)):
            with (self.subTest(old=old, new=new), patch.object(
                resources, "_root", return_value=(0, 0, 0, 0)), patch.object(
                resources.lock_runtime, "_acquire_process_lock") as acquire,
                self.assertRaises(resources.FinalBrokerResourcesError)):
                resources.rotate_final_dev_broker_workflow_authority(
                    current_expected_workflow_sha=old, new_expected_workflow_sha=new)
            acquire.assert_not_called()

    def test_full_old_and_new_qualification_under_lock(self):
        old, new = pairs()
        lock = resources.lock_runtime._ProcessLock(((7, None, None, ()),), 7)
        events = []
        def qualify(pair, host, outcomes):
            events.append(("qualify", pair.broker.expected_workflow_sha))
            self.assertEqual(outcomes, ("unchanged",) * 8)
        def replace_file(old_host, new_host, directories):
            events.append(("replace", old_host.configuration.expected_workflow_sha,
                           new_host.configuration.expected_workflow_sha))
            self.assertEqual(directories, ())
        with (patch.object(resources, "_root", return_value=(0, 0, 0, 0)), patch.object(
            resources.lock_runtime, "_acquire_process_lock", return_value=lock), patch.object(
            resources.lock_runtime, "_release_process_lock", return_value=None) as release, patch.object(
            resources, "_pair", side_effect=[old, new]), patch.object(
            resources, "_qualify", side_effect=qualify), patch.object(
            resources, "_authorities", return_value=()), patch.object(
            resources, "_temporary_absent"), patch.object(
            resources, "_replace_workflow_configuration", side_effect=replace_file)):
            evidence = resources.rotate_final_dev_broker_workflow_authority(
                current_expected_workflow_sha=OLD, new_expected_workflow_sha=NEW)
        self.assertEqual(events, [
            ("qualify", OLD), ("replace", OLD, NEW), ("qualify", NEW)])
        self.assertEqual(evidence.operation, "rotated")
        self.assertEqual(evidence.old_workflow_sha, OLD)
        self.assertEqual(evidence.new_workflow_sha, NEW)
        self.assertEqual(evidence.old_broker_config_sha256,
                         hashlib.sha256(old[1].canonical_configuration_bytes()).hexdigest())
        self.assertEqual(evidence.new_broker_config_sha256,
                         hashlib.sha256(new[1].canonical_configuration_bytes()).hexdigest())
        release.assert_called_once_with(lock)

    def test_unexpected_old_installation_never_replaces(self):
        old, new = pairs()
        lock = resources.lock_runtime._ProcessLock(((7, None, None, ()),), 7)
        with (patch.object(resources, "_root", return_value=(0, 0, 0, 0)), patch.object(
            resources.lock_runtime, "_acquire_process_lock", return_value=lock), patch.object(
            resources.lock_runtime, "_release_process_lock", return_value=None), patch.object(
            resources, "_pair", side_effect=[old, new]), patch.object(
            resources, "_qualify", side_effect=OSError), patch.object(
            resources, "_replace_workflow_configuration") as replace_file,
            self.assertRaises(resources.FinalBrokerResourcesError)):
            resources.rotate_final_dev_broker_workflow_authority(
                current_expected_workflow_sha=OLD, new_expected_workflow_sha=NEW)
        replace_file.assert_not_called()

    def test_separate_qualifier_is_read_only_and_requires_nonzero_sha(self):
        marker = object()
        with patch.object(resources, "qualify_final_dev_broker_resources",
                          return_value=marker) as qualify:
            self.assertIs(resources.qualify_final_dev_broker_workflow_authority(
                expected_workflow_sha=NEW), marker)
        qualify.assert_called_once_with(expected_workflow_sha=NEW)
        with self.assertRaises(resources.FinalBrokerResourcesError):
            resources.qualify_final_dev_broker_workflow_authority(
                expected_workflow_sha="0" * 40)

    def test_same_directory_atomic_replacement_and_exact_old_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dev.json"
            path.write_bytes(b"canonical old\n")
            path.chmod(0o640)
            requirement = resources.host_runtime._FileAuthority(
                str(path), 0o640, os.getuid(), os.getgid())
            class Host:
                def __init__(self, payload):
                    self.payload = payload
                def broker_configuration_file(self):
                    return requirement
                def broker_configuration_directory(self):
                    return directory
                def canonical_configuration_bytes(self):
                    return self.payload
            def parent(_path, _authorities, owned):
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                owned.append(descriptor)
                return descriptor, "dev.json", []
            old = Host(b"canonical old\n")
            new = Host(b"canonical new\n")
            original_inode = path.stat().st_ino
            real_replace = os.replace
            def observed_replace(source, target, **kwargs):
                self.assertEqual((source, target),
                                 (resources._ROTATION_TEMPORARY, "dev.json"))
                self.assertEqual(path.read_bytes(), b"canonical old\n")
                return real_replace(source, target, **kwargs)
            with patch.object(resources, "PRODUCTION_BROKER_SERVICE_CONFIG_PATH", str(path)), \
                    patch.object(resources.host_runtime, "_open_parent", side_effect=parent), \
                    patch.object(resources.os, "replace", side_effect=observed_replace):
                hardlink = Path(directory) / "linked.json"
                os.link(path, hardlink)
                with self.assertRaises(OSError):
                    resources._replace_workflow_configuration(old, new, ())
                hardlink.unlink()
                path.unlink()
                path.symlink_to(hardlink)
                with self.assertRaises(OSError):
                    resources._replace_workflow_configuration(old, new, ())
                path.unlink()
                path.write_bytes(b"canonical old\n")
                path.chmod(0o640)
                original_inode = path.stat().st_ino
                resources._replace_workflow_configuration(old, new, ())
            self.assertEqual(path.read_bytes(), b"canonical new\n")
            self.assertNotEqual(path.stat().st_ino, original_inode)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertFalse((Path(directory) / resources._ROTATION_TEMPORARY).exists())
            with patch.object(resources, "PRODUCTION_BROKER_SERVICE_CONFIG_PATH", str(path)), \
                    patch.object(resources.host_runtime, "_open_parent", side_effect=parent), \
                    self.assertRaises(OSError):
                resources._replace_workflow_configuration(old, new, ())
            self.assertEqual(path.read_bytes(), b"canonical new\n")


if __name__ == "__main__":
    unittest.main()
