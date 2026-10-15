"""File: deployment/tests/test_c34n_root_predecessor_adapter.py

Purpose: Test C34N's fixed root-anchored no-follow directory chains,
closed 41-file predecessor comparison, stopped-unit precondition, unchanged
rootless signatures, exclusive lock lifecycle and non-authorizing receipts.
Related: deployment/c34n_root_predecessor_adapter.py,
deployment/c34m_descriptor_source_observation.py,
deployment/dev_host_provisioning_orchestration.py.

Tests use disposable unprivileged roots and mocked service/runtime probes.
Never use sudo, installed application/configs, systemd, real lock, database,
network, registry, secrets or deployment commands.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deployment import c34n_root_predecessor_adapter as gate
from deployment import c34m_descriptor_source_observation as observation
from deployment.application_source_set import DevApplicationSourceSet
from deployment import c34f_application_generation_evidence as reference
from deployment import dev_host_provisioning_orchestration as orchestration
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_executor_service_config import configuration_values
from deployment.tests.test_broker_service_config import configuration_values as broker_values


class C34NTrustedDescriptorTests(unittest.TestCase):
    """Prove fixed closed root-anchored chains on synthetic paths only."""

    def setUp(self) -> None:
        """Create exact app/config directory topology inside a fresh temp root."""
        self.tmp = tempfile.TemporaryDirectory(prefix="omnilyzer-c34n-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.uid, self.gid = os.getuid(), os.getgid()
        for components in (gate._APP, gate._EXECUTOR, gate._BROKER):
            path = self.root
            for component in components:
                path = path / component
                path.mkdir(exist_ok=True)
                path.chmod(0o755)
        for leaf in (gate._EXECUTOR, gate._BROKER):
            (self.root.joinpath(*leaf)).chmod(0o750)
        self.paths = tuple(
            file.repository_path for file in DevApplicationSourceSet().files
        )
        self.expected = []
        for name in self.paths:
            location = self.root.joinpath(*gate._APP) / name
            location.parent.mkdir(parents=True, exist_ok=True)
            parent = location.parent
            while parent != self.root.joinpath(*gate._APP):
                parent.chmod(0o755)
                parent = parent.parent
            content = ("source:" + name + "\n").encode("ascii")
            location.write_bytes(content)
            location.chmod(0o644)
            self.expected.append((name, hashlib.sha256(content).hexdigest()))
        self.fd = os.open(
            self.root, os.O_RDONLY | os.O_DIRECTORY
            | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        self.addCleanup(os.close, self.fd)

    def _inspect(self):
        """Bind the reviewed 41-file names to local fixture bytes only."""
        with patch.object(gate, "_EXPECTED", tuple(self.expected)):
            return gate._read_qualified(
                self.fd, owner_uid=self.uid,
                executor_gid=self.gid, broker_gid=self.gid,
            )

    def test_all_41_regular_source_paths_are_observed(self):
        """Descriptor lineage, canonical order and no-stage state all pass."""
        result = self._inspect()
        self.assertIsInstance(result, observation.C34MSourceObservation)
        self.assertEqual(result.source_digests, tuple(self.expected))
        self.assertEqual(result.pending_stages, ())

    def test_unexpected_source_file_blocks_full_identity(self):
        """No extra application entry may be ignored by C34N."""
        extra = self.root.joinpath(*gate._APP, "deployment", "unknown.py")
        extra.write_bytes(b"unreviewed")
        with self.assertRaises(ValueError):
            self._inspect()

    def test_unexpected_stage_blocks_predecessor(self):
        """C34N is predecessor-only; partial migrations need a different gate."""
        stage = self.root.joinpath(
            *gate._APP, "deployment", ".omnilyzer-c34j-broker.py.stage",
        )
        stage.write_bytes(b"")
        stage.chmod(0o600)
        with self.assertRaises(ValueError):
            self._inspect()

    def test_intermediate_symlink_is_rejected(self):
        """Root-relative component traversal never follows a symbolic link."""
        location = self.root / "opt"
        moved = self.root / "renamed-opt"
        location.rename(moved)
        location.symlink_to(moved, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self._inspect()

    def test_writable_ancestor_directory_is_rejected(self):
        """Reject substitution through a group/world-writable ancestor."""
        (self.root / "etc").chmod(0o777)
        with self.assertRaises(ValueError):
            self._inspect()

    def test_wrong_configuration_directory_mode_is_rejected(self):
        """The canonical configuration leaf must have exact 0750 mode."""
        self.root.joinpath(*gate._BROKER).chmod(0o700)
        with self.assertRaises(ValueError):
            self._inspect()

    def test_hardlink_and_source_mode_drift_rejected(self):
        """Protected source files must remain 0644, single-link originals."""
        source = self.root.joinpath(*gate._APP, "deployment", "broker.py")
        external = self.root / "another-link"
        os.link(source, external)
        with self.assertRaises(Exception):
            self._inspect()
        external.unlink()
        source.chmod(0o600)
        with self.assertRaises(Exception):
            self._inspect()

    def test_revalidate_detects_removed_directory(self):
        """Rename after opening the directory must invalidate the chain."""
        chain = gate._open_chain(
            self.fd, gate._APP, owner_uid=self.uid,
            final_gid=self.gid, final_mode=0o755,
        )
        try:
            anchor = gate._snapshot(os.fstat(self.fd))
            original = self.root.joinpath(*gate._APP)
            original.rename(original.with_name("replaced-app"))
            with self.assertRaises((ValueError, FileNotFoundError)):
                gate._revalidate_chains(self.fd, (chain,), anchor)
        finally:
            for fd, _parent, _name, _fingerprint in reversed(chain):
                os.close(fd)


class C34NRootHostGateTests(unittest.TestCase):
    """Mock privileged host probes but never alter a real service or file."""

    def setUp(self) -> None:
        """Construct aligned typed synthetic predecessor configurations."""
        self.executor = DevExecutorServiceConfiguration(
            **configuration_values(reviewed_commit=reference.PREDECESSOR)
        )
        shared = {
            k: getattr(self.executor, k)
            for k in (
                "broker_uid", "broker_gid", "executor_uid", "executor_gid",
                "replay_group_gid", "socket_group_gid",
                "runtime_configuration_sha256", "ingress_file_sha256",
            )
        }
        self.broker = DevBrokerServiceConfiguration(
            **broker_values(
                reviewed_commit=reference.PREDECESSOR,
                expected_workflow_sha=reference.C34D_MAIN,
                **shared,
            )
        )

    def _mocks(self, stack: ExitStack):
        """Replace every live probe with closed synthetic fixtures."""
        spies = {}
        lock = orchestration._ProcessLock((), -1)
        fixed = (
            ("root", "deployment.c34n_root_predecessor_adapter.runtime._root_identity", (0, 0)),
            ("units", "deployment.c34n_root_predecessor_adapter.runtime._service_snapshot", (("stopped",),)),
            ("runtime", "deployment.c34n_root_predecessor_adapter.runtime._rootless_runtime_signature", (1005, 1006, ())),
            ("executor", "deployment.c34n_root_predecessor_adapter.read_root_dev_executor_configuration", self.executor),
            ("broker", "deployment.c34n_root_predecessor_adapter.read_root_dev_broker_configuration", self.broker),
            ("scan", "deployment.c34n_root_predecessor_adapter._read_qualified",
             observation.C34MSourceObservation(gate._EXPECTED, ())),
            ("acquire", "deployment.c34n_root_predecessor_adapter.orchestration._acquire_process_lock", lock),
            ("release", "deployment.c34n_root_predecessor_adapter.orchestration._release_process_lock", None),
        )
        for name, target, result in fixed:
            spies[name] = stack.enter_context(patch(target, return_value=result))
        return spies

    def test_stopped_host_receipt_is_never_deployment_approval(self):
        """Root-only read-only checks run twice under the exclusive lock."""
        with ExitStack() as stack:
            spies = self._mocks(stack)
            receipt = gate.qualify_c34n_root_predecessor()
            self.assertEqual(receipt.protected_files, 41)
            self.assertTrue(receipt.stopped_units_verified)
            self.assertFalse(receipt.migration_ready)
            spies["scan"].assert_called()
            self.assertEqual(spies["scan"].call_count, 2)
            spies["acquire"].assert_called_once()
            spies["release"].assert_called_once()

    def test_stopped_service_failure_releases_lock_and_holds(self):
        """A running broker must not lead to a migration readiness claim."""
        with ExitStack() as stack:
            spies = self._mocks(stack)
            spies["units"].side_effect = OSError("synthetic service not stopped")
            with self.assertRaises(gate.C34NRootPredecessorError):
                gate.qualify_c34n_root_predecessor()
            spies["release"].assert_called_once()

    def test_rootless_runtime_change_aborts(self):
        """A changed manager/runtime signature blocks qualification."""
        with ExitStack() as stack:
            spies = self._mocks(stack)
            spies["runtime"].side_effect = [
                (1005, 1006, ()), (1005, 1006, ((3, 4),)),
            ]
            with self.assertRaises(gate.C34NRootPredecessorError):
                gate.qualify_c34n_root_predecessor()
            spies["release"].assert_called_once()

    def test_wrong_workflow_identity_rejected(self):
        """A new pin cannot be inferred from existing source."""
        with ExitStack() as stack:
            spies = self._mocks(stack)
            spies["broker"].return_value = replace(
                self.broker, expected_workflow_sha="f" * 40,
            )
            with self.assertRaises(gate.C34NRootPredecessorError):
                gate.qualify_c34n_root_predecessor()

    def test_lock_release_failure_never_returns_pass(self):
        """Even complete source integrity is insufficient if unlock fails."""
        with ExitStack() as stack:
            spies = self._mocks(stack)
            spies["release"].side_effect = OSError("synthetic unlock failure")
            with self.assertRaises(gate.C34NRootPredecessorError):
                gate.qualify_c34n_root_predecessor()

    def test_fail_closed_on_unprivileged_identity_before_lock(self):
        """No root directory may be examined without a real UID gate."""
        with ExitStack() as stack:
            spies = self._mocks(stack)
            spies["root"].side_effect = PermissionError("root only")
            with self.assertRaises(gate.C34NRootPredecessorError):
                gate.qualify_c34n_root_predecessor()
            spies["acquire"].assert_not_called()

    def test_root_receipt_cannot_be_forged_ready(self):
        """No public receipt may contain migration_ready=True."""
        receipt = gate.C34NRootPredecessorReceipt(
            reference.PREDECESSOR, reference.C34D_MAIN, 41,
            True, True, True, False,
        )
        with self.assertRaises(ValueError):
            replace(receipt, migration_ready=True)
        self.assertEqual(gate.__all__, (
            "C34NRootPredecessorError", "C34NRootPredecessorReceipt",
            "qualify_c34n_root_predecessor",
        ))


if __name__ == "__main__":
    unittest.main()
