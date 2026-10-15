"""File: deployment/tests/test_c34l_one_prefix_coordinator.py

Purpose: Prove that an exact final-main six-prefix migration may proceed in
an isolated sandbox only after all five original backups are present, with
full 41-file observations, canonical config states and C34J atomic writes.
Related: deployment/c34l_one_prefix_coordinator.py,
deployment/c34k_five_file_backup_barrier.py,
deployment/c34j_atomic_file_mechanics.py,
deployment/c34i_merged_migration_authority.py.

Tests are non-root, temporary-directory-only and never access installed
DEV paths, deployment credentials, service units, replay or audit state.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deployment import c34f_application_generation_evidence as evidence
from deployment import c34i_final_main_seal as final
from deployment import c34i_merged_migration_authority as merged
from deployment import c34j_atomic_file_mechanics as atomic
from deployment import c34k_five_file_backup_barrier as backup
from deployment import c34l_one_prefix_coordinator as subject
from deployment.application_manifest import DevApplicationManifest
from deployment.application_source_set import DevApplicationSourceSet
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.tests.test_executor_service_config import configuration_values
from deployment.tests.test_broker_service_config import configuration_values as broker_values


_TEST_FINAL = "abcdef0123456789abcdef0123456789abcdef01"


class C34LOnePrefixTests(unittest.TestCase):
    """Use a fresh 41-file sandbox and a mocked, independently sealed SHA."""

    @classmethod
    def setUpClass(cls):
        """Prepare the exact source evidence from previously reviewed Git blobs."""
        cls.paths = tuple(
            entry.repository_path for entry in DevApplicationSourceSet().files
        )
        cls.old = dict(evidence.git_source._git_blobs(
            evidence.PREDECESSOR, cls.paths,
        ))
        cls.new = dict(evidence.git_source._git_blobs(
            evidence.C34E_PROPOSAL, cls.paths,
        ))
        cls.old_manifest = evidence._manifest(evidence.PREDECESSOR, cls.paths)
        candidate = evidence._manifest(evidence.C34E_PROPOSAL, cls.paths)
        cls.final_manifest = DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256",
            _TEST_FINAL, candidate.entries,
        )
        cls.seal = final.C34IFinalMainSourceSeal(
            _TEST_FINAL, 41,
            evidence._digest(cls.final_manifest.canonical_bytes()),
            evidence.CHANGED, False,
        )

    def setUp(self):
        """Create five installed originals, 38 others and private backup FD."""
        self.tmp = tempfile.TemporaryDirectory(prefix="omnilyzer-c34l-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.app = root / "app"
        self.config = root / "config"
        self.private = root / "backup"
        self.app.mkdir(mode=0o755)
        self.config.mkdir(mode=0o750)
        self.private.mkdir(mode=0o700)
        # CI runners and the isolated omnilyzerdev account use different
        # umasks. Explicitly qualify the intended sandbox directory modes;
        # never weaken any real host permission or installed configuration.
        self.app.chmod(0o755)
        self.config.chmod(0o750)
        self.private.chmod(0o700)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.fd_app = self._open(self.app / "deployment", make=True, mode=0o755)
        self.fd_config = self._open(self.config)
        self.fd_backup = self._open(self.private)
        for name in self.paths:
            target = self.app / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(self.old[name])
            target.chmod(0o644)
        ex = DevExecutorServiceConfiguration(
            **configuration_values(reviewed_commit=evidence.PREDECESSOR)
        )
        shared = {
            key: getattr(ex, key) for key in merged.draft._SHARED
        }
        br = DevBrokerServiceConfiguration(
            **broker_values(
                reviewed_commit=evidence.PREDECESSOR,
                expected_workflow_sha=evidence.C34D_MAIN,
                **shared,
            )
        )
        self.executor = ex
        self.broker = br
        self._write_config(self.config / "executor.json", ex.canonical_bytes())
        self._write_config(self.config / "dev.json", br.canonical_bytes())

        def get_manifest(commit, paths):
            """Use exact historical bytes with a synthetic future main identity."""
            if paths != self.paths:
                raise ValueError
            if commit == evidence.PREDECESSOR:
                return self.old_manifest
            if commit == _TEST_FINAL:
                return self.final_manifest
            raise ValueError

        with patch.object(merged.final, "prepare_c34i_final_main_source_seal",
                          return_value=self.seal), patch.object(
                merged.evidence, "_manifest", side_effect=get_manifest):
            self.authority = merged.C34IMergedMigrationAuthority(
                source_seal=self.seal,
                predecessor_executor=ex,
                predecessor_broker=br,
            )
        self.target_executor, self.target_broker = (
            self.authority.target_configuration_pair()
        )
        originals = (
            self.old["deployment/broker.py"],
            self.old["deployment/broker_https_ingress.py"],
            self.old["deployment/broker_integration.py"],
            ex.canonical_bytes(), br.canonical_bytes(),
        )
        targets = (
            self.new["deployment/broker.py"],
            self.new["deployment/broker_https_ingress.py"],
            self.new["deployment/broker_integration.py"],
            self.target_executor.canonical_bytes(),
            self.target_broker.canonical_bytes(),
        )
        self.targets = targets
        self.sources = tuple(
            backup.C34KOriginalSource(
                identity=atomic.C34JFileIdentity(
                    name=name, uid=self.uid, gid=self.gid,
                    mode=0o640 if name.endswith(".json") else 0o644,
                    original_sha256=hashlib.sha256(raw).hexdigest(),
                    target_sha256=hashlib.sha256(target).hexdigest(),
                ),
                source_dir_fd=(
                    self.fd_config if name.endswith(".json") else self.fd_app
                ),
                original=raw,
            )
            for name, raw, target
            in zip(backup._ORDER, originals, targets, strict=True)
        )

    def _open(self, path: Path, *, make: bool = False, mode: int = 0o755):
        """Create and retain one sandbox directory descriptor only."""
        if make:
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY
                     | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        return fd

    @staticmethod
    def _write_config(path: Path, raw: bytes):
        """Populate one ephemeral canonical JSON file at mode 0640."""
        path.write_bytes(raw)
        path.chmod(0o640)

    def _snapshot(self):
        """Read all 41 sandbox blobs plus both typed canonical configurations."""
        digests = tuple(
            (name, hashlib.sha256((self.app / name).read_bytes()).hexdigest())
            for name in self.paths
        )
        ex = DevExecutorServiceConfiguration.from_dict(json.loads(
            (self.config / "executor.json").read_text(encoding="ascii")
        ))
        br = DevBrokerServiceConfiguration.from_dict(json.loads(
            (self.config / "dev.json").read_text(encoding="ascii")
        ))
        return digests, ex, br

    def _seal_all(self):
        """Create all five original backups before the first source change."""
        return backup.seal_all_five_original_backups(
            sources=self.sources, backup_dir_fd=self.fd_backup,
            backup_uid=self.uid, backup_gid=self.gid,
        )

    def _prepare(self, *, sources=None, observation=None):
        """Bind all five backups to one exact 41-file+config prefix."""
        d, e, b = self._snapshot() if observation is None else observation
        return subject.prepare_c34l_one_prefix(
            authority=self.authority,
            observed_application_digests=d,
            executor=e, broker=b,
            sources=self.sources if sources is None else sources,
            backup_dir_fd=self.fd_backup,
            backup_uid=self.uid, backup_gid=self.gid,
        )

    def _publish(self, phase):
        """Exercise existing C34J writer solely in the synthetic temp sandbox."""
        item = self.sources[phase]
        name = item.identity.name
        return atomic.publish_exact_file(
            parent_fd=item.source_dir_fd, backup_dir_fd=self.fd_backup,
            backup_uid=self.uid, backup_gid=self.gid,
            backup_name=backup._BACKUPS[phase], identity=item.identity,
            original=item.original, target=self.targets[phase],
            stage_name=".omnilyzer-c34j-" + name + ".stage",
        )

    def test_all_five_requalify_before_each_real_sandbox_atomic_step(self):
        """Use a complete backup barrier, stage each file, and reach full final SHA."""
        self._seal_all()
        for phase in range(5):
            with self.subTest(phase=phase):
                planned = self._prepare()
                self.assertEqual(planned.completed_steps, phase)
                self.assertEqual(planned.target_basename, backup._ORDER[phase])
                self.assertEqual(planned.original_sha256,
                                 self.sources[phase].identity.original_sha256)
                self.assertEqual(planned.target_sha256,
                                 self.sources[phase].identity.target_sha256)
                self.assertFalse(planned.live_authorization)
                self.assertTrue(self._publish(phase).target_published)
                self.assertEqual(
                    self.authority.classify(
                        observed_application_digests=self._snapshot()[0],
                        executor=self._snapshot()[1],
                        broker=self._snapshot()[2],
                    ).completed_steps, phase + 1,
                )
        finished = self._prepare()
        self.assertEqual(finished.completed_steps, 5)
        self.assertEqual(finished.next_operation, "complete")
        self.assertIsNone(finished.target_basename)
        self.assertFalse(finished.live_authorization)
        self.assertEqual(self._snapshot()[2].expected_workflow_sha, _TEST_FINAL)

    def test_missing_fifth_backup_refuses_even_step_zero(self):
        """A partial backup cohort never yields a one-file publication plan."""
        self._seal_all()
        (self.private / backup._BACKUPS[-1]).unlink()
        with self.assertRaises(subject.C34LOnePrefixError):
            self._prepare()
        self.assertEqual((self.app / evidence.CHANGED[0]).read_bytes(),
                         self.old[evidence.CHANGED[0]])

    def test_corrupted_original_backup_refuses_recovery_at_second_phase(self):
        """Backups are all reread after a source has been atomically replaced."""
        self._seal_all()
        self._publish(0)
        (self.private / backup._BACKUPS[3]).write_bytes(b"tampered")
        with self.assertRaises(subject.C34LOnePrefixError):
            self._prepare()

    def test_out_of_order_config_and_unrelated_blob_change_refused(self):
        """A complete backup is never sufficient for an invalid source prefix."""
        self._seal_all()
        self._write_config(self.config / "dev.json",
                           self.target_broker.canonical_bytes())
        with self.assertRaises(subject.C34LOnePrefixError):
            self._prepare()
        self._write_config(self.config / "dev.json",
                           self.broker.canonical_bytes())
        unrelated = next(x for x in self.paths if x not in evidence.CHANGED)
        (self.app / unrelated).write_bytes(b"unreviewed-change")
        with self.assertRaises(subject.C34LOnePrefixError):
            self._prepare()

    def test_forged_file_hash_and_backup_identity_refused(self):
        """Every original and target digest is anchored in C34I's source seal."""
        self._seal_all()
        first = self.sources[0]
        changed = replace(
            first, identity=replace(first.identity, target_sha256="f" * 64),
        )
        with self.assertRaises(subject.C34LOnePrefixError):
            self._prepare(sources=(changed, *self.sources[1:]))
        with self.assertRaises(subject.C34LOnePrefixError):
            self._prepare(sources=(*self.sources[1:], self.sources[0]))

    def test_half_written_next_stage_keeps_prefix_plan_and_recovers(self):
        """A C34J stage fragment does not advance the source/config authority."""
        self._seal_all()
        staged = self.app / "deployment" / ".omnilyzer-c34j-broker.py.stage"
        staged.write_bytes(self.targets[0][:17])
        staged.chmod(0o600)
        self.assertEqual(self._prepare().completed_steps, 0)
        self._publish(0)
        self.assertEqual(self._prepare().completed_steps, 1)

    def test_private_fixture_remains_valid_under_strict_umask(self):
        """Server-style umask 077 must not silently change sandbox policy."""
        prior = os.umask(0o077)
        case = None
        try:
            case = type(self)("test_no_plan_can_claim_live_authorization")
            case.setUp()
            case._seal_all()
            self.assertEqual(case._prepare().completed_steps, 0)
        finally:
            if case is not None:
                case.doCleanups()
            os.umask(prior)

    def test_no_plan_can_claim_live_authorization(self):
        """The result is review-only, even when all backups and hashes match."""
        self._seal_all()
        p = self._prepare()
        with self.assertRaises(ValueError):
            replace(p, live_authorization=True)
        with self.assertRaises(ValueError):
            replace(p, target_basename="arbitrary.py")
        self.assertEqual(subject.__all__, (
            "C34LOnePrefixError", "C34LOnePrefixPlan",
            "prepare_c34l_one_prefix",
        ))


if __name__ == "__main__":
    unittest.main()
