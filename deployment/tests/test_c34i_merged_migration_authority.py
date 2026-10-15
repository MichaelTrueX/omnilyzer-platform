"""File: deployment/tests/test_c34i_merged_migration_authority.py

Purpose: Verify exact six-stage five-file migration/rollback contract can
bind to the true merged-main SHA, never to the old or draft C34E SHA.
Related: deployment/c34i_merged_migration_authority.py,
deployment/c34i_final_main_seal.py,
deployment/tests/test_c34g_migration_authority.py.

Synthetic final-main hash and Git manifests; no root, installed source,
network access, file mutation, systemd, registry or live promotion.
"""

from __future__ import annotations

from dataclasses import replace
import unittest
from unittest.mock import patch

from deployment import c34f_application_generation_evidence as original
from deployment import c34i_final_main_seal as seal
from deployment import c34i_merged_migration_authority as module
from deployment.application_manifest import DevApplicationManifest
from deployment.application_source_set import DevApplicationSourceSet
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_executor_service_config import configuration_values
from deployment.tests.test_broker_service_config import configuration_values as broker_values


FINAL = "abcdef0123456789abcdef0123456789abcdef01"


class C34IMergedAuthorityTests(unittest.TestCase):
    """Prove every allowed prefix and reject identity, SHA and source drift."""

    @classmethod
    def setUpClass(cls):
        """Prepare exact old and proposed Git blobs with a synthetic final SHA."""
        cls.paths = tuple(
            item.repository_path for item in DevApplicationSourceSet().files
        )
        cls.old_manifest = original._manifest(original.PREDECESSOR, cls.paths)
        proposal = original._manifest(original.C34E_PROPOSAL, cls.paths)
        cls.final_manifest = DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", FINAL,
            proposal.entries,
        )
        cls.receipt = seal.C34IFinalMainSourceSeal(
            FINAL, 41, original._digest(cls.final_manifest.canonical_bytes()),
            original.CHANGED, False,
        )
        cls.executor = DevExecutorServiceConfiguration(
            **configuration_values(reviewed_commit=original.PREDECESSOR)
        )
        aligned = {
            k: getattr(cls.executor, k) for k in module.draft._SHARED
        }
        cls.broker = DevBrokerServiceConfiguration(
            **broker_values(
                reviewed_commit=original.PREDECESSOR,
                expected_workflow_sha=original.C34D_MAIN,
                **aligned,
            )
        )

    def _make_authority(self):
        """Patch only local final Git provenance for deterministic acceptance."""
        def choose(commit, paths):
            """Bind old and synthetic final source without untrusted fallback."""
            if paths != self.paths:
                raise ValueError
            if commit == original.PREDECESSOR:
                return self.old_manifest
            if commit == FINAL:
                return self.final_manifest
            raise ValueError

        with patch.object(module.final, "prepare_c34i_final_main_source_seal",
                          return_value=self.receipt), patch.object(
                              module.evidence, "_manifest", side_effect=choose
                          ):
            return module.C34IMergedMigrationAuthority(
                source_seal=self.receipt,
                predecessor_executor=self.executor,
                predecessor_broker=self.broker,
            )

    def _source_prefix(self, phase):
        """Produce a completely canonical 41-file source snapshot."""
        old = tuple((v.path, v.sha256) for v in self.old_manifest.entries)
        new = tuple((v.path, v.sha256) for v in self.final_manifest.entries)
        return tuple(
            (name, target if name in original.CHANGED[:min(phase, 3)] else prior)
            for (name, prior), (_, target) in zip(old, new, strict=True)
        )

    def test_all_six_final_main_prefixes_and_reverse_operations(self):
        """Source/config ordering remains byte-identical to reviewed C34G."""
        authority = self._make_authority()
        new_executor, new_broker = authority.target_configuration_pair()
        for phase in range(6):
            with self.subTest(phase=phase):
                state = authority.classify(
                    observed_application_digests=self._source_prefix(phase),
                    executor=new_executor if phase >= 4 else self.executor,
                    broker=new_broker if phase >= 5 else self.broker,
                )
                self.assertEqual(state.completed_steps, phase)
                self.assertEqual(
                    state.next_operation, module.draft._OPERATIONS[phase]
                )
                self.assertEqual(state.target_main_commit, FINAL)
                self.assertIsInstance(state.rollback_operation(), str)

    def test_wrong_sequence_and_workflow_sha_fail_closed(self):
        """Reject advanced configs and a changed workflow trust revision."""
        authority = self._make_authority()
        new_executor, new_broker = authority.target_configuration_pair()
        cases = (
            (0, new_executor, self.broker),
            (2, new_executor, self.broker),
            (3, self.executor, new_broker),
            (4, new_executor, replace(new_broker,
                                      expected_workflow_sha="f" * 40)),
        )
        for phase, executor, broker in cases:
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                authority.classify(
                    observed_application_digests=self._source_prefix(phase),
                    executor=executor, broker=broker,
                )

    def test_arbitrary_blob_drift_fails_closed(self):
        """Other 38 protected files must be byte-identical to predecessor."""
        authority = self._make_authority()
        altered = list(self._source_prefix(0))
        altered[-1] = (altered[-1][0], "f" * 64)
        with self.assertRaises(ValueError):
            authority.classify(
                observed_application_digests=tuple(altered),
                executor=self.executor, broker=self.broker,
            )

    def test_altered_external_source_seal_refused(self):
        """A forged final-main manifest hash cannot become an authority."""
        bad = replace(self.receipt, source_manifest_sha256="f" * 64)
        with patch.object(module.final,
                          "prepare_c34i_final_main_source_seal",
                          return_value=self.receipt):
            with self.assertRaises(ValueError):
                module.C34IMergedMigrationAuthority(
                    source_seal=bad, predecessor_executor=self.executor,
                    predecessor_broker=self.broker,
                )

    def test_forged_state_and_public_surface(self):
        """No draft/main shortcut or executable mutation is exposed."""
        with self.assertRaises(ValueError):
            module.C34IMergedMigrationState(
                4, "complete", FINAL,
            )
        with self.assertRaises(ValueError):
            module.C34IMergedMigrationState(
                0, module.draft._OPERATIONS[0], original.C34E_PROPOSAL,
            )
        self.assertEqual(module.__all__, (
            "C34IMergedMigrationState",
            "C34IMergedMigrationAuthority",
        ))


if __name__ == "__main__":
    unittest.main()
