"""File: deployment/tests/test_c34g_migration_authority.py

Purpose: Prove six permitted five-file migration prefixes, exact config-only
revision changes, and rejection of unsafe mixed/forged states.
Related: deployment/c34g_migration_authority.py,
deployment/c34f_application_generation_evidence.py,
deployment/tests/test_c34f_application_generation_evidence.py.

Pure synthetic configuration fixtures; no privileged host I/O, Docker,
service changes, credentials or live promotion calls.
"""

from __future__ import annotations

from dataclasses import replace
import unittest

from deployment import c34f_application_generation_evidence as proof
from deployment import c34g_migration_authority as subject
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.application_source_set import DevApplicationSourceSet
from deployment.tests.test_executor_service_config import configuration_values
from deployment.tests.test_broker_service_config import configuration_values as broker_values


class C34GPrefixTests(unittest.TestCase):
    """Exercise exact old-to-new prefixes and all nearby rejection states."""

    @classmethod
    def setUpClass(cls) -> None:
        """Construct immutable Git manifests and one synthetic current config pair."""
        cls.paths = tuple(
            item.repository_path for item in DevApplicationSourceSet().files
        )
        cls.old_manifest = proof._manifest(proof.PREDECESSOR, cls.paths)
        cls.new_manifest = proof._manifest(proof.C34E_PROPOSAL, cls.paths)
        cls.old_executor = DevExecutorServiceConfiguration(
            **configuration_values(reviewed_commit=proof.PREDECESSOR)
        )
        shared = {
            name: getattr(cls.old_executor, name)
            for name in subject._SHARED
        }
        cls.old_broker = DevBrokerServiceConfiguration(
            **broker_values(
                reviewed_commit=proof.PREDECESSOR,
                expected_workflow_sha=proof.C34D_MAIN,
                **shared,
            )
        )
        cls.authority = subject.C34GMigrationAuthority(
            predecessor_manifest=cls.old_manifest,
            proposal_manifest=cls.new_manifest,
            predecessor_executor=cls.old_executor,
            predecessor_broker=cls.old_broker,
        )
        cls.new_executor, cls.new_broker = cls.authority.target_configuration_pair()
        cls.old = tuple((item.path, item.sha256) for item in cls.old_manifest.entries)
        cls.new = tuple((item.path, item.sha256) for item in cls.new_manifest.entries)

    @classmethod
    def _prefix(cls, count: int) -> tuple[tuple[str, str], ...]:
        """Return exactly count updated source modules and other 38 old hashes."""
        return tuple(
            (name, newsha if name in proof.CHANGED[:count] else oldsha)
            for (name, oldsha), (_, newsha) in zip(cls.old, cls.new, strict=True)
        )

    def test_all_six_legal_prefixes(self) -> None:
        """Classify three source swaps, two config swaps and completion."""
        for prefix in range(6):
            with self.subTest(prefix=prefix):
                state = self.authority.classify(
                    observed_application_digests=self._prefix(min(prefix, 3)),
                    executor=self.new_executor if prefix >= 4 else self.old_executor,
                    broker=self.new_broker if prefix >= 5 else self.old_broker,
                )
                self.assertEqual(state.completed_steps, prefix)
                self.assertEqual(state.next_operation, subject._OPERATIONS[prefix])
                self.assertEqual(state.proposal_commit, proof.C34E_PROPOSAL)

    def test_disorder_and_mixed_configs_fail_closed(self) -> None:
        """Reject changed source order and prematurely updated config pairs."""
        out_of_order = tuple(
            (name, newsha if name == proof.CHANGED[1] else oldsha)
            for (name, oldsha), (_, newsha) in zip(self.old, self.new, strict=True)
        )
        combinations = (
            (out_of_order, self.old_executor, self.old_broker),
            (self.old, self.new_executor, self.old_broker),
            (self._prefix(2), self.new_executor, self.old_broker),
            (self._prefix(3), self.old_executor, self.new_broker),
            (self._prefix(3), self.new_executor, self.new_broker),
            (self._prefix(3), self.new_executor,
             replace(self.new_broker, expected_workflow_sha="f" * 40)),
        )
        for hashes, executor, broker in combinations:
            with self.subTest(executor=executor.reviewed_commit,
                              broker=broker.reviewed_commit):
                with self.assertRaisesRegex(ValueError, "C34G protected"):
                    self.authority.classify(
                        observed_application_digests=hashes,
                        executor=executor,
                        broker=broker,
                    )

    def test_changed_digest_and_unlisted_path_fail_closed(self) -> None:
        """Reject one extra source change, forged path, or malformed hash."""
        original = list(self.old)
        for changed in (
            [*original[:-1], (original[-1][0], "f" * 64)],
            [("deployment/malicious.py", original[0][1]), *original[1:]],
            [*original[:-1], (original[-1][0], "not-sha256")],
        ):
            with self.subTest(candidate=changed[-1]):
                with self.assertRaises(ValueError):
                    self.authority.classify(
                        observed_application_digests=tuple(changed),
                        executor=self.old_executor, broker=self.old_broker,
                    )

    def test_source_update_preserves_existing_workflow_pin(self) -> None:
        """Only reviewed_commit changes in each of the two canonical configs."""
        self.assertEqual(self.old_broker.expected_workflow_sha, proof.C34D_MAIN)
        self.assertEqual(self.new_broker.expected_workflow_sha, proof.C34D_MAIN)
        for before, after in (
            (self.old_executor, self.new_executor),
            (self.old_broker, self.new_broker),
        ):
            b, a = before.to_dict(), after.to_dict()
            self.assertEqual(
                {name for name in b if b[name] != a[name]}, {"reviewed_commit"}
            )
            self.assertEqual(a["reviewed_commit"], proof.C34E_PROPOSAL)

    def test_forged_config_identity_and_manifest_fail_closed(self) -> None:
        """Changing an identity or using an unpinned manifest cannot construct."""
        with self.assertRaises(ValueError):
            subject.C34GMigrationAuthority(
                predecessor_manifest=self.old_manifest,
                proposal_manifest=self.new_manifest,
                predecessor_executor=self.old_executor,
                predecessor_broker=replace(self.old_broker,
                                           reviewed_commit="f" * 40),
            )
        with self.assertRaises(ValueError):
            subject.C34GMigrationAuthority(
                predecessor_manifest=self.old_manifest,
                proposal_manifest=self.old_manifest,
                predecessor_executor=self.old_executor,
                predecessor_broker=self.old_broker,
            )

    def test_forged_state_and_public_api(self) -> None:
        """The state and exposed operations cannot be caller-selected."""
        with self.assertRaises(ValueError):
            subject.C34GMigrationState(2, "complete", proof.C34E_PROPOSAL)
        with self.assertRaises(ValueError):
            subject.C34GMigrationState(True, subject._OPERATIONS[1], proof.C34E_PROPOSAL)
        self.assertEqual(subject.__all__, ("C34GMigrationAuthority", "C34GMigrationState"))


if __name__ == "__main__":
    unittest.main()
