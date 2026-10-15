"""File: deployment/tests/test_c34q_python_runtime_compatibility.py

Purpose: Reconcile the actual 73 Git source imports with existing C24 wheels,
C27 CPython, C31A environment, C31P pip and C32 Sigstore authority while
rejecting forged live runtime/root approval and unreviewed dependency drift.
Related: deployment/c34q_python_runtime_compatibility.py,
deployment/c34p_dependency_source_closure.py,
deployment/installation_integrity_contract.py,
deployment/python_environment_qualification.py,
deployment/tests/test_c34p_dependency_source_closure.py.

All Git reads use locally available immutable objects and disable lazy fetch.
Tests never access installed /opt or /etc, root identity, services, networking,
private keys or executables in the proposed 73-source code closure.
"""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from deployment import c34q_python_runtime_compatibility as subject
from deployment import c34p_dependency_source_closure as source
from deployment import installation_integrity_contract as integrity
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_executor_service_config import configuration_values


class C34QReadOnlyRuntimeRequirementTests(unittest.TestCase):
    """Revalidate fixed wheel/interpreter requirements against immutable Git."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load only local reviewed Git-object bytes without network fallback."""
        cls.root = Path(__file__).resolve().parents[2]
        cls.sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=cls.root,
            check=True, capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        cls.environment = dict(os.environ, GIT_NO_LAZY_FETCH="1")
        cls.configuration = DevExecutorServiceConfiguration(
            **configuration_values(reviewed_commit=cls.sha),
        )

    @classmethod
    def _blob(cls, path: str) -> bytes:
        """Use git cat-file on an explicit commit and path, never worktree."""
        return subprocess.run(
            ["git", "cat-file", "blob", cls.sha + ":" + path],
            cwd=cls.root, check=True, capture_output=True,
            timeout=10, env=cls.environment,
        ).stdout

    def _qualify(self, *, reader=None, config=None):
        """Ask only for static compatibility evidence, not a host inspection."""
        return subject.qualify_c34q_runtime_requirements(
            candidate_sha=self.sha,
            blob_reader=self._blob if reader is None else reader,
            executor_configuration=(
                self.configuration if config is None else config
            ),
        )

    def test_exact_c24_c27_c31_compatibility_without_host_approval(self):
        """Four reviewed wheels cover crypto and installed model distribution pins."""
        result = self._qualify()
        self.assertEqual(result.transitive_module_count, 73)
        self.assertEqual(result.python_version_series, "3.12")
        self.assertEqual(result.unresolved_import_roots, ("cryptography",))
        self.assertEqual(result.dependency_lock_sha256, integrity._LOCK[1])
        self.assertEqual(result.wheel_sha256_pairs, integrity._WHEELS)
        self.assertEqual(
            result.installed_tree_manifest_sha256_requirement,
            subject._environment._MANIFEST_SHA256,
        )
        self.assertTrue(result.runtime_requirement_consistent)
        self.assertFalse(result.installed_runtime_qualified)
        self.assertFalse(result.root_execution_approved)
        self.assertEqual(result, self._qualify())

    def test_tampered_lockfile_is_rejected_despite_old_requirement(self):
        """A forged Git-blob lock must not inherit prior SHA-256 trust."""
        def forged(path):
            """Change only dependency lock bytes, not other source blobs."""
            original = self._blob(path)
            return original + b" # unexpected" if path == integrity._LOCK[0] else original

        with self.assertRaises(subject.C34QPythonRuntimeError):
            self._qualify(reader=forged)

    def test_missing_transitive_blob_blocks_runtime_qualification(self):
        """Incomplete import provenance cannot be reconciled to C24."""
        def missing(path):
            """Deny the reviewed C34O root entrypoint while preserving lock."""
            if path == source._ENTRY:
                raise FileNotFoundError
            return self._blob(path)

        with self.assertRaises(subject.C34QPythonRuntimeError):
            self._qualify(reader=missing)

    def test_new_third_party_import_cannot_be_covered_implicitly(self):
        """A second package requires a new independently reviewed closure."""
        original = source.inspect_c34p_git_blob_closure(
            candidate_sha=self.sha, blob_reader=self._blob,
        )
        extended = replace(
            original,
            unresolved_third_party=("cryptography", "unknownpackage"),
        )
        with patch.object(subject._source, "inspect_c34p_git_blob_closure",
                          return_value=extended):
            with self.assertRaises(subject.C34QPythonRuntimeError):
                self._qualify()

    def test_missing_crypto_import_cannot_silently_remove_cryptography(self):
        """Changed import set still needs new review even if wheel pins remain."""
        original = source.inspect_c34p_git_blob_closure(
            candidate_sha=self.sha, blob_reader=self._blob,
        )
        stripped = replace(original, unresolved_third_party=())
        with patch.object(subject._source, "inspect_c34p_git_blob_closure",
                          return_value=stripped):
            with self.assertRaises(subject.C34QPythonRuntimeError):
                self._qualify()

    def test_wheel_count_or_binary_only_policy_cannot_be_relaxed(self):
        """The established four hashed wheel closure is mandatory."""
        with patch.object(subject._integrity, "_WHEELS", ()):
            with self.assertRaises(subject.C34QPythonRuntimeError):
                self._qualify()

    def test_untrusted_executor_configuration_is_rejected(self):
        """A raw dict cannot substitute for a canonical typed C17 authority."""
        with self.assertRaises(subject.C34QPythonRuntimeError):
            self._qualify(config={"reviewed_commit": self.sha})

    def test_bad_blob_reader_is_rejected(self):
        """No object source means no transitive dependency provenance."""
        with self.assertRaises(subject.C34QPythonRuntimeError):
            subject.qualify_c34q_runtime_requirements(
                candidate_sha=self.sha,
                blob_reader=None,
                executor_configuration=self.configuration,
            )

    def test_forged_host_qualification_and_root_approval_rejected(self):
        """Requirements consistent is never a claim that /opt was verified."""
        result = self._qualify()
        with self.assertRaises(ValueError):
            replace(result, installed_runtime_qualified=True)
        with self.assertRaises(ValueError):
            replace(result, root_execution_approved=True)
        with self.assertRaises(ValueError):
            replace(result, unresolved_import_roots=("other",))
        self.assertEqual(subject.__all__, (
            "C34QPythonRuntimeError",
            "C34QRuntimeCompatibilityReceipt",
            "qualify_c34q_runtime_requirements",
        ))


if __name__ == "__main__":
    unittest.main()
