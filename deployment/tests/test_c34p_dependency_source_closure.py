"""File: deployment/tests/test_c34p_dependency_source_closure.py

Purpose: Qualify nonexecuting AST-derived Git-object dependency provenance,
dynamic import rejection, missing-object HOLD and immutable review-only
receipts for Task 014 privileged code packaging.
Related: deployment/c34p_dependency_source_closure.py,
deployment/c34o_six_prefix_recovery_inspection.py,
deployment/c34n_root_predecessor_adapter.py,
docs/operations/task014-c34p-transitive-python-provenance.md.

Only local immutable Git blob reads; no installed server paths, third-party
import execution, root escalation, network, systemd, deploy or source writes.
"""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import subprocess
import unittest

from deployment import c34p_dependency_source_closure as subject


# Section 1: A closed synthetic dependency graph with one cycle.
_SHA = "a" * 40
_ENTRY = subject._ENTRY
_PACKAGE = subject._PACKAGE


def _fixture_reader(mapping):
    """Return one byte-only fake immutable blob reader for unit tests."""
    def read(name):
        """Reject any missing blob; no filesystem path is traversed."""
        return mapping[name]
    return read


class C34PStaticImportTests(unittest.TestCase):
    """Ensure the AST inventory cannot authorize executing unknown modules."""

    def setUp(self):
        """Create a small synthetic import closure entirely as in-memory bytes."""
        self.modules = {
            _PACKAGE: b'"""Empty package root."""\n',
            _ENTRY: (
                b"from . import alpha\n"
                b"import hashlib\n"
                b"from cryptography.hazmat.primitives import hashes\n"
            ),
            "deployment/alpha.py": b"from . import beta\n",
            "deployment/beta.py": b"from . import alpha\n",
        }

    def _check(self, modules=None):
        """Run a pure closure audit without importing any inspected source."""
        return subject.inspect_c34p_git_blob_closure(
            candidate_sha=_SHA,
            blob_reader=_fixture_reader(
                self.modules if modules is None else modules
            ),
        )

    def test_closed_cycle_has_sorted_digest_provenance_and_dependency_hold(self):
        """Cycles terminate; third-party crypto remains explicitly unresolved."""
        receipt = self._check()
        self.assertEqual(receipt.local_module_count, 4)
        self.assertEqual(
            tuple(name for name, _ in receipt.local_source_blobs),
            tuple(sorted(self.modules)),
        )
        self.assertEqual(receipt.unresolved_third_party, ("cryptography",))
        self.assertTrue(receipt.requires_dependency_review)
        self.assertFalse(receipt.root_execution_approved)
        self.assertEqual(receipt, self._check())

    def test_missing_transitive_import_fails_closed(self):
        """Missing a single relative module can never yield a partial seal."""
        modules = dict(self.modules)
        del modules["deployment/beta.py"]
        with self.assertRaises(subject.C34PSourceClosureError):
            self._check(modules)

    def test_changed_payload_changes_manifest_hash(self):
        """A source byte change produces a different canonical source seal."""
        old = self._check()
        modules = dict(self.modules)
        modules["deployment/beta.py"] += b"# changed\n"
        new = self._check(modules)
        self.assertNotEqual(
            old.closure_manifest_sha256, new.closure_manifest_sha256
        )

    def test_reject_dynamic_import_and_source_execution(self):
        """No runtime-added dependency may be silently omitted."""
        for unsafe in (
            b"__import__('os')\n",
            b"importlib.import_module('deployment.alpha')\n",
            b"exec('pass')\n",
            b"eval('2')\n",
            b"compile('x','y','exec')\n",
        ):
            with self.subTest(code=unsafe):
                modules = dict(self.modules)
                modules["deployment/alpha.py"] = unsafe
                with self.assertRaises(subject.C34PSourceClosureError):
                    self._check(modules)

    def test_wildcard_parent_relative_and_nested_imports_rejected(self):
        """Do not infer provenance for unreviewed import resolution patterns."""
        for unsafe in (
            b"from .alpha import *\n",
            b"from .. import secrets\n",
            b"from .nested.alpha import anything\n",
            b"from deployment.deep.child import unknown\n",
        ):
            with self.subTest(code=unsafe):
                modules = dict(self.modules)
                modules[_ENTRY] = unsafe
                with self.assertRaises(subject.C34PSourceClosureError):
                    self._check(modules)

    def test_malformed_commit_and_untrusted_blob_fail_closed(self):
        """Never accept a short commit SHA, string blob or parse failure."""
        with self.assertRaises(subject.C34PSourceClosureError):
            subject.inspect_c34p_git_blob_closure(
                candidate_sha="short",
                blob_reader=_fixture_reader(self.modules),
            )
        data = dict(self.modules)
        data[_ENTRY] = "not bytes"
        with self.assertRaises(subject.C34PSourceClosureError):
            self._check(data)
        data[_ENTRY] = b"def malformed(:\n"
        with self.assertRaises(subject.C34PSourceClosureError):
            self._check(data)

    def test_changing_blob_reader_between_passes_is_a_hold(self):
        """Never seal a manifest assembled from an unstable object source."""
        calls = {}

        def mutable_reader(path):
            """Return a changed transitive blob on its second read only."""
            calls[path] = calls.get(path, 0) + 1
            raw = self.modules[path]
            if path == "deployment/alpha.py" and calls[path] > 1:
                return raw + b"# changed-after-first-pass\\n"
            return raw

        with self.assertRaises(subject.C34PSourceClosureError):
            subject.inspect_c34p_git_blob_closure(
                candidate_sha=_SHA,
                blob_reader=mutable_reader,
            )

    def test_receipt_cannot_claim_privileged_approval(self):
        """Receipt cannot be promoted into a root installation capability."""
        result = self._check()
        with self.assertRaises(ValueError):
            replace(result, root_execution_approved=True)
        with self.assertRaises(ValueError):
            replace(result, local_source_blobs=tuple(reversed(result.local_source_blobs)))
        self.assertEqual(subject.__all__, (
            "C34PSourceClosureError",
            "C34PSourceClosureReceipt",
            "inspect_c34p_git_blob_closure",
        ))


class C34PActualGitSourceTests(unittest.TestCase):
    """Read only local Git objects from a pinned *review candidate* checkout."""

    def test_real_c34o_closure_records_complete_local_graph_and_crypto_hold(self):
        """Discover nonobvious imported host modules without executing any."""
        root = Path(__file__).resolve().parents[2]
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True,
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        self.assertRegex(revision, r"^[0-9a-f]{40}$")
        environment = dict(os.environ, GIT_NO_LAZY_FETCH="1")

        def immutable_blob(path):
            """Get only a path in the named Git commit, no lazy network fetch."""
            result = subprocess.run(
                ["git", "cat-file", "blob", revision + ":" + path],
                cwd=root, check=True, capture_output=True, timeout=10,
                env=environment,
            )
            return result.stdout

        result = subject.inspect_c34p_git_blob_closure(
            candidate_sha=revision,
            blob_reader=immutable_blob,
        )
        self.assertEqual(result.local_module_count, 73)
        self.assertIn(
            "deployment/c34o_six_prefix_recovery_inspection.py",
            dict(result.local_source_blobs),
        )
        self.assertIn(
            "deployment/state_store_successor_host_migration_runtime.py",
            dict(result.local_source_blobs),
        )
        self.assertEqual(result.unresolved_third_party, ("cryptography",))
        self.assertFalse(result.root_execution_approved)
        self.assertEqual(
            result.closure_manifest_sha256,
            subject.inspect_c34p_git_blob_closure(
                candidate_sha=revision, blob_reader=immutable_blob,
            ).closure_manifest_sha256,
        )


if __name__ == "__main__":
    unittest.main()
