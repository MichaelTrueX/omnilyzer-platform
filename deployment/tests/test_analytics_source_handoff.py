"""File: deployment/tests/test_analytics_source_handoff.py

Purpose: Qualify the exact 20+4+3 additive Analytics Task014 Git-object
         package against the original 40-module canary app source contract.
Related: deployment/analytics_source_handoff.py,
         deployment/application_manifest.py (original Git read-only reader),
         deployment/analytics_executor_service_config.py,
         deployment/tests/test_analytics_executor_service_bootstrap.py.

Sections: real Git HEAD object-based manifest; source claim/profile binding;
          invalid commit/repository; immutable Git blobs vs working tree;
          tampered file content and cross-product omission rejection.

No Git push, network, file provisioning, host root write, Docker, secrets,
systemd or PostgreSQL access. Returned manifest is NOT deployment authority.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import deployment.analytics_source_handoff as handoff
from deployment.analytics_source_handoff import (
    AnalyticsSourceHandoffError, review_analytics_source_handoff,
)
from deployment.analytics_executor_service_config import (
    ANALYTICS_INSTALLED_FILES, _INSTALLED_RUNTIME_FILES,
    _SOURCE_CLAIM_PATH, _SOURCE_CLAIM_SHA256,
)
from deployment.analytics_source_handoff import (
    _SHARED_BASE_COMMIT, _SHARED_COMPATIBILITY_FILES,
    _SHARED_PREIMAGE_SHA256, _SHARED_PREIMAGE_COMMITS,
)
from deployment.application_source_set import DevApplicationSourceSet

ROOT = Path(__file__).resolve().parents[2]


def source_commit() -> str:
    """Read one local immutable Git HEAD; do not fetch a mutable branch."""
    return subprocess.check_output(
        ("/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"),
        stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
    ).strip()


class AdditiveSourceHandoffTests(unittest.TestCase):
    """Reuse original C26 Git content proofs, with no new install power."""

    def test_real_git_object_manifest_is_exact_and_never_authorizes_deploy(self):
        """One real Git review binds 27 additions plus four shared patches."""
        raw = review_analytics_source_handoff(
            repository_root=str(ROOT), reviewed_commit=source_commit(),
        )
        manifest = json.loads(raw)
        self.assertEqual(manifest["source_commit"], source_commit())
        self.assertEqual(manifest["source_file_count"], 31)
        self.assertIs(manifest["signed_release_authorized"], False)
        self.assertIs(manifest["deployment_authorized"], False)
        self.assertEqual(
            set(manifest), {
                "schema_version", "purpose", "source_commit", "source_repository",
                "source_file_count", "source_entries",
                "reviewed_compose_sha256", "reviewed_product_profile_sha256",
                "reviewed_runtime_profile_sha256", "reviewed_source_claim_sha256",
                "signed_release_authorized", "deployment_authorized",
                "shared_base_source_commit", "shared_patch_paths",
                "shared_preimage_sha256", "shared_preimage_commits",
                "inherited_canary_sha256", "isolation_target",
            },
        )
        entries = manifest["source_entries"]
        self.assertEqual(len(entries), 31)
        self.assertEqual(manifest["isolation_target"],
                         "/opt/omnilyzer/deployment/analytics-app")
        self.assertEqual(len(manifest["inherited_canary_sha256"]), 39)
        self.assertEqual(
            set(manifest["inherited_canary_sha256"]),
            {x.repository_path for x in DevApplicationSourceSet().files}
            - set(_SHARED_COMPATIBILITY_FILES),
        )
        self.assertEqual(manifest["shared_base_source_commit"], _SHARED_BASE_COMMIT)
        self.assertEqual(manifest["shared_patch_paths"],
                         list(_SHARED_COMPATIBILITY_FILES))
        self.assertEqual(manifest["shared_preimage_sha256"],
                         _SHARED_PREIMAGE_SHA256)
        self.assertEqual(manifest["shared_preimage_commits"],
                         _SHARED_PREIMAGE_COMMITS)

        self.assertEqual(manifest["reviewed_source_claim_sha256"], _SOURCE_CLAIM_SHA256)
        self.assertEqual(manifest["reviewed_product_profile_sha256"],
                         "e54bad9537541c7ecc4056753e8cbddbf6653d53deb1be222daf2b9ffe1659f0")
        self.assertEqual(manifest["reviewed_runtime_profile_sha256"],
                         "95fd22e7a406bbc90d1f014e29fc8564028adae9dd352abfece46c3b24faf661")
        self.assertEqual(
            [item["path"] for item in entries],
            sorted(item["path"] for item in entries),
        )
        names = {item["path"] for item in entries}
        self.assertEqual(
            names & {x.repository_path for x in DevApplicationSourceSet().files},
            set(_SHARED_COMPATIBILITY_FILES),
        )
        self.assertEqual(len(names.intersection(ANALYTICS_INSTALLED_FILES)), 20)
        self.assertEqual(len(names.intersection(_INSTALLED_RUNTIME_FILES)), 4)
        self.assertEqual(
            next(item["sha256"] for item in entries
                 if item["path"] == _SOURCE_CLAIM_PATH), _SOURCE_CLAIM_SHA256,
        )
        for item in entries:
            self.assertEqual(item["mode"], "0644")
            self.assertEqual(len(item["sha256"]), 64)
        self.assertLess(len(raw), 16384)
        self.assertEqual(raw, handoff.canonical_bytes(manifest))

    def test_three_shared_preimages_match_original_protected_git_blobs(self):
        """A real DEV preimage mismatch must abort before a shared-file write."""
        from deployment import application_manifest as git
        for name in _SHARED_COMPATIBILITY_FILES:
            commit = _SHARED_PREIMAGE_COMMITS[name]
            record = git._tree(git._output(str(ROOT), (
                "ls-tree", "-r", "-z", "--full-tree", commit, "--", name,
            ), 8192), (name,))
            blob = git._output(str(ROOT), ("cat-file", "blob", record[0][1]),
                               1024 * 1024)
            self.assertEqual(hashlib.sha256(blob).hexdigest(),
                             _SHARED_PREIMAGE_SHA256[name])

    def test_wrong_git_revision_and_invalid_repository_denied(self):
        """A mutable branch string, guessed SHA or fake source path is NO grant."""
        sha = source_commit()
        wrongs = (
            ("main", str(ROOT)),
            ("0" * 40, str(ROOT)),
            ("a" * 40, str(ROOT)),
            (sha.upper(), str(ROOT)),
            (sha, str(ROOT / "deployment")),
            (sha, "/tmp/does-not-exist"),
            (sha, "."),
        )
        for review, root in wrongs:
            with self.subTest(commit=review, repo=root), self.assertRaises(
                AnalyticsSourceHandoffError,
            ):
                review_analytics_source_handoff(
                    repository_root=root, reviewed_commit=review,
                )

    def test_git_object_not_mutable_worktree_is_source(self):
        """Even a hidden working-tree edit cannot influence reviewed Git blobs."""
        raw = review_analytics_source_handoff(
            repository_root=str(ROOT), reviewed_commit=source_commit(),
        )
        with patch.object(
            Path, "read_bytes",
            side_effect=AssertionError("working-tree file read is not allowed"),
        ):
            self.assertEqual(
                review_analytics_source_handoff(
                    repository_root=str(ROOT), reviewed_commit=source_commit(),
                ),
                raw,
            )

    def test_tampered_signed_source_claim_blob_is_denied(self):
        """Wrong release-claim bytes fail without an install or raw-digest grant."""
        original_output = handoff._git._output
        touched = []

        def corrupted_blob(root, arguments, maximum):
            """Only change signed source claim blob, never alter Git itself."""
            result = original_output(root, arguments, maximum)
            if arguments[:2] == ("cat-file", "blob"):
                # Identify by exact Git content fingerprint without path input.
                if hashlib.sha256(result).hexdigest() == _SOURCE_CLAIM_SHA256:
                    touched.append(1)
                    return result[:-1] + (b"0" if result[-1:] != b"0" else b"1")
            return result

        with patch.object(handoff._git, "_output", side_effect=corrupted_blob):
            with self.assertRaises(AnalyticsSourceHandoffError):
                review_analytics_source_handoff(
                    repository_root=str(ROOT), reviewed_commit=source_commit(),
                )
        self.assertEqual(touched, [1])

    def test_original_canary_selection_remains_untouched(self):
        """No generic future installer source allowlist is changed."""
        originals = {
            item.repository_path for item in DevApplicationSourceSet().files
        }
        self.assertEqual(len(originals), 43)
        self.assertTrue(originals.isdisjoint(ANALYTICS_INSTALLED_FILES))
        self.assertTrue(originals.isdisjoint(_INSTALLED_RUNTIME_FILES))
        self.assertEqual(set(_SHARED_COMPATIBILITY_FILES) & originals,
                         set(_SHARED_COMPATIBILITY_FILES))
        self.assertEqual(len(_SHARED_PREIMAGE_SHA256), 4)


if __name__ == "__main__":
    unittest.main()
