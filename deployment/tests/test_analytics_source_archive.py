"""File: deployment/tests/test_analytics_source_archive.py

Purpose: End-to-end deterministic original-C26 Git-object Analytics additive
         installer-archive evidence, exact 27 member validation and negative
         archive/security tests; all filesystem work is disposable.
Related: deployment/analytics_source_archive.py,
         deployment/analytics_source_handoff.py,
         deployment/tests/test_analytics_source_handoff.py,
         deployment/application_source_set.py.

Sections: real immutable Git round-trip, reproducibility, private disposable
          source tree, malformed TAR and source manipulation denial, original
          closed canary overlap regression and zero host-install operations.

No actual root service, network, database, secrets, promotion or Docker.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from deployment.analytics_source_archive import (
    AnalyticsSourceArchiveError,
    build_analytics_source_archive,
    verify_analytics_source_archive,
)
from deployment.analytics_source_handoff import review_analytics_source_handoff
from deployment.application_source_set import DevApplicationSourceSet
from deployment import application_manifest as original_manifest
from deployment import dev_host_provisioning_mechanics as original_materialization

ROOT = Path(__file__).resolve().parents[2]


def _identities():
    """Resolve exact current Git source and its independently computed digest."""
    root = str(ROOT)
    sha = subprocess.check_output(
        ("/usr/bin/git", "-C", root, "rev-parse", "HEAD"),
        stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True,
    ).strip()
    manifest = review_analytics_source_handoff(
        repository_root=root, reviewed_commit=sha,
    )
    return root, sha, hashlib.sha256(manifest).hexdigest()


class OriginalC26ArchiveTests(unittest.TestCase):
    """Canonical archive is source evidence only, never an installation grant."""

    @classmethod
    def setUpClass(cls):
        """Read the real Git objects once to avoid redundant full blob builds."""
        cls.root, cls.sha, cls.manifest_sha = _identities()
        cls.archive = build_analytics_source_archive(
            repository_root=cls.root, reviewed_commit=cls.sha,
        )

    def inspect(self, blob=None, digest=None, commit=None):
        """Use explicit trusted digest and Git commit, never archive claims."""
        return verify_analytics_source_archive(
            self.archive if blob is None else blob,
            expected_manifest_sha256=(
                self.manifest_sha if digest is None else digest
            ),
            reviewed_commit=self.sha if commit is None else commit,
        )

    def test_real_git_archive_roundtrip_and_rebuild_is_deterministic(self):
        """Original immutable Git blobs survive exact canonical TAR transport."""
        source = self.inspect()
        self.assertEqual(len(source), 27)
        self.assertEqual(
            tuple(name for name, _ in source),
            tuple(sorted(name for name, _ in source)),
        )
        self.assertLess(len(self.archive), 14 * 1024 * 1024)
        self.assertEqual(self.archive, build_analytics_source_archive(
            repository_root=self.root, reviewed_commit=self.sha,
        ))
        self.assertIn(
            ("release/products/analytics-source.json", (
                ROOT / "release/products/analytics-source.json"
            ).read_bytes()), source,
        )
        with tarfile.open(fileobj=io.BytesIO(self.archive), mode="r:") as tar:
            self.assertEqual(len(tar.getmembers()), 28)
            self.assertEqual(
                tar.getmembers()[0].name,
                ".omnilyzer-analytics-source-review.json",
            )
            self.assertTrue(all(
                x.isfile() and x.mode == 0o644
                and x.uid == x.gid == x.mtime == 0
                for x in tar.getmembers()
            ))

    def test_complete_disposable_70_file_overlay_preserves_original_canary(self):
        """Use real Git objects for all ORIGINAL 43 files, then 27 Analytics.

        Original Task014 C31B verifies the 43-file rootless TEST tree before
        the additive review bytes are staged. All 43 originals remain exact;
        a missing, added or modified old file fails original preflight.
        This is a disposable fixture, NOT a privileged installation API.
        """
        sources = self.inspect()
        original_names = tuple(
            item.repository_path for item in DevApplicationSourceSet().files
        )
        self.assertEqual(len(original_names), 43)
        self.assertTrue(set(original_names).isdisjoint(
            {name for name, _ in sources}
        ))
        original_tree = original_manifest._tree(
            original_manifest._output(self.root, (
                "ls-tree", "-r", "-z", "--full-tree", self.sha,
                "--", *original_names,
            ), 32768),
            original_names,
        )
        original_blobs = {
            name: original_manifest._output(
                self.root, ("cat-file", "blob", git_oid), 1024 * 1024,
            )
            for name, git_oid in original_tree
        }
        initial = original_manifest.DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", self.sha,
            tuple(
                original_manifest.ApplicationManifestEntry(
                    name, hashlib.sha256(original_blobs[name]).hexdigest(),
                    "0644",
                )
                for name in original_names
            ),
        )
        with tempfile.TemporaryDirectory(prefix="m05-14-70file-overlay-") as temp:
            app = Path(temp) / "app"
            app.mkdir(mode=0o755)
            app.chmod(0o755)
            for name, payload in original_blobs.items():
                file = app / name
                file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                # Explicitly normalize nested dirs; test runner may use umask077.
                for parent in (file.parent, *file.parent.parents):
                    if parent == app.parent:
                        break
                    parent.chmod(0o755)
                file.write_bytes(payload)
                file.chmod(0o644)
            descriptor = os.open(app, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                original_materialization._verify_application(
                    descriptor, initial, os.getuid(), os.getgid(),
                )
            finally:
                os.close(descriptor)
            for name, payload in sources:
                file = app / name
                self.assertFalse(file.exists())
                file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                # Explicitly normalize nested dirs; test runner may use umask077.
                for parent in (file.parent, *file.parent.parents):
                    if parent == app.parent:
                        break
                    parent.chmod(0o755)
                file.write_bytes(payload)
                file.chmod(0o644)
            self.assertEqual(sum(
                1 for item in app.rglob("*") if item.is_file()
            ), 70)
            for name, original in original_blobs.items():
                self.assertEqual((app / name).read_bytes(), original, name)
            for name, payload in sources:
                self.assertEqual((app / name).read_bytes(), payload, name)
            self.assertEqual(
                hashlib.sha256((
                    app / "release/products/analytics-source.json"
                ).read_bytes()).hexdigest(),
                "45e13536c413a5e5c0a39a4d8c98daf412614dec535398b2ba204039772c88b9",
            )
            # The original verifier MUST reject the new files if the old
            # canary-only manifest were reused as the additive installer.
            descriptor = os.open(app, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(OSError):
                    original_materialization._verify_application(
                        descriptor, initial, os.getuid(), os.getgid(),
                    )
            finally:
                os.close(descriptor)

    def test_bad_expected_authority_digest_commit_and_mutation_fail(self):
        """Caller-generated bytes cannot override externally reviewed digest."""
        for kwargs in (
            {"digest": "0" * 64},
            {"digest": "z" * 64},
            {"commit": "0" * 40},
            {"commit": "a" * 40},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(
                AnalyticsSourceArchiveError,
            ):
                self.inspect(**kwargs)
        raw = bytearray(self.archive)
        # Change the first payload region after the first TAR header; the
        # manifest digest is checked independent of the archive checksum.
        raw[512] ^= 0x01
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(blob=bytes(raw))

    def test_alternative_tar_headers_and_garbage_are_rejected(self):
        """Reject appendages, unsorted members, wrong modes and symlink types."""
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(blob=self.archive + b"EXTRA")
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(blob=self.archive + b"\0" * 10240)
        # Change an original USTAR mode header then recalculate checksum:
        # a syntactically valid archive is still not our reviewed archive.
        raw = bytearray(self.archive)
        raw[100:108] = b"0000777\0"
        raw[148:156] = b"        "
        checksum = sum(raw[:512])
        raw[148:156] = ("%06o\0 " % checksum).encode("ascii")
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(blob=bytes(raw))
        raw = bytearray(self.archive)
        raw[156] = ord("2")  # symlink TAR type
        raw[148:156] = b"        "
        checksum = sum(raw[:512])
        raw[148:156] = ("%06o\0 " % checksum).encode("ascii")
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(blob=bytes(raw))

    def test_reject_path_injection_even_with_rebuilt_checksum(self):
        """Unsafe member path cannot become an installed file."""
        raw = bytearray(self.archive)
        # Locate the actual SECOND TAR header after the variable-sized
        # source-review manifest. Mutate the HEADER, not file body/padding.
        with tarfile.open(fileobj=io.BytesIO(self.archive), mode="r:") as tar:
            second_offset = tar.getmembers()[1].offset
        raw[second_offset:second_offset + 6] = b"../bad"
        raw[second_offset + 148:second_offset + 156] = b"        "
        checksum = sum(raw[second_offset:second_offset + 512])
        raw[second_offset + 148:second_offset + 156] = (
            "%06o\0 " % checksum
        ).encode("ascii")
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(blob=bytes(raw))

    def test_inert_build_never_opens_root_or_net(self):
        """A source reader is NOT a root installer or privileged action."""
        with patch("os.chown", side_effect=AssertionError("no chown")), patch(
            "os.chmod", side_effect=AssertionError("no chmod"),
        ), patch(
            "os.mkdir", side_effect=AssertionError("no mkdir"),
        ), patch(
            "subprocess.run", side_effect=AssertionError("must use C26 only"),
        ):
            archive = build_analytics_source_archive(
                repository_root=self.root, reviewed_commit=self.sha,
            )
        self.assertEqual(archive, self.archive)


if __name__ == "__main__":
    unittest.main()
