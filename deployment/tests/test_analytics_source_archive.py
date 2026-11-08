"""File: deployment/tests/test_analytics_source_archive.py

Purpose: Original C26 exact 32-entry Analytics source archive regression,
         plus V2 38-entry successor deterministic Git-object evidence,
         canonical manifests and negative cross-schema/archive security tests.
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
    build_analytics_successor_source_archive,
    verify_analytics_successor_source_archive,
    _archive_bytes,
)
from deployment.analytics_source_handoff import (
    review_analytics_source_handoff,
    review_analytics_successor_source_handoff, _SHARED_BASE_COMMIT,
    _SHARED_COMPATIBILITY_FILES, _SHARED_PREIMAGE_SHA256,
    _SHARED_PREIMAGE_COMMITS,
)
from deployment.application_source_set import DevApplicationSourceSet
from deployment.policy import canonical_bytes
import json
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
        self.assertEqual(len(source), 32)
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
            self.assertEqual(len(tar.getmembers()), 33)
            self.assertEqual(
                tar.getmembers()[0].name,
                ".omnilyzer-analytics-source-review.json",
            )
            self.assertTrue(all(
                x.isfile() and x.mode == 0o644
                and x.uid == x.gid == x.mtime == 0
                for x in tar.getmembers()
            ))

    def test_disposable_70_file_five_shared_upgrade_and_full_rollback(self):
        """Prove 38 immutable originals + five bounded compatibility patches.

        Four real installed DEV SHA-256 preimages are pinned to original
        protected Git objects (promotion.py is from an older historical
        revision). All 27 new files are add-only; the four
        shared files require an exact PREIMAGE before replacement. After
        local source simulation, rollback restores the exact original 43
        files and removes all newly created file and directory paths.
        No actual host installer, root privileges or live filesystem used.
        """
        sources = self.inspect()
        original_names = tuple(
            item.repository_path for item in DevApplicationSourceSet().files
        )
        self.assertEqual(len(original_names), 43)
        self.assertEqual(
            set(original_names) & {name for name, _ in sources},
            set(_SHARED_COMPATIBILITY_FILES),
        )
        original_tree = original_manifest._tree(
            original_manifest._output(self.root, (
                "ls-tree", "-r", "-z", "--full-tree", _SHARED_BASE_COMMIT,
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
        # Actual installed DEV is a MIXED verified historical snapshot:
        # 42 original files match b9e22e, while promotion.py matches ba4fd3.
        # Do not forge a DevApplicationManifest claiming all 43 from b9e22e.
        promotion = "deployment/promotion.py"
        old = _SHARED_PREIMAGE_COMMITS[promotion]
        entry = original_manifest._tree(original_manifest._output(
            self.root, ("ls-tree", "-r", "-z", "--full-tree", old,
                        "--", promotion), 8192), (promotion,))
        original_blobs[promotion] = original_manifest._output(
            self.root, ("cat-file", "blob", entry[0][1]), 1024 * 1024,
        )
        for path, old_sha in _SHARED_PREIMAGE_SHA256.items():
            self.assertEqual(
                hashlib.sha256(original_blobs[path]).hexdigest(), old_sha,
            )
        from types import SimpleNamespace
        # This is a local FD verifier view of the REAL mixed DEV hashes,
        # not a false claim that a single Git commit produced that mix.
        previous = SimpleNamespace(entries=tuple(
            original_manifest.ApplicationManifestEntry(
                name, hashlib.sha256(original_blobs[name]).hexdigest(),
                "0644",
            )
            for name in original_names
        ))
        with tempfile.TemporaryDirectory(prefix="m05-14-70file-upgrade-") as temp:
            app = Path(temp) / "app"
            app.mkdir(mode=0o755)
            app.chmod(0o755)

            def add_directory(file):
                """Normalize directories independent of the runner umask."""
                file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                for parent in (file.parent, *file.parent.parents):
                    if parent == app.parent:
                        break
                    parent.chmod(0o755)

            def original_verification():
                """Invoke the unchanged original C31B FD-relative verifier."""
                desc = os.open(app, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    original_materialization._verify_application(
                        desc, previous, os.getuid(), os.getgid(),
                    )
                finally:
                    os.close(desc)

            for name, payload in original_blobs.items():
                file = app / name
                add_directory(file)
                file.write_bytes(payload)
                file.chmod(0o644)
            original_verification()
            # A real DEV preflight found 18 historical root-owned CPython
            # bytecode files. The original C31B manifest rightly rejects
            # any unlisted cache even though the 43 source hashes match.
            # Never silently delete caches in the privileged installation.
            legacy_cache = app / "deployment/__pycache__"
            legacy_cache.mkdir(mode=0o755)
            legacy_cache.chmod(0o755)
            unexpected = legacy_cache / "promotion.cpython-312.pyc"
            unexpected.write_bytes(b"synthetic legacy cache")
            unexpected.chmod(0o644)
            with self.assertRaises(OSError):
                original_verification()
            unexpected.unlink()
            legacy_cache.rmdir()
            original_verification()
            original_directories = {
                p.relative_to(app) for p in app.rglob("*") if p.is_dir()
            }

            updated = []
            added = []
            for name, payload in sources:
                file = app / name
                if name in _SHARED_PREIMAGE_SHA256:
                    self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(),
                                     _SHARED_PREIMAGE_SHA256[name])
                    updated.append(name)
                else:
                    self.assertFalse(file.exists())
                    added.append(name)
                add_directory(file)
                file.write_bytes(payload)
                file.chmod(0o644)
            self.assertEqual(updated, list(_SHARED_COMPATIBILITY_FILES))
            self.assertEqual(len(added), 27)
            self.assertEqual(len(updated), 5)
            self.assertEqual(sum(
                1 for item in app.rglob("*") if item.is_file()
            ), 70)
            for name, original in original_blobs.items():
                if name not in _SHARED_PREIMAGE_SHA256:
                    self.assertEqual((app / name).read_bytes(), original, name)
            for name, payload in sources:
                self.assertEqual((app / name).read_bytes(), payload, name)
            # Before service cutover, the old manifest MUST reject changes.
            with self.assertRaises(OSError):
                original_verification()

            # Disposable rollback proof: retain all original canary bytes.
            for name in reversed(updated):
                (app / name).write_bytes(original_blobs[name])
                (app / name).chmod(0o644)
            for name in reversed(added):
                (app / name).unlink()
            for directory in sorted(
                (p for p in app.rglob("*") if p.is_dir()),
                key=lambda p: len(p.parts), reverse=True,
            ):
                if directory.relative_to(app) not in original_directories:
                    directory.rmdir()
            self.assertEqual(sum(
                1 for item in app.rglob("*") if item.is_file()
            ), 43)
            original_verification()
            self.assertEqual(
                {p.relative_to(app) for p in app.rglob("*") if p.is_dir()},
                original_directories,
            )

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


# Section: successor V2 additive source-generation review. This is a
# separate, review-only 37-entry archive. Original V1/Canary remains unchanged.
class SuccessorC26SourceArchiveTests(unittest.TestCase):
    """Prove exact source bytes and complete closure without root privilege."""

    @classmethod
    def setUpClass(cls):
        """Read only current reviewed Git objects, not working-tree edits."""
        cls.root, cls.sha, cls.original_sha = _identities()
        cls.manifest = review_analytics_successor_source_handoff(
            repository_root=cls.root, reviewed_commit=cls.sha,
        )
        cls.manifest_sha = hashlib.sha256(cls.manifest).hexdigest()
        cls.archive = build_analytics_successor_source_archive(
            repository_root=cls.root, reviewed_commit=cls.sha,
        )
        cls.contents = verify_analytics_successor_source_archive(
            cls.archive, expected_manifest_sha256=cls.manifest_sha,
            reviewed_commit=cls.sha,
        )

    def inspect(self, archive=None, sha=None):
        """Require externally selected reviewed V2 SHA for every readback."""
        return verify_analytics_successor_source_archive(
            self.archive if archive is None else archive,
            expected_manifest_sha256=self.manifest_sha if sha is None else sha,
            reviewed_commit=self.sha,
        )

    def test_exact_source_graph_and_original_version_still_separate(self):
        """V2 attests five added Python sources and the exact Compose overlay."""
        original = dict(verify_analytics_source_archive(
            build_analytics_source_archive(
                repository_root=self.root, reviewed_commit=self.sha,
            ),
            expected_manifest_sha256=self.original_sha,
            reviewed_commit=self.sha,
        ))
        future = dict(self.contents)
        self.assertEqual(len(original), 32)
        self.assertEqual(len(future), 38)
        self.assertEqual(
            set(future) - set(original), {
                "deployment/analytics_active_state_review.py",
                "deployment/analytics_loopback_guard.py",
                "deployment/analytics_route_journal.py",
                "deployment/sigstore_authority_provenance.py",
                "release/analytics_owner_source_selection.py",
                "deployment/runtime/dev/analytics.compose.successor-ports.yaml",
            },
        )
        self.assertTrue(all(future[p] == body for p, body in original.items()))
        self.assertEqual(self.archive, build_analytics_successor_source_archive(
            repository_root=self.root, reviewed_commit=self.sha,
        ))
        with self.assertRaises(AnalyticsSourceArchiveError):
            verify_analytics_source_archive(
                self.archive, expected_manifest_sha256=self.manifest_sha,
                reviewed_commit=self.sha,
            )
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(archive=build_analytics_source_archive(
                repository_root=self.root, reviewed_commit=self.sha,
            ))

    def test_wrong_root_sha_version_and_noncanonical_manifest_denied(self):
        """A mutable ref, altered source count or forged manifest cannot pass."""
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(sha="0" * 64)
        for alteration in (
            {"source_file_count": 32},
            {"schema_version": 1},
            {"source_commit": "0" * 40},
            {"deployment_authorized": True},
            {"purpose": "analytics-task014-additive-source-review-only"},
            {"baseline_review": {}},
        ):
            with self.subTest(alteration=alteration):
                model = json.loads(self.manifest)
                model.update(alteration)
                forged = canonical_bytes(model)
                with self.assertRaises(AnalyticsSourceArchiveError):
                    self.inspect(
                        archive=_archive_bytes(forged, self.contents),
                        sha=hashlib.sha256(forged).hexdigest(),
                    )

    def test_corrupt_missing_new_source_and_symlink_tar_denied(self):
        """Do not accept a wrong extra image inspector or path injection."""
        changed = list(self.contents)
        changed[-1] = (
            changed[-1][0], changed[-1][1] + b"\n# tampered\n",
        )
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(archive=_archive_bytes(self.manifest, tuple(changed)))
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(archive=_archive_bytes(self.manifest, self.contents[:-1]))
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(archive=self.archive + b"not tar")
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(archive=self.archive[:-512])
        # Unknown append cannot become a legitimate source under any SHA.
        injected = tuple((*self.contents, ("release/unsafe.py", b"bad")))
        with self.assertRaises(AnalyticsSourceArchiveError):
            self.inspect(archive=_archive_bytes(self.manifest, injected))

    def test_no_mutable_worktree_or_privileged_source_side_effect(self):
        """Only reviewed Git objects, never network, root install or prompts."""
        with (
            patch("os.chown", side_effect=AssertionError("root write forbidden")),
            patch("os.mkdir", side_effect=AssertionError("host write forbidden")),
            patch("subprocess.run", side_effect=AssertionError("C26 Git only")),
        ):
            rebuilt = build_analytics_successor_source_archive(
                repository_root=self.root, reviewed_commit=self.sha,
            )
        self.assertEqual(rebuilt, self.archive)


if __name__ == "__main__":
    unittest.main()

