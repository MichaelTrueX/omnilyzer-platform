"""File: deployment/tests/test_analytics_isolated_source_install.py

Purpose: Exercise genuine C31B FD/root-owned 70-file source staging and
         fail-closed rollback on a disposable Linux directory. The exact
         signed Analytics source handoff and actual 43-file DEV baseline
         are used; no root-owned host path, service, database or secrets touched.
Related: deployment/analytics_isolated_source_install.py,
         deployment/analytics_source_archive.py,
         deployment/analytics_source_handoff.py,
         deployment/dev_host_provisioning_mechanics.py.

Sections: real historical Git data; exact 70-file success and 43-file
          preservation; intentional bytecode exclusion; preimage/drift/symlink
          refusal; fault-injected stage cleanup; root-only entrypoint denial.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import deployment.analytics_isolated_source_install as install
from deployment.analytics_source_handoff import (
    review_analytics_source_handoff,
    _SHARED_BASE_COMMIT,
    _SHARED_COMPATIBILITY_FILES,
    _SHARED_PREIMAGE_COMMITS,
)
from deployment.analytics_source_archive import (
    build_analytics_source_archive,
)
from deployment.application_source_set import DevApplicationSourceSet
from deployment.policy import canonical_bytes
from deployment import application_manifest as _git
from deployment import dev_host_provisioning_mechanics as _c31b


ROOT = Path(__file__).resolve().parents[2]


def _blob(repo: str, revision: str, path: str) -> bytes:
    """Use original Task014's bounded Git blob reader, no network or checkout."""
    records = _git._tree(_git._output(
        repo, ("ls-tree", "-r", "-z", "--full-tree", revision, "--", path),
        8192,
    ), (path,))
    return _git._output(repo, ("cat-file", "blob", records[0][1]), 1024 * 1024)


class IsolatedSourceGenerationTests(unittest.TestCase):
    """All host mutations are performed only under a temporary test directory."""

    @classmethod
    def setUpClass(cls):
        """Assemble the authentic source archive and observed legacy mix once."""
        cls.repo = str(ROOT)
        cls.sha = subprocess.check_output(
            ("/usr/bin/git", "-C", cls.repo, "rev-parse", "HEAD"),
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
        manifest = review_analytics_source_handoff(
            repository_root=cls.repo, reviewed_commit=cls.sha,
        )
        cls.manifest_sha = hashlib.sha256(manifest).hexdigest()
        cls.archive = build_analytics_source_archive(
            repository_root=cls.repo, reviewed_commit=cls.sha,
        )
        cls.old = {
            item.repository_path: _blob(
                cls.repo,
                _SHARED_PREIMAGE_COMMITS.get(
                    item.repository_path, _SHARED_BASE_COMMIT,
                ),
                item.repository_path,
            )
            for item in DevApplicationSourceSet().files
        }
        cls.initial_hashes = {
            k: hashlib.sha256(v).hexdigest() for k, v in cls.old.items()
        }

    def setUp(self):
        """Create only disposable 43-source+18-bytecode fixture data."""
        self.temp = tempfile.TemporaryDirectory(prefix="m05-task014-isolated-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.old_root = self.base / "original"
        self.old_root.mkdir(mode=0o755)
        self.old_root.chmod(0o755)
        self.parent = self.base / "deployment"
        self.parent.mkdir(mode=0o755)
        self.parent.chmod(0o755)
        for name, payload in self.old.items():
            file = self.old_root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            self._fix_dirs(file.parent, self.old_root)
            file.write_bytes(payload)
            file.chmod(0o644)
        cache = self.old_root / "deployment/__pycache__"
        cache.mkdir(exist_ok=True)
        cache.chmod(0o755)
        self.bytecode = tuple(
            cache / (f"synthetic-{i}.cpython-312.pyc")
            for i in range(18)
        )
        for name in self.bytecode:
            name.write_bytes(b"legacy canary cache retained")
            name.chmod(0o644)

    @staticmethod
    def _fix_dirs(directory: Path, root: Path):
        """Normalize permissions irrespective of test runner umask."""
        current = directory
        while current != root.parent:
            current.chmod(0o755)
            if current == root:
                break
            current = current.parent

    def _test_fd_open(self, path: str, owned: list[int], uid: int, gid: int):
        """Use the actual C31B descriptor chain, projecting only /tmp owners.

        Protected production _open_checked_root is NOT changed. This test
        adapter avoids treating system-owned / and /tmp as owned by omnigpt.
        Internal content, inode, source hash and materialization use real FDs.
        """
        root, chain = _c31b._open_directory(path, owned)
        _c31b._revalidate_chain(chain)
        return root

    def stage(self, archive=None):
        """Exercise complete source composition and C31B verified publication."""
        with patch.object(install, "_open_checked_root",
                          side_effect=self._test_fd_open):
            return install._publish_isolated_generation(
                parent_root=str(self.parent),
                original_root=str(self.old_root),
                archive=self.archive if archive is None else archive,
                manifest_sha=self.manifest_sha, reviewed_commit=self.sha,
                uid=os.getuid(), gid=os.getgid(),
            )

    def test_70_sources_are_real_verified_and_legacy_tree_is_identical(self):
        """New product root works WITHOUT replacing ANY protected canary inode."""
        before = {
            name: os.stat(self.old_root / name).st_ino for name in self.old
        }
        self.assertEqual(self.stage(), str(self.parent / "analytics-app"))
        new_root = self.parent / "analytics-app"
        self.assertTrue(new_root.is_dir())
        actual = {
            str(item.relative_to(new_root))
            for item in new_root.rglob("*") if item.is_file()
        }
        self.assertEqual(len(actual), 70)
        self.assertEqual(
            len(actual - set(self.old)), 27,
        )
        for name, payload in self.old.items():
            self.assertEqual((self.old_root / name).read_bytes(), payload)
            self.assertEqual(
                os.stat(self.old_root / name).st_ino, before[name],
            )
        self.assertTrue(all(x.is_file() for x in self.bytecode))
        self.assertFalse((new_root / "deployment/__pycache__").exists())
        changed = {
            name for name, data in self.old.items()
            if (new_root / name).read_bytes() != data
        }
        self.assertEqual(changed, set(_SHARED_COMPATIBILITY_FILES))
        self.assertFalse((self.parent / install._STAGING).exists())
        # Real separate Python process imports ONLY the isolated 70-file
        # generation, not our development worktree or the original canary.
        program = (
            "import deployment.analytics_broker_service_entrypoint as b; "
            "import deployment.analytics_executor_service_entrypoint as e; "
            "import deployment.analytics_signed_source_pin as p; "
            "from pathlib import Path; "
            "assert Path(b.__file__).resolve().parents[1] == Path.cwd(); "
            "assert Path(e.__file__).resolve().parents[1] == Path.cwd(); "
            "assert p._load_pinned_source()['product'] == 'analytics'; "
            "print('ISOLATED_BROKER_EXECUTOR_IMPORT_OK')"
        )
        result = subprocess.run(
            ("/usr/bin/python3", "-B", "-c", program),
            cwd=str(new_root),
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(new_root),
                 "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ISOLATED_BROKER_EXECUTOR_IMPORT_OK", result.stdout)
        self.assertFalse((new_root / "deployment/__pycache__").exists())

    def test_wrong_legacy_preimage_and_symlink_fail_before_a_host_write(self):
        """Reject even one changed canary file, including old promotion.py."""
        for name in (
            "deployment/promotion.py",
            "deployment/oci_verifier.py",
            "deployment/broker.py",
        ):
            original = (self.old_root / name).read_bytes()
            file = self.old_root / name
            with self.subTest(name=name):
                file.write_bytes(original + b"malformed")
                with self.assertRaises(OSError):
                    self.stage()
                self.assertFalse((self.parent / "analytics-app").exists())
                self.assertFalse((self.parent / install._STAGING).exists())
                file.write_bytes(original)
                file.chmod(0o644)
        symlink = self.old_root / "deployment/broker.py"
        symlink.unlink()
        symlink.symlink_to(self.old_root / "deployment/promotion.py")
        with self.assertRaises(OSError):
            self.stage()
        self.assertFalse((self.parent / "analytics-app").exists())

    def test_preexisting_generation_and_stale_staging_fail_closed(self):
        """Never overwrite prior source generation or clean unfamiliar paths."""
        original = self.parent / "analytics-app"
        original.mkdir()
        marker = original / "user-owned-marker"
        marker.write_bytes(b"preserve")
        with self.assertRaises(OSError):
            self.stage()
        self.assertEqual(marker.read_bytes(), b"preserve")
        marker.unlink()
        original.rmdir()
        stale = self.parent / install._STAGING
        stale.mkdir()
        marker = stale / "manual-recovery-required"
        marker.write_bytes(b"preserve")
        with self.assertRaises(OSError):
            self.stage()
        self.assertEqual(marker.read_bytes(), b"preserve")

    def test_midwrite_failure_removes_only_created_stage_preserving_legacy(self):
        """Fault after several real writes; no partial app or legacy changes."""
        write = install._original._write_all
        count = 0

        def broken(fd, payload):
            """Inject one controlled error into the real C31B file writer."""
            nonlocal count
            count += 1
            if count == 9:
                raise OSError("injected disposable test write error")
            return write(fd, payload)

        with patch.object(install, "_open_checked_root",
                          side_effect=self._test_fd_open), patch.object(
            install._original, "_write_all", side_effect=broken,
        ):
            with self.assertRaises(OSError):
                install._publish_isolated_generation(
                    parent_root=str(self.parent),
                    original_root=str(self.old_root),
                    archive=self.archive,
                    manifest_sha=self.manifest_sha,
                    reviewed_commit=self.sha,
                    uid=os.getuid(), gid=os.getgid(),
                )
        self.assertEqual(count, 9)
        self.assertFalse((self.parent / "analytics-app").exists())
        self.assertFalse((self.parent / install._STAGING).exists())
        for name, payload in self.old.items():
            self.assertEqual((self.old_root / name).read_bytes(), payload)
        self.assertTrue(all(p.is_file() for p in self.bytecode))

    def test_atomic_publish_error_rolls_back_only_verified_source_stage(self):
        """A failed final rename cannot strand newly created source files."""
        with patch.object(install, "_open_checked_root",
                          side_effect=self._test_fd_open), patch.object(
            install.os, "rename", side_effect=OSError("injected rename failure"),
        ):
            with self.assertRaises(OSError):
                install._publish_isolated_generation(
                    parent_root=str(self.parent), original_root=str(self.old_root),
                    archive=self.archive, manifest_sha=self.manifest_sha,
                    reviewed_commit=self.sha, uid=os.getuid(), gid=os.getgid(),
                )
        self.assertFalse((self.parent / install._STAGING).exists())
        self.assertFalse((self.parent / "analytics-app").exists())
        self.assertTrue(all(p.is_file() for p in self.bytecode))
        self.assertTrue(all((self.old_root / n).read_bytes() == v
                            for n, v in self.old.items()))

    def test_invalid_archive_is_denied_before_any_file_stage(self):
        """Review metadata cannot override the trusted root manifest SHA."""
        with self.assertRaises(Exception):
            self.stage(archive=self.archive[:-512] + b"X" * 512)
        self.assertFalse((self.parent / "analytics-app").exists())

    def test_public_root_entrypoint_refuses_unprivileged_caller(self):
        """No public review/HTTP schema can turn into a host installer."""
        with patch.object(
            install, "_read_protected_file",
            side_effect=AssertionError("must not read protected paths"),
        ):
            with self.assertRaises(install.AnalyticsIsolatedSourceInstallError):
                install.install_approved_analytics_source_generation()

    def test_protected_approval_schema_denies_paths_duplicates_and_truthy(self):
        """Only separately root-installed exact-commit approval is usable."""
        obj = {
            "schema_version": 1, "product_id": "analytics", "stage": "dev",
            "reviewed_commit": self.sha,
            "manifest_sha256": self.manifest_sha,
            "archive_sha256": hashlib.sha256(self.archive).hexdigest(),
            "destination": "/opt/omnilyzer/deployment/analytics-app",
        }
        self.assertEqual(install._approval(canonical_bytes(obj)), obj)
        for bad in (
            {**obj, "destination": "/opt/omnilyzer/deployment/app"},
            {**obj, "schema_version": True},
            {**obj, "product_id": "canary"},
            {**obj, "unknown": True},
            {**obj, "archive_sha256": "0" * 63},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                install._approval(canonical_bytes(bad))
        with self.assertRaises(ValueError):
            install._approval(
                canonical_bytes(obj).replace(
                    b'"product_id":"analytics"',
                    b'"product_id":"analytics","product_id":"analytics"',
                )
            )


if __name__ == "__main__":
    unittest.main()
