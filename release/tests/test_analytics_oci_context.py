"""File: release/tests/test_analytics_oci_context.py

Purpose: Source-executed tests for exact immutable Git-based OCI build input.
Related: release/analytics_oci_context.py, M05 Task013 source receipt,
         Analytics Dockerfile.analytics, .dockerignore and Task013 BuildKit.
These tests never invoke a signer, broker, release publisher or host service.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from deployment.policy import DeploymentPolicyError
from release.analytics_oci_context import (
    _excluded, snapshot_committed_tree, ESSENTIAL,
)

def git(root: Path, *args: str) -> str:
    """Run only test-owned disposable Git commands; never real repositories."""
    result = subprocess.run(["git", "-C", str(root), *args],
                            check=True, capture_output=True, text=True)
    return result.stdout.strip()


def fixture(root: Path) -> str:
    """Build a representative tiny Next/Prisma source commit with ignored secrets."""
    git(root, "init", "-q")
    for name in ESSENTIAL | {
        "app/page.tsx", "lib/sample.ts", ".env.memory",
        "backups/private.sql", ".venv_backup_20250630/id.key",
    }:
        item = root / name
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_text("PRIVATE" if name.startswith((".env", "backups", ".venv")) else name)
    git(root, "add", "-A")
    git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "-qm", "isolated test")
    return git(root, "rev-parse", "HEAD")


class ImmutableSourceBuildContextTests(unittest.TestCase):
    """Review exact source bytes and ignore rules before BuildKit receives a tar."""

    def test_excludes_tracked_secrets_and_untracked_code(self):
        """Untracked files and tracked secret-like files cannot reach build input."""
        with tempfile.TemporaryDirectory(prefix="task013-oci-") as scratch:
            root = Path(scratch)
            source = root / "source"
            source.mkdir()
            commit = fixture(source)
            extra = source / "app" / "untracked-malicious.ts"
            extra.write_text("not committed")
            target = root / "context.tar"
            out = snapshot_committed_tree(source, commit, target)
            self.assertFalse(out["release_authorized"])
            self.assertFalse(out["deployment_authorized"])
            with tarfile.open(target) as archive:
                members = {m.name for m in archive.getmembers()}
                self.assertTrue(ESSENTIAL.issubset(members))
                self.assertIn("app/page.tsx", members)
                self.assertNotIn("app/untracked-malicious.ts", members)
                self.assertNotIn(".env.memory", members)
                self.assertNotIn("backups/private.sql", members)
                self.assertNotIn(".venv_backup_20250630/id.key", members)
                self.assertEqual(archive.extractfile("lib/sample.ts").read(), b"lib/sample.ts")
                self.assertTrue(all(x.isfile() for x in archive.getmembers()))
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_dirty_worktree_is_never_used(self):
        """Changed local file contents cannot replace the committed Git blob."""
        with tempfile.TemporaryDirectory(prefix="task013-oci-") as scratch:
            root = Path(scratch)
            source = root / "repo"
            source.mkdir()
            commit = fixture(source)
            (source / "app/page.tsx").write_text("unreviewed mutation")
            one = root / "a.tar"
            two = root / "b.tar"
            a = snapshot_committed_tree(source, commit, one)
            b = snapshot_committed_tree(source, commit, two)
            self.assertEqual(a["context_sha256"], b["context_sha256"])
            self.assertEqual(one.read_bytes(), two.read_bytes())
            with tarfile.open(one) as archive:
                self.assertEqual(archive.extractfile("app/page.tsx").read(), b"app/page.tsx")

    def test_symlink_in_allowed_source_denied(self):
        """Never ship a Git symlink that could redirect a runtime build path."""
        with tempfile.TemporaryDirectory(prefix="task013-oci-") as scratch:
            root = Path(scratch)
            source = root / "repo"
            source.mkdir()
            fixture(source)
            (source / "lib/linked").symlink_to("../app/page.tsx")
            git(source, "add", "lib/linked")
            git(source, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "commit", "-qm", "link")
            with self.assertRaises(DeploymentPolicyError):
                snapshot_committed_tree(source, git(source, "rev-parse", "HEAD"),
                                        root / "bad.tar")
            self.assertFalse((root / "bad.tar").exists())

    def test_commit_mismatch_and_existing_output_denied(self):
        """Never accept a different source commit or clobber a previous archive."""
        with tempfile.TemporaryDirectory(prefix="task013-oci-") as scratch:
            root = Path(scratch)
            source = root / "repo"
            source.mkdir()
            commit = fixture(source)
            with self.assertRaises(DeploymentPolicyError):
                snapshot_committed_tree(source, "1" * 40, root / "never.tar")
            existing = root / "context.tar"
            existing.write_text("do not overwrite")
            with self.assertRaises(DeploymentPolicyError):
                snapshot_committed_tree(source, commit, existing)
            self.assertEqual(existing.read_text(), "do not overwrite")

    def test_dockerignore_secret_exclusions(self):
        """Bound exact dangerous source path patterns, not just a root .env."""
        for name in (".env.memory", "a/.env.production", "private/tokens.txt",
                     "node_modules/lib/x.js", "app/.next/source.js",
                     "src/backup.pem", "a/secrets/token", "logs/x.log"):
            with self.subTest(name=name):
                self.assertTrue(_excluded(name))
        for name in ("app/page.tsx", "public/logo.svg", "prisma/schema.prisma"):
            self.assertFalse(_excluded(name))


if __name__ == "__main__":
    unittest.main()
