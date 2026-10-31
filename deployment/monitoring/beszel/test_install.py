#!/usr/bin/env python3
# File: deployment/monitoring/beszel/test_install.py
# Purpose: Regression tests for fail-closed Omnilyzer UID991 monitoring install.
# Related: install.py, metrics_proxy.py, the two new systemd system units.
"""Isolated tests: no root, Docker, production deployment, or live systemd."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


# Section: Import the exact installer without executing the privileged entry.
SPEC = importlib.util.spec_from_file_location(
    "omnilyzer_beszel_installer", Path(__file__).with_name("install.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InstallerTests(unittest.TestCase):
    """Use private fixture directories and mock every privileged interaction."""

    def setUp(self):
        """Create isolated source/target identities with no real server writes."""
        self.t = tempfile.TemporaryDirectory(prefix="omnilyzer-monitor-test-")
        self.addCleanup(self.t.cleanup)
        top = Path(self.t.name)
        source = top / "source"
        source.mkdir()
        prefix = top / "opt-monitor"
        state = top / "state"
        unitdir = top / "systemd"
        unitdir.mkdir()
        names = ("README.md", "metrics_proxy.py", "test_metrics_proxy.py",
                 "beszel-omnilyzer-proxy.service", "beszel-omnilyzer-agent.service")
        for name in names:
            (source / name).write_text("test fixture: " + name)
        binary = top / "beszel-agent"
        binary.write_bytes(b"static-test-agent")
        public = top / "hub-public-key"
        public.write_bytes(b"test-public-key")
        replacements = dict(
            UID=os.getuid(), GID=os.getgid(), ROOT_UID=os.getuid(), ROOT_GID=os.getgid(), SOURCE=source, PREFIX=prefix,
            STATE=state, DATA=state / "data", UNITDIR=unitdir,
            MANIFEST=prefix / "install-manifest.json",
            SOCKET=top / "metrics.sock", BINARY=binary, PUBLIC=public,
            SOURCE_HASHES={name: "fixture-sha" for name in names},
        )
        for name, val in replacements.items():
            patcher = mock.patch.object(MODULE, name, val)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name, func in [
            ("preflight", lambda: None),
            ("start_and_check", lambda: None),
            ("systemctl", lambda *a, **k: subprocess.CompletedProcess(a, 0)),
        ]:
            patcher = mock.patch.object(MODULE, name, func)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Test as a non-root user: remap only the root ownership assertions
        # to the current fixture owner, without weakening the production code.
        original_require_dir = MODULE.require_dir

        def fixture_require_dir(path, uid, gid, mode=None):
            """Assert ownership and mode against this test process's files."""
            return original_require_dir(
                path, os.getuid() if uid == 0 else uid,
                os.getgid() if gid == 0 else gid, mode,
            )

        for target, replacement in (
            ("require_dir", fixture_require_dir),
        ):
            patcher = mock.patch.object(MODULE, target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        for method in ("chown", "fchown"):
            patcher = mock.patch.object(MODULE.os, method, lambda *args: None)
            patcher.start()
            self.addCleanup(patcher.stop)

        # Test as a non-root user: remap only the root ownership assertions
        # to the current fixture owner, without weakening the production code.
        original_require_dir = MODULE.require_dir

        def fixture_require_dir(path, uid, gid, mode=None):
            """Assert ownership and mode against this test process's files."""
            return original_require_dir(
                path, os.getuid() if uid == 0 else uid,
                os.getgid() if gid == 0 else gid, mode,
            )

        for target, replacement in (
            ("require_dir", fixture_require_dir),
        ):
            patcher = mock.patch.object(MODULE, target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        for method in ("chown", "fchown"):
            patcher = mock.patch.object(MODULE.os, method, lambda *args: None)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.prefix, self.state, self.unitdir = prefix, state, unitdir
        self.old_umask = os.umask(0o077)
        self.addCleanup(os.umask, self.old_umask)

    def test_new_private_services_and_manifest(self):
        """First install has two services, root-owned source and 0700 data."""
        MODULE.install()
        self.assertTrue((self.prefix / "metrics_proxy.py").is_file())
        self.assertTrue((self.state / "data" / "hub-public-key").exists())
        self.assertEqual((self.state / "data").stat().st_mode & 0o777, 0o700)
        self.assertTrue(all((self.unitdir / x).exists() for x in MODULE.UNITS))
        self.assertEqual(json.loads(MODULE.MANIFEST.read_text())["marker"], MODULE.MARKER)
        MODULE.rollback()
        self.assertFalse(self.prefix.exists())
        self.assertFalse(self.state.exists())
        self.assertFalse(any((self.unitdir / x).exists() for x in MODULE.UNITS))

    def test_failed_real_start_cleans_only_monitor(self):
        """Simulated startup failure must not leave any monitoring files."""
        with mock.patch.object(MODULE, "start_and_check", side_effect=RuntimeError("simulated boot failure")):
            with self.assertRaisesRegex(RuntimeError, "simulated boot failure"):
                MODULE.install()
        self.assertFalse(self.prefix.exists())
        self.assertFalse(self.state.exists())
        self.assertFalse(any((self.unitdir / x).exists() for x in MODULE.UNITS))

    def test_rollback_rejects_unexpected_manifest(self):
        """An unrelated installation must never be removed by this command."""
        self.prefix.mkdir()
        MODULE.MANIFEST.write_text('{"marker":"WRONG"}')
        with self.assertRaisesRegex(RuntimeError, "match this monitor"):
            MODULE.rollback()
        self.assertTrue(self.prefix.is_dir())

    def test_rollback_preserves_unknown_files(self):
        """Fail closed instead of recursively deleting unknown root-owned data."""
        MODULE.install()
        (self.prefix / "unrelated-file").write_text("preserve")
        with self.assertRaises(OSError):
            MODULE.rollback()
        self.assertEqual((self.prefix / "unrelated-file").read_text(), "preserve")

    def test_disallow_overwriting_existing_path(self):
        """Preflight path check rejects existing regular files and symlinks."""
        f = Path(self.t.name) / "existing"
        f.write_text("keep")
        with self.assertRaisesRegex(RuntimeError, "Refusing to replace"):
            MODULE.require_new(f)
        symlink = Path(self.t.name) / "alias"
        symlink.symlink_to(f)
        with self.assertRaisesRegex(RuntimeError, "Refusing to replace"):
            MODULE.require_new(symlink)

    def test_uid991_role_cannot_claim_unrelated_directory(self):
        """Directory ownership validator must reject foreign user/GID."""
        bad = Path(self.t.name) / "bad"
        bad.mkdir()
        with self.assertRaisesRegex(RuntimeError, "Unsafe monitoring directory"):
            MODULE.require_dir(bad, -1, -1, 0o700)


if __name__ == "__main__":
    unittest.main()
