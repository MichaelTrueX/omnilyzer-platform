"""File: deployment/tests/test_analytics_prod_rootless_bootstrap.py
Purpose: Focused source-only safety checks for first PROD rootless prerequisites.
Related: deployment/analytics_prod_rootless_bootstrap.py,
         docs/operations/analytics-prod-first-install.md.
No host package, user, service, database or network changes occur.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deployment import analytics_prod_rootless_bootstrap as boot


class AnalyticsProdRootlessBootstrapTests(unittest.TestCase):
    """Protect one-time install, fixed identity and rootless-only boundaries."""

    def test_subordinate_id_ranges_reject_collisions_and_malformed_entries(self):
        """Never overlap existing service or human UID/GID allocations."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subuid"
            path.write_text("trusthansen:100000:65536\nomnigpt:165536:65536\n")
            self.assertEqual(boot.subid_conflicts(path), [])
            path.write_text("trusthansen:100000:65536\nother:231072:65536\nbad\n")
            result = boot.subid_conflicts(path)
            self.assertEqual(len(result), 2)
            self.assertIn("overlapping", result[0])
            self.assertIn("invalid", result[1])

    def test_exclusive_file_creation_denies_overwrite_and_symlink(self):
        """Root-controlled artifacts cannot overwrite unrelated files."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned"
            boot.write_new(path, b"original", 0o600)
            with self.assertRaises(FileExistsError):
                boot.write_new(path, b"replacement", 0o600)
            self.assertEqual(path.read_bytes(), b"original")
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(FileExistsError):
                boot.write_new(alias, b"replacement", 0o600)

    def test_apply_requires_root_before_any_mutation(self):
        """No unprivileged user can enter the package installation path."""
        with patch.object(boot.os, "geteuid", return_value=1000):
            with patch.object(boot, "preflight") as preflight:
                with self.assertRaisesRegex(RuntimeError, "root required"):
                    boot.install()
                preflight.assert_not_called()

    def test_only_pinned_packages_and_no_rootful_or_public_listener(self):
        """Keep PROD's new runtime separate from existing public services."""
        self.assertEqual(boot.HOST, "truexmainserver")
        self.assertEqual(boot.USER, "omnilyzer-analytics")
        self.assertEqual(boot.SUBID_START, 231072)
        self.assertEqual(len(boot.PACKAGES), 7)
        self.assertTrue(all("=" in package for package in boot.PACKAGES))
        self.assertIn("unix://%t/docker.sock", boot.UNIT_TEXT)
        self.assertIn("ConditionUser=omnilyzer-analytics", boot.UNIT_TEXT)
        self.assertIn("DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=true", boot.UNIT_TEXT)
        self.assertNotIn("tcp://", boot.UNIT_TEXT)
        self.assertNotIn("0.0.0.0", boot.UNIT_TEXT)
        self.assertEqual(boot.ROOTFUL_UNITS, ("docker.service", "docker.socket", "containerd.service"))
        self.assertEqual(len(boot.DOCKER_FINGERPRINT), 40)

    def test_dedicated_user_command_uses_no_shell_or_shared_docker_socket(self):
        """Deployment user cannot silently become host root or share a socket."""
        with patch.object(boot, "run") as runner:
            boot.user_command(989, "/usr/bin/docker", "info")
        args = runner.call_args.args
        self.assertEqual(args[:5], ("/usr/sbin/runuser", "-u", "omnilyzer-analytics", "--", "/usr/bin/env"))
        self.assertIn("DOCKER_HOST=unix:///run/user/989/docker.sock", args)
        self.assertNotIn("/bin/sh", args)
        self.assertNotIn("/var/run/docker.sock", args)

    def test_bootstrap_does_not_install_application_or_grant_sudo(self):
        """A runtime prerequisite is not an Analytics release authorization."""
        import inspect
        source = inspect.getsource(boot.install)
        self.assertNotIn("sudoers", source)
        self.assertNotIn("docker run", source)
        self.assertNotIn("nginx", source)
        self.assertNotIn("prisma", source)
        self.assertIn("prod_application_installed", source)


if __name__ == "__main__":
    unittest.main()
