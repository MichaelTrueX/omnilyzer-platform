"""File: deployment/tests/test_analytics_prod_scoped_ops.py

Purpose: Prevent privilege escalation in persistent PROD root-only operations.
Related: deployment/analytics_prod_scoped_ops.py,
         deployment/analytics_prod_ops_install.py,
         deployment/analytics_prod_pg_readonly.py.

Sections: exact sudo command policy; host, caller, file authenticity;
          operational allowlist; root-only installer and no-source-overwrite.
Tests execute no sudo, PostgreSQL, Docker or other privileged operation.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deployment import analytics_prod_ops_install as install
from deployment import analytics_prod_scoped_ops as ops


class AnalyticsProdScopedOpsTests(unittest.TestCase):
    """Keep persistent unattended access restricted to reviewed operations."""

    def test_exact_sudo_rule_has_no_general_root_or_wildcards(self) -> None:
        """Only two fully fixed Python commands are allowed, without shell."""
        policy = install.SUDOERS_TEXT
        self.assertIn("NOPASSWD:NOSETENV:", policy)
        self.assertEqual(policy.count("/usr/bin/python3 -I -B"), 2)
        self.assertIn("/usr/local/libexec/omnilyzer-analytics-prod-ops.py pg-audit", policy)
        self.assertIn("/usr/local/libexec/omnilyzer-analytics-prod-ops.py runtime-status", policy)
        self.assertNotIn("NOPASSWD:ALL", policy)
        self.assertNotIn("/bin/bash", policy)
        self.assertNotIn("/usr/bin/env ", policy)
        self.assertNotIn("*", policy)
        self.assertEqual(ops.OPERATIONS, ("pg-audit", "runtime-status"))

    def test_nonroot_or_wrong_sudo_owner_denied(self) -> None:
        """Even direct root/helper invocation must prove the expected owner."""
        with patch.object(ops.os, "geteuid", return_value=1000):
            with self.assertRaises(ops.AccessDenied):
                ops.require_context()
        with patch.object(ops.os, "geteuid", return_value=0):
            with patch.object(ops.os, "getuid", return_value=0):
                with patch.object(ops.socket, "gethostname", return_value=ops.HOST):
                    with patch.dict(ops.os.environ, {"SUDO_USER": "other", "SUDO_UID": "1001"}):
                        with self.assertRaises(ops.AccessDenied):
                            ops.require_context()

    def test_invalid_arguments_do_not_reach_any_privileged_method(self) -> None:
        """Reject dynamic files, commands and unapproved release operations."""
        with patch.object(ops, "require_context"):
            with patch.object(ops, "postgres_audit") as pg:
                with patch.object(ops, "runtime_status") as status:
                    for argv in (
                        ["program"], ["program", "pg-audit", "extra"],
                        ["program", "release"], ["program", "install"],
                        ["program", "/bin/bash"], ["program", "--shell"],
                    ):
                        with self.subTest(argv=argv):
                            with patch.object(ops.sys, "argv", argv):
                                self.assertEqual(ops.main(), 1)
                    pg.assert_not_called()
                    status.assert_not_called()

    def test_root_owned_pg_source_must_match_exact_digest_and_mode(self) -> None:
        """A mutable or altered PG audit can never become root code."""
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit"
            payload = b"canonical read-only audit"
            path.write_bytes(payload)
            path.chmod(0o500)
            digest = hashlib.sha256(payload).hexdigest()
            original_lstat = ops.os.lstat

            def privileged_inode(value):
                """Model root ownership while retaining real type/mode."""
                result = original_lstat(value)
                return SimpleNamespace(
                    st_mode=result.st_mode, st_uid=0,
                    st_gid=0, st_nlink=result.st_nlink,
                )

            with patch.object(ops.os, "lstat", side_effect=privileged_inode):
                ops.require_root_file(path, digest)
                with self.assertRaises(ops.AccessDenied):
                    ops.require_root_file(path, "0" * 64)
                path.chmod(0o644)
                with self.assertRaises(ops.AccessDenied):
                    ops.require_root_file(path, digest)

    def test_runtime_status_only_reads_fixed_services_and_loopback(self) -> None:
        """No service start/stop, Docker socket or untrusted command argument."""
        self.assertEqual(len(ops.OPERATIONS), 2)
        seen = []

        def fake_run(argv, **kwargs):
            seen.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, "active\n", "")

        class ClosedSocket:
            """A closed loopback port, without any network call."""
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def settimeout(self, _):
                return None

            def connect_ex(self, _):
                return 111

        with patch.object(ops.subprocess, "run", side_effect=fake_run):
            with patch.object(ops.socket, "socket", return_value=ClosedSocket()):
                output = ops.runtime_status()
        self.assertIn("READONLY_PASS no_changes=true", output)
        self.assertEqual(len(seen), 6)
        self.assertTrue(all(call[0:2] == ("/usr/bin/systemctl", "is-active") for call in seen))
        self.assertNotIn("docker ", str(seen).lower())

    def test_installer_root_gate_and_exclusive_creation(self) -> None:
        """Do not write privileged destinations as unprivileged user."""
        with patch.object(install.os, "geteuid", return_value=1000):
            with self.assertRaises(install.InstallHold):
                install.check_context()
        with TemporaryDirectory() as directory:
            file = Path(directory) / "root_file"
            install.install_new(file, b"reviewed", 0o500)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o500)
            with self.assertRaises(FileExistsError):
                install.install_new(file, b"replacement", 0o500)
            self.assertEqual(file.read_bytes(), b"reviewed")
            alias = Path(directory) / "alias"
            alias.symlink_to(file)
            with self.assertRaises(FileExistsError):
                install.install_new(alias, b"bad", 0o500)

    def test_existing_pg_script_digest_is_pinned_and_no_dynamic_imports(self) -> None:
        """Only the merged PostgreSQL read-only file may run as root."""
        from deployment import analytics_prod_pg_readonly
        source = Path(analytics_prod_pg_readonly.__file__).read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), ops.AUDIT_SHA256)
        self.assertEqual(ops.AUDIT_SHA256, install.PG_SHA256)
        self.assertEqual(ops.AUDIT, install.INSTALLED_PG)
        self.assertNotIn("importlib", Path(ops.__file__).read_text())
        self.assertNotIn("eval(", Path(ops.__file__).read_text())
        self.assertNotIn("exec(", Path(ops.__file__).read_text())


if __name__ == "__main__":
    unittest.main()
