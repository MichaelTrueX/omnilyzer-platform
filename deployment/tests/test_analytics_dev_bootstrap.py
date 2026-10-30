"""File: deployment/tests/test_analytics_dev_bootstrap.py

Purpose: Static and mocked first-install safety checks for the DEV-only
         Analytics PostgreSQL bootstrap operator, without changing any host.
Related: deployment/analytics_dev_bootstrap.py.

Sections: host/privilege denial, no-replacement secret files, precise SQL and
          container command construction, restricted named credential handoff.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from deployment import analytics_dev_bootstrap as bootstrap


class BootstrapOperatorTests(unittest.TestCase):
    """Exercise privilege boundaries using synthetic inputs only."""

    def test_declines_wrong_identity_and_host(self):
        """Reject before any filesystem or Docker interaction."""
        with patch.object(bootstrap.os, "geteuid", return_value=1005):
            with self.assertRaises(bootstrap.BootstrapDenied):
                bootstrap.preflight()
        with patch.object(bootstrap.os, "geteuid", return_value=0), \
             patch.object(bootstrap.socket, "gethostname", return_value="prod-host"):
            with self.assertRaises(bootstrap.BootstrapDenied):
                bootstrap.preflight()

    def test_exact_sql_and_secret_contracts(self):
        """Prevent ad hoc schema, credential names or unpinned Docker tag."""
        self.assertEqual(len(bootstrap.STAGES), 5)
        self.assertEqual(len({name for name, _ in bootstrap.STAGES}), 5)
        self.assertTrue(all(len(digest) == 64 for _, digest in bootstrap.STAGES))
        self.assertIn("@sha256:", bootstrap.IMAGE)
        self.assertEqual(bootstrap.NETWORK, "omnilyzer-analytics-backend-dev")
        self.assertEqual(bootstrap.MAPPED_APP_UID, 503216)
        self.assertEqual(bootstrap.SECRET_NAMES, (
            "COLLECTOR_DATABASE_URL", "DATABASE_URL", "JWT_REFRESH_SECRET", "JWT_SECRET"))

    def test_secret_never_overwrites_existing_file(self):
        """An existing credential inode must survive unchanged on retry."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "credential"
            bootstrap.private_file(path, b"FIRST=value\n", uid=os.geteuid(),
                                   gid=os.getegid(), mode=0o600)
            self.assertEqual(path.read_bytes(), b"FIRST=value\n")
            with self.assertRaises(FileExistsError):
                bootstrap.private_file(path, b"SECOND=wrong\n", uid=os.geteuid(),
                                       gid=os.getegid(), mode=0o600)
            self.assertEqual(path.read_bytes(), b"FIRST=value\n")

    def test_postgres_exec_password_only_on_stdin(self):
        """Never place secret SQL in process argv or Docker environment."""
        calls = []
        def capture(argv, **kwargs):
            calls.append((argv, kwargs))
            return b"5\n"
        with patch.object(bootstrap, "run", side_effect=capture):
            self.assertEqual(bootstrap.postgres_exec(b"ALTER ROLE a PASSWORD 'synthetic';",
                                                    secret_step=True), b"5\n")
        argv, kwargs = calls[0]
        self.assertEqual(argv[:3], (*bootstrap.DOCKER[:2], bootstrap.DOCKER[2]))
        self.assertNotIn("synthetic", " ".join(argv))
        self.assertIn(b"synthetic", kwargs["data"])
        self.assertTrue(kwargs["secret_step"])

    def test_only_four_correct_mapped_secrets_created(self):
        """Verify original UID10001 mapping and SQL/app role separation."""
        created = []
        query_calls = []
        def capture_file(path, data, *, uid, gid, mode):
            created.append((path.name, data, uid, gid, mode))
        def capture_sql(sql, *, secret_step=False):
            query_calls.append((sql, secret_step))
            return b""
        tokens = ["A"*64, "B"*64, "C"*64, "D"*64]
        with patch.object(bootstrap, "private_file", side_effect=capture_file), \
             patch.object(bootstrap, "postgres_exec", side_effect=capture_sql):
            bootstrap.install_runtime_credentials(*tokens)
        self.assertEqual([a[0] for a in created], list(bootstrap.SECRET_NAMES))
        self.assertTrue(all(a[2:] == (503216, 503216, 0o600) for a in created))
        self.assertIn(b"ALTER ROLE omni_runtime LOGIN PASSWORD", query_calls[0][0])
        self.assertIn(b"ALTER ROLE collector_runtime LOGIN PASSWORD", query_calls[0][0])
        self.assertTrue(query_calls[0][1])
        self.assertTrue(created[0][1].startswith(b"COLLECTOR_DATABASE_URL=postgresql://collector_runtime:"))
        self.assertTrue(created[1][1].startswith(b"DATABASE_URL=postgresql://omni_runtime:"))
        self.assertIn(bootstrap.CONTAINER.encode(), created[0][1])

    def test_failure_does_not_expose_credentials(self):
        """Caller receives a generic failure when secret commands fail."""
        fake_result = types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"secret-leak-string")
        with patch.object(bootstrap.subprocess, "run", return_value=fake_result):
            with self.assertRaisesRegex(bootstrap.BootstrapDenied, "secret operation denied") as cm:
                bootstrap.run(["/usr/bin/false"], data=b"secret-sql", secret_step=True)
        self.assertNotIn("secret-leak-string", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
