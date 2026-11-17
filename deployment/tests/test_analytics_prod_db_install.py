#!/usr/bin/env python3
"""File: deployment/tests/test_analytics_prod_db_install.py

Purpose: Unit-only fail-closed checks for the one-shot private Analytics PROD
         PostgreSQL bootstrap and non-secret source/credential boundaries.
Related: deployment/analytics_prod_db_install.py,
         deployment/analytics_prod_sql_admission.py.

Sections: fixed source gate, one-shot controls, SQL sequencing, credential
          custody, and no-retry failures. No actual PG/host mutation.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "analytics_prod_db_install.py"
SPEC = importlib.util.spec_from_file_location("analytics_prod_db_install", SOURCE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class TestFirstInstall(unittest.TestCase):
    """The interpreter must only support the reviewed new-db contract."""

    def test_empty_gate_pin_holds(self):
        """An unpinned release operator cannot import writable code as root."""
        with self.assertRaisesRegex(m.InstallHold, "missing reviewed gate"):
            m.gate_module()

    def test_prod_preflight_refuses_marker(self):
        """A prior partial first install cannot replay its original action."""
        with mock.patch.object(m, "check_context"), \
             mock.patch.object(m, "directory"), \
             mock.patch.object(m.os.path, "lexists", return_value=True):
            with self.assertRaisesRegex(m.InstallHold, "prior DB installation"):
                m.preflight()

    def test_context_refuses_nonroot(self):
        """No direct unprivileged install."""
        with mock.patch.object(m.os, "getuid", return_value=1000), \
             mock.patch.object(m.os, "geteuid", return_value=1000):
            with self.assertRaises(m.InstallHold):
                m.check_context()

    def test_migration_order(self):
        """Only the five accepted SHA-pinned SQL stages run, in fixed order."""
        gate = mock.Mock()
        gate.exact_file.side_effect = lambda path, **kwargs: path.name.encode()
        with mock.patch.object(m, "run") as run, mock.patch.object(m, "psql") as psql:
            m.execute_sql(gate)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(psql.call_count, 5)
        self.assertEqual([x.args[1] for x in psql.call_args_list],
                         [x.encode() for x in m.SQL_NAMES])

    def test_migration_failure_stops_sequence(self):
        """A failed migration does not proceed to later SQL stages."""
        gate = mock.Mock()
        gate.exact_file.return_value = b"approved SQL"
        with mock.patch.object(m, "run"), mock.patch.object(
                m, "psql", side_effect=m.InstallHold("stop")) as sql:
            with self.assertRaises(m.InstallHold):
                m.execute_sql(gate)
        self.assertEqual(sql.call_count, 1)

    def test_secrets_only_prod_names(self):
        """The prepared credential set matches the existing Compose secrets."""
        with mock.patch.object(m.secrets, "token_urlsafe",
                               side_effect=["A"*64, "B"*64, "C"*64, "D"*64]), \
             mock.patch.object(m, "psql") as sql:
            contents = m.generate_credentials()
        self.assertEqual(set(contents), set(m.SECRET_NAMES))
        self.assertEqual(sql.call_count, 2)
        self.assertIn(b"ALTER ROLE omni_runtime", sql.call_args_list[0].args[1])
        self.assertIn(b"ALTER ROLE collector_runtime", sql.call_args_list[1].args[1])
        self.assertIn(b"host=/var/run/postgresql", contents["DATABASE_URL"])
        self.assertIn(b"omnilyzer_analytics_prod", contents["COLLECTOR_DATABASE_URL"])
        self.assertNotIn(b"omnilyzer_analytics_dev", b"".join(contents.values()))

    def test_wrong_secret_set_rejected(self):
        """Missing one of four secrets must prevent private directory creation."""
        with mock.patch.object(m.os, "mkdir") as mkdir:
            with self.assertRaises(m.InstallHold):
                m.seal_secrets({"JWT_SECRET": b"JWT_SECRET=A\n"})
        mkdir.assert_not_called()

    def test_secret_format_rejected(self):
        """An incorrect label never silently produces an unreadable app secret."""
        data = {n: (n+"=ABC\n").encode() for n in m.SECRET_NAMES}
        data["DATABASE_URL"] = b"WRONG=not a database url\n"
        with mock.patch.object(m.os, "mkdir"), mock.patch.object(m.os, "chown"), \
             mock.patch.object(m.os, "chmod"), mock.patch.object(m, "new_file") as store:
            with self.assertRaises(m.InstallHold):
                m.seal_secrets(data)
        store.assert_not_called()

    def test_apply_preserves_partial_on_error(self):
        """The failure marker is kept, with no automatic cleanup or second attempt."""
        with mock.patch.object(m, "preflight", return_value=mock.Mock()), \
             mock.patch.object(m, "start_marker") as marker, \
             mock.patch.object(m, "execute_sql", side_effect=m.InstallHold("partial")), \
             mock.patch.object(m, "generate_credentials") as creds, \
             mock.patch.object(m, "install_hba") as hba:
            with self.assertRaises(m.InstallHold):
                m.apply()
        marker.assert_called_once()
        creds.assert_not_called()
        hba.assert_not_called()

    def test_hba_insertion_only_target_db(self):
        """Do not insert broad or different-DB authentication rules."""
        self.assertEqual(m.HBA_INSERT.count(b"\n"), 2)
        for line in m.HBA_INSERT.splitlines():
            self.assertIn(b"local   omnilyzer_analytics_prod ", line)
            self.assertIn(b" scram-sha-256", line)
            self.assertNotIn(b"trust", line)

    def test_hba_preserve_existing_peer(self):
        """The original peer rule is retained after the new narrow entries."""
        original = b"local all postgres peer\n"+m.HBA_NEEDLE
        self.assertEqual(original.count(m.HBA_NEEDLE), 1)
        updated = original.replace(m.HBA_NEEDLE, m.HBA_INSERT + m.HBA_NEEDLE, 1)
        self.assertIn(m.HBA_NEEDLE, updated)
        self.assertEqual(updated.replace(m.HBA_INSERT, b""), original)

    def test_inspection_has_no_privileged_mutation(self):
        """Metadata-only inspection never contacts DB or Docker."""
        with mock.patch.object(m, "check_context"), \
             mock.patch.object(m, "STATE", mock.Mock(is_file=lambda: False)), \
             mock.patch.object(m, "HBA_ORIGINAL", mock.Mock(is_file=lambda: False)), \
             mock.patch.object(m, "SECRETS", mock.Mock(is_dir=lambda: False)), \
             mock.patch.object(m, "run") as run:
            m.inspect()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
