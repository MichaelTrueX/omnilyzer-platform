"""File: deployment/tests/test_analytics_prod_pg_readonly.py

Purpose: Focused validation of the real PROD PostgreSQL catalog audit.
Related: deployment/analytics_prod_pg_readonly.py,
         deployment/runtime/prod/analytics.compose.private.yaml.

Sections: root/host gate, fixed read-only SQL subprocess and report integrity.
No actual PostgreSQL connection, privileged access, or server mutation.
"""
from __future__ import annotations

from unittest import TestCase, main
from unittest.mock import patch
import subprocess

from deployment import analytics_prod_pg_readonly as audit


REPORT = "\n".join((
    "CLUSTER|160015|5432|/var/run/postgresql|scram-sha-256",
    "TARGET_DB|0",
    "ROLE|omni_runtime|f|f|f|f|f|f",
    "HBA_LOCAL|90|all|postgres|peer",
    "HBA_LOCAL|95|all|all|peer",
    "HBA_ERRORS|0",
    "DATABASE_COUNT|3",
))


class ProdPostgresReadOnlyTests(TestCase):
    """Preserve least privilege for a single metadata-only PROD audit."""

    def test_fixed_query_is_explicitly_read_only(self) -> None:
        """No SQL creates credentials, roles, databases or HBA changes."""
        self.assertIn("BEGIN TRANSACTION READ ONLY;", audit.SQL)
        self.assertIn("SET LOCAL statement_timeout", audit.SQL)
        self.assertIn("COMMIT;", audit.SQL)
        for forbidden in (
            "CREATE ROLE", "ALTER ROLE", "CREATE DATABASE",
            "DROP ", "DELETE ", "INSERT ", "UPDATE ",
            "pg_read_file(", "rolpassword", "pg_authid",
        ):
            self.assertNotIn(forbidden, audit.SQL.upper() if forbidden.isupper() else audit.SQL)
        self.assertEqual(audit.HOST, "truexmainserver")
        self.assertEqual(audit.PSQL[:4], (
            "/usr/sbin/runuser", "-u", "postgres", "--",
        ))

    def test_inspection_rejects_unprivileged_host(self) -> None:
        """A privileged run can only happen on the intended existing PROD."""
        with patch.object(audit.os, "geteuid", return_value=1000):
            with self.assertRaises(audit.AuditHold):
                audit.check_context()
        with patch.object(audit.os, "geteuid", return_value=0):
            with patch.object(audit.socket, "gethostname", return_value="other"):
                with self.assertRaises(audit.AuditHold):
                    audit.check_context()

    def test_readonly_subprocess_never_uses_shell_or_password(self) -> None:
        """Only postgres peer access is used, without inherited environment."""
        completed = subprocess.CompletedProcess(audit.PSQL, 0, REPORT, "")
        with patch.object(audit.subprocess, "run", return_value=completed) as run:
            self.assertEqual(audit.execute_readonly(), REPORT)
        arguments, named = run.call_args
        self.assertEqual(arguments[0], audit.PSQL)
        self.assertEqual(named["input"], audit.SQL)
        self.assertIs(named["capture_output"], True)
        self.assertIs(named["check"], False)
        self.assertIs(named["text"], True)
        self.assertNotIn("shell", named)
        self.assertNotIn("PGPASSWORD", named["env"])
        self.assertIn("-w", audit.PSQL)
        self.assertIn("-q", audit.PSQL)

    def test_complete_catalog_report_and_negative_fail_closed(self) -> None:
        """Reject missing HBA rules, errors and major-version mismatches."""
        self.assertEqual(len(audit.verify_report(REPORT)), 7)
        for invalid in (
            REPORT.replace("HBA_ERRORS|0", "HBA_ERRORS|1"),
            REPORT.replace("160015", "150016"),
            REPORT.replace("HBA_LOCAL|", "HBA_OTHER|"),
            REPORT + "\nLEAK|secret",
            REPORT.replace("DATABASE_COUNT|3", ""),
        ):
            with self.subTest(invalid=invalid[-30:]):
                with self.assertRaises(audit.AuditHold):
                    audit.verify_report(invalid)

    def test_failure_never_exposes_server_diagnostics(self) -> None:
        """No password verifiers, PostgreSQL error body or files are printed."""
        completed = subprocess.CompletedProcess(
            audit.PSQL, 1, "", "hidden database diagnostic",
        )
        with patch.object(audit.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(
                audit.AuditHold, "catalog check rejected"
            ) as captured:
                audit.execute_readonly()
        self.assertNotIn("hidden database", str(captured.exception))


if __name__ == "__main__":
    main()
