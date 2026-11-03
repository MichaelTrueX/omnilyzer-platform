"""File: services/identity/tests/test_bff_session_db_prepare.py
Purpose: Security-unit proof for ONE inactive Django PostgreSQL session
    database bootstrap, without a PostgreSQL server or privileged operations.
Related: services/identity/ops/bff_session_db_prepare.py,
    services/identity/config/settings.py,
    services/identity/omnilyzer-identity.service, SECURITY.md.

All tests use synthetic credentials and injected database results. These
tests do NOT authorize production SQL, a new learner, or release activation.
"""
import importlib.util
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "ops/bff_session_db_prepare.py"
SPEC = importlib.util.spec_from_file_location("bff_session_db_prepare", SOURCE)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class BffSessionDbPrepareTests(unittest.TestCase):
    """Assert least-privilege boundaries before any owner-root execution."""

    def test_pin_only_existing_original_platform_scope(self):
        """Keep current Keycloak, single offline Django venv and dedicated DB."""
        self.assertEqual(MOD.HOST, "truexmainserver")
        self.assertEqual(MOD.DB, "omnilyzer_identity_sessions")
        self.assertEqual(MOD.RUNTIME_ROLE, "omnilyzer_identity_runtime")
        self.assertEqual(MOD.DB_PORT, 5432)
        self.assertTrue(str(MOD.SOURCE).endswith(
            "omnilyzer-identity-bff-candidate-f8fe41d056d8"))
        self.assertEqual(MOD.SOURCE_TAR_SHA256,
                         "584399803a6d94f52cf9950e8c39f4618aa9cde81036154f6527c4e40f364d59")
        self.assertIn("partial", MOD.PARTIAL_ENV.name)

    def test_safety_check_fails_closed_before_root_operations(self):
        """Do not create a DB or role when root or source seal is missing."""
        with mock.patch.object(MOD.os, "geteuid", return_value=1000), \
             mock.patch.object(MOD, "pgsql") as sql:
            with self.assertRaisesRegex(RuntimeError, "owner-root"):
                MOD.root_guard()
            sql.assert_not_called()
        with mock.patch.object(MOD.os, "geteuid", return_value=0), \
             mock.patch.object(MOD, "local_preflight",
                               return_value=["existing production environment"]), \
             mock.patch.object(MOD, "pgsql") as sql:
            with self.assertRaisesRegex(RuntimeError, "existing production environment"):
                MOD.root_guard()
            sql.assert_not_called()

    def test_schema_grants_limit_runtime_to_session_table_dml(self):
        """Separate PostgreSQL DBA ownership from narrowly scoped Django user."""
        commands = []

        def fake_sql(sql, database="postgres"):
            commands.append((sql, database))
            return "1|0|1|1|1|1|0|0"

        with mock.patch.object(MOD, "pgsql", side_effect=fake_sql), redirect_stdout(io.StringIO()):
            MOD.restrict_runtime_role()
        self.assertEqual(len(commands), 3)
        db_rights, object_rights, audit = commands
        self.assertEqual(db_rights[1], "postgres")
        self.assertIn("REVOKE ALL ON DATABASE omnilyzer_identity_sessions FROM PUBLIC",
                      db_rights[0])
        self.assertIn("GRANT CONNECT ON DATABASE", db_rights[0])
        self.assertEqual(object_rights[1], MOD.DB)
        self.assertIn("REVOKE ALL ON SCHEMA public FROM PUBLIC", object_rights[0])
        self.assertIn("SELECT,INSERT,UPDATE,DELETE ON TABLE public.django_session",
                      object_rights[0])
        self.assertNotIn("GRANT ALL", object_rights[0])
        self.assertNotIn("django_migrations TO", object_rights[0])
        self.assertNotIn("CREATE ON SCHEMA", object_rights[0])
        self.assertIn("has_table_privilege", audit[0])
        self.assertIn("django_migrations','SELECT", audit[0])

    def test_grant_audit_denial_fails_closed(self):
        """Fail on any unexpected DDL, migration read, or missing session grant."""
        for bad in ("1|1|1|1|1|1|0|0", "1|0|1|1|1|1|1|0",
                    "1|0|1|1|1|1|0|1", "1|0|1|1|1|0|0|0"):
            with self.subTest(grants=bad), \
                 mock.patch.object(MOD, "pgsql", return_value=bad):
                with self.assertRaisesRegex(RuntimeError, "grants not verified"):
                    MOD.restrict_runtime_role()

    def test_password_is_sent_only_to_psql_stdin(self):
        """No SQL statement, generated password or DSN can appear in argv."""
        psql_response = mock.Mock(returncode=0, stdout="0|0\n", stderr="")
        with mock.patch.object(MOD.subprocess, "run", return_value=psql_response) as runner:
            result = MOD.pgsql("SELECT 'SYNTHETIC_SECRET_SHOULD_NOT_BE_IN_ARGV';")
        self.assertEqual(result, "0|0")
        args = runner.call_args.args[0]
        self.assertEqual(args[0], "/usr/sbin/runuser")
        self.assertIn("-X", args)
        self.assertIn("ON_ERROR_STOP=1", args)
        self.assertNotIn("SYNTHETIC_SECRET_SHOULD_NOT_BE_IN_ARGV", " ".join(args))
        self.assertIn("SYNTHETIC_SECRET_SHOULD_NOT_BE_IN_ARGV",
                      runner.call_args.kwargs["input"])

    def test_unprivileged_preflight_never_probes_root_private_secret_files(self):
        """A source-only owner cannot infer absent secrets inside root0700."""
        class Forbidden:
            def exists(self):
                raise AssertionError("unprivileged code probed root private file")
            def is_symlink(self):
                raise AssertionError("unprivileged code probed root private file")
        with mock.patch.multiple(
                MOD, LIVE_ENV=Forbidden(), PARTIAL_ENV=Forbidden(),
                APPROVAL=Forbidden()), \
             mock.patch.object(MOD.os, "geteuid", return_value=1000), \
             mock.patch.object(MOD, "call",
                               return_value="ActiveState=inactive\nUnitFileState=disabled"):
            problems = MOD.local_preflight()
            self.assertIsInstance(problems, list)

    def test_postgres_migrations_use_dba_not_runtime_role(self):
        """Use old pinned Django migration code only under local postgres peer."""
        captured = []

        def fake_call(argv, **kwargs):
            captured.append((argv, kwargs))
            return ""

        with mock.patch.object(MOD, "call", side_effect=fake_call):
            MOD.django_migrate()
        self.assertEqual(len(captured), 1)
        command, values = captured[0]
        self.assertEqual(command[:5], [
            "/usr/sbin/runuser", "-u", "postgres", "--",
            str(MOD.ORIGINAL_RELEASE / ".venv/bin/python"),
        ])
        self.assertEqual(command[-3:], ["migrate", "--noinput", "--verbosity", "0"][-3:])
        env = values["env"]
        self.assertEqual(env["IDENTITY_PG_USER"], "postgres")
        self.assertEqual(env["IDENTITY_PG_DATABASE"], MOD.DB)
        self.assertEqual(env["PRODUCT_ORIGIN"], "https://app.sumlaude.com")
        self.assertEqual(env["OIDC_ISSUER"],
                         "https://login.omnilyzer.ai/realms/omnilyzer")
        self.assertTrue(env["SUMLAUDE_ISSUER_DSN"].startswith("dbname=UNREACHABLE"))
        self.assertNotIn("real", env["IDENTITY_PG_PASSWORD"])

    def test_prepare_only_once_creates_root_only_partial_not_live_env(self):
        """Test exact partial config without accessing actual prod credentials."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fragment = root / "identity-session-db.env.partial"
            result = iter(["0", "ActiveState=inactive\nUnitFileState=disabled"])

            def fake_pgsql(sql, database="postgres"):
                return "0" if "count(*)" in sql else ""

            with mock.patch.multiple(MOD, PARTIAL_ENV=fragment,
                                     LIVE_ENV=root / "identity.env",
                                     APPROVAL=root / "owner-approved-go"), \
                 mock.patch.object(MOD, "root_guard"), \
                 mock.patch.object(MOD, "pgsql", side_effect=fake_pgsql) as sql, \
                 mock.patch.object(MOD, "django_migrate") as migrations, \
                 mock.patch.object(MOD, "restrict_runtime_role") as grants, \
                 mock.patch.object(MOD, "verify_runtime_connection") as runtime, \
                 mock.patch.object(MOD, "call",
                      return_value="ActiveState=inactive\nUnitFileState=disabled"), \
                 redirect_stdout(io.StringIO()):
                MOD.prepare()
                self.assertEqual(fragment.stat().st_mode & 0o777, 0o600)
                lines = fragment.read_text().splitlines()
                self.assertEqual(len(lines), 5)
                self.assertEqual(lines[0], "IDENTITY_PG_DATABASE=" + MOD.DB)
                self.assertEqual(lines[1], "IDENTITY_PG_USER=" + MOD.RUNTIME_ROLE)
                self.assertTrue(lines[2].startswith("IDENTITY_PG_PASSWORD="))
                self.assertGreaterEqual(len(lines[2].split("=", 1)[1]), 48)
                self.assertEqual(lines[3], "IDENTITY_PG_HOST=127.0.0.1")
                self.assertFalse((root / "identity.env").exists())
                self.assertFalse((root / "owner-approved-go").exists())
                migrations.assert_called_once()
                grants.assert_called_once()
                runtime.assert_called_once()
                self.assertTrue(any("scram-sha-256" in c.args[0]
                                    for c in sql.call_args_list))
                with self.assertRaises(FileExistsError):
                    MOD.prepare()

    def test_runtime_scram_login_is_proved_without_argv_secret(self):
        """Use localhost-only password auth with actual least privilege check."""
        with mock.patch.object(
                MOD, "call",
                return_value=MOD.RUNTIME_ROLE + "|0|0|1|0|0") as call, \
             redirect_stdout(io.StringIO()):
            MOD.verify_runtime_connection("SYNTHETIC_PASSWORD_FOR_TESTS_ONLY")
        args, kwargs = call.call_args
        command = args[0]
        self.assertEqual(command[0], "/usr/bin/psql")
        self.assertIn("127.0.0.1", command)
        self.assertIn(MOD.DB, command)
        self.assertIn(MOD.RUNTIME_ROLE, command)
        self.assertNotIn("SYNTHETIC_PASSWORD_FOR_TESTS_ONLY", " ".join(command))
        self.assertEqual(kwargs["env"]["PGPASSWORD"],
                         "SYNTHETIC_PASSWORD_FOR_TESTS_ONLY")
        self.assertEqual(kwargs["env"]["PGSSLMODE"], "disable")
        self.assertIn("django_migrations", " ".join(command))
        with mock.patch.object(MOD, "call",
                               return_value=MOD.RUNTIME_ROLE + "|1|0|1|0|0"):
            with self.assertRaisesRegex(RuntimeError, "isolation failed"):
                MOD.verify_runtime_connection("SYNTHETIC_PASSWORD_FOR_TESTS_ONLY")

    def test_no_live_services_or_existing_product_changes(self):
        """Reject any Task014, S03, Keycloak or Nginx writes in this operator."""
        source = SOURCE.read_text()
        for forbidden in (
            "systemctl start", "systemctl enable", "systemctl restart",
            "systemctl reload", "nginx -s reload", "kc.sh", "CREATE DATABASE sumlaude",
            "DROP DATABASE", "DROP ROLE", "ALTER TABLE sumlaude",
            "CREATE USER student", "CREATE TABLE learner_admission",
            "CREATE DATABASE analytics", "ALTER ROLE postgres",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('choices=("preflight", "prepare")', source)
        self.assertIn("os.O_EXCL", source)


if __name__ == "__main__":
    unittest.main()
