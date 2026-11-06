"""File: services/identity/tests/test_prepare_identity_runtime_env.py
Purpose: Offline tests of the exact existing-secret Django BFF EnvironmentFile
  preparation, isolated database roles, nonroot Django checks and root-only
  exclusive file creation.
Linked: services/identity/ops/prepare_identity_runtime_env.py,
  services/identity/config/settings.py,
  services/identity/omnilyzer-identity.service.
"""
import base64
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest import mock


# Section 1: Source-executed operator with synthetic credentials only.
FILE = Path(__file__).resolve().parents[1] / "ops/prepare_identity_runtime_env.py"
SPEC = importlib.util.spec_from_file_location("m01_bff_runtime_env", FILE)
OP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OP)
CLIENT = {
    "OIDC_ISSUER": OP.OIDC_ISSUER,
    "OIDC_CLIENT_ID": OP.OIDC_CLIENT_ID,
    "OIDC_CLIENT_SECRET": "s" * 64,
}
DB = {
    "IDENTITY_PG_DATABASE": "omnilyzer_identity_sessions",
    "IDENTITY_PG_USER": "omnilyzer_identity_runtime",
    "IDENTITY_PG_PASSWORD": "p" * 64,
    "IDENTITY_PG_HOST": "127.0.0.1",
    "IDENTITY_PG_PORT": "5432",
}
SECRET_VALUES = {**CLIENT, **DB}


def fragment(data):
    """Prepare one fictitious upstream KEY=value source fragment."""
    return "".join(key + "=" + val + "\n"
                   for key, val in data.items()).encode("ascii")


class RuntimeEnvTests(unittest.TestCase):
    """Enforce exact config, negative credential cases and no service actions."""

    def test_upstream_fragments_exact(self):
        self.assertEqual(OP.exact_fragment(fragment(CLIENT), OP.OIDC_KEYS), CLIENT)
        self.assertEqual(OP.exact_fragment(fragment(DB), OP.DB_KEYS), DB)

    def test_reject_missing_duplicate_and_extra_credentials(self):
        bad = (
            fragment(CLIENT).replace(b"OIDC_CLIENT_SECRET=", b"EXTRA="),
            fragment(CLIENT) + b"OIDC_CLIENT_SECRET=duplicate\n",
            fragment(CLIENT) + b"UNEXPECTED_FIELD=foo\n",
            fragment(CLIENT).replace(b"OIDC_CLIENT_SECRET=s",
                                     b'OIDC_CLIENT_SECRET=bad"s'),
            fragment(CLIENT).rstrip(b"\n"),
            fragment(CLIENT).replace(b"\n", b"\r\n"),
        )
        for case in bad:
            with self.subTest(case=case[:20]):
                with self.assertRaisesRegex(RuntimeError, "HOLD"):
                    OP.exact_fragment(case, OP.OIDC_KEYS)

    def test_production_source_values_cannot_be_changed(self):
        with mock.patch.object(OP, "secure_regular_file",
                               side_effect=[fragment(CLIENT), fragment(DB)]):
            self.assertEqual(OP.credentials(), SECRET_VALUES)
        for changes in (
            {"OIDC_CLIENT_ID": "other-client"},
            {"OIDC_ISSUER": "https://evil.example/realms/x"},
            {"OIDC_CLIENT_SECRET": "short"},
            {"IDENTITY_PG_DATABASE": "sumlaude_learning"},
            {"IDENTITY_PG_USER": "postgres"},
            {"IDENTITY_PG_HOST": "/var/run/postgresql"},
            {"IDENTITY_PG_PASSWORD": "short"},
        ):
            edited = {**SECRET_VALUES, **changes}
            with mock.patch.object(OP, "secure_regular_file", side_effect=[
                fragment({k: edited[k] for k in CLIENT}),
                fragment({k: edited[k] for k in DB}),
            ]):
                with self.subTest(changes=changes):
                    with self.assertRaisesRegex(RuntimeError, "mismatch"):
                        OP.credentials()

    def test_env_uses_exact_server_side_issuer_dsn_and_quoted_value(self):
        fernet = base64.urlsafe_b64encode(bytes(range(32))).decode()
        env, body = OP.assembled_variables(
            SECRET_VALUES, signing_key="signing-" + "x" * 64, fernet_key=fernet)
        self.assertEqual(env["SUMLAUDE_ISSUER_DSN"], OP.ISSUER_DSN)
        self.assertIn(
            b'SUMLAUDE_ISSUER_DSN="dbname=sumlaude_learning '
            b'user=sumlaude_identity_issuer '
            b'host=/var/run/postgresql port=5432"\n', body)
        self.assertEqual(body.count(b"IDENTITY_PG_PASSWORD="), 1)
        self.assertNotIn(b"owner-approved-go", body)
        self.assertNotIn(b"JWT", body)

    def test_reject_unsafe_runtime_secret_characters(self):
        for value in ("bad\nvalue", 'bad"quote', "bad\\slash", ""):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "unsafe"):
                    OP.assembled_variables(
                        {**SECRET_VALUES, "OIDC_CLIENT_SECRET": value},
                        signing_key="s" * 64,
                        fernet_key=base64.urlsafe_b64encode(b"x" * 32).decode())

    def test_nonroot_operator_denied(self):
        with mock.patch.object(OP.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "trusted root"):
                OP.root_operator_guard()

    def test_live_env_or_go_marker_denied_before_secret_read(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            old = root / "old"
            old.mkdir()
            selected = root / "selected"
            selected.symlink_to(old, target_is_directory=True)
            m = mock.Mock()
            m.st_mode = stat.S_IFDIR | 0o700
            m.st_uid = m.st_gid = 0
            with (mock.patch.object(OP, "root_operator_guard"),
                  mock.patch.object(OP.socket, "gethostname", return_value=OP.HOST),
                  mock.patch.object(OP, "PRIVATE_DIR") as private,
                  mock.patch.object(OP, "KEYCLOAK_DIR") as keycloak,
                  mock.patch.object(OP, "CURRENT", selected),
                  mock.patch.object(OP, "OLD_RELEASE", old),
                  mock.patch.object(OP, "DEST", root / "identity.env"),
                  mock.patch.object(OP, "APPROVAL", root / "owner-approved-go")):
                private.lstat.return_value = m
                keycloak.lstat.return_value = m
                (root / "owner-approved-go").write_text("no")
                with self.assertRaisesRegex(RuntimeError, "activation marker"):
                    OP.host_guard()
                (root / "owner-approved-go").unlink()
                (root / "identity.env").write_text("no")
                with self.assertRaisesRegex(RuntimeError, "identity.env already"):
                    OP.host_guard()

    def test_preflight_never_writes_and_uses_existing_credentials(self):
        with (mock.patch.object(OP, "host_guard") as host,
              mock.patch.object(OP, "credentials", return_value=SECRET_VALUES) as cred,
              mock.patch.object(OP, "verify_runtime") as verify,
              mock.patch("builtins.print")):
            OP.preflight()
            host.assert_called_once()
            cred.assert_called_once()
            verify.assert_called_once()
            cfg = verify.call_args.args[0]
            self.assertEqual(cfg["OIDC_CLIENT_SECRET"], CLIENT["OIDC_CLIENT_SECRET"])
            self.assertTrue(cfg["DJANGO_SECRET_KEY"].startswith("synthetic-preflight"))

    def test_real_nonroot_check_invokes_unchanged_systemd_manage_and_db(self):
        with (mock.patch.object(OP, "run", side_effect=[
                mock.Mock(returncode=0,
                          stdout="System check identified no issues (0 silenced)."),
                mock.Mock(returncode=0, stdout=""),
              ]) as run,
              mock.patch.object(OP, "RELEASE") as release):
            release.__truediv__.return_value.__truediv__.return_value.is_file.return_value = True
            OP.verify_runtime({"DJANGO_SECRET_KEY": "synthetic"})
            self.assertEqual(run.call_count, 2)
            cmd = run.call_args_list[0].args[0]
            self.assertEqual(cmd[-3:], ["manage.py", "check", "--deploy"])
            self.assertNotIn("-I", cmd)
            self.assertEqual(run.call_args_list[1].args[0][-2], "-c")

    def test_prepare_writes_only_exclusive_root0600_file(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "identity.env"
            real_lstat = Path.lstat

            def no_root_fs_test_lstat(path):
                """Treat only the synthetic output as root-owned after mocked chown."""
                result = real_lstat(path)
                if path == dest:
                    return SimpleNamespace(
                        st_mode=result.st_mode, st_uid=0, st_gid=0)
                return result

            with (mock.patch.object(OP, "DEST", dest),
                  mock.patch.object(OP, "preflight"),
                  mock.patch.object(OP, "host_guard"),
                  mock.patch.object(OP, "credentials",
                                    return_value=SECRET_VALUES),
                  mock.patch.object(OP, "verify_runtime"),
                  mock.patch.object(OP.os, "fchown"),
                  mock.patch.object(Path, "lstat", no_root_fs_test_lstat),
                  mock.patch("builtins.print")):
                OP.prepare()
                self.assertTrue(dest.is_file())
                self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
                self.assertIn(b"SUMLAUDE_ISSUER_DSN=", dest.read_bytes())
                with self.assertRaises(FileExistsError):
                    OP.prepare()


if __name__ == "__main__":
    unittest.main()
