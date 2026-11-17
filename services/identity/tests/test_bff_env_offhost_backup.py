"""File: services/identity/tests/test_bff_env_offhost_backup.py
Purpose: Exercise exactly-once encrypted BFF EnvironmentFile backup contract,
  pinned independent recipient, source-fragment equality, guarded root export
  and no plaintext, SQL, app startup or mutable-Keycloak backup changes.
Related: services/identity/ops/bff_env_offhost_backup.py,
  services/identity/ops/keycloak_offhost_backup.py,
  services/identity/ops/prepare_identity_runtime_env.py.
All credentials and test ciphertext below are synthetic and ephemeral.
"""
import base64
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


# Section 1: Read the source operator without executing main().
SOURCE = Path(__file__).resolve().parents[1] / "ops/bff_env_offhost_backup.py"
SPEC = importlib.util.spec_from_file_location("m01_bff_offhost_backup", SOURCE)
OP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OP)

CLIENT_VALUES = {
    "OIDC_ISSUER": "https://login.omnilyzer.ai/realms/omnilyzer",
    "OIDC_CLIENT_ID": "sumlaude-bff",
    "OIDC_CLIENT_SECRET": "C" * 64,
}
DB_VALUES = {
    "IDENTITY_PG_DATABASE": "omnilyzer_identity_sessions",
    "IDENTITY_PG_USER": "omnilyzer_identity_runtime",
    "IDENTITY_PG_PASSWORD": "D" * 64,
    "IDENTITY_PG_HOST": "127.0.0.1",
    "IDENTITY_PG_PORT": "5432",
}
LIVE_VALUES = {
    "DJANGO_SECRET_KEY": "django-signing-test-" + "s" * 64,
    "TOKEN_FERNET_KEY": base64.urlsafe_b64encode(b"\x11" * 32).decode(),
    "PRODUCT_ORIGIN": "https://app.sumlaude.com",
    **CLIENT_VALUES,
    **DB_VALUES,
    "SUMLAUDE_ISSUER_DSN": OP.ISSUER_DSN,
}


def env_bytes(data):
    """Construct only a synthetic systemd EnvironmentFile for test input."""
    return ("".join(
        key + "=" + ('"' + value + '"' if " " in value else value) + "\n"
        for key, value in data.items()
    )).encode("ascii")


class BffIdentityBackupTests(unittest.TestCase):
    """Check guarded source preservation and age-ciphertext-only behavior."""

    def test_source_matches_current_12_field_contract(self):
        self.assertEqual(set(LIVE_VALUES), OP.ALL_KEYS)
        self.assertEqual(OP.parse_env(env_bytes(LIVE_VALUES),
                                      expected=OP.ALL_KEYS), LIVE_VALUES)

    def test_source_fields_must_be_exactly_unique(self):
        cases = (
            env_bytes(LIVE_VALUES).replace(b"DJANGO_SECRET_KEY=",
                                           b"UNKNOWN_FIELD="),
            env_bytes(LIVE_VALUES) + b"OIDC_CLIENT_ID=duplicate\n",
            env_bytes(LIVE_VALUES).rstrip(b"\n"),
            env_bytes(LIVE_VALUES).replace(b"\n", b"\r\n"),
            env_bytes(LIVE_VALUES).replace(b"OIDC_CLIENT_ID=sumlaude-bff",
                                           b'OIDC_CLIENT_ID="sumlaude-bff\\"x"'),
        )
        for case in cases:
            with self.subTest(case=case[:22]):
                with self.assertRaisesRegex(RuntimeError, "HOLD"):
                    OP.parse_env(case, expected=OP.ALL_KEYS)

    def test_existing_sources_exactly_match_without_secret_logging(self):
        with mock.patch.object(OP, "file_bytes", side_effect=[
            env_bytes(LIVE_VALUES), env_bytes(CLIENT_VALUES),
            env_bytes(DB_VALUES)
        ]):
            self.assertTrue(OP.inspect_configuration())

    def test_disagreeing_confidential_client_denied(self):
        client = {**CLIENT_VALUES, "OIDC_CLIENT_SECRET": "unauthorized-secret"}
        with mock.patch.object(OP, "file_bytes", side_effect=[
            env_bytes(LIVE_VALUES), env_bytes(client), env_bytes(DB_VALUES)
        ]):
            with self.assertRaisesRegex(RuntimeError, "credentials differ"):
                OP.inspect_configuration()

    def test_invalid_or_changed_signing_fernet_and_issuer_denied(self):
        mutated = (
            {"DJANGO_SECRET_KEY": "tiny"},
            {"TOKEN_FERNET_KEY": "not-fernet"},
            {"OIDC_ISSUER": "https://lookalike.example.com/realms/omnilyzer"},
            {"SUMLAUDE_ISSUER_DSN": "host=public.example.com"},
            {"PRODUCT_ORIGIN": "https://other.example.com"},
        )
        for changes in mutated:
            values = {**LIVE_VALUES, **changes}
            matched_client = {k: values[k] for k in CLIENT_VALUES}
            matched_db = {k: values[k] for k in DB_VALUES}
            with mock.patch.object(OP, "file_bytes", side_effect=[
                env_bytes(values),
                env_bytes(matched_client),
                env_bytes(matched_db)
            ]):
                with self.subTest(changes=changes):
                    with self.assertRaisesRegex(RuntimeError, "HOLD"):
                        OP.inspect_configuration()

    def test_nonroot_unauthorized_operator_denied(self):
        with mock.patch.object(OP.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "root operator"):
                OP.operator_guard()

    def test_protected_regular_file_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"
            source.write_text("synthetic")
            linked = Path(td) / "linked"
            linked.symlink_to(source)
            with self.assertRaisesRegex(RuntimeError, "metadata"):
                OP.file_bytes(linked, owner_uid=0)

    def test_encryption_source_open_rejects_symlink(self):
        """No symlink replacement after the preceding root-only inspection."""
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "real-source"
            source.write_text("synthetic-only")
            link = Path(td) / "hidden-source"
            link.symlink_to(source)
            with mock.patch.object(OP, "ENV", link):
                with self.assertRaisesRegex(RuntimeError, "metadata"):
                    OP.open_checked_source()

    def test_offhost_separation_is_current_recipient(self):
        self.assertEqual(
            OP.RECIPIENT_SHA256,
            "d6955c0bbc8a74847aa464196ac516275561ce6a7306674c9a8dd39d5150a492")
        self.assertEqual(OP.CIPHER_NAME,
                         "omnilyzer-bff-identity-env-20261106.age")
        self.assertNotEqual(OP.BACKUP_DIR.name, "omnilyzer-keycloak")
        self.assertTrue(str(OP.STAGED_CIPHER).startswith(
            "/home/trusthansen/.cache/omnilyzer-identity-production-preflight"))
        self.assertTrue(str(OP.ROOT_CIPHER).startswith(
            "/var/backups/omnilyzer-bff/"))

    def test_export_invokes_backup_only_once(self):
        with (mock.patch.object(OP, "preflight") as pre,
              mock.patch.object(OP, "inspect_configuration") as inspect,
              mock.patch.object(OP, "exclusive_cipher",
                                return_value=("f" * 64, 987)) as encrypt,
              mock.patch.object(OP, "stage_cipher") as stage,
              mock.patch("builtins.print") as printed):
            OP.export_once()
            pre.assert_called_once()
            inspect.assert_called_once()
            encrypt.assert_called_once()
            stage.assert_called_once_with("f" * 64)
            text = " ".join(str(call) for call in printed.call_args_list)
            self.assertIn("offsite_storage_PENDING=true", text)

    def test_preflight_failed_must_stop_before_encryption(self):
        with (mock.patch.object(OP, "preflight",
                                side_effect=RuntimeError("M01_BFF_BACKUP_HOLD")),
              mock.patch.object(OP, "exclusive_cipher") as encrypt,
              mock.patch.object(OP, "stage_cipher") as stage):
            with self.assertRaisesRegex(RuntimeError, "HOLD"):
                OP.export_once()
            encrypt.assert_not_called()
            stage.assert_not_called()

    def test_ciphertext_staging_only_copies_bytes_and_owner_mode(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.age"
            stage = root / "stage.age"
            payload = b"age-encryption.org/v1\n" + b"ciphertext-test" * 20
            source.write_bytes(payload)
            with (mock.patch.object(OP, "ROOT_CIPHER", source),
                  mock.patch.object(OP, "STAGED_CIPHER", stage),
                  mock.patch.object(OP.pwd, "getpwnam") as owner,
                  mock.patch.object(OP.os, "chown")):
                owner.return_value.pw_uid = 1000
                owner.return_value.pw_gid = 1000
                OP.stage_cipher(OP.digest(source))
            self.assertEqual(source.read_bytes(), stage.read_bytes())
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o600)
            with (mock.patch.object(OP, "ROOT_CIPHER", source),
                  mock.patch.object(OP, "STAGED_CIPHER", stage),
                  mock.patch.object(OP.pwd, "getpwnam") as owner):
                owner.return_value.pw_uid = 1000
                with self.assertRaises(FileExistsError):
                    OP.stage_cipher(OP.digest(source))


if __name__ == "__main__":
    unittest.main()
