"""File: services/identity/tests/test_prepare_s03_issuer_peer.py
Purpose: Fail-closed independent regression of the narrow root-operated S03
  PostgreSQL peer/ident change. All fixtures are in-memory or temporary files.
Related: services/identity/ops/prepare_s03_issuer_peer.py,
  services/identity/identity_bff/issuer.py.
No real PostgreSQL conf, service, credentials or S03 learner rows are touched.
"""
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


# Section 1: Load exact operator source for real pure-function tests.
SOURCE = Path(__file__).resolve().parents[1] / "ops/prepare_s03_issuer_peer.py"
SPEC = importlib.util.spec_from_file_location("m01_s03_issuer_peer", SOURCE)
OP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OP)

HBA = (
    "# PostgreSQL16 default local authentication\n"
    "local   all             postgres                     peer\n"
    "# TYPE DATABASE USER ADDRESS METHOD\n"
    "local   all             all                          peer\n"
    "host    all             all             127.0.0.1/32  scram-sha-256\n"
    "local   replication     all                          peer\n"
    "host    replication     all             ::1/128       scram-sha-256\n"
)
IDENT = (
    "# map-name system-username database-username\n"
    "# existing comments deliberately preserved\n"
)


class S03IssuerPeerOperatorTests(unittest.TestCase):
    """Verify exact least-privilege mapping and rejection of unsafe drift."""

    def test_exact_baseline_inserts_one_local_only_mapping(self):
        hba, ident = OP.propose_auth_change(HBA, IDENT)
        self.assertEqual(hba.count(OP.HBA_ENTRY), 1)
        self.assertEqual(ident.count(OP.IDENT_ENTRY), 1)
        self.assertEqual(hba.replace(OP.HBA_ENTRY, "", 1), HBA)
        self.assertEqual(ident.removesuffix(OP.IDENT_ENTRY), IDENT)
        self.assertLess(hba.index(OP.HBA_ENTRY),
                        hba.index("local   all             all"))
        self.assertIn("host    all             all", hba)
        self.assertNotIn("trust", hba)
        self.assertEqual(
            [r for r in OP.parse_rules(hba) if r[0] == "local"],
            [OP.HBA_EXPECTED_LOCAL[0], OP.HBA_ENTRY.split(),
             *OP.HBA_EXPECTED_LOCAL[1:]],
        )

    def test_idempotency_denied_instead_of_double_mapping(self):
        hba, ident = OP.propose_auth_change(HBA, IDENT)
        for a, b in ((hba, IDENT), (HBA, ident), (hba, ident)):
            with self.subTest(with_hba=a != HBA, with_ident=b != IDENT):
                with self.assertRaisesRegex(RuntimeError, "HOLD"):
                    OP.propose_auth_change(a, b)

    def test_unexpected_local_auth_change_denied(self):
        variants = [
            HBA.replace("local   all             all                          peer",
                        "local   all             all                          trust"),
            HBA.replace("local   all             all                          peer",
                        "local   all             all                          md5"),
            HBA.replace("local   all             all                          peer",
                        "local   all             all                          peer map=allusers"),
            "local all all peer\n",
        ]
        for text in variants:
            with self.subTest(text=text[:35]):
                with self.assertRaisesRegex(RuntimeError, "local auth rules"):
                    OP.propose_auth_change(text, IDENT)

    def test_existing_issuer_mapping_any_alias_is_denied(self):
        bad = IDENT + "another-map other-user sumlaude_identity_issuer\n"
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            OP.propose_auth_change(HBA, bad)

    def test_bad_config_format_denied(self):
        for a, b in ((HBA + "\0", IDENT), (HBA[:-1], IDENT),
                     (HBA, IDENT + "\r"), (HBA, IDENT[:-1])):
            with self.subTest(case=len(a)):
                with self.assertRaises(RuntimeError):
                    OP.propose_auth_change(a, b)

    def test_mutable_root_execution_denied(self):
        with mock.patch.object(OP.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "root privileges"):
                OP.protected_root_operator()

    def test_wrong_current_release_denied(self):
        with (mock.patch.object(OP.socket, "gethostname", return_value=OP.HOST),
              mock.patch.object(OP.os, "geteuid", return_value=1000),
              mock.patch.object(OP, "BFF_CURRENT") as current):
            current.is_symlink.return_value = True
            current.resolve.return_value = Path("/wrong")
            with self.assertRaisesRegex(RuntimeError, "original current"):
                OP.check_service_and_runtime()

    def test_replace_config_preserves_postgres_owner_mode(self):
        """Simulate atomic root-owned install with patched OS chmod/chown."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "pg_hba.conf"
            p.write_bytes(b"original\n")
            with (mock.patch.object(OP.os, "chown") as chown,
                  mock.patch.object(OP.pwd, "getpwnam") as user):
                user.return_value.pw_uid = 1234
                user.return_value.pw_gid = 4321
                OP.replace_config(p, b"new\n")
            self.assertEqual(p.read_bytes(), b"new\n")
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o640)
            chown.assert_called_once()
            self.assertEqual(list(Path(td).glob(".m01-peer-*")), [])

    def test_false_positive_peer_login_denied(self):
        with mock.patch.object(OP, "pgsql", side_effect=["1", "1", "wrong|role|db"]):
            with self.assertRaisesRegex(RuntimeError, "peer login mismatch"):
                OP.verify_new_mapping()

    def test_unknown_role_grant_matrix_denied(self):
        with mock.patch.object(OP, "pgsql",
                               side_effect=["1|1|1|0|0|1", "1|1|1|1|0"]):
            with self.assertRaisesRegex(RuntimeError, "restricted S03 issuer"):
                OP.check_role_authority()


if __name__ == "__main__":
    unittest.main()
