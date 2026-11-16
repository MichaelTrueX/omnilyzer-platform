"""File: services/identity/tests/test_keycloak_add_public_callback_once.py
Purpose: Verify the one existing confidential Keycloak client is the ONLY
    object eligible for a public login callback addition. No live admin calls.
Related: services/identity/ops/keycloak_add_public_callback_once.py,
    tests/test_keycloak_provision_realm.py, config/settings.py.
"""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / (
    "ops/keycloak_add_public_callback_once.py"
)
spec = importlib.util.spec_from_file_location("m01_callback_one", SOURCE)
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)


def client():
    """Construct an existing confidential client without actual credentials."""
    return {
        "id": "a5f87eb2-c010-40a9-bbd1-e60052421191",
        "clientId": "sumlaude-bff",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "clientAuthenticatorType": "client-secret",
        "redirectUris": [op.APP],
        "webOrigins": ["https://app.sumlaude.com"],
        "attributes": {"pkce.code.challenge.method": "S256"},
        "secret": "synthetic-never-production",
        "consentRequired": False,
    }


class CallbackGuardTests(unittest.TestCase):
    """Use exact source and synthetic Keycloak objects only."""

    def test_one_exact_existing_callback_added_without_any_other_field(self):
        """Ensure public callback addition is a strict one-field update."""
        before = client()
        after = op.new_document(before)
        self.assertEqual(before["redirectUris"], [op.APP])
        self.assertEqual(after["redirectUris"], [op.APP, op.PUBLIC])
        self.assertEqual(
            {k for k in after if after[k] != before[k]}, {"redirectUris"}
        )
        self.assertEqual(after["secret"], before["secret"])
        self.assertEqual(after["webOrigins"], before["webOrigins"])
        op.verify_security_contract(after, after=True)

    def test_no_wildcard_other_host_or_second_client(self):
        """Reject callback and origin tampering instead of broadening trust."""
        for changed in (
            {"redirectUris": [op.APP, op.PUBLIC, "https://other.example/cb"]},
            {"redirectUris": [op.APP, "https://*.sumlaude.com/auth/callback"]},
            {"webOrigins": ["*"]},
            {"webOrigins": ["https://sumlaude.com"]},
            {"clientId": "another-client"},
            {"publicClient": True},
            {"directAccessGrantsEnabled": True},
            {"implicitFlowEnabled": True},
            {"standardFlowEnabled": False},
            {"serviceAccountsEnabled": True},
            {"enabled": False},
            {"attributes": {"pkce.code.challenge.method": "plain"}},
        ):
            candidate = {**client(), **changed}
            with self.subTest(change=changed):
                with self.assertRaisesRegex(
                    RuntimeError, "M01_CALLBACK_HOLD_CONFIDENTIAL_CLIENT"):
                    op.new_document(candidate)

    def test_approved_mutation_cannot_start_without_exact_owner_go(self):
        """Reject all root update calls without the review-specific GO."""
        with mock.patch.dict(os.environ, {
            "M01_CANONICAL_KEYCLOAK_OWNER_GO": "",
        }):
            with mock.patch.object(op, "public_preflight") as probe:
                with self.assertRaisesRegex(
                    RuntimeError, "M01_CALLBACK_HOLD_EXACT_OWNER_GO_ABSENT"):
                    op.apply_once()
                probe.assert_not_called()

    def test_existing_receipt_blocks_duplicate_mutation_before_admin(self):
        """One-shot receipt never triggers an automatic replay."""
        with tempfile.TemporaryDirectory() as d:
            receipt = Path(d) / "protected"
            receipt.mkdir(mode=0o700)
            real_tmp = tempfile.TemporaryDirectory
            with (
                mock.patch.dict(os.environ, {
                    "M01_CANONICAL_KEYCLOAK_OWNER_GO": op.GO_SCOPE,
                }),
                mock.patch.object(op, "RECEIPTS", receipt),
                mock.patch.object(op, "public_preflight",
                                  return_value=(200, 400)),
                mock.patch.object(op, "root_admin_env") as admin,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "M01_CALLBACK_HOLD_PRIOR_ATTEMPT"):
                    op.apply_once()
                admin.assert_called_once()

    def test_reject_existing_public_callback_to_avoid_unexpected_replay(self):
        """Already-enabled callbacks cannot be overwritten or retried."""
        with (
            mock.patch.dict(os.environ, {
                "M01_CANONICAL_KEYCLOAK_OWNER_GO": op.GO_SCOPE,
            }),
            mock.patch.object(op, "public_preflight",
                              return_value=(200, 200)),
            mock.patch.object(op, "root_admin_env") as admin,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "M01_CALLBACK_HOLD_NEW_CALLBACK_NOT_ABSENT"):
                op.apply_once()
            admin.assert_not_called()

    def test_admin_query_requires_exactly_one_confidential_client(self):
        """A wrong or repeated Keycloak client is not eligible for update."""
        for content in ("[]", json.dumps([client(), client()]), "{}",
                        "invalid-json"):
            with mock.patch.object(op, "command", return_value=content):
                with self.assertRaisesRegex(
                    RuntimeError, "M01_CALLBACK_HOLD_(EXACT_CLIENT|CLIENT_JSON)"):
                    op.admin_client(Path("/run/test.config"), {})

    def test_source_requires_approved_public_and_private_urls(self):
        """Only two exact existing and new callbacks may be returned."""
        self.assertEqual(op.OLD_REDIRECTS,
                         ["https://app.sumlaude.com/auth/callback"])
        self.assertEqual(op.NEW_REDIRECTS,
                         ["https://app.sumlaude.com/auth/callback",
                          "https://sumlaude.com/auth/callback"])
        self.assertEqual(op.EXPECTED_ORIGINS, ["https://app.sumlaude.com"])
        self.assertEqual(op.SERVER, "http://127.0.0.1:18742")
        self.assertNotIn("http://", "".join(op.NEW_REDIRECTS))

    def test_synthetic_success_updates_one_client_and_writes_receipts(self):
        """Exercise exact kcadm command flow without network or root actions."""
        with tempfile.TemporaryDirectory(prefix="m01-qa-callback-") as d:
            root = Path(d)
            # Isolate the fixed path and source with no production permissions.
            out = root / "receipts"
            changes = []
            before = client()
            after = op.new_document(before)
            now = iter([(200, 400), (200, 200)])
            query = iter([before, after])

            def fake_command(args, **kwargs):
                """Inspect command order, including sole intended update."""
                changes.append(args)
                if "update" in args:
                    self.assertEqual(args[args.index("update") + 1],
                                     "clients/" + before["id"])
                    self.assertEqual(args[args.index("-r") + 1], "omnilyzer")
                    payload = Path(args[args.index("-f") + 1])
                    self.assertEqual(json.loads(payload.read_text()), after)
                return ""

            real_tmp = tempfile.TemporaryDirectory
            with (
                mock.patch.dict(os.environ, {
                    "M01_CANONICAL_KEYCLOAK_OWNER_GO": op.GO_SCOPE,
                }),
                mock.patch.object(op, "RECEIPTS", out),
                mock.patch.object(op, "ATTEMPT", out / "attempt.json"),
                mock.patch.object(op, "SUCCESS", out / "success.json"),
                mock.patch.object(op, "root_admin_env", return_value={
                    "KC_BOOTSTRAP_ADMIN_USERNAME": "synthetic-admin",
                    "KC_BOOTSTRAP_ADMIN_PASSWORD": "synthetic-only",
                }),
                mock.patch.object(op, "public_preflight",
                                  side_effect=lambda: next(now)),
                mock.patch.object(op, "admin_client",
                                  side_effect=lambda *_: next(query)),
                mock.patch.object(op, "command", side_effect=fake_command),
                mock.patch.object(op.tempfile, "TemporaryDirectory",
                                  side_effect=lambda **_: real_tmp(
                                      dir=d, prefix="private-run-")),
            ):
                # Strict root-owned receipt checks require root in production;
                # mock this one filesystem guard, not the client or kcadm flow.
                with mock.patch.object(op, "create_attempt_receipt",
                                       side_effect=lambda: (
                                           out.mkdir(),
                                           (out / "attempt.json").write_text(
                                               "synthetic-attempt\n"))):
                    op.apply_once()
            self.assertEqual([x[1] for x in changes], ["config", "update"])
            self.assertTrue((out / "success.json").exists())
            self.assertEqual(
                json.loads((out / "success.json").read_text())["redirectUris"],
                [op.APP, op.PUBLIC],
            )


if __name__ == "__main__":
    unittest.main()
