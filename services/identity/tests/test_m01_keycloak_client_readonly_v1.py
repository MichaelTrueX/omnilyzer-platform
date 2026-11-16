#!/usr/bin/env python3
"""File: services/identity/tests/test_m01_keycloak_client_readonly_v1.py

Purpose: Verify the bounded root-only Keycloak diagnostic, no-secret output
    and the exact optional single sudoers permission extension.
Related: services/identity/ops/m01_keycloak_client_readonly_v1.py,
    deployment/enable_prod_m01_keycloak_readonly_v1.py and PR298.
Tests use disposable files and synthetic client metadata; no live credentials.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]


def load(path: Path, name: str):
    """Read source-only modules from the checkout without invoking main."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUDIT = load(ROOT / "services/identity/ops/m01_keycloak_client_readonly_v1.py",
             "m01_kc_audit")
SETUP = load(ROOT / "deployment/enable_prod_m01_keycloak_readonly_v1.py",
             "m01_kc_audit_setup")


def fixture() -> dict:
    """Create nonsecret synthetic client fields including the two callbacks."""
    return {
        "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "clientId": "sumlaude-bff", "protocol": "openid-connect",
        "publicClient": False, "enabled": True, "standardFlowEnabled": True,
        "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": [AUDIT.EXPECTED_APP, AUDIT.EXPECTED_PUBLIC],
        "webOrigins": [AUDIT.EXPECTED_ORIGIN],
        "attributes": {"pkce.code.challenge.method": "S256"},
    }


class ReadOnlyDiagnosticTests(unittest.TestCase):
    """Inspect the trusted one-client security contract in memory only."""

    def test_exact_expected_client_all_known_fields_pass(self):
        """Valid current client has twelve fixed-name PASS outcomes."""
        results = AUDIT.classify(fixture())
        self.assertEqual(len(results), 12)
        self.assertEqual(set(results.values()), {"PASS"})

    def test_provider_reordered_exact_callbacks_still_match_current_contract(self):
        """Keycloak persists callback membership, not caller list ordering."""
        item = fixture()
        item['redirectUris'].reverse()
        self.assertEqual(set(AUDIT.classify(item).values()), {'PASS'})

    def test_callback_membership_type_and_cardinality_remain_exact(self):
        """Never hide duplicates, wildcards, foreign or missing callbacks."""
        for value in (
            [AUDIT.EXPECTED_APP, AUDIT.EXPECTED_APP],
            [AUDIT.EXPECTED_PUBLIC, AUDIT.EXPECTED_PUBLIC],
            [AUDIT.EXPECTED_APP], [], None, True,
            [AUDIT.EXPECTED_APP, AUDIT.EXPECTED_PUBLIC, AUDIT.EXPECTED_APP],
            [AUDIT.EXPECTED_APP, 'https://*.sumlaude.com/auth/callback'],
            [AUDIT.EXPECTED_APP, 'https://foreign.invalid/auth/callback'],
            [AUDIT.EXPECTED_APP, {'uri': AUDIT.EXPECTED_PUBLIC}],
            [AUDIT.EXPECTED_APP, 1],
            {'first': AUDIT.EXPECTED_APP, 'second': AUDIT.EXPECTED_PUBLIC},
        ):
            with self.subTest(value=value):
                results = AUDIT.classify({**fixture(), 'redirectUris': value})
                self.assertEqual(results['TWO_EXACT_REDIRECTS'], 'FAIL')
                self.assertEqual(len(results), 12)

    def test_each_confidential_flow_field_rejected_individually(self):
        """Detect all forbidden flow and PKCE changes without disclosing data."""
        flips = {
            "clientId": "evil", "protocol": "saml", "publicClient": True,
            "enabled": False, "standardFlowEnabled": False,
            "implicitFlowEnabled": True, "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": True,
            "webOrigins": ["https://another.invalid"],
            "redirectUris": [AUDIT.EXPECTED_APP],
            "attributes": {"pkce.code.challenge.method": "plain"},
            "id": "invalid",
        }
        for name, value in flips.items():
            with self.subTest(name=name):
                item = fixture()
                item[name] = value
                outcomes = AUDIT.classify(item)
                self.assertIn("FAIL", outcomes.values())
                self.assertTrue(all(v in ("PASS", "FAIL")
                                    for v in outcomes.values()))

    def test_unknown_nested_client_secrets_never_emitted(self):
        """Ignore and never expose unknown fields, IDs or secrets."""
        item = fixture()
        item["secret"] = "SUPER_SECRET_DO_NOT_PRINT"
        item["nestedDanger"] = {"token": "TOKEN_DO_NOT_PRINT"}
        self.assertNotIn("SECRET", str(AUDIT.classify(item)))
        self.assertNotIn("TOKEN", str(AUDIT.classify(item)))
        self.assertNotIn(item["id"], str(AUDIT.classify(item)))

    def test_empty_or_wrong_type_client_rejected(self):
        """Non-dictionary admin responses cannot be treated as client data."""
        for value in ([], None, "secret"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "CLIENT_READBACK_NOT_OBJECT"):
                    AUDIT.classify(value)

    def test_receipts_absent_do_not_create_any_file(self):
        """Receipt inspection does not create or modify a missing path."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "never-created"
            self.assertEqual(AUDIT.safe_receipts(p),
                             {"attempt.json": "ABSENT", "success.json": "ABSENT"})
            self.assertFalse(p.exists())

    def test_wrong_operator_args_denied_before_root(self):
        """Only one exact read-only action, no arbitrary future commands."""
        for argv in ([], ["help"], ["inspect", "/etc/shadow"]):
            with self.subTest(argv=argv):
                with mock.patch("sys.argv", ["test", *argv]):
                    with self.assertRaisesRegex(RuntimeError,
                                                "ONLY_EXACT_INSPECT_ARGUMENT"):
                        AUDIT.main()

    def test_live_root_execution_from_checkout_is_denied(self):
        """Do not permit a writable checkout to gain admin client authority."""
        with (mock.patch.object(AUDIT.os, "getuid", return_value=0),
              mock.patch.object(AUDIT.os, "geteuid", return_value=0),
              mock.patch.object(AUDIT.socket, "gethostname",
                                return_value="truexmainserver")):
            with self.assertRaisesRegex(RuntimeError,
                                        "REVIEWED_ROOT_INSTALLED_PATH_ONLY"):
                AUDIT.root_entrypoint()


class ReadOnlyAccessSetupTests(unittest.TestCase):
    """Prove that the change to the accepted role is one fixed read-only rule."""

    def test_exact_one_new_privilege_only(self):
        """Keep fixed root interpreter, no shell, secrets or wildcard args."""
        rule = SETUP.ADD_LINE.decode()
        self.assertEqual(rule.count("omnigpt ALL=(root)"), 1)
        self.assertIn("NOPASSWD:NOSETENV", rule)
        self.assertIn("/usr/bin/python3 -I", rule)
        self.assertIn("m01-keycloak-client-readonly-v1 inspect", rule)
        self.assertNotIn("*", rule)
        self.assertNotIn("ALL=(ALL)", rule)
        self.assertNotIn("sudoedit", rule)

    def test_existing_five_command_sudoers_is_preserved_exactly(self):
        """Only exact reviewed original bytes may be extended or re-read."""
        old = (b"# synthetic\n" + b"omnigpt ALL=(root) NOPASSWD:NOSETENV: "
               + b"/usr/bin/python3 -I /fixed/source ")
        old = b"".join(old + str(i).encode() + b"\n" for i in range(5))
        with tempfile.TemporaryDirectory() as d:
            policy = Path(d) / "sudoers"
            policy.write_bytes(old)
            with (mock.patch.object(SETUP, "SUDOERS", policy),
                  mock.patch.object(SETUP, "SUDOERS_OLD_SHA256",
                                    hashlib.sha256(old).hexdigest())):
                new = SETUP.proposed_rule()
                self.assertEqual(new, old + SETUP.ADD_LINE)
                policy.write_bytes(new)
                self.assertEqual(SETUP.proposed_rule(), new)

    def test_unreviewed_existing_sudoers_refused(self):
        """Do not silently replace a policy whose hash is not pinned."""
        with tempfile.TemporaryDirectory() as d:
            policy = Path(d) / "sudoers"
            policy.write_bytes(b"unapproved root access\n")
            with mock.patch.object(SETUP, "SUDOERS", policy):
                with self.assertRaisesRegex(RuntimeError,
                                            "PRIVILEGE_POLICY_CHANGED"):
                    SETUP.proposed_rule()

    def test_owner_setup_wrong_args_never_run_as_root(self):
        """Require one exact source-bound owner install invocation."""
        with mock.patch("sys.argv", ["test", "unknown"]):
            with self.assertRaisesRegex(RuntimeError, "EXACT_INSTALL_ONLY"):
                SETUP.main()


if __name__ == "__main__":
    unittest.main(verbosity=2)
