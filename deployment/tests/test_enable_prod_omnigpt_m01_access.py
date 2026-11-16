#!/usr/bin/env python3
"""File: deployment/tests/test_enable_prod_omnigpt_m01_access.py

Purpose: Test exact M01 sudo authority, source pins and root/host protection.
Related: deployment/enable_prod_omnigpt_m01_access.py, AGENTS.md, PR298.
No test creates accounts, runs sudo, writes real sudoers or changes a service.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "enable_prod_omnigpt_m01_access.py"
SPEC = importlib.util.spec_from_file_location("prod_ai", SOURCE)
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


class ProdAIPermanentAccessTests(unittest.TestCase):
    """Evaluate fixed, least-privilege delegated authority as source only."""

    def test_exact_five_root_commands_without_wildcards(self):
        """Only the approved M01 operator verbs can execute as root."""
        rules = APP.rules().decode("ascii")
        commands = [line for line in rules.splitlines()
                    if line.startswith("omnigpt ALL=(root)")]
        self.assertEqual(len(commands), 5)
        for command in commands:
            self.assertIn("NOPASSWD:NOSETENV:", command)
            self.assertNotIn("*", command)
            self.assertNotIn("/bin/sh", command)
            self.assertNotIn("/bin/bash", command)
            self.assertIn("/usr/bin/python3 -I ", command)
        self.assertIn("m01-keycloak-public-callback-once apply", rules)
        self.assertIn("m01-active-bff-def92-upgrade-once stage", rules)
        self.assertIn("m01-active-bff-def92-upgrade-once apply", rules)
        self.assertIn("m01-active-bff-def92-upgrade-once verify", rules)
        self.assertNotIn("NOPASSWD: ALL", rules)
        self.assertNotIn("ALL=(ALL)", rules)

    def test_approved_go_and_source_pins_fixed(self):
        """The source, archive and GO marker cannot be supplied by the caller."""
        policy = APP.rules().decode("ascii")
        self.assertEqual(policy.count("M01_CANONICAL_KEYCLOAK_EXACT_CALLBACK_ONCE_GO"), 1)
        self.assertEqual(policy.count("M01_CANONICAL_BFF_DEF92_DIRECT_UPGRADE_GO"), 2)
        self.assertEqual(policy.count("fd46713dd62b407c0d1ea8b4afb45e342fdc87dd9a3baf53a730b5d0447e0db9"), 2)
        self.assertEqual(policy.count("/usr/bin/env "), 3)
        self.assertEqual(policy.count("/usr/bin/python3 -I "), 5)
        self.assertEqual(APP.HOST, "truexmainserver")
        self.assertEqual(APP.ACCOUNT, "omnigpt")
        self.assertEqual(APP.KEYCLOAK_HASH, "6a43414a89a38514a3553bb92374d9f520e278d4bf8b4a3bc2a61e7015ff2d2d")
        self.assertEqual(APP.BFF_HASH, "83e8748ba898b339da1a4811682a934ab58a6e13e5700b4235b96af5e9dffe0e")

    def test_user_can_never_supply_an_install_argument(self):
        """Reject unknown operations or caller-chosen paths."""
        for args in (["inspect"], ["install", "/tmp/change"], []):
            with self.subTest(args=args):
                with mock.patch("sys.argv", [str(SOURCE), *args]):
                    with self.assertRaisesRegex(RuntimeError, "EXACT_INSTALL_ARGUMENT_REQUIRED"):
                        APP.main()

    def test_untrusted_checkout_denied_even_if_root(self):
        """A source checkout cannot become a privileged installer."""
        with (mock.patch.object(APP.socket, "gethostname", return_value=APP.HOST),
              mock.patch.object(APP.os, "getuid", return_value=0),
              mock.patch.object(APP.os, "geteuid", return_value=0)):
            with self.assertRaisesRegex(RuntimeError, "ROOT_OWNED_FIXED_BOOTSTRAP_REQUIRED"):
                APP.root_preflight()

    def test_modified_root_operator_is_rejected(self):
        """No different operator bytes may inherit release authority."""
        with tempfile.TemporaryDirectory() as scratch:
            f = Path(scratch) / "bad"
            f.write_bytes(b"not the reviewed operator")
            with self.assertRaisesRegex(RuntimeError, "SOURCE_FILE_CHANGED"):
                APP.trusted_file(f, uid=f.stat().st_uid,
                                 mode=0o600, expected=APP.BFF_HASH)

    def test_agent_node_is_a_pinned_unprivileged_binary(self):
        """Pin the actual Node24 runtime without opening a root script path."""
        self.assertEqual(APP.NODE_TARGET, Path("/home/omnigpt/bin/node"))
        self.assertEqual(APP.NODE_HASH, "67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c")
        self.assertIn("v24.22.0", str(APP.NODE_SOURCE))


if __name__ == "__main__":
    unittest.main(verbosity=2)
