#!/usr/bin/env python3
"""Static host-specific root systemd isolation regression tests.

Does not claim to verify the active systemd/polkit runtime on a real host.
"""
import configparser
from pathlib import Path
import unittest

BASE = Path(__file__).resolve().parents[1]


def service(name):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read(BASE / name, encoding="utf-8")
    return parser


class RootSandbox(unittest.TestCase):
    def test_root_dispatcher_unmountable_even_if_python_is_compromised(self):
        for name in ("sumlaude-ai-ops@.service", "omnilyzer-ai-ops@.service"):
            with self.subTest(name=name):
                unit = service(name)
                s = unit["Service"]
                self.assertEqual(s["Type"], "oneshot")
                self.assertEqual(s["User"], "root")
                self.assertEqual(s["NoNewPrivileges"], "yes")
                self.assertEqual(s["ProtectSystem"], "strict")
                self.assertEqual(s["ProtectHome"], "yes")
                self.assertEqual(s["CapabilityBoundingSet"], "~CAP_SYS_ADMIN")
                self.assertEqual(s["SystemCallFilter"], "~@mount")
                self.assertEqual(s["RestrictNamespaces"], "yes")
                self.assertEqual(s["RestrictAddressFamilies"], "AF_UNIX")
                self.assertEqual(s["PrivateDevices"], "yes")
                self.assertEqual(s["PrivateTmp"], "yes")
                self.assertEqual(s["UMask"], "0077")
                self.assertNotIn("ExecStartPre", s)
                self.assertIn("/usr/bin/python3 -I /usr/local/libexec/shared-ai-ops/dispatcher.py ", s["ExecStart"])

    def test_cross_product_root_unit_has_no_mutating_paths(self):
        s = service("sumlaude-ai-ops@.service")["Service"]
        o = service("omnilyzer-ai-ops@.service")["Service"]
        self.assertIn("/var/lib/sumlaude-s03-current35-108-110-once", s["ReadWritePaths"])
        self.assertIn("/usr/local/sbin", s["ReadWritePaths"])
        self.assertNotIn("ReadWritePaths", o)
        self.assertNotIn("/opt/omnilyzer", s["ReadWritePaths"])
        self.assertNotIn("sumlaude", o["ExecStart"])
        self.assertNotIn("omnilyzer", s["ExecStart"])

    def test_remote_services_never_run_as_root(self):
        for product in ("sumlaude", "omnilyzer"):
            with self.subTest(product=product):
                s = service(product + "-agent-remote.service")["Service"]
                self.assertEqual(s["User"], product + "-agent")
                self.assertEqual(s["Group"], product + "-agent")
                self.assertEqual(s["NoNewPrivileges"], "yes")
                self.assertEqual(s["ProtectSystem"], "strict")
                self.assertEqual(s["ReadWritePaths"], "/home/" + product + "-agent")
                self.assertIn("/usr/local/libexec/shared-ai-ops/node ", s["ExecStart"])
                self.assertNotIn("/usr/bin/node ", s["ExecStart"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
