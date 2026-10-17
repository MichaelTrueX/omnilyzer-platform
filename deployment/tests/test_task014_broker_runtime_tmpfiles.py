# File: deployment/tests/test_task014_broker_runtime_tmpfiles.py
# Purpose: Enforce exact source-to-tmpfiles consistency after a confirmed
#          systemd 226/NAMESPACE failure with missing /run verifier paths.
# Related: docs/operations/task014-broker-runtime-tmpfiles.conf,
#          deployment/systemd/dev/omnilyzer-deployment-broker.service,
#          deployment/broker_host_service_contract.py.
# Sections: static fail-closed policy, adversarial policy mutation tests.
"""Static no-privilege validation of Task 014 ephemeral directory recreation."""

from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONF = ROOT / "docs/operations/task014-broker-runtime-tmpfiles.conf"
SERVICE = ROOT / "deployment/systemd/dev/omnilyzer-deployment-broker.service"

EXPECTED = (
    ("d", "/run/omnilyzer", "0755", "root", "root", "-"),
    ("d", "/run/omnilyzer/deployment", "0755", "root", "root", "-"),
    ("d", "/run/omnilyzer/deployment/dev", "0755", "root", "root", "-"),
    ("d", "/run/omnilyzer/deployment/dev/blob-verifier",
     "0700", "omnilyzer-broker", "omnilyzer-broker", "-"),
    ("d", "/run/omnilyzer/deployment/dev/oci-verifier",
     "0700", "omnilyzer-broker", "omnilyzer-broker", "-"),
)


def validate_tmpfiles(content: str) -> None:
    """Allow only the five known directory-create lines in their exact order."""
    assert isinstance(content, str)
    entries = tuple(
        tuple(line.split())
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if entries != EXPECTED:
        raise ValueError("task014 unexpected runtime tmpfiles authority")


class BrokerRuntimeTmpfilesTests(unittest.TestCase):
    """Test fail-closed lifecycle resource management without touching /run."""

    def test_exact_directory_contract(self) -> None:
        """Recreate original five exact paths with root and broker ownership."""
        content = CONF.read_text(encoding="utf-8")
        self.assertIn("File: docs/operations/task014-broker-runtime-tmpfiles.conf", content)
        self.assertIn("Purpose:", content)
        self.assertIn("Related:", content)
        validate_tmpfiles(content)

    def test_original_broker_sandbox_remains_non_optional(self) -> None:
        """Do not conceal missing paths or widen the fixed writable set."""
        unit = SERVICE.read_text(encoding="utf-8")
        text = next(
            line for line in unit.splitlines() if line.startswith("ReadWritePaths=")
        )
        self.assertEqual(
            text.split("=", 1)[1].split(),
            [
                "/var/lib/omnilyzer/deployment/authority",
                EXPECTED[3][1],
                EXPECTED[4][1],
            ],
        )
        for value in EXPECTED[3:]:
            self.assertNotIn("-" + value[1], unit)
        self.assertNotIn("ReadWritePaths=/run/", unit)

    def test_reject_unsafe_directory_mutations(self) -> None:
        """Fail on wildcard, loose mode, wrong identity or unknown path."""
        contents = CONF.read_text(encoding="utf-8")
        for old, new in (
            ("0700 omnilyzer-broker", "0777 omnilyzer-broker"),
            ("0700 omnilyzer-broker", "0700 root"),
            ("d /run/omnilyzer/deployment/dev", "D /run/omnilyzer/deployment/dev"),
            ("0755 root root -", "0775 root root -"),
            ("-\n", "1d\n"),
            ("/run/omnilyzer/deployment/dev/oci-verifier",
             "/run/omnilyzer/deployment/dev/other"),
        ):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                validate_tmpfiles(contents.replace(old, new, 1))

    def test_no_execution_or_secret_material(self) -> None:
        """Only systemd-tmpfiles directory directives may be present."""
        content = CONF.read_text(encoding="utf-8")
        for fragment in ("http", "Authorization", "token=", "password=",
                         "sudo ", "ExecStart=", "systemctl ", "rm -rf",
                         "LOCALSTORAGE", "Environment="):
            self.assertNotIn(fragment, content)
        self.assertEqual(len(EXPECTED), 5)


if __name__ == "__main__":
    unittest.main()
