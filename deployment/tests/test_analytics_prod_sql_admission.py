#!/usr/bin/env python3
"""File: deployment/tests/test_analytics_prod_sql_admission.py

Purpose: Focused positive and negative checks for the read-only PROD SQL gate.
Related: deployment/analytics_prod_sql_admission.py and
         deployment/analytics_dev_bootstrap.py.

Sections: in-memory fixture construction, SQL custody checks, PROD HBA ordering,
          readonly catalog contract and CLI denial.
No PROD database or service is contacted by these tests.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import os
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "analytics_prod_sql_admission.py"
SPEC = importlib.util.spec_from_file_location("analytics_prod_sql_admission", SCRIPT)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class TestSqlAdmission(unittest.TestCase):
    """Reject changed or substituted SQL sources independently of the host."""

    def setUp(self) -> None:
        """Create a private disposable directory and inject fake accepted digests."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.uid = os.getuid()
        self.inputs = []
        for i in range(5):
            name = f"reviewed-{i}.sql"
            data = f"SELECT {i};\n".encode()
            path = self.dir / name
            path.write_bytes(data)
            path.chmod(0o400)
            self.inputs.append((name, hashlib.sha256(data).hexdigest()))
        patch = mock.patch.object(gate, "SQL", tuple(self.inputs))
        patch.start()
        self.addCleanup(patch.stop)
        self.dir.chmod(0o700)

    def verify(self) -> None:
        """Exercise exact file inventory, ownership, mode and SHA checks."""
        gate.verify_sql(self.dir, uid=self.uid, file_mode=0o400, directory_mode=0o700)

    def test_good_sources(self) -> None:
        """An intact source set is accepted."""
        self.verify()

    def test_changed_bytes(self) -> None:
        """The first changed SQL byte must fail closed."""
        path = self.dir / self.inputs[0][0]
        path.chmod(0o600)
        path.write_text("SELECT 999;\n")
        path.chmod(0o400)
        with self.assertRaises(gate.AdmissionHold):
            self.verify()

    def test_extra_file(self) -> None:
        """Unknown SQL files are not silently included."""
        (self.dir / "sixth.sql").write_text("SELECT 1;")
        with self.assertRaises(gate.AdmissionHold):
            self.verify()

    def test_missing_file(self) -> None:
        """Incomplete reviews cannot be promoted."""
        (self.dir / self.inputs[0][0]).unlink()
        with self.assertRaises(gate.AdmissionHold):
            self.verify()

    def test_wrong_mode(self) -> None:
        """Writable input is not admitted."""
        (self.dir / self.inputs[0][0]).chmod(0o600)
        with self.assertRaises(gate.AdmissionHold):
            self.verify()

    def test_symlink(self) -> None:
        """A symlink is rejected even when its target matches the digest."""
        name = self.inputs[0][0]
        original = self.dir / name
        target = self.dir / "target.sql"
        original.rename(target)
        original.symlink_to(target)
        target.unlink()
        with self.assertRaises(gate.AdmissionHold):
            self.verify()

    def test_hardlink(self) -> None:
        """Hardlinked inputs are not accepted."""
        original = self.dir / self.inputs[0][0]
        os.link(original, self.dir / "other-copy")
        with self.assertRaises(gate.AdmissionHold):
            gate.exact_file(original, uid=self.uid, mode=0o400, max_bytes=65536)

    def test_wrong_directory_mode(self) -> None:
        """A shared directory cannot hold privileged original SQL."""
        self.dir.chmod(0o750)
        with self.assertRaises(gate.AdmissionHold):
            self.verify()


class TestPgAdmission(unittest.TestCase):
    """Preserve the fixed PROD HBA and fail-closed catalog assumptions."""

    def setUp(self) -> None:
        """Model the four exact known peer rules without using any live database."""
        self.hba = (
            "local all postgres peer\n"
            "local sumlaude_learning sumlaude_identity_issuer peer map=m01_sumlaude_bff\n"
            "local all all peer\n"
            "local replication all peer\n"
        )

    def test_original_hba(self) -> None:
        """Known rule order is accepted."""
        gate.verify_hba(self.hba)

    def test_changed_hba_order(self) -> None:
        """Moving general peer ahead of a named special rule is rejected."""
        lines = self.hba.splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        with self.assertRaises(gate.AdmissionHold):
            gate.verify_hba("\n".join(lines))

    def test_missing_sumlaude_mapping(self) -> None:
        """The protected Sumlaude peer mapping cannot disappear."""
        with self.assertRaises(gate.AdmissionHold):
            gate.verify_hba(self.hba.replace("map=m01_sumlaude_bff", ""))

    def test_prior_analytics_rule(self) -> None:
        """A partial installation must be reconciled rather than replayed."""
        with self.assertRaises(gate.AdmissionHold):
            gate.verify_hba(self.hba + "local omnilyzer_analytics_prod omni_runtime scram-sha-256\n")

    def test_hba_include(self) -> None:
        """External HBA rules cannot bypass the exact admission order."""
        with self.assertRaises(gate.AdmissionHold):
            gate.verify_hba(self.hba + "include_dir 'hba.d'\n")

    def test_catalog_unexpected_role(self) -> None:
        """Any existing shared-PG Analytics role requires manual reconciliation."""
        response = mock.Mock(returncode=0, stdout="VERSION|160015\nDATABASE|0\nROLES|1\nHBA_ERRORS|0\n")
        with mock.patch.object(gate.subprocess, "run", return_value=response):
            with self.assertRaises(gate.AdmissionHold):
                gate.postgres_catalog()

    def test_catalog_absent(self) -> None:
        """The original read-only catalog result is recognized."""
        response = mock.Mock(returncode=0, stdout="VERSION|160015\nDATABASE|0\nROLES|0\nHBA_ERRORS|0\n")
        with mock.patch.object(gate.subprocess, "run", return_value=response):
            gate.postgres_catalog()

    def test_catalog_wrong_version(self) -> None:
        """A changed server version cannot inherit prior acceptance."""
        response = mock.Mock(returncode=0, stdout="VERSION|170000\nDATABASE|0\nROLES|0\nHBA_ERRORS|0\n")
        with mock.patch.object(gate.subprocess, "run", return_value=response):
            with self.assertRaises(gate.AdmissionHold):
                gate.postgres_catalog()


if __name__ == "__main__":
    unittest.main()
