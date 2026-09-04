"""Focused Task 012B policy and captured-evidence tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest


SPIKE = Path(__file__).resolve().parents[1]
ROOT = SPIKE.parents[1]
sys.path.insert(0, str(SPIKE))

from durability.forgejo_packages import build_packages  # noqa: E402


RESULT = json.loads((SPIKE / "results/forgejo-recovery-validation.json").read_text())


class ForgejoRecoveryTests(unittest.TestCase):
    def test_task012b_passes_with_exact_forgejo_identity(self) -> None:
        self.assertEqual(RESULT["task"], "012B")
        self.assertEqual(RESULT["classification"], "TASK 012B — PASS")
        self.assertEqual(RESULT["forgejo"]["version"], "16.0.3+gitea-1.22.0")
        self.assertEqual(
            RESULT["forgejo"]["binary_sha256"],
            "6d29dca8c14a884cbca19a162fb55f06cb8b3181032cf6d175aa34b5eae2ea5b",
        )
        self.assertEqual(RESULT["forgejo"]["binary_path"], "/app/gitea/gitea")

    def test_packages_are_deterministic_and_match_evidence(self) -> None:
        fixtures = build_packages()
        for name, content in {
            "Generic": fixtures.generic, "PyPI": fixtures.wheel, "npm": fixtures.npm
        }.items():
            self.assertEqual(RESULT["packages"][name], {
                "sha256": hashlib.sha256(content).hexdigest(), "length": len(content)
            })

    def test_all_formats_pass_before_and_after_restore(self) -> None:
        expected = {"Generic": True, "PyPI": True, "npm": True}
        self.assertEqual(RESULT["pre_backup_results"], expected)
        self.assertEqual(RESULT["post_restore_results"], expected)

    def test_backup_contains_metadata_storage_and_config(self) -> None:
        self.assertEqual(RESULT["backup"]["mode"], "cold")
        self.assertTrue(RESULT["backup"]["integrity_verified"])
        self.assertEqual(RESULT["backup"]["logical_components"], [
            "forgejo-database-metadata", "forgejo-package-storage", "forgejo-config-state"
        ])
        self.assertEqual(RESULT["restore"]["logical_components"], RESULT["backup"]["logical_components"])

    def test_source_was_removed_and_restore_used_a_different_port(self) -> None:
        self.assertTrue(RESULT["source_removal"]["temporary_source_removed"])
        self.assertTrue(RESULT["isolation"]["different_ports"])
        self.assertTrue(RESULT["isolation"]["temporary_sqlite"])
        self.assertTrue(RESULT["isolation"]["temporary_package_storage"])
        self.assertFalse(RESULT["isolation"]["external_services"])
        self.assertFalse(RESULT["isolation"]["live_infrastructure_accessed"])

    def test_limited_negative_matrix_fails_closed(self) -> None:
        self.assertEqual(RESULT["negative_test_matrix"], {
            "corrupt_archive_rejected": True,
            "checksum_mismatch_rejected": True,
            "path_traversal_rejected": True,
            "nonempty_destination_rejected": True,
            "database_metadata_loss_rejected": True,
            "package_storage_loss_rejected": True,
        })

    def test_backup_uses_forgejo_dump_and_rejects_unsafe_members(self) -> None:
        source = (SPIKE / "durability/forgejo_backup.py").read_text()
        self.assertIn('"dump", "--file"', source)
        self.assertIn('"forgejo-db.sql" not in files', source)
        self.assertIn('name.startswith("data/packages/")', source)
        self.assertIn("links and special archive members are forbidden", source)
        self.assertIn("restore destination must be a new empty directory", source)

    def test_forgejo_test_is_package_only_and_loopback_only(self) -> None:
        package_source = (SPIKE / "durability/forgejo_packages.py").read_text()
        process_source = (SPIKE / "durability/forgejo_process.py").read_text()
        self.assertNotIn("/v2/", package_source)
        self.assertIn("Generic", package_source)
        self.assertIn("pypi", package_source)
        self.assertIn("npm", package_source)
        self.assertIn("HTTP_ADDR = 127.0.0.1", process_source)
        self.assertNotIn("0.0.0.0", process_source)

    def test_adr_and_protected_task008_files_remain_unchanged(self) -> None:
        adr = (ROOT / "docs/adr/0010-forgejo-and-zot-package-registries.md").read_text()
        self.assertIn("- Status: Accepted", adr)
        protected = {
            ".github/workflows/task008-publish.yml": "0d6bd4a5715e6366250c427c959401e13b1f63b79786717a99b3816fd87a74b8",
            ".github/workflows/task008-consume.yml": "2712a221da0e4c4502fc2bc7dea6096cc015d8e0527a95a37f476c3fe3c7d5d1",
            ".github/workflows/task008-zot-publish.yml": "b0af8b0e017627972624d62c9e434037649200c3c56feae4495ca27469920a2d",
            ".github/workflows/task008-zot-consume.yml": "1d8618b15685f973c0af677f7557833c2e16b3b992571ea186f344532748adf9",
        }
        for relative, expected in protected.items():
            self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), expected)

    def test_limitations_do_not_claim_production_recovery(self) -> None:
        limitations = " ".join(RESULT["limitations"])
        for phrase in ("cold backup only", "not production RPO or RTO", "not online backup", "not off-host"):
            self.assertIn(phrase, limitations)

    def test_documentation_records_narrow_evidence_without_reopening_architecture(self) -> None:
        readme = (SPIKE / "README.md").read_text()
        decisions = (ROOT / "docs/architecture/technology-decisions.md").read_text()
        self.assertIn("TASK 012B — PASS", readme)
        self.assertIn("does not establish online backup", readme)
        row = next(
            line for line in decisions.splitlines()
            if line.startswith("| Package registry / trusted publishing |")
        )
        self.assertIn("Task 012B validated local synthetic Forgejo Generic/PyPI/npm cold dump", row)
        self.assertIn("| ACCEPTED DIRECTION |", row)
        self.assertIn("production encryption and off-host copies", row)


if __name__ == "__main__":
    unittest.main()
