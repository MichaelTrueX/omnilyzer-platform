"""Assertions over captured Task 012A local recovery evidence."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


RESULT = json.loads(
    (Path(__file__).resolve().parents[1] / "results/zot-recovery-validation.json").read_text()
)


class EvidenceTests(unittest.TestCase):
    def test_classification_and_exact_zot_binary(self) -> None:
        self.assertEqual(RESULT["task"], "012A")
        self.assertEqual(RESULT["classification"], "TASK 012A — PASS")
        self.assertEqual(RESULT["zot"]["version"], "v2.1.20")
        self.assertEqual(
            RESULT["zot"]["binary_sha256"],
            "a32e42d042d1f17b5b1317e55cc1a415a744c873dcd05c25c56b665478258bcb",
        )
        self.assertTrue(RESULT["zot"]["version_command_verified"])

    def test_loopback_temporary_cold_boundary(self) -> None:
        isolation = RESULT["isolation"]
        self.assertEqual(isolation["address"], "127.0.0.1")
        self.assertTrue(isolation["dynamic_ports"])
        self.assertTrue(isolation["temporary_storage_only"])
        self.assertFalse(isolation["gc"])
        self.assertFalse(isolation["authentication_in_scope"])
        self.assertFalse(isolation["live_registry_accessed"])
        self.assertEqual(RESULT["backup"]["mode"], "cold")

    def test_current_and_rollback_have_distinct_exact_identity(self) -> None:
        current = RESULT["releases"]["CURRENT"]
        rollback = RESULT["releases"]["ROLLBACK"]
        self.assertEqual(current["tag"], "task012-current")
        self.assertEqual(rollback["tag"], "task012-rollback")
        for field in ("manifest_digest", "config_digest", "layer_digest"):
            self.assertNotEqual(current[field], rollback[field])
            self.assertRegex(current[field], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(rollback[field], r"^sha256:[0-9a-f]{64}$")
        for field in ("manifest_length", "config_length", "layer_length"):
            self.assertGreater(current[field], 0)
            self.assertGreater(rollback[field], 0)

    def test_pre_backup_and_post_restore_exact_checks_pass(self) -> None:
        expected = {
            "tag": True,
            "manifest_by_tag": True,
            "manifest_by_digest": True,
            "config": True,
            "layer": True,
        }
        for phase in ("pre_backup_validation", "post_restore_exact_digest_verification"):
            self.assertEqual(RESULT[phase], {"CURRENT": expected, "ROLLBACK": expected})

    def test_backup_shutdown_source_destruction_and_restore_pass(self) -> None:
        self.assertEqual(RESULT["cold_shutdown"], {"source_clean": True, "restored_clean": True})
        self.assertTrue(RESULT["backup"]["manifest_complete"])
        self.assertTrue(RESULT["backup"]["integrity_verified"])
        self.assertTrue(RESULT["source_destruction"]["temporary_source_removed"])
        self.assertTrue(RESULT["restore"]["restored"])

    def test_all_nine_corruption_negatives_pass(self) -> None:
        negatives = RESULT["corruption_negative_results"]
        self.assertEqual(len(negatives), 9)
        self.assertTrue(all(negatives.values()))

    def test_duration_evidence_is_not_an_rpo_or_rto_claim(self) -> None:
        self.assertEqual(set(RESULT["durations_seconds"]), {"backup", "restore", "verification"})
        self.assertTrue(all(value >= 0 for value in RESULT["durations_seconds"].values()))
        self.assertTrue(RESULT["claims"]["retained_exact_digest_recoverability_after_restore"])
        self.assertFalse(RESULT["claims"]["application_deployment_rollback"])
        self.assertFalse(RESULT["claims"]["production_rpo_or_rto"])
        self.assertFalse(RESULT["claims"]["indefinite_retention"])


if __name__ == "__main__":
    unittest.main()
