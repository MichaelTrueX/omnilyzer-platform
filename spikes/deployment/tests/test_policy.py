import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from common import AuditLog, atomic_json, immutable_ref, require_immutable, require_loopback, validate_migration_checksum
from deployment import PromotionController, validate_compose_text

DIGEST_A = "repo.local/app@sha256:" + "a" * 64
DIGEST_B = "repo.local/app@sha256:" + "b" * 64


class PolicyTests(unittest.TestCase):
    def test_accepts_digest_reference(self):
        self.assertTrue(immutable_ref(DIGEST_A))

    def test_rejects_mutable_reference(self):
        with self.assertRaises(ValueError):
            require_immutable("repo.local/app:candidate")

    def test_rejects_short_digest(self):
        self.assertFalse(immutable_ref("repo/app@sha256:1234"))

    def test_loopback_binding(self):
        self.assertEqual(require_loopback("127.0.0.1:18080"), "127.0.0.1:18080")

    def test_rejects_public_binding(self):
        with self.assertRaises(ValueError):
            require_loopback("0.0.0.0:18080")

    def test_audit_rejects_secret_key(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.jsonl")
            with self.assertRaises(ValueError):
                audit.append("bad", password="value")

    def test_audit_rejects_known_secret_value(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = AuditLog(Path(directory) / "audit.jsonl", ["known-secret"])
            with self.assertRaises(ValueError):
                audit.append("bad", result="known-secret")

    def test_atomic_state_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            atomic_json(path, {"active_slot": "blue"})
            self.assertEqual(json.loads(path.read_text())["active_slot"], "blue")

    def test_order_rejects_staging_before_dev(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            atomic_json(manifest, {"candidate_release": "1.1.0", "candidate_digest": DIGEST_B})
            audit = AuditLog(root / "audit.jsonl")
            controller = PromotionController(root, manifest, audit)
            controller.initialize("dev", "1.0.0", DIGEST_A)
            with self.assertRaises(ValueError):
                controller.verify_promotion("staging", "1.1.0", DIGEST_B)

    def test_state_transition_retains_previous_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            atomic_json(manifest, {"candidate_release": "1.1.0", "candidate_digest": DIGEST_B})
            controller = PromotionController(root, manifest, AuditLog(root / "audit.jsonl"))
            controller.initialize("dev", "1.0.0", DIGEST_A)
            state = controller.record_switch("dev", "1.1.0", DIGEST_B, "green", 2)
            self.assertEqual(state["previous_digest"], DIGEST_A)

    def test_checksum_match_and_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "001.sql"
            path.write_text("SELECT 1;")
            import hashlib
            checksum = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertTrue(validate_migration_checksum(checksum, path))
            path.write_text("SELECT 2;")
            with self.assertRaises(ValueError):
                validate_migration_checksum(checksum, path)

    def test_compose_rejects_build(self):
        with self.assertRaises(ValueError):
            validate_compose_text("services:\n  app:\n    build: .\n")

    def test_compose_rejects_public_listener(self):
        with self.assertRaises(ValueError):
            validate_compose_text("ports:\n - 0.0.0.0:8080:8080\n")


if __name__ == "__main__":
    unittest.main()
