from __future__ import annotations

import unittest

from deployment.audit import AuditEvent, EVENT_TYPES
from deployment.policy import DeploymentPolicyError

from deployment.tests.fixtures import DIGEST, REPOSITORY, SOURCE_SHA, TIMESTAMP, VERSION


def value(event_type: str = "promotion_started") -> dict[str, object]:
    migration = "014_additive" if event_type.startswith("migration_") else None
    previous = "sha256:" + "3" * 64 if event_type.startswith("rollback_") else None
    result = "succeeded" if event_type.endswith("succeeded") else "failed" if event_type.endswith("failed") else "started"
    return {
        "schema_version": 1,
        "event_id": "run-34088735049-1",
        "event_type": event_type,
        "stage": "dev",
        "release_version": VERSION,
        "source_sha": SOURCE_SHA,
        "oci_repository": REPOSITORY,
        "digest": DIGEST,
        "previous_digest": previous,
        "active_slot": "blue",
        "candidate_slot": "green",
        "actor": "github:task014",
        "migration_identity": migration,
        "result": result,
        "timestamp": TIMESTAMP,
    }


class AuditEventTests(unittest.TestCase):
    def test_all_required_event_types_validate(self) -> None:
        for event_type in EVENT_TYPES:
            with self.subTest(event_type=event_type):
                self.assertEqual(AuditEvent.from_dict(value(event_type)).event_type, event_type)

    def test_unknown_or_missing_fields_are_rejected(self) -> None:
        unknown = value()
        unknown["extra"] = "value"
        missing = value()
        missing.pop("source_sha")
        for candidate in (unknown, missing):
            with self.assertRaises(DeploymentPolicyError):
                AuditEvent.from_dict(candidate)

    def test_required_candidate_identity_is_validated(self) -> None:
        candidate = value()
        candidate["digest"] = "sha256:1234"
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(candidate)

    def test_migration_events_require_identity(self) -> None:
        candidate = value("migration_started")
        candidate["migration_identity"] = None
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(candidate)

    def test_rollback_events_require_previous_digest(self) -> None:
        candidate = value("rollback_started")
        candidate["previous_digest"] = None
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(candidate)

    def test_secret_like_values_are_rejected(self) -> None:
        candidate = value()
        candidate["actor"] = "token=value"
        with self.assertRaises(DeploymentPolicyError):
            AuditEvent.from_dict(candidate)

    def test_canonical_serialization_is_deterministic(self) -> None:
        event = AuditEvent.from_dict(value())
        reversed_event = AuditEvent.from_dict(dict(reversed(list(value().items()))))
        self.assertEqual(event.canonical_bytes(), reversed_event.canonical_bytes())
        self.assertTrue(event.canonical_bytes().endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
