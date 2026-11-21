"""File: deployment/tests/test_analytics_broker_workflow_rebind_20261121.py

Purpose: Focused offline regression of the one-field Task014 base broker SHA
         rebind, rejecting untrusted source, noncanonical JSON, and invocation.
Related: deployment/analytics_broker_workflow_rebind_20261121.py,
         deployment/tests/test_broker_service_config.py, M05 Issue281.
No privileged operations, actual service restart, socket, JWT, or deployment.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json
import unittest
from unittest.mock import patch

from deployment import analytics_broker_workflow_rebind_20261121 as candidate
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.tests.test_broker_service_config import configuration_values


class BrokerWorkflowRebindTests(unittest.TestCase):
    """Exercise the exact old/new broker schema and fail-closed entry points."""

    @staticmethod
    def old_bytes():
        """Build valid, offline existing C32H broker configuration bytes."""
        return DevBrokerServiceConfiguration(
            **configuration_values(expected_workflow_sha=candidate.OLD)
        ).canonical_bytes()

    def test_one_field_diff_preserves_every_other_canonical_byte_value(self):
        """Only expected_workflow_sha may differ in a signed config review."""
        old = self.old_bytes()
        new, gid = candidate._rebound_bytes(old)
        before = json.loads(old)
        after = json.loads(new)
        self.assertEqual(gid, before["broker_gid"])
        self.assertEqual(after["expected_workflow_sha"], candidate.NEW)
        self.assertEqual(
            {key for key in before if before[key] != after[key]},
            {"expected_workflow_sha"},
        )
        self.assertEqual(
            DevBrokerServiceConfiguration.from_dict(after).canonical_bytes(), new
        )

    def test_other_sha_and_repeated_rotation_are_denied(self):
        """No arbitrary SHA, old-release retry, or implicit second rotation."""
        old = DevBrokerServiceConfiguration(
            **configuration_values(expected_workflow_sha="f" * 40)
        ).canonical_bytes()
        current = DevBrokerServiceConfiguration(
            **configuration_values(expected_workflow_sha=candidate.NEW)
        ).canonical_bytes()
        for raw in (old, current, b"", b"[]", b"{}"):
            with self.subTest(value=raw[:8]), self.assertRaises(Exception):
                candidate._rebound_bytes(raw)

    def test_noncanonical_or_duplicate_json_is_denied(self):
        """The original hardened schema parser owns exact JSON byte acceptance."""
        old = self.old_bytes()
        invalid = (
            old.rstrip(b"\n"),
            old.replace(b":", b": ", 1),
            old.replace(b'"stage":"dev"', b'"stage":"dev","stage":"dev"'),
            old + b"\n",
        )
        for raw in invalid:
            with self.subTest(length=len(raw)), self.assertRaises(Exception):
                candidate._rebound_bytes(raw)

    def test_exact_source_and_operation_allowlists_are_not_caller_controlled(self):
        """No caller chooses a service, host, source directory or new Git SHA."""
        self.assertEqual(candidate.OLD, "c6d6b067f932e60d82f8b7a9d75a2629a62606c8")
        self.assertEqual(candidate.NEW, "630db1ae5a05a691493764637e066e487f52f599")
        self.assertEqual(candidate.SERVICE, "omnilyzer-deployment-broker.service")
        self.assertEqual(candidate.TARGET, "dev.json")
        self.assertEqual(candidate.DIRECTORY, Path("/etc/omnilyzer/deployment/broker"))
        self.assertEqual(len(candidate.SOURCE_SHA256), 7)
        with patch.object(candidate, "_execute") as execute:
            with patch.object(candidate.sys, "argv", ["operator"]):
                self.assertEqual(candidate.main(), 2)
            with patch.object(candidate.sys, "argv", ["operator", "--apply", "--force"]):
                self.assertEqual(candidate.main(), 2)
            execute.assert_not_called()

    def test_preflight_and_apply_have_explicit_and_distinct_entry_points(self):
        """The default is always deny, and only two exact modes are accepted."""
        with patch.object(candidate, "_execute") as execute:
            with patch.object(candidate.sys, "argv", ["operator", "--preflight"]):
                self.assertEqual(candidate.main(), 0)
                execute.assert_called_once_with(False)
            execute.reset_mock()
            with patch.object(candidate.sys, "argv", ["operator", "--apply"]):
                self.assertEqual(candidate.main(), 0)
                execute.assert_called_once_with(True)

    def test_unprivileged_invocation_fails_before_file_access(self):
        """A remote UID1005 cannot use the operator as an elevation helper."""
        with (
            patch.object(candidate.os, "getuid", return_value=1005),
            patch.object(candidate, "_trusted_regular") as read,
            self.assertRaises(candidate.RebindDenied),
        ):
            candidate._trust_root()
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
