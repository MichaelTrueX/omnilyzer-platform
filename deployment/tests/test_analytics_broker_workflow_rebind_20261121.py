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


    def _fake_host(self, *, initial=b"old", new=b"new"):
        """Patch only root I/O boundaries; no privileged fixture is touched."""
        from contextlib import ExitStack
        from types import SimpleNamespace
        from unittest.mock import Mock
        stack = ExitStack()
        state = {"target": initial}
        directory = SimpleNamespace(stat=lambda: SimpleNamespace(st_gid=990))
        stack.enter_context(patch.object(candidate, "_trust_root"))
        stack.enter_context(patch.object(candidate, "DIRECTORY", directory))
        stack.enter_context(patch.object(candidate.os, "open", return_value=17))
        stack.enter_context(patch.object(candidate.os, "close"))
        stack.enter_context(patch.object(candidate.fcntl, "flock"))
        stack.enter_context(patch.object(candidate, "_rebound_bytes", return_value=(new, 990)))
        stack.enter_context(patch.object(candidate, "_missing_at"))
        stack.enter_context(patch("builtins.print"))
        stage = stack.enter_context(patch.object(candidate, "_stage_file"))
        publish = stack.enter_context(patch.object(candidate, "_publish"))
        restart = stack.enter_context(patch.object(candidate, "_restart_broker"))
        service = stack.enter_context(patch.object(candidate, "_service_state", return_value=17))
        route = stack.enter_context(patch.object(candidate, "_route_state", return_value=("active", {"phase":"switched"})))

        def read(_parent, name, **_kwargs):
            if name == candidate.BACKUP:
                return initial, (1, 8, 2, 3, 0)
            return state["target"], (1, 7, 2, 3, 990)

        stack.enter_context(patch.object(candidate, "_read_at", side_effect=read))
        return stack, state, stage, publish, restart, service, route

    def test_full_preflight_has_zero_write_or_restart(self):
        """Real root-only write helpers cannot be reached during preflight."""
        stack, _state, stage, publish, restart, _service, route = self._fake_host()
        with stack:
            candidate._execute(False)
        stage.assert_not_called()
        publish.assert_not_called()
        restart.assert_not_called()
        route.assert_called_once_with()

    def test_successful_apply_swaps_once_and_restarts_only_broker(self):
        """Commit only one exact config exchange with unchanged active writer."""
        stack, state, stage, publish, restart, service, route = self._fake_host()
        service.side_effect = [17, 18]
        def exchange(_dir, name, old, new, **_kwargs):
            self.assertEqual((name, old, new), (candidate.STAGED, b"old", b"new"))
            state["target"] = new
        publish.side_effect = exchange
        with stack:
            candidate._execute(True)
        self.assertEqual(stage.call_count, 1)
        self.assertEqual(publish.call_count, 1)
        restart.assert_called_once_with()
        self.assertEqual(route.call_count, 2)

    def test_failure_after_atomic_swap_triggers_restore(self):
        """An error after rename must not strand the changed original broker."""
        stack, state, stage, publish, restart, service, route = self._fake_host()
        def interrupted(_dir, name, _old, new, **_kwargs):
            state["target"] = new
            if name == candidate.STAGED:
                raise OSError("synthetic post-rename fsync failure")
        publish.side_effect = interrupted
        with stack, self.assertRaises(candidate.RebindDenied):
            candidate._execute(True)
        self.assertEqual(
            [c.args[1] for c in publish.call_args_list],
            [candidate.STAGED, candidate.RESTORE],
        )
        self.assertEqual(state["target"], b"old")
        restart.assert_called_once_with()
        self.assertEqual(route.call_count, 2)

    def test_failure_before_swap_never_restarts_service(self):
        """A failed backup write cannot touch the running broker or its route."""
        stack, state, stage, publish, restart, service, route = self._fake_host()
        stage.side_effect = OSError("synthetic backup denied")
        with stack, self.assertRaises(candidate.RebindDenied):
            candidate._execute(True)
        self.assertEqual(state["target"], b"old")
        publish.assert_not_called()
        restart.assert_not_called()
        route.assert_called_once_with()



if __name__ == "__main__":
    unittest.main()
