"""File: deployment/tests/test_private_executor_preflight.py

Purpose: Verify private Zot manifest preflight happens BEFORE the executor
consumes replay or changes deployment state, with exact bound request bytes.
Related: deployment/executor.py, deployment/private_registry_pull.py,
deployment/private_registry_fd.py, deployment/tests/test_executor.py.

Sections: synthetic authority fixture; replay ordering; context cleanup and
failed preflight rejection. No live Docker, Zot, network or root privileges.
"""

from __future__ import annotations

import os
import time
import unittest

from deployment.execution import ExecutorRequest
from deployment.executor import ExecutorUnavailableError, RestrictedPrivilegedExecutor
from deployment.private_registry_fd import (
    create_sealed_credential, read_sealed_credential,
)
from deployment.private_registry_pull import current_private_zot_request
from deployment.tests.test_executor import Operation, Replay, request_bytes

REQUEST = request_bytes()
IMAGE = ExecutorRequest.from_dict(
    __import__("deployment.tests.fixtures", fromlist=["executor_request_value"]).executor_request_value()
).exact_image_reference
TOKEN = "synthetic-verification-only.jwt"


class Preflight:
    """One inert read-only manifest authority collaborator."""

    def __init__(self, events: list[str], *, reject: bool = False) -> None:
        self.events = events
        self.reject = reject

    def preflight_private_registry(self, canonical_request: bytes,
                                   credential_fd: int) -> None:
        """Reject malformed credentials before replay transition."""
        self.events.append("preflight")
        validated = read_sealed_credential(
            credential_fd, canonical_request=canonical_request, image=IMAGE,
        )
        assert validated.token == TOKEN
        if self.reject:
            raise OSError("synthetic private registry returned 401")


class Deployment:
    """The existing exact deploy(request) boundary observes only scoped fd."""

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls = 0

    def deploy(self, request: ExecutorRequest) -> None:
        """Require only one exact credential binding while deploying."""
        self.events.append("deploy")
        self.calls += 1
        scoped = current_private_zot_request()
        assert scoped is not None
        fd, original = scoped
        assert original == REQUEST
        assert read_sealed_credential(fd, canonical_request=REQUEST, image=IMAGE).token == TOKEN


class PrivateExecutorPreflightTests(unittest.TestCase):
    """Fail closed without replay writes when registry authorization fails."""

    def fd(self, *, lifetime: int = 100) -> int:
        """Create and register one test-only sealed fd."""
        now = int(time.time())
        descriptor = create_sealed_credential(
            TOKEN, expires_at=now + lifetime, image=IMAGE,
            canonical_request=REQUEST, now=now,
        )
        self.addCleanup(os.close, descriptor)
        return descriptor

    def test_success_orders_preflight_before_replay_and_deploy(self) -> None:
        """The executor accepts exactly one checked private registry operation."""
        events: list[str] = []
        replay = Replay(events)
        deploy = Deployment(events)
        executor = RestrictedPrivilegedExecutor(
            replay_guard=replay, operation=deploy,
            private_registry_preflight=Preflight(events),
        )
        result = executor.execute_private(REQUEST, credential_fd=self.fd())
        self.assertIsInstance(result, bytes)
        self.assertEqual(
            events, ["preflight", "begin_execution", "deploy", "finish_execution"],
        )
        self.assertEqual(deploy.calls, 1)
        self.assertIsNone(current_private_zot_request())

    def test_manifest_denial_does_not_touch_replay(self) -> None:
        """A Zot 401 preflight leaves replay, audit and deployment idle."""
        events: list[str] = []
        replay = Replay(events)
        deploy = Deployment(events)
        executor = RestrictedPrivilegedExecutor(
            replay_guard=replay, operation=deploy,
            private_registry_preflight=Preflight(events, reject=True),
        )
        with self.assertRaises(ExecutorUnavailableError) as failed:
            executor.execute_private(REQUEST, credential_fd=self.fd())
        self.assertEqual(str(failed.exception), "executor is unavailable")
        self.assertEqual(events, ["preflight"])
        self.assertEqual(replay.begin_calls, [])
        self.assertEqual(deploy.calls, 0)
        self.assertIsNone(current_private_zot_request())

    def test_legacy_uncredentialed_method_rejected_before_replay(self) -> None:
        """Enabling private mode removes the old unauthenticated execution path."""
        events: list[str] = []
        replay = Replay(events)
        deploy = Deployment(events)
        executor = RestrictedPrivilegedExecutor(
            replay_guard=replay, operation=deploy,
            private_registry_preflight=Preflight(events),
        )
        with self.assertRaises(Exception):
            executor.execute(REQUEST)
        self.assertEqual(events, [])
        self.assertEqual(replay.begin_calls, [])

    def test_wrong_request_and_unsealed_fd_never_run_preflight(self) -> None:
        """Malformed or unbound FD rejects before the manifest request."""
        events: list[str] = []
        executor = RestrictedPrivilegedExecutor(
            replay_guard=Replay(events),
            operation=Deployment(events),
            private_registry_preflight=Preflight(events),
        )
        with self.assertRaises(ExecutorUnavailableError):
            executor.execute_private(REQUEST + b" ", credential_fd=self.fd())
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
