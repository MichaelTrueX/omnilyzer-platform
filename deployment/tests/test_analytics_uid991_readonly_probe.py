"""File: deployment/tests/test_analytics_uid991_readonly_probe.py

Purpose: Test the isolated UID991 diagnostic's exact fixed-output classifier.
Related: deployment/analytics_uid991_readonly_probe.py,
         deployment/analytics_active_state_review.py.

Authority: Synthetic, unprivileged regression only. Never contacts Docker,
           performs setpriv, installs files, or calls a root operator.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

# Section 1: Load only the locally checked first-party source for tests.
_SOURCE = Path(__file__).resolve().parent.parent / "analytics_uid991_readonly_probe.py"
_spec = importlib.util.spec_from_file_location("uid991_probe_under_test", _SOURCE)
assert _spec is not None and _spec.loader is not None
_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_probe)


def _fake_modules(*, ports, digests, green=None, fail="") -> dict:
    """Build inert test modules with the exact projected product API shape."""
    package = types.ModuleType("deployment")
    package.__path__ = []
    config = types.ModuleType("deployment.analytics_executor_service_config")
    active = types.ModuleType("deployment.analytics_active_state_review")
    signed = types.ModuleType("deployment.analytics_signed_release_consumer")
    signed.PINNED_DIGEST = "sha256:" + "b" * 64
    signed.PINNED_IMAGE = "example.org/analytics@" + signed.PINNED_DIGEST

    def load(*, require_successor=False):
        """Return exact immutable 766e mock identities or raise a test hold."""
        if fail == "SOURCE":
            raise RuntimeError("synthetic private value never emitted")
        return (
            {"reviewed_installed_commit": _probe._EXPECTED_COMMIT},
            {"expected_workflow_sha": _probe._EXPECTED_COMMIT,
             "owner_authorized_first_successor": True,
             "expected_executor_uid": 991, "expected_executor_gid": 991},
        )

    def observe():
        """Return a blue signed snapshot or intentionally fail the observer."""
        if fail == "ACTIVE":
            raise RuntimeError("synthetic private value never emitted")
        return types.SimpleNamespace(
            active_slot="blue", active_digest=signed.PINNED_DIGEST,
            active_image=signed.PINNED_IMAGE, candidate_probe_present=False,
        )

    def empty():
        """Simulate Docker's separately checked empty successor condition."""
        if fail == "EMPTY" or green is not None:
            raise RuntimeError("synthetic private value never emitted")

    def get(_endpoint, path):
        """Return only predetermined in-memory Docker example responses."""
        if path.endswith("blue-1/json"):
            return {"NetworkSettings": {"Ports": {"3000/tcp": ports}},
                    "Image": "sha256:" + "a" * 64}
        if path.endswith("green-1/json"):
            return green
        if path.startswith("/images/"):
            return {"RepoDigests": digests}
        raise AssertionError("unexpected mock API")

    config.load_analytics_executor_service_config = load
    active.inspect_analytics_active_state = observe
    active.verify_empty_analytics_successor_slot = empty
    active._unix_get = get
    active._DOCKER = "/run/user/991/docker.sock"
    active._PREFIX = "omnilyzer-analytics-dev-analytics-"
    return {
        "deployment": package,
        config.__name__: config,
        active.__name__: active,
        signed.__name__: signed,
    }


# Section 2: Prove no privileges and mutually exclusive known response shapes.
class ProbeTests(unittest.TestCase):
    """Require fixed markers without touching the actual private DEV daemon."""

    def test_non_uid991_direct_run_is_denied(self):
        """The normal development user cannot run the active probe."""
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(_SOURCE)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=4,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"M05_UID991_PROCESS_HOLD\n")
        self.assertEqual(result.stderr, b"")

    def test_unprivileged_launcher_refuses_without_writes(self):
        """The privileged launcher must refuse a normal user immediately."""
        launcher = _SOURCE.parent / "m05_uid991_readonly_once.sh"
        for tail in ([], ["unexpected"]):
            with self.subTest(tail=tail):
                result = subprocess.run(
                    ["/usr/bin/bash", str(launcher), *tail],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, timeout=4,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(
                    result.stdout,
                    b"M05_UID991_READONLY_LAUNCH_HOLD_NO_RETRY\n",
                )
                self.assertEqual(result.stderr, b"")

    def test_approved_null_and_single_digest(self):
        """Preserve the original rootless Docker fixture's fixed green state."""
        with patch.object(_probe, "_trusted_source_root", return_value=True):
            with patch.dict(sys.modules, _fake_modules(ports=None, digests=["x"])):
                state = _probe._diagnose()
        self.assertEqual([state[k] for k in _probe._MARKERS[:5]], ["PASS"] * 5)
        self.assertEqual(state["BLUE_PORT_SHAPE"], "NULL")
        self.assertEqual(state["BLUE_REPODIGEST_SHAPE"], "ONE")
        self.assertEqual(state["GREEN_EXISTS"], "NO")

    def test_alternate_valid_docker_shapes_are_reported_only(self):
        """Describe empty-list and multiple-digest variants without accepting them."""
        with patch.object(_probe, "_trusted_source_root", return_value=True):
            with patch.dict(sys.modules, _fake_modules(ports=[], digests=["x", "y"])):
                state = _probe._diagnose()
        self.assertEqual(state["BLUE_PORT_SHAPE"], "EMPTY_LIST")
        self.assertEqual(state["BLUE_REPODIGEST_SHAPE"], "MULTIPLE")

    def test_separate_uid991_holds_without_exception_leaks(self):
        """Surface the actual failed stage while never emitting secret text."""
        for stage in ("SOURCE", "ACTIVE", "EMPTY"):
            with self.subTest(stage=stage):
                with patch.object(_probe, "_trusted_source_root", return_value=True):
                    with patch.dict(sys.modules, _fake_modules(ports=None, digests=["x"], fail=stage)):
                        state = _probe._diagnose()
                self.assertEqual(state[stage], "HOLD")
                self.assertEqual(state["IDENTITY"], "HOLD" if stage != "EMPTY" else "PASS")
                self.assertFalse(any("synthetic" in value for value in state.values()))

    def test_fd_level_output_suppression_drops_private_stream_writes(self):
        """Do not let imported code emit API data through either OS FD."""
        payload = f"""import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('fixed_probe', {str(_SOURCE)!r})
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
probe._authorized_process = lambda: True
probe._diagnose = lambda: (
    os.write(1, b'PRIVATE_DOCKER_RESPONSE\\n'),
    os.write(2, b'PRIVATE_TOKEN_RESPONSE\\n'),
    {{name: 'PASS' for name in probe._MARKERS}},
)[2]
raise SystemExit(probe.main())
"""
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", payload],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=4,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        expected = "".join(
            f"M05_UID991_{key}=PASS\n" for key in _probe._MARKERS
        )
        self.assertEqual(result.stdout, expected.encode("ascii"))

    def test_stopped_green_is_identified_without_contents(self):
        """A stopped or unattached green remains a present candidate slot."""
        with patch.object(_probe, "_trusted_source_root", return_value=True):
            with patch.dict(sys.modules, _fake_modules(ports=None, digests=["x"], green={})):  # 404 is None
                state = _probe._diagnose()
        self.assertEqual(state["EMPTY"], "HOLD")
        self.assertEqual(state["GREEN_EXISTS"], "YES")


if __name__ == "__main__":
    unittest.main()
