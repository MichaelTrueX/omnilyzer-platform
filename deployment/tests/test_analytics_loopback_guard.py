"""File: deployment/tests/test_analytics_loopback_guard.py

Purpose: Exercise the narrow Analytics DEV RootlessKit lifecycle guard in a
         fully mocked, unprivileged environment without Docker/systemd writes.
Related: deployment/analytics_loopback_guard.py,
         deployment/systemd/rootless/omnilyzer-analytics-loopback.service,
         docs/operations/task014-analytics-loopback-20261031.md.

Security: No test connects to any socket, launches Docker, changes a port or
uses host secrets. Fail-closed route, container identity and cleanup required.
"""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from deployment import analytics_loopback_guard as guard


# Section 1: Complete synthetic Docker and RootlessKit authority fixtures.
CID = "a" * 64
CANARY = {"id": 1, "spec": dict(guard._CANARY)}


class FakeAPIs:
    """Simulate exactly the closed two local Unix APIs, never a real socket."""

    def __init__(self):
        """Initialize the authorized, signed immutable blue image fixture."""
        self.container = {
            "Name": "/" + guard._CONTAINER,
            "Id": CID,
            "Config": {"Image": guard._IMAGE, "User": "10001:10001"},
            "State": {"Running": True, "Health": {"Status": "healthy"}},
            "HostConfig": {"PortBindings": {"3000/tcp": [
                {"HostIp": "127.0.0.1", "HostPort": "3141"}]},
                "ReadonlyRootfs": True, "Privileged": False,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"]},
            "NetworkSettings": {
                "Ports": {"3000/tcp": None},
                "Networks": {guard._NETWORK: {
                    "IPAddress": "172.20.0.3", "Gateway": "",
                    "NetworkID": guard._NETWORK_ID}}},
        }
        self.network = {"Name": guard._NETWORK,
                        "Id": guard._NETWORK_ID,
                        "Internal": True, "Driver": "bridge"}
        self.info = {"apiVersion": "1.1.2", "version": "3.1.0",
                     "portDriver": {"driver": "builtin", "protos": ["tcp4"]},
                     "networkDriver": {"driver": "slirp4netns"}}
        self.rules = [deepcopy(CANARY)]
        self.writes = []
        self.post_response_bad = False

    def __call__(self, path, method, resource, body=None, status=200):
        """Return bounded fixture values and record only routing mutations."""
        if method == "GET":
            return deepcopy({
                (guard._DOCKER, "/containers/" + guard._CONTAINER + "/json"):
                self.container,
                (guard._DOCKER, "/networks/" + guard._NETWORK): self.network,
                (guard._ROOTLESS, "/v1/info"): self.info,
                (guard._ROOTLESS, "/v1/ports"): self.rules,
            }[(path, resource)])
        if method == "POST":
            assert (path, resource, status) == (guard._ROOTLESS, "/v1/ports", 201)
            assert body == guard._TARGET
            self.writes.append("add")
            added = {"id": 2, "spec": dict(body)}
            self.rules.append(added)
            return deepcopy({"id": 2, "spec": {"proto": "wrong"}} if self.post_response_bad
                            else added)
        if method == "DELETE":
            assert path == guard._ROOTLESS
            self.writes.append("remove:" + resource)
            identifier = int(resource.removeprefix("/v1/ports/"))
            assert identifier != 1  # Never delete the existing Canary mapping.
            self.rules = [x for x in self.rules if x["id"] != identifier]
            return None
        raise AssertionError("unexpected API request")


# Section 2: Security and lifecycle regressions around a single loopback rule.
class LoopbackGuardTests(unittest.TestCase):
    """Demonstrate the signed reference cannot leak to an unrelated container."""

    def setUp(self):
        """Bind all requests to private fakes and exact reviewed container ID."""
        self.fake = FakeAPIs()
        self.patches = [
            patch.dict(os.environ, {"ANALYTICS_APPROVED_CONTAINER_ID": CID}),
            patch.object(guard.os, "geteuid", return_value=991),
            patch.object(guard, "_api", side_effect=self.fake),
            patch.object(guard, "_http_ready", return_value=None),
        ]
        for instance in self.patches:
            instance.start()
            self.addCleanup(instance.stop)

    def test_valid_first_start_exposes_then_removes_exact_mapping(self):
        """A graceful stop removes only the new rule and keeps Canary ID 1."""
        with patch.object(guard.time, "sleep", side_effect=guard._Stop):
            with self.assertRaises(guard._Stop):
                guard._serve()
        self.assertEqual(self.fake.rules, [CANARY])
        self.assertEqual(self.fake.writes,
                         ["add", "remove:/v1/ports/2"])

    def test_docker_image_swap_denied_before_any_port_add(self):
        """Unsigned image changes cannot inherit the approved host loopback."""
        self.fake.container["Config"]["Image"] = "other@sha256:" + "f" * 64
        with self.assertRaises(ValueError):
            guard._serve()
        self.assertEqual(self.fake.writes, [])

    def test_unreviewed_replacement_container_id_denied(self):
        """An otherwise healthy replacement cannot adopt the previous rule."""
        self.fake.container["Id"] = "b" * 64
        with self.assertRaises(ValueError):
            guard._serve()
        self.assertEqual(self.fake.writes, [])

    def test_network_not_internal_denied(self):
        """Never approve a switch to a public or arbitrary bridge network."""
        self.fake.network["Internal"] = False
        with self.assertRaises(ValueError):
            guard._serve()
        self.assertEqual(self.fake.writes, [])

    def test_missing_canary_denies_new_publication(self):
        """Unexpected changes to original Canary cannot be papered over."""
        self.fake.rules = []
        with self.assertRaises(ValueError):
            guard._serve()
        self.assertEqual(self.fake.writes, [])

    def test_wrong_creation_response_still_cleans_up(self):
        """An API response ambiguity after POST must never strand an open port."""
        self.fake.post_response_bad = True
        with self.assertRaises(ValueError):
            guard._serve()
        self.assertEqual(self.fake.rules, [CANARY])
        self.assertEqual(self.fake.writes,
                         ["add", "remove:/v1/ports/2"])

    def test_failed_host_health_after_publish_cleans_up(self):
        """A failed loopback health probe closes the port immediately."""
        with patch.object(guard, "_http_ready", side_effect=OSError):
            with self.assertRaises(OSError):
                guard._serve()
        self.assertEqual(self.fake.rules, [CANARY])
        self.assertEqual(self.fake.writes,
                         ["add", "remove:/v1/ports/2"])

    def test_container_stops_during_monitoring_cleans_up(self):
        """A now-stopped container loses the mapping on the next check."""
        def change_state(_seconds):
            self.fake.container["State"]["Running"] = False
        with patch.object(guard.time, "sleep", side_effect=change_state):
            with self.assertRaises(ValueError):
                guard._serve()
        self.assertEqual(self.fake.rules, [CANARY])
        self.assertEqual(self.fake.writes,
                         ["add", "remove:/v1/ports/2"])

    def test_stale_rule_removed_before_verifying_replacement(self):
        """Crash residue is removed before a changed container can be served."""
        self.fake.rules.append({"id": 7, "spec": dict(guard._TARGET)})
        self.fake.container["Id"] = "b" * 64
        with self.assertRaises(ValueError):
            guard._serve()
        self.assertEqual(self.fake.rules, [CANARY])
        self.assertEqual(self.fake.writes, ["remove:/v1/ports/7"])

    def test_cleanup_when_canary_absent_still_removes_target(self):
        """Canary loss cannot prevent cleanup of a previously opened port."""
        self.fake.rules = [{"id": 8, "spec": dict(guard._TARGET)}]
        guard._delete_target()
        self.assertEqual(self.fake.rules, [])
        self.assertEqual(self.fake.writes, ["remove:/v1/ports/8"])

    def test_original_canary_never_removed_when_unrelated_rule_present(self):
        """A third-party port does not grant authority to touch Canary."""
        self.fake.rules.append({"id": 9, "spec": {
            "proto": "tcp4", "parentIP": "127.0.0.1", "parentPort": 3333,
            "childIP": "127.0.0.1", "childPort": 3333}})
        with self.assertRaises(ValueError):
            guard._serve()
        self.assertEqual(self.fake.writes, [])

    def test_uid_and_container_pin_are_mandatory(self):
        """Service may not select an ID from unreviewed mutable Docker state."""
        with patch.object(guard.os, "geteuid", return_value=1005):
            with self.assertRaises(ValueError):
                guard._identity()
        with patch.dict(os.environ, {"ANALYTICS_APPROVED_CONTAINER_ID": ""}):
            with self.assertRaises(ValueError):
                guard._identity()

    def test_unit_contains_narrow_systemd_boundaries(self):
        """Root manager must supervise UID991, root-owned ID and loopback only."""
        p = Path(__file__).resolve().parents[1] / "systemd/rootless/omnilyzer-analytics-loopback.service"
        content = p.read_text()
        for expected in ("User=omnilyzer-executor", "NoNewPrivileges=yes",
                         "ExecStopPost=", "Restart=always",
                         "EnvironmentFile=/etc/omnilyzer/deployment/analytics-loopback.env",
                         "IPAddressAllow=localhost"):
            self.assertIn(expected, content)


if __name__ == "__main__":
    unittest.main()
