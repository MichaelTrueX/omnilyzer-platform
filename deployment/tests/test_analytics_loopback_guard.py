"""File: deployment/tests/test_analytics_loopback_guard.py

Purpose: Preserve original signed blue-only loopback lifecycle tests,
         plus synthetic journaled 3142 candidate preparation, exact-image
         blue/green route replacement and recovery across crash boundaries.
Related: deployment/analytics_loopback_guard.py,
         deployment/analytics_active_state_review.py,
         deployment/systemd/rootless/omnilyzer-analytics-loopback.service,
         docs/operations/task14b-release-identity-contract-20261102.md.

Security: No test connects to any live socket, Docker or systemd. Canary
3020, original 0.15.0 identity, private OCI bytes and rollback are strictly
checked against fake local APIs. Synthetic failure recovery is NOT proof
of crash-atomic routing, real writes or owner-authorized DEV deployment.
"""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deployment import analytics_loopback_guard as guard
from deployment.analytics_route_journal import (
    AnalyticsRouteJournal, AnalyticsRouteJournalUnavailable,
)


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


# Section 3: staged rootless API transaction for a later, separately
# approved supervisor upgrade. All tests run against synthetic APIs only.
class SuccessorRoutes:
    """Falsifiable route inventory with deliberate partial-write failures."""

    def __init__(self, *, active_slot: str = "blue"):
        from deployment.tests.test_analytics_active_state_review import staged

        state = staged(active_slot=active_slot)
        self.state = state
        self.rules = deepcopy(state["ports"])
        self.changes = []
        self.new_ack_bad = False
        self.new_post_fails = False
        self.restore_fails = False
        self.delete_fails_before_mutation = False
        self.delete_fails_after_mutation = False
        self.next_id = 5

    def __call__(self, path, method, resource, body=None, status=200):
        """Emulate only existing local RootlessKit and Docker APIs."""
        if method == "GET":
            fixtures = {
                (guard._ROOTLESS, "/v1/info"): self.state["info"],
                (guard._ROOTLESS, "/v1/ports"): self.rules,
                (guard._DOCKER, "/networks/" + guard._NETWORK): self.state["network"],
            }
            for slot in ("blue", "green"):
                container = self.state[slot]
                fixtures[(
                    guard._DOCKER,
                    "/containers/" + guard._SLOT_NAMES[slot] + "/json",
                )] = container
                fixtures[(
                    guard._DOCKER, "/images/" + container["Image"] + "/json",
                )] = {
                    "Id": container["Image"],
                    "RepoDigests": [container["Config"]["Image"]],
                    "Os": "linux", "Architecture": "amd64",
                }
            return deepcopy(fixtures[(path, resource)])
        if method == "DELETE":
            self.changes.append(("DELETE", resource))
            if self.delete_fails_before_mutation:
                self.delete_fails_before_mutation = False
                raise OSError("no RootlessKit DELETE was performed")
            identifier = int(resource.removeprefix("/v1/ports/"))
            assert identifier != self.rules[0]["id"]
            self.rules = [r for r in self.rules if r["id"] != identifier]
            if self.delete_fails_after_mutation:
                self.delete_fails_after_mutation = False
                raise OSError("lost RootlessKit DELETE acknowledgement")
            return None
        if method == "POST":
            assert (path, resource, status) == (
                guard._ROOTLESS, "/v1/ports", 201,
            )
            self.changes.append(("POST", deepcopy(body)))
            if body["childIP"] == "172.20.0.4" and self.new_post_fails:
                raise OSError("new target unavailable")
            if body["childIP"] == "172.20.0.3" and self.restore_fails:
                raise OSError("original restoration failed")
            created = {"id": self.next_id, "spec": deepcopy(body)}
            self.next_id += 1
            self.rules.append(created)
            if body["childIP"] == "172.20.0.4" and self.new_ack_bad:
                return {"id": created["id"], "spec": {"proto": "wrong"}}
            return deepcopy(created)
        raise AssertionError("unexpected API")

    def route(self, port):
        """Return the exact current rule for one loopback parent port."""
        return [r for r in self.rules if r["spec"].get("parentPort") == port]


class AnalyticsSuccessorRouteTransactionTests(unittest.TestCase):
    """Preserve the old signed blue image, Canary and rollback under failures."""

    def setUp(self):
        """Grant only a simulated upgraded UID991 supervisor environment."""
        self.backend = SuccessorRoutes()
        self._directory = tempfile.TemporaryDirectory(
            prefix="omnilyzer-route-guard-",
        )
        self.addCleanup(self._directory.cleanup)
        self.journal = AnalyticsRouteJournal(
            self._directory.name, expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
        self.old = {
            "previous_slot": "blue", "previous_image": guard._IMAGE,
            "previous_id": self.backend.state["blue"]["Id"],
            "next_slot": "green",
            "next_image": self.backend.state["green"]["Config"]["Image"],
            "next_id": self.backend.state["green"]["Id"],
            "journal": self.journal, "request_sha256": "c" * 64,
        }
        self.original_canary = deepcopy(self.backend.rules[0])
        self.original_stable = deepcopy(self.backend.route(3141)[0])
        self.patches = (
            patch.dict(os.environ, {guard._SUCCESSOR_SCOPE: "1"}),
            patch(
                "deployment.analytics_route_journal.ROUTE_JOURNAL_DIRECTORY",
                self._directory.name,
            ),
            patch.object(guard.os, "geteuid", return_value=991),
            patch.object(guard, "_api", side_effect=self.backend),
            patch.object(guard, "_candidate_http_ready", return_value=None),
            patch.object(guard, "_http_ready", return_value=None),
        )
        for controlled in self.patches:
            controlled.start()
            self.addCleanup(controlled.stop)

    def _seed_reviewed_ready_journal(self):
        """Replay a prior successful candidate-stage journal for old cutover tests.

        This test-only helper does not modify RootlessKit or approve a release.
        It writes the same fsync-checked phase the new real staging primitive
        must emit, using OCI identities from the independent fake Docker state.
        """
        if self.journal.read() is not None:
            return
        current_ip = self.backend.route(3141)[0]["spec"]["childIP"]
        previous = next(
            slot for slot in ("blue", "green")
            if self.backend.state[slot]["NetworkSettings"]["Networks"][
                guard._NETWORK
            ]["IPAddress"] == current_ip
        )
        next_slot = "green" if previous == "blue" else "blue"
        old = self.backend.state[previous]
        nxt = self.backend.state[next_slot]
        previous_ip = old["NetworkSettings"]["Networks"][guard._NETWORK]["IPAddress"]
        next_ip = nxt["NetworkSettings"]["Networks"][guard._NETWORK]["IPAddress"]
        prepared = self.journal.begin(
            request_sha256="c" * 64,
            previous_slot=previous,
            previous_image=old["Config"]["Image"],
            previous_container_id=old["Id"], previous_ip=previous_ip,
            next_slot=next_slot,
            next_image=nxt["Config"]["Image"],
            next_container_id=nxt["Id"], next_ip=next_ip,
        )
        self.journal.finish(prepared, phase="candidate_ready")

    def _without_candidate_route(self):
        """Simulate healthy green container before its private probe is routed."""
        self.backend.rules = [
            entry for entry in self.backend.rules
            if entry["spec"].get("parentPort") != 3142
        ]

    def test_journaled_candidate_probe_then_exact_green_cutover(self):
        """Persist pre-3142 intent, prove health and reuse only candidate_ready."""
        self._without_candidate_route()
        self.assertIsNone(guard._stage_reviewed_private_candidate_probe(**self.old))
        intent = self.journal.read()
        self.assertEqual(intent["phase"], "candidate_ready")
        self.assertEqual(intent["request_sha256"], self.old["request_sha256"])
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(len(self.backend.route(3142)), 1)
        self.assertEqual(self.backend.route(3142)[0]["spec"]["parentIP"],
                         "127.0.0.1")
        self.assertEqual(self.backend.changes[0][0], "POST")
        self.assertEqual(self.backend.changes[0][1]["parentPort"], 3142)
        # No independent authority for another request/JTI at cutover.
        with self.assertRaises(ValueError):
            guard._switch_reviewed_private_route(
                **{**self.old, "request_sha256": "f" * 64}
            )
        self.assertEqual(len(self.backend.changes), 1)
        self.assertEqual(self.journal.read(), intent)
        self.assertIsNone(guard._switch_reviewed_private_route(**self.old))
        self.assertEqual(self.journal.read()["phase"], "switched")
        self.assertEqual(self.backend.route(3141)[0]["spec"]["childIP"],
                         "172.20.0.4")
        self.assertEqual(self.backend.rules[0], self.original_canary)

    # Section: signed first successor can be reversed AFTER an acknowledged
    # switch when the executor cannot durably finish the original JTI.
    # No real Docker/RootlessKit/DB calls occur in these synthetic fixtures.
    def _commit_green_for_rollback(self):
        """Produce one actual journaled synthetic green cutover."""
        self._without_candidate_route()
        self.assertIsNone(guard._stage_reviewed_private_candidate_probe(**self.old))
        self.assertIsNone(guard._switch_reviewed_private_route(**self.old))
        self.assertEqual(self.journal.read()["phase"], "switched")
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(self.backend.route(3141)[0]["spec"]["childIP"],
                         "172.20.0.4")

    def test_post_commit_rollback_restores_original_signed_blue(self):
        """Rollback finished switch without deleting data, containers or Canary."""
        self._commit_green_for_rollback()
        self.assertIsNone(guard._rollback_committed_private_successor(**self.old))
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.route(3141)[0]["spec"]["childIP"],
                         "172.20.0.3")
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.state["blue"]["State"]["Running"], True)
        self.assertEqual(self.backend.state["green"]["State"]["Running"], True)
        self.assertEqual(self.backend.changes[-2][0], "DELETE")
        self.assertEqual(self.backend.changes[-1][0], "POST")

    def test_post_commit_rollback_wrong_request_or_canary_never_mutates(self):
        """JTI, actor source or live routing drift is checked before fsync."""
        self._commit_green_for_rollback()
        before = list(self.backend.changes)
        for mutation in (
            {"request_sha256": "f" * 64},
            {"previous_image": guard._SUCCESSOR_REPOSITORY + "d" * 64},
            {"previous_id": "c" * 64},
            {"next_id": "e" * 64},
            {"next_image": guard._SUCCESSOR_REPOSITORY + "d" * 64},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                guard._rollback_committed_private_successor(
                    **{**self.old, **mutation},
                )
            self.assertEqual(self.journal.read()["phase"], "switched")
            self.assertEqual(before, self.backend.changes)
        self.backend.rules[0]["spec"]["parentPort"] = 3000
        with self.assertRaises(ValueError):
            guard._rollback_committed_private_successor(**self.old)
        self.assertEqual(self.journal.read()["phase"], "switched")
        self.assertEqual(before, self.backend.changes)

    def test_rollback_pending_crash_before_delete_recovers_old_writer(self):
        """A signed, fsync'd intent survives process loss before DELETE."""
        self._commit_green_for_rollback()
        swapped = self.journal.read()
        pending = self.journal.finish(swapped, phase="rollback_pending")
        self.assertEqual(pending["phase"], "rollback_pending")
        with self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.begin(**{
                "request_sha256": "f" * 64,
                "previous_slot": "green", "previous_image": self.old["next_image"],
                "previous_container_id": self.old["next_id"],
                "previous_ip": "172.20.0.4",
                "next_slot": "blue", "next_image": guard._IMAGE,
                "next_container_id": self.old["previous_id"],
                "next_ip": "172.20.0.3",
            })
        self.assertIsNone(guard._recover_reviewed_private_route(**self.old))
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.route(3141)[0]["spec"]["childIP"],
                         "172.20.0.3")
        self.assertEqual(self.backend.rules[0], self.original_canary)

    def test_rollback_pending_crash_after_delete_recovers_from_canary_only(self):
        """A crash between route DELETE and POST cannot strand all writers."""
        self._commit_green_for_rollback()
        pending = self.journal.finish(
            self.journal.read(), phase="rollback_pending",
        )
        self.backend.rules = [self.backend.rules[0]]
        self.assertEqual(pending["phase"], "rollback_pending")
        self.assertEqual(self.backend.route(3141), [])
        self.assertIsNone(guard._recover_reviewed_private_route(**self.old))
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.route(3141)[0]["spec"]["childIP"],
                         "172.20.0.3")
        self.assertEqual(self.backend.rules[0], self.original_canary)

    def test_rollback_pending_crash_after_blue_repost_only_marks_verified(self):
        """Crash after old3141 POST but before fsync is safely idempotent."""
        self._commit_green_for_rollback()
        self.journal.finish(
            self.journal.read(), phase="rollback_pending",
        )
        self.backend.rules = [
            self.original_canary, self.original_stable,
        ]
        before = list(self.backend.changes)
        self.assertIsNone(guard._recover_reviewed_private_route(**self.old))
        self.assertEqual(self.backend.changes, before)
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        self.assertEqual(self.backend.rules[0], self.original_canary)

    def test_post_commit_rollback_requires_protected_uid_and_service_scope(self):
        """Environment selector alone cannot override the kernel UID or owner."""
        self._commit_green_for_rollback()
        before = list(self.backend.changes)
        with patch.dict(os.environ, {guard._SUCCESSOR_SCOPE: "0"}):
            with self.assertRaises(ValueError):
                guard._rollback_committed_private_successor(**self.old)
        with patch.object(guard.os, "geteuid", return_value=1000):
            with self.assertRaises(ValueError):
                guard._rollback_committed_private_successor(**self.old)
        self.assertEqual(self.journal.read()["phase"], "switched")
        self.assertEqual(before, self.backend.changes)
        self.assertEqual(self.backend.rules[0], self.original_canary)

    def test_failed_pending_intent_fsync_prevents_route_deletion(self):
        """No POST/DELETE when the durable post-COMMIT rollback intent fails."""
        self._commit_green_for_rollback()
        before = list(self.backend.changes)
        original = self.journal.read()
        with patch.object(
            AnalyticsRouteJournal, "finish",
            side_effect=AnalyticsRouteJournalUnavailable(
                "synthetic fsync failure",
            ),
        ):
            with self.assertRaises(AnalyticsRouteJournalUnavailable):
                guard._rollback_committed_private_successor(**self.old)
        self.assertEqual(self.backend.changes, before)
        self.assertEqual(self.journal.read(), original)
        self.assertEqual(
            self.backend.route(3141)[0]["spec"]["childIP"], "172.20.0.4",
        )
        self.assertEqual(self.backend.rules[0], self.original_canary)

    def test_post_commit_failed_recovery_stays_pending_no_false_success(self):
        """Unconfirmed post-commit restoration remains a durable operational HOLD."""
        self._commit_green_for_rollback()
        self.backend.restore_fails = True
        with self.assertRaises(Exception):
            guard._rollback_committed_private_successor(**self.old)
        self.assertEqual(self.journal.read()["phase"], "rollback_pending")
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.backend.restore_fails = False
        self.assertIsNone(guard._recover_reviewed_private_route(**self.old))
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.route(3141)[0]["spec"]["childIP"],
                         "172.20.0.3")

    def test_crash_before_first_3142_post_restores_without_mutation(self):
        """A durable prepare may exist without any route due to process kill."""
        self._without_candidate_route()
        self._prepared_recovery()
        self.assertIsNone(self._reconcile())
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.changes, [])
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        self.assertEqual(self.backend.route(3142), [])

    def test_two_generations_reuse_same_probe_without_new_issuer_or_port(self):
        """Blue0.15.0 -> green successor -> blue next, same durable journal."""
        from deployment.analytics_active_state_review import _active_state
        self._without_candidate_route()
        self.assertIsNone(guard._stage_reviewed_private_candidate_probe(**self.old))
        self.assertIsNone(guard._switch_reviewed_private_route(**self.old))
        self.assertEqual(self.journal.read()["generation"], 1)
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(self.backend.route(3141)[0]["spec"]["childIP"],
                         "172.20.0.4")
        # After the previous blue is separately stopped and preserved by a
        # future approved service, the next reviewed source occupies blue.
        # No actual container, database or route is touched in this fixture.
        new_image = guard._SUCCESSOR_REPOSITORY + "e" * 64
        self.backend.state["blue"]["Config"]["Image"] = new_image
        self.backend.state["blue"]["Image"] = "sha256:" + "e" * 64
        self.backend.state["blue"]["HostConfig"]["PortBindings"] = {}
        later = {
            **self.old,
            "previous_slot": "green",
            "previous_image": self.backend.state["green"]["Config"]["Image"],
            "previous_id": self.backend.state["green"]["Id"],
            "next_slot": "blue", "next_image": new_image,
            "next_id": self.backend.state["blue"]["Id"],
            "request_sha256": "d" * 64,
        }
        self.assertIsNone(guard._stage_reviewed_private_candidate_probe(**later))
        self.assertEqual(self.journal.read()["phase"], "candidate_ready")
        self.assertEqual(self.journal.read()["generation"], 2)
        self.assertEqual(self.backend.route(3142)[0]["spec"]["childIP"],
                         "172.20.0.3")
        self.assertIsNone(guard._switch_reviewed_private_route(**later))
        self.assertEqual(self.journal.read()["phase"], "switched")
        self.assertEqual(self.journal.read()["generation"], 2)
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(self.backend.route(3141)[0]["spec"]["childIP"],
                         "172.20.0.3")
        self.assertEqual(self.backend.rules[0], self.original_canary)
        state = _active_state(
            info=self.backend.state["info"], network=self.backend.state["network"],
            ports=self.backend.rules, blue=self.backend.state["blue"],
            green=self.backend.state["green"],
        )
        self.assertEqual(state.active_slot, "blue")
        self.assertFalse(state.candidate_probe_present)

    def test_restart_after_candidate_probe_retired_restores_signed_old_writer(self):
        """Crash after removing 3142 but before switched fsync is recoverable."""
        self._without_candidate_route()
        self.assertIsNone(guard._stage_reviewed_private_candidate_probe(**self.old))
        self.backend.rules = [
            entry for entry in self.backend.rules
            if entry["spec"]["parentPort"] != 3142
        ]
        self.backend.route(3141)[0]["spec"]["childIP"] = "172.20.0.4"
        self.assertIsNone(self._reconcile())
        self.assertEqual(self.backend.route(3141)[0]["spec"],
                         self.original_stable["spec"])
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.rules[0], self.original_canary)

    def test_candidate_ready_restart_cleans_up_only_orphan_3142(self):
        """Recovered candidate stage preserves old 3141 and drops private probe."""
        self._without_candidate_route()
        self.assertIsNone(guard._stage_reviewed_private_candidate_probe(**self.old))
        self.assertEqual(self.journal.read()["phase"], "candidate_ready")
        changes_before = len(self.backend.changes)
        self.assertIsNone(self._reconcile())
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(
            [x[0] for x in self.backend.changes[changes_before:]],
            ["DELETE"],
        )
        # A previous completed recovery cannot be reused for another JTI.
        with self.assertRaises(ValueError):
            self._reconcile()

    def test_candidate_ready_restart_after_3141_swap_restores_blue(self):
        """Crash after routing mutation but before journal commit restores blue."""
        self._without_candidate_route()
        self.assertIsNone(guard._stage_reviewed_private_candidate_probe(**self.old))
        # Model a crash after DELETE old and POST next, before finish().
        old_rule = self.backend.route(3141)[0]
        self.backend.rules.remove(old_rule)
        self.backend.rules.append({
            "id": 99,
            "spec": {
                **old_rule["spec"], "childIP": "172.20.0.4",
            },
        })
        self.assertIsNone(self._reconcile())
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.route(3141)[0]["spec"],
                         self.original_stable["spec"])
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(self.backend.rules[0], self.original_canary)

    def test_candidate_ready_restart_rejects_unknown_canary_without_delete(self):
        """Corrupt production-like forwarding never triggers speculative cleanup."""
        self._without_candidate_route()
        self.assertIsNone(guard._stage_reviewed_private_candidate_probe(**self.old))
        self.backend.rules[0]["spec"]["childPort"] = 3000
        before = len(self.backend.changes)
        with self.assertRaises(ValueError):
            self._reconcile()
        self.assertEqual(len(self.backend.changes), before)
        self.assertEqual(self.journal.read()["phase"], "candidate_ready")

    def test_candidate_probe_bad_ack_removes_only_3142_and_marks_restored(self):
        """POST may take effect even when its reply is invalid."""
        self._without_candidate_route()
        self.backend.new_ack_bad = True
        with self.assertRaisesRegex(RuntimeError, "CANDIDATE_STAGE_REJECTED"):
            guard._stage_reviewed_private_candidate_probe(**self.old)
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual([x[0] for x in self.backend.changes],
                         ["POST", "DELETE"])

    def test_candidate_probe_failed_health_closes_3142_and_avoids_cutover(self):
        """Candidate HTTP failures retain signed writer and Canary rules."""
        self._without_candidate_route()
        with (
            patch.object(guard, "_candidate_http_ready",
                         side_effect=OSError("synthetic candidate not ready")),
            self.assertRaisesRegex(RuntimeError, "CANDIDATE_STAGE_REJECTED"),
        ):
            guard._stage_reviewed_private_candidate_probe(**self.old)
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(self.backend.route(3141), [self.original_stable])

    def test_candidate_probe_ambiguous_cleanup_remains_prepared_hold(self):
        """Lost DELETE acknowledgement must never be classified as rollback."""
        self._without_candidate_route()
        self.backend.new_ack_bad = True
        self.backend.delete_fails_after_mutation = True
        with self.assertRaisesRegex(RuntimeError,
                                    "CANDIDATE_RECOVERY_UNCONFIRMED"):
            guard._stage_reviewed_private_candidate_probe(**self.old)
        self.assertEqual(self.journal.read()["phase"], "prepared")
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        # After a crash, same signed request may independently reconcile it.
        self.assertIsNone(self._reconcile())
        self.assertEqual(self.journal.read()["phase"], "restored")

    def test_no_existing_release_journal_cannot_start_from_untrusted_green(self):
        """First candidate always originates from protected signed blue 0.15.0."""
        other = SuccessorRoutes(active_slot="green")
        other.rules = [
            x for x in other.rules if x["spec"]["parentPort"] != 3142
        ]
        data = {
            "previous_slot": "green",
            "previous_image": other.state["green"]["Config"]["Image"],
            "previous_id": other.state["green"]["Id"],
            "next_slot": "blue",
            "next_image": other.state["blue"]["Config"]["Image"],
            "next_id": other.state["blue"]["Id"],
            "request_sha256": "c" * 64,
            "journal": self.journal,
        }
        with (
            patch.object(guard, "_api", side_effect=other),
            self.assertRaises(ValueError),
        ):
            guard._stage_reviewed_private_candidate_probe(**data)
        self.assertIsNone(self.journal.read())
        self.assertEqual(other.changes, [])

    def test_candidate_probe_denies_wrong_scope_and_existing_route(self):
        """Never add candidate route from legacy supervisor or unknown source."""
        self._without_candidate_route()
        for patcher in (
            patch.object(guard.os, "geteuid", return_value=1005),
            patch.dict(os.environ, {guard._SUCCESSOR_SCOPE: ""}),
        ):
            with patcher, self.assertRaises(ValueError):
                guard._stage_reviewed_private_candidate_probe(**self.old)
        with self.assertRaises(ValueError):
            guard._stage_reviewed_private_candidate_probe(
                **{**self.old, "next_image": "analytics:latest"}
            )
        self.assertEqual(self.backend.changes, [])
        self.assertIsNone(self.journal.read())
        # A 3142 port that already exists without matching durable journal
        # is never silently adopted by another request.
        self.backend.rules.append(self.backend.state["ports"][2])
        with self.assertRaises(ValueError):
            guard._stage_reviewed_private_candidate_probe(**self.old)
        self.assertEqual(self.backend.changes, [])

    def test_reversible_cutover_selects_green_without_touching_canary(self):
        """After validated candidate health, only 3141 moves to exact green."""
        self._seed_reviewed_ready_journal()
        self.assertIsNone(guard._switch_reviewed_private_route(**self.old))
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.route(3141)[0]["spec"]["childIP"], "172.20.0.4")
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(
            [(kind, value) for kind, value in self.backend.changes if kind == "DELETE"],
            [("DELETE", "/v1/ports/3"), ("DELETE", "/v1/ports/4")],
        )
        self.assertEqual(len(self.backend.changes), 3)
        # Reused inspector must accept a quiet completed successor with
        # only Canary3020 + current Analytics3141; no stale 3142.
        from deployment.analytics_active_state_review import _active_state
        self.assertEqual(
            _active_state(
                info=self.backend.state["info"], network=self.backend.state["network"],
                ports=self.backend.rules, blue=self.backend.state["blue"],
                green=self.backend.state["green"],
            ).active_slot, "green",
        )

    def test_reusable_reverse_green_to_blue_switch_preserves_canary(self):
        """After one future release, the same routine handles either slot."""
        self.backend = SuccessorRoutes(active_slot="green")
        self.old = {
            "previous_slot": "green",
            "previous_image": self.backend.state["green"]["Config"]["Image"],
            "previous_id": self.backend.state["green"]["Id"],
            "next_slot": "blue",
            "next_image": self.backend.state["blue"]["Config"]["Image"],
            "next_id": self.backend.state["blue"]["Id"],
            "journal": self.journal, "request_sha256": "c" * 64,
        }
        self._seed_reviewed_ready_journal()
        with patch.object(guard, "_api", side_effect=self.backend):
            self.assertIsNone(guard._switch_reviewed_private_route(**self.old))
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.route(3141)[0]["spec"]["childIP"], "172.20.0.3")
        self.assertEqual(self.backend.route(3142), [])
        self.assertEqual(len(self.backend.changes), 3)

    def test_candidate_health_failure_does_not_remove_existing_writers(self):
        """Even a healthy Docker candidate needs a real 3142 probe."""
        self._seed_reviewed_ready_journal()
        with patch.object(
            guard, "_candidate_http_ready",
            side_effect=OSError("synthetic private candidate unavailable"),
        ), self.assertRaises(OSError):
            guard._switch_reviewed_private_route(**self.old)
        self.assertEqual(self.backend.changes, [])
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        self.assertEqual(self.backend.rules[0], self.original_canary)

    def test_failed_delete_keeps_original_route_and_rejects_without_repost(self):
        """An unchanged old forwarding rule is already a valid recovery."""
        self._seed_reviewed_ready_journal()
        self.backend.delete_fails_before_mutation = True
        with self.assertRaisesRegex(RuntimeError, "ROUTE_CHANGE_REJECTED"):
            guard._switch_reviewed_private_route(**self.old)
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        self.assertEqual(len(self.backend.changes), 2)
        self.assertEqual([c[0] for c in self.backend.changes], ["DELETE", "DELETE"])
        self.assertEqual(self.backend.route(3142), [])

    def test_lost_delete_ack_restores_original_route_without_touching_canary(self):
        """API might mutate and then lose its response: restore old identity."""
        self._seed_reviewed_ready_journal()
        self.backend.delete_fails_after_mutation = True
        with self.assertRaisesRegex(RuntimeError, "ROUTE_CHANGE_REJECTED"):
            guard._switch_reviewed_private_route(**self.old)
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.route(3141)[0]["spec"], self.original_stable["spec"])
        self.assertEqual(self.backend.route(3142), [])

    def test_failed_create_restores_old_target_without_orphan_probe(self):
        """Old signed writer remains available if new RootlessKit POST fails."""
        self._seed_reviewed_ready_journal()
        self.backend.new_post_fails = True
        with self.assertRaisesRegex(RuntimeError, "ROUTE_CHANGE_REJECTED"):
            guard._switch_reviewed_private_route(**self.old)
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.route(3141)[0]["spec"], self.original_stable["spec"])
        self.assertEqual(self.backend.route(3142), [])

    def test_ambiguous_new_post_receipt_removes_new_and_recovers_old(self):
        """No unconfirmed new rule may remain when API response was malformed."""
        self._seed_reviewed_ready_journal()
        self.backend.new_ack_bad = True
        with self.assertRaisesRegex(RuntimeError, "ROUTE_CHANGE_REJECTED"):
            guard._switch_reviewed_private_route(**self.old)
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.route(3141)[0]["spec"], self.original_stable["spec"])
        self.assertEqual(len(self.backend.route(3141)), 1)

    def test_restoration_failure_is_hard_hold_not_false_rollback_success(self):
        """If no healthy old listener can be recovered, report unconfirmed."""
        self._seed_reviewed_ready_journal()
        self.backend.new_post_fails = True
        self.backend.restore_fails = True
        with self.assertRaisesRegex(RuntimeError, "RECOVERY_UNCONFIRMED"):
            guard._switch_reviewed_private_route(**self.old)
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.route(3141), [])
        self.assertEqual(len(self.backend.route(3142)), 1)

    def test_invalid_identity_image_scope_and_routes_never_mutate(self):
        """Reject all incorrect immutable image, network and caller claims."""
        changes = (
            ("wrong next id", lambda s: s.old.update(next_id="f" * 64)),
            ("wrong image", lambda s: s.old.update(next_image=guard._IMAGE)),
            ("wrong slot", lambda s: s.old.update(next_slot="blue")),
            ("wrong digest", lambda s: s.old.update(
                next_image=guard._SUCCESSOR_REPOSITORY + "f" * 64,
            )),
            ("wrong scheme", lambda s: s.old.update(next_image="analytics:latest")),
            ("public 3142", lambda s: s.backend.rules[2]["spec"].update(parentIP="0.0.0.0")),
            ("unexpected 3333", lambda s: s.backend.rules[2]["spec"].update(parentPort=3333)),
            ("other child", lambda s: s.backend.rules[2]["spec"].update(childIP="172.20.0.8")),
            ("duplicate canary", lambda s: s.backend.rules.append(
                deepcopy(s.original_canary),
            )),
            ("wrong network", lambda s: s.backend.state["network"].update(Internal=False)),
            ("candidate unhealthy", lambda s: s.backend.state["green"]["State"]["Health"].update(
                Status="unhealthy",
            )),
            ("candidate published", lambda s: s.backend.state["green"]["HostConfig"].update(
                PortBindings={"3000/tcp": [{"HostIp":"0.0.0.0","HostPort":"3142"}]},
            )),
        )
        self._seed_reviewed_ready_journal()
        for reason, change in changes:
            with self.subTest(reason=reason):
                self.backend = SuccessorRoutes()
                self.old = {
                    "previous_slot": "blue", "previous_image": guard._IMAGE,
                    "previous_id": self.backend.state["blue"]["Id"],
                    "next_slot": "green",
                    "next_image": self.backend.state["green"]["Config"]["Image"],
                    "next_id": self.backend.state["green"]["Id"],
                    "journal": self.journal, "request_sha256": "c" * 64,
                }
                change(self)
                with patch.object(guard, "_api", side_effect=self.backend):
                    with self.assertRaises(Exception):
                        guard._switch_reviewed_private_route(**self.old)
                self.assertEqual(self.backend.changes, [])
                self.assertEqual(self.backend.rules[0], self.original_canary)

    def _prepared_recovery(self):
        """Persist exact intent as if the worker stopped mid-port change."""
        return self.journal.begin(
            request_sha256=self.old["request_sha256"],
            previous_slot=self.old["previous_slot"],
            previous_image=self.old["previous_image"],
            previous_container_id=self.old["previous_id"],
            previous_ip="172.20.0.3",
            next_slot=self.old["next_slot"],
            next_image=self.old["next_image"],
            next_container_id=self.old["next_id"],
            next_ip="172.20.0.4",
        )

    def _reconcile(self, **changes):
        """Reopen real journal, pass reviewed exact identities after restart."""
        reopened = AnalyticsRouteJournal(
            self._directory.name,
            expected_uid=os.getuid(), expected_gid=os.getgid(),
        )
        arguments = {key: value for key, value in self.old.items()
                     if key != "journal"}
        return guard._recover_reviewed_private_route(
            journal=reopened, **{**arguments, **changes},
        )

    def test_prepared_restart_with_unchanged_old_route_never_mutates(self):
        """A crash BEFORE DELETE is durably reconciled as restored."""
        self._prepared_recovery()
        self.assertEqual(self.journal.read()["phase"], "prepared")
        self.assertIsNone(self._reconcile())
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.changes, [])
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        self.assertEqual(self.backend.rules[0], self.original_canary)

    def test_prepared_restart_after_delete_restores_original_signed_image(self):
        """A crash BETWEEN DELETE and POST recovers previous healthy writer."""
        self._prepared_recovery()
        self.backend.rules = [
            rule for rule in self.backend.rules
            if rule["spec"].get("parentPort") != 3141
        ]
        self.assertIsNone(self._reconcile())
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual(self.backend.route(3141)[0]["spec"],
                         self.original_stable["spec"])
        self.assertEqual(self.backend.route(3142)[0]["id"], 4)

    def test_prepared_restart_after_new_route_posts_restores_old(self):
        """A crash AFTER new POST but BEFORE commit reverts the new route."""
        self._prepared_recovery()
        self.backend.rules[1]["spec"]["childIP"] = "172.20.0.4"
        self.assertIsNone(self._reconcile())
        self.assertEqual(self.journal.read()["phase"], "restored")
        self.assertEqual(self.backend.route(3141)[0]["spec"],
                         self.original_stable["spec"])
        self.assertEqual(self.backend.rules[0], self.original_canary)
        self.assertEqual([x[0] for x in self.backend.changes],
                         ["DELETE", "POST"])

    def test_prepared_restart_rejects_wrong_trust_and_changed_canary(self):
        """No caller-provided hash or public port may authorize recovery."""
        self._prepared_recovery()
        with self.assertRaises(Exception):
            self._reconcile(request_sha256="f" * 64)
        self.assertEqual(self.backend.changes, [])
        self.backend.rules[0]["spec"]["childPort"] = 3000
        with self.assertRaises(Exception):
            self._reconcile()
        self.assertEqual(self.backend.changes, [])
        self.assertEqual(self.journal.read()["phase"], "prepared")

    def test_unresolved_journal_refuses_second_cutover_before_any_api_write(self):
        """A previous uncertain route can never silently be promoted again."""
        self._prepared_recovery()
        with self.assertRaises(ValueError):
            guard._switch_reviewed_private_route(**self.old)
        self.assertEqual(self.backend.changes, [])
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        self.assertEqual(self.journal.read()["phase"], "prepared")

    def test_unwritable_or_foreign_journal_refuses_cutover_before_api_write(self):
        """RootlessKit is never touched when durable intent cannot be stored."""
        self._without_candidate_route()
        with patch(
            "deployment.analytics_route_journal.os.fsync",
            side_effect=OSError("synthetic storage failure"),
        ):
            with self.assertRaises(AnalyticsRouteJournalUnavailable):
                guard._stage_reviewed_private_candidate_probe(**self.old)
        self.assertEqual(self.backend.changes, [])
        self.assertEqual(self.backend.route(3141), [self.original_stable])
        self.assertFalse(
            (Path(self._directory.name) / "transaction.json").exists()
        )
        self.assertTrue(
            (Path(self._directory.name) / ".transaction.json.next").exists()
        )

    def test_only_privileged_approved_supervisor_may_request_swap(self):
        """Existing 0.15.0 guard mode cannot invoke the successor transition."""
        with patch.object(guard.os, "geteuid", return_value=1005):
            with self.assertRaises(ValueError):
                guard._switch_reviewed_private_route(**self.old)
        with patch.dict(os.environ, {guard._SUCCESSOR_SCOPE: ""}):
            with self.assertRaises(ValueError):
                guard._switch_reviewed_private_route(**self.old)
        self.assertEqual(self.backend.changes, [])


if __name__ == "__main__":
    unittest.main()
