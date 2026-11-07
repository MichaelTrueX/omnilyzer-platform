"""File: deployment/tests/test_analytics_active_state_review.py

Purpose: Verify independent private Analytics active-image/route snapshot
         using synthetic read-only Docker and RootlessKit API responses.
Related: deployment/analytics_active_state_review.py,
         deployment/tests/test_analytics_execution.py,
         platform PR278 analytics_loopback_guard.py.

Sections: exact blue/green identity, route-to-image binding, rejected
          counterfeit state/port rules, and no privileged/live API calls.
No Docker, RootlessKit, database or ingress changes in these tests.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from deployment.analytics_active_state_review import (
    _active_state, _json_bytes, inspect_analytics_active_state,
    AnalyticsActiveStateDenied, AnalyticsActiveState,
)


# Section 1: synthetic observed system state, not a trusted signed release.
DIGEST_BLUE = "sha256:" + "6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1"
DIGEST_GREEN = "sha256:" + "c" * 64
NET_ID = "0f150b2be3c52e7e1c69f0747f9bf1ea89e381f964e402b270f8f8ac67bdefa5"
PREFIX = "oci-dev.omnilyzer.ai/omnilyzer/analytics@"
NET = "omnilyzer-analytics-backend-dev"


def container(slot: str, ip: str, image: str) -> dict:
    """Make legacy blue or unpublished successor rootless observation."""
    historical_blue = slot == "blue" and image == PREFIX + DIGEST_BLUE
    binding = (
        {"3000/tcp": [{
            "HostIp": "127.0.0.1", "HostPort": "3141",
        }]} if historical_blue else {}
    )
    return {
        "Id": ("a" if slot == "blue" else "b") * 64,
        "Name": "/omnilyzer-analytics-dev-analytics-" + slot + "-1",
        "Image": "sha256:" + ("c" if slot == "blue" else "d") * 64,
        "Config": {"Image": image, "User": "10001:10001"},
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "HostConfig": {
            "ReadonlyRootfs": True, "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PortBindings": binding,
        },
        "NetworkSettings": {
            "Ports": {"3000/tcp": None},
            "Networks": {
                NET: {"NetworkID": NET_ID, "IPAddress": ip},
            },
        },
    }


def observed(*, active_slot: str = "blue") -> dict:
    """Build private slots and ingress; old published blue is stopped after cutover."""
    child_ip = "172.20.0.3" if active_slot == "blue" else "172.20.0.4"
    blue = container("blue", "172.20.0.3", PREFIX + DIGEST_BLUE)
    if active_slot == "green":
        blue["State"] = {"Running": False}
    return {
        "info": {
            "version": "3.1.0", "apiVersion": "1.1.2",
            "portDriver": {"driver": "builtin", "protos": ["tcp4"]},
            "networkDriver": {"driver": "slirp4netns"},
        },
        "network": {
            "Name": NET, "Id": NET_ID, "Driver": "bridge", "Internal": True,
        },
        "ports": [
            {"id": 2, "spec": {
                "proto": "tcp4", "parentIP": "127.0.0.1", "parentPort": 3020,
                "childIP": "127.0.0.1", "childPort": 3020,
            }},
            {"id": 3, "spec": {
                "proto": "tcp4", "parentIP": "127.0.0.1", "parentPort": 3141,
                "childIP": child_ip, "childPort": 3000,
            }},
        ],
        "blue": blue,
        "green": container("green", "172.20.0.4", PREFIX + DIGEST_GREEN),
    }


# Section 2: synthetic candidate staging on the already private network.
def staged(*, active_slot: str = "blue", candidate_digest: str | None = None) -> dict:
    """One temporary private 3142 route to the OTHER running Analytics slot."""
    raw = observed(active_slot=active_slot)
    slot = "green" if active_slot == "blue" else "blue"
    if candidate_digest is None:
        candidate_digest = DIGEST_GREEN if slot == "green" else "sha256:" + "e" * 64
    ip = "172.20.0.4" if slot == "green" else "172.20.0.3"
    raw[slot] = container(slot, ip, PREFIX + candidate_digest)
    raw["ports"].append({
        "id": 4,
        "spec": {
            "proto": "tcp4", "parentIP": "127.0.0.1",
            "parentPort": 3142, "childIP": ip, "childPort": 3000,
        },
    })
    return raw


# Section 3: actual read-only parser tests with observed Router-Docker equality.
class AnalyticsActiveStateReviewTests(unittest.TestCase):
    """Reject forged candidate state, stale routes, public exposure and drift."""

    def test_active_blue_and_green_derive_from_real_port_forward_not_ci(self):
        for slot in ("blue", "green"):
            with self.subTest(slot=slot):
                state = _active_state(**observed(active_slot=slot))
                self.assertIs(type(state), AnalyticsActiveState)
                self.assertEqual(state.active_slot, slot)
                self.assertEqual(state.active_digest,
                                 DIGEST_BLUE if slot == "blue" else DIGEST_GREEN)
                self.assertEqual(state.active_image, PREFIX + state.active_digest)
                self.assertEqual(state.private_ingress_port, 3141)
                self.assertEqual(state.candidate_slot,
                                 "green" if slot == "blue" else "blue")
                self.assertEqual(state.candidate_port, 3142)
                self.assertIs(state.read_only, True)
                self.assertIs(state.deployment_authorized, False)

    def test_successor_blue_no_published_port_and_original_green_cutover(self):
        """Stable ingress3141 is separate from either slot's future host ports."""
        state = observed()
        state["blue"] = container(
            "blue", "172.20.0.3", PREFIX + "sha256:" + "e" * 64,
        )
        actual = _active_state(**state)
        self.assertEqual(actual.active_slot, "blue")
        self.assertEqual(actual.candidate_port, 3142)
        self.assertEqual(state["blue"]["HostConfig"]["PortBindings"], {})

        forged = deepcopy(state)
        forged["blue"]["HostConfig"]["PortBindings"] = {
            "3000/tcp": [{
                "HostIp": "127.0.0.1", "HostPort": "3141",
            }],
        }
        with self.assertRaises(ValueError):
            _active_state(**forged)

        green = observed(active_slot="green")
        self.assertEqual(green["green"]["HostConfig"]["PortBindings"], {})
        self.assertEqual(_active_state(**green).candidate_slot, "blue")
        self.assertEqual(_active_state(**green).candidate_port, 3142)
        green["blue"]["State"] = {
            "Running": True, "Health": {"Status": "healthy"},
        }
        # Original DEV signed blue stays healthy as the rollback standby
        # even while the one actual RootlessKit 3141 rule selects green.
        # Docker did not publish the original declared HostPort on the
        # isolated internal network. Reject only actual duplicate routing.
        rollback_standby = _active_state(**green)
        self.assertEqual(rollback_standby.active_slot, "green")
        self.assertEqual(rollback_standby.active_digest, DIGEST_GREEN)
        self.assertEqual(rollback_standby.candidate_slot, "blue")
        green["blue"]["NetworkSettings"]["Networks"][NET]["IPAddress"] = "172.20.0.4"
        with self.assertRaises(ValueError):
            _active_state(**green)

    def test_private_candidate_probe_exact_blue_green_network_and_digest(self):
        """Three routes allowed ONLY for exact distinct healthy candidate 3142."""
        for slot, expected in (("blue", "green"), ("green", "blue")):
            with self.subTest(active=slot):
                fixture = staged(active_slot=slot)
                result = _active_state(**fixture)
                self.assertEqual(result.active_slot, slot)
                self.assertEqual(result.candidate_slot, expected)
                self.assertEqual(result.candidate_port, 3142)
                self.assertIs(result.candidate_probe_present, True)
                self.assertEqual(
                    result.candidate_digest,
                    DIGEST_GREEN if slot == "blue" else "sha256:" + "e" * 64,
                )
                self.assertEqual(
                    result.candidate_container_id,
                    fixture[expected]["Id"],
                )
                self.assertIs(result.deployment_authorized, False)

    def test_candidate_probe_rejects_public_wrong_image_route_and_extra_rules(self):
        """Never accept a third rule as an arbitrary RootlessKit exemption."""
        malformed = (
            ("public", lambda s: s["ports"][2]["spec"].update(parentIP="0.0.0.0")),
            ("other port", lambda s: s["ports"][2]["spec"].update(parentPort=3300)),
            ("wrong target port", lambda s: s["ports"][2]["spec"].update(childPort=3001)),
            ("wrong protocol", lambda s: s["ports"][2]["spec"].update(proto="tcp6")),
            ("other destination", lambda s: s["ports"][2]["spec"].update(childIP="172.20.0.8")),
            ("active destination", lambda s: s["ports"][2]["spec"].update(childIP="172.20.0.3")),
            ("duplicate id", lambda s: s["ports"][2].update(id=3)),
            ("unrecognized extra field", lambda s: s["ports"][2]["spec"].update(unknown=True)),
            ("duplicate 3142", lambda s: s["ports"].append({**s["ports"][2], "id": 5})),
            ("changed canary", lambda s: s["ports"][0]["spec"].update(childPort=1)),
            ("duplicate child ip", lambda s: s["green"]["NetworkSettings"]["Networks"][NET].update(IPAddress="172.20.0.3")),
            ("stopped candidate", lambda s: s["green"]["State"].update(Running=False)),
            ("unhealthy candidate", lambda s: s["green"]["State"]["Health"].update(Status="unhealthy")),
            ("unapproved digest", lambda s: s["green"]["Config"].update(Image="analytics:latest")),
            ("same digest", lambda s: s["green"]["Config"].update(Image=PREFIX + DIGEST_BLUE)),
            ("published candidate port", lambda s: s["green"]["HostConfig"].update(PortBindings={
                "3000/tcp": [{"HostIp":"127.0.0.1","HostPort":"3142"}],
            })),
        )
        for reason, change in malformed:
            with self.subTest(reason=reason):
                fixture = staged()
                change(fixture)
                with self.assertRaises(Exception):
                    _active_state(**fixture)

    def test_reviewed_compose_override_removes_only_successor_host_ports(self):
        """Real Compose v5 parse, no Docker daemon, socket or container usage."""
        if shutil.which("docker") is None:
            self.skipTest("Docker Compose binary unavailable")
        root = Path(__file__).resolve().parents[2]
        base = root / "deployment/runtime/dev/analytics.compose.review.yaml"
        overlay = root / "deployment/runtime/dev/analytics.compose.successor-ports.yaml"
        images = {
            **os.environ,
            "ANALYTICS_BLUE_IMAGE": PREFIX + DIGEST_BLUE,
            "ANALYTICS_GREEN_IMAGE": PREFIX + DIGEST_GREEN,
        }

        def render(with_overlay: bool) -> dict:
            args = ["docker", "compose", "-f", str(base)]
            if with_overlay:
                args += ["-f", str(overlay)]
            args += ["--profile", "blue", "--profile", "green",
                     "config", "--format", "json"]
            result = subprocess.run(
                args, capture_output=True, text=True, env=images,
                check=False, timeout=15,
            )
            if result.returncode:
                self.fail("reviewed Compose config unavailable: "
                          + result.stderr[:200])
            return json.loads(result.stdout)

        original = render(False)["services"]
        future = render(True)["services"]
        self.assertEqual(
            {s for s in original}, {"analytics-blue", "analytics-green"},
        )
        self.assertTrue(original["analytics-blue"]["ports"])
        self.assertTrue(original["analytics-green"]["ports"])
        for slot in ("analytics-blue", "analytics-green"):
            self.assertFalse(future[slot].get("ports"))
            self.assertTrue(future[slot]["read_only"])
            self.assertEqual(future[slot]["user"], "10001:10001")
            self.assertEqual(future[slot]["cap_drop"], ["ALL"])
            self.assertEqual(
                future[slot]["networks"], original[slot]["networks"],
            )
            self.assertEqual(
                future[slot]["secrets"], original[slot]["secrets"],
            )
            self.assertEqual(
                future[slot]["image"], original[slot]["image"],
            )

    def test_staged_candidate_verifies_both_local_images_and_private_health(self):
        """A ready green OCI must be real before any later route cutover."""
        fixture = staged()
        blue_image = {
            "Id": fixture["blue"]["Image"], "RepoDigests": [PREFIX + DIGEST_BLUE],
            "Os": "linux", "Architecture": "amd64",
        }
        green_image = {
            "Id": fixture["green"]["Image"], "RepoDigests": [PREFIX + DIGEST_GREEN],
            "Os": "linux", "Architecture": "amd64",
        }
        response = [
            fixture["info"], fixture["ports"], fixture["network"],
            fixture["blue"], fixture["green"], blue_image, green_image,
            fixture["ports"],
        ]
        for case in ("success", "wrong candidate OCI", "unhealthy", "routing drift"):
            with self.subTest(case=case):
                reads = deepcopy(response)
                if case == "wrong candidate OCI":
                    reads[6]["RepoDigests"] = [PREFIX + DIGEST_BLUE]
                if case == "routing drift":
                    reads[-1][2]["spec"]["childIP"] = "172.20.0.8"
                with (
                    patch(
                        "deployment.analytics_active_state_review.os.geteuid",
                        return_value=991,
                    ),
                    patch(
                        "deployment.analytics_active_state_review._unix_get",
                        side_effect=reads,
                    ) as reader,
                    patch(
                        "deployment.analytics_active_state_review._candidate_health",
                        side_effect=(
                            RuntimeError("unhealthy")
                            if case == "unhealthy" else None
                        ),
                    ) as health,
                ):
                    if case == "success":
                        actual = inspect_analytics_active_state()
                        self.assertEqual(actual.candidate_digest, DIGEST_GREEN)
                        self.assertIs(actual.candidate_probe_present, True)
                        health.assert_called_once_with()
                        self.assertEqual(reader.call_count, 8)
                    else:
                        with self.assertRaises(AnalyticsActiveStateDenied):
                            inspect_analytics_active_state()

    def test_candidate_health_is_loopback_only_and_requires_200(self):
        """No redirect, credential forwarding or public target allowed."""
        from deployment.analytics_active_state_review import _candidate_health
        class Response:
            def __init__(self, status):
                self.status = status
            def read(self, limit):
                assert limit == 2049
                return b"ok"
        class PrivateConnection:
            calls: list[tuple] = []
            statuses = [200, 200]
            def __init__(self, host, port, timeout):
                assert (host, port, timeout) == ("127.0.0.1", 3142, 3)
            def request(self, method, path, headers):
                self.calls.append((method, path, headers))
            def getresponse(self):
                return Response(self.statuses[len(self.calls) - 1])
            def close(self):
                pass
        with patch(
            "deployment.analytics_active_state_review.http.client.HTTPConnection",
            PrivateConnection,
        ):
            _candidate_health()
            self.assertEqual(
                [(x[0], x[1]) for x in PrivateConnection.calls],
                [("GET", "/readyz"), ("GET", "/livez")],
            )
            self.assertTrue(all(
                "Authorization" not in call[2] for call in PrivateConnection.calls
            ))
            PrivateConnection.calls.clear()
            PrivateConnection.statuses = [302, 200]
            with self.assertRaises(ValueError):
                _candidate_health()
            self.assertEqual(len(PrivateConnection.calls), 1)

    def test_pre_pull_requires_true_absence_of_green_container(self):
        """A stopped/unrouted green cannot be silently adopted on first pull."""
        from deployment import analytics_active_state_review as source
        from unittest.mock import call

        target = "/containers/omnilyzer-analytics-dev-analytics-green-1/json"
        with (
            patch.object(source.os, "geteuid", return_value=991),
            patch.object(source, "_unix_get", return_value=None) as read,
        ):
            self.assertIsNone(source.verify_empty_analytics_successor_slot())
        read.assert_called_once_with(source._DOCKER, target)
        for existing in (container("green", "172.20.0.4", PREFIX + DIGEST_GREEN),
                         {"State": {"Running": False}}):
            with (
                patch.object(source.os, "geteuid", return_value=991),
                patch.object(source, "_unix_get", return_value=existing),
                self.assertRaises(AnalyticsActiveStateDenied),
            ):
                source.verify_empty_analytics_successor_slot()
        for actor in (0, 1000):
            with (
                patch.object(source.os, "geteuid", return_value=actor),
                patch.object(source, "_unix_get") as read,
                self.assertRaises(AnalyticsActiveStateDenied),
            ):
                source.verify_empty_analytics_successor_slot()
            read.assert_not_called()
        with (
            patch.object(source.os, "geteuid", return_value=991),
            patch.object(source, "_unix_get", side_effect=OSError("no docker socket")),
            self.assertRaises(AnalyticsActiveStateDenied),
        ):
            source.verify_empty_analytics_successor_slot()

    def test_absent_or_stopped_candidate_still_allows_verified_active_image(self):
        for candidate in (None, {
            **container("green", "172.20.0.4", PREFIX + DIGEST_GREEN),
            "State": {"Running": False},
        }):
            with self.subTest(candidate=candidate is None):
                state = observed()
                state["green"] = candidate
                self.assertEqual(_active_state(**state).active_slot, "blue")

    def test_all_invalid_route_network_image_and_hardening_are_denied(self):
        modifications = (
            ("no canary", lambda x: x["ports"].pop(0)),
            ("no Analytics route", lambda x: x["ports"].pop()),
            ("extra public route", lambda x: x["ports"].append({
                "id": 8, "spec": dict(x["ports"][1]["spec"]),
            })),
            ("duplicate port id", lambda x: x["ports"][1].update(id=2)),
            ("wrong route ip", lambda x: x["ports"][1]["spec"].update(childIP="172.20.0.9")),
            ("public parent", lambda x: x["ports"][1]["spec"].update(parentIP="0.0.0.0")),
            ("public port", lambda x: x["ports"][1]["spec"].update(parentPort=80)),
            ("candidate port", lambda x: x["ports"][1]["spec"].update(parentPort=3142)),
            ("wrong proto", lambda x: x["ports"][1]["spec"].update(proto="tcp6")),
            ("wrong child port", lambda x: x["ports"][1]["spec"].update(childPort=80)),
            ("unexpected rule member", lambda x: x["ports"][1]["spec"].update(extra="x")),
            ("stopped active", lambda x: x["blue"]["State"].update(Running=False)),
            ("unhealthy active", lambda x: x["blue"]["State"]["Health"].update(Status="starting")),
            ("altered image", lambda x: x["blue"]["Config"].update(Image=PREFIX + "sha256:" + "0" * 64)),
            ("mutable tag", lambda x: x["blue"]["Config"].update(Image="analytics:latest")),
            ("different user", lambda x: x["blue"]["Config"].update(User="0:0")),
            ("writable rootfs", lambda x: x["blue"]["HostConfig"].update(ReadonlyRootfs=False)),
            ("privileged", lambda x: x["blue"]["HostConfig"].update(Privileged=True)),
            ("caps enabled", lambda x: x["blue"]["HostConfig"].update(CapDrop=[])),
            ("security opt removed", lambda x: x["blue"]["HostConfig"].update(SecurityOpt=[])),
            ("external port", lambda x: x["blue"]["HostConfig"]["PortBindings"]["3000/tcp"][0].update(HostIp="0.0.0.0")),
            ("wrong Docker name", lambda x: x["blue"].update(Name="/other")),
            ("wrong Docker ID", lambda x: x["blue"].update(Id="bad")),
            ("other network", lambda x: x["blue"]["NetworkSettings"]["Networks"].update(other={})),
            ("wrong network id", lambda x: x["blue"]["NetworkSettings"]["Networks"][NET].update(NetworkID="b" * 64)),
            ("public network", lambda x: x["network"].update(Internal=False)),
            ("network driver", lambda x: x["network"].update(Driver="host")),
            ("wrong rootless driver", lambda x: x["info"]["networkDriver"].update(driver="vpnkit")),
            ("unknown rootless API", lambda x: x["info"].update(apiVersion="1.2.0")),
            ("duplicated IP", lambda x: x["green"]["NetworkSettings"]["Networks"][NET].update(IPAddress="172.20.0.3")),
        )
        for name, edit in modifications:
            with self.subTest(name=name), self.assertRaises(Exception):
                state = deepcopy(observed())
                edit(state)
                _active_state(**state)

    def test_reject_duplicate_nonfinite_or_oversize_api_json(self):
        for raw in (
            b'{"id":1,"id":2}', b'{"active":NaN}', b'{"x":Infinity}',
            b"not-json", b"{}", b" " * 262145,
        ):
            with self.subTest(raw=raw[:25]):
                if raw == b"{}":
                    self.assertEqual(_json_bytes(raw), {})
                else:
                    with self.assertRaises(Exception):
                        _json_bytes(raw)

    def test_live_inspection_restricts_broker_and_checks_route_changes(self):
        with patch("deployment.analytics_active_state_review.os.geteuid", return_value=990), patch(
            "deployment.analytics_active_state_review._unix_get"
        ) as reader:
            with self.assertRaises(AnalyticsActiveStateDenied):
                inspect_analytics_active_state()
            reader.assert_not_called()
        fixture = observed()
        local_image = {
            "Id": fixture["blue"]["Image"],
            "RepoDigests": [PREFIX + DIGEST_BLUE],
            "Os": "linux", "Architecture": "amd64",
        }
        sequence = [
            fixture["info"], fixture["ports"], fixture["network"],
            fixture["blue"], fixture["green"], local_image, fixture["ports"],
        ]
        with patch("deployment.analytics_active_state_review.os.geteuid", return_value=991), patch(
            "deployment.analytics_active_state_review._unix_get", side_effect=sequence,
        ) as reader:
            state = inspect_analytics_active_state()
            self.assertEqual(state.active_slot, "blue")
            self.assertEqual(reader.call_count, 7)
            self.assertEqual(
                [call.args[1] for call in reader.call_args_list],
                ["/v1/info", "/v1/ports", "/networks/" + NET,
                 "/containers/omnilyzer-analytics-dev-analytics-blue-1/json",
                 "/containers/omnilyzer-analytics-dev-analytics-green-1/json",
                 "/images/" + fixture["blue"]["Image"] + "/json",
                 "/v1/ports"],
            )
        changed = deepcopy(fixture["ports"])
        changed[1]["spec"]["childIP"] = "172.20.0.4"
        with patch("deployment.analytics_active_state_review.os.geteuid", return_value=0), patch(
            "deployment.analytics_active_state_review._unix_get",
            side_effect=sequence[:-1] + [changed],
        ):
            with self.assertRaises(AnalyticsActiveStateDenied):
                inspect_analytics_active_state()

        # A container's requested image string is NOT enough. The local
        # Docker image identity and immutable RepoDigests must also match.
        for case in (
            {"RepoDigests": [PREFIX + DIGEST_GREEN]},
            {"RepoDigests": []},
            {"Id": "sha256:" + "f" * 64},
            {"Os": "windows"},
            {"Architecture": "arm64"},
        ):
            with self.subTest(image=case), patch(
                "deployment.analytics_active_state_review.os.geteuid", return_value=0,
            ), patch(
                "deployment.analytics_active_state_review._unix_get",
                side_effect=sequence[:5] + [{**local_image, **case}],
            ), self.assertRaises(AnalyticsActiveStateDenied):
                inspect_analytics_active_state()
        invalid_container = deepcopy(fixture["blue"])
        invalid_container.pop("Image")
        with patch(
            "deployment.analytics_active_state_review.os.geteuid", return_value=0,
        ), patch(
            "deployment.analytics_active_state_review._unix_get",
            side_effect=sequence[:3] + [invalid_container, fixture["green"]],
        ), self.assertRaises(AnalyticsActiveStateDenied):
            inspect_analytics_active_state()


# Section 3: integrate live measured active release with immutable signed
# previous-release evidence and the already closed successor request parser.
class AnalyticsLiveSuccessorRequestTests(unittest.TestCase):
    """No GitHub-provided previous image or slot can override live routing."""

    def _candidate(self):
        from dataclasses import replace
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        from deployment.analytics_signed_release_consumer import PINNED_IMAGE, PINNED_DIGEST
        from deployment.policy import canonical_bytes
        data, context = AnalyticsSuccessorRequestTests().candidate()
        previous = replace(
            context["signed_release"], release_version="0.15.0",
            image=PINNED_IMAGE,
            source=replace(
                context["signed_release"].source,
                oci_manifest_digest=PINNED_DIGEST,
            ),
        )
        return canonical_bytes(data), context, previous

    def test_observed_root_image_must_match_previous_signed_release(self):
        from dataclasses import replace
        from deployment.analytics_execution import (
            review_analytics_successor_with_live_active, AnalyticsRequestError,
        )
        from deployment.policy import canonical_bytes
        raw, context, prev = self._candidate()
        live = _active_state(**observed())
        kwargs = {
            key: value for key, value in context.items()
            if key not in ("observed_active_digest", "observed_active_slot")
        }
        with patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=live,
        ) as inspect:
            result = review_analytics_successor_with_live_active(
                raw, signed_previous=prev, **kwargs,
            )
            inspect.assert_called_once_with()
            self.assertEqual(result.rollback_reference["previous_slot"], "blue")
            self.assertEqual(result.rollback_reference["previous_digest"],
                             live.active_digest)

        bad_previous = (
            replace(prev, image="oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:" + "f" * 64),
            replace(prev, release_version="0.15.2"),
            replace(prev, deployment_authorized=True),
            replace(prev, source=replace(prev.source, oci_manifest_digest="sha256:" + "d" * 64)),
            replace(prev, source=replace(prev.source, release_authorized=True)),
        )
        for item in bad_previous:
            with self.subTest(previous=item), patch(
                "deployment.analytics_active_state_review.inspect_analytics_active_state",
                return_value=live,
            ), self.assertRaises(AnalyticsRequestError):
                review_analytics_successor_with_live_active(
                    raw, signed_previous=item, **kwargs,
                )

        tampered = json.loads(raw)
        tampered["rollback_reference"]["previous_digest"] = "sha256:" + "f" * 64
        with patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=live,
        ), self.assertRaises(AnalyticsRequestError):
            review_analytics_successor_with_live_active(
                canonical_bytes(tampered), signed_previous=prev, **kwargs,
            )

    def test_repeated_green_to_blue_reads_same_stable_3141_and_candidate_3142(self):
        """After a future signed release, both routing slots stay reusable."""
        from dataclasses import replace
        from deployment.analytics_ci_request import build_analytics_successor_ci_request
        from deployment.analytics_execution import review_analytics_successor_with_live_active
        from deployment.tests.test_analytics_ci_request import (
            AnalyticsSuccessorCIRequestTests, token,
        )
        _data, context, env = AnalyticsSuccessorCIRequestTests().candidate()
        env["ANALYTICS_ACTIVE_SLOT"] = "green"
        env["ANALYTICS_ACTIVE_DIGEST"] = DIGEST_GREEN
        raw = build_analytics_successor_ci_request(
            deployment_oidc_token=token(), environment=env,
        )
        live = _active_state(**observed(active_slot="green"))
        previous = replace(
            context["signed_release"],
            release_version="0.15.0",
            image=PREFIX + DIGEST_GREEN,
            source=replace(
                context["signed_release"].source,
                oci_manifest_digest=DIGEST_GREEN,
            ),
        )
        context = {
            key: value for key, value in context.items()
            if key not in ("observed_active_digest", "observed_active_slot")
        }
        with patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=live,
        ):
            checked = review_analytics_successor_with_live_active(
                raw, signed_previous=previous, **context,
            )
        self.assertEqual(checked.ingress_reference["slot"], "blue")
        self.assertEqual(checked.ingress_reference["loopback_port"], 3142)
        self.assertEqual(checked.ingress_reference["active_slot"], "green")
        self.assertEqual(checked.rollback_reference["previous_slot"], "green")
        self.assertEqual(checked.rollback_reference["previous_digest"], DIGEST_GREEN)

    def test_signed_successor_requires_exact_live_staged_candidate(self):
        """Executor may require a healthy 3142 OCI before later cutover."""
        from dataclasses import replace
        from deployment.analytics_execution import (
            review_analytics_successor_with_live_active, AnalyticsRequestError,
        )
        raw, context, previous = self._candidate()
        expected = context["signed_release"].source.oci_manifest_digest
        kwargs = {
            key: value for key, value in context.items()
            if key not in ("observed_active_digest", "observed_active_slot")
        }
        ready = _active_state(**staged(candidate_digest=expected))
        with patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=ready,
        ):
            checked = review_analytics_successor_with_live_active(
                raw, signed_previous=previous,
                require_staged_candidate=True, **kwargs,
            )
            self.assertEqual(checked.exact_image_reference, PREFIX + expected)
            self.assertEqual(checked.rollback_reference["previous_digest"], DIGEST_BLUE)
        for case in (
            _active_state(**observed()),                    # no 3142 candidate
            _active_state(**staged(candidate_digest=DIGEST_GREEN)), # wrong image
            replace(ready, candidate_container_id=None),   # no container identity
            replace(ready, candidate_probe_present=False), # client-supplied fake
        ):
            with self.subTest(case=case), patch(
                "deployment.analytics_active_state_review.inspect_analytics_active_state",
                return_value=case,
            ), self.assertRaises(AnalyticsRequestError):
                review_analytics_successor_with_live_active(
                    raw, signed_previous=previous,
                    require_staged_candidate=True, **kwargs,
                )
        with patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=ready,
        ), self.assertRaises(AnalyticsRequestError):
            review_analytics_successor_with_live_active(
                raw, signed_previous=previous,
                require_staged_candidate="yes", **kwargs,
            )

    def test_missing_or_counterfeit_live_state_never_authorizes_request(self):
        from dataclasses import replace
        from deployment.analytics_execution import (
            review_analytics_successor_with_live_active, AnalyticsRequestError,
        )
        raw, context, prev = self._candidate()
        kwargs = {
            key: value for key, value in context.items()
            if key not in ("observed_active_digest", "observed_active_slot")
        }
        live = _active_state(**observed())
        for result in (
            None,
            replace(live, deployment_authorized=True),
            replace(live, read_only=False),
            replace(live, active_slot="invalid"),
            replace(live, active_digest="sha256:" + "a" * 64),
            replace(live, candidate_slot="blue"),
            replace(live, private_ingress_port=3020),
            replace(live, candidate_port=3020),
        ):
            with self.subTest(result=result), patch(
                "deployment.analytics_active_state_review.inspect_analytics_active_state",
                return_value=result,
            ), self.assertRaises(AnalyticsRequestError):
                review_analytics_successor_with_live_active(
                    raw, signed_previous=prev, **kwargs,
                )

    def test_rootless_unix_reads_reject_other_sockets_and_unsafe_metadata(self):
        import stat
        from types import SimpleNamespace
        from deployment.analytics_active_state_review import _unix_get
        sock = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=991)
        with patch(
            "deployment.analytics_active_state_review.os.stat",
            return_value=sock,
        ), patch(
            "deployment.analytics_active_state_review._UnixConnection",
        ) as conn:
            with self.assertRaises(ValueError):
                _unix_get("/tmp/injected.sock", "/v1/ports")
            conn.assert_not_called()
        for uid, mode in ((0, stat.S_IFSOCK | 0o660),
                          (991, stat.S_IFREG | 0o660),
                          (991, stat.S_IFSOCK | 0o666)):
            with self.subTest(uid=uid, mode=mode), patch(
                "deployment.analytics_active_state_review.os.stat",
                return_value=SimpleNamespace(st_mode=mode, st_uid=uid),
            ), patch(
                "deployment.analytics_active_state_review._UnixConnection",
            ) as conn:
                with self.assertRaises(ValueError):
                    _unix_get("/run/user/991/dockerd-rootless/api.sock", "/v1/ports")
                conn.assert_not_called()


# Section 6: restarted committed route must match real journal and the
# independently reviewed release expectation. Only isolated filesystem I/O.
class AnalyticsCommittedRouteRestartTests(unittest.TestCase):
    """A journal is never an unsigned grant to reattach a mutable image."""

    def setUp(self):
        """Create a real strict UID-owned journal in an isolated test dir."""
        import tempfile
        from deployment.analytics_route_journal import AnalyticsRouteJournal
        self.temp = tempfile.TemporaryDirectory(prefix="route-restart-")
        self.addCleanup(self.temp.cleanup)
        self.journal = AnalyticsRouteJournal(
            self.temp.name,
            expected_uid=os.getuid(), expected_gid=os.getgid(),
        )
        self.patches = (
            patch(
                "deployment.analytics_route_journal.ROUTE_JOURNAL_DIRECTORY",
                self.temp.name,
            ),
            patch(
                "deployment.analytics_active_state_review.ROUTE_JOURNAL_DIRECTORY",
                self.temp.name, create=True,
            ),
            patch(
                "deployment.analytics_active_state_review.os.geteuid",
                return_value=991,
            ),
        )
        for scope in self.patches:
            scope.start()
            self.addCleanup(scope.stop)

    def _record(self, phase):
        """Persist one synthetic but correctly framed blue-to-green release."""
        record = self.journal.begin(
            request_sha256="f" * 64, previous_slot="blue",
            previous_image=PREFIX + DIGEST_BLUE,
            previous_container_id="a" * 64, previous_ip="172.20.0.3",
            next_slot="green", next_image=PREFIX + DIGEST_GREEN,
            next_container_id="b" * 64, next_ip="172.20.0.4",
        )
        if phase == "switched":
            # A committed route is impossible without a previously fsynced
            # candidate_ready stage. Preserve the runtime's closed sequence
            # in this independently verified restart fixture.
            ready = self.journal.finish(record, phase="candidate_ready")
            return self.journal.finish(ready, phase="switched")
        if phase == "restored":
            return self.journal.finish(record, phase="restored")
        return record

    def _review(self, *, phase="switched", **changes):
        """Expect caller-owned signed identities, never journal-derived trust."""
        image = (PREFIX + DIGEST_GREEN
                 if phase == "switched" else PREFIX + DIGEST_BLUE)
        expected = {
            "journal": self.journal,
            "reviewed_image": image,
            "reviewed_slot": "green" if phase == "switched" else "blue",
            "reviewed_container_id": (
                "b" * 64 if phase == "switched" else "a" * 64
            ),
            "reviewed_request_sha256": "f" * 64,
        }
        expected.update(changes)
        return expected

    def test_signed_expectation_matches_durable_committed_green_after_restart(self):
        """Completed next route may be supervised only after real OCI match."""
        from deployment.analytics_active_state_review import (
            inspect_committed_analytics_route,
        )
        record = self._record("switched")
        live = _active_state(**observed(active_slot="green"))
        self.assertEqual(live.active_child_ip, "172.20.0.4")
        with patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=live,
        ) as inspector:
            active = inspect_committed_analytics_route(**self._review())
        self.assertEqual(active.active_image, record["next_image"])
        self.assertIs(active.deployment_authorized, False)
        inspector.assert_called_once_with()
        self.assertEqual(self.journal.read(), record)

    def test_restored_old_signed_writer_is_valid_separate_completed_phase(self):
        """A completed rollback is not mistaken for a successful successor."""
        from deployment.analytics_active_state_review import (
            inspect_committed_analytics_route,
        )
        self._record("restored")
        live = _active_state(**observed(active_slot="blue"))
        with patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=live,
        ):
            active = inspect_committed_analytics_route(
                **self._review(phase="restored"),
            )
        self.assertEqual(active.active_slot, "blue")
        self.assertEqual(active.active_digest, DIGEST_BLUE)

    def test_interrupted_prepared_never_rejoins_normal_supervision(self):
        """Interrupted 3141 switch must use explicit verified recovery path."""
        from deployment.analytics_active_state_review import (
            inspect_committed_analytics_route, AnalyticsActiveStateDenied,
        )
        self._record("prepared")
        with patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
        ) as inspector, self.assertRaises(AnalyticsActiveStateDenied):
            inspect_committed_analytics_route(**self._review())
        inspector.assert_not_called()

    def test_restart_refuses_wrong_release_receipt_identity_and_drifted_host(self):
        """No wrong OCI, rollback JTI, container, IP or route is accepted."""
        from dataclasses import replace
        from deployment.analytics_active_state_review import (
            inspect_committed_analytics_route, AnalyticsActiveStateDenied,
        )
        self._record("switched")
        live = _active_state(**observed(active_slot="green"))
        for change in (
            {"reviewed_image": PREFIX + DIGEST_BLUE},
            {"reviewed_image": "analytics:latest"},
            {"reviewed_request_sha256": "e" * 64},
            {"reviewed_slot": "blue"},
            {"reviewed_container_id": "a" * 64},
        ):
            with self.subTest(input=change), patch(
                "deployment.analytics_active_state_review.inspect_analytics_active_state",
            ) as inspector, self.assertRaises(AnalyticsActiveStateDenied):
                inspect_committed_analytics_route(
                    **self._review(**change),
                )
            inspector.assert_not_called()
        for observed_result in (
            None,
            replace(live, active_child_ip="172.20.0.3"),
            replace(live, active_digest=DIGEST_BLUE,
                    active_image=PREFIX + DIGEST_BLUE),
            replace(live, active_container_id="a" * 64),
            replace(live, private_ingress_port=3020),
            replace(live, deployment_authorized=True),
            replace(live, read_only=False),
        ):
            with self.subTest(live=observed_result), patch(
                "deployment.analytics_active_state_review.inspect_analytics_active_state",
                return_value=observed_result,
            ), self.assertRaises(AnalyticsActiveStateDenied):
                inspect_committed_analytics_route(**self._review())

    def test_wrong_principal_missing_journal_or_concurrent_writer_denied(self):
        """No bootstrap from empty state and no concurrent route admission."""
        from deployment.analytics_active_state_review import (
            inspect_committed_analytics_route, AnalyticsActiveStateDenied,
        )
        with self.assertRaises(AnalyticsActiveStateDenied):
            inspect_committed_analytics_route(**self._review())
        self._record("switched")
        with patch(
            "deployment.analytics_active_state_review.os.geteuid",
            return_value=990,
        ), self.assertRaises(AnalyticsActiveStateDenied):
            inspect_committed_analytics_route(**self._review())
        with self.journal.exclusive():
            with self.assertRaises(AnalyticsActiveStateDenied):
                inspect_committed_analytics_route(**self._review())


if __name__ == "__main__":
    unittest.main()
