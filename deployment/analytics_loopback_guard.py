#!/usr/bin/env python3
"""File: deployment/analytics_loopback_guard.py

Purpose: Supervise one DEV-only RootlessKit loopback port for the already signed
         Analytics 0.15.0 blue container, without changing its isolated network.
Related: deployment/analytics_first_install.py,
         deployment/runtime/dev/analytics.compose.review.yaml,
         deployment/systemd/rootless/omnilyzer-analytics-loopback.service,
         deployment/tests/test_analytics_loopback_guard.py,
         docs/operations/task014-analytics-loopback-20261031.md.

Security: This is an optional, separately approved owner-installed DEV service,
not a Task013/014 authorization or a change to the signed executor. It runs only
as the existing rootless Docker UID991. It accesses only the existing Docker and
RootlessKit Unix sockets, never a registry credential, database or external host.
The root-owned systemd environment pins the exact approved 64-character Docker
container ID. Changes/recreation are denied until independently reviewed.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import signal
import socket
import sys
import time

# Section 1: Closed DEV-only release identity and original backend network.
_UID = 991
_CONTAINER = "omnilyzer-analytics-dev-analytics-blue-1"
_IMAGE = (
    "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
    "6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1"
)
_NETWORK = "omnilyzer-analytics-backend-dev"
_NETWORK_ID = "0f150b2be3c52e7e1c69f0747f9bf1ea89e381f964e402b270f8f8ac67bdefa5"
_DOCKER = "/run/user/991/docker.sock"
_ROOTLESS = "/run/user/991/dockerd-rootless/api.sock"
_CANARY = {"proto": "tcp4", "parentIP": "127.0.0.1", "parentPort": 3020,
           "childIP": "127.0.0.1", "childPort": 3020}
_TARGET = {"proto": "tcp4", "parentIP": "127.0.0.1", "parentPort": 3141,
           "childIP": "172.20.0.3", "childPort": 3000}
_HTTP_MAX = 262144
_CHECK_INTERVAL = 2.0
_HEALTH_EVERY = 10.0
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


# Section 2: Fixed, bounded, socket-only JSON API; never log response bodies.
class _UnixHTTP(http.client.HTTPConnection):
    """Use exactly one local Unix socket, never DNS/TCP to reach Docker APIs."""

    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=4)
        self.path = path

    def connect(self) -> None:
        """Connect to a local UDS with a strict 4-second timeout."""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(4)
        self.sock.connect(self.path)


def _decode_json(raw: bytes) -> object:
    """Reject oversized, ambiguous, malformed and nonfinite API replies."""
    if not 0 < len(raw) <= _HTTP_MAX:
        raise ValueError("API response size invalid")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Reject duplicate members rather than accepting the final value."""
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate API member")
            result[key] = item
        return result

    def invalid_constant(_constant: str) -> None:
        """Disallow non-JSON NaN/Infinity values in authoritative metadata."""
        raise ValueError("nonfinite API member")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=invalid_constant)


def _api(path: str, method: str, resource: str,
         body: dict[str, object] | None = None, status: int = 200) -> object:
    """Make only a fixed API request through an approved existing Unix socket."""
    if ((path, method) not in ((_DOCKER, "GET"), (_ROOTLESS, "GET"),
                              (_ROOTLESS, "POST"), (_ROOTLESS, "DELETE"))
            or not resource.startswith("/") or "?" in resource):
        raise ValueError("unapproved API operation")
    connection = _UnixHTTP(path)
    payload = (None if body is None else
               json.dumps(body, separators=(",", ":"), sort_keys=True).encode("ascii"))
    try:
        connection.request(method, resource, body=payload,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(_HTTP_MAX + 1)
        if response.status != status:
            raise RuntimeError("unexpected Unix API response status")
        if method == "DELETE":
            return None
        return _decode_json(raw)
    finally:
        connection.close()


# Section 3: Immutable container, network, image and rootless identity checks.
def _identity() -> str:
    """Require existing rootless owner and the root-pinned exact Docker ID."""
    identifier = os.environ.get("ANALYTICS_APPROVED_CONTAINER_ID", "")
    if os.geteuid() != _UID or _HEX64.fullmatch(identifier) is None:
        raise ValueError("unapproved rootless or container identity")
    return identifier


def _rootless_info() -> None:
    """Verify same running RootlessKit API and the builtin TCP4 port driver."""
    info = _api(_ROOTLESS, "GET", "/v1/info")
    if (type(info) is not dict or info.get("version") != "3.1.0"
            or info.get("apiVersion") != "1.1.2"
            or type(info.get("portDriver")) is not dict
            or info["portDriver"].get("driver") != "builtin"
            or "tcp4" not in info["portDriver"].get("protos", [])
            or type(info.get("networkDriver")) is not dict
            or info["networkDriver"].get("driver") != "slirp4netns"):
        raise ValueError("RootlessKit authority changed")


def _container_state(approved_id: str) -> None:
    """Reject changed/recreated containers, weakened runtime or network."""
    item = _api(_DOCKER, "GET", "/containers/" + _CONTAINER + "/json")
    network = _api(_DOCKER, "GET", "/networks/" + _NETWORK)
    if type(item) is not dict or type(network) is not dict:
        raise ValueError("Docker inspection invalid")
    config, host, state, network_settings = (
        item.get("Config"), item.get("HostConfig"), item.get("State"),
        item.get("NetworkSettings"),
    )
    if not all(type(x) is dict for x in (config, host, state, network_settings)):
        raise ValueError("Docker container metadata invalid")
    health = state.get("Health")
    ports = host.get("PortBindings")
    if (item.get("Name") != "/" + _CONTAINER
            or item.get("Id") != approved_id
            or config.get("Image") != _IMAGE
            or config.get("User") != "10001:10001"
            or state.get("Running") is not True
            or type(health) is not dict or health.get("Status") != "healthy"
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or host.get("CapDrop") != ["ALL"]
            or host.get("SecurityOpt") != ["no-new-privileges:true"]
            or ports != {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3141"}]}
            or network_settings.get("Ports") != {"3000/tcp": None}):
        raise ValueError("immutable Analytics container mismatch")
    nets = network_settings.get("Networks")
    if type(nets) is not dict or set(nets) != {_NETWORK}:
        raise ValueError("unexpected Analytics network attachment")
    props = nets[_NETWORK]
    if (type(props) is not dict or props.get("IPAddress") != _TARGET["childIP"]
            or props.get("NetworkID") != _NETWORK_ID
            or props.get("Gateway") not in (None, "")):
        raise ValueError("Analytics network endpoint changed")
    if (network.get("Name") != _NETWORK or network.get("Id") != _NETWORK_ID
            or network.get("Driver") != "bridge"
            or network.get("Internal") is not True):
        raise ValueError("private backend network changed")


def _raw_rules() -> list[dict[str, object]]:
    """Inspect bounded port inventory without requiring Canary to remain up."""
    inventory = _api(_ROOTLESS, "GET", "/v1/ports")
    if type(inventory) is not list or len(inventory) > 30:
        raise ValueError("unexpected RootlessKit port inventory")
    for record in inventory:
        if (type(record) is not dict or type(record.get("id")) is not int
                or record["id"] < 1 or type(record.get("spec")) is not dict):
            raise ValueError("RootlessKit port record invalid")
    if len({r["id"] for r in inventory}) != len(inventory):
        raise ValueError("duplicate RootlessKit port ID")
    return inventory


def _rules() -> list[dict[str, object]]:
    """Require one original Canary rule and at most one Analytics rule."""
    inventory = _raw_rules()
    if len(inventory) > 2 or sum(r["spec"] == _CANARY for r in inventory) != 1:
        raise ValueError("original Canary port rule changed")
    if any(r["spec"] not in (_CANARY, _TARGET) for r in inventory):
        raise ValueError("unexpected RootlessKit forwarding")
    if sum(r["spec"] == _TARGET for r in inventory) > 1:
        raise ValueError("duplicate Analytics forwarding")
    return inventory


def _delete_target() -> None:
    """Remove only matching Analytics forwarding even if Canary is unavailable."""
    records = _raw_rules()
    target = [r for r in records if r["spec"] == _TARGET]
    if len(target) > 1:
        raise ValueError("multiple Analytics port records; operator audit required")
    if target:
        _api(_ROOTLESS, "DELETE", "/v1/ports/" + str(target[0]["id"]))
    after = _raw_rules()
    if [r for r in records if r["spec"] != _TARGET] != after:
        raise RuntimeError("RootlessKit port cleanup not confirmed")


def _http_ready(resource: str) -> None:
    """Test the exact host-loopback livez/readyz path without body exposure."""
    if resource not in ("/livez", "/readyz"):
        raise ValueError("unexpected health probe path")
    connection = http.client.HTTPConnection("127.0.0.1", 3141, timeout=3)
    try:
        connection.request("GET", resource, headers={"Cache-Control": "no-store"})
        response = connection.getresponse()
        response.read(2048)
        if response.status != 200:
            raise RuntimeError("private Analytics health unavailable")
    finally:
        connection.close()


# Section 4: Closed lifecycle: remove stale target, supervise, remove on stop.
class _Stop(Exception):
    """Normal SIGINT/SIGTERM service shutdown requiring port cleanup."""


def _on_signal(_signal: int, _frame: object) -> None:
    """Translate termination into a catchable event for fail-safe cleanup."""
    raise _Stop()


def _serve() -> int:
    """Forward only the approved live image, closing on every state change."""
    approved = _identity()
    _rootless_info()
    _delete_target()  # Clear only a stale exact 3141 mapping from a prior crash.
    _container_state(approved)
    started = False
    try:
        if len(_rules()) != 1:
            raise ValueError("RootlessKit port already allocated")
        started = True  # Also clean up if POST succeeded but response was lost.
        created = _api(_ROOTLESS, "POST", "/v1/ports", _TARGET, status=201)
        if (type(created) is not dict or type(created.get("id")) is not int
                or created.get("spec") != _TARGET):
            raise ValueError("unexpected port creation response")
        registered_id = created["id"]
        if (len(_rules()) != 2 or not any(r["id"] == registered_id
                                          and r["spec"] == _TARGET for r in _rules())):
            raise ValueError("port not established as requested")
        _container_state(approved)
        _http_ready("/readyz")
        _http_ready("/livez")
        print("ANALYTICS_LOOPBACK_ACTIVE localhost_3141 readyz=200 livez=200", flush=True)
        last_health = time.monotonic()
        while True:
            time.sleep(_CHECK_INTERVAL)
            _container_state(approved)
            actual = _rules()
            if (len(actual) != 2 or not any(r["id"] == registered_id
                                            and r["spec"] == _TARGET for r in actual)):
                raise RuntimeError("forwarding was replaced or removed")
            if time.monotonic() - last_health >= _HEALTH_EVERY:
                _http_ready("/readyz")
                _http_ready("/livez")
                last_health = time.monotonic()
    finally:
        if started:
            _delete_target()
            print("ANALYTICS_LOOPBACK_CLOSED target_3141_removed", flush=True)


def main() -> int:
    """Start bounded service, or execute only its stop-time cleanup hook."""
    if len(sys.argv) != 2 or sys.argv[1] not in ("--serve", "--cleanup"):
        print("ANALYTICS_LOOPBACK_HOLD unsupported_mode", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    try:
        _identity()
        _rootless_info()
        if sys.argv[1] == "--cleanup":
            _delete_target()
            print("ANALYTICS_LOOPBACK_CLEANUP_PASS", flush=True)
            return 0
        return _serve()
    except _Stop:
        return 0
    except Exception as exc:
        # Exception type, not Docker/HTTP/credentials or environment, is logged.
        print("ANALYTICS_LOOPBACK_HOLD " + type(exc).__name__, file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
