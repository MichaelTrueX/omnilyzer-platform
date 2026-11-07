#!/usr/bin/env python3
"""File: deployment/analytics_loopback_guard.py

Purpose: Preserve the exact original, signed Analytics 0.15.0 DEV
         RootlessKit blue-only supervisor; add an inert future successor
         3141/3142 route transaction using the SAME local APIs and UID991.
         Candidate 3142 preparation is durably journaled before routing.
Related: deployment/analytics_first_install.py,
         deployment/analytics_active_state_review.py,
         deployment/analytics_execution.py (signed next-release contract),
         deployment/runtime/dev/analytics.compose.successor-ports.yaml,
         deployment/systemd/rootless/omnilyzer-analytics-loopback.service,
         deployment/tests/test_analytics_loopback_guard.py,
         docs/operations/task14b-release-identity-contract-20261102.md.

Security: ORIGINAL --serve and --cleanup modes are unchanged, and the installed
DEV source/unit are not touched. The new private route-swap is NOT called
by either mode and gives NO deployment permission. Only a separately reviewed
future supervisor with a signed replay-authorized executor, persistent
recovery intent and approved installation may invoke it. The environment
selector is merely an opt-in guard, NOT a signature or trusted authorization.
All routes are fixed localhost3141/3142 and original Canary3020 is untouched.
The code never reads registry credentials, keys or database values.
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


# Section 4: bounded, opt-in successor routing transaction. This is NOT
# reachable from --serve/--cleanup, nor from the installed 0.15.0 supervisor.
# A future independently reviewed UID991 executor must supply the exact signed
# previous/next immutable images and verify durable replay/rollback BEFORE
# asking the upgraded, exclusive supervisor to call this function.
_SUCCESSOR_SCOPE = "ANALYTICS_REVIEWED_SUPERVISOR_V2"
_SUCCESSOR_REPOSITORY = "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
_SLOT_NAMES = {
    "blue": "omnilyzer-analytics-dev-analytics-blue-1",
    "green": "omnilyzer-analytics-dev-analytics-green-1",
}


def _verified_slot(slot: str, image: str, identifier: str) -> str:
    """Resolve only approved running/healthy private OCI, never an input IP."""
    import ipaddress

    if (
        type(slot) is not str or slot not in _SLOT_NAMES
        or type(image) is not str
        or not image.startswith(_SUCCESSOR_REPOSITORY)
        or _HEX64.fullmatch(image[len(_SUCCESSOR_REPOSITORY):]) is None
        or image == _SUCCESSOR_REPOSITORY + "0" * 64
        or type(identifier) is not str
        or _HEX64.fullmatch(identifier) is None
    ):
        raise ValueError("unapproved Analytics slot identity")
    container = _api(
        _DOCKER, "GET", "/containers/" + _SLOT_NAMES[slot] + "/json",
    )
    network = _api(_DOCKER, "GET", "/networks/" + _NETWORK)
    if type(container) is not dict or type(network) is not dict:
        raise ValueError("unreviewed rootless container")
    config, host, state, settings = (
        container.get("Config"), container.get("HostConfig"),
        container.get("State"), container.get("NetworkSettings"),
    )
    if not all(type(item) is dict for item in (config, host, state, settings)):
        raise ValueError("unreviewed rootless container metadata")
    health = state.get("Health")
    historical_blue = slot == "blue" and image == _IMAGE
    expected_bindings = (
        {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3141"}]}
        if historical_blue else {}
    )
    current_bindings = host.get("PortBindings")
    if historical_blue:
        valid_bindings = current_bindings == expected_bindings
    else:
        valid_bindings = current_bindings in ({}, None)
    if (
        container.get("Id") != identifier
        or container.get("Name") != "/" + _SLOT_NAMES[slot]
        or config.get("Image") != image
        or config.get("User") != "10001:10001"
        or state.get("Running") is not True
        or type(health) is not dict or health.get("Status") != "healthy"
        or host.get("Privileged") is not False
        or host.get("ReadonlyRootfs") is not True
        or host.get("CapDrop") != ["ALL"]
        or host.get("SecurityOpt") != ["no-new-privileges:true"]
        or not valid_bindings
        or settings.get("Ports") != {"3000/tcp": None}
        or network.get("Id") != _NETWORK_ID
        or network.get("Name") != _NETWORK
        or network.get("Internal") is not True
        or network.get("Driver") != "bridge"
    ):
        raise ValueError("unreviewed rootless image or isolation")
    networks = settings.get("Networks")
    if type(networks) is not dict or set(networks) != {_NETWORK}:
        raise ValueError("unexpected image networks")
    entry = networks[_NETWORK]
    if (
        type(entry) is not dict
        or entry.get("NetworkID") != _NETWORK_ID
        or entry.get("Gateway") not in ("", None)
    ):
        raise ValueError("unreviewed internal network")
    address = ipaddress.ip_address(entry.get("IPAddress"))
    if (
        type(address) is not ipaddress.IPv4Address
        or not address.is_private
        or address.is_loopback or address.is_link_local
        or address.is_reserved or address.is_multicast
    ):
        raise ValueError("unapproved private child IP")
    local_image_id = container.get("Image")
    if (
        type(local_image_id) is not str
        or not local_image_id.startswith("sha256:")
        or _HEX64.fullmatch(local_image_id[7:]) is None
    ):
        raise ValueError("unreviewed actual OCI image ID")
    local = _api(_DOCKER, "GET", "/images/" + local_image_id + "/json")
    if (
        type(local) is not dict or local.get("Id") != local_image_id
        or local.get("RepoDigests") != [image]
        or local.get("Os") != "linux"
        or local.get("Architecture") != "amd64"
    ):
        raise ValueError("unreviewed installed OCI bytes")
    return str(address)


def _verified_three_routes(
    old_ip: str, next_ip: str,
) -> tuple[int, dict, list[dict[str, object]]]:
    """Bind exact Canary+3141 old+3142 next, with complete rule inventory."""
    inventory = _raw_rules()
    old = {
        "proto": "tcp4", "parentIP": "127.0.0.1",
        "parentPort": 3141, "childIP": old_ip, "childPort": 3000,
    }
    candidate = {
        "proto": "tcp4", "parentIP": "127.0.0.1",
        "parentPort": 3142, "childIP": next_ip, "childPort": 3000,
    }
    if (
        old_ip == next_ip
        or type(inventory) is not list or len(inventory) != 3
        or sum(r["spec"] == _CANARY for r in inventory) != 1
        or sum(r["spec"] == old for r in inventory) != 1
        or sum(r["spec"] == candidate for r in inventory) != 1
        or any(r["spec"] not in (_CANARY, old, candidate) for r in inventory)
    ):
        raise ValueError("private port inventory changed")
    return next(r["id"] for r in inventory if r["spec"] == old), old, inventory


def _candidate_http_ready(resource: str) -> None:
    """Probe only localhost3142 without cookies, headers or public URLs."""
    if resource not in ("/readyz", "/livez"):
        raise ValueError("unapproved candidate health endpoint")
    connection = http.client.HTTPConnection("127.0.0.1", 3142, timeout=3)
    try:
        connection.request(
            "GET", resource, headers={"Cache-Control": "no-store"},
        )
        response = connection.getresponse()
        response.read(2048)
        if response.status != 200:
            raise RuntimeError("private Analytics candidate not ready")
    finally:
        connection.close()


def _require_route_journal(journal: object) -> None:
    """Require the one protected product journal, never a request path."""
    from .analytics_route_journal import (
        AnalyticsRouteJournal, ROUTE_JOURNAL_DIRECTORY,
    )

    if (
        type(journal) is not AnalyticsRouteJournal
        or object.__getattribute__(journal, "_directory")
            != ROUTE_JOURNAL_DIRECTORY
    ):
        raise ValueError("unreviewed successor journal")


def _stage_reviewed_private_candidate_probe(
    *, previous_slot: str, previous_image: str, previous_id: str,
    next_slot: str, next_image: str, next_id: str,
    journal: object, request_sha256: str,
) -> None:
    """Durably stage only the private 3142 candidate route, never 3141.

    The caller MUST separately authenticate signed Task013/OIDC evidence
    and replay. This low-level primitive may execute only in an independently
    installed future UID991 V2 supervisor with a root-provisioned journal.
    The existing live 0.15.0 supervisor does not call this method.
    """
    _require_route_journal(journal)
    with journal.exclusive():
        if (
            not journal.exclusive_active()
            or os.geteuid() != _UID
            or os.environ.get(_SUCCESSOR_SCOPE) != "1"
            or previous_slot not in _SLOT_NAMES
            or next_slot not in _SLOT_NAMES
            or next_slot == previous_slot or next_image == previous_image
            or type(request_sha256) is not str
            or _HEX64.fullmatch(request_sha256) is None
            or request_sha256 == "0" * 64
        ):
            raise ValueError("unreviewed private candidate principal")
        prior = journal.read()
        if prior is None:
            # No prior journal means this is the FIRST successor only.
            if previous_slot != "blue" or previous_image != _IMAGE:
                raise ValueError("first successor must preserve signed 0.15.0")
        elif (
            prior["phase"] not in ("switched", "restored")
        ):
            raise ValueError("unfinished prior release requires recovery")
        _rootless_info()
        previous_ip = _verified_slot(
            previous_slot, previous_image, previous_id,
        )
        next_ip = _verified_slot(next_slot, next_image, next_id)
        if previous_ip == next_ip:
            raise ValueError("candidate shares previous writer address")
        old = {
            "proto": "tcp4", "parentIP": "127.0.0.1",
            "parentPort": 3141, "childIP": previous_ip, "childPort": 3000,
        }
        candidate = dict(old, parentPort=3142, childIP=next_ip)
        inventory = _raw_rules()
        if (
            len(inventory) != 2
            or sum(entry["spec"] == _CANARY for entry in inventory) != 1
            or sum(entry["spec"] == old for entry in inventory) != 1
            or any(entry["spec"] not in (_CANARY, old) for entry in inventory)
        ):
            raise ValueError("unreviewed prior ingress or existing candidate")
        _http_ready("/readyz")
        _http_ready("/livez")
        if _raw_rules() != inventory:
            raise ValueError("ingress changed before durable prepare")
        # A real fsync-protected journal record MUST precede the POST. A
        # crash after preparing but before POST is recoverable as old 3141.
        intent = journal.begin(
            request_sha256=request_sha256,
            previous_slot=previous_slot, previous_image=previous_image,
            previous_container_id=previous_id, previous_ip=previous_ip,
            next_slot=next_slot, next_image=next_image,
            next_container_id=next_id, next_ip=next_ip,
        )
        try:
            created = _api(
                _ROOTLESS, "POST", "/v1/ports", candidate, status=201,
            )
            if (
                type(created) is not dict
                or type(created.get("id")) is not int
                or created.get("id") < 1
                or created.get("spec") != candidate
            ):
                raise RuntimeError("unconfirmed candidate route creation")
            observed = _raw_rules()
            if (
                len(observed) != 3
                or sorted(
                    (entry for entry in observed
                     if entry["id"] != created["id"]),
                    key=lambda entry: entry["id"],
                ) != sorted(inventory, key=lambda entry: entry["id"])
                or sum(
                    entry["id"] == created["id"]
                    and entry["spec"] == candidate for entry in observed
                ) != 1
            ):
                raise RuntimeError("unapproved candidate route inventory")
            _candidate_http_ready("/readyz")
            _candidate_http_ready("/livez")
            if (
                _raw_rules() != observed
                or _verified_slot(
                    previous_slot, previous_image, previous_id
                ) != previous_ip
                or _verified_slot(next_slot, next_image, next_id) != next_ip
            ):
                raise RuntimeError("candidate or original writer changed")
            # Commit candidate readiness separately from PREPARED. An
            # interrupted generic PREPARED journal MUST NOT grant cutover
            # permission merely because its input fields happen to match.
            journal.finish(intent, phase="candidate_ready")
            return None
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            # Leave PREPARED for restart recovery; never claim completion.
            raise
        except Exception:
            try:
                current = _raw_rules()
                if (
                    len(current) not in (2, 3)
                    or sum(x["spec"] == _CANARY for x in current) != 1
                    or sum(x["spec"] == old for x in current) != 1
                    or any(x["spec"] not in (_CANARY, old, candidate)
                           for x in current)
                ):
                    raise RuntimeError("ambiguous rollback inventory")
                staged = [entry for entry in current
                          if entry["spec"] == candidate]
                if len(staged) > 1:
                    raise RuntimeError("multiple candidate routes")
                if staged:
                    _api(
                        _ROOTLESS, "DELETE",
                        "/v1/ports/" + str(staged[0]["id"]),
                    )
                if sorted(_raw_rules(), key=lambda x: x["id"]) != sorted(
                    inventory, key=lambda x: x["id"]
                ):
                    raise RuntimeError("candidate cleanup not confirmed")
                _http_ready("/readyz")
                _http_ready("/livez")
                journal.finish(intent, phase="restored")
            except Exception:
                raise RuntimeError(
                    "TASK014_ANALYTICS_CANDIDATE_RECOVERY_UNCONFIRMED"
                ) from None
            raise RuntimeError(
                "TASK014_ANALYTICS_CANDIDATE_STAGE_REJECTED"
            ) from None


def _recover_reviewed_private_route(
    *, journal: object, request_sha256: str,
    previous_slot: str, previous_image: str, previous_id: str,
    next_slot: str, next_image: str, next_id: str,
) -> None:
    """Serialize one recovery across all UID991 processes."""
    _require_route_journal(journal)
    with journal.exclusive():
        _recover_reviewed_private_route_locked(
            journal=journal, request_sha256=request_sha256,
            previous_slot=previous_slot, previous_image=previous_image,
            previous_id=previous_id, next_slot=next_slot,
            next_image=next_image, next_id=next_id,
        )


def _recover_reviewed_private_route_locked(
    *, journal: object, request_sha256: str,
    previous_slot: str, previous_image: str, previous_id: str,
    next_slot: str, next_image: str, next_id: str,
) -> None:
    """Reconcile an interrupted PREPARED cutover to the old healthy writer.

    This is a private future-supervisor recovery action, NOT a public CLI,
    signature check or permission to deploy. Also handles a fsync-protected
    rollback_pending transaction AFTER a completed 3141 cutover, e.g. when
    replay finalization fails. The caller must independently verify both
    exact signed releases, the previous healthy writer and original JTI.
    A missing/finished/foreign/corrupt journal or unrecognized local rule is
    a hard HOLD, never an inferred permission to recreate host forwarding.
    """
    _require_route_journal(journal)
    if (
        not journal.exclusive_active()
        or os.geteuid() != _UID
        or os.environ.get(_SUCCESSOR_SCOPE) != "1"
    ):
        raise ValueError("unreviewed recovery principal")
    intent = journal.read()
    if (
        type(intent) is not dict
        or intent.get("phase") not in (
            "prepared", "candidate_ready", "rollback_pending",
        )
        or intent.get("request_sha256") != request_sha256
        or intent.get("previous_slot") != previous_slot
        or intent.get("previous_image") != previous_image
        or intent.get("previous_container_id") != previous_id
        or intent.get("next_slot") != next_slot
        or intent.get("next_image") != next_image
        or intent.get("next_container_id") != next_id
    ):
        raise ValueError("unreviewed interrupted upgrade")
    # The old immutable OCI must STILL exist and be healthy.
    _rootless_info()
    old_ip = _verified_slot(previous_slot, previous_image, previous_id)
    if old_ip != intent["previous_ip"]:
        raise ValueError("the former writer has moved")
    old = {
        "proto": "tcp4", "parentIP": "127.0.0.1",
        "parentPort": 3141, "childIP": old_ip, "childPort": 3000,
    }
    new = dict(old, childIP=intent["next_ip"])
    candidate = dict(new, parentPort=3142)
    observed = _raw_rules()
    old_rules = [r for r in observed if r["spec"] == old]
    new_rules = [r for r in observed if r["spec"] == new]
    if (
        # A post-COMMIT rollback has no 3142 probe. If the executor dies
        # exactly AFTER deleting green3141 but BEFORE reposting blue3141,
        # the only remaining rule can legitimately be the untouched Canary.
        # Permit that narrow 1-rule recovery shape ONLY for the fsync-proven
        # rollback_pending phase, never for prepared/candidate_ready.
        len(observed) not in (
            (1, 2) if intent["phase"] == "rollback_pending" else (2, 3)
        )
        or len(old_rules) > 1 or len(new_rules) > 1
        or bool(old_rules) and bool(new_rules)
        or sum(r["spec"] == _CANARY for r in observed) != 1
        or sum(r["spec"] == candidate for r in observed) not in (0, 1)
        or any(
            r["spec"] not in (_CANARY, old, new, candidate)
            for r in observed
        )
    ):
        raise ValueError("interrupted route has unrecognized or public rules")
    # Candidate preparation may crash after fsyncing PREPARED but BEFORE
    # posting the candidate probe. With unchanged old 3141 + Canary, no
    # forwarding mutation is needed. Mark only this exact intent restored.
    if (
        len(observed) == 2
        and len(old_rules) == 1 and len(new_rules) == 0
        and sum(r["spec"] == candidate for r in observed) == 0
        and sorted(
            (r["spec"] for r in observed), key=lambda record: str(record)
        ) == sorted((_CANARY, old), key=lambda record: str(record))
    ):
        if _raw_rules() != observed:
            raise RuntimeError("candidate absence changed during recovery")
        _http_ready("/readyz")
        _http_ready("/livez")
        journal.finish(intent, phase="restored")
        return None
    # Recheck the exact unchanged Canary/candidate *IDs* before mutation.
    preserved = sorted(
        (r for r in observed if r["spec"] in (_CANARY, candidate)),
        key=lambda r: r["id"],
    )
    if sorted(
        (r for r in _raw_rules() if r["spec"] in (_CANARY, candidate)),
        key=lambda r: r["id"],
    ) != preserved:
        raise ValueError("Canary or candidate changed during recovery")
    if new_rules:
        # No auth, DB, replay or other product changes. Remove the one
        # interrupted 3141 route before recreating the signed old rule.
        _api(_ROOTLESS, "DELETE", "/v1/ports/" + str(new_rules[0]["id"]))
    if not old_rules:
        after = _raw_rules()
        if sorted(after, key=lambda r: r["id"]) != preserved:
            raise RuntimeError("TASK014_ANALYTICS_ROUTE_RECOVERY_UNCONFIRMED")
        _api(_ROOTLESS, "POST", "/v1/ports", old, status=201)
    after = _raw_rules()
    if (
        len(after) != len(preserved) + 1
        or sum(r["spec"] == old for r in after) != 1
        or sorted(
            (r for r in after if r["spec"] != old),
            key=lambda r: r["id"],
        ) != preserved
        or _verified_slot(
            previous_slot, previous_image, previous_id,
        ) != old_ip
    ):
        raise RuntimeError("TASK014_ANALYTICS_ROUTE_RECOVERY_UNCONFIRMED")
    _http_ready("/readyz")
    _http_ready("/livez")
    if intent["phase"] == "candidate_ready":
        # A previously health-proven candidate may have been left behind by
        # a crash. Remove ONLY this exact 3142 probe, after old writer is
        # independently healthy and the durable JTI is still matched.
        candidate_rules = [
            rule for rule in after if rule["spec"] == candidate
        ]
        if len(candidate_rules) > 1:
            raise RuntimeError("TASK014_ANALYTICS_ROUTE_RECOVERY_UNCONFIRMED")
        if candidate_rules:
            _api(
                _ROOTLESS, "DELETE",
                "/v1/ports/" + str(candidate_rules[0]["id"]),
            )
        settled = _raw_rules()
        if (
            len(settled) != 2
            or sum(rule["spec"] == _CANARY for rule in settled) != 1
            or sum(rule["spec"] == old for rule in settled) != 1
            or any(rule["spec"] not in (_CANARY, old) for rule in settled)
        ):
            raise RuntimeError("TASK014_ANALYTICS_ROUTE_RECOVERY_UNCONFIRMED")
        _http_ready("/readyz")
        _http_ready("/livez")
    journal.finish(intent, phase="restored")


def _switch_reviewed_private_route(
    *, previous_slot: str, previous_image: str, previous_id: str,
    next_slot: str, next_image: str, next_id: str,
    journal: object, request_sha256: str,
) -> None:
    """Serialize journal preparation, ingress change and result as one unit."""
    _require_route_journal(journal)
    with journal.exclusive():
        _switch_reviewed_private_route_locked(
            previous_slot=previous_slot, previous_image=previous_image,
            previous_id=previous_id, next_slot=next_slot,
            next_image=next_image, next_id=next_id,
            journal=journal, request_sha256=request_sha256,
        )


def _switch_reviewed_private_route_locked(
    *, previous_slot: str, previous_image: str, previous_id: str,
    next_slot: str, next_image: str, next_id: str,
    journal: object, request_sha256: str,
) -> None:
    """Durably prepared, reversible localhost3141 route swap, Canary untouched.

    This low-level transaction is intentionally not a public CLI entrypoint
    or deploy authorization. It requires a separately approved supervisor V2
    service environment, same UID991, and independently verified OCI and
    replay/owner-signed successor at its future ONLY caller. On ANY ambiguous
    or failed replacement, attempt to restore exact old route; an unconfirmed
    restoration is a hard operational HOLD, never success. This API itself
    does not write DB, replay or release state and is NOT crash-atomic.
    """
    from .analytics_route_journal import (
        AnalyticsRouteJournal, ROUTE_JOURNAL_DIRECTORY,
    )

    if (
        type(journal) is not AnalyticsRouteJournal
        or object.__getattribute__(journal, "_directory")
            != ROUTE_JOURNAL_DIRECTORY
        or not journal.exclusive_active()
        or os.geteuid() != _UID
        or os.environ.get(_SUCCESSOR_SCOPE) != "1"
        or type(request_sha256) is not str
        or _HEX64.fullmatch(request_sha256) is None
        or request_sha256 == "0" * 64
        or type(previous_slot) is not str
        or type(next_slot) is not str
        or previous_slot not in _SLOT_NAMES or next_slot not in _SLOT_NAMES
        or next_slot == previous_slot
        or previous_image == next_image
    ):
        raise ValueError("successor route change has no reviewed authority")
    _rootless_info()
    previous_ip = _verified_slot(previous_slot, previous_image, previous_id)
    next_ip = _verified_slot(next_slot, next_image, next_id)
    previous_rule_id, old, before = _verified_three_routes(
        previous_ip, next_ip,
    )
    # Protect complete Canary/candidate IDs, not merely their port numbers.
    # Never mutate when even an independently read inventory has drifted.
    if sorted(_raw_rules(), key=lambda r: r["id"]) != sorted(
        before, key=lambda r: r["id"],
    ):
        raise ValueError("active forwarding changed before switching")
    preserved = sorted(
        (r for r in before if r["id"] != previous_rule_id),
        key=lambda r: r["id"],
    )
    new = dict(old, childIP=next_ip)
    if new == old:
        raise ValueError("identical route targets are not an upgrade")
    _candidate_http_ready("/readyz")
    _candidate_http_ready("/livez")
    if sorted(_raw_rules(), key=lambda r: r["id"]) != sorted(
        before, key=lambda r: r["id"],
    ):
        raise ValueError("route drifted after candidate health")
    # A prepared, fsync-confirmed journal MUST precede RootlessKit mutation.
    # A previous unfinished intent blocks this operation on every retry.
    # This disk record is NOT signature, replay or release authorization.
    approved_fields = {
        "request_sha256": request_sha256,
        "previous_slot": previous_slot,
        "previous_image": previous_image,
        "previous_container_id": previous_id,
        "previous_ip": previous_ip,
        "next_slot": next_slot, "next_image": next_image,
        "next_container_id": next_id, "next_ip": next_ip,
    }
    existing = journal.read()
    # Requiring the complete journal phase is stronger than a merely
    # healthy 3142 port. Unknown, missing, or partially PREPARED attempts
    # can never be adopted for a cutover.
    if (
        type(existing) is not dict
        or existing.get("phase") != "candidate_ready"
        or any(existing.get(k) != v for k, v in approved_fields.items())
    ):
        raise ValueError("candidate was not durably verified for this request")
    intent = existing
    began = False
    try:
        began = True
        _api(_ROOTLESS, "DELETE", "/v1/ports/" + str(previous_rule_id))
        after = _raw_rules()
        if sorted(after, key=lambda r: r["id"]) != preserved:
            raise RuntimeError("unexpected route mutation after delete")
        created = _api(_ROOTLESS, "POST", "/v1/ports", new, status=201)
        if (
            type(created) is not dict
            or type(created.get("id")) is not int
            or created.get("spec") != new
        ):
            raise RuntimeError("new private route not acknowledged")
        after = _raw_rules()
        if (
            len(after) != 3
            or sorted(
                (r for r in after if r["id"] != created["id"]),
                key=lambda r: r["id"],
            ) != preserved
            or not any(
                r["id"] == created["id"] and r["spec"] == new for r in after
            )
        ):
            raise RuntimeError("new private route not established")
        _http_ready("/readyz")
        _http_ready("/livez")
        if (
            sorted(_raw_rules(), key=lambda r: r["id"])
                != sorted(after, key=lambda r: r["id"])
            or _verified_slot(
                previous_slot, previous_image, previous_id,
            ) != previous_ip
            or _verified_slot(
                next_slot, next_image, next_id,
            ) != next_ip
        ):
            raise RuntimeError("route or image changed during cutover")
        candidate_probes = [
            entry for entry in after if (
                entry["spec"].get("parentPort") == 3142
                and entry["spec"].get("childIP") == next_ip
            )
        ]
        if len(candidate_probes) != 1:
            raise RuntimeError("new writer has no exact private probe")
        _api(
            _ROOTLESS, "DELETE",
            "/v1/ports/" + str(candidate_probes[0]["id"]),
        )
        # A completed successor has EXACTLY Canary and stable 3141.
        # 3142 is always temporary; keeping it would prevent the next
        # candidate from using the opposite slot safely.
        settled = _raw_rules()
        if (
            len(settled) != 2
            or sum(item["spec"] == _CANARY for item in settled) != 1
            or sum(item["spec"] == new for item in settled) != 1
            or any(item["spec"] not in (_CANARY, new) for item in settled)
            or _verified_slot(next_slot, next_image, next_id) != next_ip
        ):
            raise RuntimeError("temporary candidate route not retired")
        _http_ready("/readyz")
        _http_ready("/livez")
        journal.finish(intent, phase="switched")
        return
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        if began:
            try:
                # May have committed the POST despite an unreceived reply:
                # remove ONLY the exact new Analytics route if present.
                current = _raw_rules()
                candidate = {
                    "proto": "tcp4", "parentIP": "127.0.0.1",
                    "parentPort": 3142, "childIP": next_ip,
                    "childPort": 3000,
                }
                if (
                    any(r["spec"] not in (_CANARY, old, new, candidate)
                        for r in current)
                    or len(current) not in (2, 3)
                ):
                    raise RuntimeError("unknown route during rollback")
                newer = [r for r in current if r["spec"] == new]
                older = [r for r in current if r["spec"] == old]
                if len(newer) > 1 or len(older) > 1 or (newer and older):
                    raise RuntimeError("ambiguous 3141 route during rollback")
                if newer:
                    _api(
                        _ROOTLESS, "DELETE",
                        "/v1/ports/" + str(newer[0]["id"]),
                    )
                    current = _raw_rules()
                canary_before = [
                    r for r in before if r["spec"] == _CANARY
                ]
                if (
                    len(canary_before) != 1
                    or sum(r["spec"] == _CANARY for r in current) != 1
                    or not any(r == canary_before[0] for r in current)
                    or any(r["spec"] not in (_CANARY, old, candidate)
                           for r in current)
                ):
                    raise RuntimeError("Canary or candidate changed during rollback")
                if not older:
                    # Never restore traffic to a changed/stopped container.
                    _verified_slot(
                        previous_slot, previous_image, previous_id,
                    )
                    restored = _api(
                        _ROOTLESS, "POST", "/v1/ports", old, status=201,
                    )
                    if (
                        type(restored) is not dict
                        or type(restored.get("id")) is not int
                        or restored.get("spec") != old
                    ):
                        raise RuntimeError("restoration not acknowledged")
                current = _raw_rules()
                if (
                    len(current) not in (2, 3)
                    or sum(r["spec"] == old for r in current) != 1
                    or sum(r["spec"] == _CANARY for r in current) != 1
                    or not any(r == canary_before[0] for r in current)
                    or any(r["spec"] not in (_CANARY, old, candidate)
                           for r in current)
                ):
                    raise RuntimeError("rollback routing not confirmed")
                # Restore a TWO-port idle state for a normal next release.
                # Candidate 3142 is never a durable active ingress.
                staged = [
                    r for r in current if r["spec"] == candidate
                ]
                if len(staged) > 1:
                    raise RuntimeError("duplicate candidate route")
                if staged:
                    _api(
                        _ROOTLESS, "DELETE",
                        "/v1/ports/" + str(staged[0]["id"]),
                    )
                current = _raw_rules()
                if (
                    len(current) != 2
                    or sum(r["spec"] == _CANARY for r in current) != 1
                    or sum(r["spec"] == old for r in current) != 1
                    or not any(r == canary_before[0] for r in current)
                    or any(r["spec"] not in (_CANARY, old) for r in current)
                ):
                    raise RuntimeError("rollback probe cleanup not confirmed")
                _http_ready("/readyz")
                _http_ready("/livez")
                journal.finish(intent, phase="restored")
            except Exception:
                raise RuntimeError("TASK014_ANALYTICS_ROUTE_RECOVERY_UNCONFIRMED") from None
        raise RuntimeError("TASK014_ANALYTICS_ROUTE_CHANGE_REJECTED") from None


# Section 4b: an already switched first successor can be reversed only
# through a durable, matched rollback intent. No service currently calls it.
def _rollback_committed_private_successor(
    *, previous_slot: str, previous_image: str, previous_id: str,
    next_slot: str, next_image: str, next_id: str,
    journal: object, request_sha256: str,
) -> None:
    """Restore the original signed blue writer after a COMMITTED V2 switch.

    A failure of replay.finish_execution after the already healthy green
    switch cannot be treated as a completed release. Record the exact
    rollback_pending phase DURABLY before changing localhost3141, and reuse
    the existing checked recovery algorithm to restore ONLY the original
    signed 0.15.0 route, with Canary untouched and database writes preserved.
    Interrupted rollback remains pending and blocks another candidate until
    the same independently reviewed release identity is recovered.

    This future-supervisor primitive does NOT validate OIDC, SBOM, signed
    release or replay itself and is not installed/enabled by this source.
    The sole eventual caller must pass those checks before any route change.
    It cannot stop containers, delete volumes, switch public ingress or
    synthesize a release success.
    """
    _require_route_journal(journal)
    with journal.exclusive():
        if (
            not journal.exclusive_active()
            or os.geteuid() != _UID
            or os.environ.get(_SUCCESSOR_SCOPE) != "1"
            or type(request_sha256) is not str
            or _HEX64.fullmatch(request_sha256) is None
            or request_sha256 == "0" * 64
            or previous_slot != "blue" or previous_image != _IMAGE
            or next_slot != "green"
            or type(next_image) is not str
            or not next_image.startswith(_SUCCESSOR_REPOSITORY)
            or _HEX64.fullmatch(
                next_image[len(_SUCCESSOR_REPOSITORY):]
            ) is None
            or next_image == previous_image
        ):
            raise ValueError("unreviewed post-switch rollback authority")
        existing = journal.read()
        if (
            type(existing) is not dict
            or existing.get("phase") != "switched"
            or existing.get("request_sha256") != request_sha256
            or existing.get("previous_slot") != previous_slot
            or existing.get("previous_image") != previous_image
            or existing.get("previous_container_id") != previous_id
            or existing.get("next_slot") != next_slot
            or existing.get("next_image") != next_image
            or existing.get("next_container_id") != next_id
        ):
            raise ValueError("foreign or unfinished committed release")
        _rootless_info()
        old_ip = _verified_slot(previous_slot, previous_image, previous_id)
        if old_ip != existing["previous_ip"]:
            raise ValueError("signed previous writer is not intact")
        old = {
            "proto": "tcp4", "parentIP": "127.0.0.1",
            "parentPort": 3141, "childIP": old_ip, "childPort": 3000,
        }
        new = dict(old, childIP=existing["next_ip"])
        actual = _raw_rules()
        # No unknown, duplicate, public, Canary-replaced or partially
        # prepared forwarding state may be mistaken for a committed release.
        if (
            len(actual) != 2
            or sum(rule["spec"] == _CANARY for rule in actual) != 1
            or sum(rule["spec"] == new for rule in actual) != 1
            or any(rule["spec"] not in (_CANARY, new) for rule in actual)
            or _raw_rules() != actual
        ):
            raise ValueError("committed private route is not unchanged")
        # Fsync both the temporary file and its directory BEFORE first DELETE.
        journal.finish(existing, phase="rollback_pending")
        # This exact recovery is also callable after a crash on restart,
        # only with the same UID991 environment, signed identities and JTI.
        _recover_reviewed_private_route_locked(
            journal=journal, request_sha256=request_sha256,
            previous_slot=previous_slot, previous_image=previous_image,
            previous_id=previous_id, next_slot=next_slot,
            next_image=next_image, next_id=next_id,
        )
        committed = journal.read()
        if type(committed) is not dict or committed.get("phase") != "restored":
            raise RuntimeError("TASK014_ANALYTICS_ROLLBACK_UNCONFIRMED")
    return None


# Section 5: unchanged original closed lifecycle, no successor dispatch.
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
