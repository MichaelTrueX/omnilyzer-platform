"""File: deployment/analytics_active_state_review.py

Purpose: Independently observe the actual private Analytics DEV active
         blue/green OCI image from rootless Docker AND RootlessKit forwarding.
         Read-only groundwork for the existing Task014 successor request.
Related: deployment/analytics_execution.py (inert schema-3 admission),
         deployment/analytics_dev_release_review.py (existing slot contract),
         deployment/runtime/dev/analytics.compose.review.yaml,
         deployment/analytics_first_install.py (runtime hardening),
         platform PR278 analytics_loopback_guard.py (original blue route),
         deployment/tests/test_analytics_active_state_review.py.

Authority: This module does NOT sign, authorize deployment, set ingress,
           install, write files, read credentials or act on the database.
           It only observes fixed, local, product-scoped Unix API endpoints
           when invoked by a privileged, independently installed process.
           The actual executor MUST recheck live state immediately before
           any write and preserve durable replay/rollback across interruption.
"""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import json
import os
import re
import socket
import stat

from .analytics_execution import ANALYTICS_SUCCESSOR_CANDIDATE_PORT
from .analytics_signed_release_consumer import PINNED_DIGEST
from .policy import validate_digest

# Section 1: the exact existing rootless Docker/RootlessKit sockets and
# immutable Analytics/Canary ports. No user-provided paths, ports or hosts.
_DOCKER = "/run/user/991/docker.sock"
_ROOTLESS = "/run/user/991/dockerd-rootless/api.sock"
_NETWORK = "omnilyzer-analytics-backend-dev"
_PREFIX = "omnilyzer-analytics-dev-analytics-"
_IMAGE_PREFIX = "oci-dev.omnilyzer.ai/omnilyzer/analytics@"
_CANARY = {
    "proto": "tcp4", "parentIP": "127.0.0.1", "parentPort": 3020,
    "childIP": "127.0.0.1", "childPort": 3020,
}
_ACTIVE_PORT = 3141
_MAX_RESPONSE = 262144
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_INSPECT = re.compile(r"/images/sha256:[0-9a-f]{64}/json\Z")
_READ_PATHS = frozenset({
    (_ROOTLESS, "/v1/info"),
    (_ROOTLESS, "/v1/ports"),
    (_DOCKER, "/networks/" + _NETWORK),
    (_DOCKER, "/containers/" + _PREFIX + "blue-1/json"),
    (_DOCKER, "/containers/" + _PREFIX + "green-1/json"),
})
ERROR = "TASK014_ANALYTICS_ACTIVE_STATE_UNVERIFIED"


class AnalyticsActiveStateDenied(Exception):
    """No independently verified private active image and forwarding."""


@dataclass(frozen=True, slots=True)
class AnalyticsActiveState:
    """Live read-only observation, NOT a release/deployment authorization."""

    schema_version: int
    active_slot: str
    active_digest: str
    active_image: str
    active_container_id: str
    active_child_ip: str
    active_network_id: str
    private_ingress_port: int
    candidate_slot: str
    candidate_port: int
    candidate_probe_present: bool = False
    candidate_digest: str | None = None
    candidate_container_id: str | None = None
    read_only: bool = True
    deployment_authorized: bool = False


# Section 2: bounded, duplicate-safe JSON reads through ONLY fixed Unix
# socket paths. Even error text and Docker Config.Env are never returned.
class _UnixConnection(http.client.HTTPConnection):
    """HTTP over one already approved local Unix socket, never TCP/DNS."""

    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=3)
        self._unix_path = path

    def connect(self) -> None:
        """Connect to the fixed AF_UNIX socket with a strict timeout."""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(self._unix_path)


def _json_bytes(raw: bytes) -> object:
    """Reject oversized, ambiguous, nonfinite and malformed API objects."""
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RESPONSE:
        raise ValueError("bounded rootless response required")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate API member")
            result[key] = value
        return result

    return json.loads(
        raw.decode("utf-8"), object_pairs_hook=unique,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError),
    )


def _unix_get(endpoint: str, resource: str) -> object | None:
    """One read-only API GET, never a mutating method, shell or credential."""
    if (
        (endpoint, resource) not in _READ_PATHS
        and not (
            endpoint == _DOCKER and type(resource) is str
            and _IMAGE_INSPECT.fullmatch(resource) is not None
        )
    ):
        raise ValueError("unreviewed active-state endpoint")
    info = os.stat(endpoint, follow_symlinks=False)
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != 991
        or stat.S_IMODE(info.st_mode) & 0o002
    ):
        raise ValueError("untrusted rootless socket")
    conn = _UnixConnection(endpoint)
    try:
        conn.request("GET", resource, headers={"Accept": "application/json"})
        reply = conn.getresponse()
        raw = reply.read(_MAX_RESPONSE + 1)
        if reply.status == 404 and endpoint == _DOCKER and resource.startswith(
            "/containers/" + _PREFIX
        ):
            if raw and len(raw) > 512:
                raise ValueError("unbounded missing-container response")
            return None
        if reply.status != 200:
            raise ValueError("private rootless API denied")
        return _json_bytes(raw)
    finally:
        conn.close()


# Section 3: prove exactly which live hardened Analytics container matches
# the *actual* forwarding child IP. No request, cache or file ledger is trusted.
def _container_identity(
    raw: object, *, slot: str, network_id: str,
) -> tuple[str, str, str] | None:
    """Validate running slot's digest, hardening, network and bind profile."""
    if raw is None:
        return None
    if type(raw) is not dict:
        raise ValueError("Docker container shape")
    state, config, host, settings = (
        raw.get("State"), raw.get("Config"), raw.get("HostConfig"),
        raw.get("NetworkSettings"),
    )
    if not all(type(item) is dict for item in (state, config, host, settings)):
        raise ValueError("Docker container metadata")
    if state.get("Running") is not True:
        return None
    image = config.get("Image")
    if type(image) is not str or not image.startswith(_IMAGE_PREFIX):
        raise ValueError("unexpected product image")
    digest = validate_digest(image[len(_IMAGE_PREFIX):])
    if digest == "sha256:" + "0" * 64:
        raise ValueError("invalid zero OCI digest")
    # Historical signed 0.15.0 blue keeps its installed Docker port3141.
    # Future successor blue/green containers use the separately reviewed
    # Compose reset override: NO Docker host-published ports whatsoever.
    # RootlessKit alone owns stable 3141 and temporary candidate 3142.
    historical_blue = (slot == "blue" and digest == PINNED_DIGEST)
    bindings = host.get("PortBindings")
    if historical_blue:
        valid_bindings = bindings == {
            "3000/tcp": [{
                "HostIp": "127.0.0.1", "HostPort": "3141",
            }],
        }
    else:
        valid_bindings = bindings in (None, {})
    identifier = raw.get("Id")
    health = state.get("Health")
    if (
        (digest == PINNED_DIGEST and not historical_blue)
        or type(identifier) is not str
        or _HEX64.fullmatch(identifier) is None
        or raw.get("Name") != "/" + _PREFIX + slot + "-1"
        or config.get("User") != "10001:10001"
        or type(health) is not dict or health.get("Status") != "healthy"
        or host.get("ReadonlyRootfs") is not True
        or host.get("Privileged") is not False
        or host.get("CapDrop") != ["ALL"]
        or host.get("SecurityOpt") != ["no-new-privileges:true"]
        or not valid_bindings
        or settings.get("Ports") != {"3000/tcp": None}
    ):
        raise ValueError("unreviewed Analytics container")
    nets = settings.get("Networks")
    if type(nets) is not dict or set(nets) != {_NETWORK}:
        raise ValueError("nonisolated Analytics attachment")
    entry = nets[_NETWORK]
    if type(entry) is not dict or entry.get("NetworkID") != network_id:
        raise ValueError("wrong Analytics network")
    ip = entry.get("IPAddress")
    try:
        address = ipaddress.ip_address(ip)
        if not (
            type(address) is ipaddress.IPv4Address
            and address.is_private and not address.is_loopback
            and not address.is_link_local and not address.is_unspecified
            and not address.is_reserved and not address.is_multicast
        ):
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("untrusted internal Docker address") from None
    return digest, identifier, str(address)


def _active_state(
    *, info: object, network: object, ports: object,
    blue: object, green: object,
) -> AnalyticsActiveState:
    """Correlate rootless route with running Docker image and exact network."""
    if (
        type(info) is not dict
        or info.get("version") != "3.1.0"
        or info.get("apiVersion") != "1.1.2"
        or type(info.get("portDriver")) is not dict
        or info["portDriver"].get("driver") != "builtin"
        or type(info["portDriver"].get("protos")) is not list
        or "tcp4" not in info["portDriver"]["protos"]
        or type(info.get("networkDriver")) is not dict
        or info["networkDriver"].get("driver") != "slirp4netns"
        or type(network) is not dict
        or network.get("Name") != _NETWORK
        or network.get("Driver") != "bridge"
        or network.get("Internal") is not True
        or type(network.get("Id")) is not str
        or _HEX64.fullmatch(network["Id"]) is None
        or type(ports) is not list
        or len(ports) not in (2, 3)
    ):
        raise ValueError("unreviewed rootless configuration")
    network_id = network["Id"]
    candidates = {
        "blue": _container_identity(blue, slot="blue", network_id=network_id),
        "green": _container_identity(green, slot="green", network_id=network_id),
    }
    if any(
        type(rule) is not dict
        or type(rule.get("id")) is not int
        or rule["id"] < 1
        or type(rule.get("spec")) is not dict
        for rule in ports
    ):
        raise ValueError("invalid port rules")
    if len({rule["id"] for rule in ports}) != len(ports):
        raise ValueError("duplicate port rule")
    canary = [p for p in ports if p["spec"] == _CANARY]
    ingress = [
        p["spec"] for p in ports
        if p["spec"].get("parentPort") == _ACTIVE_PORT
    ]
    probes = [
        p["spec"] for p in ports
        if p["spec"].get("parentPort") == ANALYTICS_SUCCESSOR_CANDIDATE_PORT
    ]
    if (
        len(canary) != 1 or len(ingress) != 1
        or len(probes) != len(ports) - 2
        or len(probes) > 1
    ):
        raise ValueError("Canary/Analytics/candidate routing changed")
    rule = ingress[0]
    if (
        rule.get("proto") != "tcp4"
        or rule.get("parentIP") != "127.0.0.1"
        or type(rule.get("parentPort")) is not int
        or rule["parentPort"] != _ACTIVE_PORT
        or type(rule.get("childPort")) is not int
        or rule["childPort"] != 3000
        or type(rule.get("childIP")) is not str
        or set(rule) != {
            "proto", "parentIP", "parentPort", "childIP", "childPort",
        }
    ):
        raise ValueError("public or unreviewed forwarding")
    matching = [
        (slot, candidate)
        for slot, candidate in candidates.items()
        if candidate is not None and candidate[2] == rule["childIP"]
    ]
    if len(matching) != 1:
        raise ValueError("active route/image ambiguous")
    active_slot, (digest, identifier, _ip) = matching[0]
    # Keep a healthy, signed historical blue as a standby rollback target.
    # Its Docker HostConfig advertises 3141, but the original approved DEV
    # acceptance proved that the internal=true network does NOT publish a
    # second host listener. The actual RootlessKit 3141 rule, not this
    # metadata, determines which image is serving. Reject ambiguous child
    # IP matching above; do not discard a viable rollback container.
    candidate_slot = "green" if active_slot == "blue" else "blue"
    candidate = candidates[candidate_slot]
    probe_present = bool(probes)
    if probe_present:
        probe = probes[0]
        if (
            set(probe) != {
                "proto", "parentIP", "parentPort", "childIP", "childPort",
            }
            or probe.get("proto") != "tcp4"
            or probe.get("parentIP") != "127.0.0.1"
            or type(probe.get("parentPort")) is not int
            or probe["parentPort"] != ANALYTICS_SUCCESSOR_CANDIDATE_PORT
            or type(probe.get("childPort")) is not int
            or probe["childPort"] != 3000
            or candidate is None
            or probe.get("childIP") != candidate[2]
            or candidate[2] == rule["childIP"]
            or candidate[0] == digest
        ):
            raise ValueError("candidate port not bound to distinct verified image")
    return AnalyticsActiveState(
        schema_version=1, active_slot=active_slot,
        active_digest=digest, active_image=_IMAGE_PREFIX + digest,
        active_container_id=identifier, active_child_ip=_ip,
        active_network_id=network_id,
        private_ingress_port=_ACTIVE_PORT,
        candidate_slot=candidate_slot,
        candidate_port=ANALYTICS_SUCCESSOR_CANDIDATE_PORT,
        candidate_probe_present=probe_present,
        candidate_digest=candidate[0] if probe_present else None,
        candidate_container_id=candidate[1] if probe_present else None,
    )


# Section 4: the local OCI image and optional candidate route must be real.
def _check_local_image(container: object, expected: str) -> None:
    """Reject a spoofed Docker Config.Image using actual image RepoDigests."""
    if type(container) is not dict:
        raise ValueError("missing running image")
    image_id = container.get("Image")
    if (
        type(image_id) is not str
        or not image_id.startswith("sha256:")
        or _HEX64.fullmatch(image_id[7:]) is None
    ):
        raise ValueError("unreviewed local image ID")
    image = _unix_get(_DOCKER, "/images/" + image_id + "/json")
    if (
        type(image) is not dict
        or image.get("Id") != image_id
        or image.get("RepoDigests") != [expected]
        or image.get("Os") != "linux"
        or image.get("Architecture") != "amd64"
    ):
        raise ValueError("local image differs from immutable digest")


def _candidate_health() -> None:
    """Verify the private 3142 candidate, never follow redirects or send auth."""
    for path in ("/readyz", "/livez"):
        connection = http.client.HTTPConnection(
            "127.0.0.1", ANALYTICS_SUCCESSOR_CANDIDATE_PORT, timeout=3,
        )
        try:
            connection.request(
                "GET", path, headers={"Cache-Control": "no-store"},
            )
            response = connection.getresponse()
            response.read(2049)
            if response.status != 200:
                raise ValueError("unhealthy successor candidate")
        finally:
            connection.close()


# Section 5: authorized rootless executor or root-host preflight only.
def inspect_analytics_active_state() -> AnalyticsActiveState:
    """Observe real local Docker+RootlessKit, without trusting CI slot hints.

    Broker independently verifies OIDC and signatures but has NO rootless
    socket access. The socket-activated executor (UID991) must inspect the
    live host, reconciling the previously signed release and reobserving
    immediately before any mutation. This snapshot gives NO permission.
    """
    try:
        # The installed socket-activated Analytics executor runs as UID991,
        # not as Linux root; the independently managed root user may also run
        # a separately authorized read-only host preflight. The deployment
        # broker uses a different UID and MUST NOT gain rootless Docker API
        # access. Reject every other principal before the first socket read.
        if os.geteuid() not in (0, 991):
            raise ValueError("rootless executor or root preflight required")
        info = _unix_get(_ROOTLESS, "/v1/info")
        ports = _unix_get(_ROOTLESS, "/v1/ports")
        network = _unix_get(_DOCKER, "/networks/" + _NETWORK)
        blue = _unix_get(_DOCKER, "/containers/" + _PREFIX + "blue-1/json")
        green = _unix_get(_DOCKER, "/containers/" + _PREFIX + "green-1/json")
        observed = _active_state(
            info=info, network=network, ports=ports,
            blue=blue, green=green,
        )
        # Docker Config.Image is NOT sufficient provenance. Independently
        # verify local image ID + immutable RepoDigests for active and, when
        # staged, candidate. The candidate must also answer over its OWN
        # private RootlessKit 3142 route before any later switchover.
        active_container = blue if observed.active_slot == "blue" else green
        _check_local_image(active_container, observed.active_image)
        if observed.candidate_probe_present:
            candidate_container = (
                green if observed.candidate_slot == "green" else blue
            )
            _check_local_image(
                candidate_container, _IMAGE_PREFIX + observed.candidate_digest,
            )
            _candidate_health()
        # Re-read forwarding at end of other socket reads. A route changing
        # during inspection is a hard failure. No mutable active ledger used.
        if _unix_get(_ROOTLESS, "/v1/ports") != ports:
            raise ValueError("forwarding changed during inspection")
        return observed
    except Exception:
        raise AnalyticsActiveStateDenied(ERROR) from None


# Section 6: read-only restart reconciliation against externally reviewed
# exact current release authority. This cannot issue a deployment grant.
def inspect_committed_analytics_route(
    *, journal: object, reviewed_image: str, reviewed_slot: str,
    reviewed_container_id: str, reviewed_request_sha256: str,
) -> AnalyticsActiveState:
    """Confirm a durable completed route still serves the reviewed image.

    The expected OCI, container, slot and request SHA MUST come from a
    separately protected, independently verified signed release/replay
    source. They are NOT authenticated by this function, a journal record,
    a type-checked dataclass, or the caller's request. The live UID991
    supervisor would use this only AFTER its source authority is accepted.
    Original signed 0.15.0 without a successor journal uses its ORIGINAL
    supervisor, and is not grandfathered into the new route mode.
    """
    from .analytics_route_journal import (
        AnalyticsRouteJournal, ROUTE_JOURNAL_DIRECTORY,
    )

    try:
        if (
            os.geteuid() not in (0, 991)
            or type(journal) is not AnalyticsRouteJournal
            or object.__getattribute__(journal, "_directory")
                != ROUTE_JOURNAL_DIRECTORY
            or type(reviewed_image) is not str
            or not reviewed_image.startswith(_IMAGE_PREFIX + "sha256:")
            or _HEX64.fullmatch(
                reviewed_image[len(_IMAGE_PREFIX + "sha256:"):]
            ) is None
            or reviewed_image == _IMAGE_PREFIX + "sha256:" + "0" * 64
            or type(reviewed_slot) is not str
            or reviewed_slot not in ("blue", "green")
            or type(reviewed_container_id) is not str
            or _HEX64.fullmatch(reviewed_container_id) is None
            or type(reviewed_request_sha256) is not str
            or _HEX64.fullmatch(reviewed_request_sha256) is None
            or reviewed_request_sha256 == "0" * 64
        ):
            raise ValueError("unreviewed restart authority")
        with journal.exclusive():
            record = journal.read()
            if type(record) is not dict:
                raise ValueError("missing durable transition")
            phase = record.get("phase")
            if phase not in ("switched", "restored"):
                raise ValueError("interrupted transition requires recovery")
            prefix = "next_" if phase == "switched" else "previous_"
            if (
                record.get("request_sha256") != reviewed_request_sha256
                or record.get(prefix + "slot") != reviewed_slot
                or record.get(prefix + "image") != reviewed_image
                or record.get(prefix + "container_id") != reviewed_container_id
            ):
                raise ValueError("journal differs from reviewed signed release")
            live = inspect_analytics_active_state()
            if (
                type(live) is not AnalyticsActiveState
                or live.schema_version != 1
                or live.deployment_authorized is not False
                or live.read_only is not True
                or live.private_ingress_port != 3141
                or live.active_slot != reviewed_slot
                or live.active_image != reviewed_image
                or live.active_container_id != reviewed_container_id
                or live.active_child_ip != record[prefix + "ip"]
                or journal.read() != record
            ):
                raise ValueError("active OCI or ingress does not match journal")
            return live
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise AnalyticsActiveStateDenied(ERROR) from None


__all__ = (
    "AnalyticsActiveState", "AnalyticsActiveStateDenied",
    "inspect_analytics_active_state", "inspect_committed_analytics_route",
)
