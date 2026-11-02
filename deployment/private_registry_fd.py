"""File: deployment/private_registry_fd.py

Purpose: Linux-only, request-scoped sealed-memory transfer of an already
cryptographically verified Zot read credential from broker to executor.
Original Task014 canary default is unchanged; explicitly scoped Analytics
mode permits ONLY the one reviewed, immutable signed 0.15.0 digest.
Related: deployment/registry_oidc_credentials.py, deployment/unix_transport.py,
deployment/executor_server.py, deployment/docker_runtime.py,
deployment/analytics_promotion_broker.py and deployment/tests/test_private_registry_fd.py.

Sections: exact credential policy; sealed FD lifecycle; SCM_RIGHTS framing.
This low-level module neither verifies a JWT signature nor authorizes a
promotion. Callers must authenticate broker SO_PEERCRED and validate the
GitHub OIDC JWT before handing it to this boundary. Import is inert: no
network, Docker, replay, filesystem mutation, or service activation.
"""

from __future__ import annotations

from array import array
import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import time

OCI_PREFIX = "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:"
# Exact digest, not an Analytics repository prefix or tag/wildcard.
ANALYTICS_IMAGE = (
    "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
    "6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1"
)
OCI_HOST = "oci-dev.omnilyzer.ai"
MAX_TOKEN_BYTES = 8192
MAX_ENVELOPE_BYTES = 9216
MAX_LIFETIME_SECONDS = 300
_MIN_LIFETIME_SECONDS = 1
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEALS = (
    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
)
_FD_SIZE = array("i").itemsize


class PrivateRegistryTransferError(Exception):
    """One redacted error for rejected ancillary data and sealed credentials."""


class ScopedReadCredential:
    """Immutable, nonserializable view of a token for one pinned OCI image."""

    __slots__ = ("_token", "expires_at", "image", "request_sha256")

    def __init__(self, token: str, expires_at: int, image: str, request_sha256: str) -> None:
        # The object is constructed only through verified envelope validation.
        object.__setattr__(self, "_token", token)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "image", image)
        object.__setattr__(self, "request_sha256", request_sha256)

    def __setattr__(self, name: str, value: object) -> None:
        """Prevent supported mutation of credential identity or expiry."""
        raise AttributeError("immutable credential")

    def __repr__(self) -> str:
        """Never expose JWT bytes in normal diagnostic output."""
        return "<ScopedReadCredential redacted>"

    def __reduce__(self) -> object:
        """Do not serialize short-lived credentials."""
        raise TypeError("credentials cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        """Do not serialize short-lived credentials."""
        raise TypeError("credentials cannot be serialized")

    @property
    def token(self) -> str:
        """Return credential bytes only to the explicitly authorized Docker adapter."""
        return object.__getattribute__(self, "_token")


# Section 1: exact schema, image, request digest and clock policy.
def _normalize(token: object, expires_at: object, image: object,
               request_sha256: object, now: object,
               *, product_id: str = "canary") -> ScopedReadCredential:
    """Reject all out-of-scope, stale, overlong or unbound credentials.

    Original canary callers use the unmodified default. Analytics is a
    separate, EXPLICIT version+digest, never a general repository allowlist.
    """
    canary = (type(product_id) is str and product_id == "canary"
              and type(image) is str and image.startswith(OCI_PREFIX)
              and _SHA256.fullmatch(image[len(OCI_PREFIX):]) is not None)
    analytics = (type(product_id) is str and product_id == "analytics"
                 and type(image) is str and image == ANALYTICS_IMAGE)
    if (not (canary or analytics)
            or type(token) is not str or not 1 <= len(token) <= MAX_TOKEN_BYTES
            or not token.isascii() or any(ord(x) < 33 or ord(x) > 126 for x in token)
            or type(expires_at) is not int or type(now) is not int
            or not _MIN_LIFETIME_SECONDS <= expires_at - now <= MAX_LIFETIME_SECONDS
            or type(request_sha256) is not str
            or _SHA256.fullmatch(request_sha256) is None):
        raise PrivateRegistryTransferError("invalid private registry authority")
    return ScopedReadCredential(token, expires_at, image, request_sha256)


def _envelope(credential: ScopedReadCredential) -> bytes:
    """Encode exactly the fixed, token-containing volatile message."""
    return (json.dumps({
        "expires_at": credential.expires_at,
        "host": OCI_HOST,
        "image": credential.image,
        "request_sha256": credential.request_sha256,
        "schema_version": 1,
        "token": credential.token,
    }, separators=(",", ":"), sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


# Section 2: create, seal, inspect, and close broker-owned ephemeral memfds.
def create_sealed_credential(token: str, *, expires_at: int, image: str,
                             canonical_request: bytes, now: int | None = None,
                             product_id: str = "canary") -> int:
    """Build one CLOEXEC sealed memfd; original canary default unchanged.

    Analytics requires an explicit product_id and the exact signed 0.15.0
    digest. Creating a file descriptor does NOT authorize a deployment;
    the root-owned executor must independently validate the signed request.
    """
    if type(canonical_request) is not bytes or not canonical_request or len(canonical_request) > 65536:
        raise PrivateRegistryTransferError("invalid private registry authority")
    current = int(time.time()) if now is None else now
    credential = _normalize(token, expires_at, image,
                            hashlib.sha256(canonical_request).hexdigest(), current,
                            product_id=product_id)
    raw = _envelope(credential)
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise PrivateRegistryTransferError("invalid private registry authority")
    fd = -1
    try:
        fd = os.memfd_create("omnilyzer-zot-read", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        if os.write(fd, raw) != len(raw):
            raise OSError("short memfd write")
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _SEALS)
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & _SEALS != _SEALS:
            raise OSError("unsealed memory")
        return fd
    except Exception:
        if fd >= 0:
            os.close(fd)
        raise PrivateRegistryTransferError("private registry handoff unavailable") from None


def read_sealed_credential(fd: int, *, canonical_request: bytes,
                            image: str, now: int | None = None,
                            product_id: str = "canary") -> ScopedReadCredential:
    """Validate sealed descriptor, exact product, digest and request binding.

    The original canary-only default also refuses Analytics envelopes.
    """
    try:
        if type(fd) is not int or fd < 0 or type(canonical_request) is not bytes                 or not canonical_request or len(canonical_request) > 65536:
            raise ValueError("invalid fd or request")
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size <= 0
                or info.st_size > MAX_ENVELOPE_BYTES or info.st_nlink != 0
                or fcntl.fcntl(fd, fcntl.F_GET_SEALS) & _SEALS != _SEALS):
            raise ValueError("invalid sealed fd metadata")
        raw = os.pread(fd, info.st_size + 1, 0)
        if len(raw) != info.st_size or not raw.endswith(b"\n"):
            raise ValueError("invalid message framing")
        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            """Reject duplicated envelope keys rather than last-value-wins parsing."""
            value: dict[str, object] = {}
            for key, part in pairs:
                if key in value:
                    raise ValueError("duplicate envelope key")
                value[key] = part
            return value
        value = json.loads(raw, object_pairs_hook=unique)
        if type(value) is not dict or set(value) != {
            "expires_at", "host", "image", "request_sha256", "schema_version", "token"
        } or value["schema_version"] != 1 or type(value["schema_version"]) is not int                 or value["host"] != OCI_HOST or type(value["host"]) is not str:
            raise ValueError("incorrect registry schema")
        current = int(time.time()) if now is None else now
        credential = _normalize(value["token"], value["expires_at"], value["image"],
                                value["request_sha256"], current,
                                product_id=product_id)
        if (credential.image != image or
                credential.request_sha256 != hashlib.sha256(canonical_request).hexdigest()
                or _envelope(credential) != raw):
            raise ValueError("request/image envelope mismatch")
        return credential
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise PrivateRegistryTransferError("private registry handoff unavailable") from None


# Section 3: exact one-FD SCM_RIGHTS transfer in the existing AF_UNIX stream.
def send_sealed_header(sock: socket.socket, header: bytes, fd: int) -> None:
    """Send four framing bytes and exactly one sealed descriptor atomically."""
    if type(header) is not bytes or len(header) != 4 or type(fd) is not int or fd < 0:
        raise PrivateRegistryTransferError("invalid private registry frame")
    try:
        rights = array("i", (fd,))
        if sock.sendmsg([header], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    rights.tobytes())]) != 4:
            raise OSError("partial ancillary header")
    except Exception:
        raise PrivateRegistryTransferError("private registry handoff unavailable") from None


def receive_sealed_header(sock: socket.socket) -> tuple[bytes, int]:
    """Receive first four stream bytes plus exactly one CLOEXEC descriptor.

    Caller must close the returned descriptor. All descriptors received on any
    invalid packet are closed before reporting a redacted error.
    """
    received: list[int] = []
    try:
        message, ancillaries, flags, _ = sock.recvmsg(
            4, socket.CMSG_SPACE(_FD_SIZE * 4), socket.MSG_CMSG_CLOEXEC
        )
        for level, kind, payload in ancillaries:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS                     or len(payload) % _FD_SIZE:
                raise ValueError("invalid ancillary")
            received.extend(array("i", payload).tolist())
        if (len(message) != 4 or len(received) != 1
                or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)):
            raise ValueError("incomplete ancillary request")
        return message, received.pop()
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise PrivateRegistryTransferError("private registry handoff unavailable") from None
    finally:
        for candidate in received:
            try:
                os.close(candidate)
            except OSError:
                pass


def _close_received_credential(fd: int) -> None:
    """Close one executor-owned received descriptor without inspecting secrets."""
    os.close(fd)


__all__ = (
    "PrivateRegistryTransferError", "ScopedReadCredential",
    "create_sealed_credential", "read_sealed_credential",
    "send_sealed_header", "receive_sealed_header",
)
