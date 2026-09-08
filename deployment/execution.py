"""Closed broker-to-executor request and privilege-boundary contracts.

There is deliberately no server, socket, process, Docker, Compose, Nginx, or
filesystem implementation here.  A later privileged executor must parse these
canonical bytes and call :meth:`ExecutorRequest.from_dict` again; locality is
not authorization.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit

from .identity import (
    AuthorizedGitHubIdentity,
    DEV_REPOSITORY_ID,
    DEV_WORKFLOW_REF,
    MAX_TOKEN_LIFETIME_SECONDS,
    ReplayGuard,
    validate_jti,
)
from .policy import (
    APPROVED_OCI_ORIGIN,
    DeploymentPolicyError,
    canonical_bytes,
    exact_image_reference,
    validate_digest,
    validate_sha256,
    validate_source_sha,
    validate_semver,
)


EXECUTION_SCHEMA_VERSION = 1
ALLOWED_OPERATIONS = ("deploy",)
DEV_STAGE = "dev"
DEV_OCI_REPOSITORY = "omnilyzer/task013-release-canary"
RUNTIME_CONFIGURATION_PATH = "deployment/runtime/dev/canary-runtime.json"
NO_SECRETS_REASON = "task014-synthetic-canary-has-no-runtime-secrets"
DEV_LOOPBACK_ADDRESS = "127.0.0.1"
DEV_LOOPBACK_PORT = 3020
DEV_PUBLIC_ORIGIN = "https://canary-dev.omnilyzer.ai"
INGRESS_PATHS = (
    "deployment/runtime/dev/compose.yaml",
    "deployment/runtime/dev/host-nginx.conf",
    "deployment/runtime/dev/nginx/nginx.conf",
)

REFERENCE_FIELDS = {
    "schema_version", "kind", "repository_id", "reviewed_commit", "path", "sha256",
}
SECRETS_REFERENCE_FIELDS = {"schema_version", "kind", "required", "reason"}
INGRESS_FILE_FIELDS = {"path", "sha256"}
INGRESS_REFERENCE_FIELDS = {
    "schema_version", "kind", "repository_id", "reviewed_commit", "files",
    "loopback_address", "loopback_port", "public_origin",
}
EXECUTOR_REQUEST_FIELDS = {
    "schema_version", "operation", "stage", "release_version", "source_sha",
    "oci_origin", "oci_repository", "manifest_digest", "exact_image_reference",
    "release_manifest_sha256", "provenance_sha256", "originating_release_run_id",
    "promotion_request_sha256", "requested_by_actor_id", "github_repository_id",
    "github_workflow_ref", "github_workflow_sha", "github_run_id",
    "github_run_attempt", "oidc_jti", "oidc_issued_at", "oidc_expires_at",
    "runtime_configuration_reference", "secrets_reference", "ingress_reference",
}
MAX_IDENTIFIER = 2**63 - 1
MAX_CANONICAL_REQUEST_BYTES = 64 * 1024


class ExecutorRequestError(DeploymentPolicyError):
    """A broker-to-executor request is outside the DEV allowlist."""


def _closed(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExecutorRequestError(f"{context} must be an object")
    actual = set(value)
    if actual != fields:
        raise ExecutorRequestError(
            f"{context} fields differ: missing={sorted(fields-actual)} "
            f"unknown={sorted(actual-fields)}"
        )
    return value


def _positive_integer(value: Any, context: str) -> int:
    if (isinstance(value, bool) or not isinstance(value, int)
            or not 1 <= value <= MAX_IDENTIFIER):
        raise ExecutorRequestError(f"{context} must be a bounded positive integer")
    return value


def _sha256(value: Any, context: str) -> str:
    try:
        return validate_sha256(value, context)
    except DeploymentPolicyError as exc:
        raise ExecutorRequestError(str(exc)) from exc


def _source_sha(value: Any, context: str) -> str:
    try:
        return validate_source_sha(value)
    except DeploymentPolicyError as exc:
        raise ExecutorRequestError(f"{context} is not an exact source revision") from exc


@dataclass(frozen=True)
class RuntimeConfigurationReference:
    schema_version: int
    kind: str
    repository_id: int
    reviewed_commit: str
    path: str
    sha256: str

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimeConfigurationReference":
        data = _closed(value, REFERENCE_FIELDS, "runtime configuration reference")
        if data["schema_version"] != EXECUTION_SCHEMA_VERSION:
            raise ExecutorRequestError("runtime reference schema version is unsupported")
        if data["kind"] != "repository-blob-sha256":
            raise ExecutorRequestError("runtime reference kind is unsupported")
        repository_id = _positive_integer(data["repository_id"], "runtime repository_id")
        if repository_id != DEV_REPOSITORY_ID:
            raise ExecutorRequestError("runtime reference repository is not authorized")
        if data["path"] != RUNTIME_CONFIGURATION_PATH:
            raise ExecutorRequestError("runtime reference path is not authorized")
        return cls(
            EXECUTION_SCHEMA_VERSION, data["kind"], repository_id,
            _source_sha(data["reviewed_commit"], "runtime reviewed_commit"),
            data["path"], _sha256(data["sha256"], "runtime sha256"),
        )


@dataclass(frozen=True)
class NoSecretsReference:
    schema_version: int
    kind: str
    required: tuple[()]
    reason: str

    @classmethod
    def from_dict(cls, value: Any) -> "NoSecretsReference":
        data = _closed(value, SECRETS_REFERENCE_FIELDS, "secrets reference")
        if (data["schema_version"] != EXECUTION_SCHEMA_VERSION
                or data["kind"] != "none" or data["required"] != []
                or data["reason"] != NO_SECRETS_REASON):
            raise ExecutorRequestError("synthetic DEV canary requires the exact no-secrets reference")
        return cls(EXECUTION_SCHEMA_VERSION, "none", (), NO_SECRETS_REASON)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "kind": self.kind,
            "required": [], "reason": self.reason,
        }


@dataclass(frozen=True)
class IngressFileReference:
    path: str
    sha256: str

    @classmethod
    def from_dict(cls, value: Any) -> "IngressFileReference":
        data = _closed(value, INGRESS_FILE_FIELDS, "ingress file reference")
        if not isinstance(data["path"], str):
            raise ExecutorRequestError("ingress file path must be a string")
        return cls(data["path"], _sha256(data["sha256"], "ingress file sha256"))


@dataclass(frozen=True)
class IngressReference:
    schema_version: int
    kind: str
    repository_id: int
    reviewed_commit: str
    files: tuple[IngressFileReference, ...]
    loopback_address: str
    loopback_port: int
    public_origin: str

    @classmethod
    def from_dict(cls, value: Any) -> "IngressReference":
        data = _closed(value, INGRESS_REFERENCE_FIELDS, "ingress reference")
        if data["schema_version"] != EXECUTION_SCHEMA_VERSION:
            raise ExecutorRequestError("ingress reference schema version is unsupported")
        if data["kind"] != "repository-file-set-sha256":
            raise ExecutorRequestError("ingress reference kind is unsupported")
        repository_id = _positive_integer(data["repository_id"], "ingress repository_id")
        if repository_id != DEV_REPOSITORY_ID:
            raise ExecutorRequestError("ingress reference repository is not authorized")
        raw_files = data["files"]
        if not isinstance(raw_files, list):
            raise ExecutorRequestError("ingress files must be an array")
        files = tuple(IngressFileReference.from_dict(item) for item in raw_files)
        paths = tuple(item.path for item in files)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ExecutorRequestError("ingress files must be sorted and unique")
        if paths != INGRESS_PATHS:
            raise ExecutorRequestError("ingress files differ from the DEV allowlist")
        try:
            address = str(ipaddress.ip_address(data["loopback_address"]))
        except (TypeError, ValueError) as exc:
            raise ExecutorRequestError("ingress address is invalid") from exc
        if address != DEV_LOOPBACK_ADDRESS or not ipaddress.ip_address(address).is_loopback:
            raise ExecutorRequestError("ingress address is not the reviewed loopback")
        port = _positive_integer(data["loopback_port"], "ingress loopback_port")
        if port != DEV_LOOPBACK_PORT:
            raise ExecutorRequestError("ingress port is not authorized")
        if data["public_origin"] != DEV_PUBLIC_ORIGIN:
            raise ExecutorRequestError("ingress public origin is not authorized")
        parsed = urlsplit(data["public_origin"])
        if (parsed.scheme != "https" or parsed.netloc != "canary-dev.omnilyzer.ai"
                or parsed.path or parsed.query or parsed.fragment):
            raise ExecutorRequestError("ingress public origin is malformed")
        return cls(
            EXECUTION_SCHEMA_VERSION, data["kind"], repository_id,
            _source_sha(data["reviewed_commit"], "ingress reviewed_commit"),
            files, address, port, data["public_origin"],
        )


@dataclass(frozen=True)
class ExecutorRequest:
    schema_version: int
    operation: str
    stage: str
    release_version: str
    source_sha: str
    oci_origin: str
    oci_repository: str
    manifest_digest: str
    exact_image_reference: str
    release_manifest_sha256: str
    provenance_sha256: str
    originating_release_run_id: int
    promotion_request_sha256: str
    requested_by_actor_id: int
    github_repository_id: int
    github_workflow_ref: str
    github_workflow_sha: str
    github_run_id: int
    github_run_attempt: int
    oidc_jti: str
    oidc_issued_at: int
    oidc_expires_at: int
    runtime_configuration_reference: RuntimeConfigurationReference
    secrets_reference: NoSecretsReference
    ingress_reference: IngressReference

    @classmethod
    def from_dict(cls, value: Any) -> "ExecutorRequest":
        data = _closed(value, EXECUTOR_REQUEST_FIELDS, "executor request")
        if data["schema_version"] != EXECUTION_SCHEMA_VERSION:
            raise ExecutorRequestError("executor request schema version is unsupported")
        if data["operation"] not in ALLOWED_OPERATIONS:
            raise ExecutorRequestError("executor operation is unsupported")
        if data["stage"] != DEV_STAGE:
            raise ExecutorRequestError("executor stage is not authorized")
        try:
            release_version = validate_semver(data["release_version"])
            source_sha = validate_source_sha(data["source_sha"])
            digest = validate_digest(data["manifest_digest"])
        except DeploymentPolicyError as exc:
            raise ExecutorRequestError(str(exc)) from exc
        if data["oci_origin"] != APPROVED_OCI_ORIGIN:
            raise ExecutorRequestError("executor OCI origin is not authorized")
        if data["oci_repository"] != DEV_OCI_REPOSITORY:
            raise ExecutorRequestError("executor OCI repository is not authorized")
        expected_image = exact_image_reference(DEV_OCI_REPOSITORY, digest)
        if data["exact_image_reference"] != expected_image:
            raise ExecutorRequestError("exact image reference does not match its digest")
        repository_id = _positive_integer(
            data["github_repository_id"], "github_repository_id",
        )
        if repository_id != DEV_REPOSITORY_ID:
            raise ExecutorRequestError("GitHub repository ID is not authorized")
        if data["github_workflow_ref"] != DEV_WORKFLOW_REF:
            raise ExecutorRequestError("GitHub workflow identity is not authorized")
        issued_at = data["oidc_issued_at"]
        expires_at = data["oidc_expires_at"]
        for name, timestamp in (("oidc_issued_at", issued_at), ("oidc_expires_at", expires_at)):
            if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
                raise ExecutorRequestError(f"{name} must be a non-negative integer")
        if not 0 < expires_at - issued_at <= MAX_TOKEN_LIFETIME_SECONDS:
            raise ExecutorRequestError("executor OIDC lifetime is invalid")
        try:
            jti = validate_jti(data["oidc_jti"])
        except DeploymentPolicyError as exc:
            raise ExecutorRequestError(str(exc)) from exc
        return cls(
            EXECUTION_SCHEMA_VERSION, data["operation"], DEV_STAGE, release_version,
            source_sha, APPROVED_OCI_ORIGIN, DEV_OCI_REPOSITORY, digest, expected_image,
            _sha256(data["release_manifest_sha256"], "release_manifest_sha256"),
            _sha256(data["provenance_sha256"], "provenance_sha256"),
            _positive_integer(data["originating_release_run_id"], "originating_release_run_id"),
            _sha256(data["promotion_request_sha256"], "promotion_request_sha256"),
            _positive_integer(data["requested_by_actor_id"], "requested_by_actor_id"),
            repository_id, DEV_WORKFLOW_REF,
            _source_sha(data["github_workflow_sha"], "github_workflow_sha"),
            _positive_integer(data["github_run_id"], "github_run_id"),
            _positive_integer(data["github_run_attempt"], "github_run_attempt"),
            jti, issued_at, expires_at,
            RuntimeConfigurationReference.from_dict(data["runtime_configuration_reference"]),
            NoSecretsReference.from_dict(data["secrets_reference"]),
            IngressReference.from_dict(data["ingress_reference"]),
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["secrets_reference"] = self.secrets_reference.to_dict()
        return value

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def bind_request_to_identity(
    request: ExecutorRequest, identity: AuthorizedGitHubIdentity,
) -> None:
    """Reject a valid request that does not belong to its authorized token."""

    compared = (
        request.requested_by_actor_id == identity.actor_id,
        request.github_repository_id == identity.repository_id,
        request.github_workflow_ref == identity.workflow_ref,
        request.github_workflow_sha == identity.workflow_sha,
        request.github_run_id == identity.run_id,
        request.github_run_attempt == identity.run_attempt,
        request.oidc_jti == identity.jti,
        request.oidc_issued_at == identity.issued_at,
        request.oidc_expires_at == identity.expires_at,
    )
    if not all(compared):
        raise ExecutorRequestError("executor request does not bind its authorized OIDC identity")


def parse_canonical_request(raw: bytes) -> ExecutorRequest:
    """Parse, close, and re-canonicalize bytes at the privileged boundary."""

    if (not isinstance(raw, bytes) or not raw
            or len(raw) > MAX_CANONICAL_REQUEST_BYTES):
        raise ExecutorRequestError("canonical executor request has an invalid byte bound")
    try:
        text = raw.decode("ascii")

        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ExecutorRequestError("canonical executor request has duplicate keys")
                value[key] = item
            return value

        decoded = json.loads(text, object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutorRequestError("canonical executor request is not valid ASCII JSON") from exc
    request = ExecutorRequest.from_dict(decoded)
    if request.canonical_bytes() != raw:
        raise ExecutorRequestError("executor request bytes are not canonical")
    return request


class ExecutorTransport(Protocol):
    """Send canonical bytes over a local Unix-domain transport; never a command."""

    def send(self, canonical_request: bytes) -> bytes:
        ...


class DeploymentBroker(Protocol):
    """Authorize verified claims, consume replay, and forward canonical bytes."""

    def authorize_and_forward(
        self, *, cryptographically_verified_claims: Mapping[str, Any],
        received_at: int, request: ExecutorRequest, replay_guard: ReplayGuard,
        transport: ExecutorTransport,
    ) -> bytes:
        ...


class PrivilegedExecutor(Protocol):
    """Reparse and revalidate canonical bytes, then perform an approved operation."""

    def execute(self, canonical_request: bytes) -> bytes:
        ...
