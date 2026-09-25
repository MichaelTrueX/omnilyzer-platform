"""Inert, read-only Task 013 evidence acquisition for Task 014 DEV.

Credential providers and signature verification are injected. This module never
exchanges credentials, invokes a publisher, or starts a deployment.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import gzip
import hashlib
import http.client
import io
import ssl
import tarfile
import time
from typing import Any, Callable, Protocol

from .broker import IDENTITY_FIELDS, _normalize_identity
from .execution import (
    NO_SECRETS_REASON, ExecutorRequest,
    IngressReference, NoSecretsReference, RuntimeConfigurationReference,
    bind_request_to_identity,
)
from .identity import AuthorizedGitHubIdentity, authorize_verified_github_oidc
from .jwks import SYSTEM_CA_BUNDLE, parse_bounded_json
from .policy import (
    APPROVED_OCI_ORIGIN, DeploymentPolicyError, EXPECTED_CERTIFICATE_IDENTITY,
    EXPECTED_CERTIFICATE_ISSUER, EXPECTED_RELEASE_WORKFLOW, validate_digest,
    validate_semver, validate_sha256,
)
from .promotion import PromotionRequest, TrustedRelease, verify_release_evidence


ZOT_HOST = "oci-dev.omnilyzer.ai"
FORGEJO_HOST = "registry-dev.omnilyzer.ai"
REPOSITORY = "omnilyzer/task013-release-canary"
OCI_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
ARCHIVE_MEDIA_TYPE = "application/gzip"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_UNPACKED_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_HEADERS = 64
MAX_HEADER_BYTES = 16 * 1024
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 3.0
ERROR = "release consumer evidence is unavailable or invalid"

EVIDENCE_NAMES = frozenset({
    "release-manifest.json", "release-provenance.json",
    "release-manifest.sigstore.json", "release-provenance.sigstore.json",
})
ARCHIVE_NAMES = EVIDENCE_NAMES | frozenset({
    "release-plan.json", "build-manifest.json", "vulnerability-policy.json",
    "vulnerability-policy-result.json", "grype-db-status.json",
    "python-sbom.cdx.json", "npm-sbom.cdx.json", "oci-sbom.cdx.json",
    "python-grype.json", "npm-grype.json", "oci-grype.json",
})
MANIFEST_FIELDS = frozenset({
    "schema_version", "platform_version", "source_commit", "python", "npm",
    "oci", "sbom_sha256", "vulnerability_policy_sha256",
    "vulnerability_policy_result_sha256", "vulnerability_report_sha256",
    "grype_database_status_sha256", "release_plan_sha256",
    "build_manifest_sha256", "tool_versions", "evidence", "provenance", "signing",
})
PROVENANCE_FIELDS = frozenset({
    "schema_version", "statement_type", "claim", "platform_version",
    "source_commit", "execution", "subjects",
})


class ReleaseConsumerError(DeploymentPolicyError):
    """One fixed read-only consumer boundary failed closed."""


@dataclass(frozen=True, repr=False)
class ZotReadCredential:
    token: str
    expires_at: int


@dataclass(frozen=True, repr=False)
class ForgejoReadCredential:
    token: str
    expires_at: int


class ZotCredentialProvider(Protocol):
    def zot_read_credential(self) -> ZotReadCredential: ...


class ForgejoCredentialProvider(Protocol):
    def forgejo_read_credential(self) -> ForgejoReadCredential: ...


class ReleaseSignatureVerifier(Protocol):
    """Cryptographically verify the supplied exact blobs and exact OCI reference.

    The returned closed results are consumed by promotion.verify_release_evidence.
    A production implementation and its authority are a later reviewed phase.
    """

    def verify(
        self, manifest: bytes, provenance: bytes, manifest_bundle: bytes,
        provenance_bundle: bytes, image_reference: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]: ...


def _credential(value: object, expected_type: type, now: int) -> str:
    if (type(value) is not expected_type or type(now) is not int or now < 0
            or type(value.expires_at) is not int or not now < value.expires_at <= now + 300
            or type(value.token) is not str or not 1 <= len(value.token) <= 8192
            or not value.token.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in value.token)):
        raise ReleaseConsumerError(ERROR) from None
    return value.token


ConnectionFactory = Callable[[str, int, float, ssl.SSLContext], http.client.HTTPSConnection]


def _connection(host: str, port: int, timeout: float, context: ssl.SSLContext) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)


def _get(
    route: str, reference: str, token: str, factory: ConnectionFactory,
) -> tuple[bytes, dict[str, str]]:
    if route == "zot":
        host = ZOT_HOST
        path = f"/v2/{REPOSITORY}/manifests/{validate_digest(reference)}"
        media_type, limit = OCI_MEDIA_TYPE, MAX_MANIFEST_BYTES
    elif route == "forgejo":
        host = FORGEJO_HOST
        path = (
            "/api/packages/omnilyzer/generic/task013-release-evidence/"
            f"{validate_semver(reference)}/release-evidence.tar.gz"
        )
        media_type, limit = ARCHIVE_MEDIA_TYPE, MAX_ARCHIVE_BYTES
    else:
        raise ReleaseConsumerError(ERROR)
    connection = response = None
    failed = False
    close_failed = False
    body = b""
    normalized: dict[str, str] = {}
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=SYSTEM_CA_BUNDLE)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        started = time.monotonic()
        connection = factory(host, 443, CONNECT_TIMEOUT, context)
        connection.request("GET", path, None, {
            "Host": host, "Accept": media_type, "Authorization": "Bearer " + token,
        })
        response = connection.getresponse()
        headers = response.getheaders()
        if (time.monotonic() - started > CONNECT_TIMEOUT + READ_TIMEOUT
                or type(response.status) is not int or response.status != 200
                or type(headers) is not list or len(headers) > MAX_HEADERS):
            raise ValueError
        if any(
            type(name) is not str or not name or len(name) > 128
            or not name.isascii() or not name.replace("-", "").isalnum()
            or type(value) is not str or len(value) > MAX_HEADER_BYTES
            or not value.isascii() or any(ord(character) < 32 or ord(character) > 126 for character in value)
            for name, value in headers
        ):
            raise ValueError
        if sum(len(name) + len(value) + 4 for name, value in headers) > MAX_HEADER_BYTES:
            raise ValueError
        for name, value in headers:
            key = name.lower()
            if key in normalized:
                raise ValueError
            normalized[key] = value
        if (normalized.get("content-type") != media_type
                or "transfer-encoding" in normalized
                or "content-encoding" in normalized
                or "location" in normalized
                or not normalized.get("content-length", "").isdecimal()):
            raise ValueError
        length = int(normalized["content-length"])
        if not 0 < length <= limit or normalized["content-length"] != str(length):
            raise ValueError
        body = response.read(limit + 1)
        if (type(body) is not bytes or len(body) != length
                or time.monotonic() - started > CONNECT_TIMEOUT + READ_TIMEOUT):
            raise ValueError
    except Exception:
        failed = True
    finally:
        for item in (response, connection):
            if item is not None:
                try:
                    item.close()
                except Exception:
                    close_failed = True
    if failed or close_failed:
        raise ReleaseConsumerError(ERROR)
    return body, normalized


def _json(raw: bytes, fields: frozenset[str], *, schema: int | None = 1) -> dict[str, Any]:
    failed = False
    try:
        value = parse_bounded_json(
            raw, maximum_bytes=MAX_EVIDENCE_BYTES, maximum_root_members=len(fields),
            maximum_depth=12, maximum_nodes=4096, maximum_array=256,
            maximum_string=MAX_EVIDENCE_BYTES,
        )
        if set(value) != fields or (schema is not None and (
            type(value["schema_version"]) is not int or value["schema_version"] != schema
        )):
            raise ValueError
    except Exception:
        failed = True
    if failed:
        raise ReleaseConsumerError(ERROR)
    return value


def _archive(raw: bytes) -> dict[str, bytes]:
    failed = False
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as source:
            unpacked = source.read(MAX_UNPACKED_BYTES + 1)
        if len(unpacked) > MAX_UNPACKED_BYTES:
            raise ValueError
        result: dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) != len(ARCHIVE_NAMES) or {m.name for m in members} != ARCHIVE_NAMES:
                raise ValueError
            for member in members:
                if (not member.isfile() or member.size < 0
                        or member.size > MAX_UNPACKED_BYTES):
                    raise ValueError
                if member.name in EVIDENCE_NAMES:
                    if member.size > MAX_EVIDENCE_BYTES:
                        raise ValueError
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError
                    result[member.name] = stream.read(MAX_EVIDENCE_BYTES + 1)
                    if len(result[member.name]) != member.size:
                        raise ValueError
    except Exception:
        failed = True
    if failed:
        raise ReleaseConsumerError(ERROR)
    return result


def _hash_map(value: object) -> bool:
    if type(value) is not dict or set(value) != {"python", "npm", "oci"}:
        return False
    try:
        return all(validate_sha256(item, "evidence hash") == item for item in value.values())
    except DeploymentPolicyError:
        return False


def _artifact(value: object, expected_filename: str) -> bool:
    if type(value) is not dict or set(value) != {"filename", "sha256", "size"}:
        return False
    try:
        return (value["filename"] == expected_filename
                and validate_sha256(value["sha256"], "artifact hash") == value["sha256"]
                and type(value["size"]) is int and 0 < value["size"] <= 2**40)
    except DeploymentPolicyError:
        return False


class ZotCandidateConsumer:
    """GET exactly one digest-addressed Task 014 OCI manifest."""

    __slots__ = ("_provider", "_factory")

    def __init__(self, provider: ZotCredentialProvider, factory: ConnectionFactory = _connection):
        object.__setattr__(self, "_provider", provider)
        object.__setattr__(self, "_factory", factory)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("zot consumer collaborators are immutable")

    def acquire(self, request: PromotionRequest, *, now: int) -> bytes:
        request = _promotion(request)
        digest = validate_digest(request.manifest_digest)
        credential = None
        token = None
        failed = False
        try:
            credential = self._provider.zot_read_credential()
            token = _credential(credential, ZotReadCredential, now)
            body, headers = _get("zot", digest, token, self._factory)
        except Exception:
            failed = True
        finally:
            token = None
            credential = None
        if failed:
            raise ReleaseConsumerError(ERROR)
        if (headers.get("docker-content-digest") != digest
                or "sha256:" + hashlib.sha256(body).hexdigest() != digest):
            raise ReleaseConsumerError(ERROR)
        manifest = _json(body, frozenset({"schemaVersion", "mediaType", "config", "layers"}), schema=None)
        if manifest["schemaVersion"] != 2 or manifest["mediaType"] != OCI_MEDIA_TYPE:
            raise ReleaseConsumerError(ERROR)
        return body


class ForgejoEvidenceConsumer:
    """GET exactly the versioned Task 013 Generic evidence archive."""

    __slots__ = ("_provider", "_factory")

    def __init__(self, provider: ForgejoCredentialProvider, factory: ConnectionFactory = _connection):
        object.__setattr__(self, "_provider", provider)
        object.__setattr__(self, "_factory", factory)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Forgejo consumer collaborators are immutable")

    def acquire(self, request: PromotionRequest, *, now: int) -> dict[str, bytes]:
        request = _promotion(request)
        credential = None
        token = None
        failed = False
        try:
            credential = self._provider.forgejo_read_credential()
            token = _credential(credential, ForgejoReadCredential, now)
            body, _ = _get("forgejo", request.release_version, token, self._factory)
        except Exception:
            failed = True
        finally:
            token = None
            credential = None
        if failed:
            raise ReleaseConsumerError(ERROR)
        evidence = _archive(body)
        manifest = _json(evidence["release-manifest.json"], MANIFEST_FIELDS, schema=2)
        provenance = _json(evidence["release-provenance.json"], PROVENANCE_FIELDS, schema=2)
        try:
            structure_valid = (
                type(manifest["oci"]) is dict
                and set(manifest["oci"]) == {"registry", "repository", "tag", "manifest_digest", "deployment_identity"}
                and type(manifest["provenance"]) is dict
                and set(manifest["provenance"]) == {"filename", "sha256"}
                and type(manifest["signing"]) is dict
                and set(manifest["signing"]) == {"method", "release_manifest_bundle", "provenance_bundle", "oci_signature"}
                and type(provenance["subjects"]) is dict
                and set(provenance["subjects"]) == {
                    "python_wheel_sha256", "npm_tarball_sha256", "oci_archive_sha256",
                    "oci_manifest_digest", "sbom_sha256", "vulnerability_policy_sha256",
                    "vulnerability_policy_result_sha256",
                }
                and type(manifest["evidence"]) is dict
                and set(manifest["evidence"]) == {"identity", "artifact_filename"}
                and type(manifest["python"]) is dict
                and set(manifest["python"]) == {"identity", "artifact"}
                and manifest["python"]["identity"] == {"name": "omnilyzer-release-canary", "owner": "omnilyzer"}
                and _artifact(
                    manifest["python"]["artifact"],
                    f"omnilyzer_release_canary-{request.release_version}-py3-none-any.whl",
                )
                and type(manifest["npm"]) is dict
                and set(manifest["npm"]) == {"identity", "artifact"}
                and manifest["npm"]["identity"] == {"name": "@omnilyzer/release-canary", "owner": "omnilyzer"}
                and _artifact(
                    manifest["npm"]["artifact"],
                    f"omnilyzer-release-canary-{request.release_version}.tgz",
                )
                and _hash_map(manifest["sbom_sha256"])
                and _hash_map(manifest["vulnerability_report_sha256"])
                and _hash_map(provenance["subjects"]["sbom_sha256"])
                and manifest["sbom_sha256"] == provenance["subjects"]["sbom_sha256"]
                and type(manifest["tool_versions"]) is dict
                and set(manifest["tool_versions"]) == {
                    "syft", "grype", "cosign", "cyclonedx_spec", "buildx", "buildkit",
                }
                and all(type(item) is str and 0 < len(item) <= 64 for item in manifest["tool_versions"].values())
                and all(
                    validate_sha256(manifest[name], name) == manifest[name]
                    for name in (
                        "vulnerability_policy_sha256", "vulnerability_policy_result_sha256",
                        "grype_database_status_sha256", "release_plan_sha256",
                        "build_manifest_sha256",
                    )
                )
                and all(
                    validate_sha256(provenance["subjects"][name], name) == provenance["subjects"][name]
                    for name in (
                        "python_wheel_sha256", "npm_tarball_sha256", "oci_archive_sha256",
                        "vulnerability_policy_sha256", "vulnerability_policy_result_sha256",
                    )
                )
                and manifest["vulnerability_policy_sha256"] == provenance["subjects"]["vulnerability_policy_sha256"]
                and manifest["vulnerability_policy_result_sha256"] == provenance["subjects"]["vulnerability_policy_result_sha256"]
                and manifest["python"]["artifact"]["sha256"] == provenance["subjects"]["python_wheel_sha256"]
                and manifest["npm"]["artifact"]["sha256"] == provenance["subjects"]["npm_tarball_sha256"]
            )
        except Exception:
            raise ReleaseConsumerError(ERROR) from None
        if (not structure_valid
                or manifest["oci"]["tag"] != request.release_version
                or provenance["statement_type"] != "https://omnilyzer.ai/release-provenance/v2"
                or provenance["claim"] != "build-once release evidence; no formal SLSA level is asserted"
                or manifest["evidence"]["identity"] != {
                    "name": "task013-release-evidence", "owner": "omnilyzer",
                }
                or manifest["evidence"]["artifact_filename"] != "release-evidence.tar.gz"
                or manifest["provenance"] != {
                    "filename": "release-provenance.json",
                    "sha256": hashlib.sha256(evidence["release-provenance.json"]).hexdigest(),
                }
                or manifest["signing"]["release_manifest_bundle"] != "release-manifest.sigstore.json"
                or manifest["signing"]["provenance_bundle"] != "release-provenance.sigstore.json"
                or manifest["signing"]["method"] != "keyless Sigstore/Fulcio/Rekor with GitHub OIDC"
                or manifest["signing"]["oci_signature"] != f"{REPOSITORY}@{request.manifest_digest}"):
            raise ReleaseConsumerError(ERROR)
        return evidence


def _promotion(value: PromotionRequest) -> PromotionRequest:
    if type(value) is not PromotionRequest:
        raise ReleaseConsumerError(ERROR)
    try:
        checked = PromotionRequest.from_dict(value.to_dict())
        if checked.target_stage != "dev" or checked.oci_repository != REPOSITORY:
            raise ValueError
        return checked
    except Exception:
        raise ReleaseConsumerError(ERROR) from None


def _construct_dev_request(
    promotion: PromotionRequest, trusted: TrustedRelease,
    identity: AuthorizedGitHubIdentity, runtime: RuntimeConfigurationReference,
    ingress: IngressReference, *, received_at: int,
) -> ExecutorRequest:
    """Project verified evidence and authorized identity into the existing schema."""

    promotion = _promotion(promotion)
    if (type(trusted) is not TrustedRelease
            or trusted.release_workflow != EXPECTED_RELEASE_WORKFLOW
            or trusted.certificate_identity != EXPECTED_CERTIFICATE_IDENTITY
            or trusted.certificate_issuer != EXPECTED_CERTIFICATE_ISSUER
            or (trusted.release_version, trusted.source_sha, trusted.oci_repository,
                trusted.manifest_digest, trusted.exact_image_reference) != (
                    promotion.release_version, promotion.source_sha, promotion.oci_repository,
                    promotion.manifest_digest, promotion.exact_image_reference)):
        raise ReleaseConsumerError(ERROR)
    try:
        authorized = _normalize_identity(
            identity, received_at=received_at,
            authorization=authorize_verified_github_oidc,
            expected_fields=IDENTITY_FIELDS,
        )
        if type(runtime) is not RuntimeConfigurationReference or type(ingress) is not IngressReference:
            raise ValueError
        reference = RuntimeConfigurationReference.from_dict(asdict(runtime))
        ingress_value = asdict(ingress)
        ingress_value["files"] = list(ingress_value["files"])
        ingress_reference = IngressReference.from_dict(ingress_value)
        if (reference.reviewed_commit != ingress_reference.reviewed_commit
                or reference.repository_id != authorized.repository_id
                or ingress_reference.repository_id != authorized.repository_id):
            raise ValueError
        result = ExecutorRequest.from_dict({
            "schema_version": 1, "operation": "deploy", "stage": "dev",
            "release_version": promotion.release_version, "source_sha": promotion.source_sha,
            "oci_origin": APPROVED_OCI_ORIGIN, "oci_repository": promotion.oci_repository,
            "manifest_digest": promotion.manifest_digest,
            "exact_image_reference": promotion.exact_image_reference,
            "release_manifest_sha256": promotion.release_manifest_sha256,
            "provenance_sha256": promotion.provenance_sha256,
            "originating_release_run_id": promotion.originating_release_run_id,
            "promotion_request_sha256": promotion.sha256(),
            "requested_by_actor_id": authorized.actor_id,
            "github_repository_id": authorized.repository_id,
            "github_workflow_ref": authorized.workflow_ref,
            "github_workflow_sha": authorized.workflow_sha,
            "github_run_id": authorized.run_id,
            "github_run_attempt": authorized.run_attempt,
            "oidc_jti": authorized.jti, "oidc_issued_at": authorized.issued_at,
            "oidc_expires_at": authorized.expires_at,
            "runtime_configuration_reference": asdict(reference),
            "secrets_reference": NoSecretsReference(1, "none", (), NO_SECRETS_REASON).to_dict(),
            "ingress_reference": ingress_value,
        })
        bind_request_to_identity(result, authorized)
        return result
    except Exception:
        raise ReleaseConsumerError(ERROR) from None


def acquire_and_construct_dev_request(
    promotion: PromotionRequest, identity: AuthorizedGitHubIdentity,
    runtime: RuntimeConfigurationReference, ingress: IngressReference,
    zot: ZotCandidateConsumer, forgejo: ForgejoEvidenceConsumer,
    signatures: ReleaseSignatureVerifier,
    *, received_at: int,
) -> ExecutorRequest:
    """Acquire exact bytes, verify them, then construct one canonical request."""

    promotion = _promotion(promotion)
    if type(zot) is not ZotCandidateConsumer or type(forgejo) is not ForgejoEvidenceConsumer:
        raise ReleaseConsumerError(ERROR)
    failed = False
    try:
        zot.acquire(promotion, now=received_at)
        evidence = forgejo.acquire(promotion, now=received_at)
        manifest = evidence["release-manifest.json"]
        provenance = evidence["release-provenance.json"]
        sigstore, oci = signatures.verify(
            manifest, provenance, evidence["release-manifest.sigstore.json"],
            evidence["release-provenance.sigstore.json"], promotion.exact_image_reference,
        )
        trusted = verify_release_evidence(promotion, manifest, provenance, sigstore, oci)
        result = _construct_dev_request(
            promotion, trusted, identity, runtime, ingress, received_at=received_at,
        )
    except Exception:
        failed = True
    if failed:
        raise ReleaseConsumerError(ERROR)
    return result
