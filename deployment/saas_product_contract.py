"""File: deployment/saas_product_contract.py

Purpose: Strict, inert admission preflight for an independently versioned SaaS
product to reuse Task 013 release identity and Task 014 promotion machinery.
Related: deployment/policy.py, deployment/promotion.py,
deployment/release_consumer.py, deployment/products/analytics-dev.json,
deployment/tests/test_saas_product_contract.py.

IMPORTANT: This module validates planned product metadata and a previously
verified TrustedRelease. It neither performs signature verification nor adds
authority to the installed broker/executor. It must NEVER be substituted for
the existing Task 013/014 cryptographic, source-set or replay gates.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .policy import (
    APPROVED_OCI_HOST,
    APPROVED_OCI_ORIGIN,
    EXPECTED_CERTIFICATE_IDENTITY,
    EXPECTED_CERTIFICATE_ISSUER,
    EXPECTED_RELEASE_WORKFLOW,
    DeploymentPolicyError,
    canonical_bytes,
    validate_digest,
    validate_source_sha,
)
from .promotion import TrustedRelease


# Section 1: one explicit, reviewable DEV product. Future modules must gain
# individually reviewed profile entries; no regex wildcards authorize a module.
SCHEMA_VERSION = 1
APPROVED_PRODUCTS: dict[str, tuple[str, str]] = {
    "analytics": ("MichaelTrueX/omnilyzer", "omnilyzer/analytics"),
}
APPROVED_DEV_PORTS = frozenset({3000})
ALLOWED_PROBE_PATHS = frozenset({"/api/v1/readyz"})
REQUIRED_ANALYTICS_SECRET_NAMES = ("DATABASE_URL", "JWT_REFRESH_SECRET", "JWT_SECRET")
_SOURCE = frozenset({"repository", "commit"})
_ARTIFACT = frozenset({"registry", "repository"})
_RUNTIME = frozenset({"stage", "app_port", "readiness_path", "database", "secret_names"})
_PROFILE = frozenset({"schema_version", "product_id", "source", "artifact", "runtime"})
_PRODUCT_ID = re.compile(r"[a-z][a-z0-9-]{1,39}\Z")
_ERROR = "SaaS product contract rejected"


def _exact_dict(value: object, fields: frozenset[str]) -> dict[str, Any]:
    """Reject unknown/missing keys and non-exact dictionaries."""
    if type(value) is not dict or set(value) != fields:
        raise DeploymentPolicyError(_ERROR)
    return value


def _id(value: object) -> str:
    """Reject unbounded product identifiers and ambiguous case."""
    if type(value) is not str or _PRODUCT_ID.fullmatch(value) is None:
        raise DeploymentPolicyError(_ERROR)
    return value


@dataclass(frozen=True, slots=True)
class SaaSProductProfile:
    """Pure, pinned product identity with no mutable tags or secret values."""

    product_id: str
    source_repository: str
    source_commit: str
    oci_repository: str
    app_port: int
    readiness_path: str
    database: str
    secret_names: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: object) -> "SaaSProductProfile":
        """Validate the complete descriptor, with strict per-product policies."""
        data = _exact_dict(value, _PROFILE)
        if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION:
            raise DeploymentPolicyError(_ERROR)
        product_id = _id(data["product_id"])
        if product_id not in APPROVED_PRODUCTS:
            raise DeploymentPolicyError(_ERROR)
        source = _exact_dict(data["source"], _SOURCE)
        artifact = _exact_dict(data["artifact"], _ARTIFACT)
        runtime = _exact_dict(data["runtime"], _RUNTIME)
        expected_repository, expected_oci = APPROVED_PRODUCTS[product_id]
        if (
            type(source["repository"]) is not str
            or source["repository"] != expected_repository
            or type(artifact["registry"]) is not str
            or artifact["registry"] != APPROVED_OCI_ORIGIN
            or type(artifact["repository"]) is not str
            or artifact["repository"] != expected_oci
            or runtime["stage"] != "dev"
            or type(runtime["app_port"]) is not int
            or runtime["app_port"] not in APPROVED_DEV_PORTS
            or type(runtime["readiness_path"]) is not str
            or runtime["readiness_path"] not in ALLOWED_PROBE_PATHS
            or runtime["database"] != "postgresql-private"
            or type(runtime["secret_names"]) is not list
            or tuple(runtime["secret_names"]) != REQUIRED_ANALYTICS_SECRET_NAMES
        ):
            raise DeploymentPolicyError(_ERROR)
        try:
            sha = validate_source_sha(source["commit"])
        except (ValueError, TypeError) as exc:
            raise DeploymentPolicyError(_ERROR) from exc
        return cls(
            product_id=product_id,
            source_repository=source["repository"],
            source_commit=sha,
            oci_repository=artifact["repository"],
            app_port=runtime["app_port"],
            readiness_path=runtime["readiness_path"],
            database=runtime["database"],
            secret_names=tuple(runtime["secret_names"]),
        )

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> "SaaSProductProfile":
        """Reject duplicate JSON members and parse a bounded descriptor."""
        if type(raw) is not bytes or len(raw) > 4096:
            raise DeploymentPolicyError(_ERROR)

        def no_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            """Fail closed if an untrusted descriptor repeats a field."""
            data: dict[str, Any] = {}
            for key, value in pairs:
                if key in data:
                    raise DeploymentPolicyError(_ERROR)
                data[key] = value
            return data

        try:
            parsed = json.loads(raw, object_pairs_hook=no_duplicate)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeploymentPolicyError(_ERROR) from exc
        return cls.from_dict(parsed)

    def to_dict(self) -> dict[str, Any]:
        """Reconstruct the exact, canonical reviewable descriptor."""
        return {
            "schema_version": SCHEMA_VERSION,
            "product_id": self.product_id,
            "source": {
                "repository": self.source_repository,
                "commit": self.source_commit,
            },
            "artifact": {
                "registry": APPROVED_OCI_ORIGIN,
                "repository": self.oci_repository,
            },
            "runtime": {
                "stage": "dev",
                "app_port": self.app_port,
                "readiness_path": self.readiness_path,
                "database": self.database,
                "secret_names": list(self.secret_names),
            },
        }

    def sha256(self) -> str:
        """Bind exact profile bytes to future signed Task 013 evidence."""
        return hashlib.sha256(canonical_bytes(self.to_dict())).hexdigest()


def validate_existing_signed_release(
    profile: SaaSProductProfile,
    release: TrustedRelease,
    *,
    signed_external_source: Mapping[str, object] | None = None,
) -> str:
    """Fail closed until the existing verified release carries this product.

    The supplied TrustedRelease must originate from existing
    deployment.promotion.verify_release_evidence: no raw manifest, caller
    string or syntactically plausible sha256 is itself signature proof.
    The external-source claim MUST be extracted from and cryptographically
    bound to that verified release's immutable signed provenance, not passed
    from an unsigned JSON manifest. Until Task 013 defines that signed claim
    and Task 014 consumes it, this call rejects Analytics intentionally.
    """
    if type(profile) is not SaaSProductProfile or type(release) is not TrustedRelease:
        raise DeploymentPolicyError(_ERROR)
    if (
        release.oci_repository != profile.oci_repository
        or release.release_workflow != EXPECTED_RELEASE_WORKFLOW
        or release.certificate_identity != EXPECTED_CERTIFICATE_IDENTITY
        or release.certificate_issuer != EXPECTED_CERTIFICATE_ISSUER
        or release.exact_image_reference != (
            f"{APPROVED_OCI_HOST}/{profile.oci_repository}@{release.manifest_digest}"
        )
    ):
        raise DeploymentPolicyError(_ERROR)
    try:
        validate_digest(release.manifest_digest)
        validate_source_sha(release.source_sha)
    except (ValueError, TypeError) as exc:
        raise DeploymentPolicyError(_ERROR) from exc

    # No signed cross-repository source binding exists in the current Task013
    # canary release schema. Do NOT turn the caller-provided mapping into an
    # authority: a forged mapping would permit external source substitution.
    _ = signed_external_source
    raise DeploymentPolicyError(
        "Analytics requires Task 013 signed external-source provenance "
        "and Task 014 installed product-scoped broker/executor authority"
    )


def load_reviewed_profile(path: Path) -> SaaSProductProfile:
    """Read a bounded local review file; no server configuration is changed."""
    if type(path) is not Path or path.is_symlink() or not path.is_file():
        raise DeploymentPolicyError(_ERROR)
    if path.stat().st_size > 4096:
        raise DeploymentPolicyError(_ERROR)
    return SaaSProductProfile.from_json_bytes(path.read_bytes())
