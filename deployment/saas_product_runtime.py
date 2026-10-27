"""File: deployment/saas_product_runtime.py

Purpose: Bounded metadata profile for a *future* first SaaS product runtime
using the ORIGINAL Task014 broker/executor. Reject unexpected product IDs,
secret names/values, stages, ingress and rollback behavior without granting
any release or deployment authority.

Related:
  deployment/products/analytics-runtime-dev.json
  deployment/tests/test_saas_product_runtime.py
  release/analytics_source_admission.py (M01 signed-source input boundary)
  deployment/promotion.py, deployment/execution.py, deployment/docker_runtime.py
  docs/operations/m05-analytics-task014-runtime-review.md

This is intentionally inert and does NOT replace Task013 signatures,
Task014 OIDC/replay/manifest checks, source authority or the installed
executor's current canary-only allowlist. Nothing is deployed on import.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from .policy import DeploymentPolicyError, canonical_bytes

# Section 1: Explicit product policies. Future modules require independent
# reviewed additions rather than wildcard regex or arbitrary repository names.
VERSION = 1
LIMIT = 4096
ERROR = "SaaS runtime profile is unapproved or invalid"
PRODUCTS = {
    "analytics": {
        "oci_repository": "omnilyzer/analytics",
        "container_port": 3000,
        "database": "postgresql-separate-auth-and-collector-roles",
        "health": {"live": "/livez", "ready": "/readyz"},
        "runtime_secret_names": [
            "COLLECTOR_DATABASE_URL",
            "DATABASE_URL",
            "JWT_REFRESH_SECRET",
            "JWT_SECRET",
        ],
    },
}
FIELDS = frozenset({
    "schema_version", "product_id", "stage", "oci_repository",
    "container_port", "database", "health", "runtime_secret_names",
    "ingress", "rollback",
})
INGRESS = "private-task014-only"
ROLLBACK = "task014-immutable-digest-preserve-database-writes"


def _exact_object(value: Any, required: frozenset[str]) -> dict[str, Any]:
    """Fail closed on missing, unknown, non-dict or nested ambiguous fields."""
    if type(value) is not dict or frozenset(value.keys()) != required:
        raise DeploymentPolicyError(ERROR)
    return value


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate untrusted JSON members instead of last-value-wins."""
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise DeploymentPolicyError(ERROR)
        obj[key] = value
    return obj


@dataclass(frozen=True, slots=True)
class SaaSRuntimeProfile:
    """Pure value object describing an unprivileged product runtime contract."""

    product_id: str
    oci_repository: str
    container_port: int
    database: str
    live_path: str
    ready_path: str
    runtime_secret_names: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: Any) -> "SaaSRuntimeProfile":
        """Accept exactly the reviewed DEV Analytics shape, nothing broader."""
        data = _exact_object(value, FIELDS)
        if type(data["schema_version"]) is not int or data["schema_version"] != VERSION:
            raise DeploymentPolicyError(ERROR)
        product_id = data["product_id"]
        if type(product_id) is not str or product_id not in PRODUCTS:
            raise DeploymentPolicyError(ERROR)
        expected = PRODUCTS[product_id]
        health = _exact_object(data["health"], frozenset({"live", "ready"}))
        if (
            data["stage"] != "dev"
            or type(data["stage"]) is not str
            or type(data["oci_repository"]) is not str
            or data["oci_repository"] != expected["oci_repository"]
            or type(data["container_port"]) is not int
            or data["container_port"] != expected["container_port"]
            or type(data["database"]) is not str
            or data["database"] != expected["database"]
            or health != expected["health"]
            or type(data["runtime_secret_names"]) is not list
            or data["runtime_secret_names"] != expected["runtime_secret_names"]
            or not all(type(v) is str for v in data["runtime_secret_names"])
            or data["ingress"] != INGRESS
            or type(data["ingress"]) is not str
            or data["rollback"] != ROLLBACK
            or type(data["rollback"]) is not str
        ):
            raise DeploymentPolicyError(ERROR)
        return cls(
            product_id=product_id,
            oci_repository=data["oci_repository"],
            container_port=data["container_port"],
            database=data["database"],
            live_path=health["live"],
            ready_path=health["ready"],
            runtime_secret_names=tuple(data["runtime_secret_names"]),
        )

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> "SaaSRuntimeProfile":
        """Parse a size-bounded, duplicate-free profile without env evaluation."""
        if type(raw) is not bytes or not raw or len(raw) > LIMIT:
            raise DeploymentPolicyError(ERROR)
        try:
            return cls.from_dict(json.loads(raw, object_pairs_hook=_no_duplicates))
        except (UnicodeError, ValueError, TypeError) as exc:
            raise DeploymentPolicyError(ERROR) from exc

    def to_dict(self) -> dict[str, Any]:
        """Reproduce the complete approved profile for reproducible SHA checks."""
        return {
            "schema_version": VERSION,
            "product_id": self.product_id,
            "stage": "dev",
            "oci_repository": self.oci_repository,
            "container_port": self.container_port,
            "database": self.database,
            "health": {"live": self.live_path, "ready": self.ready_path},
            "runtime_secret_names": list(self.runtime_secret_names),
            "ingress": INGRESS,
            "rollback": ROLLBACK,
        }

    def sha256(self) -> str:
        """Fingerprint canonical metadata; NOT a signature or permission grant."""
        return hashlib.sha256(canonical_bytes(self.to_dict())).hexdigest()


def load_review_profile(path: Path) -> SaaSRuntimeProfile:
    """Read only a local regular review file without following a path symlink."""
    if type(path) is not Path or path.is_symlink() or not path.is_file():
        raise DeploymentPolicyError(ERROR)
    if path.stat().st_size > LIMIT:
        raise DeploymentPolicyError(ERROR)
    return SaaSRuntimeProfile.from_json_bytes(path.read_bytes())
