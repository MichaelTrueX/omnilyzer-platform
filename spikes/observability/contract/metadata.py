"""Application, platform, build, and deployment metadata contract."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from importlib import metadata
import re
from typing import Callable, Mapping


_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def installed_version(distribution_name: str) -> str:
    """Resolve a version from installed distribution metadata."""

    return metadata.version(distribution_name)


def _timestamp(value: str) -> str:
    if not value.endswith("Z"):
        raise ValueError("deployment timestamp must be UTC RFC3339 ending in Z")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError("deployment timestamp must be valid RFC3339") from error
    return value


@dataclass(frozen=True, slots=True)
class BuildMetadata:
    """Validated metadata, separated from per-request metric dimensions."""

    service: str
    product: str
    environment: str
    app_version: str
    platform_version: str
    git_commit: str
    deployment_timestamp: str
    oci_digest: str

    def as_dict(self) -> dict[str, str]:
        """Return complete metadata for controlled inventory/logging use."""

        return asdict(self)

    def build_info_labels(self) -> dict[str, str]:
        """Return only bounded labels appropriate for one build-info series."""

        return {
            "service": self.service,
            "product": self.product,
            "environment": self.environment,
            "app_version": self.app_version,
            "platform_version": self.platform_version,
        }


def load_build_metadata(
    values: Mapping[str, str],
    resolver: Callable[[str], str] = installed_version,
) -> BuildMetadata:
    """Load package versions from distributions and deployment facts from injection."""

    app_version = resolver(values["APPLICATION_DISTRIBUTION"])
    platform_version = resolver(values["PLATFORM_DISTRIBUTION"])
    if _VERSION.fullmatch(app_version) is None or _VERSION.fullmatch(platform_version) is None:
        raise ValueError("application and platform versions must be version metadata")
    git_commit = values["GIT_COMMIT"]
    oci_digest = values["OCI_DIGEST"]
    if _GIT_SHA.fullmatch(git_commit) is None:
        raise ValueError("Git commit must be a full lowercase SHA")
    if _OCI_DIGEST.fullmatch(oci_digest) is None:
        raise ValueError("OCI digest must be an immutable sha256 digest")
    return BuildMetadata(
        service=values["OBSERVABILITY_SERVICE"],
        product=values["OBSERVABILITY_PRODUCT"],
        environment=values["OBSERVABILITY_ENVIRONMENT"],
        app_version=app_version,
        platform_version=platform_version,
        git_commit=git_commit,
        deployment_timestamp=_timestamp(values["DEPLOYMENT_TIMESTAMP"]),
        oci_digest=oci_digest,
    )
