"""File: deployment/analytics_dev_activation_inputs.py

Purpose: Construct FOUR exact UNSIGNED Task014 Analytics 0.15.0 DEV root inputs
         from the previously reviewed immutable Git source archive.
Related: deployment/analytics_source_handoff.py (31 Git objects),
         deployment/analytics_source_archive.py (canonical USTAR),
         deployment/analytics_isolated_source_install.py (root approval),
         deployment/analytics_executor_service_config.py (20 source hashes),
         deployment/analytics_broker_service.py (broker config admission),
         deployment/tests/test_analytics_dev_activation_inputs.py.

Sections: fixed destinations, read-only source binding, independent root
          approval and exact broker/executor source configuration.

SECURITY: Review data is NOT root installation authority. No write, network,
secret, Docker, systemd, session, OIDC, replay or database side effect.
A separately approved root actor must install exact bytes at fixed paths
with original Task014 ownership checks. No caller can grant deployment.
"""
from __future__ import annotations

import hashlib
import json

from .analytics_executor_service_config import (
    ANALYTICS_INSTALLED_FILES, _INSTALLED_RUNTIME_FILES,
    _SOURCE_CLAIM_SHA256, parse_analytics_executor_service_config,
)
from .analytics_isolated_source_install import _approval
from .analytics_source_archive import (
    build_analytics_source_archive, verify_analytics_source_archive,
)
from .analytics_source_handoff import review_analytics_source_handoff
from .policy import canonical_bytes

SOURCE_ARCHIVE = "/opt/omnilyzer/deployment/.analytics-source-review.tar"
SOURCE_APPROVAL = "/etc/omnilyzer/deployment/dev/analytics-source-install.json"
EXECUTOR_CONFIG = "/etc/omnilyzer/deployment/dev/analytics-executor.json"
BROKER_CONFIG = "/etc/omnilyzer/deployment/broker/analytics.json"
DESTINATION = "/opt/omnilyzer/deployment/analytics-app"
_CLOSED_PATHS = (SOURCE_ARCHIVE, SOURCE_APPROVAL, EXECUTOR_CONFIG, BROKER_CONFIG)
_ERROR = "Analytics Task014 source activation inputs are unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class AnalyticsActivationInputsError(Exception):
    """One rejected unsigned source-input review, never an install permission."""


def build_unsigned_analytics_activation_inputs(
    *, repository_root: str, reviewed_commit: str,
) -> dict[str, bytes]:
    """Bind four review inputs to the SAME exact immutable Git source.

    The original Analytics parser validates the broker/executor config and
    original root-only approval parser validates the installation request.
    Return values are publicly constructible and NEVER grant root authority.
    """
    try:
        manifest = review_analytics_source_handoff(
            repository_root=repository_root, reviewed_commit=reviewed_commit,
        )
        metadata = json.loads(manifest)
        manifest_sha = hashlib.sha256(manifest).hexdigest()
        archive = build_analytics_source_archive(
            repository_root=repository_root, reviewed_commit=reviewed_commit,
        )
        contents = dict(verify_analytics_source_archive(
            archive, expected_manifest_sha256=manifest_sha,
            reviewed_commit=reviewed_commit,
        ))
        entries = {
            item["path"]: item["sha256"]
            for item in metadata["source_entries"]
        }
        if (
            len(contents) != 31 or len(entries) != 31
            or len(ANALYTICS_INSTALLED_FILES) != 20
            or not set(ANALYTICS_INSTALLED_FILES).issubset(entries)
            or not set(_INSTALLED_RUNTIME_FILES).issubset(entries)
            or metadata["reviewed_source_claim_sha256"] != _SOURCE_CLAIM_SHA256
            or metadata["source_commit"] != reviewed_commit
            or metadata["isolation_target"] != DESTINATION
            or metadata["deployment_authorized"] is not False
            or metadata["signed_release_authorized"] is not False
        ):
            raise ValueError
        product_config = canonical_bytes({
            "schema_version": 1, "product_id": "analytics", "stage": "dev",
            "reviewed_installed_commit": reviewed_commit,
            "reviewed_compose_sha256": metadata["reviewed_compose_sha256"],
            "reviewed_product_profile_sha256":
                metadata["reviewed_product_profile_sha256"],
            "reviewed_runtime_profile_sha256":
                metadata["reviewed_runtime_profile_sha256"],
            "source_sha256": {
                path: entries[path] for path in ANALYTICS_INSTALLED_FILES
            },
        })
        parsed = parse_analytics_executor_service_config(product_config)
        if (
            parsed["reviewed_installed_commit"] != reviewed_commit
            or parsed["reviewed_compose_sha256"]
                != metadata["reviewed_compose_sha256"]
            or parsed["reviewed_product_profile_sha256"]
                != metadata["reviewed_product_profile_sha256"]
            or parsed["reviewed_runtime_profile_sha256"]
                != metadata["reviewed_runtime_profile_sha256"]
            or tuple(parsed["source_sha256"]) != tuple(
                (path, entries[path]) for path in ANALYTICS_INSTALLED_FILES
            )
        ):
            raise ValueError
        approval = canonical_bytes({
            "schema_version": 1, "product_id": "analytics", "stage": "dev",
            "reviewed_commit": reviewed_commit,
            "manifest_sha256": manifest_sha,
            "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "destination": DESTINATION,
        })
        if _approval(approval)["archive_sha256"] != hashlib.sha256(archive).hexdigest():
            raise ValueError
        result = {
            SOURCE_ARCHIVE: archive,
            SOURCE_APPROVAL: approval,
            EXECUTOR_CONFIG: product_config,
            BROKER_CONFIG: product_config,
        }
        if set(result) != set(_CLOSED_PATHS):
            raise ValueError
        return result
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsActivationInputsError(_ERROR) from None


__all__ = (
    "AnalyticsActivationInputsError", "build_unsigned_analytics_activation_inputs",
    "SOURCE_ARCHIVE", "SOURCE_APPROVAL", "EXECUTOR_CONFIG", "BROKER_CONFIG",
)
