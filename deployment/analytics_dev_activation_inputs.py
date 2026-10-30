"""File: deployment/analytics_dev_activation_inputs.py

Purpose: Construct exact UNSIGNED Task014 Analytics 0.15.0 DEV review
         inputs from the previously reviewed immutable Git source archive,
         including the original C32ZF rootless socket source contract.
Related: deployment/analytics_source_handoff.py (31 Git objects),
         deployment/analytics_source_archive.py (canonical USTAR),
         deployment/analytics_isolated_source_install.py (root approval),
         deployment/analytics_executor_service_config.py (20 source hashes),
         deployment/analytics_broker_service.py (broker config admission),
         deployment/rootless_docker_authority.py (original C32ZF contract),
         deployment/tests/test_analytics_dev_activation_inputs.py.

Sections: fixed destinations, read-only source binding, independent root
          approval, exact broker/executor configs, immutable systemd source
          selection and product-private mount-namespace isolation.

SECURITY: Review data is NOT root installation authority. No write, network,
secret, Docker, systemd, session, OIDC, replay or database side effect.
A separately approved root actor must install exact bytes at fixed paths
with original Task014 ownership checks. No caller can grant deployment.
"""
from __future__ import annotations

import hashlib
import json

from . import application_manifest as _original_git
from .rootless_docker_authority import AUTHORITY
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
# These systemd objects remain inert until separately installed by root.
# Exactly three are already bound in the canonical 31-object reviewed archive.
_SERVICE_SOURCES = (
    ("deployment/systemd/dev/analytics-broker-enabled.conf",
     "/etc/systemd/system/omnilyzer-deployment-broker.service.d/analytics-enabled.conf"),
    ("deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service",
     "/etc/systemd/system/omnilyzer-deployment-analytics-executor.service"),
    ("deployment/systemd/dev/omnilyzer-deployment-analytics-executor.socket",
     "/etc/systemd/system/omnilyzer-deployment-analytics-executor.socket"),
)
_ORIGINAL_ROOTLESS_SOURCE = (
    "deployment/systemd/rootless/rootless-docker-executor-socket.conf"
)
_ANALYTICS_RUNTIME_DROPIN = (
    "/etc/systemd/system/"
    "omnilyzer-deployment-analytics-executor.service.d/"
    "rootless-runtime.conf"
)
_ORIGINAL_RUNTIME_DIRECTORY = (
    "RuntimeDirectory=omnilyzer/deployment/rootless-docker"
)
_ORIGINAL_RUNTIME_MODE = "RuntimeDirectoryMode=0700"
# A separate PRIVATE mount namespace makes Analytics independent of the
# canary unit's shared RuntimeDirectory lifecycle. Explicit UID/GID991
# matches the existing reviewed rootless Docker owner, and the original
# binding path inside the executor remains byte-for-byte unchanged.
_PRIVATE_TMPFS = (
    "TemporaryFileSystem=/run/omnilyzer/deployment/rootless-docker:"
    "mode=0700,uid=991,gid=991"
)
_ROOTLESS_BIND = (
    "BindReadOnlyPaths=/run/user/991/docker.sock:"
    "/run/omnilyzer/deployment/rootless-docker/docker.sock"
)
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


def build_unsigned_analytics_service_inputs(
    *, repository_root: str, reviewed_commit: str,
) -> dict[str, bytes]:
    """Bind EXACT service review bytes to one Git generation and original C32ZF.

    The original Task014 canary owns a lifecycle-managed host
    RuntimeDirectory. Sharing it is unsafe: canary stopping could remove
    Analytics' socket target. Analytics therefore overlays its original
    fixed socket destination with a service-private tmpfs INSIDE its own
    mount namespace, created with the same reviewed UID/GID991 ownership
    and 0700 directory mode. The canary's host directory is never reused,
    created, stopped or modified. Signed source pinning, broker signatures
    and systemd activation remain independent and mandatory.
    Neither unit is installed or started by this review-only builder.
    """
    try:
        sources = build_unsigned_analytics_activation_inputs(
            repository_root=repository_root, reviewed_commit=reviewed_commit,
        )
        approval = _approval(sources[SOURCE_APPROVAL])
        selected = dict(verify_analytics_source_archive(
            sources[SOURCE_ARCHIVE],
            expected_manifest_sha256=approval["manifest_sha256"],
            reviewed_commit=reviewed_commit,
        ))
        if len(selected) != 31 or len(_SERVICE_SOURCES) != 3:
            raise ValueError
        result = {
            destination: selected[source]
            for source, destination in _SERVICE_SOURCES
        }
        # Original Task014 C26 immutable Git reader: not the mutable working
        # tree or a caller-specified path. The existing source authority
        # supplies the sole permitted SHA for its rootless Docker drop-in.
        records = _original_git._tree(_original_git._output(
            repository_root, ("ls-tree", "-r", "-z", "--full-tree",
                              reviewed_commit, "--", _ORIGINAL_ROOTLESS_SOURCE),
            1024,
        ), (_ORIGINAL_ROOTLESS_SOURCE,))
        if len(records) != 1 or records[0][0] != _ORIGINAL_ROOTLESS_SOURCE:
            raise ValueError
        original = _original_git._output(
            repository_root, ("cat-file", "blob", records[0][1]), 4096,
        )
        expected = [
            sha for source, _dest, sha, _uid, _gid, _mode in AUTHORITY.installed_assets
            if source == _ORIGINAL_ROOTLESS_SOURCE
        ]
        if (
            len(expected) != 1
            or hashlib.sha256(original).hexdigest() != expected[0]
            or original.decode("ascii").splitlines().count(_ORIGINAL_RUNTIME_DIRECTORY) != 1
            or original.decode("ascii").splitlines().count(_ORIGINAL_RUNTIME_MODE) != 1
            or original.decode("ascii").splitlines().count(_ROOTLESS_BIND) != 1
            or AUTHORITY.socket !=
                "/run/omnilyzer/deployment/rootless-docker/docker.sock"
            or AUTHORITY.daemon_socket != "/run/user/991/docker.sock"
        ):
            raise ValueError
        service = result[_SERVICE_SOURCES[1][1]].decode("ascii")
        service_rows = service.splitlines()
        if (
            service_rows.count(_ROOTLESS_BIND) != 1
            or sum(row.startswith("BindReadOnlyPaths=")
                   for row in service_rows) != 1
            or "WorkingDirectory=/opt/omnilyzer/deployment/analytics-app"
                not in service_rows
            or "User=omnilyzer-executor" not in service_rows
            or "NoNewPrivileges=yes" not in service_rows
            or "ProtectSystem=strict" not in service_rows
            or "CapabilityBoundingSet=" not in service_rows
            or _ORIGINAL_RUNTIME_DIRECTORY in service_rows
            or _ORIGINAL_RUNTIME_MODE in service_rows
            or any(row.startswith("TemporaryFileSystem=")
                   for row in service_rows)
        ):
            raise ValueError

        # Keep the exact product-private mount option fixed, never user
        # supplied. The original C32ZF authority pins socket destination
        # and source; only the Analytics mount namespace is independent.
        if _PRIVATE_TMPFS != (
            "TemporaryFileSystem=/run/omnilyzer/deployment/rootless-docker:"
            "mode=0700,uid=991,gid=991"
        ):
            raise ValueError
        result[_ANALYTICS_RUNTIME_DROPIN] = (
            "[Service]\n" + _PRIVATE_TMPFS + "\n"
        ).encode("ascii")
        if (
            set(result) != {
                _ANALYTICS_RUNTIME_DROPIN,
                *(destination for _source, destination in _SERVICE_SOURCES),
            }
            or any(type(raw) is not bytes or not raw for raw in result.values())
        ):
            raise ValueError
        return result
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsActivationInputsError(_ERROR) from None


__all__ = (
    "AnalyticsActivationInputsError", "build_unsigned_analytics_activation_inputs",
    "SOURCE_ARCHIVE", "SOURCE_APPROVAL", "EXECUTOR_CONFIG", "BROKER_CONFIG",
    "build_unsigned_analytics_service_inputs",
)
