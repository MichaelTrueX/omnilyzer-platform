"""File: deployment/analytics_dev_activation_inputs.py

Purpose: Construct exact UNSIGNED Task014 Analytics 0.15.0/V2 DEV review
         inputs from independently verified immutable Git source archives,
         including the original C32ZF rootless socket source contract and inert,
         generation-specific broker/executor service override inputs.
Related: deployment/analytics_source_handoff.py (32 Git objects),
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
    ANALYTICS_INSTALLED_FILES, ANALYTICS_SUCCESSOR_INSTALLED_FILES,
    _INSTALLED_RUNTIME_FILES,
    _SOURCE_CLAIM_SHA256, parse_analytics_executor_service_config,
)
from .analytics_isolated_source_install import _approval
from .analytics_source_archive import (
    build_analytics_source_archive, verify_analytics_source_archive,
    build_analytics_successor_source_archive,
    verify_analytics_successor_source_archive,
)
from .analytics_source_handoff import (
    review_analytics_source_handoff, review_analytics_successor_source_handoff,
)
from .policy import canonical_bytes

SOURCE_ARCHIVE = "/opt/omnilyzer/deployment/.analytics-source-review.tar"
SOURCE_APPROVAL = "/etc/omnilyzer/deployment/dev/analytics-source-install.json"
EXECUTOR_CONFIG = "/etc/omnilyzer/deployment/dev/analytics-executor.json"
BROKER_CONFIG = "/etc/omnilyzer/deployment/broker/analytics.json"
DESTINATION = "/opt/omnilyzer/deployment/analytics-app"
# V2 reviewed candidate must be independently installed *beside* V1.
# The original V1 active service continues to refer to DESTINATION.
SUCCESSOR_DESTINATION = "/opt/omnilyzer/deployment/analytics-app-candidate"
_CLOSED_PATHS = (SOURCE_ARCHIVE, SOURCE_APPROVAL, EXECUTOR_CONFIG, BROKER_CONFIG)
# These systemd objects remain inert until separately installed by root.
# Exactly three are already bound in the canonical 32-object reviewed archive.
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
# The *inactive* successor source must never overwrite either original unit
# or the original installed V1 broker/executor WorkingDirectory. These two
# fixed drop-in filenames are generated as uninstalled review inputs ONLY.
_SUCCESSOR_BROKER_DROPIN = (
    "/etc/systemd/system/omnilyzer-deployment-broker.service.d/"
    "analytics-v2-source.conf"
)
_SUCCESSOR_EXECUTOR_DROPIN = (
    "/etc/systemd/system/omnilyzer-deployment-analytics-executor.service.d/"
    "analytics-v2-source.conf"
)
# The original Cosign and TrustedRoot reader requires two protected directories
# to have the *current verifier principal's* group, not broker UID990's group.
# Systemd binds separately root-provisioned 0:991 copies into the old paths
# INSIDE the UID991 service mount namespace. No shared broker file becomes
# group-readable, and neither signed binary nor original verifier is modified.
_SUCCESSOR_VERIFIER_BINDS = (
    "BindReadOnlyPaths="
    "/etc/omnilyzer/deployment/dev/analytics-executor-sigstore:"
    "/etc/omnilyzer/deployment/broker "
    "/opt/omnilyzer/deployment/analytics-executor-tools:"
    "/opt/omnilyzer/deployment/tools"
)
# The original original C32G/C32I verifier demands independently private
# 0700 workspaces for its sealed evidence and Docker OIDC auth. The private
# parent mount is already in rootless-runtime.conf and is never shared with
# Canary/UID990. Nested mounts grant only UID991 temporary write capability.
_SUCCESSOR_VERIFIER_TMPFS = (
    "TemporaryFileSystem="
    "/run/omnilyzer/deployment/dev:mode=0755,uid=0,gid=0 "
    "/run/omnilyzer/deployment/dev/blob-verifier:mode=0700,uid=991,gid=991 "
    "/run/omnilyzer/deployment/dev/oci-verifier:mode=0700,uid=991,gid=991"
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
    "TemporaryFileSystem=/run/omnilyzer/deployment:mode=0755,uid=0,gid=0 "
    "/run/omnilyzer/deployment/rootless-docker:"
    "mode=0700,uid=991,gid=991"
)
_LISTENER_BIND = (
    "BindReadOnlyPaths=/run/omnilyzer/deployment/analytics-executor.sock:"
    "/run/omnilyzer/deployment/analytics-executor.sock"
)
_ROOTLESS_BIND = (
    "BindReadOnlyPaths=/run/user/991/docker.sock:"
    "/run/omnilyzer/deployment/rootless-docker/docker.sock"
)
# Historical accepted DEV platform-promotion workflow commit. V2's fixed
# root-owned candidate config pins this once; per-Analytics-version changes
# NEVER select their own workflow identity. Changing the platform workflow
# is a separate owner-reviewed platform source/config update, not a product
# release parameter or mutable request field.
_REVIEWED_TASK014_DEV_WORKFLOW_SHA = (
    "9d29fa1a4010e6e72676580c36a94c1e97e8794b"
)
_ERROR = "Analytics Task014 source activation inputs are unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class AnalyticsActivationInputsError(Exception):
    """One rejected unsigned source-input review, never an install permission."""


def build_unsigned_analytics_activation_inputs(
    *, repository_root: str, reviewed_commit: str,
    successor_source: bool = False,
    owner_authorized_first_successor: bool = False,
) -> dict[str, bytes]:
    """Bind four review inputs to exactly one verified Git source generation.

    The default retains the independently accepted V1 root-install request.
    Explicit V2 emits unsigned successor review data and schema-2 config;
    generation3 emits only unsigned future owner-install review inputs,
    which the CURRENT root-only installer still rejects. This is never an
    installation, deployment authorization or signature acceptance.
    """
    try:
        if (
            type(successor_source) is not bool
            or type(owner_authorized_first_successor) is not bool
            or (owner_authorized_first_successor and not successor_source)
        ):
            raise ValueError
        manifest = (
            review_analytics_successor_source_handoff(
                repository_root=repository_root, reviewed_commit=reviewed_commit,
            ) if successor_source else review_analytics_source_handoff(
                repository_root=repository_root, reviewed_commit=reviewed_commit,
            )
        )
        metadata = json.loads(manifest)
        manifest_sha = hashlib.sha256(manifest).hexdigest()
        archive = (
            build_analytics_successor_source_archive(
                repository_root=repository_root, reviewed_commit=reviewed_commit,
            ) if successor_source else build_analytics_source_archive(
                repository_root=repository_root, reviewed_commit=reviewed_commit,
            )
        )
        contents = dict((
            verify_analytics_successor_source_archive if successor_source
            else verify_analytics_source_archive
        )(
            archive, expected_manifest_sha256=manifest_sha,
            reviewed_commit=reviewed_commit,
        ))
        baseline = metadata["baseline_review"] if successor_source else metadata
        paths = (
            ANALYTICS_SUCCESSOR_INSTALLED_FILES if successor_source
            else ANALYTICS_INSTALLED_FILES
        )
        expected_count = 38 if successor_source else 32
        entries = {
            item["path"]: item["sha256"]
            for item in metadata["source_entries"]
        }
        if (
            len(contents) != expected_count or len(entries) != expected_count
            or len(paths) != (26 if successor_source else 20)
            or not set(paths).issubset(entries)
            or not set(_INSTALLED_RUNTIME_FILES).issubset(entries)
            or any(hashlib.sha256(contents[path]).hexdigest() != entries[path]
                   for path in paths)
            or baseline["reviewed_source_claim_sha256"] != _SOURCE_CLAIM_SHA256
            or metadata["source_commit"] != reviewed_commit
            or baseline["isolation_target"] != DESTINATION
            or metadata["deployment_authorized"] is not False
            or metadata["signed_release_authorized"] is not False
            or baseline["deployment_authorized"] is not False
            or baseline["signed_release_authorized"] is not False
        ):
            raise ValueError
        generation = (3 if owner_authorized_first_successor
                      else 2 if successor_source else 1)
        product_config = canonical_bytes({
            "schema_version": generation, "product_id": "analytics", "stage": "dev",
            **({"expected_workflow_sha": _REVIEWED_TASK014_DEV_WORKFLOW_SHA}
               if successor_source else {}),
            **({"owner_authorized_first_successor": True}
               if owner_authorized_first_successor else {}),
            "reviewed_installed_commit": reviewed_commit,
            "reviewed_compose_sha256": baseline["reviewed_compose_sha256"],
            "reviewed_product_profile_sha256":
                baseline["reviewed_product_profile_sha256"],
            "reviewed_runtime_profile_sha256":
                baseline["reviewed_runtime_profile_sha256"],
            "source_sha256": {
                path: entries[path] for path in paths
            },
        })
        parsed = parse_analytics_executor_service_config(product_config)
        if (
            (successor_source and parsed.get("expected_workflow_sha")
                != _REVIEWED_TASK014_DEV_WORKFLOW_SHA)
            or parsed["reviewed_installed_commit"] != reviewed_commit
            or parsed["reviewed_compose_sha256"]
                != baseline["reviewed_compose_sha256"]
            or parsed["reviewed_product_profile_sha256"]
                != baseline["reviewed_product_profile_sha256"]
            or parsed["reviewed_runtime_profile_sha256"]
                != baseline["reviewed_runtime_profile_sha256"]
            or tuple(parsed["source_sha256"]) != tuple(
                (path, entries[path]) for path in paths
            )
        ):
            raise ValueError
        # Source archive approval remains V2 schema2: generation3 is a
        # distinct root-owned *runtime execution* selection, not permission
        # to weaken or replace the immutable 38-entry source archive.
        approval = canonical_bytes({
            "schema_version": 2 if successor_source else 1,
            "product_id": "analytics", "stage": "dev",
            "reviewed_commit": reviewed_commit,
            "manifest_sha256": manifest_sha,
            "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "destination": (SUCCESSOR_DESTINATION if successor_source
                            else DESTINATION),
        })
        # Original ROOT installer still accepts V1 ONLY: allowing V2 here
        # makes a reproducible reviewed input, not a usable root install.
        if not successor_source and _approval(approval)["archive_sha256"] != (
            hashlib.sha256(archive).hexdigest()
        ):
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
    successor_source: bool = False,
    owner_authorized_first_successor: bool = False,
) -> dict[str, bytes]:
    """Bind EXACT service review bytes to one Git generation and original C32ZF.

    The original Task014 canary owns a lifecycle-managed host
    RuntimeDirectory. Sharing it is unsafe: canary stopping could remove
    Analytics' socket target. Analytics therefore overlays its original
    fixed socket destination with a service-private tmpfs INSIDE its own
    mount namespace, created with the same reviewed UID/GID991 ownership
    and 0700 directory mode. A private root-owned parent tmpfs prevents
    Canary host-directory cleanup from detaching the nested Docker mount.
    Rebind only the exact Analytics listener inode read-only into that parent
    for the original listener metadata checks. Do not list either tmpfs in
    ReadWritePaths: systemd255 keeps READ_WRITE ahead of a duplicate TMPFS
    and fails when the host mountpoint is absent. systemd may create a bare
    host mountpoint; its contents are hidden by the private filesystem.
    Actual Canary start/stop coexistence still requires live verification.
    Signed source pinning, broker signatures and systemd activation remain
    independent and mandatory.
    Neither unit is installed or started by this review-only builder.
    """
    try:
        if (
            type(successor_source) is not bool
            or type(owner_authorized_first_successor) is not bool
            or (owner_authorized_first_successor and not successor_source)
        ):
            raise ValueError("invalid source generation")
        # Always preserve the historical 4 original service files byte-for-byte.
        # V2 add-ons may only be returned after the full immutable 38-source
        # V2 archive, 25 modules + pinned Compose override and root-config shape pass.
        if successor_source:
            candidate = build_unsigned_analytics_activation_inputs(
                repository_root=repository_root, reviewed_commit=reviewed_commit,
                successor_source=True,
                owner_authorized_first_successor=owner_authorized_first_successor,
            )
            from .analytics_isolated_source_install import _successor_approval
            approved_candidate = _successor_approval(candidate[SOURCE_APPROVAL])
            parsed_candidate = parse_analytics_executor_service_config(
                candidate[EXECUTOR_CONFIG]
            )
            if (
                approved_candidate["destination"] != SUCCESSOR_DESTINATION
                or parsed_candidate["source_generation"] != (
                    3 if owner_authorized_first_successor else 2
                )
                or tuple(name for name, _ in parsed_candidate["source_sha256"])
                    != ANALYTICS_SUCCESSOR_INSTALLED_FILES
                or candidate[EXECUTOR_CONFIG] != candidate[BROKER_CONFIG]
            ):
                raise ValueError("candidate service source identity mismatch")
        sources = build_unsigned_analytics_activation_inputs(
            repository_root=repository_root, reviewed_commit=reviewed_commit,
        )
        approval = _approval(sources[SOURCE_APPROVAL])
        selected = dict(verify_analytics_source_archive(
            sources[SOURCE_ARCHIVE],
            expected_manifest_sha256=approval["manifest_sha256"],
            reviewed_commit=reviewed_commit,
        ))
        if len(selected) != 32 or len(_SERVICE_SOURCES) != 3:
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
            or service_rows.count("ReadWritePaths=/var/lib/omnilyzer/deployment") != 1
            or sum(row.startswith("ReadWritePaths=") for row in service_rows) != 1
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
            "TemporaryFileSystem=/run/omnilyzer/deployment:mode=0755,uid=0,gid=0 "
            "/run/omnilyzer/deployment/rootless-docker:"
            "mode=0700,uid=991,gid=991"
        ) or _LISTENER_BIND != (
            "BindReadOnlyPaths=/run/omnilyzer/deployment/analytics-executor.sock:"
            "/run/omnilyzer/deployment/analytics-executor.sock"
        ):
            raise ValueError
        result[_ANALYTICS_RUNTIME_DROPIN] = (
            "[Service]\n" + _PRIVATE_TMPFS + "\n" + _LISTENER_BIND + "\n"
        ).encode("ascii")
        # Appending these two separately installed override inputs does not
        # grant a service restart, source selection or signed release GO.
        # Neither overrides ExecStart, identity, secrets, sockets nor ports.
        if successor_source:
            candidate_bytes = (
                "[Service]\nWorkingDirectory=" + SUCCESSOR_DESTINATION + "\n"
            ).encode("ascii")
            result[_SUCCESSOR_BROKER_DROPIN] = candidate_bytes
            # The broker uses its own already-qualified UID990 signer assets.
            # Only UID991's *private* V2 mount namespace receives isolated
            # signer copies and writable temporary verifier workspaces.
            result[_SUCCESSOR_EXECUTOR_DROPIN] = (
                candidate_bytes
                + (_SUCCESSOR_VERIFIER_BINDS + "\n"
                   + _SUCCESSOR_VERIFIER_TMPFS + "\n").encode("ascii")
                + (b"Environment=ANALYTICS_REVIEWED_SUPERVISOR_V2=1\n"
                   if owner_authorized_first_successor else b"")
            )
        expected_paths = {
            _ANALYTICS_RUNTIME_DROPIN,
            *(destination for _source, destination in _SERVICE_SOURCES),
        }
        if successor_source:
            expected_paths.update((
                _SUCCESSOR_BROKER_DROPIN, _SUCCESSOR_EXECUTOR_DROPIN,
            ))
        if (
            set(result) != expected_paths
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

