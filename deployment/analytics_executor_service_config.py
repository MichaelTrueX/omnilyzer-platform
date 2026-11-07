"""File: deployment/analytics_executor_service_config.py

Purpose: Read the one root-controlled Analytics-only Task014 DEV service
         authorization configuration and verify the installed product code.
Related: deployment/executor_service_config_loader.py (existing hardened C17
         source, UID/GID and root-owned directory checks),
         deployment/analytics_executor_composition.py (inert runtime graph),
         deployment/analytics_executor_service_bootstrap.py (socket activation),
         deployment/tests/test_analytics_executor_service_config.py.

Sections: original closed 20-source schema-1 installation, separate
          closed 24-object V2 root-approved installation grammar, canonical JSON configuration,
          descriptor-relative owner verification, immutable installed
          file hash checking and original C17 executor identity binding.

SECURITY: This module is inert until load_analytics_executor_service_config()
is explicitly called by the separate installed root-owned systemd service.
Even successful loading is NOT GitHub approval, signature acceptance or a
user-install authorization. The original Task014 broker still verifies the
real signed 0.15.0 release, OIDC and sealed Zot permission.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from .analytics_signed_release_consumer import PINNED_IMAGE
from .analytics_unix_boundary import _root_reviewed_source
from .executor_service_config_loader import (
    load_dev_executor_service_configuration,
    _open_directories, _required_flags, _process_identity, _configuration_file,
    _bounded_read, _revalidate_directories, _close_owned,
)
from .policy import canonical_bytes
from .identity import validate_expected_workflow_sha
from .rootless_docker_authority import RootlessDockerAuthority
from .saas_product_contract import SaaSProductProfile
from .saas_product_runtime import SaaSRuntimeProfile

# Only these exact new Analytics sources are in the privilege-changing graph.
# Existing Task014 canary sources are protected by their original 43-file
# installed source manifest; this list must be separately reviewed by M04.
ANALYTICS_INSTALLED_FILES = (
    "deployment/analytics_broker_router.py",
    "deployment/analytics_broker_service.py",
    "deployment/analytics_broker_service_entrypoint.py",
    "deployment/analytics_dev_release_review.py",
    "deployment/analytics_execution.py",
    "deployment/analytics_executor.py",
    "deployment/analytics_executor_composition.py",
    "deployment/analytics_executor_service_bootstrap.py",
    "deployment/analytics_executor_service_config.py",
    "deployment/analytics_executor_service_entrypoint.py",
    "deployment/analytics_first_install.py",
    "deployment/analytics_private_registry.py",
    "deployment/analytics_promotion_broker.py",
    "deployment/analytics_registry_review_composition.py",
    "deployment/analytics_signed_release_consumer.py",
    "deployment/analytics_signed_source_pin.py",
    "deployment/rootless_docker_authority.py",
    "deployment/analytics_unix_boundary.py",
    "deployment/saas_product_contract.py",
    "deployment/saas_product_runtime.py",
)
# Section: future V2 upgrade source graph. The 20-source original
# Analytics 0.15.0 installed schema-1 set above MUST remain unchanged.
# An owner-reviewed future source-generation-2 installer must attest each
# EXTRA file and approve a separately bound source/config version.
# Merely having the files in this source tree confers no deployment authority.
ANALYTICS_SUCCESSOR_DEPLOYMENT_FILES = (
    "deployment/analytics_active_state_review.py",
    "deployment/analytics_loopback_guard.py",
    "deployment/analytics_route_journal.py",
    "deployment/sigstore_authority_provenance.py",
)
ANALYTICS_SUCCESSOR_RELEASE_FILES = (
    "release/analytics_owner_source_selection.py",
)
# The existing candidate Compose reset overlay is a privileged routing
# input: bind its immutable Git blob in the SAME root-controlled V2 source
# closure. The historical 0.15.0 V1 source set remains byte-identical.
ANALYTICS_SUCCESSOR_COMPOSE_FILES = (
    "deployment/runtime/dev/analytics.compose.successor-ports.yaml",
)
ANALYTICS_SUCCESSOR_INSTALLED_FILES = tuple(sorted((
    *ANALYTICS_INSTALLED_FILES,
    *ANALYTICS_SUCCESSOR_DEPLOYMENT_FILES,
    *ANALYTICS_SUCCESSOR_RELEASE_FILES,
    *ANALYTICS_SUCCESSOR_COMPOSE_FILES,
)))

# These three are already bound inside the signed Analytics source claim.
# Product/runtime profile hashes are SHA256(canonical parsed profile), NOT
# SHA256(raw JSON file bytes); the original exact profile classes own them.
_PRODUCT_PATH = "deployment/products/analytics-dev.json"
_RUNTIME_PATH = "deployment/products/analytics-runtime-dev.json"
_COMPOSE_PATH = "deployment/runtime/dev/analytics.compose.review.yaml"
# A required signed-release source-claim is read at runtime from the
# INSTALLED app's release/ directory by analytics_signed_source_pin.py.
# Its exact raw SHA comes from original reviewed Git-object evidence.
# Omitting this file would let the source pass preflight but always reject
# the genuine signed 0.15.0 release in the live broker.
_SOURCE_CLAIM_PATH = "release/products/analytics-source.json"
_SOURCE_CLAIM_SHA256 = "45e13536c413a5e5c0a39a4d8c98daf412614dec535398b2ba204039772c88b9"
_INSTALLED_RUNTIME_FILES = (
    _PRODUCT_PATH, _RUNTIME_PATH, _COMPOSE_PATH, _SOURCE_CLAIM_PATH,
)
CONFIG_PATH = "/etc/omnilyzer/deployment/dev/analytics-executor.json"
_INSTALLED_ROOT = Path("/opt/omnilyzer/deployment/analytics-app")
# A separately owner-installed schema-2 source is verified only beside V1.
# This is NOT a generic source root or permission to alter active service.
_SUCCESSOR_INSTALLED_ROOT = Path("/opt/omnilyzer/deployment/analytics-app-candidate")
_CONFIGURATION_NAME = "analytics-executor.json"
_FIELDS = frozenset({
    "schema_version", "product_id", "stage", "reviewed_installed_commit",
    "reviewed_compose_sha256", "reviewed_product_profile_sha256",
    "reviewed_runtime_profile_sha256", "source_sha256",
})
# Only a root-installed V2 source is allowed to carry the independent
# workflow trust anchor used by UID991 for three-audience signature checking.
# Historical V1 schema/bytes and source allowlist remain exactly unchanged.
_SUCCESSOR_FIELDS = _FIELDS | frozenset({"expected_workflow_sha"})
_MAX_BYTES = 4096
_FILE_BOUND = 1024 * 1024
_TOTAL_BOUND = 12 * 1024 * 1024
_ERROR = "Task014 Analytics executor installed authority is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class AnalyticsInstalledAuthorityError(Exception):
    """One fail-closed root-owned installed source/identity verification."""


def _exact_json(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicated JSON keys before any source may be accepted."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def parse_analytics_executor_service_config(raw: bytes) -> dict[str, object]:
    """Parse canonical root-owned product configuration, never a caller grant."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _MAX_BYTES:
            raise ValueError
        value = json.loads(
            raw.decode("ascii"), object_pairs_hook=_exact_json,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError),
        )
        if type(value) is not dict:
            raise ValueError
        # Section: disjoint exact V1/V2 schemas; a successor-only workflow
        # SHA can never make historical schema-1 bytes newly acceptable.
        generation = value.get("schema_version")
        if (
            type(generation) is not int or generation not in (1, 2)
            or set(value) != (_FIELDS if generation == 1 else _SUCCESSOR_FIELDS)
        ):
            raise ValueError
        if (type(generation) is not int or generation not in (1, 2)
                or value["product_id"] != "analytics"
                or type(value["product_id"]) is not str
                or type(value["stage"]) is not str or value["stage"] != "dev"):
            raise ValueError
        paths = (ANALYTICS_INSTALLED_FILES if generation == 1
                 else ANALYTICS_SUCCESSOR_INSTALLED_FILES)
        source = value["source_sha256"]
        if (
            len(ANALYTICS_INSTALLED_FILES) != 20
            or len(set(ANALYTICS_INSTALLED_FILES)) != 20
            or len(ANALYTICS_SUCCESSOR_INSTALLED_FILES) != 26
            or len(set(ANALYTICS_SUCCESSOR_INSTALLED_FILES)) != 26
            or set(ANALYTICS_SUCCESSOR_INSTALLED_FILES) - set(ANALYTICS_INSTALLED_FILES)
                != set(ANALYTICS_SUCCESSOR_DEPLOYMENT_FILES)
                | set(ANALYTICS_SUCCESSOR_RELEASE_FILES)
                | set(ANALYTICS_SUCCESSOR_COMPOSE_FILES)
            or type(source) is not dict or set(source) != set(paths)
            or any(type(key) is not str or type(v) is not str
                   or len(v) != 64 or any(c not in "0123456789abcdef" for c in v)
                   for key, v in source.items())
        ):
            raise ValueError
        workflow = None
        if generation == 2:
            workflow = validate_expected_workflow_sha(
                value["expected_workflow_sha"],
            )
            if workflow == "0" * 40:
                raise ValueError("missing reviewed workflow")
        reviewed = _root_reviewed_source({
            key: value[key] for key in (
                "reviewed_installed_commit",
                "reviewed_compose_sha256",
                "reviewed_product_profile_sha256",
                "reviewed_runtime_profile_sha256",
            )
        })
        # No arbitrary path, unknown profile, build/version/registry or
        # user-provided role can enter this source admission.
        if canonical_bytes(value) != raw or len(raw) > _MAX_BYTES:
            raise ValueError
        return {
            **dict(reviewed),
            "source_generation": generation,
            **({"expected_workflow_sha": workflow}
               if generation == 2 else {}),
            "source_sha256": tuple((p, source[p]) for p in paths),
        }
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsInstalledAuthorityError(_ERROR) from None


def _verify_source_bytes(
    expected: tuple[tuple[str, str], ...],
    *, root: Path = _INSTALLED_ROOT,
) -> None:
    """Read exact generation-specific source via fd-relative O_NOFOLLOW.

    Root-owned schema 1 accepts only the original 20-file live directory;
    schema 2 accepts only the exact 24-file inactive candidate directory.
    The real installed root and all ancestors must be root-owned and not
    writable by any unprivileged role. Files must be single-link, mode0644,
    bounded, regular and byte-hash identical to root-owned installed policy.
    """
    if type(expected) is not tuple or root not in (
        _INSTALLED_ROOT, _SUCCESSOR_INSTALLED_ROOT,
    ):
        raise AnalyticsInstalledAuthorityError(_ERROR)
    # Check generation/root pairing before opening even one host descriptor.
    # V2 cannot self-authorize a read of the V1 active path and vice versa.
    v1_names = (*ANALYTICS_INSTALLED_FILES, *_INSTALLED_RUNTIME_FILES)
    v2_names = (*ANALYTICS_SUCCESSOR_INSTALLED_FILES, *_INSTALLED_RUNTIME_FILES)
    names = tuple(name for name, _sha in expected)
    if (
        (root == _INSTALLED_ROOT and names != v1_names)
        or (root == _SUCCESSOR_INSTALLED_ROOT and names != v2_names)
    ):
        raise AnalyticsInstalledAuthorityError(_ERROR)
    descriptors: list[int] = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        current = Path("/")
        parent: int | None = None
        for component in ("", *root.parts[1:]):
            if component:
                current /= component
            directory = os.open(str(current), directory_flags)
            descriptors.append(directory)
            meta = os.fstat(directory)
            named = os.stat(str(current), follow_symlinks=False)
            if (
                not stat.S_ISDIR(meta.st_mode)
                or meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) & 0o022
                or (meta.st_dev, meta.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise OSError
            parent = directory
        assert parent is not None
        total = 0
        # Only a complete schema-1 or schema-2 ordered source vector is
        # accepted, followed by the SAME four original runtime assets.
        # V2 additionally pins the Compose reset override as a SHA source.
        approved_names = set(v2_names)
        for name, digest in expected:
            if name not in approved_names or type(digest) is not str:
                raise ValueError
            parts = name.split("/")
            if (
                not 2 <= len(parts) <= 5
                or not (parts[0] == "deployment"
                        or name in (_SOURCE_CLAIM_PATH,
                                    *ANALYTICS_SUCCESSOR_RELEASE_FILES))
            ):
                raise ValueError
            # All components are literally selected from reviewed module
            # constants above. No request-selected path or filesystem walk.
            inside = parent
            for part in parts[:-1]:
                next_dir = os.open(part, directory_flags, dir_fd=inside)
                descriptors.append(next_dir)
                dir_status = os.fstat(next_dir)
                named_dir = os.stat(part, dir_fd=inside, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(dir_status.st_mode)
                    or dir_status.st_uid != 0
                    or stat.S_IMODE(dir_status.st_mode) & 0o022
                    or (dir_status.st_dev, dir_status.st_ino)
                    != (named_dir.st_dev, named_dir.st_ino)
                ):
                    raise OSError
                inside = next_dir
            filename = parts[-1]
            desc = os.open(filename, file_flags, dir_fd=inside)
            descriptors.append(desc)
            before = os.fstat(desc)
            named_file = os.stat(filename, dir_fd=inside, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o644
                or not 0 < before.st_size <= _FILE_BOUND
                or (before.st_dev, before.st_ino) != (named_file.st_dev, named_file.st_ino)
            ):
                raise OSError
            data = bytearray()
            while len(data) <= _FILE_BOUND:
                part = os.read(desc, min(65536, _FILE_BOUND + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            total += len(data)
            if name == _PRODUCT_PATH:
                actual = SaaSProductProfile.from_json_bytes(bytes(data)).sha256()
            elif name == _RUNTIME_PATH:
                actual = SaaSRuntimeProfile.from_json_bytes(bytes(data)).sha256()
            else:
                actual = hashlib.sha256(data).hexdigest()
            after = os.fstat(desc)
            if (
                len(data) != before.st_size or total > _TOTAL_BOUND
                or actual != digest
                # Read-only access can legitimately change access time;
                # source identity, content, mode and change time MUST NOT.
                or (after.st_dev, after.st_ino, after.st_mode,
                    after.st_uid, after.st_gid, after.st_nlink,
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (before.st_dev, before.st_ino, before.st_mode,
                    before.st_uid, before.st_gid, before.st_nlink,
                    before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            ):
                raise OSError
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsInstalledAuthorityError(_ERROR) from None
    finally:
        for desc in reversed(descriptors):
            os.close(desc)


def load_analytics_executor_service_config(
    *, require_successor: bool = False,
) -> tuple[dict[str, str], dict[str, int]]:
    """Check original hardened C17 identity and selected root-owned source.

    This is the only intended runtime route to a reviewed_installed_source
    mapping. A caller-constructible mapping never proves host installation.
    Default mode preserves original V1. An explicitly selected successor
    candidate requires schema2 plus the exact root-owned port-reset overlay.
    Neither successful read nor the flag confers release/deployment authority.
    """
    owned: list[int] = []
    try:
        if type(require_successor) is not bool:
            raise ValueError("invalid source-generation selection")
        base = load_dev_executor_service_configuration()
        initial = _process_identity()
        directory_flags, file_flags = _required_flags()
        dirs, parent = _open_directories(owned, directory_flags)
        named = _configuration_file(os.stat(
            _CONFIGURATION_NAME, dir_fd=parent, follow_symlinks=False,
        ))
        desc = os.open(_CONFIGURATION_NAME, file_flags, dir_fd=parent)
        owned.append(desc)
        opened = _configuration_file(os.fstat(desc))
        if opened != named or opened[5] != base.executor_gid:
            raise ValueError
        raw = _bounded_read(desc, opened[6])
        # C17 still owns process identity and canary runtime/ingress pins.
        # This separate root-owned config owns the Analytics generation;
        # verify its exact source bytes below without equating product releases.
        product = parse_analytics_executor_service_config(raw)
        # The original V1 service may keep its unchanged default, but a
        # successor Docker operation must never run against a V1-only root
        # source manifest that did not attest the port-reset overlay.
        if require_successor and product["source_generation"] != 2:
            raise ValueError("candidate requires protected generation two")
        if (
            _configuration_file(os.fstat(desc)) != opened
            or _configuration_file(os.stat(
                _CONFIGURATION_NAME, dir_fd=parent, follow_symlinks=False,
            )) != opened
            or _revalidate_directories(dirs)[5] != base.executor_gid
            or _process_identity() != initial
        ):
            raise ValueError
        identities = base.installation_contract().executor_composition_identity_kwargs()
        if (
            base.executor_uid != RootlessDockerAuthority().executor_uid
            or base.executor_gid != RootlessDockerAuthority().executor_gid
        ):
            raise ValueError
        source_root = (
            _SUCCESSOR_INSTALLED_ROOT if product["source_generation"] == 2
            else _INSTALLED_ROOT
        )
        _verify_source_bytes((
            *product["source_sha256"],
            (_PRODUCT_PATH, product["reviewed_product_profile_sha256"]),
            (_RUNTIME_PATH, product["reviewed_runtime_profile_sha256"]),
            (_COMPOSE_PATH, product["reviewed_compose_sha256"]),
            (_SOURCE_CLAIM_PATH, _SOURCE_CLAIM_SHA256),
        ), root=source_root)
        result = (
            {key: product[key] for key in (
                "reviewed_installed_commit", "reviewed_compose_sha256",
                "reviewed_product_profile_sha256", "reviewed_runtime_profile_sha256",
            )},
            {
                # The original canary projection also includes state-owner
                # IDs. Analytics uses its own operation and accepts only
                # the six shared peer/replay/socket IDs plus executor IDs.
                **{key: identities[key] for key in (
                    "expected_replay_directory_uid", "expected_replay_directory_gid",
                    "expected_broker_uid", "expected_broker_gid",
                    "expected_socket_owner_uid", "expected_socket_group_gid",
                )},
                "expected_executor_uid": base.executor_uid,
                "expected_executor_gid": base.executor_gid,
                **({"expected_workflow_sha": product["expected_workflow_sha"]}
                   if product["source_generation"] == 2 else {}),
            },
        )
    except _CONTROL:
        _close_owned(owned)
        raise
    except Exception:
        _close_owned(owned)
        raise AnalyticsInstalledAuthorityError(_ERROR) from None
    failed, control = _close_owned(owned)
    if control is not None:
        raise control
    if failed:
        raise AnalyticsInstalledAuthorityError(_ERROR)
    return result


__all__ = (
    "ANALYTICS_INSTALLED_FILES", "CONFIG_PATH", "AnalyticsInstalledAuthorityError",
    "parse_analytics_executor_service_config", "load_analytics_executor_service_config",
)

