"""File: deployment/analytics_source_handoff.py

Purpose: Produce a read-only, deterministic Git-object handoff for the EXACT
         Analytics Task014 DEV source, including five explicit shared-file updates. This is the missing input to
         an independently authorized root-owned application installation.
Related: deployment/application_manifest.py (original closed Git-object reader),
         deployment/application_source_set.py (original canary source boundary),
         deployment/analytics_executor_service_config.py (20 mandatory Python
         source hashes plus four signed runtime/source assets),
         deployment/systemd/dev/analytics-broker-enabled.conf,
         deployment/tests/test_analytics_source_handoff.py.

Sections: exact new and shared-compatibility source selection; original Git-blob and source-claim
          validation; canonical unsigned install-handoff review manifest.

SECURITY: This module reads Git objects only. It has no installer, root writer,
Docker/registry/secret access, systemd action, or deployment authorization.
The resulting hashes are NOT a trusted release, root-owned source manifest,
approved repository revision or permission to install. An original approved
Task014 host operation must independently bind the exact reviewed Git commit,
source hashes, protected config, process identities and existing canary state.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re

from . import application_manifest as _git
from .application_source_set import DevApplicationSourceSet
from .analytics_executor_service_config import (
    ANALYTICS_INSTALLED_FILES,
    _INSTALLED_RUNTIME_FILES,
    _SOURCE_CLAIM_PATH,
    _SOURCE_CLAIM_SHA256,
)
from .policy import canonical_bytes
from .saas_product_contract import SaaSProductProfile
from .saas_product_runtime import SaaSRuntimeProfile

_ERROR = "Analytics Task014 additive Git source handoff is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_MAX_TOTAL_BYTES = 12 * 1024 * 1024
_MAX_HANDOFF_BYTES = 16 * 1024
_MAX_ONE_FILE = 1024 * 1024
_ADDITIVE_UNITS = (
    "deployment/systemd/dev/analytics-broker-enabled.conf",
    "deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service",
    "deployment/systemd/dev/omnilyzer-deployment-analytics-executor.socket",
)
# Five pre-existing ORIGINAL C32V Task014 modules must be updated to let
# the new Analytics broker use scoped registry GET, OCI signature, sealed
# credential APIs and SIGNED external-source parsing. Three match the
# protected platform base; the fourth (promotion.py) is a genuine older
# installed source from ba4fd3. All FIVE preimage hashes were independently
# verified against the LIVE DEV host and exact historical Git objects on
# 2026-10-30. This explicit closed
# compatibility patch is NOT a generic canary source allowlist expansion.
_SHARED_BASE_COMMIT = "b9e22e745ecbaf96dc15998e91d1a74f70e5ad77"
_SHARED_COMPATIBILITY_FILES = (
    "deployment/oci_verifier.py",
    "deployment/private_registry_fd.py",
    "deployment/promotion.py",
    "deployment/release_consumer.py",
    "deployment/unix_transport.py",
)
_PROMOTION_INSTALLED_COMMIT = "ba4fd3cacb33f71a626eeb3877a886f0fe31c82a"
_SHARED_PREIMAGE_COMMITS = {
    "deployment/oci_verifier.py": _SHARED_BASE_COMMIT,
    "deployment/private_registry_fd.py": _SHARED_BASE_COMMIT,
    "deployment/promotion.py": _PROMOTION_INSTALLED_COMMIT,
    "deployment/release_consumer.py": _SHARED_BASE_COMMIT,
    "deployment/unix_transport.py": _SHARED_BASE_COMMIT,
}
_SHARED_PREIMAGE_SHA256 = {
    "deployment/unix_transport.py":
        "8488bad2876df513c1aa3ddda626c8e9cb85e0ed905357561a3e004ee2bf6904",
    "deployment/oci_verifier.py":
        "caf85eb39585ce35d5b3e5528401f78e7abe98cdcb470af55ee4dd6bdbbc30c2",
    "deployment/private_registry_fd.py":
        "79bae35b1f62a7b33f1851275e24fa4a8f5b2077fc61fbb80b119ed7c2d4ad80",
    "deployment/promotion.py":
        "dd5fdc5dfaf3734eb26bfc7dae293d0797480ab03930f3da165bed710c5cbea0",
    "deployment/release_consumer.py":
        "d087a956ec74b2f9aaf5653537afb533460b7a0f7be498d9f6c0daa72abc6784",
}
_PRODUCT_PROFILE_SHA256 = "e54bad9537541c7ecc4056753e8cbddbf6653d53deb1be222daf2b9ffe1659f0"
_RUNTIME_PROFILE_SHA256 = "95fd22e7a406bbc90d1f014e29fc8564028adae9dd352abfece46c3b24faf661"
_PRODUCT_PATH, _RUNTIME_PATH, _COMPOSE_PATH, _CLAIM_PATH = _INSTALLED_RUNTIME_FILES


class AnalyticsSourceHandoffError(Exception):
    """One fail-closed error for unsigned additive source evidence."""


def review_analytics_source_handoff(
    *, repository_root: str, reviewed_commit: str,
) -> bytes:
    """Inspect exactly one checked-out immutable Git generation without writes.

    The returned canonical JSON is an *unsigned review input* only, not an
    install operation, a signature verification, or root authority. Every file
    is selected by fixed code, and ALL bytes come from matching Git objects,
    never from mutable working-tree copies or user-controlled file paths.
    """
    try:
        if (
            type(repository_root) is not str or not repository_root.startswith("/")
            or type(reviewed_commit) is not str
            or re.fullmatch(r"[0-9a-f]{40}", reviewed_commit) is None
            or reviewed_commit == "0" * 40
            or not Path(repository_root).is_dir()
        ):
            raise ValueError
        base = DevApplicationSourceSet()
        original = {item.repository_path for item in base.files}
        if (
            type(base) is not DevApplicationSourceSet
            or len(ANALYTICS_INSTALLED_FILES) != 20
            or len(set(ANALYTICS_INSTALLED_FILES)) != 20
            or len(_INSTALLED_RUNTIME_FILES) != 4
            or len(_ADDITIVE_UNITS) != 3
        ):
            raise ValueError
        selected = tuple(sorted((
            *ANALYTICS_INSTALLED_FILES, *_INSTALLED_RUNTIME_FILES,
            *_ADDITIVE_UNITS, *_SHARED_COMPATIBILITY_FILES,
        )))
        if (
            len(selected) != 32 or len(set(selected)) != 32
            or set(selected) & original != set(_SHARED_COMPATIBILITY_FILES)
            or set(_SHARED_PREIMAGE_SHA256) != set(_SHARED_COMPATIBILITY_FILES)
            or set(_SHARED_PREIMAGE_COMMITS) != set(_SHARED_COMPATIBILITY_FILES)
        ):
            raise ValueError

        # Original Task014 C26 performs bounded Git commands with no hooks,
        # no replacement object lookups, no network, and strict 100644 mode.
        top = _git._output(
            repository_root, ("rev-parse", "--show-toplevel"), 4096,
        )
        if (
            top != os.fsencode(repository_root) + b"\n"
            or _git._output(
                repository_root, ("rev-parse", "--verify", "HEAD^{commit}"), 41,
            ) != reviewed_commit.encode("ascii") + b"\n"
            or _git._output(
                repository_root, ("cat-file", "-t", reviewed_commit), 16,
            ) != b"commit\n"
        ):
            raise ValueError
        records = _git._tree(_git._output(
            repository_root, (
                "ls-tree", "-r", "-z", "--full-tree", reviewed_commit,
                "--", *selected,
            ), 32768,
        ), selected)
        sizes: list[int] = []
        for _name, blob in records:
            size_raw = _git._output(
                repository_root, ("cat-file", "-s", blob), 32,
            )
            if re.fullmatch(rb"[1-9][0-9]*\n", size_raw) is None:
                raise ValueError
            sizes.append(int(size_raw[:-1]))
        if (
            any(value > _MAX_ONE_FILE for value in sizes)
            or sum(sizes) > _MAX_TOTAL_BYTES
        ):
            raise ValueError

        entries: list[dict[str, object]] = []
        found: dict[str, bytes] = {}
        for (path, blob), expected_size in zip(records, sizes):
            raw = _git._output(
                repository_root, ("cat-file", "blob", blob),
                expected_size,
            )
            if type(raw) is not bytes or len(raw) != expected_size:
                raise ValueError
            found[path] = raw
            entries.append({
                "path": path, "sha256": hashlib.sha256(raw).hexdigest(),
                "mode": "0644",
            })
        # The historical original three *installed* files must have the
        # exact independently verified preimage; otherwise a root-approved
        # host operation cannot safely replace or roll them back.
        for path in _SHARED_COMPATIBILITY_FILES:
            historical = _SHARED_PREIMAGE_COMMITS[path]
            previous = _git._tree(_git._output(
                repository_root, (
                    "ls-tree", "-r", "-z", "--full-tree", historical,
                    "--", path,
                ), 8192,
            ), (path,))
            preimage = _git._output(
                repository_root, ("cat-file", "blob", previous[0][1]),
                _MAX_ONE_FILE,
            )
            if (
                hashlib.sha256(preimage).hexdigest() != _SHARED_PREIMAGE_SHA256[path]
                or hashlib.sha256(found[path]).hexdigest() == _SHARED_PREIMAGE_SHA256[path]
            ):
                raise ValueError
        # The 38 unchanged protected canary files are COPIED from the already
        # root-owned original application into a separate Analytics source
        # generation. Pin their raw Git preimage hashes here so a future
        # privileged installer can reject altered host bytes before staging.
        inherited = tuple(item.repository_path for item in base.files
                          if item.repository_path not in _SHARED_COMPATIBILITY_FILES)
        if len(inherited) != 38:
            raise ValueError
        inherited_records = _git._tree(_git._output(
            repository_root, ("ls-tree", "-r", "-z", "--full-tree",
                              _SHARED_BASE_COMMIT, "--", *inherited), 32768,
        ), inherited)
        inherited_hashes: dict[str, str] = {}
        for path, oid in inherited_records:
            blob = _git._output(
                repository_root, ("cat-file", "blob", oid), _MAX_ONE_FILE,
            )
            # The copied legacy file must be identical at the NEW product
            # generation as it was in the protected C32V original baseline.
            current = _git._tree(_git._output(
                repository_root, ("ls-tree", "-r", "-z", "--full-tree",
                                  reviewed_commit, "--", path), 8192,
            ), (path,))
            if current[0][1] != oid:
                raise ValueError
            inherited_hashes[path] = hashlib.sha256(blob).hexdigest()
        if (
            hashlib.sha256(found[_SOURCE_CLAIM_PATH]).hexdigest()
                != _SOURCE_CLAIM_SHA256
            or SaaSProductProfile.from_json_bytes(
                found[_PRODUCT_PATH],
            ).sha256() != _PRODUCT_PROFILE_SHA256
            or SaaSRuntimeProfile.from_json_bytes(
                found[_RUNTIME_PATH],
            ).sha256() != _RUNTIME_PROFILE_SHA256
            or _git._output(
                repository_root, ("rev-parse", "--verify", "HEAD^{commit}"), 41,
            ) != reviewed_commit.encode("ascii") + b"\n"
        ):
            raise ValueError

        review = canonical_bytes({
            "schema_version": 1,
            "purpose": "analytics-task014-additive-source-review-only",
            "source_commit": reviewed_commit,
            "source_repository": "MichaelTrueX/omnilyzer-platform",
            "source_file_count": 32,
            "source_entries": entries,
            "shared_base_source_commit": _SHARED_BASE_COMMIT,
            "shared_patch_paths": list(_SHARED_COMPATIBILITY_FILES),
            "shared_preimage_sha256": dict(_SHARED_PREIMAGE_SHA256),
            "shared_preimage_commits": dict(_SHARED_PREIMAGE_COMMITS),
            "inherited_canary_sha256": inherited_hashes,
            "isolation_target": "/opt/omnilyzer/deployment/analytics-app",
            # These four reviewed hashes are exactly the inputs needed by
            # the separately ROOT-OWNED service config after owner approval.
            # They do NOT authorize an install by themselves.
            "reviewed_compose_sha256": hashlib.sha256(
                found[_COMPOSE_PATH],
            ).hexdigest(),
            "reviewed_product_profile_sha256": _PRODUCT_PROFILE_SHA256,
            "reviewed_runtime_profile_sha256": _RUNTIME_PROFILE_SHA256,
            "reviewed_source_claim_sha256": _SOURCE_CLAIM_SHA256,
            "signed_release_authorized": False,
            "deployment_authorized": False,
        })
        if len(review) > _MAX_HANDOFF_BYTES:
            raise ValueError
        return review
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsSourceHandoffError(_ERROR) from None


__all__ = (
    "AnalyticsSourceHandoffError", "review_analytics_source_handoff",
)

