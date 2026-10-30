"""File: deployment/analytics_source_archive.py

Purpose: Build and verify ONE deterministic unsigned Task014 Analytics additive
         source archive containing the existing 27-file Git-object handoff.
Related: deployment/analytics_source_handoff.py (original C26 Git-object
         evidence), deployment/analytics_executor_service_config.py (closed
         exact service source set), deployment/application_manifest.py (Git
         verifier), deployment/tests/test_analytics_source_archive.py.

Sections: canonical source archive writer, exact Git blob acquisition, bounded
          canonical source archive parser, original immutable source verification.

Security: import/build/verify have NO installation, root privilege, network,
          Docker, systemd, database, secret access or deployment authorization.
          The archive is NOT a signed release or a privileged grant. A future
          authorized original Task014 root-owned installer must bind its digest
          and reviewed Git commit to owner-approved source policy BEFORE
          using the returned bytes. Never tar.extractall() on this archive.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile

from . import application_manifest as _original_git
from .analytics_source_handoff import (
    AnalyticsSourceHandoffError, review_analytics_source_handoff,
)
from .policy import canonical_bytes

_ERROR = "Task014 Analytics source archive is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_META_PATH = ".omnilyzer-analytics-source-review.json"
_MAX_TOTAL = 14 * 1024 * 1024
_MAX_FILE = 1024 * 1024
_MAX_MANIFEST = 8192
_SOURCE_TOTAL = 27
_SHA_RE = re.compile(r"[0-9a-f]{64}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")


class AnalyticsSourceArchiveError(Exception):
    """A canonical unsigned source archive was invalid or unavailable."""


def _validate_manifest(raw: bytes, expected_sha: str, commit: str) -> dict:
    """Require one exact, canonical, immutable additive source review."""
    if (
        type(raw) is not bytes or not 0 < len(raw) <= _MAX_MANIFEST
        or type(expected_sha) is not str
        or _SHA_RE.fullmatch(expected_sha) is None
        or type(commit) is not str or _COMMIT_RE.fullmatch(commit) is None
        or commit == "0" * 40 or hashlib.sha256(raw).hexdigest() != expected_sha
    ):
        raise ValueError
    value = json.loads(raw)
    if (
        type(value) is not dict or set(value) != {
            "schema_version", "purpose", "source_commit", "source_repository",
            "source_file_count", "source_entries", "reviewed_compose_sha256",
            "reviewed_product_profile_sha256", "reviewed_runtime_profile_sha256",
            "reviewed_source_claim_sha256", "signed_release_authorized",
            "deployment_authorized",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["purpose"] != "analytics-task014-additive-source-review-only"
        or value["source_commit"] != commit
        or value["source_repository"] != "MichaelTrueX/omnilyzer-platform"
        or type(value["source_file_count"]) is not int
        or value["source_file_count"] != _SOURCE_TOTAL
        or value["signed_release_authorized"] is not False
        or value["deployment_authorized"] is not False
        or type(value["source_entries"]) is not list
        or len(value["source_entries"]) != _SOURCE_TOTAL
        or canonical_bytes(value) != raw
    ):
        raise ValueError
    for field in (
        "reviewed_compose_sha256", "reviewed_product_profile_sha256",
        "reviewed_runtime_profile_sha256", "reviewed_source_claim_sha256",
    ):
        if type(value[field]) is not str or _SHA_RE.fullmatch(value[field]) is None:
            raise ValueError
    return value


def _archive_bytes(
    manifest: bytes, entries: tuple[tuple[str, bytes], ...],
) -> bytes:
    """Write one exact USTAR, fixed mode/UID/GID/mtime and selected paths."""
    with io.BytesIO() as output:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for path, payload in ((_META_PATH, manifest), *entries):
                if type(path) is not str or type(payload) is not bytes:
                    raise ValueError
                header = tarfile.TarInfo(path)
                header.size = len(payload)
                header.mode = 0o644
                header.uid = 0
                header.gid = 0
                header.uname = ""
                header.gname = ""
                header.mtime = 0
                header.type = tarfile.REGTYPE
                tar.addfile(header, io.BytesIO(payload))
        result = output.getvalue()
    if not 0 < len(result) <= _MAX_TOTAL:
        raise ValueError
    return result


def build_analytics_source_archive(
    *, repository_root: str, reviewed_commit: str,
) -> bytes:
    """Read original C26 pinned Git blobs, never working-tree or release tags.

    Rechecks the same Git HEAD after the full read and rejects any discrepancy
    with the 27-file source inventory. No user-provided path, URL or package
    member can change the exact repository-to-application selection.
    """
    try:
        review = review_analytics_source_handoff(
            repository_root=repository_root, reviewed_commit=reviewed_commit,
        )
        model = _validate_manifest(
            review, hashlib.sha256(review).hexdigest(), reviewed_commit,
        )
        names = tuple(entry["path"] for entry in model["source_entries"])
        records = _original_git._tree(_original_git._output(
            repository_root,
            ("ls-tree", "-r", "-z", "--full-tree", reviewed_commit, "--", *names),
            32768,
        ), names)
        entries: list[tuple[str, bytes]] = []
        total = 0
        for (path, blob), expected in zip(records, model["source_entries"]):
            size_raw = _original_git._output(
                repository_root, ("cat-file", "-s", blob), 32,
            )
            if re.fullmatch(rb"[1-9][0-9]*\n", size_raw) is None:
                raise ValueError
            size = int(size_raw[:-1])
            if size > _MAX_FILE:
                raise ValueError
            total += size
            if total > _MAX_TOTAL - _MAX_MANIFEST:
                raise ValueError
            payload = _original_git._output(
                repository_root, ("cat-file", "blob", blob), size,
            )
            if (
                len(payload) != size or path != expected["path"]
                or hashlib.sha256(payload).hexdigest() != expected["sha256"]
                or expected["mode"] != "0644"
            ):
                raise ValueError
            entries.append((path, payload))
        if _original_git._output(
            repository_root, ("rev-parse", "--verify", "HEAD^{commit}"), 41,
        ) != reviewed_commit.encode("ascii") + b"\n":
            raise ValueError
        return _archive_bytes(review, tuple(entries))
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsSourceArchiveError(_ERROR) from None


def verify_analytics_source_archive(
    raw: bytes, *, expected_manifest_sha256: str, reviewed_commit: str,
) -> tuple[tuple[str, bytes], ...]:
    """Verify exact 28-member canonical USTAR and return 27 inert raw blobs.

    The caller must derive expected_manifest_sha256 from separately reviewed
    ROOT-OWNED authority, never from the archive or HTTP request. The return
    value is only verified data; it cannot deploy, authenticate or grant.
    """
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _MAX_TOTAL:
            raise ValueError
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            # tar.getmembers() can allocate memory for every header in a
            # malicious small-input zero-length-file TAR. Cap iteration at
            # the exact 28 legitimate members plus ONE unexpected header.
            members = []
            for _ in range(_SOURCE_TOTAL + 2):
                member = tar.next()
                if member is None:
                    break
                members.append(member)
            if len(members) != _SOURCE_TOTAL + 1 or tar.next() is not None:
                raise ValueError
            if members[0].name != _META_PATH:
                raise ValueError
            if any(
                not member.isfile()
                or member.mode != 0o644 or member.uid != 0 or member.gid != 0
                or member.mtime != 0 or member.uname or member.gname
                or member.pax_headers or member.linkname
                or not 0 < member.size <= _MAX_FILE
                for member in members
            ):
                raise ValueError
            manifest_source = tar.extractfile(members[0])
            if manifest_source is None or members[0].size > _MAX_MANIFEST:
                raise ValueError
            manifest = manifest_source.read(_MAX_MANIFEST + 1)
            model = _validate_manifest(
                manifest, expected_manifest_sha256, reviewed_commit,
            )
            entries = model["source_entries"]
            names = tuple(entry["path"] for entry in entries)
            # Fixed product-specific paths only; no traversal or extras.
            from .analytics_executor_service_config import (
                ANALYTICS_INSTALLED_FILES, _INSTALLED_RUNTIME_FILES,
            )
            from .analytics_source_handoff import _ADDITIVE_UNITS
            approved = tuple(sorted((
                *ANALYTICS_INSTALLED_FILES,
                *_INSTALLED_RUNTIME_FILES,
                *_ADDITIVE_UNITS,
            )))
            if names != approved or tuple(m.name for m in members[1:]) != approved:
                raise ValueError
            contents: list[tuple[str, bytes]] = []
            for member, entry in zip(members[1:], entries):
                if (type(entry) is not dict or set(entry) != {"path", "sha256", "mode"}
                        or member.name != entry["path"] or entry["mode"] != "0644"):
                    raise ValueError
                handle = tar.extractfile(member)
                if handle is None:
                    raise ValueError
                payload = handle.read(_MAX_FILE + 1)
                if (
                    len(payload) != member.size
                    or hashlib.sha256(payload).hexdigest() != entry["sha256"]
                ):
                    raise ValueError
                contents.append((member.name, payload))
        # Deny duplicate headers, noncanonical bytes, trailing TAR garbage,
        # links, sparse objects and alternate encodings, not just bad hashes.
        if _archive_bytes(manifest, tuple(contents)) != raw:
            raise ValueError
        return tuple(contents)
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsSourceArchiveError(_ERROR) from None


__all__ = (
    "AnalyticsSourceArchiveError", "build_analytics_source_archive",
    "verify_analytics_source_archive",
)
