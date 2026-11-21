"""DEV-only legacy Analytics0.16.0 OAT attestation, NOT a release grant.

The historical owner-approved root maintenance returned original signed
Analytics0.16.0 from blue0.15 to green0.16 using the SAME signed Task014
request SHA, but the route journal now shows generation2. Its original JWT
anti-replay row legitimately expired and the historical OAT did not create a
schema3 ordinary execution proof. A new UID991 user-created file MUST NOT
repair this authority: only a root:991 readonly 0440 lineage certificate,
created after owner-attended root receipt and live-OCI verification, can be
reviewed. Even this certificate is never sufficient on its own: UID991 must
also validate the existing installed Ed25519 owner source, the exact OCI
image/container/RootlessKit route and replay state separately on every boot.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from typing import Any

from .policy import canonical_bytes

LEGACY_REQUEST = "73071f42dffcce2dc7eaa2cf494335b6cc7e85eb7346c074529065f4fb079004"
LEGACY_RUN = 43838827603
LEGACY_FINAL_SHA = "e1efe4109156c6c0116a806dc287f7edbd6e828973db77f2fe4f6d2ceaa5d341"
LEGACY_VERSION = "0.16.0"
LEGACY_SOURCE = "a86a9b5e6a72afac05628e85335cbdf47c6f0255"
LEGACY_PLATFORM_SOURCE = "d18f8f5cab4be0be7873472c26d44d5d9c42a195"
LEGACY_IMAGE = (
    "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
    "a0ce1e63dd379c939a2e558b04307b129fa79128da1362"
    "caa90d963d8bb3f6a1"
)
LEGACY_GREEN = "c160029c449cbdf37f35515dd25e5e2235cdeb08f3eebe6525fee17d2d839432"
LEGACY_SLOT = "green"
CERTIFICATE_NAME = "legacy-completion-" + LEGACY_REQUEST + ".json"
_KIND = "owner_root_attested_legacy_0160_oat"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = frozenset({
    "schema_version", "kind", "original_run_id", "request_sha256",
    "current_journal_sha256", "final_release_receipt_sha256",
    "oat_before_sha256", "oat_restored_sha256",
    "oat_returned_sha256", "oat_result_sha256",
    "image", "container_id", "slot", "generation",
})


class Legacy0160AuthorityUnavailable(Exception):
    """A root-attested historical recovery boundary did not verify."""


def _reject() -> None:
    raise Legacy0160AuthorityUnavailable("legacy completed release is not verified")


def verify_root_legacy_certificate(
    payload: bytes, *, intent: dict[str, Any], file_uid: int,
    file_gid: int, file_mode: int, file_nlink: int,
) -> dict[str, Any]:
    """Check strictly root-owned immutable bridge + exact current journal.

    A pure parser for negative QA, but *its acceptance alone is NOT authority*.
    Real reads must establish immutable POSIX root:991 mode0440/nlink1 and
    independent live signed release proof in the caller.
    """
    try:
        if (type(payload) is not bytes or not 0 < len(payload) <= 1250
                or (file_uid, file_gid, file_mode, file_nlink) !=
                (0, 991, 0o440, 1)
                or type(intent) is not dict
                or intent.get("generation") != 2
                or intent.get("phase") != "switched"
                or intent.get("request_sha256") != LEGACY_REQUEST
                or intent.get("next_slot") != LEGACY_SLOT
                or intent.get("next_image") != LEGACY_IMAGE
                or intent.get("next_container_id") != LEGACY_GREEN):
            _reject()

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    _reject()
                result[key] = value
            return result

        document = json.loads(payload.decode("ascii"), object_pairs_hook=unique)
        if (type(document) is not dict
                or set(document) != _FIELDS
                or type(document["schema_version"]) is not int
                or document["schema_version"] != 1
                or document["kind"] != _KIND
                or type(document["original_run_id"]) is not int
                or document["original_run_id"] != LEGACY_RUN
                or document["request_sha256"] != LEGACY_REQUEST
                or document["final_release_receipt_sha256"] != LEGACY_FINAL_SHA
                or document["image"] != LEGACY_IMAGE
                or document["container_id"] != LEGACY_GREEN
                or document["slot"] != LEGACY_SLOT
                or type(document["generation"]) is not int
                or document["generation"] != 2
                or document["current_journal_sha256"] !=
                hashlib.sha256(canonical_bytes(intent)).hexdigest()
                or canonical_bytes(document) != payload):
            _reject()
        for key in (
            "oat_before_sha256", "oat_restored_sha256",
            "oat_returned_sha256", "oat_result_sha256",
        ):
            if (type(document[key]) is not str
                    or _SHA.fullmatch(document[key]) is None
                    or document[key] == "0" * 64):
                _reject()
        if len({
            document["oat_before_sha256"], document["oat_restored_sha256"],
            document["oat_returned_sha256"], document["oat_result_sha256"],
        }) != 4:
            _reject()
        return document
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        _reject()


def read_root_legacy_certificate(journal: object, intent: dict[str, Any]) -> dict[str, Any]:
    """Read the actual root-minted 0440 file inside UID991 protected journal.

    No caller input can pick a pathname, prefix, uid, mode or source SHA.
    The caller *must additionally verify* replay status, owner Ed25519 and live
    route and recheck journal stability before permitting socket receive.
    """
    from .analytics_route_journal import AnalyticsRouteJournal
    directory = proofs = fd = None
    try:
        if (type(journal) is not AnalyticsRouteJournal
                or (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) !=
                (991, 991, 991, 991)):
            _reject()
        directory = journal._open_dir()
        proofs = journal._open_executions(directory)
        fd = os.open(
            CERTIFICATE_NAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=proofs,
        )
        before = os.fstat(fd)
        named = os.stat(CERTIFICATE_NAME, dir_fd=proofs, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode)
                or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                or before.st_nlink != 1 or not 0 < before.st_size <= 1250):
            _reject()
        payload = os.read(fd, 1251)
        after = os.fstat(fd)
        if (len(payload) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            _reject()
        return verify_root_legacy_certificate(
            payload, intent=intent,
            file_uid=before.st_uid, file_gid=before.st_gid,
            file_mode=stat.S_IMODE(before.st_mode), file_nlink=before.st_nlink,
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        _reject()
    finally:
        if fd is not None:
            os.close(fd)
        if proofs is not None:
            os.close(proofs)
        if directory is not None:
            os.close(directory)
