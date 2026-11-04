"""Read-only, owner-selected Analytics source preflight for Task14B.

This is *not* source approval, signing authority or deployment authorization.
The original installed 0.15.0 static pin remains enforced elsewhere.
A successor release must separately verify reviewed source approval, signed
Task013 evidence, original OIDC issuer and Task014 installed authority.

No Git fetch, shell, network, secret, OCI, registry or host mutation occurs.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import tempfile
from typing import Mapping


EXPECTED_REPOSITORY = "MichaelTrueX/omnilyzer-platform"
EXPECTED_ACTOR = "MichaelTrueX"
EXPECTED_ACTOR_ID = "130741173"
EXPECTED_REF = "refs/heads/main"
EXPECTED_WORKFLOW_REF = (
    "MichaelTrueX/omnilyzer-platform/"
    ".github/workflows/platform-release.yml@refs/heads/main"
)
SOURCE_REPOSITORY = "MichaelTrueX/omnilyzer"
SOURCE_ORIGINS = frozenset({
    "https://github.com/MichaelTrueX/omnilyzer.git",
    "git@github.com:MichaelTrueX/omnilyzer.git",
})
REVIEWED_0150_ANCESTOR = "4cdda7faeba57abb3388f9be5c450fe6afb1140d"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_CONTEXT = frozenset({
    "GITHUB_REPOSITORY", "GITHUB_ACTOR", "GITHUB_ACTOR_ID",
    "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_WORKFLOW_REF", "GITHUB_SHA",
})
_SELECTION = frozenset({"product", "source_repository", "source_commit", "release_version"})


class AnalyticsOwnerSourceSelectionDenied(ValueError):
    """Owner-controlled source selection or Git object has a mismatch."""


@dataclass(frozen=True, slots=True)
class AnalyticsOwnerSourceSelection:
    """Inert evidence, not a reviewed source/signing/deployment grant."""

    source_commit: str
    source_tree: str
    release_version: str
    platform_workflow_commit: str
    owner_actor_id: str
    independent_review_verified: bool = False
    release_authorized: bool = False
    deployment_authorized: bool = False


def _git(directory: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(directory), *args],
            capture_output=True, check=False, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AnalyticsOwnerSourceSelectionDenied("Git source unavailable") from exc
    if proc.returncode or len(proc.stdout) > 4096:
        raise AnalyticsOwnerSourceSelectionDenied("Git source unavailable")
    try:
        return proc.stdout.decode("ascii").strip()
    except UnicodeError as exc:
        raise AnalyticsOwnerSourceSelectionDenied("noncanonical Git identity") from exc


def _commit(value: object) -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None or value == "0" * 40:
        raise AnalyticsOwnerSourceSelectionDenied("invalid source SHA")
    return value


def verify_owner_source_selection(
    context: Mapping[str, str],
    selected: Mapping[str, str],
    platform_checkout: Path,
    analytics_checkout: Path,
) -> AnalyticsOwnerSourceSelection:
    """Validate owner context and reviewed-source ancestry before a build.

    This is an additional READ-ONLY preflight only. The caller must still
    independently establish owner approval of exact source, verify original
    Task013 signatures/immutable manifest, and satisfy Task014's signed consumer
    before gaining any authority. Do not use this result as a permission token.
    """
    try:
        if (not isinstance(context, Mapping)
                or not isinstance(selected, Mapping)
                or set(selected) != _SELECTION
                or not _CONTEXT.issubset(context)
                or context["GITHUB_REPOSITORY"] != EXPECTED_REPOSITORY
                or context["GITHUB_ACTOR"] != EXPECTED_ACTOR
                or context["GITHUB_ACTOR_ID"] != EXPECTED_ACTOR_ID
                or context["GITHUB_EVENT_NAME"] != "workflow_dispatch"
                or context["GITHUB_REF"] != EXPECTED_REF
                or context["GITHUB_WORKFLOW_REF"] != EXPECTED_WORKFLOW_REF
                or selected["product"] != "analytics"
                or selected["source_repository"] != SOURCE_REPOSITORY
                or type(selected["release_version"]) is not str
                or _SEMVER.fullmatch(selected["release_version"]) is None
                or not isinstance(platform_checkout, Path)
                or not isinstance(analytics_checkout, Path)):
            raise AnalyticsOwnerSourceSelectionDenied("owner source context mismatch")
        platform_sha = _commit(context["GITHUB_SHA"])
        source_sha = _commit(selected["source_commit"])
        for checkout in (platform_checkout, analytics_checkout):
            if not checkout.is_dir() or checkout.is_symlink():
                raise AnalyticsOwnerSourceSelectionDenied("invalid source checkout")
        if _git(platform_checkout, "rev-parse", "HEAD") != platform_sha:
            raise AnalyticsOwnerSourceSelectionDenied("platform SHA differs from runner")
        if _git(analytics_checkout, "config", "--get", "remote.origin.url") not in SOURCE_ORIGINS:
            raise AnalyticsOwnerSourceSelectionDenied("product source origin mismatch")
        if _git(analytics_checkout, "rev-parse", "HEAD") != source_sha:
            raise AnalyticsOwnerSourceSelectionDenied("product source SHA mismatch")
        if _git(analytics_checkout, "cat-file", "-t", source_sha) != "commit":
            raise AnalyticsOwnerSourceSelectionDenied("product source is not a commit")
        # An ordinary next version must retain the originally accepted source ancestry.
        _git(analytics_checkout, "merge-base", "--is-ancestor",
             REVIEWED_0150_ANCESTOR, source_sha)
        tree = _commit(_git(analytics_checkout, "rev-parse", source_sha + "^{tree}"))
        for checkout in (platform_checkout, analytics_checkout):
            # Ignore ephemeral untracked CI build outputs. Tracked files must be exact.
            if _git(checkout, "status", "--porcelain", "--untracked-files=no"):
                raise AnalyticsOwnerSourceSelectionDenied("tracked source checkout dirty")
        return AnalyticsOwnerSourceSelection(
            source_commit=source_sha,
            source_tree=tree,
            release_version=selected["release_version"],
            platform_workflow_commit=platform_sha,
            owner_actor_id=EXPECTED_ACTOR_ID,
        )
    except AnalyticsOwnerSourceSelectionDenied:
        raise
    except Exception:
        raise AnalyticsOwnerSourceSelectionDenied("invalid source selection") from None


# Section 2: owner-held detached signature over one exact release source.
# Read-only: the future privileged deployment boundary must pin a root-owned
# key outside mutable GitHub product/platform source. Git checkout or workflow
# inputs are NEVER an allowed final trust anchor.
OWNER_APPROVAL_NAMESPACE = "omnilyzer-analytics-source-v1"
OWNER_SIGNER_IDENTITY = "MichaelTrueX"
# An independently root-controlled, one-time key anchor on DEV. GitHub
# workflow/source changes cannot change this authority for each release.
# The existing /etc/omnilyzer/deployment/dev directory is reused.
TRUSTED_OWNER_SIGNERS = Path(
    "/etc/omnilyzer/deployment/dev/analytics-owner-source-signers"
)
_MAX_APPROVAL = 2048
_MAX_SIGNATURE = 4096


@dataclass(frozen=True, slots=True)
class AnalyticsOwnerSignatureReceipt:
    """Evidence of a detached owner signature, NOT M04 or deployment GO."""

    source_commit: str
    source_tree: str
    release_version: str
    approval_sha256: str
    signature_sha256: str
    owner_signature_verified: bool = False
    independent_review_verified: bool = False
    release_authorized: bool = False
    deployment_authorized: bool = False


def _bounded_file(path: Path, maximum: int) -> bytes:
    """Read only one opened regular, nonsymlinked bounded file descriptor.

    lstat()/read_bytes() would admit a path replacement between checks. This
    local review check reads from one O_NOFOLLOW descriptor and fails closed.
    """
    if not isinstance(path, Path) or type(maximum) is not int or maximum < 1:
        raise AnalyticsOwnerSourceSelectionDenied("invalid owner approval path")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not 0 < metadata.st_size <= maximum
            ):
                raise AnalyticsOwnerSourceSelectionDenied("owner approval file size invalid")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(maximum + 1)
            if len(raw) != metadata.st_size:
                raise AnalyticsOwnerSourceSelectionDenied("owner approval changed while reading")
            return raw
        finally:
            os.close(fd)
    except AnalyticsOwnerSourceSelectionDenied:
        raise
    except (OSError, ValueError, TypeError):
        raise AnalyticsOwnerSourceSelectionDenied("owner approval file unavailable") from None


def _root_controlled_signers() -> bytes:
    """Read trusted public-key bytes from the existing root-owned DEV hierarchy.

    The trust key must be provisioned and reviewed once through a separately
    authorized privileged setup. Never use a repository file or user-selected
    path as the final installed source-approval authority.
    """
    try:
        for directory in (
            Path("/etc"), Path("/etc/omnilyzer"),
            Path("/etc/omnilyzer/deployment"),
            Path("/etc/omnilyzer/deployment/dev"),
        ):
            metadata = directory.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022
            ):
                raise AnalyticsOwnerSourceSelectionDenied("insecure source trust directory")
        if TRUSTED_OWNER_SIGNERS != Path(
            "/etc/omnilyzer/deployment/dev/analytics-owner-source-signers"
        ):
            raise AnalyticsOwnerSourceSelectionDenied("source trust path changed")
        fd = os.open(
            TRUSTED_OWNER_SIGNERS,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o022
                or not 0 < metadata.st_size <= _MAX_SIGNATURE
            ):
                raise AnalyticsOwnerSourceSelectionDenied("unsafe owner trust anchor")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(_MAX_SIGNATURE + 1)
            if len(raw) != metadata.st_size:
                raise AnalyticsOwnerSourceSelectionDenied("source trust anchor changed")
            return raw
        finally:
            os.close(fd)
    except AnalyticsOwnerSourceSelectionDenied:
        raise
    except (OSError, ValueError, TypeError):
        raise AnalyticsOwnerSourceSelectionDenied("owner trust anchor unavailable") from None


def expected_owner_approval_bytes(selected: AnalyticsOwnerSourceSelection) -> bytes:
    """Canonical exact-source approval, including workflow SHA and owner identity.

    This constructs bytes to be signed by the owner's *separate private SSH key*.
    It does not sign, attest, dispatch, create any file, or grant release authority.
    """
    if (
        type(selected) is not AnalyticsOwnerSourceSelection
        or selected.independent_review_verified is not False
        or selected.release_authorized is not False
        or selected.deployment_authorized is not False
        or not _SHA.fullmatch(selected.source_commit)
        or not _SHA.fullmatch(selected.source_tree)
        or not _SHA.fullmatch(selected.platform_workflow_commit)
        or not _SEMVER.fullmatch(selected.release_version)
        or selected.owner_actor_id != EXPECTED_ACTOR_ID
    ):
        raise AnalyticsOwnerSourceSelectionDenied("invalid inert source selection")
    payload = {
        "schema_version": 1,
        "purpose": OWNER_APPROVAL_NAMESPACE,
        "product": "analytics",
        "source_repository": SOURCE_REPOSITORY,
        "source_commit": selected.source_commit,
        "source_tree": selected.source_tree,
        "release_version": selected.release_version,
        "platform_repository": EXPECTED_REPOSITORY,
        "platform_workflow_ref": EXPECTED_WORKFLOW_REF,
        "platform_workflow_commit": selected.platform_workflow_commit,
        "owner_actor_id": EXPECTED_ACTOR_ID,
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _verify_owner_signature_with_signers(
    selected: AnalyticsOwnerSourceSelection,
    approval: bytes,
    signature: bytes,
    signers: bytes,
) -> AnalyticsOwnerSignatureReceipt:
    """Check an exact signature against supplied bytes without granting any GO.

    This low-level helper enables disposable fixture tests; it is NOT source
    authorization. The production entrypoint always loads root-owned bytes.
    """
    try:
        canonical = expected_owner_approval_bytes(selected)
        if (
            type(approval) is not bytes or not 0 < len(approval) <= _MAX_APPROVAL
            or type(signature) is not bytes or not 0 < len(signature) <= _MAX_SIGNATURE
            or type(signers) is not bytes or not 0 < len(signers) <= _MAX_SIGNATURE
        ):
            raise AnalyticsOwnerSourceSelectionDenied("invalid owner approval evidence")
        if approval != canonical or not signers.startswith(
            (OWNER_SIGNER_IDENTITY + ' namespaces="' + OWNER_APPROVAL_NAMESPACE
             + '" ssh-ed25519 ').encode("ascii")
        ) or signers.count(b"\n") != 1:
            raise AnalyticsOwnerSourceSelectionDenied("owner approval binding mismatch")
        # Verify exact signature bytes already hashed, not a mutable path.
        with tempfile.TemporaryDirectory(prefix="analytics-source-sig-") as temp:
            immutable_signature = Path(temp) / "signature"
            immutable_signature.write_bytes(signature)
            immutable_signers = Path(temp) / "allowed-signers"
            immutable_signers.write_bytes(signers)
            result = subprocess.run(
                [
                    "ssh-keygen", "-Y", "verify", "-f", str(immutable_signers),
                    "-I", OWNER_SIGNER_IDENTITY, "-n", OWNER_APPROVAL_NAMESPACE,
                    "-s", str(immutable_signature),
                ],
                input=approval, capture_output=True, check=False, timeout=10,
            )
        if result.returncode != 0 or len(result.stdout) > 4096:
            raise AnalyticsOwnerSourceSelectionDenied("invalid owner source signature")
        return AnalyticsOwnerSignatureReceipt(
            source_commit=selected.source_commit,
            source_tree=selected.source_tree,
            release_version=selected.release_version,
            approval_sha256=hashlib.sha256(approval).hexdigest(),
            signature_sha256=hashlib.sha256(signature).hexdigest(),
            owner_signature_verified=True,
        )
    except AnalyticsOwnerSourceSelectionDenied:
        raise
    except (OSError, subprocess.TimeoutExpired, UnicodeError, ValueError, TypeError):
        raise AnalyticsOwnerSourceSelectionDenied("owner source signature verification failed") from None



# Section 3: read a successor source selection only after verifying the
# canonical approval bytes against the independently installed signer key.
_APPROVAL_FIELDS = frozenset({
    "schema_version", "purpose", "product", "source_repository",
    "source_commit", "source_tree", "release_version",
    "platform_repository", "platform_workflow_ref",
    "platform_workflow_commit", "owner_actor_id",
})


def load_and_verify_owner_signed_source(
    approval_file: Path, signature_file: Path,
) -> tuple[AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt]:
    """Load exact owner-approved identity using the established local verifier.

    A missing trusted signer, unknown field, noncanonical document or invalid
    Ed25519 signature rejects the release. The result is review evidence only.
    """
    try:
        trusted_signers = _root_controlled_signers()
        approval = _bounded_file(approval_file, _MAX_APPROVAL)
        signature = _bounded_file(signature_file, _MAX_SIGNATURE)

        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            """Reject ambiguous owner approval JSON keys."""
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise AnalyticsOwnerSourceSelectionDenied("duplicate approval field")
                result[key] = value
            return result

        document = json.loads(approval.decode("ascii"), object_pairs_hook=unique)
        if (
            type(document) is not dict or set(document) != _APPROVAL_FIELDS
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or document["purpose"] != OWNER_APPROVAL_NAMESPACE
            or document["product"] != "analytics"
            or document["source_repository"] != SOURCE_REPOSITORY
            or document["platform_repository"] != EXPECTED_REPOSITORY
            or document["platform_workflow_ref"] != EXPECTED_WORKFLOW_REF
            or document["owner_actor_id"] != EXPECTED_ACTOR_ID
            or type(document["release_version"]) is not str
            or _SEMVER.fullmatch(document["release_version"]) is None
            or tuple(map(int, document["release_version"].split("."))) <= (0, 15, 0)
            or document["source_commit"] == REVIEWED_0150_ANCESTOR
        ):
            raise AnalyticsOwnerSourceSelectionDenied("approval contract denied")
        selected = AnalyticsOwnerSourceSelection(
            source_commit=_commit(document["source_commit"]),
            source_tree=_commit(document["source_tree"]),
            release_version=document["release_version"],
            platform_workflow_commit=_commit(document["platform_workflow_commit"]),
            owner_actor_id=document["owner_actor_id"],
        )
        if approval != expected_owner_approval_bytes(selected):
            raise AnalyticsOwnerSourceSelectionDenied("noncanonical owner approval")
        receipt = _verify_owner_signature_with_signers(
            selected, approval, signature, trusted_signers,
        )
        if (
            receipt.owner_signature_verified is not True
            or receipt.release_authorized is not False
            or receipt.deployment_authorized is not False
        ):
            raise AnalyticsOwnerSourceSelectionDenied("invalid review-only receipt")
        return selected, receipt
    except AnalyticsOwnerSourceSelectionDenied:
        raise
    except (TypeError, KeyError, ValueError, UnicodeError, OverflowError):
        raise AnalyticsOwnerSourceSelectionDenied("owner approval denied") from None


# Section 3b: non-privileged Task013 signer check before any BuildKit input.
# The protected workflow MUST supply the public allowlist from an independently
# configured GitHub credential/setting, NOT an editable Git source file.
# Task014 must independently check its ROOT-owned trust key regardless.
def review_ci_owner_signed_source(
    context: Mapping[str, str], payload: Mapping[str, str],
    platform_checkout: Path, analytics_checkout: Path,
    *, signature_base64: str, protected_signers: bytes,
) -> tuple[AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt]:
    """Check exact Git source plus detached owner signature, before OCI build.

    The caller must independently establish that protected_signers came from
    a trusted CI configuration outside the checked-out repository. Supplying
    arbitrary bytes is not authorization, and the return flags are always
    false. The real installed Task014 root anchor stays a separate gate.
    """
    try:
        if (
            type(signature_base64) is not str
            or not 1 <= len(signature_base64) <= 8192
            or not signature_base64.isascii()
            or type(protected_signers) is not bytes
            or not 0 < len(protected_signers) <= _MAX_SIGNATURE
        ):
            raise AnalyticsOwnerSourceSelectionDenied("invalid CI signature source")
        selected = verify_owner_source_selection(
            context, payload, platform_checkout, analytics_checkout,
        )
        if (
            selected.source_commit == REVIEWED_0150_ANCESTOR
            or tuple(map(int, selected.release_version.split("."))) <= (0, 15, 0)
        ):
            raise AnalyticsOwnerSourceSelectionDenied("original source denied in successor gate")
        signature = base64.b64decode(signature_base64, validate=True)
        if (
            not 0 < len(signature) <= _MAX_SIGNATURE
            or base64.b64encode(signature).decode("ascii") != signature_base64
        ):
            raise AnalyticsOwnerSourceSelectionDenied("noncanonical owner signature")
        receipt = _verify_owner_signature_with_signers(
            selected, expected_owner_approval_bytes(selected),
            signature, protected_signers,
        )
        if (
            receipt.owner_signature_verified is not True
            or receipt.release_authorized is not False
            or receipt.deployment_authorized is not False
        ):
            raise AnalyticsOwnerSourceSelectionDenied("owner signature review denied")
        return selected, receipt
    except AnalyticsOwnerSourceSelectionDenied:
        raise
    except (binascii.Error, ValueError, TypeError, UnicodeError):
        raise AnalyticsOwnerSourceSelectionDenied("CI owner source approval denied") from None


# Section 3c: protected Forgejo signer job does not check out private Git.
# Reverify owner Ed25519 against the exact claim already checked by the Git
# source job and Zot publisher before the final original Sigstore signing.
def review_ci_owner_signed_claim(
    claim: Mapping[str, object],
    context: Mapping[str, str],
    payload: Mapping[str, str],
    *, signature_base64: str, protected_signers: bytes,
) -> AnalyticsOwnerSignatureReceipt:
    """Reverify owner approval of a source claim without elevating authority.

    The protected source and Zot jobs MUST separately recheck the actual
    immutable Git checkout. This function prevents a changed transport claim
    from silently entering the original Sigstore/Cosign signer job.
    """
    try:
        if (
            not isinstance(claim, Mapping)
            or not isinstance(context, Mapping)
            or not isinstance(payload, Mapping)
            or set(payload) != _SELECTION
            or not _CONTEXT.issubset(context)
            or context["GITHUB_REPOSITORY"] != EXPECTED_REPOSITORY
            or context["GITHUB_ACTOR"] != EXPECTED_ACTOR
            or context["GITHUB_ACTOR_ID"] != EXPECTED_ACTOR_ID
            or context["GITHUB_EVENT_NAME"] != "workflow_dispatch"
            or context["GITHUB_REF"] != EXPECTED_REF
            or context["GITHUB_WORKFLOW_REF"] != EXPECTED_WORKFLOW_REF
            or payload["product"] != "analytics"
            or payload["source_repository"] != SOURCE_REPOSITORY
            or claim.get("schema_version") != 2
            or type(claim.get("schema_version")) is not int
            or claim.get("source_repository") != SOURCE_REPOSITORY
            or claim.get("product_id") != "analytics"
            or claim.get("source_commit") != payload["source_commit"]
            or claim.get("release_version") != payload["release_version"]
            or claim.get("platform_source_commit") != context["GITHUB_SHA"]
            or not isinstance(signature_base64, str)
            or not 1 <= len(signature_base64) <= 8192
            or not signature_base64.isascii()
            or type(protected_signers) is not bytes
            or not 0 < len(protected_signers) <= _MAX_SIGNATURE
        ):
            raise AnalyticsOwnerSourceSelectionDenied("signer claim identity mismatch")
        selected = AnalyticsOwnerSourceSelection(
            source_commit=_commit(claim["source_commit"]),
            source_tree=_commit(claim["source_tree"]),
            release_version=claim["release_version"],
            platform_workflow_commit=_commit(claim["platform_source_commit"]),
            owner_actor_id=EXPECTED_ACTOR_ID,
        )
        if (
            not _SEMVER.fullmatch(selected.release_version)
            or tuple(map(int, selected.release_version.split("."))) <= (0, 15, 0)
            or selected.source_commit == REVIEWED_0150_ANCESTOR
        ):
            raise AnalyticsOwnerSourceSelectionDenied("old Analytics source denied")
        signature = base64.b64decode(signature_base64, validate=True)
        if (
            not 0 < len(signature) <= _MAX_SIGNATURE
            or base64.b64encode(signature).decode("ascii") != signature_base64
        ):
            raise AnalyticsOwnerSourceSelectionDenied("signature encoding mismatch")
        receipt = _verify_owner_signature_with_signers(
            selected, expected_owner_approval_bytes(selected),
            signature, protected_signers,
        )
        if (
            claim.get("owner_approval_sha256") != receipt.approval_sha256
            or receipt.owner_signature_verified is not True
            or receipt.release_authorized is not False
            or receipt.deployment_authorized is not False
        ):
            raise AnalyticsOwnerSourceSelectionDenied("source approval SHA mismatch")
        return receipt
    except AnalyticsOwnerSourceSelectionDenied:
        raise
    except (binascii.Error, TypeError, ValueError, KeyError, UnicodeError):
        raise AnalyticsOwnerSourceSelectionDenied("protected signer source denied") from None


def verify_owner_detached_source_approval(
    selected: AnalyticsOwnerSourceSelection,
    approval_file: Path,
    signature_file: Path,
) -> AnalyticsOwnerSignatureReceipt:
    """Read only root-controlled trust, then verify owner-signed exact source.

    Review-only receipt: never M04 review, Task013 signature, or Task014 GO.
    Missing owner-installed trust anchor always denies. No key generation,
    network, privileged writes or dispatch occurs here.
    """
    signers = _root_controlled_signers()
    approval = _bounded_file(approval_file, _MAX_APPROVAL)
    signature = _bounded_file(signature_file, _MAX_SIGNATURE)
    return _verify_owner_signature_with_signers(
        selected, approval, signature, signers,
    )
