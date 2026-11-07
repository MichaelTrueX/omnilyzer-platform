"""File: deployment/tests/test_analytics_signed_release_consumer.py

Purpose: Isolated, no-network regression tests for the original Task013
         Analytics schema-v1 producer versus read-only Task014 review consumer.
         Test signature collaborators are SYNTHETIC and NEVER deployment proof.
Related: deployment/analytics_signed_release_consumer.py,
         deployment/release_consumer.py (original canary remains default),
         deployment/promotion.py, deployment/analytics_signed_source_pin.py,
         release/analytics_release_evidence.py,
         release/analytics_forgejo_evidence.py.

Sections: complete authentic-schema fixture, positive review, negative signer,
          subject, source, scanner and archive cases, TLS route isolation.
"""
from __future__ import annotations

from dataclasses import replace
import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from deployment.analytics_signed_release_consumer import (
    _analytics_archive, acquire_and_review_analytics_release,
    acquire_and_review_owner_approved_analytics_release,
    verify_analytics_signed_evidence,
    verify_owner_selected_analytics_signed_evidence,
    review_owner_approved_analytics_signed_evidence, AnalyticsSignedEvidenceError,
    PINNED_DIGEST, PINNED_IMAGE, PINNED_PLATFORM_COMMIT, PINNED_RUN_ID,
    PINNED_VERSION,
)
from deployment.analytics_signed_source_pin import (
    CONTEXT_SHA256, SOURCE_COMMIT, SOURCE_TREE,
)
from deployment.policy import (
    APPROVED_OCI_ORIGIN, EXPECTED_CERTIFICATE_IDENTITY,
    EXPECTED_CERTIFICATE_ISSUER, EXPECTED_RELEASE_WORKFLOW, canonical_bytes,
)
from deployment.promotion import ANALYTICS_REPOSITORY
from deployment.release_consumer import (
    _get, ZotReadCredential, OCI_MEDIA_TYPE,
    ReleaseConsumerError,
)
from deployment.saas_product_contract import load_reviewed_profile
from deployment.saas_product_runtime import load_review_profile
from pathlib import Path

from release.analytics_owner_source_selection import (
    AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt,
    expected_owner_approval_bytes,
)

ROOT = Path(__file__).resolve().parents[2]
SCANNERS = (
    "oci-sbom.cdx.json", "oci-grype.json", "grype-db-status.json",
    "vulnerability-policy.json",
)


def sha(data: bytes) -> str:
    """Hash exact bytes without accepting guessed evidence hashes."""
    return hashlib.sha256(data).hexdigest()


def fixture() -> tuple[dict[str, bytes], dict[str, str]]:
    """Recreate the genuine Task013 Analytics v1 schema using synthetic bytes."""
    product = load_reviewed_profile(ROOT / "deployment/products/analytics-dev.json")
    runtime = load_review_profile(ROOT / "deployment/products/analytics-runtime-dev.json")
    # Source fields are mock hashes except reviewed exact identities/profiles.
    claim = {
        "schema_version": 1, "product_id": "analytics",
        "platform_source_commit": PINNED_PLATFORM_COMMIT,
        "platform_tree": "a" * 40,
        "source_repository": "MichaelTrueX/omnilyzer",
        "source_commit": SOURCE_COMMIT,
        "source_tree": SOURCE_TREE,
        "source_manifest_sha256": "1" * 64,
        "source_binding_sha256": "2" * 64,
        "source_files_verified": 78,
        "dockerfile_sha256": "3" * 64,
        "dockerignore_sha256": "4" * 64,
        "oci_test_source_sha256": "5" * 64,
        "build_context_sha256": CONTEXT_SHA256,
        "oci_repository": ANALYTICS_REPOSITORY,
        "oci_archive_sha256": "6" * 64,
        "oci_manifest_digest": PINNED_DIGEST,
        "product_profile_sha256": product.sha256(),
        "runtime_profile_sha256": runtime.sha256(),
        "readiness_path": "/readyz",
    }
    scanner_bytes = {
        name: canonical_bytes({"synthetic": name}) for name in SCANNERS
    }
    scanner_hashes = {name: sha(raw) for name, raw in scanner_bytes.items()}
    execution = {
        "repository": "MichaelTrueX/omnilyzer-platform",
        "repository_id": 1350104356,
        "workflow_ref": EXPECTED_RELEASE_WORKFLOW,
        "workflow_sha": PINNED_PLATFORM_COMMIT,
        "run_id": PINNED_RUN_ID, "run_attempt": 1,
        "event_name": "workflow_dispatch",
        "source_commit": PINNED_PLATFORM_COMMIT,
    }
    provenance = {
        "schema_version": 1,
        "statement_type": "https://omnilyzer.ai/analytics-release-provenance/v1",
        "product_id": "analytics", "version": PINNED_VERSION,
        "source_commit": PINNED_PLATFORM_COMMIT,
        "execution": execution,
        "external_source": claim,
        "subjects": {
            "oci_repository": ANALYTICS_REPOSITORY,
            "oci_manifest_digest": PINNED_DIGEST,
            "oci_archive_sha256": claim["oci_archive_sha256"],
            "scanner_sha256": scanner_hashes,
            "security_exceptions": 0,
        },
    }
    raw_provenance = canonical_bytes(provenance)
    manifest = {
        "schema_version": 1, "product_id": "analytics",
        "version": PINNED_VERSION, "source_commit": PINNED_PLATFORM_COMMIT,
        "external_source": claim,
        "oci": {
            "registry": APPROVED_OCI_ORIGIN,
            "repository": ANALYTICS_REPOSITORY,
            "manifest_digest": PINNED_DIGEST,
            "deployment_identity": ANALYTICS_REPOSITORY + "@" + PINNED_DIGEST,
        },
        "provenance": {
            "filename": "release-provenance.json", "sha256": sha(raw_provenance),
        },
        "signing": {
            "method": "keyless Sigstore/Fulcio/Rekor with GitHub OIDC",
            "release_manifest_bundle": "release-manifest.sigstore.json",
            "provenance_bundle": "release-provenance.sigstore.json",
            "oci_signature": ANALYTICS_REPOSITORY + "@" + PINNED_DIGEST,
        },
    }
    evidence = {
        "release-manifest.json": canonical_bytes(manifest),
        "release-provenance.json": raw_provenance,
        "release-manifest.sigstore.json": b"synthetic-manifest-bundle",
        "release-provenance.sigstore.json": b"synthetic-provenance-bundle",
        "analytics-source-claim.json": canonical_bytes(claim),
        "oci-publication.json": canonical_bytes({
            "schema_version": 1, "registry": APPROVED_OCI_ORIGIN,
            "repository": ANALYTICS_REPOSITORY, "tag": PINNED_VERSION,
            "manifest_digest": PINNED_DIGEST,
        }),
        **scanner_bytes,
    }
    return evidence, scanner_hashes


def change(evidence: dict[str, bytes], file: str, mutate) -> dict[str, bytes]:
    """Clone an evidence fixture and mutate one JSON file deliberately."""
    result = dict(evidence)
    document = json.loads(result[file])
    mutate(document)
    result[file] = canonical_bytes(document)
    return result


def archive(files: dict[str, bytes], *, replace_name: str | None = None,
            omit_name: str | None = None) -> bytes:
    """Make a tar/gzip fixture without using the filesystem or network."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in sorted(files.items()):
            if name == omit_name:
                continue
            actual = replace_name if name == "oci-grype.json" and replace_name else name
            member = tarfile.TarInfo(actual)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return gzip.compress(output.getvalue(), mtime=0)


class SyntheticBlobSignatureVerifier:
    """Synthetic mock, NOT a valid Sigstore cryptographic implementation."""

    def verify(self, manifest, provenance, manifest_bundle, provenance_bundle):
        if (
            manifest_bundle != b"synthetic-manifest-bundle"
            or provenance_bundle != b"synthetic-provenance-bundle"
        ):
            raise ValueError("invalid test marker")
        return {
            "release_manifest_verified": True, "provenance_verified": True,
            "certificate_identity": EXPECTED_CERTIFICATE_IDENTITY,
            "issuer": EXPECTED_CERTIFICATE_ISSUER,
        }


class SyntheticOCISignatureVerifier:
    """Synthetic mock, NOT a real Cosign registry signature."""

    def verify(self, image_reference, now):
        if image_reference != PINNED_IMAGE or now != 1700000000:
            raise ValueError("bad pinned test subject")
        return {
            "verified": True,
            "repository": ANALYTICS_REPOSITORY,
            "manifest_digest": PINNED_DIGEST,
            "certificate_identity": EXPECTED_CERTIFICATE_IDENTITY,
            "issuer": EXPECTED_CERTIFICATE_ISSUER,
        }


class SyntheticSuccessorOCISignatureVerifier:
    """A synthetic version-specific Cosign stub, NEVER signature proof."""

    def __init__(self, digest):
        self.digest = digest

    def verify(self, image_reference, now):
        if image_reference != (
            f"oci-dev.omnilyzer.ai/omnilyzer/analytics@{self.digest}"
        ) or now != 1700000000:
            raise ValueError("mismatched synthetic successor digest")
        return {
            "verified": True,
            "repository": ANALYTICS_REPOSITORY,
            "manifest_digest": self.digest,
            "certificate_identity": EXPECTED_CERTIFICATE_IDENTITY,
            "issuer": EXPECTED_CERTIFICATE_ISSUER,
        }


def synthetic_successor(*, digest_override=None):
    """Bind synthetic next-version evidence to a synthetic owner review.

    Tests a coherent schema, not an actual owner key, signing authority,
    full source-to-OCI build, or independent real CI/Task014 deployment.
    """
    selected = AnalyticsOwnerSourceSelection(
        source_commit="f" * 40, source_tree="e" * 40,
        release_version="0.15.1", platform_workflow_commit="d" * 40,
        owner_actor_id="130741173",
    )
    owner = AnalyticsOwnerSignatureReceipt(
        source_commit=selected.source_commit,
        source_tree=selected.source_tree,
        release_version=selected.release_version,
        approval_sha256=sha(expected_owner_approval_bytes(selected)),
        signature_sha256="a" * 64, owner_signature_verified=True,
    )
    evidence, scanner = fixture()
    claim = json.loads(evidence["analytics-source-claim.json"])
    for old_field in (
        "source_manifest_sha256", "source_binding_sha256", "source_files_verified",
    ):
        claim.pop(old_field)
    claim.update({
        "schema_version": 2,
        "full_git_tree_file_count": 612,
        "owner_approval_sha256": owner.approval_sha256,
        "release_version": selected.release_version,
        "source_commit": selected.source_commit,
        "source_tree": selected.source_tree,
        "build_context_sha256": "d" * 64,
        "platform_source_commit": selected.platform_workflow_commit,
        "oci_manifest_digest": "sha256:" + "b" * 64,
    })
    digest = claim["oci_manifest_digest"] if digest_override is None else digest_override
    claim["oci_manifest_digest"] = digest
    evidence["analytics-source-claim.json"] = canonical_bytes(claim)
    provenance = json.loads(evidence["release-provenance.json"])
    provenance["version"] = selected.release_version
    provenance["source_commit"] = selected.platform_workflow_commit
    provenance["execution"].update({
        "workflow_sha": selected.platform_workflow_commit,
        "source_commit": selected.platform_workflow_commit,
        "run_id": 5010,
    })
    provenance["external_source"] = claim
    provenance["subjects"]["oci_manifest_digest"] = digest
    evidence["release-provenance.json"] = canonical_bytes(provenance)
    manifest = json.loads(evidence["release-manifest.json"])
    manifest["version"] = selected.release_version
    manifest["source_commit"] = selected.platform_workflow_commit
    manifest["external_source"] = claim
    manifest["oci"]["manifest_digest"] = digest
    manifest["oci"]["deployment_identity"] = ANALYTICS_REPOSITORY + "@" + digest
    manifest["signing"]["oci_signature"] = ANALYTICS_REPOSITORY + "@" + digest
    manifest["provenance"]["sha256"] = sha(evidence["release-provenance.json"])
    evidence["release-manifest.json"] = canonical_bytes(manifest)
    receipt = json.loads(evidence["oci-publication.json"])
    receipt["tag"] = selected.release_version
    receipt["manifest_digest"] = digest
    evidence["oci-publication.json"] = canonical_bytes(receipt)
    return selected, owner, evidence, scanner, digest


class DeniedBlobSignatureVerifier(SyntheticBlobSignatureVerifier):
    """Return explicit signature rejection despite valid-looking signed JSON."""

    def verify(self, *args):
        return dict(super().verify(*args), provenance_verified=False)


class DeniedOCISignatureVerifier(SyntheticOCISignatureVerifier):
    """Return explicit OCI signature rejection despite valid-looking digest."""

    def verify(self, *args):
        return dict(super().verify(*args), verified=False)


class OwnerCryptographicSuccessorReviewTests(unittest.TestCase):
    """Real disposable Ed25519 approval plus synthetic original release proofs."""

    def test_local_owner_signature_is_required_before_successor_review(self):
        """No untrusted approval receipt or source can bypass owner-key checks."""
        selected, _fake_owner, evidence, scanner, digest = synthetic_successor()
        signed_evidence = {k: v for k, v in evidence.items() if k not in SCANNERS}
        with tempfile.TemporaryDirectory(prefix="task14b-real-owner-sig-") as tmp:
            root = Path(tmp)
            key = root / "temporary-ed25519-key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                capture_output=True, check=True, timeout=10,
            )
            public = (root / "temporary-ed25519-key.pub").read_text().strip()
            signers = (
                'MichaelTrueX namespaces="omnilyzer-analytics-source-v1" '
                + public + "\n"
            ).encode("ascii")
            approval = root / "source-approval.json"
            approval.write_bytes(expected_owner_approval_bytes(selected))
            subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-f", str(key),
                 "-n", "omnilyzer-analytics-source-v1", str(approval)],
                capture_output=True, check=True, timeout=10,
            )
            signature = root / "source-approval.json.sig"
            def check():
                return review_owner_approved_analytics_signed_evidence(
                    signed_evidence, scanner, SyntheticBlobSignatureVerifier(),
                    SyntheticSuccessorOCISignatureVerifier(digest),
                    received_at=1700000000,
                    approval_file=approval, signature_file=signature,
                )

            with patch(
                "release.analytics_owner_source_selection._root_controlled_signers",
                return_value=signers,
            ):
                reviewed = check()
                self.assertEqual(reviewed.release_version, selected.release_version)
                self.assertEqual(reviewed.source.source_commit, selected.source_commit)
                self.assertEqual(reviewed.source.source_tree, selected.source_tree)
                self.assertEqual(reviewed.image,
                                 "oci-dev.omnilyzer.ai/omnilyzer/analytics@" + digest)
                self.assertFalse(reviewed.deployment_authorized)
                self.assertFalse(reviewed.source.deployment_authorized)

                raw = approval.read_bytes()
                for bad in (
                    raw.replace(b'"0.15.1"', b'"0.16.0"'),
                    raw.replace(selected.source_commit.encode(), b"a" * 40),
                    raw.rstrip() + b" ",
                    raw.replace(
                        b'"product":"analytics"',
                        b'"product":"canary"'
                    ),
                    raw.replace(b'"schema_version":1', b'"schema_version":true'),
                    raw.replace(b'"owner_actor_id":"130741173"',
                                b'"owner_actor_id":"999"'),
                ):
                    with self.subTest(raw=bad[-80:]):
                        approval.write_bytes(bad)
                        with self.assertRaises(AnalyticsSignedEvidenceError):
                            check()
                approval.write_bytes(raw)

                original_sig = signature.read_bytes()
                signature.write_bytes(original_sig[:-2] + b"XX")
                with self.assertRaises(AnalyticsSignedEvidenceError):
                    check()
                signature.write_bytes(original_sig)

                with self.assertRaises(AnalyticsSignedEvidenceError):
                    review_owner_approved_analytics_signed_evidence(
                        signed_evidence, scanner, DeniedBlobSignatureVerifier(),
                        SyntheticSuccessorOCISignatureVerifier(digest),
                        received_at=1700000000,
                        approval_file=approval, signature_file=signature,
                    )
                with self.assertRaises(AnalyticsSignedEvidenceError):
                    review_owner_approved_analytics_signed_evidence(
                        signed_evidence, scanner, SyntheticBlobSignatureVerifier(),
                        SyntheticSuccessorOCISignatureVerifier("sha256:" + "f" * 64),
                        received_at=1700000000,
                        approval_file=approval, signature_file=signature,
                    )
                with self.assertRaises(AnalyticsSignedEvidenceError):
                    review_owner_approved_analytics_signed_evidence(
                        signed_evidence, {**scanner, "oci-grype.json": "0" * 64},
                        SyntheticBlobSignatureVerifier(),
                        SyntheticSuccessorOCISignatureVerifier(digest),
                        received_at=1700000000,
                        approval_file=approval, signature_file=signature,
                    )

            # An actual missing/uninstalled trusted host key fails closed.
            with self.assertRaises(AnalyticsSignedEvidenceError):
                check()


class OwnerSignedRegistryAcquisitionTests(unittest.TestCase):
    """Original read-only HTTPS/TLS envelope with synthetic signed objects."""

    def test_signed_successor_registry_digest_readback_and_wrong_bytes(self):
        """Never trust a tag or an unverified Zot header as an OCI digest."""
        from deployment.tests.test_release_consumer import Factory, Response
        from deployment.release_consumer import ForgejoReadCredential

        oci_bytes = canonical_bytes({
            "schemaVersion": 2, "mediaType": OCI_MEDIA_TYPE,
            "config": {}, "layers": [],
        })
        digest = "sha256:" + sha(oci_bytes)
        selected, owner, evidence, scanner, _ = synthetic_successor(
            digest_override=digest,
        )

        class ZotProvider:
            """Synthetic short-lived read-only bearer credential provider."""

            def zot_read_credential(self):
                return ZotReadCredential("SYNTHETIC.TEST.ONLY", 1700000100)

        class ForgejoProvider:
            """Synthetic original Forgejo-scoped credential provider."""

            def forgejo_read_credential(self):
                return ForgejoReadCredential("SYNTHETIC.TEST.ONLY", 1700000100)

        forgejo = Factory(Response(archive(evidence), "application/octet-stream"))

        def make_zot(body, reported_digest):
            return Factory(Response(
                body, OCI_MEDIA_TYPE,
                extra=[("Docker-Content-Digest", reported_digest)],
            ))

        def acquire(zot):
            return acquire_and_review_owner_approved_analytics_release(
                ZotProvider(), ForgejoProvider(),
                SyntheticBlobSignatureVerifier(),
                SyntheticSuccessorOCISignatureVerifier(digest),
                received_at=1700000000,
                approval_file=Path("/not/used/in/isolated/test"),
                signature_file=Path("/not/used/in/isolated/test"),
                zot_factory=zot, forgejo_factory=forgejo,
            )

        # The independent owner Ed25519 validation is covered above with
        # real ephemeral keys; patch ONLY its result in this HTTPS boundary.
        with patch(
            "deployment.analytics_signed_release_consumer."
            "load_and_verify_owner_signed_source",
            return_value=(selected, owner),
        ):
            zot = make_zot(oci_bytes, digest)
            reviewed = acquire(zot)
            self.assertEqual(reviewed.source.oci_manifest_digest, digest)
            self.assertEqual(reviewed.source.source_commit, selected.source_commit)
            self.assertFalse(reviewed.deployment_authorized)
            self.assertEqual(forgejo.calls[1][1],
                "/api/packages/omnilyzer/generic/analytics-release-evidence/"
                "0.15.1/release-evidence.tar.gz")
            self.assertEqual(zot.calls[1][1],
                "/v2/omnilyzer/analytics/manifests/" + digest)
            for body, head in (
                (oci_bytes + b" ", digest),
                (oci_bytes, "sha256:" + "0" * 64),
                (b'{"schemaVersion":1}', digest),
            ):
                with self.subTest(body=body, head=head):
                    with self.assertRaises(AnalyticsSignedEvidenceError):
                        acquire(make_zot(body, head))
            bad_forgejo = Factory(Response(
                b"unverified archive", "application/octet-stream",
            ))
            with self.assertRaises(AnalyticsSignedEvidenceError):
                acquire_and_review_owner_approved_analytics_release(
                    ZotProvider(), ForgejoProvider(),
                    SyntheticBlobSignatureVerifier(),
                    SyntheticSuccessorOCISignatureVerifier(digest),
                    received_at=1700000000,
                    approval_file=Path("/not/used/in/isolated/test"),
                    signature_file=Path("/not/used/in/isolated/test"),
                    zot_factory=make_zot(oci_bytes, digest),
                    forgejo_factory=bad_forgejo,
                )

        # No root-owned trust anchor means no registry credential or GET.
        with self.assertRaises(AnalyticsSignedEvidenceError):
            acquire(make_zot(oci_bytes, digest))


class AnalyticsSignedReleaseConsumerTests(unittest.TestCase):
    """Protect actual v1 schema and signer controls without deployment."""

    def test_successor_signed_review_preserves_signature_and_source_chain(self):
        """One synthetic future release must pass all existing source checks."""
        selected, owner, evidence, scanner, digest = synthetic_successor()
        small = {k: v for k, v in evidence.items() if k not in SCANNERS}
        with self.assertRaises(AnalyticsSignedEvidenceError):
            verify_analytics_signed_evidence(
                small, scanner, SyntheticBlobSignatureVerifier(),
                SyntheticSuccessorOCISignatureVerifier(digest),
                received_at=1700000000,
            )
        report = verify_owner_selected_analytics_signed_evidence(
            small, scanner, SyntheticBlobSignatureVerifier(),
            SyntheticSuccessorOCISignatureVerifier(digest),
            received_at=1700000000, selected=selected, owner_approval=owner,
        )
        self.assertEqual(report.release_version, "0.15.1")
        self.assertEqual(report.release_run_id, 5010)
        self.assertEqual(report.source.source_commit, selected.source_commit)
        self.assertEqual(report.source.source_tree, selected.source_tree)
        self.assertTrue(report.image.endswith(digest))
        self.assertFalse(report.deployment_authorized)
        self.assertFalse(report.source.release_authorized)

    def test_successor_rejects_oversized_early_evidence_before_json_parse(self):
        """The untrusted preview parse must preserve original 4MiB cap."""
        selected, owner, evidence, scanner, digest = synthetic_successor()
        small = {k: v for k, v in evidence.items() if k not in SCANNERS}
        small["release-manifest.json"] = b"x" * (4 * 1024 * 1024 + 1)
        with self.assertRaises(AnalyticsSignedEvidenceError):
            verify_owner_selected_analytics_signed_evidence(
                small, scanner, SyntheticBlobSignatureVerifier(),
                SyntheticSuccessorOCISignatureVerifier(digest),
                received_at=1700000000, selected=selected,
                owner_approval=owner,
            )

    def test_successor_synthetic_signed_approval_mutations_rejected(self):
        """Changing any actor/workflow/source/version/subject must deny review."""
        selected, owner, evidence, scanner, digest = synthetic_successor()
        original = {k: v for k, v in evidence.items() if k not in SCANNERS}
        cases = (
            (replace(selected, platform_workflow_commit="a" * 40), owner, original),
            (replace(selected, source_tree="c" * 40), owner, original),
            (replace(selected, release_version="0.15.2"), owner, original),
            (selected, replace(owner, signature_sha256="invalid"), original),
            (selected, replace(owner, owner_signature_verified=False), original),
            (selected, replace(owner, approval_sha256="0" * 64), original),
            (selected, replace(owner, release_authorized=True), original),
            (selected, owner, change(original, "release-provenance.json",
                                   lambda d: d["execution"].update(
                                       workflow_ref="attacker/workflow",
                                   ))),
            (selected, owner, change(original, "release-provenance.json",
                                   lambda d: d["subjects"].update(
                                       security_exceptions=1,
                                   ))),
            (selected, owner, change(original, "oci-publication.json",
                                   lambda d: d.update(manifest_digest=PINNED_DIGEST))),
        )
        for proposed, approval, sample in cases:
            with self.subTest(source=proposed, approval=approval), self.assertRaises(
                AnalyticsSignedEvidenceError
            ):
                verify_owner_selected_analytics_signed_evidence(
                    sample, scanner, SyntheticBlobSignatureVerifier(),
                    SyntheticSuccessorOCISignatureVerifier(digest),
                    received_at=1700000000, selected=proposed,
                    owner_approval=approval,
                )
        with self.assertRaises(AnalyticsSignedEvidenceError):
            verify_owner_selected_analytics_signed_evidence(
                original, scanner, DeniedBlobSignatureVerifier(),
                SyntheticSuccessorOCISignatureVerifier(digest),
                received_at=1700000000, selected=selected,
                owner_approval=owner,
            )
        with self.assertRaises(AnalyticsSignedEvidenceError):
            verify_owner_selected_analytics_signed_evidence(
                original, scanner, SyntheticBlobSignatureVerifier(),
                DeniedOCISignatureVerifier(),
                received_at=1700000000, selected=selected,
                owner_approval=owner,
            )

    def test_matching_synthetic_schema_yields_inert_review_receipt(self):
        evidence, scanner = fixture()
        result = verify_analytics_signed_evidence(
            {key: value for key, value in evidence.items() if key not in SCANNERS},
            scanner, SyntheticBlobSignatureVerifier(), SyntheticOCISignatureVerifier(),
            received_at=1700000000,
        )
        self.assertEqual(result.image, PINNED_IMAGE)
        self.assertEqual(result.release_version, PINNED_VERSION)
        self.assertEqual(result.release_run_id, PINNED_RUN_ID)
        self.assertEqual(result.source.source_commit, SOURCE_COMMIT)
        self.assertFalse(result.deployment_authorized)
        self.assertFalse(result.source.release_authorized)
        self.assertFalse(result.source.deployment_authorized)

    def test_signer_or_oci_rejection_fails_closed(self):
        evidence, scanner = fixture()
        small = {name: value for name, value in evidence.items() if name not in SCANNERS}
        for signature, oci in (
            (DeniedBlobSignatureVerifier(), SyntheticOCISignatureVerifier()),
            (SyntheticBlobSignatureVerifier(), DeniedOCISignatureVerifier()),
        ):
            with self.subTest(signature=type(signature).__name__), self.assertRaises(
                AnalyticsSignedEvidenceError
            ):
                verify_analytics_signed_evidence(
                    small, scanner, signature, oci, received_at=1700000000,
                )

    def test_source_claim_mismatch_is_denied(self):
        evidence, scanner = fixture()
        changed = change(evidence, "analytics-source-claim.json",
                         lambda doc: doc.update(source_commit="f" * 40))
        with self.assertRaises(AnalyticsSignedEvidenceError):
            verify_analytics_signed_evidence(
                {k: v for k, v in changed.items() if k not in SCANNERS},
                scanner, SyntheticBlobSignatureVerifier(),
                SyntheticOCISignatureVerifier(), received_at=1700000000,
            )
        changed = change(evidence, "release-manifest.json",
                         lambda doc: doc["external_source"].update(source_commit="f" * 40))
        with self.assertRaises(AnalyticsSignedEvidenceError):
            verify_analytics_signed_evidence(
                {k: v for k, v in changed.items() if k not in SCANNERS},
                scanner, SyntheticBlobSignatureVerifier(),
                SyntheticOCISignatureVerifier(), received_at=1700000000,
            )

    def test_consistent_but_unreviewed_signed_source_is_denied(self):
        """Matching signed blob claims still need the independent M01 source pin."""
        evidence, scanner = fixture()
        for mutation in (
            {"source_commit": "f" * 40},
            {"source_tree": "f" * 40},
            {"build_context_sha256": "f" * 64},
            {"product_profile_sha256": "f" * 64},
            {"runtime_profile_sha256": "f" * 64},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(
                AnalyticsSignedEvidenceError
            ):
                updated = dict(evidence)
                provenance = json.loads(updated["release-provenance.json"])
                manifest = json.loads(updated["release-manifest.json"])
                claim = json.loads(updated["analytics-source-claim.json"])
                for document in (claim, manifest["external_source"],
                                 provenance["external_source"]):
                    document.update(mutation)
                updated["analytics-source-claim.json"] = canonical_bytes(claim)
                updated["release-provenance.json"] = canonical_bytes(provenance)
                manifest["provenance"]["sha256"] = sha(
                    updated["release-provenance.json"]
                )
                updated["release-manifest.json"] = canonical_bytes(manifest)
                verify_analytics_signed_evidence(
                    {k: v for k, v in updated.items() if k not in SCANNERS},
                    scanner, SyntheticBlobSignatureVerifier(),
                    SyntheticOCISignatureVerifier(), received_at=1700000000,
                )

    def test_wrong_source_workflow_digest_version_and_scanner_denied(self):
        evidence, scanner = fixture()
        changed: list[tuple[str, object]] = [
            ("release-provenance.json",
             lambda doc: doc["execution"].update(workflow_ref="attacker/workflow")),
            ("release-provenance.json",
             lambda doc: doc.update(version="0.15.1")),
            ("release-provenance.json",
             lambda doc: doc["subjects"].update(security_exceptions=1)),
            ("release-provenance.json",
             lambda doc: doc["subjects"].update(oci_manifest_digest="sha256:" + "f" * 64)),
            ("release-manifest.json",
             lambda doc: doc["oci"].update(repository="omnilyzer/task013-release-canary")),
            ("release-manifest.json",
             lambda doc: doc.update(schema_version=2)),
            ("oci-publication.json",
             lambda doc: doc.update(tag="0.15.1")),
        ]
        for name, mutation in changed:
            with self.subTest(name=name), self.assertRaises(AnalyticsSignedEvidenceError):
                bad = change(evidence, name, mutation)
                verify_analytics_signed_evidence(
                    {k: v for k, v in bad.items() if k not in SCANNERS},
                    scanner, SyntheticBlobSignatureVerifier(),
                    SyntheticOCISignatureVerifier(), received_at=1700000000,
                )
        with self.assertRaises(AnalyticsSignedEvidenceError):
            verify_analytics_signed_evidence(
                {k: v for k, v in evidence.items() if k not in SCANNERS},
                dict(scanner, **{"oci-grype.json": "f" * 64}),
                SyntheticBlobSignatureVerifier(),
                SyntheticOCISignatureVerifier(), received_at=1700000000,
            )

    def test_archive_streaming_exact_files_and_digest(self):
        evidence, scanner = fixture()
        selected, hashes = _analytics_archive(archive(evidence))
        self.assertEqual(hashes, scanner)
        self.assertEqual(selected["release-manifest.json"],
                         evidence["release-manifest.json"])
        self.assertNotIn("oci-sbom.cdx.json", selected)
        for broken in (
            archive(evidence, omit_name="oci-grype.json"),
            archive(evidence, replace_name="../escape"),
            archive(dict(evidence, **{"extra.txt": b"unsafe"})),
            b"not-gzip",
        ):
            with self.subTest(length=len(broken)), self.assertRaises(
                AnalyticsSignedEvidenceError
            ):
                _analytics_archive(broken)

    def test_original_cosign_verifier_is_explicitly_product_scoped(self):
        """Analytics verifier must never read/verify the canary repository."""
        from deployment.oci_verifier import (
            CosignOCISignatureVerifier, OCIVerificationError,
        )
        from deployment.tests.test_blob_verifier import AUTHORITY

        class Counter:
            """Fail visibly if construction or wrong-product rejection reads token."""

            calls = 0

            def zot_read_credential(self):
                self.calls += 1
                raise AssertionError("unexpected credential read")

        class DummyRunner:
            """Never called when the signed OCI repository does not match."""

            def run(self, argv, blob, *, executable, descriptors, home, docker_config):
                raise AssertionError("unexpected Cosign execution")

        provider = Counter()
        canary = CosignOCISignatureVerifier(
            **AUTHORITY, zot_credential_provider=provider, runner=DummyRunner(),
        )
        analytics = CosignOCISignatureVerifier(
            **AUTHORITY, zot_credential_provider=provider, runner=DummyRunner(),
            product_id="analytics",
        )
        self.assertEqual(object.__getattribute__(canary, "_authority")[4],
                         "omnilyzer/task013-release-canary")
        self.assertEqual(object.__getattribute__(analytics, "_authority")[4],
                         ANALYTICS_REPOSITORY)
        with self.assertRaises(OCIVerificationError):
            analytics.verify(
                "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@" + PINNED_DIGEST,
                1700000000,
            )
        with self.assertRaises(OCIVerificationError):
            canary.verify(PINNED_IMAGE, 1700000000)
        self.assertEqual(provider.calls, 0)
        for invalid in ("cybersecurity", "Analytics", "", None, True, 1):
            with self.subTest(invalid=invalid), self.assertRaises(OCIVerificationError):
                CosignOCISignatureVerifier(
                    **AUTHORITY, zot_credential_provider=provider,
                    runner=DummyRunner(), product_id=invalid,
                )
        self.assertEqual(provider.calls, 0)

    def test_real_cosign_wrapper_analytics_scope_with_sealed_mock_runner(self):
        """Exercise the ORIGINAL Cosign verifier's positive immutable OCI path.

        The original test harness mocks pinned executable/TrustedRoot bytes,
        prohibits actual process/network access, and asserts sealed FDs.
        This is NOT a real published OCI signature verification.
        """
        from unittest.mock import patch
        from deployment import oci_verifier as ov
        from deployment.tests import test_oci_verifier as baseline

        harness = baseline.VerifierTests()
        try:
            with patch.object(baseline, "REFERENCE", PINNED_IMAGE):
                _canary, _directory, provider, runner = harness.sandbox()
                analytics = ov.CosignOCISignatureVerifier(
                    **baseline.AUTHORITY, zot_credential_provider=provider,
                    runner=runner, product_id="analytics",
                )
                result = analytics.verify(PINNED_IMAGE, baseline.NOW)
                self.assertEqual(result, {
                    "verified": True,
                    "repository": ANALYTICS_REPOSITORY,
                    "manifest_digest": PINNED_DIGEST,
                    "certificate_identity": EXPECTED_CERTIFICATE_IDENTITY,
                    "issuer": EXPECTED_CERTIFICATE_ISSUER,
                })
                self.assertEqual(provider.calls, 1)
                self.assertEqual(len(runner.calls), 1)
        finally:
            harness.doCleanups()

    def test_acquisition_denies_wrong_oci_before_forgejo_or_verifiers(self):
        """Reject a mismatched real GET payload before retrieving signed blobs."""
        from deployment.tests.test_release_consumer import Factory, Response

        class ZotProvider:
            """Return only a synthetic, short-lived, read-only Zot credential."""

            def zot_read_credential(self):
                return ZotReadCredential("SYNTHETIC.TEST.ONLY", 1700000100)

        class ForgejoProvider:
            """Must not be reached if the immutable OCI bytes differ."""

            def forgejo_read_credential(self):
                raise AssertionError("should not reach Forgejo")

        bad_bytes = canonical_bytes({
            "schemaVersion": 2, "mediaType": OCI_MEDIA_TYPE,
            "config": {}, "layers": [],
        })
        zot = Factory(Response(
            bad_bytes, OCI_MEDIA_TYPE,
            extra=[("Docker-Content-Digest", PINNED_DIGEST)],
        ))
        with self.assertRaises(AnalyticsSignedEvidenceError):
            acquire_and_review_analytics_release(
                ZotProvider(), ForgejoProvider(),
                SyntheticBlobSignatureVerifier(), SyntheticOCISignatureVerifier(),
                received_at=1700000000, zot_factory=zot,
            )
        self.assertEqual(zot.calls[1][1],
                         f"/v2/omnilyzer/analytics/manifests/{PINNED_DIGEST}")

    def test_bounded_gzip_decompression_includes_trailing_data(self):
        """Reject a gzip bomb even if TAR stops before its trailing bytes."""
        from unittest.mock import patch
        from deployment import analytics_signed_release_consumer as consumer

        evidence, _scanner = fixture()
        good = archive(evidence)
        with patch.object(consumer, "_MAX_UNCOMPRESSED", 1024):
            with self.assertRaises(AnalyticsSignedEvidenceError):
                _analytics_archive(good)
        # Concatenated gzip members are legal to gzip but not a chance to
        # bypass the review consumer's maximum decompressed evidence size.
        trailing = good + gzip.compress(b"x" * 50000, mtime=0)
        with patch.object(consumer, "_MAX_UNCOMPRESSED", 40000):
            with self.assertRaises(AnalyticsSignedEvidenceError):
                _analytics_archive(trailing)

    def test_original_canary_paths_default_and_distinct_analytics_paths(self):
        """Original HTTP path grammar remains strict, no product wildcard."""
        from deployment.tests.test_release_consumer import Factory, Response
        from deployment.release_consumer import OCI_MEDIA_TYPE

        body = canonical_bytes({
            "schemaVersion": 2, "mediaType": OCI_MEDIA_TYPE,
            "config": {}, "layers": [],
        })
        factory = Factory(Response(body, OCI_MEDIA_TYPE))
        _get("zot", PINNED_DIGEST, "synthetic", factory, product="analytics")
        self.assertEqual(factory.calls[1][1],
                         f"/v2/omnilyzer/analytics/manifests/{PINNED_DIGEST}")
        factory = Factory(Response(body, OCI_MEDIA_TYPE))
        _get("zot", PINNED_DIGEST, "synthetic", factory)
        self.assertEqual(factory.calls[1][1],
                         f"/v2/omnilyzer/task013-release-canary/manifests/{PINNED_DIGEST}")
        factory = Factory(Response(b"archive", "application/octet-stream"))
        _get("forgejo", PINNED_VERSION, "synthetic", factory, product="analytics")
        self.assertEqual(
            factory.calls[1][1],
            "/api/packages/omnilyzer/generic/analytics-release-evidence/"
            + PINNED_VERSION + "/release-evidence.tar.gz",
        )
        with self.assertRaises(ReleaseConsumerError):
            _get("zot", PINNED_DIGEST, "synthetic", factory, product="cybersecurity")


if __name__ == "__main__":
    unittest.main()
