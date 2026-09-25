"""Deterministic, no-network tests for the inert C32B consumer boundary."""

from __future__ import annotations

from dataclasses import replace
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import unittest

from deployment.execution import IngressReference, RuntimeConfigurationReference, parse_canonical_request
from deployment.identity import authorize_verified_github_oidc
from deployment.policy import canonical_bytes
from deployment.promotion import PromotionRequest
from deployment.release_consumer import (
    ARCHIVE_NAMES, FORGEJO_HOST, OCI_MEDIA_TYPE, REPOSITORY, ZOT_HOST,
    ForgejoEvidenceConsumer, ForgejoReadCredential, ReleaseConsumerError,
    ZotCandidateConsumer, ZotReadCredential, acquire_and_construct_dev_request,
)
from deployment.tests.fixtures import (
    VERSION, evidence as base_evidence, oci_signature_result,
    request as base_request, sigstore_result,
)
from deployment.tests.test_execution import ingress_reference, runtime_reference
from deployment.tests.test_identity import NOW, valid_claims


TOKEN = "private-consumer-token"
ROOT = Path(__file__).resolve().parents[2]


class Response:
    def __init__(self, body: bytes, media: str, *, status: int = 200, extra=()):
        self.body = body
        self.status = status
        self.headers = [("Content-Type", media), ("Content-Length", str(len(body))), *extra]
        self.closed = False

    def getheaders(self):
        return self.headers

    def read(self, amount=None):
        return self.body[:amount]

    def close(self):
        self.closed = True


class Factory:
    def __init__(self, response: Response):
        self.response = response
        self.calls = []

    def __call__(self, host, port, timeout, context):
        self.calls.append((host, port, timeout, context))
        return self

    def request(self, method, path, body, headers):
        self.calls.append((method, path, body, headers))

    def getresponse(self):
        return self.response

    def close(self):
        pass


class ZotProvider:
    def zot_read_credential(self):
        return ZotReadCredential(TOKEN, NOW + 100)


class ForgejoProvider:
    def forgejo_read_credential(self):
        return ForgejoReadCredential(TOKEN, NOW + 100)


class Signatures:
    def verify(self, manifest, provenance, manifest_bundle, provenance_bundle, image_reference):
        if (manifest_bundle != b"bundle-manifest" or provenance_bundle != b"bundle-provenance"
                or not image_reference.endswith("@" + json.loads(manifest)["oci"]["manifest_digest"])):
            raise ValueError("signature mismatch")
        oci = oci_signature_result()
        oci["manifest_digest"] = json.loads(manifest)["oci"]["manifest_digest"]
        return sigstore_result(), oci


class ReleaseRun:
    def verify_release_run(self, run_id, release_manifest_sha256, provenance_sha256,
                           source_sha, release_version, manifest_digest):
        return run_id == 34088735049


def manifest_bytes() -> bytes:
    return canonical_bytes({
        "schemaVersion": 2, "mediaType": OCI_MEDIA_TYPE,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + "a" * 64, "size": 10},
        "layers": [],
    })


def evidence_bytes(digest: str) -> tuple[bytes, bytes]:
    old_manifest, old_provenance = base_evidence()
    manifest = json.loads(old_manifest)
    provenance = json.loads(old_provenance)
    manifest["oci"]["manifest_digest"] = digest
    manifest["oci"]["deployment_identity"] = f"{REPOSITORY}@{digest}"
    provenance["subjects"] = {
        "python_wheel_sha256": "a" * 64, "npm_tarball_sha256": "b" * 64,
        "oci_archive_sha256": "c" * 64, "oci_manifest_digest": digest,
        "sbom_sha256": {"python": "d" * 64, "npm": "e" * 64, "oci": "f" * 64},
        "vulnerability_policy_sha256": "1" * 64,
        "vulnerability_policy_result_sha256": "2" * 64,
    }
    provenance["statement_type"] = "https://omnilyzer.ai/release-provenance/v1"
    raw_provenance = canonical_bytes(provenance)
    artifact = lambda name, digest: {"filename": name, "sha256": digest, "size": 10}
    manifest.update({
        "python": {"identity": {"name": "omnilyzer-release-canary", "owner": "omnilyzer"},
                   "artifact": artifact("omnilyzer_release_canary-0.13.4-py3-none-any.whl", "a" * 64)},
        "npm": {"identity": {"name": "@omnilyzer/release-canary", "owner": "omnilyzer"},
                "artifact": artifact("omnilyzer-release-canary-0.13.4.tgz", "b" * 64)},
        "sbom_sha256": {"python": "d" * 64, "npm": "e" * 64, "oci": "f" * 64},
        "vulnerability_policy_sha256": "1" * 64,
        "vulnerability_policy_result_sha256": "2" * 64,
        "vulnerability_report_sha256": {"python": "6" * 64, "npm": "7" * 64, "oci": "8" * 64},
        "grype_database_status_sha256": "3" * 64,
        "release_plan_sha256": "4" * 64, "build_manifest_sha256": "5" * 64,
        "tool_versions": {"syft": "1.51.0", "grype": "0.118.0", "cosign": "3.1.2",
                          "cyclonedx_spec": "1.6", "buildx": "0.36.1", "buildkit": "0.24.0"},
        "evidence": {
            "identity": {"owner": "omnilyzer", "name": "task013-release-evidence"},
            "artifact_filename": "release-evidence.tar.gz",
        },
        "provenance": {"filename": "release-provenance.json", "sha256": hashlib.sha256(raw_provenance).hexdigest()},
        "signing": {
            "method": "keyless Sigstore/Fulcio/Rekor with GitHub OIDC",
            "release_manifest_bundle": "release-manifest.sigstore.json",
            "provenance_bundle": "release-provenance.sigstore.json",
            "oci_signature": f"{REPOSITORY}@{digest}",
        },
    })
    manifest["oci"]["tag"] = VERSION
    return canonical_bytes(manifest), raw_provenance


def archive_bytes(files: dict[str, bytes], *, omit=frozenset()) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name in sorted(ARCHIVE_NAMES - omit):
            data = files.get(name, b"other")
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return gzip.compress(out.getvalue(), mtime=0)


def setup():
    oci_body = manifest_bytes()
    digest = "sha256:" + hashlib.sha256(oci_body).hexdigest()
    release_manifest, provenance = evidence_bytes(digest)
    files = {
        "release-manifest.json": release_manifest,
        "release-provenance.json": provenance,
        "release-manifest.sigstore.json": b"bundle-manifest",
        "release-provenance.sigstore.json": b"bundle-provenance",
    }
    value = base_request().to_dict()
    value.update({
        "manifest_digest": digest,
        "exact_image_reference": f"{ZOT_HOST}/{REPOSITORY}@{digest}",
        "release_manifest_sha256": hashlib.sha256(release_manifest).hexdigest(),
        "provenance_sha256": hashlib.sha256(provenance).hexdigest(),
    })
    request = PromotionRequest.from_dict(value)
    zot_factory = Factory(Response(oci_body, OCI_MEDIA_TYPE, extra=[("Docker-Content-Digest", digest)]))
    forgejo_factory = Factory(Response(archive_bytes(files), "application/gzip"))
    return request, files, ZotCandidateConsumer(ZotProvider(), zot_factory), ForgejoEvidenceConsumer(ForgejoProvider(), forgejo_factory), zot_factory, forgejo_factory


class ConsumerTests(unittest.TestCase):
    def test_exact_candidate_and_evidence_construct_stable_request(self):
        request, files, zot, forgejo, zf, ff = setup()
        identity = authorize_verified_github_oidc(valid_claims(), received_at=NOW)
        runtime = RuntimeConfigurationReference.from_dict(runtime_reference())
        ingress = IngressReference.from_dict(ingress_reference())
        signature = Signatures()
        first = acquire_and_construct_dev_request(request, identity, runtime, ingress, zot, forgejo, signature, ReleaseRun(), received_at=NOW)
        second = acquire_and_construct_dev_request(request, identity, runtime, ingress, zot, forgejo, signature, ReleaseRun(), received_at=NOW)
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(parse_canonical_request(first.canonical_bytes()), first)
        self.assertEqual(first.promotion_request_sha256, request.sha256())
        self.assertEqual(first.manifest_digest, request.manifest_digest)
        self.assertEqual(first.github_workflow_sha, identity.workflow_sha)
        self.assertEqual(zf.calls[0][:2], (ZOT_HOST, 443))
        self.assertEqual(zf.calls[1][:3], ("GET", f"/v2/{REPOSITORY}/manifests/{request.manifest_digest}", None))
        self.assertEqual(ff.calls[0][:2], (FORGEJO_HOST, 443))
        self.assertEqual(ff.calls[1][:3], ("GET", f"/api/packages/omnilyzer/generic/task013-release-evidence/{VERSION}/release-evidence.tar.gz", None))
        self.assertFalse(any(hasattr(zot, name) or hasattr(forgejo, name) for name in ("put", "post", "delete", "upload")))
        self.assertNotIn(TOKEN, repr(first) + first.canonical_bytes().decode())
        self.assertEqual(first.runtime_configuration_reference, runtime)
        self.assertEqual(first.ingress_reference, ingress)
        with self.assertRaises(AttributeError):
            zot._factory = ff
        with self.assertRaises(AttributeError):
            forgejo._factory = zf

    def test_zot_response_and_identity_fail_closed(self):
        request, _, zot, _, factory, _ = setup()
        original = factory.response
        cases = [
            Response(original.body, "text/plain", extra=[("Docker-Content-Digest", request.manifest_digest)]),
            Response(original.body, OCI_MEDIA_TYPE, status=302, extra=[("Location", "https://evil.invalid"), ("Docker-Content-Digest", request.manifest_digest)]),
            Response(original.body + b"x", OCI_MEDIA_TYPE, extra=[("Docker-Content-Digest", request.manifest_digest)]),
            Response(original.body, OCI_MEDIA_TYPE, extra=[("Docker-Content-Digest", "sha256:" + "0" * 64)]),
            Response(original.body, OCI_MEDIA_TYPE, extra=[("Docker-Content-Digest", request.manifest_digest), ("Transfer-Encoding", "chunked")]),
            Response(original.body, OCI_MEDIA_TYPE, extra=[("Docker-Content-Digest", request.manifest_digest), ("Content-Type", OCI_MEDIA_TYPE)]),
            Response(original.body, OCI_MEDIA_TYPE, extra=[("Docker-Content-Digest", request.manifest_digest), ("Location", "https://evil.invalid")]),
            Response(b"x" * (1024 * 1024 + 1), OCI_MEDIA_TYPE, extra=[("Docker-Content-Digest", request.manifest_digest)]),
        ]
        for response in cases:
            with self.subTest(response=response.headers):
                factory.response = response
                with self.assertRaises(ReleaseConsumerError) as caught:
                    zot.acquire(request, now=NOW)
                self.assertNotIn(TOKEN, str(caught.exception))
        factory.response = original
        for bad in ("0.13.4", "sha256:" + "A" * 64, "sha256:" + "0" * 64):
            value = request.to_dict()
            value["manifest_digest"] = bad
            with self.assertRaises(ReleaseConsumerError):
                zot.acquire(PromotionRequest(**value), now=NOW)
        value = request.to_dict()
        value["oci_repository"] = "attacker/repository"
        with self.assertRaises(ReleaseConsumerError):
            zot.acquire(PromotionRequest(**value), now=NOW)
        malformed = b"{"
        malformed_digest = "sha256:" + hashlib.sha256(malformed).hexdigest()
        value = request.to_dict()
        value["manifest_digest"] = malformed_digest
        value["exact_image_reference"] = f"{ZOT_HOST}/{REPOSITORY}@{malformed_digest}"
        factory.response = Response(malformed, OCI_MEDIA_TYPE, extra=[("Docker-Content-Digest", malformed_digest)])
        with self.assertRaises(ReleaseConsumerError):
            zot.acquire(PromotionRequest(**value), now=NOW)

    def test_credentials_and_transport_fail_closed(self):
        request, _, zot, forgejo, zf, ff = setup()
        class Wrong:
            def zot_read_credential(self):
                return ForgejoReadCredential(TOKEN, NOW + 100)
        for provider in (Wrong(), type("Expired", (), {"zot_read_credential": lambda self: ZotReadCredential(TOKEN, NOW)})(),
                         type("Absent", (), {"zot_read_credential": lambda self: None})()):
            with self.assertRaises(ReleaseConsumerError):
                ZotCandidateConsumer(provider, zf).acquire(request, now=NOW)
        class Broken:
            def __call__(self, *args):
                raise TimeoutError(TOKEN)
        with self.assertRaises(ReleaseConsumerError) as caught:
            ZotCandidateConsumer(ZotProvider(), Broken()).acquire(request, now=NOW)
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        ff.response.headers[1] = ("Content-Length", str(len(ff.response.body) + 1))
        with self.assertRaises(ReleaseConsumerError):
            forgejo.acquire(request, now=NOW)

    def test_forgejo_schema_and_hash_failures(self):
        request, files, _, forgejo, _, ff = setup()
        for name, change in (
            ("malformed", b"{"),
            ("duplicate", files["release-manifest.json"].replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')),
            ("unknown", files["release-manifest.json"].replace(b'"schema_version":1', b'"unknown":1,"schema_version":1')),
            ("missing", files["release-manifest.json"].replace(b'"schema_version":1,', b"")),
            ("unknown nested", files["release-manifest.json"].replace(
                b'"oci":{"deployment_identity":', b'"oci":{"unknown":1,"deployment_identity":',
            )),
        ):
            changed = dict(files)
            changed["release-manifest.json"] = change
            ff.response = Response(archive_bytes(changed), "application/gzip")
            with self.subTest(name=name), self.assertRaises(ReleaseConsumerError):
                forgejo.acquire(request, now=NOW)
        ff.response = Response(archive_bytes(files, omit={"release-provenance.json"}), "application/gzip")
        with self.assertRaises(ReleaseConsumerError):
            forgejo.acquire(request, now=NOW)
        ff.response = Response(archive_bytes(files), "text/plain")
        with self.assertRaises(ReleaseConsumerError):
            forgejo.acquire(request, now=NOW)

    def test_promotion_mismatch_and_signature_failure(self):
        request, _, zot, forgejo, _, _ = setup()
        identity = authorize_verified_github_oidc(valid_claims(), received_at=NOW)
        runtime = RuntimeConfigurationReference.from_dict(runtime_reference())
        ingress = IngressReference.from_dict(ingress_reference())
        for field, value in (
            ("release_version", "0.13.5"), ("source_sha", "f" * 40),
            ("release_manifest_sha256", "a" * 64), ("provenance_sha256", "b" * 64),
            ("target_stage", "prod"), ("originating_release_run_id", 1),
        ):
            changed = replace(request, **{field: value})
            with self.subTest(field=field), self.assertRaises(ReleaseConsumerError):
                acquire_and_construct_dev_request(changed, identity, runtime, ingress, zot, forgejo, Signatures(), ReleaseRun(), received_at=NOW)
        class BadSignatures:
            def verify(self, *args):
                result = sigstore_result()
                result["provenance_verified"] = False
                return result, oci_signature_result()
        with self.assertRaises(ReleaseConsumerError):
            acquire_and_construct_dev_request(request, identity, runtime, ingress, zot, forgejo, BadSignatures(), ReleaseRun(), received_at=NOW)
        wrong_identity = replace(identity, repository_id=1)
        with self.assertRaises(ReleaseConsumerError):
            acquire_and_construct_dev_request(request, wrong_identity, runtime, ingress, zot, forgejo, Signatures(), ReleaseRun(), received_at=NOW)
        class UnavailableRun:
            def verify_release_run(self, *args):
                return None
        with self.assertRaises(ReleaseConsumerError):
            acquire_and_construct_dev_request(request, identity, runtime, ingress, zot, forgejo, Signatures(), UnavailableRun(), received_at=NOW)

    def test_repository_inertness(self):
        source = (ROOT / "deployment/release_consumer.py").read_text()
        for forbidden in ("subprocess", "systemctl", "systemd", "Popen", "os.system", "write_bytes", "write_text"):
            self.assertNotIn(forbidden, source.lower() if forbidden.islower() else source)
        environment = json.loads((ROOT / "deployment/environments/dev.json").read_text())
        self.assertIs(environment["activation"]["deployment_enabled"], False)
        workflow = (ROOT / ".github/workflows/platform-promote.yml").read_text()
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("environment: task014-dev", workflow)


if __name__ == "__main__":
    unittest.main()
