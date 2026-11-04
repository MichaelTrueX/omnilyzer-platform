"""File: release/tests/test_analytics_task013_build_input.py

Purpose: Source/OCI/profile negative and deterministic review-input tests.
Links: release/analytics_task013_build_input.py, M01 source admission,
M05 OCI PR45, M01 product/runtime PR230, original Task013 signer and Task014.
No registry, Docker daemon, privileged executor or live database is accessed.
"""
from __future__ import annotations

from dataclasses import replace
import base64
from unittest.mock import patch
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest

from deployment.policy import DeploymentPolicyError, canonical_bytes
from release import analytics_owner_source_selection as selection
from release.analytics_oci_context import ESSENTIAL
from deployment.saas_product_contract import load_reviewed_profile
from deployment.saas_product_runtime import load_review_profile
from release.analytics_task013_build_input import (
    ROOT, ERROR, _coherent_profiles, _load_object, build_input,
    review_successor_build_input,
)

SOURCE = ROOT / "release/products/analytics-source.json"
PRODUCT = ROOT / "deployment/products/analytics-dev.json"
RUNTIME = ROOT / "deployment/products/analytics-runtime-dev.json"


class AnalyticsTask013BuildInputTests(unittest.TestCase):
    """Exercise existing signed boundary without claiming any signed release."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load actual reviewed platform JSON files and native profile loaders."""
        cls.source = json.loads(SOURCE.read_text(encoding="utf-8"))
        cls.product = load_reviewed_profile(PRODUCT)
        cls.runtime = load_review_profile(RUNTIME)

    def test_current_three_review_profiles_are_coherent(self) -> None:
        """Prove final PR45 source, /readyz, OCI repo and secrets match."""
        _coherent_profiles(self.source, self.product, self.runtime)
        self.assertEqual(self.source["source_commit"], "4cdda7faeba57abb3388f9be5c450fe6afb1140d")

    def test_old_unpacked_git_revision_is_denied(self) -> None:
        """PR42 alone cannot become a signed OCI artifact by profile drift."""
        bad = dict(self.source, source_commit="597a3415dfee76cc63f6ba70d3660f287a09b0c8")
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(bad, self.product, self.runtime)

    def test_private_readiness_cannot_use_marketing_root(self) -> None:
        """The root landing page must not satisfy app+collector DB readiness."""
        bad = dict(self.source)
        bad["runtime"] = dict(bad["runtime"], http_ready_path="/")
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(bad, self.product, self.runtime)

    def test_changing_oci_repositories_is_denied(self) -> None:
        """No canary repository alias or attacker-controlled module ID."""
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(self.source, replace(self.product, oci_repository="omnilyzer/task013-release-canary"), self.runtime)

    def test_port_and_secret_names_are_exact(self) -> None:
        """Secret reference *names*, never values, are part of the review contract."""
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(self.source, self.product, replace(self.runtime, container_port=8080))
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(self.source, self.product, replace(self.runtime, runtime_secret_names=("DATABASE_URL",)))

    def test_no_review_profile_can_grant_authority(self) -> None:
        """A caller changing review-only authorization is rejected."""
        bad = dict(self.source, authorization="release-authorized")
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(bad, self.product, self.runtime)

    def test_duplicate_json_members_are_rejected(self) -> None:
        """Reject duplicate-key ambiguity at the input-document boundary."""
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "review.json"
            path.write_bytes(b'{"product":"analytics","product":"canary"}')
            with self.assertRaises(DeploymentPolicyError):
                _load_object(path)

    def test_local_symlink_review_file_is_denied(self) -> None:
        """Do not load a replaced review profile through a symlink."""
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "real.json"
            link = Path(root) / "link.json"
            source.write_bytes(b'{}')
            link.symlink_to(source)
            with self.assertRaises(DeploymentPolicyError):
                _load_object(link)

    def test_invalid_path_types_denied_without_network(self) -> None:
        """Reject untrusted caller input rather than guessing a checkout."""
        with self.assertRaises(DeploymentPolicyError):
            build_input("/tmp/not-a-path")  # type: ignore[arg-type]
        with self.assertRaises(DeploymentPolicyError):
            build_input(ROOT, platform_root="bad")  # type: ignore[arg-type]

    def test_original_platform_checkout_is_not_analytics(self) -> None:
        """A platform checkout cannot impersonate the separate product source."""
        with self.assertRaises((DeploymentPolicyError, ValueError)):
            build_input(ROOT)

    def test_real_pr45_git_source_and_unsigned_receipt_when_supplied(self) -> None:
        """Read exact 72 pinned Git objects and prove deterministic nonauthority."""
        source = os.environ.get("OMNILYZER_ANALYTICS_CHECKOUT")
        if not source:
            self.skipTest("optional verified local Analytics PR45 checkout not supplied")
        first = build_input(Path(source))
        second = build_input(Path(source))
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(first["source_files_verified"], 78)
        self.assertEqual(first["analytics_source_commit"], self.source["source_commit"])
        self.assertEqual(first["readiness_path"], "/readyz")
        self.assertEqual(first["oci_repository"], "omnilyzer/analytics")
        self.assertFalse(first["release_authorized"])
        self.assertFalse(first["deployment_authorized"])
        self.assertEqual(len(first["analytics_tree"]), 40)
        self.assertEqual(len(first["dockerfile_sha256"]), 64)
        self.assertNotIn("manifest_digest", first)
        self.assertNotIn("JWT_SECRET", canonical_bytes(first).decode("utf-8"))
        self.assertNotIn("DATABASE_URL", canonical_bytes(first).decode("utf-8"))


class AnalyticsSuccessorBuildInputTests(unittest.TestCase):
    """Local Git end-to-end source tree fixtures, no OCI build or signing."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="task14b-input-git-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.platform = base / "platform"
        self.product = base / "product"
        for repo in (self.platform, self.product):
            repo.mkdir()
            self.git(repo, "init", "-q", "-b", "main")
            self.git(repo, "config", "user.name", "Synthetic Release Test")
            self.git(repo, "config", "user.email", "synthetic@example.invalid")
        for relative in (
            "release/products/analytics-source.json",
            "deployment/products/analytics-dev.json",
            "deployment/products/analytics-runtime-dev.json",
        ):
            target = self.platform / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.git(self.platform, "add", "--all")
        self.git(self.platform, "commit", "-q", "-m", "reviewed platform baseline")
        self.platform_sha = self.git(self.platform, "rev-parse", "HEAD")
        for relative in sorted(ESSENTIAL | {
            "scripts/accept-m05-analytics-oci-dev.py", "lib/product-route.ts",
        }):
            target = self.product / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("synthetic source " + relative + "\n")
        self.git(self.product, "add", "--all")
        self.git(self.product, "commit", "-q", "-m", "original source ancestor")
        self.ancestor = self.git(self.product, "rev-parse", "HEAD")
        (self.product / "lib/product-route.ts").write_text(
            "synthetic next release source\n"
        )
        self.git(self.product, "add", "--all")
        self.git(self.product, "commit", "-q", "-m", "reviewed source successor")
        self.git(self.product, "remote", "add", "origin",
                 "https://github.com/MichaelTrueX/omnilyzer.git")
        self.source_sha = self.git(self.product, "rev-parse", "HEAD")
        self.owner_context = {
            "GITHUB_REPOSITORY": selection.EXPECTED_REPOSITORY,
            "GITHUB_ACTOR": selection.EXPECTED_ACTOR,
            "GITHUB_ACTOR_ID": selection.EXPECTED_ACTOR_ID,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": selection.EXPECTED_REF,
            "GITHUB_WORKFLOW_REF": selection.EXPECTED_WORKFLOW_REF,
            "GITHUB_SHA": self.platform_sha,
        }
        self.selected_payload = {
            "product": "analytics",
            "source_repository": selection.SOURCE_REPOSITORY,
            "source_commit": self.source_sha,
            "release_version": "0.15.1",
        }
        # Only the Git-ancestry fixture is rebased. The installed platform
        # 0.15.0 profile/source pin MUST remain the real original SHA.
        override = patch.object(
            selection, "REVIEWED_0150_ANCESTOR", self.ancestor
        )
        override.start()
        self.addCleanup(override.stop)

    @staticmethod
    def git(repo, *args):
        return subprocess.check_output(
            ["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL,
            timeout=10,
        ).decode().strip()

    def review(self, *, context=None, payload=None):
        return review_successor_build_input(
            self.product, self.owner_context if context is None else context,
            self.selected_payload if payload is None else payload,
            platform_root=self.platform,
        )

    def test_full_immutable_git_tree_passes_without_release_authority(self):
        """A changed product file is bound without repinning original 49 hashes."""
        first = self.review()
        second = self.review()
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(first["analytics_source_commit"], self.source_sha)
        self.assertEqual(first["analytics_tree"],
                         self.git(self.product, "rev-parse", "HEAD^{tree}"))
        self.assertEqual(first["platform_source_commit"], self.platform_sha)
        self.assertEqual(first["release_version"], "0.15.1")
        self.assertEqual(first["full_git_tree_file_count"], len(ESSENTIAL) + 2)
        self.assertEqual(len(first["build_context_sha256"]), 64)
        self.assertEqual(len(first["owner_approval_sha256"]), 64)
        self.assertEqual(first["oci_repository"], "omnilyzer/analytics")
        self.assertEqual(first["readiness_path"], "/readyz")
        self.assertEqual(first["owner_signature_verified"], False)
        self.assertEqual(first["release_signatures_verified"], False)
        self.assertEqual(first["release_authorized"], False)
        self.assertEqual(first["deployment_authorized"], False)
        self.assertNotIn("JWT_SECRET", canonical_bytes(first).decode())
        self.assertNotIn("DATABASE_URL", canonical_bytes(first).decode())

    def test_successor_source_reuses_original_oci_runtime_verifier(self):
        """Full Git receipt flows into original strict OCI content verifier.

        This is a *synthetic OCI archive* and a local-only review, not an
        authenticated BuildKit build or a signed published image.
        """
        from release.analytics_oci_archive import verify_archive
        from release.tests.test_analytics_oci_archive import build_test_archive

        source = self.review()
        with tempfile.TemporaryDirectory(prefix="task14b-oci-fixture-") as root:
            image = Path(root) / "synthetic.oci.tar"
            build_test_archive(image)
            outcome = verify_archive(image, source)
            self.assertEqual(outcome["source_commit"], self.source_sha)
            self.assertEqual(outcome["source_tree"], source["analytics_tree"])
            self.assertEqual(outcome["oci_repository"], "omnilyzer/analytics")
            self.assertFalse(outcome["release_authorized"])
            self.assertFalse(outcome["deployment_authorized"])

            examples = (
                {"release_version": "0.15.0"},
                {"input_kind": "unexpected"},
                {"analytics_source_commit": "4cdda7faeba57abb3388f9be5c450fe6afb1140d"},
                {"build_context_sha256": "not-a-sha"},
                {"full_git_tree_file_count": 999999},
                {"owner_signature_verified": True},
                {"release_signatures_verified": True},
                {"release_authorized": True},
                {"deployment_authorized": True},
                {"oci_repository": "omnilyzer/task013-release-canary"},
                {"runtime_profile_sha256": "not-a-sha"},
                {"unknown": "surprise"},
            )
            for mutation in examples:
                with self.subTest(mutation=mutation), self.assertRaises(
                    DeploymentPolicyError
                ):
                    verify_archive(image, {**source, **mutation})

            build_test_archive(image, runtime_patch={"User": "0:0"})
            with self.assertRaises(DeploymentPolicyError):
                verify_archive(image, source)

    def test_successor_presign_claim_is_bound_to_real_git_context_and_oci(self):
        """Schema 2 source claim cannot be generated from a caller-chosen TAR."""
        from release.analytics_release_source_binding import (
            prepare_successor_source_claim,
        )
        from release.tests.test_analytics_oci_archive import build_test_archive
        from release.analytics_oci_context import snapshot_committed_tree
        from deployment.promotion import SIGNED_SUCCESSOR_SOURCE_FIELDS

        with tempfile.TemporaryDirectory(prefix="task14b-presign-") as tmp:
            archive = Path(tmp) / "reviewed-source.tar"
            image = Path(tmp) / "synthetic-oci.tar"
            snapshot_committed_tree(self.product, self.source_sha, archive)
            build_test_archive(image)

            def claim():
                return prepare_successor_source_claim(
                    self.product, archive, image,
                    platform_root=self.platform, owner_context=self.owner_context,
                    owner_payload=self.selected_payload,
                )

            c = claim()
            self.assertEqual(set(c), SIGNED_SUCCESSOR_SOURCE_FIELDS)
            self.assertEqual(c["schema_version"], 2)
            self.assertEqual(c["release_version"], "0.15.1")
            self.assertEqual(c["source_commit"], self.source_sha)
            self.assertEqual(c["source_tree"],
                             self.git(self.product, "rev-parse", "HEAD^{tree}"))
            self.assertEqual(c["full_git_tree_file_count"], len(ESSENTIAL) + 2)
            self.assertEqual(c["build_context_sha256"], self.review()["build_context_sha256"])
            self.assertEqual(c["owner_approval_sha256"], self.review()["owner_approval_sha256"])
            self.assertEqual(len(c["oci_archive_sha256"]), 64)
            self.assertTrue(c["oci_manifest_digest"].startswith("sha256:"))
            self.assertNotIn("release_authorized", c)
            self.assertNotIn("deployment_authorized", c)
            self.assertEqual(c, claim())

            with archive.open("ab") as stream:
                stream.write(b"unreviewed extra build bytes")
            with self.assertRaises(DeploymentPolicyError):
                claim()
            archive.unlink()
            snapshot_committed_tree(self.product, self.source_sha, archive)

            build_test_archive(image, runtime_patch={"User": "0:0"})
            with self.assertRaises(DeploymentPolicyError):
                claim()

            build_test_archive(image)
            selected = {**self.selected_payload, "release_version": "0.15.0"}
            with self.assertRaises(DeploymentPolicyError):
                prepare_successor_source_claim(
                    self.product, archive, image,
                    platform_root=self.platform, owner_context=self.owner_context,
                    owner_payload=selected,
                )

    def test_real_git_successor_claim_crosses_original_evidence_consumer(self):
        """End-to-end unprivileged Git -> OCI -> signed-input -> read-only consumer.

        Only the Ed25519/Sigstore/Cosign collaborators are synthetic here.
        Real registry authentication, build, policy and release remain HOLD.
        """
        from release.analytics_release_source_binding import (
            prepare_successor_source_claim,
        )
        from release.analytics_release_evidence import create
        from release.tests.test_analytics_release_evidence import (
            synthetic_owner_signature,
        )
        from release.analytics_oci_context import snapshot_committed_tree
        from release.analytics_owner_source_selection import (
            verify_owner_source_selection, expected_owner_approval_bytes,
            AnalyticsOwnerSignatureReceipt,
        )
        from release.tests.test_analytics_oci_archive import build_test_archive
        from release.provenance import REPOSITORY, REPOSITORY_ID, WORKFLOW_REF
        from deployment.tests.test_analytics_signed_release_consumer import (
            SyntheticBlobSignatureVerifier,
            SyntheticSuccessorOCISignatureVerifier,
        )
        from deployment.analytics_signed_release_consumer import (
            verify_owner_selected_analytics_signed_evidence,
        )

        with tempfile.TemporaryDirectory(prefix="task14b-full-provenance-") as tmp:
            root = Path(tmp)
            context_tar = root / "source.tar"
            image = root / "synthetic.oci.tar"
            snapshot_committed_tree(self.product, self.source_sha, context_tar)
            build_test_archive(image)
            claim = prepare_successor_source_claim(
                self.product, context_tar, image,
                platform_root=self.platform, owner_context=self.owner_context,
                owner_payload=self.selected_payload,
            )
            selected = verify_owner_source_selection(
                self.owner_context, self.selected_payload,
                self.platform, self.product,
            )
            owner = AnalyticsOwnerSignatureReceipt(
                source_commit=selected.source_commit,
                source_tree=selected.source_tree,
                release_version=selected.release_version,
                approval_sha256=hashlib.sha256(
                    expected_owner_approval_bytes(selected)
                ).hexdigest(),
                signature_sha256="a" * 64, owner_signature_verified=True,
            )
            owner_kwargs, actual_owner_sha = synthetic_owner_signature(
                root, claim,
            )
            self.assertEqual(claim["owner_approval_sha256"],
                             owner.approval_sha256)
            self.assertEqual(actual_owner_sha, owner.approval_sha256)
            source = root / "source-claim.json"
            source.write_bytes(canonical_bytes(claim))
            publication = root / "zot-publication.json"
            publication.write_bytes(canonical_bytes({
                "schema_version": 1,
                "registry": "https://oci-dev.omnilyzer.ai",
                "repository": "omnilyzer/analytics",
                "tag": selected.release_version,
                "manifest_digest": claim["oci_manifest_digest"],
            }))
            scan = root / "scan"
            scan.mkdir()
            names = (
                "oci-sbom.cdx.json", "oci-grype.json",
                "grype-db-status.json", "vulnerability-policy.json",
            )
            for name in names:
                (scan / name).write_bytes(canonical_bytes({"synthetic": name}))
            execution = {
                "repository": REPOSITORY, "repository_id": REPOSITORY_ID,
                "workflow_ref": WORKFLOW_REF,
                "workflow_sha": self.platform_sha,
                "run_id": 5010, "run_attempt": 1,
                "event_name": "workflow_dispatch",
                "source_commit": self.platform_sha,
            }
            out = root / "unsigned-original-signer-input"
            with (
                patch("release.analytics_release_evidence.validate_policy",
                      return_value={"exceptions": []}),
                patch("release.analytics_release_evidence.validate_database_status",
                      return_value={"valid": True}),
                patch("release.analytics_release_evidence.evaluate",
                      return_value={"decision": "PASS", "blocked_findings": []}),
            ):
                create(source, publication, scan, out,
                       version=selected.release_version, execution=execution,
                       **owner_kwargs)
            evidence = {
                filename: (out / filename).read_bytes()
                for filename in (
                    "release-manifest.json", "release-provenance.json",
                    "analytics-source-claim.json", "oci-publication.json",
                )
            }
            evidence["release-manifest.sigstore.json"] = (
                b"synthetic-manifest-bundle"
            )
            evidence["release-provenance.sigstore.json"] = (
                b"synthetic-provenance-bundle"
            )
            scanners = {
                name: hashlib.sha256((out / name).read_bytes()).hexdigest()
                for name in names
            }
            reviewed = verify_owner_selected_analytics_signed_evidence(
                evidence, scanners,
                SyntheticBlobSignatureVerifier(),
                SyntheticSuccessorOCISignatureVerifier(claim["oci_manifest_digest"]),
                received_at=1700000000, selected=selected, owner_approval=owner,
            )
            self.assertEqual(reviewed.source.source_tree, claim["source_tree"])
            self.assertEqual(reviewed.source.source_commit, self.source_sha)
            self.assertEqual(reviewed.source.claim_sha256,
                             hashlib.sha256(canonical_bytes(claim)).hexdigest())
            self.assertEqual(reviewed.source.oci_manifest_digest,
                             claim["oci_manifest_digest"])
            self.assertFalse(reviewed.deployment_authorized)
            self.assertFalse(reviewed.source.release_authorized)

            # The independent owner approval SHA is signed in provenance:
            # changing it in BOTH blobs is still rejected by owner binding.
            bad = {**claim, "owner_approval_sha256": "f" * 64}
            malicious = dict(evidence)
            for name in (
                "analytics-source-claim.json", "release-manifest.json",
                "release-provenance.json",
            ):
                if name == "analytics-source-claim.json":
                    malicious[name] = canonical_bytes(bad)
                else:
                    modified = json.loads(malicious[name])
                    modified["external_source"] = bad
                    malicious[name] = canonical_bytes(modified)
            modified_manifest = json.loads(malicious["release-manifest.json"])
            modified_manifest["provenance"]["sha256"] = hashlib.sha256(
                malicious["release-provenance.json"]
            ).hexdigest()
            malicious["release-manifest.json"] = canonical_bytes(modified_manifest)
            with self.assertRaises(DeploymentPolicyError):
                verify_owner_selected_analytics_signed_evidence(
                    malicious, scanners,
                    SyntheticBlobSignatureVerifier(),
                    SyntheticSuccessorOCISignatureVerifier(claim["oci_manifest_digest"]),
                    received_at=1700000000, selected=selected, owner_approval=owner,
                )

    def test_owner_signed_successor_builder_reuses_original_pinned_build_path(self):
        """A real disposable SSH signature gates mocked BuildKit BEFORE OCI.

        No Docker daemon is executed: image output is a synthetic OCI fixture.
        The exact Git source and real ssh-keygen signature checks are NOT mocked.
        """
        from release.analytics_owner_source_selection import (
            expected_owner_approval_bytes, verify_owner_source_selection,
            OWNER_APPROVAL_NAMESPACE,
        )
        from release.analytics_task013_build_candidate import build_candidate
        from release.tests.test_analytics_oci_archive import build_test_archive

        with tempfile.TemporaryDirectory(prefix="task14b-signed-build-") as tmp:
            root = Path(tmp)
            key = root / "test-owner-ed25519"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True, capture_output=True, timeout=10,
            )
            pub = key.with_suffix(".pub").read_text().strip()
            trusted = (
                'MichaelTrueX namespaces="' + OWNER_APPROVAL_NAMESPACE +
                '" ' + pub + "\n"
            ).encode("ascii")
            selected = verify_owner_source_selection(
                self.owner_context, self.selected_payload,
                self.platform, self.product,
            )
            approval = root / "owner-approved.json"
            approval.write_bytes(expected_owner_approval_bytes(selected))
            subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-f", str(key),
                 "-n", OWNER_APPROVAL_NAMESPACE, str(approval)],
                check=True, capture_output=True, timeout=10,
            )
            signature = base64.b64encode(
                (root / "owner-approved.json.sig").read_bytes()
            ).decode("ascii")
            kwargs = {
                "owner_context": self.owner_context,
                "owner_payload": self.selected_payload,
                "owner_signature_base64": signature,
                "protected_owner_signers": trusted,
                "platform_root": self.platform,
            }
            with patch(
                "release.analytics_task013_build_candidate._preflight_builder"
            ) as preflight:
                reviewed = build_candidate(
                    self.product, "m01-analytics-task013", **kwargs,
                )
                self.assertEqual(reviewed["schema_version"], 2)
                self.assertEqual(reviewed["source_commit"], self.source_sha)
                self.assertIs(reviewed["release_authorized"], False)
                preflight.assert_called_once_with("m01-analytics-task013")
                preflight.reset_mock()

                for changed in (
                    {"owner_signature_base64": ""},
                    {"owner_signature_base64": signature[:-5]},
                    {"protected_owner_signers": b"untrusted"},
                    {"owner_payload": {**self.selected_payload,
                                       "release_version": "0.15.0"}},
                    {"owner_payload": {**self.selected_payload,
                                       "source_commit": self.ancestor}},
                    {"owner_context": {**self.owner_context,
                                       "GITHUB_ACTOR_ID": "999"}},
                ):
                    with self.subTest(changed=list(changed)), self.assertRaises(
                        DeploymentPolicyError
                    ):
                        build_candidate(
                            self.product, "m01-analytics-task013",
                            execute=True, **{**kwargs, **changed},
                        )
                preflight.assert_not_called()

                # Actual Git, TAR and OCI verification exercise the original
                # builder command with a synthetic OCI artifact as output.
                actual_run = subprocess.run
                docker_calls = []

                def fake_only_docker(argv, *args, **opts):
                    if argv[:3] == ["docker", "buildx", "build"]:
                        docker_calls.append(argv)
                        out = next(
                            item.removeprefix("type=oci,dest=")
                            for item in argv
                            if item.startswith("type=oci,dest=")
                        )
                        build_test_archive(Path(out))
                        return subprocess.CompletedProcess(argv, 0)
                    return actual_run(argv, *args, **opts)

                with patch(
                    "release.analytics_task013_build_candidate.subprocess.run",
                    side_effect=fake_only_docker,
                ):
                    completed = build_candidate(
                        self.product, "m01-analytics-task013",
                        execute=True, **kwargs,
                    )
                self.assertEqual(completed["schema_version"], 2)
                self.assertEqual(completed["source_commit"], self.source_sha)
                self.assertEqual(completed["release_version"], "0.15.1")
                self.assertEqual(
                    completed["owner_approval_sha256"],
                    hashlib.sha256(approval.read_bytes()).hexdigest(),
                )
                self.assertTrue(completed["local_oci_manifest_digest"].startswith("sha256:"))
                self.assertEqual(len(docker_calls), 1)
                self.assertEqual(docker_calls[0][-1], "-")
                self.assertNotIn("--push", docker_calls[0])
                self.assertNotIn("--tag", docker_calls[0])
                self.assertFalse(completed["release_authorized"])
                self.assertFalse(completed["deployment_authorized"])

    def test_successor_zot_publisher_rechecks_signed_encrypted_handoff(self):
        """Real Git + real owner Ed25519, synthetic OCI and no-network Zot.

        The producer claim from the encrypted transport must be byte-equal to
        freshly regenerated source/OCI checks, BEFORE any OIDC token read.
        """
        from release.analytics_publish_zot import publish
        from release.analytics_release_source_binding import (
            prepare_successor_source_claim,
        )
        from release.analytics_oci_context import snapshot_committed_tree
        from release.analytics_owner_source_selection import (
            verify_owner_source_selection, expected_owner_approval_bytes,
            OWNER_APPROVAL_NAMESPACE,
        )
        from release.tests.test_analytics_oci_archive import build_test_archive
        from release.tests.test_analytics_publish_zot import FakeClient

        with tempfile.TemporaryDirectory(prefix="task14b-zot-signed-") as temp:
            root = Path(temp)
            source_tar = root / "source.tar"
            image = root / "oci.tar"
            snapshot_committed_tree(self.product, self.source_sha, source_tar)
            build_test_archive(image)
            claim_data = prepare_successor_source_claim(
                self.product, source_tar, image,
                platform_root=self.platform, owner_context=self.owner_context,
                owner_payload=self.selected_payload,
            )
            claim = root / "analytics-source-claim.json"
            claim.write_bytes(canonical_bytes(claim_data))
            selected = verify_owner_source_selection(
                self.owner_context, self.selected_payload,
                self.platform, self.product,
            )
            approval = root / "approval.json"
            approval.write_bytes(expected_owner_approval_bytes(selected))
            private = root / "owner-test-ed25519"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)],
                capture_output=True, check=True, timeout=10,
            )
            subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-f", str(private),
                 "-n", OWNER_APPROVAL_NAMESPACE, str(approval)],
                capture_output=True, check=True, timeout=10,
            )
            allowed = (
                'MichaelTrueX namespaces="' + OWNER_APPROVAL_NAMESPACE +
                '" ' + private.with_suffix(".pub").read_text().strip() + "\n"
            ).encode("ascii")
            signature = base64.b64encode(
                (root / "approval.json.sig").read_bytes()
            ).decode("ascii")
            kwargs = {
                "owner_context": self.owner_context,
                "owner_payload": self.selected_payload,
                "owner_signature_base64": signature,
                "protected_owner_signers": allowed,
                "successor_claim_file": claim,
            }
            fake = FakeClient(
                "https://oci-dev.omnilyzer.ai", "synthetic-token",
                "omnilyzer/analytics",
            )
            output = root / "publication.json"
            with (
                patch("release.analytics_publish_zot._load_token",
                      return_value="synthetic-token") as token,
                patch("release.analytics_publish_zot.Client", return_value=fake),
            ):
                publish(
                    self.product, source_tar, image, root / "unused.jwt",
                    output, "0.15.1", self.platform, **kwargs,
                )
                token.assert_called_once()
            self.assertEqual(
                json.loads(output.read_bytes())["manifest_digest"],
                claim_data["oci_manifest_digest"],
            )
            self.assertEqual(fake.requests[-1][0], "GET")
            self.assertEqual(fake.requests[-2][0], "GET")

            bad_cases = (
                ({"owner_signature_base64": signature[:-10]}, "0.15.1"),
                ({"protected_owner_signers": b"untrusted"}, "0.15.1"),
                ({"owner_payload": {**self.selected_payload,
                                   "release_version": "0.15.2"}}, "0.15.1"),
                ({"owner_context": {**self.owner_context,
                                   "GITHUB_ACTOR_ID": "999"}}, "0.15.1"),
                ({}, "0.15.2"),
                ({"successor_claim_file": None}, "0.15.1"),
            )
            for i, (changes, version) in enumerate(bad_cases):
                with self.subTest(changes=changes, version=version):
                    with (
                        patch("release.analytics_publish_zot._load_token") as token,
                        patch("release.analytics_publish_zot.Client") as client,
                    ):
                        with self.assertRaises((ValueError, DeploymentPolicyError)):
                            publish(
                                self.product, source_tar, image, root / "unused.jwt",
                                root / ("no-publication-" + str(i)), version,
                                self.platform, **{**kwargs, **changes},
                            )
                        token.assert_not_called()
                        client.assert_not_called()

            raw = claim.read_bytes()
            for i, corrupted in enumerate((
                raw + b" ", raw.replace(
                    self.source_sha.encode("ascii"), b"f" * 40,
                ), raw.replace(
                    claim_data["owner_approval_sha256"].encode("ascii"),
                    b"f" * 64,
                ),
            )):
                claim.write_bytes(corrupted)
                with self.subTest(corrupted=i):
                    with patch("release.analytics_publish_zot._load_token") as token:
                        with self.assertRaises(DeploymentPolicyError):
                            publish(
                                self.product, source_tar, image,
                                root / "unused.jwt", root / ("bad-" + str(i)),
                                "0.15.1", self.platform, **kwargs,
                            )
                        token.assert_not_called()
            claim.write_bytes(raw)
            with source_tar.open("ab") as file:
                file.write(b"transported-unreviewed-bytes")
            with patch("release.analytics_publish_zot._load_token") as token:
                with self.assertRaises(DeploymentPolicyError):
                    publish(
                        self.product, source_tar, image, root / "unused.jwt",
                        root / "corrupt-tar", "0.15.1", self.platform, **kwargs,
                    )
                token.assert_not_called()

    def test_full_tree_changes_on_new_valid_reviewed_commit(self):
        """One additional noncritical source file changes signed tree identity."""
        baseline = self.review()
        (self.product / "lib/feature.ts").write_text("additional source\n")
        self.git(self.product, "add", "--all")
        self.git(self.product, "commit", "-q", "-m", "new source content")
        advanced = self.review(payload={
            **self.selected_payload,
            "source_commit": self.git(self.product, "rev-parse", "HEAD"),
        })
        self.assertNotEqual(
            baseline["build_context_sha256"], advanced["build_context_sha256"]
        )
        self.assertNotEqual(baseline["analytics_tree"], advanced["analytics_tree"])
        self.assertEqual(
            advanced["full_git_tree_file_count"],
            baseline["full_git_tree_file_count"] + 1,
        )

    def test_reject_wrong_owner_workflow_product_sha_and_version(self):
        """No untrusted API SHA, old source or non-owner runner can pass."""
        cases = (
            ({**self.owner_context, "GITHUB_ACTOR_ID": "99"}, self.selected_payload),
            ({**self.owner_context, "GITHUB_SHA": "a" * 40}, self.selected_payload),
            ({**self.owner_context, "GITHUB_REF": "refs/heads/dev"}, self.selected_payload),
            (self.owner_context, {**self.selected_payload, "source_commit": "f" * 40}),
            (self.owner_context, {**self.selected_payload, "source_commit": self.ancestor}),
            (self.owner_context, {**self.selected_payload, "release_version": "0.15.0"}),
            (self.owner_context, {**self.selected_payload, "release_version": "0.16.0-rc1"}),
            (self.owner_context, {**self.selected_payload, "product": "canary"}),
        )
        for context, payload in cases:
            with self.subTest(context=context, payload=payload), self.assertRaises(
                DeploymentPolicyError
            ):
                self.review(context=context, payload=payload)

    def test_dirty_checkout_or_source_origin_is_not_reviewed(self):
        """Unsigned local changes and changed origin are fail-closed."""
        source_file = self.product / "lib/product-route.ts"
        source_file.write_text("dirty source\n")
        with self.assertRaises(DeploymentPolicyError):
            self.review()
        self.git(self.product, "restore", "--", "lib/product-route.ts")
        self.git(self.product, "remote", "set-url", "origin",
                 "https://example.invalid/attacker.git")
        with self.assertRaises(DeploymentPolicyError):
            self.review()

    def test_cannot_bypass_original_profile_or_omit_essential_route(self):
        """Keep original health, secret and runtime configuration intact."""
        runtime_file = self.platform / "deployment/products/analytics-runtime-dev.json"
        original = runtime_file.read_bytes()
        try:
            runtime_file.write_bytes(original.replace(b'"/readyz"', b'"/unsafez"'))
            with self.assertRaises(DeploymentPolicyError):
                self.review()
        finally:
            runtime_file.write_bytes(original)
        self.git(self.product, "rm", "-q", "app/readyz/route.ts")
        self.git(self.product, "commit", "-q", "-m", "remove original health")
        with self.assertRaises(DeploymentPolicyError):
            self.review(payload={
                **self.selected_payload,
                "source_commit": self.git(self.product, "rev-parse", "HEAD"),
            })

    def test_no_unreviewed_platform_metadata_or_symbolic_git_source(self):
        """The inspected root must be the expected clean workflow source."""
        source_file = self.platform / "release/products/analytics-source.json"
        source_file.write_text("{}")
        with self.assertRaises(DeploymentPolicyError):
            self.review()
        self.git(self.platform, "restore", "--",
                 "release/products/analytics-source.json")
        original = self.product / "lib/product-route.ts"
        original.unlink()
        original.symlink_to("../package.json")
        self.git(self.product, "add", "--all")
        self.git(self.product, "commit", "-q", "-m", "unreviewed symlink")
        with self.assertRaises(DeploymentPolicyError):
            self.review(payload={
                **self.selected_payload,
                "source_commit": self.git(self.product, "rev-parse", "HEAD"),
            })


if __name__ == "__main__":
    unittest.main()
