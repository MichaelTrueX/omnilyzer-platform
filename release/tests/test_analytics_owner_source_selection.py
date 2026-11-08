"""Isolated Git-backed negative tests for inert Task14B owner-source selection."""
from __future__ import annotations

from pathlib import Path
import base64
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from release import analytics_owner_source_selection as selection


class OwnerSelectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="task14b-owner-source-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.platform = self.root / "platform"
        self.product = self.root / "product"
        for name, repo in (("platform", self.platform), ("product", self.product)):
            repo.mkdir()
            self.run_git(repo, "init", "-q", "-b", "main")
            self.run_git(repo, "config", "user.name", "Test Fixture")
            self.run_git(repo, "config", "user.email", "fixture@example.invalid")
            (repo / "sample.txt").write_text(name + "\n")
            self.run_git(repo, "add", "--", "sample.txt")
            self.run_git(repo, "commit", "-q", "-m", "base")
        self.platform_sha = self.run_git(self.platform, "rev-parse", "HEAD")
        self.base_sha = self.run_git(self.product, "rev-parse", "HEAD")
        (self.product / "sample.txt").write_text("reviewed successor\n")
        self.run_git(self.product, "commit", "-q", "-am", "successor")
        self.product_sha = self.run_git(self.product, "rev-parse", "HEAD")
        self.run_git(self.product, "remote", "add", "origin",
                     "https://github.com/MichaelTrueX/omnilyzer.git")
        self.patched_ancestor = patch.object(
            selection, "REVIEWED_0150_ANCESTOR", self.base_sha,
        )
        self.patched_ancestor.start()
        self.addCleanup(self.patched_ancestor.stop)
        self.context = {
            "GITHUB_REPOSITORY": selection.EXPECTED_REPOSITORY,
            "GITHUB_ACTOR": selection.EXPECTED_ACTOR,
            "GITHUB_ACTOR_ID": selection.EXPECTED_ACTOR_ID,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": selection.EXPECTED_REF,
            "GITHUB_WORKFLOW_REF": selection.EXPECTED_WORKFLOW_REF,
            "GITHUB_SHA": self.platform_sha,
        }
        self.payload = {
            "product": "analytics",
            "source_repository": selection.SOURCE_REPOSITORY,
            "source_commit": self.product_sha,
            "release_version": "0.16.0",
        }

    def run_git(self, repo, *args):
        return subprocess.check_output(
            ["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode().strip()

    def qualify(self, context=None, payload=None):
        return selection.verify_owner_source_selection(
            self.context if context is None else context,
            self.payload if payload is None else payload,
            self.platform, self.product,
        )

    def test_real_local_git_success_is_never_a_release_grant(self):
        got = self.qualify()
        self.assertEqual(got.source_commit, self.product_sha)
        self.assertEqual(got.release_version, "0.16.0")
        self.assertEqual(got.platform_workflow_commit, self.platform_sha)
        self.assertEqual(got.source_tree,
                         self.run_git(self.product, "rev-parse", "HEAD^{tree}"))
        self.assertFalse(got.independent_review_verified)
        self.assertFalse(got.release_authorized)
        self.assertFalse(got.deployment_authorized)

    def test_wrong_workflow_actor_or_repository_fails_closed(self):
        for key, bad in (
            ("GITHUB_REPOSITORY", "other/repo"),
            ("GITHUB_ACTOR", "other"),
            ("GITHUB_ACTOR_ID", "130741174"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_WORKFLOW_REF", "other/workflow@refs/heads/main"),
            ("GITHUB_SHA", "a" * 40),
        ):
            with self.subTest(key=key), self.assertRaises(
                selection.AnalyticsOwnerSourceSelectionDenied
            ):
                self.qualify(context={**self.context, key: bad})

    def test_unreviewed_source_shapes_and_version_fail_closed(self):
        for key, bad in (
            ("product", "canary"),
            ("source_repository", "other/private"),
            ("source_commit", "main"),
            ("source_commit", "a" * 40),
            ("source_commit", "0" * 40),
            ("release_version", "0.16.0-rc"),
            ("release_version", "01.16.0"),
        ):
            with self.subTest(key=key), self.assertRaises(
                selection.AnalyticsOwnerSourceSelectionDenied
            ):
                self.qualify(payload={**self.payload, key: bad})
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            self.qualify(payload={**self.payload, "extra": "fake approval"})

    def test_source_origin_change_fails_closed(self):
        self.run_git(self.product, "remote", "set-url", "origin",
                     "https://example.invalid/malicious.git")
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            self.qualify()

    def test_no_valid_reviewed_ancestor_fails_closed(self):
        with patch.object(selection, "REVIEWED_0150_ANCESTOR", "a" * 40):
            with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
                self.qualify()

    def test_dirty_source_and_platform_fail_closed(self):
        for repo in (self.product, self.platform):
            path = repo / "sample.txt"
            original = path.read_text()
            path.write_text("dirty\n")
            try:
                with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
                    self.qualify()
            finally:
                path.write_text(original)

    def test_missing_context_field_denies(self):
        for key in tuple(self.context):
            context = dict(self.context)
            del context[key]
            with self.subTest(key=key), self.assertRaises(
                selection.AnalyticsOwnerSourceSelectionDenied
            ):
                self.qualify(context=context)

    def test_checkout_must_be_real_directory(self):
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            selection.verify_owner_source_selection(
                self.context, self.payload, self.platform, self.root / "absent",
            )

    def test_untracked_output_does_not_affect_signed_git_tree(self):
        (self.product / "test-output.tmp").write_text("throwaway")
        self.assertEqual(self.qualify().source_commit, self.product_sha)


    def test_owner_detached_signature_bound_to_exact_git_and_workflow(self):
        # Real ssh-keygen signing/verification, fixture key never used as a
        # production trust anchor. No Github dispatch, Docker or network.
        signed = self.root / "signed"
        signed.mkdir()
        private = signed / "owner-test-ed25519"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)],
            check=True, capture_output=True, timeout=5,
        )
        public = private.with_suffix(".pub").read_text().strip()
        trusted = signed / "trusted-allowed-signers"
        trusted.write_text(
            'MichaelTrueX namespaces="omnilyzer-analytics-source-v1" '
            + public + "\n"
        )
        selected = self.qualify()
        approval = signed / "source-approval.json"
        approval.write_bytes(selection.expected_owner_approval_bytes(selected))
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(private),
             "-n", selection.OWNER_APPROVAL_NAMESPACE, str(approval)],
            check=True, capture_output=True, timeout=5,
        )
        signature = signed / "source-approval.json.sig"
        def review(a, sig):
            return selection._verify_owner_signature_with_signers(
                a, approval.read_bytes(), sig.read_bytes(), trusted.read_bytes(),
            )
        receipt = review(selected, signature)
        self.assertTrue(receipt.owner_signature_verified)
        self.assertFalse(receipt.independent_review_verified)
        self.assertFalse(receipt.release_authorized)
        self.assertFalse(receipt.deployment_authorized)

        # Section: same owner signature accepted at the protected Task013
        # pre-BuildKit boundary when the public trust key comes from a
        # separately provisioned CI setting, not the product Git checkout.
        b64 = base64.b64encode(signature.read_bytes()).decode("ascii")

        def ci(context=None, payload=None, signature_value=b64, trusted=None):
            return selection.review_ci_owner_signed_source(
                self.context if context is None else context,
                self.payload if payload is None else payload,
                self.platform, self.product,
                signature_base64=signature_value,
                protected_signers=trusted.read_bytes() if trusted is not None
                    else trusted_signers,
            )

        trusted_signers = trusted.read_bytes()
        ci_selection, ci_receipt = ci()
        self.assertEqual(ci_selection, selected)
        self.assertEqual(ci_receipt.approval_sha256, receipt.approval_sha256)
        self.assertFalse(ci_receipt.release_authorized)
        self.assertFalse(ci_receipt.deployment_authorized)
        for bad_signature in (
            "", "not-base64", b64 + "\\n", b64[:-4], "A" * 8193,
        ):
            with self.subTest(signature=bad_signature[:20]), self.assertRaises(
                selection.AnalyticsOwnerSourceSelectionDenied
            ):
                ci(signature_value=bad_signature)
        for bad_context, bad_payload in (
            ({**self.context, "GITHUB_ACTOR_ID": "999"}, None),
            ({**self.context, "GITHUB_SHA": "a" * 40}, None),
            (None, {**self.payload, "release_version": "0.15.0"}),
            (None, {**self.payload, "source_commit": self.base_sha}),
            (None, {**self.payload, "source_commit": "f" * 40}),
        ):
            with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
                ci(context=bad_context, payload=bad_payload)
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            selection.review_ci_owner_signed_source(
                self.context, self.payload, self.platform, self.product,
                signature_base64=b64,
                protected_signers=b'not-a-trusted-owner-public-key',
            )
        # Replacing either the selected Git commit, SemVer, or release
        # workflow SHA cannot replay an old owner's detached signature.
        for key, value in (
            ("source_commit", "a" * 40),
            ("release_version", "0.17.0"),
            ("platform_workflow_commit", "b" * 40),
            ("source_tree", "c" * 40),
        ):
            with self.subTest(key=key), self.assertRaises(
                selection.AnalyticsOwnerSourceSelectionDenied
            ):
                changed = {
                    field: getattr(selected, field)
                    for field in selected.__dataclass_fields__
                }
                changed[key] = value
                review(
                    selection.AnalyticsOwnerSourceSelection(**changed), signature,
                )
        # Wrong signature, untrusted signer and syntactically valid
        # self-declared approval must all be rejected fail closed.
        badsig = signed / "invalid.sig"
        badsig.write_bytes(signature.read_bytes().replace(
            b"SSH SIGNATURE", b"BAD SIGNATURE",
        ))
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            review(selected, badsig)
        # A different key signing identical content is NOT authorized.
        otherkey = signed / "untrusted-ed25519"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
             "-f", str(otherkey)],
            check=True, capture_output=True, timeout=5,
        )
        otherapproval = signed / "untrusted-source.json"
        otherapproval.write_bytes(approval.read_bytes())
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(otherkey),
             "-n", selection.OWNER_APPROVAL_NAMESPACE, str(otherapproval)],
            check=True, capture_output=True, timeout=5,
        )
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            review(selected, signed / "untrusted-source.json.sig")
        # Altered signer bytes must not verify an authentic signature.
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            selection._verify_owner_signature_with_signers(
                selected, approval.read_bytes(), signature.read_bytes(),
                b'MichaelTrueX namespaces="omnilyzer-analytics-source-v1" ssh-ed25519 BAD\\n',
            )
        # The root-controlled entrypoint must fail on missing authority.
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            selection.verify_owner_detached_source_approval(
                selected, approval, signature,
            )

    def test_owner_signature_absent_by_default(self):
        selected = self.qualify()
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            selection.verify_owner_detached_source_approval(
                selected, self.root / "unknown.approval",
                self.root / "unknown.signature",
            )

    def test_signature_file_read_rejects_symlinks_and_mutated_shape(self):
        source = self.root / "approval"
        source.write_bytes(b"fixed-owner-approval")
        linked = self.root / "linked-approval"
        linked.symlink_to(source)
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            selection._bounded_file(linked, 1024)
        self.assertEqual(
            selection._bounded_file(source, 1024), b"fixed-owner-approval",
        )
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            selection._bounded_file(source, 4)
        source.write_bytes(b"")
        with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
            selection._bounded_file(source, 1024)

    def test_repository_source_trust_key_cannot_replace_root_anchor(self):
        # A committed or untracked local allowlist is no longer sufficient.
        repo_signer = self.root / "allowed-signers"
        repo_signer.write_text('MichaelTrueX ssh-ed25519 FAKE\\n')
        with patch.object(selection, "TRUSTED_OWNER_SIGNERS", repo_signer):
            with self.assertRaises(selection.AnalyticsOwnerSourceSelectionDenied):
                selection._root_controlled_signers()


if __name__ == "__main__":
    unittest.main()
