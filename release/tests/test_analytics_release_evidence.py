"""File: release/tests/test_analytics_release_evidence.py
Purpose: Verify exact Analytics-only release provenance and fail-closed negative
cases without OIDC, remote registry, or artificial Python/npm distributions.
Links: release/analytics_release_evidence.py, release/analytics_forgejo_evidence.py,
.github/workflows/platform-release.yml.
Sections: synthetic inputs; positive source/scan binding; negative release gates.
"""
import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from deployment.policy import canonical_bytes
from release.analytics_release_source_binding import REQUIRED_SOURCE_CLAIM
from release.analytics_release_evidence import create
from release.analytics_owner_source_selection import (
    AnalyticsOwnerSourceSelection, EXPECTED_WORKFLOW_REF,
    OWNER_APPROVAL_NAMESPACE, expected_owner_approval_bytes,
)
from release.provenance import REPOSITORY, REPOSITORY_ID, WORKFLOW_REF

SHA = 'a' * 40
DIGEST = 'sha256:' + 'b' * 64
VERSION = '1.2.3'


def setup(tmp):
    """Construct fixture-only source claim and metadata; never real scan results."""
    root = Path(tmp)
    scan = root / 'scan'
    scan.mkdir()
    for name in ('oci-sbom.cdx.json', 'oci-grype.json', 'grype-db-status.json',
                 'vulnerability-policy.json'):
        (scan / name).write_bytes(b'{}')
    claim = {key: 'c' * 64 for key in REQUIRED_SOURCE_CLAIM}
    claim.update({'schema_version': 1, 'product_id': 'analytics',
                  'platform_source_commit': SHA, 'platform_tree': 'c' * 40,
                  'source_tree': 'd' * 40,
                  'oci_repository': 'omnilyzer/analytics',
                  'oci_manifest_digest': DIGEST,
                  'source_repository': 'MichaelTrueX/omnilyzer',
                  'source_commit': '4cdda7faeba57abb3388f9be5c450fe6afb1140d',
                  'source_files_verified': 78, 'readiness_path': '/readyz'})
    source = root / 'claim.json'
    source.write_bytes(canonical_bytes(claim))
    receipt = root / 'publication.json'
    receipt.write_bytes(canonical_bytes({'schema_version': 1,
        'registry': 'https://oci-dev.omnilyzer.ai',
        'repository': 'omnilyzer/analytics', 'tag': VERSION, 'manifest_digest': DIGEST}))
    execution = {'repository': REPOSITORY, 'repository_id': REPOSITORY_ID,
        'workflow_ref': WORKFLOW_REF, 'workflow_sha': SHA,
        'source_commit': SHA, 'run_id': 123, 'run_attempt': 1,
        'event_name': 'workflow_dispatch'}
    return source, receipt, scan, execution


# Section: actual disposable Ed25519 proof for protected signer fixtures.
# No test key is committed or used to authorize a real release.
def synthetic_owner_signature(root: Path, claim: dict) -> tuple[dict, str]:
    """Sign one exact synthetic successor claim with a temporary SSH key."""
    selected = AnalyticsOwnerSourceSelection(
        source_commit=claim["source_commit"],
        source_tree=claim["source_tree"],
        release_version=claim["release_version"],
        platform_workflow_commit=claim["platform_source_commit"],
        owner_actor_id="130741173",
    )
    approval = root / "signer-approval.json"
    approval.write_bytes(expected_owner_approval_bytes(selected))
    key = root / "temporary-signer-ed25519"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True, capture_output=True, timeout=10,
    )
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key),
         "-n", OWNER_APPROVAL_NAMESPACE, str(approval)],
        check=True, capture_output=True, timeout=10,
    )
    allowed = (
        'MichaelTrueX namespaces="' + OWNER_APPROVAL_NAMESPACE +
        '" ' + key.with_suffix(".pub").read_text().strip() + "\n"
    ).encode("ascii")
    context = {
        "GITHUB_REPOSITORY": "MichaelTrueX/omnilyzer-platform",
        "GITHUB_ACTOR": "MichaelTrueX",
        "GITHUB_ACTOR_ID": "130741173",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": EXPECTED_WORKFLOW_REF,
        "GITHUB_SHA": claim["platform_source_commit"],
    }
    payload = {
        "product": "analytics",
        "source_repository": "MichaelTrueX/omnilyzer",
        "source_commit": claim["source_commit"],
        "release_version": claim["release_version"],
    }
    return ({
        "owner_context": context,
        "owner_payload": payload,
        "owner_signature_base64": base64.b64encode(
            (root / "signer-approval.json.sig").read_bytes()
        ).decode("ascii"),
        "protected_owner_signers": allowed,
    }, hashlib.sha256(approval.read_bytes()).hexdigest())


class AnalyticsReleaseEvidenceTests(unittest.TestCase):
    """Check source and OCI identity in OCI-only signed inputs."""
    def test_positive_source_and_scanner_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, receipt, scan, execution = setup(tmp)
            with patch('release.analytics_release_evidence.validate_policy', return_value={'exceptions': []}), \
                 patch('release.analytics_release_evidence.validate_database_status', return_value={'valid': True}), \
                 patch('release.analytics_release_evidence.evaluate', return_value={'decision': 'PASS', 'blocked_findings': []}):
                create(source, receipt, scan, Path(tmp) / 'evidence', version=VERSION, execution=execution)
            d = Path(tmp) / 'evidence'
            manifest = json.loads((d / 'release-manifest.json').read_bytes())
            provenance_raw = (d / 'release-provenance.json').read_bytes()
            provenance = json.loads(provenance_raw)
            self.assertEqual(manifest['provenance']['sha256'], hashlib.sha256(provenance_raw).hexdigest())
            self.assertEqual(provenance['subjects']['oci_manifest_digest'], DIGEST)
            self.assertEqual(manifest['external_source'], provenance['external_source'])
            self.assertNotIn('python', manifest)
            self.assertNotIn('npm', manifest)
            self.assertEqual(provenance['subjects']['security_exceptions'], 0)

    def test_successor_schema2_emits_only_original_oci_release_with_owner_hash(self):
        """A future reviewed Git tree shares the existing zero-high signer input."""
        with tempfile.TemporaryDirectory(prefix='task14b-next-evidence-') as tmp:
            source, publication, scanner, execution = setup(tmp)
            claim = json.loads(source.read_bytes())
            for old_name in (
                'source_manifest_sha256', 'source_binding_sha256',
                'source_files_verified',
            ):
                claim.pop(old_name)
            claim.update({
                'schema_version': 2, 'source_commit': 'f' * 40,
                'release_version': VERSION,
                'full_git_tree_file_count': 612,
                'owner_approval_sha256': 'e' * 64,
            })
            owner_kwargs, approval_sha = synthetic_owner_signature(
                Path(tmp), claim,
            )
            claim["owner_approval_sha256"] = approval_sha
            source.write_bytes(canonical_bytes(claim))
            with self.assertRaises(ValueError):
                create(
                    source, publication, scanner, Path(tmp) / "unsigned-denied",
                    version=VERSION, execution=execution,
                )

            def emit(output_name='evidence', owner_inputs=None):
                with (
                    patch('release.analytics_release_evidence.validate_policy',
                          return_value={'exceptions': []}),
                    patch('release.analytics_release_evidence.validate_database_status',
                          return_value={'valid': True}),
                    patch('release.analytics_release_evidence.evaluate',
                          return_value={'decision': 'PASS', 'blocked_findings': []}),
                ):
                    create(source, publication, scanner, Path(tmp) / output_name,
                           version=VERSION, execution=execution,
                           **(owner_kwargs if owner_inputs is None else owner_inputs))

            emit()
            out = Path(tmp) / 'evidence'
            signed_input = json.loads((out / 'release-manifest.json').read_bytes())
            provenance = json.loads((out / 'release-provenance.json').read_bytes())
            self.assertEqual(signed_input['external_source'], claim)
            self.assertEqual(provenance['external_source'], claim)
            self.assertEqual(signed_input['version'], VERSION)
            self.assertEqual(provenance['subjects']['security_exceptions'], 0)
            self.assertEqual(signed_input['signing']['method'],
                             'keyless Sigstore/Fulcio/Rekor with GitHub OIDC')
            self.assertEqual((out / 'analytics-source-claim.json').read_bytes(),
                             canonical_bytes(claim))
            # A protected signer must never proceed from a substituted
            # signature, GitHub actor, platform SHA or public trust key.
            for i, inputs in enumerate((
                {**owner_kwargs, "owner_signature_base64": "bad-signature"},
                {**owner_kwargs, "protected_owner_signers": b"untrusted"},
                {**owner_kwargs, "owner_context": {
                    **owner_kwargs["owner_context"], "GITHUB_ACTOR_ID": "999",
                }},
                {**owner_kwargs, "owner_payload": {
                    **owner_kwargs["owner_payload"], "source_commit": "a" * 40,
                }},
            )):
                with self.subTest(signer_case=i), self.assertRaises(Exception):
                    emit('denied-signer-' + str(i), inputs)
            # Counterfeit claim, old commit, bad approval SHA, mismatched
            # release SemVer, and historical 78 count cannot be promoted.
            for i, changes in enumerate((
                {'release_version': '1.2.4'},
                {'source_commit': '4cdda7faeba57abb3388f9be5c450fe6afb1140d'},
                {'owner_approval_sha256': 'wrong'},
                {'full_git_tree_file_count': 78.0},
                {'full_git_tree_file_count': 10001},
                {'source_manifest_sha256': 'a' * 64},
                {'schema_version': 1},
                {'oci_repository': 'omnilyzer/task013-release-canary'},
            )):
                with self.subTest(changes=changes):
                    source.write_bytes(canonical_bytes({**claim, **changes}))
                    with self.assertRaises(Exception):
                        emit('denied-' + str(i))

    def test_wrong_registry_digest_and_protected_source_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, receipt, scan, execution = setup(tmp)
            bad = json.loads(receipt.read_bytes())
            bad['repository'] = 'omnilyzer/task013-release-canary'
            receipt.write_bytes(canonical_bytes(bad))
            with self.assertRaises(Exception):
                create(source, receipt, scan, Path(tmp) / 'out', version=VERSION, execution=execution)
            bad['repository'] = 'omnilyzer/analytics'
            receipt.write_bytes(canonical_bytes(bad))
            execution['source_commit'] = 'd' * 40
            with self.assertRaises(Exception):
                create(source, receipt, scan, Path(tmp) / 'out', version=VERSION, execution=execution)

    def test_security_waiver_and_high_finding_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, receipt, scan, execution = setup(tmp)
            with patch('release.analytics_release_evidence.validate_policy', return_value={'exceptions': ['waiver']}), \
                 patch('release.analytics_release_evidence.validate_database_status', return_value={'valid': True}):
                with self.assertRaises(ValueError):
                    create(source, receipt, scan, Path(tmp) / 'out', version=VERSION, execution=execution)
            with patch('release.analytics_release_evidence.validate_policy', return_value={'exceptions': []}), \
                 patch('release.analytics_release_evidence.validate_database_status', return_value={'valid': True}), \
                 patch('release.analytics_release_evidence.evaluate', return_value={'decision': 'DENY', 'blocked_findings': ['HIGH']}):
                with self.assertRaises(ValueError):
                    create(source, receipt, scan, Path(tmp) / 'out', version=VERSION, execution=execution)


if __name__ == '__main__':
    unittest.main()
