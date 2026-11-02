"""File: release/tests/test_analytics_release_evidence.py
Purpose: Verify exact Analytics-only release provenance and fail-closed negative
cases without OIDC, remote registry, or artificial Python/npm distributions.
Links: release/analytics_release_evidence.py, release/analytics_forgejo_evidence.py,
.github/workflows/platform-release.yml.
Sections: synthetic inputs; positive source/scan binding; negative release gates.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from deployment.policy import canonical_bytes
from release.analytics_release_source_binding import REQUIRED_SOURCE_CLAIM
from release.analytics_release_evidence import create
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
                  'platform_source_commit': SHA, 'oci_repository': 'omnilyzer/analytics',
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
