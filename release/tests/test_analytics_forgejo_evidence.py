"""File: release/tests/test_analytics_forgejo_evidence.py
Purpose: Test fail-closed Analytics-only Forgejo evidence without network.
Links: release/analytics_forgejo_evidence.py, release/analytics_release_source_binding.py.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from release.analytics_forgejo_evidence import archive_evidence, publish

DIGEST = 'sha256:' + 'a' * 64
VERSION = '1.2.3'


def fixture(directory):
    """Section: Create synthetic unsigned test evidence; never production credentials."""
    claim = {'oci_repository': 'omnilyzer/analytics', 'oci_manifest_digest': DIGEST}
    provenance = {'subjects': {'oci_manifest_digest': DIGEST}}
    provenance_raw = json.dumps(provenance).encode()
    manifest = {'oci': {'repository': 'omnilyzer/analytics', 'manifest_digest': DIGEST},
                'provenance': {'sha256': hashlib.sha256(provenance_raw).hexdigest()}}
    data = {'analytics-source-claim.json': json.dumps(claim).encode(),
            'oci-publication.json': json.dumps({'schema_version': 1,
                'registry': 'https://oci-dev.omnilyzer.ai', 'repository': 'omnilyzer/analytics',
                'tag': VERSION, 'manifest_digest': DIGEST}).encode(),
            'release-manifest.json': json.dumps(manifest).encode(),
            'release-provenance.json': provenance_raw,
            'release-manifest.sigstore.json': b'fixture-only',
            'release-provenance.sigstore.json': b'fixture-only'}
    for name, value in data.items():
        (directory / name).write_bytes(value)


class AnalyticsForgejoEvidenceTests(unittest.TestCase):
    """Section: Validate digest, destination, file integrity and registry readback."""
    def test_deterministic_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture(directory)
            self.assertEqual(archive_evidence(directory, DIGEST, VERSION),
                             archive_evidence(directory, DIGEST, VERSION))

    def test_invalid_digest_version_and_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture(directory)
            for digest, version in [('sha256:' + 'b' * 64, VERSION), (DIGEST, 'latest')]:
                with self.assertRaises(ValueError):
                    archive_evidence(directory, digest, version)
            (directory / 'unexpected').write_text('no')
            with self.assertRaises(ValueError):
                archive_evidence(directory, DIGEST, VERSION)

    def test_publish_readback_must_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture(directory)
            token = directory / 'token'
            with patch('release.analytics_forgejo_evidence._token', return_value='test'), \
                 patch('release.analytics_forgejo_evidence._request', side_effect=[(201, b''), (200, b'wrong')]):
                with self.assertRaises(RuntimeError):
                    publish(directory, token, DIGEST, VERSION)


if __name__ == '__main__':
    unittest.main()
