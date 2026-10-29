"""File: release/tests/test_analytics_publish_zot.py
Purpose: Defend exact registry digest/immutable-tag requirements of Task013.
Links: release/analytics_publish_zot.py, release/publish_zot.py,
release/tests/test_analytics_oci_archive.py.
Sections: local fixture; refusing occupied tags; receipt verification.
"""
import hashlib
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from release.analytics_publish_zot import publish
from release.tests.test_analytics_oci_archive import build_test_archive


class FakeClient:
    """Non-network OCI registry fixture that records accepted writes."""
    def __init__(self, origin, token, repository):
        self.origin = origin
        self.repository = repository
        self.manifest = b''
        self.requests = []

    def request(self, method, path, data=None, headers=None):
        self.requests.append((method, path))
        if path == '/v2/':
            return 200, {}, b''
        if method == 'HEAD':
            return 404, {}, b''
        if method == 'PUT':
            self.manifest = data
            return 201, {}, b''
        if method == 'GET':
            return 200, {}, self.manifest
        raise ValueError('Unexpected mock registry operation')

    def upload_blob(self, digest, data):
        if 'sha256:' + hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('invalid OCI blob')


class AnalyticsZotPublisherTests(unittest.TestCase):
    """Test OCI publication call order and pre-OIDC refusal conditions."""
    def test_verified_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / 'image.tar'
            build_test_archive(archive)
            with tarfile.open(archive) as tar:
                index = json.loads(tar.extractfile('index.json').read())
                digest = index['manifests'][0]['digest']
            fake = FakeClient('https://oci-dev.omnilyzer.ai', 'fixture', 'omnilyzer/analytics')
            with patch('release.analytics_publish_zot.prepare_source_claim', return_value={
                    'oci_repository': 'omnilyzer/analytics', 'oci_manifest_digest': digest}), \
                 patch('release.analytics_publish_zot._load_token', return_value='fixture'), \
                 patch('release.analytics_publish_zot.Client', return_value=fake):
                publication = root / 'receipt.json'
                publish(root, root, archive, root / 'jwt', publication, '1.2.3', root)
            result = json.loads(publication.read_bytes())
            self.assertEqual(result['manifest_digest'], digest)
            self.assertEqual(result['repository'], 'omnilyzer/analytics')
            self.assertEqual(fake.requests[-2][0], 'GET')
            self.assertEqual(fake.requests[-1][0], 'GET')

    def test_refuse_occupied_tag_without_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / 'image.tar'
            build_test_archive(archive)
            with tarfile.open(archive) as tar:
                digest = json.loads(tar.extractfile('index.json').read())['manifests'][0]['digest']
            fake = FakeClient('https://oci-dev.omnilyzer.ai', 'fixture', 'omnilyzer/analytics')
            original_request = fake.request
            def occupied(method, path, data=None, headers=None):
                if method == 'HEAD':
                    return 200, {}, b''
                return original_request(method, path, data, headers)
            fake.request = occupied
            with patch('release.analytics_publish_zot.prepare_source_claim', return_value={
                    'oci_repository': 'omnilyzer/analytics', 'oci_manifest_digest': digest}), \
                 patch('release.analytics_publish_zot._load_token', return_value='fixture'), \
                 patch('release.analytics_publish_zot.Client', return_value=fake):
                with self.assertRaises(RuntimeError):
                    publish(root, root, archive, root / 'jwt', root / 'receipt', '1.2.3', root)
                self.assertFalse((root / 'receipt').exists())


if __name__ == '__main__':
    unittest.main()
