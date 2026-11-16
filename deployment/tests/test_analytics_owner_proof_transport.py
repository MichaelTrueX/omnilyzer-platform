"""Public approval transport uses real isolated Ed25519/OpenSSH verification.

Only the installed public-key reader is substituted with a generated fixture
key. OIDC/registry fixtures retain their existing tests; no production key,
signature, network, replay or host installation is used here.
"""
from contextlib import ExitStack
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from release import analytics_owner_source_selection as owner
from deployment.analytics_execution import parse_analytics_successor_request
from deployment.analytics_executor import _verify_executor_owner_source
from deployment.policy import canonical_bytes
from deployment.tests import test_analytics_execution as execution_tests


class OwnerProofTransportTests(unittest.TestCase):
    """No per-version root file or request-derived signer authority."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='m05-public-owner-proof-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.data, self.context = execution_tests.AnalyticsSuccessorRequestTests().candidate()
        self.selected = self.context['selected']
        key = self.root / 'fixture-ed25519'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
            check=True, capture_output=True, timeout=5)
        self.signers = ('MichaelTrueX namespaces="omnilyzer-analytics-source-v1" '
            + key.with_suffix('.pub').read_text().strip() + '\n').encode('ascii')
        approval = self.root / 'approval.json'
        approval.write_bytes(owner.expected_owner_approval_bytes(self.selected))
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key),
            '-n', owner.OWNER_APPROVAL_NAMESPACE, str(approval)],
            check=True, capture_output=True, timeout=5)
        self.envelope = {'approval': approval.read_text(),
            'signature_base64': base64.b64encode(
                approval.with_suffix('.json.sig').read_bytes()).decode('ascii')}
        self.proof = canonical_bytes(self.envelope).decode('ascii')
        self.assertLessEqual(len(self.proof), 2048)
        self.data['owner_source_proof'] = self.proof
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.trust = self.stack.enter_context(patch.object(owner,
            '_root_controlled_signers', return_value=self.signers))

    def test_real_signature_roundtrip_and_executor_bind_without_owner_files(self):
        with patch.object(owner, '_bounded_file', side_effect=AssertionError('no owner files')):
            selected, receipt = owner.verify_owner_signed_source_proof(self.proof)
            self.assertEqual(selected, self.selected)
            self.assertTrue(receipt.owner_signature_verified)
            self.assertFalse(receipt.deployment_authorized)
            self.assertEqual(receipt.approval_sha256,
                self.data['owner_approval_sha256'])
            self.assertIsNone(_verify_executor_owner_source(self.data))
        self.assertEqual(self.trust.call_count, 2)

    def test_wrong_trusted_key_changed_payload_and_untrusted_signer_are_denied(self):
        other = self.root / 'other-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other)],
            check=True, capture_output=True, timeout=5)
        wrong = ('MichaelTrueX namespaces="omnilyzer-analytics-source-v1" '
            + other.with_suffix('.pub').read_text().strip() + '\n').encode('ascii')
        with patch.object(owner, '_root_controlled_signers', return_value=wrong):
            with self.assertRaises(owner.AnalyticsOwnerSourceSelectionDenied):
                owner.verify_owner_signed_source_proof(self.proof)
        changed = {**self.envelope,
            'approval': self.envelope['approval'].replace('"analytics"', '"other"')}
        with self.assertRaises(owner.AnalyticsOwnerSourceSelectionDenied):
            owner.verify_owner_signed_source_proof(canonical_bytes(changed).decode())
        with self.assertRaises(owner.AnalyticsOwnerSourceSelectionDenied):
            owner.verify_owner_signed_source_proof(canonical_bytes(
                {**self.envelope, 'signers': self.signers.decode()}).decode())

    def test_malformed_proof_never_falls_back_to_files_or_another_key(self):
        for proof in (None, True, '', 'x' * 2049, self.proof + '\n',
                self.proof.replace('{', '{"approval":"duplicate",', 1),
                canonical_bytes({**self.envelope, 'signature_base64': 'bad!'}).decode()):
            with self.subTest(proof=str(proof)[:15]), patch.object(owner,
                    '_bounded_file', side_effect=AssertionError('no fallback')):
                with self.assertRaises((owner.AnalyticsOwnerSourceSelectionDenied, ValueError)):
                    _verify_executor_owner_source({**self.data, 'owner_source_proof': proof})

    def test_executor_binds_signature_to_requested_source_version_and_hash(self):
        for field in ('product_source_sha', 'source_sha', 'release_version',
                'owner_approval_sha256'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                _verify_executor_owner_source({**self.data, field: 'wrong'})

    def test_request_ci_and_sealed_transport_keep_exact_proof_and_request_hash(self):
        from deployment.analytics_ci_request import build_analytics_successor_ci_request
        from deployment.tests.test_analytics_ci_request import AnalyticsSuccessorCIRequestTests, token
        from deployment.private_registry_fd import (
            create_sealed_successor_review_credentials, read_sealed_successor_review_credentials)
        from deployment.tests.test_identity import NOW
        from deployment.tests.test_broker_integration import TOKEN, ZOT_TOKEN, FORGEJO_TOKEN
        data, context, environment = AnalyticsSuccessorCIRequestTests().candidate()
        environment['ANALYTICS_OWNER_SOURCE_PROOF'] = self.proof
        raw = build_analytics_successor_ci_request(deployment_oidc_token=token(), environment=environment)
        parsed = parse_analytics_successor_request(raw, **context)
        self.assertEqual(parsed.owner_source_proof, self.proof)
        self.assertEqual(parsed.canonical_bytes(), raw)
        self.assertEqual(parsed.sha256(), hashlib.sha256(raw).hexdigest())
        # The existing sealed credential binds the ENTIRE canonical request.
        import os
        fd = create_sealed_successor_review_credentials(
            ZOT_TOKEN, expires_at=NOW + 270,
            canonical_request=raw, image=parsed.exact_image_reference,
            github_oidc_token=TOKEN, forgejo_token=FORGEJO_TOKEN, now=NOW)
        try:
            result = read_sealed_successor_review_credentials(fd,
                canonical_request=raw, image=parsed.exact_image_reference, now=NOW)
            self.assertEqual(result.zot.request_sha256, hashlib.sha256(raw).hexdigest())
        finally:
            os.close(fd)

    def test_broker_reverifies_public_signature_without_per_release_root_files(self):
        from deployment.tests.test_analytics_promotion_broker import make_broker, evidence
        from deployment.tests.test_broker_integration import TOKEN, ZOT_TOKEN, FORGEJO_TOKEN
        from deployment.tests.test_identity import NOW
        from deployment.broker import BrokerUnavailableError
        broker, replay, transport = make_broker()
        args = dict(compact_token=TOKEN, zot_token=ZOT_TOKEN,
            forgejo_token=FORGEJO_TOKEN, received_at=NOW)
        with patch('deployment.analytics_registry_review_composition.acquire_and_review_analytics_release',
                return_value=evidence()), patch(
                'deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release',
                return_value=self.context['signed_release']) as remote, patch.object(owner,
                '_bounded_file', side_effect=AssertionError('no files')):
            checked = broker.review_first_successor_without_forwarding(
                canonical_request=canonical_bytes(self.data), **args)
            self.assertEqual(checked.owner_source_proof, self.proof)
            self.assertEqual(remote.call_args.kwargs['owner_source_proof'], self.proof)
            remote.reset_mock()
            with self.assertRaises(BrokerUnavailableError):
                broker.review_first_successor_without_forwarding(
                    canonical_request=canonical_bytes({**self.data, 'owner_source_proof': '{}'}), **args)
            remote.assert_not_called()
        self.assertEqual(transport.requests, [])

    def test_signed_consumer_rechecks_proof_and_exact_registry_digest(self):
        from types import SimpleNamespace
        from deployment.analytics_signed_release_consumer import (
            acquire_and_review_owner_approved_analytics_release)
        from deployment.release_consumer import ZotReadCredential, ForgejoReadCredential, OCI_MEDIA_TYPE
        from deployment.tests.test_release_consumer import Factory, Response
        from deployment.tests.test_analytics_signed_release_consumer import (
            synthetic_successor, archive, SyntheticBlobSignatureVerifier,
            SyntheticSuccessorOCISignatureVerifier)
        manifest = canonical_bytes({'schemaVersion': 2, 'mediaType': OCI_MEDIA_TYPE,
            'config': {}, 'layers': []})
        digest = 'sha256:' + hashlib.sha256(manifest).hexdigest()
        selected, _, evidence, _, _ = synthetic_successor(digest_override=digest)
        self.assertEqual(selected, self.selected)
        zot = SimpleNamespace(zot_read_credential=lambda:
            ZotReadCredential('SYNTHETIC.TEST.ONLY', 1700000100))
        forgejo = SimpleNamespace(forgejo_read_credential=lambda:
            ForgejoReadCredential('SYNTHETIC.TEST.ONLY', 1700000100))
        with patch.object(owner, '_bounded_file', side_effect=AssertionError('no files')):
            result = acquire_and_review_owner_approved_analytics_release(
                zot, forgejo, SyntheticBlobSignatureVerifier(),
                SyntheticSuccessorOCISignatureVerifier(digest),
                received_at=1700000000, approval_file=None, signature_file=None,
                owner_source_proof=self.proof,
                forgejo_factory=Factory(Response(archive(evidence), 'application/octet-stream')),
                zot_factory=Factory(Response(manifest, OCI_MEDIA_TYPE,
                    extra=[('Docker-Content-Digest', digest)])))
        self.assertEqual(result.source.source_commit, self.selected.source_commit)
        self.assertEqual(result.image.rsplit('@', 1)[1], digest)
        self.assertFalse(result.deployment_authorized)

    def test_uid991_signed_review_reverifies_same_proof_and_binds_request(self):
        from deployment.tests.test_analytics_signed_binding_diagnostics import SignedBindingDiagnosticTests
        case = SignedBindingDiagnosticTests()
        case.setUp()
        try:
            case.raw = canonical_bytes(self.data)
            parsed = parse_analytics_successor_request(case.raw, **self.context)
            case.parser.return_value = parsed
            with patch('deployment.analytics_executor._verify_executor_owner_source',
                    wraps=_verify_executor_owner_source), patch.object(owner,
                    '_bounded_file', side_effect=AssertionError('no root file fallback')):
                self.assertEqual(case.review(), parsed)
                self.assertEqual(case.signed.call_args.kwargs['owner_source_proof'], self.proof)
                case.signed.reset_mock()
                case.raw = canonical_bytes({**self.data, 'owner_source_proof': '{}'})
                from deployment.executor import ExecutorUnavailableError
                with self.assertRaises(ExecutorUnavailableError):
                    case.review()
                case.signed.assert_not_called()
        finally:
            case.doCleanups()

