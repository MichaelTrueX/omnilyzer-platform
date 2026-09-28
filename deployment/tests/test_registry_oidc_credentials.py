"""C32O signed synthetic registry JWTs; no GitHub, registry or host I/O."""

import ast
from dataclasses import asdict
import inspect
import json
from pathlib import Path
import pickle
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from deployment import identity, oidc_verifier, registry_oidc_credentials as registry
from deployment.broker import IDENTITY_FIELDS
from deployment.jwks import OIDCVerificationError, OIDCVerificationUnavailable
from deployment.oci_verifier import CosignOCISignatureVerifier
from deployment.release_consumer import (
    ForgejoReadCredential, ZotCandidateConsumer, ZotReadCredential,
)
from deployment.tests.test_identity import NOW, WORKFLOW_SHA, valid_claims
from deployment.tests.test_oidc_verifier import b64url, manual_token, private_pem

ROOT = Path(__file__).resolve().parents[2]
ERROR = "DEV registry credential verification is unavailable or invalid"
ZOT_AUDIENCE = "https://oci-dev.omnilyzer.ai"
FORGEJO_AUDIENCE = "u:2:316bec9a-53e4-4807-9557-7febdc979d0a"


class StaticCache:
    def __init__(self, key):
        self.key, self.kids = key, []

    def get_key(self, kid):
        self.kids.append(kid)
        if kid != 'key-1':
            raise OIDCVerificationError('unreviewed key')
        return self.key


class RegistryCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.cache = StaticCache(self.key.public_key())
        self.deployment = oidc_verifier.GitHubOIDCVerifier(
            expected_workflow_sha=WORKFLOW_SHA, jwks_cache=self.cache,
        ).verify(self.token(valid_claims()), received_at=NOW)
        self.cache.kids.clear()
        self.verifier = registry.GitHubRegistryCredentialVerifier(
            expected_workflow_sha=WORKFLOW_SHA, jwks_cache=self.cache,
        )

    def token(self, claims, *, key=None, headers=None, algorithm='RS256'):
        return jwt.encode(claims, private_pem(key or self.key), algorithm=algorithm,
                          headers={'kid': 'key-1', 'typ': 'JWT'} | (headers or {}))

    def claims(self, audience, *, jti='registry-jti-1', iat=NOW - 10,
               nbf=NOW - 15, exp=NOW + 290):
        return valid_claims() | {'aud': audience, 'jti': jti,
                                 'iat': iat, 'nbf': nbf, 'exp': exp}

    def pair(self, *, zot=None, forgejo=None):
        return (self.token(self.claims(ZOT_AUDIENCE)) if zot is None else zot,
                self.token(self.claims(FORGEJO_AUDIENCE, jti='registry-jti-2',
                                       iat=NOW - 5, nbf=NOW - 8, exp=NOW + 200))
                if forgejo is None else forgejo)

    def verify(self, *, zot=None, forgejo=None, deployment=None, received_at=NOW):
        zot_token, forgejo_token = self.pair(zot=zot, forgejo=forgejo)
        return self.verifier.verify(
            self.deployment if deployment is None else deployment,
            zot_token=zot_token, forgejo_token=forgejo_token, received_at=received_at,
        )

    def reject(self, *, zot=None, forgejo=None, deployment=None, received_at=NOW):
        tokens = self.pair(zot=zot, forgejo=forgejo)
        with self.assertRaises(registry.RegistryCredentialVerificationError) as caught:
            self.verifier.verify(self.deployment if deployment is None else deployment,
                                 zot_token=tokens[0], forgejo_token=tokens[1],
                                 received_at=received_at)
        self.assertEqual(str(caught.exception), ERROR)
        self.assertIsNone(caught.exception.__cause__)
        for token in tokens:
            if token:
                self.assertNotIn(token, str(caught.exception))

    def test_exact_audience_authorities_match_reviewed_release_configuration(self):
        release = json.loads((ROOT / 'release/environments/dev.json').read_text())
        self.assertEqual(identity.DEV_AUDIENCE, 'https://deploy-dev.omnilyzer.ai/task014-dev')
        self.assertEqual(identity.DEV_ZOT_READ_AUDIENCE, ZOT_AUDIENCE)
        self.assertEqual(identity.DEV_FORGEJO_READ_AUDIENCE, FORGEJO_AUDIENCE)
        self.assertEqual(release['zot_oidc_audience'], ZOT_AUDIENCE)
        self.assertEqual(release['forgejo_oidc_audience'], FORGEJO_AUDIENCE)
        self.assertEqual({p.audience for p in (identity.DEV_AUTHORIZATION_POLICY,
            identity._ZOT_AUTHORIZATION_POLICY, identity._FORGEJO_AUTHORIZATION_POLICY)},
            {identity.DEV_AUDIENCE, ZOT_AUDIENCE, FORGEJO_AUDIENCE})

    def test_success_independent_jti_and_timestamps_and_signed_expiry(self):
        zot, forgejo = self.pair()
        value = self.verifier.verify(self.deployment, zot_token=zot,
                                     forgejo_token=forgejo, received_at=NOW)
        self.assertIs(type(value), registry.VerifiedRegistryCredentials)
        self.assertEqual(value.zot_read_credential(), ZotReadCredential(zot, NOW + 290))
        self.assertEqual(value.forgejo_read_credential(), ForgejoReadCredential(forgejo, NOW + 200))
        self.assertEqual(self.cache.kids, ['key-1', 'key-1'])
        self.assertNotEqual(self.deployment.jti, self.claims(ZOT_AUDIENCE)['jti'])
        self.assertNotEqual(self.claims(ZOT_AUDIENCE)['jti'],
                            self.claims(FORGEJO_AUDIENCE, jti='registry-jti-2')['jti'])

    def test_deployment_verifier_remains_closed_no_audience_override(self):
        self.assertEqual(tuple(inspect.signature(oidc_verifier.GitHubOIDCVerifier).parameters),
                         ('expected_workflow_sha', 'jwks_cache'))
        self.assertEqual(tuple(inspect.signature(oidc_verifier.GitHubOIDCVerifier.verify).parameters),
                         ('self', 'compact_token', 'received_at'))
        with self.assertRaises(TypeError):
            oidc_verifier.GitHubOIDCVerifier(expected_workflow_sha=WORKFLOW_SHA,
                                             audience=ZOT_AUDIENCE)
        with self.assertRaises(TypeError):
            oidc_verifier.GitHubOIDCVerifier(expected_workflow_sha=WORKFLOW_SHA,
                                             jwks_cache=self.cache).verify(
                self.token(self.claims(ZOT_AUDIENCE)), received_at=NOW,
                audience=ZOT_AUDIENCE,
            )
        for aud in (ZOT_AUDIENCE, FORGEJO_AUDIENCE, [identity.DEV_AUDIENCE]):
            with self.subTest(aud=aud), self.assertRaises(OIDCVerificationError):
                oidc_verifier.GitHubOIDCVerifier(expected_workflow_sha=WORKFLOW_SHA,
                    jwks_cache=self.cache).verify(self.token(self.claims(aud)), received_at=NOW)

    def test_registry_constructor_no_audience_and_no_tokens(self):
        self.assertEqual(tuple(inspect.signature(registry.GitHubRegistryCredentialVerifier).parameters),
                         ('expected_workflow_sha', 'jwks_cache'))
        self.assertEqual(tuple(inspect.signature(registry.GitHubRegistryCredentialVerifier.verify).parameters),
                         ('self', 'deployment_identity', 'zot_token', 'forgejo_token', 'received_at'))
        for name in ('audience', 'issuer', 'repository', 'workflow_ref', 'environment',
                     'zot_audience', 'forgejo_audience', 'token', 'expires_at'):
            with self.subTest(name=name), self.assertRaises(TypeError):
                registry.GitHubRegistryCredentialVerifier(expected_workflow_sha=WORKFLOW_SHA,
                    **{name: 'caller'})
        for authority in (None, True, '0'*40, WORKFLOW_SHA.upper(), WORKFLOW_SHA[:-1]):
            with self.subTest(authority=authority), self.assertRaises(registry.RegistryCredentialVerificationError):
                registry.GitHubRegistryCredentialVerifier(expected_workflow_sha=authority)
        self.assertFalse(hasattr(self.verifier, '__dict__'))
        for slot in registry.GitHubRegistryCredentialVerifier.__slots__:
            with self.assertRaises(AttributeError):
                setattr(self.verifier, slot, None)
            with self.assertRaises(AttributeError):
                delattr(self.verifier, slot)

    def test_audience_substitutions_and_arrays_rejected(self):
        deployment_token = self.token(valid_claims())
        zot, forgejo = self.pair()
        for name, token in (('zot', deployment_token), ('forgejo', deployment_token),
                            ('zot', forgejo), ('forgejo', zot)):
            with self.subTest(name=name):
                self.reject(**{name: token})
        for audience in ('https://other.invalid', ZOT_AUDIENCE + '/extra',
                         '', None, True, [ZOT_AUDIENCE],
                         [ZOT_AUDIENCE, FORGEJO_AUDIENCE]):
            with self.subTest(audience=audience):
                self.reject(zot=self.token(self.claims(audience)))
        for audience in ('another-forgejo', '', None, True, [FORGEJO_AUDIENCE],
                         [FORGEJO_AUDIENCE, ZOT_AUDIENCE]):
            with self.subTest(audience=audience):
                self.reject(forgejo=self.token(self.claims(audience)))

    def test_closed_policy_static_identity_claims_for_both_tokens(self):
        changes = {
            'iss': 'https://issuer.invalid',
            'repository': 'other/repository',
            'repository_id': '1350104357',
            'repository_owner_id': '130741174',
            'workflow_ref': identity.DEV_WORKFLOW_REF.replace('platform-promote', 'other-workflow'),
            'workflow_sha': 'f'*40,
            'ref': 'refs/heads/other',
            'environment': 'other-environment',
            'event_name': 'push',
            'runner_environment': 'self-hosted',
        }
        for name, value in changes.items():
            for side, audience in (('zot', ZOT_AUDIENCE), ('forgejo', FORGEJO_AUDIENCE)):
                with self.subTest(name=name, side=side):
                    self.reject(**{side: self.token(self.claims(audience) | {name: value})})

    def test_cross_run_attempt_actor_and_revision_bound_for_both(self):
        changes = {'run_id': '34150000001', 'run_attempt': '2', 'actor_id': '130741174',
                   'workflow_sha': 'f'*40,
                   'workflow_ref': identity.DEV_WORKFLOW_REF.replace('main', 'other'),
                   'environment': 'other-environment'}
        for name, value in changes.items():
            for side, audience in (('zot', ZOT_AUDIENCE), ('forgejo', FORGEJO_AUDIENCE)):
                with self.subTest(name=name, side=side):
                    self.reject(**{side: self.token(self.claims(audience) | {name: value})})
        self.assertEqual(set(registry._CROSS_BOUND_FIELDS), {
            'issuer', 'repository', 'repository_id', 'repository_owner_id', 'workflow_ref',
            'workflow_sha', 'ref', 'environment', 'event_name', 'runner_environment',
            'run_id', 'run_attempt', 'actor_id',
        })

    def test_normalizes_deployment_identity_and_rejects_forged_fields(self):
        from dataclasses import replace
        original = self.deployment
        class Subclass(identity.AuthorizedGitHubIdentity):
            pass
        self.reject(deployment=Subclass(**vars(original)))
        for field, value in (('run_id', original.run_id + 1),
                             ('run_attempt', original.run_attempt + 1),
                             ('actor_id', original.actor_id + 1),
                             ('audience', ZOT_AUDIENCE),
                             ('workflow_sha', 'f'*40),
                             ('repository_id', True),
                             ('issued_at', True)):
            with self.subTest(field=field):
                candidate = replace(original)
                object.__setattr__(candidate, field, value)
                self.reject(deployment=candidate)
        candidate = replace(original)
        candidate.__dict__['unknown'] = 'forged'
        self.reject(deployment=candidate)
        self.assertEqual(len(IDENTITY_FIELDS), len(vars(original)))

    def test_temporal_limits_and_signed_exp_for_both_tokens(self):
        cases = (
            {'iat': NOW - 10, 'exp': NOW + 291},  # 301-second lifetime
            {'iat': NOW - 61, 'nbf': NOW - 61, 'exp': NOW + 100},
            {'iat': NOW - 50, 'nbf': NOW - 60, 'exp': NOW - 31},
            {'iat': NOW - 50, 'nbf': NOW - 60, 'exp': NOW},
            {'iat': NOW + 31, 'nbf': NOW, 'exp': NOW + 100},
            {'iat': NOW - 10, 'nbf': NOW + 31, 'exp': NOW + 100},
            {'iat': True}, {'nbf': False}, {'exp': True},
            {'exp': NOW + 301},  # read credential expiry bound
        )
        for changes in cases:
            for side, audience in (('zot', ZOT_AUDIENCE), ('forgejo', FORGEJO_AUDIENCE)):
                with self.subTest(changes=changes, side=side):
                    self.reject(**{side: self.token(self.claims(audience) | changes)})
        for audience, side in ((ZOT_AUDIENCE, 'zot'), (FORGEJO_AUDIENCE, 'forgejo')):
            token = self.token(self.claims(audience, iat=NOW + 30, nbf=NOW + 30, exp=NOW + 300))
            value = self.verify(**{side: token})
            self.assertEqual(getattr(value, side + '_read_credential')().expires_at, NOW + 300)

    def test_malformed_id_jti_missing_claims_and_wrong_types(self):
        for name, bad in (('run_id', '0'), ('run_attempt', '01'), ('actor_id', 'actor'),
                          ('repository_id', True), ('jti', '../path')):
            self.reject(zot=self.token(self.claims(ZOT_AUDIENCE) | {name: bad}))
        for name in identity.REQUIRED_AUTHORIZATION_CLAIMS:
            claims = self.claims(FORGEJO_AUDIENCE)
            del claims[name]
            with self.subTest(name=name):
                self.reject(forgejo=self.token(claims))

    def test_real_signature_unknown_kid_and_wrong_algorithm_fail(self):
        token = self.token(self.claims(ZOT_AUDIENCE))
        pieces = token.split('.')
        # Both tampered claims and independently mutated signature must fail.
        pieces[1] = b64url(json.dumps(self.claims(ZOT_AUDIENCE) | {'run_id': '34150000001'},
                                       separators=(',', ':')).encode())
        self.reject(zot='.'.join(pieces))
        pieces = token.split('.')
        pieces[2] = pieces[2][:-1] + ('A' if pieces[2][-1] != 'A' else 'B')
        self.reject(zot='.'.join(pieces))
        self.reject(zot=self.token(self.claims(ZOT_AUDIENCE), key=self.other))
        self.reject(forgejo=self.token(self.claims(FORGEJO_AUDIENCE), key=self.other))
        self.reject(zot=self.token(self.claims(ZOT_AUDIENCE), headers={'kid': 'unknown'}))
        for value in ('../path', '', None):
            header = json.dumps({'alg': 'RS256', 'kid': value}, separators=(',', ':')).encode()
            self.reject(zot=manual_token(header, json.dumps(self.claims(ZOT_AUDIENCE)).encode(), self.key))
        for algorithm in ('PS256', 'HS256'):
            if algorithm == 'HS256':
                token = jwt.encode(self.claims(ZOT_AUDIENCE), b'synthetic-secret',
                                   algorithm='HS256', headers={'kid': 'key-1'})
            else:
                token = self.token(self.claims(ZOT_AUDIENCE), algorithm=algorithm)
            self.reject(zot=token)
        self.reject(zot=manual_token(b'{"alg":"none","kid":"key-1"}',
            json.dumps(self.claims(ZOT_AUDIENCE)).encode(), self.key))

    def test_compact_limits_duplicate_json_and_verified_claim_consistency(self):
        valid = self.token(self.claims(ZOT_AUDIENCE))
        for token in ('', 'one.two', 'one.two.three.four', valid + 'é',
                      'a'*(oidc_verifier.MAX_COMPACT_TOKEN_BYTES+1),
                      valid.replace('.', '=.', 1),
                      manual_token(b'{"alg":"RS256","alg":"RS256","kid":"key-1"}',
                          json.dumps(self.claims(ZOT_AUDIENCE)).encode(), self.key),
                      manual_token(b'{"alg":"RS256","kid":"key-1","jku":"https://invalid"}',
                          json.dumps(self.claims(ZOT_AUDIENCE)).encode(), self.key)):
            with self.subTest(token=token[:16]):
                self.reject(zot=token)
        self.reject(zot=self.token(self.claims(ZOT_AUDIENCE), headers={'extra': 'x'*2100}))
        self.reject(zot=self.token(self.claims(ZOT_AUDIENCE) | {'extra': 'x'*12000}))
        huge_signature = valid.rsplit('.', 1)[0] + '.' + b64url(b'x'*513)
        self.reject(zot=huge_signature)
        inconsistent = self.claims(ZOT_AUDIENCE) | {'run_id': '34150000001'}
        with patch('deployment.oidc_verifier.jwt.decode', return_value=inconsistent):
            self.reject(zot=valid)
        bounded = self.claims(ZOT_AUDIENCE) | {'extra': 1}
        with patch('deployment.oidc_verifier.jwt.decode', return_value=bounded | {'extra': True}):
            self.reject(zot=self.token(bounded))

    def test_jwks_unavailable_and_strict_pyjwt_options(self):
        with patch.object(self.cache, 'get_key', side_effect=OIDCVerificationUnavailable('secret key')):
            with self.assertRaises(registry.RegistryCredentialUnavailableError) as caught:
                self.verify()
            self.assertEqual(str(caught.exception), ERROR)
        for failure in (RuntimeError('secret infrastructure detail'),
                        TypeError('secret cache detail')):
            with patch.object(self.cache, 'get_key', side_effect=failure):
                with self.assertRaises(registry.RegistryCredentialUnavailableError) as caught:
                    self.verify()
                self.assertEqual(str(caught.exception), ERROR)
        with self.assertRaises(registry.RegistryCredentialRejectedError) as caught:
            self.verify(zot=self.token(self.claims(FORGEJO_AUDIENCE)))
        self.assertEqual(str(caught.exception), ERROR)
        with patch('deployment.oidc_verifier.jwt.decode', wraps=jwt.decode) as decode:
            self.verify()
        self.assertEqual([call.kwargs['audience'] for call in decode.call_args_list],
                         [ZOT_AUDIENCE, FORGEJO_AUDIENCE])
        for call in decode.call_args_list:
            self.assertEqual(call.kwargs['algorithms'], ['RS256'])
            self.assertEqual(call.kwargs['issuer'], identity.DEV_ISSUER)
            for key in ('verify_signature', 'verify_iss', 'verify_aud', 'strict_aud'):
                self.assertIs(call.kwargs['options'][key], True)
            for key in ('verify_exp', 'verify_iat', 'verify_nbf'):
                self.assertIs(call.kwargs['options'][key], False)

    def test_secret_container_immutable_redacted_and_unserializable(self):
        value = self.verify()
        zot, forgejo = value.zot_read_credential(), value.forgejo_read_credential()
        self.assertIs(type(zot), ZotReadCredential)
        self.assertIs(type(forgejo), ForgejoReadCredential)
        self.assertEqual(value.zot_read_credential(), zot)
        self.assertEqual(value.zot_read_credential(), zot)
        self.assertEqual(value.forgejo_read_credential(), forgejo)
        self.assertFalse(hasattr(value, '__dict__'))
        for text in (repr(value), repr(zot), repr(forgejo), str(value)):
            self.assertNotIn(zot.token, text)
            self.assertNotIn(forgejo.token, text)
        for slot in registry.VerifiedRegistryCredentials.__slots__:
            with self.assertRaises(AttributeError):
                setattr(value, slot, None)
            with self.assertRaises(AttributeError):
                delattr(value, slot)
        with self.assertRaises(TypeError):
            registry.VerifiedRegistryCredentials()
        for operation in (lambda: vars(value), lambda: json.dumps(value),
                          lambda: pickle.dumps(value), lambda: asdict(value)):
            with self.assertRaises(TypeError):
                operation()
        for name in ('to_dict', 'canonical_bytes', 'to_json', 'audit_projection',
                     'executor_request', 'jti'):
            self.assertFalse(hasattr(value, name))

    def test_result_provides_both_scopes_and_zot_twice(self):
        value = self.verify()
        self.assertEqual(value.zot_read_credential(), value.zot_read_credential())
        self.assertIs(type(value.zot_read_credential()), ZotReadCredential)
        self.assertIs(type(value.forgejo_read_credential()), ForgejoReadCredential)
        # Constructor-only uses: no network, no Cosign execution.
        from deployment.tests.test_blob_verifier import AUTHORITY
        ZotCandidateConsumer(value)
        CosignOCISignatureVerifier(**AUTHORITY, zot_credential_provider=value)

    def test_no_runtime_release_import_handler_workflow_or_activation(self):
        sources = [ROOT / 'deployment' / name for name in
                   ('registry_oidc_credentials.py', 'identity.py', 'oidc_verifier.py')]
        for path in sources:
            source = path.read_text()
            tree = ast.parse(source)
            self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module
                and (node.module == 'release' or node.module.startswith('release.'))
                for node in ast.walk(tree)))
        text = sources[0].read_text()
        for forbidden in ('InertDevPromotionHandler', 'consume(', 'subprocess',
                          'systemctl', 'docker login', 'audit.record', 'time.time('):
            self.assertNotIn(forbidden, text)
        self.assertNotIn('id-token: write',
            (ROOT / '.github/workflows/platform-promote.yml').read_text())
        self.assertIs(json.loads((ROOT / 'deployment/environments/dev.json').read_text())
                      ['activation']['deployment_enabled'], False)
        from deployment.application_source_set import DevApplicationSourceSet
        from deployment import application_manifest, dev_post_c31_application_update as update
        paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(paths), 41)
        self.assertIn('deployment/registry_oidc_credentials.py', paths)
        self.assertEqual((len(application_manifest._predecessor_paths()),
                          len(application_manifest._paths())), (28, 31))
        self.assertEqual(update.PREDECESSOR, '3ef02a6d61d20df3a1495b290c20807162b65b06')
        self.assertEqual(update.TARGET, 'c04e66008cff556315603a9de59dacb4679787d4')


if __name__ == '__main__':
    unittest.main()
