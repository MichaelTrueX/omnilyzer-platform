"""Deterministic C32I authority identity and exact retained-evidence tests."""

import ast
import base64
import builtins
from contextlib import ExitStack
import copy
from dataclasses import fields, FrozenInstanceError
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch
import urllib.request

from deployment import sigstore_authority_provenance as provenance
from deployment import sigstore_authority_review as review
from deployment import blob_verifier, broker_service_config
from deployment import application_manifest, dev_post_c31_application_update
from deployment.application_source_set import DevApplicationSourceSet
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.tests.test_broker_service_config import configuration_values

ROOT = Path(__file__).resolve().parents[2]
BINARY_SHA = 'f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf'
ROOT_SHA = '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66'
BUNDLE_SHA = 'fdaa1c168d67041cd0d8f5782f8136ac5d148827b6911ba8bb577cbc7e13de2c'
ROOT_BLOB = 'effb0a19e6a0b3f69b3f0a2c72b5c2a02a0ddeea'
TARGETS_BLOB = '5ad0d090f7f08da0031a10ef57c0de21a25b3244'


def retained_bytes():
    value = provenance.DevSigstoreVerificationProvenance()
    return {
        'trusted_root': (ROOT / value.trusted_root.retained_target_path).read_bytes(),
        'targets_metadata': (ROOT / value.trusted_root.retained_metadata_path).read_bytes(),
        'checksums': (ROOT / value.cosign.retained_checksums_path).read_bytes(),
        'binary_bundle': (ROOT / value.cosign.retained_bundle_path).read_bytes(),
        'checksums_bundle': (ROOT / value.cosign.retained_checksums_bundle_path).read_bytes(),
    }


def forged(value):
    replacement = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(replacement, field.name, getattr(value, field.name))
    return replacement


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.value = provenance.DevSigstoreVerificationProvenance()

    def test_zero_input_models_and_closed_public_surface(self):
        self.assertEqual(provenance.__all__, (
            'CosignReleaseProvenance', 'SigstoreTrustedRootProvenance',
            'DevSigstoreVerificationProvenance',
        ))
        for kind in (provenance.CosignReleaseProvenance,
                     provenance.SigstoreTrustedRootProvenance,
                     provenance.DevSigstoreVerificationProvenance):
            self.assertEqual(tuple(inspect.signature(kind).parameters), ())
            self.assertTrue(kind.__dataclass_params__.frozen)
            self.assertEqual(kind.__slots__, tuple(field.name for field in fields(kind)))
            for field in fields(kind):
                with self.subTest(kind=kind.__name__, field=field.name), self.assertRaises(TypeError):
                    kind(**{field.name: 'unreviewed'})

    def test_models_and_nested_authorities_are_immutable(self):
        for value in (self.value, self.value.cosign, self.value.trusted_root):
            self.assertFalse(hasattr(value, '__dict__'))
            for field in fields(value):
                with self.subTest(kind=type(value).__name__, field=field.name):
                    with self.assertRaises(FrozenInstanceError):
                        setattr(value, field.name, None)
                    with self.assertRaises(FrozenInstanceError):
                        delattr(value, field.name)

    def test_exact_cosign_upstream_release_identity(self):
        value = self.value.cosign
        self.assertEqual((value.repository, value.version, value.release_tag, value.release_id),
                         ('sigstore/cosign', '3.1.2', 'v3.1.2', 355751884))
        self.assertEqual(value.tag_object_sha, 'dc80df70da727f4abdd843640594025584a270ae')
        self.assertEqual(value.source_commit_sha, '193d2153431f8bb0d945a4c1ee721872f73add67')
        self.assertEqual(value.tag_verification, 'GitHub verified: valid')
        self.assertEqual((value.platform, value.architecture), ('linux', 'amd64'))
        self.assertEqual((value.asset_name, value.asset_id, value.asset_size, value.asset_sha256),
                         ('cosign-linux-amd64', 480496709, 141150460, BINARY_SHA))

    def test_exact_cosign_bundle_and_checksums_identities(self):
        value = self.value.cosign
        self.assertEqual((value.bundle_name, value.bundle_id, value.bundle_size, value.bundle_sha256),
                         ('cosign-linux-amd64.sigstore.json', 480498776, 6433, BUNDLE_SHA))
        self.assertEqual((value.checksums_name, value.checksums_id, value.checksums_size,
                          value.checksums_sha256),
                         ('cosign_checksums.txt', 480498558, 3906,
                          '3ef5d389c3f508b96025fd1b92744a305c46e95951c91242b57467567d5622db'))
        self.assertEqual((value.checksums_bundle_name, value.checksums_bundle_id,
                          value.checksums_bundle_size, value.checksums_bundle_sha256),
                         ('cosign_checksums.txt.sigstore.json', 480498856, 6578,
                          'be73ee422be126a70190ee24bf88a1b078cde1f954f076ddf9c0901de4136362'))

    def test_exact_trusted_root_upstream_identity(self):
        value = self.value.trusted_root
        self.assertEqual(value.repository, 'sigstore/root-signing')
        self.assertEqual(value.reviewed_commit, '829e81ca3db59ce8e8393f942795061b5fc0be30')
        self.assertEqual((value.target_path, value.target_name),
                         ('targets/trusted_root.json', 'trusted_root.json'))
        self.assertEqual((value.target_git_blob_sha, value.target_size, value.target_sha256),
                         (ROOT_BLOB, 6787, ROOT_SHA))
        self.assertEqual((value.metadata_path, value.metadata_git_blob_sha, value.metadata_size),
                         ('metadata/targets.json', TARGETS_BLOB, 4942))
        self.assertEqual(value.metadata_sha256,
                         '6a697f7f8908c8ab26c11786ecb490b54acec97fa8c802e399f065f8a0cc1acd')
        self.assertEqual((value.targets_role_version, value.metadata_expiration),
                         (14, '2036-05-09T09:00:52Z'))
        self.assertEqual(value.media_type, 'application/vnd.dev.sigstore.trustedroot+json;version=0.1')

    def test_every_replaced_or_malformed_authority_field_fails_revalidation(self):
        class Text(str):
            pass
        class Integer(int):
            pass
        for value in (self.value.cosign, self.value.trusted_root):
            for field in fields(value):
                original = getattr(value, field.name)
                attacks = (None, True, '', 'latest', '0' * 64,
                           Text(original) if type(original) is str else Integer(original))
                for attack in attacks:
                    replacement = forged(value)
                    object.__setattr__(replacement, field.name, attack)
                    with self.subTest(field=field.name, attack=type(attack).__name__), \
                         self.assertRaisesRegex((TypeError, ValueError), 'provenance is invalid'):
                        replacement.__post_init__()

    def test_aggregate_rejects_forged_nested_authority_and_projection(self):
        for field in ('cosign', 'trusted_root'):
            replacement = forged(self.value)
            nested = forged(getattr(replacement, field))
            object.__setattr__(nested, 'repository', 'unreviewed/repository')
            object.__setattr__(replacement, field, nested)
            with self.assertRaises(ValueError):
                replacement.__post_init__()
            with self.assertRaises(ValueError):
                replacement.broker_service_configuration_kwargs()
            object.__setattr__(replacement, field, object())
            with self.assertRaises(TypeError):
                replacement.__post_init__()
        with self.assertRaises(TypeError):
            object.__new__(provenance.DevSigstoreVerificationProvenance).__post_init__()
        with self.assertRaises(TypeError):
            object.__new__(provenance.CosignReleaseProvenance).__post_init__()
        with self.assertRaises(TypeError):
            object.__new__(provenance.SigstoreTrustedRootProvenance).__post_init__()

    def test_narrow_immutable_c32h_authority_projection(self):
        projection = self.value.broker_service_configuration_kwargs()
        self.assertEqual(dict(projection), {
            'cosign_version': '3.1.2', 'cosign_binary_sha256': BINARY_SHA,
            'sigstore_trusted_root_sha256': ROOT_SHA,
        })
        self.assertNotIn('expected_workflow_sha', projection)
        with self.assertRaises(TypeError):
            projection['cosign_version'] = 'latest'
        with self.assertRaises(TypeError):
            del projection['cosign_version']
        value = DevBrokerServiceConfiguration(**(configuration_values() | dict(projection)))
        self.assertEqual(value.expected_workflow_sha, configuration_values()['expected_workflow_sha'])
        self.assertEqual(value.blob_verifier_kwargs()['expected_binary_sha256'], BINARY_SHA)

    def test_import_construction_and_projection_have_zero_io(self):
        code = compile(Path(provenance.__file__).read_text(), provenance.__file__, 'exec')
        namespace = {'__name__': provenance.__name__, '__package__': 'deployment'}
        with ExitStack() as stack:
            for owner, name in ((builtins, 'open'), (os, 'open'), (os, 'stat'),
                                (socket, 'socket'), (subprocess, 'Popen'),
                                (urllib.request, 'urlopen'), (hashlib, 'sha256')):
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
            exec(code, namespace)
            value = namespace['DevSigstoreVerificationProvenance']()
            self.assertEqual(value.broker_service_configuration_kwargs()['cosign_version'], '3.1.2')


class RetainedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.raw = retained_bytes()
        self.authority = provenance.DevSigstoreVerificationProvenance()

    def test_all_retained_sizes_and_digests_match_reviewed_upstream(self):
        c, r = self.authority.cosign, self.authority.trusted_root
        expected = {
            'trusted_root': (6787, ROOT_SHA), 'targets_metadata': (4942, r.metadata_sha256),
            'checksums': (3906, c.checksums_sha256), 'binary_bundle': (6433, BUNDLE_SHA),
            'checksums_bundle': (6578, c.checksums_bundle_sha256),
        }
        for name, raw in self.raw.items():
            with self.subTest(name=name):
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), expected[name])
                self.assertLess(len(raw), 8192)

    def test_git_blob_ids_remain_externally_reviewed_provenance(self):
        root = review.review_retained_sigstore_authority(**self.raw).trusted_root
        self.assertEqual(root.target_git_blob_sha, ROOT_BLOB)
        self.assertEqual(root.metadata_git_blob_sha, TARGETS_BLOB)

    def test_content_integrity_boundary_receives_only_size_and_sha256(self):
        self.assertEqual(tuple(inspect.signature(review._exact_bytes).parameters),
                         ('raw', 'size', 'sha256'))
        c, r = self.authority.cosign, self.authority.trusted_root
        with patch.object(review, '_exact_bytes', wraps=review._exact_bytes) as validate:
            self.assertEqual(review.review_retained_sigstore_authority(**self.raw), self.authority)
        self.assertEqual([item.args for item in validate.call_args_list], [
            (self.raw['trusted_root'], r.target_size, r.target_sha256),
            (self.raw['targets_metadata'], r.metadata_size, r.metadata_sha256),
            (self.raw['checksums'], c.checksums_size, c.checksums_sha256),
            (self.raw['binary_bundle'], c.bundle_size, c.bundle_sha256),
            (self.raw['checksums_bundle'], c.checksums_bundle_size, c.checksums_bundle_sha256),
        ])
        operations = {node.attr for node in ast.walk(ast.parse(inspect.getsource(review)))
                      if isinstance(node, ast.Attribute)}
        self.assertTrue(operations.isdisjoint({'target_git_blob_sha', 'metadata_git_blob_sha'}))

    def test_signed_targets_record_matches_retained_target_bytes(self):
        value = json.loads(self.raw['targets_metadata'])
        self.assertEqual(set(value), {'signed', 'signatures'})
        self.assertEqual(len(value['signatures']), 5)
        signed = value['signed']
        self.assertEqual(signed['_type'], 'targets')
        self.assertEqual((signed['version'], signed['expires']), (14, '2036-05-09T09:00:52Z'))
        self.assertEqual(signed['targets']['trusted_root.json'], {
            'length': len(self.raw['trusted_root']),
            'hashes': {'sha256': hashlib.sha256(self.raw['trusted_root']).hexdigest()},
        })

    def test_public_sigstore_trusted_root_media_type_and_services(self):
        value = json.loads(self.raw['trusted_root'])
        self.assertEqual(value['mediaType'], 'application/vnd.dev.sigstore.trustedroot+json;version=0.1')
        self.assertEqual({item['baseUrl'] for item in value['tlogs']},
                         {'https://rekor.sigstore.dev', 'https://log2025-1.rekor.sigstore.dev'})
        self.assertEqual({item['baseUrl'] for item in value['ctlogs']},
                         {'https://ctfe.sigstore.dev/test', 'https://ctfe.sigstore.dev/2022'})
        self.assertEqual({item['uri'] for item in value['certificateAuthorities']},
                         {'https://fulcio.sigstore.dev'})
        self.assertEqual({item['uri'] for item in value['timestampAuthorities']},
                         {'https://timestamp.sigstore.dev/api/v1/timestamp'})
        review._review_trusted_root(value)

    def test_checksums_and_bundles_bind_exact_subject_digests(self):
        selected = [line.split() for line in self.raw['checksums'].decode().splitlines()
                    if line.endswith('  cosign-linux-amd64')]
        self.assertEqual(selected, [[BINARY_SHA, 'cosign-linux-amd64']])
        for name, digest in (('binary_bundle', BINARY_SHA),
                             ('checksums_bundle', self.authority.cosign.checksums_sha256)):
            value = json.loads(self.raw[name])
            self.assertEqual(value['mediaType'], 'application/vnd.dev.sigstore.bundle.v0.3+json')
            message = value['messageSignature']['messageDigest']
            self.assertEqual(message['algorithm'], 'SHA2_256')
            self.assertEqual(base64.b64decode(message['digest']).hex(), digest)

    def test_retained_bytes_accepted_without_io(self):
        with ExitStack() as stack:
            for owner, name in ((builtins, 'open'), (os, 'open'), (os, 'stat'),
                                (socket, 'socket'), (subprocess, 'Popen'), (urllib.request, 'urlopen')):
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
            reviewed = review.review_retained_sigstore_authority(**self.raw)
        self.assertEqual(reviewed, self.authority)

    def test_any_replaced_truncated_or_oversized_retained_bytes_fail_closed(self):
        class Bytes(bytes):
            pass
        for name, raw in self.raw.items():
            for attack in (b'', raw[:-1], raw + b' ', b'x' + raw[1:], Bytes(raw),
                           bytearray(raw), raw.decode(), b'x' * 8193, None):
                with self.subTest(name=name, kind=type(attack).__name__), \
                     self.assertRaisesRegex(review.SigstoreAuthorityReviewError,
                                            'retained Sigstore verification authority evidence is invalid'):
                    review.review_retained_sigstore_authority(**(self.raw | {name: attack}))

    def test_no_reserialization_is_accepted(self):
        for name in ('trusted_root', 'targets_metadata', 'binary_bundle', 'checksums_bundle'):
            raw = self.raw[name]
            rewritten = (json.dumps(json.loads(raw), sort_keys=True, separators=(',', ':')) + '\n').encode()
            self.assertNotEqual(rewritten, raw)
            with self.subTest(name=name), self.assertRaises(review.SigstoreAuthorityReviewError):
                review.review_retained_sigstore_authority(**(self.raw | {name: rewritten}))

    def test_review_has_only_exact_bytes_inputs(self):
        parameters = inspect.signature(review.review_retained_sigstore_authority).parameters
        self.assertEqual(set(parameters), set(self.raw))
        self.assertTrue(all(item.kind == inspect.Parameter.KEYWORD_ONLY for item in parameters.values()))
        self.assertTrue(all(item.default is inspect.Parameter.empty for item in parameters.values()))
        with self.assertRaises(TypeError):
            review.review_retained_sigstore_authority(path='/tmp/untrusted')

    def test_private_json_parser_rejects_duplicate_nonfinite_and_unbounded_data(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}',
                    b'{"a":1e999}', b'[]', b' ' * 8193,
                    b'{"a":' + b'[' * 15 + b'0' + b']' * 15 + b'}',
                    b'{"a":"' + b'x' * 4097 + b'"}',
                    b'{"a":[' + b','.join([b'0'] * 33) + b']}'):
            with self.subTest(size=len(raw)), self.assertRaises(Exception):
                review._json(raw)

    def test_private_root_schema_rejects_bad_media_services_and_keys(self):
        valid = json.loads(self.raw['trusted_root'])
        attacks = []
        for key in valid:
            changed = copy.deepcopy(valid)
            del changed[key]
            attacks.append(changed)
        changed = copy.deepcopy(valid)
        changed['unexpected'] = True
        attacks.append(changed)
        for field, value in (('mediaType', 'application/json'), ('tlogs', []),
                             ('ctlogs', []), ('certificateAuthorities', []),
                             ('timestampAuthorities', [])):
            changed = copy.deepcopy(valid)
            changed[field] = value
            attacks.append(changed)
        for field, value in (('baseUrl', 'https://unreviewed.invalid'),
                             ('hashAlgorithm', 'SHA2_512')):
            changed = copy.deepcopy(valid)
            changed['tlogs'][0][field] = value
            attacks.append(changed)
        for field, value in (('rawBytes', 'invalid'), ('rawBytes', 'MA=='),
                             ('rawBytes', 'MAIA'), ('keyDetails', 'PKIX_RSA_PKCS1V15_2048_SHA256'),
                             ('validFor', {'start': '2021-02-30T00:00:00Z'})):
            changed = copy.deepcopy(valid)
            changed['tlogs'][0]['publicKey'][field] = value
            attacks.append(changed)
        changed = copy.deepcopy(valid)
        changed['tlogs'][1] = copy.deepcopy(changed['tlogs'][0])
        attacks.append(changed)
        changed = copy.deepcopy(valid)
        changed['certificateAuthorities'][1]['certChain']['certificates'] = []
        attacks.append(changed)
        for changed in attacks:
            with self.subTest(changed_keys=tuple(changed)), self.assertRaises((ValueError, TypeError)):
                review._review_trusted_root(changed)

    def test_structural_review_does_not_depend_on_array_order(self):
        value = json.loads(self.raw['trusted_root'])
        for key in ('tlogs', 'ctlogs', 'certificateAuthorities', 'timestampAuthorities'):
            value[key].reverse()
        review._review_trusted_root(value)

    def test_targets_role_version_expiration_length_and_digest_fail_closed(self):
        valid = json.loads(self.raw['targets_metadata'])
        for key, attack in (('_type', 'root'), ('version', True), ('version', 15),
                           ('expires', '2037-05-09T09:00:52Z')):
            changed = copy.deepcopy(valid)
            changed['signed'][key] = attack
            with self.subTest(field=key), self.assertRaises(ValueError):
                review._review_targets(changed, self.raw['trusted_root'], self.authority.trusted_root)
        for key, attack in (('length', True), ('length', 6788), ('hashes', {'sha256': '0' * 64})):
            changed = copy.deepcopy(valid)
            changed['signed']['targets']['trusted_root.json'][key] = attack
            with self.subTest(field=key), self.assertRaises(ValueError):
                review._review_targets(changed, self.raw['trusted_root'], self.authority.trusted_root)

    def test_cleanup_control_flow_and_generic_error_convention(self):
        for exception in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with patch.object(review, '_json', side_effect=exception), self.assertRaises(exception):
                review.review_retained_sigstore_authority(**self.raw)
        with patch.object(review, '_json', side_effect=ValueError('sensitive diagnostic marker')):
            with self.assertRaises(review.SigstoreAuthorityReviewError) as caught:
                review.review_retained_sigstore_authority(**self.raw)
        self.assertEqual(str(caught.exception), 'retained Sigstore verification authority evidence is invalid')


class SeparationTests(unittest.TestCase):
    def test_c32i_python_has_no_sha1_hashing_operation(self):
        # Scoped to C32I; legacy Git handling elsewhere is outside this contract.
        for path in (Path(provenance.__file__), Path(review.__file__), Path(__file__)):
            tree = ast.parse(path.read_text())
            with self.subTest(path=path.name):
                for node in ast.walk(tree):
                    if isinstance(node, ast.Attribute):
                        self.assertNotEqual(node.attr.lower(), 'sha1')
                    elif isinstance(node, ast.Name):
                        self.assertNotEqual(node.id.lower(), 'sha1')
                    elif isinstance(node, (ast.Import, ast.ImportFrom)):
                        for alias in node.names:
                            self.assertNotEqual(alias.name.lower().split('.')[-1], 'sha1')
                    elif (isinstance(node, ast.Call)
                          and ((isinstance(node.func, ast.Attribute) and node.func.attr == 'new')
                               or (isinstance(node.func, ast.Name) and node.func.id in {'new', 'getattr'}))):
                        # Reject algorithm selection through hashlib.new/getattr too.
                        for argument in (*node.args, *(item.value for item in node.keywords)):
                            if isinstance(argument, ast.Constant) and type(argument.value) is str:
                                self.assertNotEqual(argument.value.lower().replace('-', ''), 'sha1')

    def test_no_network_ambient_updates_mutation_or_credentials(self):
        for module in (provenance, review):
            source = Path(module.__file__).read_text()
            tree = ast.parse(source)
            imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
            imports |= {item.name for node in ast.walk(tree) if isinstance(node, ast.Import) for item in node.names}
            self.assertTrue(imports.isdisjoint({'os', 'pathlib', 'socket', 'subprocess', 'urllib', 'http', 'shutil'}))
            operations = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
            self.assertTrue(operations.isdisjoint({'open', 'read_bytes', 'write', 'mkdir', 'unlink',
                                                 'chmod', 'chown', 'replace', 'run', 'Popen', 'getenv', 'environ'}))
            for forbidden in ('TUF_MIRROR', 'TUF_ROOT', 'TUF_ROOT_JSON', 'cosign initialize',
                              'refs/heads/main', 'expected_workflow_sha', 'bearer', 'password',
                              'PRIVATE KEY', 'cookies', 'session_token'):
                self.assertNotIn(forbidden, source)

    def test_review_module_import_is_inert(self):
        code = compile(Path(review.__file__).read_text(), review.__file__, 'exec')
        namespace = {'__name__': review.__name__, '__package__': 'deployment'}
        with ExitStack() as stack:
            for owner, name in ((builtins, 'open'), (os, 'open'), (os, 'stat'),
                                (socket, 'socket'), (subprocess, 'Popen'),
                                (urllib.request, 'urlopen')):
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError(name)))
            exec(code, namespace)
        self.assertIn('review_retained_sigstore_authority', namespace)

    def test_retained_evidence_contains_only_public_trust_material(self):
        raw = retained_bytes()
        for name, content in raw.items():
            with self.subTest(name=name):
                for marker in (b'PRIVATE KEY', b'Bearer ', b'Authorization:',
                               b'password', b'session_token', b'registry_credentials'):
                    self.assertNotIn(marker, content)
                if name != 'checksums':
                    self.assertIs(type(json.loads(content)), dict)

    def test_source_set_and_c32d_remain_closed(self):
        paths = {item.repository_path for item in DevApplicationSourceSet().files}
        self.assertEqual(len(paths), 41)
        self.assertEqual((len(application_manifest._predecessor_paths()), len(application_manifest._paths())), (28, 31))
        self.assertEqual(dev_post_c31_application_update.PREDECESSOR, '3ef02a6d61d20df3a1495b290c20807162b65b06')
        self.assertEqual(dev_post_c31_application_update.TARGET, 'c04e66008cff556315603a9de59dacb4679787d4')
        self.assertNotIn('deployment/sigstore_authority_provenance.py', paths)
        self.assertNotIn('deployment/sigstore_authority_review.py', paths)
        self.assertFalse(any(name.startswith('deployment/provenance/') for name in paths))
        self.assertFalse(any(name.endswith('/cosign-linux-amd64') for name in paths))

    def test_runtime_trusted_root_bound_and_reviewed_binary_size_authority(self):
        self.assertEqual(blob_verifier.TRUSTED_ROOT_PATH,
                         '/etc/omnilyzer/deployment/broker/sigstore-trusted-root.json')
        self.assertEqual(blob_verifier.MAX_ROOT_BYTES, 1024 * 1024)
        self.assertIs(type(broker_service_config.COSIGN_BINARY_SIZE), int)
        self.assertEqual(blob_verifier.COSIGN_BINARY_SIZE, broker_service_config.COSIGN_BINARY_SIZE)
        self.assertEqual(blob_verifier.COSIGN_BINARY_SIZE,
                         provenance.DevSigstoreVerificationProvenance().cosign.asset_size)
        self.assertFalse(hasattr(blob_verifier, 'MAX_BINARY_BYTES'))

    def test_no_environment_activation(self):
        self.assertIs(json.loads((ROOT / 'deployment/environments/dev.json').read_bytes())
                      ['activation']['deployment_enabled'], False)


if __name__ == '__main__':
    unittest.main()
