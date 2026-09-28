"""C32H/C32S pure broker authority tests; all hashes here are synthetic."""

from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields
import inspect
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import socket
import subprocess
import unittest
from unittest.mock import patch

from deployment import blob_verifier as bv
from deployment import broker_service_config as config
from deployment.application_source_set import DevApplicationSourceSet
from deployment.installation_contract import DevHostInstallationContract
from deployment.execution import INGRESS_PATHS, RuntimeConfigurationReference, IngressReference
from deployment.executor_service_config import DevExecutorServiceConfiguration
from deployment.tests.test_executor_service_config import configuration_values as executor_values
from deployment.identity import authorize_verified_github_oidc, OIDCAuthorizationError
from deployment.tests.test_identity import valid_claims, NOW


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = {
    'schema_version', 'stage', 'broker_uid', 'broker_gid', 'executor_uid',
    'executor_gid', 'replay_group_gid', 'socket_group_gid', 'expected_workflow_sha',
    'cosign_version', 'cosign_binary_sha256', 'sigstore_trusted_root_sha256',
    'reviewed_commit', 'runtime_configuration_sha256', 'ingress_file_sha256',
}


def configuration_values(**updates):
    value = dict(
        schema_version=2, stage='dev', broker_uid=1001, broker_gid=1002,
        executor_uid=2001, executor_gid=2002, replay_group_gid=2003,
        socket_group_gid=2004, expected_workflow_sha='c' * 40,
        cosign_version='3.1.2', cosign_binary_sha256='a' * 64,
        sigstore_trusted_root_sha256='b' * 64,
        reviewed_commit='d' * 40, runtime_configuration_sha256='e' * 64,
        ingress_file_sha256=('1' * 64, '2' * 64, '3' * 64),
    )
    value.update(updates)
    return value


class ConfigurationTests(unittest.TestCase):
    def reject(self, value):
        if type(value) is dict and type(value.get('ingress_file_sha256')) is tuple:
            value = value | {'ingress_file_sha256': dict(zip(
                INGRESS_PATHS, value['ingress_file_sha256'], strict=False))}
        with self.assertRaises(config.BrokerServiceConfigurationError) as caught:
            config.DevBrokerServiceConfiguration.from_dict(value)
        self.assertEqual(str(caught.exception), 'DEV broker authority configuration is invalid')

    def test_canonical_valid_and_round_trip(self):
        value = configuration_values()
        instance = config.DevBrokerServiceConfiguration(**value)
        expected = (json.dumps(instance.to_dict(), sort_keys=True, separators=(',', ':'),
                               ensure_ascii=True) + '\n').encode('ascii')
        self.assertEqual(instance.canonical_bytes(), expected)
        self.assertEqual(config.parse_canonical_broker_service_configuration(expected), instance)
        self.assertEqual(instance.to_dict()['ingress_file_sha256'], dict(zip(
            INGRESS_PATHS, value['ingress_file_sha256'], strict=True)))
        self.assertEqual(set(instance.to_dict()), SCHEMA)
        self.assertEqual({item.name for item in fields(instance) if item.init}, SCHEMA)

    def test_exact_schema_and_stage(self):
        for key, values in {'schema_version': [True, 0, 1, 3, 2.0, '2'],
                            'stage': ['DEV', 'staging', '', None, ['dev']]}.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.reject(configuration_values(**{key: value}))

    def test_all_identities_exact_bounded_builtins(self):
        for key in ('broker_uid', 'broker_gid', 'executor_uid', 'executor_gid',
                    'replay_group_gid', 'socket_group_gid'):
            for value in (True, -1, 0, 2**32 - 1, 1.0, '1001', None, {}):
                with self.subTest(key=key, value=value):
                    self.reject(configuration_values(**{key: value}))

    def test_identity_contract_and_unchanged_memberships(self):
        instance = config.DevBrokerServiceConfiguration(**configuration_values())
        installation = instance.installation_contract()
        self.assertIs(type(installation), DevHostInstallationContract)
        self.assertEqual(installation.broker_required_group_gids, (2003, 2004))
        self.assertEqual(installation.executor_required_group_gids, (2003,))
        self.assertNotIn(instance.executor_gid, installation.broker_required_group_gids)
        self.assertNotIn(instance.broker_gid, installation.executor_required_group_gids)
        self.assertEqual(installation.broker_composition_kwargs(), {
            'expected_replay_directory_uid': 0, 'expected_replay_directory_gid': 2003,
            'expected_broker_uid': 1001, 'expected_executor_uid': 2001,
            'expected_executor_gid': 2002, 'expected_socket_group_gid': 2004,
        })

    def test_uid_separation_and_all_group_aliases_rejected(self):
        self.reject(configuration_values(executor_uid=1001))
        gids = ('broker_gid', 'executor_gid', 'replay_group_gid', 'socket_group_gid')
        for left, right in itertools.combinations(gids, 2):
            with self.subTest(left=left, right=right):
                self.reject(configuration_values(**{left: configuration_values()[right]}))

    def test_exact_workflow_sha_authority(self):
        sha = '0123456789abcdef0123456789abcdef01234567'
        instance = config.DevBrokerServiceConfiguration(**configuration_values(expected_workflow_sha=sha))
        self.assertEqual(dict(instance.oidc_authorization_kwargs()), {'expected_workflow_sha': sha})

    def test_invalid_workflow_sha(self):
        for value in (None, True, 123, '', '0' * 40, 'A' * 40, 'a' * 39,
                      'a' * 41, 'refs/heads/main', 'a' * 40 + '\n', ' ' + 'a' * 40):
            with self.subTest(value=value):
                self.reject(configuration_values(expected_workflow_sha=value))

    def test_source_revision_has_no_automatic_workflow_authority(self):
        instance = config.DevBrokerServiceConfiguration(**configuration_values())
        source_sha = 'a' * 40
        # A valid release revision cannot replace the root-selected workflow revision.
        identity_claims = valid_claims()
        identity_claims['workflow_sha'] = source_sha
        with self.assertRaises(OIDCAuthorizationError):
            authorize_verified_github_oidc(identity_claims, received_at=NOW,
                                          **instance.oidc_authorization_kwargs())
        identity_claims['workflow_sha'] = instance.expected_workflow_sha
        self.assertEqual(authorize_verified_github_oidc(
            identity_claims, received_at=NOW, **instance.oidc_authorization_kwargs(),
        ).workflow_sha, instance.expected_workflow_sha)
        self.reject(configuration_values(source_sha=source_sha))
        self.assertEqual(instance.reviewed_commit, 'd' * 40)
        self.assertNotEqual(instance.reviewed_commit, instance.expected_workflow_sha)

    def test_exact_cosign_version(self):
        for value in ('3.1.1', '3.1.3', 'v3.1.2', 'latest', '', None, True, 3.12):
            with self.subTest(value=value):
                self.reject(configuration_values(cosign_version=value))

    def test_both_hash_authorities_fail_closed(self):
        for key in ('cosign_binary_sha256', 'sigstore_trusted_root_sha256'):
            for value in (None, '', '0' * 64, 'A' * 64, 'a' * 63, 'a' * 65,
                          'sha256:' + 'a' * 64, True, [], {}, 'a' * 64 + '\n'):
                with self.subTest(key=key, value=value):
                    self.reject(configuration_values(**{key: value}))

    def test_reviewed_revision_and_release_hashes_are_exact(self):
        class String(str):
            pass
        class Tuple(tuple):
            pass
        for value in (None, True, 'A' * 40, 'a' * 39, 'a' * 41, '0' * 40,
                      'refs/heads/main', String('a' * 40)):
            with self.subTest(commit=value):
                self.reject(configuration_values(reviewed_commit=value))
        for value in (None, True, 'A' * 64, 'a' * 63, 'a' * 65,
                      '0' * 64, String('a' * 64)):
            with self.subTest(runtime_digest=value):
                self.reject(configuration_values(runtime_configuration_sha256=value))
        for value in ([], ['1' * 64] * 3, ('1' * 64,), ('1' * 64,) * 4,
                      ('0' * 64, '2' * 64, '3' * 64),
                      ('A' * 64, '2' * 64, '3' * 64),
                      (String('1' * 64), '2' * 64, '3' * 64),
                      Tuple(('1' * 64, '2' * 64, '3' * 64))):
            with self.subTest(ingress=value):
                with self.assertRaises(config.BrokerServiceConfigurationError):
                    config.DevBrokerServiceConfiguration(**configuration_values(
                        ingress_file_sha256=value))

    def test_ingress_json_keys_are_closed(self):
        base = config.DevBrokerServiceConfiguration(**configuration_values()).to_dict()
        for mapping in ({}, {'arbitrary/path': 'a' * 64},
                        base['ingress_file_sha256'] | {'fourth/path': 'a' * 64},
                        dict(list(base['ingress_file_sha256'].items())[:-1])):
            with self.subTest(mapping=mapping):
                self.reject(base | {'ingress_file_sha256': mapping})
        class Dictionary(dict):
            pass
        self.reject(base | {'ingress_file_sha256': Dictionary(base['ingress_file_sha256'])})

    def test_closed_release_reference_projection(self):
        instance = config.DevBrokerServiceConfiguration(**configuration_values())
        runtime, ingress = instance.release_references()
        self.assertIs(type(runtime), RuntimeConfigurationReference)
        self.assertIs(type(ingress), IngressReference)
        self.assertEqual(runtime, RuntimeConfigurationReference.from_dict(runtime.__dict__))
        self.assertEqual(runtime.reviewed_commit, instance.reviewed_commit)
        self.assertEqual(runtime.sha256, instance.runtime_configuration_sha256)
        self.assertEqual(runtime.path, 'deployment/runtime/dev/canary-runtime.json')
        self.assertEqual(tuple(item.path for item in ingress.files), INGRESS_PATHS)
        self.assertEqual(tuple(item.sha256 for item in ingress.files), instance.ingress_file_sha256)
        self.assertEqual(ingress.reviewed_commit, instance.reviewed_commit)
        self.assertEqual((ingress.loopback_address, ingress.loopback_port,
                          ingress.public_origin),
                         ('127.0.0.1', 3020, 'https://canary-dev.omnilyzer.ai'))

    def test_broker_executor_pair_alignment_is_explicit(self):
        broker = config.DevBrokerServiceConfiguration(**configuration_values())
        identities = ('broker_uid', 'broker_gid', 'executor_uid', 'executor_gid',
                      'replay_group_gid', 'socket_group_gid')
        authority = (*identities, 'reviewed_commit', 'runtime_configuration_sha256',
                     'ingress_file_sha256')
        paired = DevExecutorServiceConfiguration(**executor_values(**{
            key: getattr(broker, key) for key in authority
        }))
        self.assertTrue(all(getattr(broker, key) == getattr(paired, key)
                            for key in authority))
        for key in authority:
            if key == 'ingress_file_sha256':
                for index in range(3):
                    changed = list(paired.ingress_file_sha256)
                    changed[index] = 'f' * 64
                    other = DevExecutorServiceConfiguration(**executor_values(**{
                        **{name: getattr(paired, name) for name in authority},
                        key: tuple(changed),
                    }))
                    self.assertNotEqual(getattr(broker, key), getattr(other, key))
                continue
            replacement = (9999 if key in identities else
                           'f' * 40 if key == 'reviewed_commit' else 'f' * 64)
            other = DevExecutorServiceConfiguration(**executor_values(**{
                **{name: getattr(paired, name) for name in authority}, key: replacement,
            }))
            self.assertNotEqual(getattr(broker, key), getattr(other, key))

    def test_missing_and_unknown_fields(self):
        for key in SCHEMA:
            value = configuration_values()
            del value[key]
            with self.subTest(missing=key):
                self.reject(value)
        for key in ('path', 'url', 'command', 'service', 'token', 'password',
                    'private_key', 'cookies', 'registry_credentials', 'git_ref'):
            with self.subTest(unknown=key):
                self.reject(configuration_values(**{key: 'untrusted'}))

    def test_exact_types_reject_subclasses(self):
        class String(str):
            pass
        class Integer(int):
            pass
        class Dictionary(dict):
            pass
        class Bytes(bytes):
            pass
        self.reject(Dictionary(configuration_values()))
        for key, value in configuration_values().items():
            replacement = (String(value) if type(value) is str else
                           Integer(value) if type(value) is int else list(value))
            with self.subTest(key=key):
                self.reject(configuration_values(**{key: replacement}))
        value = configuration_values()
        value[String('stage')] = value.pop('stage')
        self.reject(value)
        with self.assertRaises(config.BrokerServiceConfigurationError):
            config.parse_canonical_broker_service_configuration(Bytes(b'{}\n'))

    def test_immutable_configuration_installation_and_projections(self):
        instance = config.DevBrokerServiceConfiguration(**configuration_values())
        for name in (*SCHEMA, '_installation'):
            with self.subTest(name=name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(instance, name, None)
                with self.assertRaises(FrozenInstanceError):
                    delattr(instance, name)
        installation = instance.installation_contract()
        with self.assertRaises(FrozenInstanceError):
            installation.broker_gid = 2002
        with self.assertRaises(FrozenInstanceError):
            del installation.broker_gid
        for projection in (instance.oidc_authorization_kwargs(), instance.blob_verifier_kwargs()):
            key = next(iter(projection))
            with self.assertRaises(TypeError):
                projection[key] = None
            with self.assertRaises(TypeError):
                del projection[key]
        value = instance.to_dict()
        value['broker_gid'] = 2002
        self.assertEqual(instance.broker_gid, 1002)

    def test_narrow_blob_projection_and_inert_verifier_construction(self):
        instance = config.DevBrokerServiceConfiguration(**configuration_values())
        expected = dict(expected_cosign_version='3.1.2', expected_binary_sha256='a' * 64,
                        expected_trusted_root_sha256='b' * 64, broker_uid=1001, broker_gid=1002)
        self.assertEqual(dict(instance.blob_verifier_kwargs()), expected)
        with patch.object(os, 'open', side_effect=AssertionError('host access')):
            verifier = bv.CosignReleaseBlobVerifier(**instance.blob_verifier_kwargs())
        self.assertEqual(verifier._broker, (1001, 1002))
        self.assertEqual(verifier._authority[1], config.PRODUCTION_SIGSTORE_TRUSTED_ROOT_PATH)


class ParserTests(unittest.TestCase):
    def reject_raw(self, raw):
        with self.assertRaises(config.BrokerServiceConfigurationError):
            config.parse_canonical_broker_service_configuration(raw)

    def test_duplicate_json_fields_rejected(self):
        raw = config.DevBrokerServiceConfiguration(**configuration_values()).canonical_bytes()
        for key in SCHEMA:
            extra = json.dumps(key).encode() + b':' + json.dumps(config.DevBrokerServiceConfiguration(
                **configuration_values()).to_dict()[key]).encode() + b','
            with self.subTest(key=key):
                self.reject_raw(b'{' + extra + raw[1:])

    def test_noncanonical_bytes_rejected(self):
        raw = config.DevBrokerServiceConfiguration(**configuration_values()).canonical_bytes()
        for value in (raw[:-1], raw + b'\n', b' ' + raw, raw.replace(b':', b': ', 1),
                      json.dumps(config.DevBrokerServiceConfiguration(**configuration_values()).to_dict()).encode() + b'\n',
                      raw.replace(b'dev', b'\\u0064ev'), b'\xff', bytearray(raw), '', None):
            with self.subTest(value=type(value).__name__):
                self.reject_raw(value)

    def test_oversized_and_empty_configuration(self):
        self.assertEqual(config.MAX_BROKER_SERVICE_CONFIG_BYTES, 4096)
        for value in (b'', b' ' * 4097, b'{"stage":"' + b'x' * 4096 + b'"}\n'):
            self.reject_raw(value)

    def test_nonfinite_and_nested_data_rejected(self):
        for value in (b'NaN', b'Infinity', b'-Infinity', b'{}', b'[]', b'[[[1]]]', b'1e999'):
            raw = config.DevBrokerServiceConfiguration(**configuration_values()).canonical_bytes()
            self.reject_raw(raw.replace(b'"dev"', value))
        self.reject_raw(b'[' * 2000 + b']' * 2000)


class SeparationTests(unittest.TestCase):
    def test_fixed_paths_outside_executor_boundary(self):
        executor_directory = PurePosixPath('/etc/omnilyzer/deployment/dev')
        self.assertEqual(config.PRODUCTION_BROKER_SERVICE_CONFIG_PATH,
                         '/etc/omnilyzer/deployment/broker/dev.json')
        self.assertEqual(bv.TRUSTED_ROOT_PATH,
                         '/etc/omnilyzer/deployment/broker/sigstore-trusted-root.json')
        self.assertEqual(bv.TRUSTED_ROOT_PATH, config.PRODUCTION_SIGSTORE_TRUSTED_ROOT_PATH)
        for path in (config.PRODUCTION_BROKER_SERVICE_CONFIG_PATH, bv.TRUSTED_ROOT_PATH):
            self.assertFalse(PurePosixPath(path).is_relative_to(executor_directory))
        self.assertEqual(bv.COSIGN_PATH, '/opt/omnilyzer/deployment/tools/cosign-v3.1.2-linux-amd64')
        self.assertEqual(config.BROKER_SERVICE_CONFIG_DIRECTORY_MODE, 0o750)
        self.assertEqual(config.BROKER_SERVICE_CONFIG_FILE_MODE, 0o640)
        parameters = inspect.signature(config.DevBrokerServiceConfiguration).parameters
        self.assertEqual(set(parameters), SCHEMA)

    def test_import_construction_and_parsing_are_inert(self):
        code = compile(Path(config.__file__).read_text(), config.__file__, 'exec')
        namespace = {'__name__': config.__name__, '__package__': 'deployment'}
        with ExitStack() as stack:
            for name in ('open', 'stat', 'mkdir', 'chmod', 'chown', 'getuid', 'getgroups', 'getenv'):
                stack.enter_context(patch.object(os, name, side_effect=AssertionError(name)))
            stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('process')))
            stack.enter_context(patch.object(socket, 'socket', side_effect=AssertionError('socket')))
            exec(code, namespace)
            instance = namespace['DevBrokerServiceConfiguration'](**configuration_values())
            parsed = namespace['parse_canonical_broker_service_configuration'](instance.canonical_bytes())
            self.assertEqual(parsed, instance)

    def test_source_set_history_and_non_activation_unchanged(self):
        from deployment import application_manifest as c26
        from deployment import dev_post_c31_application_update as c32d
        paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(paths), 31)
        self.assertEqual((len(c26._predecessor_paths()), len(c26._paths())), (28, 31))
        self.assertEqual(c32d.PREDECESSOR, '3ef02a6d61d20df3a1495b290c20807162b65b06')
        self.assertEqual(c32d.TARGET, 'c04e66008cff556315603a9de59dacb4679787d4')
        for path in ('deployment/blob_verifier.py', 'deployment/broker_service_config.py',
                     'deployment/broker_service_config_loader.py'):
            self.assertNotIn(path, paths)
        self.assertIs(json.loads((ROOT / 'deployment/environments/dev.json').read_text())
                      ['activation']['deployment_enabled'], False)
        workflow = (ROOT / '.github/workflows/platform-promote.yml').read_text()
        self.assertNotIn('id-token: write', workflow)
        self.assertNotIn('environment: task014-dev', workflow)


if __name__ == '__main__':
    unittest.main()
