"""C32L pure future authority; no real installation or artifact execution."""

from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from deployment import broker_service_config as config
from deployment import sigstore_resource_contract as contract
from deployment import blob_verifier as verifier
from deployment.application_source_set import DevApplicationSourceSet
from deployment.installation_contract import HostResourceRequirement
from deployment.sigstore_authority_provenance import DevSigstoreVerificationProvenance
from deployment.tests.test_broker_service_config import configuration_values, SCHEMA

ROOT = Path(__file__).resolve().parents[2]


def configuration():
    return config.DevBrokerServiceConfiguration(**configuration_values(
        **DevSigstoreVerificationProvenance().broker_service_configuration_kwargs(),
    ))


class ResourceContractTests(unittest.TestCase):
    def model(self):
        return contract.DevSigstoreResourceContract(configuration=configuration())

    def test_closed_constructor_and_immutable_capture(self):
        original = configuration()
        model = contract.DevSigstoreResourceContract(configuration=original)
        self.assertIsNot(model.configuration, original)
        self.assertEqual(model.configuration, original)
        self.assertEqual(tuple(inspect.signature(type(model)).parameters), ('configuration',))
        for value in (model, model.configuration, *model.directory_requirements(),
                      *model.file_requirements(), *(item.resource for item in model.file_requirements())):
            for item in fields(value):
                with self.subTest(model=type(value).__name__, field=item.name):
                    with self.assertRaises(FrozenInstanceError):
                        setattr(value, item.name, None)
                    with self.assertRaises(FrozenInstanceError):
                        delattr(value, item.name)
        for name in ('path', 'mode', 'broker_gid', 'size', 'sha256', 'installation'):
            with self.subTest(name=name), self.assertRaises(TypeError):
                contract.DevSigstoreResourceContract(configuration=original, **{name: None})

    def test_exact_directories(self):
        tools, root = self.model().directory_requirements()
        self.assertEqual(tools, HostResourceRequirement(
            '/opt/omnilyzer/deployment/tools', 'directory', 0o750, 0, 1002,
            'must-exist-before-activation'))
        self.assertEqual(root, HostResourceRequirement(
            '/etc/omnilyzer/deployment/broker', 'directory', 0o750, 0, 1002,
            'must-exist-before-activation'))
        self.assertEqual(tools.path, config.COSIGN_TOOLS_DIRECTORY)
        self.assertEqual(tools.mode, config.COSIGN_TOOLS_DIRECTORY_MODE)
        self.assertEqual(root.path, config.BROKER_SERVICE_CONFIG_DIRECTORY)

    def test_exact_cosign(self):
        binary = self.model().file_requirements()[0]
        self.assertEqual(binary.resource, HostResourceRequirement(
            '/opt/omnilyzer/deployment/tools/cosign-v3.1.2-linux-amd64',
            'regular_file', 0o540, 0, 1002, 'must-exist-before-activation'))
        self.assertEqual(binary.size, 141150460)
        self.assertEqual(binary.sha256, 'f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf')
        self.assertEqual(binary.nlink, 1)
        self.assertEqual(binary.resource.path, verifier.COSIGN_PATH)
        self.assertEqual(binary.resource.mode, verifier.COSIGN_BINARY_MODE)
        self.assertEqual(binary.size, verifier.COSIGN_BINARY_SIZE)

    def test_exact_trusted_root(self):
        root = self.model().file_requirements()[1]
        self.assertEqual(root.resource, HostResourceRequirement(
            '/etc/omnilyzer/deployment/broker/sigstore-trusted-root.json',
            'regular_file', 0o640, 0, 1002, 'must-exist-before-activation'))
        self.assertEqual(root.size, 6787)
        self.assertEqual(root.sha256, '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66')
        self.assertEqual(root.nlink, 1)
        self.assertEqual(root.resource.path, verifier.TRUSTED_ROOT_PATH)
        self.assertEqual(root.resource.mode, verifier.BROKER_SERVICE_CONFIG_FILE_MODE)

    def test_artifact_authorities_and_retained_root_agree(self):
        provenance = DevSigstoreVerificationProvenance()
        binary, root = self.model().file_requirements()
        self.assertEqual((binary.size, binary.sha256),
                         (provenance.cosign.asset_size, provenance.cosign.asset_sha256))
        self.assertEqual((root.size, root.sha256),
                         (provenance.trusted_root.target_size, provenance.trusted_root.target_sha256))
        import hashlib
        raw = (ROOT / provenance.trusted_root.retained_target_path).read_bytes()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (root.size, root.sha256))

    def test_identity_relationships_and_schema_unchanged(self):
        model = self.model()
        identity = model.configuration.installation_contract()
        self.assertEqual(identity.broker_required_group_gids, (2003, 2004))
        self.assertEqual(identity.executor_required_group_gids, (2003,))
        self.assertNotIn(identity.executor_gid, identity.broker_required_group_gids)
        self.assertNotIn(identity.broker_gid, identity.executor_required_group_gids)
        self.assertEqual({item.group_gid for item in model.directory_requirements()}, {identity.broker_gid})
        self.assertEqual({item.resource.group_gid for item in model.file_requirements()}, {identity.broker_gid})
        self.assertEqual(set(model.configuration.to_dict()), SCHEMA)
        self.assertEqual(model.configuration.schema_version, 2)

    def test_rejects_wrong_configuration_or_subclass(self):
        class Configuration(config.DevBrokerServiceConfiguration):
            pass
        for value in (None, {}, configuration().installation_contract(),
                      Configuration(**configuration_values(
                          **DevSigstoreVerificationProvenance().broker_service_configuration_kwargs()))):
            with self.subTest(value=type(value)), self.assertRaisesRegex(ValueError, '^DEV Sigstore static resource contract is invalid$'):
                contract.DevSigstoreResourceContract(configuration=value)

    def test_rejects_unreviewed_config_digests(self):
        for field in ('cosign_binary_sha256', 'sigstore_trusted_root_sha256'):
            value = replace(configuration(), **{field: 'a' * 64})
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.DevSigstoreResourceContract(configuration=value)

    def test_rejects_forged_configuration_and_cached_identity(self):
        for name, bad in (('broker_gid', True), ('executor_uid', 1001),
                          ('cosign_version', 'latest'), ('expected_workflow_sha', '0' * 40)):
            value = configuration()
            object.__setattr__(value, name, bad)
            with self.subTest(name=name), self.assertRaises(ValueError):
                contract.DevSigstoreResourceContract(configuration=value)
        for name, bad in (('broker_gid', 999), ('broker_required_group_gids', (2002,)),
                          ('executor_required_group_gids', (1002,)), ('_resources', ())):
            value = configuration()
            object.__setattr__(value.installation_contract(), name, bad)
            with self.subTest(name=name), self.assertRaises(ValueError):
                contract.DevSigstoreResourceContract(configuration=value)
        value = configuration()
        object.__setattr__(value, '_installation', {})
        with self.assertRaises(ValueError):
            contract.DevSigstoreResourceContract(configuration=value)

    def test_forged_directory_metadata_rejected_on_projection(self):
        for name, bad in (('path', '/unreviewed'), ('mode', 0o755), ('owner_uid', 1001),
                          ('group_gid', 2002), ('kind', 'regular_file'), ('lifecycle', 'may-be-created-on-first-audit-append')):
            for index in range(2):
                model = self.model()
                object.__setattr__(model._directories[index], name, bad)
                with self.subTest(name=name, index=index), self.assertRaises(ValueError):
                    model.directory_requirements()

    def test_forged_file_metadata_content_and_links_rejected(self):
        for index in range(2):
            for name, bad in (('path', '/unreviewed'), ('mode', 0o550), ('owner_uid', 1001),
                              ('group_gid', 2002), ('kind', 'directory'), ('owner_uid', False)):
                model = self.model()
                object.__setattr__(model._files[index].resource, name, bad)
                with self.subTest(index=index, name=name), self.assertRaises(ValueError):
                    model.file_requirements()
            for name, bad in (('size', 1), ('size', True), ('sha256', 'a' * 64),
                              ('sha256', '0' * 64), ('nlink', 2), ('nlink', True), ('resource', {})):
                model = self.model()
                object.__setattr__(model._files[index], name, bad)
                with self.subTest(index=index, name=name), self.assertRaises(ValueError):
                    model.file_requirements()
                with self.assertRaises(ValueError):
                    model._files[index].__post_init__()

    def test_file_and_directory_nested_subclasses_rejected(self):
        class Resource(HostResourceRequirement):
            pass
        class File(contract.SigstoreStaticFileRequirement):
            pass
        for name, value in (('_directories', []), ('_files', []), ('_files', ({},))):
            model = self.model()
            object.__setattr__(model, name, value)
            with self.subTest(name=name), self.assertRaises(ValueError):
                model.__post_init__()
        model = self.model()
        binary = model._files[0]
        nested = Resource(**{item.name: getattr(binary.resource, item.name) for item in fields(binary.resource)})
        with self.assertRaises(ValueError):
            contract.SigstoreStaticFileRequirement(nested, binary.size, binary.sha256)
        object.__setattr__(model, '_files', (File(binary.resource, binary.size, binary.sha256), model._files[1]))
        with self.assertRaises(ValueError):
            model.file_requirements()

    def test_exact_scalar_types_no_bool_or_subclasses(self):
        class Integer(int):
            pass
        class String(str):
            pass
        for index in range(2):
            for name in ('path', 'kind', 'mode', 'owner_uid', 'group_gid', 'lifecycle'):
                model = self.model()
                value = getattr(model._files[index].resource, name)
                object.__setattr__(model._files[index].resource, name,
                                   String(value) if type(value) is str else Integer(value))
                with self.subTest(index=index, name=name), self.assertRaises(ValueError):
                    model.file_requirements()
            for name in ('size', 'sha256', 'nlink'):
                model = self.model()
                value = getattr(model._files[index], name)
                object.__setattr__(model._files[index], name,
                                   String(value) if type(value) is str else Integer(value))
                with self.subTest(index=index, name=name), self.assertRaises(ValueError):
                    model.file_requirements()

    def test_import_construction_projection_zero_io(self):
        code = compile(Path(contract.__file__).read_text(), contract.__file__, 'exec')
        namespace = {'__name__': contract.__name__, '__package__': 'deployment'}
        value = configuration()
        with ExitStack() as stack:
            for name in ('open', 'stat', 'mkdir', 'chmod', 'chown', 'getuid', 'getegid', 'getenv'):
                stack.enter_context(patch.object(os, name, side_effect=AssertionError(name)))
            stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('process')))
            stack.enter_context(patch.object(socket, 'socket', side_effect=AssertionError('network')))
            exec(code, namespace)
            with patch.dict(os.environ, {'COSIGN_PATH': '/unreviewed', 'COSIGN_BINARY_MODE': '0755'}):
                model = namespace['DevSigstoreResourceContract'](configuration=value)
                self.assertEqual(model.directory_requirements()[0].path, config.COSIGN_TOOLS_DIRECTORY)
                self.assertEqual(model.file_requirements()[0].resource.mode, 0o540)

    def test_history_source_set_and_nonlive_policy(self):
        from deployment import application_manifest as manifest
        from deployment import dev_post_c31_application_update as history
        paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(paths), 41)
        self.assertNotIn('deployment/sigstore_resource_contract.py', paths)
        self.assertIn('deployment/blob_verifier.py', paths)
        self.assertEqual((len(manifest._predecessor_paths()), len(manifest._paths())), (28, 31))
        self.assertEqual(history.PREDECESSOR, '3ef02a6d61d20df3a1495b290c20807162b65b06')
        self.assertEqual(history.TARGET, 'c04e66008cff556315603a9de59dacb4679787d4')
        self.assertIs(json.loads((ROOT / 'deployment/environments/dev.json').read_text())['activation']['deployment_enabled'], False)
        workflow = (ROOT / '.github/workflows/platform-promote.yml').read_text()
        self.assertNotIn('id-token: write', workflow)
        self.assertNotIn('environment: task014-dev', workflow)


if __name__ == '__main__':
    unittest.main()
