"""C32U pure future broker host authority; no host mutation or live sockets."""

from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

import deployment.broker_host_service_contract as module
from deployment.application_source_set import DevApplicationSourceSet
from deployment.blob_verifier import RUNTIME_DIRECTORY as BLOB_RUNTIME_DIRECTORY
from deployment.broker_service_config import (
    BROKER_SERVICE_CONFIG_DIRECTORY, PRODUCTION_BROKER_SERVICE_CONFIG_PATH,
    DevBrokerServiceConfiguration,
)
from deployment.host_provisioning_contract import (
    DevHostProvisioningContract, HostInstalledAssetRequirement,
)
from deployment.installation_contract import HostResourceRequirement
from deployment.oci_verifier import _RUNTIME_DIRECTORY as OCI_RUNTIME_DIRECTORY
from deployment.replay_sqlite import PRODUCTION_REPLAY_DATABASE
from deployment.sigstore_resource_contract import DevSigstoreResourceContract
from deployment.tests.test_broker_service_config import configuration_values
from deployment.tests.test_sigstore_resource_contract import configuration
from deployment.unix_transport import PRODUCTION_EXECUTOR_SOCKET_PATH


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "deployment/systemd/dev/omnilyzer-deployment-broker.service"
SHA = "594c3038451ad867e80e1361bef81711814e7aec1a727f33e85de9fd590bf0c2"


def model():
    return module.DevBrokerHostServiceContract(configuration=configuration())


def unit():
    sections = {}
    current = None
    for line in SOURCE.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections[current] = {}
            continue
        key, separator, value = line.partition("=")
        if not separator or current is None:
            raise AssertionError("malformed reviewed broker unit")
        sections[current].setdefault(key, []).append(value)
    return sections


class ContractTests(unittest.TestCase):
    def test_exact_one_input_and_immutable_revalidated_configuration(self):
        original = configuration()
        contract = module.DevBrokerHostServiceContract(configuration=original)
        self.assertEqual(tuple(inspect.signature(type(contract)).parameters),
                         ("configuration",))
        self.assertIsNot(contract.configuration, original)
        self.assertEqual(contract.configuration, original)
        self.assertEqual(contract.configuration.schema_version, 2)
        for item in fields(contract):
            with self.assertRaises(FrozenInstanceError):
                setattr(contract, item.name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(contract, item.name)
        class Subclass(DevBrokerServiceConfiguration):
            pass
        for candidate in (None, {}, object(), Subclass(**configuration_values())):
            with self.subTest(candidate=type(candidate)), self.assertRaisesRegex(
                    ValueError, "^DEV broker host service contract is invalid$"):
                module.DevBrokerHostServiceContract(configuration=candidate)
        with self.assertRaises(TypeError):
            module.DevBrokerHostServiceContract(configuration=original, path="/tmp")

    def test_forged_identity_and_schema_are_rejected(self):
        forged = configuration()
        object.__setattr__(forged, "_installation", object())
        with self.assertRaises(ValueError):
            module.DevBrokerHostServiceContract(configuration=forged)
        forged = configuration()
        object.__setattr__(forged, "schema_version", 1)
        with self.assertRaises(ValueError):
            module.DevBrokerHostServiceContract(configuration=forged)
        contract = model()
        object.__setattr__(contract, "configuration", forged)
        with self.assertRaises(ValueError):
            contract.broker_configuration_file()

    def test_config_directory_file_and_canonical_content_source(self):
        contract = model()
        directory = contract.broker_configuration_directory()
        self.assertEqual(directory, HostResourceRequirement(
            "/etc/omnilyzer/deployment/broker", "directory", 0o750, 0, 1002,
            "must-exist-before-activation"))
        self.assertEqual(directory.path, BROKER_SERVICE_CONFIG_DIRECTORY)
        config_file = contract.broker_configuration_file()
        self.assertEqual(config_file, module.BrokerConfigurationFileRequirement(
            "/etc/omnilyzer/deployment/broker/dev.json", "regular_file", 0o640,
            0, 1002, 1,
            "must-contain-canonical-schema-2-broker-config-before-activation"))
        self.assertEqual(config_file.path, PRODUCTION_BROKER_SERVICE_CONFIG_PATH)
        self.assertEqual(contract.canonical_configuration_bytes(),
                         contract.configuration.canonical_bytes())
        self.assertNotIn(b"token", contract.canonical_configuration_bytes())
        for changes in ({"group_gid": True}, {"mode": 0o660}, {"nlink": 2},
                        {"path": "/tmp/dev.json"}, {"lifecycle": "unknown"}):
            values = dict(path=config_file.path, kind=config_file.kind,
                          mode=config_file.mode, owner_uid=config_file.owner_uid,
                          group_gid=config_file.group_gid, nlink=config_file.nlink,
                          lifecycle=config_file.lifecycle) | changes
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                module.BrokerConfigurationFileRequirement(**values)

    def test_sigstore_is_reused_with_shared_broker_directory(self):
        contract = model()
        sigstore = contract.sigstore_resources()
        self.assertIs(type(sigstore), DevSigstoreResourceContract)
        self.assertEqual(sigstore.directory_requirements()[1],
                         contract.broker_configuration_directory())
        binary, root = sigstore.file_requirements()
        self.assertEqual((binary.resource.path, binary.resource.mode, binary.size,
                          binary.sha256, binary.nlink),
                         ("/opt/omnilyzer/deployment/tools/cosign-v3.1.2-linux-amd64",
                          0o540, 141150460,
                          "f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf", 1))
        self.assertEqual((root.resource.path, root.resource.mode, root.size,
                          root.sha256, root.nlink),
                         ("/etc/omnilyzer/deployment/broker/sigstore-trusted-root.json",
                          0o640, 6787,
                          "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66", 1))
        self.assertEqual(root.resource.group_gid,
                         contract.broker_configuration_file().group_gid)

    def test_runtime_prerequisites_have_exact_ownership(self):
        resources = model().runtime_directory_requirements()
        self.assertEqual(tuple((item.path, item.mode, item.owner_uid, item.group_gid)
                               for item in resources), (
            ("/run/omnilyzer", 0o755, 0, 0),
            ("/run/omnilyzer/deployment", 0o755, 0, 0),
            ("/run/omnilyzer/deployment/dev", 0o755, 0, 0),
            ("/run/omnilyzer/deployment/dev/blob-verifier", 0o700, 1001, 1002),
            ("/run/omnilyzer/deployment/dev/oci-verifier", 0o700, 1001, 1002),
        ))
        self.assertEqual((resources[3].path, resources[4].path),
                         (BLOB_RUNTIME_DIRECTORY, OCI_RUNTIME_DIRECTORY))
        self.assertTrue(all(item.kind == "directory" and not item.mode & 0o022
                            for item in resources))

    def test_replay_and_socket_are_exact_c13_objects(self):
        contract = model()
        installation = contract.configuration.installation_contract()
        historical = installation.resource_requirements()
        replay = contract.replay_requirements()
        self.assertEqual(replay, historical[2:4])
        self.assertEqual(tuple((item.path, item.mode, item.owner_uid, item.group_gid)
                               for item in replay), (
            (str(PRODUCTION_REPLAY_DATABASE.parent), 0o2770, 0, 2003),
            (str(PRODUCTION_REPLAY_DATABASE), 0o660, 0, 2003),
        ))
        sock = contract.executor_socket_requirement()
        self.assertEqual(sock, historical[6])
        self.assertEqual(sock.path, PRODUCTION_EXECUTOR_SOCKET_PATH)
        self.assertEqual((sock.owner_uid, sock.group_gid, sock.mode), (2001, 2004, 0o660))
        self.assertEqual(installation.broker_required_group_gids, (2003, 2004))
        self.assertNotIn(installation.executor_gid, installation.broker_required_group_gids)
        self.assertNotIn(installation.broker_gid, installation.executor_required_group_gids)

    def test_broker_layout_unit_asset_and_writable_paths(self):
        contract = model()
        layout = contract.service_layout()
        self.assertEqual(contract.broker_principals(),
                         ("omnilyzer-broker", "omnilyzer-broker",
                          ("omnilyzer-replay", "omnilyzer-deployment")))
        self.assertEqual(contract.broker_exec_argv(),
                         (layout.python_executable, "-m",
                          "deployment.broker_service_entrypoint"))
        self.assertEqual(contract.broker_module(), "deployment.broker_service_entrypoint")
        self.assertEqual(contract.broker_service_unit_name(),
                         "omnilyzer-deployment-broker.service")
        self.assertEqual(contract.loopback_bind(), ("127.0.0.1", 3031))
        self.assertEqual(contract.address_families(), ("AF_UNIX", "AF_INET", "AF_INET6"))
        self.assertEqual(contract.writable_paths(), (
            "/var/lib/omnilyzer/deployment/authority",
            "/run/omnilyzer/deployment/dev/blob-verifier",
            "/run/omnilyzer/deployment/dev/oci-verifier",
        ))
        asset = contract.installed_asset_requirement()
        self.assertIs(type(asset), HostInstalledAssetRequirement)
        self.assertEqual((asset.source_path, asset.destination_path, asset.sha256,
                          asset.mode, asset.owner_uid, asset.group_gid),
                         ("deployment/systemd/dev/omnilyzer-deployment-broker.service",
                          "/etc/systemd/system/omnilyzer-deployment-broker.service",
                          SHA, 0o644, 0, 0))
        self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(), asset.sha256)

    def test_import_and_construction_are_pure(self):
        source = Path(module.__file__).read_text()
        namespace = {"__name__": module.__name__, "__package__": "deployment"}
        with ExitStack() as stack:
            for name in ("open", "stat", "getuid", "getgid", "getenv"):
                stack.enter_context(patch.object(os, name,
                    side_effect=AssertionError("host I/O")))
            stack.enter_context(patch.object(socket, "socket",
                side_effect=AssertionError("socket")))
            stack.enter_context(patch.object(subprocess, "Popen",
                side_effect=AssertionError("process")))
            exec(compile(source, module.__file__, "exec"), namespace)
            namespace["DevBrokerHostServiceContract"](configuration=configuration())


class UnitTests(unittest.TestCase):
    def test_exact_unit_dependencies_identity_execution_and_hardening(self):
        parsed = unit()
        self.assertEqual(set(parsed), {"Unit", "Service"})
        units, service = parsed["Unit"], parsed["Service"]
        self.assertEqual(units["Description"], ["Omnilyzer DEV deployment broker"])
        self.assertEqual(units["Requires"], ["omnilyzer-deployment-executor.socket"])
        self.assertEqual(units["After"], ["omnilyzer-deployment-executor.socket",
                                          "network-online.target"])
        self.assertEqual(units["Wants"], ["network-online.target"])
        expected = {
            "Type": "exec", "User": "omnilyzer-broker", "Group": "omnilyzer-broker",
            "SupplementaryGroups": "omnilyzer-replay omnilyzer-deployment",
            "WorkingDirectory": "/opt/omnilyzer/deployment/app",
            "ExecStart": "/opt/omnilyzer/deployment/venv/bin/python -m deployment.broker_service_entrypoint",
            "Restart": "no", "UMask": "0077", "NoNewPrivileges": "yes",
            "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectHome": "yes",
            "ProtectSystem": "strict", "ProtectControlGroups": "yes",
            "ProtectKernelModules": "yes", "ProtectKernelTunables": "yes",
            "ProtectKernelLogs": "yes", "ProtectClock": "yes",
            "ProtectHostname": "yes", "LockPersonality": "yes",
            "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes",
            "RestrictNamespaces": "yes", "CapabilityBoundingSet": "",
            "AmbientCapabilities": "",
            "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
            "ReadWritePaths": " ".join(model().writable_paths()),
        }
        self.assertEqual(service, {key: [value] for key, value in expected.items()})
        self.assertNotIn("omnilyzer-executor", service["SupplementaryGroups"][0])
        self.assertNotIn("/opt/omnilyzer ", service["ReadWritePaths"][0])
        self.assertNotIn("/etc/omnilyzer", service["ReadWritePaths"][0])
        self.assertNotIn("PrivateNetwork", service)
        for name in ("DynamicUser", "Environment", "EnvironmentFile", "ExecStartPre",
                     "ExecStartPost", "ExecReload", "PermissionsStartOnly", "RootDirectory",
                     "BindPaths", "BindReadOnlyPaths", "RuntimeDirectory", "StateDirectory",
                     "CacheDirectory", "LogsDirectory", "IPAddressAllow", "IPAddressDeny",
                     "SocketBindAllow", "SocketBindDeny"):
            self.assertNotIn(name, service)

    def test_historical_executor_assets_and_nonlive_state(self):
        from deployment import application_manifest, dev_post_c31_application_update as c32d
        paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(paths), 41)
        self.assertNotIn("deployment/broker_host_service_contract.py", paths)
        self.assertNotIn("deployment/systemd/dev/omnilyzer-deployment-broker.service", paths)
        c23 = DevHostProvisioningContract(installation=configuration().installation_contract())
        self.assertEqual(tuple(x.sha256 for x in c23.installed_asset_requirements()), (
            "4211b0a4498548a54c4aedeaeb419aef84fb76d16f9da5f60a40b20be1daf95f",
            "a79a89ccd97c1de6b7038337ab1f7089c4dad501532e376a71a811854d1e8c86",
        ))
        for asset in c23.installed_asset_requirements():
            self.assertEqual(hashlib.sha256((ROOT / asset.source_path).read_bytes()).hexdigest(),
                             asset.sha256)
        self.assertEqual((len(application_manifest._predecessor_paths()),
                          len(application_manifest._paths())), (28, 31))
        self.assertEqual((c32d.PREDECESSOR, c32d.TARGET),
                         ("3ef02a6d61d20df3a1495b290c20807162b65b06",
                          "c04e66008cff556315603a9de59dacb4679787d4"))
        environment = json.loads((ROOT / "deployment/environments/dev.json").read_text())
        self.assertEqual(environment["runtime"], {
            "configuration_reference": None, "secrets_reference": None,
            "ingress_reference": None,
        })
        self.assertIs(environment["activation"]["deployment_enabled"], False)
        self.assertFalse((ROOT / "deployment/systemd/dev/omnilyzer-deployment-broker.socket").exists())
        self.assertNotIn("deployment/ingress/dev-broker-https.nginx.review.conf",
                         tuple(asset.source_path for asset in c23.installed_asset_requirements()))


if __name__ == "__main__":
    unittest.main()
