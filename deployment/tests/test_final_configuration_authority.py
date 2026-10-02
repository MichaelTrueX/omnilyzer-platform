"""C32X pure final executor/broker configuration alignment tests."""

from dataclasses import FrozenInstanceError, replace
from contextlib import ExitStack
import builtins
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

from deployment import application_manifest as manifest
from deployment import dev_post_c31_application_update as historical
from deployment import final_application_generation as frozen
from deployment.application_source_set import DevApplicationSourceSet
from deployment.broker_host_service_contract import DevBrokerHostServiceContract
from deployment.broker_service_config import (
    DevBrokerServiceConfiguration, parse_canonical_broker_service_configuration,
)
from deployment.execution import (
    DEV_LOOPBACK_ADDRESS, DEV_LOOPBACK_PORT, DEV_PUBLIC_ORIGIN,
    DEV_REPOSITORY_ID, INGRESS_PATHS, RUNTIME_CONFIGURATION_PATH,
    IngressReference, RuntimeConfigurationReference,
)
from deployment.executor_service_config import (
    DevExecutorServiceConfiguration, parse_canonical_executor_service_configuration,
)
from deployment.final_configuration_authority import (
    DevFinalConfigurationAuthority, DevFinalConfigurationPair,
)
from deployment.sigstore_authority_provenance import DevSigstoreVerificationProvenance
from deployment.sigstore_resource_contract import DevSigstoreResourceContract
from deployment.tests.test_executor_service_config import configuration_values


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = "a" * 40
HISTORICAL_PIN = historical.PREDECESSOR_C17


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        values = configuration_values(reviewed_commit=frozen.TARGET_REVIEWED_COMMIT)
        self.seed = DevExecutorServiceConfiguration(**values)
        historical_seed = replace(self.seed, reviewed_commit=historical.PREDECESSOR)
        self.fixture_hash = hashlib.sha256(historical_seed.canonical_bytes()).hexdigest()
        self.pin = patch("deployment.final_configuration_authority.c32d.PREDECESSOR_C17",
                         self.fixture_hash)
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def authority(self):
        return DevFinalConfigurationAuthority(executor_configuration=self.seed)

    def test_constructor_exact_type_pinned_generation_and_historical_hash(self):
        self.assertEqual(HISTORICAL_PIN,
                         "2da08e1d83ae6baa007ca0f5b8492c7e9df30a6922007095fb129f76fc924762")
        with patch("deployment.final_configuration_authority.c32d.PREDECESSOR_C17",
                   HISTORICAL_PIN), self.assertRaises(ValueError):
            self.authority()  # synthetic identity fixture is not real host authority
        self.assertEqual(inspect.signature(DevFinalConfigurationAuthority).parameters.keys(),
                         {"executor_configuration"})
        for value in (self.seed.to_dict(), object()):
            with self.assertRaises(ValueError):
                DevFinalConfigurationAuthority(executor_configuration=value)
        class Subclass(DevExecutorServiceConfiguration):
            pass
        with self.assertRaises(ValueError):
            DevFinalConfigurationAuthority(executor_configuration=Subclass(**configuration_values(
                reviewed_commit=frozen.TARGET_REVIEWED_COMMIT)))
        for change in (
            {"reviewed_commit": historical.TARGET},
            {"runtime_configuration_sha256": "b" * 64},
            *({"ingress_file_sha256": tuple("b" * 64 if index == changed else item
                for index, item in enumerate(self.seed.ingress_file_sha256))}
              for changed in range(3)),
            *({name: getattr(self.seed, name) + 10} for name in (
                "broker_uid", "broker_gid", "executor_uid", "executor_gid",
                "replay_group_gid", "socket_group_gid")),
            {"canary_image": self.seed.canary_image[:-1] + "b"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                DevFinalConfigurationAuthority(executor_configuration=replace(self.seed, **change))

    def test_reconstructs_forged_cache_and_returns_independent_executor(self):
        damaged = replace(self.seed)
        object.__setattr__(damaged, "_installation", object())
        authority = DevFinalConfigurationAuthority(executor_configuration=damaged)
        self.assertIsNot(authority.executor_configuration, damaged)
        first, second = authority.executor(), authority.executor()
        self.assertIsNot(first, second)
        self.assertEqual(first.to_dict(), self.seed.to_dict())
        self.assertIsNot(first.installation_contract(), damaged._installation)
        self.assertEqual(first.reviewed_commit, frozen.TARGET_REVIEWED_COMMIT)
        self.assertEqual(first.runtime_configuration_sha256, frozen.TARGET_RUNTIME_SHA256)
        self.assertEqual(first.ingress_file_sha256, frozen.TARGET_INGRESS_SHA256)
        with self.assertRaises(FrozenInstanceError):
            authority.executor_configuration = self.seed

    def test_construction_and_projections_do_no_host_or_network_io(self):
        blockers = (
            patch.object(builtins, "open", side_effect=AssertionError("file read")),
            patch.object(os, "open", side_effect=AssertionError("host open")),
            patch.object(os, "getenv", side_effect=AssertionError("environment")),
            patch.object(socket, "socket", side_effect=AssertionError("socket")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
        )
        with ExitStack() as stack:
            for blocker in blockers:
                stack.enter_context(blocker)
            pair = self.authority().configuration_pair(expected_workflow_sha=WORKFLOW)
            pair.broker.release_references()
            DevBrokerHostServiceContract(configuration=pair.broker)

    def test_broker_uses_only_explicit_workflow_and_reviewed_sigstore_projection(self):
        authority = self.authority()
        broker = authority.broker_configuration(expected_workflow_sha=WORKFLOW)
        self.assertEqual(broker.schema_version, 2)
        self.assertEqual(broker.stage, "dev")
        self.assertEqual(broker.expected_workflow_sha, WORKFLOW)
        self.assertNotEqual(WORKFLOW, broker.reviewed_commit)
        self.assertEqual(broker.reviewed_commit, frozen.TARGET_REVIEWED_COMMIT)
        provenance = DevSigstoreVerificationProvenance()
        projected = provenance.broker_service_configuration_kwargs()
        self.assertEqual(projected, {
            "cosign_version": "3.1.2",
            "cosign_binary_sha256": "f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf",
            "sigstore_trusted_root_sha256": "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
        })
        for name, value in projected.items():
            self.assertEqual(getattr(broker, name), value)
        self.assertEqual(tuple(inspect.signature(authority.broker_configuration).parameters),
                         ("expected_workflow_sha",))
        with self.assertRaises(TypeError):
            authority.broker_configuration()
        self.assertEqual(authority.broker_configuration(
            expected_workflow_sha=frozen.TARGET_REVIEWED_COMMIT).expected_workflow_sha,
            frozen.TARGET_REVIEWED_COMMIT)
        for value in ("0" * 40, "A" * 40, "short", True, 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                authority.broker_configuration(expected_workflow_sha=value)
        with self.assertRaises(TypeError):
            authority.broker_configuration(expected_workflow_sha=WORKFLOW,
                                           cosign_binary_sha256="b" * 64)

    def test_pair_exact_alignment_and_nested_revalidation(self):
        pair = self.authority().configuration_pair(expected_workflow_sha=WORKFLOW)
        self.assertEqual(type(pair), DevFinalConfigurationPair)
        self.assertEqual(type(pair.executor), DevExecutorServiceConfiguration)
        self.assertEqual(type(pair.broker), DevBrokerServiceConfiguration)
        for name in ("broker_uid", "broker_gid", "executor_uid", "executor_gid",
                     "replay_group_gid", "socket_group_gid", "reviewed_commit",
                     "runtime_configuration_sha256", "ingress_file_sha256"):
            self.assertEqual(getattr(pair.executor, name), getattr(pair.broker, name))
        self.assertEqual(pair.executor.installation_contract(),
                         pair.broker.installation_contract())
        self.assertNotIn(pair.executor.executor_gid,
                         pair.broker.installation_contract().broker_required_group_gids)
        self.assertNotIn(pair.broker.broker_gid,
                         pair.executor.installation_contract().executor_required_group_gids)
        with self.assertRaises(FrozenInstanceError):
            pair.broker = pair.broker
        for broker in (pair.broker.to_dict(), replace(pair.broker, broker_uid=1010),
                       replace(pair.broker, expected_workflow_sha="b" * 40,
                               runtime_configuration_sha256="b" * 64)):
            with self.assertRaises(ValueError):
                DevFinalConfigurationPair(executor=pair.executor, broker=broker)
        forged = replace(pair.broker)
        object.__setattr__(forged, "_installation", object())
        rebuilt = DevFinalConfigurationPair(executor=pair.executor, broker=forged)
        self.assertIsNot(rebuilt.broker.installation_contract(), forged._installation)

    def test_canonical_bytes_and_release_references(self):
        pair = self.authority().configuration_pair(expected_workflow_sha=WORKFLOW)
        executor_raw, broker_raw = pair.executor.canonical_bytes(), pair.broker.canonical_bytes()
        self.assertEqual(parse_canonical_executor_service_configuration(executor_raw).to_dict(),
                         pair.executor.to_dict())
        self.assertEqual(parse_canonical_broker_service_configuration(broker_raw).to_dict(),
                         pair.broker.to_dict())
        self.assertEqual(executor_raw, json.dumps(pair.executor.to_dict(), sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode() + b"\n")
        self.assertEqual(broker_raw, json.dumps(pair.broker.to_dict(), sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode() + b"\n")
        self.assertNotIn(b"expected_workflow_sha", executor_raw)
        self.assertIn(WORKFLOW.encode(), broker_raw)
        runtime, ingress = pair.broker.release_references()
        self.assertEqual((type(runtime), type(ingress)),
                         (RuntimeConfigurationReference, IngressReference))
        self.assertEqual(runtime.reviewed_commit, frozen.TARGET_REVIEWED_COMMIT)
        self.assertEqual(runtime.sha256, frozen.TARGET_RUNTIME_SHA256)
        self.assertEqual(runtime.path, RUNTIME_CONFIGURATION_PATH)
        self.assertEqual(runtime.repository_id, DEV_REPOSITORY_ID)
        self.assertEqual(ingress.reviewed_commit, frozen.TARGET_REVIEWED_COMMIT)
        self.assertEqual(tuple(item.sha256 for item in ingress.files),
                         frozen.TARGET_INGRESS_SHA256)
        self.assertEqual(tuple(item.path for item in ingress.files), INGRESS_PATHS)
        self.assertEqual((ingress.loopback_address, ingress.loopback_port,
                          ingress.public_origin),
                         (DEV_LOOPBACK_ADDRESS, DEV_LOOPBACK_PORT, DEV_PUBLIC_ORIGIN))
        self.assertEqual((DEV_LOOPBACK_ADDRESS, DEV_LOOPBACK_PORT, DEV_PUBLIC_ORIGIN),
                         ("127.0.0.1", 3020, "https://canary-dev.omnilyzer.ai"))

    def test_broker_host_and_executor_integrity_contracts_accept_pair(self):
        pair = self.authority().configuration_pair(expected_workflow_sha=WORKFLOW)
        host = DevBrokerHostServiceContract(configuration=pair.broker)
        self.assertEqual(host.configuration, pair.broker)
        self.assertEqual(host.canonical_configuration_bytes(), pair.broker.canonical_bytes())
        self.assertEqual(host.sigstore_resources(),
                         DevSigstoreResourceContract(configuration=pair.broker))
        self.assertEqual(host.loopback_bind(), ("127.0.0.1", 3031))
        self.assertEqual(host.broker_principals(),
                         ("omnilyzer-broker", "omnilyzer-broker",
                          ("omnilyzer-replay", "omnilyzer-deployment")))
        runtime = host.runtime_directory_requirements()
        self.assertEqual(tuple(item.path for item in runtime[-2:]), (
            "/run/omnilyzer/deployment/dev/blob-verifier",
            "/run/omnilyzer/deployment/dev/oci-verifier"))
        self.assertTrue(all((item.owner_uid, item.group_gid, item.mode) ==
                            (pair.broker.broker_uid, pair.broker.broker_gid, 0o700)
                            for item in runtime[-2:]))
        self.assertEqual(host.replay_requirements()[1].path,
                         "/var/lib/omnilyzer/deployment/authority/replay.sqlite3")
        self.assertEqual(host.executor_socket_requirement().path,
                         "/run/omnilyzer/deployment/executor.sock")
        self.assertEqual(pair.executor.canary_image, self.seed.canary_image)
        # An older C17 test reloads its module in the broad suite. Check C24
        # compatibility in a fresh interpreter so stale dataclass identities
        # in this test process do not masquerade as a contract failure.
        script = """
from dataclasses import replace
import hashlib
import sys
from deployment import dev_post_c31_application_update as c32d
from deployment.executor_service_config import parse_canonical_executor_service_configuration
from deployment.final_configuration_authority import DevFinalConfigurationAuthority
from deployment.installation_integrity_contract import DevInstallationIntegrityContract
seed = parse_canonical_executor_service_configuration(sys.stdin.buffer.read())
c32d.PREDECESSOR_C17 = hashlib.sha256(replace(seed, reviewed_commit=c32d.PREDECESSOR).canonical_bytes()).hexdigest()
pair = DevFinalConfigurationAuthority(executor_configuration=seed).configuration_pair(expected_workflow_sha="a" * 40)
integrity = DevInstallationIntegrityContract(configuration=pair.executor)
assert integrity.application_requirement().reviewed_commit == seed.reviewed_commit
assert integrity.python_environment_requirement().implementation == "CPython"
"""
        result = subprocess.run((sys.executable, "-c", script), input=pair.executor.canonical_bytes(),
                                cwd=ROOT, capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_repository_freeze_and_non_live_scope(self):
        selected = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(selected), 41)
        self.assertEqual(selected, manifest._current_paths())
        self.assertNotIn("deployment/final_configuration_authority.py", selected)
        successor_deltas = []
        for path in (*selected, "deployment/application_source_set.py",
                     "deployment/application_manifest.py",
                     "deployment/final_application_generation.py",
                     "deployment/dev_final_application_update.py",
                     "deployment/dev_post_c31_application_update.py"):
            historical = subprocess.check_output(
                ("git", "show", f"2a99fbe5fe0a376a04b37a2dfa7cc1da7faa3893:{path}"))
            if (ROOT / path).read_bytes() != historical:
                successor_deltas.append(path)
        self.assertEqual(tuple(successor_deltas), ("deployment/docker_runtime.py", "deployment/state_store.py"))
        policy = json.loads((ROOT / "deployment/environments/dev.json").read_text())
        self.assertIs(policy["activation"]["deployment_enabled"], False)
        source = (ROOT / "deployment/final_configuration_authority.py").read_text()
        for forbidden in ("os.environ", "os.getenv", "subprocess", "socket.socket", "systemctl",
                          "__main__", "time.time", "open(", "write("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
