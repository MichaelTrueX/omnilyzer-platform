"""deployment/tests/test_executor_service_config.py — pure C17 contract tests.

These tests prove the closed canonical DEV executor service configuration and
its C13/C15 projections without filesystem, systemd, socket, Docker, or host I/O.
"""

from __future__ import annotations

import ast
import builtins
from contextlib import ExitStack
import importlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

import deployment.executor_service_config as config_module
from deployment.execution import INGRESS_PATHS
from deployment.executor_composition import DevExecutorComposition
from deployment.executor_service_config import (
    EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE,
    EXECUTOR_SERVICE_CONFIG_FILE_MODE,
    MAX_EXECUTOR_SERVICE_CONFIG_BYTES,
    PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH,
    DevExecutorServiceConfiguration,
    ExecutorServiceConfigurationError,
    parse_canonical_executor_service_configuration,
)
from deployment.installation_contract import DevHostInstallationContract
from deployment.policy import canonical_bytes
from deployment.replay_sqlite import MAX_UID_GID


SOURCE = Path(config_module.__file__)
CANARY_IMAGE = (
    "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:"
    "628af866084f08763b31a44c8a484c5ae4c64db6697f4c4ceaad91bbf54ba72a"
)
REVIEWED_COMMIT = "4" * 40
RUNTIME_HASH = "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f"
INGRESS_HASHES = (
    "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
    "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
)
FIELDS = {
    "schema_version", "stage", "broker_uid", "broker_gid", "executor_uid",
    "executor_gid", "replay_group_gid", "socket_group_gid", "canary_image",
    "reviewed_commit", "runtime_configuration_sha256", "ingress_file_sha256",
}


class Text(str):
    """Represent a non-exact string rejected at the configuration boundary."""


class Integer(int):
    """Represent a non-exact integer rejected by C13 identity validation."""


class Dictionary(dict):
    """Represent a mapping subclass rejected by strict from-dict parsing."""


def configuration_values(**changes: object) -> dict[str, object]:
    """Return valid direct-constructor values with selected replacements."""

    values: dict[str, object] = {
        "schema_version": 1,
        "stage": "dev",
        "broker_uid": 1001,
        "broker_gid": 1002,
        "executor_uid": 1003,
        "executor_gid": 1004,
        "replay_group_gid": 1005,
        "socket_group_gid": 1006,
        "canary_image": CANARY_IMAGE,
        "reviewed_commit": REVIEWED_COMMIT,
        "runtime_configuration_sha256": RUNTIME_HASH,
        "ingress_file_sha256": INGRESS_HASHES,
    }
    values.update(changes)
    return values


def make_configuration(**changes: object) -> DevExecutorServiceConfiguration:
    """Construct one valid immutable configuration with selected replacements."""

    return DevExecutorServiceConfiguration(**configuration_values(**changes))  # type: ignore[arg-type]


def serialized_values(**changes: object) -> dict[str, object]:
    """Return a fresh exact serialized-schema dictionary."""

    values = make_configuration().to_dict()
    values.update(changes)
    return values


class ImportAndInertnessTests(unittest.TestCase):
    """Prove import, construction, and parsing perform no operational I/O."""

    def test_reload_performs_no_host_or_environment_operation(self) -> None:
        global DevExecutorServiceConfiguration
        global ExecutorServiceConfigurationError
        global parse_canonical_executor_service_configuration

        blockers = (
            patch.object(builtins, "open", side_effect=AssertionError("open")),
            patch.object(os, "open", side_effect=AssertionError("os.open")),
            patch.object(os, "stat", side_effect=AssertionError("stat")),
            patch.object(os, "lstat", side_effect=AssertionError("lstat")),
            patch.object(os, "getenv", side_effect=AssertionError("getenv")),
            patch.object(os, "getuid", side_effect=AssertionError("getuid")),
            patch.object(os, "getgid", side_effect=AssertionError("getgid")),
            patch.object(socket, "socket", side_effect=AssertionError("socket")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
        )
        with ExitStack() as stack:
            for blocker in blockers:
                stack.enter_context(blocker)
            importlib.reload(config_module)
        DevExecutorServiceConfiguration = (
            config_module.DevExecutorServiceConfiguration
        )
        ExecutorServiceConfigurationError = (
            config_module.ExecutorServiceConfigurationError
        )
        parse_canonical_executor_service_configuration = (
            config_module.parse_canonical_executor_service_configuration
        )

    def test_construction_and_parser_are_pure(self) -> None:
        blockers = (
            patch.object(builtins, "open", side_effect=AssertionError("open")),
            patch.object(os, "open", side_effect=AssertionError("os.open")),
            patch.object(os, "stat", side_effect=AssertionError("stat")),
            patch.object(os, "lstat", side_effect=AssertionError("lstat")),
            patch.object(os, "getenv", side_effect=AssertionError("getenv")),
            patch.object(os, "getuid", side_effect=AssertionError("getuid")),
            patch.object(os, "getgid", side_effect=AssertionError("getgid")),
            patch.object(socket, "socket", side_effect=AssertionError("socket")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
        )
        with ExitStack() as stack:
            for blocker in blockers:
                stack.enter_context(blocker)
            configured = make_configuration()
            parsed = parse_canonical_executor_service_configuration(
                configured.canonical_bytes(),
            )
        self.assertEqual(parsed, configured)


class SchemaAndValidationTests(unittest.TestCase):
    """Exercise the exact schema and all reused validation boundaries."""

    def test_exact_public_surface_and_resource_constants(self) -> None:
        self.assertEqual(config_module.__all__, (
            "ExecutorServiceConfigurationError",
            "DevExecutorServiceConfiguration",
            "parse_canonical_executor_service_configuration",
            "PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH",
            "EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE",
            "EXECUTOR_SERVICE_CONFIG_FILE_MODE",
            "MAX_EXECUTOR_SERVICE_CONFIG_BYTES",
        ))
        self.assertEqual(
            PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH,
            "/etc/omnilyzer/deployment/dev/executor.json",
        )
        self.assertEqual(EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE, 0o750)
        self.assertEqual(EXECUTOR_SERVICE_CONFIG_FILE_MODE, 0o640)
        self.assertEqual(MAX_EXECUTOR_SERVICE_CONFIG_BYTES, 4096)
        self.assertEqual(config_module._CONFIGURATION_OWNER_UID, 0)
        self.assertEqual(
            config_module._CONFIGURATION_DIRECTORY,
            "/etc/omnilyzer/deployment/dev",
        )
        for forbidden in (
            "load", "save", "install", "provision", "bootstrap", "run",
            "execute", "activate", "deploy", "read_file", "write_file",
            "from_path", "from_environment",
        ):
            self.assertFalse(hasattr(config_module, forbidden))

    def test_valid_configuration_and_allowed_zero_executor_ids(self) -> None:
        configured = make_configuration()
        self.assertEqual(configured.schema_version, 1)
        self.assertEqual(configured.stage, "dev")
        zero_executor = make_configuration(executor_uid=0, executor_gid=0)
        self.assertEqual(zero_executor.executor_uid, 0)
        self.assertEqual(zero_executor.executor_gid, 0)

    def test_constructor_has_only_exact_keyword_only_schema_fields(self) -> None:
        parameters = inspect.signature(DevExecutorServiceConfiguration).parameters
        self.assertEqual(tuple(parameters), (
            "schema_version", "stage", "broker_uid", "broker_gid",
            "executor_uid", "executor_gid", "replay_group_gid",
            "socket_group_gid", "canary_image", "reviewed_commit",
            "runtime_configuration_sha256", "ingress_file_sha256",
        ))
        self.assertTrue(all(
            parameter.kind is inspect.Parameter.KEYWORD_ONLY
            and parameter.default is inspect.Parameter.empty
            for parameter in parameters.values()
        ))

    def test_identity_validation_is_exactly_delegated_to_c13(self) -> None:
        invalid = (
            ("broker_uid", 0), ("broker_gid", 0),
            ("replay_group_gid", 0), ("socket_group_gid", 0),
            ("broker_uid", 1003), ("socket_group_gid", 1004),
        )
        for name, value in invalid:
            with self.subTest(name=name, value=value), self.assertRaises(
                ExecutorServiceConfigurationError,
            ):
                make_configuration(**{name: value})
        for name in (
            "broker_uid", "broker_gid", "executor_uid", "executor_gid",
            "replay_group_gid", "socket_group_gid",
        ):
            for value in (True, False, -1, 1.0, "1001", Integer(1001), object(), MAX_UID_GID + 1):
                with self.subTest(name=name, value=repr(value)), self.assertRaises(
                    ExecutorServiceConfigurationError,
                ):
                    make_configuration(**{name: value})

    def test_canary_image_uses_closed_existing_validation(self) -> None:
        invalid = (
            "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary:latest",
            CANARY_IMAGE.replace("oci-dev", "other", 1),
            CANARY_IMAGE.replace("task013-release-canary", "other", 1),
            CANARY_IMAGE[:-1], CANARY_IMAGE + "0",
            CANARY_IMAGE[:-64] + "A" * 64,
            CANARY_IMAGE + " ", " " + CANARY_IMAGE,
            CANARY_IMAGE + "?x=1", CANARY_IMAGE + "#fragment",
            Text(CANARY_IMAGE), None, object(),
        )
        for value in invalid:
            with self.subTest(value=repr(value)), self.assertRaises(
                ExecutorServiceConfigurationError,
            ):
                make_configuration(canary_image=value)

    def test_reviewed_commit_and_every_hash_are_strict(self) -> None:
        invalid_strings = (
            "", "a" * 39, "a" * 41, "A" * 40, "a" * 39 + " ",
            "sha256:" + "a" * 64, Text("a" * 40), None, object(),
        )
        for value in invalid_strings:
            with self.subTest(kind="commit", value=repr(value)), self.assertRaises(
                ExecutorServiceConfigurationError,
            ):
                make_configuration(reviewed_commit=value)
        invalid_hashes = (
            "", "a" * 63, "a" * 65, "A" * 64, "a" * 63 + " ",
            "sha256:" + "a" * 64, Text("a" * 64), None, object(),
        )
        for value in invalid_hashes:
            with self.subTest(kind="runtime", value=repr(value)), self.assertRaises(
                ExecutorServiceConfigurationError,
            ):
                make_configuration(runtime_configuration_sha256=value)
            for index in range(3):
                hashes = list(INGRESS_HASHES)
                hashes[index] = value  # type: ignore[list-item]
                with self.subTest(index=index, value=repr(value)), self.assertRaises(
                    ExecutorServiceConfigurationError,
                ):
                    make_configuration(ingress_file_sha256=tuple(hashes))

    def test_direct_constructor_rejects_wrong_closed_scalar_shapes(self) -> None:
        invalid = (
            ("schema_version", True), ("schema_version", 0),
            ("schema_version", 1.0), ("schema_version", Integer(1)),
            ("stage", "staging"), ("stage", Text("dev")),
            ("ingress_file_sha256", list(INGRESS_HASHES)),
            ("ingress_file_sha256", INGRESS_HASHES[:2]),
            ("ingress_file_sha256", INGRESS_HASHES + ("a" * 64,)),
        )
        for name, value in invalid:
            with self.subTest(name=name), self.assertRaises(
                ExecutorServiceConfigurationError,
            ):
                make_configuration(**{name: value})

    def test_from_dict_requires_exact_top_level_schema(self) -> None:
        valid = serialized_values()
        self.assertEqual(set(valid), FIELDS)
        for missing in ("schema_version", "broker_uid", "canary_image", "ingress_file_sha256"):
            value = serialized_values()
            value.pop(missing)
            with self.subTest(missing=missing), self.assertRaises(
                ExecutorServiceConfigurationError,
            ):
                DevExecutorServiceConfiguration.from_dict(value)
        for change in (
            {"unknown": 1}, {"schema_version": 2}, {"schema_version": True},
            {"schema_version": "1"}, {"stage": "prod"},
        ):
            value = serialized_values()
            value.update(change)
            with self.subTest(change=change), self.assertRaises(
                ExecutorServiceConfigurationError,
            ):
                DevExecutorServiceConfiguration.from_dict(value)
        with self.assertRaises(ExecutorServiceConfigurationError):
            DevExecutorServiceConfiguration.from_dict(Dictionary(valid))
        hostile = dict(valid)
        hostile[Text("stage")] = hostile.pop("stage")
        with self.assertRaises(ExecutorServiceConfigurationError):
            DevExecutorServiceConfiguration.from_dict(hostile)

    def test_ingress_object_has_only_code_owned_paths(self) -> None:
        valid = serialized_values()
        ingress = valid["ingress_file_sha256"]
        self.assertIs(type(ingress), dict)
        self.assertEqual(tuple(ingress), INGRESS_PATHS)  # type: ignore[arg-type]
        variations = []
        for missing in INGRESS_PATHS:
            altered = dict(ingress)  # type: ignore[arg-type]
            altered.pop(missing)
            variations.append(altered)
        for extra in (
            "/deployment/runtime/dev/compose.yaml", "../compose.yaml",
            "deployment/runtime/dev/Compose.yaml", "other",
        ):
            altered = dict(ingress)  # type: ignore[arg-type]
            altered[extra] = "a" * 64
            variations.append(altered)
        for altered in variations:
            value = serialized_values(ingress_file_sha256=altered)
            with self.subTest(keys=tuple(altered)), self.assertRaises(
                ExecutorServiceConfigurationError,
            ):
                DevExecutorServiceConfiguration.from_dict(value)


class SerializationAndProjectionTests(unittest.TestCase):
    """Prove canonical encoding, strict parsing, and exact pure projections."""

    def test_to_dict_is_exact_fresh_and_contains_no_override_or_secret(self) -> None:
        configured = make_configuration()
        first = configured.to_dict()
        second = configured.to_dict()
        self.assertIs(type(first), dict)
        self.assertIs(type(first["ingress_file_sha256"]), dict)
        self.assertEqual(set(first), FIELDS)
        self.assertEqual(tuple(first["ingress_file_sha256"]), INGRESS_PATHS)  # type: ignore[arg-type]
        self.assertIsNot(first, second)
        self.assertIsNot(first["ingress_file_sha256"], second["ingress_file_sha256"])
        first["stage"] = "prod"
        first["ingress_file_sha256"].clear()  # type: ignore[union-attr]
        self.assertEqual(configured.stage, "dev")
        self.assertEqual(configured.to_dict(), second)
        lowered = " ".join(configured.to_dict()).lower()
        for forbidden in (
            "password", "token", "secret", "credential", "private_key",
            "socket_path", "state_path", "audit_path", "replay_path", "clock",
            "listener", "docker", "python", "http_host", "http_port",
        ):
            self.assertNotIn(forbidden, lowered)

    def test_canonical_bytes_are_bounded_deterministic_and_shared(self) -> None:
        configured = make_configuration()
        encoded = configured.canonical_bytes()
        self.assertEqual(encoded, canonical_bytes(configured.to_dict()))
        self.assertEqual(encoded, configured.canonical_bytes())
        self.assertGreater(len(encoded), 0)
        self.assertLessEqual(len(encoded), MAX_EXECUTOR_SERVICE_CONFIG_BYTES)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertFalse(encoded.endswith(b"\n\n"))
        encoded.decode("ascii")

    def test_canonical_parser_round_trip(self) -> None:
        configured = make_configuration()
        encoded = configured.canonical_bytes()
        parsed = parse_canonical_executor_service_configuration(encoded)
        self.assertEqual(parsed, configured)
        self.assertEqual(parsed.canonical_bytes(), encoded)

    def test_canonical_parser_rejects_nonbytes_bounds_and_noncanonical_json(self) -> None:
        configured = make_configuration()
        encoded = configured.canonical_bytes()
        noncanonical = (
            bytearray(encoded), memoryview(encoded), encoded.decode("ascii"), b"",
            b"x" * (MAX_EXECUTOR_SERVICE_CONFIG_BYTES + 1), b"\xff",
            b"\xef\xbb\xbf" + encoded, b"not-json\n", b"[]\n",
            b" " + encoded, encoded + b" ", encoded[:-1], encoded + b"\n",
            json.dumps(configured.to_dict(), indent=2).encode("ascii") + b"\n",
            json.dumps(configured.to_dict()).encode("ascii") + b"\n",
        )
        for raw in noncanonical:
            with self.subTest(raw_type=type(raw).__name__, size=len(raw)), self.assertRaises(
                ExecutorServiceConfigurationError,
            ):
                parse_canonical_executor_service_configuration(raw)  # type: ignore[arg-type]

    def test_canonical_parser_rejects_duplicates_and_invalid_nested_schema(self) -> None:
        encoded = make_configuration().canonical_bytes()
        duplicate_top = encoded.replace(
            b'"stage":"dev"', b'"stage":"dev","stage":"dev"', 1,
        )
        first_path = INGRESS_PATHS[0].encode("ascii")
        needle = b'"' + first_path + b'":"' + INGRESS_HASHES[0].encode("ascii") + b'"'
        duplicate_ingress = encoded.replace(needle, needle + b"," + needle, 1)
        unknown = serialized_values(unknown=1)
        missing = serialized_values()
        missing.pop("reviewed_commit")
        wrong_nested = serialized_values(ingress_file_sha256=[])
        wrong_scalar = serialized_values(broker_uid=True)
        for raw in (
            duplicate_top,
            duplicate_ingress,
            canonical_bytes(unknown),
            canonical_bytes(missing),
            canonical_bytes(wrong_nested),
            canonical_bytes(wrong_scalar),
        ):
            with self.assertRaises(ExecutorServiceConfigurationError):
                parse_canonical_executor_service_configuration(raw)

    def test_installation_contract_and_c15_projection_are_exact(self) -> None:
        configured = make_configuration()
        installation = configured.installation_contract()
        self.assertIsInstance(installation, DevHostInstallationContract)
        for name in (
            "broker_uid", "broker_gid", "executor_uid", "executor_gid",
            "replay_group_gid", "socket_group_gid",
        ):
            self.assertEqual(getattr(installation, name), getattr(configured, name))
        projection = configured.executor_composition_kwargs()
        identity = installation.executor_composition_identity_kwargs()
        for name, value in identity.items():
            self.assertEqual(projection[name], value)
        expected = set(inspect.signature(DevExecutorComposition).parameters) - {
            "listener", "clock",
        }
        self.assertEqual(set(projection), expected)
        self.assertNotIn("listener", projection)
        self.assertNotIn("clock", projection)

    def test_projection_values_order_and_freshness(self) -> None:
        configured = make_configuration()
        first = configured.executor_composition_kwargs()
        second = configured.executor_composition_kwargs()
        self.assertIsNot(first, second)
        self.assertEqual(first, second)
        self.assertIs(first["canary_image"], configured.canary_image)
        self.assertIs(first["reviewed_commit"], configured.reviewed_commit)
        self.assertIs(
            first["runtime_configuration_sha256"],
            configured.runtime_configuration_sha256,
        )
        self.assertIs(first["ingress_file_sha256"], configured.ingress_file_sha256)
        self.assertEqual(first["ingress_file_sha256"], INGRESS_HASHES)
        first["canary_image"] = "changed"
        first["expected_broker_uid"] = 9999
        self.assertEqual(second, configured.executor_composition_kwargs())
        self.assertIs(type(configured.ingress_file_sha256), tuple)

    def test_configuration_and_installation_contract_are_immutable(self) -> None:
        configured = make_configuration()
        with self.assertRaises((AttributeError, TypeError)):
            configured.stage = "prod"  # type: ignore[misc]
        with self.assertRaises((AttributeError, TypeError)):
            configured.installation_contract().executor_gid = 9999  # type: ignore[misc]

    def test_no_secret_or_dynamic_request_field_exists(self) -> None:
        names = {name.lower() for name in make_configuration().to_dict()}
        for forbidden in (
            "password", "token", "secret", "credential", "private_key",
            "release_version", "promotion_request_sha256",
            "release_manifest_sha256", "provenance_sha256", "github_run_id",
            "requested_by_actor_id", "oidc_jti",
        ):
            self.assertFalse(any(forbidden in name for name in names))


class StructuralBoundaryTests(unittest.TestCase):
    """Prove the module has no loader, operational dependency, or path widening."""

    def test_no_operational_import_or_instantiation(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        forbidden = {
            "DevExecutorComposition", "acquire_systemd_executor_listener",
            "UnixExecutorListener", "SubprocessCommandRunner",
            "DockerRuntimeAdapter", "DockerComposeCandidateHttpClient",
            "FilesystemDeploymentStateStore", "SQLiteReplayGuard",
            "FilesystemAuditSink",
        }
        self.assertTrue(imported_names.isdisjoint(forbidden))
        self.assertIn("DevHostInstallationContract", imported_names)
        self.assertIn("INGRESS_PATHS", imported_names)

    def test_no_filesystem_loader_or_arbitrary_path_surface(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        called_attributes = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(called_names.isdisjoint({"open"}))
        self.assertTrue(called_attributes.isdisjoint({
            "open", "read_bytes", "read_text", "stat", "lstat", "fstat",
            "getenv", "getuid", "getgid",
        }))
        self.assertNotIn("from_path", source)
        self.assertNotIn("load_from_path", source)
        parameters = inspect.signature(DevExecutorServiceConfiguration).parameters
        for name in (
            "path", "config_path", "directory_mode", "file_mode", "owner_uid",
            "listener", "clock", "fd", "docker_binary", "python_binary",
        ):
            self.assertNotIn(name, parameters)


if __name__ == "__main__":
    unittest.main()
