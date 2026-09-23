"""deployment/tests/test_installation_contract.py — inert C13 contract tests.

Purpose: prove the declarative DEV host contract has exact immutable resources,
coherent C11/C12 identity projections, and no host inspection, provisioning, or
activation behavior during import or construction.
"""

from __future__ import annotations

import ast
import builtins
from contextlib import ExitStack
from dataclasses import FrozenInstanceError
import grp
import importlib
import inspect
import os
from pathlib import Path
import pwd
import socket
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

import deployment.installation_contract as contract_module
from deployment.audit import AUDIT_PATH
from deployment.broker_composition import GitHubDevBrokerComposition
from deployment.executor_composition import DevExecutorComposition
from deployment.executor_listener import (
    PRODUCTION_EXECUTOR_SOCKET_PATH as LISTENER_EXECUTOR_SOCKET_PATH,
)
from deployment.installation_contract import (
    DevHostInstallationContract,
    HostResourceRequirement,
)
from deployment.replay_sqlite import (
    DATABASE_MODE,
    DIRECTORY_MODE as REPLAY_DIRECTORY_MODE,
    MAX_UID_GID,
    PRODUCTION_REPLAY_DATABASE,
)
from deployment.state_store import (
    PRODUCTION_DEV_STATE_PATH,
    STATE_DIRECTORY_MODE,
    STATE_FILE_MODE,
)
from deployment.unix_transport import PRODUCTION_EXECUTOR_SOCKET_PATH


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "deployment/installation_contract.py"
AUDIT_SOURCE = ROOT / "deployment/audit.py"


class IntegerSubclass(int):
    """Represent a non-exact integer that strict identity validation rejects."""


class CoercibleIdentity:
    """Offer integer coercion that the contract must never invoke."""

    def __int__(self) -> int:
        raise AssertionError("identity coercion was attempted")


def contract(**changes: object) -> DevHostInstallationContract:
    """Build one valid sample contract with selected identity changes."""

    values: dict[str, object] = {
        "broker_uid": 1001,
        "broker_gid": 1002,
        "executor_uid": 2001,
        "executor_gid": 2002,
        "replay_group_gid": 3001,
        "socket_group_gid": 3002,
    }
    values.update(changes)
    return DevHostInstallationContract(**values)  # type: ignore[arg-type]


def requirements_by_path(
    value: DevHostInstallationContract,
) -> dict[str, HostResourceRequirement]:
    """Index the closed resource tuple by canonical path for exact assertions."""

    return {requirement.path: requirement for requirement in value.resource_requirements()}


class InertnessTests(unittest.TestCase):
    """Prove import and construction perform no host operation or inspection."""

    @staticmethod
    def blockers() -> tuple[object, ...]:
        """Return representative hostile patches for every prohibited I/O family."""

        return (
            patch.object(builtins, "open", side_effect=AssertionError("file open")),
            patch.object(os, "open", side_effect=AssertionError("file open")),
            patch.object(os, "stat", side_effect=AssertionError("stat")),
            patch.object(os, "lstat", side_effect=AssertionError("lstat")),
            patch.object(os, "scandir", side_effect=AssertionError("scandir")),
            patch.object(os, "mkdir", side_effect=AssertionError("mkdir")),
            patch.object(os, "makedirs", side_effect=AssertionError("makedirs")),
            patch.object(os, "chmod", side_effect=AssertionError("chmod")),
            patch.object(os, "chown", side_effect=AssertionError("chown")),
            patch.object(os, "unlink", side_effect=AssertionError("unlink")),
            patch.object(os, "replace", side_effect=AssertionError("replace")),
            patch.object(os, "fsync", side_effect=AssertionError("fsync")),
            patch.object(os, "getuid", side_effect=AssertionError("getuid")),
            patch.object(os, "getgid", side_effect=AssertionError("getgid")),
            patch.object(os, "getgroups", side_effect=AssertionError("getgroups")),
            patch.object(pwd, "getpwuid", side_effect=AssertionError("passwd")),
            patch.object(pwd, "getpwnam", side_effect=AssertionError("passwd")),
            patch.object(grp, "getgrgid", side_effect=AssertionError("group")),
            patch.object(grp, "getgrnam", side_effect=AssertionError("group")),
            patch.object(sqlite3, "connect", side_effect=AssertionError("SQLite")),
            patch.object(socket, "socket", side_effect=AssertionError("socket")),
            patch.object(socket, "create_connection", side_effect=AssertionError("network")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
        )

    def test_reload_is_inert(self) -> None:
        with ExitStack() as stack:
            for blocker in self.blockers():
                stack.enter_context(blocker)  # type: ignore[arg-type]
            importlib.reload(contract_module)

    def test_construction_is_inert(self) -> None:
        with ExitStack() as stack:
            for blocker in self.blockers():
                stack.enter_context(blocker)  # type: ignore[arg-type]
            result = contract()
        self.assertIsInstance(result, DevHostInstallationContract)


class IdentityContractTests(unittest.TestCase):
    """Verify the exact constructor choices and strict identity relationships."""

    def test_exact_keyword_only_constructor_surface(self) -> None:
        signature = inspect.signature(DevHostInstallationContract)
        self.assertEqual(tuple(signature.parameters), (
            "broker_uid", "broker_gid", "executor_uid", "executor_gid",
            "replay_group_gid", "socket_group_gid",
        ))
        self.assertTrue(all(
            parameter.kind is inspect.Parameter.KEYWORD_ONLY
            for parameter in signature.parameters.values()
        ))
        forbidden = {
            "state_path", "replay_path", "audit_path", "socket_path",
            "state_owner", "state_group", "audit_owner", "audit_group",
            "socket_owner", "replay_owner", "mode", "oidc", "repository",
            "workflow", "systemd", "docker_socket",
        }
        self.assertTrue(forbidden.isdisjoint(signature.parameters))

    def test_every_identity_rejects_non_exact_or_out_of_range_values(self) -> None:
        invalid = (
            "1001", b"1001", True, False, -1, 1.0, object(),
            IntegerSubclass(1001), CoercibleIdentity(), MAX_UID_GID + 1,
        )
        for name in inspect.signature(DevHostInstallationContract).parameters:
            for value in invalid:
                with self.subTest(name=name, value=repr(value)):
                    with self.assertRaises((TypeError, ValueError)):
                        contract(**{name: value})

    def test_required_non_root_identities_reject_zero(self) -> None:
        for name in (
            "broker_uid", "broker_gid", "replay_group_gid", "socket_group_gid",
        ):
            with self.subTest(name=name), self.assertRaises(TypeError):
                contract(**{name: 0})

    def test_required_separation_is_enforced(self) -> None:
        with self.assertRaises(ValueError):
            contract(broker_uid=2001)
        with self.assertRaises(ValueError):
            contract(socket_group_gid=2002)

    def test_executor_uid_and_gid_may_be_root(self) -> None:
        value = contract(executor_uid=0, executor_gid=0)
        self.assertEqual((value.executor_uid, value.executor_gid), (0, 0))


class ProjectionTests(unittest.TestCase):
    """Verify C11/C12 constructor projections cannot diverge through C13."""

    def test_broker_projection_has_exact_valid_keys_and_values(self) -> None:
        value = contract()
        projected = value.broker_composition_kwargs()
        self.assertEqual(projected, {
            "expected_replay_directory_uid": 0,
            "expected_replay_directory_gid": 3001,
            "expected_executor_uid": 2001,
            "expected_executor_gid": 2002,
            "expected_socket_group_gid": 3002,
        })
        self.assertEqual(set(projected), set(
            inspect.signature(GitHubDevBrokerComposition).parameters,
        ))
        projected["expected_executor_uid"] = 9999
        self.assertEqual(value.broker_composition_kwargs()["expected_executor_uid"], 2001)

    def test_executor_projection_has_exact_valid_identity_keys(self) -> None:
        value = contract()
        projected = value.executor_composition_identity_kwargs()
        self.assertEqual(projected, {
            "expected_state_owner_uid": 2001,
            "expected_state_group_gid": 2002,
            "expected_replay_directory_uid": 0,
            "expected_replay_directory_gid": 3001,
            "expected_broker_uid": 1001,
            "expected_broker_gid": 1002,
            "expected_socket_owner_uid": 2001,
            "expected_socket_group_gid": 3002,
        })
        executor_parameters = inspect.signature(DevExecutorComposition).parameters
        self.assertTrue(set(projected) < set(executor_parameters))
        projected["expected_broker_uid"] = 9999
        self.assertEqual(
            value.executor_composition_identity_kwargs()["expected_broker_uid"],
            1001,
        )

    def test_cross_composition_identities_are_coherent(self) -> None:
        value = contract()
        broker = value.broker_composition_kwargs()
        executor = value.executor_composition_identity_kwargs()
        self.assertEqual(
            broker["expected_replay_directory_uid"],
            executor["expected_replay_directory_uid"],
        )
        self.assertEqual(broker["expected_replay_directory_uid"], 0)
        self.assertEqual(
            broker["expected_replay_directory_gid"],
            executor["expected_replay_directory_gid"],
        )
        self.assertEqual(broker["expected_replay_directory_gid"], value.replay_group_gid)
        self.assertEqual(broker["expected_executor_uid"], value.executor_uid)
        self.assertEqual(broker["expected_executor_gid"], value.executor_gid)
        self.assertEqual(executor["expected_socket_owner_uid"], value.executor_uid)
        self.assertEqual(
            broker["expected_socket_group_gid"],
            executor["expected_socket_group_gid"],
        )
        self.assertEqual(executor["expected_broker_uid"], value.broker_uid)
        self.assertEqual(executor["expected_broker_gid"], value.broker_gid)


class ResourceRequirementTests(unittest.TestCase):
    """Verify exact fixed paths, modes, ownership, and lifecycle responsibility."""

    def test_exact_resources_paths_kinds_and_modes(self) -> None:
        resources = requirements_by_path(contract())
        self.assertEqual(set(resources), {
            "/var/lib/omnilyzer/deployment/dev",
            "/var/lib/omnilyzer/deployment/dev/state.json",
            "/var/lib/omnilyzer/deployment/authority",
            "/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
            "/var/log/omnilyzer/deployment/dev",
            "/var/log/omnilyzer/deployment/dev/events.jsonl",
            "/run/omnilyzer/deployment/executor.sock",
        })
        expected = {
            "/var/lib/omnilyzer/deployment/dev": ("directory", 0o700),
            "/var/lib/omnilyzer/deployment/dev/state.json": ("regular_file", 0o600),
            "/var/lib/omnilyzer/deployment/authority": ("directory", 0o770),
            "/var/lib/omnilyzer/deployment/authority/replay.sqlite3": (
                "sqlite_database", 0o660,
            ),
            "/var/log/omnilyzer/deployment/dev": ("directory", 0o700),
            "/var/log/omnilyzer/deployment/dev/events.jsonl": (
                "regular_file", 0o600,
            ),
            "/run/omnilyzer/deployment/executor.sock": ("unix_socket", 0o660),
        }
        self.assertEqual(
            {path: (item.kind, item.mode) for path, item in resources.items()},
            expected,
        )

    def test_paths_and_existing_modes_derive_from_authoritative_constants(self) -> None:
        self.assertEqual(PRODUCTION_DEV_STATE_PATH, str(
            Path("/var/lib/omnilyzer/deployment/dev/state.json"),
        ))
        self.assertEqual((STATE_DIRECTORY_MODE, STATE_FILE_MODE), (0o700, 0o600))
        self.assertEqual(
            str(PRODUCTION_REPLAY_DATABASE),
            "/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
        )
        self.assertEqual((REPLAY_DIRECTORY_MODE, DATABASE_MODE), (0o770, 0o660))
        self.assertEqual(str(AUDIT_PATH), "/var/log/omnilyzer/deployment/dev/events.jsonl")
        self.assertEqual(
            PRODUCTION_EXECUTOR_SOCKET_PATH,
            "/run/omnilyzer/deployment/executor.sock",
        )
        self.assertEqual(
            PRODUCTION_EXECUTOR_SOCKET_PATH, LISTENER_EXECUTOR_SOCKET_PATH,
        )

    def test_audit_mode_declarations_match_sink_behavior(self) -> None:
        tree = ast.parse(AUDIT_SOURCE.read_text(encoding="utf-8"))
        directory_modes: set[int] = set()
        file_modes: set[int] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr == "mkdir":
                for keyword in node.keywords:
                    if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                        directory_modes.add(keyword.value.value)
            if node.func.attr == "chmod" and len(node.args) >= 2:
                if isinstance(node.args[1], ast.Constant):
                    directory_modes.add(node.args[1].value)
            if node.func.attr in {"open", "fchmod"} and node.args:
                for argument in node.args[1:]:
                    if isinstance(argument, ast.Constant) and type(argument.value) is int:
                        file_modes.add(argument.value)
        self.assertIn(0o700, directory_modes)
        self.assertIn(0o600, file_modes)

    def test_resource_ownership_is_derived_only_from_service_identities(self) -> None:
        resources = requirements_by_path(contract())
        for path in (
            "/var/lib/omnilyzer/deployment/dev",
            "/var/lib/omnilyzer/deployment/dev/state.json",
            "/var/log/omnilyzer/deployment/dev",
            "/var/log/omnilyzer/deployment/dev/events.jsonl",
        ):
            self.assertEqual(
                (resources[path].owner_uid, resources[path].group_gid),
                (2001, 2002),
            )
        for path in (
            "/var/lib/omnilyzer/deployment/authority",
            "/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
        ):
            self.assertEqual(
                (resources[path].owner_uid, resources[path].group_gid),
                (0, 3001),
            )
        socket_requirement = resources["/run/omnilyzer/deployment/executor.sock"]
        self.assertEqual(
            (socket_requirement.owner_uid, socket_requirement.group_gid),
            (2001, 3002),
        )

    def test_resource_lifecycles_assign_future_responsibility_exactly(self) -> None:
        resources = requirements_by_path(contract())
        self.assertEqual(
            resources["/var/lib/omnilyzer/deployment/dev/state.json"].lifecycle,
            "must-contain-canonical-no-active-state-before-activation",
        )
        self.assertEqual(
            resources[
                "/var/lib/omnilyzer/deployment/authority/replay.sqlite3"
            ].lifecycle,
            "future-reviewed-replay-initialization-only",
        )
        self.assertEqual(
            resources["/var/log/omnilyzer/deployment/dev"].lifecycle,
            "must-exist-before-activation",
        )
        self.assertEqual(
            resources["/var/log/omnilyzer/deployment/dev/events.jsonl"].lifecycle,
            "may-be-created-on-first-audit-append",
        )
        self.assertEqual(
            resources["/run/omnilyzer/deployment/executor.sock"].lifecycle,
            "future-reviewed-runtime-service-creation-only",
        )


class GroupRequirementTests(unittest.TestCase):
    """Verify minimal supplementary groups without duplicates or primary groups."""

    def test_default_group_requirements_are_minimal(self) -> None:
        value = contract()
        self.assertEqual(value.broker_required_group_gids, (3001, 3002))
        self.assertEqual(value.executor_required_group_gids, (3001,))
        self.assertNotIn(value.socket_group_gid, value.executor_required_group_gids)

    def test_broker_primary_and_duplicate_required_groups_are_omitted(self) -> None:
        self.assertEqual(
            contract(broker_gid=3001).broker_required_group_gids, (3002,),
        )
        self.assertEqual(
            contract(replay_group_gid=3002).broker_required_group_gids, (3002,),
        )

    def test_executor_primary_replay_group_is_omitted(self) -> None:
        self.assertEqual(
            contract(executor_gid=3001).executor_required_group_gids, (),
        )


class PublicAndStructuralTests(unittest.TestCase):
    """Verify immutable declarative surface and separation from host operations."""

    def test_public_operations_are_declarative_only(self) -> None:
        public_methods = {
            name for name, member in inspect.getmembers(
                DevHostInstallationContract, inspect.isfunction,
            ) if not name.startswith("_")
        }
        self.assertEqual(public_methods, {
            "broker_composition_kwargs",
            "executor_composition_identity_kwargs",
            "resource_requirements",
        })
        for forbidden in (
            "install", "apply", "provision", "initialize", "create", "start",
            "enable", "connect", "listen", "deploy", "preflight", "check_host",
            "write", "save", "delete", "remove", "migrate",
        ):
            self.assertFalse(hasattr(DevHostInstallationContract, forbidden))

    def test_contract_and_resource_values_are_immutable(self) -> None:
        value = contract()
        requirement = value.resource_requirements()[0]
        with self.assertRaises(FrozenInstanceError):
            value.executor_uid = 9  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            requirement.mode = 0o777  # type: ignore[misc]
        self.assertIsInstance(value.resource_requirements(), tuple)
        self.assertIs(value.resource_requirements(), value.resource_requirements())

    def test_source_has_no_operational_or_composition_dependency(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
            if (node.module if isinstance(node, ast.ImportFrom) else alias.name)
        }
        imported_leaves = {name.rsplit(".", 1)[-1] for name in imported}
        self.assertTrue(imported_leaves.isdisjoint({
            "os", "pwd", "grp", "socket", "sqlite3", "subprocess", "http",
            "executor_composition", "broker_composition", "deployment_operation",
            "docker_runtime", "jwks", "oidc_verifier",
        }))
        forbidden_calls = {
            "open", "stat", "lstat", "scandir", "mkdir", "chmod", "chown",
            "unlink", "replace", "fsync", "connect", "bind", "listen",
            "initialize", "install", "provision", "start", "systemctl",
        }
        called_attributes = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(forbidden_calls.isdisjoint(called_attributes))
        source = SOURCE.read_text(encoding="utf-8")
        for forbidden in (
            "SQLiteReplayGuard(", "FilesystemAuditSink(",
            "FilesystemDeploymentStateStore(", "UnixExecutorTransport(",
            "UnixExecutorListener(", "DevExecutorComposition(",
            "GitHubDevBrokerComposition(", "restricted-network",
            "manual authorization",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
