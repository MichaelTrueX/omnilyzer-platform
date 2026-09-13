"""deployment/tests/test_broker_composition.py — inert C12 composition tests.

Purpose: prove the GitHub-authorized DEV broker composition uses the reviewed
fixed-authority components while import and construction remain local, inert,
closed, and separate from executor composition and future authorization profiles.
"""

from __future__ import annotations

import ast
import builtins
from contextlib import ExitStack
import http.client
import importlib
import inspect
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

import deployment.broker_composition as composition_module
from deployment.broker import RestrictedDeploymentBroker
from deployment.broker_composition import GitHubDevBrokerComposition
from deployment.jwks import (
    DISCOVERY_URL,
    JWKS_URL,
    OIDC_HOST,
    OIDC_ISSUER,
    SYSTEM_CA_BUNDLE,
    GitHubJWKSCache,
    GitHubOIDCHTTPSFetcher,
)
from deployment.oidc_verifier import GitHubOIDCVerifier
from deployment.replay_sqlite import (
    MAX_UID_GID,
    PRODUCTION_REPLAY_DATABASE,
    SQLiteReplayGuard,
)
from deployment.unix_transport import (
    PRODUCTION_EXECUTOR_SOCKET_PATH,
    UnixExecutorTransport,
)


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "deployment/broker_composition.py"


def configuration(**changes: object) -> dict[str, object]:
    """Return one valid installation-identity configuration with changes."""

    values: dict[str, object] = {
        "expected_replay_directory_uid": 1001,
        "expected_replay_directory_gid": 1002,
        "expected_executor_uid": 1003,
        "expected_executor_gid": 1004,
        "expected_socket_group_gid": 1005,
    }
    values.update(changes)
    return values


class ImportInertnessTests(unittest.TestCase):
    """Prove loading the composition module performs no external operation."""

    def test_reload_is_inert(self) -> None:
        blockers = (
            patch.object(builtins, "open", side_effect=AssertionError("file open")),
            patch.object(os, "open", side_effect=AssertionError("file open")),
            patch.object(os, "stat", side_effect=AssertionError("path stat")),
            patch.object(os, "lstat", side_effect=AssertionError("path lstat")),
            patch.object(os, "mkdir", side_effect=AssertionError("directory create")),
            patch.object(os, "makedirs", side_effect=AssertionError("directory create")),
            patch.object(sqlite3, "connect", side_effect=AssertionError("SQLite")),
            patch.object(socket, "socket", side_effect=AssertionError("socket")),
            patch.object(socket, "create_connection", side_effect=AssertionError("network")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")),
            patch.object(http.client, "HTTPSConnection", side_effect=AssertionError("HTTPS")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
        )
        with ExitStack() as stack:
            for blocker in blockers:
                stack.enter_context(blocker)
            importlib.reload(composition_module)


class ConstructionTests(unittest.TestCase):
    """Prove construction is inert and uses the exact reviewed object graph."""

    def test_construction_calls_no_operational_boundary(self) -> None:
        def verify(verifier: object, compact_token: str, *, received_at: int) -> object:
            raise AssertionError("OIDC verification")

        def get_key(cache: object, kid: str) -> object:
            raise AssertionError("JWKS lookup")

        def fetch_discovery(fetcher: object) -> object:
            raise AssertionError("discovery fetch")

        def fetch_jwks(fetcher: object) -> object:
            raise AssertionError("JWKS fetch")

        def initialize(guard: object) -> None:
            raise AssertionError("replay initialization")

        def consume(
            guard: object, jti: str, *, expires_at: int, request_hash: str,
            run_id: int, run_attempt: int,
        ) -> None:
            raise AssertionError("replay consumption")

        def send(transport: object, canonical_request: bytes) -> bytes:
            raise AssertionError("executor connection")

        def authorize_and_forward(
            broker: object, *, compact_token: str, canonical_request: bytes,
            received_at: int,
        ) -> bytes:
            raise AssertionError("broker operation")

        blockers = (
            patch.object(GitHubOIDCVerifier, "verify", verify),
            patch.object(GitHubJWKSCache, "get_key", get_key),
            patch.object(GitHubOIDCHTTPSFetcher, "fetch_discovery", fetch_discovery),
            patch.object(GitHubOIDCHTTPSFetcher, "fetch_jwks", fetch_jwks),
            patch.object(SQLiteReplayGuard, "initialize", initialize),
            patch.object(SQLiteReplayGuard, "consume", consume),
            patch.object(UnixExecutorTransport, "send", send),
            patch.object(RestrictedDeploymentBroker, "authorize_and_forward", authorize_and_forward),
            patch.object(builtins, "open", side_effect=AssertionError("file open")),
            patch.object(os, "open", side_effect=AssertionError("file open")),
            patch.object(os, "stat", side_effect=AssertionError("production stat")),
            patch.object(os, "lstat", side_effect=AssertionError("socket inspect")),
            patch.object(os, "mkdir", side_effect=AssertionError("directory create")),
            patch.object(Path, "exists", side_effect=AssertionError("path exists")),
            patch.object(Path, "stat", side_effect=AssertionError("path stat")),
            patch.object(sqlite3, "connect", side_effect=AssertionError("SQLite")),
            patch.object(socket, "socket", side_effect=AssertionError("socket")),
            patch.object(socket, "create_connection", side_effect=AssertionError("network")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")),
            patch.object(http.client, "HTTPSConnection", side_effect=AssertionError("HTTPS")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
        )
        with ExitStack() as stack:
            for blocker in blockers:
                stack.enter_context(blocker)
            composed = GitHubDevBrokerComposition(**configuration())

        self.assertIsInstance(composed, GitHubDevBrokerComposition)

    def test_graph_uses_actual_reviewed_components(self) -> None:
        created: dict[str, object] = {}

        def record(name: str, constructor: object):
            """Wrap one constructor and retain its exact inputs and result."""

            def construct(*args: object, **kwargs: object) -> object:
                instance = constructor(*args, **kwargs)  # type: ignore[operator]
                created[name] = instance
                created[f"{name}_args"] = args
                created[f"{name}_kwargs"] = kwargs
                return instance

            return construct

        replacements = {
            "_GitHubOIDCVerifier": record("verifier", GitHubOIDCVerifier),
            "_SQLiteReplayGuard": record("replay", SQLiteReplayGuard),
            "_UnixExecutorTransport": record("transport", UnixExecutorTransport),
            "_RestrictedDeploymentBroker": record("broker", RestrictedDeploymentBroker),
        }
        with patch.multiple(composition_module, **replacements):
            composed = composition_module.GitHubDevBrokerComposition(**configuration())

        self.assertIsInstance(created["verifier"], GitHubOIDCVerifier)
        self.assertIsInstance(created["replay"], SQLiteReplayGuard)
        self.assertIsInstance(created["transport"], UnixExecutorTransport)
        self.assertIsInstance(created["broker"], RestrictedDeploymentBroker)
        self.assertEqual(created["verifier_args"], ())
        self.assertEqual(created["verifier_kwargs"], {})
        self.assertEqual(created["replay_args"], (PRODUCTION_REPLAY_DATABASE,))
        self.assertEqual(set(created["replay_kwargs"]), {  # type: ignore[arg-type]
            "expected_directory_uid", "expected_directory_gid",
        })
        self.assertEqual(created["transport_args"], ())
        self.assertEqual(set(created["transport_kwargs"]), {  # type: ignore[arg-type]
            "expected_executor_uid", "expected_executor_gid",
            "expected_socket_group_gid",
        })
        broker_arguments = created["broker_kwargs"]
        self.assertIs(broker_arguments["verifier"], created["verifier"])  # type: ignore[index]
        self.assertIs(broker_arguments["replay_guard"], created["replay"])  # type: ignore[index]
        self.assertIs(broker_arguments["transport"], created["transport"])  # type: ignore[index]
        self.assertIs(composed._authorize_and_forward.__self__, created["broker"])

    def test_construction_needs_no_production_path(self) -> None:
        with (
            patch.object(os, "open", side_effect=AssertionError("replay open")),
            patch.object(os, "stat", side_effect=AssertionError("replay stat")),
            patch.object(os, "lstat", side_effect=AssertionError("socket inspect")),
            patch.object(sqlite3, "connect", side_effect=AssertionError("SQLite")),
            patch.object(socket, "socket", side_effect=AssertionError("socket")),
        ):
            self.assertIsInstance(
                GitHubDevBrokerComposition(**configuration()),
                GitHubDevBrokerComposition,
            )

    def test_invalid_installation_identities_fail_closed(self) -> None:
        names = tuple(configuration())
        invalid_values = ("1001", True, -1, 1.5, object(), MAX_UID_GID + 1)
        for name in names:
            for value in invalid_values:
                with self.subTest(name=name, value_type=type(value).__name__):
                    with self.assertRaises((TypeError, ValueError)):
                        GitHubDevBrokerComposition(**configuration(**{name: value}))


class ClosedSurfaceTests(unittest.TestCase):
    """Prove fixed authority choices and the one-method public profile surface."""

    def test_constructor_exposes_only_installation_identities(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(GitHubDevBrokerComposition).parameters),
            (
                "expected_replay_directory_uid", "expected_replay_directory_gid",
                "expected_executor_uid", "expected_executor_gid",
                "expected_socket_group_gid",
            ),
        )
        source = SOURCE.read_text(encoding="utf-8")
        for forbidden in (
            "replay_path", "socket_path", "issuer", "discovery_url", "jwks_url",
            "ca_bundle", "audience", "repository_identity", "workflow_identity",
            "verifier=", "replay_guard=", "transport=", "timeout", "proxy",
        ):
            self.assertNotIn(
                forbidden, str(inspect.signature(GitHubDevBrokerComposition)),
            )
        self.assertNotIn("PRODUCTION_EXECUTOR_SOCKET_PATH", source)

    def test_existing_fixed_constants_remain_authoritative(self) -> None:
        self.assertEqual(
            str(PRODUCTION_REPLAY_DATABASE),
            "/var/lib/omnilyzer/deployment/authority/replay.sqlite3",
        )
        self.assertEqual(
            PRODUCTION_EXECUTOR_SOCKET_PATH,
            "/run/omnilyzer/deployment/executor.sock",
        )
        self.assertEqual(OIDC_ISSUER, "https://token.actions.githubusercontent.com")
        self.assertEqual(OIDC_HOST, "token.actions.githubusercontent.com")
        self.assertEqual(
            DISCOVERY_URL,
            "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
        )
        self.assertEqual(
            JWKS_URL, "https://token.actions.githubusercontent.com/.well-known/jwks",
        )
        self.assertEqual(SYSTEM_CA_BUNDLE, "/etc/ssl/certs/ca-certificates.crt")

    def test_public_instance_surface_is_only_authorize_and_forward(self) -> None:
        composed = GitHubDevBrokerComposition(**configuration())
        public = {name for name in dir(composed) if not name.startswith("_")}
        self.assertEqual(public, {"authorize_and_forward"})
        for forbidden in (
            "start", "run", "listen", "serve", "serve_forever", "connect",
            "initialize", "deploy", "execute", "verify", "consume", "send",
            "fetch", "refresh",
        ):
            self.assertFalse(hasattr(composed, forbidden))
        with self.assertRaises(AttributeError):
            composed._authorize_and_forward = lambda **kwargs: b""  # type: ignore[method-assign]

    def test_profile_remains_separate_from_executor_and_alternate_auth(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        imported = {
            ("." * node.level) + node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertTrue(imported.isdisjoint({
            ".executor_composition", ".executor", ".executor_server",
            ".executor_listener", ".deployment_operation", ".docker_runtime",
            ".runtime", ".execution", ".identity",
        }))
        lowered = SOURCE.read_text(encoding="utf-8").lower()
        for alternate in ("bisma", "manual auth", "local auth", "password", "ssh"):
            self.assertNotIn(alternate, lowered)


class DelegationTests(unittest.TestCase):
    """Prove exact one-call delegation, result identity, and error preservation."""

    def test_forwards_keywords_once_and_returns_exact_bytes(self) -> None:
        result = b"exact broker response"

        class RecordingBroker:
            """Record the sole operation without implementing broker behavior."""

            def __init__(self, **kwargs: object) -> None:
                self.calls: list[dict[str, object]] = []

            def authorize_and_forward(
                self, *, compact_token: str, canonical_request: bytes,
                received_at: int,
            ) -> bytes:
                self.calls.append({
                    "compact_token": compact_token,
                    "canonical_request": canonical_request,
                    "received_at": received_at,
                })
                return result

        with patch.object(composition_module, "_RestrictedDeploymentBroker", RecordingBroker):
            composed = composition_module.GitHubDevBrokerComposition(**configuration())
        broker = composed._authorize_and_forward.__self__
        token = "opaque.test.token"
        request = b"canonical request bytes"
        returned = composed.authorize_and_forward(
            compact_token=token, canonical_request=request, received_at=123456,
        )
        self.assertIs(returned, result)
        self.assertEqual(broker.calls, [{
            "compact_token": token,
            "canonical_request": request,
            "received_at": 123456,
        }])

    def test_preserves_exception_identity_without_retry(self) -> None:
        marker = RuntimeError("broker failure marker")

        class FailingBroker:
            """Raise one stable marker from the captured broker operation."""

            def __init__(self, **kwargs: object) -> None:
                self.calls = 0

            def authorize_and_forward(
                self, *, compact_token: str, canonical_request: bytes,
                received_at: int,
            ) -> bytes:
                self.calls += 1
                raise marker

        with patch.object(composition_module, "_RestrictedDeploymentBroker", FailingBroker):
            composed = composition_module.GitHubDevBrokerComposition(**configuration())
        broker = composed._authorize_and_forward.__self__
        with self.assertRaises(RuntimeError) as caught:
            composed.authorize_and_forward(
                compact_token="token", canonical_request=b"request", received_at=1,
            )
        self.assertIs(caught.exception, marker)
        self.assertEqual(broker.calls, 1)

    def test_rejects_non_bytes_test_double_result_without_coercion(self) -> None:
        class InvalidBroker:
            """Return a mutable result to exercise composition fail-closed behavior."""

            def __init__(self, **kwargs: object) -> None:
                self.calls = 0

            def authorize_and_forward(
                self, *, compact_token: str, canonical_request: bytes,
                received_at: int,
            ) -> bytes:
                self.calls += 1
                return bytearray(b"invalid")  # type: ignore[return-value]

        with patch.object(composition_module, "_RestrictedDeploymentBroker", InvalidBroker):
            composed = composition_module.GitHubDevBrokerComposition(**configuration())
        broker = composed._authorize_and_forward.__self__
        with self.assertRaises(TypeError):
            composed.authorize_and_forward(
                compact_token="token", canonical_request=b"request", received_at=1,
            )
        self.assertEqual(broker.calls, 1)


if __name__ == "__main__":
    unittest.main()
