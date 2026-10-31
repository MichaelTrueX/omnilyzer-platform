"""File: deployment/tests/test_analytics_unix_boundary.py

Purpose: Isolated real Linux Task014-style Analytics private Unix transport,
         SO_PEERCRED connected receiver, sealed SCM_RIGHTS credential, exact
         release/request revalidation, preflight and original executor replay.
Related: deployment/analytics_unix_boundary.py,
         deployment/analytics_executor.py,
         deployment/analytics_promotion_broker.py,
         deployment/private_registry_fd.py, deployment/executor_server.py,
         deployment/unix_transport.py,
         deployment/tests/test_private_registry_end_to_end.py.

Sections: original callback fixtures, exact first-install receiver, adversarial
          private credential and request tests, real one-shot Unix socket flow,
          cross-product and incorrect peer denial.

The synthetic operation and preflight are NOT a real Docker, PostgreSQL,
rootless executor or signed registry verification. No installed process,
external network, credentials or production path are used.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from deployment.analytics_executor import AnalyticsPrivilegedExecutor
import deployment.analytics_unix_boundary as analytics_boundary
from deployment.analytics_unix_boundary import (
    AnalyticsUnixExecutorConnectionHandler,
    AnalyticsUnixExecutorTransport, AnalyticsUnixExecutorListener,
)
from deployment.analytics_signed_release_consumer import PINNED_IMAGE
from deployment.executor import (
    ExecutorRejectedError, ExecutorUnavailableError,
    parse_canonical_response,
)
from deployment.executor_server import ExecutorConnectionUnavailableError
from deployment.private_registry_fd import (
    PrivateRegistryTransferError, create_sealed_credential,
    read_sealed_credential,
)
from deployment.private_registry_pull import current_private_zot_request
from deployment.unix_transport import (
    ExecutorTransportUnavailableError, UnixExecutorTransport,
)
from deployment.tests.test_analytics_execution import EXPECTED, fixture
from deployment.tests.test_executor import Replay
from deployment.tests.test_identity import NOW
from deployment.policy import canonical_bytes

REQUEST = canonical_bytes(fixture())
TOKEN = "synthetic-test-only-zot-auth-token"
CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class SyntheticPreflight:
    """Test-only callback that checks the original Linux sealed descriptor."""

    def __init__(self, events: list[str], *, error: bool = False,
                 token: str = TOKEN):
        self.events, self.error, self.token = events, error, token

    def preflight_analytics(self, canonical_request, credential_fd):
        """Do no runtime action; assert broker request and sealed image scope."""
        self.events.append("private_manifest")
        assert canonical_request == REQUEST
        authority = read_sealed_credential(
            credential_fd, canonical_request=canonical_request,
            image=PINNED_IMAGE, now=NOW, product_id="analytics",
        )
        assert authority.token == self.token
        if self.error:
            raise OSError("synthetic image preflight failed")


class SyntheticFirstInstall:
    """Test-only marker that does NOT install a product or change any DB."""

    def __init__(self, events: list[str], *, error: bool = False,
                 token: str = TOKEN):
        self.events, self.error, self.token = events, error, token

    def deploy_analytics(self, request):
        """Record the exact reviewed request and simulate success/failure."""
        self.events.append("deploy_analytics")
        assert request.exact_image_reference == PINNED_IMAGE
        assert request.ingress_reference["public_origin"] is None
        assert request.rollback_reference["previous_digest"] is None
        assert request.rollback_reference["preserve_database_writes"] is True
        scoped = current_private_zot_request()
        assert scoped is not None
        fd, original = scoped
        assert original == REQUEST
        assert read_sealed_credential(
            fd, canonical_request=original, image=PINNED_IMAGE,
            now=NOW, product_id="analytics",
        ).token == self.token
        if self.error:
            raise OSError("synthetic private install failed")

    def rollback_first_analytics(self, request):
        """Synthetic no-op rollback for original executor failure paths."""
        self.events.append("rollback_first_analytics")
        return None


def receiver(*, events=None, fail_preflight=False, fail_deploy=False):
    """Assemble actual original replay and product-specific executor callbacks."""
    history = [] if events is None else events
    replay = Replay(history)
    executor = AnalyticsPrivilegedExecutor(
        replay_guard=replay,
        private_registry_preflight=SyntheticPreflight(
            history, error=fail_preflight,
        ),
        operation=SyntheticFirstInstall(history, error=fail_deploy),
        reviewed_installed_source=EXPECTED,
    )
    return executor, replay, history


def credential(*, image=PINNED_IMAGE, request=REQUEST, expires_at=NOW + 270,
               product_id="analytics"):
    """Create one real sealed synthetic capability with the original kernel API."""
    return create_sealed_credential(
        TOKEN, expires_at=expires_at, image=image,
        canonical_request=request, product_id=product_id, now=NOW,
    )


class AnalyticsExecutorPrivateTests(unittest.TestCase):
    """Receiver revalidates all fields without trusting broker-derived objects."""

    def setUp(self):
        self.clocks = [
            patch("deployment.analytics_executor.time.time", return_value=NOW),
            patch("deployment.private_registry_fd.time.time", return_value=NOW),
        ]
        for p in self.clocks:
            p.start()
            self.addCleanup(p.stop)

    def test_exact_first_install_replay_order_and_original_response(self):
        """Real sealed FD, double credential check then begin/deploy/finish."""
        executor, replay, events = receiver()
        fd = credential()
        try:
            reply = executor.execute_private(REQUEST, credential_fd=fd)
            result = parse_canonical_response(reply)
            self.assertEqual(
                result.executor_request_sha256, hashlib.sha256(REQUEST).hexdigest(),
            )
            self.assertEqual(
                events,
                ["private_manifest", "begin_execution", "deploy_analytics",
                 "finish_execution"],
            )
            self.assertEqual(len(replay.begin_calls), 1)
            self.assertEqual(len(replay.finish_calls), 1)
        finally:
            os.close(fd)

    def test_wrong_request_schema_or_fd_rejects_before_replay(self):
        """No canary, tampered request, absent FD or unreviewed root hashes."""
        executor, replay, events = receiver()
        fd = credential()
        try:
            for raw, credential_fd in (
                (b"{}", fd), (REQUEST + b" ", fd),
                (canonical_bytes({**fixture(), "stage": "prod"}), fd),
                (REQUEST, -1),
            ):
                with self.subTest(length=len(raw)), self.assertRaises(
                    (ExecutorRejectedError, ExecutorUnavailableError)
                ):
                    executor.execute_private(raw, credential_fd=credential_fd)
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(events, [])
        finally:
            os.close(fd)

    def test_unsealed_canary_or_wrong_digest_fd_never_works(self):
        """A synthetically accepted broker cannot bypass executor FD policy."""
        executor, replay, events = receiver()
        canary = (
            "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:"
            + "b" * 64
        )
        fd = credential(image=canary, product_id="canary")
        try:
            with self.assertRaises(ExecutorUnavailableError):
                executor.execute_private(REQUEST, credential_fd=fd)
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(events, [])
        finally:
            os.close(fd)

    def test_short_token_preflight_fail_and_deploy_fail_hold_replay(self):
        """Do not begin replay for invalid TTL or failed registry preflight."""
        for expires, preflight_failure in (
            (NOW + 224, False), (NOW + 270, True),
        ):
            executor, replay, events = receiver(fail_preflight=preflight_failure)
            fd = credential(expires_at=expires)
            try:
                with self.assertRaises(ExecutorUnavailableError):
                    executor.execute_private(REQUEST, credential_fd=fd)
                self.assertEqual(replay.begin_calls, [])
                self.assertNotIn("deploy_analytics", events)
            finally:
                os.close(fd)
        executor, replay, events = receiver(fail_deploy=True)
        fd = credential()
        try:
            with self.assertRaises(ExecutorUnavailableError):
                executor.execute_private(REQUEST, credential_fd=fd)
            self.assertEqual(len(replay.begin_calls), 1)
            self.assertEqual(replay.finish_calls, [])
        finally:
            os.close(fd)

    def test_constructor_strictly_requires_product_named_callbacks(self):
        """An original canary deploy() callback is not an Analytics installer."""
        class CanaryOnly:
            def deploy(self, request):
                return None

        with self.assertRaises(TypeError):
            AnalyticsPrivilegedExecutor(
                replay_guard=Replay([]),
                private_registry_preflight=SyntheticPreflight([]),
                operation=CanaryOnly(), reviewed_installed_source=EXPECTED,
            )
        with self.assertRaises(TypeError):
            AnalyticsPrivilegedExecutor(
                replay_guard=Replay([]),
                private_registry_preflight=SyntheticPreflight([]),
                operation=SyntheticFirstInstall([]),
                reviewed_installed_source={
                    **EXPECTED, "reviewed_compose_sha256": "invalid",
                },
            )

    def test_original_canary_handler_transport_still_refuses_analytics(self):
        """No automatic schema-v2 support is added to ordinary canary socket."""
        from deployment.executor_server import UnixExecutorConnectionHandler
        with self.assertRaises(TypeError):
            UnixExecutorConnectionHandler(
                executor=object(), expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(), private_registry_transfer=True,
            )
        transport = UnixExecutorTransport(
            expected_executor_uid=os.getuid(),
            expected_executor_gid=os.getgid(),
            expected_socket_group_gid=os.getgid(),
        )
        self.assertFalse(hasattr(transport, "_send_analytics_private"))


class AnalyticsActualUnixSocketTests(unittest.TestCase):
    """Actual AF_UNIX and SO_PEERCRED with no host root or network."""

    def setUp(self):
        self.clock1 = patch(
            "deployment.analytics_executor.time.time", return_value=NOW,
        )
        self.clock2 = patch(
            "deployment.private_registry_fd.time.time", return_value=NOW,
        )
        self.clock1.start()
        self.clock2.start()
        self.addCleanup(self.clock1.stop)
        self.addCleanup(self.clock2.stop)

    def test_systemd_analytics_listener_transfers_descriptor_after_exact_peer_check(self):
        """Join the real Analytics sender to the real shared PID1 decision."""
        from deployment import unix_transport as wire
        from deployment.tests.test_unix_transport import FakeSocket, metadata, Clock, RESPONSE, PEER
        fd = credential()
        try:
            for pid, uid, gid in ((1,0,0),(2,0,0),(1,1,0),(1,0,1)):
                fake = FakeSocket(peer=PEER.pack(pid,uid,gid))
                with patch.object(wire.os, 'lstat', side_effect=[metadata(uid=991,gid=993),metadata(uid=991,gid=993)]), patch.object(wire.socket, 'socket', return_value=fake), patch.object(wire.time, 'monotonic', Clock()), patch.object(wire, 'send_sealed_header') as send:
                    transport = AnalyticsUnixExecutorTransport(expected_executor_uid=991,expected_executor_gid=991,expected_socket_group_gid=993,reviewed_installed_source=EXPECTED)
                    if (pid,uid,gid)==(1,0,0):
                        self.assertEqual(transport._send_analytics_private(REQUEST,credential_fd=fd), RESPONSE)
                        send.assert_called_once_with(fake,len(REQUEST).to_bytes(4,'big'),fd)
                    else:
                        with self.assertRaises(ExecutorTransportUnavailableError):transport._send_analytics_private(REQUEST,credential_fd=fd)
                        send.assert_not_called()
                self.assertTrue(fake.closed)
        finally:os.close(fd)

    def test_systemd_peer_does_not_approve_foreign_paths_or_replaced_inodes(self):
        from deployment import unix_transport as wire
        from deployment.tests.test_unix_transport import FakeSocket, metadata, Clock, PEER
        fd = credential()
        try:
            for path, after in (('/tmp/unreviewed-analytics.sock', metadata(uid=991,gid=993)), (analytics_boundary.ANALYTICS_EXECUTOR_SOCKET_PATH, metadata(uid=991,gid=993,inode=999))):
                fake = FakeSocket(peer=PEER.pack(1,0,0))
                with patch.object(analytics_boundary,'ANALYTICS_EXECUTOR_SOCKET_PATH',path), patch.object(wire.os,'lstat',side_effect=[metadata(uid=991,gid=993),after]), patch.object(wire.socket,'socket',return_value=fake), patch.object(wire.time,'monotonic',Clock()), patch.object(wire,'send_sealed_header') as send:
                    transport=AnalyticsUnixExecutorTransport(expected_executor_uid=991,expected_executor_gid=991,expected_socket_group_gid=993,reviewed_installed_source=EXPECTED)
                    with self.assertRaises(ExecutorTransportUnavailableError):transport._send_analytics_private(REQUEST,credential_fd=fd)
                    send.assert_not_called()
                self.assertTrue(fake.closed)
        finally:os.close(fd)

    def test_real_analytics_unix_socket_and_sealed_fd_roundtrip(self):
        """Reuse original metadata, peer, expiry, framing and response checks."""
        with tempfile.TemporaryDirectory(prefix="m05-14-analytics-unix-") as root:
            path = str(Path(root) / "executor.sock")
            executor, replay, events = receiver()
            handler = AnalyticsUnixExecutorConnectionHandler(
                executor=executor, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(),
                reviewed_installed_source=EXPECTED,
            )
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            os.chmod(path, 0o660)
            listener.listen(1)
            listener.settimeout(3)
            errors = []

            def serve():
                """Provide only a local, disposable one-shot socket service."""
                try:
                    client, _ = listener.accept()
                    handler.handle(client)
                except BaseException as exc:
                    errors.append(exc)

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            try:
                with patch.object(
                    analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH", path
                ):
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )
                fd = credential()
                try:
                    before = set(os.listdir("/proc/self/fd"))
                    reply = transport._send_analytics_private(
                        REQUEST, credential_fd=fd,
                    )
                    after = set(os.listdir("/proc/self/fd"))
                    self.assertEqual(before, after)
                    self.assertEqual(
                        parse_canonical_response(reply).executor_request_sha256,
                        hashlib.sha256(REQUEST).hexdigest(),
                    )
                finally:
                    os.close(fd)
            finally:
                server.join(5)
                listener.close()
            self.assertFalse(server.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(
                events,
                ["private_manifest", "begin_execution",
                 "deploy_analytics", "finish_execution"],
            )
            self.assertEqual(len(replay.begin_calls), 1)
            self.assertEqual(len(replay.finish_calls), 1)

    def test_full_broker_jwt_to_real_unix_credential_and_durable_sqlite(self):
        """Real local socket+memfd+SQLite; synthetic external signature result.

        This is end-to-end Task014 CONTROL FLOW, not live signed registry,
        Docker image, PostgreSQL, or an approved installation.
        """
        from deployment.replay_sqlite import SQLiteReplayGuard
        from deployment.analytics_promotion_broker import AnalyticsPrivatePromotionBroker
        from deployment.tests.test_analytics_promotion_broker import evidence
        from deployment.tests.test_analytics_review_composition import handler as review_handler
        from deployment.tests.test_broker import Verifier
        from deployment.tests.test_broker_integration import (
            TOKEN as DEPLOYMENT_TOKEN, ZOT_TOKEN, FORGEJO_TOKEN, KEY,
        )
        from deployment.tests.test_identity import WORKFLOW_SHA
        from deployment.tests.test_registry_oidc_credentials import StaticCache

        with tempfile.TemporaryDirectory(prefix="m05-14-full-chain-") as root:
            base = Path(root)
            # The ORIGINAL SQLite replay guard rejects unrelated directory
            # entries, including an executor socket. Keep the protected
            # replay directory separate from the AF_UNIX socket parent.
            replay_dir = base / "replay"
            replay_dir.mkdir(mode=0o2770)
            replay_dir.chmod(0o2770)
            replay = SQLiteReplayGuard(
                replay_dir / "replay.sqlite3", expected_directory_uid=os.getuid(),
                expected_directory_gid=os.getgid(), current_time=lambda: NOW,
            )
            replay.initialize()
            socket_path = str(base / "analytics-executor.sock")
            server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server_socket.bind(socket_path)
            os.chmod(socket_path, 0o660)
            server_socket.listen(1)
            server_socket.settimeout(3)
            events = []
            privileged = AnalyticsPrivilegedExecutor(
                replay_guard=replay,
                private_registry_preflight=SyntheticPreflight(
                    events, token=ZOT_TOKEN,
                ),
                operation=SyntheticFirstInstall(events, token=ZOT_TOKEN),
                reviewed_installed_source=EXPECTED,
            )
            receiver = AnalyticsUnixExecutorConnectionHandler(
                executor=privileged, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(), reviewed_installed_source=EXPECTED,
            )
            errors = []

            def serve():
                """Accept exactly one private, local, synthetic product attempt."""
                try:
                    connection, _ = server_socket.accept()
                    receiver.handle(connection)
                except BaseException as exc:
                    errors.append(exc)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                with patch.object(
                    analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH", socket_path,
                ):
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )
                broker = AnalyticsPrivatePromotionBroker(
                    expected_workflow_sha=WORKFLOW_SHA, verifier=Verifier(),
                    signed_review_handler=review_handler(),
                    replay_guard=replay, analytics_transport=transport,
                    reviewed_installed_source=EXPECTED,
                    jwks_cache=StaticCache(KEY.public_key()),
                )
                with patch(
                    "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                    return_value=evidence(),
                ) as signed_mock, patch(
                    "deployment.analytics_promotion_broker.time.time", return_value=NOW,
                ):
                    result = broker.authorize_and_forward(
                        compact_token=DEPLOYMENT_TOKEN, zot_token=ZOT_TOKEN,
                        forgejo_token=FORGEJO_TOKEN, canonical_request=REQUEST,
                        received_at=NOW,
                    )
                    self.assertEqual(
                        parse_canonical_response(result).executor_request_sha256,
                        hashlib.sha256(REQUEST).hexdigest(),
                    )
                    # A second legitimate original OIDC call with same JTI/run
                    # must be denied by the EXISTING on-disk replay state.
                    with self.assertRaises(Exception):
                        broker.authorize_and_forward(
                            compact_token=DEPLOYMENT_TOKEN, zot_token=ZOT_TOKEN,
                            forgejo_token=FORGEJO_TOKEN,
                            canonical_request=REQUEST, received_at=NOW,
                        )
                    self.assertEqual(signed_mock.call_count, 2)
            finally:
                worker.join(5)
                server_socket.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(events, [
                "private_manifest", "deploy_analytics",
            ])

    def test_original_single_accept_listener_validates_exact_analytics_socket(self):
        """Original Task014 listener independently binds socket inode and path.

        This is a real disposable Linux AF_UNIX accept/SCM_RIGHTS flow. It
        neither installs nor activates a systemd service.
        """
        with tempfile.TemporaryDirectory(prefix="m05-14-listener-") as folder:
            path = str(Path(folder) / "analytics-executor.sock")
            privileged, replay, events = receiver()
            handler = AnalyticsUnixExecutorConnectionHandler(
                executor=privileged, expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(), reviewed_installed_source=EXPECTED,
            )
            original = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            original.bind(path)
            original.set_inheritable(False)
            os.chmod(path, 0o660)
            original.listen(1)
            errors = []
            try:
                with patch.object(
                    analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH", path,
                ):
                    executor_listener = AnalyticsUnixExecutorListener(
                        listener=original, handler=handler,
                        expected_socket_owner_uid=os.getuid(),
                        expected_socket_group_gid=os.getgid(),
                    )
                    # Relocate only the original ancestor tuple for a local
                    # disposable socket; original installed /run hierarchy
                    # remains fixed in the production Analytics class.
                    settings = list(object.__getattribute__(
                        executor_listener, "_configuration",
                    ))
                    settings[27] = ("/", "/tmp", folder)
                    object.__setattr__(
                        executor_listener, "_configuration", tuple(settings),
                    )
                    transport = AnalyticsUnixExecutorTransport(
                        expected_executor_uid=os.getuid(),
                        expected_executor_gid=os.getgid(),
                        expected_socket_group_gid=os.getgid(),
                        reviewed_installed_source=EXPECTED,
                    )

                def serve_once():
                    """Run the *original* listener identity and socket checks."""
                    try:
                        executor_listener.serve_once()
                    except BaseException as exc:
                        errors.append(exc)

                server = threading.Thread(target=serve_once, daemon=True)
                server.start()
                fd = credential()
                try:
                    result = transport._send_analytics_private(
                        REQUEST, credential_fd=fd,
                    )
                    self.assertEqual(
                        parse_canonical_response(result).executor_request_sha256,
                        hashlib.sha256(REQUEST).hexdigest(),
                    )
                finally:
                    os.close(fd)
                server.join(5)
                self.assertFalse(server.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(
                    events, ["private_manifest", "begin_execution",
                             "deploy_analytics", "finish_execution"],
                )
            finally:
                original.close()

    def test_original_canary_listener_never_accepts_analytics_handler_as_route(self):
        """Analytics listener does not use ordinary canary executor path."""
        from deployment.executor_listener import UnixExecutorListener
        privileged, replay, events = receiver()
        handler = AnalyticsUnixExecutorConnectionHandler(
            executor=privileged, expected_broker_uid=os.getuid(),
            expected_broker_gid=os.getgid(), reviewed_installed_source=EXPECTED,
        )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with self.assertRaises(TypeError):
                AnalyticsUnixExecutorListener(
                    listener=listener, handler=object(),
                    expected_socket_owner_uid=os.getuid(),
                    expected_socket_group_gid=os.getgid(),
                )
            original = UnixExecutorListener(
                listener=listener, handler=handler,
                expected_socket_owner_uid=os.getuid(),
                expected_socket_group_gid=os.getgid(),
            )
            original_settings = object.__getattribute__(
                original, "_configuration",
            )
            self.assertEqual(
                original_settings[26], "/run/omnilyzer/deployment/executor.sock",
            )
            with patch.object(
                analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH",
                "/run/omnilyzer/deployment/executor.sock",
            ), self.assertRaises(TypeError):
                AnalyticsUnixExecutorListener(
                    listener=listener, handler=handler,
                    expected_socket_owner_uid=os.getuid(),
                    expected_socket_group_gid=os.getgid(),
                )
        finally:
            listener.close()

    def test_explicit_analytics_transport_denies_canonical_canary_fallback(self):
        """No generic send() or original canary _send_private() on Analytics."""
        with patch.object(
            analytics_boundary, "ANALYTICS_EXECUTOR_SOCKET_PATH",
            "/tmp/m05-14-analytics-denied.sock",
        ):
            transport = AnalyticsUnixExecutorTransport(
                expected_executor_uid=os.getuid(),
                expected_executor_gid=os.getgid(),
                expected_socket_group_gid=os.getgid(),
                reviewed_installed_source=EXPECTED,
            )
        for op in (lambda: transport.send(REQUEST),
                   lambda: transport._send_private(REQUEST, credential_fd=3)):
            with self.assertRaises(ExecutorTransportUnavailableError):
                op()

    def test_mismatched_authenticated_broker_peer_is_denied(self):
        """Real Linux SO_PEERCRED must reject an unexpected broker UID."""
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        executor, replay, events = receiver()
        handler = AnalyticsUnixExecutorConnectionHandler(
            executor=executor, expected_broker_uid=os.getuid() + 1,
            expected_broker_gid=os.getgid(),
            reviewed_installed_source=EXPECTED,
        )
        try:
            with self.assertRaises(ExecutorConnectionUnavailableError):
                handler.handle(right)
            self.assertEqual(replay.begin_calls, [])
            self.assertEqual(events, [])
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()

