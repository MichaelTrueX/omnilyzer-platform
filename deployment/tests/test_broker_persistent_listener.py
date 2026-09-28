"""C32T persistent listener tests use only fake sockets; never bind port 3031."""

import socket
import threading
import unittest
from unittest.mock import patch

from deployment.broker_loopback_listener import (
    BrokerLoopbackListenerError, BrokerStopController, DevBrokerLoopbackListener,
)
from deployment.tests.test_broker_loopback_listener import (
    FakeConnection, FakeServer, Handler, wire,
)


class SequenceServer(FakeServer):
    def __init__(self, outcomes):
        super().__init__(None)
        self.outcomes = list(outcomes)

    def accept(self):
        self.calls.append(("accept",))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome, ("127.0.0.1", 44902)


class PersistentTests(unittest.TestCase):
    def build(self, server, handler):
        calls = []
        def factory(family, kind):
            calls.append((family, kind))
            return server
        listener = DevBrokerLoopbackListener(
            handler, socket_factory=factory,
            wall_clock=lambda: 123.75, monotonic=lambda: 1.0,
        )
        return listener, calls

    def test_two_requests_one_bind_one_listen_sequential_and_closed(self):
        stop = BrokerStopController()
        connections = [FakeConnection([wire()]), FakeConnection([wire()])]
        class StoppingHandler(Handler):
            def handle(self, **kwargs):
                result = super().handle(**kwargs)
                if len(self.calls) == 2:
                    stop.request_stop()
                return result
        handler = StoppingHandler()
        server = SequenceServer(connections)
        listener, factory_calls = self.build(server, handler)
        with patch.object(threading, "Thread", side_effect=AssertionError("worker")):
            self.assertIsNone(listener.serve_until_stopped(stop))
        self.assertEqual(factory_calls, [(socket.AF_INET, socket.SOCK_STREAM)])
        self.assertEqual([call for call in server.calls if call[0] == "bind"],
                         [("bind", ("127.0.0.1", 3031))])
        self.assertEqual([call for call in server.calls if call[0] == "listen"],
                         [("listen", 2)])
        self.assertEqual(len([call for call in server.calls if call[0] == "accept"]), 2)
        self.assertTrue(server.closed)
        self.assertTrue(all(connection.closed for connection in connections))
        self.assertEqual(len(handler.calls), 2)

    def test_accept_timeout_rechecks_stop_and_continues(self):
        stop = BrokerStopController()
        connection = FakeConnection([wire()])
        server = SequenceServer([TimeoutError(), connection])
        class StoppingHandler(Handler):
            def handle(self, **kwargs):
                result = super().handle(**kwargs)
                stop.request_stop()
                return result
        listener, _ = self.build(server, StoppingHandler())
        self.assertIsNone(listener.serve_until_stopped(stop))
        self.assertEqual(len([call for call in server.calls if call[0] == "accept"]), 2)
        self.assertTrue(connection.closed and server.closed)

    def test_ordinary_rejected_and_unavailable_requests_keep_service_alive(self):
        stop = BrokerStopController()
        connections = [FakeConnection([wire(method=b"GET")]),
                       FakeConnection([wire()]), FakeConnection([wire()])]
        server = SequenceServer(connections)
        class VariableHandler(Handler):
            def handle(self, **kwargs):
                self.calls.append(kwargs)
                if len(self.calls) == 1:
                    raise RuntimeError("private registry diagnostic")
                stop.request_stop()
                return b"opaque"
        handler = VariableHandler()
        listener, _ = self.build(server, handler)
        self.assertIsNone(listener.serve_until_stopped(stop))
        self.assertEqual(len(handler.calls), 2)
        self.assertTrue(all(connection.closed for connection in connections))
        self.assertTrue(server.closed)
        self.assertIn(b"HTTP/1.0 403", connections[0].sent)
        self.assertIn(b"HTTP/1.0 503", connections[1].sent)
        self.assertIn(b"HTTP/1.0 202", connections[2].sent)
        self.assertNotIn(b"private registry diagnostic", connections[1].sent)

    def test_stop_before_accept_and_during_active_request(self):
        stop = BrokerStopController()
        stop.request_stop()
        server = SequenceServer([])
        listener, calls = self.build(server, Handler())
        self.assertIsNone(listener.serve_until_stopped(stop))
        self.assertEqual(calls, [])
        active_stop = BrokerStopController()
        connection = FakeConnection([wire()])
        server = SequenceServer([connection])
        class Active(Handler):
            def handle(self, **kwargs):
                active_stop.request_stop()
                self.assertion = not connection.closed
                return super().handle(**kwargs)
        handler = Active()
        listener, _ = self.build(server, handler)
        self.assertIsNone(listener.serve_until_stopped(active_stop))
        self.assertTrue(handler.assertion)
        self.assertEqual(len(handler.calls), 1)
        self.assertTrue(connection.closed and server.closed)
        self.assertEqual(len([call for call in server.calls if call[0] == "accept"]), 1)

    def test_bad_peer_cleanup_control_and_concurrent_call(self):
        stop = BrokerStopController()
        connection = FakeConnection([wire()])
        server = SequenceServer([connection])
        server.accept = lambda: (connection, ("10.0.0.2", 44902))
        listener, _ = self.build(server, Handler())
        with self.assertRaisesRegex(BrokerLoopbackListenerError,
                                    "^deployment listener is unavailable$"):
            listener.serve_until_stopped(stop)
        self.assertTrue(connection.closed and server.closed)

        connection = FakeConnection([wire()])
        server = SequenceServer([connection])
        class Interrupting(Handler):
            def handle(self, **kwargs):
                raise KeyboardInterrupt()
        listener, _ = self.build(server, Interrupting())
        with self.assertRaises(KeyboardInterrupt):
            listener.serve_until_stopped(BrokerStopController())
        self.assertTrue(connection.closed and server.closed)

        stop = BrokerStopController()
        connection = FakeConnection([wire()])
        server = SequenceServer([connection])
        class Reentrant(Handler):
            def handle(self, **kwargs):
                with test.assertRaises(BrokerLoopbackListenerError):
                    listener.serve_until_stopped(stop)
                stop.request_stop()
                return super().handle(**kwargs)
        test = self
        listener, _ = self.build(server, Reentrant())
        self.assertIsNone(listener.serve_until_stopped(stop))
        self.assertTrue(server.closed and connection.closed)

    def test_stop_controller_is_immutable_and_socket_never_reuses_port(self):
        stop = BrokerStopController()
        with self.assertRaises(AttributeError):
            stop._event = object()
        with self.assertRaises(AttributeError):
            del stop._event
        connection = FakeConnection([wire()])
        server = SequenceServer([connection])
        class Stopping(Handler):
            def handle(self, **kwargs):
                stop.request_stop()
                return super().handle(**kwargs)
        listener, _ = self.build(server, Stopping())
        listener.serve_until_stopped(stop)
        self.assertEqual([call for call in server.calls if call[0] == "setsockopt"],
                         [("setsockopt", (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1))])

    def test_accept_and_server_close_failure_are_fixed(self):
        for server in (SequenceServer([OSError("private accept")]),
                       SequenceServer([TimeoutError()])):
            if isinstance(server.outcomes[0], TimeoutError):
                server.close_error = True
                stop = BrokerStopController()
                original = server.accept
                def stop_on_timeout():
                    stop.request_stop()
                    return original()
                server.accept = stop_on_timeout
            else:
                stop = BrokerStopController()
            listener, _ = self.build(server, Handler())
            with self.assertRaisesRegex(BrokerLoopbackListenerError,
                                        "^deployment listener is unavailable$"):
                listener.serve_until_stopped(stop)
            self.assertTrue(server.closed)


if __name__ == "__main__":
    unittest.main()
