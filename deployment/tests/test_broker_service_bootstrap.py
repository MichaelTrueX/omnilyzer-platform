"""C32T bootstrap/entrypoint tests never open a production listener or host path."""

from contextlib import ExitStack
import importlib
import inspect
import json
import os
from pathlib import Path
import runpy
import signal
import socket
import sqlite3
import sys
import unittest
import warnings
from unittest.mock import patch

from deployment import broker_service_bootstrap as bootstrap
from deployment import broker_service_entrypoint as entrypoint
from deployment.broker_loopback_listener import BrokerStopController
from deployment.broker_service_config import DevBrokerServiceConfiguration
from deployment.replay_sqlite import PRODUCTION_REPLAY_DATABASE
from deployment.tests.test_broker_service_config import configuration_values


ROOT = Path(__file__).resolve().parents[2]


class BootstrapTests(unittest.TestCase):
    def composition(self, *, load_error=None, validation_error=None):
        calls = []
        controller = BrokerStopController()
        configuration = DevBrokerServiceConfiguration(**configuration_values())
        object.__setattr__(configuration, "_installation", object())
        cache = object()
        verifier = object()
        replay = object()
        transport = object()
        blob = object()
        handler = object()

        def load():
            calls.append(("load",))
            if load_error:
                raise load_error
            return configuration

        def jwks():
            calls.append(("jwks",))
            return cache

        def oidc(**kwargs):
            calls.append(("oidc", kwargs))
            return verifier

        class Replay:
            def __init__(self, *args, **kwargs):
                calls.append(("replay", args, kwargs))
            def validate(self):
                calls.append(("validate",))
                if validation_error:
                    raise validation_error
            def initialize(self):
                raise AssertionError("replay initialization forbidden")

        def unix(**kwargs):
            calls.append(("transport", kwargs))
            return transport

        def cosign(**kwargs):
            calls.append(("blob", kwargs))
            return blob

        def compose(**kwargs):
            calls.append(("compose", kwargs))
            return handler

        class Listener:
            def __init__(self, selected):
                calls.append(("listener", selected))
            def serve_until_stopped(self, selected):
                calls.append(("serve", selected))
                return None

        stack = ExitStack()
        for name, replacement in (
            ("_load_configuration", load), ("_GitHubJWKSCache", jwks),
            ("_GitHubOIDCVerifier", oidc), ("_SQLiteReplayGuard", Replay),
            ("_UnixExecutorTransport", unix), ("_CosignReleaseBlobVerifier", cosign),
            ("_compose_handler", compose), ("_DevBrokerLoopbackListener", Listener),
        ):
            stack.enter_context(patch.object(bootstrap, name, replacement))
        expected = dict(cache=cache, verifier=verifier, replay=replay,
                        transport=transport, blob=blob, handler=handler,
                        configuration=configuration)
        return stack, calls, controller, expected

    def test_exact_startup_order_shared_cache_and_closed_projections(self):
        stack, calls, stop, expected = self.composition()
        with stack:
            self.assertIsNone(bootstrap.run_dev_broker_service(stop_controller=stop))
        self.assertEqual([call[0] for call in calls], [
            "load", "jwks", "oidc", "replay", "validate", "transport",
            "blob", "compose", "listener", "serve",
        ])
        self.assertEqual(calls[2][1], {
            "expected_workflow_sha": expected["configuration"].expected_workflow_sha,
            "jwks_cache": expected["cache"],
        })
        self.assertEqual(calls[3][1], (PRODUCTION_REPLAY_DATABASE,))
        self.assertEqual(calls[3][2], {
            "expected_directory_uid": 0, "expected_directory_gid": 2003,
            "expected_broker_uid": 1001, "expected_executor_uid": 2001,
        })
        self.assertEqual(calls[5][1], {
            "expected_executor_uid": 2001, "expected_executor_gid": 2002,
            "expected_socket_group_gid": 2004,
        })
        self.assertEqual(calls[6][1], dict(expected["configuration"].blob_verifier_kwargs()))
        composed = calls[7][1]
        self.assertIs(composed["jwks_cache"], expected["cache"])
        self.assertIs(composed["verifier"], expected["verifier"])
        self.assertIs(composed["transport"], expected["transport"])
        self.assertIs(composed["blob_signatures"], expected["blob"])
        self.assertIsNot(composed["configuration"], expected["configuration"])
        self.assertIs(type(composed["configuration"].installation_contract()),
                      type(DevBrokerServiceConfiguration(**configuration_values()).installation_contract()))
        self.assertEqual(composed["configuration"].schema_version, 2)
        self.assertNotIn("runtime", composed)
        self.assertNotIn("ingress", composed)
        self.assertIs(calls[8][1], expected["handler"])
        self.assertIs(calls[9][1], stop)

    def test_bad_config_and_replay_prevent_listener_construction(self):
        for error, last in ((ValueError("private"), "load"),
                            (RuntimeError("private"), "validate")):
            options = ({"load_error": error} if last == "load" else
                       {"validation_error": error})
            stack, calls, stop, _ = self.composition(**options)
            with self.subTest(last=last), stack, self.assertRaisesRegex(
                    bootstrap.BrokerServiceBootstrapError,
                    "^DEV broker service bootstrap is unavailable$"):
                bootstrap.run_dev_broker_service(stop_controller=stop)
            self.assertEqual(calls[-1][0], last)
            self.assertNotIn("listener", [item[0] for item in calls])

    def test_configuration_is_exact_and_revalidated(self):
        stack, calls, stop, _ = self.composition()
        with stack, patch.object(bootstrap, "_load_configuration", return_value={}):
            with self.assertRaises(bootstrap.BrokerServiceBootstrapError):
                bootstrap.run_dev_broker_service(stop_controller=stop)
        self.assertEqual(calls, [])
        stack, calls, stop, _ = self.composition()
        forged = DevBrokerServiceConfiguration(**configuration_values())
        object.__setattr__(forged, "schema_version", 1)
        with stack, patch.object(bootstrap, "_load_configuration", return_value=forged):
            with self.assertRaises(bootstrap.BrokerServiceBootstrapError):
                bootstrap.run_dev_broker_service(stop_controller=stop)
        self.assertEqual(calls, [])
        self.assertEqual(tuple(inspect.signature(bootstrap.run_dev_broker_service).parameters),
                         ("stop_controller",))
        with self.assertRaises(bootstrap.BrokerServiceBootstrapError):
            bootstrap.run_dev_broker_service(stop_controller=object())

    def test_control_exception_propagates(self):
        stack, calls, stop, _ = self.composition(load_error=KeyboardInterrupt())
        with stack, self.assertRaises(KeyboardInterrupt):
            bootstrap.run_dev_broker_service(stop_controller=stop)
        self.assertEqual(calls, [("load",)])


class EntrypointTests(unittest.TestCase):
    def test_imports_are_inert(self):
        with patch.object(os, "open", side_effect=AssertionError("host open")), \
             patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("database")):
            importlib.reload(bootstrap)
            importlib.reload(entrypoint)

    def test_unsupported_argv_exits_before_bootstrap(self):
        with warnings.catch_warnings(), \
             patch.object(sys, "argv", ["broker_service_entrypoint", "--port", "3031"]), \
             patch.object(bootstrap, "run_dev_broker_service",
                          side_effect=AssertionError("bootstrap must not run")):
            warnings.filterwarnings("ignore", message=".*found in sys.modules.*", category=RuntimeWarning)
            with self.assertRaises(SystemExit) as caught:
                runpy.run_module("deployment.broker_service_entrypoint", run_name="__main__")
        self.assertEqual(caught.exception.code, 2)

    def test_signal_handlers_stop_only_and_restore(self):
        installed = {}
        changes = []
        def change(signum, handler):
            prior = installed.get(signum, f"previous-{signum}")
            installed[signum] = handler
            changes.append((signum, handler))
            return prior
        def run(*, stop_controller):
            self.assertFalse(stop_controller.is_stopping())
            installed[signal.SIGTERM](signal.SIGTERM, None)
            self.assertTrue(stop_controller.is_stopping())
            installed[signal.SIGINT](signal.SIGINT, None)
            return None
        with patch.object(entrypoint._signal, "signal", side_effect=change), \
             patch.object(entrypoint, "_run_service", side_effect=run):
            self.assertEqual(entrypoint.main(), 0)
        self.assertEqual(installed[signal.SIGTERM], f"previous-{signal.SIGTERM}")
        self.assertEqual(installed[signal.SIGINT], f"previous-{signal.SIGINT}")
        self.assertEqual(len(changes), 4)

    def test_failure_and_no_raw_exception_output(self):
        with patch.object(entrypoint, "_run_service", side_effect=RuntimeError("secret")), \
             patch.object(entrypoint._signal, "signal", return_value=object()), \
             patch("builtins.print", side_effect=AssertionError("output")):
            self.assertEqual(entrypoint.main(), 1)
        with patch.object(entrypoint, "_run_service", return_value=object()), \
             patch.object(entrypoint._signal, "signal", return_value=object()):
            self.assertEqual(entrypoint.main(), 1)

    def test_control_exception_restores_signal_handlers(self):
        changes = []
        def change(signum, handler):
            changes.append((signum, handler))
            return f"previous-{signum}"
        with patch.object(entrypoint, "_run_service", side_effect=KeyboardInterrupt()), \
             patch.object(entrypoint._signal, "signal", side_effect=change):
            with self.assertRaises(KeyboardInterrupt):
                entrypoint.main()
        self.assertEqual(len(changes), 4)
        self.assertEqual(changes[-2:], [
            (signal.SIGINT, f"previous-{signal.SIGINT}"),
            (signal.SIGTERM, f"previous-{signal.SIGTERM}"),
        ])

    def test_inert_repository_and_history(self):
        from deployment.application_source_set import DevApplicationSourceSet
        from deployment import application_manifest, dev_post_c31_application_update as c32d
        paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(paths), 31)
        for path in ("deployment/broker_service_bootstrap.py",
                     "deployment/broker_service_entrypoint.py",
                     "deployment/broker_loopback_listener.py"):
            self.assertNotIn(path, paths)
        self.assertEqual((len(application_manifest._predecessor_paths()),
                          len(application_manifest._paths())), (28, 31))
        self.assertEqual((c32d.PREDECESSOR, c32d.TARGET),
                         ("3ef02a6d61d20df3a1495b290c20807162b65b06",
                          "c04e66008cff556315603a9de59dacb4679787d4"))
        env = json.loads((ROOT / "deployment/environments/dev.json").read_text())
        self.assertFalse(env["activation"]["deployment_enabled"])
        self.assertEqual(env["runtime"], {
            "configuration_reference": None, "secrets_reference": None,
            "ingress_reference": None,
        })
        workflow = (ROOT / ".github/workflows/platform-promote.yml").read_text()
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("environment: task014-dev", workflow)
        self.assertFalse((ROOT / "deployment/systemd/dev/omnilyzer-deployment-broker.service").exists())


if __name__ == "__main__":
    unittest.main()
