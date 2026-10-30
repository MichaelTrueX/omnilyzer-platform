"""File: deployment/tests/test_analytics_executor_service_bootstrap.py

Purpose: Test the exact Task014 Analytics root-owned service-admission schema,
         inherited named-FD checks and one-shot service lifecycle.
Related: deployment/analytics_executor_service_config.py,
         deployment/analytics_executor_service_bootstrap.py,
         deployment/analytics_executor_service_entrypoint.py,
         deployment/analytics_executor_composition.py,
         deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service,
         deployment/systemd/dev/omnilyzer-deployment-analytics-executor.socket,
         deployment/tests/test_analytics_executor_composition.py.

Sections: pure closed source identity grammar, root-controlled fail-closed
          loader, named socket activation, bootstrap order and cleanup, inert
          static systemd identity and original canary unchanged regression.
No sudo, Docker, systemd activation, registry, genuine JWT, or host secrets.
"""
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest.mock import patch

import deployment.analytics_executor_service_bootstrap as boot
import deployment.analytics_executor_service_config as config
from deployment.analytics_executor_service_bootstrap import (
    AnalyticsExecutorBootstrapError, _acquire_analytics_systemd_socket,
    run_analytics_executor_service_once,
)
from deployment.analytics_executor_service_config import (
    ANALYTICS_INSTALLED_FILES, AnalyticsInstalledAuthorityError,
    load_analytics_executor_service_config,
    parse_analytics_executor_service_config,
)
from deployment.analytics_executor_service_entrypoint import main
from deployment.tests.test_analytics_execution import EXPECTED
from deployment.policy import canonical_bytes

ROOT = Path(__file__).resolve().parents[2]


def sample_config():
    """An explicitly SYNTHETIC root-owned candidate: NEVER an install grant."""
    return {
        "schema_version": 1,
        "product_id": "analytics",
        "stage": "dev",
        **EXPECTED,
        "source_sha256": {
            item: "a" * 64 for item in ANALYTICS_INSTALLED_FILES
        },
    }


def sample_identities():
    """Original C13 process identity projection for a fake service start."""
    return {
        "expected_replay_directory_uid": 0,
        "expected_replay_directory_gid": 992,
        "expected_broker_uid": 990,
        "expected_broker_gid": 990,
        "expected_executor_uid": 991,
        "expected_executor_gid": 991,
        "expected_socket_owner_uid": 991,
        "expected_socket_group_gid": 993,
    }


class InstalledSourceConfigTests(unittest.TestCase):
    """Public dataclass/json grammar must NOT be a privileged authority."""

    def test_exact_product_source_root_is_disjoint_from_original_canary(self):
        """Signed Analytics source lives in its own root-owned app generation."""
        self.assertEqual(str(config._INSTALLED_ROOT), "/opt/omnilyzer/deployment/analytics-app")
        self.assertNotEqual(str(config._INSTALLED_ROOT), "/opt/omnilyzer/deployment/app")
        unit = (ROOT / "deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service").read_text()
        self.assertIn("WorkingDirectory=/opt/omnilyzer/deployment/analytics-app", unit)
        self.assertNotIn("WorkingDirectory=/opt/omnilyzer/deployment/app\n", unit)

    def test_exact_canonical_config_is_only_a_parsed_shape(self):
        """Check sorted source paths and exact pinned 0.15.0 source metadata."""
        encoded = canonical_bytes(sample_config())
        parsed = parse_analytics_executor_service_config(encoded)
        self.assertEqual(
            parsed["source_sha256"],
            tuple((item, "a" * 64) for item in ANALYTICS_INSTALLED_FILES),
        )
        for name in EXPECTED:
            self.assertEqual(parsed[name], EXPECTED[name])
        self.assertLessEqual(len(encoded), 4096)

    def test_privileged_analytics_import_closure_exactly_attested(self):
        """Mirror the original Task014 AST closure, without changing canary.

        All Python modules reachable from either Analytics service entrypoint
        must be covered by the original closed source set OR the distinct
        Analytics source_sha256 set. A new import cannot silently escape the
        future root-owned installation SHA manifest. Dynamic imports are
        already forbidden by the original static resolver.
        """
        from deployment.application_source_set import DevApplicationSourceSet
        from deployment.tests.test_application_source_set import local_imports

        original = {
            item.repository_path for item in DevApplicationSourceSet().files
            if item.kind == "python-module"
        }
        pending = {
            "deployment/analytics_broker_service_entrypoint.py",
            "deployment/analytics_executor_service_entrypoint.py",
            "deployment/__init__.py",
        }
        visited: set[str] = set()
        while pending:
            path = pending.pop()
            if path in visited:
                continue
            visited.add(path)
            source = ROOT / path
            self.assertTrue(source.is_file(), path)
            self.assertFalse(source.is_symlink(), path)
            tree = ast.parse(source.read_text(), filename=path)
            module = path.removesuffix(".py").replace("/", ".")
            pending.update(local_imports(tree, module) - visited)
        self.assertEqual(len(ANALYTICS_INSTALLED_FILES), len(set(ANALYTICS_INSTALLED_FILES)))
        self.assertEqual(set(ANALYTICS_INSTALLED_FILES), visited - original)
        self.assertTrue(original.isdisjoint(ANALYTICS_INSTALLED_FILES))

    def test_duplicate_unknown_wrong_noncanonical_and_missing_files_denied(self):
        """No attacker-chosen path, extra config or unsigned source is admitted."""
        original = sample_config()
        cases = [
            b'{"schema_version":1,"schema_version":1}\n',
            canonical_bytes({**original, "unexpected": "deny"}),
            canonical_bytes({**original, "stage": "prod"}),
            canonical_bytes({**original, "product_id": "canary"}),
            canonical_bytes({**original, "schema_version": True}),
            canonical_bytes({**original, "source_sha256": {
                **original["source_sha256"], "../etc/shadow": "a" * 64,
            }}),
            canonical_bytes({**original, "source_sha256": {
                key: value for key, value in original["source_sha256"].items()
                if key != ANALYTICS_INSTALLED_FILES[0]
            }}),
            canonical_bytes({**original, "reviewed_installed_commit": "0" * 40}),
            canonical_bytes({**original, "reviewed_compose_sha256": "bad"}),
            canonical_bytes(original).replace(b"\n", b"  \n"),
            b"X" * 4097,
        ]
        for raw in cases:
            with self.subTest(length=len(raw)), self.assertRaises(
                AnalyticsInstalledAuthorityError
            ):
                parse_analytics_executor_service_config(raw)

    def test_actual_fd_relative_installed_source_hashes_and_tampering(self):
        """Check complete approved Python, Compose and two profile source sets.

        Project only UID/root-owned metadata in a disposable directory.
        All contents are neutral one-byte fixtures; no actual privileged host,
        secrets, Docker operations or real application installation occurs.
        """
        modules = tuple(ANALYTICS_INSTALLED_FILES)
        with tempfile.TemporaryDirectory(prefix="m05-14-source-scope-") as temp:
            root = Path(temp) / "installed"
            root.mkdir()
            for name in modules:
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b"A")
                file.chmod(0o644)
            data = (
                ("deployment/products/analytics-dev.json", b"P",
                 EXPECTED["reviewed_product_profile_sha256"]),
                ("deployment/products/analytics-runtime-dev.json", b"R",
                 EXPECTED["reviewed_runtime_profile_sha256"]),
                ("deployment/runtime/dev/analytics.compose.review.yaml", b"C",
                 hashlib.sha256(b"C").hexdigest()),
                (config._SOURCE_CLAIM_PATH, (
                    ROOT / config._SOURCE_CLAIM_PATH
                ).read_bytes(), config._SOURCE_CLAIM_SHA256),
            )
            for name, value, _expected in data:
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(value)
                file.chmod(0o644)
            expected = tuple(
                (name, hashlib.sha256(b"A").hexdigest()) for name in modules
            ) + tuple((name, digest) for name, _raw, digest in data)
            actual_fstat = os.fstat
            actual_stat = os.stat

            def metadata(info):
                """Project root ownership and protected directory permissions."""
                raw = list(info)
                raw[4] = 0
                if stat.S_ISDIR(info.st_mode):
                    raw[0] = (raw[0] & ~0o7777) | 0o755
                return os.stat_result(raw)

            def projected_fstat(fd):
                """Return normal stat shape except simulated host root UID."""
                return metadata(actual_fstat(fd))

            def projected_stat(path, *args, **kwargs):
                """Preserve real inode/dev/link and symlink semantics."""
                return metadata(actual_stat(path, *args, **kwargs))

            class Product:
                """Only emulate canonical source SHA, not JSON or secrets."""
                def sha256(self):
                    return EXPECTED["reviewed_product_profile_sha256"]

            class Runtime:
                """Only emulate canonical runtime SHA, not JSON or secrets."""
                def sha256(self):
                    return EXPECTED["reviewed_runtime_profile_sha256"]

            with (
                patch.object(config, "_INSTALLED_ROOT", root),
                patch.object(config.os, "fstat", side_effect=projected_fstat),
                patch.object(config.os, "stat", side_effect=projected_stat),
                patch.object(
                    config.SaaSProductProfile, "from_json_bytes",
                    return_value=Product(),
                ) as product_parser,
                patch.object(
                    config.SaaSRuntimeProfile, "from_json_bytes",
                    return_value=Runtime(),
                ) as runtime_parser,
            ):
                self.assertIsNone(config._verify_source_bytes(expected, root=root))
                product_parser.assert_called_with(b"P")
                runtime_parser.assert_called_with(b"R")

                modified = root / modules[0]
                modified.write_bytes(b"Z")
                with self.assertRaises(AnalyticsInstalledAuthorityError):
                    config._verify_source_bytes(expected, root=root)
                modified.write_bytes(b"A")

                modified.chmod(0o666)
                with self.assertRaises(AnalyticsInstalledAuthorityError):
                    config._verify_source_bytes(expected, root=root)
                modified.chmod(0o644)

                modified.unlink()
                modified.symlink_to(root / modules[1])
                with self.assertRaises(AnalyticsInstalledAuthorityError):
                    config._verify_source_bytes(expected, root=root)
                modified.unlink()
                modified.write_bytes(b"A")
                modified.chmod(0o644)
                self.assertIsNone(config._verify_source_bytes(expected, root=root))

                # The signed-source claim is mandatory, not merely a
                # self-described candidate; same-length content mutation
                # and deletion independently fail this ORIGINAL source gate.
                claim = root / config._SOURCE_CLAIM_PATH
                approved = claim.read_bytes()
                claim.write_bytes(approved[:-1] + (b"0" if approved[-1:] != b"0" else b"1"))
                with self.assertRaises(AnalyticsInstalledAuthorityError):
                    config._verify_source_bytes(expected, root=root)
                claim.write_bytes(approved)
                claim.unlink()
                with self.assertRaises(AnalyticsInstalledAuthorityError):
                    config._verify_source_bytes(expected, root=root)

    def test_missing_privileged_file_denied_before_any_listener(self):
        """Ordinary unprivileged test process cannot spoof owner/config."""
        with patch.object(
            config, "load_dev_executor_service_configuration",
            side_effect=PermissionError("synthetic root permission denied"),
        ), patch.object(
            config, "_open_directories",
            side_effect=AssertionError("must not read untrusted file"),
        ):
            with self.assertRaises(AnalyticsInstalledAuthorityError):
                load_analytics_executor_service_config()


class SocketActivationTests(unittest.TestCase):
    """Name/PID/FD are exact before the listener can be claimed."""

    def test_wrong_systemd_named_fd_and_fd_count_denied(self):
        """Canary's FD name cannot be reused to acquire Analytics socket."""
        valid = {
            "LISTEN_PID": str(os.getpid()),
            "LISTEN_FDS": "1",
            "LISTEN_FDNAMES": "omnilyzer-analytics-executor",
            "LISTEN_PIDFDID": boot._MISSING,
        }
        for altered in (
            {"LISTEN_FDNAMES": "omnilyzer-executor"},
            {"LISTEN_FDS": "2"},
            {"LISTEN_FDS": "0"},
            {"LISTEN_PID": str(os.getpid() + 1)},
            {"LISTEN_PID": "00" + str(os.getpid())},
            {"LISTEN_FDNAMES": "analytics-unapproved"},
        ):
            with self.subTest(altered=altered), patch.object(
                boot, "_consume_activation_environment",
                return_value={**valid, **altered},
            ), patch.object(
                boot.socket, "socket",
                side_effect=AssertionError("no socket before validated PID/name"),
            ), self.assertRaises(AnalyticsExecutorBootstrapError):
                _acquire_analytics_systemd_socket()

    def test_source_failure_never_consumes_systemd_activation(self):
        """A syntactically plausible but untrusted source is NO authority."""
        with patch.object(
            boot, "load_analytics_executor_service_config",
            side_effect=AnalyticsInstalledAuthorityError("denied"),
        ), patch.object(
            boot, "_acquire_analytics_systemd_socket",
            side_effect=AssertionError("unsafe unreviewed socket activation"),
        ), self.assertRaises(AnalyticsExecutorBootstrapError):
            run_analytics_executor_service_once()

    def test_authorized_mock_once_invokes_closed_graph_and_closes_fd(self):
        """Check root admission precedes socket ownership and product dispatch."""
        events = []
        class SyntheticListener:
            """A close-only socket substitute that cannot connect to a host."""

            def close(self):
                """Record the required one-shot cleanup."""
                events.append("close")

        class SyntheticComposition:
            """A fake of exactly one original Task014 product dispatcher."""

            def __init__(self, **kwargs):
                """Capture reviewed source and exact projected C13 identities."""
                events.append("compose")
                assert kwargs["reviewed_installed_source"] == EXPECTED
                assert kwargs["expected_executor_uid"] == 991
                assert set(kwargs) == {
                    "listener", "reviewed_installed_source",
                    *sample_identities(),
                }

            def serve_once(self):
                """Return only original one-accept success shape."""
                events.append("serve")

        def verified_config():
            """One synthetic checked root config, not a real signed admission."""
            events.append("source")
            return dict(EXPECTED), sample_identities()

        def socket_ready():
            """One synthetic dedicated named FD."""
            events.append("socket")
            return SyntheticListener()

        with (
            patch.object(
                boot, "load_analytics_executor_service_config",
                side_effect=verified_config,
            ),
            patch.object(
                boot, "_acquire_analytics_systemd_socket",
                side_effect=socket_ready,
            ),
            patch.object(
                boot, "AnalyticsExecutorComposition", SyntheticComposition,
            ),
        ):
            self.assertIsNone(run_analytics_executor_service_once())
        self.assertEqual(events, ["source", "socket", "compose", "serve", "close"])

    def test_failed_composition_closes_inherited_fd(self):
        """No leaked privileged FD if source passes but graph construction fails."""
        closed = []
        class Stub:
            """A fake descriptor with only close()."""

            def close(self):
                """Count cleanup even after fail-closed composition."""
                closed.append(1)
        with (
            patch.object(
                boot, "load_analytics_executor_service_config",
                return_value=(dict(EXPECTED), sample_identities()),
            ),
            patch.object(
                boot, "_acquire_analytics_systemd_socket",
                return_value=Stub(),
            ),
            patch.object(
                boot, "AnalyticsExecutorComposition",
                side_effect=TypeError("synthetic bad graph"),
            ),
            self.assertRaises(AnalyticsExecutorBootstrapError),
        ):
            run_analytics_executor_service_once()
        self.assertEqual(closed, [1])

    def test_entrypoint_exits_nonzero_on_failing_authority(self):
        """No installer, fallback, unsigned authority or systemd changes."""
        with patch(
            "deployment.analytics_executor_service_entrypoint."
            "run_analytics_executor_service_once",
            side_effect=AnalyticsExecutorBootstrapError("denied"),
        ):
            self.assertEqual(main(), 1)


class StaticSystemdTests(unittest.TestCase):
    """Read inert repo unit files; never install, enable or start them."""

    def test_isolated_fixed_socket_and_hardened_service(self):
        """No canary socket, rootful Docker, shell, public ingress or cookies."""
        prefix = ROOT / "deployment/systemd/dev"
        sock = (prefix / "omnilyzer-deployment-analytics-executor.socket").read_text()
        svc = (prefix / "omnilyzer-deployment-analytics-executor.service").read_text()
        self.assertIn(
            "ListenStream=/run/omnilyzer/deployment/analytics-executor.sock", sock,
        )
        self.assertIn("FileDescriptorName=omnilyzer-analytics-executor", sock)
        self.assertNotIn("ListenStream=/run/omnilyzer/deployment/executor.sock", sock)
        self.assertIn("User=omnilyzer-executor", svc)
        self.assertIn("NoNewPrivileges=yes", svc)
        self.assertIn("ProtectSystem=strict", svc)
        self.assertIn("CapabilityBoundingSet=", svc)
        self.assertIn("PrivateTmp=yes", svc)
        self.assertIn(
            "BindReadOnlyPaths=/run/user/991/docker.sock:"
            "/run/omnilyzer/deployment/rootless-docker/docker.sock", svc,
        )
        self.assertIn("ConditionPathExists=/etc/omnilyzer/deployment/dev/analytics-executor.json", svc)
        self.assertNotIn("ExecStart=/bin/sh", svc)
        self.assertNotIn("127.0.0.1:3031", svc)


if __name__ == "__main__":
    unittest.main()
