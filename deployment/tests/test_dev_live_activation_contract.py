"""deployment/tests/test_dev_live_activation_contract.py - C33W contract tests.

Purpose:
- pin the only allowed DEV activation order;
- preserve executor socket activation and private ingress boundaries;
- prove the repository contract itself cannot mutate live services.

Links:
- deployment/dev_live_activation_contract.py is the pure lifecycle authority.
"""

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path
import unittest

from deployment.dev_live_activation_contract import DevLiveActivationContract


ROOT = Path(__file__).resolve().parents[2]


class DevLiveActivationContractTests(unittest.TestCase):
    """Validate the immutable C33W lifecycle contract."""

    def test_exact_activation_sequence_and_service_boundary(self) -> None:
        """Require socket-first activation and forbid direct executor start."""

        contract = DevLiveActivationContract()
        self.assertEqual(
            contract.activation_sequence,
            (
                "start-executor-socket",
                "qualify-executor-socket",
                "start-broker-service",
                "qualify-private-ingress",
            ),
        )
        self.assertEqual(
            contract.direct_start_forbidden,
            ("omnilyzer-deployment-executor.service",),
        )
        self.assertFalse(contract.automatic_retry_allowed)
        self.assertEqual(
            contract.executor_socket_path,
            "/run/omnilyzer/deployment/executor.sock",
        )

    def test_private_ingress_is_loopback_and_tailnet_only(self) -> None:
        """Preserve broker/Nginx loopback ports and private HTTPS endpoint."""

        contract = DevLiveActivationContract()
        self.assertEqual(
            (contract.broker_listen_host, contract.broker_listen_port),
            ("127.0.0.1", 3031),
        )
        self.assertEqual(
            (contract.nginx_listen_host, contract.nginx_listen_port),
            ("127.0.0.1", 3032),
        )
        self.assertEqual(
            contract.private_https_endpoint,
            "https://omnilyzerdev.tail52e570.ts.net/task014/dev/promote",
        )

    def test_contract_is_frozen(self) -> None:
        """Reject runtime mutation of reviewed lifecycle values."""

        contract = DevLiveActivationContract()
        with self.assertRaises(FrozenInstanceError):
            contract.broker_listen_port = 80

    def test_module_imports_are_inert(self) -> None:
        """Keep the lifecycle contract free of process and network primitives."""

        tree = ast.parse(
            (ROOT / "deployment/dev_live_activation_contract.py").read_text(
                encoding="utf-8"
            )
        )
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(imported.isdisjoint({"os", "socket", "subprocess"}))


if __name__ == "__main__":
    unittest.main()
