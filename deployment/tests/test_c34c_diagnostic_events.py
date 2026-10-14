"""File: deployment/tests/test_c34c_diagnostic_events.py
Purpose: Verify secret-free Task 014 diagnostic classifications and unchanged 403 responses.
Related: broker.py, broker_https_ingress.py, broker_integration.py, broker_loopback_listener.py.
Security: Synthetic identities only; no network, real credentials, replay writes or deployments.
"""

import ast
from pathlib import Path
import unittest

from deployment.broker import BrokerRejectedError, RestrictedDeploymentBroker
from deployment.broker_https_ingress import PROMOTION_PATH, dispatch_inert_dev_promotion_ingress
from deployment.jwks import OIDCVerificationError

BODY = b'{"synthetic":true}'
HEADERS = [
    ("Host", "deploy-dev.omnilyzer.ai"),
    ("Authorization", "Bearer synthetic.secret.token"),
    ("X-Omnilyzer-Zot-OIDC", "synthetic.zot.token"),
    ("X-Omnilyzer-Forgejo-OIDC", "synthetic.forgejo.token"),
    ("Content-Type", "application/json"),
    ("Content-Length", str(len(BODY))),
]
LOGGER = "omnilyzer.task014.authority"
WORKFLOW_SHA = "176ed3a31ffcf23346639ef22ac9bcab3794f0df"


class RejectingHandler:
    """A synthetic handler that rejects without invoking the executor."""

    def handle(self, **kwargs):
        """Simulate fail-closed broker authorization."""
        raise BrokerRejectedError("SENSITIVE_EXCEPTION_TEXT")


class InvalidOIDC:
    """A verifier that fails before any replay or transport occurs."""

    def verify(self, token, *, received_at):
        """Reject an intentionally invalid token without recording its bytes."""
        raise OIDCVerificationError("SENSITIVE_SIGNATURE_DETAILS")


class UnusedReplay:
    """Fail if the code reaches replay after synthetic OIDC rejection."""

    def consume(self, *args, **kwargs):
        """Never expected to be called."""
        raise AssertionError("replay should not run")


class UnusedTransport:
    """Fail if the code tries to deploy after synthetic OIDC rejection."""

    def send(self, *args, **kwargs):
        """Never expected to be called."""
        raise AssertionError("executor should not run")


class C34CDiagnosticEventTests(unittest.TestCase):
    """Test fixed event codes and unchanged external HTTP behavior."""

    def test_ingress_rejected(self):
        """Wrong Host logs a fixed category and returns fixed 403."""
        bad_headers = [("Host", "wrong.example"), *HEADERS[1:]]
        with self.assertLogs(LOGGER, level="WARNING") as recorded:
            result = dispatch_inert_dev_promotion_ingress(
                RejectingHandler(), method="POST", path=PROMOTION_PATH,
                headers=bad_headers, body=BODY, received_at=100,
            )
        self.assertEqual((result.status, result.body), (403, b'{"status":"rejected"}\n'))
        self.assertEqual([r.getMessage() for r in recorded.records],
                         ["task014_diag stage=ingress_rejected"])

    def test_handler_rejected(self):
        """Broker handler failure never logs an exception message or token."""
        with self.assertLogs(LOGGER, level="WARNING") as recorded:
            result = dispatch_inert_dev_promotion_ingress(
                RejectingHandler(), method="POST", path=PROMOTION_PATH,
                headers=HEADERS, body=BODY, received_at=100,
            )
        self.assertEqual((result.status, result.body), (403, b'{"status":"rejected"}\n'))
        self.assertEqual([r.getMessage() for r in recorded.records],
                         ["task014_diag stage=broker_rejected"])
        self.assertNotIn("SENSITIVE_EXCEPTION_TEXT", str(recorded.output))

    def test_invalid_oidc_fails_before_replay(self):
        """Signature verification fails with fixed, non-secret stage code."""
        broker = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA, verifier=InvalidOIDC(),
            replay_guard=UnusedReplay(), transport=UnusedTransport(),
        )
        with self.assertLogs(LOGGER, level="WARNING") as recorded:
            with self.assertRaises(BrokerRejectedError):
                broker.authorize_and_forward(
                    compact_token="synthetic.secret.token",
                    canonical_request=b"{}", received_at=100,
                )
        self.assertEqual([r.getMessage() for r in recorded.records],
                         ["task014_diag stage=deployment_oidc_rejected"])
        self.assertNotIn("SENSITIVE_SIGNATURE_DETAILS", str(recorded.output))
        self.assertNotIn("synthetic.secret.token", str(recorded.output))

    def test_logging_calls_are_static_literals(self):
        """Every new event is statically authored without interpolated user input."""
        root = Path(__file__).resolve().parents[2]
        paths = (
            "deployment/broker.py",
            "deployment/broker_https_ingress.py",
            "deployment/broker_loopback_listener.py",
            "deployment/broker_integration.py",
        )
        for relative in paths:
            with self.subTest(path=relative):
                source = (root / relative).read_text(encoding="utf-8")
                tree = ast.parse(source)
                calls = [
                    node for node in ast.walk(tree)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "warning"
                ]
                self.assertTrue(calls)
                for call in calls:
                    self.assertEqual(len(call.args), 1)
                    self.assertEqual(call.keywords, [])
                    self.assertIsInstance(call.args[0], ast.Constant)
                    value = call.args[0].value
                    self.assertIsInstance(value, str)
                    self.assertTrue(value.startswith("task014_diag stage="))
                    self.assertLess(len(value), 100)


if __name__ == "__main__":
    unittest.main()
