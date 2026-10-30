"""File: deployment/tests/test_analytics_broker_router.py

Purpose: Confirm one existing Task014 HTTP ingress can safely dispatch only
         the signed Analytics 0.15.0 first-install or existing canary release,
         with no new listener, port or Nginx route.
Related: deployment/analytics_broker_router.py,
         deployment/broker_https_ingress.py,
         deployment/broker_integration.py,
         deployment/analytics_promotion_broker.py,
         deployment/tests/test_broker_integration.py,
         deployment/tests/test_analytics_promotion_broker.py.

Sections: actual original canary/Analytics opaque handlers; original six
          required header checks; signed Analytics dispatch; cross-product
          and duplicate-JSON negative controls; no unintended replay.

All cryptographic signer results are synthetic; the actual Linux sealed FD is
used by the Analytics broker, but no live registry, Docker, DB or host service.
"""
from __future__ import annotations

import os
import socket
import threading
import time
import unittest
from unittest.mock import patch

from deployment.analytics_broker_router import AnalyticsDEVPromotionRouter
from deployment.broker import BrokerRejectedError
from deployment.broker_https_ingress import (
    PUBLIC_HOST, PROMOTION_PATH, FORGEJO_OIDC_HEADER, ZOT_OIDC_HEADER,
    dispatch_inert_dev_promotion_ingress,
)
from deployment.policy import canonical_bytes
from deployment.tests.test_analytics_execution import EXPECTED, fixture as analytics_request
from deployment.tests.test_analytics_promotion_broker import (
    evidence, make_broker,
)
from deployment.tests.test_broker_integration import (
    fixture as original_fixture, TOKEN as CANARY_JWT,
    ZOT_TOKEN as ZOT_JWT, FORGEJO_TOKEN as FORGEJO_JWT,
)
from deployment.tests.test_identity import NOW

ANALYTICS = canonical_bytes(analytics_request())


def original_headers(request: bytes):
    """Use exactly the existing Task014 Host+three JWT+content-type headers."""
    return [
        ("Host", PUBLIC_HOST),
        ("Authorization", "Bearer " + CANARY_JWT),
        (ZOT_OIDC_HEADER, ZOT_JWT),
        (FORGEJO_OIDC_HEADER, FORGEJO_JWT),
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(request))),
    ]


class ProductRouterTests(unittest.TestCase):
    """The additional product cannot bypass original canary ingress security."""

    def setUp(self) -> None:
        """Capture real original handler objects without opening host services."""
        self.canary, self.promotion, _, self.canary_replay, self.canary_transport, *_ = (
            original_fixture()
        )
        self.analytics, self.analytics_replay, self.analytics_transport = make_broker()
        self.router = AnalyticsDEVPromotionRouter(
            canary=self.canary, analytics=self.analytics,
            reviewed_installed_source=EXPECTED,
        )

    def test_original_https_headers_and_analytics_signed_path(self):
        """One original ingress and exact sealed FD, never the canary path."""
        request = ANALYTICS
        with patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
            return_value=evidence(),
        ) as signed, patch(
            "deployment.analytics_promotion_broker.time.time", return_value=NOW,
        ):
            response = dispatch_inert_dev_promotion_ingress(
                self.router, method="POST", path=PROMOTION_PATH,
                headers=original_headers(request), body=request, received_at=NOW,
            )
        self.assertEqual(response.status, 202)
        self.assertEqual(len(self.analytics_transport.requests), 1)
        self.assertEqual(self.analytics_transport.requests[0], request)
        self.assertEqual(len(self.analytics_replay.calls), 1)
        self.assertEqual(self.canary_transport.calls, [])
        self.assertEqual(self.canary_replay.calls, [])
        signed.assert_called_once()

    def test_existing_signed_canary_has_no_analytics_side_effect(self):
        """Same original HTTP ingress continues to use only canary handler."""
        from deployment.tests.test_release_consumer import OCISignatures
        request = self.promotion.canonical_bytes()
        with patch(
            "deployment.registry_promotion_composition.CosignOCISignatureVerifier",
            return_value=OCISignatures(),
        ), patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
            side_effect=AssertionError("Analytics signer must stay inert"),
        ):
            response = dispatch_inert_dev_promotion_ingress(
                self.router, method="POST", path=PROMOTION_PATH,
                headers=original_headers(request), body=request, received_at=NOW,
            )
        self.assertEqual(response.status, 202)
        self.assertEqual(len(self.canary_transport.calls), 1)
        self.assertEqual(len(self.canary_replay.calls), 1)
        self.assertEqual(self.analytics_transport.requests, [])
        self.assertEqual(self.analytics_replay.calls, [])

    def test_malformed_product_markers_never_reach_signer_or_replay(self):
        """No schema-2 to canary fallback, unknown product or schema grants."""
        from deployment.jwks import parse_bounded_json
        raw = ANALYTICS
        cases = [
            canonical_bytes({**analytics_request(), "product_id": "canary"}),
            canonical_bytes({**analytics_request(), "schema_version": 1}),
            canonical_bytes({**analytics_request(), "stage": "prod"}),
            canonical_bytes({**analytics_request(), "oci_repository": "omnilyzer/task013-release-canary"}),
            canonical_bytes({**self.promotion.to_dict(), "product_id": "analytics"}),
            canonical_bytes({**self.promotion.to_dict(), "product_id": "new-product"}),
            canonical_bytes({**self.promotion.to_dict(), "schema_version": 2}),
            raw + b" ",
            b'{"schema_version":2,"schema_version":2,"product_id":"analytics"}\n',
            b'{}' ,
            b"X" * 4097,
        ]
        for value in cases:
            with self.subTest(case=value[:60]):
                with patch(
                    "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                    side_effect=AssertionError("bad product cannot reach signer"),
                ):
                    response = dispatch_inert_dev_promotion_ingress(
                        self.router, method="POST", path=PROMOTION_PATH,
                        headers=original_headers(value), body=value, received_at=NOW,
                    )
                self.assertEqual(response.status, 403)
        self.assertEqual(self.canary_transport.calls, [])
        self.assertEqual(self.analytics_transport.requests, [])
        self.assertEqual(self.canary_replay.calls, [])
        self.assertEqual(self.analytics_replay.calls, [])

    def test_unauthorized_headers_cannot_trigger_any_product(self):
        """No cookie, duplicate bearer, changed Host/path or unsigned claims."""
        bad_headers = original_headers(ANALYTICS)
        variants = [
            bad_headers + [("Cookie", "session=unreviewed")],
            bad_headers + [("Authorization", "Bearer duplicated")],
            [("Host", "attacker.example"), *bad_headers[1:]],
            bad_headers[:-1],
        ]
        for headers in variants:
            with self.subTest(headers=headers[:1]):
                result = dispatch_inert_dev_promotion_ingress(
                    self.router, method="POST", path=PROMOTION_PATH,
                    headers=headers, body=ANALYTICS, received_at=NOW,
                )
                self.assertEqual(result.status, 403)
        self.assertEqual(self.canary_replay.calls, [])
        self.assertEqual(self.analytics_replay.calls, [])

    def test_actual_original_local_http_listener_to_signed_analytics_broker(self):
        """Run a disposable REAL local HTTP/1.0 request over original C32Q.

        Only the listener is real; the 0.15.0 signature result and executor
        transport remain synthetic. The sealed credential is a real memfd.
        """
        import deployment.broker_loopback_listener as listener_module
        from deployment.broker_loopback_listener import DevBrokerLoopbackListener
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        instance = DevBrokerLoopbackListener(
            self.router, wall_clock=lambda: NOW,
        )
        events = []

        def serve():
            """Run one original C32Q accept without a permanent service."""
            try:
                events.append(instance.serve_once())
            except BaseException as exc:
                events.append(type(exc).__name__)

        body = ANALYTICS
        headers = original_headers(body)
        request = (
            "POST " + PROMOTION_PATH + " HTTP/1.0\r\n"
            + "\r\n".join(f"{key}: {value}" for key, value in headers)
            + "\r\nConnection: close\r\n\r\n"
        ).encode("ascii") + body
        with (
            patch.object(listener_module, "BROKER_LOOPBACK_PORT", port),
            patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                  return_value=evidence()),
            patch("deployment.analytics_promotion_broker.time.time", return_value=NOW),
        ):
            server = threading.Thread(target=serve, daemon=True)
            server.start()
            response = b""
            try:
                for attempt in range(80):
                    try:
                        connection = socket.create_connection(("127.0.0.1", port), 1)
                        break
                    except ConnectionRefusedError:
                        time.sleep(0.015)
                else:
                    self.fail("original local listener did not bind")
                with connection:
                    connection.sendall(request)
                    while True:
                        part = connection.recv(4096)
                        if not part:
                            break
                        response += part
            finally:
                server.join(4)
            self.assertFalse(server.is_alive())
        self.assertTrue(response.startswith(b"HTTP/1.0 202 Accepted\r\n"))
        self.assertEqual(events, [202])
        self.assertEqual(len(self.analytics_replay.calls), 1)
        self.assertEqual(self.canary_replay.calls, [])
        self.assertEqual(len(self.analytics_transport.requests), 1)

    def test_constructor_requires_both_exact_handlers_and_same_source(self):
        """Public review receipts/objects may not authorize installation."""
        for changed in (
            {"analytics": object()},
            {"canary": object()},
            {"reviewed_installed_source": {
                **EXPECTED, "reviewed_compose_sha256": "a" * 64,
            }},
        ):
            values = dict(
                canary=self.canary, analytics=self.analytics,
                reviewed_installed_source=EXPECTED,
            )
            values.update(changed)
            with self.assertRaises(TypeError):
                AnalyticsDEVPromotionRouter(**values)
        with self.assertRaises(AttributeError):
            self.router._analytics = lambda **_: b"invalid"

    def test_known_analytics_broker_denial_is_original_403_or_503(self):
        """Original safe ingress body remains fixed and never reflects token."""
        with patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
            side_effect=RuntimeError("synthetic signer's denial"),
        ), patch("deployment.analytics_promotion_broker.time.time", return_value=NOW):
            result = dispatch_inert_dev_promotion_ingress(
                self.router, method="POST", path=PROMOTION_PATH,
                headers=original_headers(ANALYTICS), body=ANALYTICS,
                received_at=NOW,
            )
        self.assertEqual(result.status, 503)
        self.assertEqual(result.body, b'{"status":"unavailable"}\n')
        self.assertNotIn(ZOT_JWT.encode(), result.body)
        self.assertEqual(self.canary_replay.calls, [])
        self.assertEqual(self.analytics_replay.calls, [])


if __name__ == "__main__":
    unittest.main()
