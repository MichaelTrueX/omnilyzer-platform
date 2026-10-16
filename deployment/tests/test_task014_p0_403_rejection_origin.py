"""File: deployment/tests/test_task014_p0_403_rejection_origin.py

Purpose: Demonstrate the distinct synthetic causes of identical Task 014 HTTP
403 responses and preserve a bounded, review-only origin-diagnostic contract.
No real sockets, tokens, historical replay, systemd, root or live deployment.

Related:
- deployment/tests/test_broker_loopback_listener.py (existing fake sockets)
- deployment/broker_loopback_listener.py (HTTP/1.0 framing)
- deployment/broker_https_ingress.py (semantic and broker mapping)
- deployment/broker.py (C34E bounded private diagnostic stage vocabulary)
- deployment/ingress/dev-broker-tailscale-origin.nginx.conf (origin proxy)
- docs/operations/task014-p0-403-rejection-origin-contract.md
- .github/workflows/task014-c34d-review.yml
- https://github.com/MichaelTrueX/omnilyzer-platform/issues/182

The tests do NOT attribute October 13's real 403 or approve instrumentation.
"""

from __future__ import annotations

import logging
from pathlib import Path
import unittest

from deployment.broker import (
    BrokerRejectedError, _ALLOWED_STAGE_MESSAGES, _BoundedStageFilter,
)
from deployment.tests.test_broker_loopback_listener import (
    Handler, TOKENS, fixture, wire,
)


_ROOT = Path(__file__).resolve().parents[2]
_DESIGN = _ROOT / "docs/operations/task014-p0-403-rejection-origin-contract.md"
_NGINX = _ROOT / "deployment/ingress/dev-broker-tailscale-origin.nginx.conf"
_LISTENER = _ROOT / "deployment/broker_loopback_listener.py"
_EXPECTED_403 = b'{"status":"rejected"}\n'


def _offline_response(raw: bytes, *, handler: Handler | None = None) -> tuple[int, bytes, int]:
    """One existing fake-socket request, not a live HTTP client."""
    listener, _, connection, actual_handler, _ = fixture(
        raw=raw, handler=handler,
    )
    status = listener.serve_once()
    return status, bytes(connection.sent), len(actual_handler.calls)


class Task014P0RejectionOriginTests(unittest.TestCase):
    """Prove diagnostic ambiguity; never claim historical root-cause evidence."""

    def test_a_fixed_403_collides_for_three_independent_boundaries(self) -> None:
        """Listener framing, semantic ingress and handler rejection look identical."""
        malformed_http = wire(version=b"HTTP/1.1")
        wrong_forwarded_host = wire().replace(
            b"Host: deploy-dev.omnilyzer.ai\r\n",
            b"Host: invalid.example\r\n",
            1,
        )
        downstream_rejection = Handler(BrokerRejectedError("PRIVATE_ERROR_DETAIL"))

        framing = _offline_response(malformed_http)
        semantic = _offline_response(wrong_forwarded_host)
        broker = _offline_response(wire(), handler=downstream_rejection)

        for status, raw_response, handler_call_count in (framing, semantic, broker):
            with self.subTest(boundary=handler_call_count):
                self.assertEqual(status, 403)
                self.assertTrue(raw_response.startswith(b"HTTP/1.0 403 Forbidden\r\n"))
                self.assertTrue(raw_response.endswith(_EXPECTED_403))
                self.assertNotIn(b"PRIVATE_ERROR_DETAIL", raw_response)
                for token in TOKENS:
                    self.assertNotIn(token.encode("ascii"), raw_response)

        self.assertEqual(framing[1], semantic[1])
        self.assertEqual(semantic[1], broker[1])
        self.assertEqual(framing[2], 0)
        self.assertEqual(semantic[2], 0)
        self.assertEqual(broker[2], 1)

    def test_b_legitimate_synthetic_request_keeps_fixed_202_contract(self) -> None:
        status, response, handler_calls = _offline_response(wire())
        self.assertEqual((status, handler_calls), (202, 1))
        self.assertIn(b"HTTP/1.0 202 Accepted\r\n", response)
        self.assertTrue(response.endswith(b'{"status":"accepted"}\n'))

    def test_c_reviewed_origin_contract_is_proxy_http_1_0(self) -> None:
        """Static review only; not evidence of October 13 active process state."""
        config = _NGINX.read_text(encoding="utf-8")
        for field in (
            "access_log off;",
            "listen 127.0.0.1:3032;",
            "proxy_pass http://127.0.0.1:3031;",
            "proxy_http_version 1.0;",
            "proxy_pass_request_headers off;",
            "proxy_set_header Host deploy-dev.omnilyzer.ai;",
            "proxy_set_header Connection close;",
            "proxy_set_header Content-Type application/json;",
            "proxy_set_header Content-Length $content_length;",
        ):
            with self.subTest(field=field):
                self.assertIn(field, config)
        self.assertNotIn("access_log /", config)

    def test_d_bounded_c34e_has_no_listener_framing_attribution_yet(self) -> None:
        """Do not treat missing C34E event as proof the broker was not reached."""
        listener_source = _LISTENER.read_text(encoding="utf-8")
        self.assertIn("except _FramingRejected:", listener_source)
        self.assertIn("response = _REJECTED", listener_source)
        self.assertNotIn("listener_framing_rejected", listener_source)
        self.assertNotIn("task014_diag stage=", listener_source)
        self.assertEqual(len(_ALLOWED_STAGE_MESSAGES), 13)
        self.assertNotIn(
            "task014_diag stage=listener_framing_rejected",
            _ALLOWED_STAGE_MESSAGES,
        )

    def test_e_logger_rejects_arbitrary_or_secret_bearing_message(self) -> None:
        """A proposed private stage cannot be enabled by injecting log contents."""
        stage_filter = _BoundedStageFilter()
        for msg, args in (
            ("task014_diag stage=listener_framing_rejected", ()),
            ("task014_diag stage=broker_rejected %s", ("SENSITIVE",)),
            ("task014_diag stage=broker_rejected", ("SENSITIVE",)),
            ("Bearer SYNTHETIC-TOKEN", ()),
            ("task014_diag stage=broker_rejected token=SYNTHETIC", ()),
        ):
            with self.subTest(message=msg):
                record = logging.LogRecord(
                    "omnilyzer.task014.authority", logging.WARNING,
                    __file__, 1, msg, args, None,
                )
                self.assertFalse(stage_filter.filter(record))

    def test_f_design_requires_outer_and_inner_evidence_and_no_promotion(self) -> None:
        document = _DESIGN.read_text(encoding="utf-8")
        for requirement in (
            "P0-DIAG-01",
            "P0-DIAG-07",
            "upstream_status",
            "listener_framing_rejected",
            "AMBIGUOUS",
            "UNKNOWN",
            "NO-GO",
            "G1/G2/G3/G4 HOLD",
            "No new DEV promotion is approved",
            "fourth protected service-source difference",
            "one",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, document)
        self.assertNotIn("diagnostic instrumentation has been installed", document.lower())

    def test_g_review_only_sources_do_not_change_public_wire_contract(self) -> None:
        """No new response header or internal stage is returned to the caller."""
        _, response, _ = _offline_response(wire(version=b"HTTP/1.1"))
        for forbidden in (
            b"X-Task014-Stage:",
            b"X-Rejection-Cause:",
            b"Authorization:",
            b"Set-Cookie:",
            b"Server:",
            b"Date:",
        ):
            with self.subTest(header=forbidden):
                self.assertNotIn(forbidden, response)
        self.assertTrue(response.endswith(_EXPECTED_403))


if __name__ == "__main__":
    unittest.main()
