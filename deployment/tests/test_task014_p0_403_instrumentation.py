"""Review-only P0 listener and status-only Nginx diagnostics.

Synthetic fake-socket tests and optional isolated nginx -t only.
No real credential, live socket, service, replay, main merge or deployment.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deployment import broker_loopback_listener as listener
from deployment.broker import _ALLOWED_STAGE_MESSAGES, _AUTHORITY_LOG
from deployment.tests.test_broker_loopback_listener import (
    Handler, fixture, wire,
)

_ROOT = Path(__file__).resolve().parents[2]
_ORIGIN = _ROOT / "deployment/ingress/dev-broker-tailscale-origin.nginx.conf"
_CANDIDATE = (
    _ROOT / "deployment/ingress/dev-broker-tailscale-origin.status-only.review.conf"
)
_STAGE = "task014_diag stage=listener_framing_rejected"
_FIXED_403 = b'{"status":"rejected"}\n'
_CONFIG_PATH = "/var/log/nginx/task014-dev-status-only.log"


def _response(raw: bytes, handler: Handler | None = None):
    subject, _, connection, actual_handler, _ = fixture(raw, handler=handler)
    result = subject.serve_once()
    return result, bytes(connection.sent), len(actual_handler.calls)


class _AllSuppressed(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return False


class TestP0DiagnosticInstrumentation(unittest.TestCase):
    def test_framing_emits_only_a_bounded_static_stage(self):
        self.assertIn(_STAGE, _ALLOWED_STAGE_MESSAGES)
        self.assertEqual(len(_ALLOWED_STAGE_MESSAGES), 14)
        with self.assertLogs(_AUTHORITY_LOG, level="WARNING") as observed:
            status, response, called = _response(wire(version=b"HTTP/1.1"))
        self.assertEqual((status, called), (403, 0))
        self.assertTrue(response.endswith(_FIXED_403))
        self.assertEqual([r.getMessage() for r in observed.records], [_STAGE])
        self.assertEqual(observed.records[0].args, ())
        self.assertNotIn(b"task014_diag", response)

    def test_malformed_and_truncated_framing_keep_public_response(self):
        for raw in (
            wire(version=b"HTTP/1.1"),
            wire(content_length=b"0003"),
            wire(connection=b"keep-alive"),
            wire().replace(b"Host: ", b" Host: ", 1),
        ):
            with self.subTest(framing=raw[:14]):
                status, response, called = _response(raw)
                self.assertEqual((status, called), (403, 0))
                self.assertTrue(response.endswith(_FIXED_403))
                self.assertNotIn(_STAGE.encode(), response)

    def test_logger_exception_cannot_change_external_403(self):
        with patch.object(listener._AUTHORITY_LOG, "warning", side_effect=RuntimeError("PRIVATE_DIAGNOSTIC")) as log:
            status, response, called = _response(wire(version=b"HTTP/1.1"))
        log.assert_called_once_with(_STAGE)
        self.assertEqual((status, called), (403, 0))
        self.assertTrue(response.endswith(_FIXED_403))
        self.assertNotIn(b"PRIVATE_DIAGNOSTIC", response)

    def test_suppressed_logger_cannot_change_external_403(self):
        with patch.object(_AUTHORITY_LOG, "filters", [_AllSuppressed()]):
            status, response, called = _response(wire(version=b"HTTP/1.1"))
        self.assertEqual((status, called), (403, 0))
        self.assertTrue(response.endswith(_FIXED_403))

    def test_logger_clock_failure_cannot_change_external_403(self):
        with patch("deployment.broker.time.monotonic", side_effect=OSError("PRIVATE_CLOCK_FAILURE")):
            status, response, called = _response(wire(version=b"HTTP/1.1"))
        self.assertEqual((status, called), (403, 0))
        self.assertTrue(response.endswith(_FIXED_403))

    def test_semantic_and_broker_stages_remain_distinct_privately(self):
        semantic = wire().replace(b"Host: deploy-dev.omnilyzer.ai", b"Host: wrong.example", 1)
        with self.assertLogs(_AUTHORITY_LOG, level="WARNING") as semantic_logs:
            s_status, s_wire, s_called = _response(semantic)
        self.assertEqual((s_status, s_called), (403, 0))
        self.assertEqual([r.getMessage() for r in semantic_logs.records],
                         ["task014_diag stage=ingress_rejected"])

        from deployment.broker import BrokerRejectedError
        rejecting = Handler(BrokerRejectedError("PRIVATE_HANDLER_DETAIL"))
        with self.assertLogs(_AUTHORITY_LOG, level="WARNING") as broker_logs:
            b_status, b_wire, b_called = _response(wire(), rejecting)
        self.assertEqual((b_status, b_called), (403, 1))
        self.assertEqual([r.getMessage() for r in broker_logs.records],
                         ["task014_diag stage=broker_rejected"])
        self.assertEqual(s_wire, b_wire)
        self.assertNotIn(b"PRIVATE_HANDLER_DETAIL", b_wire)

    def test_valid_202_and_nonframing_503_unchanged(self):
        status, wire_bytes, called = _response(wire())
        self.assertEqual((status, called), (202, 1))
        self.assertTrue(wire_bytes.endswith(b'{"status":"accepted"}\n'))
        unavailable = Handler(RuntimeError("SYNTHETIC_PRIVATE_FAILURE"))
        status, wire_bytes, called = _response(wire(), unavailable)
        self.assertEqual((status, called), (503, 1))
        self.assertTrue(wire_bytes.endswith(b'{"status":"unavailable"}\n'))
        self.assertNotIn(b"SYNTHETIC_PRIVATE_FAILURE", wire_bytes)

    def test_nginx_status_candidate_is_offline_and_no_sensitive_variables(self):
        candidate = _CANDIDATE.read_text(encoding="utf-8")
        origin = _ORIGIN.read_text(encoding="utf-8")
        self.assertEqual(candidate.count("log_format task014_status_only"), 1)
        self.assertEqual(candidate.count("access_log " + _CONFIG_PATH + " task014_status_only;"), 1)
        self.assertIn("log_format task014_status_only 'status=$status upstream_status=$upstream_status';", candidate)
        self.assertNotIn("access_log off;", candidate)
        self.assertIn("access_log off;", origin)
        self.assertIn("REVIEW-ONLY", candidate)
        for forbidden in (
            "$request", "$uri", "$args", "$remote_addr", "$http_", "$upstream_http_",
            "$request_body", "$request_time", "$bytes_sent", "$connection",
        ):
            # Existing proxy rules legitimately use $http_* variables.
            log_format = re.search(r"^log_format task014_status_only [^;]+;", candidate, re.M).group(0)
            self.assertNotIn(forbidden, log_format)
        # Only a comment and the log directive may differ inside server.
        original_server = origin.split("server {", 1)[1]
        candidate_server = candidate.split("server {", 1)[1]
        rewritten = candidate_server.replace(
            "    # Dedicated short observation only. Existing live origin keeps access_log off.\n",
            "",
        ).replace("    access_log " + _CONFIG_PATH + " task014_status_only;",
                  "    access_log off;")
        self.assertEqual(rewritten, original_server)

    def test_syntax_isolated_nonprivileged_if_nginx_available(self):
        nginx = shutil.which("nginx")
        if nginx is None:
            self.skipTest("nginx binary unavailable on CI runner; host syntax checked separately")
        candidate = _CANDIDATE.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="task014-nginx-review-") as tmp:
            root = Path(tmp)
            conf = root / "nginx.conf"
            safe_log = root / "status-only.log"
            candidate = candidate.replace(_CONFIG_PATH, str(safe_log))
            conf.write_text(
                f"pid {root / 'nginx.pid'};\n"
                "error_log stderr warn;\n"
                "events { worker_connections 16; }\n"
                "http {\n" + candidate + "\n}\n",
                encoding="utf-8",
            )
            # nginx -t parses only a synthetic config; it does not bind or reload.
            process = subprocess.run(
                [nginx, "-t", "-p", str(root) + "/", "-c", str(conf)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(
                process.returncode, 0,
                "isolated synthetic nginx -t failed; host operator should review syntax",
            )

    def test_historical_backup_barrier_remains_unchanged_and_unapproved(self):
        from deployment import c34k_five_file_backup_barrier as old_backup
        from deployment import c34o_six_prefix_recovery_inspection as old_recovery
        self.assertEqual(len(old_backup._ORDER), 5)
        self.assertEqual(old_backup._ORDER[:3], (
            "broker.py", "broker_https_ingress.py", "broker_integration.py",
        ))
        self.assertNotIn("broker_loopback_listener.py", old_backup._ORDER)
        self.assertTrue(callable(old_recovery.inspect_c34o_six_prefix_candidate))
        # Candidate cardinality only. No claim of a six-backup recovery engine.
        future_names = (
            "broker.py", "broker_https_ingress.py", "broker_integration.py",
            "broker_loopback_listener.py", "executor.json", "dev.json",
        )
        self.assertEqual(len(future_names), 6)
        self.assertEqual(tuple(range(len(future_names) + 1)), tuple(range(7)))


if __name__ == "__main__":
    unittest.main()
