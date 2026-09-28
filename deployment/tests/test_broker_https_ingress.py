"""C32Q's inert HTTP transport boundary and non-live reference assertions."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
import inspect
import json
from pathlib import Path
import pickle
import unittest

from deployment.broker import BrokerRejectedError, BrokerUnavailableError
from deployment.broker_https_ingress import (
    BROKER_LOOPBACK_ADDRESS, BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT,
    FORGEJO_OIDC_HEADER, PUBLIC_HOST, PUBLIC_ORIGIN, PROMOTION_PATH,
    ZOT_OIDC_HEADER, IngressRejectedError, dispatch_inert_dev_promotion_ingress,
    parse_dev_promotion_ingress,
)
from deployment.broker_integration import MAX_PROMOTION_REQUEST_BYTES
from deployment.application_source_set import DevApplicationSourceSet
from deployment.oidc_verifier import MAX_COMPACT_TOKEN_BYTES


ROOT = Path(__file__).resolve().parents[2]
NGINX = ROOT / "deployment/ingress/dev-broker-https.nginx.review.conf"
BODY = b'{"promotion":"opaque-to-ingress"}\n'
TOKENS = ("deploy.jwt.signature", "zot.jwt.signature", "forgejo.jwt.signature")


def headers(body=BODY, tokens=TOKENS):
    return [
        ("Host", PUBLIC_HOST), ("Authorization", "Bearer " + tokens[0]),
        (ZOT_OIDC_HEADER, tokens[1]), (FORGEJO_OIDC_HEADER, tokens[2]),
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(body))),
    ]


def parse(**changes):
    values = dict(method="POST", path=PROMOTION_PATH, headers=headers(),
                  body=BODY, received_at=123)
    values.update(changes)
    return parse_dev_promotion_ingress(**values)


class RecordingHandler:
    def __init__(self, result=b"opaque executor response"):
        self.calls = []
        self.result = result

    def handle(self, **kwargs):
        self.calls.append(kwargs)
        return self.result


class BrokerHTTPSIngressTests(unittest.TestCase):
    def test_closed_origin_endpoint_and_loopback(self):
        self.assertEqual(PUBLIC_ORIGIN, "https://deploy-dev.omnilyzer.ai")
        self.assertEqual(PROMOTION_PATH, "/task014/dev/promote")
        self.assertEqual(BROKER_LOOPBACK_HOST, "127.0.0.1")
        self.assertEqual(BROKER_LOOPBACK_PORT, 3031)
        self.assertEqual(BROKER_LOOPBACK_ADDRESS, "127.0.0.1:3031")
        self.assertNotIn("0.0.0.0", BROKER_LOOPBACK_ADDRESS)
        self.assertNotIn("localhost", BROKER_LOOPBACK_ADDRESS)

    def test_exact_body_and_time_reach_c32p_once(self):
        handler = RecordingHandler()
        parsed = parse()
        self.assertIs(parsed.promotion_request, BODY)
        for token in TOKENS:
            self.assertNotIn(token.encode("ascii"), BODY)
        response = dispatch_inert_dev_promotion_ingress(
            handler, method="POST", path=PROMOTION_PATH,
            headers=headers(), body=BODY, received_at=123,
        )
        self.assertEqual(response.status, 202)
        self.assertEqual(response.body, b'{"status":"accepted"}\n')
        self.assertEqual(handler.calls, [dict(
            compact_token=TOKENS[0], zot_token=TOKENS[1],
            forgejo_token=TOKENS[2], promotion_request=BODY,
            received_at=123,
        )])
        self.assertIs(handler.calls[0]["promotion_request"], BODY)

    def test_methods_routes_and_query_are_closed(self):
        for method in ("GET", "PUT", "PATCH", "DELETE", "post", ""):
            with self.subTest(method=method), self.assertRaises(IngressRejectedError):
                parse(method=method)
        for path in ("/", PROMOTION_PATH + "?x=1", PROMOTION_PATH + "#x",
                     PROMOTION_PATH + "/", "https://deploy-dev.omnilyzer.ai" + PROMOTION_PATH):
            with self.subTest(path=path), self.assertRaises(IngressRejectedError):
                parse(path=path)

    def test_header_duplicates_and_extra_authority_rejected(self):
        for extra in (("authorization", "Bearer duplicate"),
                      (ZOT_OIDC_HEADER.lower(), TOKENS[1]),
                      ("X-Forwarded-Host", "other.example"),
                      ("Proxy-Authorization", "Bearer extra"),
                      ("Cookie", "session=secret"),
                      ("Origin", "https://other.example"),
                      ("Transfer-Encoding", "chunked"),
                      ("Content-Encoding", "gzip")):
            with self.subTest(extra=extra[0]), self.assertRaises(IngressRejectedError):
                parse(headers=headers() + [extra])
        with self.assertRaises(IngressRejectedError):
            parse(headers=dict(headers()))  # mappings erase duplicates
        with self.assertRaises(IngressRejectedError):
            parse(headers=headers()[:-1])
        supplied = headers()
        supplied[0] = ("Host", "other.example")
        with self.assertRaises(IngressRejectedError):
            parse(headers=supplied)
        supplied = headers()
        supplied[2] = ("X-Omnilyzer-Zot-OIDC\r\nInjected", TOKENS[1])
        with self.assertRaises(IngressRejectedError):
            parse(headers=supplied)
        supplied = headers()
        supplied[1] = ("Authorization", "Bearer " + "x" * (MAX_COMPACT_TOKEN_BYTES + 1))
        with self.assertRaises(IngressRejectedError):
            parse(headers=supplied)

    def test_authorization_and_token_value_rejections(self):
        for value in ("Basic abc", "bearer " + TOKENS[0],
                      "Bearer  " + TOKENS[0], "Bearer ",
                      "Bearer " + TOKENS[0] + ",other", "Bearer a\r\nb"):
            supplied = headers()
            supplied[1] = ("Authorization", value)
            with self.subTest(value=value[:16]), self.assertRaises(IngressRejectedError):
                parse(headers=supplied)
        for index in (1, 2, 3):
            for value in ("", "a,b", "é", "x" * (MAX_COMPACT_TOKEN_BYTES + 1),
                          "a\nb", "a\tb", "a\x7fb"):
                supplied = headers()
                supplied[index] = (supplied[index][0], value if index != 1 else "Bearer " + value)
                with self.subTest(index=index, length=len(value)), self.assertRaises(IngressRejectedError):
                    parse(headers=supplied)

    def test_body_and_framing_rejections(self):
        for body in (b"", b"x" * (MAX_PROMOTION_REQUEST_BYTES + 1),
                     bytearray(BODY)):
            with self.subTest(length=len(body)), self.assertRaises(IngressRejectedError):
                parse(body=body)
        for length in ("0", str(len(BODY) + 1), "0" + str(len(BODY)),
                       "+" + str(len(BODY)), "NaN"):
            supplied = headers()
            supplied[-1] = ("Content-Length", length)
            with self.subTest(length=length), self.assertRaises(IngressRejectedError):
                parse(headers=supplied)
        supplied = headers()
        supplied[-2] = ("Content-Type", "application/json; charset=utf-8")
        with self.assertRaises(IngressRejectedError):
            parse(headers=supplied)
        for received_at in (True, -1, "123"):
            with self.assertRaises(IngressRejectedError):
                parse(received_at=received_at)

    def test_redaction_immutability_and_fixed_errors(self):
        parsed = parse()
        for token in TOKENS:
            self.assertNotIn(token, repr(parsed))
            self.assertNotIn(token, str(parsed))
        with self.assertRaises(FrozenInstanceError):
            parsed.zot_token = "replacement"
        with self.assertRaises(TypeError):
            pickle.dumps(parsed)
        with self.assertRaises(IngressRejectedError) as caught:
            parse(headers=headers() + [("Cookie", "secret")])
        self.assertEqual(str(caught.exception), "deployment ingress request is not accepted")

    def test_fixed_small_response_mapping(self):
        for error, status, body in (
            (BrokerRejectedError("secret"), 403, b'{"status":"rejected"}\n'),
            (BrokerUnavailableError("secret"), 503, b'{"status":"unavailable"}\n'),
            (RuntimeError("secret"), 503, b'{"status":"unavailable"}\n'),
        ):
            class Failing:
                def handle(self, **kwargs):
                    raise error
            result = dispatch_inert_dev_promotion_ingress(
                Failing(), method="POST", path=PROMOTION_PATH,
                headers=headers(), body=BODY, received_at=123,
            )
            self.assertEqual((result.status, result.body), (status, body))
            self.assertNotIn(b"secret", result.body)
        rejected = dispatch_inert_dev_promotion_ingress(
            RecordingHandler(), method="GET", path=PROMOTION_PATH,
            headers=headers(), body=BODY, received_at=123,
        )
        self.assertEqual(rejected.status, 403)
        invalid = dispatch_inert_dev_promotion_ingress(
            RecordingHandler(result="wrong"), method="POST", path=PROMOTION_PATH,
            headers=headers(), body=BODY, received_at=123,
        )
        self.assertEqual(invalid.status, 503)
        with self.assertRaises(TypeError):
            type(invalid)(200, b"secret")

    def test_review_only_nginx_is_exact_and_secret_free(self):
        config = NGINX.read_text()
        self.assertIn("server_name deploy-dev.omnilyzer.ai;", config)
        self.assertIn("listen 443 ssl;", config)
        self.assertIn("location = /task014/dev/promote {", config)
        self.assertIn("proxy_pass http://127.0.0.1:3031;", config)
        self.assertEqual(config.count("proxy_pass http://"), 1)
        for needle in ("access_log off;", 'add_header Cache-Control "no-store" always;',
                       "proxy_cache off;", "proxy_request_buffering off;",
                       "proxy_pass_request_headers off;", "client_max_body_size 4096;",
                       "proxy_set_header Authorization $http_authorization;",
                       "proxy_set_header X-Omnilyzer-Zot-OIDC $http_x_omnilyzer_zot_oidc;",
                       "proxy_set_header X-Omnilyzer-Forgejo-OIDC $http_x_omnilyzer_forgejo_oidc;"):
            self.assertIn(needle, config)
        for forbidden in ("access_log /", "ssl_certificate /",
                          "listen 80", "X-Forwarded-For", "X-Forwarded-Host",
                          "add_header Access-Control-Allow-Origin", "return 301", "return 302"):
            self.assertNotIn(forbidden, config)

    def test_no_listener_activation_or_history_change(self):
        source = (ROOT / "deployment/broker_https_ingress.py").read_text()
        tree = ast.parse(source)
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertFalse(imports.intersection({"socket", "http.server", "ssl", "subprocess"}))
        self.assertNotIn("bind(", source)
        self.assertNotIn("listen(", source)
        environment = json.loads((ROOT / "deployment/environments/dev.json").read_text())
        self.assertIs(environment["activation"]["deployment_enabled"], False)
        self.assertEqual(len(inspect.signature(parse_dev_promotion_ingress).parameters), 5)
        selected = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(selected), 41)
        self.assertIn("deployment/broker_https_ingress.py", selected)


if __name__ == "__main__":
    unittest.main()
