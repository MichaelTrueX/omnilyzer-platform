from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
import ssl
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa

from deployment.jwks import (
    DISCOVERY_PATH,
    JWKS_PATH,
    JWKS_URL,
    OIDC_HOST,
    OIDC_ISSUER,
    OIDC_PORT,
    GitHubJWKSCache,
    GitHubOIDCHTTPSFetcher,
    HTTPDocument,
    OIDCVerificationError,
    OIDCVerificationUnavailable,
    validate_discovery,
    validate_jwks,
)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def integer(value: int) -> str:
    return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def jwk(key: rsa.RSAPrivateKey, kid: str = "key-1", **updates: object) -> dict[str, object]:
    numbers = key.public_key().public_numbers()
    value: dict[str, object] = {
        "kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
        "n": integer(numbers.n), "e": integer(numbers.e),
    }
    value.update(updates)
    return value


def jwks_bytes(*keys: dict[str, object]) -> bytes:
    return json.dumps({"keys": list(keys)}, separators=(",", ":")).encode()


def discovery_bytes(**updates: object) -> bytes:
    value: dict[str, object] = {
        "issuer": OIDC_ISSUER,
        "jwks_uri": JWKS_URL,
        "id_token_signing_alg_values_supported": ["RS256"],
        "unknown_bounded_metadata": True,
    }
    value.update(updates)
    return json.dumps(value, separators=(",", ":")).encode()


class SequenceFetcher:
    def __init__(self, rounds: list[tuple[HTTPDocument, HTTPDocument]]) -> None:
        self.rounds = list(rounds)
        self.discovery_calls = 0
        self.jwks_calls = 0

    def fetch_discovery(self) -> HTTPDocument:
        self.discovery_calls += 1
        if not self.rounds:
            raise OIDCVerificationUnavailable("synthetic")
        return self.rounds[0][0]

    def fetch_jwks(self) -> HTTPDocument:
        self.jwks_calls += 1
        _, result = self.rounds.pop(0)
        return result


def round_for(keys: bytes, ttl: int = 300) -> tuple[HTTPDocument, HTTPDocument]:
    return HTTPDocument(discovery_bytes(), ttl), HTTPDocument(keys, ttl)


class JWKSValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def reject(self, value: dict[str, object]) -> None:
        with self.assertRaises(OIDCVerificationError):
            validate_jwks(jwks_bytes(value))

    def test_valid_rsa_key(self) -> None:
        result = validate_jwks(jwks_bytes(jwk(self.key)))
        self.assertEqual(set(result), {"key-1"})
        self.assertEqual(result["key-1"].public_numbers(), self.key.public_key().public_numbers())

    def test_nonminimal_modulus_and_exponent_base64url_uint_are_rejected(self) -> None:
        canonical = jwk(self.key)
        modulus = base64.urlsafe_b64decode(str(canonical["n"]) + "==")
        nonminimal_modulus = dict(canonical)
        nonminimal_modulus["n"] = b64url(b"\x00" + modulus)
        self.reject(nonminimal_modulus)

        exponent = base64.urlsafe_b64decode(str(canonical["e"]) + "==")
        self.assertEqual(exponent, b"\x01\x00\x01")
        nonminimal_exponent = dict(canonical)
        nonminimal_exponent["e"] = b64url(b"\x00" + exponent)
        self.assertEqual(len(base64.urlsafe_b64decode(str(nonminimal_exponent["e"]) + "==")), 4)
        self.reject(nonminimal_exponent)

    def test_optional_bounded_certificate_metadata_is_accepted_but_ignored(self) -> None:
        value = jwk(
            self.key,
            x5c=[base64.b64encode(b"bounded synthetic certificate").decode()],
            x5t=b64url(b"a" * 20),
            **{"x5t#S256": b64url(b"b" * 32)},
        )
        result = validate_jwks(jwks_bytes(value))
        self.assertEqual(result["key-1"].public_numbers(), self.key.public_key().public_numbers())

    def test_duplicate_kid_and_duplicate_material_are_rejected(self) -> None:
        with self.assertRaises(OIDCVerificationError):
            validate_jwks(jwks_bytes(jwk(self.key), jwk(self.other)))
        with self.assertRaises(OIDCVerificationError):
            validate_jwks(jwks_bytes(jwk(self.key), jwk(self.key, "key-2")))

    def test_wrong_key_contract_is_rejected(self) -> None:
        for field, value in (("kty", "EC"), ("use", "enc"), ("alg", "PS256")):
            changed = jwk(self.key)
            changed[field] = value
            with self.subTest(field=field):
                self.reject(changed)

    def test_weak_and_excessive_modulus_are_rejected(self) -> None:
        weak = jwk(self.key)
        weak["n"] = integer((1 << 1023) | 1)
        self.reject(weak)
        excessive = jwk(self.key)
        excessive["n"] = integer((1 << 4096) | 1)
        self.reject(excessive)

    def test_invalid_exponents_and_encodings_are_rejected(self) -> None:
        for exponent in (0, 2, 2**32 + 1):
            value = jwk(self.key)
            value["e"] = integer(exponent) if exponent else "AA"
            with self.subTest(exponent=exponent):
                self.reject(value)
        for field, value in (("n", "bad="), ("n", "*"), ("e", "A")):
            changed = jwk(self.key)
            changed[field] = value
            with self.subTest(field=field, value=value):
                self.reject(changed)

    def test_empty_too_many_unknown_and_partial_sets_are_rejected(self) -> None:
        with self.assertRaises(OIDCVerificationError):
            validate_jwks(jwks_bytes())
        many = [jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048), f"key-{i}") for i in range(17)]
        with self.assertRaises(OIDCVerificationError):
            validate_jwks(jwks_bytes(*many))
        unknown = jwk(self.key)
        unknown["unexpected"] = True
        self.reject(unknown)
        malformed = jwk(self.other, "key-2")
        malformed["use"] = "enc"
        with self.assertRaises(OIDCVerificationError):
            validate_jwks(jwks_bytes(jwk(self.key), malformed))


class DiscoveryTests(unittest.TestCase):
    def test_exact_discovery_passes_with_unknown_bounded_metadata(self) -> None:
        validate_discovery(discovery_bytes())

    def test_wrong_issuer_jwks_or_missing_rs256_fails(self) -> None:
        cases = (
            {"issuer": "https://example.invalid"},
            {"jwks_uri": OIDC_ISSUER + "/other"},
            {"id_token_signing_alg_values_supported": ["PS256"]},
        )
        for updates in cases:
            with self.subTest(updates=updates), self.assertRaises(OIDCVerificationError):
                validate_discovery(discovery_bytes(**updates))

    def test_duplicate_and_oversized_discovery_fails(self) -> None:
        duplicate = b'{"issuer":"a","issuer":"b","jwks_uri":"x","id_token_signing_alg_values_supported":["RS256"]}'
        with self.assertRaises(OIDCVerificationError):
            validate_discovery(duplicate)
        with self.assertRaises(OIDCVerificationError):
            validate_discovery(b"{" + b" " * (16 * 1024))


class FakeResponse:
    def __init__(self, *, status: int = 200, headers: list[tuple[str, str]] | None = None, body: bytes = b"{}", read_error: Exception | None = None, close_error: Exception | None = None) -> None:
        self.status = status
        self.headers = headers or [("Content-Type", "application/json"), ("Cache-Control", "max-age=30")]
        self.body = body
        self.read_error = read_error
        self.close_error = close_error
        self.closed = False
        self.read_amount = None

    def getheaders(self) -> list[tuple[str, str]]:
        return self.headers

    def read(self, amount: int | None = None) -> bytes:
        self.read_amount = amount
        if self.read_error:
            raise self.read_error
        return self.body if amount is None else self.body[:amount]

    def close(self) -> None:
        self.closed = True
        if self.close_error:
            raise self.close_error


class FakeConnection:
    def __init__(self, response: FakeResponse, request_error: Exception | None = None, close_error: Exception | None = None) -> None:
        self.response = response
        self.request_error = request_error
        self.close_error = close_error
        self.request_args = None
        self.closed = False

    def request(self, method: str, url: str, body: None = None, headers=None) -> None:
        self.request_args = (method, url, body, headers)
        if self.request_error:
            raise self.request_error

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True
        if self.close_error:
            raise self.close_error


class HTTPSFetcherTests(unittest.TestCase):
    def factory(self, response: FakeResponse, request_error: Exception | None = None, close_error: Exception | None = None):
        observed: dict[str, object] = {}
        connection = FakeConnection(response, request_error, close_error)
        def create(host: str, port: int, timeout: float, context: ssl.SSLContext):
            observed.update(host=host, port=port, timeout=timeout, context=context)
            return connection
        return GitHubOIDCHTTPSFetcher(create), connection, observed

    def test_tls_bootstrap_failures_are_normalized_before_connection(self) -> None:
        expected = "OIDC verification metadata is unavailable"
        for operation in ("construct", "load"):
            calls = 0

            def forbidden_factory(*args):
                nonlocal calls
                calls += 1
                raise AssertionError("connection-factory-marker")

            fetcher = GitHubOIDCHTTPSFetcher(forbidden_factory)
            marker = f"synthetic-{operation}-marker"
            if operation == "construct":
                patched = patch(
                    "deployment.jwks.ssl.SSLContext",
                    side_effect=ssl.SSLError(marker),
                )
            else:
                class FailedContext:
                    def load_verify_locations(self, *, cafile: str) -> None:
                        raise OSError(marker)

                patched = patch(
                    "deployment.jwks.ssl.SSLContext",
                    return_value=FailedContext(),
                )
            with self.subTest(operation=operation), patched:
                with self.assertRaises(OIDCVerificationUnavailable) as captured:
                    fetcher.fetch_discovery()
                self.assertEqual(str(captured.exception), expected)
                self.assertNotIn(marker, str(captured.exception))
                self.assertNotIn("ca-certificates", str(captured.exception))
                self.assertEqual(calls, 0)

    def test_fixed_host_paths_get_tls_and_no_proxy_inheritance(self) -> None:
        response = FakeResponse(body=discovery_bytes())
        fetcher, connection, observed = self.factory(response)
        with patch.dict(os.environ, {
            "HTTPS_PROXY": "http://attacker.invalid:8080",
            "SSL_CERT_FILE": "/attacker/ca.pem",
            "SSLKEYLOGFILE": "/attacker/keylog",
        }):
            document = fetcher.fetch_discovery()
        self.assertEqual(document.cache_ttl, 30)
        self.assertEqual((observed["host"], observed["port"]), (OIDC_HOST, OIDC_PORT))
        self.assertEqual(connection.request_args[:3], ("GET", DISCOVERY_PATH, None))
        context = observed["context"]
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertTrue(response.closed)
        self.assertTrue(connection.closed)

    def test_jwks_uses_only_fixed_path_and_limit_plus_one(self) -> None:
        response = FakeResponse()
        fetcher, connection, _ = self.factory(response)
        fetcher.fetch_jwks()
        self.assertEqual(connection.request_args[1], JWKS_PATH)
        self.assertEqual(response.read_amount, 64 * 1024 + 1)

    def test_cache_control_can_only_shorten_reuse(self) -> None:
        for directive, expected in (
            ("max-age=10", 10), ("max-age=999", 300),
            ("no-cache", 0), ("no-store", 0), ("max-age=invalid", 0),
        ):
            response = FakeResponse(headers=[
                ("Content-Type", "application/json"),
                ("Cache-Control", directive),
            ])
            fetcher, _, _ = self.factory(response)
            with self.subTest(directive=directive):
                self.assertEqual(fetcher.fetch_discovery().cache_ttl, expected)

    def test_redirect_status_content_type_and_oversize_fail_closed(self) -> None:
        cases = (
            FakeResponse(status=302),
            FakeResponse(status=500),
            FakeResponse(headers=[("Content-Type", "text/plain")]),
            FakeResponse(body=b"x" * (16 * 1024 + 1)),
            FakeResponse(headers=[("X", "x") for _ in range(65)]),
        )
        for response in cases:
            fetcher, connection, _ = self.factory(response)
            with self.subTest(status=response.status), self.assertRaises(OIDCVerificationUnavailable):
                fetcher.fetch_discovery()
            self.assertTrue(response.closed)
            self.assertTrue(connection.closed)

    def test_read_tls_and_timeout_failures_close_connections(self) -> None:
        for response, request_error in (
            (FakeResponse(read_error=OSError("truncated")), None),
            (FakeResponse(), ssl.SSLError("TLS")),
        ):
            fetcher, connection, _ = self.factory(response, request_error)
            with self.assertRaises(OIDCVerificationUnavailable):
                fetcher.fetch_discovery()
            self.assertTrue(connection.closed)
        response = FakeResponse()
        fetcher, connection, _ = self.factory(response)
        with patch("deployment.jwks.time.monotonic", side_effect=[0.0, 7.0]):
            with self.assertRaises(OIDCVerificationUnavailable):
                fetcher.fetch_discovery()
        self.assertTrue(connection.closed)

    def test_response_and_connection_close_failures_are_normalized(self) -> None:
        expected = "OIDC verification metadata is unavailable"
        cases = (
            (FakeResponse(close_error=OSError("response-close-marker")), None),
            (FakeResponse(), OSError("connection-close-marker")),
        )
        for response, close_error in cases:
            fetcher, connection, _ = self.factory(response, close_error=close_error)
            with self.assertRaises(OIDCVerificationUnavailable) as captured:
                fetcher.fetch_discovery()
            self.assertEqual(str(captured.exception), expected)
            self.assertNotIn("marker", str(captured.exception))
            self.assertTrue(response.closed)
            self.assertTrue(connection.closed)


class CacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.first = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.second = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self) -> None:
        self.now = 1000.0

    def cache(self, fetcher: SequenceFetcher) -> GitHubJWKSCache:
        return GitHubJWKSCache(fetcher, lambda: self.now)

    def test_cold_start_cache_hit_and_ttl_expiry(self) -> None:
        fetcher = SequenceFetcher([round_for(jwks_bytes(jwk(self.first))), round_for(jwks_bytes(jwk(self.first)))])
        cache = self.cache(fetcher)
        cache.get_key("key-1")
        cache.get_key("key-1")
        self.assertEqual(fetcher.jwks_calls, 1)
        self.now += 301
        cache.get_key("key-1")
        self.assertEqual(fetcher.jwks_calls, 2)

    def test_short_ttl_cap_and_no_store_no_cache(self) -> None:
        for ttl, advance, expected_calls in ((10, 11, 2), (999, 301, 2), (0, 0, 2)):
            fetcher = SequenceFetcher([round_for(jwks_bytes(jwk(self.first)), ttl), round_for(jwks_bytes(jwk(self.first)), ttl)])
            cache = self.cache(fetcher)
            cache.get_key("key-1")
            self.now += advance
            cache.get_key("key-1")
            self.assertEqual(fetcher.jwks_calls, expected_calls)

    def test_unknown_kid_one_refresh_success_and_absence(self) -> None:
        fetcher = SequenceFetcher([
            round_for(jwks_bytes(jwk(self.first))),
            round_for(jwks_bytes(jwk(self.first), jwk(self.second, "key-2"))),
        ])
        cache = self.cache(fetcher)
        cache.get_key("key-1")
        cache.get_key("key-2")
        self.assertEqual(fetcher.jwks_calls, 2)
        absent = SequenceFetcher([
            round_for(jwks_bytes(jwk(self.first))),
            round_for(jwks_bytes(jwk(self.first))),
        ])
        other = self.cache(absent)
        other.get_key("key-1")
        with self.assertRaises(OIDCVerificationError):
            other.get_key("key-2")
        self.assertEqual(absent.jwks_calls, 2)

    def test_failed_unknown_refresh_preserves_valid_known_key(self) -> None:
        malformed = b'{"keys":[{"bad":true}]}'
        fetcher = SequenceFetcher([
            round_for(jwks_bytes(jwk(self.first))),
            round_for(malformed),
        ])
        cache = self.cache(fetcher)
        original = cache.get_key("key-1")
        with self.assertRaises(OIDCVerificationUnavailable):
            cache.get_key("key-2")
        self.assertIs(cache.get_key("key-1"), original)

    def test_expired_stale_cache_is_never_used_and_removed_key_stays_removed(self) -> None:
        malformed = b'{"keys":[]}'
        fetcher = SequenceFetcher([
            round_for(jwks_bytes(jwk(self.first)), 1),
            round_for(malformed),
        ])
        cache = self.cache(fetcher)
        cache.get_key("key-1")
        self.now += 2
        with self.assertRaises(OIDCVerificationUnavailable):
            cache.get_key("key-1")
        rotation = SequenceFetcher([
            round_for(jwks_bytes(jwk(self.first)), 1),
            round_for(jwks_bytes(jwk(self.second, "key-2"))),
        ])
        cache = self.cache(rotation)
        cache.get_key("key-1")
        self.now += 2
        with self.assertRaises(OIDCVerificationError):
            cache.get_key("key-1")

    def test_overlapping_rotation_accepts_both_until_replacement(self) -> None:
        fetcher = SequenceFetcher([
            round_for(jwks_bytes(jwk(self.first)), 1),
            round_for(jwks_bytes(jwk(self.first), jwk(self.second, "key-2"))),
        ])
        cache = self.cache(fetcher)
        cache.get_key("key-1")
        self.now += 2
        cache.get_key("key-2")
        cache.get_key("key-1")

    def test_cold_failure_fails_closed(self) -> None:
        cache = self.cache(SequenceFetcher([]))
        with self.assertRaises(OIDCVerificationUnavailable):
            cache.get_key("key-1")

    def test_concurrent_cold_refresh_is_single_flight(self) -> None:
        release = threading.Event()
        entered = threading.Event()
        key = self.first
        class BlockingFetcher:
            discovery_calls = 0
            jwks_calls = 0
            def fetch_discovery(inner_self):
                inner_self.discovery_calls += 1
                entered.set()
                release.wait(timeout=2)
                return HTTPDocument(discovery_bytes(), 300)
            def fetch_jwks(inner_self):
                inner_self.jwks_calls += 1
                return HTTPDocument(jwks_bytes(jwk(key)), 300)
        fetcher = BlockingFetcher()
        cache = GitHubJWKSCache(fetcher, lambda: self.now)
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(cache.get_key, "key-1") for _ in range(8)]
            self.assertTrue(entered.wait(timeout=2))
            release.set()
            results = [future.result(timeout=2) for future in futures]
        self.assertEqual(len(results), 8)
        self.assertEqual((fetcher.discovery_calls, fetcher.jwks_calls), (1, 1))


if __name__ == "__main__":
    unittest.main()
