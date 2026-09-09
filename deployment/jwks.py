"""Bounded GitHub OIDC discovery, HTTPS, JWKS, and memory-cache boundary."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import http.client
import json
import math
import re
import ssl
import threading
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from cryptography.hazmat.primitives.asymmetric import rsa


OIDC_ISSUER = "https://token.actions.githubusercontent.com"
DISCOVERY_PATH = "/.well-known/openid-configuration"
DISCOVERY_URL = OIDC_ISSUER + DISCOVERY_PATH
JWKS_PATH = "/.well-known/jwks"
JWKS_URL = OIDC_ISSUER + JWKS_PATH
OIDC_HOST = "token.actions.githubusercontent.com"
OIDC_PORT = 443
SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

CONNECT_TIMEOUT_SECONDS = 3.0
READ_TIMEOUT_SECONDS = 3.0
DISCOVERY_BODY_LIMIT = 16 * 1024
JWKS_BODY_LIMIT = 64 * 1024
MAX_RESPONSE_HEADERS = 64
MAX_RESPONSE_HEADER_BYTES = 16 * 1024
MAX_CACHE_TTL_SECONDS = 300
MAX_JSON_DEPTH = 4
MAX_JSON_NODES = 1024
MAX_JSON_ARRAY = 64
MAX_JSON_STRING = 16 * 1024
MAX_JWKS_KEYS = 16
MAX_CERTIFICATES = 4
MAX_CERTIFICATE_TEXT = 16 * 1024
MAX_KID_LENGTH = 128
MAX_EXPONENT = 2**32 - 1

_SAFE_KID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")


class OIDCVerificationError(Exception):
    """OIDC material is invalid or does not authorize the fixed identity."""


class OIDCVerificationUnavailable(OIDCVerificationError):
    """Required OIDC verification material cannot be obtained safely."""


class _DuplicateMember(ValueError):
    pass


def _closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise _DuplicateMember
        result[name] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError


def _walk_json(
    value: Any, *, depth: int, maximum_depth: int, maximum_nodes: int,
    maximum_array: int, maximum_string: int, counter: list[int],
) -> None:
    counter[0] += 1
    if counter[0] > maximum_nodes or depth > maximum_depth:
        raise ValueError
    if isinstance(value, str):
        if len(value) > maximum_string:
            raise ValueError
        return
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError
        return
    if isinstance(value, list):
        if len(value) > maximum_array:
            raise ValueError
        for item in value:
            _walk_json(
                item, depth=depth + 1, maximum_depth=maximum_depth,
                maximum_nodes=maximum_nodes, maximum_array=maximum_array,
                maximum_string=maximum_string, counter=counter,
            )
        return
    if isinstance(value, dict):
        for name, item in value.items():
            if not isinstance(name, str) or len(name) > maximum_string:
                raise ValueError
            _walk_json(
                item, depth=depth + 1, maximum_depth=maximum_depth,
                maximum_nodes=maximum_nodes, maximum_array=maximum_array,
                maximum_string=maximum_string, counter=counter,
            )
        return
    raise ValueError


def parse_bounded_json(
    raw: bytes, *, maximum_bytes: int, maximum_root_members: int,
    maximum_depth: int = MAX_JSON_DEPTH, maximum_nodes: int = MAX_JSON_NODES,
    maximum_array: int = MAX_JSON_ARRAY, maximum_string: int = MAX_JSON_STRING,
) -> dict[str, Any]:
    """Parse one bounded JSON object while rejecting duplicates and constants."""

    if not isinstance(raw, bytes) or not raw or len(raw) > maximum_bytes:
        raise OIDCVerificationError("OIDC JSON is invalid")
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(
            text, object_pairs_hook=_closed_pairs, parse_constant=_reject_constant,
        )
        if not isinstance(value, dict) or len(value) > maximum_root_members:
            raise ValueError
        _walk_json(
            value, depth=0, maximum_depth=maximum_depth,
            maximum_nodes=maximum_nodes, maximum_array=maximum_array,
            maximum_string=maximum_string, counter=[0],
        )
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise OIDCVerificationError("OIDC JSON is invalid") from None
    return value


def validate_kid(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_KID_LENGTH
        or not value.isascii()
        or _SAFE_KID.fullmatch(value) is None
        or ".." in value
    ):
        raise OIDCVerificationError("OIDC key identifier is invalid")
    return value


def decode_base64url(value: Any, *, maximum_decoded: int) -> bytes:
    if (
        not isinstance(value, str) or not value or "=" in value
        or not value.isascii() or _BASE64URL.fullmatch(value) is None
        or len(value) % 4 == 1
    ):
        raise OIDCVerificationError("OIDC key encoding is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        raise OIDCVerificationError("OIDC key encoding is invalid") from None
    if (
        not decoded or len(decoded) > maximum_decoded
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise OIDCVerificationError("OIDC key encoding is invalid")
    return decoded


@dataclass(frozen=True)
class HTTPDocument:
    body: bytes
    cache_ttl: int


class HTTPResponse(Protocol):
    status: int

    def getheaders(self) -> list[tuple[str, str]]: ...
    def read(self, amount: int | None = None) -> bytes: ...
    def close(self) -> None: ...


class HTTPSConnection(Protocol):
    def request(
        self, method: str, url: str, body: None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None: ...
    def getresponse(self) -> HTTPResponse: ...
    def close(self) -> None: ...


ConnectionFactory = Callable[[str, int, float, ssl.SSLContext], HTTPSConnection]


def _default_connection(
    host: str, port: int, timeout: float, context: ssl.SSLContext,
) -> HTTPSConnection:
    return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)


def _cache_ttl(headers: list[tuple[str, str]]) -> int:
    values = [value for name, value in headers if name.lower() == "cache-control"]
    if not values:
        return MAX_CACHE_TTL_SECONDS
    directives = [part.strip().lower() for value in values for part in value.split(",")]
    if "no-cache" in directives or "no-store" in directives:
        return 0
    ages: list[int] = []
    for directive in directives:
        if directive.startswith("max-age="):
            raw = directive.removeprefix("max-age=")
            if not raw.isdecimal():
                return 0
            ages.append(int(raw))
    return min([MAX_CACHE_TTL_SECONDS, *ages])


class GitHubOIDCHTTPSFetcher:
    """GET only the two fixed GitHub OIDC documents using validated system TLS."""

    def __init__(self, connection_factory: ConnectionFactory = _default_connection):
        self._connection_factory = connection_factory

    def fetch_discovery(self) -> HTTPDocument:
        return self._fetch(DISCOVERY_PATH, DISCOVERY_BODY_LIMIT)

    def fetch_jwks(self) -> HTTPDocument:
        return self._fetch(JWKS_PATH, JWKS_BODY_LIMIT)

    def _fetch(self, path: str, body_limit: int) -> HTTPDocument:
        connection: HTTPSConnection | None = None
        response: HTTPResponse | None = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cafile=SYSTEM_CA_BUNDLE)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            started = time.monotonic()
            connection = self._connection_factory(
                OIDC_HOST, OIDC_PORT, CONNECT_TIMEOUT_SECONDS, context,
            )
            connection.request(
                "GET", path, None,
                {"Accept": "application/json", "Host": OIDC_HOST},
            )
            response = connection.getresponse()
            if time.monotonic() - started > CONNECT_TIMEOUT_SECONDS + READ_TIMEOUT_SECONDS:
                raise TimeoutError
            headers = response.getheaders()
            if len(headers) > MAX_RESPONSE_HEADERS:
                raise ValueError
            aggregate = sum(len(str(name)) + len(str(value)) + 4 for name, value in headers)
            if aggregate > MAX_RESPONSE_HEADER_BYTES:
                raise ValueError
            if response.status != 200:
                raise ValueError
            content_types = [value for name, value in headers if name.lower() == "content-type"]
            if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError
            body = response.read(body_limit + 1)
            if not isinstance(body, bytes) or len(body) > body_limit:
                raise ValueError
            if time.monotonic() - started > CONNECT_TIMEOUT_SECONDS + READ_TIMEOUT_SECONDS:
                raise TimeoutError
            return HTTPDocument(body, _cache_ttl(headers))
        except (OSError, TimeoutError, ValueError, http.client.HTTPException):
            raise OIDCVerificationUnavailable("OIDC verification metadata is unavailable") from None
        except Exception:
            raise OIDCVerificationUnavailable("OIDC verification metadata is unavailable") from None
        finally:
            close_failed = False
            if response is not None:
                try:
                    response.close()
                except Exception:
                    close_failed = True
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    close_failed = True
            if close_failed:
                raise OIDCVerificationUnavailable(
                    "OIDC verification metadata is unavailable"
                ) from None


def validate_discovery(raw: bytes) -> None:
    value = parse_bounded_json(
        raw, maximum_bytes=DISCOVERY_BODY_LIMIT, maximum_root_members=64,
    )
    if value.get("issuer") != OIDC_ISSUER or value.get("jwks_uri") != JWKS_URL:
        raise OIDCVerificationError("OIDC discovery metadata is invalid")
    algorithms = value.get("id_token_signing_alg_values_supported")
    if (
        not isinstance(algorithms, list) or not 1 <= len(algorithms) <= 16
        or any(not isinstance(item, str) or len(item) > 32 for item in algorithms)
        or "RS256" not in algorithms
    ):
        raise OIDCVerificationError("OIDC discovery metadata is invalid")


def _validate_certificate_chain(value: Any) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_CERTIFICATES:
        raise OIDCVerificationError("OIDC certificate metadata is invalid")
    for item in value:
        if (
            not isinstance(item, str) or not item or len(item) > MAX_CERTIFICATE_TEXT
            or not item.isascii() or _BASE64.fullmatch(item) is None
        ):
            raise OIDCVerificationError("OIDC certificate metadata is invalid")
        try:
            decoded = base64.b64decode(item, validate=True)
        except (ValueError, binascii.Error):
            raise OIDCVerificationError("OIDC certificate metadata is invalid") from None
        if not 1 <= len(decoded) <= 12 * 1024:
            raise OIDCVerificationError("OIDC certificate metadata is invalid")


def _validate_thumbprint(value: Any, length: int) -> None:
    decoded = decode_base64url(value, maximum_decoded=length)
    if len(decoded) != length:
        raise OIDCVerificationError("OIDC certificate metadata is invalid")


def validate_jwks(raw: bytes) -> Mapping[str, rsa.RSAPublicKey]:
    value = parse_bounded_json(
        raw, maximum_bytes=JWKS_BODY_LIMIT, maximum_root_members=1,
        maximum_nodes=2048, maximum_array=MAX_JWKS_KEYS,
    )
    if set(value) != {"keys"}:
        raise OIDCVerificationError("OIDC JWKS is invalid")
    entries = value["keys"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_JWKS_KEYS:
        raise OIDCVerificationError("OIDC JWKS is invalid")

    required = {"kty", "alg", "use", "kid", "n", "e"}
    optional = {"x5c", "x5t", "x5t#S256"}
    keys: dict[str, rsa.RSAPublicKey] = {}
    materials: set[tuple[int, int]] = set()
    try:
        for entry in entries:
            if not isinstance(entry, dict) or not required <= set(entry) or not set(entry) <= required | optional:
                raise OIDCVerificationError("OIDC JWKS is invalid")
            if entry["kty"] != "RSA" or entry["alg"] != "RS256" or entry["use"] != "sig":
                raise OIDCVerificationError("OIDC JWKS is invalid")
            kid = validate_kid(entry["kid"])
            if kid in keys:
                raise OIDCVerificationError("OIDC JWKS is invalid")
            modulus_bytes = decode_base64url(entry["n"], maximum_decoded=512)
            exponent_bytes = decode_base64url(entry["e"], maximum_decoded=4)
            if (
                len(modulus_bytes) > 1 and modulus_bytes[0] == 0
                or len(exponent_bytes) > 1 and exponent_bytes[0] == 0
            ):
                raise OIDCVerificationError("OIDC JWKS is invalid")
            modulus = int.from_bytes(modulus_bytes, "big")
            exponent = int.from_bytes(exponent_bytes, "big")
            if not 2048 <= modulus.bit_length() <= 4096:
                raise OIDCVerificationError("OIDC JWKS is invalid")
            if exponent < 3 or exponent > MAX_EXPONENT or exponent % 2 == 0:
                raise OIDCVerificationError("OIDC JWKS is invalid")
            material = (modulus, exponent)
            if material in materials:
                raise OIDCVerificationError("OIDC JWKS is invalid")
            if "x5c" in entry:
                _validate_certificate_chain(entry["x5c"])
            if "x5t" in entry:
                _validate_thumbprint(entry["x5t"], 20)
            if "x5t#S256" in entry:
                _validate_thumbprint(entry["x5t#S256"], 32)
            keys[kid] = rsa.RSAPublicNumbers(exponent, modulus).public_key()
            materials.add(material)
    except OIDCVerificationError:
        raise
    except Exception:
        raise OIDCVerificationError("OIDC JWKS is invalid") from None
    return MappingProxyType(keys)


class DiscoveryFetcher(Protocol):
    def fetch_discovery(self) -> HTTPDocument: ...
    def fetch_jwks(self) -> HTTPDocument: ...


class GitHubJWKSCache:
    """Serialized, atomic, memory-only cache for the fixed GitHub signing keys."""

    def __init__(
        self, fetcher: DiscoveryFetcher | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetcher = fetcher or GitHubOIDCHTTPSFetcher()
        self._monotonic = monotonic
        self._condition = threading.Condition()
        self._keys: Mapping[str, rsa.RSAPublicKey] = MappingProxyType({})
        self._expires_at = 0.0
        self._refreshing = False
        self._refresh_serial = 0
        self._completed_serial = 0
        self._completed_success = False

    def get_key(self, kid: str) -> rsa.RSAPublicKey:
        requested = validate_kid(kid)
        with self._condition:
            try:
                now = float(self._monotonic())
            except Exception:
                raise OIDCVerificationUnavailable("OIDC verification metadata is unavailable") from None
            if not math.isfinite(now) or now < 0:
                raise OIDCVerificationUnavailable("OIDC verification metadata is unavailable")
            if now < self._expires_at and requested in self._keys:
                return self._keys[requested]
            if self._refreshing:
                active_serial = self._refresh_serial
                while self._refreshing and self._refresh_serial == active_serial:
                    self._condition.wait()
                if self._completed_serial == active_serial:
                    if not self._completed_success:
                        raise OIDCVerificationUnavailable("OIDC verification metadata is unavailable")
                    if requested in self._keys:
                        return self._keys[requested]
                    raise OIDCVerificationError("OIDC signing key is not accepted")
            self._refreshing = True
            self._refresh_serial += 1
            serial = self._refresh_serial

        try:
            discovery = self._fetcher.fetch_discovery()
            validate_discovery(discovery.body)
            jwks = self._fetcher.fetch_jwks()
            new_keys = validate_jwks(jwks.body)
            ttl = min(MAX_CACHE_TTL_SECONDS, discovery.cache_ttl, jwks.cache_ttl)
            if ttl < 0:
                raise OIDCVerificationUnavailable("OIDC verification metadata is unavailable")
            refreshed_at = float(self._monotonic())
            if not math.isfinite(refreshed_at) or refreshed_at < 0:
                raise OIDCVerificationUnavailable("OIDC verification metadata is unavailable")
        except OIDCVerificationError:
            with self._condition:
                self._refreshing = False
                self._completed_serial = serial
                self._completed_success = False
                self._condition.notify_all()
            raise OIDCVerificationUnavailable("OIDC verification metadata is unavailable") from None
        except Exception:
            with self._condition:
                self._refreshing = False
                self._completed_serial = serial
                self._completed_success = False
                self._condition.notify_all()
            raise OIDCVerificationUnavailable("OIDC verification metadata is unavailable") from None

        with self._condition:
            self._keys = new_keys
            self._expires_at = refreshed_at + ttl
            self._refreshing = False
            self._completed_serial = serial
            self._completed_success = True
            self._condition.notify_all()
            if requested not in new_keys:
                raise OIDCVerificationError("OIDC signing key is not accepted")
            return new_keys[requested]
