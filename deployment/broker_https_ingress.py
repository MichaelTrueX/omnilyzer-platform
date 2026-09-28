"""Inert, closed HTTP transport contract for the DEV promotion broker.

No socket, listener, TLS, filesystem, or network operation exists here. A future
listener must supply the original ordered header pairs, without losing duplicates.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .broker import (
    BrokerRejectedError, BrokerUnavailableError, MAX_EXECUTOR_RESPONSE_BYTES,
    _bound_operation,
)
from .broker_integration import MAX_PROMOTION_REQUEST_BYTES
from .oidc_verifier import MAX_COMPACT_TOKEN_BYTES


PUBLIC_ORIGIN = "https://deploy-dev.omnilyzer.ai"
PUBLIC_HOST = "deploy-dev.omnilyzer.ai"
BROKER_LOOPBACK_HOST = "127.0.0.1"
BROKER_LOOPBACK_PORT = 3031
BROKER_LOOPBACK_ADDRESS = "127.0.0.1:3031"
PROMOTION_PATH = "/task014/dev/promote"
ZOT_OIDC_HEADER = "X-Omnilyzer-Zot-OIDC"
FORGEJO_OIDC_HEADER = "X-Omnilyzer-Forgejo-OIDC"

_REQUIRED_HEADERS = frozenset({
    "host", "authorization", "x-omnilyzer-zot-oidc",
    "x-omnilyzer-forgejo-oidc", "content-type", "content-length",
})
_REJECTED_BODY = b'{"status":"rejected"}\n'
_UNAVAILABLE_BODY = b'{"status":"unavailable"}\n'
_ACCEPTED_BODY = b'{"status":"accepted"}\n'
REJECTED_MESSAGE = "deployment ingress request is not accepted"


class IngressRejectedError(ValueError):
    """One fixed, secret-free transport rejection."""


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ParsedPromotionIngress:
    """Call-local, nonserializable transport values; token fields stay redacted."""

    compact_token: str = field(repr=False)
    zot_token: str = field(repr=False)
    forgejo_token: str = field(repr=False)
    promotion_request: bytes = field(repr=False)
    received_at: int = field(repr=False)

    def __repr__(self) -> str:
        return "<ParsedPromotionIngress redacted>"

    def __reduce__(self) -> object:
        raise TypeError("promotion ingress is not serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("promotion ingress is not serializable")


@dataclass(frozen=True, slots=True)
class IngressResponse:
    status: int
    body: bytes
    content_type: str = "application/json"

    def __post_init__(self) -> None:
        if ((type(self.status), type(self.body), type(self.content_type))
                != (int, bytes, str)
                or (self.status, self.body) not in (
                    (202, _ACCEPTED_BODY), (403, _REJECTED_BODY),
                    (503, _UNAVAILABLE_BODY),
                ) or self.content_type != "application/json"):
            raise TypeError("ingress response contract is invalid")


def _reject() -> None:
    raise IngressRejectedError(REJECTED_MESSAGE) from None


def _token(value: str) -> str:
    if (type(value) is not str or not value.isascii()
            or not 1 <= len(value) <= MAX_COMPACT_TOKEN_BYTES
            or any(character <= " " or character >= "\x7f" or character == ","
                   for character in value)):
        _reject()
    return value


def parse_dev_promotion_ingress(
    *, method: str, path: str, headers: object, body: bytes,
    received_at: int,
) -> ParsedPromotionIngress:
    """Parse one already-framed request; never decode or alter promotion bytes.

    Headers must be an ordered tuple/list of raw (name, value) pairs so duplicate
    credential headers remain detectable. A mapping is intentionally rejected.
    """

    if (type(method) is not str or method != "POST"
            or type(path) is not str or path != PROMOTION_PATH
            or type(body) is not bytes
            or not 1 <= len(body) <= MAX_PROMOTION_REQUEST_BYTES
            or type(received_at) is not int or received_at < 0
            or type(headers) not in (tuple, list)
            or len(headers) != len(_REQUIRED_HEADERS)):
        _reject()
    values: dict[str, str] = {}
    for item in headers:
        if (type(item) not in (tuple, list) or len(item) != 2
                or type(item[0]) is not str or type(item[1]) is not str):
            _reject()
        name, value = item
        if len(name) > 64 or len(value) > MAX_COMPACT_TOKEN_BYTES + len("Bearer "):
            _reject()
        try:
            name.encode("ascii")
            value.encode("ascii")
        except UnicodeError:
            _reject()
        name = name.lower()
        if (name not in _REQUIRED_HEADERS or name in values
                or any(character <= " " or character >= "\x7f" for character in name)
                or any(character in "\r\n\x00" or character == "\x7f" for character in value)):
            _reject()
        values[name] = value
    if (values.keys() != _REQUIRED_HEADERS
            or values["host"] != PUBLIC_HOST
            or values["content-type"] != "application/json"):
        _reject()
    length = values["content-length"]
    if (not length.isascii() or not length.isdecimal()
            or length != str(len(body))):
        _reject()
    authorization = values["authorization"]
    if not authorization.startswith("Bearer "):
        _reject()
    return ParsedPromotionIngress(
        compact_token=_token(authorization[len("Bearer "):]),
        zot_token=_token(values["x-omnilyzer-zot-oidc"]),
        forgejo_token=_token(values["x-omnilyzer-forgejo-oidc"]),
        promotion_request=body,
        received_at=received_at,
    )


def dispatch_inert_dev_promotion_ingress(
    handler: object, *, method: str, path: str, headers: object,
    body: bytes, received_at: int,
) -> IngressResponse:
    """Invoke only a captured C32P operation; return fixed small responses."""

    try:
        request = parse_dev_promotion_ingress(
            method=method, path=path, headers=headers, body=body,
            received_at=received_at,
        )
    except IngressRejectedError:
        return IngressResponse(403, _REJECTED_BODY)
    try:
        handle = _bound_operation(handler, "handle")
        result = handle(
            compact_token=request.compact_token,
            zot_token=request.zot_token,
            forgejo_token=request.forgejo_token,
            promotion_request=request.promotion_request,
            received_at=request.received_at,
        )
        if type(result) is not bytes or len(result) > MAX_EXECUTOR_RESPONSE_BYTES:
            raise BrokerUnavailableError()
    except BrokerRejectedError:
        return IngressResponse(403, _REJECTED_BODY)
    except Exception:
        return IngressResponse(503, _UNAVAILABLE_BODY)
    return IngressResponse(202, _ACCEPTED_BODY)


__all__ = (
    "PUBLIC_ORIGIN", "PUBLIC_HOST", "BROKER_LOOPBACK_HOST",
    "BROKER_LOOPBACK_PORT", "BROKER_LOOPBACK_ADDRESS", "PROMOTION_PATH",
    "ZOT_OIDC_HEADER", "FORGEJO_OIDC_HEADER", "IngressRejectedError",
    "ParsedPromotionIngress", "IngressResponse", "parse_dev_promotion_ingress",
    "dispatch_inert_dev_promotion_ingress",
)
