"""Concurrency-safe request and trace correlation context."""

from __future__ import annotations

from contextvars import ContextVar, Token
import re
import secrets

from opentelemetry import trace


REQUEST_ID_HEADER = "X-Request-ID"
REQUEST_ID_PATTERN = re.compile(r"[0-9a-f]{32}")
_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)


def canonical_request_id(candidate: str | None, *, trust_incoming: bool = False) -> str:
    """Return a canonical ID, accepting input only behind a trusted ingress."""

    if (
        trust_incoming
        and isinstance(candidate, str)
        and REQUEST_ID_PATTERN.fullmatch(candidate)
    ):
        return candidate
    return secrets.token_hex(16)


def bind_request_id(request_id: str) -> Token[str | None]:
    """Bind a validated request ID to the current execution context."""

    if REQUEST_ID_PATTERN.fullmatch(request_id) is None:
        raise ValueError("request_id must be exactly 32 lowercase hexadecimal characters")
    return _request_id.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    """Restore the prior request context after a request finishes."""

    _request_id.reset(token)


def current_request_id() -> str | None:
    """Return the request ID bound to this context, if any."""

    return _request_id.get()


def current_trace_id() -> str | None:
    """Return the active valid W3C trace ID as fixed-width lowercase hex."""

    span_context = trace.get_current_span().get_span_context()
    if not span_context.is_valid:
        return None
    return f"{span_context.trace_id:032x}"
