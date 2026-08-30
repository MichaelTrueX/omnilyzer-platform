"""Django request correlation, tracing, logging, and metrics middleware."""

from __future__ import annotations

import logging
import time
from typing import Callable

from django.http import HttpRequest, HttpResponse
from opentelemetry.context import Context
from opentelemetry.trace import SpanKind, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from .context import (
    REQUEST_ID_HEADER,
    bind_request_id,
    canonical_request_id,
    reset_request_id,
)
from .metrics import normalized_route
from .runtime import get_runtime
from .structured_logging import event


_LOGGER = logging.getLogger("omnilyzer.observability")
TRACEPARENT_MAX_LENGTH = 512
TRACESTATE_MAX_LENGTH = 512
_TRACE_CONTEXT_PROPAGATOR = TraceContextTextMapPropagator()


def _header_exceeds(value: str | None, limit: int) -> bool:
    """Apply a byte-oriented bound before standard propagation parsing."""

    return value is not None and len(value.encode("utf-8")) > limit


def _incoming_trace_context(request: HttpRequest, *, trusted: bool) -> Context:
    """Extract bounded W3C context only at an explicitly trusted boundary."""

    if not trusted:
        return Context()
    traceparent = request.headers.get("traceparent")
    tracestate = request.headers.get("tracestate")
    if (
        _header_exceeds(traceparent, TRACEPARENT_MAX_LENGTH)
        or _header_exceeds(tracestate, TRACESTATE_MAX_LENGTH)
    ):
        return Context()
    carrier = {
        key: value
        for key, value in (("traceparent", traceparent), ("tracestate", tracestate))
        if value is not None
    }
    return _TRACE_CONTEXT_PROPAGATOR.extract(carrier=carrier, context=Context())


class ObservabilityMiddleware:
    """Apply telemetry without changing authentication or application outcomes."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        runtime = get_runtime()
        request_id = canonical_request_id(
            request.headers.get(REQUEST_ID_HEADER),
            trust_incoming=runtime.config.trust_incoming_request_id,
        )
        token = bind_request_id(request_id)
        started = time.perf_counter()
        if not runtime.config.enabled:
            try:
                response = self.get_response(request)
                response[REQUEST_ID_HEADER] = request_id
                return response
            finally:
                reset_request_id(token)
        parent_context = _incoming_trace_context(
            request,
            trusted=runtime.config.trust_incoming_trace_context,
        )
        response: HttpResponse | None = None
        status_code = 500
        route: str | None = None
        try:
            with runtime.tracer.start_as_current_span(
                "http.server.request",
                context=parent_context,
                kind=SpanKind.SERVER,
                attributes={"http.request.method": request.method},
            ) as span:
                try:
                    response = self.get_response(request)
                    status_code = response.status_code
                    response[REQUEST_ID_HEADER] = request_id
                    return response
                except Exception:
                    span.set_status(Status(StatusCode.ERROR))
                    raise
                finally:
                    match = getattr(request, "resolver_match", None)
                    route = normalized_route(getattr(match, "route", None))
                    span.set_attribute("http.route", route)
                    span.set_attribute("http.response.status_code", status_code)
                    elapsed = time.perf_counter() - started
                    try:
                        runtime.metrics.observe_request(
                            request.method, getattr(match, "route", None), status_code, elapsed
                        )
                        event(
                            _LOGGER,
                            "http.request_completed",
                            fields={
                                "method": request.method,
                                "route": route,
                                "status_class": f"{status_code // 100}xx",
                                "duration_ms": round(elapsed * 1000, 3),
                            },
                        )
                    except Exception:
                        # Telemetry must not replace or alter an application response.
                        pass
        finally:
            reset_request_id(token)
