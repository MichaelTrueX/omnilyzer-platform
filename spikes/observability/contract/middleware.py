"""Django request correlation, tracing, logging, and metrics middleware."""

from __future__ import annotations

import logging
import time
from typing import Callable

from django.http import HttpRequest, HttpResponse
from opentelemetry import propagate
from opentelemetry.trace import SpanKind, Status, StatusCode

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
        carrier = {
            key: request.headers[key]
            for key in ("traceparent", "tracestate")
            if key in request.headers
        }
        parent_context = propagate.extract(carrier=carrier)
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
