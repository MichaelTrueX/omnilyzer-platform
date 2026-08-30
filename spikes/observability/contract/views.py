"""Synthetic endpoints exercising health, metrics, DB, HTTP, and security boundaries."""

from __future__ import annotations

from urllib.request import Request, urlopen

from django.conf import settings
from django.db import connection
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET
from opentelemetry import propagate
from opentelemetry.trace import SpanKind
from prometheus_client import CONTENT_TYPE_LATEST

from .runtime import get_runtime


def _required_database_ready() -> bool:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        return cursor.fetchone() == (1,)


@require_GET
def livez(request: HttpRequest) -> JsonResponse:
    """Report only whether this application process can answer HTTP."""

    return JsonResponse({"status": "alive"})


@require_GET
def readyz(request: HttpRequest) -> JsonResponse:
    """Check only dependencies required to serve normal application traffic."""

    checker = getattr(settings, "REQUIRED_READINESS_CHECK", _required_database_ready)
    try:
        ready = checker()
    except Exception:
        ready = False
    return JsonResponse(
        {"status": "ready" if ready else "unready"},
        status=200 if ready else 503,
    )


@require_GET
def metrics(request: HttpRequest) -> HttpResponse:
    """Expose Prometheus text for an internal deployment/network boundary."""

    return HttpResponse(get_runtime().metrics.render(), content_type=CONTENT_TYPE_LATEST)


@require_GET
def work(request: HttpRequest, item_id: int) -> JsonResponse:
    """Exercise representative request and database spans without customer attributes."""

    runtime = get_runtime()
    with runtime.tracer.start_as_current_span(
        "database.required_operation",
        kind=SpanKind.CLIENT,
        attributes={"db.system.name": "sqlite"},
    ):
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()[0]
    return JsonResponse({"status": "ok", "result": result, "item": item_id})


@require_GET
def outbound(request: HttpRequest) -> JsonResponse:
    """Propagate W3C trace context to one fixed synthetic downstream endpoint."""

    target = getattr(settings, "SYNTHETIC_OUTBOUND_URL", None)
    if not target:
        return JsonResponse({"status": "not_configured"}, status=503)
    runtime = get_runtime()
    headers: dict[str, str] = {}
    with runtime.tracer.start_as_current_span(
        "http.synthetic_downstream",
        kind=SpanKind.CLIENT,
        attributes={"server.address": "controlled-test-receiver"},
    ):
        propagate.inject(headers)
        downstream_request = Request(target, headers=headers, method="GET")
        try:
            with urlopen(downstream_request, timeout=0.5) as response:
                status = response.status
        except OSError:
            return JsonResponse({"status": "downstream_unavailable"}, status=502)
    return JsonResponse({"status": "ok", "downstream_status": status})


@csrf_protect
def secure_boundary(request: HttpRequest) -> JsonResponse:
    """Representative auth/Workspace checks that telemetry must not bypass or mutate."""

    if request.headers.get("Authorization") != "Bearer synthetic-valid-token":
        return JsonResponse({"status": "unauthorized"}, status=401)
    if request.headers.get("X-Workspace-ID") != "00000000-0000-4000-8000-000000000001":
        return JsonResponse({"status": "forbidden"}, status=403)
    return JsonResponse({"status": "authorized"})
