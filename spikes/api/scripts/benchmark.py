"""spikes/api/scripts/benchmark.py: Run a small same-process API sanity benchmark.

Related modules: config.urls, domain.models, and spikes/api/results/benchmark.json.
This is intentionally not a production-capacity or concurrent-server benchmark.
"""
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Callable
import json
import os
import platform
import sys

SPIKE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SPIKE_ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ.setdefault("SPIKE_DEBUG", "0")

import django

django.setup()

from django.conf import settings
from django.db import connection
from django.test import Client
from domain.auth import synthetic_actor_id
from domain.models import Project, Workspace


def timed_requests(
    client: Client,
    action: Callable[[int], object],
    count: int,
) -> dict[str, float | int]:
    """Warm an endpoint and record sequential latency and throughput."""
    for index in range(5):
        response = action(-(index + 1))
        if response.status_code >= 400:
            raise RuntimeError(f"Benchmark warmup failed with {response.status_code}.")
    started = perf_counter()
    for index in range(count):
        response = action(index)
        if response.status_code >= 400:
            raise RuntimeError(f"Benchmark request failed with {response.status_code}.")
    elapsed = perf_counter() - started
    return {
        "requests": count,
        "elapsed_seconds": round(elapsed, 6),
        "mean_latency_ms": round((elapsed / count) * 1_000, 3),
        "requests_per_second": round(count / elapsed, 2),
    }


def framework_run(label: str, prefix: str) -> dict[str, object]:
    """Benchmark equivalent list, retrieve, and create calls for one adapter."""
    workspace_name = f"Task 002 benchmark {label}"
    Workspace.objects.filter(
        workspace_type=Workspace.WorkspaceType.ORGANIZATION,
        name=workspace_name,
    ).delete()
    workspace = Workspace.objects.create(
        name=workspace_name,
        workspace_type=Workspace.WorkspaceType.ORGANIZATION,
    )
    project = Project.objects.create(
        workspace=workspace,
        name="Stable benchmark retrieval project",
    )
    headers = {
        "HTTP_X_SPIKE_ACTOR": synthetic_actor_id(workspace.id),
        "HTTP_X_WORKSPACE_ID": str(workspace.id),
    }
    client = Client(raise_request_exception=False)
    list_url = f"{prefix}/projects/"
    detail_url = f"{prefix}/projects/{project.id}/"

    results = {
        "list": timed_requests(client, lambda _: client.get(list_url, **headers), 200),
        "retrieve": timed_requests(
            client, lambda _: client.get(detail_url, **headers), 200
        ),
        "create": timed_requests(
            client,
            lambda index: client.post(
                list_url,
                data=json.dumps({
                    "workspace_id": str(workspace.id),
                    "name": f"Benchmark project {index}",
                    "description": "",
                    "status": "active",
                }),
                content_type="application/json",
                **headers,
            ),
            100,
        ),
    }
    workspace.delete()
    return results


def main() -> None:
    """Run both adapters serially and persist environment-qualified measurements."""
    raw_pg_version = connection.pg_version
    postgres_version = f"{raw_pg_version // 10000}.{raw_pg_version % 10000}"
    document = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "django": django.get_version(),
            "database": f"PostgreSQL {postgres_version}",
            "debug": settings.DEBUG,
            "server_mode": "Django in-process WSGI test client",
            "concurrency": 1,
        },
        "drf": framework_run("DRF", "/api/v1/drf"),
        "django_ninja": framework_run("Ninja", "/api/v1/ninja"),
        "limitations": (
            "Sequential in-process requests include ORM/database work but omit network, "
            "production server, TLS, load balancing, and concurrent-client effects."
        ),
    }
    output = SPIKE_ROOT / "results" / "benchmark.json"
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
