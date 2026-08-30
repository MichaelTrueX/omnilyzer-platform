#!/usr/bin/env python3
"""Small reproducible three-condition Task 009 overhead measurement."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import socket
import statistics
import sys
import time
import tracemalloc


SPIKE_ROOT = Path(__file__).resolve().parents[1]
if str(SPIKE_ROOT) not in sys.path:
    sys.path.insert(0, str(SPIKE_ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "observability_spike.settings")

import django

django.setup()

from django.test import Client

from contract.runtime import set_runtime
from contract.telemetry import build_runtime
from tests.helpers import METADATA, Receiver, config


REQUESTS = 500
WARMUP = 25


def percentile(samples: list[float], fraction: float) -> float:
    """Return a nearest-rank percentile for a deliberately small sample."""

    ordered = sorted(samples)
    return ordered[max(0, int(len(ordered) * fraction) - 1)]


def measure(name: str, runtime) -> dict[str, float | int | str]:
    """Measure in-process Django request behavior and bounded shutdown."""

    previous = set_runtime(runtime)
    client = Client()
    try:
        for item in range(WARMUP):
            if client.get(f"/api/work/{item}").status_code != 200:
                raise RuntimeError(f"{name} warmup request failed")
        tracemalloc.start()
        before_current, _ = tracemalloc.get_traced_memory()
        latencies: list[float] = []
        failures = 0
        cpu_start = time.process_time()
        wall_start = time.perf_counter()
        for item in range(REQUESTS):
            started = time.perf_counter()
            response = client.get(f"/api/work/{item}")
            latencies.append(time.perf_counter() - started)
            failures += response.status_code != 200
        wall_seconds = time.perf_counter() - wall_start
        cpu_seconds = time.process_time() - cpu_start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        if runtime.provider is not None:
            runtime.provider.force_flush(timeout_millis=750)
        shutdown_started = time.perf_counter()
        runtime.shutdown()
        shutdown_seconds = time.perf_counter() - shutdown_started
    finally:
        set_runtime(previous)
    return {
        "condition": name,
        "requests": REQUESTS,
        "failures": failures,
        "latency_mean_ms": round(statistics.fmean(latencies) * 1000, 3),
        "latency_p50_ms": round(percentile(latencies, 0.50) * 1000, 3),
        "latency_p95_ms": round(percentile(latencies, 0.95) * 1000, 3),
        "throughput_requests_per_second": round(REQUESTS / wall_seconds, 1),
        "cpu_seconds": round(cpu_seconds, 4),
        "tracemalloc_current_growth_bytes": max(0, current - before_current),
        "tracemalloc_peak_growth_bytes": max(0, peak - before_current),
        "shutdown_ms": round(shutdown_seconds * 1000, 3),
    }


def main() -> None:
    """Run baseline, accepting OTLP, and unavailable OTLP conditions."""

    logger = logging.getLogger("omnilyzer.observability")
    logger.handlers = [logging.NullHandler()]
    logger.propagate = False
    logging.getLogger("opentelemetry.sdk.trace.export").disabled = True
    logging.getLogger("opentelemetry.exporter.otlp.proto.http.trace_exporter").disabled = True

    results = [measure("observability_disabled", build_runtime(config(enabled=False), METADATA))]
    with Receiver(post_status=200) as receiver:
        accepting = build_runtime(
            config(enabled=True, endpoint=receiver.otlp_endpoint, queue=128, batch=32),
            METADATA,
        )
        accepting_result = measure("otlp_accepting", accepting)
        accepting_result["receiver_posts"] = receiver.posts
        accepting_result["receiver_bytes"] = receiver.bytes
        results.append(accepting_result)

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        unused_port = int(probe.getsockname()[1])
    unavailable = build_runtime(
        config(
            enabled=True,
            endpoint=f"http://127.0.0.1:{unused_port}/v1/traces",
            timeout=100,
            queue=128,
            batch=32,
        ),
        METADATA,
    )
    results.append(measure("otlp_unavailable", unavailable))

    baseline, accepting_result, unavailable_result = results
    if any(result["failures"] != 0 for result in results):
        raise SystemExit("benchmark application request failed")
    if accepting_result["receiver_posts"] < 1:
        raise SystemExit("controlled OTLP receiver received no trace payload")
    if unavailable_result["latency_p95_ms"] - baseline["latency_p95_ms"] >= 10:
        raise SystemExit("unavailable telemetry added at least 10ms p95 request latency")
    if unavailable_result["shutdown_ms"] >= 1000:
        raise SystemExit("unavailable telemetry shutdown exceeded one second")
    if unavailable_result["tracemalloc_peak_growth_bytes"] >= 8 * 1024 * 1024:
        raise SystemExit("unavailable telemetry exceeded the 8 MiB synthetic memory bound")
    evidence = {
        "schema_version": 1,
        "mode": "in-process Django test client; synthetic sanity measurement",
        "results": results,
        "acceptance": {
            "all_requests_succeeded": True,
            "unavailable_p95_added_less_than_ms": 10,
            "unavailable_shutdown_less_than_ms": 1000,
            "unavailable_peak_growth_less_than_bytes": 8 * 1024 * 1024,
        },
    }
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
