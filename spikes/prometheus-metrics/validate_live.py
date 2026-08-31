#!/usr/bin/env python3
"""Run Task 010's reproducible, containerized Prometheus validation."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import time
from typing import Any
from urllib.parse import urlencode
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parent
COMPOSE = ["docker", "compose", "-f", str(ROOT / "compose.yaml")]
PROMETHEUS = "http://127.0.0.1:19090"
INSTANCES = ("target-alpha:8000", "target-beta:8000", "target-flaky:8000")
SENSITIVE_VALUES = (
    "00000000-0000-4000-8000-000000000099",
    "user-sensitive-010",
    "sensitive-user@example.invalid",
    "1234567890abcdef1234567890abcdef",
    "abcdefabcdefabcdefabcdefabcdefab",
    "sensitive-authorization-010",
    "session-sensitive-010",
    "query-sensitive-010",
    "customer-sensitive-object-010",
)


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a scoped Compose command without leaking noisy routine output."""

    result = subprocess.run(
        [*COMPOSE, *args], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if check and result.returncode:
        raise RuntimeError(
            f"command failed: {' '.join(result.args)}\n{result.stdout}\n{result.stderr}"
        )
    return result


def api(path: str, **parameters: str) -> Any:
    """Return the data element from a successful Prometheus HTTP API response."""

    suffix = f"?{urlencode(parameters)}" if parameters else ""
    with urlopen(f"{PROMETHEUS}{path}{suffix}", timeout=5) as response:
        document = json.load(response)
    if document.get("status") != "success":
        raise AssertionError(document)
    return document["data"]


def query(expression: str) -> list[dict[str, Any]]:
    """Evaluate one instant PromQL expression."""

    return api("/api/v1/query", query=expression)["result"]


def scalar(expression: str) -> float:
    """Return one scalar-like instant vector result."""

    results = query(expression)
    if len(results) != 1:
        raise AssertionError(f"expected one result for {expression!r}: {results!r}")
    return float(results[0]["value"][1])


def wait_until(predicate: Any, description: str, timeout: float = 25.0) -> float:
    """Poll a bounded condition and return elapsed recovery time."""

    started = time.monotonic()
    last_error: Exception | None = None
    while time.monotonic() - started < timeout:
        try:
            if predicate():
                return round(time.monotonic() - started, 3)
        except Exception as error:  # transient connection/API state is expected
            last_error = error
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {description}: {last_error}")


def all_up() -> bool:
    """Return whether all configured targets have a current successful scrape."""

    results = query('up{job="omnilyzer"}')
    values = {item["metric"]["instance"]: item["value"][1] for item in results}
    return values == {instance: "1" for instance in INSTANCES}


def instance_up(instance: str, expected: int) -> bool:
    """Check one target's current `up` value."""

    return scalar(f'up{{job="omnilyzer",instance="{instance}"}}') == expected


def target_probe(service: str, *arguments: str) -> dict[str, Any]:
    """Execute the fixed synthetic request driver within a private target."""

    result = run("exec", "-T", service, "python", "/app/target_probe.py", *arguments)
    return json.loads(result.stdout)


def inspect_service(service: str) -> dict[str, Any]:
    """Return Docker runtime metadata for one scoped Compose service."""

    container_id = run("ps", "-q", service).stdout.strip()
    if not container_id:
        raise AssertionError(f"missing container for {service}")
    result = subprocess.run(
        ["docker", "inspect", container_id], text=True, capture_output=True, check=True
    )
    return json.loads(result.stdout)[0]


def assert_runtime_network_boundary() -> dict[str, Any]:
    """Prove runtime targets have no host mapping and Prometheus is loopback-bound."""

    target_networks: dict[str, list[str]] = {}
    for service in ("target-alpha", "target-beta", "target-flaky"):
        inspection = inspect_service(service)
        bindings = inspection["HostConfig"]["PortBindings"] or {}
        if bindings:
            raise AssertionError(f"{service} unexpectedly publishes ports: {bindings}")
        networks = sorted(inspection["NetworkSettings"]["Networks"])
        if len(networks) != 1 or not networks[0].endswith("_metrics-internal"):
            raise AssertionError(f"{service} network boundary: {networks}")
        target_networks[service] = networks

    prometheus = inspect_service("prometheus")
    bindings = prometheus["HostConfig"]["PortBindings"]
    expected = {"9090/tcp": [{"HostIp": "127.0.0.1", "HostPort": "19090"}]}
    if bindings != expected:
        raise AssertionError({"actual": bindings, "expected": expected})
    return {
        "runtime_target_host_port_bindings": 0,
        "runtime_target_networks": target_networks,
        "runtime_prometheus_port_binding": "127.0.0.1:19090",
    }


def series(metric: str) -> list[dict[str, str]]:
    """Return every stored series for a metric through Prometheus's series API."""

    return api("/api/v1/series", **{"match[]": metric})


def assert_query_contract() -> dict[str, float]:
    """Prove accepted application metrics are queryable through real Prometheus."""

    expressions = {
        "request_count": "sum(omnilyzer_http_requests_total)",
        "histogram_count": "sum(omnilyzer_http_request_duration_seconds_count)",
        "build_info": "count(omnilyzer_build_info == 1)",
        "export_failures": "sum(omnilyzer_telemetry_export_failures_total)",
        "targets_up": 'sum(up{job="omnilyzer"})',
    }
    values = {name: scalar(expression) for name, expression in expressions.items()}
    if values["request_count"] <= 0 or values["histogram_count"] != values["request_count"]:
        raise AssertionError(values)
    if values["build_info"] != 3 or values["export_failures"] != 4:
        raise AssertionError(values)
    if values["targets_up"] != 3:
        raise AssertionError(values)
    return values


def cardinality_evidence() -> dict[str, Any]:
    """Compare actual series with the finite accepted label-space bound."""

    counter_series = series("omnilyzer_http_requests_total")
    base = len(counter_series)
    route_values = sorted({item["route"] for item in counter_series})
    forbidden_labels = {
        "workspace_id", "user_id", "email", "session_id", "request_id", "trace_id",
        "ip", "authorization", "query", "url", "path", "customer_id", "object_id",
        "document_id", "order_id", "git_commit", "oci_digest", "deployment_timestamp",
        "app_version", "platform_version",
    }
    label_names = set().union(*(item.keys() for item in counter_series))
    if forbidden_labels & label_names:
        raise AssertionError(f"prohibited labels: {forbidden_labels & label_names}")
    allowed_routes = {
        "/api/users/{id}", "/api/orders/{id}", "/api/documents/{id}",
        "/api/secure", "/livez", "/readyz", "/metrics", "unmatched",
    }
    if not set(route_values) <= allowed_routes or "unmatched" not in route_values:
        raise AssertionError(route_values)

    mechanics = {
        "counter_total": len(series("omnilyzer_http_requests_total")),
        "counter_created": len(series("omnilyzer_http_requests_created")),
        "histogram_bucket": len(series("omnilyzer_http_request_duration_seconds_bucket")),
        "histogram_count": len(series("omnilyzer_http_request_duration_seconds_count")),
        "histogram_sum": len(series("omnilyzer_http_request_duration_seconds_sum")),
        "histogram_created": len(series("omnilyzer_http_request_duration_seconds_created")),
    }
    expected_mechanics = {
        "counter_total": base,
        "counter_created": base,
        "histogram_bucket": base * 11,
        "histogram_count": base,
        "histogram_sum": base,
        "histogram_created": base,
    }
    if mechanics != expected_mechanics:
        raise AssertionError({"actual": mechanics, "expected": expected_mechanics})

    configured_base_bound = 3 * 8 * 8 * 6
    return {
        "actual_base_request_label_sets": base,
        "actual_request_metric_series_including_histogram_mechanics": sum(mechanics.values()),
        "expected_from_actual_base_and_mechanics": base * 16,
        "configured_theoretical_base_bound": configured_base_bound,
        "configured_theoretical_request_series_bound": configured_base_bound * 16,
        "histogram_buckets_per_label_set": 11,
        "actual_route_label_values": route_values,
        "unmatched_route_label_series": sum(item["route"] == "unmatched" for item in counter_series),
        "prohibited_request_labels_found": [],
        "mechanics": mechanics,
    }


def assert_no_sensitive_data() -> dict[str, Any]:
    """Search API-visible configuration, targets, and application series for fixtures."""

    evidence = {
        "config": api("/api/v1/status/config"),
        "targets": api("/api/v1/targets"),
        "request_series": series("omnilyzer_http_requests_total"),
    }
    serialized = json.dumps(evidence, sort_keys=True)
    found = [value for value in SENSITIVE_VALUES if value in serialized]
    if found:
        raise AssertionError(f"sensitive fixture values reached Prometheus: {found}")
    return {"searched_fixture_values": len(SENSITIVE_VALUES), "found": found}


def main() -> None:
    """Run all live gates and emit one machine-readable evidence document."""

    evidence: dict[str, Any] = {
        "schema_version": 1,
        "prometheus": {
            "version": "3.14.0",
            "image": "prom/prometheus:v3.14.0",
            "digest": "sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0",
        },
        "topology": {
            "targets": 3,
            "target_host_ports": 0,
            "prometheus_host_binding": "127.0.0.1:19090",
            "docker_network_internal": True,
            "scrape_interval_seconds": 1.0,
            "scrape_timeout_seconds": 0.5,
        },
    }
    run("down", "-v", "--remove-orphans", check=False)
    try:
        run("up", "-d", "--build")
        evidence["network_boundary"] = assert_runtime_network_boundary()
        evidence["prometheus_ready_seconds"] = wait_until(all_up, "three healthy targets")
        build = api("/api/v1/status/buildinfo")
        if build.get("version") != "3.14.0":
            raise AssertionError(build)

        started = time.monotonic()
        seeds = {
            "alpha": target_probe("target-alpha", "seed", "--users", "10000", "--unmatched", "1000"),
            "beta": target_probe("target-beta", "seed", "--users", "200", "--unmatched", "100"),
        }
        evidence["request_generation_seconds"] = round(time.monotonic() - started, 3)
        if any(seed["failures"] for seed in seeds.values()):
            raise AssertionError(seeds)
        evidence["synthetic_requests"] = sum(seed["requests"] for seed in seeds.values())
        evidence["distinct_raw_ids"] = sum(
            seed["distinct_user_ids"] + seed["distinct_unmatched_ids"] for seed in seeds.values()
        )
        time.sleep(2.25)
        evidence["queries"] = assert_query_contract()
        evidence["cardinality"] = cardinality_evidence()
        evidence["sensitive_data"] = assert_no_sensitive_data()

        target_probe("target-alpha", "deployment", "2.4.2", "1.8.1")
        time.sleep(2.25)
        current_builds = query("omnilyzer_build_info == 1")
        current_versions = sorted(item["metric"]["app_version"] for item in current_builds)
        if current_versions != ["0.0.1", "1.3.0", "2.4.2"]:
            raise AssertionError(current_versions)
        historical_builds = series("omnilyzer_build_info")
        historical_versions = sorted({item["app_version"] for item in historical_builds})
        if historical_versions != ["0.0.1", "1.3.0", "2.4.1", "2.4.2"]:
            raise AssertionError(historical_versions)
        evidence["build_info"] = {
            "current_series": 3,
            "current_versions": current_versions,
            "historical_series_after_transition": len(historical_builds),
            "historical_versions": historical_versions,
            "high_churn_labels_on_request_metrics": False,
        }

        run("stop", "target-beta")
        failed_target_seconds = wait_until(
            lambda: instance_up("target-beta:8000", 0) and instance_up("target-alpha:8000", 1),
            "isolated failed target",
        )
        if scalar('sum(up{job="omnilyzer"})') != 2:
            raise AssertionError("one failed target affected healthy targets")
        run("start", "target-beta")
        recovered_target_seconds = wait_until(all_up, "target recovery")

        target_probe("target-flaky", "mode", "slow")
        slow_seconds = wait_until(
            lambda: instance_up("target-flaky:8000", 0) and instance_up("target-alpha:8000", 1),
            "slow-target timeout",
        )
        time.sleep(3.25)
        slow_stats = json.loads(
            run("stats", "--no-stream", "--format", "{{json .}}", "target-flaky").stdout
        )
        slow_pids = int(slow_stats["PIDs"])
        if slow_pids > 8:
            raise AssertionError(f"slow scrape handlers accumulated unexpectedly: {slow_pids}")
        target_probe("target-flaky", "mode", "malformed")
        time.sleep(1.25)
        if not instance_up("target-flaky:8000", 0) or not instance_up("target-alpha:8000", 1):
            raise AssertionError("malformed target was not isolated")
        target_probe("target-flaky", "mode", "normal")
        flaky_recovery_seconds = wait_until(all_up, "flaky target recovery")
        evidence["failed_target_isolation"] = {
            "stopped_target_up": 0,
            "healthy_target_up": 1,
            "detection_seconds": failed_target_seconds,
            "restart_recovery_seconds": recovered_target_seconds,
            "slow_target_up": 0,
            "slow_target_detection_seconds": slow_seconds,
            "slow_target_pids_after_repeated_timeouts": slow_pids,
            "slow_target_pid_acceptance_bound": 8,
            "malformed_target_up": 0,
            "normal_mode_recovery_seconds": flaky_recovery_seconds,
        }

        alpha_id_before = run("ps", "-q", "target-alpha").stdout.strip()
        run("stop", "prometheus")
        outage_started = time.monotonic()
        availability = target_probe("target-alpha", "availability", "--count", "500")
        if availability["failures"] or availability["requests"] != 503:
            raise AssertionError(availability)
        alpha_id_during = run("ps", "-q", "target-alpha").stdout.strip()
        if alpha_id_during != alpha_id_before:
            raise AssertionError("application target restarted during Prometheus outage")
        run("start", "prometheus")
        prometheus_recovery = wait_until(all_up, "Prometheus restart recovery", timeout=35)
        evidence["prometheus_outage"] = {
            "outage_request_count": availability["requests"],
            "outage_request_failures": availability["failures"],
            "livez_passed": True,
            "readyz_passed": True,
            "authorization_behavior_unchanged": True,
            "application_container_restarted": False,
            "request_loop_seconds": round(time.monotonic() - outage_started, 3),
            "scrape_recovery_seconds": prometheus_recovery,
        }

        time.sleep(1.25)
        scrape_durations = query('scrape_duration_seconds{job="omnilyzer"}')
        evidence["scrape_duration_seconds"] = {
            item["metric"]["instance"]: float(item["value"][1]) for item in scrape_durations
        }
        query_started = time.monotonic()
        evidence["representative_request_rate_per_second"] = scalar(
            "sum(rate(omnilyzer_http_requests_total[1m]))"
        )
        evidence["representative_query_latency_ms"] = round(
            (time.monotonic() - query_started) * 1000, 3
        )
        stats = run("stats", "--no-stream", "--format", "{{json .}}", "prometheus")
        evidence["prometheus_resource_observation"] = json.loads(stats.stdout)
        evidence["decision"] = "PASS"
        print(json.dumps(evidence, indent=2, sort_keys=True))
    finally:
        run("down", "-v", "--remove-orphans", check=False)


if __name__ == "__main__":
    main()
