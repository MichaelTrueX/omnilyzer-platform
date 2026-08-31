#!/usr/bin/env python3
"""Validate official prometheus_client multiprocess aggregation and lifecycle rules."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


SCRIPT = Path(__file__).resolve()


def worker(
    count: int,
    app_version: str,
    gauge_mode: str,
    ready: Path,
    release: Path,
) -> None:
    """Create per-process counter, histogram, and selected build Gauge data."""

    from prometheus_client import Counter, Gauge, Histogram

    labels = {
        "service": "multiprocess-api",
        "product": "multiprocess-fixture",
        "environment": "test",
        "method": "GET",
        "route": "/api/users/{id}",
        "status_class": "2xx",
    }
    counter = Counter("omnilyzer_http_requests_total", "Requests.", tuple(labels))
    histogram = Histogram(
        "omnilyzer_http_request_duration_seconds", "Duration.", tuple(labels),
        buckets=(0.01, 0.1, 1.0),
    )
    build_arguments = {
        "name": "omnilyzer_build_info",
        "documentation": "Build.",
        "labelnames": (
            "service", "product", "environment", "app_version", "platform_version"
        ),
    }
    if gauge_mode == "default":
        build = Gauge(**build_arguments)
    else:
        build = Gauge(**build_arguments, multiprocess_mode=gauge_mode)
    build.labels(
        service="multiprocess-api", product="multiprocess-fixture", environment="test",
        app_version=app_version, platform_version="1.8.0",
    ).set(1)
    for _ in range(count):
        counter.labels(**labels).inc()
        histogram.labels(**labels).observe(0.01)
    ready.write_text(str(os.getpid()), encoding="utf-8")
    while not release.exists():
        time.sleep(0.02)


def collect() -> None:
    """Collect the multiprocess directory and emit parsed aggregate evidence."""

    from prometheus_client import CollectorRegistry, generate_latest, multiprocess
    from prometheus_client.parser import text_string_to_metric_families

    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
    text = generate_latest(registry).decode()
    result: dict[str, object] = {"counter": 0.0, "histogram_count": 0.0, "builds": []}
    for family in text_string_to_metric_families(text):
        for sample in family.samples:
            if sample.name == "omnilyzer_http_requests_total":
                result["counter"] = float(sample.value)
            elif sample.name == "omnilyzer_http_request_duration_seconds_count":
                result["histogram_count"] = float(sample.value)
            elif sample.name == "omnilyzer_build_info":
                result["builds"].append({  # type: ignore[union-attr]
                    "labels": dict(sample.labels),
                    "value": float(sample.value),
                })
    result["builds"].sort(key=lambda item: json.dumps(item, sort_keys=True))
    print(json.dumps(result, sort_keys=True))


def mark_dead(pid: int) -> None:
    """Apply the official worker-exit hook for multiprocess gauge cleanup."""

    from prometheus_client import multiprocess

    multiprocess.mark_process_dead(pid)


def subprocess_env(directory: Path) -> dict[str, str]:
    """Build an environment that sets multiprocess mode before any client import."""

    return {**os.environ, "PROMETHEUS_MULTIPROC_DIR": str(directory)}


def start_worker(
    directory: Path,
    name: str,
    count: int,
    version: str,
    gauge_mode: str,
) -> tuple[subprocess.Popen[str], Path, Path]:
    """Start one worker and wait a bounded time for its metric files."""

    ready = directory / f"{name}.ready"
    release = directory / f"{name}.release"
    process = subprocess.Popen(
        [
            sys.executable, str(SCRIPT), "worker", str(count), version, gauge_mode,
            str(ready), str(release),
        ],
        env=subprocess_env(directory), text=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not ready.exists():
        if process.poll() is not None:
            raise RuntimeError(f"worker {name} exited early")
        time.sleep(0.02)
    if not ready.exists():
        process.terminate()
        raise AssertionError(f"worker {name} did not become ready")
    return process, ready, release


def snapshot(directory: Path) -> dict[str, object]:
    """Collect through a fresh process to preserve environment-before-import semantics."""

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "collect"], env=subprocess_env(directory),
        text=True, capture_output=True, check=True,
    )
    return json.loads(result.stdout)


def stop_worker(directory: Path, worker_state: tuple[subprocess.Popen[str], Path, Path], *, clean: bool) -> int:
    """Stop a worker and optionally invoke the documented dead-worker hook."""

    process, _, release = worker_state
    release.touch()
    process.wait(timeout=5)
    if clean:
        subprocess.run(
            [sys.executable, str(SCRIPT), "mark-dead", str(process.pid)],
            env=subprocess_env(directory), check=True,
        )
    return process.pid


def sanitize_pid_values(snapshot_data: dict[str, object]) -> dict[str, object]:
    """Replace runtime PIDs with stable aliases after assertions have used real values."""

    sanitized = json.loads(json.dumps(snapshot_data))
    pid_values = sorted(item["labels"]["pid"] for item in sanitized["builds"])
    aliases = {pid: f"<worker-pid-{index}>" for index, pid in enumerate(pid_values, 1)}
    for item in sanitized["builds"]:
        item["labels"]["pid"] = aliases[item["labels"]["pid"]]
    return sanitized


def parent() -> None:
    """Prove aggregation, stale-gauge behavior, and deployment-directory cleanup."""

    with tempfile.TemporaryDirectory(prefix="task010-multiprocess-") as raw_base:
        base = Path(raw_base)

        default_directory = base / "unsafe-default"
        default_directory.mkdir()
        default_first = start_worker(
            default_directory, "default-first", 0, "1.0.0", "default"
        )
        default_second = start_worker(
            default_directory, "default-second", 0, "1.0.0", "default"
        )
        default_two_workers = snapshot(default_directory)
        default_pids = {
            item["labels"].get("pid") for item in default_two_workers["builds"]
        }
        if len(default_two_workers["builds"]) != 2 or default_pids != {
            str(default_first[0].pid), str(default_second[0].pid)
        }:
            raise AssertionError(default_two_workers)
        if any(item["value"] != 1 for item in default_two_workers["builds"]):
            raise AssertionError(default_two_workers)
        stop_worker(default_directory, default_first, clean=True)
        default_after_mark_one = snapshot(default_directory)
        if default_after_mark_one != default_two_workers:
            raise AssertionError(default_after_mark_one)
        stop_worker(default_directory, default_second, clean=True)
        default_after_mark_both = snapshot(default_directory)
        if default_after_mark_both != default_two_workers:
            raise AssertionError(default_after_mark_both)
        sanitized_default = sanitize_pid_values(default_two_workers)

        directory = base / "safe-live-mode"
        directory.mkdir()
        first = start_worker(directory, "first", 5, "1.0.0", "livemax")
        second = start_worker(directory, "second", 7, "1.0.0", "livemax")
        aggregate = snapshot(directory)
        if aggregate["counter"] != 12 or aggregate["histogram_count"] != 12:
            raise AssertionError(aggregate)
        if (
            len(aggregate["builds"]) != 1
            or "pid" in aggregate["builds"][0]["labels"]
            or aggregate["builds"][0]["value"] != 1
        ):
            raise AssertionError(aggregate)

        stop_worker(directory, first, clean=True)
        after_clean_exit = snapshot(directory)
        if after_clean_exit["counter"] != 12 or len(after_clean_exit["builds"]) != 1:
            raise AssertionError(after_clean_exit)
        third = start_worker(directory, "third", 3, "1.0.0", "livemax")
        after_restart = snapshot(directory)
        if after_restart["counter"] != 15 or after_restart["histogram_count"] != 15:
            raise AssertionError(after_restart)

        stop_worker(directory, third, clean=True)
        stop_worker(directory, second, clean=False)
        fourth = start_worker(directory, "fourth", 2, "2.0.0", "livemax")
        stale = snapshot(directory)
        stale_versions = sorted(
            build["labels"]["app_version"] for build in stale["builds"]
        )
        if stale_versions != ["1.0.0", "2.0.0"]:
            raise AssertionError(stale)
        subprocess.run(
            [sys.executable, str(SCRIPT), "mark-dead", str(second[0].pid)],
            env=subprocess_env(directory), check=True,
        )
        after_stale_cleanup = snapshot(directory)
        if [
            item["labels"]["app_version"] for item in after_stale_cleanup["builds"]
        ] != ["2.0.0"]:
            raise AssertionError(after_stale_cleanup)

        stop_worker(directory, fourth, clean=True)
        before_deployment_cleanup = snapshot(directory)
        fifth = start_worker(directory, "fifth", 2, "3.0.0", "livemax")
        contaminated = snapshot(directory)
        if contaminated["counter"] != before_deployment_cleanup["counter"] + 2:
            raise AssertionError(contaminated)
        stop_worker(directory, fifth, clean=True)

        for item in directory.iterdir():
            if item.is_file():
                item.unlink()
            else:
                shutil.rmtree(item)
        sixth = start_worker(directory, "sixth", 2, "3.0.0", "livemax")
        clean_deployment = snapshot(directory)
        if clean_deployment["counter"] != 2 or clean_deployment["histogram_count"] != 2:
            raise AssertionError(clean_deployment)
        stop_worker(directory, sixth, clean=True)

        print(json.dumps({
            "schema_version": 1,
            "client": "prometheus-client 0.26.0",
            "workers": 2,
            "unsafe_default_all_mode": {
                "two_live_workers": sanitized_default,
                "after_mark_process_dead_one_worker": sanitize_pid_values(
                    default_after_mark_one
                ),
                "after_mark_process_dead_both_workers": sanitize_pid_values(
                    default_after_mark_both
                ),
                "per_process_series": 2,
                "pid_label_present": True,
                "mark_process_dead_removed_default_series": False,
            },
            "safe_candidate_gauge_mode": "livemax",
            "initial_aggregate": aggregate,
            "after_clean_worker_exit": after_clean_exit,
            "after_worker_restart": after_restart,
            "stale_gauge_before_mark_process_dead": stale,
            "after_mark_process_dead": after_stale_cleanup,
            "counter_persists_across_worker_exit": True,
            "cross_deployment_contamination_without_directory_wipe": contaminated,
            "clean_new_deployment_after_directory_wipe": clean_deployment,
            "decision": "PASS_WITH_LIFECYCLE_REQUIREMENTS",
        }, indent=2, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("parent", "worker", "collect", "mark-dead"), nargs="?", default="parent")
    parser.add_argument("arguments", nargs="*")
    args = parser.parse_args()
    if args.command == "worker":
        worker(
            int(args.arguments[0]), args.arguments[1], args.arguments[2],
            Path(args.arguments[3]), Path(args.arguments[4]),
        )
    elif args.command == "collect":
        collect()
    elif args.command == "mark-dead":
        mark_dead(int(args.arguments[0]))
    else:
        parent()


if __name__ == "__main__":
    main()
