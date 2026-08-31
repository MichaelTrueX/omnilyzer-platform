#!/usr/bin/env python3
"""Drive deterministic synthetic requests from inside an isolated target container."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import uuid


HOST = "127.0.0.1"
PORT = 8000
SENSITIVE = {
    "workspace_id": "00000000-0000-4000-8000-000000000099",
    "user_id": "user-sensitive-010",
    "email": "sensitive-user@example.invalid",
    "request_id": "1234567890abcdef1234567890abcdef",
    "trace_id": "abcdefabcdefabcdefabcdefabcdefab",
    "authorization": "Bearer sensitive-authorization-010",
    "session": "session-sensitive-010",
    "query": "query-sensitive-010",
    "customer_id": "customer-sensitive-object-010",
}


def request(
    connection: http.client.HTTPConnection,
    method: str,
    target: str,
    *,
    headers: dict[str, str] | None = None,
) -> int:
    """Make one local request and return its status after consuming the body."""

    connection.request(method, target, headers=headers or {})
    response = connection.getresponse()
    response.read()
    return response.status


def seed(users: int, unmatched: int) -> dict[str, object]:
    """Generate high-volume hostile paths and a finite set of metric dimensions."""

    headers = {
        "X-Workspace-ID": SENSITIVE["workspace_id"],
        "X-User-ID": SENSITIVE["user_id"],
        "X-Request-ID": SENSITIVE["request_id"],
        "traceparent": f"00-{SENSITIVE['trace_id']}-1111111111111111-01",
        "Cookie": f"sessionid={SENSITIVE['session']}",
    }
    def drive_slice(kind: str, start: int, stop: int) -> int:
        connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
        failures = 0
        for item in range(start, stop):
            if kind == "users":
                target = f"/api/users/{item}?email={SENSITIVE['email']}&token={SENSITIVE['query']}"
                expected = 200
            else:
                raw_id = uuid.UUID(int=item + 1)
                target = f"/unexpected/{raw_id}/object-{item}?secret={SENSITIVE['query']}"
                expected = 404
            failures += request(connection, "GET", target, headers=headers) != expected
        connection.close()
        return failures

    work: list[tuple[str, int, int]] = []
    for kind, count in (("users", users), ("unmatched", unmatched)):
        chunk = max(1, (count + 31) // 32)
        work.extend((kind, start, min(start + chunk, count)) for start in range(0, count, chunk))
    with ThreadPoolExecutor(max_workers=32) as executor:
        failures = sum(executor.map(lambda item: drive_slice(*item), work))
    requests = users + unmatched

    connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
    fixed = [
        ("POST", f"/api/orders/{SENSITIVE['customer_id']}", {}, 200),
        ("PATCH", "/api/documents/" + "a" * 4096, {}, 200),
        ("BREW", "/api/users/unexpected-method", {}, 200),
        ("GET", "/api/secure", {"Authorization": SENSITIVE["authorization"]}, 401),
        (
            "GET",
            "/api/secure",
            {
                "Authorization": "Bearer synthetic-valid-token",
                "X-Workspace-ID": "00000000-0000-4000-8000-000000000001",
            },
            200,
        ),
        ("GET", "/livez", {}, 200),
        ("GET", "/readyz", {}, 200),
    ]
    for method, target, item_headers, expected in fixed:
        failures += request(connection, method, target, headers=item_headers) != expected
        requests += 1
    connection.close()
    return {
        "requests": requests,
        "failures": failures,
        "distinct_user_ids": users,
        "distinct_unmatched_ids": unmatched,
        "synthetic_sensitive_values": SENSITIVE,
    }


def availability(count: int) -> dict[str, int]:
    """Exercise domain, health, readiness, and security while Prometheus is absent."""

    connection = http.client.HTTPConnection(HOST, PORT, timeout=2)
    failures = 0
    for item in range(count):
        failures += request(connection, "GET", f"/api/users/{item}") != 200
    failures += request(connection, "GET", "/livez") != 200
    failures += request(connection, "GET", "/readyz") != 200
    failures += request(connection, "GET", "/api/secure") != 401
    connection.close()
    return {"requests": count + 3, "failures": failures}


def control(path: str) -> dict[str, object]:
    """Invoke a fixed synthetic control and return its status."""

    connection = http.client.HTTPConnection(HOST, PORT, timeout=2)
    status = request(connection, "POST", path)
    connection.close()
    return {"status": status}


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    seed_parser = subparsers.add_parser("seed")
    seed_parser.add_argument("--users", type=int, required=True)
    seed_parser.add_argument("--unmatched", type=int, required=True)
    availability_parser = subparsers.add_parser("availability")
    availability_parser.add_argument("--count", type=int, default=200)
    subparsers.add_parser("health")
    mode_parser = subparsers.add_parser("mode")
    mode_parser.add_argument("value", choices=("normal", "slow", "malformed"))
    deployment_parser = subparsers.add_parser("deployment")
    deployment_parser.add_argument("app_version")
    deployment_parser.add_argument("platform_version")
    args = parser.parse_args()

    if args.command == "seed":
        result = seed(args.users, args.unmatched)
    elif args.command == "availability":
        result = availability(args.count)
    elif args.command == "health":
        connection = http.client.HTTPConnection(HOST, PORT, timeout=1)
        ok = request(connection, "GET", "/livez") == 200
        connection.close()
        raise SystemExit(0 if ok else 1)
    elif args.command == "mode":
        result = control(f"/__mode?value={args.value}")
    else:
        result = control(
            f"/__deployment?app_version={args.app_version}"
            f"&platform_version={args.platform_version}"
        )
    print(json.dumps(result, sort_keys=True))
    if result.get("failures", 0) or result.get("status", 200) != 200:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
