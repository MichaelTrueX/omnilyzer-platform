"""File: deployment/analytics_dev_host_preflight.py

Purpose: Run a single read-only M05-14 Analytics DEV host prerequisite matrix,
         distinguishing missing, permission-inaccessible and malformed resources.
Related: deployment/analytics_dev_activation_inputs.py (four reviewed bytes),
         deployment/analytics_isolated_source_install.py (source root),
         deployment/analytics_executor_service_config.py (protected C17),
         deployment/rootless_docker_authority.py (daemon socket identity),
         deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service
         (BindReadOnlyPaths executor-only mount),
         deployment/tests/test_analytics_dev_host_preflight.py.

Sections: fixed product-only host paths; stat-based metadata probe; service
          activity probe; distinguish host prerequisites from executor-private
          mount targets; bounded redacted combined report and CLI.
SECURITY: No writes, sudo, privileged socket access, secret reads, remote HTTP,
Docker commands, migrations, OIDC/signature assertions or deployment. Only\nfixed loopback-only GETs are permitted in --successor-read-only mode. This
tool does not elevate a 403/permission denial into a claim of missing data.
"""
from __future__ import annotations

import http.client
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

# Exact existing Task014 DEV assets, never caller supplied or discovered paths.
_FILES = (
    ("original_canary_app", "/opt/omnilyzer/deployment/app", "directory", 0o755),
    ("analytics_app", "/opt/omnilyzer/deployment/analytics-app", "directory", 0o755),
    ("source_approval", "/etc/omnilyzer/deployment/dev/analytics-source-install.json",
     "file", 0o600),
    ("source_archive", "/opt/omnilyzer/deployment/.analytics-source-review.tar",
     "file", 0o600),
    ("analytics_broker_config", "/etc/omnilyzer/deployment/broker/analytics.json",
     "file", 0o640),
    ("analytics_executor_config", "/etc/omnilyzer/deployment/dev/analytics-executor.json",
     "file", 0o640),
    ("four_secret_directory", "/var/lib/omnilyzer/deployment/analytics/dev/secrets",
     "directory", 0o710),
    ("rootless_bind_socket", "/run/omnilyzer/deployment/rootless-docker/docker.sock",
     "socket", None),
    ("rootless_daemon_socket", "/run/user/991/docker.sock", "socket", None),
)
_SERVICES = (
    ("original_broker", "omnilyzer-deployment-broker.service"),
    ("original_executor_socket", "omnilyzer-deployment-executor.socket"),
    ("analytics_executor_socket", "omnilyzer-deployment-analytics-executor.socket"),
)
_ALLOWED_SYSTEMD = frozenset({
    "active", "inactive", "activating", "deactivating", "failed",
    "not-found", "unknown",
})


def _file_probe(path: str, kind: str, mode: int | None) -> str:
    """Observe one selected object without following links or reading content."""
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return "missing"
    except PermissionError:
        return "inaccessible"
    except OSError:
        return "unknown"
    matching = (
        (kind == "directory" and stat.S_ISDIR(info.st_mode))
        or (kind == "file" and stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        or (kind == "socket" and stat.S_ISSOCK(info.st_mode))
    )
    if (
        not matching or (info.st_uid != 0 and kind != "socket")
        or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
    ):
        return "invalid"
    return "present"


def _unit_probe(name: str) -> str:
    """Read systemd activity only; never start, stop or enable a unit."""
    try:
        result = subprocess.run(
            ("/usr/bin/systemctl", "is-active", name),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=4, check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        if len(result.stdout) > 48:
            return "unknown"
        observed = result.stdout.decode("ascii").strip()
        return observed if observed in _ALLOWED_SYSTEMD else "unknown"
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return "unknown"


def collect_analytics_dev_preflight() -> dict[str, object]:
    """Continue over ALL independent prerequisite checks; no early failure.

    A protected file returning EACCES is NOT reported missing. An inactive
    Analytics service is the correct current NON-INSTALLED state, NOT an
    installation-ready signal. This tool may only report readiness to review,
    not proof of signed release, runtime or real persisted user acceptance.
    """
    files = {
        label: _file_probe(path, kind, mode)
        for label, path, kind, mode in _FILES
    }
    units = {label: _unit_probe(name) for label, name in _SERVICES}
    original_ok = (
        files["original_canary_app"] == "present"
        and units["original_broker"] == "active"
        and units["original_executor_socket"] == "active"
    )
    # The original Task014 systemd design creates this runtime bind path
    # INSIDE the executor's private mount namespace, using RuntimeDirectory
    # and BindReadOnlyPaths from /run/user/991/docker.sock. It need not exist
    # in the host namespace before activation (or when idle).
    # The daemon socket is a real host prerequisite and MUST still be checked.
    private_mount = "rootless_bind_socket"
    required_host_paths = tuple(key for key in files if key != private_mount)
    missing = sorted(
        key for key in required_host_paths if files[key] == "missing"
    )
    inaccessible = sorted(
        key for key in required_host_paths if files[key] == "inaccessible"
    )
    invalid = sorted(
        key for key in required_host_paths if files[key] == "invalid"
    )
    return {
        "schema_version": 1,
        "product_id": "analytics",
        "stage": "dev",
        "read_only": True,
        "deployment_authorized": False,
        "source_revisions_verified": False,
        "release_signatures_verified": False,
        "real_runtime_accepted": False,
        "original_canary_healthy": original_ok,
        "executor_private_mount": {
            "name": private_mount,
            "host_observation": files[private_mount],
            "required_as_host_path": False,
            "actual_executor_mount_verified": False,
        },
        "installed_source_preflight_complete": (
            all(files[key] == "present" for key in required_host_paths)
            and original_ok
            and units["analytics_executor_socket"] == "active"
        ),
        "files": files,
        "services": units,
        "missing": missing,
        "inaccessible": inaccessible,
        "invalid": invalid,
    }



# Section: Task14B successor release preflight using the same host matrix.
# This is not a new broker, installer, release controller or authority.
_OWNER_TRUST_PATH = "/etc/omnilyzer/deployment/dev/analytics-owner-source-signers"
_OWNER_TRUST_PARENTS = (
    "/etc", "/etc/omnilyzer", "/etc/omnilyzer/deployment",
    "/etc/omnilyzer/deployment/dev",
)
_SUCCESSOR_SERVICES = (
    ("analytics_loopback", "omnilyzer-analytics-loopback.service"),
    ("analytics_broker", "omnilyzer-deployment-broker.service"),
    ("analytics_executor_socket", "omnilyzer-deployment-analytics-executor.socket"),
    ("beszel_analytics_agent", "beszel-omnilyzer-agent.service"),
    ("beszel_analytics_proxy", "beszel-omnilyzer-proxy.service"),
)
_PRIVATE_HTTP = (
    ("analytics_ready", 3141, "/readyz"),
    ("analytics_live", 3141, "/livez"),
    ("canary_ready", 3020, "/readyz"),
)


def _owner_trust_metadata_probe() -> str:
    """Inspect the dedicated owner public-key anchor without opening its bytes.

    Only exact root-controlled path and non-writable ancestors may be reported
    present. This is NOT signature verification or a release approval.
    """
    try:
        for directory in _OWNER_TRUST_PARENTS:
            info = os.stat(directory, follow_symlinks=False)
            if (
                not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022
            ):
                return "invalid"
        info = os.stat(_OWNER_TRUST_PATH, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o022
            or not 0 < info.st_size <= 4096
        ):
            return "invalid"
        return "present"
    except FileNotFoundError:
        return "missing"
    except PermissionError:
        return "inaccessible"
    except OSError:
        return "unknown"


def _private_http_status(port: int, path: str) -> str:
    """Read status from ONE fixed loopback-only route, with no redirect/proxy.

    Deliberately consume no response body and emit no headers or credentials.
    A redirect is returned as a status code, never followed to a new host.
    """
    if (port, path) not in {(3141, "/readyz"), (3141, "/livez"), (3020, "/readyz")}:
        return "not-allowed"
    connection = None
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        return str(response.status) if 100 <= response.status <= 599 else "unknown"
    except (OSError, ValueError, http.client.HTTPException):
        return "unavailable"
    finally:
        if connection is not None:
            connection.close()


def collect_analytics_successor_preflight() -> dict[str, object]:
    """Aggregate original and next-release prerequisites without early exit.

    A valid key *file* is not a verified owner signature. HTTP200 is not
    authenticated persistence/tenant isolation. No signed DEV successor is
    authorized by this report, even when every read-only observation passes.
    """
    original = collect_analytics_dev_preflight()
    owner_key = _owner_trust_metadata_probe()
    services = {
        name: _unit_probe(unit) for name, unit in _SUCCESSOR_SERVICES
    }
    http = {
        name: _private_http_status(port, path)
        for name, port, path in _PRIVATE_HTTP
    }
    missing = sorted(original["missing"] + (
        ["owner_source_approval_key"] if owner_key == "missing" else []
    ))
    inaccessible = sorted(original["inaccessible"] + (
        ["owner_source_approval_key"] if owner_key == "inaccessible" else []
    ))
    invalid = sorted(original["invalid"] + (
        ["owner_source_approval_key"] if owner_key == "invalid" else []
    ))
    return {
        **original,
        "schema_version": 2,
        "release_operation": "ordinary-analytics-successor-readonly",
        "owner_source_approval_key": owner_key,
        "successor_services": services,
        "private_http_status": http,
        # Unprivileged EACCES and network failures are UNKNOWN, not a pass
        # or an assertion that root-owned material does not exist.
        "preflight_observations_complete": (
            not inaccessible
            and all(
                status not in ("unknown", "inaccessible", "unavailable")
                for status in (
                    *original["files"].values(), *original["services"].values(),
                    owner_key, *services.values(), *http.values(),
                )
            )
        ),
        "successor_runtime_observed": (
            http["analytics_ready"] == "200"
            and http["analytics_live"] == "200"
            and services["analytics_loopback"] == "active"
            and services["analytics_broker"] == "active"
            and services["analytics_executor_socket"] == "active"
        ),
        "release_decision": "HOLD",
        "task14b_supported_release_verified": False,
        "task14b_owner_signature_verified": False,
        "task14b_m04_qa_accepted": False,
        "task14b_rollback_verified": False,
        "missing": missing,
        "inaccessible": inaccessible,
        "invalid": invalid,
    }

def main() -> int:
    """Emit only bounded source/status labels, no secret, token or full path."""
    if sys.argv[1:] == ["--read-only"]:
        report = collect_analytics_dev_preflight()
    elif sys.argv[1:] == ["--successor-read-only"]:
        report = collect_analytics_successor_preflight()
    else:
        return 2
    print(json.dumps(report, sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
