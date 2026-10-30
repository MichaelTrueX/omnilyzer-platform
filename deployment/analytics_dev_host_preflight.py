"""File: deployment/analytics_dev_host_preflight.py

Purpose: Run a single read-only M05-14 Analytics DEV host prerequisite matrix,
         distinguishing missing, permission-inaccessible and malformed resources.
Related: deployment/analytics_dev_activation_inputs.py (four reviewed bytes),
         deployment/analytics_isolated_source_install.py (source root),
         deployment/analytics_executor_service_config.py (protected C17),
         deployment/rootless_docker_authority.py (socket layout),
         deployment/tests/test_analytics_dev_host_preflight.py.

Sections: fixed product-only host paths; stat-based metadata probe; service
          activity probe; bounded redacted combined report and CLI.
SECURITY: No writes, sudo, privileged socket access, secret reads, HTTP,
Docker commands, migrations, OIDC/signature assertions or deployment. This
tool does not elevate a 403/permission denial into a claim of missing data.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys

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
    missing = sorted(key for key, value in files.items() if value == "missing")
    inaccessible = sorted(
        key for key, value in files.items() if value == "inaccessible"
    )
    invalid = sorted(key for key, value in files.items() if value == "invalid")
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
        "installed_source_preflight_complete": (
            all(value == "present" for value in files.values())
            and original_ok
            and units["analytics_executor_socket"] == "active"
        ),
        "files": files,
        "services": units,
        "missing": missing,
        "inaccessible": inaccessible,
        "invalid": invalid,
    }


def main() -> int:
    """Emit only bounded source/status labels, no secret, token or full path."""
    if sys.argv[1:] != ["--read-only"]:
        return 2
    print(json.dumps(collect_analytics_dev_preflight(), sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
