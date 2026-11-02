#!/usr/bin/env bash
# File: deployment/enable_dev_root_audit.sh
# Purpose: Owner-run, ONE-TIME restricted root metadata access on omnilyzerdev.
# Related: deployment/analytics_dev_host_preflight.py, Task014 source installer
#          and docs/operations/m05-14-task014-analytics-runtime-20261029.md.
# Sections: owner/host identity gate; root-only read-only helper; strict sudoers.
# SECURITY: Does not authorize/deploy Analytics, change services, read secret
# contents, touch databases or grant arbitrary shell/Docker/root operations.
set -euo pipefail
umask 077

if [[ "$(id -u)" != 0 ]]; then
  echo "DENIED: execute with sudo from your administrator account." >&2; exit 1
fi
if [[ "$(hostname -s)" != omnilyzerdev ]] ||
   [[ "$(/usr/bin/id -u omnigpt)" != 1005 ]] ||
   [[ "$(/usr/bin/id -g omnigpt)" != 1005 ]]; then
  echo "DENIED: wrong DEV server or omnigpt UID/GID." >&2; exit 1
fi
if [[ ! -x /usr/sbin/visudo || ! -x /usr/bin/python3 ]] ||
   [[ ! -d /opt/omnilyzer/deployment/app ]]; then
  echo "DENIED: original Task014 DEV installation not found." >&2; exit 1
fi

ROOT_HELPER=/usr/local/libexec/omnilyzer-dev-root-audit.py
SUDOERS=/etc/sudoers.d/91-omnilyzer-dev-root-audit
TMP="$(mktemp -d /root/.omnilyzer-root-audit.XXXXXXXX)"
cleanup() { rm -f -- "$TMP/helper.py" "$TMP/sudoers"; rmdir -- "$TMP"; }
trap cleanup EXIT

# All root-capable source is embedded, reviewed and immutable once installed.
# It is not dynamically imported from a user-writable checkout.
cat > "$TMP/helper.py" <<'PY'
"""File: /usr/local/libexec/omnilyzer-dev-root-audit.py

Purpose: Read-only metadata checks of fixed Task014 Analytics DEV resources.
Related: deployment/analytics_dev_host_preflight.py and original Task014 C17.
Sections: fixed resources, no-follow stat, fixed systemd status, safe report.
Security: NO source/data write, secret read, network, shell, Docker call,
database access, service mutation, installer import or user-selected paths.
"""
from __future__ import annotations
import json
import os
import stat
import subprocess
import sys

PATHS = (
    ("canary_app", "/opt/omnilyzer/deployment/app", "directory", 0o755),
    ("analytics_app", "/opt/omnilyzer/deployment/analytics-app", "directory", 0o755),
    ("source_approval", "/etc/omnilyzer/deployment/dev/analytics-source-install.json", "file", 0o600),
    ("source_archive", "/opt/omnilyzer/deployment/.analytics-source-review.tar", "file", 0o600),
    ("broker_config", "/etc/omnilyzer/deployment/broker/analytics.json", "file", 0o640),
    ("executor_config", "/etc/omnilyzer/deployment/dev/analytics-executor.json", "file", 0o640),
    ("secrets_directory", "/var/lib/omnilyzer/deployment/analytics/dev/secrets", "directory", 0o710),
    ("rootless_bind_socket", "/run/omnilyzer/deployment/rootless-docker/docker.sock", "socket", None),
    ("rootless_daemon_socket", "/run/user/991/docker.sock", "socket", None),
)
UNITS = (
    ("canary_broker", "omnilyzer-deployment-broker.service"),
    ("canary_executor_socket", "omnilyzer-deployment-executor.socket"),
    ("analytics_executor_socket", "omnilyzer-deployment-analytics-executor.socket"),
)


def inode(path: str, kind: str, mode: int | None) -> dict[str, object]:
    """Stat one fixed inode without traversing its final symlink or data."""
    try:
        meta = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return {"state": "missing"}
    except PermissionError:
        return {"state": "inaccessible"}
    except OSError:
        return {"state": "unknown"}
    correct_type = (
        (kind == "directory" and stat.S_ISDIR(meta.st_mode))
        or (kind == "file" and stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1)
        or (kind == "socket" and stat.S_ISSOCK(meta.st_mode))
    )
    correct_owner = meta.st_uid == 0 if kind != "socket" else meta.st_uid in (0, 991)
    octal = stat.S_IMODE(meta.st_mode)
    return {
        "state": "present" if correct_type and correct_owner and
                 (mode is None or mode == octal) else "invalid",
        "uid": meta.st_uid,
        "gid": meta.st_gid,
        "mode": format(octal, "04o"),
    }


def unit(name: str) -> str:
    """Ask systemd only for one fixed unit's status; never change it."""
    try:
        result = subprocess.run(
            ("/usr/bin/systemctl", "is-active", name),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=4, check=False,
            env={"LANG": "C", "PATH": "/usr/bin:/bin"},
        )
        state = result.stdout.decode("ascii").strip()
        if state in ("active", "inactive", "failed", "not-found",
                     "activating", "deactivating", "unknown"):
            return state
    except (OSError, UnicodeError, subprocess.SubprocessError):
        pass
    return "unknown"


def main() -> int:
    """Require the ONLY approved read-only argument and actual root identity."""
    if sys.argv[1:] != ["--read-only"] or os.getuid() != 0 or os.geteuid() != 0:
        return 2
    print(json.dumps({
        "stage": "dev", "product_id": "analytics", "read_only": True,
        "deployment_authorized": False, "signed_release_verified": False,
        "paths": {key: inode(path, kind, mode) for key, path, kind, mode in PATHS},
        "services": {key: unit(name) for key, name in UNITS},
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY

cat > "$TMP/sudoers" <<'SUDOERS'
# File: /etc/sudoers.d/91-omnilyzer-dev-root-audit
# Purpose: ONE exact root-owned Task014 read-only audit for omnigpt.
# Related: /usr/local/libexec/omnilyzer-dev-root-audit.py.
# No sudo ALL, wildcard arguments, writable scripts, shell, Docker or install.
omnigpt ALL=(root) NOPASSWD:NOSETENV: /usr/bin/python3 -I /usr/local/libexec/omnilyzer-dev-root-audit.py --read-only
SUDOERS

# Validate before the first privileged file is changed.
chmod 0600 "$TMP/helper.py" "$TMP/sudoers"
/usr/bin/python3 -I - "$TMP/helper.py" <<'PY'
from pathlib import Path
import sys
compile(Path(sys.argv[1]).read_bytes(), "root-audit.py", "exec")
print("ROOT_AUDIT_CODE_COMPILES")
PY
/usr/sbin/visudo -cf "$TMP/sudoers" >/dev/null
if [[ -L "$ROOT_HELPER" || -L "$SUDOERS" ]]; then
  echo "DENIED: unexpected symlink in privileged destination." >&2; exit 1
fi
if [[ -e "$ROOT_HELPER" ]] && ! cmp -s "$TMP/helper.py" "$ROOT_HELPER"; then
  echo "DENIED: different root helper already present." >&2; exit 1
fi
if [[ -e "$SUDOERS" ]] && ! cmp -s "$TMP/sudoers" "$SUDOERS"; then
  echo "DENIED: different sudoers rule already present." >&2; exit 1
fi

# Refuse any pre-existing symlink and never silently chown/chmod a
# pre-existing directory containing other applications' privileged files.
if [[ -L /usr/local/libexec ]] || [[ -L /etc/sudoers.d ]]; then
  echo "DENIED: privileged parent directory is a symlink." >&2; exit 1
fi
if [[ "$(stat -c '%u:%g:%a' /etc/sudoers.d)" != "0:0:755" ]] &&
   [[ "$(stat -c '%u:%g:%a' /etc/sudoers.d)" != "0:0:750" ]]; then
  echo "DENIED: sudoers parent ownership/mode unexpected." >&2; exit 1
fi
if [[ ! -e /usr/local/libexec ]]; then
  install -d -o root -g root -m 0755 /usr/local/libexec
fi
if [[ "$(stat -c '%u:%g:%a' /usr/local/libexec)" != "0:0:755" ]]; then
  echo "DENIED: helper directory ownership/mode unexpected." >&2; exit 1
fi
install -o root -g root -m 0644 "$TMP/helper.py" "$ROOT_HELPER"
install -o root -g root -m 0440 "$TMP/sudoers" "$SUDOERS"
/usr/sbin/visudo -cf /etc/sudoers >/dev/null
echo "SCOPED_ROOT_AUDIT_INSTALLED"
echo "ROOT_HELPER_SHA256=$(sha256sum "$ROOT_HELPER" | cut -d' ' -f1)"
echo "ROOT_SUDOERS_SHA256=$(sha256sum "$SUDOERS" | cut -d' ' -f1)"
/usr/bin/python3 -I "$ROOT_HELPER" --read-only
echo "SUCCESS: only this exact read-only root check is permitted for omnigpt."
