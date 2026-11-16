#!/usr/bin/env bash
# File: deployment/m05_uid991_readonly_once.sh
# Purpose: Execute one reviewed, fixed-output UID991 Docker/source classifier
#          from an immutable, root-protected /run snapshot. No product change.
# Related: deployment/analytics_uid991_readonly_probe.py,
#          deployment/tests/test_analytics_uid991_readonly_probe.py,
#          docs/operations/task014-pre-release-checklist.md.
# Authority: SOURCE ONLY. Requires separate independent M04 exact-SHA review
#            and Product Owner root launch. No install/dispatch/replay permission.
set -Eeuo pipefail
umask 077

# Section 1: Reject untrusted invocation before any filesystem modification.
hold() {
  # Emit only fixed literals, never dynamic path or exception information.
  printf '%s\n' 'M05_UID991_READONLY_LAUNCH_HOLD_NO_RETRY'
  exit 2
}

[[ "$#" -eq 0 ]] || hold
[[ "$(id -u)" == 0 && "$(id -g)" == 0 ]] || hold
[[ "$(hostname -s)" == omnilyzerdev ]] || hold

# Require execution from an independently prepared root-only snapshot.
self=$(readlink -f -- "$0")
[[ ! -L "$0" ]] || hold
[[ "$self" == /run/m05-uid991-launch.*/* ]] || hold
[[ -f "$self" && ! -L "$self" ]] || hold
[[ "$(stat -c '%u:%g:%a:%h' -- "$self")" == '0:0:400:1' ]] || hold
parent=$(dirname -- "$self")
[[ "$(stat -c '%u:%g:%a' -- "$parent")" == '0:0:700' ]] || hold

# Section 2: Pin the exact unprivileged review source and destination.
source_dir=/home/omnigpt/repos/omnilyzer-platform/.m05-uid991-review
source_py="$source_dir/analytics_uid991_readonly_probe.py"
expected_sha=679930c0152d528d982c17d62e178fc0ef82f6c9a96b6d19664fe89eb3db681e
[[ -d "$source_dir" && ! -L "$source_dir" ]] || hold
[[ "$(stat -c '%u:%g:%a' -- "$source_dir")" == '1005:1005:700' ]] || hold
[[ -f "$source_py" && ! -L "$source_py" ]] || hold
[[ "$(stat -c '%u:%g:%a:%h:%s' -- "$source_py")" == '1005:1005:600:1:7153' ]] || hold
[[ "$(sha256sum -- "$source_py" | cut -d' ' -f1)" == "$expected_sha" ]] || hold
[[ -x /usr/bin/setpriv && -x /opt/omnilyzer/deployment/venv/bin/python ]] || hold

# Section 3: Copy first, verify root ownership, then run as strictly UID991.
# This new private scratch is unrelated to every prior consumed installer.
run_dir=$(mktemp -d /run/m05-uid991-probe.XXXXXXXX) || hold
cleanup() {
  # Only our unique /run scratch is removed. Never touch source or receipts.
  if [[ -n "${run_dir:-}" && "$run_dir" == /run/m05-uid991-probe.* ]]; then
    rm -f -- "$run_dir/probe.py"
    rmdir -- "$run_dir"
  fi
}
trap cleanup EXIT
install -o 0 -g 991 -m 0440 -- "$source_py" "$run_dir/probe.py" || hold
chown 0:991 -- "$run_dir" || hold
chmod 0750 -- "$run_dir" || hold
[[ "$(stat -c '%u:%g:%a:%h:%s' -- "$run_dir/probe.py")" == '0:991:440:1:7153' ]] || hold
[[ "$(sha256sum -- "$run_dir/probe.py" | cut -d' ' -f1)" == "$expected_sha" ]] || hold
[[ "$(stat -c '%u:%g:%a' -- "$run_dir")" == '0:991:750' ]] || hold
printf '%s\n' 'M05_UID991_READONLY_ROOT_SNAPSHOT_PASS'

# The isolated child uses existing source/blue/green read-only APIs only.
# No stdout API payloads and no secrets leave the child process.
set +e
/usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 HOME=/nonexistent \
  /usr/bin/setpriv --reuid 991 --regid 991 --groups 992 --no-new-privs \
  /opt/omnilyzer/deployment/venv/bin/python -I -B "$run_dir/probe.py" </dev/null 2>/dev/null
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
  printf '%s\n' 'M05_UID991_READONLY_CLASSIFIER_PASS_NO_INSTALL'
else
  printf '%s\n' 'M05_UID991_READONLY_CLASSIFIER_HOLD_NO_INSTALL_OR_RETRY'
fi
exit "$status"
