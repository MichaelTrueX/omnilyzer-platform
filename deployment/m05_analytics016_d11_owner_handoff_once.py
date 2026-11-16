#!/usr/bin/env python3
"""File: deployment/m05_analytics016_d11_owner_handoff_once.py

Purpose: Perform ONE owner-interactive, SHA-locked source-only recovery
         from installed private Analytics 766e source to reviewed PR296 d11.
Related: deployment/m05_pr296_d11_fresh_20261116_source_only.py,
         deployment/tests/test_m05_analytics016_source_recovery.py,
         original signed Task013 Analytics 0.16.0, platform Issue #281.

Authority: Source candidate only until one independent M04 exact-SHA
           review. Does NOT authorize production, Task014 dispatch, replay
           reset, Docker changes, or reuse of consumed source-only operators.
Security: No password or secret is stored, forwarded to ChatGPT, or logged.
          Owner supplies existing sudo password exclusively in local terminal.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys

# Section 1: Static original DEV host, owner identity and new source-only
# SHA. There is NO user-selected host, source path, shell or operation mode.
_HOST = "trust@100.108.144.83"
_STAGE = "/home/trust/m05-analytics016-d11-fresh-review"
_SOURCE = _STAGE + "/m05_pr296_d11_fresh_20261116_source_only.py"
_SOURCE_SHA = "3201abfe5636228714385fed95655bf55a3f6baffd96dd5488523741a842ce71"
_SOURCE_SIZE = 30620

# Section 2: Fixed root-owned 0400 snapshot, exact immutable source check,
# and single execution of new source-only operator. No new sudoers rule.
_ROOT_COMMAND = r"""
set -Eeuo pipefail
umask 077
test "$(id -u)" = 0 && test "$(id -g)" = 0
test "$(hostname -s)" = omnilyzerdev
stage=""" + shlex.quote(_STAGE) + r"""
source_file=""" + shlex.quote(_SOURCE) + r"""
expected_sha=""" + _SOURCE_SHA + r"""
test -d "$stage" && test ! -L "$stage"
test "$(stat -c '%u:%g:%a' "$stage")" = 1001:1001:700
test -f "$source_file" && test ! -L "$source_file"
test "$(stat -c '%u:%g:%a:%h:%s' "$source_file")" = 1001:1001:600:1:30620
test "$(sha256sum "$source_file" | cut -d' ' -f1)" = "$expected_sha"
directory=$(mktemp -d /run/m05-analytics016-d11-fresh-launch.XXXXXXXX)
cleanup() {
    if test -n "${directory:-}" && test -d "$directory"; then
        rm -f -- "$directory/operator.py"
        rmdir -- "$directory"
    fi
}
trap cleanup EXIT
test "$(stat -c '%u:%g:%a' "$directory")" = 0:0:700
install -o 0 -g 0 -m 0400 -- "$source_file" "$directory/operator.py"
test "$(stat -c '%u:%g:%a:%h:%s' "$directory/operator.py")" = 0:0:400:1:30620
test "$(sha256sum "$directory/operator.py" | cut -d' ' -f1)" = "$expected_sha"
printf '%s\n' M05_016_FRESH_OWNER_ROOT0400_SNAPSHOT_PASS
# Preserve the real Python exit code while printing ONLY fixed marker lines.
# The operator itself does all root-owned source, replay and UID991 checks.
# This is a source-only transaction. It cannot submit the signed release.
/usr/bin/python3 -I -B "$directory/operator.py" \
  --apply-approved-analytics016-d11-fresh-once 2>/dev/null |
  /usr/bin/grep -E '^M05_016_FRESH_[A-Z0-9_]+$'
"""


def main() -> int:
    """Run once on the owner's authorized laptop, never retry after HOLD."""
    if (sys.argv != [__file__] or os.getuid() != 1004
            or os.geteuid() != 1004):
        print("M05_016_FRESH_OWNER_HANDOFF_HOLD_WRONG_CALLER")
        return 2
    command = [
        "/usr/bin/ssh", "-tt",
        "-o", "StrictHostKeyChecking=yes",
        _HOST, "sudo /bin/bash -c " + shlex.quote(_ROOT_COMMAND),
    ]
    # Inherited real terminal allows platform SSH and sudo authorization.
    # No shell=False override, no captured credentials, no automatic retries.
    return subprocess.run(command, check=False).returncode


# Section 3: Only direct, zero-argument invocation can reach SSH.
if __name__ == "__main__":
    raise SystemExit(main())
