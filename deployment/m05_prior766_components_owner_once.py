#!/usr/bin/env python3
"""Owner-interactive once-only root snapshot of the Issue281 read-only matrix.

Requires physical small-laptop terminal. Inherits SSH/sudo terminal I/O;
never captures a password. No retry after any outcome or interruption.
"""
import os
import shlex
import socket
import subprocess
import sys

ROOT_COMMAND = r'''set -euo pipefail
umask 077
[[ "$(id -u)" == 0 && "$(id -g)" == 0 && "$(hostname -s)" == omnilyzerdev ]]
P=/home/trust/m05-prior766-components-review/m05_prior766_component_readonly.py
SHA=99a3231ed29cf3b244a6756ab2db150e4925339e4cd09b12ec4a29002d3c07b0
[[ ! -L /home/trust && ! -L /home/trust/m05-prior766-components-review && ! -L "$P" ]]
[[ "$(stat -c '%u:%g:%a:%F' /home/trust/m05-prior766-components-review)" == 1001:1001:700:directory ]]
[[ "$(stat -c '%u:%g:%a:%h:%F' "$P")" == '1001:1001:600:1:regular file' ]]
printf '%s  %s\n' "$SHA" "$P" | sha256sum --check --status
R=$(mktemp -d /run/m05-prior766-components.XXXXXXXX)
cleanup() { rm -f -- "$R/readonly.py"; rmdir -- "$R"; }
trap cleanup EXIT
[[ "$(stat -c '%u:%g:%a:%F' "$R")" == 0:0:700:directory ]]
install -o 0 -g 0 -m 0400 -- "$P" "$R/readonly.py"
[[ "$(stat -c '%u:%g:%a:%h:%F' "$R/readonly.py")" == '0:0:400:1:regular file' ]]
printf '%s  %s\n' "$SHA" "$R/readonly.py" | sha256sum --check --status
printf 'M05_COMPONENT_ROOT0400_SNAPSHOT_PASS\n'
/usr/bin/python3 -I -B "$R/readonly.py"
'''


def main():
    if (len(sys.argv) != 1 or (os.getuid(), os.geteuid()) != (1004, 1004)
            or socket.gethostname() != 'small-laptop'):
        print('M05_COMPONENT_OWNER_WRONG_CALLER_HOLD_NO_RETRY')
        return 2
    command = 'sudo /bin/bash -c ' + shlex.quote(ROOT_COMMAND)
    return subprocess.run([
        '/usr/bin/ssh', '-tt', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=15',
        'trust@100.108.144.83', command,
    ], check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
