#!/usr/bin/env python3
"""Owner setup of the corrected descriptor-bound, one-use D11 capability.

Preserves source and retires only the exact unused path-only sudo grant.
Does not execute the source operator. Terminal password input is inherited.
"""
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys

ROOT_COMMAND = r'''set -euo pipefail
umask 077
[[ "$(id -u)" == 0 && "$(id -g)" == 0 && "$(hostname -s)" == omnilyzerdev ]]
D=/home/trust/m05-d11-delivery-fd-access-review
W="$D/access_fd_once.py"
WS=fe1c6c615f38a4f450ff6da0984437003de023066017bcf7ca29ef33405aba48
SS=e4ea1e0d6d1657672a4aeeafba4d444b72f89223742a7b7ddf339f67e3b6694a
OS=039efb6590591bb5061b346cc457d9ba12fa769e38df8e72bf3af747eb94c09d
R=/usr/local/lib/m05-analytics016-d11-delivery
E=/usr/local/sbin/omnilyzer-m05-d11-delivery-fd-once
G=/etc/sudoers.d/omnilyzer-m05-d11-delivery-fd
OLD=/usr/local/sbin/omnilyzer-m05-d11-delivery-once
OLDG=/etc/sudoers.d/omnilyzer-m05-d11-delivery
ARCHIVE="$R/retired-path-only-sudoers"
for p in /usr/local/lib /usr/local/sbin /etc/sudoers.d "$R"; do
 [[ ! -L "$p" && "$(stat -c '%u:%g:%a:%F' "$p")" == 0:0:755:directory ]]
done
[[ ! -L /home/trust && ! -L "$D" && "$(stat -c '%u:%g:%a:%F' "$D")" == 1001:1001:700:directory ]]
[[ ! -L "$W" && "$(stat -c '%u:%g:%a:%h:%F' "$W")" == '1001:1001:600:1:regular file' ]]
[[ ! -L "$R/operator.py" && "$(stat -c '%u:%g:%a:%h:%F' "$R/operator.py")" == '0:0:400:1:regular file' ]]
[[ ! -L "$OLD" && "$(stat -c '%u:%g:%a:%h:%F' "$OLD")" == '0:0:750:1:regular file' ]]
[[ ! -L "$OLDG" && "$(stat -c '%u:%g:%a:%h:%F' "$OLDG")" == '0:0:440:1:regular file' ]]
printf '%s  %s\n' "$WS" "$W" "$SS" "$R/operator.py" "$OS" "$OLD" | sha256sum --check --status
printf 'trust ALL=(root) NOPASSWD: sha256:%s %s ""\n' "$OS" "$OLD" | cmp -s - "$OLDG"
for p in "$E" "$G" "$ARCHIVE" /var/lib/omnilyzer/deployment/.m05-d11-delivery-fd-command-consumed /var/lib/omnilyzer/deployment/.m05-d11-delivery-command-consumed /var/lib/omnilyzer/deployment/.m05-analytics016-d11-delivery-before /opt/omnilyzer/deployment/.m05-analytics016-d11-delivery-prior-766e /opt/omnilyzer/deployment/.analytics-app-reviewed-staging; do
 [[ ! -e "$p" && ! -L "$p" ]]
done
install -o 0 -g 0 -m 0750 -- "$W" "$E"
[[ "$(stat -c '%u:%g:%a:%h:%F' "$E")" == '0:0:750:1:regular file' ]]
printf '%s  %s\n' "$WS" "$E" | sha256sum --check --status
T=$(mktemp /etc/sudoers.d/.m05-d11-delivery-fd.XXXXXXXX)
trap 'rm -f -- "$T"' EXIT
printf 'trust ALL=(root) NOPASSWD: sha256:%s %s ""\n' "$WS" "$E" > "$T"
chown 0:0 "$T"
chmod 0440 "$T"
/usr/sbin/visudo -cf "$T" >/dev/null
mv -T -- "$T" "$G"
mv -T -- "$OLDG" "$ARCHIVE"
/usr/sbin/visudo -c >/dev/null
printf 'M05_DELIVERY_FD_EXACT_ONE_USE_ACCESS_READY_NO_SOURCE_INSTALL\n'
'''


def main():
    if (len(sys.argv) != 1 or (os.getuid(), os.geteuid()) != (1004, 1004)
            or socket.gethostname() != 'small-laptop'):
        print('M05_DELIVERY_FD_ACCESS_OWNER_WRONG_CALLER_HOLD')
        return 2
    logpath = Path('/home/trust/m05-access-setup/m05-delivery-fd-access-result.txt')
    fd = os.open(logpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb', buffering=0) as log:
        command = 'sudo /bin/bash -c ' + shlex.quote(ROOT_COMMAND)
        with subprocess.Popen([
            '/usr/bin/ssh', '-tt', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=15',
            'trust@100.108.144.83', command,
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
            while chunk := child.stdout.read1(4096):
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                log.write(chunk)
            return child.wait()


if __name__ == '__main__':
    raise SystemExit(main())
