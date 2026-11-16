#!/usr/bin/env python3
"""One physical owner setup of the exact one-use D11 source capability.

The agent subsequently invokes the fixed sudo command itself. No general
shell grant, signed promotion authority or persistent privileged process.
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
D=/home/trust/m05-d11-delivery-access-review
S="$D/operator.py"
W="$D/access_once.py"
SS=e4ea1e0d6d1657672a4aeeafba4d444b72f89223742a7b7ddf339f67e3b6694a
WS=039efb6590591bb5061b346cc457d9ba12fa769e38df8e72bf3af747eb94c09d
R=/usr/local/lib/m05-analytics016-d11-delivery
E=/usr/local/sbin/omnilyzer-m05-d11-delivery-once
G=/etc/sudoers.d/omnilyzer-m05-d11-delivery
[[ ! -L /home/trust && ! -L "$D" && "$(stat -c '%u:%g:%a:%F' "$D")" == 1001:1001:700:directory ]]
for p in "$S" "$W"; do
 [[ ! -L "$p" && "$(stat -c '%u:%g:%a:%h:%F' "$p")" == '1001:1001:600:1:regular file' ]]
done
printf '%s  %s\n' "$SS" "$S" "$WS" "$W" | sha256sum --check --status
for p in /usr/local/lib /usr/local/sbin /etc/sudoers.d; do
 [[ ! -L "$p" && "$(stat -c '%u:%g:%a:%F' "$p")" == 0:0:755:directory ]]
done
[[ ! -e "$R" && ! -L "$R" && ! -e "$E" && ! -L "$E" && ! -e "$G" && ! -L "$G" ]]
[[ ! -e /var/lib/omnilyzer/deployment/.m05-d11-delivery-command-consumed ]]
mkdir -m 0755 -- "$R"
install -o 0 -g 0 -m 0400 -- "$S" "$R/operator.py"
install -o 0 -g 0 -m 0750 -- "$W" "$E"
[[ "$(stat -c '%u:%g:%a:%h:%F' "$R/operator.py")" == '0:0:400:1:regular file' ]]
[[ "$(stat -c '%u:%g:%a:%h:%F' "$E")" == '0:0:750:1:regular file' ]]
printf '%s  %s\n' "$SS" "$R/operator.py" "$WS" "$E" | sha256sum --check --status
T=$(mktemp /etc/sudoers.d/.m05-d11-delivery.XXXXXXXX)
trap 'rm -f -- "$T"' EXIT
printf 'trust ALL=(root) NOPASSWD: sha256:%s %s ""\n' "$WS" "$E" > "$T"
chown 0:0 "$T"
chmod 0440 "$T"
/usr/sbin/visudo -cf "$T" >/dev/null
mv -T -- "$T" "$G"
/usr/sbin/visudo -c >/dev/null
printf 'M05_DELIVERY_EXACT_ONE_USE_ACCESS_READY_NO_SOURCE_INSTALL\n'
'''


def main():
    if (len(sys.argv) != 1 or (os.getuid(), os.geteuid()) != (1004, 1004)
            or socket.gethostname() != 'small-laptop'):
        print('M05_DELIVERY_ACCESS_OWNER_WRONG_CALLER_HOLD')
        return 2
    logpath = Path('/home/trust/m05-access-setup/m05-delivery-access-result.txt')
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
