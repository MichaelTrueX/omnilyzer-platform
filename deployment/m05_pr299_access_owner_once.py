#!/usr/bin/env python3
"""Owner setup for the exact PR299 read-only/source-transition capability.

Bootstrap provisions reviewed immutable code and two exact commands only.
It never starts the transition, signed workflow, Docker operation or service.
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
D=/home/trust/m05-pr299-source-review
P="$D/transition.py"
F="$D/analytics_active_state_review.py"
SHA=8ad25df8c10c86d9b85f1820d6b6272627a8069ae50f34d1b0fd74e784996f56
FS=25a193c3c8511d060d8d1d4b7528edf2671a507cb7b97acde86e33d391d0fddb
RS=0d38abdf0f8fe285e715f01edb5c5c459131fd182654fefb33745fe29f19df9b
SS=e4ea1e0d6d1657672a4aeeafba4d444b72f89223742a7b7ddf339f67e3b6694a
R=/usr/local/lib/m05-pr299-source-transition
E=/usr/local/sbin/omnilyzer-m05-pr299-source-transition
G=/etc/sudoers.d/omnilyzer-m05-pr299-source-transition
OLD=/usr/local/sbin/omnilyzer-m05-d11-partial-recovery
OLDG=/etc/sudoers.d/omnilyzer-m05-d11-partial-recovery
OLDLIB=/usr/local/lib/m05-analytics016-d11-delivery
ARCHIVE="$OLDLIB/retired-d11-recovery-sudoers"
for p in /usr/local/lib /usr/local/sbin /etc/sudoers.d "$OLDLIB"; do
 [[ ! -L "$p" && "$(stat -c '%u:%g:%a:%F' "$p")" == 0:0:755:directory ]]
done
[[ ! -L /home/trust && ! -L "$D" && "$(stat -c '%u:%g:%a:%F' "$D")" == 1001:1001:700:directory ]]
for p in "$P" "$F"; do
 [[ ! -L "$p" && "$(stat -c '%u:%g:%a:%h:%F' "$p")" == '1001:1001:600:1:regular file' ]]
done
[[ ! -L "$OLD" && "$(stat -c '%u:%g:%a:%h:%F' "$OLD")" == '0:0:750:1:regular file' ]]
[[ ! -L "$OLDG" && "$(stat -c '%u:%g:%a:%h:%F' "$OLDG")" == '0:0:440:1:regular file' ]]
[[ ! -L "$OLDLIB/operator.py" && "$(stat -c '%u:%g:%a:%h:%F' "$OLDLIB/operator.py")" == '0:0:400:1:regular file' ]]
printf '%s  %s\n' "$SHA" "$P" "$FS" "$F" "$RS" "$OLD" "$SS" "$OLDLIB/operator.py" | sha256sum --check --status
printf 'trust ALL=(root) NOPASSWD: sha256:%s %s --inspect, sha256:%s %s --finish-once\n' "$RS" "$OLD" "$RS" "$OLD" | cmp -s - "$OLDG"
[[ "$(stat -c '%u:%g:%a:%F' /var/lib/omnilyzer/deployment/.m05-analytics016-d11-delivery-before)" == 0:0:700:directory ]]
for p in "$R" "$E" "$G" "$ARCHIVE" /var/lib/omnilyzer/deployment/.m05-d11-delivery-recovery-consumed /var/lib/omnilyzer/deployment/.m05-pr299-source-before /var/lib/omnilyzer/deployment/.m05-pr299-source-consumed /opt/omnilyzer/deployment/.m05-pr299-prior-d11-partial /opt/omnilyzer/deployment/.analytics-app-reviewed-staging; do
 [[ ! -e "$p" && ! -L "$p" ]]
done
mkdir -m 0750 -- "$R"
chown 0:991 "$R"
install -o 0 -g 991 -m 0440 -- "$F" "$R/analytics_active_state_review.py"
install -o 0 -g 0 -m 0750 -- "$P" "$E"
[[ "$(stat -c '%u:%g:%a:%F' "$R")" == 0:991:750:directory ]]
[[ "$(stat -c '%u:%g:%a:%h:%F' "$R/analytics_active_state_review.py")" == '0:991:440:1:regular file' ]]
[[ "$(stat -c '%u:%g:%a:%h:%F' "$E")" == '0:0:750:1:regular file' ]]
printf '%s  %s\n' "$FS" "$R/analytics_active_state_review.py" "$SHA" "$E" | sha256sum --check --status
T=$(mktemp /etc/sudoers.d/.m05-pr299-source-transition.XXXXXXXX)
trap 'rm -f -- "$T"' EXIT
printf 'trust ALL=(root) NOPASSWD: sha256:%s %s --inspect, sha256:%s %s --apply-once\n' "$SHA" "$E" "$SHA" "$E" > "$T"
chown 0:0 "$T"
chmod 0440 "$T"
/usr/sbin/visudo -cf "$T" >/dev/null
mv -T -- "$T" "$G"
mv -T -- "$OLDG" "$ARCHIVE"
/usr/sbin/visudo -c >/dev/null
printf 'M05_PR299_EXACT_ACCESS_READY_NO_SOURCE_TRANSITION\n'
'''


def main():
    if (len(sys.argv) != 1 or (os.getuid(), os.geteuid()) != (1004, 1004)
            or socket.gethostname() != 'small-laptop'):
        print('M05_PR299_OWNER_WRONG_CALLER_HOLD')
        return 2
    path = Path('/home/trust/m05-access-setup/m05-pr299-access-result.txt')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
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
