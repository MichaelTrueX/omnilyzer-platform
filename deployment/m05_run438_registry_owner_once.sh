#!/bin/bash
# Owner-interactive bounded read; no sudo grant, service change or release.
set -euo pipefail
[[ $# == 0 && $(id -u) == 1000 && $(hostname -s) == truexmainserver ]]
umask 077
set -o noclobber
RESULT=/home/trusthansen/m05-access-setup/m05-run438-registry-result.txt
sudo /bin/bash -c '
set -euo pipefail
umask 077
[[ $(id -u) == 0 && $(id -g) == 0 && $(hostname -s) == truexmainserver ]]
P=/home/trusthansen/m05-access-setup/m05_run438_registry_readonly.py
SHA=46538d1d7c17f900f27479bc96da4c269b42a0cd00b4cf72ce826a0c1e5b7ba3
[[ ! -L "$P" && $(stat -c "%u:%g:%a:%h:%F" "$P") == "1000:1000:600:1:regular file" ]]
printf "%s  %s\n" "$SHA" "$P" | sha256sum --check --status
R=$(mktemp -d /run/m05-run438-readonly.XXXXXXXX)
trap '\''rm -f -- "$R/probe.py"; rmdir -- "$R"'\'' EXIT
install -o 0 -g 0 -m 0400 -- "$P" "$R/probe.py"
printf "%s  %s\n" "$SHA" "$R/probe.py" | sha256sum --check --status
/usr/bin/python3 -I -B "$R/probe.py"
' > "$RESULT"
cat -- "$RESULT"
