#!/bin/bash
# File: deployment/m05_codex_root_access_setup.sh
# Purpose: Owner-authorized M05 operational elevation, 16 November 2026.
# Related: Issue281; SECURITY.md; owner's explicit chat authorization.
# Grants the existing operator arbitrary root commands/scripts until revoked.
# It does not run a release, change a service, or replace existing sudo rules.
set -euo pipefail
[[ $# == 0 ]]
case "$(hostname -s):$(id -u):$(id -g)" in
    omnilyzerdev:1001:1001|truexmainserver:1000:1000) ;;
    *) printf 'M05_CODEX_ACCESS_WRONG_CALLER\n' >&2; exit 2 ;;
esac

sudo /bin/bash -c '
set -euo pipefail
umask 077
[[ $(id -u) == 0 && $(id -g) == 0 ]]
case "$(hostname -s)" in
    omnilyzerdev) ACCOUNT=trust; EXPECTED_UID=1001 ;;
    truexmainserver) ACCOUNT=trusthansen; EXPECTED_UID=1000 ;;
    *) exit 2 ;;
esac
[[ $(id -u "$ACCOUNT") == "$EXPECTED_UID" ]]
for D in /etc /etc/sudoers.d; do
    [[ ! -L "$D" ]]
    case "$(stat -c "%u:%g:%a:%F" "$D")" in
        0:0:755:directory|0:0:750:directory) ;;
        *) exit 2 ;;
    esac
done
/usr/sbin/visudo -c >/dev/null
GRANT=/etc/sudoers.d/omnilyzer-m05-codex-root
RULE="$ACCOUNT ALL=(root) NOPASSWD: ALL"
if [[ -e "$GRANT" || -L "$GRANT" ]]; then
    [[ ! -L "$GRANT" && $(stat -c "%u:%g:%a:%h:%F" "$GRANT") == "0:0:440:1:regular file" ]]
    printf "%s\n" "$RULE" | cmp -s - "$GRANT"
    printf "M05_CODEX_ROOT_ACCESS_ALREADY_INSTALLED\n"
    exit 0
fi
T=$(mktemp /etc/sudoers.d/.m05-codex-access.XXXXXXXX)
trap '\''rm -f -- "$T"'\'' EXIT
printf "%s\n" "$RULE" > "$T"
chown 0:0 "$T"
chmod 0440 "$T"
/usr/sbin/visudo -cf "$T" >/dev/null
# Hard-link publication refuses to overwrite any concurrent existing grant.
ln -- "$T" "$GRANT"
rm -- "$T"
if ! /usr/sbin/visudo -c >/dev/null; then
    rm -f -- "$GRANT"
    /usr/sbin/visudo -c >/dev/null
    exit 1
fi
/usr/bin/logger -p authpriv.notice -t omnilyzer-m05 "Owner-authorized Codex root access installed for $ACCOUNT; remove grant at M05 closeout"
printf "M05_CODEX_ROOT_ACCESS_INSTALLED\n"
'

# Verify the caller can actually execute its next root command unattended.
[[ $(sudo -n /usr/bin/id -u) == 0 ]]
printf 'M05_CODEX_UNATTENDED_ROOT_PASS\n'
