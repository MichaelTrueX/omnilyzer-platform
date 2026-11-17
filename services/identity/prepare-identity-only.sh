#!/usr/bin/env bash
# File: services/identity/prepare-identity-only.sh
# Purpose: Stage the EXISTING Omnilyzer Django Keycloak BFF on
# truexmainserver as a DISABLED service. No login activation or real secrets.
# Linked files: omnilyzer-identity.service, requirements.txt,
# config/settings.py, nginx-auth-location.conf.review and
# docs/operations/p0-shared-keycloak-sumlaude-identity-20261029.md.
set -Eeuo pipefail

# Section 1: Accept only narrow preflight or administrator preparation.
ROOT=/home/trusthansen/omnilyzer-identity-prep-20261029
REPO="$ROOT/repo"
SOURCE="$ROOT/source"
ARCHIVE="$ROOT/source.tar"
RELEASES=/opt/omnilyzer/identity/releases
CURRENT=/opt/omnilyzer/identity/current
UNIT=/etc/systemd/system/omnilyzer-identity.service
PRIVATE_DIR=/etc/omnilyzer/identity
PIP_SHA=e5ef64ef63ff89a746014ad81658b76c1940385fdcdbc4fcbfa6e3ef1887352d
deny(){ echo "IDENTITY_PREP_DENIED: $*" >&2; exit 1; }
[[ $# == 3 && ("$1" == --preflight || "$1" == --prepare-only) &&
 "$2" == --source-sha && "$3" =~ ^[0-9a-f]{40}$ ]] ||
 deny "use --preflight|--prepare-only --source-sha EXACT40HEX"
MODE="$1"
SHA="$3"
# Section 2: Pin every staged file to EXACT Git source, not merely a label.
test -d "$REPO/.git" && test -s "$ARCHIVE" ||
 deny "source Git/archive missing"
test "$(git -C "$REPO" rev-parse HEAD)" == "$SHA" ||
 deny "Git HEAD mismatch"
test -z "$(git -C "$REPO" status --porcelain)" ||
 deny "Git checkout modified"
ARCHIVE_HASH="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
GIT_HASH="$(git -C "$REPO" archive --format=tar HEAD services/identity \
 docs/operations/p0-shared-keycloak-sumlaude-identity-20261029.md |
 sha256sum | cut -d' ' -f1)"
test "$ARCHIVE_HASH" == "$GIT_HASH" || deny "Git tar mismatch"
for item in services/identity/requirements.txt \
 services/identity/config/settings.py \
 services/identity/omnilyzer-identity.service \
 services/identity/nginx-auth-location.conf.review \
 services/identity/identity_bff/issuer.py \
 services/identity/prepare-identity-only.sh; do
 test -s "$SOURCE/$item" || deny "missing $item"
 a="$(sha256sum "$SOURCE/$item" | cut -d' ' -f1)"
 b="$(git -C "$REPO" show "$SHA:$item" | sha256sum | cut -d' ' -f1)"
 test "$a" == "$b" || deny "source differs: $item"
done
# Section 3: Fail closed on existing installations/approvals/ports.
test ! -e "$UNIT" && test ! -e "$CURRENT" && test ! -L "$CURRENT" ||
 deny "existing service/release"
test ! -e "$RELEASES/$SHA" || deny "release already present"
test ! -e "$PRIVATE_DIR/owner-approved-go" &&
 test ! -L "$PRIVATE_DIR/owner-approved-go" || deny "owner GO exists"
if systemctl is-active --quiet omnilyzer-identity.service; then
 deny "identity service already active"
fi
if ss -ltn | grep -Eq '127[.]0[.]0[.]1:18740[[:space:]]'; then
 deny "identity port already in use"
fi
for tool in git tar sha256sum curl python3.12 systemctl systemd-analyze; do
 command -v "$tool" >/dev/null || deny "missing $tool"
done
test -d /etc/systemd/system || deny "systemd absent"
echo "IDENTITY_SOURCE_PREFLIGHT_PASS SHA=$SHA TAR_SHA256=$ARCHIVE_HASH"
if [[ "$MODE" == --preflight ]]; then
 echo IDENTITY_PREP_READY_NOT_ACTIVE
 exit 0
fi

# Section 4: Explicit privileged host preparation, never activation.
[[ $(id -u) == 0 ]] || deny "requires interactive sudo"
[[ "$(hostname -s)" == truexmainserver ]] || deny "wrong host"
test ! -e "$RELEASES" && test ! -e "$PRIVATE_DIR" ||
 deny "unknown existing identity directory"
if getent passwd omnilyzer-identity >/dev/null; then
 deny "identity account already exists"
fi
for tool in install useradd mktemp; do
 command -v "$tool" >/dev/null || deny "missing $tool"
done
umask 022
install -d -m 0755 /opt/omnilyzer/identity "$RELEASES"
RELEASE="$RELEASES/$SHA"
install -d -m 0755 "$RELEASE"
# Until package validation succeeds this exact new release is disposable.
PIP_FILE=''
cleanup(){
 if [[ -n "$PIP_FILE" ]]; then rm -f -- "$PIP_FILE"; fi
 if [[ -n "$RELEASE" && -d "$RELEASE" ]]; then rm -rf -- "$RELEASE"; fi
}
trap cleanup EXIT
tar -xf "$ARCHIVE" -C "$RELEASE"
# Ubuntu's Python12 may lack ensurepip: use only SHA-pinned official pip
# zipapp inside this one immutable venv, not system Python or apt.
python3.12 -m venv --without-pip "$RELEASE/.venv"
PIP_FILE="$(mktemp /tmp/omnilyzer-identity-pip.XXXXXX)"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
 --max-time 60 https://bootstrap.pypa.io/pip/pip.pyz -o "$PIP_FILE"
test "$(sha256sum "$PIP_FILE" | cut -d' ' -f1)" == "$PIP_SHA" ||
 deny "official pip zipapp hash mismatch"
"$RELEASE/.venv/bin/python" "$PIP_FILE" install --no-input --no-cache-dir \
 -r "$RELEASE/services/identity/requirements.txt" >/dev/null ||
 deny "pinned requirements install failed"
# Section 5: Real installed runtime version and expected WSGI checks.
"$RELEASE/.venv/bin/python" - "$RELEASE/services/identity/requirements.txt" <<'PYCODE'
from importlib.metadata import version
from pathlib import Path
import sys
for line in Path(sys.argv[1]).read_text().splitlines():
    if not line or line.startswith("#"): continue
    name, pinned = line.split("==", 1)
    if version(name.split("[", 1)[0]) != pinned:
        raise SystemExit("IDENTITY_VERSION_PIN_DENIED")
print("IDENTITY_RUNTIME_DEPENDENCIES_PINNED")
PYCODE
test -x "$RELEASE/.venv/bin/gunicorn" &&
 test -f "$RELEASE/services/identity/config/wsgi.py" ||
 deny "WSGI/Gunicorn unavailable"
chown -R root:root "$RELEASE"
# This source is now immutable and validated; preserve it on any later
# administrative failure so no service points at a missing program.
RELEASE=''
trap - EXIT
rm -f -- "$PIP_FILE"
PIP_FILE=''
# Section 6: Install ONLY a disabled nonroot service; DO NOT prepare secrets,
# Keycloak, database, DNS, Nginx, markers, users, or student data.
useradd --system --no-create-home --home-dir /nonexistent \
 --shell /usr/sbin/nologin --user-group omnilyzer-identity
install -d -o root -g root -m 0700 "$PRIVATE_DIR"
ln -s "$RELEASES/$SHA" "$CURRENT"
install -o root -g root -m 0644 \
 "$RELEASES/$SHA/services/identity/omnilyzer-identity.service" "$UNIT"
systemctl daemon-reload
systemd-analyze verify "$UNIT" || deny "systemd definition invalid"
test "$(systemctl is-enabled omnilyzer-identity.service 2>/dev/null || true)" != enabled ||
 deny "service unexpectedly enabled"
test "$(systemctl is-active omnilyzer-identity.service 2>/dev/null || true)" != active ||
 deny "service unexpectedly active"
test ! -e "$PRIVATE_DIR/identity.env" &&
 test ! -e "$PRIVATE_DIR/owner-approved-go" ||
 deny "owner secrets/GO were unexpectedly created"
echo "IDENTITY_PREPARED_NOT_ACTIVE: pinned service, nonroot account, venv, disabled systemd"
echo "IDENTITY_KEYCLOAK_PG_DNS_NGINX_STUDENT_DATA_UNCHANGED"
