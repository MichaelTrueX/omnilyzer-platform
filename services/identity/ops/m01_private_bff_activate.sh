#!/usr/bin/env bash
# File: services/identity/ops/m01_private_bff_activate.sh
# Production stage: /home/trusthansen/m01-private-bff-go-20261108/private_bff_activate.sh
# Purpose: Execute the Product Owner-approved PRIVATE and reversible M01 BFF
#          release selection and loopback start on truexmainserver. Automatic
#          failure handling stops BFF and restores the prior INACTIVE state.
# Linked: MichaelTrueX/omnilyzer-platform PR #243, services/identity/
#         omnilyzer-identity.service (reviewed SHA256 9f49c797...),
#         services/identity/config/{settings,wsgi}.py, private existing
#         /etc/omnilyzer/identity/identity.env, systemd and NGINX vhost.
# Scope: NO Native, learner DB, release map, S01 assets, public DNS, or tokens.

set -Eeuo pipefail
umask 077

# Section 1: Immutable values, exact host and protected operator custody.
readonly REV=3481cacbef910a37d87a3c26341b1a8f16a6612f
readonly NEW="/opt/omnilyzer/identity/releases/$REV"
readonly OLD=/opt/omnilyzer/identity/releases/d65d14b69d3e5c899ab9291741b9029669244168
readonly CURRENT=/opt/omnilyzer/identity/current
readonly UNIT=/etc/systemd/system/omnilyzer-identity.service
readonly CANDIDATE=/home/trusthansen/m01-gtm-adult-choice-9e7f0ab-20261108/omnilyzer-identity.service
readonly ENV_FILE=/etc/omnilyzer/identity/identity.env
readonly GO=/etc/omnilyzer/identity/owner-approved-go
readonly BACKUP=/etc/omnilyzer/identity/m01-3481-private-rollback-20261108
readonly OPERATOR=/run/m01-bff-private-go.sh
readonly NEW_UNIT_SHA=9f49c797f8ca266b873ae7cebabcc110f35ae6f42b37d67a74e3f522e90c0586
readonly OLD_UNIT_SHA=b8adb3ee8e2a848db7b94b0ffa4a5a71cd990bc9ede87fda2faf5ed8e82d0326
readonly SERVICE=omnilyzer-identity.service
readonly NATIVE_CURRENT=/opt/sumlaude/native/current
readonly NATIVE_APPROVED=/opt/sumlaude/native/releases/ca5b54ccf3e179cc5706bd129cf4f9350f41e026

# Section 2: Helper for explicit fail-closed checks with non-secret messages.
fail() {
  echo "M01_PRIVATE_BFF_HOLD: $1" >&2
  exit 2
}

test "$#" -eq 1 || fail "exactly one action required"
test "$1" = activate || fail "only explicitly approved activate supported"
test "$(hostname -s)" = truexmainserver || fail "wrong host"
test "$(id -u)" -eq 0 || fail "root required"
test "$(readlink -f "$0")" = "$OPERATOR" || fail "untrusted operator path"
test "$(stat -Lc '%u:%g:%a' "$OPERATOR")" = 0:0:500 ||
  fail "protected root operator custody invalid"
test "$(stat -c '%h' "$OPERATOR")" = 1 || fail "operator hard link"
test -d "$NEW" && test ! -L "$NEW" || fail "new release not installed"
test -r "$NEW/services/identity/config/wsgi.py" || fail "WSGI missing"
test -r "$NEW/services/identity/identity_bff/views.py" || fail "BFF source missing"
test -x "$NEW/.venv/bin/gunicorn" || fail "approved Python runtime missing"
test -L "$CURRENT" || fail "current pointer not a symlink"
test "$(readlink -f "$CURRENT")" = "$OLD" ||
  fail "current is no longer original inactive release"
test -f "$UNIT" && test ! -L "$UNIT" ||
  fail "installed service unit missing or linked"
test "$(sha256sum "$UNIT" | cut -d' ' -f1)" = "$OLD_UNIT_SHA" ||
  fail "installed original service unit drifted"
test "$(sha256sum "$CANDIDATE" | cut -d' ' -f1)" = "$NEW_UNIT_SHA" ||
  fail "reviewed candidate unit drifted"
test ! -e "$GO" && test ! -L "$GO" ||
  fail "owner GO marker already exists"
# The first actual V2 activation already created this root-only receipt,
# then automatically restored the old inactive unit/current. Reuse only the
# validated original evidence: never delete, replace, or overwrite it.
test -d "$BACKUP" && test ! -L "$BACKUP" ||
  fail "prior root rollback receipt missing or unsafe"
test "$(stat -Lc '%u:%g:%a' "$BACKUP")" = 0:0:700 ||
  fail "root rollback directory owner/mode drift"
for receipt in previous-unit previous-current-target new-unit-sha256; do
  test -f "$BACKUP/$receipt" && test ! -L "$BACKUP/$receipt" ||
    fail "root rollback receipt type drift"
  test "$(stat -Lc '%u:%g:%a' "$BACKUP/$receipt")" = 0:0:600 ||
    fail "root rollback receipt owner/mode drift"
done
test "$(sha256sum "$BACKUP/previous-unit" | cut -d' ' -f1)" = "$OLD_UNIT_SHA" ||
  fail "previous unit receipt digest mismatch"
test "$(cat "$BACKUP/previous-current-target")" = "$(readlink "$CURRENT")" ||
  fail "previous current receipt differs from original selection"
test "$(cat "$BACKUP/new-unit-sha256")" = "$NEW_UNIT_SHA" ||
  fail "new unit receipt digest differs from reviewed source"
echo M01_PRIOR_INACTIVE_ROLLBACK_RECEIPT_REUSED_VERIFIED_PASS
test "$(stat -Lc '%u:%g:%a' "$ENV_FILE")" = 0:0:600 ||
  fail "existing protected identity env custody invalid"
test "$(systemctl is-active "$SERVICE")" = inactive ||
  fail "BFF already running or failed"
test "$(systemctl is-enabled "$SERVICE")" = disabled ||
  fail "BFF unexpectedly enabled"
test "$(systemctl show "$SERVICE" -p NeedDaemonReload --value)" = no ||
  fail "systemd currently needs reload"
test -z "$(systemctl show "$SERVICE" -p DropInPaths --value)" ||
  fail "unexpected BFF drop-in"
# Native was independently activated by S03 after this operator was staged.
# Accept ONLY the approved immutable already-running release. Never mutate it.
systemctl is-active --quiet sumlaude-native.service ||
  fail "approved Native service is not active"
test "$(systemctl is-enabled sumlaude-native.service)" = disabled ||
  fail "Native boot-enable state drifted"
test "$(readlink -f "$NATIVE_CURRENT")" = "$NATIVE_APPROVED" ||
  fail "Native current is not the reviewed immutable release"
test "$(systemctl show sumlaude-native.service -p WorkingDirectory --value)" = "$NATIVE_APPROVED/backend" ||
  fail "Native loaded working directory is not reviewed"
case "$(systemctl show sumlaude-native.service -p ExecStart --value)" in
  *"$NATIVE_APPROVED/backend/dist/sumlaude-native-main.js"*) ;;
  *) fail "Native loaded process executable is not reviewed" ;;
esac
case "$(systemctl show sumlaude-native.service -p ExecCondition --value)" in
  *"$NATIVE_CURRENT -ef $NATIVE_APPROVED"*) ;;
  *) fail "Native immutable current guard is absent" ;;
esac
test "$(systemctl show sumlaude-native.service -p NeedDaemonReload --value)" = no ||
  fail "Native systemd unit needs reload"
native_pid_before="$(systemctl show sumlaude-native.service -p MainPID --value)"
test "$native_pid_before" -gt 1 ||
  fail "Native live process PID missing"
native_bindings="$(ss -lntH | awk '$4 ~ /:18741$/ {print $4}')"
test "$native_bindings" = 127.0.0.1:18741 ||
  fail "Native is not exclusively loopback-bound"
native_api_status="$(curl --insecure --silent --show-error --output /dev/null \
  --write-out '%{http_code}' --connect-timeout 2 --max-time 7 \
  --resolve app.sumlaude.com:443:127.0.0.1 \
  https://app.sumlaude.com/api/valoria/context)"
case "$native_api_status" in
  401|403) ;;
  *) fail "Native anonymous context gate not denying access" ;;
esac
echo M01_EXISTING_APPROVED_NATIVE_18741_UNCHANGED_PASS

systemctl is-active --quiet omnilyzer-keycloak.service ||
  fail "actual Keycloak service not active"
systemctl is-active --quiet postgresql.service ||
  fail "PostgreSQL not active"
systemctl is-active --quiet nginx.service ||
  fail "NGINX not active"
if ss -lnt | grep -Eq ':(18740)[[:space:]]'; then
  fail "BFF listener already exists"
fi
test "$(getent passwd omnilyzer-identity | cut -d: -f3)" = 994 ||
  fail "existing BFF service UID drifted"
systemd-analyze verify "$CANDIDATE" ||
  fail "reviewed systemd unit invalid on real host"
nginx -t >/dev/null 2>&1 ||
  fail "existing NGINX configuration failed validation"
echo M01_PRIVATE_BFF_ROOT_PRECHECK_PASS

# Section 3: Save exact original inactive unit/current for safe rollback.
original_link="$(readlink "$CURRENT")"
scratch="$(mktemp -d /run/m01-bff-cutover-XXXXXXXX)"
newunit_stage="/etc/systemd/system/.omnilyzer-identity-m01-$$"
newlink_stage="/opt/omnilyzer/identity/.m01-current-$$"
mutation_started=0
success=0

# Section 4: On any error after modification, STOP and restore the old
# inactive unit/current state. NEVER run the obsolete BFF as rollback.
cleanup() {
  local code=$?
  trap - EXIT INT TERM
  if test "$mutation_started" = 1 && test "$success" = 0; then
    echo M01_PRIVATE_BFF_AUTO_ROLLBACK_BEGIN >&2
    systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    rm -f -- "$GO"
    if test -f "$BACKUP/previous-unit"; then
      install -o root -g root -m 0644 "$BACKUP/previous-unit" "$newunit_stage" || true
      if test -f "$newunit_stage"; then
        mv -Tf "$newunit_stage" "$UNIT" || true
      fi
    fi
    if test -L "$CURRENT"; then
      rm -f -- "$newlink_stage"
      ln -s "$original_link" "$newlink_stage" || true
      if test -L "$newlink_stage"; then
        mv -Tf "$newlink_stage" "$CURRENT" || true
      fi
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
    if test "$(systemctl is-active "$SERVICE")" = inactive &&
       test "$(readlink -f "$CURRENT")" = "$OLD" &&
       test "$(sha256sum "$UNIT" | cut -d' ' -f1)" = "$OLD_UNIT_SHA"; then
      echo M01_PRIVATE_BFF_AUTO_ROLLBACK_INACTIVE_PASS >&2
    else
      echo M01_PRIVATE_BFF_ROLLBACK_INCOMPLETE_OPERATOR_INTERVENTION_REQUIRED >&2
    fi
  fi
  rm -f -- "$newunit_stage" "$newlink_stage"
  rm -rf -- "$scratch"
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The original protected rollback receipt was verified before any write.
# Do not write or replace its contents on a repeat attempt.

# Section 5: Root-custody the SHA-reviewed unit, update unit and current
# atomically, and create the existing required owner approval marker.
install -o root -g root -m 0644 "$CANDIDATE" "$scratch/candidate.service"
test "$(sha256sum "$scratch/candidate.service" | cut -d' ' -f1)" = "$NEW_UNIT_SHA" ||
  fail "root-owned unit copy digest mismatch"
mutation_started=1
install -o root -g root -m 0644 "$scratch/candidate.service" "$newunit_stage"
mv -Tf "$newunit_stage" "$UNIT"
test "$(sha256sum "$UNIT" | cut -d' ' -f1)" = "$NEW_UNIT_SHA" ||
  fail "installed unit differs from reviewed source"
ln -s "$NEW" "$newlink_stage"
mv -Tf "$newlink_stage" "$CURRENT"
test "$(readlink -f "$CURRENT")" = "$NEW" ||
  fail "immutable source selection failed"
install -o root -g root -m 0600 /dev/null "$GO"
systemctl daemon-reload

# Section 6: Verify the loaded service has ONLY reviewed immutable paths.
test "$(systemctl show "$SERVICE" -p NeedDaemonReload --value)" = no ||
  fail "loaded unit requires reload"
test "$(systemctl show "$SERVICE" -p FragmentPath --value)" = "$UNIT" ||
  fail "systemd loaded unexpected unit"
test -z "$(systemctl show "$SERVICE" -p DropInPaths --value)" ||
  fail "systemd has unexpected drop-in"
test "$(systemctl show "$SERVICE" -p WorkingDirectory --value)" = "$NEW/services/identity" ||
  fail "loaded workdir is not immutable"
case "$(systemctl show "$SERVICE" -p ExecStart --value)" in
  *"$NEW/.venv/bin/gunicorn"*) ;;
  *) fail "loaded Gunicorn does not pin new release" ;;
esac
case "$(systemctl show "$SERVICE" -p ExecStartPre --value)" in
  *"$NEW/.venv/bin/python"*) ;;
  *) fail "loaded Django prestart does not pin new release" ;;
esac
case "$(systemctl show "$SERVICE" -p ExecCondition --value)" in
  *"$CURRENT -ef $NEW"*) ;;
  *) fail "loaded current-exact immutable guard missing" ;;
esac
test "$(systemctl show "$SERVICE" -p User --value)" = omnilyzer-identity ||
  fail "nonroot service identity mismatch"
test "$(systemctl is-enabled "$SERVICE")" = disabled ||
  fail "BFF incorrectly enabled"
echo M01_PRIVATE_BFF_LOADED_IMMUTABLE_UNIT_PASS

# Section 7: Start only the BFF. Type=simple returns before Python,
# Gunicorn and the WSGI application necessarily finish initialization.
# A bounded acceptance loop requires the real UID994 process, immutable
# cwd, exclusive IPv4 loopback 18740 and real anonymous HTTPS 200.
echo M01_PRIVATE_BFF_STAGE_SYSTEMD_START
systemctl start "$SERVICE"
echo M01_PRIVATE_BFF_STAGE_PRIVATE_READINESS

response_code=""
ready=0
deadline=$((SECONDS + 25))
while test "$SECONDS" -le "$deadline"; do
  systemctl is-active --quiet "$SERVICE" ||
    fail "BFF systemd service exited before readiness"

  pid="$(systemctl show "$SERVICE" -p MainPID --value)"
  if test "$pid" -gt 1 && test -d "/proc/$pid"; then
    owner_uid="$(stat -Lc '%u' "/proc/$pid" 2>/dev/null || true)"
    # Type=simple may expose the service process before its final UID
    # and cwd have been established. Do not mistake that pre-exec state
    # for a running incorrect process. Never accept HTTP until both match.
    actual_cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)"
    bindings="$(ss -lntH | awk '$4 ~ /:18740$/ {print $4}')"
    if test -n "$bindings" && test "$bindings" != 127.0.0.1:18740; then
      fail "BFF listener is not exclusively on 127.0.0.1:18740"
    fi
    # Once an app listener exists, wrong UID/cwd is a blocking defect.
    if test "$bindings" = 127.0.0.1:18740; then
      if test -n "$owner_uid" && test "$owner_uid" != 994; then
        fail "listening BFF process UID is not approved nonroot UID994"
      fi
      if test -n "$actual_cwd" && test "$actual_cwd" != "$NEW/services/identity"; then
        fail "listening BFF workdir is not the approved immutable release"
      fi
    fi

    if test "$owner_uid" = 994 &&
       test "$actual_cwd" = "$NEW/services/identity" &&
       test "$bindings" = 127.0.0.1:18740; then
      response_code="$(curl --insecure --silent --show-error \
          --resolve app.sumlaude.com:443:127.0.0.1 \
          --connect-timeout 2 --max-time 4 \
          --dump-header "$scratch/headers" \
          --output "$scratch/anonymous.json" \
          --write-out '%{http_code}' \
          https://app.sumlaude.com/auth/session 2>/dev/null || true)"
      if test "$response_code" = 200; then
        ready=1
        break
      fi
    fi
  fi
  sleep 1
done
test "$ready" = 1 ||
  fail "BFF immutable private runtime did not reach HTTP200 before deadline"
echo M01_PRIVATE_BFF_NONROOT_PROCESS_IMMUTABLE_PASS
echo M01_PRIVATE_BFF_PRIVATE_LOOPBACK_READINESS_PASS

# Section 8: Validate the exact anonymous BFF response and no product cookie.
python3 - "$scratch/anonymous.json" "$scratch/headers" <<'PY'
import json
import pathlib
import sys

body = json.loads(pathlib.Path(sys.argv[1]).read_text())
if body != {"authenticated": False}:
    raise SystemExit("M01_ANONYMOUS_SESSION_RESPONSE_INVALID")
headers = pathlib.Path(sys.argv[2]).read_text().lower()
if "set-cookie: __host-sumlaude_session=" in headers:
    raise SystemExit("M01_ANONYMOUS_PRODUCT_COOKIE_FORBIDDEN")
PY
systemctl is-active --quiet "$SERVICE" || fail "BFF stopped after probe"
test "$(systemctl show "$SERVICE" -p MainPID --value)" = "$pid" ||
  fail "BFF main process changed after successful probe"
test "$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)" = "$NEW/services/identity" ||
  fail "BFF immutable process workdir changed after successful probe"
test "$(stat -Lc '%u' "/proc/$pid" 2>/dev/null || true)" = 994 ||
  fail "BFF nonroot process UID changed after successful probe"
systemctl is-active --quiet sumlaude-native.service ||
  fail "S03 Native stopped during BFF activation"
test "$(systemctl show sumlaude-native.service -p MainPID --value)" = "$native_pid_before" ||
  fail "S03 Native process changed during BFF activation"
test "$(readlink -f "$NATIVE_CURRENT")" = "$NATIVE_APPROVED" ||
  fail "S03 Native immutable current changed during BFF activation"
test "$(systemctl is-enabled sumlaude-native.service)" = disabled ||
  fail "Native boot-enable state changed during BFF activation"
test "$(systemctl is-enabled "$SERVICE")" = disabled ||
  fail "BFF must not auto-start on reboot"
test "$(readlink -f "$CURRENT")" = "$NEW" ||
  fail "final BFF selected release changed"

# Section 9: Keep private BFF running, backup custody for explicit rollback,
# and leave Native, app static, GTM map, public DNS and users unchanged.
success=1
echo M01_PRIVATE_BFF_ACTIVE_18740_PASS
echo M01_PRIVATE_HTTPS_ANONYMOUS_AUTH_SESSION_200_PASS
echo M01_EXISTING_APPROVED_NATIVE_PROCESS_PRESERVED_PASS
echo M01_NATIVE_MAP_FRONTEND_DNS_NOT_CHANGED
echo "M01_ROOT_ROLLBACK_RECEIPT=$BACKUP"
