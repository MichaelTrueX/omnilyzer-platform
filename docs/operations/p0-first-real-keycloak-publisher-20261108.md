# First real publisher identity in existing Omnilyzer Keycloak

8 November 2026. SOURCE-ONLY, NOT EXECUTED ON PRODUCTION.

## Purpose and verified boundary

The Omnilyzer Keycloak realm is active at
https://login.omnilyzer.ai/realms/omnilyzer and confidential client
sumlaude-bff uses S256 with its existing redirect. Public registration
is disabled. The Sumlaude production database currently has zero
users, organizations, programs and publishers (Issue #320).

The reviewed Django BFF is inactive and currently requires an
already admitted Sumlaude identity before it can complete a login
callback. Therefore first publisher registration cannot be achieved by
fabricating a native user, directly marking email as verified or
opening an independent Sumlaude password system.

The versioned first-user operator is
services/identity/ops/first_real_keycloak_publisher_identity.py
and its exact full SHA256 is
3c27829c35e2dad0a8913e567889b5679e7c5a5851a8b72814143dde20b0ef06.

It authenticates only to existing master Keycloak admin on
127.0.0.1:18742, using the current root0600 env file, and writes
admin session tokens only in temporary root0700 /run. No secrets,
raw subject, user email or credentials appear in output.

- preflight: READ-ONLY exact chosen real email status, registration
  guard, confidential client and SMTP presence.
- invite: MUTATING, one new real mailbox identity only if absent;
  always emailVerified false, no password and NO role. Sends
  VERIFY_EMAIL and UPDATE_PASSWORD via Keycloak email. Never
  retries an already existing account or falsely marks it verified.
- verify: READ-ONLY, returns PASS only after emailVerified true and
  all required actions cleared, including any OTP or profile actions. Missing
  requiredActions is valid per Keycloak's optional UserRepresentation field;
  malformed/null requiredActions fails closed. This does not yet prove a signed
  confidential OIDC session or a Sumlaude membership.

Both operator scripts must receive the actual real publisher email
entered locally at the console, not in a GitHub comment or chat.
NO artificial test/QA account is permitted.

## Source stage on truexmainserver

The owner or authorized operator first copies the exact reviewed
Python source to this PRIVATE nonroot path using trusted SSH:
 /home/trusthansen/m01-first-real-publisher-20261108/first_real_keycloak_publisher_identity.py

Never run the user-owned source directly as root. The following
commands make a private root-owned copy (0500), verify full SHA256
before executing it, and automatically remove the temporary copy.

## A. Unprivileged source and production READ-ONLY preflight

~~~bash
set -Eeuo pipefail
src=/home/trusthansen/m01-first-real-publisher-20261108/first_real_keycloak_publisher_identity.py
printf '%s  %s\n' 3c27829c35e2dad0a8913e567889b5679e7c5a5851a8b72814143dde20b0ef06 "$src" | sha256sum -c -
test "$(hostname -s)" = truexmainserver
test "$(systemctl is-active omnilyzer-keycloak.service)" = active
test "$(systemctl is-active omnilyzer-identity.service || true)" = inactive
curl -fsS --max-time 10 https://login.omnilyzer.ai/realms/omnilyzer/.well-known/openid-configuration | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["issuer"]=="https://login.omnilyzer.ai/realms/omnilyzer"; assert "S256" in x.get("code_challenge_methods_supported",[]); print("M01_REAL_KEYCLOAK_ISSUER_S256_PASS")'
~~~

## B. Separate protected READ-ONLY Keycloak admin inventory

~~~bash
sudo -H bash -s <<'M01_ROOT_PREFLIGHT'
set -Eeuo pipefail
umask 077
src=/home/trusthansen/m01-first-real-publisher-20261108/first_real_keycloak_publisher_identity.py
sha=3c27829c35e2dad0a8913e567889b5679e7c5a5851a8b72814143dde20b0ef06
test "$(id -u)" -eq 0
test "$(hostname -s)" = truexmainserver
tmp="$(mktemp -d /run/m01-real-keycloak-XXXXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT
chmod 0700 "$tmp"
install -o root -g root -m 0500 -- "$src" "$tmp/operator.py"
printf '%s  %s\n' "$sha" "$tmp/operator.py" | sha256sum -c -
read -r -p "Real publisher email: " PUBLISHER_EMAIL < /dev/tty
export PUBLISHER_EMAIL
python3 "$tmp/operator.py" preflight
echo M01_FIRST_REAL_KEYCLOAK_READONLY_FINISHED
M01_ROOT_PREFLIGHT
~~~

Read the output. If SMTP=MISSING, account status is not ABSENT,
source/realm/client/host is rejected, or the selected real email is
not confirmed by the owner, STOP. Do not request independent QA of
old unchanged M01/S03 runtime and login tests. This NEW admin
operation needs one focused security review of its exact changed
source, email-verified flag and first identity protection.

## C. Separate privileged account invitation - MUTATING

DO NOT EXECUTE UNTIL independent focused QA, owner selection of
the real mailbox, the exact A+B preflight PASS and SMTP=PRESENT.

~~~bash
sudo -H bash -s <<'M01_ROOT_INVITE'
set -Eeuo pipefail
umask 077
src=/home/trusthansen/m01-first-real-publisher-20261108/first_real_keycloak_publisher_identity.py
sha=3c27829c35e2dad0a8913e567889b5679e7c5a5851a8b72814143dde20b0ef06
test "$(id -u)" -eq 0
test "$(hostname -s)" = truexmainserver
tmp="$(mktemp -d /run/m01-real-keycloak-XXXXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT
chmod 0700 "$tmp"
install -o root -g root -m 0500 -- "$src" "$tmp/operator.py"
printf '%s  %s\n' "$sha" "$tmp/operator.py" | sha256sum -c -
read -r -p "Confirmed real publisher email: " PUBLISHER_EMAIL < /dev/tty
export PUBLISHER_EMAIL
python3 "$tmp/operator.py" invite
echo M01_FIRST_REAL_KEYCLOAK_INVITATION_OPERATOR_FINISHED
M01_ROOT_INVITE
~~~

Expected M01_KEYCLOAK_ONE_REAL_MAILBOX_INVITATION_SENT.
The actual human must complete the emailed verification/password
actions. An email delivery failure can leave an unverified Keycloak
account; STOP, do not create a duplicate or manually mark verified.
The identical protected B wrapper may later invoke the same operator
with verify instead of preflight. Expected
M01_KEYCLOAK_EMAIL_VERIFIED_AND_ACTIONS_CLEARED_PASS.
There is deliberately no automatic role assignment or logout change.

## Actual remaining Sumlaude role

The human still must make a real confidential Keycloak/OIDC sign-in
with a verified issuer, signed subject and email assurance; a
separately reviewed first-user onboarding integration must securely
create or bind the native active/email-verified user+external identity.
Only then the S03 approved publisher bootstrap may create exactly
one real organization/program and one publisher membership with an
audit record. The existing S03 bootstrap refuses a missing link.

No Native course/release, learner account, admissions, BFF activation,
public registration, service/current/DNS/NGINX change or production
DB write is part of THIS Keycloak invitation operator. Keep real
publisher verification separate from the eventual actual 18+ pilot.

## Keycloak SMTP config using already approved Google Workspace relay

8 Nov 2026: Google Workspace owner entered both source IPs; independently
tested actual SMTP MAIL FROM and RCPT TO 250 over TLS1.3 from production
using IPv4 and IPv6, with no DATA and no mail sent. Keycloak SMTP currently
MISSING. Google accepted no-reply@sumlaude.com as sender for both IPs.

Source: services/identity/ops/configure_keycloak_google_relay.py
SHA256: f8aac1acc03430d23d4482666efd72d04d7a9ef5f9e98d35a55cff8c69daf963
Scope: one existing Keycloak realm SMTP map only. Use smtp-relay.gmail.com
implicit TLS port 465 (not opportunistic STARTTLS on 587, in light of
known SMTP TLS downgrade concern), from/envelope no-reply@sumlaude.com,
authentication disabled (Google IP allowlist). No new SMTP secret,
account, user, publisher role, BFF, DNS, database or service activation.

Code is in the existing M01 PR243 for focused independent review. It is
NOT authorization to invoke the mutating action. No root operation has
yet been executed. Stage this exact GitHub-reviewed source as
/home/trusthansen/m01-first-real-publisher-20261108/configure_keycloak_google_relay.py
owner trusthansen mode0600, private parent dir0700. Verify SHA before
running anything privileged. Never execute owner-writeable source as root.

### A. Source and actual host READ-ONLY check

~~~bash
set -Eeuo pipefail
d=/home/trusthansen/m01-first-real-publisher-20261108
sha=f8aac1acc03430d23d4482666efd72d04d7a9ef5f9e98d35a55cff8c69daf963
test "$(hostname -s)" = truexmainserver
printf '%s  %s\n' "$sha" "$d/configure_keycloak_google_relay.py" | sha256sum -c -
test "$(stat -c '%U:%a' "$d/configure_keycloak_google_relay.py")" = trusthansen:600
test "$(systemctl is-active omnilyzer-keycloak.service)" = active
echo M01_SMTP_SOURCE_AND_HOST_READONLY_PASS
~~~

### B. Protected READ-ONLY Keycloak preflight, local truexmainserver terminal

~~~bash
sudo -H bash -s <<'M01_SMTP_ROOT_READONLY'
set -Eeuo pipefail
umask 077
src=/home/trusthansen/m01-first-real-publisher-20261108/configure_keycloak_google_relay.py
sha=f8aac1acc03430d23d4482666efd72d04d7a9ef5f9e98d35a55cff8c69daf963
test "$(id -u)" -eq 0
test "$(hostname -s)" = truexmainserver
tmp="$(mktemp -d /run/m01-smtp-operator-XXXXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT
chmod 0700 "$tmp"
install -o root -g root -m 0500 -- "$src" "$tmp/smtp.py"
printf '%s  %s\n' "$sha" "$tmp/smtp.py" | sha256sum -c -
python3 "$tmp/smtp.py" preflight
echo M01_SMTP_ROOT_READONLY_PREFLIGHT_FINISHED
M01_SMTP_ROOT_READONLY
~~~

Expected current MISSING, confidential realm PASS, certificate verified
TLS 465 PASS and NO_WRITES PASS. STOP on any error, unexpected
configured email, realm/client drift, untrusted script or network error.

### C. Separate MUTATING SMTP CONFIGURE command

DO NOT EXECUTE unless B passes AND independent reviewer has accepted
this exact NEW SMTP source and authorized operator change scope.

~~~bash
sudo -H bash -s <<'M01_SMTP_ROOT_CONFIGURE'
set -Eeuo pipefail
umask 077
src=/home/trusthansen/m01-first-real-publisher-20261108/configure_keycloak_google_relay.py
sha=f8aac1acc03430d23d4482666efd72d04d7a9ef5f9e98d35a55cff8c69daf963
test "$(id -u)" -eq 0
test "$(hostname -s)" = truexmainserver
tmp="$(mktemp -d /run/m01-smtp-operator-XXXXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT
chmod 0700 "$tmp"
install -o root -g root -m 0500 -- "$src" "$tmp/smtp.py"
printf '%s  %s\n' "$sha" "$tmp/smtp.py" | sha256sum -c -
python3 "$tmp/smtp.py" configure
echo M01_SMTP_EXACT_REALM_CONFIGURATION_COMPLETED
M01_SMTP_ROOT_CONFIGURE
~~~

Expected exact TLS465/NOAUTH readback PASS. Does NOT test actual mail
delivery. Real test recipient confirmation still required.

### D. Separate rollback, only when current SMTP map is exact as installed

~~~bash
sudo -H bash -s <<'M01_SMTP_ROOT_ROLLBACK'
set -Eeuo pipefail
umask 077
src=/home/trusthansen/m01-first-real-publisher-20261108/configure_keycloak_google_relay.py
sha=f8aac1acc03430d23d4482666efd72d04d7a9ef5f9e98d35a55cff8c69daf963
test "$(id -u)" -eq 0
test "$(hostname -s)" = truexmainserver
tmp="$(mktemp -d /run/m01-smtp-operator-XXXXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT
chmod 0700 "$tmp"
install -o root -g root -m 0500 -- "$src" "$tmp/smtp.py"
printf '%s  %s\n' "$sha" "$tmp/smtp.py" | sha256sum -c -
python3 "$tmp/smtp.py" rollback
echo M01_SMTP_ROLLBACK_COMPLETED
M01_SMTP_ROOT_ROLLBACK
~~~

Expected Keycloak SMTP_ROLLBACK_DISABLED_PASS after live Keycloak readback.
Rollback refuses unexpected config and other realms/client/settings.
Do not attempt a forced restoration in case of drift. Real publisher
identity invitation remains separately gated on exact M04 review and
verification of an actual delivered email.
