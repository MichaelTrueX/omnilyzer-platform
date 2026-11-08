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
0b595d00bdcf454269f3e9873a9123d695b4ffa910092dc9bb8e40a4432d052d.

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
  required actions cleared. This does not yet prove a signed
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
printf '%s  %s\n' 0b595d00bdcf454269f3e9873a9123d695b4ffa910092dc9bb8e40a4432d052d "$src" | sha256sum -c -
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
sha=0b595d00bdcf454269f3e9873a9123d695b4ffa910092dc9bb8e40a4432d052d
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
sha=0b595d00bdcf454269f3e9873a9123d695b4ffa910092dc9bb8e40a4432d052d
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
