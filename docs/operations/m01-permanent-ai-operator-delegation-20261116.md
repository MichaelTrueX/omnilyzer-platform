<!--
File: docs/operations/m01-permanent-ai-operator-delegation-20261116.md
Purpose: One-time installation and lasting operation of the restricted
         production AI account for the already approved M01 release.
Related: deployment/enable_prod_omnigpt_m01_access.py, AGENTS.md,
         services/identity/ops/keycloak_add_public_callback_once.py,
         services/identity/ops/m01_active_bff_upgrade_once.py, PR298.
-->

# Permanent AI operations access for M01

## Outcome

ChatGPT connects to truexmainserver via a separate, non-admin Linux account
named omnigpt. This account has exactly five fixed privileged commands:
Keycloak callback status/apply and immutable BFF stage/apply/verify. These are
persistent Linux rights, not a one-time script substitution. The account is
password-locked, has its own private home, and is not in sudo, Docker or
other privileged Linux groups.

The old personal trusthansen Remote Desktop Commander session keeps its existing
command restrictions. The new dedicated omnigpt session is the one that may
invoke sudo, subject to OS sudoers matching the entire executable and arguments.

## Source-bound operator authority

- Keycloak root operator: /usr/local/sbin/m01-keycloak-public-callback-once
  SHA256: 6a43414a89a38514a3553bb92374d9f520e278d4bf8b4a3bc2a61e7015ff2d2d
- BFF root operator: /usr/local/sbin/m01-active-bff-def92-upgrade-once
  SHA256: 83e8748ba898b339da1a4811682a934ab58a6e13e5700b4235b96af5e9dffe0e
- BFF Git source TAR is already staged at
  /home/trusthansen/m01-bff-def92-source-20261116/identity-source-def92.tar
- The existing Node 24.22.0 binary is copied for unprivileged remote-agent use
  only after a complete SHA256 equality check:
  67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c

## The one-time owner setup

The actual machine owner must select the reviewed exact Git commit and verify the
whole-file SHA256 of deployment/enable_prod_omnigpt_m01_access.py. Install that
file root:root 0500 under
/usr/local/sbin/omnilyzer-prod-omnigpt-access-bootstrap, then execute:

    sudo /usr/bin/python3 -I /usr/local/sbin/omnilyzer-prod-omnigpt-access-bootstrap install

Never execute root bootstrap code directly from a writable Git checkout or
unreviewed home script. The bootstrap verifies the real server identity,
existing root operators and Node SHA before creating the isolated user, copies
only the pinned Node bytes, and validates/installs
/etc/sudoers.d/91-omnilyzer-prod-omnigpt-m01 as root:root 0440.
It never changes Keycloak, the active BFF, NGINX, DNS, users' product roles,
cookies, secrets or public site configuration.

## Connecting the dedicated Desktop Commander account once

Run the following command as the owner to start a separate unprivileged
agent process on truexmainserver:

    sudo -u omnigpt -H /home/omnigpt/bin/node /usr/lib/node_modules/npm/bin/npx-cli.js --yes @wonderwhy-er/desktop-commander@0.3.1 remote

Follow the connector's ordinary authorization UI. Never copy tokens from
trusthansen. Verify the new connected device shows hostname truexmainserver,
id -un = omnigpt, and no additional Linux groups. Only on THAT restricted
remote connection should the sudo client block be changed to permit the
exact OS-allowlisted operator calls. Preserve all other blocked commands.

## Future release boundaries

Ordinary unprivileged scripts and diagnostics can run automatically. Root
operations already covered by a reviewed, root-owned release operator can
be executed by ChatGPT without repeated SSH copy/paste. A genuinely new class
of privileged action needs an explicit narrow review and allowlist addition.
This is not unlimited passwordless root for arbitrary future scripts.

Revocation is through the single exact sudoers policy file. Do not remove
one-time operator receipts, retry ambiguous Keycloak/BFF applies, or delete
the Linux user while a remote agent is connected.
