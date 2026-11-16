<!--
File: docs/operations/analytics-prod-first-install.md
Purpose: One controlled PROD host prerequisite for signed Analytics 0.16.0.
Related: AGENTS.md, deployment/analytics_prod_rootless_bootstrap.py,
         deployment/direct_dev_prod_preflight.py,
         docs/operations/task014-pre-release-checklist.md.
-->

# Analytics PROD first installation: rootless prerequisite only

Scope: truexmainserver, existing PROD. The Product Owner authorized a
bounded initial administrator setup on 16 November 2026. The accepted
Analytics 0.16.0 artifact already runs on DEV. This procedure does not
deploy the application, authorize Task014, migrate databases, edit Nginx,
modify Keycloak, create public routes, or change legacy PM2 services.

## Preconditions

The root bootstrap requires Ubuntu 24.04 x86_64, free loopback ports
3141/3142, at least 1 GiB available RAM and 12 GiB free disk, no existing
Docker/containerd installation, no existing omnilyzer-analytics service
user, and non-overlapping subordinate IDs 231072:65536. It reports all
independent preflight mismatches before making changes. Existing DEV uses
Docker CE 29.8.1, Compose 5.5.1 and containerd 2.3.6, pinned here. The
official Docker apt signing-key fingerprint is verified before repository
activation. Rootful Docker/containerd services are masked before package
post-install scripts run.

The installer creates only a dedicated system user, subordinate UID/GID
ranges, a root-owned global user systemd unit limited by ConditionUser,
a rootless daemon and a private Docker Unix socket. The service home
is root-owned to prevent persistent user-unit overrides; only the
explicit Docker data directory is service-user-writable. It reuses the
existing AppArmor user-namespace profile whose SHA256 matches DEV. It
installs no application image. The rootless daemon has no TCP listener.
Public Nginx/PM2 routes remain unchanged.

## Operator execution

1. Fetch the reviewed GitHub commit or transfer the exact reviewed file
   to the existing owner home directory. Compare its SHA256 with the
   reviewed source-bound receipt.
2. Copy the file to /usr/local/sbin/omnilyzer-analytics-prod-bootstrap
   with sudo install -o root -g root -m 0500. Verify the SHA256 of the
   root-owned copy before execution. Never run owner-writable code as root.
3. Execute the reviewed root-owned script using Python 3 isolated mode
   with --check, then only after PASS with --apply. A partial failure is
   a HOLD, not an invitation to retry. Capture the full output and
   inspect actual installed state.
4. Expected result: PROD_ROOTLESS_BOOTSTRAP_PASS, the dynamically
   assigned dedicated UID and app=not-installed. Rootful Docker/containerd
   must remain inactive and /var/run/docker.sock absent.

The connected remote agent cannot execute sudo on PROD. The initial
privileged command must be run through the owner's authorized terminal.
Do not grant a broad shell, docker group membership, rootless socket
access to the agent, or unrestricted sudo. Future release automation
requires a separately reviewed, root-owned fixed adapter that verifies
original signatures, exact DEV identity, tenant/database readiness,
one-time owner authorization and rollback before using rootless Docker.

## Specific partial-install recovery, 16 November 2026

The exact reviewed first installer stopped on an unsupported Python
`Path.chown()` call after packages, service account and subordinate IDs
were created, but before the rootless daemon was configured or started.
The first `--apply` is **consumed and must never be retried**.

The version-bound correction in the same bootstrap source replaces both
unsupported calls with `os.chown()` and includes two *new*, narrowly
scoped modes. `--check-partial` validates the exact original root-owned
installer SHA, package versions, apt key/source, AppArmor profile,
UID/GID 990:982, subordinate ranges, rootful masks, empty service home,
missing post-user artifacts and unused ports. `--resume-after-user` runs
only the previously unfinished post-user stage after repeating that
preflight, without installing packages, creating users or changing
Nginx/PM2/Keycloak/PostgreSQL.

After the independent source review, owner copies the updated **exact**
GitHub script to a **different** root-owned mode0500 filename,
`/usr/local/sbin/omnilyzer-analytics-prod-recover-20261116`, after
SHA256 verification. The original root-owned installer is preserved
unchanged as evidence. Run the new file with isolated Python and
`--check-partial`, then once with `--resume-after-user` if PASS.
If the recovery itself fails part-way, preserve state and do not retry.
The success marker proves only the rootless runtime prerequisite,
not the Analytics application or public release.

## Next release boundary

After the daemon passes, qualify the signed Task014 release-admission
path for PROD with separate production DB/collector roles, sealed
credentials, backups, loopback-only 3141 smoke checks, preserved legacy
application and stop-only first-install rollback. Do not repurpose the
disabled Canary-only prod.json or replay consumed DEV Task014 requests.
Public Nginx cutover is separate and retains Issue #280 security,
consent and CSP controls.
