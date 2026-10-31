<!--
File: docs/operations/task014-analytics-loopback-20261031.md
Purpose: Review-only lifecycle-bound private ingress correction for the signed
         Analytics 0.15.0 DEV first install after verified RootlessKit probe.
Related: deployment/analytics_loopback_guard.py,
         deployment/systemd/rootless/omnilyzer-analytics-loopback.service,
         deployment/analytics_first_install.py,
         MichaelTrueX/omnilyzer#27.
-->
# Analytics Task014: private loopback ingress, DEV only

## Problem and proven facts

The existing `omnilyzer-analytics-backend-dev` Docker network is internal-only.
Docker records `HostConfig.PortBindings` for 3141 but does not publish a
`NetworkSettings.Ports` entry. The signed Analytics 0.15.0 blue container is
healthy on its internal port 3000. The authorized one-shot RootlessKit 3.1.0
loopback test reported `readyz=200 livez=200` via temporary forwarding
`127.0.0.1:3141 -> 172.20.0.3:3000`, then deleted the temporary rule and
preserved original Canary 3020. This is **not** permanent DEV acceptance.

## One-time operational change (not an approved install instruction)

The separately reviewed Python service supervises exactly one signed blue
container, without adding any Docker network, public bind, database migration,
registry request, authentication token, or Task013/014 dispatch. Install only
after owner approval and independent review of the actual full files.

Place the Python program at the root-owned regular file
`/opt/omnilyzer/deployment/analytics-loopback/analytics_loopback_guard.py`
(mode 0644). Place the system unit at
`/etc/systemd/system/omnilyzer-analytics-loopback.service` (root-owned 0644).
Create a root-owned 0600 configuration at
`/etc/omnilyzer/deployment/analytics-loopback.env` containing ONLY
`ANALYTICS_APPROVED_CONTAINER_ID=<exact already-reviewed 64-char Docker ID>`.
The ID MUST be independently retrieved from the signed 0.15.0 container and
checked against the immutable image, actual network, and running health before
approval. A recreation/upgrade needs a new authorized review and ID, not
automatic adoption of a mutable container name. Preserve platform `main`,
original workflow SHA, installed signed execution bundle and replay ledger.

Review systemd confinement compatibility with the actual Ubuntu 24.04 host.
The service uses user `omnilyzer-executor` (UID991), connects only to existing
private rootless Docker and RootlessKit Unix sockets, and listens ONLY on
127.0.0.1. It starts with a conservative stale-rule cleanup and never touches
the existing Canary 3020 rule. Once established it rechecks the exact signed
container ID, runtime security, health, network and forwarding rule every two
seconds. On an unexpected change it removes the Analytics rule and exits;
systemd may retry but cannot approve a different container ID/image/network.
The `ExecStopPost` hook handles systemd stop or ungraceful process termination.
A complete RootlessKit daemon restart also loses its volatile port rules; the
supervised process detects and recreates the rule only for an unchanged signed
container. No generalized port publishing framework is introduced.

## Required acceptance before DEV GO

Verify effective service unit and root-owned file hashes, then test first
startup, live loopback `/livez`/`/readyz`, one restart and preserved 3020,
fail-closed service stop, rootless daemon restart, container replacement deny,
no external-facing bind (IPv4/IPv6), and no unexpected Docker network or
database changes. Check that protected ports do not persist after service stop.
Then perform authenticated Analytics UI/API and collector persistence,
authorization and cross-tenant rejection, consent/CORS/CSP, and independent M04
acceptance. Prior GitHub workflow #41197459430 success alone is insufficient.

The Python systemd service is a separate operational boundary and requires
owner approval; source files in a draft PR or staged on DEV are not installed.
