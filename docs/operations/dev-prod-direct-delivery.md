<!--
File: docs/operations/dev-prod-direct-delivery.md
Purpose: Give one owner and one delivery chat a practical two-host workflow.
Related: AGENTS.md, ADR 0012, deployment/direct_dev_prod_preflight.py,
deployment/controller.py (historical), docs/architecture/deployment-model.md,
docs/operations/task013-release-readiness.md.
-->

# Omnilyzer: build on DEV, approve once, release on PROD

## Environments and ownership

| Role | Host | What happens |
| --- | --- | --- |
| DEV + backup | `omnilyzerdev` | Real development, visible private preview, testing, backup |
| PROD | `truexmainserver` | Approved immutable application versions, real users |
| Source | GitHub | Protected repository, branches, traceable PR and release evidence |

There is **no STAGING host** and no mandatory staging step. Historical
`staging.json` stays inactive for compatibility, not for operational use.
Do not add a third host or duplicate release chat.

## Working feature cycle

1. The owner describes the user-visible outcome. One accountable chat reads
   `AGENTS.md`, the actual current code and existing safeguards.
2. Make the smallest useful update directly in the approved development
   checkout on `omnilyzerdev`, on a feature branch. Preserve other ongoing
   source changes and the current healthy signed DEV release.
3. Run targeted automated checks and launch/reload/deploy the changed
   application safely on the same DEV host. Show the owner a **real,
   private browser address** and the observable working feature. Repeat
   small increments on DEV rather than creating a staging release queue.
4. When the owner confirms DEV is satisfactory, run only the existing
   necessary Task013 source/security/SBOM/signature and Task014
   deployment/recovery gates for the reviewed version.
5. Promote the **same signed OCI digest** that succeeded on DEV to PROD,
   only after explicit owner GO and production config/secrets/identity
   qualification. No PROD rebuild or patching source directly there.
6. Verify real PROD health and the relevant functional journey, preserve the
   old release/rollback receipt, and document the result in the existing
   issue/PR. Do not invent multiple parallel review/QA streams.

## Viewing real development

An actual signed Analytics 0.16.0 instance currently responds on
`omnilyzerdev` at `http://127.0.0.1:3141/`. The port is loopback-only.
The existing tailnet Serve host has other configured routes but **does not
currently expose port 3141**; do not confuse a health check with a browser
preview that the owner can already reach.

For an immediate read-only view from an owner workstation with authorized SSH
access, use SSH local-port forwarding to map workstation
`127.0.0.1:3141` to DEV `127.0.0.1:3141`, then open
`http://127.0.0.1:3141/` on the workstation. The owner account, hostname
and SSH credentials are chosen from its existing authorized connection.
A permanent, private Tailscale preview URL may replace the tunnel when its
exact routing and access controls have been separately verified.
Do **not** expose an unfinished DEV application to the public Internet.

Source updates do **not** appear inside the immutable running 0.16.0
container merely because someone edited Git. A changed application must
actually be safely built and deployed/reloaded on DEV. For every feature,
the delivery chat reports both the new source SHA and the working browser
preview version, not just a PR link. Prefer incremental DEV functionality
without changing the installed signed release until the candidate is ready.

## PROD release gates kept, not multiplied

- Matching successful DEV release event: same version, source SHA, OCI
  repository and immutable image digest.
- Existing release signature, provenance, SBOM, Critical/High policy,
  independent material-risk review, product owner authorization and audit.
- PROD-specific Keycloak/OIDC, session/CSRF, tenant-isolation and data
  protection controls, sealed runtime secrets, database readiness and
  recoverable backups.
- Inactive-slot health and controlled traffic switch, previous immutable
  release retained for rollback, non-destructive schema compatibility.
- The historical Task014 `deployment/environments/prod.json` is still
  disabled and retains its old STAGING predecessor for frozen-source
  compatibility. It is NOT the new PROD operator. The separate
  `direct_dev_prod_preflight.py` checks matching DEV evidence but cannot
  activate PROD. A properly reviewed PROD adapter and runtime/ingress/secrets
  installation are required before any real promotion.

## Boundaries and next real migration

This release contract is **source policy**, not a PROD installation.
M05 owns Analytics product-specific direct DEV-to-PROD activation and the
existing Task013/014 executor. Do not repurpose or activate its DEV-only
broker on production without separately qualifying the existing PROD host.
M01 owns Sumlaude identity on PROD independently of Analytics 0.16.0.
