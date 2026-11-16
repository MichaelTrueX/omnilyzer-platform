<!--
File: docs/adr/0012-direct-dev-prod-delivery.md
Purpose: Record the two-server development, owner preview and immutable release decision.
Related: AGENTS.md, docs/adr/0006-immutable-oci-deployment-and-promotion.md,
deployment/policy.py, deployment/controller.py, deployment/environments/prod.json,
docs/operations/dev-prod-direct-delivery.md.
-->

# ADR 0012: Direct DEV to PROD delivery without a STAGING environment

- Status: Proposed (Product Owner direction approved 2026-11-16; repository review pending)
- Date: 2026-11-16
- Amends: [ADR 0006](0006-immutable-oci-deployment-and-promotion.md) only for environment count and required predecessor.

## Context

Omnilyzer is operated by one owner, with omnilyzerdev available for
development and backups and truexmainserver serving production. The historical
Task007 DEV -> STAGING -> PROD experiment introduced an additional, mandatory
promotion step despite the absence of a separate, operationally needed staging
server. The owner wants to see functional changes on DEV while they are being
made and release to PROD when satisfied.

## Options considered

- Continue a three-stage chain: rejected as unnecessary owner overhead,
  without evidence that a permanent STAGING host improves this product.
- Develop directly on PROD: rejected due to customer impact, identity/data
  exposure, unreproducible source edits and difficult rollback.
- Use existing DEV and PROD only, with an immutable signed release boundary:
  selected. No third host, orchestration system or generic preview framework.

## Decision

1. **DEV (omnilyzerdev)** is the only development and backup host. The
   accountable feature chat develops there, presents incrementally working
   private browser/API views, and runs focused checks. Code changes are not
   falsely described as visible until the DEV application was actually
   reloaded/deployed and observed in a browser.
2. **PROD (truexmainserver)** receives the exact previously verified DEV
   source/release identity, signed OCI manifest digest and associated evidence
   only after explicit Product Owner approval. No rebuild or source edit on
   PROD, no public exposure of unapproved DEV work.
3. The promotion prerequisite for PROD is an exact matching **DEV success**
   event, never a STAGING success. Version, source SHA, OCI repository and
   manifest digest must all match. The existing production approval policy
   remains true; signed Task013/Task014 admission, security, authentication,
   tenant isolation, readiness, migrations and rollback remain unchanged.
4. A former STAGING environment definition and audit/schema vocabulary may
   remain disabled for historical compatibility. They are not an operational
   deployment environment and are not required before PROD.
5. Existing private DEV runtime stays pinned and healthy. A live DEV preview
   uses the already-approved private access path and/or a separately accepted
   private route. Development may not patch the running signed container in
   place; a fresh development build/deploy is required for changes to appear.

## Consequences

One fewer environment, no independent STAGING maintenance or release approval.
The owner can review an actual DEV experience during feature delivery. DEV
acceptance and PROD runtime configuration are different things: production
still requires independent secrets, health, backups and a final owner GO.
Source-only policy changes do not activate an unconfigured PROD executor.

## Security implications

Do not weaken digest/signature checks, independently owned systemd/NGINX
boundaries, OIDC, session and CSRF controls, tenant RLS, CSP/CORS, backups,
auditable one-shot release authority or rollback. DEV previews must be
private and use no production credentials/customer data. A deliberate
production release approval is retained even without STAGING.

## Operational implications

Use one accountable development/release chat, one GitHub PR per meaningful
feature, one working DEV preview and one production promotion decision.
Automation reuses Task013/014, not a new pipeline per version. Existing
signed Analytics 0.16.0 on DEV proves DEV acceptance only; its separate
PROD environment has not been activated by this decision.

## Migration and rollback implications

The present change migrates the repository's PROD prerequisite from
STAGING to DEV and adds regression tests rejecting unmatched staging-only
evidence. The currently disabled PROD config remains disabled. Existing
historical STAGING fixtures and metadata remain untouched to avoid loss of
evidence. Application rollback remains previous signed digest plus compatible
database state. The old three-stage rule can be restored only by a reviewed
policy decision and matching source/test change, never by a runtime shortcut.
