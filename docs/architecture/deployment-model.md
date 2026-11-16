<!--
File: docs/architecture/deployment-model.md
Purpose: Define the current two-server developer-preview and immutable release model.
Related: AGENTS.md, deployment/direct_dev_prod_preflight.py,
deployment/controller.py (historical DEV source),
docs/adr/0006-immutable-oci-deployment-and-promotion.md,
docs/adr/0012-direct-dev-prod-delivery.md.
-->

# Deployment Model

## Current operating environments

```text
                 GitHub
             versioned source
                   |
                   v
   DEV: omnilyzerdev (also backup)
   edit -> safe preview -> test -> owner sees it
                   |
             Product Owner GO
          exact signed DEV digest
                   |
                   v
   PROD: truexmainserver
   verify -> readiness -> atomic traffic switch
              retain rollback
```

Only these two actual hosts are used for application development and
production. There is no permanent STAGING server or mandatory staging release.
Legacy STAGING fixtures remain disabled solely for old test and audit
compatibility; they are not part of the current promotion sequence.

## Develop visibly on DEV

Use the existing Git workspace on omnilyzerdev. The accountable delivery chat
edits, runs tests and shows a real user journey on DEV as the feature evolves.
The owner sees functional changes through approved private browser access;
the delivered preview URL and actual running version must be explicit.
Analytics 0.16.0 is currently a signed private DEV container on
`127.0.0.1:3141` and remains immutable while active. It is not a writable
development directory. Incremental application changes need a legitimate
DEV deployment/reload before they can be called browser-visible. Do not
modify the live signed container filesystem or bypass identity/tenant controls.
Private Tailscale/SSH access may be used for preview, not unreviewed public DNS.

## Source, review and promotion

One feature chat, one source branch and one cohesive PR. GitHub is authoritative.
Use the existing Task013/014 build, scan, evidence, SBOM, provenance, signature,
promotion and rollback logic. A release candidate is built once, is identified
by a pinned OCI digest, and is the **same artifact** promoted from a successful
DEV release to PROD. No rebuild of application source in PROD.

The mandatory PROD predecessor is the exact DEV success event with matching
version, source commit, repository and OCI manifest digest. Historical
STAGING success cannot substitute for missing DEV evidence. Production
requires an independent Product Owner GO and the configured production
runtime, identity, secrets, security/readiness and backup/rollback gates.

The repository's historical `deployment/environments/prod.json` retains
`required_prior_stage=staging`, `deployment_enabled=false` and null
runtime references. That is inert Task014 Phase-1 source, NOT a production
configuration or permission for a staging server. The approved two-host
policy is implemented separately by `direct_dev_prod_preflight.py`.
It is source-only and cannot deploy. The eventual PROD operator must wire
that exact evidence check to the existing signed-release, owner approval,
health, backup and rollback controls before public activation.

## Recovery and database safety

Keep the last healthy immutable version ready for rollback. Roll back the
application release/traffic route, not customer data or database history.
Apply backward-compatible schema expansion with serialized and checked
migrations; remove old schema only after consumers and rollback windows have
been addressed. Preserve tenant authorization, authentication and CSP/CORS.

## Explicit non-goals

No new staging server, generic preview framework, Kubernetes, cluster,
repeated QA organization, global DEV source hot patch to PROD, paid GitHub
service requirement or automatic production approval. Legacy experiments and
recorded evidence may remain as documentation and must not be used to
silently change current live deployment authority.
