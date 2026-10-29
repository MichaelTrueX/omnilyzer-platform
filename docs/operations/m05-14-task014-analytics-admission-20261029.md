# File: docs/operations/m05-14-task014-analytics-admission-20261029.md

## Purpose and linked source
M05-14 Task014 integration checkpoint, based *exactly* on original platform PR #244 commit `1fd343d15a8faffe695f8272f7e2fa150fcf7b8f` and Analytics PR #52 commit `4cdda7faeba57abb3388f9be5c450fe6afb1140d`.

Relevant files: `deployment/saas_product_contract.py`, `deployment/promotion.py`, `deployment/release_consumer.py`, `deployment/execution.py`, `deployment/docker_runtime.py`, `deployment/runtime/dev/analytics.compose.review.yaml`, `deployment/products/analytics-dev.json` and `deployment/products/analytics-runtime-dev.json`. Canary code and existing protected Task014 authority were **not modified**.

## Delivered
The Analytics product admission validator now requires the *signed* `TrustedRelease.external_source` immutable projection, exact reviewed Analytics source Git SHA, product profile hash, runtime profile hash, approved OCI registry/repository and digest, original Task013 signer workflow and identity, DEV runtime port/readiness path, and four secret names. A caller-supplied `signed_external_source` mapping cannot substitute for signed evidence. Unit tests provide positive synthetic admission and negative tampering coverage. The validator does not mint or verify signatures and cannot be independently used as an authorization token.

## NO-GO conditions
- Existing `deployment/policy.py`, `deployment/execution.py`, `deployment/release_consumer.py`, and `deployment/docker_runtime.py` still restrict installation to the legacy canary. This branch does not bypass the existing broker/executor.
- An object of type `TrustedRelease` is NOT in itself cryptographic proof. The original verifier must perform real Sigstore/Cosign, OCI signature, certificate identity/issuer, subject and exact source/provenance hash checks before returning it. No raw/untrusted caller-created object may reach the privileged executor.
- Existing M05 PR #244 recorded a real Grype scan of the previous Analytics PR49 source with Critical/High vulnerabilities. That evidence cannot be treated as cleared merely because PR52 is newer. Rebuild and re-scan exact PR52 OCI, enforce zero Critical/High with no exceptions, and sign/publish under protected Task013 before any Task014 installation.
- No signed, published PR52 image/release package or validated broker promotion was available to this integration branch. No installation, host secret creation, live PostgreSQL permissions alteration, public ingress, production activation or rollback was performed.

## Exact steps required to finish Task014
1. M05-13 completes protected original Task013 for PR52 with zero Critical/High, signs OCI digest and release manifest/provenance with original trusted OIDC signer; independently verify Cosign OCI and both evidence blob signatures and external source claim.
2. Extend the existing original Task014 `release_consumer` with **exact Analytics-specific** signed evidence schema, without adding Analytics to the general canary allowlist; bind verified identity to product-specific broker operation, scoped executor request schema and replay/audit gate.
3. Retain separate canary Compose and backend. Install Analytics only by an authorized release and rootless host executor using the already-reviewed isolated blue/green Compose; candidate slot must pass `/livez`, `/readyz`, real JWT login, restricted DB roles and tenant isolation before the route is switched.
4. Host prerequisites: isolated rootless Docker socket/UID and actual host-to-container UID10001 mapping; external network `omnilyzer-analytics-backend-dev`; two restricted least-privilege PostgreSQL roles with current column grants and FORCE RLS validation; four nonempty individual 0600 secret files under `/var/lib/omnilyzer/deployment/analytics/dev/secrets` owned by effective rootless-mapped UID; prove container positive read and unrelated UID negative read. Port 3141/3142 must be free and loopback-only. No secret value in Compose config, logs or git.
5. Persist *both* signed immutable digests and active slot. For rollback use already signed previous digest in the inactive slot and health/tenant regression test before atomic loopback route reversal; do not reverse database migrations or delete learner/customer writes. Always preserve the original canary service and source. Do not interpret a syntactically correct sha256 or unsigned OCI archive as a release.

## Status
Partial integration only, no signed install and no production changes. Owner authorization for development does not override cryptographic/security/production gates.
