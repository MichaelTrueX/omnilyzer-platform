<!--
File: docs/operations/task013-authenticated-version-preflight.md
Purpose: Operation and security contract for the authenticated one-use release
         version absence check before any external Task 013 registry publication.
Related: .github/workflows/platform-release.yml,
         release/registry_absence_preflight.py,
         release/tests/test_registry_absence_preflight.py,
         release/publish_zot.py, release/publish_forgejo.py,
         docs/operations/task013-forgejo-oidc-auth-probe.md.
Authority: Source and policy review; no independent publication/deployment.
-->

# Task 013 — authenticated registry-absence gate

## Scope

The October 17, 2026 production Forgejo OIDC correction has been
independently verified through two successful authenticated GitHub Actions
diagnostics. The incomplete version `0.14.4` remains immutable and must
never be re-dispatched. The planned new coordinated version is `0.14.5`.

The first registry-writing job in `platform-release.yml` is
`publish-zot`. It still verifies the complete immutable build handoff
before requesting JWTs. This job now performs a **separate read-only
absence preflight** before publishing any OCI blob or tag. The dependent
`publish-forgejo` job cannot run unless the entire zot job succeeds.

## Read-only authenticated checks

The preflight requests **two independent, fresh GitHub OIDC JWTs** in the
already protected `task013-dev-release` GitHub environment, each under
the existing exact `platform-release.yml@refs/heads/main` identity.

- Forgejo audience: `u:2:316bec9a-53e4-4807-9557-7febdc979d0a`
- zot audience: `https://oci-dev.omnilyzer.ai`

Only hardcoded HTTPS origins, owner `omnilyzer`, the original fixed package
names and the validated `X.Y.Z` release version are accepted. The URLs
are not workflow inputs. The read-only Python module accepts token **file
paths**, not secrets or tokens on command lines. Files are mode `0600`,
deleted by a trap after the probe, and no token or HTTP response body is
logged. Redirects are forbidden.

Forgejo must first return **HTTP 200 with a valid package-list response**
to demonstrate authentication; a 404 cannot count as absence before that.
The preflight then requires the precise package-version API to return
**HTTP 404** for `omnilyzer-release-canary` (PyPI),
`@omnilyzer/release-canary` (npm) and
`task013-release-evidence` (generic). Each package type is independently
checked against bounded, paginated authenticated package lists to protect
against URL-encoding ambiguities, including the npm scope separator.

zot must return **HTTP 200** to the authenticated `GET /v2/`, followed
by **HTTP 404** to an authenticated `HEAD` of
`/v2/omnilyzer/task013-release-canary/manifests/<version>`.
This endpoint and 404 semantics follow the OCI Distribution API.

A 200 occupied destination, 401/403 unauthorized result, 5xx error,
network/TLS failure, unexpected JSON, exceeded pagination/size bound, or
HTTP redirect **fails closed** and prevents any new publication. There is
no write, registry cleanup, tag replacement or fallback token.

## Release acceptance and rollback

Before dispatch verify protected-main SHA, green required CI, and branch
policy. Under the user's separate approval, dispatch a single
`workflow_dispatch` with `auth_probe=false`, unused coordinated version
and exact main SHA. Do not assume another publication is harmless if a
workflow fails; preserve the historical partial version and use a **new**
version following remediation and re-approval.

Accept a full release only after the normal `gate`, `build`,
`publish-zot` and `publish-forgejo` jobs succeed; the Forgejo diagnostic
job must remain skipped. Confirm the exact
`REGISTRY_PREFLIGHT_ALL_FOUR_DESTINATIONS_ABSENT` marker preceded the
first publishing write. Then independently check zot OCI digest, package
round-trip bytes, signed manifest and provenance, and immutable evidence
bundle. A green GitHub run alone is not permission to deploy.

The preflight narrows accidental version collisions; it cannot guarantee
absolute race freedom if another authorized system creates the exact same
version between the check and publication. Existing zot immutable-tag refusal,
Forgejo version duplicate refusal, protected workflow concurrency and
restricted publishing identities remain mandatory.

**DEV/PROD activation is not authorized** by this change. The distinct
Task 014 broker and application authentication/session handling are
unmodified.
