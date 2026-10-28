<!--
FILE: docs/operations/m01-task013-local-source-to-oci-candidate-20261028.md
PURPOSE: Full review and verification for an additive ORIGINAL Task013
         source-to-OCI locally verified Analytics build candidate.
RELATED: release/analytics_task013_build_candidate.py,
         release/tests/test_analytics_task013_build_candidate.py,
         release/analytics_oci_context.py, release/analytics_oci_archive.py,
         release/analytics_task013_build_input.py, release/builder_versions.py,
         release/release_plan.py, .github/workflows/platform-release.yml,
         deployment/release_consumer.py, deployment/saas_product_contract.py.
STATUS: LOCAL REVIEW ONLY. No original Task013 signer/workflow mutation,
        registry publication, installed Task014 broker or host change.
-->

# Analytics candidate OCI build through ORIGINAL Task013 components

**Date:** 28 October 2026. **Candidate:** final Analytics source PR45
`8648adba2db884cc78274080b9836ca46bafd630`, pinned and verified
by M01 source authority (51 file identities). M05 PR231 supplies original
Task013 immutable source input and independently verifies a local OCI
archive. M01 PR232 supplies sanitized deterministic Git-only Docker
build context. The new helper **joins these existing components**;
it is not a second release framework or cryptographic signing system.

## Complete build pipeline - local, explicitly unsigned

1. Verify M05's strict `build_input()`: product, external SHA, OCI repository,
   both exact read-only JSON profiles, /livez and /readyz, four secret NAMES
   only, 51 Git-source hashes and review-only status.
2. Validate current original pinned Buildx **v0.36.1** and existing
   `docker-container` builder's BuildKit **v0.24.0**. Require a
   constrained builder name. The caller must provision the pinned
   BuildKit container as original Task013 CI already does.
3. Create a private, temporary **Git-only source tar**, omitting
   historical tracked .env/backup/key/virtualenv data and all local
   untracked/modified files. Its Dockerfile is exactly PR45.
4. Invoke the original Docker Buildx command with that tar on standard
   input (not `docker buildx build .`). The only output is a temporary
   local OCI archive, no mutable tag, `--push`, registry destination,
   runtime secret or user-specific credential. Use exact linux/amd64
   and explicit Dockerfile path; BuildKit registry networking for pinned
   base/npm dependencies is a separately accepted CI egress boundary.
5. Verify archive with **M05's existing `verify_archive()`**: every
   OCI content digest, single image, linux/amd64, UID/GID 10001,
   restricted Next.js launch command and port3000, no JWT/PG Env secrets.
6. Return only a local manifest digest, archive digest and source TAR
   hash under `release_authorized:false`, `deployment_authorized:false`.
   Private OCI/TAR files are deleted on success or failure, and the
   temporary BuildKit instance is cleaned by the invoking test harness.

This code does not create, install, execute or modify an original
Task014 executor request. Neither its local digest nor the output
from `verify_archive` is a signed Task013 provenance attestation.

## Invocation for approved LOCAL DEV tests

The caller first provisions a temporary, digest-pinned BuildKit builder
using the original `docker buildx create --driver docker-container`
mechanism. Its name is passed into the following review-only command
(the builder must match pinned versions):

```bash
python3 -m release.analytics_task013_build_candidate \
  --analytics-checkout /path/to/clean/exact-PR45-Git-checkout \
  --builder approved-ephemeral-buildkit-name \
  --build
```

Without `--build`, only source/profile and builder preflight is run.
A future reviewed Task013 workflow can invoke this helper rather than
creating a separate release producer. It will still need its ORIGINAL
protected-main signer workflow, SBOM/Grype, Cosign, Forgejo/Zot,
approved and signed external-repo source claim, and exact immutable
registry manifest digest.

## Security invariants

- Closed product/source SHA/repository/ready route, explicit builder
  pinning, no shell calls or arbitrary flags, no local mutable checkout
  context, no bypass of original release gate.
- Real Analytics JWT remains JSON Bearer with localStorage in this
  product; session revocation and dedicated PostgreSQL roles unchanged.
  Task013 GitHub OIDC is release authorization, not an end-user identity
  migration. Any future shared Keycloak identity requires separate
  compatibility review and cannot silently change Analytics tokens.
- Fail-closed on malformed, wrong/stale external source, wrong OCI
  repository, altered digest, unknown builder, unpinned BuildKit,
  container root user, wrong health or runtime secret leak.
- The original 0.14.6 signed DEV canary and original Task014 canary-only
  policy/registry/broker/runtime remain unchanged.
- No production, live database, website, Cloudflare/DNS/Nginx, protected
  main, installed DEV broker/executor or signing workflow changes.

## Release-blocking gates

**The verified LOCAL OCI candidate is not a signed Task013 release.**
A real protected-main workflow must cryptographically include the
reviewed external Git/source and OCI digest in its original signed
provenance and publish/verify the exact OCI manifest through Zot and
Forgejo. Task014 then needs a reviewed product-specific signed evidence
consumer and installed isolated Analytics executor with private secret
references, blue/green selection, audit/replay protection and safe
digest rollback. M04 must independently approve this full chain before
any actual DEV dispatch or stage promotion.

A local Buildx artefact alone does not establish true cross-product
shared identity, Workspace or Website Engine consumption.

## Actual complete original-BuildKit DEV execution on 28 October 2026

This source-only candidate was executed on `truexdevelopment` with a
temporary `docker-container` Buildx builder pinned to the exact original
BuildKit `v0.24.0` image digest
`sha256:6eceb8971ce4fceb3daca562832642706238b7eea72941fcf9896c93c3c4a53e`.
Original platform Buildx was `v0.36.1`. It used only the deterministic
532-file canonical source Git TAR via standard input, not `docker buildx
build .`. M05's existing `release/analytics_oci_archive.py` verified
all resulting local OCI content-addressed blobs, Next runtime identity,
linux/amd64 architecture, rootless user, port and no JWT/database Env
values; all checks returned **PASS**.

**Actual local source + OCI receipt (NOT a signed release):**

- Final exact Analytics source commit:
  `8648adba2db884cc78274080b9836ca46bafd630`
- Actual Git tree: `5806948189acba458cd8b817db15a563ea3eebee`
- Canonical build context SHA-256:
  `d64d272944b775085ad62e9d8ef0f4be5b272fc87286f8f607d59105ccb4b818`
- **LOCAL, UNSIGNED** OCI image manifest:
  `sha256:114c5fe582cd43f96e8479961a48c8e7b49ec5fc461c3831cbffef2e9ebc26a6`
- Local OCI export TAR SHA-256:
  `32eda852adb5522ee3485b827276be2b16859ebd8a7f5833014f0d19b573d4d3`
- `release_authorized:false`, `deployment_authorized:false`.
- Temporary OCI TAR, Git TAR, BuildKit builder/container removed in the
  original CI-like test harness; no registry, live platform service, DB,
  production, Cloudflare or DNS mutation.

The OCI manifest differs from M05's earlier local build because the
build input and build execution are not yet independently guaranteed
bit-for-bit reproducible at the dependency-layer level. The deterministic
source TAR does **not** prove fully deterministic layers, nor does an
unsigned local manifest digest have supply-chain signing authority.
Further reproducibility hardening should not delay the higher-priority
original Task013 signed external-source provenance and private Task014
release-authorized deployment.
