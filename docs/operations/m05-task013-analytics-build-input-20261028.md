<!--
FILE: docs/operations/m05-task013-analytics-build-input-20261028.md
PURPOSE: Executable handover for an immutable UNSIGNED Analytics OCI input to the
         ORIGINAL Task013 protected-main signing and Task014 broker/executor.
LINKED FILES: release/analytics_task013_build_input.py;
              release/tests/test_analytics_task013_build_input.py;
              release/analytics_source_admission.py;
              release/products/analytics-source.json;
              deployment/saas_product_contract.py;
              deployment/products/analytics-dev.json;
              deployment/saas_product_runtime.py;
              deployment/products/analytics-runtime-dev.json;
              .github/workflows/platform-release.yml;
              deployment/release_consumer.py, execution.py, docker_runtime.py.
STATUS: DRAFT REVIEW ONLY, neither signed nor deployable.
-->

# M05: original Task 013 Analytics build-input handover

**Date:** 2026-10-28
**Source baseline:** original-platform M01 PR #230 `fab90b339300583752c40c370e58e344e9375d0e`
**Product:** M05 packaged Analytics PR #45 `8648adba2db884cc78274080b9836ca46bafd630`
**Scope:** One additive release-side input guard. No new signer, executor, broker or website engine.

## 1. Executed verification

This review branch consumes the complete current M01 source-admission verifier and
both current native product profile loaders. It verifies the original integrated
29-file source manifest and the 22 additional critical full Git blobs. The three
M05 OCI source files must be in the verified critical set.

Execute from the isolated original-platform checkout:

```bash
export OMNILYZER_ANALYTICS_CHECKOUT=/path/to/clean/omnilyzer-checkout-at-8648adba
python3 -m unittest -q release.tests.test_analytics_task013_build_input
python3 -m release.analytics_task013_build_input \
  --analytics-checkout "$OMNILYZER_ANALYTICS_CHECKOUT"
```

The output includes the exact source Git commit/tree, platform Git commit/tree,
review profile SHA-256, Dockerfile and dockerignore SHA-256, OCI test source
SHA-256, inherited source manifest hash and 51 verified file identities.
It carries no database credentials, token values, registry signature,
immutable published OCI manifest digest or promotion request. In particular,
`release_authorized=false` and `deployment_authorized=false` are mandatory.

A syntactically valid receipt is not a trusted release. The program cannot
request OIDC, publish to Zot or Forgejo, invoke a broker or start a container.

## 2. Boundaries that remain blocked

The existing protected-main `.github/workflows/platform-release.yml` still
builds, scans, signs and publishes the **synthetic Task013 canary**. Extending
it for Analytics requires an authorized source fetch of the independent private
GitHub repository; an exact built OCI archive based on PR45 Git tree and Docker
recipe; the existing Syft/Grype/immutable evidence pipeline; signed external
source identity tied cryptographically to the built image digest; and the
original protected-main OIDC certificate identity. A local Docker image ID is
not an immutable published registry manifest digest.

The current Task014 policy, trusted release consumer, broker, executor and
rootless runtime accept only the original no-secrets canary release. An actual
Analytics DEV promotion requires separately reviewed product identity and
secret-reference authority, **private** ingress, isolated blue/green application
runtime, existing signed artifact verification and replay protection, and
rollback to a *previously signed* digest without reverting persisted events.
Do not treat the two inert SaaS review profiles as installed authority.

No shared-platform identity, Workspace or Website Engine consumption is
demonstrated merely by matching Prisma entity names. The current Analytics
JSON Bearer/localStorage token model is intentionally unchanged. M01 owns the
architecture/consumer compatibility decision.

## 3. Owner and independent QA gates

1. M01 integrates this build input only if it retains the exact source/profile
   contracts and chooses one original-platform release implementation.
2. M04 independently reviews the final combined release+consumer code, negative
   OIDC/source/substitution/secret/rollback cases and exact artifact digest.
3. Before a genuine signed release, owner separately approves protected-main
   merges, required release authority and the specific DEV change window.
4. Before DEV activation, verify installed Task014 source set, private DB role
   grants, reversible slot, root-controlled broker, ingress, and unchanged
   Task014 0.14.6 canary. Obtain verified promotion audit/rollback proof.
5. Production, live PostgreSQL, Nginx, DNS, Cloudflare and all other websites
   remain excluded from this review and unchanged.

**Current verdict:** source-verified unsigned candidate only; signed original
Task013 Analytics release and Task014 broker-controlled promotion not yet done.
