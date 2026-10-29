<!--
File: docs/operations/m05-14-task014-analytics-runtime-20261029.md
Purpose: Auditable original Task014 Analytics DEV continuation after the signed
         Task013 0.15.0 publication, including read-only host findings,
         synthetic runtime evidence, first-install rollback correction, and
         precise remaining authorization gates.
Related: deployment/analytics_dev_release_review.py,
         deployment/tests/test_analytics_dev_release_review.py,
         deployment/tests/test_m05_14_analytics_compose_envfiles.py,
         deployment/runtime/dev/analytics.compose.review.yaml,
         deployment/execution.py, deployment/broker.py,
         deployment/release_consumer.py, deployment/docker_runtime.py,
         deployment/products/analytics-dev.json,
         release/analytics_release_source_binding.py,
         MichaelTrueX/omnilyzer issue #27.
Authorization: Does not install a product, change privileged source sets,
               publish a release, expose ingress, or modify production.
-->

# M05-14: Signed Task013 0.15.0 and remaining original Task014 DEV gates

Date: 2026-10-29. Review branch based on protected platform main
`b9e22e745ecbaf96dc15998e91d1a74f70e5ad77`.

## Signed release status (independent GitHub job-status check)

Original protected Task013 GitHub Actions run:
https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/40881693662

The actual GitHub API reports **SUCCESS**, including all three Analytics
jobs: `analytics-source-admission`, `analytics-publish-zot`, and
`analytics-publish-forgejo`. Canary build/publisher jobs were skipped as
expected. Run source is platform main SHA `b9e22e745ecbaf96dc15998e91d1a74f70e5ad77`.

Issue #27 M05-13 release evidence reports immutable Analytics version
`0.15.0`, OCI repository `oci-dev.omnilyzer.ai/omnilyzer/analytics`,
digest `sha256:6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1`,
source PR52 SHA `4cdda7faeba57abb3388f9be5c450fe6afb1140d`,
original Sigstore bundles and Cosign signature verification, with zero
Critical/High vulnerability-policy exceptions. These are signer-run
claims, **not an independent original Task014 release consumer verification
in this branch**. The immutable release MUST be acquired and checked by
original Task014 Zot + Forgejo consumers and Sigstore/Cosign verifier before
any privileged request. No standalone `TrustedRelease` construction is allowed.

## Actual isolated development observations

- `truexdevelopment` Docker Compose version: v5.5.0.
- Docker daemon reports AppArmor/seccomp but **not rootless**; socket is
  `/var/run/docker.sock`, root-owned. This host cannot be treated as
  an accepted *rootless Task014 installed execution host*.
- The required `/var/lib/omnilyzer/deployment/analytics/dev/secrets`
  directory is absent on this test host. No secrets were provisioned.
- Local security-test image `omnilyzer-analytics-pr52-security:local` is
  cached. It was used **solely in an ephemeral, no-network functional
  secret-loading probe**, not as a signed release or installed product.
- The original Node/Compose invocation accepted four *distinct*
  `NAME=SYNTHETIC_TEST_...` env-file contents under UID 10001.
  The first isolated container succeeded; removal of the JWT file
  forced a failure. All test containers were deleted.
  This demonstrates basic UID10001 + Node env-file functionality on
  this rootful test daemon, **not rootless UID/GID mapping**.
- Because Compose local-file secrets do not enforce requested uid/gid/mode,
  the actual approved rootless execution host must separately prove
  ownership mapping, positive reads and negative reads before activation.

Reproduction (isolated, no registry/promotion/host installation):

```bash
cd /path/to/omnilyzer-platform
python3 -m unittest deployment.tests.test_analytics_dev_release_review deployment.tests.test_m05_14_analytics_compose_envfiles -v
M05_REAL_ANALYTICS_COMPOSE_TEST=1 python3 -m unittest deployment.tests.test_m05_14_analytics_compose_envfiles.AnalyticsEnvfileRuntimeTests.test_actual_node_loads_exact_secrets_and_denies_missing_file -v
```

The opt-in test runs only if the locally cached security-test image is
present. It never fetches images, opens ports, accesses real secrets, or
creates an external PostgreSQL connection.

## First-install rollback distinction fixed

Before this change, review-only metadata said the first deployment could
roll back to a previous immutable image even when `existing_image=None`.
That is inaccurate. The existing review function now specifies:

- First install, no prior Analytics digest: stop/deactivate the new private
  slot, leave it unexposed, and preserve acknowledged database writes.
- Subsequent upgrade, prior *signed and independently verified* digest:
  reuse the original Task014 immutable-digest rollback, without reverting
  committed PostgreSQL records.

This is a **metadata correction only**. It does not implement a privileged
stop operation or bypass the current original canary-only executor.

## Current go/no-go and necessary integration

**NO-GO for installed Analytics DEV Task014** despite a successful signed
Task013 release. Exact missing gates:

1. Original Task014 `PromotionRequest`, `ExecutorRequest`,
   release consumer, broker, privileged executor and installed source set
   still enforce the canary-only repository and `NoSecretsReference`.
   Do not widen global `validate_repository` or silently accept a
   public constructible `TrustedRelease`; add a separate closed product
   operation bound to verified original signed Analytics source evidence.
2. Install and independently qualify an approved rootless Docker authority
   on the intended *private DEV host*. Never substitute the rootful test
   daemon as privileged executor evidence.
3. Preprovision the four private `NAME=value` env-file references with
   host-to-container UID mapping, secure ownership and effective 0600,
   and positively and negatively test real mounts. Do not print secrets.
4. Prove restricted separate PostgreSQL auth and collector roles, FORCE RLS,
   readiness, and migration/writer-fence rules on an isolated DEV database.
5. Original broker-controlled signed 0.15.0 promotion, replay-denial, audit,
   private readiness/identity, and original-executor first-install stop
   rollback must pass. Canary runtime and publisher ACL must remain unchanged.

No unsigned installation, production modification, canary policy expansion,
registry write, release dispatch, merge, or Task014 privileged activation
was performed by this change.
