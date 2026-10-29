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

## Additional signed Analytics evidence v1 compatibility (M05-14)

**Actual important format difference:** The original protected Task013
Analytics-only producer `release/analytics_release_evidence.py` emits
*schema-version 1*, an Analytics-specific provenance statement, a signed
`external_source` claim in BOTH manifest and provenance, and **no synthetic
canary Python/npm packages**. The original canary-only Task014 release
consumer requires schema v2 and canary Python/npm artifact identities.
Simply adding an Analytics repository to `APPROVED_OCI_REPOSITORIES` would
both fail and broaden the wrong trust boundary.

The follow-up adds these complete review-only files:

- `deployment/analytics_signed_release_consumer.py`: an immutable 0.15.0
  Analytics evidence reader fixed to signed Task013 run 40881693662, platform
  source SHA `b9e22e7...` and the exact published digest recorded above.
  Reuses the ORIGINAL TLS, read-token, Sigstore blob and Cosign OCI verifier
  *interfaces*. Validates the genuine Analytics v1 manifest/provenance schema,
  separate Forgejo Generic package, closed gzip/TAR file set, streaming
  scanner SHA256 hashes, zero security exceptions, signer issuer/identity,
  source claim and reviewed product/runtime pins. Returns an INERT receipt.
  Does not return a privileged request or permit installation.
- `deployment/tests/test_analytics_signed_release_consumer.py`: synthetic
  end-to-end schema fixture and adversarial cases. Synthetic verifier results
  do not prove signatures of the actual published release.
- `deployment/release_consumer.py`: exact Analytics-only GET routes in the
  original TLS helper, preserving all default canary paths and size limits.
- `deployment/oci_verifier.py`: explicit constructor-only
  `product_id="analytics"` read-only OCI repository selection. The ORIGINAL
  existing default remains the canary-only verifier and continues using the
  original global canary repository validator. No wildcard or unapproved
  product name is accepted.

The review-only consumer intentionally remains OUTSIDE the current installed
`deployment/application_source_set.py`. It is NOT wired into the original
broker, privileged executor, workflow, installed rootless socket, secret
mounts, ingress or deployment policy, because those require separate
product-scoped Task014 integration and independent security approval.

The real signer/OCI release status is independently confirmed via GitHub,
but **no original Task014 authenticated Forgejo/Zot GET plus actual Cosign
signature verification against those live bytes has yet been executed**.
The synthetic regression tests validate only the code path and rejection
logic. No install, no production host modification, and no extension to the
canary runtime authority is implied.

### Independent CI / baseline and least-privilege registry follow-up

The original `deployment/tests/test_execution.py` static historical
`test_protected_live_files_are_byte_identical` expects an old hash for
`.github/workflows/platform-release.yml`. It fails with the same exact
observed and expected SHA256 values on a **fresh, untouched** detached
platform `origin/main` checkout at `b9e22e7...`. That baseline failure is
not introduced by this branch and is NOT waived or silently rewritten.
The original 245-test focused release/broker/executor/OCI subset without
that preexisting baseline case passed (3 expected skips). A missing
`test_registry_promotion_composition` name in an initial ad hoc command
was operator test selection error; no such test module exists.

The successful Zot publisher ACL added for `omnilyzer/analytics` was
reported by M05-13 as the publisher's exact read/create identity, NOT an
independent grant to `platform-promote.yml`. Before attempting original
Task014 authenticated read-only admission, separately verify and, with
explicit operator approval, configure an Analytics-only **read** grant for
the exact existing Task014 promotion workflow identity on the actual Zot
server (`truexmainserver`), preserving all existing canary ACLs and the
anonymous deny rule. Independently verify the corresponding Forgejo
Generic `analytics-release-evidence` reader grant. Do not assume that a
signer's successful publication confers promoter access.

The review-only code has NO runtime-activated registry permission or
read-token fallback. Its signed evidence verification is only as strong as
its actual installed, original Task014 Cosign/Sigstore implementations.
Synthetic mocks establish negative test coverage, not live sigstore
cryptographic acceptance. Release 0.15.0 is immutable and must NOT be
rerun or overwritten during Task014 testing.
