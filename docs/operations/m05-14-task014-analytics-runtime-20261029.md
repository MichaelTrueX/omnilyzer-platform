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

### Independent genuine Task013 Zot receipt artifact check

Downloaded ONLY the original small, nonsecret GitHub Actions artifact
`analytics-task013-zot-40881693662-1` from protected successful run
https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/40881693662.
The actual `analytics-oci-publication.json` is 205 bytes, SHA256:
`6c64d2248ce4ce081742ad4a57bbf8abbe40b2bdb9dfe432f72894d3a3dffd46`.
Its exact five fields are `schema_version=1`, original Zot origin,
`repository=omnilyzer/analytics`, `tag=0.15.0` and original digest
`sha256:6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1`.
All five values match the read-only Task014 consumer's reviewed pin.
This is a genuine Task013 publication *receipt*, not the signed Forgejo
manifest/provenance, actual registry readback, or Cosign verification
by Task014. The private source archive was neither accessed nor disclosed.

## M05-14: Closed Analytics request grammar and actual host readiness

### Task014 first-install request v2, inert and NOT routed

The original schema-v1 canary `deployment/execution.py` request, installed
broker, privileged executor, sealed Zot FD and private Docker pull are all
**canary-specific**. They cannot be safely generalized with a single OCI
repository allowlist edit. To avoid breaking the old canary route, the
separate complete `deployment/analytics_execution.py` adds one closed
**Analytics-only schema-v2 FIRST-install request grammar**, tested in
`deployment/tests/test_analytics_execution.py`.

This request is constrained to release 0.15.0, exact signed Task013 platform
source/run/OCI, exact external Analytics source commit, four signed-evidence
hash fields, original GitHub OIDC actor/run/JTI/expiry, installed reviewed
Compose + product/runtime SHA256s, four names-only host-secret references,
mandatory rootless+UID10001+0600 metadata, blue slot at 127.0.0.1:3141,
separate backend network, NO public origin and NO previous rollback digest.

`parse_analytics_request` explicitly REQUIRES four independent values supplied
by the future root-owned installer: installed platform commit, Compose SHA,
product profile SHA and runtime profile SHA. These inputs are never copied
from untrusted promotion fields. `bind_analytics_request_to_identity` requires
all original authorized GitHub OIDC identity fields. The companion
`bind_analytics_request_to_verified_evidence` requires exact original signed
manifest/provenance hashes, external-source claim SHA, OCI release and profile
hashes.

**Important trust distinction:** Neither the new public request dataclass,
`AnalyticsSignedEvidenceReview`, nor the public OIDC dataclass proves a
signature. A caller could construct all three in normal Python. Therefore
parsing/binding SHALL NOT be used as deployment permission. The ORIGINAL
protected broker must invoke actual signature verification and verified OIDC,
apply replay and sealed credentials, and route through an independently
reviewed product-only executor before any installation. Currently it does
none of that for Analytics. The existing canary parser explicitly rejects
Analytics schema-v2 request bytes. NO live installation authority was added.

### Observed host prerequisites, read-only check

- `truexdevelopment`: existing Docker is ROOTFUL, not the accepted original
  Task014 rootless Docker authority. Its Analytics secret directory is absent.
- `truexmainserver`: active `zot.service`, original Task014 DEV broker and
  executor services not active under the checked names. Expected Task014
  rootless socket and Analytics secrets directory absent. Zot configuration
  is root-protected and its Analytics *promoter* read ACL was not inspected.
- `omnilyzerdev`: checked standard Task014 rootless socket absent and default
  Docker CLI cannot reach a daemon in the authorized unprivileged session.
  This does not prove that no other user's rootless daemon exists.

Actual production registry is `truexmainserver`, which also hosts production.
No sudo, registry ACL modification, systemd, Docker host installation, secrets
provisioning, firewall or traffic change was performed.

### Exact remaining Task014 secure activation path

1. Review and install signed Analytics schema-v1 **read-only consumer** under
   root-controlled source authority, preserving canary schema v2 unchanged.
2. Add a separately closed Analytics request to original OIDC broker + replay
   + sealed registry credential and bound receiver, without allowing arbitrary
   caller-provided schema-v2 bytes to reach the executor.
3. Implement product-scoped rootless Compose/secret UID mapping, isolated
   PostgreSQL auth and collector roles, original audited first-install state,
   readiness gate and first-install **stop/deactivate** rollback, without
   reusing canary migrations/state or resetting database writes.
4. Independently confirm `platform-promote.yml` Analytics Zot and Forgejo
   reader ACL, actual original Sigstore and Cosign v1 evidence and root-owned
   installed manifest hashes. Then M04 independently reviews the combined
   evidence, security boundaries and rollback.
5. Only after explicit owner approval, execute one original-Task014-authorized
   private DEV promotion with replay-denial proof and actual rollback. This
   does not authorize public or production activation.

### Original verified OIDC + signed Analytics review composition (not broker)

The complete new `deployment/analytics_registry_review_composition.py`
implements `InertAnalyticsSignedReleaseReviewHandler`. It REUSES the
original Task014 `_normalize_identity` and already reviewed OIDC verifier,
`GitHubRegistryCredentialVerifier`/`VerifiedRegistryCredentials`, exact
three-JWT audience and workflow checks, sealed-method Sigstore collaborator,
constructor-scoped original Cosign verifier with the exact Analytics read-only
repository, and the separate v1 consumer. Its only output is an INERT review
receipt, not an `ExecutorRequest` or broker transport result. It intentionally
NEVER calls original replay, executor transport or Docker.

The complete independent test file
`deployment/tests/test_analytics_review_composition.py` exercises valid
synthetic original OIDC/registry context, wrong audience/token, unavailable
OIDC classification, false source/signer review, immutable constructor
collaborators and original canary composition. It additionally checks that
ALL new Analytics consumer/request/composition/Compose modules remain OUTSIDE
the installed `DevApplicationSourceSet` until separately approved.

**Important installed-source protection:** The existing
`deployment/registry_promotion_composition.py`, `broker.py`, `executor.py`,
`execution.py`, `private_registry_fd.py`, `private_registry_pull.py`,
`docker_runtime.py` and `application_source_set.py` are byte-unchanged.
Their original imported source closure and installed canary authorization
therefore remain intact. The new read-only Analytics composition lives in
its own module and does not introduce missing imports in the installed
canary environment. No request forwarding, plugin runtime or privileged
feature flag was activated.

## M05-14 after independent M04 5699460077: private broker and sealed Zot scope

M04 reviewed exact prior PR258 HEAD
`90d57c4d19ce5f44a16e00ac821dbbe7d584f6ed` and conditionally accepted
its read-only/inert code only. That review is **not a security approval of the
following new broker/FD transport boundary**. No new general QA meeting or
parallel PR is needed; request ONE independent final M04 acceptance after the
complete privileged executor, actual isolated rootless DEV runtime, PG roles,
health and first-install rollback work exists.

### Exact existing Task014 primitives reused

- `deployment/private_registry_fd.py` now supports an *explicit*
  `product_id="analytics"` on existing sealed-FD creation/read operations,
  requiring the **exact signed 0.15.0 digest**. The original default is still
  `product_id="canary"` and rejects Analytics. No tags, repository patterns,
  prefixes or caller-selected registries accepted. The same original Linux
  CLOEXEC, F_SEAL_* seals, request-SHA256, max 300-second TTL and credential
  redaction apply. `deployment/tests/test_private_registry_fd.py` adds exact
  positive/negative Analytics and cross-product cases. No credential data is
  added to executor request JSON or disk.
- New complete `deployment/analytics_promotion_broker.py` composes the
  original GitHub OIDC authorization and `_normalize_identity`, exact root-
  reviewed schema-v2 Analytics request parser, **internal** call to the
  original verified OIDC/registry/Sigstore/Cosign review composition,
  `bind_analytics_request_to_verified_evidence`, an independent original
  `GitHubRegistryCredentialVerifier` (separate authenticated Zot/Forgejo
  audiences), then seals the short-lived exact-image token. It requires the
  original 180-second pull budget plus 45 seconds BEFORE consuming the
  existing replay-guard JTI/run/request-hash. It then invokes only a distinct
  `_send_analytics_private` method, carrying canonical token-free bytes and
  the sealed descriptor; cannot default to the old canary transport method.
  Linux FD is closed on success, replay denial and transport failure.
- New complete `deployment/tests/test_analytics_promotion_broker.py` exercises
  the actual original JWT audience validation and sealed Linux FD, mocked
  **signed-release result** and private transport, source mismatch, wrong
  audience, invalid canonical request, OIDC failure, replay duplicate,
  short token TTL, runtime transport failure, canary transport separation,
  collaborator capture and FD cleanup. The mocked release **does not prove
  real Sigstore/Cosign verification**. No code can supply a release-review
  dataclass as a public argument to the broker. The reviewed request object
  remains *only a data shape*, not grant authority.

### Important explicit outstanding boundaries

1. The above broker is **not yet installed** in the reviewed Task014 source
   manifest, has no activated listener or owner-authorized root-controlled
   dependency composition, and uses no existing canary transport fallback.
   A test-only transport can return simulated success; that is NOT acceptance
   of a privileged action.
2. There is no root-owned Analytics-specific executor receiver that
   independently verifies SO_PEERCRED, exact signed source, schema-v2
   request, FD scope, replay and installed source manifest, nor an approved
   rootless Docker/Compose product installer. The original canary executor
   still rejects Analytics; do not alter it by broad allowlisting.
3. No real Task014 Zot/Forgejo reader ACL or live signature acceptance has
   been demonstrated, and no real DEV app or PostgreSQL two-role RLS and
   rollback has been tested. Signed Task013 0.15.0 must not be regenerated.
4. Real runtime activation requires an exact root-owned source check and
   approved product-specific private transport. Until completed and finally
   reviewed by M04, this PR remains **draft / installed Analytics NO-GO**.
5. PR branch baseline was protected `b9e22e7...`; protected main subsequently
   acquired the unrelated product-first `AGENTS.md` change (`25c5ecf...`).
   Reconcile before any eventual approved merge; do not reset main or
   silently override its new development rules.

### M04 follow-up validation and original canary regression

The complete new test file
`deployment/tests/test_analytics_promotion_broker.py` also checks an
**actual AF_UNIX SCM_RIGHTS Linux descriptor transfer** (no Docker) from
broker to simulated private Analytics receiver, AND the original durable
`SQLiteReplayGuard` across two separately constructed brokers with one
persisted JTI/run. A second attempt is rejected before transport. A credential
with less than the original `MIN_POST_PREFLIGHT_VALIDITY_SECONDS=225` fails
before consuming replay. These are synthetic signing tests; there is no live
privileged executor on the target host.

One original canary integration test,
`deployment/tests/test_private_registry_end_to_end.py`, FAILED identically on
untouched protected main SHA `25c5ecfab1f0df5df413bb0e722c5c5c3747b510`
with `TASK014_EXECUTOR_FAILURE boundary=private phase=credential_pull_budget`.
Its synthetic Zot credential TTL was **120 seconds**, incompatible with the
already enforced original **180-second pull + 45-second safety** threshold.
The test fixture now uses a **270-second** synthetic TTL (inside original
300-second cap). The original policy, pull budget, execution control and
runtime behavior are unchanged; the actual Linux canary end-to-end test then
passes. No real credential or registry host was read during this regression.

Final focused validation on `truexdevelopment`:

```
python3 -m unittest \
  deployment.tests.test_analytics_promotion_broker \
  deployment.tests.test_analytics_review_composition \
  deployment.tests.test_analytics_execution \
  deployment.tests.test_analytics_signed_release_consumer \
  deployment.tests.test_analytics_signed_source_evidence \
  deployment.tests.test_analytics_signed_source_pin \
  deployment.tests.test_analytics_cross_repo_product_binding \
  deployment.tests.test_release_consumer \
  deployment.tests.test_oci_verifier \
  deployment.tests.test_blob_verifier \
  deployment.tests.test_registry_oidc_credentials \
  deployment.tests.test_executor \
  deployment.tests.test_broker \
  deployment.tests.test_broker_integration \
  deployment.tests.test_private_registry_broker \
  deployment.tests.test_private_registry_end_to_end \
  deployment.tests.test_private_registry_fd \
  deployment.tests.test_private_registry_pull \
  deployment.tests.test_request_scoped_registry_integration \
  deployment.tests.test_analytics_dev_release_review \
  deployment.tests.test_m05_14_analytics_signed_admission \
  deployment.tests.test_m05_14_analytics_compose_envfiles \
  deployment.tests.test_application_source_set \
  deployment.tests.test_executor_composition \
  deployment.tests.test_executor_service_entrypoint \
  deployment.tests.test_rootless_docker_authority -q
```

Result: **366 run, 363 passed, 3 skipped, 0 failures**. The historic
independent `test_execution.NonLiveRegressionTests` protected workflow
SHA256 baseline issue was reproduced on untouched main in an earlier pass;
that test was not silently removed or weakened. This exact 366-case focused
set does not include that known historical hash test.

**Still NO-GO for Analytics installation.** The new broker and private
product transport are NOT registered in the root-controlled installed source
set and use only a synthetic receiver in tests. Original executor cannot
accept Analytics schema v2; no rootless DEV product runtime, PostgreSQL role
separation, signed live GET/Cosign consumer or stop-first-install rollback was
performed. Keep PR draft, no merge or rollout. M04 prior conditional review
covered the previous read-only HEAD only; the new broker/FD change needs the
ONE final independent review after the complete privileged executor and
actual isolated DEV acceptance have been implemented.

## M05-14: Isolated product-specific privileged receiver, real local Unix and rootless Zot adapter

**Security boundary and review:** This continuation changes the privileged
executor/Unix socket and private Docker registry-access implementation. M04's
prior conditional review 5699460077 applied to earlier HEAD
`90d57c4d19ce5f44a16e00ac821dbbe7d584f6ed`; it does **not** approve
this new privilege boundary. All new code remains OUTSIDE installed original
Task014 `DevApplicationSourceSet`; no service or host configuration changed.

### Three COMPLETE modules and two complete test files

- `deployment/analytics_executor.py`: constructor binds the original exact
  `begin_execution`/`finish_execution` replay operations, a product-only
  `preflight_analytics` callback, an explicitly named `deploy_analytics`
  callback, and four root-reviewed installed source/profile SHA values. On
  each request, it independently reparses the canonical signed Analytics
  schema-v2 first-install contract, validates the Linux sealed credential
  for the **exact published 0.15.0 image**, runs the private manifest probe,
  rechecks the original 225-second private pull budget **before executor
  replay**, then calls the exact scoped Analytics deployment operation and
  records original replay finish. The original Task014 `ExecutorResponse`
  schema and hash binding are reused. The token exists only in the original
  request-local FD scope, never in request bytes, logs or persistent files.
- `deployment/analytics_unix_boundary.py`: new explicitly named separate
  `AnalyticsUnixExecutorTransport` and
  `AnalyticsUnixExecutorConnectionHandler` reusing the actual original
  `UnixExecutorTransport` and `UnixExecutorConnectionHandler` **unchanged**
  (secure socket inode/owner and peer checks, strict timing, bounded frames,
  SO_PEERCRED, SCM_RIGHTS, cleanup and canonical response). Dedicated exact
  future socket `/run/omnilyzer/deployment/analytics-executor.sock` may only
  use Analytics request schema-v2 and original sealed credential with explicit
  `product_id="analytics"`. The adapter fails closed if the original
  internal reviewed handler/transport tuple layout changes. Public/default
  canary `send`/`_send_private` are rejected by the Analytics transport and
  its ordinary canary executor remains unable to parse Analytics schema-v2.
- `deployment/analytics_private_registry.py`: new product-only adapter
  `AnalyticsPrivateZotPullAdapter` reuses original rootless Docker socket
  authority, `CommandRunner` method validation, short-lived sealed FD,
  original `manifest inspect` and `pull --quiet` commands, capped 30s/180s
  command timeouts, original private runtime-directory checks, and original
  exclusive volatile Docker `config.json` 0600 under a 0700 temp directory.
  It checks exact root-reviewed schema-v2 source hashes and uses the original
  task-local FD scope; there is no Docker login, permanent auth file, token
  on argv/env, arbitrary registry, canary image, or rootful fallback. It
  invokes no Docker operation during import or constructor execution.
- `deployment/tests/test_analytics_unix_boundary.py`: actual isolated Linux
  AF_UNIX socket + SO_PEERCRED + kernel SCM_RIGHTS FD handoff and original
  on-disk SQLiteReplayGuard through the original JWT-authorized broker and
  new executor. It verifies tampering, wrong peer, canary fallback refusal,
  preflight failure, replay/no-replay, rollback-reference preservation and
  token/FD cleanup. **Original signer and deployment operations mocked**;
  proves control flow, not actual product acceptance.
- `deployment/tests/test_analytics_private_registry.py`: actual kernel
  credential with fake original Docker runner; checks source hash scope,
  original Docker command and rootless socket selection, positive 30s
  manifest + 180s pull with same FD under original executor's context,
  0600 temporary config and cleanup, short TTL and missing socket failures,
  no temporary secrets surviving errors.

### Real install remaining / GO gate

- A **real** root-owned Analytics installation composition, exact source-set
  update and the separate product socket's systemd listener/receiver and
  approved UID mapping are NOT implemented/installed. The product-only
  executor `deploy_analytics` callback remains a separately required
  root-owned runtime operation, not yet an implemented privileged Docker
  Compose rollout/health/rollback engine.
- No true rootless Docker daemon was available in approved DEV host checks;
  synthetic runner+socket tests DO NOT establish successful real OCI manifest,
  image pull, actual UID10001 secret reads or real Next `/readyz`.
- Product-separated PostgreSQL auth and collector DB roles, grants/RLS,
  backup/persistence and first-install stop-only rollback remain the next
  **one** operational acceptance bundle. No new independent review until the
  complete live integration exists; M04's prior review remains valid only
  for the earlier inert source boundary.
- Production remains unchanged; no merge, registry publication, deployment,
  real tokens, DB writes, or public traffic were authorized or attempted.
