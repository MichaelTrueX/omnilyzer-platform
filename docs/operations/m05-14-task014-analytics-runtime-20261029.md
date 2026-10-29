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
- `omnilyzerdev` (initial 2026-10-29 unprivileged check): the Task014
  executor bind-mount target rootless socket was absent outside its systemd
  namespace and ordinary `omnigpt` could not open Docker. **Superseded by the
  verified 2026-10-30 host preflight below**: the actual, original rootless
  Docker service and source socket are running under protected UID991; no
  new rootless daemon or installation is required.

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

## M05-14: signed 0.15.0 first-install rootless Compose/health/rollback (2026-10-30)

**Complete source:** `deployment/analytics_first_install.py` and
`deployment/tests/test_analytics_first_install.py`. The original protected
Task014 canary Docker runtime, Compose file, deployment controller, broker,
executor, executor_server, Unix transport and installed source set remain
byte-unchanged. The new component is STILL OUTSIDE the installed source set;
this is not a live Task014 deployment or an activation grant.

### Closed first-install phase sequence

When explicitly composed behind the original verified OIDC + signed evidence,
sealed Zot FD, durable replay and root-owned source manifest, the new
`AnalyticsFirstInstallOperation.deploy_analytics`:

1. Requires EXACT pinned source/profile/Compose hashes, signed Analytics 0.15.0
   image, initial blue/127.0.0.1:3141/no-public-ingress/no-prior-slot,
   original rootless socket and the **existing four private secret names**.
   Checks the reviewed Compose bytes and refuses symlinks or source drift.
   Calls existing `review_private_secret_paths` for four 0600, non-symlink,
   nonempty files owned by mapped host UID/GID **503216** (container UID10001).
   The private host source directory must be **root:991 mode0710**, so the
   rootless UID991 Docker daemon can traverse source paths through its group,
   but cannot replace or read file contents. It cannot be writable by UID991
   or UID503216. **No real secret contents are opened or logged.**
2. Verifies the already provisioned, separate external Docker backend network
   name `omnilyzer-analytics-backend-dev` and actual Compose parser with the
   exact immutable image references. Denies first install if an Analytics-blue
   container already exists, including one merely stopped. Does NOT create
   network, initialize DB or modify any canary Docker project.
3. Calls the already implemented private immutable Zot pull with the broker-
   provided sealed short-lived FD, original 30s manifest + 180s pull bounds,
   then requires actual local Docker `RepoDigests == [pinned-0.15.0-image]`.
4. Executes ONLY `docker compose --project-name omnilyzer-analytics-dev
   --file <reviewed-YAML> --profile blue up --detach --no-deps
   --force-recreate --no-build --pull never analytics-blue`. The green profile
   remains inactive; the environment contains only fixed immutable image
   references, PATH and LANG. No token, URL, DB password or JWT value is an
   argv/environment parameter.
5. Verifies the actual started image, UID10001, read-only root filesystem,
   privileged=false, all capabilities dropped, no-new-privileges, exact
   127.0.0.1:3141 port bind and sole separate backend network. Checks bounded
   Docker health status and makes a **private in-container 127.0.0.1:3000
   GET /readyz** (not an Nginx/public endpoint), demanding HTTP success.
6. On every failure that could follow a partial container start, invokes
   **only `docker compose stop --timeout 15 analytics-blue`** and confirms no
   running slot. Never `down`, `rm`, `prune`, delete PG writes, volumes,
   networks or images, or roll back to a nonexistent prior signed release.
   Rollback errors are reported as `rollback=unconfirmed`; no positive result
   is returned. The modified Analytics executor also captures the operation's
   exact `rollback_first_analytics` method: if the newly healthy container
   exists but original durable `replay.finish_execution` fails, it stops that
   same slot before returning failure. Request-bound in-memory nonsecret SHA
   prevents unrelated requests from stopping this slot.

### Real parser and Node envfile proof (no Docker daemon writes)

On `truexdevelopment` 2026-10-30:

- Installed Docker Compose **v5.5.0** `--profile blue config --quiet` with
  both immutable OCI digest image variables: **PASS**, no daemon/container
  operation and no host or registry mutation.
- Installed Node **v22.23.3** with exactly FOUR disposable 0600
  `NAME=SYNTHETIC_VALUE` env-file secrets: **PASS 4/4**. Omitting
  `JWT_SECRET` caused the expected failing exit status **91**.
- The existing optional disposable Docker/UID10001 integration test remains
  a separate opt-in (`M05_REAL_ANALYTICS_COMPOSE_TEST=1`) and is NOT real
  rootless host acceptance. No real Analytics secret or personal user data
  was read; the test did not start an application container.

### Still NO-GO for installing on a real host

These checks do not prove the original installed Task014 broker/executor source
selection, actual rootless UID mapping/Compose file-secret bind reads, active
Zot/Forgejo promoter ACL + real signed consumer, private PostgreSQL auth and
collector roles/RLS or a durable installed first-install state/audit/rollback.
The unprivileged DEV session can neither open the private UID991 Docker
source socket nor see the four Analytics secret files. The original rootless
service is now independently observed running (see below); an isolated
privileged Task014 service context still has to prove source socket
bind-mount and real mapped-file reads. Actual Analytics `/readyz`, persisted
PostgreSQL data and rollback are **not demonstrated**. M04's last security
review was on older PR HEAD; a complete changed privileged boundary still
requires one independent final review and explicit owner approval for live
host promotion. No merge, systemd, Docker write, PG change, or public traffic
activation is performed by this coding delivery.


### 2026-10-30 corrective host preflight and root-controlled secret traversal

**Read-only host evidence** from the isolated `omnigpt@omnilyzerdev` user,
without sudo, registry credentials, systemd mutations or Docker changes:

| Original Task014 component | Observed host fact | Interpretation |
|---|---|---|
| Rootless Docker user manager | `user@991.service` active since 2026-10-15 | Rootless engine already exists |
| Rootless Docker process | UID991 `rootlesskit`, `slirp4netns`, `dockerd` active | Do NOT install another daemon |
| Real source socket | `/run/user/991/docker.sock` LISTEN in kernel | Protected UID991 path, not readable by `omnigpt` |
| Executor bind-mount target | `/run/omnilyzer/deployment/rootless-docker/docker.sock` absent outside service | Expected: systemd `BindReadOnlyPaths` creates mount in executor service namespace when activated; not proof of daemon failure |
| Original broker | `omnilyzer-deployment-broker.service` active | Existing broker is running, canary-only |
| Executor | `.socket` active at `/run/omnilyzer/deployment/executor.sock`, service inactive | Normal socket activation; do not wake privileged executor during read-only review |
| Canary at `127.0.0.1:3020` | Nginx returns HTTP 503 body `{"status":"maintenance","active_slot":null}` | Controlled maintenance with no promoted canary slot, not a crashed daemon |
| Analytics 3141/3142 | No listeners | Analytics is NOT installed |
| Analytics four secret files | `/var/lib/omnilyzer/deployment/analytics/dev/secrets` absent | Real host provisioning still required |
| Analytics PG16 | A separate legacy unprivileged PG process exists under user `trust` | NOT approved Task014 product DB; do not reuse its credentials/data without independent identity/role qualification |

**Important security correction discovered during this live-host review:**
Original `review_private_secret_paths` required the private *directory* and
four *files* all be owned by mapped host UID503216 with directory mode0700.
This would deny UID991 Docker daemon traversal of bind-mount source paths.
Simply changing directory ownership to UID991 would let the daemon replace
secret source files; that is unnecessary and weakens source integrity.

For the Analytics rootless staging source only, the reviewed contract now
requires the directory **root:991, mode0710**, with the exact four regular
files **503216:503216, mode0600**, no symlinks and bounded sizes. The root
keeps exclusive ability to create/replace entries; the daemon obtains only
execute/traverse permission via its own group, not list or write. Existing
review-only callers of `review_private_secret_paths` retain their default
0700 same-owner behavior. This is a metadata gate, not a substitute for
**real positive+negative container UID10001 secret-read tests** under the
approved Task014 rootless daemon before a real deployment.

**Activation remains HOLD:** no owner-approved root host mutation or M04 final
privileged-source review has been performed. Existing rootless service is an
asset to reuse, not a missing installation step. The remaining concrete
requirements are product-specific source-set/entrypoint admission, verified
Zot/Forgejo promoter reader ACL and genuine Sigstore/Cosign, the four approved
secret sources under the mapped UID, PostgreSQL nonowner app/collector roles
and RLS with actual DB access, real private blue health, durable state and
stop-only rollback. Do not promote 0.15.0 through unapproved generic Docker
commands or any canary route.

### M05-14 final corrective verification, 2026-10-30

After the actual `user@991.service` rootless host inspection, the review-only
secret source metadata checks were corrected for **root:991 mode0710 private
source directory** and exact **503216:503216 mode0600** four regular secret
files. The root-owned directory avoids granting the rootless Docker daemon
permission to create, remove, swap or list source entries. The daemon's
UID991/GID991 has traverse-only access; the mapped container UID10001 can
read only its four file sources. Earlier inert same-owner mode0700 callers
retain their unchanged default contract. The actual rootless Compose
positive/negative secret mount check remains REQUIRED before installation.

- Complete source files: `deployment/analytics_dev_release_review.py`,
  `deployment/analytics_first_install.py` (existing first-install code),
  `deployment/tests/test_analytics_dev_release_review.py`,
  `deployment/tests/test_analytics_first_install.py`.
- Synthetic stat-UID/GID tests simulate root:991 directory and mapped file
  owner; explicitly reject daemon-owned directories, wrong group, world/group
  access, wrong mode, missing files, symlinks, or relaxed file modes.
  No privileged `chown`, Docker, genuine JWT, database or filesystem secret
  content is accessed in these tests.
- Broad relevant Task014/Analytics regression: **604 tests, 601 PASS,
  3 expected SKIP, 0 FAIL**, including existing canary broker/executor,
  rootless authority, original OIDC/JWT/Cosign boundaries, Analytics Unix
  receiver and blue/rollback safety controls.
- **NO-GO remains** for active Analytics DEV installation: installed source
  admission, approved signed Zot/Forgejo reader ACL, real UID10001 rootless
  secret-read + deny proof, actual PostgreSQL nonowner role/RLS separation,
  actual OCI runtime `/readyz`, state/rollback and final independent M04
  review are all still unconfirmed. A running UID991 Docker daemon and
  green unit tests do not supersede the owner's installation approval.


## M05-14: original socket identity and complete inert executor composition (2026-10-30)

**New complete file** `deployment/analytics_executor_composition.py` constructs
one product-only receiver using the SAME original privileged Task014 primitives:
`SQLiteReplayGuard(PRODUCTION_REPLAY_DATABASE)`,
`SubprocessCommandRunner`, `AnalyticsPrivateZotPullAdapter`,
`AnalyticsFirstInstallOperation`, `AnalyticsPrivilegedExecutor`,
`AnalyticsUnixExecutorConnectionHandler`, and
`AnalyticsUnixExecutorListener`. This is a single explicit product-specific
graph, not a configurable deployment framework. It uses one common original
replay store with canary rather than silently creating a second JTI ledger.

**Modified complete file** `deployment/analytics_unix_boundary.py` adds the
Analytics-specific `AnalyticsUnixExecutorListener` subclass of the original
`UnixExecutorListener`, bound to exactly
`/run/omnilyzer/deployment/analytics-executor.sock`. It reuses the original
inode/procfs socket binding check, socket owner/group, one-accept deadline,
transport close semantics, peer authentication, SCM_RIGHTS and original replay.
It verifies the original listener's exact reviewed configuration shape before
selecting the separate socket; no canary listener code or canary socket path
is changed.

**New complete test** `deployment/tests/test_analytics_executor_composition.py`
verifies all actual original classes are captured without any Docker, secret,
registry, SQLite connect, listener bind or socket accept during construction;
validates the shared replay DB and a separate fixed socket; rejects invalid
source profiles and dynamic nonlistener dependencies. The modified complete
`deployment/tests/test_analytics_unix_boundary.py` exercises a real
disposable local AF_UNIX socket with the **original listener's** procfs inode
validation through the original handler, actual Linux sealed FD transfer, and
the original schema-v2 Analytics executor; no live application is installed.
The existing `deployment/tests/test_analytics_review_composition.py` asserts
both new source files remain OUT of original Task014 installed canary source
allowlist. Canonical README/AGENTS and canary source files remain unchanged.

**Required activation step:** the root-owned Task014 source/manifest installer
must first attest every new Analytics source file, exact protected release SHA
and product/runtime profiles; a dedicated pre-authorized systemd listener must
then supply the exact named Unix FD with correct UID/GID; and the original
OIDC broker, real Sigstore/Cosign, signed Zot/Forgejo reader access and
rootless runtime must be composed under an approved host configuration.
The public `reviewed_installed_source` dict accepted by this inert class is
NOT root authority, and the class is **not installed or started** by this PR.
No new endpoint is exposed, and the existing canary socket, broker and
executor code have no changes.

**Status remains HARD NO-GO:** service activation is not demonstrated or
authorized; real rootless secrets, PostgreSQL restricted app/collector role
isolation, private health and rollback must be verified by a single final
privileged DEV acceptance followed by M04 approval and owner authorization.

## M05-14: root-controlled Analytics executor service bootstrap (2026-10-30)

**Same delivery PR #258.** This increment introduces exactly one product-only,
fail-closed Task014 Analytics bootstrap. It does NOT install or enable a systemd
unit or start a Docker container. There is no generic routing framework and
no change to the original installed canary or its reserved socket.

### Complete files

- `deployment/analytics_executor_service_config.py`: read the ORIGINAL
  hardening-validated Task014 C17 `executor.json` first, in the original
  executor UID/GID and group context. Read only the second fixed, root-owned
  `/etc/omnilyzer/deployment/dev/analytics-executor.json` via original
  descriptor-relative and O_NOFOLLOW directory checks; require root:executor
  group, mode0640, one link, bounded canonical duplicate-free JSON, matching
  original installed platform commit, and exact product=Analytics/stage=DEV.
  Check real root-owned installed app source bytes through fd-relative reads
  and SHA256 for 14 named Python modules. Check the exact Docker Compose bytes
  and the two product/runtime profile **canonical parsed profile hashes**;
  these differ from simple file SHA256, and match the signed release's pinned
  profile hashes. Reject symlinks, wrong modes, non-root ownership, extra
  source entries, file drift, malformed metadata and arbitrary paths.
  Construct only four reviewed root-controlled source hashes and original
  C13 numeric identities; never accept them from a promotion HTTP request.
- `deployment/analytics_executor_service_bootstrap.py`: require the above
  verified installed source BEFORE consuming any systemd activation FD.
  Require exactly one FD3, the exact `omnilyzer-analytics-executor` name,
  proper LISTEN_PID/PIDFDID, and original UID/GID; instantiate only
  `AnalyticsExecutorComposition` and run one original secured accept, then
  close the FD on both success/failure. No canary socket/name fallback.
- `deployment/analytics_executor_service_entrypoint.py`: explicit, closed
  exit-status entrypoint. Import has no infrastructure side effect.
- `deployment/systemd/dev/omnilyzer-deployment-analytics-executor.socket`:
  inert reserved original-style systemd socket unit, exact fixed separate
  `/run/omnilyzer/deployment/analytics-executor.sock`,
  `omnilyzer-executor:omnilyzer-deployment` 0660, one named FD, Accept=no.
- `deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service`:
  inert separate, uninstalled original UID991 systemd unit with original
  restricted account, original rootless user socket's protected bind mount,
  private writable volatile auth dir, no privileges/capabilities, strict
  filesystem, exact Python module and fail-closed root config condition.
  Neither unit is enabled in this branch.
- `deployment/tests/test_analytics_executor_service_bootstrap.py`: complete
  root-owned source schema/duplicates/strict paths, simulated real
  descriptor-backed byte/inode/mode/symlink/changed-hash checks, original
  C17 load failure before FD use, reserved systemd named-FD/PID denial,
  one-shot FD close on success/failure, and inert systemd checks.
- `deployment/tests/test_analytics_review_composition.py`: prove all new
  Analytics modules/unit paths remain OUTSIDE the original canary source set.
  This documentation file is also complete.

### Product-first admission and installation acceptance, still HOLD

The root-owned JSON file is **not committed with deployment-specific hashes
or any real credentials**. When the approved immutable platform commit is
installed by the existing Task014 root-owned installer, it must produce the
*exact* 14 Git-object SHA256 values in `source_sha256` and reviewed Compose
SHA256 and canonical product/runtime profile hashes. Its
`reviewed_installed_commit` must match original hardened C17
`executor.json` for that installation, not a mutable branch or the current
conversation's suggested hash. The source pin is installation authority ONLY
when the independent root-controlled file and installed source file checks
pass; the original broker still independently checks OIDC, true Sigstore/
Cosign/Forgejo/Zot signatures, 0.15.0 source and digest, audience/replay/FD.
The separate systemd socket and service must be installed and enabled only by
a subsequently approved root-owned Task014 host operation. They are
intentionally uninstalled, disabled and absent on the current DEV host.

`systemd-analyze verify` read the source unit files without installing them.
It returned only the expected uninstalled-venv warning that
`/opt/omnilyzer/deployment/venv/bin/python` is not accessible from the
current development sandbox; the initial unit-section placement warning was
corrected. This is NOT installed-host systemd verification. Original canary
units and rootless daemon configurations remain byte-identical to main.

**Validation:** 691 relevant original Task014 and Analytics tests ran,
**688 PASS, 3 expected SKIP, 0 FAIL**, including the new descriptor-backed
tamper/ownership test. No privileged socket or real Docker was touched.
Actual final approval must still demonstrate the root-controlled installed
manifest/units, approved UID10001 four source secrets mounted with positive
and negative file-access checks, two restricted PostgreSQL app/collector roles
and RLS, genuine signed release registry and original OIDC broker, actual
private blue /readyz, first-install stop-only rollback and one bounded M04
security review. NO-GO for live DEV install, merge and production remains.

## M05-14: one existing Task014 broker HTTP endpoint, root-owned Analytics opt-in

**The first, rejected approach would have added Analytics imports into the
ORIGINAL installed canary broker bootstrap. Original C32V's protected
source-import-closure regression rejected 53 imports instead of the approved
40. That approach was REMOVED, not whitelisted or hidden behind a dynamic
import.** Original `deployment/broker_service_bootstrap.py`, original
`deployment/broker_service_entrypoint.py`, original 3031 HTTP ingress, original
Nginx and the original installed `DevApplicationSourceSet` are unchanged.

### Complete source files

- `deployment/analytics_broker_router.py`: a closed *product-only* router
  behind the EXISTING /task014/dev/promote HTTP/1.0 endpoint. Its unchanged
  ingress validates Host, Authorization Bearer, two separate registry OIDC
  headers, Content-Type, exact Content-Length, duplicates and no cookies.
  Original canary schema-v1 requests enter the existing original broker;
  ONLY canonical, fully parsed schema-v2 product_id=analytics and exact signed
  0.15.0 request shape enters Analytics. Unknown product, mixed schemas,
  duplicated JSON, wrong digest, noncanonical bytes and extra authority are
  rejected BEFORE any registry/signature or replay. A true signer outage
  retains original HTTP503; malformed claims retain 403.
- `deployment/analytics_broker_service.py`: reuses the original C32H
  broker's fixed root-owned `/etc/omnilyzer/deployment/broker` directory
  and protected UID/GID, 0640 file and descriptor-relative source reader.
  The single, separately root-provisioned **analytics.json** configuration
  uses the same closed source schema as the executor's **analytics-executor.json**
  but matches the EXISTING original broker installation's reviewed Git SHA.
  Exact product Python source digests, Compose SHA256 and canonical signed
  product/runtime profile hashes are checked through O_NOFOLLOW, inode/mode
  and root ownership controls. The root-controlled source config cannot be
  supplied through HTTP, a review receipt, an unsigned mapping or a remote
  token. A missing product config may mean canary-only under the unchanged
  ORIGINAL broker; when the **explicit opt-in replacement service** runs,
  missing or malformed config is a hard failure (NEVER auto-downgrade).
  The approved replacement reuses the existing C32H broker config,
  GitHubJWKSCache, GitHubOIDCVerifier, original Sqlite replay, original Cosign
  signature verifier, original registry readers, original canary handler and
  original DevBrokerLoopbackListener on the SAME 127.0.0.1:3031 port.
- `deployment/analytics_broker_service_entrypoint.py`: closed opt-in
  service entrypoint with the original SIGTERM/SIGINT stop behavior, fixed
  exit status and restored signal handlers. No auto-start on import.
- `deployment/systemd/dev/analytics-broker-enabled.conf`: **inert,
  uninstalled root-owned systemd drop-in** for the existing original
  `omnilyzer-deployment-broker.service` (not a new service):
  `ConditionPathExists=/etc/omnilyzer/deployment/broker/analytics.json`
  and a fixed `ExecStart` override to the Analytics-aware entrypoint.
  Installation destination ONLY after owner/M04 approval:
  `/etc/systemd/system/omnilyzer-deployment-broker.service.d/analytics-enabled.conf`.
  Without this drop-in the existing canary process and port remain untouched.
  Removing the separately approved drop-in and restarting the original broker
  is the broker-only rollback; never delete shared replay/DB data.
- `deployment/tests/test_analytics_broker_router.py`: true disposable
  Linux TCP 127.0.0.1 HTTP/1.0 request through the ACTUAL original
  `DevBrokerLoopbackListener`, signed-shaped schema-v2 broker and real
  sealed memfd. Test uses only synthetic signer and receiving executor.
  Additional tests verify canary controls, no cross-product routing,
  rejection of credential/header injection and 403/503 behavior.
- `deployment/tests/test_analytics_broker_service.py`: actual original
  broker classes compose with a shared replay, JWT/JWKS, Cosign and exact
  product transport without service startup; synthetic root-owned descriptor
  metadata tests enforce owner/group/commit/permissions, absent/mismatched
  configs and no fallback. Tests verify opt-in service cannot run without
  validated root-owned source; no second network listener exists.
- `deployment/analytics_executor_service_config.py`: the exact separate
  root-owned source allowlist now contains the new broker modules as well as
  original Analytics-only executor source. It does NOT modify the protected
  C32V canary source selection. Both product bootstrap configurations must
  bind all these files and canonical signed profiles.
- `deployment/tests/test_analytics_review_composition.py` protects the
  new broker files against accidental entry into the original canary source
  selection.

### Release/operational state (NO-GO for installation)

The original Task013 signed Analytics v0.15.0 release is immutable, not
reissued, and still the exact OCI digest. Original Task014 broker remains on
the original canary-only service entrypoint unless a separate root-owned
systemd drop-in is installed and enabled by the approved original host
release workflow. The active rootless daemon, existing broker and canary are
NOT touched by this code change.

The remaining single DEV acceptance must prove actual original GitHub OIDC
JWTs with three separate audiences, live original Zot/Forgejo archive and
Sigstore/Cosign, root-owned signed-source file admission and service drop-in,
real rootless container UID10001 access to four genuine secret files, PG
nonowner analytics app/collector roles + RLS, private /readyz and first
blue stop-only rollback with database writes preserved. A standalone PR,
local actual HTTP test or synthetic security test does not grant that live
authority. One independent final M04 review is needed of the NEW broker
root-owned trust boundary before approved installation. No merge, service
enablement, registry write, real credential or production change here.

### 2026-10-30 — Exact installed Analytics source closure completed

This final targeted security audit found that the review-only Analytics
privileged-service source manifest had not listed every statically imported
product module. The protected original canary source selection had correctly
remained unchanged, but the separate Analytics root-owned source-admission
list was incomplete. The explicit fixed list now includes **20 unique
Analytics-only Python modules**, with no duplicates and no overlap with
the original **40** Python canary modules. The existing 3 canary runtime-data
files are separate and remain untouched. The two Analytics service entrypoints
plus `deployment/__init__.py` resolve to the exact declared original-source
union plus 20 Analytics-only modules using the original Task014 AST static
import resolver; dynamic imports are denied. A new test
`test_privileged_analytics_import_closure_exactly_attested` fails closed on
future added transitive imports, missing hashes, duplicate source names,
unreviewed imports or changed source selection, without installing anything.

A read-only candidate of the complete review schema from this isolated
checkout shows **20 source hashes and 2,668 canonical JSON bytes**, below
the existing 4,096-byte root-owned config limit. This is only a syntax and
source-coverage verification. Such a candidate is **not** an installer, a
signed source manifest or a privileged authorization; the original Task014
root-controlled installed manifest must independently attest the exact Git
source bytes and approved target installation SHA. No new canary source
imports or unprivileged host changes have been made.

Parallel validation after correcting the source contract: Analytics focused
**140 tests, 137 PASS and 3 expected SKIP**; original canary/Task014 focused
**592 PASS**, 0 failures. The source closure, source-configuration parser and
real protected host status were verified separately. The original active
rootless daemon UID991 and the existing Task014 broker/executor socket were
observed read-only; neither the two Analytics root-owned service configs nor
four Analytics secret source files are available, and ports 3141/3142 have
no listener. Exact root-controlled activation, signed registry identity,
separate restricted PostgreSQL roles/RLS, real private readiness and stop
rollback remain explicit conditions for DEV installation. **NO-GO unchanged.**

### 2026-10-30 — Fixed mutually exclusive secret-directory GID policy

A full source-and-host preflight independently reproduced a real **P0 first
installation blocker**: the preceding Analytics first-install preflight
required the secret source directory to be root:GID991 mode0710, but the
following legacy `_require_mapped_secret_groups` helper also required this
**same directory** to be GID503216. No host permissions could satisfy both.
The owning helper now validates ONLY the four actual file GIDs against the
mapped container UID10001/GID503216. The previously reviewed metadata guard
still requires **directory root:991 mode0710** and four exact **regular files
UID503216:GID503216 mode0600**. Any wrong file group remains hard NO-GO.
No secret content is read by this preflight.

The complete first-install pipeline was exercised with disposable one-byte
file inodes and projected rootless UID/GID metadata (real application code,
real metadata guard, real mapped GID guard, synthetic Docker runner).
Correct directory GID991 and four mapped source file GIDs503216 reach the
private blue health/proof stage; changing one file group fails **before any
Docker command**. The original rollback, replay, original Unix transport and
signed-source constraints are unchanged. This is not a privileged host test.

Independent read-only DEV host inspection confirms **40 original Python
modules** under `/opt/omnilyzer/deployment/app/deployment`, and **none of the
20 Analytics-only modules are installed**. Therefore the presently installed
original Task014 application manifest and original installer do NOT themselves
supply Analytics files. The explicit M05-14 root-owned source admission code
will reject missing modules; a newly approved original Task014 installation
handoff must first provision the exact 20 Analytics modules plus three
product/runtime/Compose data files and two protected product configs without
weakening the original canary source closure or losing rollback capability.
Merely enabling the proposed systemd drop-in cannot succeed and is forbidden.

Two parallel regression groups after this fix: **142 Analytics tests (139 PASS,
3 expected SKIP, zero failures)** and **177 original core Task014 tests PASS**.
DEV broker and executor socket remain active, original canary maintenance
port returns HTTP503 (no active canary slot), Analytics port3141 still has
no listener. This remains **NO-GO for real installation, merger or promotion**.

### 2026-10-30 — Additive Git-object source handoff and mandatory signed claim

The live-path audit found an additional **actual P0 source-install blocker**:
`analytics_signed_source_pin.review_signed_analytics_source()` reads the
installed `release/products/analytics-source.json` file for every real signed
0.15.0 review, yet neither existing root-owned Analytics source admission
checked nor the proposed installer supplied that exact file. Installing the
20 modules and the three original Compose/product/runtime assets would
therefore still produce a hard denial when checking the actual signed release.

Both `deployment/analytics_executor_service_config.py` and
`deployment/analytics_broker_service.py` now require **four** exact additive
runtime/source assets. The fourth is the signed-source claim at
`release/products/analytics-source.json`, SHA256
`45e13536c413a5e5c0a39a4d8c98daf412614dec535398b2ba204039772c88b9`.
This hard-coded digest is the checked original Git-object file identity; a
root-owned source must match it byte-for-byte before accessing OIDC/registry,
inherited systemd socket or starting rootless Docker. Updated fd-relative
tests exercise the actual claim-file bytes and reject tampering or deletion,
including if the other three profiles and 20 Python hashes match. The
original canary source set remains unchanged.

**New complete, review-only handoff:**
`deployment/analytics_source_handoff.py` plus
`deployment/tests/test_analytics_source_handoff.py`.
The handoff reuses ORIGINAL Task014 C26's bounded, hook-free, no-network Git
object reader. It requires a reviewed immutable repository HEAD and
constructs one canonical additive **27-file** inventory:
**20 required Python modules + 4 exact data/source assets + 3 proposed
inert systemd assets**. All files must be regular Git mode100644, bounded
and checked against raw blob hashes; both product profile hashes match the
original signed Analytics source policy. It produces a small unsigned JSON
review inventory (no secrets, no deploy privileges) without inspecting any
mutable working-tree contents or making a host write. Wrong SHA, other root,
modified Git object bytes or missing signed-source claim are rejected. This
is tangible input to the **existing** protected root-owned Task014 host
installer and separate M04 security review, **not** an installer/approval
by itself. No generic new framework or canary source-policy widening.

**Actual DEV:** The authorized original application still has 40 root-owned
Python modules; none of the 20 Analytics-only modules, the four required
extra source assets, two protected product configurations or proposed
systemd units has been installed. A future Task014 root-controlled additive
source operation must preserve and reverify the existing 40-module canary,
install the exact reviewed 27-file Git blob inventory and two protected
configuration files, and safely roll back newly created files if any
verification fails. It requires owner permission and M04 review. Product
activation, real OCI read, UID10001 secret mount, PG role/RLS, /readyz and
stop-only rollback remain **NO-GO** pending the same one approved DEV gate.
