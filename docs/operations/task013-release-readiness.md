<!--
File: docs/operations/task013-release-readiness.md
Purpose: Required pre-dispatch GO/HOLD checklist for ChatGPT and the owner before
         every Task013 product release, based on the verified Analytics 0.15.0 run.
Related: AGENTS.md; .github/workflows/platform-release.yml;
         release/registry_absence_preflight.py; release/products/analytics-source.json;
         release/analytics_private_handoff.py;
         docs/operations/m05-analytics-normal-release-procedure-20261029.md;
         docs/operations/m05-task013-private-handoff-20261029.md;
         release/tests/test_workflow_policy.py; Task014 remains separate.
Security: No secrets, token values, private source archives, or registry credentials
          belong in this checklist or its release evidence.
-->

# Task013 release readiness: mandatory ChatGPT checkfile

**Current executable scope:** the existing `product=analytics` Task013 release
path. For the legacy canary or a different SaaS product, review that product's
approved independent contract and use the same readiness categories; **do not
pretend** the Analytics-only OIDC job or source binding qualifies other products.

**Use before every Task013 dispatch, including a release after a successful prior
release.** ChatGPT owns these checks. Never ask the owner to repeat normal
read-only investigations or copy logs between chats. Ask for owner action only
when a required privileged operation or protected approval cannot be completed
with the available authorized tools.

**Two separate decisions:** Sections 0-3 and the presence of the live
preflight job in Section 4 must be **PASS** before **GO_TO_DISPATCH**.
Any **FAIL**, **UNKNOWN**, mismatched source, wrong registry server, unknown
ownership or competing release means **HOLD: DO NOT DISPATCH**. The authenticated
live absence proof cannot exist until GitHub issues a short-lived OIDC token:
the **first** Task013 job then runs this proof **before** the expensive build.
Only its actual PASS permits **GO_TO_BUILD**. No previous run's result may
substitute for the current version and current workload identity.

## 0. Begin with the authoritative source

- [ ] Read current `AGENTS.md`, `SECURITY.md`, and this checkfile on **GitHub
  protected main**. Read current `.github/workflows/platform-release.yml`,
  `release/products/analytics-source.json`, applicable release contract and
  the specific product change. Inspect the current canonical issue/PR.
- [ ] Record the *distinct* identities: product; proposed new SemVer; approved
  product-source Git SHA; protected **platform-main Git SHA**; exact workflow
  file/ref; intended OCI repository; Forgejo package. Never derive approval
  from a chat summary or use a mutable branch/tag as an artifact identity.
- [ ] Confirm the product's actual test/acceptance results and required
  approvals. A successful Task013 is **not** Task014 installation, browser
  acceptance, traffic activation, or PROD approval.

## 1. Source and version contract: fail early

- [ ] The proposed version is a **new strict X.Y.Z** that has not already
  been signed, used, or partially written to either registry. Inspect current
  release runs for `in_progress` attempts and failed attempts that may have
  reached a registry write. Never rerun an occupied or partially published
  immutable version; reconcile exact remote state first.
- [ ] The **private product repository** is the intended one
  (`MichaelTrueX/omnilyzer` for Analytics) and the reviewed commit exists.
  Confirm required product CI, source manifest, critical-file hashes, Docker
  runtime profile and source-to-OCI binding for that exact commit.
- [ ] **Known current blocker for the next changed Analytics commit:**
  `release/products/analytics-source.json`, the release build candidate and
  two workflow checkouts still pin PR52 SHA
  `4cdda7faeba57abb3388f9be5c450fe6afb1140d`. Until a separate reviewed
  dynamic-source admission implementation is merged, a different Analytics
  source SHA is **HOLD**, even if the version is new. Do not silently repin
  or relax critical-file checks as a workaround. Source commit approval and
  platform workflow SHA must never be confused.
- [ ] Protected platform `main` has the exact reviewed workflow and all
  required repository checks passed. The Task013 dispatch input named
  `source_sha` is the **platform-main SHA**, not the Analytics source SHA.

## 2. Credentials and private-data boundary

- [ ] GitHub repository `MichaelTrueX/omnilyzer-platform` is **public** and
  Analytics source `MichaelTrueX/omnilyzer` is **private**. Both private
  checkouts use `ANALYTICS_SOURCE_DEPLOY_KEY`, whose deploy key is registered
  **only on the private source repository, read-only**, not a broad PAT.
  Check GitHub secret existence/last update and deploy-key metadata, **never
  read or print the private key**. A present secret name is not proof of
  usable access: the existing checkout must still authenticate in Task013.
- [ ] Protected `task013-dev-release` environment contains
  `ANALYTICS_HANDOFF_DECRYPT_KEY`. Confirm the checked-in public GPG
  recipient `release/analytics_handoff_recipient.asc` is not expired or
  revoked, and matches `release/analytics_private_handoff.py` fingerprint.
  Rotate scoped keys together when needed; never commit the private key.
- [ ] The source job has **no** signing, registry write or private
  decryption authority. Private source TAR and OCI blobs are encrypted
  **before** `actions/upload-artifact`. Only the ciphertext
  `analytics-task013-transport.gpg` crosses the public GitHub artifact
  boundary. Both protected publishers decrypt inside their own jobs and
  reverify source/OCI identity. Preserve the repository's existing
  `release.tests.test_workflow_policy` confidentiality checks.
- [ ] The existing `platform-release.yml` identity, protected environment,
  short-lived audience-specific OIDC, pinned runtime and action SHAs remain
  intact. Do not introduce cookies, personal access tokens, hardcoded
  credentials, mutable image tags, insecure fallback or new public endpoints.

## 3. Real infrastructure: check the endpoint, not the server nickname

- [ ] Resolve `oci-dev.omnilyzer.ai` and
  `registry-dev.omnilyzer.ai` **fresh**. Identify the actual host serving
  each endpoint from the resolved address and authorized inventory; verify
  that the Zot/Forgejo service is active **on that host**. Do **not** assume
  `truexdevelopment` is the live Zot server because of the `-dev` hostname.
  On 2026-10-29, Zot was served by `truexmainserver`, NOT
  `truexdevelopment`; those IPs may change. Never pin an old IP as authority.
- [ ] For a newly configured repository, DNS/host change, Zot policy change,
  previous HTTP 403, or missing prior verification, inspect the **live Zot
  host's** `/etc/zot/config.json` read-only (privileged inspection only
  if authorized). For `omnilyzer/analytics`, only the exact protected
  `platform-release.yml@refs/heads/main` principal may have `read/create`.
  `**` must default-deny; no anonymous policy; do not grant `update` or
  `delete`. Preserve independent canary publisher and
  `platform-promote.yml` read-only consumer rules unchanged.
- [ ] Verify server certificate, HTTPS origin, original OIDC audiences,
  service uptime, registry/release artifact capacity and reachability.
  An unauthenticated `401` alone does **not** prove an OIDC identity can
  read or write the Analytics repository. A `403` on the exact manifest
  is an authorization **HOLD**, not a missing version.
- [ ] **Never restart Zot or edit registry ACL based on the wrong host.**
  On a server that also serves production, any privileged registry change
  requires explicit authority, a narrow exact-delta backup, config validation,
  maintenance impact assessment, verified restart and rollback. A routine
  product release should require **no** infrastructure mutation.

## 4. Automatic no-write gate before the expensive build

- [ ] The current Task013 workflow includes
  `analytics-registry-preflight` **before**
  `analytics-source-admission`, and runs the existing
  `release.registry_absence_preflight` with exact short-lived OIDC tokens
  against **both** actual remote registries. A missing job or failed job is
  **HOLD**; do not skip it just because the previous release succeeded.
- [ ] Forgejo's authenticated package check and Zot's authenticated
  `/v2/` plus exact `HEAD /v2/omnilyzer/analytics/manifests/VERSION`
  must prove the proposed version absent. **Only verified HTTP 404 after
  authentication is absence**. Any 401, 403, 5xx, redirect, timeout,
  inconsistent read, occupied tag/package or unknown result is **HOLD**.
  The existing publisher must repeat authenticated absence checks
  immediately **before** any registry write (race and immutability safety).
- [ ] Failures in this early registry gate stop the expensive BuildKit/Grype
  work. Do not weaken the registry's authorization to make a check pass.

## 5. GO / HOLD handoff, dispatch and postrelease evidence

Before dispatch, ChatGPT records **one concise decision** in the canonical
feature/release issue, without publishing secrets. Use these fields:

`Product | Version | Product SHA | Platform main SHA | GitHub workflow |
credentials metadata | private artifact encryption | resolved actual Zot
host and ACL | registry preflight design | pending/active/partial versions |
required product test status | release approval | GO or HOLD + blockers`.

- [ ] **GO_TO_DISPATCH only** with Sections 0-3 and the Section 4 workflow
  design verified on protected main. If an optional fresh privileged ACL
  inspection is not needed, cite current unchanged actual-host evidence.
  If registry state cannot be trusted, choose HOLD. Never treat the proposed
  early OIDC check as already completed before it runs.
- [ ] Dispatch **once** from protected `main`:
  `product=analytics`, `version=<fresh-X.Y.Z>`,
  `source_sha=<exact-platform-main-SHA>`, `auth_probe=false`.
  Never dispatch on behalf of an owner without release authorization.
- [ ] Watch all four actual Analytics jobs:
  `analytics-registry-preflight`, `analytics-source-admission`,
  `analytics-publish-zot`, `analytics-publish-forgejo`.
  `analytics-registry-preflight` must be PASS before the build begins.
  Legacy canary jobs being skipped in Analytics mode is expected.
- [ ] At completion require **real** source binding, pinned OCI BuildKit,
  current Syft/Grype SBOM and **0 Critical / 0 High with no waivers**,
  GPG ciphertext transport, authenticated Zot exact tag/digest readback,
  Cosign manifest/provenance/OCI signature validation, and Forgejo evidence
  publish/readback. Record final exact OCI `sha256:...`, workflow run ID,
  source SHA and registry receipts.
- [ ] Only now mark **Task013 SUCCESS**. An image in Zot without verified
  Forgejo signature/evidence is **PARTIAL, NOT SUCCESS**. Never replay a
  partially published version. Task014 installation, health checks, rollback
  and production promotion are **separate approvals and evidence**.

**Acceptance precedent (not permission to reuse):** Analytics `0.15.0`,
Task013 successful run
[40881693662](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/40881693662),
immutable digest
`sha256:6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1`.
This version is occupied and MUST NOT be released again.

**No additional frameworks, per-release platform PRs or manual vulnerability
spreadsheets.** The one-time dynamic Analytics source-binding gap above
remains separately outstanding until an accepted implementation proves an
ordinary changed-product-code release without repinning Task013 itself.
