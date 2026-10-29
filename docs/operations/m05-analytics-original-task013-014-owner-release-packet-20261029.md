<!--
FILE: docs/operations/m05-analytics-original-task013-014-owner-release-packet-20261029.md
PURPOSE: Single controlled owner-facing DEV then production deployment sequence
         for Analytics using ORIGINAL Omnilyzer Task013/014, not an extra stack.
LINKS: deployment/analytics_dev_release_review.py,
       deployment/runtime/dev/analytics.compose.review.yaml,
       deployment/products/analytics-dev.json,
       deployment/products/analytics-runtime-dev.json,
       deployment/promotion.py, deployment/release_consumer.py,
       deployment/analytics_signed_source_pin.py,
       deployment/broker.py, deployment/executor.py,
       deployment/docker_runtime.py, deployment/runtime/dev/compose.yaml,
       release/analytics_task013_build_candidate.py,
       release/analytics_release_source_binding.py,
       .github/workflows/platform-release.yml.
AUTHORIZATION: This document is REVIEW ONLY. No protected-main merge,
               signing, registry publication, live SQL or installed service
               change is authorized by its existence.
-->

# M05: One controlled original-platform Analytics release and deployment

**29 October 2026 — draft review only.** Owner authority: Omnilyzer Issue
#27 comment 6487992867. M01 is sole integration lead. Reuse the existing
original-platform deployment control plane and preserve its currently
working, separately signed canary and broker. This packet records
**what is implemented versus what still must be genuinely delivered**.

## 1. Exact current source boundaries

- Analytics M01 PR49 reviewed-candidate Git SHA:
  `2472d5265688b4f1e18d91f140afe61307ea371b`. It includes M02
  PR46 JSON/localStorage cross-tab isolation, the patched digest-pinned
  Node22.23.4 base from PR48, and nonbypass PostgreSQL application RLS.
- Original-platform M01 PR242 source-admission integration:
  `9ec3bc8b952cf008f5990fcb7605101fae17ada5`, stacked on M05
  combined PR239. **Preparatory**, not M04 final source acceptance.
- Exact current PR49 canonical Git-only source TAR verified by M01:
  SHA256 `3e0cabf5fdd112c18c9a4540c379fbeac1de3df18f117e60e8601ed88dd4f367`,
  540 committed files; 72 source/hash checks in PR242. **NOT an OCI
  registry digest or signed release.**
- Do not publish the obsolete PR45 Node20 release or reuse M05's older
  PR45 local OCI manifest digests. If final M01/M04 PR49 SHA changes,
  update the single original-platform source admission and runtime
  product profile, source Git TAR and signed claim once after freeze.

## 2. What this review adds without touching the installed canary

The existing Task014 remains **canary-only** in
`deployment/policy.py`, `deployment/execution.py`,
`deployment/release_consumer.py` and `deployment/docker_runtime.py`.
This review does **not** widen their allowlists, replace the signer,
introduce a second executor or grant deployment from an unsigned
receipt. It adds a separate, explicit **not-installed** product-only
Compose template at
`deployment/runtime/dev/analytics.compose.review.yaml` and an
inert Python contract at `deployment/analytics_dev_release_review.py`.

The product template has one project name, separate from
`omnilyzer-task014-dev`: `omnilyzer-analytics-dev`.
It offers two opt-in profiles: blue on **127.0.0.1:3141** and green on
**127.0.0.1:3142** (each internal Next.js port 3000). These are
**proposed local-only bind ports, not verified available on target
servers**. Existing canary port **3020** and its source files remain
untouched. Public routing is **not configured**. A dedicated existing
or separately provisioned private backend Docker network must give
Analytics access ONLY to the appropriate PostgreSQL writer, not to
arbitrary other products. No backend network is created by this
template.

OCI references must be exact:
`oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:<digest>` (no tags).
The original signed-repository, exact Git-source, release-version,
Cosign, GitHub OIDC, replay, rollback and Task014 broker/executor
admission **must independently succeed**. A syntactically valid digest
passed to `review_dev_rollout()` cannot authorize a deployment.

## 3. Runtime secrets (references only; no values in Git/Docker inspect)

Four named runtime secrets are required, each as one owner-provisioned
private file under the reviewed fixed host directory
`/var/lib/omnilyzer/deployment/analytics/dev/secrets/`:

| Secret file | Expected file content format | Least-privilege source |
|---|---|---|
| `DATABASE_URL` | `DATABASE_URL=<private PG app URI>` | `omni_runtime` non-superuser/nonbypass application role |
| `COLLECTOR_DATABASE_URL` | `COLLECTOR_DATABASE_URL=<private PG collector URI>` | distinct scoped collector role |
| `JWT_SECRET` | `JWT_SECRET=<strong random secret>` | existing JSON Bearer Session signing |
| `JWT_REFRESH_SECRET` | `JWT_REFRESH_SECRET=<different strong random secret>` | independent refresh signing |

These textual **example placeholders are not credentials**. The actual
files are provisioned out-of-band ONLY by authorized host execution,
with private directory mode **0700** and each nonempty regular file
mode **0600**, owned by the precisely mapped unprivileged runtime
identity. The Compose reference requests runtime `uid=10001`,
`gid=10001`, and restrictive `mode=0400`. **Important limitation:**
Docker Compose local-file secrets may implement these as host bind mounts
and may not honor requested uid/gid/mode remapping. Do not trust YAML
alone: original Task014's authorized host installer must verify real
container UID10001 access and that other container UIDs cannot read the
four files before enabling ingress. Failure must block activation;
never relax modes to 0444/0666 to make the app start.
The Python reviewer checks only names, ownership, sizes,
mode and symlinks; it **never opens or returns secret contents**.
In each container, read-only mounted individual secrets are loaded
by the official Node22 CLI `--env-file=/run/secrets/<NAME>`.
The four secret values do not appear in the OCI layers, Compose
`environment:` or Docker inspect `Config.Env`; Node creates runtime
process environment as required by existing Next14/Prisma/JWT code.
Runtime process environment is still sensitive and must not be
exposed through debugging, shell access, telemetry, logs or admin
interfaces. Rootless UID mapping/secret read access MUST be verified on
the real target host before deployment. No fallback to world-readable
secrets or migration-owner PostgreSQL runtime credentials.

**Actually tested in isolation on truexdevelopment:** Docker Compose
v5.5.0 parses each profile and confines ports to 127.0.0.1; no
secret value in the parsed environment. An offline, read-only,
`--cap-drop ALL`, `no-new-privileges` Node22.23.4 test container
running as UID 10001 successfully consumed four **synthetic** private
0600 mounted files via Node `--env-file`. No live secrets or installed
product services were accessed. Test files and containers removed.

## 4. Exactly one release/build/sign chain after source freeze

**Required before protected signing** (all currently HOLD until the
M03/M04 source checkpoint):

1. M01 chooses one final source Git SHA and publishes the accepted
   immutable source manifest. M03/M04 independently verify real PG16
   restricted app/collector roles, tenant A/B and session revocation on
   that SHA. M02 confirms actual browser auth→Workspace→Website→report.
2. M05 uses ORIGINAL `release.analytics_source_admission`,
   `release.analytics_task013_build_input`,
   `release.analytics_oci_context`,
   `release.analytics_task013_build_candidate` with the ORIGINAL
   pinned Buildx/BuildKit. It produces the exact verified OCI archive
   and immutable Git TAR for **the same** selected source, retaining
   their SHA256s in a private review-only handoff.
3. The ORIGINAL Task013 workflow `.github/workflows/platform-release.yml`
   must be product-aware in ONE reviewed branch and must verify the
   cross-private-repo source READ identity under the protected workflow.
   It must run its existing exact Syft/CycloneDX SBOM and Grype
   **fail-closed Critical/High** policy, with no waiver for the old
   Alpine canary issue. Use ORIGINAL signed keyless Cosign/issuer
   and workflow identity, Zot and Forgejo publication/absence checks
   and signed external-source mirror in BOTH original pre-sign blobs.
   Do **not** run a second release or signing service.
4. Record the original signed release manifest/provenance, immutable Zot
   repository@manifest digest, complete OCI archive hash, signed source
   and product/runtime profile hash, SBOM hashes and original workflow
   run. A local unsigned image ID is NOT interchangeable.
5. The ORIGINAL Task014 signed-release consumer must retrieve **and
   verify** these exact bytes and original Sigstore/OCI signatures.
   Only after that should product-specific
   `deployment.analytics_signed_source_pin` check one exact
   reviewed Analytics source. The original OIDC broker/replay/executor
   must use a separately reviewed, closed Analytics request schema
   containing the four secret **references**, never secret values.
   **Current installed Task014 still rejects this request**; this
   extension is necessary before any DEV activation.

## 5. Controlled DEV deployment after separate owner approval

1. **Read-only preflight:** verify original canary `/livez`,
   `/readyz`, `/metadata` and its signed active/previous digests;
   broker health; target host Docker/rootless identity; port
   3141/3142 availability; planned PG cluster identity and backup
   destination; existing Nginx routing; current website/API health;
   private secrets metadata; and exact previously signed state.
2. **Database and backup:** take a recoverable, *off-host* PostgreSQL
   backup and run restore verification BEFORE schema changes.
   Apply reviewed additive SQL using a separate authorized migrator,
   not the application role. Verify effective PostgreSQL role flags,
   RLS policies, tenant A/B isolation, consent and persistence.
3. **Candidate:** original Task014 broker with signed release/OIDC,
   one-shot replay and exact immutable image, four secret references,
   separate rootless Compose slot. Keep prior Analytics slot running.
   Never reuse canary slots or compose project. Check the candidate's
   actual functional authenticated Workspace+Website+report+collector
   API under the **same nonowner application DB connection**; a
   basic `/readyz` 200 alone is NOT acceptance.
4. **Traffic:** only after functional proof, switch the separately
   approved Analytics origin/loopback upstream by the EXISTING
   Task014 state/controller operation; do not change canary route.
   Verify two-browser/account tenant isolation, refresh/logout
   revocation, CSP/CORS/consent and persisted report rows.
5. **Rollback/abort:** on any failure, restore the PREVIOUS signed
   Analytics OCI digest/slot and approved ingress routing. Never roll
   back by deleting or overwriting database writes, and never blindly
   reverse a migration that destroys current data. Preserve the new
   database state for forensic/repair decision; destructive PG
   restore is a **separate, explicitly approved incident action**.
   Re-verify original canary and all other unaffected services.
6. Store the original provenance, immutable release and previous
   digest, source SHA, signed rollback evidence, the exact one-shot
   approval, pre/post smoke results and off-host backup reference.
   No secrets are allowed in this decision packet.

**The installed broker and executor do not yet support Analytics.**
This is a guarded owner runbook, **not executable deployment
authorization**, and none of these steps have been run on live DEV.

## 6. Lean truexmainserver production plan (later separate approval)

Only after real **signed, independently accepted DEV Analytics**:
reuse the currently installed original SaaS PG16, Zot, Forgejo, Docker,
Nginx and Cloudflare origin control. Do not install a second SaaS
foundation, CMS, Redis, an extra permanent staging stack, or extra
signers. For truexmainserver individually verify:

- Real `hostname`, host/cluster identity, rootless Docker UID/GID
  mapping, existing bind ports, mounted Nginx config and service
  statuses. No assumption that the DEV host is production.
- Independent Analytics PostgreSQL product database and nonbypass
  application/collector roles, installed migration revision, shared
  PG host/tenant isolation, non-superuser effective credentials and
  scoped backups. A healthy DB connection is not proof of app readiness.
- Off-host backup with test restore, RPO/RTO and write-preserving
  immutable-digest rollback. Reject destructive SQL as "rollback".
- HTTPS origin, restricted CORS, strict CSP, authenticated SaaS API,
  GA4/Cloudflare analytics and consent conditions; preserve other
  websites and existing authenticated sessions.
- Install exactly one reviewed signed container version and private
  secret refs through the original platform. Verify user login,
  website creation, event attribution, reporting, tenant denial,
  logout/revocation and one reversible switch without touching canary.
- Only then allow M01 to declare Analytics product GO and use one
  external static-first website as a consumer of the existing APIs.
  No website engine or CMS project is a release prerequisite.

## 7. Current real readiness and missing owner decisions

| Boundary | 29 Oct review evidence | Ready for release? |
|---|---|---|
| PR49 Node22 + nonowner application API | M01 real PG9/9, HTTP16/16; M03/M04 independent acceptance pending | HOLD |
| PR242 source/profile review | Preparatory 72 Git/hash checks, 540-file tar; **unsigned** | HOLD |
| Task013 immutable builder+private OCI handoff | Previously real with PR45; current PR49 OCI and current Syft/Grype evidence not yet built/verified here | HOLD |
| Original Task013 protected OCI signing/Zot/Forgejo | Still canary-only, no actual signed Analytics release | HOLD |
| Original Task014 signed product broker+secret ref+slot | New inert review metadata/Compose only; installed broker still denies Analytics | HOLD |
| Functional DEV Analytics/canary parity | Existing canary running, no genuine signed product activation | HOLD |
| Production truexmainserver Analytics | Deliberately untouched pending separate owner authorization | HOLD |

**No rollback or readiness result may be marked PASS from a syntactic
signed-looking test fixture, user-provided Git SHA, forged TrustedRelease
dataclass, local OCI digest, or mocked broker/executor.**

**Current next M05 integration after M01/M03/M04 checkpoint:** wire the
single final product into ORIGINAL Task013 signed producer and ORIGINAL
Task014 closed product-specific broker/executor. Independent M04
security/release acceptance and separate owner authorization precede
any installed service change.

## 8. Actual original pinned Task013 PR49 OCI proof (2026-10-29)

M05 executed the **original platform's** retained verified source→OCI
builder from the exact M01 PR242 preparatory source against exact M01
Analytics PR49 Git `2472d5265688b4f1e18d91f140afe61307ea371b`.
Source review **72/72**, original Docker Buildx 0.36.1 and pinned
container BuildKit **v0.24.0**, original source-only immutable 540-file
Docker TAR from Git objects, genuine locally built linux/amd64 OCI archive,
and M05's existing all-content digest/OCI/nonroot/Next14 validator **PASS**.
The private 0700 handoff contained the exact original OCI TAR and source
TAR, with 0600 file permissions; M05 original pre-sign source-binding
helper independently reconstructed/verifed the matching source and OCI.

Actual **local, unsigned** build identifiers:
- Git source TAR SHA256
  `3e0cabf5fdd112c18c9a4540c379fbeac1de3df18f117e60e8601ed88dd4f367`
- Full OCI archive SHA256
  `e749d11974a13d4ee97cf75515ce4230bbcb4656c21f2352905a04c42a598c25`
- OCI archive's local manifest digest
  `sha256:de152e3d0e69f457cab2a238ccfa806f77e4865726c128ee73572f2c260e3bd4`

**These SHA256 values are NOT a published Zot manifest or a signed Task013
release**, and the evidence was not sent to the original protected
GitHub Actions signer. The ~hundreds-MB local archive, context TAR,
private handoff folder and isolated BuildKit builder/container were
cleanly removed after verification. Default builder and canary unchanged.

Combined **338 Task013/014 plus product runtime tests: 337 PASS,
1 documented optional test SKIP, 0 FAIL**. Real Docker Compose profile
parser/Node22 secret-reference mechanism additionally PASS. M04's formal
PR49 source/runtime acceptance and original protected Syft/Grype
Critical/High scan are still required prior to final source freeze and
any signed real release. No signing, push, broker or installed service action.
