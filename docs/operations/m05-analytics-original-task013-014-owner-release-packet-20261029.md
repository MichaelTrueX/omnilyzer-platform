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
identity. **Verified limitation:** Docker Compose v5.5.0 explicitly
reports that its local-file secret `uid`, `gid` and `mode` properties
**are ignored**. The reviewed Compose template therefore no longer claims
these mount attributes protect secrets. Actual source file ownership
(effective host UID mapped to container UID10001), directory mode 0700
and per-file mode 0600 determine access. On truexdevelopment, an isolated
real Compose container (Node22.23.4, UID10001, read-only, no network,
cap_drop ALL) read all four synthetic 0600 source files when owned by
the mapped UID10001. Changing just synthetic JWT_SECRET ownership to
UID0 made the same container fail to read it. Exact positive and
negative actual Compose outcomes PASS, with temporary test-only Docker
containers/project and files cleaned. This is still **not proof** that
the separately authorized target rootless Docker daemon's host/userns
UID mapping matches truexdevelopment: original Task014 must verify
its *actual* secret-file read and wrong-owner denial on the target
before enabling ingress, with **no** 0444/0666 permission fallback.
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

## 9. 29 October: REAL PR49 OCI Syft/Grype result — RELEASE POLICY FAIL

**Mandatory P0 blocker, not a signed release.** After M01 froze Analytics
PR49 SHA `2472d5265688b4f1e18d91f140afe61307ea371b`, and M02/M03/M04
independently accepted the exact nonowner PG16/Next14/browser product source
(Omnilyzer Issue #27 comments 6488111449, 6488147833, 6488148479 and
6488212594), M05 built that exact source AGAIN with the ORIGINAL pinned
BuildKit v0.24.0 and strict PR242 72-source hashes. Genuine Git-only TAR,
actual linux/amd64 OCI, M05 existing archive verifier and cross-repository
unsigned source claim all **PASS**. No protected-main signer/OIDC dispatch,
registry publication, policy waiver, installed service or live database used.

- Original Syft **1.51.0** on the **actual OCI archive** generated a valid
  CycloneDX **1.6** SBOM containing **22,750 components**. This is **not**
  a generic source-dir scan or synthetic test report.
- Original Grype **0.118.0**, actual SBOM input, real vulnerability database:
  **2,796 matches: 67 Critical, 510 High, 886 Medium, 276 Low,
  1,008 Negligible and 49 Unknown**.
- Real Grype DB metadata: built `2026-10-28T06:23:30Z`, schema `v6.1.10`,
  checksum `sha256:b08902b91738f1a9bc7fd61942f331d8e5e76a5df0c0b5f8c17c18bd787ee278`,
  valid **true**.
- Representative actually observed blocker IDs/packages:
  `GHSA-p293-qw3h-jr36` **Critical** on Next `14.2.32`;
  `GHSA-2464-fhr4-w9x` and `GHSA-2xp9-vwfh-vxw4` **Critical** on Next;
  `GHSA-2w6w-674q-4c4q` and `GHSA-8r5x-fm3f-whwj` **Critical** on Handlebars `4.7.8`;
  `CVE-2026-19931` **Critical** on curl/libcurl Debian packages;
  `CVE-2026-5450` **Critical** on Debian libc;
  many additional High matches for Next, Axios, Systeminformation, Curl,
  Node dependencies and Debian base packages. These are scanner findings
  by package and advisory, **not claims of verified exploitability**.
- The immutable original policy `release/vulnerability-policy.json` is
  `block_severities=[Critical,High]` with `exceptions=[]`.
  **Security gate outcome: FAIL / no release.** Never weaken severity
  rules, manufacture a clean OCI/SBOM, sign the obsolete Node20 PR45,
  or claim the new Node22 base alone resolves all current findings.
- Latest **local UNSIGNED** original builder candidate receipt:
  OCI manifest `sha256:50591d5ee093339536d3dab21aa2896eff848edca00bab9935fc817c4091542e`,
  whole OCI archive SHA256 `ba0248000c02cdaefab1c7e47eef0ca627622b6d82470aefc8487ee15c3740ec`,
  exact Git-only source TAR SHA256
  `3e0cabf5fdd112c18c9a4540c379fbeac1de3df18f117e60e8601ed88dd4f367`.
  Local OCI digest differs from earlier independent local build; no OCI
  binary bit-for-bit reproducibility or published registry digest claimed.

**Required one-owner remediation:** M01 must select the smallest reviewable
Analytics Docker/runtime+dependency security patch (for example eliminate
unneeded build-only dependencies from the final runtime OCI, use a patched
minimal supported base, and upgrade demonstrably vulnerable direct and
transitive application packages while preserving existing Next14/Prisma6
and JSON Bearer / PostgreSQL session / tenant behavior). M04 must
independently review only the actual changed security boundary. This will
change the final Analytics Git HEAD and therefore requires exactly ONE
post-remediation M01 PR242 source/hash/OCI re-freeze and ONE genuine
Syft/Grype run on that new signed candidate. Do not keep repinning and
rebuilding the same failing source. Distinguish exploitable runtime
vulnerabilities from build-only package inventory using real OCI evidence,
without weakening the original fail-closed policy.

**Operational cleanup VERIFIED:** The ~600MB temporary OCI archive, source
TAR, ~3.3GB Grype database and scanner report directory, and isolated
original pinned BuildKit builder/container were deleted after results were
recorded. Available root filesystem space recovered to ~12GB; original
Docker builder unchanged. Original signed canary Compose source SHA256
`c878123f77a74fba2e11e08b1d13b7cd40e8232f51471d656e927229f94dfdc9`
and active DEV/production services were untouched.

**Production host discovery limitation:** read-only SSH from
`truexdevelopment` to hostname `truexmainserver` failed DNS lookup;
Tailscale currently listed `truexdevelopment` and `omnilyzerdev`, but
not `truexmainserver`. No claim about truexmainserver's current ports,
secret ownership, writer DB cluster, Nginx loaded config or available
storage is made from that failed check; such facts must be verified
read-only before an independently authorized production cutover.

**Result for owner decision:** product SOURCE GREEN; ORIGINAL Task013 local
source→OCI and Syft/Grype engineering EXECUTED; actual scanner policy
NO-GO with 67 Critical + 510 High. Original Task013 protected signed
Analytics publication and original Task014 installed Analytics broker,
secret refs, functional DEV runtime and write-preserving rollback remain
UNEXECUTED, as explicitly required by current owner authorization.

## 10. 29 October: source-remediated PR50 source-identity checkpoint

This **supersedes the PR49 build input for subsequent signing** while retaining
section 9 as explicit historical failing PR49 OCI evidence. M01 security patch
Analytics draft PR50 exact Git HEAD
`b2a02e54cb5d51f06cb56b9f9d7aa7ca2fae2a50`, Git tree
`09a4a2a63c1db3bbe8774b8292d78e8d653ece63`, based directly on
previous M02/M03/M04 accepted PR49. Independent M04 targeted Next15+
production-dependency+slim-container acceptance: Issue #27 comment
6488856441, review 5693289561. The seven changed source files are
`Dockerfile.analytics`, `app/api/chatbot/route.ts`,
`docs/qa/m01-security-runtime-repin-20261029.md`, `next.config.js`,
`package-lock.json`, `package.json`,
`scripts/test_m01_node22_analytics_oci.py`.

M05 refreshed the **same original** Task013/014 source admission, immutable
BuildKit build input, OCI validator, signed external-source review, product
profile and test fixtures to PR50. Four additional changed-file types are
included in exact critical SHA checks, preserving all prior 43: 47 critical
files + original immutable historical 29-file manifest = **76** checked Git
source identities. Both PR49 and the older vulnerable PR45 are denied by
exact HEAD/source/hash checks. The 541 committed source TAR files (Git only,
no local dependencies or untracked files) have SHA256
`2fe0a3e59d01eab1da4a53e834576a4e4adfee57310456aae001a8d61e6abfc8`.
The runtime contract is exactly `nextjs-15`; JSON Bearer/localStorage,
revocable PostgreSQL Session and nonbypass tenant RLS remain unchanged.

**Original platform source-test evidence:** 111 focused Task013/014
source/OCI/provenance/product tests (110 pass, 1 optional skip);
full combined existing release/broker/executor/original-canary plus product
runtime suite **338 tests (337 pass, 1 optional skip, zero fail)**.
Both are inert review-only tests. No protected signer, public registry, host
install or canary mutation is implied. Final Task013 OCI vulnerability
policy Critical/High **must be tested against the new PR50 image**; PR50 npm
audit or historical PR49 OCI Grype counts do not prove PR50 OCI security.

The original protected Task013 workflow and installed Task014 broker/executor
remain canary-only. Product runtime Compose remains a separate **not-installed**
review file, pending explicit owner-approved original Task013 signing,
Task014 product-aware closed authority/secret references, genuine hosted
functional readiness and write-preserving signed immutable-digest rollback.

## 11. 29 October: REAL PR50 OCI Syft/Grype security re-scan — STILL NO-GO

**Scope and chronology:** M01 PR50 exact source
`b2a02e54cb5d51f06cb56b9f9d7aa7ca2fae2a50`, M04 independently
accepted only its changed source boundary for this scan (GitHub Issue #27
comment 6488856441). The original-platform source commit which actually
executed this **unsigned local scan** was
`cf3b436cb98b74aba35e4f5e179dfcb25c8eb0cf`; subsequent documentation
updates do not retroactively change its source/provenance identity. This is
NOT an original Task013 protected-main GitHub signed release or any registry
OCI digest. No installed Task014 Analytics deployment occurred.

The real locally generated OCI from the original pinned BuildKit **v0.24.0**
passed exact 76 Git source identities, immutable 541-file Git-only TAR
(SHA256 `2fe0a3e59d01eab1da4a53e834576a4e4adfee57310456aae001a8d61e6abfc8`),
original OCI blob/content digest validation and original pre-sign external
source claim binding. The OCI had a source-only build recipe with the Node
22.23.4 bookworm-slim runtime and Next.js 15.5.28 source from PR50.

**Actual scan, not npm audit or a scanner fixture:**
- Syft **1.51.0** analyzed the real OCI archive and produced CycloneDX 1.6
  with **4,482 detected components** (historical PR49 OCI: 22,750).
- Grype **0.118.0** analyzed that exact OCI SBOM. Grype DB v6.1.10,
  built **2026-10-28T06:23:30Z**, valid `true`, DB checksum
  `sha256:b08902b91738f1a9bc7fd61942f331d8e5e76a5df0c0b5f8c17c18bd787ee278`.
- Scanner matches: **2 Critical, 81 High, 82 Medium, 15 Low,
  67 Negligible — 247 total**. Previously PR49 had 67 Critical,
  510 High, 886 Medium, 276 Low, 1,008 Negligible, 49 Unknown,
  2,796 total. Current Critical/High **83** versus PR49 **577**.
- Both Critical **matches** refer to Debian libc packages with the
  *same advisory*: `CVE-2026-5450` for `libc6` and `libc-bin`
  (version `2.36-9+deb12u14`). Do not present these as two different
  root vulnerability IDs. Examples of remaining High matches:
  `CVE-2025-13151` on `libtasn1-6` `4.19.0-2+deb12u1`;
  `CVE-2026-41992` on `gzip` `1.12-1`;
  `GHSA-rgw5-rvv9-x895`/`GHSA-mh99-v99m-4gvg` on
  `brace-expansion` `2.0.2`;
  `GHSA-ch52-4w7c-c8xp` on `http-cache-semantics` `4.2.0`;
  `GHSA-mwp4-54f8-5fhr` on `ip-address` `10.1.0`;
  and additional Debian `perl-base`, `zlib1g`, `ncurses` hits.
  These are package/advisory **scan matches**, not individually
  demonstrated exploits; all nonetheless block under the current policy.
- Original `release/vulnerability-policy.json` remains untouched:
  `block_severities=[Critical,High]`, `exceptions=[]`.
  **SECURITY GATE = FAIL, RELEASE NO-GO**. Never waive, ignore these
  findings, sign PR49, or treat PR50 npm-only audit as sufficient.

**Actual local unsigned archive proof** (for diagnosis only; NOT registry):
- OCI manifest digest
  `sha256:443b54786ddddd8bc636d36a1984cbea88cb07bbd1443e84e8f0a5c26c7d8d54`
- Full OCI tar SHA256
  `8e8931a2dbce8cba7fd4d8d7bf4931ab7ee6d8ab17571d254ed60a94ded4a4dc`
- Original source claim `signed=false`, `release_authorized=false`,
  `deployment_authorized=false`; no protected workflow, Zot/Forgejo
  publish or Task014 promotion.

**M01 remediation handoff:** keep the same accepted Analytics features,
JSON Bearer/localStorage, revocable DB Sessions and real RLS. Patch or
replace remaining vulnerable Debian runtime packages/base and direct and
transitive npm runtime dependencies. Review whether an updated digest-pinned
slim base + fully security-updated OS packages suffices. Do NOT delete
required Prisma OpenSSL3 or relax Docker rootless/capability controls.
M04 reviews only actual new changes; M05 then performs one exact Git source
repin and original pinned BuildKit/Syft/Grype re-scan on the new source.
No further Task013 signing/Task014 installed product activation until zero
policy-blocking findings and separately authorized protected release.

**Disk safety/cleanup:** This re-scan stored the ~3.3 GB Grype database
in a private **/dev/shm RAM filesystem** because the shared DEV disk had
limited free storage. The temporary ~335 MB OCI TAR, ~10 MB source TAR,
Grype DB, Syft/Grype intermediate reports, temporary original BuildKit
v0.24.0 builder/container were all removed. Actual post-scan available
root space **~7.0 GB**; `/dev/shm` returned to ~3.1 MB use; the original
Docker default builder remains running/unchanged. Neither original DEV
canary nor product services, DB, Nginx, Cloudflare, registry, signing
identity, DNS, token/cookie handling, secrets or production changed.

## 12. 29 October: Original Compose local-secret permission caveat closed

**Actual observed, not inferred from parsed YAML:** isolated Docker Compose
v5.5.0 explicitly warned that file secret `uid/gid/mode` are unsupported
and silently ignored. M05 removed those misleading fields from the
review-only Analytics Compose file and moved trust to host 0700 directory,
0600 regular secret files, carefully established effective host UID/GID
and an actual runtime positive/negative test. Four synthetic secrets
were mounted inside a rootless-user **container** UID10001 with all
capabilities dropped, no network, no exposed ports, read-only rootfs,
Node22.23.4. The actual Compose execution succeeded when all four
synthetic files were owned by UID10001; changing only JWT_SECRET to
owner UID0 prevented Node's --env-file from loading it. The short setup
container was allowed CHOWN only for its own synthetic temp file; the
running app container never received CHOWN privileges. No production
credentials, no real Analytics OCI, no installed Task014 broker, canary
or shared network were used.

**Persistent opt-in regression** added to the existing
`deployment/tests/test_analytics_dev_release_review.py`:
`M05_REAL_COMPOSE_SECRET_TEST=1 python3 -m unittest -v
deployment.tests.test_analytics_dev_release_review`.
Requires a pre-cached pinned Node22 base, local Docker Compose and PyYAML;
test always creates a unique throwaway Compose project and removes it.
Default CI keeps this optional to prevent access to host Docker when it
is not authorized. The original Task014 target rootless UID mapping
and secure secret provisioning **still need real host acceptance**.

## 13. 29 October — independently accepted PR51 source pin (review only)

M04 independently approved Analytics [PR51](https://github.com/MichaelTrueX/omnilyzer/pull/51)
exact HEAD `df40b4632a088232de4699d5826641e0cf269dc8`, Git tree
`b6b4f5f210d61d2cfef25cfe3f04b55eb8f509a8`, for the original
Task013 source repin and genuine OCI scan ONLY (M04 GitHub review
`5693751996`, Issue #27 comment `6489733825`). M04 independently also
accepted PR244's separate Compose file-secret security correction in
review `5693770571`, comment `6489772603`. Neither review authorizes
signing, registry publication, installed Task014, DEV activation or PROD.

This existing PR244 source/presign binding has been refreshed from accepted
PR50 to exact PR51 in **the same original Task013/014 files**:
- **77 exact committed Git source identities**: 29 historic source identities
  plus 48 current security-critical file hashes, including all three PR51
  changed files; every previous PR49/PR50 source mismatch denied.
- Reproducible **542-file** Git-only sanitized source TAR SHA256
  `815fd9c6e2ca9fc019c7c6b782e4276849a9d410bee166e811ced63719258cbe`.
- Changed Dockerfile SHA256
  `b395a091001e44739c9caab8324d755e9cc72fd26da0be771de4e4ad06d88c9e`.
- Existing original signed external-source projection, product profile,
  Next15 runtime identity, OCI file check and original Task014 source claims
  now all require the **same PR51 Git commit, tree and 77 hashes**.
- Independently repeated on a disposable review-only platform copy:
  focused 112 tests: **110 PASS, 2 opt-in SKIP, 0 FAIL**; full original
  Task013/014 broker/executor/canary + product suite 339 tests:
  **337 PASS, 2 opt-in SKIP, 0 FAIL**. The two skipped tests involve
  environment-specific optional Docker/handoff scenarios and are NOT
  presented as runtime security evidence.

**Current next decisive release gate:** BUILD the exact PR51 candidate from
these committed source hashes using ORIGINAL pinned BuildKit v0.24.0,
generate a genuine Syft1.51.0 CycloneDX1.6 OCI SBOM, scan using
Grype0.118.0 and its valid DB, and enforce the original zero-exception
Critical/High policy. Previous PR50 2 Critical/81 High remains historical
failure evidence only, not a claim about PR51. If PR51 has any blocking
findings, stop before signing and provide a **complete sanitized machine-
readable blocker inventory**, not a selective list. No owner approval has
been given to operate protected signing/registry or live Task014.
