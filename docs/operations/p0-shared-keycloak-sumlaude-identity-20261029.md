# P0 shared platform identity BFF for Sumlaude (29 Oct 2026)

**Source-only integration candidate. NOT merged, deployed, or authorized for learner access.**

## Why it exists

Original Omnilyzer ADR-0003 and Task004 real Keycloak reference are reused.
The original Authlib 1.7.2 dependency is intentionally upgraded to the
security-fixed Authlib 1.9.1 (October 2026 GitHub vulnerability findings).
Likewise pin cryptography 50.0.0, the patched version required by the
GitHub dependency review (three earlier cryptography advisories).
The original Task004 code remained an isolated spike. This is the smallest
persistent Django/Authlib service candidate for mounting under
`https://app.sumlaude.com/auth/*`, using ONE shared Keycloak issuer.
It is not a second IdP, Sumlaude password database, Website Engine, or CMS.

## Browser and trust contract

| Route | Handler | Behavior |
|---|---|---|
| GET /auth/login | platform Django | 5-minute server-held state/nonce/PKCE S256 -> Keycloak |
| GET /auth/callback | platform Django | exact HTTPS redirect, code exchange, signed issuer/audience/sub/nonce, verified S03 admission issuance |
| GET /auth/csrf | platform Django | Django CSRF bootstrap for refresh/logout |
| GET /auth/session | platform Django | authentication state only, no OAuth bearer, stable ID or guardian entitlement |
| POST /auth/refresh | platform Django | CSRF, check original issuer+subject, rotate S03 session, revoke old digest, return CSRF refresh requirement |
| POST /auth/logout | platform Django | CSRF, revoke S03 first, flush Django session, delete host-only S03 cookie; best-effort Keycloak refresh-token revocation |
| GET /api/auth/csrf | existing S03 Fastify | S03's own independent session-bound CSRF, not the Django token |
| /api/valoria/* | existing S03 Fastify | still independently checks real consent, learner identity, owner/course and PostgreSQL restrictions |

The browser receives two **independent opaque host-only** cookies on
`app.sumlaude.com`:
`__Host-omnilyzer_identity` (Django provider BFF session) and
`__Host-sumlaude_session` (S03 learner session). Both are
Secure/HttpOnly/SameSite=Lax/Path=/, with NO Domain attribute.
No cross-host cookie forwarding and no client-side OAuth tokens.
Django's PostgreSQL session JSON contains only Fernet-encrypted OAuth token
material, the verified immutable issuer/subject, and SHA256 of the S03
cookie; it does NOT store raw S03 cookie or refresh token plaintext.
The separate server secret TOKEN_FERNET_KEY is NOT kept in Git or DB.

The restricted DB issuer `SUMLAUDE_ISSUER_DSN` has no user/guardian CRUD.
Issuance calls `sumlaude_auth.issue_admitted_oidc_session(issuer,sub,
digest,expires)` and revocation calls
`sumlaude_auth.revoke_issued_oidc_session(digest)`. This is the exact
required **production contract**, not proof those production SQL functions
exist. S03's review-only functions use a `qa_` prefix and are intentionally
**rejected** by this candidate to prevent accidentally wiring QA grants into
a live product. S03 must separately review/migrate those functions and
confirm explicit NOINHERIT role permissions, independently verified legal
adult/guardian decisions, account ownership, and institutional/educational
rules. No automatic identity linking or new learner creation occurs.
Existing guardian and identity entries fabricated by the QA harness
MUST NOT be copied or approved for production.

## Minimal configuration / deployment (AFTER explicit owner GO)

1. Use one existing truexmainserver. Create DNS/TLS for
   `app.sumlaude.com` and a Keycloak login hostname/certificate.
   Register ONE Keycloak confidential client with exact callback
   `https://app.sumlaude.com/auth/callback` and Code+PKCE S256.
2. On the SAME public origin, Nginx reverse-proxy `/auth/*` to a private
   loopback service running this Django BFF; `/api/*` to S03 Fastify;
   `/start` to S01 frontend. Strip client-supplied forwarding headers
   and set a trusted `X-Forwarded-Proto https` only at Nginx; block
   direct internet access to Django/Fastify backend ports.
3. Provide root/service-controlled environment secret **values** outside
   source and backups: DJANGO_SECRET_KEY (>=50 chars), TOKEN_FERNET_KEY
   (Fernet key), OIDC_ISSUER, OIDC_CLIENT_ID,
   OIDC_CLIENT_SECRET, PRODUCT_ORIGIN=https://app.sumlaude.com,
   IDENTITY_PG_DATABASE, IDENTITY_PG_USER,
   IDENTITY_PG_PASSWORD, IDENTITY_PG_HOST, optional IDENTITY_PG_PORT,
   SUMLAUDE_ISSUER_DSN (separate least-privilege role). Optional
   SUMLAUDE_ISSUE_FUNCTION / SUMLAUDE_REVOKE_FUNCTION override reviewed
   production function names only.
4. Initialize the Django sessions table using reviewed migrations and
   a migration principal distinct from runtime. Snapshot both databases.
   Keep `session` rows/private auth data out of unaudited logs and
   production traces. Use one rootless/nonprivileged gunicorn service:
   working directory `services/identity`, WSGI
   `config.wsgi:application`, private loopback, limited workers,
   restart-on-failure, health check and rollback via prior immutable source.
5. S01 use GET /auth/login for signin, GET /auth/session for identity
   state, POST /auth/refresh with Django CSRF proactively before
   S03's 10-minute cookie expires, then reacquire
   GET /api/auth/csrf before Native writes. POST /auth/logout with Django
   CSRF. Preserve S03's per-request admission/owner checks.
6. One local disposable real Keycloak+PG16+Chromium suite should prove
   callback, mounted app, real S03 contract, 2 independently verified
   synthetic learners, CSRF, rejected/tampered nonce, invalid audience,
   forged identity, refresh, revocation, no cross-user data and return.
   Then verify a read-only preflight on truexmainserver.
7. Activate only after Product Owner release authorization and completed
   S02 academic/rights acceptance and verified real S03 adult/minor
   admission. Do not convert tests-only guardian flags into approval.

## Session/security decisions

- Product session = **10 minutes** per issuance (within S03 <=30min);
  Django identity idle = 30min, absolute = 8h. Login callback rotates
  Django session ID. Browser refresh creates a NEW S03 random 256-bit
  cookie and revokes the previous hash. Failed **or expired-session**
  refresh revokes the current product session and clears the client
  product cookie/local auth. If S03 revocation is unavailable the
  platform responds HTTP503, preserves the server-side digest for a
  subsequent retry, and cannot issue another product cookie. CSRF
  cross-origin requests, expired OIDC state, wrong callback issuer and
  invalid signed identity are explicit negative tests.
- Keycloak signing keys cache 5min; invalid signature triggers one
  forced JWKS refresh (normal provider signing-key rollover).
- JWT algorithm pinned to RS256, issuer/audience/exp/iat/sub/nonce
  validation. Never trust browser issuer/sub/email for issuance.
- Normal logout revokes S03 first and makes Keycloak revocation
  best effort; providerTokenRevoked=false is a **real limitation**,
  NOT full provider SSO logout. No provider back-channel logout event
  handler or global logout across other product devices is yet
  implemented. Security event revocation must be driven through S03
  issuer's restricted revoke function. No Redis, per-school realm or
  extra cloud environments are introduced.
- The two independent sessions require S01 refresh integration and
  S03 cookie validation to remain aligned. A token expiry alone does
  not automatically revoke a previously minted S03 cookie before
  its short expiration; final product admission is always checked at S03.
- Production connectivity, concurrent refresh/logout races, Keycloak
  recovery, real registration/guardian evidence, SMTP/account recovery,
  operational secret rotation and production Nginx/DNS have NOT been
  accepted by this source-only change.

## Verification and precise blockers

Local candidate test command (isolated dependency environment):

```sh
python3 -m venv .venv && .venv/bin/pip install -r services/identity/requirements.txt
cd services/identity
../../.venv/bin/python -m unittest discover -s tests -v
```

S03 canonical PR #230 HEAD 402ec2c3ea24be864d37a645cb3b670af1944306
has QA ONLY `qa_issue_admitted_oidc_session` and
`qa_revoke_issued_oidc_session`. S01 canonical PR #243 HEAD
1c115b568ad3be915ab226e59cab7292f930d9c3 has an
unmounted functional LC1 browser journey.
The integrated real-provider tests are evidenced in S03 docs
`s03-original-omnilyzer-https-keycloak-real-handoff-20261028.md`,
but its Django->S03 invocation was still **joined by test orchestration**,
not this new live BFF. No false claim of actual deployment.

Blocking owners:
- **S03**: reviewed production SQL function names, dedicated issuer
  credentials, no test/fictional guardian bypass, real admission
  authorization and production DB migration/backup proposal.
- **S01**: mount frontend and integrate /auth routes, CSRF renewal and
  per-product cookie expiration.
- **Platform/operations**: approved Keycloak production realm/client,
  HTTPS origin, session database, secret management, Nginx and runtime.
- **Product owner + S02/S05**: real minor/guardian legal decision,
  LC1 academic/content rights and explicit GO for any public/live switch.

Rollback: withdraw /auth/* ingress and leave S03 private API 503;
revoke sessions using controlled issuer role before retiring backend;
restore prior service release and DB snapshot without deleting learner data.
No protected branch merge, production SQL, DNS, server modification,
Keycloak config, or real student login is performed by this review PR.


## Verified REAL platform adapter -> S03 production SQL interoperability (29 Oct)

New independently executed **disposable PostgreSQL16.15** evidence, after this
document's initial source-only acceptance:

- Exact S03 canonical DRAFT PR #230 HEAD
  `8f1ff7f9503c2cb33a987c225041d857c5bfbd4a`, unmodified SQL input
  `scripts/production/s03-verified-oidc-session-issuer.sql.candidate`,
  SHA256 `1a61604b7ac7327ecd74e08f52b2f7daf6f6d138205bef05c9dd3f8169a32cba`.
- Ran the exact S03 disposable QA script from a separate **temporary copy**,
  modifying only the temporary script to mount an isolated test Unix socket
  into the network-disabled PostgreSQL container and to invoke the actual
  platform `services/identity/identity_bff/issuer.py` before teardown.
  Original S03 Git worktree, canonical SQL and platform production config
  were NOT modified by the test.
- **PASS**: real restricted `sumlaude_identity_issuer` login and exact
  production-named SQL function calls; platform-generated 256-bit random
  cookie and SHA256 digest actually stored in PostgreSQL, exact mapped
  adult and separately approved fictional minor account, revoke then
  idempotent repeat, unknown subject denied. Existing S03 **12 negative
  cases** plus source installer wrong-database denial PASS. The isolated
  container and data were automatically removed after test completion.
- This is **real PostgreSQL BFF-adapter integration**, NOT real HTTPS
  Keycloak callback through this new persistent Django BFF or legal
  verification of a student/guardian. Both fixture admissions are
  synthetic. Full production Native/RLS migration, secret-carrying
  runtime issuer DSN, operational origin DNS/TLS and end-to-end real OIDC
  browser cycle remain separate P0 activities. No main merge, production
  database migration, server change or learner access was authorized.


## Subsequent platform identity QA (29 Oct, no production changes)

On the disconnected development host, the current persistent original-platform
`services/identity/identity_bff/oidc.py` successfully fetched **actual live
Keycloak 26.7.2** OIDC discovery and RSA JWKS from the temporary TLS test
issuer `https://127.0.0.1:18443/realms/omnilyzer-auth-spike` using its
test-only SAN certificate, and verified that discovery advertised PKCE S256.
**PERSISTENT_BFF_TO_REAL_KEYCLOAK_26_TLS_DISCOVERY_JWKS_S256_PASS.**

Also changed callback ordering: signed identity is verified, OAuth state
is encrypted and its expiry verified **before** attempting any S03 restricted
session issuance. Earlier ordering issued a learner session first and could
leave a short-lived orphan if provider token contents were unsealable or
expiry invalid. Two negative regression cases confirm S03 issue/revoke are
not called for failed sealing or invalid expiry. **21/21** local identity
tests PASS and Python compilation PASS.

**Evidence boundary:** This validates real Keycloak HTTPS discovery/JWKS
connectivity and the separate real PostgreSQL issuer adapter test; it does
**NOT** validate the full new Django BFF Authorization Code callback
exchange against that actual Keycloak test client, refresh-token rotation
against Keycloak, production PostgreSQL-backed Django sessions or the real
browser+Native full journey. Those remain explicit blockers before any
authorization to lift HTTP503. The disposable test Keycloak was shut down
after these checks, with no change to the production realm or Sumlaude.


## Joined actual Keycloak 26 -> permanent Django BFF -> full S03 PG16 (29 Oct)

**PASS** on `truexdevelopment`, no production access. The new optional
`services/identity/tests/run_keycloak_provider_interop_qa.py` drives the
original isolated Keycloak 26.7.2 SAN-TLS fixture, **not** the original
Task004 BFF. The actual new platform `identity_bff/oidc.py`, `views.py`
and `issuer.py` run in the same test. Exact S03 PR #230 schema source was
fetched from Git HEAD `952974ef78470bf45ec8b579115302e0c23c3760`;
`scripts/production/s03-native-full-schema.sql.candidate` SHA256
`5a69447bf27acb844eb9ae2f953eb7e9109a5712474bbd6e4d5877ea2d3da455`.

The S03 canonical self-cleaning `scripts/qa/s03-str013-production-sql-pg16.sh`
was copied to an outside-Git **temporary** shell wrapper, with the root
pointing to the exact S03 worktree and one extra call to the platform
interoperability script immediately after S03's synthetic admission setup,
while the isolated PostgreSQL16.15 container was running. The **actual
unmodified, SHA-pinned full schema** was installed. This QA script created
one additional `identity_disposable` database in the *same disposable
PostgreSQL container*, ran real Django session migrations there, and
used a separate `sumlaude_learning` database with actual restricted
`sumlaude_identity_issuer` role and 33-table Native/RLS source schema.

Observed PASS, in order:
1. Actual Keycloak HTTPS Authorization Code + PKCE, server-side token
   exchange and signed issuer/sub/nonce/JWKS validation through the
   **new persistent** Django BFF; callback returns query-free `/start`.
2. Test-only fictional adult admission attached to the **actual signed**
   Keycloak subject, created in the ephemeral DB by the QA harness,
   never by the BFF; exact role-bound S03 SQL function issued the digest
   of the real newly generated opaque cookie.
3. Cross-client Django login state **persisted in separate PostgreSQL**
   `django_session`, with the browser's host-only secure/httpOnly cookies.
4. Actual Keycloak refresh token exchange: old S03 session revoked,
   new S03 opaque cookie minted and session remained authenticated.
5. Django CSRF-protected logout: new S03 session revoked in real PG16,
   Django identity database session record removed, UI auth state false.
6. All existing S03 actual migration/RLS/privilege tests passed, including
   22 sensitive access denials and mutation-detected grant regression,
   migration/bootstrap reapply denial and disposable container cleanup.

**Trust boundary:** Adult admission row was fictional, created ONLY by the
QA test after a verified provider subject; the test does **not** provide
real registration/guardian evidence, a real production Keycloak confidential
client or live enrollment. Django and Native PG were two distinct databases
within one disposable container, not a deployed server layout. The joined
S01 real Chromium practice journey, public/private LC1 rights/release,
operational TLS/domain/secret rotation, and owner-authorized production
rollout remain outstanding. Never lift production HTTP503 based on this test.


## OIDC transport regression, 29 October

The OIDC provider transport now rejects HTTP redirects instead of following them. This applies to its discovery, JWKS, token and revocation requests. Regression tests cover five redirect status codes and handler installation. The previous isolated real Keycloak and S03 full-schema PostgreSQL login, refresh and logout test was rerun and passed following the transport change. The private Chromium lesson journey remains separately unverified against this specific persistent BFF.


## S01 real Chromium identity acceptance (29 Oct)

The optional `services/identity/tests/qa_s01_browser_gate.py` test used S01 source 5730b9edbf7adce3d2e920f2f20a65d29baeae1c built with the private Native BFF Vite configuration. In isolated PG16, a genuine Keycloak 26 HTTPS signed callback created the original platform Django identity session and a restricted S03 learner session for a fictional, already approved adult. The Playwright Chromium browser sent its real secure identity cookie to the actual PostgreSQL-backed Django /auth/session handler and S01 displayed the authenticated Account session controls. Private `/api/*` intentionally returned 503. After refresh and logout, a browser reusing its old session cookie was denied and S01 displayed Sign in to study without private API requests. Both browser checks passed without page errors. This is a verified real browser identity gate, NOT the complete five-unit Native lesson with the same issued S03 cookie. The latter remains to be tested. No production changes.


## Rechecked against current restricted Native production SQL (29 Oct)

Exact S03 draft #230 HEAD `d038f085d84db085055432c03cf99e4bad12d828`, full migration SHA256 `3beb7d4ac8c9cce3d8735ebb0d3432a985b252b047535d4b5e88689b3b6de2e9` (replaces older candidate hashes). On `truexdevelopment`, copied S03's self-clean PG16 test runner OUTSIDE Git, changed only its checkout root and added a temporary optional call to the original platform real-Keycloak join script. Installed the exact current production-shaped 33-table migration into disposable network-disabled PG16. Real S03 `sumlaude_app` restricted role plus 22/22 privilege/RLS mutation checks PASS. Actual Fastify route and HMAC role proved allowed empty learner context, CSRF and revocation controls; private production startup stays held. New persistent Django BFF signed real Keycloak 26.7.2 HTTPS login PASS; Django identity session persisted in a separate DB inside the ephemeral PG16, actual `sumlaude_identity_issuer` issued/revoked learner cookie, real provider refresh rotated, and S01's genuine Chromium private build recognized the PostgreSQL Django identity session, then rejected its stale cookie after logout with no private API request. Entire isolated suite PASS, cleanup exit 0. Private content API deliberately returned 503 in this browser-gate test. This is NOT yet one five-unit Chromium journey with a real provider-issued cookie or lawful real admission.


## Full Keycloak -> S01 Chromium -> Native LC1 joined QA (29 October)

**PASS on fresh AND Valoria-reused disposable PostgreSQL16.15.** Exact reviewed
S01 DRAFT #243 HEAD `5730b9edbf7adce3d2e920f2f20a65d29baeae1c`;
S03 DRAFT #230 HEAD `d038f085d84db085055432c03cf99e4bad12d828`.
The original Omnilyzer BFF at this PR HEAD validates a real local Keycloak
26.7.2 HTTPS Authorization Code + PKCE callback, signed issuer/subject,
audience, nonce and JWKS, and persists its private identity session in a
**second PostgreSQL database** inside S03's disposable network-disabled PG16
container. S03's actual Valoria Native Fastify/PG16 production codepaths run
in the canonical disposable QA role/fixture; no source or release is deployed.

Reproducible opt-in QA artifacts added here:
- `services/identity/tests/run_keycloak_s01_full_lc1_qa.py` checks exact
  S01/S03 Git commit hashes and reuses a *temporary copy* of S03's existing
  self-cleaning PostgreSQL test shell; never edits S03's canonical test.
- `services/identity/tests/qa_keycloak_native_bridge.py` authenticates a
  fictional Keycloak test account through the **real permanent Django BFF**,
  stores sealed OAuth tokens only in PostgreSQL-backed Django session,
  and writes the temporary host-only identity/product cookie values into
  a 0600 file under S03's automatically deleted QA directory.
- `services/identity/tests/qa_keycloak_s01_full_lc1.cjs` reuses S03's
  original real Chromium/React Native logic, with the same content SHA
  `6f6502a6ccda3ad6d418973fd481d29941a7b11f9461b1ec90b8bcce3cf335b9`.
  The positive `/auth/session` is served by a **fresh Django client reading
  the actual signed identity cookie from PostgreSQL** on every browser request;
  it is NOT a synthetic `authenticated:true` stub. S03's real Fastify
  noncredit backend handles private content and submissions.

Evidence: real Keycloak verified signed subject is stored in S03's test-only
immutable identity link for the independently *fictional* admitted learner.
Chromium saved exactly 7 noncredit activities and 11 answers across 5 LC1
units; all 6 authored manual prompts remained read-only. Reload persisted
progress without duplicate POSTs. Focus return and forced identity outage
hid private content without any additional S03 API request. Revoked S03
digest denied private API. Original Django logout revoked its server-side
session; Chromium with the previous HttpOnly identity cookie displayed
"Sign in to study" with ZERO private Native API calls. Original S03
PG16/S01 tests and mandatory negative security tests still pass.
Both fresh and reused original Valoria074 PG16 cleanup PASS.

**Critical separation:** the test-only product cookie registration in the
QA Native learner database is intentionally materialized by S03's fictional
test harness *after* Keycloak's signed ID token was verified. The existing
S03 **production restricted-role issuer SQL** is separately tested against
the exact latest SHA256 `3beb7d4ac8c9cce3d8735ebb0d3432a985b252b047535d4b5e88689b3b6de2e9`
in an independent isolated PG16 run. A live deployment combining the new
Keycloak issuer and the production-role Native HTTP bridge with real lawful
adult/minor/guardian admissions is **not** yet authorized or proven.
The LC1 content fixture is synthetic/review-only and does not grant
academic release, credits or mastery.

To repeat on `truexdevelopment` only: start the existing disposable
`sumlaude-keycloak-https-handoff-20261028/scripts/start-keycloak.sh` fixture;
build the exact S01 private candidate with
`npm run build:private-bff-native`; ensure QA Node/Playwright and
platform Python 3 QA dependencies (including cryptography, psycopg, Django)
are installed. Export `S03_QA_S03_ROOT` and `S03_QA_S01_ROOT` to the
respective review-only source checkouts under `/tmp`; run
`python services/identity/tests/run_keycloak_s01_full_lc1_qa.py fresh`
and `... reused`. Both check exact Git identity, reuse the S03 canonical
disposable shell and delete DB, session secrets and cookies after exit.
Do not run on the live host. No main merge, DNS, product login or release
change was performed.
