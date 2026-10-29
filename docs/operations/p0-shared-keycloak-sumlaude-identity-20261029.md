# P0 shared platform identity BFF for Sumlaude (29 Oct 2026)

**Source-only integration candidate. NOT merged, deployed, or authorized for learner access.**

## Why it exists

Original Omnilyzer ADR-0003 and Task004 real Keycloak reference are reused.
The original Authlib 1.7.2 dependency is intentionally upgraded to the
security-fixed Authlib 1.9.1 (October 2026 GitHub vulnerability findings).
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
  cookie and revokes the previous hash. Failed refresh revokes the
  current product session and clears local auth, unless S03 revocation
  itself is unavailable (HTTP503 fail closed for the platform action).
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
