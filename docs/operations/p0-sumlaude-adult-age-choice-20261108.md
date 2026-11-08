# M01 / S01 shared OIDC then explicit adult choice, 8 Nov 2026

**SOURCE ONLY, never production live acceptance or automatic activation.**
Use current existing M01 PR243 and S01 PR325; retain accepted old BFF
OIDC/PKCE/refresh/CSRF tests and original one publisher account.
Original Keycloak realm, confidential client and existing approved
S03 restricted issuer are reused; no independent adult ID verification,
no new realm, account provider, native password or sign-up service.

Binding Product Owner policy:
https://github.com/MichaelTrueX/SHSLearningStudio/issues/320#issuecomment-6718101565
Self-declared 18+ uses truthful declared_adult and
sumlaude-adult-self-declaration-v1; never verified_adult.
Known minors retain separate guardian/under16 protection. The self
declaration can be falsified, an explicitly accepted product risk.

## Exact new source contract

- After signed Keycloak authorization code and PKCE S256, matching
  nonce/state/issuer/audience, Django BFF saves a short-lived encrypted
  identity-only session and rotates the Django cookie. **It does NOT
  call S03.issue or return the __Host-sumlaude_session product cookie.**
  It redirects to /professional/gtm-001 with old product cookie cleared.
- GET /auth/session authenticated-but-pending response is exactly
  {"authenticated":true,"productAuthorized":"adult-choice-required"},
  with no browser-visible email, subject, provider token or DOB.
- S01 presents an initially unselected accessible age-band choice. S01
  only sends POST /auth/age-choice body {"ageBand":"adult"} or
  {"ageBand":"under18"}, same-origin credentials, no-store, JSON,
  X-CSRFToken fetched from GET /auth/csrf; no client subject or email.
- On under18, Django permanently denies age upgrade in the SAME
  identity session: {"authenticated":true,
  "productAuthorized":"adult-pilot-denied"}. No S03 product issuance.
  Exit this adult-only pilot. General minors/guardian enrollment is
  NOT invented here.
- On adult, Django requires an existing unexpired identity-only
  session, verifies fresh signed provider claims against stored full
  issuer/sub, then and ONLY THEN invokes the EXISTING restricted S03
  issuer. Only if S03 independently confirms genuine user2 active
  declared_adult, program/course source and permission may it mint
  __Host-sumlaude_session and return exactly:
  {"authenticated":true,"productAuthorized":"check-S03",
  "adultDeclared":true,"csrfResetRequired":true}.
- The S01 client then independently reacquires S03 Native CSRF,
  verifies actual server session and source-bound GTM context before
  rendering any private learning content. Under18, unknown, missing
  CSRF, invalid JSON, wrong signed subject, issuer downtime, denied
  admission and failed Django persistence all deny.
- On any fatal Django session persistence failure after issuing
  a product cookie, existing M01 compensation revokes the newly
  issued S03 digest and clears both cookies. No orphan valid cookie.
- A same-person second Keycloak account is still a separate full
  principal. Current real test18 user ID2 was already created in S03.
  No manual user2 bootstrap or external age check is repeated.
- Backend identity-only state persists across one browser reload.
  Once product authorized, valid Django session retains 18+ choice;
  re-authentication creates a NEW pending choice. No DOB, identity
  document or age flag in browser local/session storage.

## Source and test evidence

- Local isolated M01 DEV Django6.1 tests: 12 new explicit-age/cross
  origin/CSRF/malformed body/under18/signed-sub/S03-deny/replay/
  persistence tests PASS. Previous 80 M01 identity-target tests PASS.
- Broad M01 discover included 201 tests with **two unrelated
  environment-only PermissionError** in preexisting offhost recovery
  test fixtures accessing /home/trust/.cache/omnilyzer-identity-offhost;
  not a new code failure. Do not escalate/review unrelated backups.
- Source-only Python syntax and git diff --check PASS.
- S01 companion client source and controlled Chromium synthetic
  browser tests belong to existing PR325, not proof of real OIDC login.

## Required actual deployment and rollback steps, NOT RUN

- Source review only of changed M01 and S01 files. Do NOT repeat
  original first-user SMTP, Native source or restore tests.
- Immutable newly built BFF release must be separately staged
  root-owned without mutating active BFF; preserve previous approved
  BFF release 304b5acdc642ec4b26e08867af467e63c1b04c5e,
  exact static current release, existing NGINX config and old service
  disabled state. Never make ExecStart follow mutable current.
- S03 actual owner 18+ policy migration and user2 declared_adult/
  active program/course already COMMITTED on truexmainserver; do not
  rerun. Map source-bound GTM001 still deliberately enabled=false.
- NGINX app private origin HTTPS through Cloudflare must be valid and
  BFF/Native loopback 18740/18741 healthy. Never enable public app
  DNS while upstream /auth and /api return 502.
- Only after exact real owner activation/rollback and one legitimate
  true Keycloak browser OAT may the source-bound map be enabled.
  Real signed browser OAT must include: anon denied; pending age choice
  no product cookie; under18 denied; verified test18 full OIDC user2
  after confirmed adult receives cookie only if S03 admits; original
  GTM001 7-phase gated content, persistence/reload; CSRF, cross-user,
  logout, expiry, background timeout, key leak and emergency revoke.
- Any critical FAIL: restore previous static and native pointers,
  original ingress and systemd state and SOURCE MAP OFF. Do not delete
  immutable GTM001 original course/release, publisher1, learner2,
  self-declaration audit or saved progress as rollback.

**Current status: M01/S01 SOURCE candidate, PROD BFF not modified.
Live actual user acceptance NOT RUN.**

## Exact immutable BFF deployment pin (source preparation)

The first real user2 `declared_adult` admission and original GTM-001
course enrollment already exist; NEVER reapply S03 bootstrap/admission.
The adult-choice Django runtime is immutable Git commit
`3481cacbef910a37d87a3c26341b1a8f16a6612f`.
A later unit-only commit does not change this pinned runtime.

- The production Git source archive must exactly match the above commit
  with SHA256 `0411e353e41365cf316d1a71de08cb2a4f5c228853478b88411b57aaa012f1cd`.
  The existing nonroot inactive-install preflight passed this archive.
- Existing `services/identity/omnilyzer-identity.service` is updated for
  the new immutable runtime. `ExecCondition`, `WorkingDirectory`,
  `ExecStartPre` and `ExecStart` pin the identical source directory.
  Never start via a mutable `current` executable path.
- Before any owner-root action, obtain focused independent M04 review of
  the six new age-choice source files and this precise unit/test/document
  pin update; reuse prior unchanged OIDC and package integrity evidence.
- Root inactive installer must first verify its exact source SHA after
  root-owned 0500 copy to `/run`, run owner-root readonly preflight and
  then separately authorized `install`. Do not execute user-owned code
  directly as root. Inactive install must leave current, loaded systemd,
  owner GO marker, env, DB, NGINX, DNS and learner data unchanged.
- A separate reversible live cutover must verify source and new unit,
  pass actual host `systemd-analyze verify`, prove loaded immutable
  paths, then under scoped owner authorization select exact new source,
  create protected GO marker and start 18740 on loopback with valid
  root-protected Keycloak/DB env. Confirm anonymous HTTPS session is
  no longer 502 only after S03 Native 18741 becomes healthy.
- Before GTM source map enable and public app DNS, S03 authenticates the
  exact existing admitted adult and source-bound course. S01 activates
  the latest age-choice static frontend, not the obsolete installed
  `s01-gtm001-d25bb559-20261107` build.
- If any critical acceptance fails, STOP private BFF/Native, turn the
  single GTM map OFF and revert the static public shell. Preserve the
  immutable original GTM source and existing data. Never start the
  obsolete d65 BFF or d74 Native as rollback.
