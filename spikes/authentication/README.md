# Authentication architecture validation spike

This spike validates Keycloak 26.7.2 with Authlib 1.7.2 in two deliberately
different flows. A browser uses an opaque, host-bound Django BFF session cookie;
the confidential BFF performs Authorization Code + PKCE S256 and keeps OAuth
access, refresh, and ID tokens in a PostgreSQL-backed server session. A simulated
native public client uses an external system browser and Authorization Code +
PKCE S256, then presents its access token to a bearer-protected API endpoint.

The browser application and its BFF/API are intended to be same-origin. There is
no wildcard CORS configuration and no browser token storage. Browser API routes
use session authentication; the mobile route independently requires a validated
bearer token with the `omnilyzer-api-spike` audience.

## Security design

The session cookie is `__Host-omnilyzer_session`, `Secure`, `HttpOnly`, host-only,
path `/`, and `SameSite=Lax`. `Lax` supports OIDC navigation when Keycloak and the
product are cross-site; it does not replace CSRF protection. Django CSRF
middleware protects writes, with a secure, host-only, path `/`, `SameSite=Lax`
CSRF cookie. `SameSite=Strict` is preferred later if the final domains allow it
without breaking OIDC navigation.

Sessions live in PostgreSQL 16.15 through Django's database session backend.
The migration owner owns the database, schema, and session table. Normal runtime
uses a non-owner role with only session-table data privileges. This initially
provides opaque, revocable, server-side state shareable by multiple application
nodes without requiring Redis. It is not a scale or failover result.

Stable application identity is the pair OIDC `issuer + sub`; email is profile
data, not an immutable key. Responsibilities remain:

```text
Keycloak                -> authentication / identity
Omnilyzer application   -> Workspace membership, roles, permissions,
                           and product authorization
PostgreSQL RLS          -> tenant isolation defense in depth
```

The synthetic realm is an identity boundary, not a Workspace. The spike creates
no Workspace realms, membership claims, or product roles.

## Run

From the repository root, with Python 3.12 and the existing `.venv`:

```bash
spikes/authentication/scripts/init-postgres.sh
spikes/authentication/scripts/start-keycloak.sh
cd spikes/authentication
../../.venv/bin/python manage.py migrate --database=migration --noinput
scripts/init-postgres.sh --grant-runtime
../../.venv/bin/python scripts/run-tests.py
cd ../..
spikes/authentication/scripts/stop-all.sh
```

The Keycloak script runs exactly `quay.io/keycloak/keycloak:26.7.2`, binds only
`127.0.0.1:18080`, imports the realm, and waits for discovery. It creates admin,
BFF, and test-user credentials in `/tmp/omnilyzer-auth-spike-runtime.env` with
mode `0600`; committed files contain placeholders only. Cleanup removes the
container and runtime secret file and stops PostgreSQL.

`start-dev` and Keycloak's development persistence are solely for this isolated
spike. They are not the production Keycloak architecture.

## Boundaries and limitations

Future React Native/Expo work should use an external browser, Authorization Code,
PKCE S256, the exact public-client redirect, and secure OS token storage. Claimed
HTTPS App Links/Universal Links should be preferred where feasible. The fallback
private-use scheme is reverse-domain based. Expo AuthSession, deep-link ownership,
iOS Keychain, Android Keystore/SecureStore, and app-store builds remain untested.

This protocol spike does not validate production Keycloak clustering or database
topology, backups, disaster recovery, upgrades, HA, MFA, passkeys, federation,
social login, SMTP recovery, multi-product SSO, or production secret rotation.
Coordinated IdP logout remains implementation work. It also does not prove 100k
session performance, cleanup throughput, database failover, or production
horizontal scale.
