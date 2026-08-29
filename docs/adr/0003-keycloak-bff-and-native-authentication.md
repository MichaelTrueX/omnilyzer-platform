# ADR 0003: Keycloak Authentication with Browser BFF Sessions and Native PKCE

- Status: Accepted
- Date: 2026-08-29

## Context

Omnilyzer needs one standards-based identity architecture supporting authenticated browser products, future native iOS and Android applications, multiple independent products, strong separation between authentication and product/Workspace authorization, and horizontally shareable browser sessions without requiring Redis.

Task 004 validated with real Keycloak 26.7.2 and Authlib 1.7.2:

- OIDC discovery;
- a confidential browser BFF client;
- Authorization Code + PKCE S256;
- state and nonce validation;
- server-side token exchange;
- PostgreSQL-backed Django browser sessions;
- a Secure, HttpOnly, host-bound session cookie;
- CSRF enforcement;
- session fixation protection;
- server-side refresh;
- local logout;
- a public native client;
- native Authorization Code + PKCE S256 without a client secret;
- exact native redirects and wrong-verifier rejection;
- signed access-token, issuer, and API-audience validation;
- ID-token rejection as an API bearer.

Reference evidence:

- [`spikes/authentication/README.md`](../../spikes/authentication/README.md)
- [`authentication-validation.md`](../../spikes/authentication/results/authentication-validation.md)

## Options considered

### Keycloak + OIDC/OAuth

Selected. Keycloak provides authentication and identity-provider functionality using open standards, while Omnilyzer retains application authorization.

### Browser-held OAuth tokens

Not selected. Access and refresh tokens must not be deliberately exposed to authenticated browser JavaScript or persisted in `localStorage`, `sessionStorage`, or IndexedDB.

### Browser BFF with server-side session

Selected. The browser holds only an opaque application session identifier.

### Native confidential client

Not selected. Installed native applications cannot safely maintain a client secret.

### Native public client + Authorization Code + PKCE

Selected. Native clients use an external browser and PKCE S256.

### Password grant / implicit flow

Not selected and prohibited for normal Omnilyzer authentication.

## Decision

1. Keycloak is the default Omnilyzer identity provider.
2. OpenID Connect/OAuth 2 Authorization Code flow is the default interactive authentication protocol.
3. PKCE S256 is mandatory for browser BFF and native authorization flows.
4. Browser applications use a confidential BFF client.
5. OAuth access tokens, refresh tokens, and ID tokens remain server-side for browser applications.
6. Browser JavaScript must not deliberately persist OAuth tokens in `localStorage`, `sessionStorage`, or IndexedDB.
7. Browser authentication uses an opaque host-bound application session cookie.
8. The initial server-side session store is PostgreSQL through Django's database-backed session mechanism. Redis is not mandatory.
9. Browser session cookies must be Secure, HttpOnly, host-only, and use path `/`.
10. `SameSite=Lax` is the default when cross-site IdP navigation requires it. `SameSite=Strict` may be used when deployment topology permits it without breaking authentication.
11. SameSite does not replace CSRF protection. State-changing browser requests require Django CSRF protection.
12. Successful authentication must rotate the application session identifier to prevent session fixation.
13. Native applications use a public OAuth client with no client secret.
14. Native authorization uses the external system browser and Authorization Code + PKCE S256.
15. Native redirect URIs must be exact and non-wildcard. Claimed HTTPS, App Links, or Universal Links are preferred where feasible; reverse-domain private-use schemes are allowed when necessary.
16. Native OAuth tokens must eventually be stored in secure OS facilities. Actual iOS and Android secure-storage implementation remains to be validated.
17. Stable external identity is the tuple `issuer + sub`.
18. Email address is profile data and must not be treated as the immutable identity key.
19. API bearer authentication uses OAuth access tokens, not ID tokens.
20. Bearer-token validation must require a cryptographic signature, trusted issuer, intended Omnilyzer API audience, expiration, applicable not-before validation, and an explicit accepted algorithm set.
21. Keycloak is responsible for authentication and identity.
22. Omnilyzer application data remains responsible for Workspace membership, roles, permissions, and product authorization.
23. PostgreSQL RLS remains tenant-isolation defense in depth and is not replaced by Keycloak.
24. Do not create one Keycloak realm or database role per Workspace.
25. Implicit flow and Resource Owner Password Credentials/password grant are prohibited for normal Omnilyzer authentication.
26. Runtime secrets, OAuth client secrets, and identity-provider credentials must remain outside committed source control.
27. Production browser redirect URIs must use HTTPS.

```text
                         Keycloak
                            |
                     OIDC / OAuth
                   _________|_________
                  |                   |
            Browser BFF           Native app
                  |                   |
       opaque session cookie      public client
                  |              Code + PKCE
        server-side tokens             |
                  |                     |
                  +----------+----------+
                             |
                     Omnilyzer backend
                             |
            application authorization
                             |
                         Workspace
                             |
                      PostgreSQL RLS
```

## Token-at-rest requirement

The Task 004 spike proves that browser OAuth tokens can remain server-side in PostgreSQL-backed session state.

It does not establish ordinary Django database-session serialization as the final production protection mechanism for long-lived OAuth refresh tokens. Production implementation must explicitly design and review protection for sensitive OAuth token material at rest. Possible implementation mechanisms are outside this ADR and are not selected here. PostgreSQL session storage alone must not be treated as providing encryption at rest.

## Signing-key rotation requirement

The spike validated trusted JWKS signature verification. Production implementation must handle normal Keycloak signing-key rotation without requiring indefinite use of process-start cached keys. A token referencing a newly trusted provider key should cause controlled metadata/JWKS refresh rather than permanently failing until application restart. This ADR does not design the final caching mechanism.

## Session lifecycle requirement

Production implementation must explicitly define:

- browser session maximum lifetime;
- idle lifetime if used;
- OAuth refresh behavior;
- failure behavior when refresh is rejected;
- IdP/session revocation handling;
- local logout;
- coordinated Keycloak logout where required;
- expired-session cleanup;
- security-event-driven invalidation where required.

Task 004 validated local refresh and local logout, but not the complete production revocation lifecycle.

## Security implications

- OAuth tokens are credentials and must not be logged.
- Browser token exposure must remain prohibited.
- Client secrets must not be shipped to native applications.
- Redirect URIs must be exact and controlled.
- Browser authentication requires CSRF protection.
- Authorization response state and nonce must be validated.
- ID tokens are authentication assertions, not API bearer credentials.
- Application authorization occurs after authentication.
- A valid Keycloak identity does not automatically grant access to any Workspace.
- Runtime session compromise remains security-sensitive.
- Production Keycloak must use TLS.
- Production redirect URIs must use HTTPS except standards-appropriate native redirects.

## Consequences

Positive consequences:

- browser applications do not manage OAuth tokens;
- native applications follow the public-client OAuth security model;
- one identity provider can serve multiple products;
- authentication remains separate from Workspace authorization;
- PostgreSQL sessions permit multiple application nodes without mandatory Redis;
- standards-based flows reduce platform coupling.

Tradeoffs:

- the BFF adds server-side session and token lifecycle responsibility;
- Keycloak becomes critical identity infrastructure;
- PostgreSQL session load and cleanup need operational management;
- mobile secure storage and deep links still require platform-specific implementation;
- signing-key rotation needs robust JWKS refresh behavior;
- sensitive server-side token material needs explicit at-rest protection.

## Operational implications

This ADR does not validate:

- Keycloak clustering;
- Keycloak production PostgreSQL topology;
- HA or failover;
- Keycloak backups and restore;
- upgrades;
- disaster recovery;
- MFA;
- passkeys;
- federation;
- social login;
- SMTP or account recovery;
- multi-product SSO;
- production secret rotation;
- production session throughput;
- 100k concurrent sessions;
- actual Expo integration;
- App Links or Universal Links;
- iOS Keychain;
- Android Keystore or SecureStore.

These remain later implementation and operations validation.

## Migration/compatibility implications

- This is a new platform, so no legacy browser-token compatibility is required.
- Permanent browser OAuth-token storage in `localStorage` is not part of the new architecture.
- Products consume the platform authentication contract rather than inventing independent flows.
- Breaking changes to the identity/session contract require compatibility planning and, when architectural, a new ADR.
