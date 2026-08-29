# Authentication validation result

## Evidence

- **Keycloak discovery:** Real Keycloak 26.7.2 discovery returned the exact
  configured issuer, protocol endpoints, JWKS URI, RP logout endpoint, and S256.
- **Browser authorization:** A real Keycloak Authorization Code login completed
  through the BFF with transaction state, nonce, and PKCE S256. Tampered state
  and callback replay failed closed.
- **Server-side tokens:** Access, refresh, and ID tokens were present in the
  PostgreSQL session and absent from browser JSON, URLs, redirects, and cookies.
- **Cookie configuration:** The opaque `__Host-omnilyzer_session` cookie was
  Secure, HttpOnly, host-only, path `/`, and SameSite Lax.
- **Session fixation:** The successful callback rotated the session identifier;
  the pre-login identifier neither matched nor authenticated.
- **Session persistence:** A fresh Django client loaded the authenticated session
  from PostgreSQL using only the opaque cookie.
- **CSRF:** Missing-token and hostile-Origin writes were rejected; the correct
  Django CSRF token succeeded.
- **Refresh and logout:** One real Keycloak refresh updated server-side token
  state without browser exposure. CSRF-protected logout removed the local session
  and invalidated the old cookie. Coordinated IdP logout is still future work.
- **Native authorization:** A simulated public native client completed a separate
  real Keycloak Authorization Code + PKCE S256 exchange without a client secret.
  A distinct code exchanged with a wrong verifier was rejected.
- **Redirect validation:** The exact reverse-domain private-use redirect worked;
  an unregistered redirect was rejected and no wildcard is configured. Claimed
  HTTPS links should be preferred later where feasible.
- **Bearer validation:** Authlib verified the access-token RS256 signature,
  issuer, expiration/not-before, and `omnilyzer-api-spike` audience from trusted
  discovery/JWKS. Missing, malformed, tampered, and ID-token bearers were rejected.
- **Authentication boundary:** Browser routes use database-backed BFF sessions;
  the native route uses bearer validation. Neither mechanism substitutes for the
  other.
- **Authorization boundary:** Keycloak supplies authentication/identity.
  Omnilyzer owns Workspace membership, roles, permissions, and product
  authorization; PostgreSQL RLS remains tenant-isolation defense in depth.

## Limitations

This validates protocol and application architecture, not production Keycloak
clustering/PostgreSQL, backups, disaster recovery, upgrades, HA, MFA, passkeys,
federation, social login, email recovery, multi-product SSO, or secret rotation.
It does not validate Expo/mobile link handling or secure OS storage. PostgreSQL
session load, cleanup, failover, 100k concurrency, and production horizontal
capacity remain deployment/performance work. Development-mode Keycloak and its
development persistence are not production architecture.

## Recommendation

adopt
