<!--
File: docs/architecture/security-model.md
Purpose: Defines platform security boundaries, candidate identity flows, and baseline controls.
Related:
- docs/architecture/tenancy-model.md
- docs/architecture/deployment-model.md
- SECURITY.md
-->

# Security Model

## Boundaries and responsibility

The platform uses a zero-trust mindset between Workspace boundaries: identity, network location, prior access, or possession of an identifier does not establish access to another Workspace. Every request must authenticate its actor where required, resolve an explicit Workspace context, authorize the action, and enforce data isolation. Application authorization and PostgreSQL RLS are planned as independent layers.

Authentication establishes identity and session assurance. Authorization determines whether that identity may perform a specific product action in a specific Workspace. Keycloak is a **TO VALIDATE** primary identity-provider candidate; product roles and permissions remain owned by product/platform authorization models rather than being inferred solely from identity-provider groups.

## Candidate authentication flows

- OAuth 2 / OpenID Connect Authorization Code with PKCE is **TO VALIDATE** for browser and native authorization flows.
- A browser BFF/server-session model using secure, HttpOnly cookies and initially PostgreSQL-backed session state is **TO VALIDATE**. Authenticated web should be strict same-origin where practical to reduce cross-origin exposure.
- Browser flows must use appropriate `Secure`, `HttpOnly`, and `SameSite` cookie policy, explicit CSRF protection for state-changing requests, narrow origins, and rotation after privilege changes.
- Native clients must store credentials only in operating-system secure credential storage. Tokens must not be persisted in general application storage, logs, analytics, or crash reports.
- CORS must be minimized to known origins and methods; it is not an authorization control. Content Security Policy must restrict executable and embedded content with a deployment-appropriate, tested policy.

The authentication spike must validate login, logout, expiry, renewal, session revocation, device/session visibility, lost-device response, account recovery, and multi-product behavior. MFA and passkeys are required capabilities to assess, including enrollment, recovery, step-up authentication, and accessible fallback paths.

## Authorization and database enforcement

Authorization defaults to deny and evaluates the actor, Workspace, product role/permission, resource, and action. Identifiers supplied by clients never establish ownership. Elevated support and administration access must be explicit, time-bounded where possible, and audited.

Runtime database roles must not own application schemas, use superuser privileges, carry `BYPASSRLS`, or otherwise bypass RLS. Migration ownership and runtime access must use separate roles. Connection reuse must not leak Workspace context; fail-closed setup and reset behavior must be proven in the tenancy spike.

## Operational controls

- Record tamper-resistant, access-controlled audit events for authentication, authorization decisions of security significance, administrative changes, sensitive exports, integration credentials, and Workspace-boundary operations.
- Never log passwords, tokens, session secrets, private keys, provider credentials, or unnecessary personal data. Define structured redaction and retention rules.
- Store secrets outside Git in an approved secret-management mechanism, scope them narrowly, rotate them, and audit access. No production credentials may be used in spikes.
- Pin and inventory dependencies, review licenses and provenance, scan artifacts, evaluate vulnerabilities by exploitability and severity, and apply timely updates through reviewed immutable builds.
- Prohibit production source editing, interactive development on PROD, and uncommitted production source. Production changes arrive only as promoted immutable artifacts.

Security controls require threat modeling, automated tests, review, monitoring, incident response, and periodic recovery exercises. Compliance requirements must be translated into explicit controls rather than treated as labels.
