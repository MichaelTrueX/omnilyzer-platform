<!--
File: docs/architecture/integration-model.md
Purpose: Defines provider-neutral platform boundaries for communications and external integrations.
Related:
- docs/architecture/platform-principles.md
- docs/architecture/security-model.md
- docs/architecture/tenancy-model.md
-->

# Integration Model

Products depend on versioned platform contracts, not directly on provider SDKs such as Twilio, Amazon SES, Microsoft Graph, SendGrid, or Firebase Cloud Messaging. Provider adapters implement platform-owned interfaces and remain replaceable without changing product domain logic.

## Notification capabilities

The platform abstraction must support email, SMS, push, and in-app notifications through a common delivery model while retaining channel-specific capabilities. It must define:

- Workspace- and user-aware notification preferences, lawful-purpose/consent rules, suppression, and mandatory-message policy;
- versioned templates with typed inputs, safe rendering, localization, locale fallback, and accessible content;
- delivery status with provider-neutral states plus retained diagnostic detail;
- retry policies, deduplication, idempotency keys, rate limits, expiry, and poison-message handling;
- provider routing and controlled failover without exposing provider concepts to product code.

## External integrations

Platform contracts must cover outbound REST APIs, OAuth integrations, outgoing webhooks, incoming webhooks, and file/object-storage adapters. Contracts define authentication, timeouts, retry eligibility, idempotency, pagination, rate limiting, version negotiation, error translation, and observability.

Outgoing webhooks require signed requests, replay resistance, stable event identifiers, delivery history, endpoint disablement, and secret rotation. Incoming webhooks require signature verification, timestamp/replay checks, strict parsing, idempotent processing, source allowlisting where useful, and safe failure responses. OAuth adapters must minimize scopes, protect state and redirect URIs, encrypt refresh credentials, handle revocation, and keep provider-specific claims outside product authorization.

File/object-storage adapters must define Workspace ownership, authorization, content/type limits, malware scanning policy, encryption, retention, deletion, integrity, and safe download behavior. A storage locator alone never grants access.

## Credentials and auditability

Provider credentials belong in an approved secret store, never Git, product configuration payloads, URLs, logs, or client applications. Scope credentials by environment, provider, capability, and preferably Workspace where the integration is Workspace-managed. Support rotation without source changes.

Record auditable configuration and delivery events with actor, Workspace, operation, outcome, correlation identifier, and safe provider metadata. Logs must redact message bodies, credentials, tokens, signatures, and sensitive personal data by default. Provider replacement, degradation, and recovery must be testable through adapter contract tests and controlled failure simulations.
