<!--
File: docs/architecture/platform-principles.md
Purpose: Defines durable engineering principles for the Omnilyzer Platform.
Related:
- docs/architecture/technology-decisions.md
- docs/architecture/security-model.md
- docs/architecture/deployment-model.md
-->

# Platform Principles

These principles constrain architecture and implementation across platform capabilities and consuming products.

## Trust, safety, and inclusion

- **Security by design:** define assets, threats, trust boundaries, and controls before implementation; verify controls continuously.
- **Privacy by design:** minimize collection and retention, limit processing to stated purposes, and support applicable data-subject rights.
- **Workspace isolation:** treat `Workspace` as the tenant security boundary and test every data path for cross-Workspace exposure.
- **Least privilege:** grant people, services, and database roles only the access required for their current responsibility.
- **Defense in depth:** combine application authorization, database enforcement, secure deployment, and monitoring so one control failure is not sufficient for compromise.
- **Accessibility:** target WCAG 2.2 AA across supported user experiences and include accessibility in design, implementation, and verification.

## Product and interface boundaries

- **API-first and mobile-ready:** define stable contracts and domain concepts usable by web, iOS, Android, and integrations without coupling them to one UI.
- **Independent product deployments:** a product failure or upgrade must not automatically affect another product.
- **Versioned platform dependencies:** consumers select and upgrade explicit platform versions; source is not copied between repositories.
- **Backward compatibility:** evolve public contracts compatibly by default. Breaking changes require explicit approval and a transition plan.
- **Clean architecture boundaries:** isolate domain policy from delivery frameworks, storage mechanisms, and provider-specific behavior.
- **Provider abstractions:** products use platform integration contracts rather than external provider SDKs directly.
- **Reusable design system:** govern styling and interaction primitives centrally while allowing product branding and platform-appropriate web/native implementation.

## Delivery and operation

- **Immutable deployments:** build once, promote the same artifact, and prohibit source editing in deployed environments.
- **Controlled migrations:** plan, test, observe, and make migrations reversible where feasible; use expand/migrate/contract for incompatible data changes.
- **Observability:** produce actionable structured telemetry and audit evidence without exposing secrets or sensitive data.
- **No unnecessary infrastructure:** add services only for demonstrated requirements and understood operational costs. Modular monoliths are the default; microservices and Kubernetes require real boundaries or scale evidence.
- **Explicit ownership:** every file, component, capability, and operational responsibility must have a maintained purpose and accountable owner.
- **No orphan files:** remove or migrate superseded assets and update every affected relationship.

## Engineering quality

- **Testability:** design deterministic boundaries and support automated verification of behavior, security, compatibility, and migrations.
- **Professional maintainability:** favor clear terminology, cohesive modules, documented contracts, simple operations, and changes reviewable by professional developers.
- **Equal standards for generated work:** AI-generated code and documentation must meet the same design, security, test, review, and maintenance standards as human-created work.
