<!--
File: docs/architecture/technology-decisions.md
Purpose: Records accepted, provisional, and rejected technology directions and validation needs.
Related:
- docs/adr/README.md
- spikes/README.md
- docs/architecture/platform-principles.md
-->

# Technology Decisions

Status labels in this document are deliberate: **ACCEPTED DIRECTION** constrains current planning, **TO VALIDATE** requires evidence before adoption, and **REJECTED / NOT CURRENTLY PLANNED** must not be introduced without reopening the decision through an ADR.

## Decision matrix

| Area | Candidate or direction | Status | Rationale | Validation needed |
|---|---|---|---|---|
| Platform architecture | Enterprise SaaS; modular monolith by default; API-first | ACCEPTED DIRECTION | Keeps boundaries explicit without premature distributed operations. | Validate boundary enforcement through later implementation reviews. |
| Backend | Python + Django 6 | TO VALIDATE | Candidate integrated foundation for domain, data, administration, and security capabilities. | Confirm version availability/support, modular boundaries, async constraints, security behavior, and operational fit; compare with FastAPI and NestJS. |
| Backend alternatives | FastAPI; NestJS | TO VALIDATE | Credible API-focused alternatives to Django with different ecosystems and operational tradeoffs. | Compare representative API implementation, authorization, validation, performance, maintainability, ecosystem, and packaging. |
| API framework | Django REST Framework vs Django Ninja | TO VALIDATE | Both can expose Django-backed APIs with different maturity, typing, and ergonomics. | API spike covering contracts, validation, errors, authorization, OpenAPI, testability, and performance. |
| Primary data store | PostgreSQL | ACCEPTED DIRECTION | Relational integrity, transactional behavior, and mature security features suit core platform data. | Validate the proposed tenancy and queue uses independently. |
| Tenancy | Shared schema with `workspace_id` | TO VALIDATE | Offers a consistent model and simpler fleet management than schema-per-Workspace. | Cross-Workspace tests, uniqueness rules, migration behavior, query ergonomics, and operational scale. |
| Database isolation | PostgreSQL Row-Level Security (RLS) | TO VALIDATE | Adds database enforcement beneath application authorization. | Verify fail-closed policies, connection context, pooling, privileged roles, migrations, background jobs, and attack tests. |
| Identity | Keycloak | TO VALIDATE | Open-source identity provider candidate with OIDC and federation capabilities. | Lifecycle, upgrade, recovery, MFA/passkeys, multi-product SSO, tenancy mapping, operations, and exit strategy. |
| Identity protocols | OAuth 2 / OpenID Connect Authorization Code + PKCE | TO VALIDATE | Candidate standards-based flow suitable for public clients and browser mediation. | Threat model and working browser/native flows, logout, rotation, revocation, and recovery. |
| Browser authentication | BFF/server session, secure HttpOnly cookie, PostgreSQL-backed state | TO VALIDATE | Reduces browser token exposure and permits horizontally shared sessions without mandatory Redis. | CSRF/CSP behavior, refresh/revocation, latency, cleanup, failure handling, and horizontal tests. |
| Public web | Next.js + React + TypeScript | TO VALIDATE | Candidate for public, SEO-sensitive websites. | Rendering, caching, accessibility, content workflow, deployment, security headers, and versioning. |
| Authenticated web | React + Vite + TypeScript | TO VALIDATE | Candidate focused application stack without coupling authenticated products to public-site rendering. | BFF integration, contracts, build outputs, accessibility, design-system consumption, and testing. |
| Native mobile | React Native + Expo + TypeScript | TO VALIDATE | Candidate for iOS and Android while sharing contracts and domain concepts. | Secure OAuth storage/redirects, native capabilities, accessibility, updates, store builds, and design-system fit. |
| Design tokens | DTCG-compatible shared semantic token source + Style Dictionary | TO VALIDATE | Could provide platform-neutral token semantics and generated web/native outputs. | Token schema, transformations, versioning, theming, visual regression, and consumer upgrade behavior. |
| Web components | Tailwind constrained by platform abstractions; Radix primitives | TO VALIDATE | Candidates for efficient styling and accessible low-level behavior without arbitrary product CSS. | Escape-hatch governance, accessibility, bundle/runtime costs, theming, and API stability. |
| Background jobs | Django Tasks abstraction + PostgreSQL-backed production queue initially | TO VALIDATE | Could avoid premature queue infrastructure while retaining an abstraction boundary. | Delivery semantics, locking, retries, idempotency, scheduling, observability, throughput, and recovery. |
| Deployment artifact | OCI containers | TO VALIDATE | Portable immutable artifact candidate supported by multiple runtimes. | Reproducible builds, provenance, scanning, promotion, configuration, rollback, and multi-architecture needs. |
| Initial orchestration | Docker Compose or similarly simple orchestration; Nginx proxy | TO VALIDATE | Minimizes initial operational complexity. | Availability, zero/low-downtime deployment, TLS boundary, scaling, logging, and recovery. |
| Backup and PITR | pgBackRest | TO VALIDATE | Mature PostgreSQL-focused backup and point-in-time recovery candidate. | Encrypted backup, retention, restore drills, RPO/RTO, monitoring, and provider portability. |
| Platform distribution | Separate versioned repository/packages consumed by independent product repositories | TO VALIDATE | Supports independent releases and avoids source copying. | Packaging spike with dummy products, compatibility policy, release provenance, rollback, and private/public registry options. |

## Other accepted directions

- `Workspace` is the tenant security boundary, with personal and organization Workspace types; users may belong to multiple Workspaces.
- Authentication and product-specific authorization are separate. Tenant isolation is strict.
- Public web and authenticated application surfaces are separate. Responsive web plus native iOS and Android are required.
- DEV, STAGING, and PROD are separate stages using pull requests and immutable releases; eventual horizontal scaling is required.
- Open-source and permissively licensed technology is preferred. Hosted GitHub and Cloudflare services are allowed, with vendor lock-in minimized.
- Security, auditability, privacy, compliance, and WCAG 2.2 AA are architectural concerns. Designs must accommodate relevant EU, US, and Asian regulation, including GDPR and Valoria data concerning minors or students.

## Rejected or not currently planned

- Evolving legacy Bisma or SHSLearningStudio into this platform, or importing other legacy implementation code.
- One global public Workspace for all consumer users.
- Schema-per-Workspace as the default.
- Microservices by default or Kubernetes at initial scale.
- Redis as a mandatory session store or memory-only sessions that prevent horizontal scaling.
- Permanent browser-token storage in `localStorage`.
- Manual copying or synchronization of platform source between products.
- Direct production source editing.
- Arbitrary per-product CSS systems.
- A large third-party SaaS boilerplate as the platform core.

Each validated major choice must be recorded through the [`ADR process`](../adr/README.md); a successful spike does not change status by itself.
