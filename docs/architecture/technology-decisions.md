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
| Backend | Python + Django 6 | ACCEPTED DIRECTION | Task 002 validated Django as the core backend foundation with PostgreSQL, transactions, migrations, application-service separation, security extension points, admin, OpenAPI adapters, and horizontally scalable topology. | Validate remaining authentication, deployment, background-work, and production-scale concerns independently; routine Django version upgrades remain subject to regression testing. |
| Backend alternatives | FastAPI for independently justified specialized services; NestJS not currently planned for core | ACCEPTED DIRECTION | Django showed no material core-platform blocker; maintaining multiple primary backend stacks without a demonstrated need would add complexity. FastAPI remains available when a specialized workload has a measured requirement. | Any specialized service or reopening of the core-stack decision requires its own evidence and ADR. |
| API framework | Django Ninja default; Django REST Framework approved fallback | ACCEPTED DIRECTION | Task 002 demonstrated equivalent behavioral/security contracts while Ninja provided a smaller type-led adapter and successful OpenAPI 3.1 to TypeScript generation. DRF remains the mature fallback. | Ninja upgrades must regression-test API behavior, generated OpenAPI/TypeScript, authentication/error behavior, and the PATCH omission/non-null workaround; concrete requirements may justify DRF. |
| Primary data store | PostgreSQL | ACCEPTED DIRECTION | Relational integrity, transactional behavior, and mature security features suit core platform data. | Validate the proposed queue use independently. |
| Tenancy | Shared schema with `workspace_id` | ACCEPTED DIRECTION | Task 003 validated shared-schema Workspace isolation across ORM, raw SQL, joins, aggregates, bulk operations, and connection reuse. | Final domain-model coverage, operational scale, and migration procedures remain implementation concerns. |
| Database isolation | PostgreSQL Row-Level Security (RLS) | ACCEPTED DIRECTION | Task 003 validated RLS with `FORCE ROW LEVEL SECURITY`, a non-owner `NOBYPASSRLS` runtime role, transaction-local Workspace context, fail-closed missing context, and cross-Workspace read/write isolation. | Validate external connection poolers, privileged and data migration procedures, the production credential lifecycle, and operational monitoring. |
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

Each validated major choice must be recorded through the [`ADR process`](../adr/README.md); a successful spike does not change status by itself. The accepted backend and API direction is recorded in [ADR 0001](../adr/0001-backend-framework-and-api-adapter.md), and the accepted tenancy and database-isolation direction is recorded in [ADR 0002](../adr/0002-workspace-tenancy-and-postgresql-rls.md).
