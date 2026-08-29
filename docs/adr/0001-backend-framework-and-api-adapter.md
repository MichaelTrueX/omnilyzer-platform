# ADR 0001: Django Backend with Django Ninja API Adapter

- Status: Accepted
- Date: 2026-08-29

## Context

Omnilyzer Platform requires a reusable enterprise SaaS backend supporting:

- modular-monolith architecture;
- PostgreSQL;
- transactions;
- controlled migrations;
- Workspace-based authorization;
- future PostgreSQL RLS;
- future Keycloak/OIDC integration;
- generated OpenAPI contracts;
- browser and native clients;
- horizontal scaling;
- internal administration;
- long-term maintainability.

Task 002 validated Django 6.1 with PostgreSQL 16.15 and compared Django REST Framework 3.18.0 with Django Ninja 1.6.3 over the same models and application/service layer.

Reference evidence:

- [`spikes/api/README.md`](../../spikes/api/README.md)
- [`django-suitability.md`](../../spikes/api/results/django-suitability.md)
- [`comparison.md`](../../spikes/api/results/comparison.md)

## Options considered

### Django + Django Ninja

Selected. Shared Django services remain independent of the API adapter. The spike generated OpenAPI 3.1 and a TypeScript contract that validated successfully. Ninja required a smaller API-specific implementation than DRF in this spike, its direct Python typing is useful for API-first development, and it demonstrated security behavior equivalent to DRF under the tested contracts.

Its disadvantages are a younger ecosystem than DRF and somewhat more fragmented exception handling. PATCH omission/non-null semantics currently require a narrow pinned-version typing workaround. Framework upgrades therefore require regression testing.

### Django + Django REST Framework

Not selected as the default, but explicitly approved as a fallback. DRF has a mature ecosystem, explicit authentication, permission, and serializer abstractions, and a strong operational history.

The spike demonstrated more API-specific code, an additional `drf-spectacular` dependency for the required OpenAPI quality, and more parallel serializer/schema declarations.

### FastAPI

FastAPI is not rejected globally. No core-platform FastAPI comparison is required now because Django showed no material architectural blocker. FastAPI remains available for a future specialized service where independent deployment, high-concurrency network I/O, AI processing, streaming, or another measured requirement materially benefits from it. Introducing such a service requires a separate architecture decision.

### NestJS

NestJS is not selected or currently planned for the Omnilyzer core backend. Introducing a second primary backend language/runtime without a demonstrated requirement would increase platform complexity. This decision may be reopened only if a concrete future requirement justifies it.

## Decision

1. Python is the primary server-side language for Omnilyzer Platform.
2. Django is the core backend framework.
3. Django Ninja is the default HTTP API adapter.
4. Domain/application logic must remain independent of Django Ninja-specific delivery code.
5. Django REST Framework remains an approved fallback where a concrete requirement materially benefits from its ecosystem or abstractions.
6. FastAPI may be considered for independently justified specialized services, not as a competing default core backend.
7. NestJS is not currently planned for the core backend.
8. PostgreSQL remains the primary datastore.
9. This ADR does NOT accept the proposed tenancy/RLS/authentication/deployment designs; those remain subject to their respective validation work.

The API framework choice must not become the domain architecture. The intended dependency direction is:

```text
HTTP/API
   |
Django Ninja
   |
application/services
   |
Django ORM
   |
PostgreSQL
```

The application/service layer must not depend on Ninja request objects, schemas, routers, or authentication classes.

## Consequences

Positive consequences:

- one primary Python backend ecosystem;
- strong Django migrations, ORM, admin, and security foundation;
- a typed API-first contract;
- OpenAPI and TypeScript client generation;
- a replaceable API adapter;
- avoidance of unnecessary FastAPI or NestJS core-framework work.

Negative consequences and tradeoffs:

- Django synchronous transactions remain a constraint;
- Ninja's ecosystem is smaller than DRF's;
- Ninja upgrades require contract, authentication, error, and PATCH regression testing;
- specialized asynchronous or long-running work may eventually require background workers or dedicated services.

Neutral consequences:

- this decision does not imply that all workloads must execute synchronously;
- this decision does not mandate Django Ninja for every future independently justified service.

## Security implications

Authentication remains separate from Workspace authorization. API adapters authenticate and translate delivery credentials, while application services enforce authorization. Future PostgreSQL RLS remains defense in depth below application authorization.

This ADR accepts no browser OAuth or session-token architecture. Normalized errors must avoid information leakage. Framework upgrades must retain security regression testing, and production dependencies require normal vulnerability and provenance review.

## Operational implications

Django nodes are intended to be horizontally scalable and stateless except for externalized state. PostgreSQL is shared infrastructure, and migrations require controlled deployment sequencing. Django admin is for trusted internal administration only, never product end-user UX. Framework and version upgrades require CI regression testing of API contracts and generated client types.

## Migration and rollback implications

There is no production migration because the platform has not yet been built on this foundation. Products should depend on platform APIs and services rather than Ninja internals. Keeping domain logic outside the API adapter preserves the ability to replace Ninja if required.

Breaking API changes require versioned API contracts such as `/api/v2`. A future framework replacement requires its own ADR and compatibility and migration plan.
