<!--
File: spikes/api/results/django-suitability.md
Purpose: Answers the Task 002 Django foundation questions from reproducible evidence.
Related:
- spikes/api/README.md
- spikes/api/results/comparison.md
- docs/architecture/technology-decisions.md
-->

# Django suitability assessment

Outcome: **Django passed the Task 002 acceptance criteria as a candidate foundation.**
This is evidence for human review, not an accepted architecture decision.

## 1. Does Django introduce a material architectural blocker?

No blocker was found in the tested scope. Django 6.1 provided PostgreSQL ORM integration,
constraints/indexes, transactions, schema migrations, admin, middleware/security
settings, WSGI and ASGI entry points, test database isolation and clean boundaries around
two API adapters. All 26 final PostgreSQL tests passed.

This is conditional evidence. RLS, real OIDC, audit events, background work, production
deployment and alternatives remain unvalidated.

## 2. Can Django support stateless/horizontally scalable API nodes?

Yes architecturally. The API modules keep no mutable process-local user or tenant state.
Nodes can share PostgreSQL and externalized configuration. Browser state can use Django's
database-backed session engine, whose cookie carries a session identifier rather than
the session data
([Django session documentation](https://docs.djangoproject.com/en/6.0/topics/http/sessions/)).
Mobile bearer requests can remain stateless. Multiple WSGI/ASGI workers and nodes can be
placed behind a load balancer.

This spike did not deploy multiple nodes or measure connection-pool/session behavior.
Production must avoid local-memory session/cache assumptions, size database connections,
coordinate migrations, externalize uploads and telemetry, and validate graceful
shutdown/readiness.

## 3. Can Django separate API, services, domain logic and persistence?

Yes. DRF and Ninja depend on `domain.services`; services depend on the principal,
domain exceptions and Django models; models own persistence mapping. The domain service
module has no delivery-framework imports. The same transaction and authorization logic
passed through both adapters. This demonstrates a workable modular-monolith boundary,
although the experiment's models remain ORM-aware rather than persistence-agnostic.

## 4. Can Django support future PostgreSQL RLS?

No blocker is apparent, but Task 002 does not validate RLS. Django uses native PostgreSQL
connections, can execute parameterized SQL, and migrations support reversible
`RunSQL` for database features not modeled directly
([Django migration operations](https://docs.djangoproject.com/en/6.1/ref/migration-operations/)).
A request/transaction boundary could set fail-closed Workspace context before ORM
queries, leaving API adapters unchanged.

Task 003 must prove non-owning/non-`BYPASSRLS` runtime roles, policy correctness,
`SET LOCAL` or equivalent context lifecycle, connection reuse/reset, background jobs,
admin/migration roles, raw SQL, missing context and attack cases. Application filtering
here is not RLS evidence.

## 5. Can Django support Keycloak/OIDC without domain coupling?

Yes at the boundary-design level. The test authenticator converts delivery credentials
and Workspace context into `RequestPrincipal`; services know nothing about headers,
sessions, JWTs, Keycloak or either API framework. DRF authentication classes, Ninja auth
callables and Django's pluggable authentication mechanisms provide replacement points.
Django documents extensible authentication backends and request authentication
([Django authentication documentation](https://docs.djangoproject.com/en/6.1/topics/auth/default/)).

Real issuer discovery, JWT signature/audience/expiry, claim mapping, key rotation,
revocation, logout, recovery and Keycloak operations remain Task 004 work.

## 6. Can browser BFF sessions and mobile bearer APIs coexist?

Yes architecturally. A BFF/session middleware can resolve a server-side Django session;
a DRF/Ninja bearer authenticator can resolve a mobile token. Both produce the same
principal and call the same authorization services. Routing or authenticator selection
can keep CSRF-protected cookie requests distinct from bearer requests.

The spike did not implement this coexistence. The auth spike must prove CSRF,
`Secure`/`HttpOnly`/`SameSite` cookies, session rotation/revocation, PKCE, secure
mobile storage, CORS/origin policy and error behavior.

## 7. Are Django migrations appropriate for enterprise schema evolution?

Yes, with normal operational discipline. Evidence includes a generated initial migration,
clean-database bootstrap and usable ORM, a generated optional-column migration, forward
apply, direct schema inspection and successful targeted rollback. Django also supports
data and custom SQL operations.

The framework does not make risky changes safe automatically. Production requires
expand/migrate/contract, compatible mixed-version windows, rehearsal, backup/restore,
lock and table-rewrite analysis, observability, reversible data steps where feasible and
separate migration ownership. `results/migration-validation.md` records the experiment.

## 8. Is Django admin valuable without becoming end-user UX?

Yes. Minimal registration immediately provided model-centric Workspace and Project
inspection, search and filters suitable as a starting point for trusted support and
audit investigation. Django explicitly recommends admin for internal management, not an
entire front end
([Django admin documentation](https://docs.djangoproject.com/en/6.0/ref/contrib/admin/)).

Admin access still needs dedicated staff identity, least privilege, Workspace-aware
controls, audit events, MFA/session policy and tests. Process-heavy support workflows
should use purpose-built internal views. Admin is not the HR or Valoria end-user UI.

## 9. Are Django's sync/async limitations material?

Not for the representative transactional CRUD path. Synchronous `transaction.atomic`
is clear and passed rollback tests. Django 6.1 has async views, an ASGI stack and async
ORM methods, but transactions do not yet work directly in async mode; transactional work
should remain one synchronous function called through a boundary when needed
([Django async documentation](https://docs.djangoproject.com/en/6.1/topics/async/)).

Ninja offers first-class async endpoint ergonomics; this spike did not prove first-class
DRF async support. Async can help concurrent external AI/integration calls or streaming,
but it does not replace a durable background-job system. HR and learning CRUD are not
materially blocked; long integrations, file processing and AI jobs need bounded request
I/O or later background work.

## 10. Is Django viable at initial scale and 100k+ registered-user scale?

Architecturally, yes; capacity remains unproven. Registered-user count is not concurrency.
The design can use horizontally replicated stateless API workers, PostgreSQL indexes and
constraints, connection pooling, database-backed shared sessions, caching only when
evidence warrants it, and separate background workers later. Nothing in the spike
requires node-local state or a single process.

The benchmark observed millisecond-scale same-process requests but cannot forecast
production throughput. Before a 100k+ claim, load tests must model active concurrency,
query plans/data volume, connection limits, hot Workspaces, session traffic, uploads,
integrations, background work, SLOs, failover and observability. Django passes
architectural viability, not capacity certification.

## Overall conclusion

Django satisfies the spike's foundation criteria for enterprise SaaS structure,
PostgreSQL, transactions, migrations, security extension points, maintainability,
testability, generated contracts and horizontal topology. Its most relevant constraint
is that transactional ORM workflows remain synchronous; this is manageable for the
expected core request types and should be isolated when async network fan-out is useful.

Recommendation: **adopt Django as the candidate foundation**, subject to human
architecture review and the remaining tenancy, authentication, alternatives, deployment,
background-work and production-scale evidence. Do not change the technology decision
status or create an accepted ADR from this report alone.
