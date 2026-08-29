<!--
File: spikes/api/README.md
Purpose: Records the Task 002 Django API framework validation spike and its evidence.
Related:
- spikes/api/results/comparison.md
- spikes/api/results/django-suitability.md
- spikes/README.md
-->

# Django API framework validation spike

This directory is a removable architecture experiment. It is not production code, and
its recommendations do not change any status in
`docs/architecture/technology-decisions.md`.

## Hypothesis

The spike tested two claims independently:

1. Django 6 can provide a maintainable, testable, transactional, PostgreSQL-backed,
   security-conscious foundation for a modular enterprise SaaS API without coupling
   application services to delivery frameworks, and without blocking future Workspace
   RLS, Keycloak/OIDC, audit, OpenAPI client, or horizontal-deployment work.
2. One of DRF or Django Ninja offers materially stronger default API ergonomics for the
   same domain and service layer, judged by validation, errors, schema quality, typing,
   authorization extension points, testing, maintenance, security, and non-pathological
   performance rather than by novelty or line count alone.

## Environment

Evidence was generated on 2026-08-28 with:

| Component | Exact version/configuration |
| --- | --- |
| OS | Ubuntu 24.04.3 LTS; Linux 6.8.0-101-generic x86_64 |
| Python | CPython 3.12.3 |
| pip | 26.0.1 |
| Django | 6.1 |
| Django REST Framework | 3.18.0 |
| Django Ninja | 1.6.3 |
| drf-spectacular | 0.30.0 |
| psycopg / psycopg-binary | 3.3.4 / 3.3.4 |
| PostgreSQL server/client | 16.15 / 16.15 |
| Test tools | Django 6.1 test runner and Python 3.12.3 `unittest.mock`; no pytest |
| Benchmark mode | DEBUG false, in-process WSGI test client, concurrency 1 |

The isolated PostgreSQL cluster lives under
`/tmp/omnilyzer-platform-api-spike-pgdata`, listens on no TCP address, and exposes only
the dedicated Unix socket and port 55434. Application settings use
`omnilyzer_api_spike_owner`, a non-superuser/non-role-admin role. It has `CREATEDB`
only so Django can create disposable test databases. The cluster bootstrap administrator
is never present in application settings. Local `trust` authentication is acceptable
only for this isolated, no-TCP, synthetic spike and is not a production recommendation.

### Dependency review

This review was recorded before installation. Exact transitive versions are in
`requirements-lock.txt`.

| Direct dependency | Purpose | License | Why built-ins are insufficient | Future production acceptability |
| --- | --- | --- | --- | --- |
| Django 6.1 | Web foundation, ORM, migrations, transactions, admin and security controls | BSD-3-Clause | Python has no equivalent integrated framework | Acceptable subject to architecture review |
| Django REST Framework 3.18.0 | First API adapter candidate | BSD-3-Clause | Django has no equivalent serializer/API toolkit | Acceptable if selected |
| Django Ninja 1.6.3 | Second API adapter candidate | MIT | Django has no equivalent type-driven router/schema toolkit | Acceptable if selected |
| drf-spectacular 0.30.0 | Precise DRF OpenAPI 3 generation | BSD-3-Clause | DRF's built-in generator is deprecated and insufficient for explicit response/error contracts | Acceptable, but it is an extra DRF-specific dependency counted in the comparison |
| psycopg 3.3.4 with binary extra | PostgreSQL driver | LGPL-3.0-only | Python and Django do not include a PostgreSQL wire driver | Acceptable in principle; production packaging must choose binary versus system-linked build deliberately |

Django's test runner replaces pytest, and the benchmark uses the Python standard
library. No unrelated service or tooling dependency was installed.

## Architecture

Both adapters call the same models, principal type, authorization decisions, exceptions,
and application services:

```text
DRF API ---------+
                 |
                 v
        domain services + synthetic principal
                 |
                 v
          Django ORM / transaction.atomic
                 ^
                 |
Ninja API -------+
```

`domain/services.py` documents and implements `create_project`, `get_project`,
`list_projects`, `update_project`, `archive_or_delete_project`, and the atomic
`create_workspace_with_first_project`. No shared-domain module imports DRF, Ninja, or
Pydantic.

The two adapters expose equivalent JSON behavior at:

- `/api/v1/drf/projects/` and `/api/v1/drf/projects/{id}/`
- `/api/v1/ninja/projects/` and `/api/v1/ninja/projects/{id}/`
- separate minimal `/api/v1/.../health/` endpoints

Both support list, create, retrieve, partial update, real delete, `status` and safe
`workspace_id` filtering, and deterministic `page/page_size/total/items` pagination.
Explicit `/api/v1/` routing allows a future `/api/v2/` adapter to coexist. Old mobile
clients can remain on v1 while compatible changes and security fixes continue; breaking
changes require a new route and an explicit support/deprecation window.

### Authentication and authorization extension point

`domain.auth.RequestPrincipal` contains only `actor_id` and resolved
`workspace_id`. The test-only resolver requires matching `X-Spike-Actor` and
`X-Workspace-ID`; it stores no token. DRF adapts it through `BaseAuthentication` plus
a permission, while Ninja adapts it through `APIKeyHeader`. Services receive the same
principal and perform resource authorization, so identity-provider code does not enter
domain operations.

A future browser BFF can construct the principal from a secure Django server session. A
mobile/integration adapter can construct it after bearer-token issuer, audience, expiry
and signature validation. Both can coexist as separate authenticators while sharing
authorization services. Keycloak and those real flows were not validated here.

### Workspace isolation simulation

Every Project queryset includes `workspace_id=principal.workspace_id`. Cross-Workspace
read, update, delete, relationship substitution, filter substitution, and identifier
guessing return the same opaque 404 as an unknown Project.

> This is not a substitute for the PostgreSQL RLS validation planned in Task 003.

### Transactions, migrations and admin

The shared atomic operation creates a Workspace and first Project. A second-insert
constraint failure rolled back the Workspace; the success case committed both.

Django generated `0001_initial.py` and the permanent database enum checks in
`0002_enum_value_constraints.py`. A clean database migrated and served ORM work. A
temporary optional field migration was generated, applied, inspected, rolled back, then
removed with its model change. See `results/migration-validation.md`. Production
migrations still require expand/migrate/contract sequencing, lock/runtime review,
backups, observability, and separate migration/runtime roles.

Workspace and Project have minimal admin registrations for trusted internal inspection,
search, filtering and support investigation. Django's own guidance describes admin as an
internal management tool, not an entire front end. It must not become the end-user HR or
Valoria UI.

### Async assessment

This implementation deliberately uses synchronous endpoints because representative CRUD
and transactional workflows are ORM-bound. Django 6.1 supports ASGI, async views and
async ORM methods, but transactions still require a synchronous function (or one
`sync_to_async` boundary), and persistent connections should be disabled for async mode
([Django async documentation](https://docs.djangoproject.com/en/6.1/topics/async/)).
Django Ninja directly supports sync and async operations
([Ninja async documentation](https://django-ninja.dev/guides/async-support/)). DRF 3.18's
core documentation and this spike provide no equivalent first-class async endpoint
evidence; adopting third-party async DRF extensions would be another dependency and
validation decision.

This difference is not material for ordinary HR workflows, learning requests, or short
database transactions. Async may help request concurrency for bounded upstream AI/API
fan-out, streaming, or file I/O, with cancellation/timeouts and an ASGI deployment.
Background jobs are a different concern: long AI calls, imports, notifications, and
durable integration retries need the later background-job spike, not long-lived request
handlers.

## Reproduction

From repository root:

```bash
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install -r spikes/api/requirements-lock.txt
bash spikes/api/scripts/init-postgres.sh
.venv/bin/python spikes/api/manage.py migrate --noinput
.venv/bin/python spikes/api/manage.py test tests --verbosity 2
.venv/bin/python spikes/api/scripts/generate_openapi.py
.venv/bin/python spikes/api/scripts/benchmark.py
.venv/bin/python spikes/api/scripts/code_metrics.py
```

Optional local server:

```bash
.venv/bin/python spikes/api/manage.py runserver 127.0.0.1:8000
```

Stop without deleting the isolated database files:

```bash
bash spikes/api/scripts/stop-postgres.sh
```

No environment file is needed. The explicit supported overrides are
`SPIKE_DATABASE_ENGINE`, `SPIKE_DATABASE_NAME`, `SPIKE_DATABASE_USER`,
`SPIKE_DATABASE_PASSWORD`, `SPIKE_DATABASE_HOST`, `SPIKE_DATABASE_PORT`,
`SPIKE_DJANGO_SECRET_KEY`, and `SPIKE_DEBUG`. SQLite is selected only by explicitly
setting `SPIKE_DATABASE_ENGINE=sqlite`; it was not used for primary evidence.

To repeat clean-database validation, create a uniquely named disposable database owned by
the spike role, set `SPIKE_DATABASE_NAME` for `manage.py migrate` and a service smoke
operation, then drop only that explicit database. Never point these commands at an
existing or unknown database.

## Acceptance criteria

These criteria were stated before findings.

### Django

- **Pass:** clean PostgreSQL migrations and rollback work; shared services have no API
  framework imports; transactions roll back atomically; admin works; all contract,
  isolation-simulation, error, security and schema tests pass; no evidence reveals a
  blocker to stateless nodes or future RLS/OIDC adapters.
- **Fail:** a required capability cannot be implemented safely without violating the
  platform boundaries, or migration/transaction/isolation behavior is unreliable.
- **Inconclusive:** PostgreSQL evidence or major security/schema paths are absent, or a
  scale conclusion depends only on a synthetic benchmark.

### API framework candidates

- **Adopt candidate:** equivalent behavior/security tests pass; generated OpenAPI is
  suitable for typed-client tooling with documented customization; integration does not
  couple domain and authentication; tradeoffs are supportable.
- **Reject candidate:** equivalent contracts cannot be safe/maintainable, schemas are
  materially incomplete, or a required extension point is blocked.
- **Revise/investigate further:** both are viable but material tradeoffs need human
  preference, ecosystem evidence, or another workload.

Performance passes only if no pathological overhead appears. It cannot prove production
capacity or 100k-user scale.

## Findings

- All 26 PostgreSQL tests passed in the final run (0.656 seconds).
- Empty-database migration, incremental optional-field migration, rollback, and
  post-migration ORM usability passed.
- Both generated schemas contain all six operations, three paths, explicit auth and
  Workspace-context input, reusable Project/error/page schemas, UUIDs, status enums,
  request bodies, response codes and stable operation IDs.
- DRF emitted OpenAPI 3.0.3 with eight reusable schemas. Ninja emitted OpenAPI 3.1.0 with
  eight reusable schemas.
- DRF required drf-spectacular, extensive endpoint annotations, an authentication schema
  extension, a permission adapter, an unknown-field mixin and an exception adapter.
  Ninja inferred more from type declarations but required five error handlers and a
  boundary normalization for framework-external 405 responses.
- Measured framework-specific code was 385 nonblank/non-comment physical lines in nine
  DRF files versus 264 lines in four Ninja files (`results/code-metrics.json`).
  Docstrings count. Fewer lines are not automatically safer; DRF's extra lines make
  permissions, serialization and schema metadata explicit.
- Final benchmark results are in `results/benchmark.json`. Ninja was faster in all
  three runs, but both were millisecond-scale and no framework choice is based on this.
- Django's application-service boundary, PostgreSQL integration, transaction semantics,
  normal migrations, admin and test isolation met the representative criteria.
- No material architectural blocker was found for stateless, horizontally replicated
  Django API nodes backed by shared PostgreSQL and externalized session/state services.

## Security findings

| Check | Result |
| --- | --- |
| DEBUG disabled/internal exception | 500 normalized; no exception type, message or trace in body |
| Missing/mismatched authentication | 401 normalized for both |
| Malformed JSON | 400 `malformed_request` for both |
| Body over 1 MiB | 413 `request_too_large` before parsing |
| Unsafe PUT | 405 normalized for both |
| SQL-injection-style name | Stored/retrieved literally through parameterized ORM; no query broadening |
| Cross-Workspace guessed ID | Read/update/delete all returned opaque 404; foreign row unchanged |
| Relationship/filter substitution | Foreign Workspace returned opaque 404 |
| Mass assignment | Unexpected JSON fields returned 422 |
| Duplicate scoped name | Database uniqueness conflict normalized to 409 |
| Unknown resource/context | Opaque 404 |
| Health exposure | Exact body `{"status":"ok"}`; no environment, DB or server details |
| Secure defaults checked | DEBUG false; secure cookies, nosniff and frame denial configured |

`manage.py check --deploy` intentionally retains TLS-boundary warnings for HSTS and
HTTP-to-HTTPS redirect because this non-deployed test client has no TLS proxy. A
production deployment must terminate/redirect HTTPS correctly and enable reviewed HSTS.
The synthetic headers are forgeable and are not authentication. Local trust database
auth is isolated-spike-only. No RLS, real OIDC, CSRF/BFF flow, CORS policy, rate limiting,
audit log, secret manager, dependency vulnerability scan, TLS, admin hardening, or
penetration test was performed.

## Limitations

This spike does not prove:

- PostgreSQL RLS or connection-context safety;
- final Workspace membership, roles, or permissions;
- Keycloak/OIDC, browser session/BFF, mobile bearer tokens, CSRF or logout/revocation;
- production server behavior, concurrency, capacity, 100k-user throughput, autoscaling,
  connection-pool sizing, failover, observability or load-balancer behavior;
- background processing, AI-call orchestration, large files or durable integrations;
- complete penetration testing, compliance, audit-event design or admin support policy;
- FastAPI/NestJS comparison, final package boundaries, deployment, tenancy, auth, design
  system, or product behavior;
- production dependency maintenance, vulnerability posture or TypeScript generator
  compatibility across chosen client tools.

## Recommendation

- **Django — adopt:** it passed the predeclared criteria as a candidate backend
  foundation. Human review and the remaining alternative, tenancy, auth, deployment and
  scale spikes are still required.
- **DRF — revise:** it is viable and passed the behavioral/security contract, but for
  this API-first typed contract it needed more adapter/schema code and one extra direct
  dependency. Retain it as the mature fallback or choose it if ecosystem requirements
  later outweigh typing/schema overhead.
- **Django Ninja — adopt:** it is the stronger default candidate from this comparison:
  equivalent safety behavior, more direct typing/OpenAPI 3.1, fewer framework-specific
  files/lines, and no pathological overhead. Adoption remains contingent on human review,
  maintenance/security due diligence, real authentication, and client-generation tests.

These recommendations are evidence for an ADR review only.
`docs/architecture/technology-decisions.md` remains `TO VALIDATE`.
