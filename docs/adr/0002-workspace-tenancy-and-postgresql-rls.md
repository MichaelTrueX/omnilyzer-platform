# ADR 0002: Workspace Tenancy with PostgreSQL Row-Level Security

- Status: Accepted
- Date: 2026-08-29

## Context

Omnilyzer requires strong multi-tenant isolation for personal and organization Workspaces while retaining one manageable PostgreSQL platform.

Task 003 validated a shared PostgreSQL database and schema with a `workspace_id` tenant boundary, a non-owner runtime role, a separate migration owner, PostgreSQL RLS with `FORCE ROW LEVEL SECURITY`, transaction-local Workspace context, and fail-closed behavior when context is missing. The spike demonstrated isolation for Django ORM queries, raw SQL, joins, aggregates, and bulk writes, as well as cleanup across connection reuse and transaction rollback.

Reference evidence:

- [`spikes/tenancy/README.md`](../../spikes/tenancy/README.md)
- [`rls-validation.md`](../../spikes/tenancy/results/rls-validation.md)

## Options considered

### Shared schema + workspace_id + PostgreSQL RLS

Selected.

Benefits:

- one manageable relational schema;
- application and database isolation layers;
- broad ORM and raw SQL mistakes remain tenant-restricted;
- normal Django migrations remain possible;
- supports many Workspaces without per-tenant database objects.

Tradeoffs:

- every tenant table must participate correctly;
- database connection context becomes security-critical;
- data migrations and privileged maintenance need deliberate procedures;
- external connection poolers need separate validation.

### Shared schema with application filtering only

Not selected. Application authorization remains mandatory, but application filtering alone does not protect against forgotten Workspace predicates or broad raw SQL.

### Schema per Workspace

Not selected as the default. It adds migration, operational, and scaling complexity without a demonstrated requirement.

### PostgreSQL role per Workspace

Not selected. Database roles must not grow in proportion to tenant count.

## Decision

1. `Workspace` is the platform tenant security boundary.
2. Workspaces may be `personal` or `organization`.
3. Core tenant data uses one shared PostgreSQL schema with explicit `workspace_id`.
4. Application authorization determines whether an actor may enter a Workspace.
5. Only an already-authorized Workspace ID may be supplied to the database tenancy context.
6. PostgreSQL RLS provides mandatory defense in depth beneath application authorization.
7. Tenant tables must enable RLS and `FORCE ROW LEVEL SECURITY`.
8. Runtime application roles must be `NOSUPERUSER`, `NOBYPASSRLS`, and must not own tenant tables/schema/database.
9. Migration ownership uses separate credentials and must never be used as runtime application credentials.
10. Workspace database context is transaction-local using the semantic equivalent of `set_config('omnilyzer.workspace_id', workspace_id, true)`.
11. Missing Workspace context must fail closed.
12. No default/fallback Workspace may be silently selected.
13. Per-Workspace PostgreSQL roles and schema-per-Workspace are not the default architecture.
14. RLS does not replace authentication, membership checks, permissions, or application authorization.

```text
authentication
      |
application authorization
      |
authorized Workspace ID
      |
workspace transaction scope
      |
PostgreSQL RLS
      |
tenant data
```

## Consequences

Positive consequences:

- the database protects against omitted tenant predicates;
- raw SQL and bulk operations gain the same boundary;
- shared-schema operations remain manageable;
- horizontal application nodes can use the same security model.

Tradeoffs:

- each tenant-owned table needs reviewed policies;
- connection-context setup is security-sensitive;
- privileged migrations and maintenance require separate controls;
- RLS policies require migration and regression testing;
- query and index design should start with `workspace_id` where appropriate.

Future domain models with tenant-owned data must not be added without tenancy-policy review.

## Security implications

PostgreSQL superusers and `BYPASSRLS` roles remain outside RLS protection. Runtime roles must never have those capabilities. Migration-owner compromise remains privileged, and runtime and migration credentials require separate secret handling.

RLS cannot stop unauthorized code from setting another valid Workspace ID; application authorization must occur first. Tenant context must be parameterized rather than interpolated into SQL. Session-global tenant settings are prohibited for normal runtime usage, and no request may inherit tenant context from a previous request.

Task 003 did not validate Keycloak, OAuth, Workspace memberships, browser sessions, PgBouncer, production credential storage, backup and restore, or production scale.

## Operational implications

Runtime and migration credentials are distinct. Runtime does not execute schema migrations, while the migration owner owns tenant schema and tables. `FORCE ROW LEVEL SECURITY` means ownership is not treated as an ordinary application read bypass. Privileged and data migrations need an explicit controlled strategy.

External PgBouncer and connection-pool behavior remains to be validated during deployment work. Production monitoring should detect unexpected privileged or `BYPASSRLS` runtime roles and missing RLS or `FORCE ROW LEVEL SECURITY` configuration.

## Migration and rollback implications

This is a new platform, so there is no existing production tenant-data migration. New tenant tables require their RLS policy in the same controlled migration sequence. Schema evolution must preserve Workspace boundaries throughout expand/migrate/contract changes, and rollback must not leave a tenant table without required RLS. Changing the tenancy model requires a new ADR.
