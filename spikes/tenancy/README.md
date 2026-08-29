# Workspace tenancy RLS validation spike

This removable spike tests one PostgreSQL 16 database and shared schema with
`workspace_id` as the tenant boundary. Django application authorization supplies
an already-authorized Workspace ID to `workspace_scope()`, and PostgreSQL row-level
security (RLS) provides defense in depth against missing or incorrect tenant
predicates in application queries.

The two Django aliases point to the same database with separate roles:

- `default`: `omnilyzer_tenancy_runtime`, a non-owner data-only role.
- `migration`: `omnilyzer_tenancy_owner`, the database, schema, and table owner.

A database router sends normal model reads/writes to `default` and allows schema
migrations only on `migration`. It also makes Django's migration consistency check
inspect the owner alias without granting runtime access to `django_migrations`.

The cluster-created bootstrap administrator is used only by `init-postgres.sh` for
initial role/database creation and exceptional disposable-cluster maintenance. It
does not appear in Django configuration. Both application-visible roles are
`NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION`. Migrations must
always be run explicitly with `--database=migration`; the runtime role must not run
migrations.

## Run

From this directory, using the repository's existing `.venv`:

```bash
./scripts/init-postgres.sh
../../.venv/bin/python manage.py migrate --database=migration
../../.venv/bin/python scripts/run-tests.py
../../.venv/bin/python manage.py makemigrations --check --dry-run
../../.venv/bin/python -m compileall -q .
../../.venv/bin/python -m pip check
git diff --check
git status --short
```

Stop the disposable cluster with `./scripts/stop-postgres.sh`. Its fixed data and
socket paths are `/tmp/omnilyzer-platform-tenancy-spike-pgdata` and
`/tmp/omnilyzer-platform-tenancy-spike-socket`; TCP is disabled. The socket
directory and socket use mode `0700`. Local `trust` authentication is acceptable
only because this is an isolated, no-TCP, disposable spike owned by the current OS
user. It is not a production authentication design.

## Context contract

`workspace_scope(workspace_id)` uses the `default` runtime connection, starts one
database transaction, and parameterizes:

```sql
SELECT set_config('omnilyzer.workspace_id', %s, true)
```

The `true` makes the setting transaction-local, so commit or rollback clears it
even when Django reuses the underlying connection. Missing context deliberately
fails closed. Nested transactions/scopes are rejected to prevent context rebinding.
No Python global or thread-local tenant state is used.

The caller must authenticate and authorize access before calling the scope. RLS
does not determine whether a user belongs to the requested Workspace:

```text
authentication
        ↓
application authorization
        ↓
authorized Workspace ID
        ↓
workspace_scope()
        ↓
PostgreSQL RLS
```

RLS protects against application query bugs and missing Workspace predicates. It
does not protect against PostgreSQL superuser compromise, `BYPASSRLS` roles, code
permitted to establish an unauthorized Workspace context, migration-owner
compromise, or arbitrary privileged database administration. The migration owner
is forced through RLS during ordinary data access, but ownership still permits it
to alter database objects; its credentials are therefore a separate privileged
operational concern and must never be runtime credentials. No generic application
`BYPASSRLS` role exists.

Transaction-local context was intentionally selected to avoid session-level
Workspace leakage. This spike does not prove safety with an external pooler;
actual PgBouncer or deployment connection-pool behavior must be revalidated during
deployment/infrastructure validation.

The two models are synthetic evidence models, not the complete platform tenancy
model.
