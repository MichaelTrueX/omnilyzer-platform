# RLS validation result

## Outcome

- **Role separation:** migration ownership and data-only runtime access are separate.
- **RLS/FORCE state:** enabled and forced on both tenant tables.
- **Missing context:** reads and aggregates return zero; inserts fail; updates and deletes affect zero rows.
- **ORM isolation:** broad unfiltered queries return only the active Workspace.
- **Raw SQL isolation:** an unfiltered Project select returns only the active Workspace.
- **Join/aggregate isolation:** joins and counts reflect only the active Workspace.
- **Bulk write isolation:** broad updates and deletes affect only the active Workspace.
- **Cross-Workspace writes:** foreign inserts and reassignment are rejected.
- **Connection reuse:** one underlying Django connection is reused without context leakage.
- **Rollback cleanup:** data rolls back and context does not leak after an exception.
- **Migration/runtime separation:** migrations use the owner alias; runtime owns no database, schema, or tenant table and cannot alter/drop tables or disable RLS.

## Limitations

- This validates synthetic Workspace and Project models, not the final domain model.
- RLS is defense in depth for query mistakes; authentication and application authorization remain mandatory.
- Superusers, `BYPASSRLS`, migration-owner compromise, unauthorized context selection, and privileged administration remain outside the protection boundary.
- Local `trust` authentication is limited to this no-TCP disposable cluster and is not a production design.
- External poolers were not tested; deployment pool behavior requires separate validation.
- Operational credential storage, rotation, backup, restore, and incident response were not tested.

## Recommendation

**adopt** — shared-schema `workspace_id` tenancy with application authorization and PostgreSQL RLS as defense in depth passed this spike's isolation tests.
