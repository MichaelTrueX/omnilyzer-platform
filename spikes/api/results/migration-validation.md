<!--
File: spikes/api/results/migration-validation.md
Purpose: Records clean, incremental, and rollback migration evidence for Task 002.
Related:
- spikes/api/domain/migrations/0001_initial.py
- spikes/api/domain/migrations/0002_enum_value_constraints.py
- spikes/api/README.md
-->

# Migration validation evidence

Date: 2026-08-28. Backend: isolated PostgreSQL 16.15.

## Empty database

A new, explicitly disposable database named
`omnilyzer_platform_api_spike_clean_validation` was created. Running
`manage.py migrate --noinput` applied all Django migrations and both domain migrations
successfully. The shared transaction service then created one Workspace and
one Project; observed counts were `workspace_count 1 project_count 1`. The disposable
database was dropped afterward.

## Incremental schema change and rollback

A temporary optional `Project.reference_note varchar(80) NOT NULL DEFAULT ''` model
field was added. Django generated `0002_optional_reference_experiment`; applying it
succeeded, and `information_schema.columns` reported
`reference_note|character varying|NO`. Migrating back to `domain 0001` succeeded and
the column count returned to zero.

The optional-field model change and temporary migration were then removed. The retained
schema is represented by `0001_initial.py` plus the later permanent
`0002_enum_value_constraints.py`; final `makemigrations --check --dry-run`
must report no changes.

## Assessment

Autodetection, forward application, targeted rollback, and empty-database bootstrap were
straightforward. Production changes still need backups, locks/runtime estimates,
expand/migrate/contract sequencing, backward-compatible application deployment, explicit
reversible data steps, and separate migration/runtime database roles. PostgreSQL-only
features such as future RLS can use reversible `RunSQL` operations, but Task 003 must
validate policy and connection-context behavior.
