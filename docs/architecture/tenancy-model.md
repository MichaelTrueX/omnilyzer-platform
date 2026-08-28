<!--
File: docs/architecture/tenancy-model.md
Purpose: Defines the conceptual Workspace tenancy model and planned isolation defenses.
Related:
- docs/architecture/security-model.md
- spikes/README.md
- docs/architecture/technology-decisions.md
-->

# Tenancy Model

`Workspace` is the platform tenant security boundary. Every Workspace-scoped resource must be attributable to exactly one Workspace unless a separately documented global/platform scope is necessary. “Organization” describes a Workspace type and profile; it is not a substitute term for the security boundary.

## Conceptual entities

```text
User
Workspace
WorkspaceMembership
OrganizationProfile
PersonalProfile
Role
Permission
```

- **User:** a platform identity reference, independent of any single Workspace.
- **Workspace:** the isolation boundary, with at least `personal` and `organization` types.
- **WorkspaceMembership:** associates a User with an organization Workspace and its lifecycle state.
- **OrganizationProfile:** organization-specific attributes attached to an organization Workspace.
- **PersonalProfile:** personal attributes attached to a personal Workspace.
- **Role:** a product- or platform-defined grouping of permissions in an explicit scope.
- **Permission:** a named authorization capability evaluated for a resource and action.

A User may have a personal Workspace and memberships in zero or more organization Workspaces. Membership in one Workspace grants no access to another. The model must not place all individuals into a common “public tenant”; consumer users retain isolated personal Workspaces where a Workspace boundary is required.

Cardinality, lifecycle rules, invitations, ownership transfer, deletion, regulatory retention, and whether every User receives a personal Workspace are implementation details requiring validation or later decisions. Product-specific authorization remains separate from authentication and may add product roles without weakening the Workspace boundary.

## Planned isolation defense

```text
application authorization
+
PostgreSQL RLS
```

Shared-schema PostgreSQL tenancy using `workspace_id` and RLS is **TO VALIDATE**, not final. Application code must resolve and authorize explicit Workspace context, scope queries, validate relationships, and deny ambiguous context. RLS is intended to enforce the same boundary at the database layer under a non-owning, non-bypass runtime role.

The tenancy spike must attempt deliberate cross-Workspace attacks, including guessed identifiers, nested-resource substitution, bulk operations, joins, aggregates, background jobs, administrative paths, concurrent connection reuse, missing context, malformed context, imports/exports, and raw SQL. Tests must prove fail-closed behavior and absence of data leakage through content, counts, errors, timing where material, logs, caches, and audit records.

Uniqueness constraints, foreign keys, indexing, migrations, privileged maintenance, backup/restore, and observability must preserve Workspace isolation. The spike recommendation must document limitations and residual risks before the direction can become accepted.
