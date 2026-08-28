<!--
File: .github/pull_request_template.md
Purpose: Provides the required scope, quality, security, and architecture review checklist.
Related:
- CONTRIBUTING.md
- SECURITY.md
- docs/adr/README.md
-->

## Summary

Describe the change, its purpose, and its boundaries.

## Validation

List tests and checks run, including relevant results.

## Checklist

- [ ] The scope and intended outcome are understood.
- [ ] This change introduces no undocumented architecture changes.
- [ ] Tests were added or updated where applicable.
- [ ] Security implications were considered and documented where applicable.
- [ ] Workspace isolation was considered where applicable.
- [ ] Backward compatibility was considered; any approved break is explicit.
- [ ] Documentation and linked architecture records were updated.
- [ ] No secrets, credentials, private data, or production data are included.
- [ ] No obsolete or orphan files remain.
- [ ] Dependency additions are justified, reviewed, and documented.
- [ ] Migration and rollback implications were considered where applicable.

## Architecture, security, migration, and rollback notes

Link ADRs or explain why none are required. Describe material risks and mitigations.
