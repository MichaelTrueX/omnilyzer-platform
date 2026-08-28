<!--
File: CONTRIBUTING.md
Purpose: Defines the contribution, review, and architecture-change workflow.
Related:
- README.md
- docs/adr/README.md
- .github/pull_request_template.md
-->

# Contributing

## Workflow

1. Branch from `main` using a descriptive feature or fix branch.
2. Keep commits focused and explain why a change is needed.
3. Add or update tests and repository checks where applicable.
4. Open a pull request and complete the repository checklist.
5. Obtain review and pass required checks before merge.

Direct changes to `main` are prohibited except for explicitly authorized emergency repository administration. Emergency changes must be reviewed and documented retrospectively.

## Architecture and dependencies

- Update linked documentation whenever architecture changes.
- Record major decisions through the [`docs/adr/`](docs/adr/) process.
- Do not add dependencies silently. Explain their purpose, license, security implications, maintenance burden, and alternatives in the pull request.
- Do not add an infrastructure service without documented architectural justification.
- Preserve backward compatibility unless a breaking change is explicitly approved and accompanied by migration and rollback planning.
- Remove obsolete files when replacing functionality; do not leave orphaned implementations or documentation.
- Keep product-specific behavior outside reusable platform capabilities.

## Quality and review

Changes must pass applicable automated checks and focused tests. Review must consider security, Workspace isolation, accessibility, compatibility, operational effects, and documentation as relevant to the change. No secrets, production data, or private credentials may be committed.

AI-generated code and documentation follow exactly the same engineering, testing, security, authorship, and review requirements as human-created work. The author remains responsible for validating generated output.
