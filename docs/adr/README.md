<!--
File: docs/adr/README.md
Purpose: Defines the Architecture Decision Record process and required record format.
Related:
- docs/architecture/technology-decisions.md
- CONTRIBUTING.md
- spikes/README.md
-->

# Architecture Decision Records

Architecture Decision Records (ADRs) capture major technology and architecture decisions after sufficient investigation. A spike recommendation is evidence for an ADR, not an automatic decision. Create an ADR when a choice establishes or materially changes a platform boundary, technology, persistence model, security control, integration contract, deployment mechanism, or compatibility commitment.

Number records sequentially with a concise kebab-case name, for example `0001-example-decision.md`. Pull requests must link related evidence and update affected architecture documents. Do not rewrite the outcome of an accepted record; supersede it with a new ADR that links both directions.

## Statuses

- **Proposed:** under review and not authorized for production reliance.
- **Accepted:** approved direction, with stated constraints and consequences.
- **Superseded:** replaced by a later ADR, which must be linked.
- **Rejected:** considered and deliberately not selected.

## Required format

```markdown
# ADR NNNN: Title

- Status: Proposed | Accepted | Superseded | Rejected
- Date: YYYY-MM-DD

## Context

Describe the problem, constraints, assumptions, and decision drivers.

## Options considered

Describe credible options and their relevant tradeoffs.

## Decision

State the chosen direction and its scope. Proposed records may state a recommendation.

## Consequences

Record positive, negative, and neutral consequences, including compatibility effects.

## Security implications

Describe threat-boundary and control changes, or explain why none apply.

## Operational implications

Describe ownership, deployment, observability, cost, support, and recovery effects.

## Migration and rollback implications

Describe adoption, data/code migration, compatibility windows, rollback, or why they do not apply.
```

Use an actual calendar date when the record is created. State uncertainty explicitly and link validation results. An ADR becomes Accepted only through the repository review process.
