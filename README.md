<!--
File: README.md
Purpose: Explain the reusable SaaS platform's owner-approved product boundary,
         current delivery status, and links to the governing technical decisions.
Related:
- docs/architecture/platform-principles.md
- docs/architecture/technology-decisions.md
- docs/operations/task013-release-0145-acceptance.md
- deployment/README.md
- AGENTS.md
- spikes/README.md
-->

# Omnilyzer Platform

**Omnilyzer is the reusable technical foundation for multiple independently
operated SaaS products, not a general-purpose content-management system.**
This product boundary was explicitly confirmed by the owner on 2026-10-17.

The platform provides reusable, versioned capabilities when required by
real consuming products: secure identity integration, Workspace and tenant
isolation, shared API and design contracts, security, observability, software
distribution, and deployment controls. Each SaaS product owns its business
logic, domain data, user experience, deployment schedule, and product-specific
authorization. Sharing infrastructure **does not** grant products unrestricted
access to one another's databases or customers. A CMS can be implemented by
a product that needs content publishing; it is **not a mandatory platform
capability or a controlling project milestone**.

Potential consumers include Omnilyzer Analytics, HR applications, education
applications, and public marketing websites. These examples are **not claims
that the products are integrated or migrated**. Existing website repositories
and their data remain separate unless migration is explicitly scoped,
approved, and verified.

This repository remains an **architecture-validation and delivery-control
repository**. It contains accepted architecture decisions, isolated technical
spikes, and source for release and deployment automation. It does **not**
yet contain an integrated, usable SaaS business application. Experimental
components are not production application code merely because they pass CI.

> Experiments validate architecture. They do not define production architecture by accident.

> Codex may implement documented architecture. Codex must not silently invent architecture.

If an implementation request requires a technology, service, dependency, persistence model, or architectural boundary not covered by the current documentation, work must stop at that boundary and identify the architecture decision required. The decision must be validated and documented before implementation proceeds.

## Current phase and near-term priorities

- **Task 013 — validated for its synthetic release scope:** signed, scanned,
  coordinated version `0.14.5` was successfully published to zot and Forgejo
  and its retained handoff/OCI receipt independently verified on two hosts.
  See [the acceptance record](docs/operations/task013-release-0145-acceptance.md).
- **Task 014 — live DEV promotion remains blocked:** repository automation and
  security models exist, but a successful end-to-end DEV promotion has not
  been demonstrated. See [deployment status](deployment/README.md) and the
  [open incident](https://github.com/MichaelTrueX/omnilyzer-platform/issues/182).
- **Next business milestone:** once DEV deployment is demonstrably functional,
  integrate one actual SaaS product workflow (identity, Workspace isolation,
  product API, persisted business data, and tested customer authorization).
  Do not substitute an arbitrary CMS page-editing flow for that milestone.

Prioritize resolving demonstrated delivery blockers and the first consuming
product over speculative shared frameworks, additional approval bureaucracy,
or a generic CMS. Keep necessary authentication, tenant separation, source
integrity, signing, security gates, backup, and rollback safeguards intact.
Production deployment or a new SaaS product implementation still requires
its own bounded authorization.

## Directory map

- [`docs/architecture/`](docs/architecture/) records principles, models, and the current status of technology choices.
- [`docs/adr/`](docs/adr/) defines how durable architecture decisions are recorded.
- [`spikes/`](spikes/) reserves isolated locations for temporary architecture experiments.
- [`.github/`](.github/) contains repository review and quality automation.

Repository policies are defined in [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md). [`LICENSE`](LICENSE) contains the unmodified standard Apache License 2.0 text; it intentionally has no repository header because adding one would modify the standard license text.

## Contribution workflow

Branch from `main`, make a focused change on a feature or fix branch, run relevant checks, and open a pull request. Review and passing checks are required before merge. Architecture changes require corresponding documentation and, when they settle a major decision, an Architecture Decision Record. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the complete policy.

Spike code is experimental and must not automatically become production code or a production dependency. Production code must never import from `spikes/`.
