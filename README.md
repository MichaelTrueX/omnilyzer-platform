<!--
File: README.md
Purpose: Introduces the Omnilyzer Platform architecture-validation repository.
Related:
- docs/architecture/platform-principles.md
- docs/architecture/technology-decisions.md
- spikes/README.md
-->

# Omnilyzer Platform

Omnilyzer Platform is the planned reusable foundation for independently deployable enterprise SaaS products, initially including Valoria, Omnilyzer HR, and public marketing and sales websites. Products remain separate from the platform and consume explicitly versioned platform components; they do not copy platform source or inherit another product's release schedule.

This repository is currently an **architecture-validation repository**. It contains governance, architecture documentation, and isolated locations for future proof-of-concept spikes. It does not yet contain production application code, finalized framework choices, or production deployment configuration.

> Experiments validate architecture. They do not define production architecture by accident.

> Codex may implement documented architecture. Codex must not silently invent architecture.

If an implementation request requires a technology, service, dependency, persistence model, or architectural boundary not covered by the current documentation, work must stop at that boundary and identify the architecture decision required. The decision must be validated and documented before implementation proceeds.

## Current phase

Task 001 establishes repository hygiene, contribution and security policies, documented architectural direction, an ADR process, lightweight repository checks, and empty spike work areas. Future tasks may execute the documented spikes. Successful spike code is evidence, not production code; it requires deliberate redesign or promotion through the normal review process.

## Directory map

- [`docs/architecture/`](docs/architecture/) records principles, models, and the current status of technology choices.
- [`docs/adr/`](docs/adr/) defines how durable architecture decisions are recorded.
- [`spikes/`](spikes/) reserves isolated locations for temporary architecture experiments.
- [`.github/`](.github/) contains repository review and quality automation.

Repository policies are defined in [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md). [`LICENSE`](LICENSE) contains the unmodified standard Apache License 2.0 text; it intentionally has no repository header because adding one would modify the standard license text.

## Contribution workflow

Branch from `main`, make a focused change on a feature or fix branch, run relevant checks, and open a pull request. Review and passing checks are required before merge. Architecture changes require corresponding documentation and, when they settle a major decision, an Architecture Decision Record. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the complete policy.

Spike code is experimental and must not automatically become production code or a production dependency. Production code must never import from `spikes/`.
