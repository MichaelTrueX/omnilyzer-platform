<!--
File: spikes/README.md
Purpose: Governs temporary architecture experiments and lists planned validation spikes.
Related:
- docs/architecture/technology-decisions.md
- docs/adr/README.md
- README.md
-->

# Architecture Spikes

Spike implementations are temporary experimental code. Production code must not import code from `spikes/`, and spike dependencies do not automatically become production dependencies. A successful experiment informs a reviewed architecture decision; it does not become production code by location, resemblance, or convenience.

Failed or completed spikes must be removable without damaging production architecture. Spikes must use synthetic data and isolated credentials, must not depend on production systems, and must stay within their named directory.

## Required spike record

Each implemented spike must document:

1. **Hypothesis:** the precise claim being tested.
2. **Acceptance criteria:** measurable conditions for success, failure, and inconclusive results.
3. **Security checks:** threats, isolation cases, credential handling, and abuse cases relevant to the experiment.
4. **Test approach:** representative scenarios, fixtures, tools, and reproducible commands.
5. **Findings:** evidence, limitations, unexpected results, and unresolved questions.
6. **Recommendation:** adopt, reject, revise, or investigate further, with rationale.

Recommendations that settle major choices must proceed through an ADR. Production implementation must be designed and reviewed independently, with intentional dependency selection and migration from any useful experimental concepts.

## Planned spikes

1. **API** (`api/`): compare Django REST Framework and Django Ninja using representative API contracts, authorization, errors, schema generation, tests, and performance.
2. **Tenancy** (`tenancy/`): validate the Workspace model plus shared-schema PostgreSQL RLS through deliberate cross-Workspace attack tests and operational scenarios.
3. **Authentication** (`authentication/`): validate Keycloak, browser BFF/server sessions, and Expo native OAuth, including revocation, recovery, and secure storage.
4. **Design system** (`design-system/`): validate shared semantic tokens and responsive, accessible web/native components without forcing identical UI implementations.
5. **Platform packaging** (`platform-packaging/`): validate versioned platform packages consumed and upgraded independently by dummy products.
6. **Deployment** (`deployment/`): validate promotion of one immutable image through DEV, STAGING, and PROD, including configuration, migration, rollback, and auditability.
7. **Supply chain** (`supply-chain/`): validate private Python, npm, and OCI delivery through separate GitHub OIDC publisher and consumer identities, with signing and stronger policy evidence deferred to Task 008B.
8. **Observability contract** (`observability/`): validate secure structured logging, correlation IDs, OpenTelemetry tracing, bounded Prometheus-compatible metrics, health semantics, deployment metadata, and failure isolation without selecting production collector infrastructure.
9. **Prometheus metrics** (`prometheus-metrics/`): validate real Prometheus scraping and queries, closed cardinality, private metrics networking, monitoring failure isolation, recovery, build-info behavior, and Python multiprocess lifecycle semantics without accepting production monitoring infrastructure.
10. **Grafana operator security** (`grafana-security/`): validate Grafana OSS as a private operator interface over Prometheus, including real Keycloak OIDC, fail-closed roles, datasource/query authorization boundaries, reproducible provisioning, failure isolation, and runtime-only secrets without accepting a visualization architecture.
11. **Registry durability** (`registry-durability/`): validate zot cold-backup integrity, fresh restore, exact-digest recovery, corruption rejection, and operational recovery boundaries without claiming production HA, disaster recovery, RPO, or RTO.

Task 001 creates only these isolated locations and governance. It does not implement any spike.
