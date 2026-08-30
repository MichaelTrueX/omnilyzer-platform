# ADR 0007: Product Observability Contract

- Status: Accepted
- Date: 2026-08-30

## Context

Omnilyzer will have multiple independently deployed products that consume reusable,
versioned platform capabilities. If each product invents its own logging, correlation,
tracing, metrics, health, and deployment-metadata behavior, security controls and
operational semantics will diverge. Product teams would repeatedly solve the same
integration problems, central monitoring would receive incompatible telemetry, and
platform upgrades would be harder to govern.

Observability is privileged. Logs, traces, and metrics can expose credentials, sessions,
customer content, user identities, tenant identities, internal topology, and unbounded
dimensions if their contracts are not deliberately constrained. `Workspace` is the
tenant security boundary, but neither `workspace_id` nor user identifiers should become
standard telemetry dimensions. Correlation must not acquire identity, authorization,
tenant, session, or deduplication meaning.

Monitoring infrastructure also fails. A collector, exporter destination, log service,
metrics backend, or visualization system must not become a synchronous application
dependency or a readiness dependency. Product requests must continue when telemetry is
unavailable, rejecting data, slow within configured bounds, or saturated. Losing bounded
telemetry is preferable to causing user-visible application degradation.

Product instrumentation must remain portable across collector and backend choices.
Products should depend on a stable platform contract and open telemetry protocols, not a
specific visualization, storage, or collection product.

[Task 009 observability-contract evidence](../../spikes/observability/README.md) validated
the product-side contract with an isolated Django 6.1 fixture. It exercised
structured logging, request and trace correlation, OpenTelemetry tracing and OTLP export,
Prometheus-compatible metrics, health endpoints, metadata, privacy controls, bounded
cardinality, concurrent requests, exporter rejection and outage, queue saturation,
bounded shutdown, and three-condition synthetic overhead measurements. The spike did not
deploy or select production monitoring infrastructure and did not validate production
WSGI/ASGI, multiprocess, PostgreSQL, collector, storage, retention, or load behavior.

## Options considered

### No platform observability contract

Each product could independently select logging formats, correlation behavior, tracing
libraries, metrics, health semantics, and metadata. This minimizes initial platform work
but creates inconsistent security controls, duplicated integration, incompatible
telemetry, and product-specific operational burden. It also makes central monitoring and
cross-product incident response harder.

### Vendor-specific product instrumentation

Products could directly integrate a selected monitoring vendor's SDKs and APIs. This can
provide rapid access to vendor features, but couples application code and upgrades to one
backend, weakens provider portability, and makes a later collector or storage change a
product-code migration.

### Synchronous direct calls to monitoring backends

Applications could send logs, traces, or metrics directly to central backends during
request handling. This offers immediate delivery feedback but makes backend latency and
availability part of application latency and availability. It violates the required
failure-isolation boundary and risks cascading failures during incidents.

### Standardized vendor-neutral product contract

Products can use stable OpenTelemetry API/SDK interfaces with OTLP export, structured
JSON-compatible logging to process streams, and Prometheus-compatible application
metrics. A shared contract can also standardize correlation, health, metadata, privacy,
cardinality, and failure isolation while leaving collector, storage, and visualization
choices replaceable. Task 009 supports this option within its stated synthetic scope.

### Arbitrary inbound correlation and trace context

Applications could accept any syntactically valid request ID or W3C trace context from
public callers. This improves end-to-end correlation without ingress configuration, but
lets an untrusted caller select canonical internal correlation identifiers and remote
trace parents. Parent-based sampling may also respect a remote sampled flag. Explicit,
independently configured trust boundaries are safer: local identifiers and trace roots
are the default, while reviewed ingress or service boundaries may sanitize and forward
bounded context.

The standardized vendor-neutral contract is preferred because it minimizes
product-specific implementation, preserves backend portability, makes security defaults
consistent, bounds telemetry cost and cardinality, and keeps observability failure out of
the application availability path.

## Decision

This ADR accepts the following product-side observability contract. The accepted scope is
the application contract only; production implementation must separately address the
remaining validation and infrastructure decisions recorded below.

### Logging

1. Application logs are structured and JSON-compatible.
2. Applications write logs to stdout/stderr for asynchronous collection by deployment
   infrastructure.
3. Product code does not synchronously call Loki, Grafana, or another central log
   backend.
4. Standard fields include timestamp, level, service, product, environment, event,
   request ID, and active trace ID where applicable.
5. Event names are reviewed and bounded. Event-specific fields are structured and
   deliberately selected.
6. Omission is preferred over attempting to sanitize arbitrary captured data. Defensive
   redaction is an additional control, not permission for broad capture.
7. Passwords, OAuth access or refresh tokens, API keys, secrets, Authorization headers,
   session cookies, CSRF tokens, request bodies, tenant/customer content, and customer
   documents are not logged by default.

### Request correlation

1. A canonical request ID represents 128 random bits as exactly 32 lowercase hexadecimal
   characters.
2. IDs are generated with cryptographically secure randomness.
3. Externally supplied request IDs are ignored by default, including syntactically valid
   values.
4. Accepting an incoming request ID requires an explicit trusted-ingress configuration
   for a topology where the ingress strips or overwrites the public caller's header.
5. Trusted incoming values still require the exact bounded canonical format. Invalid or
   oversized values are replaced.
6. Source-IP trust logic is not part of the product contract.
7. Request IDs are correlation metadata only. They are never authentication,
   authorization, tenant context, session state, request deduplication keys, or metric
   labels.
8. Request context uses a concurrency-safe mechanism and is reset after each request.

### Distributed tracing

1. Stable OpenTelemetry API/SDK interfaces are the accepted product-side tracing
   abstraction.
2. OTLP is the vendor-neutral export boundary.
3. Trace export is asynchronous and bounded by reviewed queue, batch, schedule,
   exporter-timeout, and shutdown behavior. Any exporter or transport retry behavior
   must also remain bounded and must not become part of the synchronous request path.
4. Exporter failures do not propagate into application responses.
5. Queue pressure may drop telemetry rather than block or fail application requests.
6. Telemetry loss remains diagnosable through bounded failure metrics and rate-limited
   warnings.
7. Standard trace attributes exclude Workspace, user, email, session, token,
   Authorization, request-body, query-string, arbitrary URL, and customer-content data by
   default.
8. The product contract does not freeze a final production sampling percentage.

Inbound W3C trace context has its own trust decision:

1. Incoming `traceparent` and `tracestate` are ignored by default. The application starts
   a local root context, so a public caller cannot select the internal trace ID, remote
   parent, or parent sampling state.
2. Trace-context trust is configured independently from request-ID trust.
3. Trusted mode is only for a reviewed ingress or service-to-service boundary that has
   sanitized propagation headers.
4. Trusted context uses the standard OpenTelemetry W3C Trace Context propagator rather
   than a custom complete parser.
5. Propagation headers are subject to reviewed byte limits before parsing. Task 009
   validated a 512-byte limit for each of `traceparent` and `tracestate`, with oversized
   input falling back to a local root.
6. W3C baggage is not ingested through the validated inbound trace-context path.
7. Trace context grants no identity, authentication, authorization, tenancy, session,
   or deduplication privilege.
8. Outbound W3C trace propagation remains standard.

### Metrics

Every product should support these standard application metrics:

- HTTP request count;
- HTTP request duration using a reviewed fixed-bucket histogram;
- bounded response/status classification;
- bounded build-info metadata;
- bounded telemetry-export failure diagnostics.

Ordinary request metrics use a closed, reviewed dimension set such as:

- service;
- product;
- environment;
- HTTP method;
- normalized framework route template;
- bounded HTTP status class.

Framework-owned route templates are used instead of raw paths. For example,
`/api/users/123` is recorded as `/api/users/{id}`. Unmatched or unsafe routes collapse to
a bounded fallback rather than becoming arbitrary label values.

The following are prohibited as ordinary request metric labels by default:

- `workspace_id`;
- `user_id`;
- email;
- `session_id`;
- `request_id`;
- `trace_id`;
- IP address;
- Authorization data;
- raw query strings;
- raw arbitrary URLs;
- customer, object, document, or order IDs;
- Git commit;
- OCI digest;
- deployment timestamp.

Application and platform versions may appear in a dedicated bounded build-info series,
not as ordinary request dimensions. High-churn deployment identity is not attached to
every request metric.

### Health

`/livez` answers whether the application process is alive enough to serve the probe. It
is process-local and does not check the database, collector, Grafana, logging service,
metrics backend, external monitoring, or other downstream systems.

`/readyz` answers whether the application should receive normal traffic. It checks only
dependencies genuinely required to serve requests correctly. Depending on the product,
these may include:

- required application configuration;
- primary database reachability;
- required schema or migration state;
- an indispensable synchronous service dependency without which correct requests cannot
  be served.

Collectors, exporters, logging services, metrics backends, visualization systems, and
other monitoring infrastructure do not affect readiness. Health responses expose only
minimal state and do not reveal credentials, internal endpoints, stack traces, or
detailed dependency failures.

### Metrics security boundary

`/metrics` is intended for internal scraping and is not a public Internet endpoint. It
does not require browser authentication, and the default contract does not introduce a
bespoke bearer-token mechanism. Production network and reverse-proxy rules must enforce
the internal monitoring access boundary. Task 009 validated the application endpoint and
data contract, not production network enforcement.

### Build and deployment metadata

The contract supports:

- product and service name;
- environment;
- application version;
- Omnilyzer platform package version;
- Git commit;
- OCI digest;
- deployment timestamp.

Installed application and platform versions should be derived from installed package
metadata where practical. Git commit is injected as build-time metadata. The final OCI
digest and deployment timestamp are deployment-time metadata because the final digest
does not exist until the image artifact has been created.

Complete Git, OCI, and deployment identity belongs in controlled deployment inventory
and structured startup evidence. It is not repeated on every request metric. A dedicated
bounded build-info metric may include product, service, environment, application version,
and platform version.

### Reusable platform integration

Future production implementation belongs in a versioned Omnilyzer Python package with a
small reviewed public contract for configuration, Django integration, request context,
structured logging, metrics, health helpers, metadata, and bounded startup/shutdown.
Products consume explicit package versions and provide only the configuration or narrow
product hooks they require. Production code must not import or copy Task 009 spike code.

## Consequences

Positive consequences include:

- consistent observability semantics across independently deployed products;
- minimal product-specific implementation;
- a vendor-neutral collector and backend boundary;
- safer logging, tracing, propagation, and metrics defaults;
- bounded metric cardinality and bounded exporter work;
- request and trace correlation without tenant or user identifiers;
- monitoring failures cannot directly take down applications or remove them from
  readiness;
- easier future integration with Grafana, Prometheus, Loki, Tempo, or alternatives
  without selecting them in product code;
- standard application, platform, build, and deployment visibility;
- independent product adoption through normal platform package versions.

Tradeoffs and limitations include:

- tracing, metrics, logging, and context handling add application CPU, memory, and latency
  overhead;
- Task 009's extremely small in-process synthetic handler showed a material throughput
  reduction with observability enabled, but it is not a production capacity benchmark;
- telemetry is intentionally dropped when bounded queues saturate;
- asynchronous exporter initialization, diagnostics, flushing, and shutdown require
  operational discipline;
- OpenTelemetry upgrades require compatibility and emitted-schema regression testing;
- the transitive beta-versioned OpenTelemetry semantic-conventions package used by the
  spike is not part of the accepted Omnilyzer public contract;
- the targeted queue-warning filter depends on the pinned OpenTelemetry SDK's internal
  logger name and exact message tuple and must be reviewed on upgrades;
- Django 6.1 validates this contract against a current Django 6 release but does not
  freeze the future production patch/minor upgrade policy;
- production WSGI/ASGI and multiprocess behavior remain unproven;
- real PostgreSQL ORM tracing remains unproven;
- production internal-network enforcement for `/metrics` remains unproven;
- production collector, backend, sampling, retention, and load behavior remain unproven.

Task 009 measured only 500 in-process requests per condition. In its final recorded run,
observability-disabled p95 was 1.277 ms and unavailable-OTLP p95 was 3.066 ms; throughput
was 1182.2 versus 650.2 requests/second. All requests succeeded, traced-memory growth and
shutdown remained within the spike's bounds, and the result rejects obvious synchronous
coupling. These figures must not be extrapolated to production capacity or service-level
objectives.

## Security implications

- Telemetry is privileged operational data and requires collection, access, retention,
  and deletion controls.
- Tenant and user identifiers are not standard metric labels or default trace attributes.
- Authentication/session secrets, passwords, tokens, cookies, Authorization headers,
  request bodies, and customer content are not emitted into logs or traces by default.
- Observability integration does not bypass or weaken authentication, authorization,
  PostgreSQL RLS, CSRF, CORS, CSP, browser-token handling, or session boundaries.
- Correlation IDs and trace context are telemetry metadata only and grant no security
  privilege.
- Untrusted callers cannot choose canonical request IDs or internal remote trace parents
  by default.
- Trusted request-ID and trace propagation are enabled separately and only behind a
  sanitizing ingress or service boundary.
- Inbound propagation values remain bounded and semantically validated even when trusted;
  baggage is not ingested through the validated path.
- `/metrics` remains internal and depends on network/proxy enforcement.
- `/livez` and `/readyz` reveal minimal state and no detailed dependency failures.
- Telemetry endpoint credentials, TLS, authorization, certificate validation, and network
  topology remain later infrastructure work.

## Operational implications

- Applications continue operating when telemetry infrastructure is unavailable.
- The `BatchSpanProcessor` uses bounded queue, batch, and schedule parameters; the
  exporter uses a bounded request timeout, and tests bound observed retry, memory, latency,
  and shutdown behavior.
- Telemetry loss is preferable to blocking requests or returning telemetry-generated
  failures.
- Deployment owns telemetry initialization, diagnostics, bounded flush, and bounded
  shutdown.
- Queue saturation and exporter failures remain diagnosable without unbounded log storms.
- The future collector implementation remains replaceable behind OTLP.
- Logging and metrics collection, storage, retention, and access are separate
  infrastructure decisions.
- Production trace sampling remains later work.
- Central monitoring infrastructure, capacity, availability, backup, and recovery remain
  separate work.

## Migration and rollback implications

Task 009 created no production observability code. A production implementation must be
designed independently in a versioned Omnilyzer Python package; products must not import
or copy code from `spikes/`.

Products adopt observability through explicit platform package versions and existing
SemVer, exact-pin, review, CI, and staged-deployment mechanisms. Products upgrade
independently. Configuration should permit observability export to be disabled without
making domain behavior depend on telemetry availability.

Rollback of an observability package must preserve application behavior when telemetry
configuration, export, or schemas change. A rollback may restore a prior compatible
product revision and exact package pin when product code has adopted a newer public
contract. Telemetry schema evolution, semantic-convention changes, propagator behavior,
and collector compatibility require regression testing during upgrades and rollback
planning.

## Explicit non-decisions

ADR 0007 does not select, accept, deploy, or define:

- Grafana versus a custom operations portal;
- Prometheus server deployment or topology;
- Loki;
- Tempo versus Jaeger;
- Grafana Alloy versus an upstream OpenTelemetry Collector implementation;
- Alertmanager;
- blackbox exporter;
- `node_exporter`, cAdvisor, PostgreSQL exporter, or Nginx exporter;
- external uptime or Playwright synthetic monitoring;
- certificate or DNS monitoring;
- backup, restore, or PITR monitoring;
- final SLOs or error budgets;
- a production trace-sampling ratio;
- logs, traces, or metrics retention;
- monitoring object storage;
- central monitoring server sizing;
- high availability or disaster recovery for monitoring;
- Kubernetes;
- multi-region observability;
- a final monitoring hostname, including `monitor.omnilyzer.ai`;
- Keycloak/Grafana authentication or authorization design;
- Mimir, Thanos, VictoriaMetrics, or Kafka;
- a custom operations portal implementation.

Prometheus-compatible application metrics are part of the accepted product contract;
Prometheus server infrastructure is not. OTLP is part of the accepted application
contract; collector implementation and backend selection remain separate decisions.
