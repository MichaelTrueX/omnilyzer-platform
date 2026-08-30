<!--
File: spikes/observability/README.md
Purpose: Records Task 009 observability-contract architecture evidence.
Related:
- results/benchmark.json
- spikes/README.md
- docs/architecture/platform-principles.md
-->

# Observability contract validation spike

This is removable architecture evidence, not production implementation. Nothing outside
`spikes/` imports it, and a passing result does not accept a technology direction.

## Hypothesis

Future Python/Django products can inherit one small platform integration that provides
safe JSON logs, canonical correlation IDs, vendor-neutral traces, bounded application
metrics, health semantics, and deployment metadata without coupling domain code to a
collector or making application availability depend on telemetry availability.

The mandatory invariant is:

> Application availability must not depend on observability availability.

## Acceptance criteria

The spike passes only when all of the following are true:

- normal, rejecting-exporter, and unreachable-OTLP request loops return their expected
  application responses without exporter exceptions or telemetry-generated 5xx errors;
- request p95 added by an unavailable exporter stays below 10 ms in the synthetic test,
  shutdown stays below one second, and traced-memory peak growth stays below 8 MiB;
- exporter work uses a bounded queue, timeout, and batch size, with bounded diagnostics;
- JSON logs contain the standard metadata and no representative credentials, request
  body, token, cookie, or CSRF secret;
- correlation IDs are exactly 32 lowercase hexadecimal characters; external values are
  ignored by default, trusted-ingress values remain format-checked, context is isolated
  concurrently, and trace IDs correlate with request logs;
- request metrics use only the closed label set and route templates, never raw IDs,
  users, Workspaces, requests, traces, URLs, query strings, or deployment identifiers;
- `/livez` has no downstream checks, `/readyz` checks only required serving
  dependencies, and telemetry failure cannot change readiness;
- application, platform, source, deployment, and OCI metadata is validated while
  high-churn deployment metadata stays out of per-request metrics;
- tests exercise request, database, and outbound HTTP spans and W3C propagation without
  recording sensitive customer or identity attributes;
- no production infrastructure, credentials, collector, Prometheus server, or product
  package is required.

Failure of any availability, privacy, cardinality, or security criterion fails the
spike. Small synthetic performance results are evidence of obvious suitability only,
not production capacity evidence.

## Architecture under test

```text
Django request
    |
    +-- generated request ID (or validated trusted-ingress ID) -> contextvars -> JSON log
    |
    +-- OTel stable API spans -> bounded BatchSpanProcessor -> OTLP/HTTP
    |                                                   |
    |                                                   +-- collector implementation TBD
    |
    +-- normalized route -> Prometheus client registry -> internal /metrics
    |
    +-- /livez: process only
    +-- /readyz: required serving dependencies only
```

The middleware is above representative Django views and below no domain policy. It does
not read or mutate tokens, sessions, Workspace authorization, database tenant context,
CSRF state, CORS policy, CSP, or browser storage. The synthetic secure endpoint verifies
that authentication, Workspace authorization, CSRF denial, absent CORS grants, and
absent browser cookies retain their application outcomes during exporter failure. This
does not repeat the full accepted authentication or RLS spikes.

Trace export uses OTLP over HTTP/Protobuf. No application code refers to Tempo, Jaeger,
Grafana, Grafana Alloy, or OpenTelemetry Collector configuration. An isolated loopback
HTTP receiver accepts or rejects OTLP payloads without acting as production collector
infrastructure.

## Structured logging contract

The candidate uses Python `logging` with a small JSON formatter rather than a new logging
framework. Every application event has:

| Stable field | Contract |
| --- | --- |
| `timestamp` | UTC RFC3339, millisecond precision |
| `level` | standard bounded logging level |
| `service` | deployment-configured bounded slug |
| `product` | deployment-configured bounded slug |
| `environment` | `local`, `test`, `dev`, `staging`, or `prod` |
| `event` | reviewed lowercase dotted identifier, maximum 64 characters |
| `request_id` | canonical ID or null outside a request |
| `trace_id` | active W3C trace ID or null |
| `fields` | event-specific, recursively sanitized values |

Passwords, access and refresh tokens, Authorization values, session cookies, CSRF
tokens, API keys, secrets, request bodies, and customer document content are denylisted
and redacted. Middleware logs method, normalized route, status class, and duration; it
does not log raw paths, query strings, headers, bodies, users, or Workspaces. Application
processes write locally to stdout/stderr; they never call a central logging service in a
request.

## Correlation-ID decision

The candidate format is 128 random bits rendered as exactly 32 lowercase hexadecimal
characters and generated with `secrets.token_hex(16)`.

- UUID4 is cryptographically appropriate but accepts several textual representations
  unless deliberately narrowed and carries unnecessary punctuation.
- UUID7 is useful for sortable storage, but request correlation needs no time ordering;
  its timestamp leaks creation time and Python 3.12 does not provide it in the standard
  library.
- Fixed random hex has one representation, a trivial length bound, no timing component,
  and no extra dependency.

The secure default ignores every incoming `X-Request-ID`, including a syntactically valid
one, and generates a new canonical ID. A deployment may set
`OBSERVABILITY_TRUST_INCOMING_REQUEST_ID=true` only when a trusted ingress such as Nginx
owns the external boundary and strips or overwrites the caller's header before forwarding
the request. Even then, only the exact canonical form is accepted; uppercase, whitespace,
punctuation, malformed, and oversized values are replaced rather than reflected. No
source-IP trust logic belongs in the application.

Request IDs remain correlation data only: they confer no identity, authorization, tenant,
deduplication, or database meaning. They are returned in `X-Request-ID`, stored in a
resettable `ContextVar`, included in logs, and never used as metric labels.

## OpenTelemetry contract

The stable OpenTelemetry API and SDK create:

- one server span for Django request processing;
- a representative child database span without SQL statement text;
- a representative outbound HTTP client span that injects W3C `traceparent`;
- resource attributes for bounded service, product namespace, and environment only.

Default trace attributes exclude `workspace_id`, `user_id`, email, sessions, tokens,
Authorization, request bodies, customer content, raw query strings, and raw arbitrary
URLs. The middleware extracts only `traceparent` and `tracestate`; it does not ingest
externally supplied baggage into application attributes.

This spike intentionally does not add the beta `opentelemetry-instrumentation-django`
package. The reusable middleware and explicit representative spans use stable OTel APIs.
The stable SDK 1.44.0 nevertheless pins the transitive
`opentelemetry-semantic-conventions==0.65b0`; that beta-versioned semantic-conventions
dependency is an upstream packaging fact and must be reviewed on upgrades. Compatibility
of official Django, database, and HTTP auto-instrumentation remains later work. Static
tests prove application code imports neither `_incubating` nor `opentelemetry.semconv`
APIs. The beta transitive package is not part of Omnilyzer's public contract: the
candidate contract is the stable OpenTelemetry API/SDK plus OTLP. Production dependency
upgrades must regression-test emitted telemetry schemas because semantic-convention
groups can evolve independently.

## Metrics contract and security

Every product should expose:

- `omnilyzer_http_requests_total`;
- `omnilyzer_http_request_duration_seconds` as a histogram with fixed buckets;
- bounded HTTP status/error classification through `status_class`;
- `omnilyzer_build_info` with exactly one series per running deployment identity;
- a bounded trace-export failure counter for operational diagnosis.

Request metrics use exactly these owned dimensions before histogram bucket mechanics:

```text
service, product, environment, method, normalized route, status class
```

Django route templates are converted from `/api/work/<int:item_id>` to
`/api/work/{item_id}`. An unresolved or unsafe template becomes the single value
`unmatched`; raw request paths never become labels.

Prohibited labels include Workspace, user, email, session, request ID, trace ID, IP,
Authorization, query string, arbitrary URL, customer/object/document/order ID, Git
commit, OCI digest, deployment timestamp, application version, and platform version on
request instruments. Prometheus histogram `le` is the client's fixed bucket dimension,
not application-controlled cardinality.

`/metrics` requires no browser login and no bespoke bearer token. It is not an internet
endpoint. The expected production boundary is the backend/internal Docker network and
reverse-proxy/firewall routing that permits only monitoring scrapers. The spike does not
deploy that network rule, so production topology must verify it.

## Health contract

`/livez` means the process can answer a minimal HTTP probe. It performs no database,
network, collector, log-service, or metrics-service call.

`/readyz` means the instance should receive ordinary traffic. Dependency classes that
may affect readiness are limited to those genuinely necessary for correct service:

- valid required application configuration;
- primary database reachability for database-dependent products;
- required migration/schema state;
- a synchronous downstream only when the product cannot serve correctly or degrade
  safely without it.

OTLP exporters, collectors, Grafana Alloy, Prometheus, Loki, Tempo, Grafana, log
shippers, and optional integrations must not affect readiness. Making them dependencies
would turn a diagnostic outage into an application outage and could create cascading
failures exactly when telemetry is most needed. Health responses contain only
`{"status":"alive"}`, `{"status":"ready"}`, or `{"status":"unready"}` and never
contain hosts, credentials, endpoints, stack traces, or detailed dependency errors.

## Application and deployment metadata

`importlib.metadata.version()` is the preferred source for installed application and
platform package versions. The tests resolve installed Django 6.1 and the installed
synthetic spike distribution, and separately exercise arbitrary application/platform
distribution names.

Git commit is a full build-time SHA. Deployment timestamp and final OCI digest are
deployment-time values because the digest does not exist until the image is built.
Complete metadata belongs in controlled deployment inventory and a structured startup
event, not request metric labels. The dedicated `omnilyzer_build_info` series contains
only service, product, environment, application version, and platform version. Git SHA,
OCI digest, and deployment timestamp are deliberately excluded to avoid unnecessary
time-series churn.

## Telemetry failure isolation evidence

Export uses `BatchSpanProcessor` with explicit bounds in the evidence configuration:

```text
queue: 128 spans
batch: 32 spans
schedule delay: 50 ms
total exporter timeout: 100-250 ms
```

The exporter runs outside request threads. A diagnostic wrapper converts exporter
exceptions/rejections to failure results, a bounded reason metric, and rate-limited
structured warnings without rethrowing. Queue saturation drops spans and is itself
diagnosable; it does not block or fail requests.

Pinned OpenTelemetry 1.44.0 emits `Queue full, dropping Span.` from
`opentelemetry.sdk._shared_internal` once for every dropped span; the upstream path has no
warning suppression or rate limit. A targeted logger filter therefore preserves the
first warning and one warning per 60-second interval while suppressing only repeats of
that exact warning/logger/level/argument tuple. It does not suppress unrelated
OpenTelemetry warnings or errors. A blocked-exporter stress test generated more than
1,200 spans across 600 measured successful requests with a 16-span queue and captured
exactly one queue-full warning during the sub-minute burst. Export rejection remained
visible in the bounded failure metric.

Automated failure injection covered an exception-throwing exporter, a loopback receiver
returning HTTP 503, and a connection-refused loopback OTLP endpoint. Repeated application
requests, readiness, and existing 401/403 decisions retained their outcomes. The 503
receiver test bounds observed POST attempts to at most 16 for the fixed test workload.
The unavailable-endpoint test bounds p95 request latency, traced-memory growth, and
shutdown time and checks that callers receive no exporter details or stack traces.

## Measured overhead

The reproducible measurement used CPython 3.12.3, Django 6.1, the in-process synchronous
Django test client, SQLite `SELECT 1`, 25 warmups, and 500 measured requests per
condition. Logging output was suppressed to avoid measuring terminal I/O. Exact evidence
is in [`results/benchmark.json`](results/benchmark.json).

| Condition | Success | Mean | p50 | p95 | Throughput | CPU | Peak traced growth | Shutdown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Observability disabled | 500/500 | 0.838 ms | 0.798 ms | 1.089 ms | 1189.4 req/s | 0.4203 s | 272,601 B | 0.001 ms |
| OTLP accepting | 500/500 | 1.765 ms | 1.479 ms | 3.155 ms | 565.7 req/s | 0.8999 s | 830,232 B | 0.221 ms |
| OTLP unavailable | 500/500 | 1.472 ms | 1.315 ms | 1.979 ms | 678.4 req/s | 0.7496 s | 1,082,375 B | 0.202 ms |

Unavailable OTLP added 0.890 ms at p95 versus the disabled baseline, stayed below the
8 MiB synthetic memory bound, and shut down below one second. The accepting receiver saw
16 OTLP requests and 80,814 payload bytes. The roughly 43% synthetic throughput drop is
material evidence to carry forward, but the ratio is exaggerated by a sub-millisecond
in-process baseline and cannot predict production throughput. Sampling, real WSGI/ASGI,
networking, PostgreSQL, log I/O, multiprocess workers, and production load require later
measurement.

## Security checks

| Check | Evidence |
| --- | --- |
| Credentials committed | synthetic values only; static repository checks reject key/credential patterns |
| Tokens, cookies, Authorization, CSRF, bodies in logs | representative secret values absent from captured JSON |
| Sensitive/default trace attributes | forbidden keys and values absent from exported spans |
| High-cardinality metrics | closed label set and raw-ID route attacks tested |
| Exporter details/stack traces to callers | absent during exception and unavailable-endpoint cases |
| Request-ID abuse | valid external ID ignored by default; trusted-ingress mode remains exact-format bounded; malformed and 4 KiB inputs replaced |
| Queue/log storm | 600-request blocked-exporter burst emitted exactly one queue warning; unrelated OTel warning/error records remained visible |
| Concurrent context leakage | eight synchronized Django requests retained distinct IDs |
| Authentication/authorization | synthetic 401/403/200 outcomes unchanged by telemetry failure |
| CSRF/CORS/browser cookies | CSRF denial retained; no CORS grant or browser token cookie introduced |
| Workspace/RLS | middleware does not read/mutate Workspace headers or DB context; accepted RLS behavior is not reimplemented here |
| Health exposure | exact minimal bodies only |
| Availability | all outage requests succeeded; bounded queue, latency, memory, retry, and shutdown evidence passed |

## Test approach

From the repository root:

```bash
python3 -m venv /tmp/omnilyzer-task009-venv
/tmp/omnilyzer-task009-venv/bin/python -m pip install --upgrade pip==26.0.1
/tmp/omnilyzer-task009-venv/bin/python -m pip install -r spikes/observability/requirements-lock.txt
/tmp/omnilyzer-task009-venv/bin/python -m pip install --no-deps -e spikes/observability
cd spikes/observability
/tmp/omnilyzer-task009-venv/bin/python manage.py check
/tmp/omnilyzer-task009-venv/bin/python manage.py test tests --verbosity 2
/tmp/omnilyzer-task009-venv/bin/python scripts/benchmark.py
cd ../..
/tmp/omnilyzer-task009-venv/bin/python -m pip check
/tmp/omnilyzer-task009-venv/bin/python -m compileall -q spikes/observability
```

The tests need no production system, credential, collector, Prometheus server, Docker,
Kubernetes, or external network after dependencies are installed.

## Dependencies

All dependencies are spike-only and exact direct pins are in `pyproject.toml`; the full
environment is in `requirements-lock.txt`.

| Direct dependency | Purpose | License / maturity | Why required |
| --- | --- | --- | --- |
| Django 6.1 | accepted backend and real middleware/request/health fixture | BSD-3-Clause; stable | validates Task 009 against a current Django 6 release; it does not freeze future production patch/minor upgrade policy |
| OpenTelemetry API 1.44.0 | vendor-neutral trace and propagation contract | Apache-2.0; stable | Python has no standard trace/OTLP API |
| OpenTelemetry SDK 1.44.0 | tracer provider and bounded batch processing | Apache-2.0; stable | implements sampling/export lifecycle behind the API |
| OTLP HTTP exporter 1.44.0 | standard collector-neutral Protobuf export | Apache-2.0; stable | proves the real OTLP boundary and outage behavior |
| Prometheus client 0.26.0 | canonical exposition, counters, gauges, histograms | Apache-2.0/BSD-2-Clause; official client, PyPI beta classifier | avoids inventing metric formats and bucket mechanics |

No logging framework, collector SDK, Grafana library, retry library, HTTP client, UUID
package, benchmark framework, or test framework was added directly. The standard library
provides JSON formatting, context variables, cryptographic randomness, synthetic HTTP
receivers, outbound HTTP, timing, memory measurement, and unittest support.

## Findings and architecture-question answers

1. **OpenTelemetry:** appropriate as a product-side tracing candidate because its stable
   API, W3C propagation, and OTLP boundary remained collector-neutral.
2. **Failure isolation:** yes under the tested bounds; async export failures, rejection,
   and connection refusal did not change application or readiness responses.
3. **Logging:** standard-library newline JSON with the stable envelope, reviewed event
   names, sanitized structured fields, stdout/stderr output, and no synchronous backend.
4. **Correlation format:** exactly 32 lowercase hex characters representing 128 random
   bits.
5. **External trust:** ignore incoming IDs by default. Accept exact-format values only in
   explicitly configured trusted-ingress mode, where the reverse proxy has already
   stripped/overwritten the caller header. IDs remain non-security metadata.
6. **Standard HTTP metrics:** request counter, status class, and fixed-bucket duration
   histogram, plus bounded build and exporter diagnostics.
7. **Prohibited labels:** identity, tenant, correlation, network/client, arbitrary URL,
   object, secret, and high-churn deployment dimensions listed above.
8. **Route normalization:** only framework-owned templates; unmatched input collapses to
   one value and raw paths never become labels.
9. **Liveness:** process can answer a minimal probe, without downstream calls.
10. **Readiness:** required configuration/database/schema and only indispensable serving
    dependencies are healthy.
11. **Readiness dependencies:** database and migration state normally qualify; optional
    integrations and observability do not.
12. **Why exclude observability:** diagnostic failure must not amplify into traffic loss
    or a cascading outage.
13. **Metadata:** installed package metadata for app/platform versions, build-time Git
    SHA, and deployment-time OCI digest/timestamp.
14. **Git/OCI/time:** controlled deployment inventory and startup event, not request
    labels; build-info retains bounded versions only.
15. **Reusable adoption:** a future versioned platform package should expose one settings
    parser, middleware, metrics registry, health helpers, metadata loader, and startup/
    shutdown hook with minimal product configuration.
16. **Collector portability:** the same OTLP product instrumentation can target Alloy or
    upstream Collector without product-code changes; neither was deployed here.
17. **Measured overhead:** table above; suitable for continued validation, not production
    sizing.
18. **Unproven:** real worker topology, Postgres/ORM coverage, ASGI, auto-instrumentation,
    sampling, network security, production load, retention, and operations.
19. **ADR:** the evidence justifies drafting a **Proposed** ADR for review; it does not
    justify silently marking the direction accepted or copying this spike into production.

## Privacy and cardinality findings

The safest default is omission, not exhaustive redaction. Redaction is defense in depth
for reviewed event fields; arbitrary request capture remains prohibited. Request and
trace correlation is possible without customer identifiers. Route templates and closed
labels kept three different object IDs in one time series. Build metadata needs two
planes: bounded version identity in Prometheus and complete deployment identity in
inventory/log evidence.

## Limitations

- The fixture is synchronous WSGI-style Django test-client evidence, not Gunicorn/Uvicorn,
  ASGI, or multiprocess evidence.
- SQLite `SELECT 1` is representative span evidence, not PostgreSQL ORM/query coverage.
- Database and HTTP spans are explicit; official beta auto-instrumentation was not tested.
- The loopback receiver validates OTLP delivery behavior but does not parse every semantic
  field or represent Alloy/Collector operations, TLS, authentication, buffering, or HA.
- Prometheus multiprocess mode, worker aggregation, scrape concurrency, and real internal
  network isolation remain untested.
- The benchmark suppresses log I/O, uses a tiny synthetic handler, and is not capacity,
  cost, tail-latency, or long-duration leak evidence.
- Memory evidence is Python `tracemalloc`, not full process RSS over hours.
- Queue saturation deliberately drops telemetry. Production sampling, queue sizing, and
  acceptable diagnostic loss need workload evidence.
- Queue-warning mitigation intentionally binds to the pinned SDK's exact internal logger
  name and message tuple. Every OpenTelemetry upgrade must regression-test that narrow
  integration and remove or revise it if upstream behavior changes.
- Redaction cannot make arbitrary logging safe; code review and allowlisted events remain
  required.
- Full Keycloak/BFF, PostgreSQL RLS, CSP, CORS topology, and real product authorization are
  preserved architectural boundaries but were not redeployed by this isolated spike.

## Recommendation

### RECOMMENDED CANDIDATE DIRECTION

- OpenTelemetry stable API/SDK with OTLP as the product-side trace boundary.
- A versioned Omnilyzer Python package providing the strict configuration, middleware,
  context, JSON formatter, metrics, health helpers, metadata, and bounded lifecycle.
- Python standard logging to stdout/stderr, fixed random-hex correlation IDs,
  Prometheus-compatible internal metrics, and observability-independent readiness.
- Batch export with explicit queue, timeout, batch, diagnostic, and shutdown bounds.
- Generated request IDs by default; optional incoming-ID trust only behind a reverse proxy
  that sanitizes and overwrites the external header before forwarding.

### TO VALIDATE LATER

- proposed ADR review and exact public package API;
- Django Ninja integration, ASGI/context behavior, official auto-instrumentation, real
  PostgreSQL ORM spans, and outbound client conventions;
- sampling and exemplar policy, multiprocess metrics, production worker topology, and
  performance under representative workloads;
- TLS/auth to the collector, final Alloy versus upstream Collector operations, buffering,
  deployment, cost, and disaster recovery;
- real internal `/metrics` network enforcement and controlled complete metadata inventory;
- logging retention/access policy, schema evolution, and operational dashboards/alerts in
  separately scoped work.

### REJECTED / NOT CURRENTLY PLANNED

- synchronous request calls to Loki, Tempo, Grafana, or any collector;
- observability as a readiness dependency;
- raw paths, queries, request/trace/user/Workspace IDs, secrets, or deployment digests as
  request labels;
- request-body or authentication-header logging by default;
- direct Internet control of canonical request IDs, arbitrary external request IDs,
  bespoke metrics bearer tokens, vendor-specific product
  APIs, Kafka, Kubernetes, or production observability infrastructure in this task.

## Unresolved questions

- What sampling policy preserves security diagnostics without excessive volume?
- Should the platform expose explicit span helpers or rely primarily on reviewed official
  auto-instrumentation once Django 6 compatibility is proven?
- How should Gunicorn/ASGI workers aggregate Prometheus metrics and perform bounded flush?
- Which route-template adapter is required for Django Ninja operation IDs and 404s?
- What are acceptable production p95/CPU/memory budgets per product workload?
- Which complete deployment metadata system owns OCI digest and deployment-time history?
- What internal network and proxy controls protect `/metrics` in each initial deployment?
- Which collector candidate, security topology, retention policy, and operating owner pass
  later infrastructure validation?
