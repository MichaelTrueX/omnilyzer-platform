# ADR 0008: Prometheus Metrics Scraper and Query Component

- Status: Accepted
- Date: 2026-08-31

## Context

Omnilyzer needs an initial server-side metrics component that can scrape application
metrics, provide local time-series history under explicit finite operational storage
bounds, support useful queries, expose independent target health, and remain operationally
proportionate to the platform's initial scale. Independently deployed products need one
consistent metrics control-plane direction rather than product-specific monitoring
backends.

[ADR 0007](0007-product-observability-contract.md) already accepts the **product-side**
observability contract, including:

- Prometheus-compatible application metrics;
- a closed low-cardinality label vocabulary;
- normalized framework route templates rather than raw paths;
- internal-only `/metrics` semantics;
- bounded build-info metadata; and
- application availability and readiness independent of observability availability.

Prometheus-compatible metrics are not the same decision as Prometheus server. ADR 0007
defines what products expose; it deliberately does not select the server that scrapes,
stores, or queries those metrics. This ADR concerns that server-side component only.

[Task 010 Prometheus metrics evidence](../../spikes/prometheus-metrics/README.md) tested a
real Prometheus server against the ADR 0007 contract. Three synthetic targets represented
multiple products and environments. The spike validated real scraping and PromQL/API
queries, target `up`, closed cardinality under hostile inputs, internal target networking,
Prometheus outage isolation, individual target failure isolation, recovery, build-info
history, and Python-client multiprocess behavior.

Task 010 used Prometheus 3.14.0, an exact digest-pinned official image, explicit one-second
scrape intervals, 500-millisecond scrape timeouts, and ephemeral storage bounded to 30
minutes and 64 MB. Those are test inputs, not permanent production defaults, storage
limits, or capacity recommendations.

The principal evidence was:

- 11,300 distinct hostile raw identifiers produced 22 populated base request-label sets;
- those sets produced exactly 352 request series under the tested Python-client mechanics;
- raw identifiers did not expand normalized route labels;
- no tested tenant, user, request, trace, session, Authorization, query, or customer
  identifier appeared in Prometheus-visible labels;
- stopping Prometheus caused zero failures across 503 synthetic application, security,
  liveness, and readiness checks and did not restart the application;
- a failed target became `up=0` while a healthy target remained `up=1`;
- slow and malformed targets failed independently and recovered after restoration; and
- Python multiprocess aggregation worked with explicit Gauge and process-lifecycle rules.

The local suitability run observed three targets, more than 11,000 synthetic requests,
low single-digit-millisecond scrape durations, approximately 34 MiB Prometheus memory,
approximately 1 ms representative local query latency, and automatic restart recovery.
These numbers reject obvious architectural problems but do not predict production
capacity, production latency objectives, or behavior at 10,000 or 100,000 users.

## Options considered

### Prometheus server

Prometheus can natively scrape the accepted exposition format, provides a mature pull
model, records independent target health, stores local time-series data, and supports
PromQL and an HTTP API. It can begin with a comparatively simple deployment and does not
require product applications to adopt provider-specific SDKs. Its application boundary
remains replaceable because products expose a standard metrics contract.

Prometheus still introduces operational responsibility for discovery, access control,
storage, retention, upgrades, resource use, query governance, recovery, and its own
monitoring. A single server is not highly available, and Prometheus does not make
unbounded application labels safe.

### No standardized metrics server

Each product could choose its own scraper, store, and query system. This preserves local
autonomy but duplicates operational work, fragments query and target-health semantics,
and makes cross-product operations and platform metric evolution harder. Products could
also diverge from the accepted cardinality and security boundary.

### Direct vendor or SaaS integration from products

Products could send metrics through provider-specific libraries or APIs. This may offer
managed operations and vendor features, but it couples product code and upgrades to the
provider. It would weaken the open product boundary accepted by ADR 0007 and could make
provider availability part of application telemetry behavior.

### Distributed metrics infrastructure from the beginning

Mimir, Thanos, VictoriaMetrics, or another horizontally distributed system could address
long retention, large fleets, high availability, or multi-region needs. The current
evidence does not establish those requirements. Selecting distributed infrastructure now
would add components and operational cost before scale, retention, and availability needs
are measured. Such systems remain credible future options rather than permanent
rejections.

### A logs- or traces-oriented backend as the metrics system

Another observability backend could be extended to receive or store metrics. This may
simplify a future unified operations stack, but the logs/traces infrastructure is not yet
selected and should not drive the initial metrics decision without direct metrics
evidence. Metrics should retain their standard exposition and query boundary regardless
of future visualization or tracing choices.

Prometheus is selected for the initial direction because it directly consumes the
accepted contract, provides a mature pull and query model, isolates target health, is
open source, and can start without distributed metrics infrastructure. The standard
product boundary preserves a later migration path if requirements outgrow the initial
component.

## Decision

Prometheus server is the initial Omnilyzer metrics scraper, local TSDB, and PromQL query
engine. Production storage operates with explicit finite retention and/or storage limits,
but the exact retention duration, storage size, disk architecture, backup model, and
availability architecture remain separate operational decisions.

```text
Omnilyzer application
       |
    /metrics
       |
       v
 Prometheus
       |
   PromQL/API
       |
 future visualization /
 alerting / operations
```

The accepted scope ends at the Prometheus query/API boundary. No visualization,
alert-delivery, logs, tracing, collector, portal, or complete monitoring platform is
selected by this ADR.

### Scrape model

1. Prometheus uses pull-based scraping of internal Omnilyzer `/metrics` endpoints.
2. Application metrics targets are not exposed to the public Internet merely to support
   scraping.
3. Scrape interval and timeout are explicit reviewed configuration.
4. `scrape_timeout` remains less than `scrape_interval`.
5. The exact production interval and timeout remain operational settings to validate;
   Task 010's one-second and 500-millisecond values are synthetic test values only.
6. Each target's scrape state is independently observable, including a state such as
   `up=0` for a failed target.
7. One failed, slow, unavailable, or malformed target does not invalidate monitoring of
   healthy targets.
8. Prometheus availability does not affect application liveness, readiness,
   authentication, authorization, or domain availability.

### Cardinality contract

Prometheus is acceptable only while the ADR 0007 closed application-label contract is
preserved. Prometheus does not make arbitrary high-cardinality labels safe.

Ordinary request dimensions remain a reviewed finite set such as:

- service;
- product;
- environment;
- HTTP method;
- normalized route template; and
- bounded status class.

Caller-controlled identifiers—including Workspace, user, email, session, request,
trace, IP, Authorization, query-string, raw URL, customer, object, document, and order
identifiers—do not become ordinary request metric labels. Raw unmatched paths collapse
to a bounded fallback.

Task 010's 11,300 hostile identifiers produced 22 populated base request-label sets and
exactly 352 request series. One populated label set produced 16 series in that fixture:
one counter, one counter `_created`, eleven histogram buckets including `+Inf`, histogram
sum, count, and `_created`. `_created` emission is Python-client configuration behavior;
16 is not a universal Prometheus law or capacity rule. This ADR does not freeze a global
maximum-series number. Each product metric and label-vocabulary change still requires
cardinality review and automated regression evidence.

### Network and security boundary

1. Application `/metrics` endpoints are internal scraper endpoints.
2. The metrics plane reaches targets through internal deployment networking without
   requiring public target ports.
3. The Prometheus UI and API are privileged operator surfaces and use a reviewed
   private/internal operator access path by default. Direct public Internet exposure is
   not accepted by this ADR. Any future requirement for Internet-accessible operator
   endpoints requires separate security review and architecture approval.
4. Production target-network enforcement, private/internal operator-access
   implementation, and operator authentication/authorization remain later topology and
   security implementation decisions.
5. Application credentials, tenant/user secrets, session material, Authorization data,
   and customer content do not belong in metric labels or committed configuration.
6. Prometheus administration or lifecycle endpoints are not enabled without explicit
   operational need and review.
7. Remote write is not required by this decision.
8. Prometheus is not an authentication, authorization, tenancy, session, or application
   health-decision service.

This ADR does not select Cloudflare rules, WireGuard, a VPN, final firewall policy, an
authentication proxy, or Keycloak integration for Prometheus.

### Python multiprocess requirements

Python multiprocess metrics are viable only with explicit application, process-manager,
and deployment lifecycle integration:

1. Task 009's single-process metric implementation is evidence, not production code to
   copy unchanged.
2. The future versioned Omnilyzer metrics package explicitly supports the selected
   production worker topology.
3. Build-info does not use the Python client's default multiprocess Gauge `all` mode when
   it would produce per-PID deployment-identity series that survive worker death.
4. Build-info uses a deliberate live Gauge mode or equivalent implementation that
   exposes one bounded logical deployment identity with value `1`.
5. `livemax` passed Task 010 as a candidate, but this ADR does not permanently select
   `livemax` or another exact Gauge mode.
6. The process manager integrates worker-death handling required by the client so stale
   live Gauge files do not accumulate.
7. `PROMETHEUS_MULTIPROC_DIR`, or equivalent lifecycle storage, is empty and clean before
   each complete deployment/process-manager start.
8. Worker exit/replacement and complete process-manager/deployment restart are distinct
   lifecycle events. Worker-death handling does not replace deployment-start cleanup.
9. Counter and histogram values retain correct cumulative meaning across worker
   replacement within one deployment lifecycle.
10. Real WSGI, ASGI, rolling-deployment, and process-manager integration remain to
    validate. This ADR does not select Gunicorn or another process manager.

### Build-info

The bounded current build-info identity may include:

- service;
- product;
- environment;
- application version; and
- Omnilyzer platform version.

Git SHA, OCI digest, and deployment timestamp do not become ordinary request labels.
Complete deployment identity remains controlled deployment inventory or startup
evidence, as accepted by ADR 0007.

Historical build-info identities naturally remain in time-series history until normal
staleness and retention behavior removes them from relevant query contexts. Queries,
recording rules, dashboards, and operational consumers must deliberately distinguish
current state from historical series. This ADR does not select retention.

### Prometheus version

Prometheus 3.14.0 is the exact version validated by Task 010, not a permanent production
version commitment. The architectural decision is Prometheus server.

Production deployment selects a supported release and considers the Prometheus LTS and
support policy current at deployment time. Version upgrades regression-test:

- application scrape compatibility;
- PromQL behavior used by Omnilyzer;
- configuration validation;
- local storage behavior and compatibility;
- security settings;
- resource use; and
- compatibility with the accepted application metric contract.

### Storage and retention

Prometheus local TSDB is part of the accepted initial component. Production storage has
explicit finite retention and/or storage limits so its resource use is operationally
bounded. Task 010's ephemeral 30-minute and 64-MB limits are test evidence only and are
not production defaults. The exact retention duration, storage size, disk architecture,
storage lifecycle, backup model, high-availability architecture, remote write, object
storage, and long-term archive remain separate operational decisions requiring later
evidence. This ADR does not infer them from the synthetic resource measurements.

## Consequences

Positive consequences include:

- direct compatibility with the ADR 0007 product contract;
- a standard pull-based metrics model;
- independent target scrape health;
- PromQL and its open ecosystem;
- no product coupling to a vendor-specific metrics SDK;
- simpler initial operation than an unproven distributed metrics system;
- application portability to another compatible backend if future requirements justify
  replacement;
- application availability remains independent of monitoring availability; and
- one standard server-side metrics direction across products.

Tradeoffs and limitations include:

- Prometheus becomes operational infrastructure requiring explicit ownership;
- local storage requires explicit finite operational bounds, while exact retention,
  capacity, disk, backup, availability, upgrade, restart, and recovery choices need
  management and further evidence;
- a single Prometheus server is not highly available;
- application cardinality discipline remains mandatory;
- PromQL and current-versus-historical query conventions need governance;
- Python multiprocess deployments require client, process-manager, and deployment
  lifecycle integration;
- target discovery and operator access controls require production design;
- supported-version upgrades require regression evidence; and
- historical build-info series can mislead queries that do not select current state
  correctly.

Task 010 validates architecture mechanics only. Three targets, approximately 34 MiB
observed memory, low single-digit-millisecond scrape times, approximately 1 ms local query
latency, and automatic recovery do not prove production HA, fleet-scale discovery,
capacity, storage sizing, or latency objectives.

## Security implications

- Prometheus contains privileged operational metadata and requires controlled access,
  retention, and lifecycle policy.
- `/metrics` remains an internal endpoint.
- The Prometheus UI and API are privileged operator surfaces whose production default is
  a reviewed private/internal access path.
- Sensitive application data is excluded at metric creation; access controls are not a
  substitute for label-data minimization.
- Network policy is part of the security boundary.
- Prometheus grants no identity, authentication, authorization, tenancy, or session
  privilege.
- Scrape health does not influence application authorization or readiness decisions.
- Direct public Internet exposure of the Prometheus operator surface is not accepted by
  this ADR. Any future requirement requires separate security review and architecture
  approval.
- Final operator-interface authentication and authorization technology remains to
  validate.
- Administration and lifecycle features remain disabled unless an explicit operational
  requirement and security review justify them.
- No credentials are embedded in application metrics or committed Prometheus
  configuration.

## Operational implications

Production implementation must establish ownership and procedures for:

- scrape configuration and validation;
- target discovery and removal;
- production target-network enforcement and private/internal operator access controls;
- explicit finite storage limits, storage lifecycle, and capacity monitoring;
- supported-version selection and upgrades;
- restart and recovery;
- PromQL and query-convention governance;
- Python worker-death and deployment-start lifecycle integration;
- resource monitoring; and
- eventual monitoring of Prometheus itself.

Final alert delivery and Alertmanager selection are outside this ADR. Final retention,
backup, HA, and disaster-recovery obligations depend on later requirements and evidence.

## Migration and rollback implications

Products remain coupled to the ADR 0007 Prometheus-compatible product contract rather
than Prometheus-specific application APIs. If a future system can scrape or ingest the
same bounded contract, replacing Prometheus should not require rewriting domain
instrumentation.

Prometheus version upgrades and rollback are infrastructure operations. Application
requests continue during metrics-server deployment, outage, or rollback. A rollback
must account for Prometheus configuration, TSDB format and compatibility, supported
upgrade/downgrade paths, and recovery state. The exact production upgrade and rollback
runbook remains future implementation work.

Product metric schema changes follow the versioned platform-package process and require
query/cardinality compatibility testing. Multiprocess lifecycle changes require
coordinated application-package, process-manager, and deployment validation.

## Explicit non-decisions

ADR 0008 does not select, accept, deploy, or define:

- Grafana;
- Loki;
- Tempo;
- Jaeger;
- Grafana Alloy;
- an OpenTelemetry Collector implementation;
- Alertmanager;
- blackbox exporter;
- `node_exporter`;
- cAdvisor;
- PostgreSQL exporter;
- Nginx exporter;
- Playwright synthetics;
- final service discovery;
- final Prometheus authentication or authorization;
- Keycloak/Grafana integration;
- a final scrape interval or timeout;
- final retention;
- production disk sizing;
- remote write;
- Mimir;
- Thanos;
- VictoriaMetrics;
- monitoring object storage;
- monitoring high availability;
- monitoring backup or disaster recovery;
- multi-region metrics;
- Kubernetes;
- a final monitoring hostname;
- recording rules;
- alert rules;
- SLOs or error budgets;
- a final Python worker or process manager; or
- the exact build-info multiprocess Gauge mode.

Prometheus 3.14.0 remains exact Task 010 evidence rather than a permanently selected
version. Prometheus server is accepted only as the initial metrics scraper, local TSDB,
and PromQL query engine. No complete monitoring platform is accepted by this ADR.
