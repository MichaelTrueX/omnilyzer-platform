<!--
File: spikes/prometheus-metrics/README.md
Purpose: Records Task 010 Prometheus server, cardinality, multiprocess, and isolation evidence.
Related:
- spikes/README.md
- spikes/observability/README.md
- docs/adr/0007-product-observability-contract.md
-->

# Task 010: Prometheus Metrics Validation

## Classification

**TASK 010 — PASS**

This is architecture evidence for a **RECOMMENDED CANDIDATE DIRECTION**. It does not
accept Prometheus server, create production code, or select production monitoring
infrastructure. A reviewed ADR is required for acceptance.

## Hypothesis

An official Prometheus server can scrape and query the accepted ADR 0007 product
metrics contract across independent products while preserving closed cardinality,
private target networking, application availability, target-failure isolation, and
understood Python multiprocess semantics.

## Acceptance criteria

The spike passes only if real Prometheus queries prove all four standard metric
families, raw identifiers cannot expand route cardinality, unmatched paths collapse,
synthetic sensitive values remain absent, targets require no host-published metrics
port, Prometheus outages do not affect application or health behavior, one failed
target does not affect healthy targets, recovery is automatic, and multiprocess
aggregation has explicit non-silent lifecycle requirements.

It fails on any Task 010 failure gate, including public target exposure, unbounded
caller-controlled labels, monitoring-dependent readiness, silently incorrect
multiprocess meaning, committed credentials, or dependence on another monitoring
backend.

## Architecture under test

```text
host validation process
        |
        | 127.0.0.1:19090 only
        v
  Prometheus 3.14.0
        |
        | metrics-internal Docker network
        +----------------+----------------+
        v                v                v
  valoria/dev      chronicle/staging  synthetic/test
  target :8000     target :8000       failure target :8000
  no host port     no host port       no host port
```

Prometheus alone also joins a validation-only bridge network so Docker can implement
the loopback host mapping. The application targets join only the Docker `internal`
network. They do not publish ports. The fixtures are synthetic and do not contact DEV,
PROD, or any external monitoring system.

## Technology and versions

| Component | Exact version | Source and purpose |
|---|---:|---|
| Prometheus server | 3.14.0 | Exact version tested from the official [Prometheus project](https://prometheus.io/), Apache-2.0 |
| Prometheus image | `prom/prometheus:v3.14.0` | Official project container |
| Image digest | `sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0` | Immutable Linux/amd64 image used for validation |
| Python | 3.12.3 | Synthetic target only; base image is digest-pinned |
| `prometheus-client` | 0.26.0 | Official Python client; metric exposition and multiprocess test |

The one Python dependency is spike-local, exact-pinned, and hash-verified in
`requirements.txt`. It is already the accepted Task 009 fixture version; Task 010
does not add a production dependency.

Prometheus 3.14.0 is the exact spike version, not a permanently selected production
version or support line. Production review must select and maintain a supported release,
consider the Prometheus LTS/support policy then in force, and regression-test upgrades.
Nothing in this fixture relies on a known 3.14-specific product contract.

## Network and security model

- Target ports are only exposed to `metrics-internal`, which is declared `internal`.
- Prometheus test API access is `127.0.0.1:19090`; no `0.0.0.0` host publication exists.
- Containers use a non-root UID, read-only root filesystems, all capabilities dropped,
  `no-new-privileges`, and bounded temporary filesystems.
- Prometheus admin and lifecycle APIs are not enabled. There is no remote write,
  external storage, authentication secret, or real endpoint.
- Production must protect the Prometheus UI/API and target `/metrics` path using
  reviewed network/proxy policy. This spike neither selects authentication technology
  nor claims that its Docker topology is a production firewall design.

## Metrics contract under test

The target exposes the ADR 0007 names without a competing convention:

- `omnilyzer_http_requests_total`
- `omnilyzer_http_request_duration_seconds`
- `omnilyzer_build_info`
- `omnilyzer_telemetry_export_failures_total`

Request labels are exactly `service`, `product`, `environment`, `method`, normalized
`route`, and bounded `status_class`. Histograms use the fixed Task 009 buckets. Methods
outside the reviewed vocabulary collapse to `OTHER`; statuses collapse to `1xx` through
`5xx` or `other`; unmatched paths collapse to `unmatched`.

## Cardinality model

For this controlled fixture the maximum base request-label combinations are:

```text
3 service/product/environment identities
× 8 bounded methods
× 8 normalized routes
× 6 bounded status classes
= 1,152 base request label sets
```

With `_created` emission enabled in the tested `prometheus-client` 0.26.0 fixture, one
populated request label set produces exactly 16 series:

```text
request counter                         1
request counter _created                1
histogram configured finite buckets    10
histogram +Inf bucket                    1
histogram _sum                           1
histogram _count                         1
histogram _created                       1
                                        --
                                        16
```

The eleven bucket series are the ten explicitly configured finite buckets plus the
client-generated `+Inf` bucket. If Python-client `_created` emission were disabled,
both the counter `_created` and histogram `_created` series would disappear, producing
`1 + 11 + 1 + 1 = 14` series per populated label set. `_created` emission is a Python
client configuration behavior, so 16 is the tested fixture count—not a universal
Prometheus law. With the tested settings, the configured ceiling is therefore 18,432
request series if every finite combination is populated; with `_created` disabled it
would be `1,152 × 14 = 16,128`. Neither is a universal production safety limit.

The live workload created 11,300 distinct raw identifiers across user and unmatched
paths. It observed 22 populated base label sets and exactly 352 request series:
`22 × 16 = 352`. The actual route vocabulary was eight values. The 1,100 unmatched
raw paths produced two `unmatched` series, one for each exercised product identity,
not one series per raw path.

## Multiprocess model and findings

The negative case instantiated `omnilyzer_build_info` exactly as an ordinary Gauge,
without `multiprocess_mode`. In `prometheus-client` 0.26.0 the default is `all`. Two
workers with the same build identity produced two series, each value `1`, with an
internally added `pid` label. Calling `multiprocess.mark_process_dead(pid)` for one and
then both workers removed neither series. The hook removes only `live*` Gauge files;
ordinary/non-live Gauge files intentionally remain until the whole directory is wiped.
Although `pid` is client-added rather than application-controlled, this per-worker,
dead-worker-retaining shape violates ADR 0007's bounded deployment-identity intent.

Task 009 proved the Gauge in one process and correctly remains unchanged. Its spike
declaration has no explicit multiprocess mode, however, so it is evidence—not production
code to copy unchanged into a multiprocess deployment. A future Omnilyzer metrics package
must deliberately choose build-info's multiprocess Gauge semantics.

The positive candidate used explicit `livemax`. Two living workers with the same build
identity produced one logical series, value `1`, with no exposed `pid`. After one worker
exited and the process manager called `mark_process_dead(pid)`, the remaining worker
still produced one series at `1`. A deliberately unclean old-version worker left its
old identity visible alongside the new identity; calling the hook removed that stale
live Gauge and left only the new build identity. `livemax` is therefore a viable
candidate for build-info's invariant value, but Task 010 does not permanently accept
the exact mode; production integration must review it with the selected worker topology.

Counters and histograms have different lifecycle semantics. Their values aggregated
exactly to 12 across workers (5 + 7), remained cumulative at 12 after normal worker
exit, and became 15 when a replacement worker added 3. `mark_process_dead` does not
delete those counter/histogram files; preserving their deployment-lifetime cumulative
meaning across worker replacement is intentional.

Worker exit and complete deployment restart are separate lifecycle events:

- **Worker exit/replacement:** the process manager must call
  `multiprocess.mark_process_dead(pid)` so `live*` Gauge files are removed. Counters and
  histograms remain cumulative within that deployment lifecycle.
- **Complete process-manager/deployment restart:** startup must wipe
  `PROMETHEUS_MULTIPROC_DIR` before workers start. The worker-death hook is not a
  substitute. Without the wipe, the new deployment's two requests aggregated with old
  files to 19; after the wipe, the same new deployment correctly reported 2.

A future platform package can hide registry construction and explicit Gauge selection,
but it cannot eliminate deployment/process-manager responsibilities. The directory
must be set before client import, writable and empty at deployment start, and integrated
with worker-death hooks. Official client limitations also include unsupported Info/Enum,
exemplars, custom collectors, and remove/clear behavior in multiprocess mode. Production
worker topology remains unselected and **TO VALIDATE LATER**.

## Failure-isolation tests

Prometheus was stopped during a target-local request loop. All 503 checks passed:
500 domain requests, `/livez`, `/readyz`, and the expected unauthorized response. The
application container ID remained unchanged, proving no restart. Prometheus restarted
and all three targets returned to `up=1` automatically in 5.791 seconds.

The reverse direction was also tested:

- stopped target: `up=0` in 0.506 seconds while healthy target remained `up=1`;
- restarted target: recovered in 0.757 seconds;
- 2-second target response against a 500 ms timeout: `up=0` in 1.513 seconds;
- after repeated slow-target timeouts, the target had 4 PIDs/threads against an
  acceptance bound of 8, with no continuing accumulation observed;
- malformed exposition: `up=0` while healthy target remained `up=1`;
- restored exposition: recovered in 0.506 seconds.

The explicit 500 ms scrape timeout is less than the explicit 1-second interval. This
prevents a slow scrape from occupying the whole interval indefinitely. These aggressive
values make the isolated test quick; they are tested values, not a production interval
decision.

## Measured evidence

| Measurement | Observed result |
|---|---:|
| Targets | 3 |
| Synthetic application requests before outage | 11,314 |
| Distinct hostile raw IDs | 11,300 |
| Prometheus-observed request count | 11,404 (includes probes/scrapes) |
| Populated base request label sets | 22 |
| Actual request series including histogram mechanics | 352 |
| Expected from populated sets | 352 |
| Scrape duration, alpha/beta/flaky | 5.74 / 1.55 / 1.62 ms |
| Representative PromQL query latency | 1.069 ms |
| Representative 1-minute request-rate query | 0.160 requests/s after restart |
| Prometheus observed memory | 34.16 MiB |
| Prometheus observed CPU | 0.77% |
| Prometheus PIDs | 13 |
| Prometheus restart-to-scrape recovery | 5.791 s |

Resource and timing observations are one local synthetic run on 2026-08-31. They are
sufficient to reject obvious coupling or runaway cardinality but are not capacity,
production latency, or user-scale forecasts. Full machine memory shown by Docker is
not a container limit; spike storage alone was bounded to 128 MiB and ephemeral.

Machine-readable results are in `results/live-validation.json` and
`results/multiprocess-validation.json`.

## Build-info behavior

Three current deployment identities produced three build-info series. Changing alpha
from application `2.4.1`/platform `1.8.0` to `2.4.2`/`1.8.1` left exactly three current
instant-vector series after Prometheus marked the old series stale. The series API still
reported four historical identities during retention. This is normal time-series
history but can confuse queries that omit time/current-state semantics.

Application and platform versions remain confined to build-info. Git SHA, OCI digest,
and deployment timestamp remain absent from all request dimensions. Complete deployment
identity belongs in controlled inventory/startup evidence as ADR 0007 specifies.
Production retention and deployment inventory remain undecided.

## Security checks

The validation searched Prometheus-visible configuration, target state, and request
series for nine distinctive synthetic values representing a Workspace ID, user ID,
email, request ID, trace ID, Authorization token, session, query secret, and customer
object ID. None appeared. Static tests reject those dimension names and high-churn build
identity on request metrics.

No credentials are committed. Metrics do not alter synthetic authorization behavior.
Prometheus absence does not affect liveness or readiness. No real tenant, user, product,
DEV, or PROD data is involved.

## Test approach

From repository root, using the existing Task 009 Python 3.12 environment:

```bash
/tmp/omnilyzer-task009-venv/bin/python -m unittest discover \
  -s spikes/prometheus-metrics/tests -p 'test_*.py' -v
/tmp/omnilyzer-task009-venv/bin/python spikes/prometheus-metrics/multiprocess_probe.py
python3 spikes/prometheus-metrics/validate_live.py
docker compose -f spikes/prometheus-metrics/compose.yaml config --quiet
docker run --rm --entrypoint=/bin/promtool \
  -v "$PWD/spikes/prometheus-metrics/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  prom/prometheus:v3.14.0@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0 \
  check config /etc/prometheus/prometheus.yml
```

`validate_live.py` builds only the synthetic target, starts the isolated Compose project,
asserts the Prometheus API evidence, and removes its containers/networks/volumes in a
`finally` block. It does not contact a live Omnilyzer environment.

## Findings

### Recommended candidate direction

- Prometheus server, as validated specifically at 3.14.0, is a suitable candidate
  initial scraper/query/time-series component for ADR 0007 application metrics.
- Retain the closed label contract and normalized framework route templates.
- Keep targets on private internal networking and separately protect Prometheus UI/API.
- Use bounded explicit scrape timeout/interval configuration.
- Require a deliberate live multiprocess Gauge mode for bounded build-info; `livemax`
  passed as a candidate, while the default `all` mode was rejected for this metric.
- Encapsulate official client multiprocess setup in the future platform package while
  requiring both process-manager worker-death hooks and deployment-start directory cleanup.
- Keep build-info bounded and query current deployment state intentionally.

### To validate later

- production WSGI/ASGI worker topology and actual process-manager hooks;
- exact production build-info live Gauge mode and integration details;
- multiprocess behavior under abrupt crash loops and rolling/overlapping deployments;
- exact supported/LTS Prometheus production version and upgrade policy;
- production scrape interval, timeout, retention, storage sizing, and resource limits;
- service discovery, TLS, authentication, authorization, and network enforcement;
- real Django/PostgreSQL deployment behavior and production load;
- HA, backups, disaster recovery, long-term/remote storage, and upgrade procedures;
- recording/alerting rules, SLOs, and operational ownership;
- native histogram suitability when client/server support and policy mature;
- whether a Prometheus server ADR should accept this candidate after review.

### Rejected / not currently planned

- raw paths, identifiers, query strings, request/trace IDs, or tenant/user data as labels;
- public target `/metrics` ports;
- metrics availability as readiness or application availability dependency;
- floating image tags, committed credentials, remote write, or admin APIs in this spike;
- Grafana, Loki, Tempo, Jaeger, Alloy, OpenTelemetry Collector, Alertmanager, Thanos,
  Mimir, VictoriaMetrics, Kafka, Kubernetes, or external SaaS monitoring in Task 010.

## Limitations

This is a single-host Docker and synthetic-Python experiment. It did not test production
traffic, TLS, hostile network peers, durable storage, compaction at scale, high
availability, production authentication, distributed service discovery, or a real
Django worker deployment. Resource numbers are one sample. The series API includes
historical stale build-info by design. The theoretical ceiling describes this exact
fixture vocabulary, not an organization-wide capacity target.

`livemax` proved the required build-info shape in the synthetic worker lifecycle, but
the exact production live Gauge mode remains unselected until a real WSGI/ASGI process
manager and rolling-deployment model are validated. The default `all` mode is explicitly
unsuitable for build-info. Correct operation depends on external lifecycle integration;
the metrics package alone cannot discover every worker death or safely infer when a
complete deployment-run directory may be wiped.

Prometheus server was tested, not accepted. No dashboard or alert delivery was needed to
validate scrape/query behavior. The test uses ephemeral storage and makes no retention,
backup, or capacity recommendation.

## Unresolved questions

1. Which reviewed production worker/process manager will own multiprocess directory
   setup, cleanup, and dead-worker callbacks?
2. What scrape interval/timeout balances freshness, target overhead, and fleet size?
3. How will production discovery and internal `/metrics` network policy be enforced?
4. What retention, storage, backup, HA, and disaster-recovery requirements apply?
5. Which Prometheus interfaces require operator authentication, and by what mechanism?
6. Which recording/alerting rules and SLOs will be defined in later work?
7. Does architecture review justify a future ADR accepting Prometheus server?

## Recommendation

Treat Prometheus server as a **RECOMMENDED CANDIDATE DIRECTION** for the initial metrics
control plane. Task 010 passed its synthetic gates: real scrape/query compatibility,
caller-independent cardinality, private target networking, monitoring and target failure
isolation, automatic recovery, and explicit multiprocess lifecycle semantics. Python
multiprocess operation is viable only with deliberate Gauge modes and mandatory worker-
death/deployment-start lifecycle integration. Task 009's single-process Gauge is not a
production implementation to copy unchanged. Preserve the limitations above and do not
mark Prometheus server—or Prometheus 3.14.0 as a permanent support line—accepted until
architecture review and ADR processing occur.
