<!--
File: spikes/grafana-security/README.md
Purpose: Records Task 011 Grafana OSS operator-access and security evidence.
Related:
- spikes/README.md
- docs/adr/0003-keycloak-bff-and-native-authentication.md
- docs/adr/0007-product-observability-contract.md
- docs/adr/0008-prometheus-metrics-scraper-and-query.md
-->

# Task 011: Grafana Operator Access and Security Validation

## Classification

**TASK 011 — PASS WITH EXPLICIT AUTHORIZATION BOUNDARY**

Grafana OSS is a **RECOMMENDED CANDIDATE** for a private visualization/query UI used by
one trusted operator population already authorized for the complete connected Prometheus
dataset. Grafana OSS is **not sufficient by itself** to enforce fine-grained product,
team, customer, Workspace, or tenant metric visibility over one shared datasource.

This is isolated architecture evidence, not production code or **ACCEPTED ARCHITECTURE**.
It does not create ADR 0009, select a complete monitoring platform, or change the
accepted Task 009/010 contracts.

## Hypothesis

Grafana OSS can be file-provisioned as the only browser-facing metrics interface over a
private Prometheus server, authenticate real operator identities through Keycloak OIDC,
map organization roles without fallback access or server-admin escalation, survive
identity/metrics failures without affecting applications, and make its OSS data-query
authorization limits explicit.

## Acceptance criteria

The spike passes only if:

- Grafana and Keycloak alone have loopback host bindings; Prometheus and the synthetic
  application have none;
- real Authorization Code OAuth login maps Viewer, Editor, and organization Admin
  exactly, while an unmapped user is denied;
- anonymous, local/basic-password, public-dashboard, snapshot, and embedding bypasses
  remain disabled;
- organization roles do not become Grafana server administrators;
- Viewer and Editor cannot create or edit datasources;
- a Viewer query outside the provisioned dashboard is tested and its authorization
  implication is recorded honestly;
- Grafana, Prometheus, and Keycloak outages fail visibly but independently and recover;
- provisioning recreates the datasource, folder, and dashboard from committed files;
- no reusable credential or token enters evidence or Git; and
- no Enterprise/Cloud-only property is attributed to OSS.

## Architecture under test

```text
synthetic application :8000                browser-style validator
  no host port                                  |             |
        | /metrics                              | HTTP        | HTTPS
        v                                       v             v
Prometheus 3.14.0 :9090                  Grafana OSS       Keycloak
  no host port                                  |             |
        ^                                       +-------------+
        | server-side datasource                  real OIDC Code + PKCE
        +--------------------------------------- 127.0.0.1:19130 / :19180

application-metrics       internal Docker network
metrics-visualization     internal Docker network
identity-backchannel      internal Docker network
validation-loopback       loopback publication only
```

Grafana reaches `http://prometheus:9090` through its server-side datasource proxy. The
browser/test client never needs a Prometheus address. The synthetic target exposes the
four ADR 0007 families for `valoria/dev`, `chronicle/staging`, and `platform/test`:

- `omnilyzer_http_requests_total`;
- `omnilyzer_http_request_duration_seconds`;
- `omnilyzer_build_info`; and
- `omnilyzer_telemetry_export_failures_total`.

The fixture uses synthetic data only and does not contact DEV or PROD.

## Technology, version, edition, and license

| Component | Exact evidence | Purpose |
|---|---|---|
| Grafana OSS | 13.2.0, released 2026-08-18 | Candidate operator visualization/query UI |
| Grafana image | `grafana/grafana:13.2.0` | Official, non-deprecated repository |
| Grafana image digest | `sha256:3fd54ae1214669f8355f065ec9f6445d5279a3d77095ab048ca045685272429b` | Immutable Linux/amd64 image tested |
| Grafana license | AGPLv3 | Architecture/legal-review consideration; this spike makes no legal conclusion |
| Keycloak | 26.7.2, digest `sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067` | Isolated accepted-IdP fixture |
| Prometheus | 3.14.0, Task 010 digest | Private accepted metrics fixture |
| Python | 3.12.3 digest-pinned image and local standard library | Synthetic target and validator |

Grafana 13.2.0 is exact Task 011 evidence, not a permanent production version choice.
The official sources are the [Grafana project](https://github.com/grafana/grafana),
[Grafana OSS download record](https://grafana.com/grafana/download?edition=oss), and
[Grafana 13.2 release record](https://grafana.com/blog/grafana-13-2-release-all-the-latest-features/).
No third-party plugin was configured or downloaded; the built-in Prometheus datasource
was sufficient. Startup plugin preinstallation and auto-update were disabled.

## Network and security model

Runtime inspection proved:

- Grafana: exactly `127.0.0.1:19130`;
- Keycloak: exactly `127.0.0.1:19180` using a runtime-generated one-run certificate;
- Prometheus: zero host-published ports;
- synthetic application: zero host-published ports; and
- Grafana datasource: server-side `http://prometheus:9090`, non-editable, without Basic
  auth, browser cookie forwarding, or stored credentials.

Grafana's local HTTP endpoint is a loopback test convenience. It is not a production
ingress design. Production requires HTTPS, a private reviewed operator path, Secure
cookies, final reverse-proxy/header/CSP integration, and datasource egress policy.

## Authentication model

The validator completed real Keycloak Authorization Code login with Grafana's Generic
OAuth provider and PKCE. Anonymous access, Grafana local sign-up, Basic authentication,
and the local login form were disabled. The randomized Grafana bootstrap administrator,
Keycloak bootstrap credential, OAuth secret, user passwords, Grafana secret key, and TLS
key existed only in a mode-0700 temporary directory; the environment/realm files were
mode 0600 and cleanup removed the directory.

Keycloak groups mapped independently and strictly:

| Synthetic identity | Keycloak group | Grafana result |
|---|---|---|
| Viewer | `/grafana-viewers` | Viewer |
| Editor | `/grafana-editors` | Editor |
| organization Admin | `/grafana-admins` | Admin, `isGrafanaAdmin=false` |
| unmapped operator | `/unmapped-operators` | login/access denied; `/api/user` returned 401 |

There is no default Viewer expression. The strict role expression returns no role when
no reviewed group matches; using Grafana's valid `None` role as the fallback was
deliberately avoided. `allow_assign_grafana_admin=false`. No Workspace, tenant, or
product authorization claim was created. Grafana authentication and organization roles
do not replace Omnilyzer application authorization or PostgreSQL RLS.

## Authorization model and capability matrix

| Capability | Viewer | Editor | organization Admin |
|---|---:|---:|---:|
| Read provisioned dashboard | yes | yes | yes |
| Save/edit dashboard | no (403) | yes | yes |
| Query organization datasource | yes | yes | yes |
| Create arbitrary datasource | no (403) | no (403) | yes |
| Edit provisioned datasource | no | no | no; provisioned/read-only |
| Grafana server-admin API | no (403) | no (403) | no (403) |
| Grafana server admin | no | no | no |

File provisioning makes the accepted datasource non-editable, but an organization Admin
can create another server-side datasource. That ability is a privileged outbound-network
and SSRF-relevant capability. Production must restrict who can become organization Admin
and restrict Grafana egress. Task 011 does not claim the final egress control is solved.

## Critical Viewer arbitrary-query finding

The committed dashboard contained only this deliberately narrow panel query:

```promql
sum by (product, environment) (
  omnilyzer_http_requests_total{product="valoria"}
)
```

An authenticated Viewer directly submitted this different expression through
Grafana's datasource query API:

```promql
sum(omnilyzer_telemetry_export_failures_total)
```

Grafana returned HTTP 200 and data. This proves the documented OSS behavior: dashboard
and folder visibility do not restrict which valid queries an organization user may send
to an available datasource.

**GRAFANA DASHBOARD VISIBILITY MUST NOT BE USED AS A TENANT, WORKSPACE, CUSTOMER,
PRODUCT, OR TEAM METRIC-DATA AUTHORIZATION BOUNDARY.**

The two architecture questions therefore have separate answers:

1. **One trusted operator population authorized for the complete operations Prometheus
   dataset:** Grafana OSS is technically suitable as a candidate.
2. **Mutually restricted teams/products/tenants over one shared Prometheus datasource:**
   Grafana OSS alone is insufficient.

The second model would require separately evaluated architecture such as genuinely
restricted datasource endpoints, separate organizations with independently restricted
datasources, separate instances, an authorization-aware metrics layer, or an Enterprise
capability. Task 011 selects none of them.

## OSS versus Enterprise / Cloud boundary

Official Grafana documentation and the live OSS behavior establish:

- basic Viewer/Editor/organization Admin roles and dashboard/folder permissions exist in
  OSS;
- every organization user can query every organization datasource by default;
- granular datasource query/edit/admin permissions are Enterprise or Cloud;
- advanced/custom RBAC is Enterprise or Cloud; and
- dedicated audit logging is Enterprise or Cloud.

Task 011 used no Enterprise image, license, feature, plugin, or Cloud service. These are
material governance boundaries, not hidden implementation details.

## Provisioning model

Version-controlled files provision one Prometheus datasource with deterministic UID
`omnilyzer-prometheus`, folder UID `omnilyzer-operations`, and dashboard UID
`task011-operations`. Grafana's embedded SQLite state was disposable. After Grafana's
container and temporary database were removed, a fresh container recreated all three
resources and queries resumed in 4.156 seconds without administrator API setup or UI
clicks.

`allowUiUpdates=true` permits the role test to prove Editor behavior, but file
provisioning remains authoritative on recreation. This does not select SQLite or a
production Grafana database.

## Public sharing, embedding, and browser surface

Anonymous search, dashboard, datasource, query, and administrative requests returned
401. Public dashboards were disabled and an enable attempt returned 404. Local and
external snapshots were disabled. Embedding was disabled and responses included
`X-Frame-Options: deny`. A Content Security Policy was present and no wildcard CORS
header was introduced.

The authenticated cookie observation was:

- name: `grafana_session`;
- `HttpOnly`: true;
- `SameSite=Lax`;
- bounded persistent expiration in the observed response; and
- `Secure`: false because Grafana itself used local loopback HTTP.

No OAuth token was placed in `localStorage`, `sessionStorage`, evidence, or application
code. Production Secure-cookie behavior remains to validate over the final HTTPS path.

## Failure-isolation evidence

### Keycloak unavailable

With an established Grafana session, stopping Keycloak left `/api/user` successful.
New OAuth login failed at the unavailable IdP without bypassing authentication. Keycloak
restart restored new login in 7.442 seconds. This brief test does not prove long-term
session, refresh-token, revocation, or IdP-HA behavior.

### Prometheus unavailable

Stopping Prometheus left Grafana running with its existing authenticated session. The
datasource query failed visibly and safely. Synthetic domain, `/livez`, and `/readyz`
checks all remained HTTP 200; Grafana did not restart. Prometheus restart restored the
query without Grafana reconfiguration in 0.600 seconds.

### Grafana unavailable

Stopping Grafana left the application and Prometheus running. Five synthetic application
requests succeeded, the request counter increased, and Prometheus continued reporting
the target as `up=1`. Grafana restart completed in 3.007 seconds and the provisioned
dashboard/query resumed. Neither application nor Prometheus restarted.

These results preserve the accepted invariant: application availability does not depend
on visualization, scraping, or identity-provider availability. They do not prove
production HA or fleet-scale behavior.

## Auditability findings

Grafana OSS console logs provided operational request-completion and authentication
diagnostics; the captured run contained 37 request-completion records and records related
to authentication and dashboard/datasource API activity. They did not provide the
dedicated structured, governance-complete, tamper-resistant audit event trail offered by
Grafana Enterprise audit logging.

Ordinary OSS logs must not be represented as equivalent audit evidence. Before
production acceptance, Omnilyzer must determine audit requirements for login attempts,
dashboard changes, datasource changes, and administration; assess compliance impact;
and complete architecture, security, and AGPL legal review. Adding Loki is not a solution
selected by this spike.

## Resource observations

One local run on 2026-08-31 observed:

| Measurement | Result |
|---|---:|
| Compose start to Grafana + Keycloak ready | 22.204 s |
| Grafana memory | 235.3 MiB |
| Grafana CPU snapshot | 0.98% |
| representative server-side query | 14.360 ms |
| Viewer/Editor/Admin OAuth flow | 0.825 / 0.194 / 0.175 s |
| Prometheus query recovery | 0.600 s |
| Grafana restart to health | 3.007 s |
| fresh Grafana recreation/provisioning | 4.156 s |

These modest synthetic observations reject an obvious suitability problem. They do not
predict production concurrency, capacity, memory sizing, latency objectives, or 10,000/
100,000-user behavior.

## Security checks

- Exact digest-pinned Grafana OSS image from `grafana/grafana`, never the deprecated
  `grafana/grafana-oss` repository or `latest`.
- Runtime-only synthetic secrets, restricted temporary files, sanitized evidence, and
  zero secret-marker matches in captured responses.
- Anonymous, Basic, local form, public-dashboard, snapshot, and embedding paths disabled.
- Strict unmapped-user denial and exact organization-role mapping.
- No OIDC server-admin assignment; all three ordinary roles received 403 from the
  server-admin stats endpoint.
- Viewer/Editor datasource creation and modification denied.
- Provisioned datasource read-only with no credential or cookie forwarding.
- Organization Admin datasource/SSRF capability exposed rather than concealed.
- Viewer arbitrary-query behavior directly proven.
- No wildcard CORS, third-party plugins, Enterprise features, real identities, tenant
  claims, production endpoints, or committed credentials.
- Grafana and Prometheus failures did not affect synthetic application domain, health,
  authentication, authorization, or readiness behavior.

## Test approach

From the repository root:

```bash
python3 spikes/grafana-security/validate_live.py
python3 -m unittest discover \
  -s spikes/grafana-security/tests \
  -p 'test_*.py' \
  -v
```

The live validator creates runtime credentials and a one-run TLS certificate, validates
Compose, builds the dependency-free synthetic target, starts the isolated services,
performs real browser-style OAuth and HTTP API tests, injects three outages, recreates
Grafana from empty disposable state, emits sanitized
[`results/live-validation.json`](results/live-validation.json), and always runs Compose
cleanup plus temporary-secret deletion.

Static tests cover images, topology, provisioning, auth settings, public-sharing policy,
role mapping, datasource configuration, negative paths, evidence schema, OSS boundaries,
and failure recovery. The validator and target use the Python standard library; Task 011
adds no Python package dependency.

## Findings

1. Grafana OSS can provide a reproducible, private, Keycloak-authenticated UI over the
   accepted Prometheus server without exposing Prometheus to the browser or host.
2. Strict OIDC mapping works, but the fallback must be absence of a role—not Grafana's
   valid `None` role—and server-admin assignment must remain disabled.
3. Basic organization roles provide the expected dashboard and datasource-management
   separation. Organization Admin remains a sensitive network-capable role.
4. Dashboard permissions do not provide query-level datasource authorization. A Viewer
   can issue arbitrary PromQL against an organization datasource.
5. File provisioning is reproducible independently of disposable SQLite state.
6. Grafana, Prometheus, and short Keycloak outages remained isolated and recoverable.
7. OSS operational logs are useful diagnostics but do not satisfy dedicated audit-log
   semantics.

## Recommended candidate direction

Continue architecture review of Grafana OSS as the initial private operator UI only for
a trusted operator population authorized to query the connected operations Prometheus
dataset. Require real Keycloak SSO, strict explicit group-to-role mapping, no default
role, no GrafanaAdmin assignment from OIDC, file provisioning, private datasource and UI
networks, disabled anonymous/local/public-sharing/embedding paths, narrowly governed
organization Admin membership, and reviewed server egress.

Do not describe dashboard/folder permissions as product, Workspace, tenant, or metric-
data isolation. If mutually restricted operator populations become a requirement, stop
and validate a separate authorization architecture before connecting them to one shared
datasource.

## To validate later

- architecture and legal review of Grafana OSS/AGPLv3;
- whether Omnilyzer's operator model is one trusted population or requires mutually
  restricted datasets;
- production private ingress, HTTPS, Secure cookies, CSP/header policy, and operator
  access controls;
- datasource egress/SSRF controls and organization-Admin governance;
- required audit-event semantics and whether the OSS auditability gap is acceptable;
- production Grafana database, backups, HA, DR, upgrades, and rollback;
- long-lived Keycloak session/refresh/revocation behavior and identity-provider HA;
- production Prometheus discovery, topology, retention, and datasource scaling;
- dashboard/query governance, accessibility, browser compatibility, and load/capacity;
- Grafana supported/LTS release selection and upgrade regression; and
- monitoring of Grafana itself.

## Rejected / not currently planned

- public Prometheus or application `/metrics` exposure;
- direct public Grafana exposure;
- anonymous Viewer access, local password fallback, iframe embedding, public dashboards,
  or public snapshots;
- using dashboard visibility as tenant/Workspace/product data authorization;
- automatic Grafana server-admin assignment from IdP claims;
- committed credentials or browser OAuth-token storage;
- Enterprise activation or third-party plugins solely to force a PASS;
- Loki, Tempo, Jaeger, Alloy, OpenTelemetry Collector infrastructure, Alertmanager,
  Mimir, Thanos, VictoriaMetrics, Elasticsearch, external SaaS, Kubernetes, or a custom
  operations portal in Task 011.

## Limitations and unresolved questions

The spike does not settle whether Grafana OSS's AGPLv3 or auditability gap is acceptable,
nor whether the future operator population needs dataset-level isolation. The datasource
creation test confirms an organization Admin can influence server-side outbound requests;
the final network policy is unproven. Grafana used loopback HTTP, disposable SQLite, one
instance, one Prometheus datasource, synthetic identities, and a small workload. The
Keycloak front channel used a generated self-signed test certificate whose trust check
the test client deliberately bypassed; that is not production certificate evidence.

Production ingress, TLS, cookies, state persistence, access lifecycle, audit retention,
HA, backup/restore, disaster recovery, upgrades, accessibility, real operator workflows,
capacity, and incident procedures remain unresolved. No visualization architecture has
been accepted by this spike.

## Recommendation

Advance Grafana OSS to architecture review as a candidate for the trusted-operator model,
carrying the Viewer arbitrary-query boundary, organization-Admin SSRF/egress authority,
OSS auditability gap, and AGPLv3 review as explicit constraints. Do not advance it as a
fine-grained shared-datasource authorization layer.
