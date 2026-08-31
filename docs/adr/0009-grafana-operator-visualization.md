<!--
File: docs/adr/0009-grafana-operator-visualization.md
Purpose: Proposes the initial private operator visualization and interactive metrics-query interface.
Related:
- docs/adr/0003-keycloak-bff-and-native-authentication.md
- docs/adr/0007-product-observability-contract.md
- docs/adr/0008-prometheus-metrics-scraper-and-query.md
- spikes/grafana-security/README.md
-->

# ADR 0009: Grafana Operator Visualization and Query Interface

- Status: Proposed
- Date: 2026-08-31

## Context

[ADR 0007](0007-product-observability-contract.md) accepts the product-side observability
contract, including bounded Prometheus-compatible application metrics. [ADR
0008](0008-prometheus-metrics-scraper-and-query.md) accepts Prometheus server as the
initial private metrics scraper, local TSDB, and PromQL query component. Neither decision
selects a visualization interface or makes the Prometheus operator surface suitable for
general browser access.

Omnilyzer operators need a reproducible interface for dashboards, folders, and
interactive PromQL without exposing Prometheus or application `/metrics` endpoints to
the browser. That interface must align with the accepted [Keycloak authentication
direction](0003-keycloak-bff-and-native-authentication.md), remain isolated from product
availability, and avoid becoming an accidental tenant or metric-data authorization
system.

Visualization is a privileged operational surface. Metrics can reveal service behavior,
deployment state, and other operational information even when the application-side
contract correctly excludes credentials and tenant/user identifiers. Dashboard
visibility, datasource access, operator roles, server-side outbound requests, sessions,
audit evidence, and mutable administrative state therefore require explicit trust
boundaries.

[Task 011 Grafana security evidence](../../spikes/grafana-security/README.md) tested
Grafana OSS 13.2.0 against an isolated, private Prometheus fixture and real Keycloak
26.7.2. The digest-pinned Grafana image was
`grafana/grafana:13.2.0@sha256:3fd54ae1214669f8355f065ec9f6445d5279a3d77095ab048ca045685272429b`.
The spike validated real Authorization Code login with PKCE, strict role mapping,
private server-side Prometheus access, file provisioning, browser-surface controls,
failure isolation, and restart recovery. It used synthetic identities and runtime-only
secrets.

The central negative finding was equally important: an authenticated Viewer submitted
valid PromQL not present in the visible dashboard and successfully queried the shared
organization datasource. Task 011 therefore classified Grafana OSS as a suitable
candidate only with an explicit authorization boundary. Grafana 13.2.0 is exact test
evidence, not a permanent production version selection.

## Options considered

### Grafana OSS

Grafana OSS provides mature Prometheus integration, interactive PromQL, dashboards and
folders, code-based provisioning, and Generic OAuth integration. Task 011 demonstrated
real Keycloak login, reproducible provisioning, private server-side datasource access,
ordinary organization-role behavior, and failure isolation without product
instrumentation changes or third-party plugins.

Its constraints are material. A Viewer with datasource query access can query the
complete dataset available through that datasource; OSS does not provide the granular
datasource permissions, advanced/custom RBAC, or dedicated audit logging available in
Enterprise or Cloud offerings. Organization Admin can create a server-side datasource,
which creates an egress and SSRF-relevant privilege. Grafana OSS is AGPL-3.0-only, and
Task 011 made no legal conclusion about that license.

### Build a custom Omnilyzer operations interface now

A custom interface could provide narrowly tailored workflows and authorization, but it
would require Omnilyzer to build and maintain query tooling, dashboards, browser
security, identity integration, accessibility, and operational UX that mature tools
already provide. Current evidence does not justify that work. A custom interface remains
a future option if operator requirements cannot be met safely by an existing tool.

### Direct Prometheus UI and API only

Using Prometheus directly would avoid another service, but provides weaker dashboard,
folder, role, provisioning, and operator-workflow capabilities. It would also make the
Prometheus operator surface itself the primary browser interface rather than preserving
the private server-side boundary proposed here.

### Grafana Enterprise or Grafana Cloud

These offerings may provide granular datasource permissions, advanced RBAC, and
dedicated audit capabilities. They also introduce licensing, cost, provider, deployment,
and operational implications that have not been established as necessary for the
trusted-operator model. Omnilyzer's current production architecture is constrained to
open-source technology, so Grafana Enterprise and Grafana Cloud are not eligible
production directions under that constraint. Either could become a candidate only if a
separate architecture decision explicitly changed the constraint. They remain useful
comparison evidence, but this ADR does not select either offering.

### Another open-source visualization or query system

Another system may satisfy future authorization, licensing, or operational
requirements. Task 011 directly validated Grafana OSS and found no blocker for the
narrow trusted-operator use case, so another spike is not currently required. The
alternative remains open rather than permanently rejected.

### Product-specific dashboards or monitoring systems

Each product could select a separate visualization system. This would fragment operator
semantics, access controls, provisioning, and maintenance while duplicating the
Prometheus direction accepted by ADR 0008. It is not the proposed initial direction.

## Decision

This ADR proposes Grafana OSS as the initial private visualization and interactive
metrics-query interface for a **trusted Omnilyzer operator population already authorized
to query the complete operations dataset exposed by the connected Prometheus
datasource**.

The proposed scope includes:

- operator metrics visualization;
- dashboards and folders;
- interactive PromQL through Grafana;
- private, server-side access to the accepted Prometheus component;
- Keycloak OIDC authentication;
- bounded Grafana organization roles for operator-interface permissions;
- reproducible datasource and dashboard provisioning; and
- failure isolation from applications and Prometheus.

```text
Omnilyzer applications
        |
   internal /metrics
        |
        v
private Prometheus
        |
 server-side datasource
        |
        v
   Grafana OSS <------ Keycloak OIDC
        |
 private HTTPS operator path
        |
 trusted operators authorized for the complete datasource
```

Grafana is not a product-user or customer-facing interface, Workspace or tenant
authorization system, product/team metric-data isolation boundary, identity provider,
application authorization service, alerting architecture, logging architecture, tracing
architecture, or complete monitoring platform.

### Metric-data authorization boundary

**GRAFANA DASHBOARD AND FOLDER VISIBILITY ARE NOT METRIC-DATA AUTHORIZATION
BOUNDARIES.**

A user who can query a shared datasource is treated as authorized to query the complete
dataset exposed by that datasource unless another independently enforced authorization
boundary exists. Dashboard and folder permissions do not isolate Workspaces, tenants,
customers, products, teams, or users.

Task 011 proved this boundary by allowing a Viewer to read a narrow dashboard and then
successfully submit different PromQL directly through Grafana's datasource query API.
The proposed OSS direction is therefore valid only for one trusted operator population
authorized for the complete connected Prometheus dataset.

If future requirements demand mutually restricted metric visibility, separate
architecture evidence is required. Possible approaches include independently restricted
Prometheus or query endpoints, separate Grafana organizations with independently
restricted datasources, separate Grafana instances, an authorization-aware query layer,
Grafana Enterprise or Cloud datasource permissions/RBAC, or another visualization/query
system. Enterprise and Cloud appear here only as capability comparisons; they are not
currently eligible choices under Omnilyzer's open-source-only production constraint.
This ADR selects none of these approaches.

### Keycloak authentication and operator roles

1. Grafana operator authentication integrates with Keycloak using OIDC Authorization
   Code with PKCE. PKCE is a normative requirement, not only a Task 011 test detail. The
   tested Grafana Generic OAuth configuration used `use_pkce=true`; a future supported
   version may use an equivalent setting that enforces PKCE rather than that exact key spelling.
2. Role mapping is explicit and fails closed. Unmapped identities receive no fallback
   Viewer access. Task 011 used `role_attribute_strict=true`; that setting, or equivalent
   fail-closed behavior in a future supported Grafana version, is required.
3. `allow_assign_grafana_admin=false`, or an equivalently restrictive posture, remains
   required unless separately reviewed.
4. Grafana organization roles do not confer Grafana server-admin status.
5. No Workspace, tenant, or product authorization is moved into Keycloak for Grafana.
6. Grafana operator roles are separate from Omnilyzer application roles. Keycloak
   remains the identity provider; application authorization and PostgreSQL RLS remain
   separate controls.

The tested OSS organization-role capabilities were:

| Capability | Viewer | Editor | Organization Admin |
|---|---:|---:|---:|
| Read dashboard | yes | yes | yes |
| Query available datasource | yes | yes | yes |
| Edit dashboard | no | yes | yes |
| Create datasource | no | no | yes |
| Edit/delete file-provisioned datasource | no | no | no |
| Use Grafana server-admin API | no | no | no |

Organization Admin assignment is security-sensitive. Task 011 proved that this role can
create a server-side datasource even though it cannot edit or delete the file-provisioned
datasource. Production tightly controls organization Admin membership and constrains
Grafana outbound network access. The final egress policy is not selected or proven here.

### Private network, ingress, and browser security

1. Prometheus and application `/metrics` endpoints remain private/internal.
2. Grafana reaches Prometheus through a server-side datasource; browsers do not require
   direct Prometheus access.
3. Grafana is a privileged operator surface whose production default is a reviewed
   private/internal access path using HTTPS.
4. Direct public Internet exposure is not the proposed direction. Any future need for
   Internet-accessible operator endpoints requires separate security and architecture
   review.
5. Production requires Secure session cookies. Task 011 observed `grafana_session` as
   HttpOnly, `SameSite=Lax`, and bounded persistent, but not Secure because the Grafana
   test endpoint used loopback HTTP.
6. Anonymous authentication, public dashboards, public snapshots, and embedding are
   disabled. Wildcard CORS is not introduced.
7. Local/basic password login is disabled when Keycloak SSO is the selected production
   route, subject to a separately governed break-glass design if later justified. This
   ADR does not select such a mechanism.
8. Omnilyzer integration does not put OAuth access, refresh, or ID tokens in browser
   `localStorage` or `sessionStorage`.

Grafana's server-side operator session is distinct from the browser BFF application
session accepted by ADR 0003. This ADR does not reinterpret Grafana as an Omnilyzer BFF.
Task 011's `127.0.0.1:19130` binding and local HTTP were isolated test mechanics, not
production ingress or cookie configuration.

This ADR does not select Cloudflare Access, WireGuard, a VPN, Nginx authentication proxy,
a final firewall, a final operator hostname, or an exact TLS topology.

### Provisioning and datasource security

Required datasources, deterministic datasource UIDs, dashboard providers, folders,
dashboards, and relevant security configuration are version-controlled and reproducibly
provisioned. Manual UI configuration is not the sole source of truth.

Task 011 recreated datasource UID `omnilyzer-prometheus`, folder UID
`omnilyzer-operations`, and dashboard UID `task011-operations` from committed files after
discarding Grafana state. Those names and the synthetic dashboard are evidence, not
permanent production configuration.

Required file-provisioned datasources are non-editable where practical and use
server-side access. Browser cookies, Authorization headers, and credentials are not
forwarded unless a separately reviewed requirement justifies them. Datasource creation
is privileged because it can make Grafana issue server-side network requests. Production
must constrain Grafana egress and tightly govern datasource administrators.

### Failure isolation

Grafana is never an application liveness, readiness, authentication, authorization, or
domain-serving dependency.

Task 011 observed:

- during a brief Keycloak outage, an established Grafana session remained usable, new
  login failed cleanly, and new login recovered after Keycloak restarted;
- during a Prometheus outage, Grafana remained running, its established session remained
  usable, queries failed visibly and safely, applications remained healthy, and queries
  recovered after Prometheus returned; and
- during a Grafana outage, applications remained available, Prometheus continued
  scraping and accumulating metrics, and Grafana recovered its provisioned query path
  after restart.

These results establish isolation mechanics only. They do not prove Grafana or Keycloak
HA, long-duration IdP behavior, fleet scale, or production recovery objectives.

### OSS, Enterprise/Cloud, audit, and license boundaries

The proposed direction is Grafana OSS. Task 011 did not validate or attribute these
Enterprise/Cloud capabilities to OSS:

- granular datasource permissions;
- advanced or custom RBAC; or
- dedicated Enterprise audit logging.

The OSS direction is viable only where those capabilities are not required to enforce
the selected trusted-operator model. Omnilyzer's current production architecture is
open-source-only; Enterprise and Cloud capabilities are therefore comparison evidence,
not eligible production directions unless a separate ADR explicitly changes that
constraint.

Grafana OSS logs provided diagnostics and some authentication and API activity records,
but they are not a dedicated, governance-complete, or tamper-resistant audit trail.
Production implementation must define required audit semantics for operator
authentication, role/privilege changes, dashboard changes, datasource changes,
datasource creation/deletion, and administrative actions. Architecture, security, and
compliance review must determine whether OSS is sufficient. This ADR does not select
Loki, Enterprise, or another audit solution.

Grafana OSS 13.2.0 is AGPL-3.0-only. Task 011 and this ADR make no legal interpretation
or conclusion. Production reliance remains subject to legal/license review appropriate
to Omnilyzer's deployment and distribution model. That unresolved review is one reason
this record remains Proposed.

### Version and persistence posture

Grafana OSS 13.2.0 and its tested immutable image digest are evidence only. Production
uses a supported Grafana release with exact deployment pinning. Upgrades regression-test
OIDC, provisioning, Prometheus datasource compatibility, session/cookie security,
roles/authorization, dashboard compatibility, failure isolation, and recovery.

Task 011 used disposable embedded SQLite. This ADR does not accept SQLite as the
production Grafana database. Production persistence still requires evidence for the
database choice and topology, backups, restore, HA, disaster recovery, upgrades,
sessions, users/organizations, and mutable dashboard state not provided entirely by
files. File provisioning reduces dependence on manual state but does not eliminate
Grafana state requirements.

## Consequences

Positive consequences include:

- a mature private operator interface over the accepted Prometheus component;
- no change to product instrumentation or the ADR 0007 metric contract;
- real Keycloak operator SSO with explicit role mapping;
- reproducible datasource and dashboard configuration;
- application and Prometheus availability independent of Grafana;
- replacement remains possible because products contain no Grafana-specific APIs; and
- Omnilyzer does not need to build a dashboard system immediately.

Tradeoffs and limitations include:

- Grafana becomes operational infrastructure requiring ownership;
- every shared-datasource user can query the connected dataset;
- organization Admin is a security-sensitive, network-capable role;
- production egress and SSRF controls are required;
- OSS auditability is limited and may not satisfy future governance requirements;
- production HTTPS, cookies, headers, CSP, and private ingress remain to validate;
- persistence, upgrade, HA, backup, and disaster recovery remain to validate;
- supported-version upgrades require regression evidence;
- AGPLv3 requires legal/license review; and
- dashboards and PromQL become versioned operational assets requiring governance.

## Security implications

- Grafana and its connected metrics are privileged operational data surfaces.
- Dashboard and folder permissions are not metric-data authorization boundaries.
- Operators with datasource query access are trusted for its complete exposed dataset
  unless another independently enforced boundary exists.
- Grafana is not an authentication, product authorization, Workspace, tenancy, or RLS
  enforcement service.
- Keycloak authentication does not grant Workspace or product access and does not weaken
  application authorization or PostgreSQL RLS.
- Role mapping fails closed, and identity-provider claims do not grant server-admin
  access by default.
- Organization Admin and datasource administration are privileged because they influence
  server-side network requests.
- Prometheus and `/metrics` remain private; Grafana uses a reviewed private HTTPS operator
  path.
- Anonymous, public-sharing, snapshot, and embedding bypasses remain disabled.
- Production requires Secure cookies and reviewed session, logout, and revocation
  behavior.
- Secrets and OAuth tokens do not belong in provisioning, evidence, URLs, browser
  storage, or logs.
- Grafana egress, operator ingress, TLS, CSP, headers, and audit controls require
  production security validation.

## Operational implications

Production implementation must establish ownership and procedures for:

- Grafana configuration and code-based provisioning;
- dashboard, folder, and PromQL review;
- Keycloak client, group mapping, role assignment, and operator lifecycle;
- tightly controlled organization Admin and datasource administration;
- private ingress, HTTPS, certificates, Secure cookies, and browser headers;
- Grafana egress and datasource network policy;
- persistence, backup, restore, HA, disaster recovery, upgrades, and rollback;
- required audit events, retention, access, integrity, and compliance review;
- supported-version selection and regression testing;
- resource and capacity monitoring; and
- monitoring Grafana itself.

Grafana outage does not affect application traffic or Prometheus scraping. Prometheus
outage produces visible query failure rather than application failure. Keycloak outage
does not create an authentication bypass. Exact production recovery objectives and
long-duration dependency behavior remain to validate.

## Migration and rollback implications

Initial adoption adds Grafana as a separate operator component. Prometheus remains
unchanged, and product applications require no migration. Products remain coupled to the
ADR 0007 metrics contract and ADR 0008 Prometheus component, not Grafana-specific APIs.
Grafana dashboards and provisioning are operator assets. Replacing Grafana should not
require rewriting product or domain instrumentation.

Grafana can be removed, disabled, upgraded, or rolled back without affecting application
availability or Prometheus scraping/query operation. Required dashboards and datasources
are version-controlled. Version rollback must account for Grafana database/schema,
dashboard/provisioning, built-in datasource and plugin compatibility, OAuth
configuration, and supported downgrade paths. The final production runbook remains
future implementation work.

## Explicit non-decisions

ADR 0009 does not select, accept, deploy, or define:

- Grafana Enterprise;
- Grafana Cloud;
- Loki;
- Tempo;
- Jaeger;
- Grafana Alloy;
- an OpenTelemetry Collector implementation;
- Alertmanager;
- Mimir;
- Thanos;
- VictoriaMetrics;
- blackbox exporter;
- `node_exporter`;
- cAdvisor;
- PostgreSQL exporter;
- Nginx exporter;
- a synthetic monitoring platform;
- final alert, log, or trace architecture;
- a final Grafana database or SQLite for production;
- final Grafana HA, backup, or disaster recovery;
- final private ingress or operator-access technology;
- Cloudflare Access;
- WireGuard or another VPN;
- a final reverse proxy, Grafana hostname, or TLS/certificate topology;
- exact Secure-cookie configuration;
- final CSP or browser-header integration;
- final Grafana egress or firewall implementation;
- separate Grafana instances;
- separate Grafana organizations as security boundaries;
- an authorization-aware metrics proxy;
- a custom operations portal;
- production alert rules;
- recording rules;
- SLOs or error budgets;
- a production dashboard catalogue; or
- a legal conclusion about AGPLv3.

Grafana is not selected as a tenant, customer, product-user, or product-facing interface.
This ADR does not select a complete monitoring platform.

## Remaining validation

Before production reliance, validate or decide:

- AGPLv3 legal/license acceptability;
- whether one trusted-operator visibility domain matches actual operations requirements;
- required compliance/audit semantics and whether Grafana OSS is sufficient;
- production private ingress and operator-access implementation;
- production HTTPS and Secure cookie behavior;
- datasource and general Grafana egress restrictions;
- production Grafana persistence/database topology;
- backup, restore, HA, and disaster recovery where required;
- production Keycloak SSO topology;
- logout, session, refresh, and revocation behavior;
- long-duration identity-provider outage behavior;
- production CSP, response headers, and reverse-proxy integration;
- accessibility and manual browser review;
- capacity and concurrency;
- operational ownership and incident procedures;
- supported-version policy and exact deployment pinning;
- upgrade and rollback runbooks; and
- the real production dashboard catalogue and query governance.
