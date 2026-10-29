<!--
File: docs/operations/m03-nonowner-runtime-readiness-20261028.md
Purpose: Independent concrete PostgreSQL16 + compiled Next14 negative acceptance
         for Analytics' least-privilege application role and readiness contract.
Related: release/tests/accept_m03_nonowner_runtime_pg16.py;
         MichaelTrueX/omnilyzer Analytics PR #45, exact HEAD 8648adba...;
         prisma/rls/m01-runtime.install.sql and analytics-app-events.install.sql;
         app/readyz/route.ts; original platform PR #234; Issue #27.
Status: REVIEW-ONLY. No live installation, signer authority or database change.
-->
# M03: restricted Analytics application role is not production-ready

**Date:** 28 October 2026 (Asia/Manila). **Release decision:** BLOCKED
for a non-superuser/non-RLS-bypass application database connection. This is
a separate question from the existing collector/archive service role tests.

## Source basis and evidence

- Canonical Analytics PR #42: `597a3415dfee76cc63f6ba70d3660f287a09b0c8`.
- Final M05 packaged Analytics PR #45: `8648adba2db884cc78274080b9836ca46bafd630`.
  Relative to PR #42, it adds only `Dockerfile.analytics`, `.dockerignore`,
  and `scripts/accept-m05-analytics-oci-dev.py`. All executable API/RLS
  code is identical.
- Original platform Task013/014 review stack, including PR #234, does
  not authorize a signed Analytics release or actual DEV promotion.
- The existing `scripts/accept-platform-integration-dev.py` application
  process connects using the synthetic PostgreSQL **migration owner**.
  The test uses `SET ROLE omni_runtime` for separate RLS checks, but it
  does not serve the actual HTTP API using that limited credential.

The reproducible companion Python script checks Git HEADs and runs only on
`truexdevelopment` as a non-root user. It starts a **brand-new disposable**
PostgreSQL16 cluster and database on a random localhost port. Prisma
creates the exact source schema; actual SQL migrations and M01's
collector/archive installer run unchanged; it then adds M01's application
event-role policy unchanged.

## Actual security counterexample

The fixture creates `omni_runtime` as `NOINHERIT NOSUPERUSER NOBYPASSRLS`
and explicitly grants the role **SELECT, INSERT, UPDATE, DELETE on every
application table** and sequence/schema usage. These deliberately broad
test grants eliminate missing ordinary ACLs as a false explanation for
the observed denial. They are **not an acceptable production GRANT plan**.

The disposable DB superuser inserts one Workspace and one linked Website.
The exact resulting observations are:

| Real PostgreSQL operation | Migration owner | `omni_runtime` |
| --- | ---: | ---: |
| `SELECT COUNT(*) FROM public."Workspace"` | 1 | 0 |
| `SELECT COUNT(*) FROM public."Website"` | 1 | 0 |
| Insert another Workspace | permitted | SQLSTATE `42501` |

M01's existing RLS installation enables **FORCE ROW LEVEL SECURITY** on
Workspace and Website. Its explicit collector policies are scoped to
`collector_runtime`, while the application event-specific additional policy
applies only to `WorkspaceAnalyticsEvent`. No equivalent app-role
policy grants meaningful Workspace/Website visibility and writes.
PostgreSQL correctly denies the missing authorization.

For an additional **actual HTTP** check, the script makes the test
`omni_runtime` a LOGIN principal and starts the genuine compiled
canonical Next.js 14 application with `DATABASE_URL` pointing to that
non-bypass role; `COLLECTOR_DATABASE_URL` points to its existing
limited collector role. Both JWT keys are synthetic review-only strings.

**Result:** `GET /readyz` returns HTTP **200** and
`{"status":"ready"}` despite this same application principal being unable
to see either existing Workspace/Website row or insert a Workspace.
The current route probes `Session` and `WorkspaceMembership` columns for
the main pool and `Website` and `WorkspaceAnalyticsEvent` for the
collector pool. Those zero-row permission checks do not establish the
product's actual Workspace/Website RLS role usability.

This does **not** show a cross-tenant data leak, arbitrary user compromise,
or failure of the collector's separate role policies. It shows a
**functional least-privilege admission gap** plus a misleading positive
health signal under the tested credential model.

## Reproduce in the existing isolated development environment

No production, named DEV, Cloudflare, Nginx or Task014 installed service is
accessed. The paths are deliberately pinned to the existing local immutable
review checkouts and may need an isolated test-runner revision on another
developer machine:

```bash
cd /home/trusthansen/workspaces/omnilyzer-platform-m03-nonowner-readiness-20261028
python3 release/tests/accept_m03_nonowner_runtime_pg16.py
```

Expected successful *negative* result ends with
`M03_NONOWNER_RUNTIME_P0_GAP_REPRODUCED`.
The runner always shuts down its own Next process and PostgreSQL cluster,
deletes temporary synthetic credentials/data and removes its temporary
dependency symlinks, including on an assertion failure. It does not merge
or alter either immutable Analytics source Git commit.

## Required M01 / M04 remediation and independent acceptance

M01 must design the **application** principal as a third explicit
least-privilege database role, separate from collector and archive. It must
safely enforce Workspace membership and tenant identity in the data access
boundary for Workspace, Website and all affected event/aggregate tables.
Do not attempt to make this pass using `BYPASSRLS`, a PostgreSQL
superuser/migration owner as the web application's runtime credential, or
permissive `TO PUBLIC USING(true)` policies.

After implementing the actual policy and required API transaction changes,
acceptance must run the **complete real HTTP authenticated login ->
Workspace create -> Website create -> public collector -> report ->
cross-Workspace denial -> session revocation** workflow with the Next app
itself configured under the non-bypass role. Both positive and negative
cases are necessary. M04 should independently verify role and policy
semantics. Readiness must not be interpreted as proof of these functional
capabilities without such evidence.

Because the canonical PR45 source and original platform source manifest
are immutable, any product policy or API code change requires a **new
reviewed source SHA, source hashes, signed build input and release evidence**.
Existing original Task013/014 canary acceptance must remain unchanged.
No live DB migration, production deployment, protected-main merge or
release authority is authorized by this review-only script.
