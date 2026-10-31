<!--
File: AGENTS.md
Purpose: Define durable development guidance and ownership boundaries for
         changes to the Omnilyzer reusable SaaS platform repository.
Related: README.md, CONTRIBUTING.md, SECURITY.md,
         docs/architecture/platform-principles.md,
         docs/architecture/technology-decisions.md.
-->

# Omnilyzer repository instructions

## Priority and existing requirements

Explicit task requirements override workflow-efficiency preferences. Security,
correctness, architectural integrity, and required validation take priority over
token reduction.

Follow [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md), and load
applicable ADRs, architecture documents, and domain contracts when relevant.
Preserve existing architectural, security, authentication, authorization,
Workspace/tenant-isolation, token/session, CSP/CORS, supply-chain, deployment,
and validation requirements. Do not silently resolve conflicting requirements:
preserve and report them unless precedence is explicit and unambiguous.

## Product scope and delivery priority

Omnilyzer is an owner-confirmed, reusable technical foundation for
**independently operated SaaS products** (2026-10-17). It is not a
mandatory CMS, nor one shared business-application monolith. Keep product
business logic, UI, domain data and release schedules in their own
approved boundaries. A CMS is optional product functionality, not the
platform roadmap. Sharing PostgreSQL or authentication infrastructure
does not authorize cross-product data access.

Do not invent general-purpose SaaS frameworks, additional control planes,
customer billing, CMS editors, plug-in systems or other abstractions
without an evidenced product requirement. For a single operator,
prefer the least complex implementation that preserves real security,
tenant isolation, provenance, reproducibility, rollback and recovery.

Near-term work is prioritized: (1) isolate and resolve the existing Task
014 DEV promotion blocker; (2) independently verify one approved
end-to-end DEV deployment; (3) integrate one real SaaS product workflow.
The successful Task 013 release 0.14.5 is distribution acceptance,
not production application acceptance. Never conflate successful CI,
a signed package or a synthetic test with live deployment readiness.

## Development orchestration

For Omnilyzer development, ChatGPT is the primary orchestrator. Treat the current
repository, this file, applicable ADRs/contracts, SECURITY.md, and
CONTRIBUTING.md as authoritative; inspect current state rather than relying on
conversation memory. Keep Omnilyzer isolated from unrelated organizations,
systems, customers, policies, prompts, documentation, tests, and code.

Use Remote Desktop Commander through the isolated omnigpt@omnilyzerdev account
for DEV-server inspection, edits, debugging, tests, browser validation, and
deployment.dev_handoff. Preserve its unprivileged boundary. Use the GitHub
connector directly for GitHub reads/writes, PRs, checks, reviews, merges, and
post-merge verification. Use Codex selectively for substantial implementation,
refactoring, or debugging where it adds value, not for mechanical workflow.

The user should normally provide requirements and decisions rather than relay
commands or output between systems. Require user action only for operations that
need their authority or cannot be performed through connected tools. Normal work
uses a dedicated branch, progressive validation, complete diff review, GitHub
security/CI checks, and a final deployment.dev_handoff leaving DEV clean and
synchronized to main.

## Lean feature delivery (owner decision 2026-10-29)

The owner is a solo operator. A normal product feature must not recreate the
large multi-chat, multi-PR, multi-week process experienced during the initial
Analytics integration. Optimize for a working user-visible capability on the
existing platform, with the existing security boundaries intact.

1. **One accountable delivery chat.** The owner describes the intended user
   outcome, not the technical task breakdown. The delivery chat owns discovery,
   implementation, integration, tests, release and final acceptance. Ask another
   specialist chat for one bounded independent check only if necessary. Coordinate
   directly through GitHub; do not require the owner to relay messages.
2. **One short feature contract.** Before coding, define the user journey,
   concrete acceptance criteria, explicit non-goals, affected product/repository,
   and what constitutes a real working deployment. Confirm a material scope
   trade-off once; do not demand approval at each implementation step.
3. **Reuse before build.** Inspect existing platform capabilities, product code,
   tests and infrastructure first. Prefer one cohesive feature PR per repository
   and one integration handoff; avoid framework-building, generic policy
   extensions, speculative security layers, duplicate evidence sets, micro-PRs,
   and unrequested features. Separate changes only for a genuine independent
   risk or required repository boundary.
4. **Demonstrate the product early.** Deliver the smallest secure end-to-end
   browser/API journey and actual persistence as soon as feasible. Evaluate
   success in terms of the feature working for its intended users, not PR count,
   test count, documentation count or release artifacts alone.
5. **Proportionate validation.** Run focused tests while changing code and the
   required integrated/security checks at the release boundary. Reuse previous
   unaffected proofs; rerun when the relevant input, code, dependency, or
   security boundary changes. Never skip mandatory security gates, tenant
   isolation, authorization, data protections or recovery checks.
6. **Task 013/014 are reusable automation, not new projects per feature.** For
   deployable product versions, use the existing approved build, scan, SBOM,
   provenance/sign, publish, verify, deploy, health and rollback workflows. Keep
   required policy gates automatic and fail-closed. A normal product change must
   not require new Task 013/014 implementation. Static-only changes may use
   their existing approved static publishing path where applicable. A material
   new runtime or trust boundary is an exception requiring explicit review.
7. **Batch work; ask the owner only for real decisions.** Progress through safe
   reads, edits, tests and review in one delivery stream. Pause for privileged
   operations, approval-required merges/deployments, changed scope, or an
   actual blocking conflict. Never treat a time target as permission to bypass
   required controls.
8. **One concise handover.** Record exactly what works, the deployed version
   and environment, real acceptance evidence, outstanding defects, rollback
   path, and the single next action. A feature is DONE only after the agreed
   real user journey works in the intended environment and required release
   checks pass; a draft PR or synthetic test alone is not DONE.

## Embedded QA and release readiness (owner decision 2026-10-30)

Quality assurance and test management are integral to each feature delivery, not
a late separate phase that first appears in Task 013/014. Apply **shift-left QA**
using existing repository checks, CI and release/deployment contracts; do not
create a separate QA organization, standing test chat, generic test framework or
approval bureaucracy for ordinary product changes.

1. **Accountability from day one.** The one accountable delivery chat owns
   functional quality, security tests, release readiness, real user acceptance
   and defect resolution. Request a narrow independent review only for a
   material risk or required existing policy; do not hand a half-tested feature
   to another chat at the end.
2. **Definition of Done starts in the brief.** Alongside the user journey,
   identify the few observable acceptance scenarios, negative/unauthorized and
   cross-tenant cases as relevant, data migration/persistence implications,
   operational prerequisites, and intended deployment/rollback path. Choose
   checks in proportion to actual change risk; avoid expansive test plans for
   simple changes.
3. **Release-contract preflight before substantial implementation.** Identify
   the current product's Task 013 build/runtime/dependency/security-policy
   expectations and Task 014 identity, configuration, secrets, readiness,
   deployment and rollback requirements. Check for missing contracts, vulnerable
   dependencies, unsupported runtime assumptions, unavailable environment
   prerequisites or incompatible ownership boundaries *early*, and fix the
   owning cause before building more features. Do not assume the synthetic
   canary proves the real product deploys.
4. **Test continuously and progressively.** Add or adjust focused automated
   tests with the changed functionality; exercise the actual browser/API/data
   path and necessary security boundaries at integration milestones. Prefer
   existing fixtures and test infrastructure. Run fast targeted tests during
   iteration, required broader checks once stable; do not rerun unchanged large
   suites or generate duplicate test evidence after every edit.
5. **Surface release blockers before the final release.** Use existing PR/CI
   checks for build reproducibility, locked dependencies, relevant SCA/image
   vulnerability exposure, configuration, schema compatibility, readiness and
   release-policy constraints as early as practical. Early scans are feedback,
   not a substitute for the mandatory final immutable-artifact scan, verified
   signature, provenance, authorization, and release gates.
6. **Keep one current defect/readiness picture.** Record only actionable open
   blockers in the canonical feature issue/PR, clearly distinguishing product
   defects, environment prerequisites, security policy failures and approvals.
   Resolve them in the owning delivery stream and record evidence once;
   escalate a genuinely blocked decision rather than starting endless
   cross-chat handoffs.
7. **Ship only proven outcomes.** At release, run the existing required Task
   013/014 controls and a small real-user smoke journey plus relevant failure
   and rollback checks. Verify the exact deployed artifact, environment,
   health, access control and data behavior. Automatic failure must stop
   promotion or safely roll back; never weaken policy to meet a schedule.
   Declare DONE only when the accepted user journey works on the intended
   live environment, not when CI or isolated tests alone are green.

## Cross-chat continuity and source of truth

ChatGPT conversation memory is useful context but is not a complete or reliable
repository state ledger. For each substantial new task, read this AGENTS.md,
the current relevant GitHub issue/PR and exact source HEAD before proceeding.
Keep one canonical feature issue/brief and one concise current-state handover,
with links to the actual code, rather than multiplying coordination threads.
Update the canonical issue at meaningful milestones and closure, not for every
small edit. The repository and current deployment evidence are authoritative
over remembered chat summaries. Do not claim an asynchronous personal-memory
update or infer that a file was deployed merely because it was committed.

## Before Task014 promotion

For Analytics release preparation or promotion, read
[the Task014 pre-release checklist](docs/operations/task014-pre-release-checklist.md)
before dispatch. Reconcile its evidence against current source and installed
state, distinguish ordinary releases from platform setup, and keep unsupported
release versions blocked. Reuse existing qualification for unchanged boundaries.

## Before editing and context discipline

- Understand the affected execution flow. Search for the owning implementation
  and relevant callers before broad reading; use targeted reads once located.
- Prefer current repository code, tests, applicable ADRs/contracts, and repository
  instructions over conversational summaries.
- Load information when relevant, rather than speculatively. Avoid rereading
  unchanged full files when a focused read or git diff suffices.
- Do not read generated artifacts, dependency trees, caches, build output, or
  large lock/data files unless the task specifically requires them.
- Preserve complete source context whenever partial reading risks an incorrect
  change.

## Implementation

- Reuse existing Omnilyzer implementations and patterns before creating new ones.
  Fix the shared root cause rather than individual symptoms.
- Prefer Python standard-library or existing platform capabilities where
  appropriate; avoid new dependencies when an existing safe solution suffices.
- Avoid speculative abstractions or scaffolding. Make the smallest correct
  change preserving the architecture; do not minimize files or lines at the
  expense of proper separation of concerns.
- Keep permanent, broadly applicable rules here. Keep task-specific procedures
  out of this file; load them on demand. Do not relocate existing rules into
  skills without a separately scoped task.

## Security and authentication

Never simplify away authentication, authorization, tenant isolation,
trust-boundary validation, token/session protections, CSP/CORS protections,
error handling needed to prevent data loss, required observability, or
security-relevant tests.

Authentication/session architecture is currently a protected boundary. Existing
owner guidance and accepted repository architecture are not fully aligned on
browser token/session storage. Do not change authentication flows, token
transport/storage, session storage, cookie behavior, or frontend credential
persistence incidentally.

For any task touching these areas:
- inspect the current implementation and applicable accepted ADRs first;
- preserve current behavior unless the task explicitly authorizes an
  authentication architecture change;
- if the requested change conflicts with an accepted ADR or current security
  contract, stop and report the conflict rather than choosing one silently.

Resolving the browser authentication/session-storage architecture requires a
separately scoped security architecture task and, where appropriate, an ADR
update before implementation.

## Validation and failures

Use progressive validation where practical:

1. Directly affected focused test/check.
2. Relevant module/domain tests.
3. Relevant integration tests.
4. Full validation once implementation stabilizes.

Complete task-required and applicable repository checks. Do not repeatedly run
the entire suite after every small edit unless necessary.

Preserve complete failure/error information; do not suppress or summarize away
details needed for diagnosis. Treat security, authentication, database, and
migration failures conservatively.

For privileged live-state qualification whose public boundary intentionally
collapses internal errors, run a reviewed read-only component-level preflight
against the live host before asking for or performing the fail-closed gate. The
preflight must continue across independent assertion failures and surface the
complete mismatch set in one run. Do not promote newly observed live values into
authority until that full matrix has been inspected; fix cross-phase helper or
allowlist coupling at its owning layer instead of widening an earlier-phase
contract.

## Completion report

Work thoroughly and report concisely. Unless the task requests another format,
use:

- **Changed:** concise summary.
- **Validation:** commands/checks and results.
- **Remaining:** unresolved risks/issues, or "none".

Avoid long implementation narratives unless specifically requested.
