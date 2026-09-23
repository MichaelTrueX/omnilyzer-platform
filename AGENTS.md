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

## External service costs

Do not introduce a production dependency on paid SaaS, a commercial license,
paid API tier, or mandatory subscription without explicit user approval. Before
selecting an external service, verify that the exact required feature is
available under the intended free, open-source, or self-hosted model; whether
private repositories or projects change pricing; and whether usage-based billing
is mandatory. Consider a free, open-source, or self-hosted alternative. If a
paid dependency appears necessary, stop before implementation and report the
exact dependency, paid feature, expected cost, and alternatives.

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

## Completion report

Work thoroughly and report concisely. Unless the task requests another format,
use:

- **Changed:** concise summary.
- **Validation:** commands/checks and results.
- **Remaining:** unresolved risks/issues, or "none".

Avoid long implementation narratives unless specifically requested.
