<!--
File: spikes/api/results/comparison.md
Purpose: Compares DRF and Django Ninja using corrected Task 002 evidence.
Related:
- spikes/api/README.md
- spikes/api/results/drf-openapi.json
- spikes/api/results/ninja-openapi.json
- spikes/api/results/drf-types.d.ts
- spikes/api/results/ninja-types.d.ts
-->

# DRF and Django Ninja comparison

Both columns describe adapters over the same models, framework-neutral principal,
authorization services, transactions and PostgreSQL database. Ratings are evidence
summaries, not durable architecture decisions.

| Area | DRF | Django Ninja |
| --- | --- | --- |
| Request validation | Serializer fields reject missing, invalid enum, overlong, malformed and unexpected input. A custom unknown-field mixin remains necessary. | Typed schemas reject the same cases with strict extra-field rejection. |
| Response modeling | Explicit response-only model fields now make every always-present Project property required in OpenAPI; drf-spectacular splits request components. | Output schemas make every Project property required directly from annotations. |
| Error normalization | One global handler covers DRF, application and unexpected exceptions; common middleware handles oversized and framework-external 405 boundaries. | Five handlers cover application, validation, auth, HTTP and unexpected errors; the same middleware handles oversized and framework-external 405 boundaries. |
| OpenAPI quality | OpenAPI 3.0.3; 3 paths, 6 operations and 8 reusable schemas. JSON-body POST/PATCH operations explicitly include normalized 400 and 413 responses. drf-spectacular, annotations and an auth extension are required. | OpenAPI 3.1.0 with the same paths, operations, reusable-schema count and POST/PATCH response coverage. Most metadata follows annotations, while response maps and header aliases remain explicit. |
| Typing ergonomics | Serializer declarations are explicit, but endpoint values still need casts and runtime schemas parallel Python annotations. | Types drive most contracts, but PATCH requires non-null annotations with None defaults and three targeted type-ignore comments to express “omittable, explicit null forbidden” correctly in Pydantic 2.13.5/OpenAPI. |
| Authentication and authorization | Authentication validates only X-Spike-Actor; permission code validates Workspace context and constructs RequestPrincipal; shared services authorize actor-to-Workspace access. | Router authentication validates only X-Spike-Actor; operation parameters/context construction validate Workspace context; the same shared services authorize actor-to-Workspace access. |
| Authorization coverage | List, retrieve, create, update, delete and Workspace filtering all cross the shared authorization boundary. Foreign actor/context and resource identifiers return opaque 404. | Identical shared-service coverage and denial behavior. |
| Pagination and filtering | Query serializer plus shared service; Workspace filter substitution is denied by the service. | Typed query parameters plus the identical shared service and denial. |
| Transaction integration | Calls the shared synchronous transaction services. | Calls the identical services with identical transaction behavior. |
| Test ergonomics | Standard Django client exercises middleware, routing, auth, parsing and errors through the shared contract suite. | The same client and contract suite; Ninja TestClient was intentionally not used because it would bypass common boundaries. |
| Dependency footprint | DRF plus drf-spectacular as direct comparison dependencies. | Django Ninja as one direct comparison dependency; Pydantic remains locked transitively. |
| Boilerplate | 9 files and 402 nonblank/non-comment physical lines, including docstrings. | 4 files and 279 measured lines. Fewer lines do not determine safety or selection. |
| Async support | This spike proves synchronous behavior only; DRF 3.18 core documentation supplied no first-class async endpoint evidence. | The spike is synchronous, although Ninja supports async operations/auth under ASGI; Django transaction constraints still apply. |
| Maintainability | Mature explicit extension classes; parallel serializer/schema metadata is more surface to synchronize. | Smaller type-led adapter, offset by fragmented exception handling, the PATCH typing workaround and a younger ecosystem that warrants upgrade tests. |
| Workspace/RLS readiness | Framework-neutral authorization is a clear insertion point; no RLS was tested. | Identical insertion point and limitation. |
| Keycloak readiness | A real authenticator can replace synthetic actor parsing and keep services unchanged. | Same boundary; no real identity-provider behavior was tested. |
| TypeScript readiness | openapi-typescript 7.13.0 generated 509 lines; TypeScript 7.0.2 compiled the declaration with strict checking and no emit. | The same generator produced 611 lines and the same compiler validation passed. Line count is descriptive only. |
| Performance sanity | List 2.724 ms/367.10 rps; retrieve 2.069 ms/483.41 rps; create 4.480 ms/223.24 rps. | List 2.475 ms/403.96 rps; retrieve 1.727 ms/579.17 rps; create 2.390 ms/418.39 rps. |

## Authentication, context and authorization

The corrected flow is explicit:

~~~text
X-Spike-Actor authentication
    -> X-Workspace-ID context validation
    -> RequestPrincipal
    -> shared service authorization
    -> Workspace-scoped ORM operation
~~~

Missing or structurally invalid actor credentials produce normalized 401 responses.
With a valid actor, missing or malformed Workspace context produces normalized 422
validation. A valid actor targeting a different Workspace reaches service authorization
and receives opaque 404. The deterministic actor-to-Workspace convention remains
synthetic and proves boundary placement only; it is not a membership or production
authorization model.

## OpenAPI and routing details

Both generated documents describe normalized error envelopes for every declared
operation response. POST create and PATCH update, the two JSON-body operations, expose:

- create: 201, 400, 401, 404, 409, 413, 422 and 500;
- update: 200, 400, 401, 404, 409, 413, 422 and 500.

HTTP 405 is deliberately documented as routing/boundary behavior rather than by adding
nonexistent operations. Runtime tests prove normalized 405 responses. Both documents
also retain required X-Workspace-ID parameters and an API-key security scheme for
X-Spike-Actor.

## Generated TypeScript comparison

The reproducible command uses openapi-typescript 7.13.0 (MIT) with
--default-non-nullable false, followed by TypeScript 7.0.2 (Apache-2.0) strict,
no-emit compilation. That generator option preserves request optionality for fields
with server defaults.

| Contract | DRF output | Ninja output | Material interpretation |
| --- | --- | --- | --- |
| Project create | ProjectCreateRequest; workspace_id/name required, description/status optional | ProjectCreate; same required/optional shape | Equivalent behavior; component names differ. |
| Project PATCH | PatchedProjectPatchRequest; three optional, non-null fields | ProjectPatch; same shape | Equivalent generated client input. |
| Project response | Project; all seven fields required, output-only fields marked readonly | ProjectOut; all seven fields required, without TypeScript readonly | Both are complete; DRF carries stronger mutation hints. |
| Status enum | string union active or archived | same union under a different component name | Equivalent. |
| UUID | string with format: uuid documentation | same | Equivalent; neither generator brands UUID strings. |
| Pagination | items, page, page_size, total | same | Equivalent apart from component names. |
| Errors | every declared status references ErrorEnvelope; details becomes unknown | every declared status references ErrorEnvelope; details becomes object-or-array | Ninja retains more detail shape; both accept every runtime normalized detail form used here. |
| Paths/operations | DRF-prefixed paths and drf-prefixed operation keys | Ninja-prefixed paths and ninja-prefixed keys | Intentional comparison prefixes; operation coverage is equivalent. |
| Workspace header | required X-Workspace-ID string on all Project operations | same | Equivalent. |
| Authentication | Present in source OpenAPI security schemes/operation security | present in source OpenAPI security schemes/operation security | openapi-typescript does not emit security metadata into either declaration; clients must configure the actor credential separately. |

OpenAPI 3.0.3 and 3.1.0 both generated successfully. Ninja 3.1 additionally represents
optional query inputs as nullable unions and emits additionalProperties false for
strict body schemas. DRF 3.0.3 has broader legacy tooling compatibility and encodes
read-only response fields more strongly. No difference blocked generation or strict
TypeScript compilation, and fewer generated lines are not treated as a preference.

## Ninja PATCH typing assessment

Django Ninja 1.6.3 uses Pydantic 2.13.5. ProjectPatch with no arguments must accept
omission while ProjectPatch with an explicit null name must fail, and OpenAPI must
describe an optional non-null string. A conventional nullable annotation accepts
explicit null and emits a nullable schema. Ninja's partial-update helpers likewise make
fields optional/nullable for this case. Experimental or custom schema manipulation would
add more risk than the three narrow ignores.

The existing non-null annotations with None defaults therefore remain. Direct Pydantic
checks and API tests prove omission succeeds, explicit null fails, and generated PATCH
properties are optional but non-null. This is effective but not frictionless: static
typing disagrees with the runtime default representation, and pinned-version upgrade
tests must protect the behavior.

## Performance interpretation

The corrected authorization boundary adds a Workspace authorization lookup to scoped
queries, so the non-production sanity benchmark was rerun. It used PostgreSQL 16.15,
DEBUG false, concurrency 1 and Django's in-process WSGI test client. Each list/retrieve
measurement used 200 sequential requests and create used 100, with five warmups.
The result omits production networking, servers, TLS, concurrency and realistic data.
It shows no pathological overhead and is not a selection basis.

## Updated outcome

Both frameworks preserve equivalent runtime behavior and are viable. Django Ninja
remains the stronger default candidate for this typed, API-first workload because it
uses less adapter code and generated complete OpenAPI/TypeScript successfully. The
recommendation is narrower than “frictionless typing”: its PATCH representation and
exception surface are real maintenance costs.

DRF remains a credible mature fallback, especially if ecosystem depth, generic views,
browsable API behavior or team familiarity outweighs its additional schema and adapter
machinery. Human architecture review must weigh those factors. No architecture status
is changed by this spike.
