<!--
File: spikes/api/results/comparison.md
Purpose: Compares DRF and Django Ninja using Task 002 implementation evidence.
Related:
- spikes/api/README.md
- spikes/api/results/drf-openapi.json
- spikes/api/results/ninja-openapi.json
-->

# DRF and Django Ninja comparison

Both columns describe adapters over the same models, principal, authorization services,
transactions and PostgreSQL database. Ratings are evidence summaries, not durable
architecture decisions.

| Area | DRF | Django Ninja |
| --- | --- | --- |
| Request validation | Serializer fields correctly rejected missing, invalid enum, >120-character name and malformed UUID input. A custom `RejectUnknownFieldsMixin` was needed because unexpected fields are otherwise ignored. | Typed `Schema` fields correctly rejected the same cases; one base `Config(extra="forbid")` rejected unexpected fields and generated `additionalProperties:false`. |
| Response modeling | Explicit `ModelSerializer` and page/error serializers produced stable responses; request/response component splitting came from drf-spectacular. | Return schemas validated/serialized Django objects and page/error models directly from annotations. |
| Error normalization | One global handler covered DRF, application and unexpected exceptions. DRF's exception taxonomy was convenient; external middleware handled the common oversized/405 boundary. | Five explicit handlers covered application, validation, auth, HTTP and unknown exceptions. A Django middleware response guard was needed because one 405 path occurred outside Ninja's handler. |
| OpenAPI quality | OpenAPI 3.0.3; 3 paths, 6 operations, 8 reusable schemas, UUIDs, enum, constraints, pagination, errors, auth and Workspace header. Needed drf-spectacular, annotations and an authentication extension. | OpenAPI 3.1.0; the same 3 paths/6 operations/8 reusable schemas with equivalent types, constraints, pagination, errors, auth and Workspace header. Most metadata followed annotations; explicit response maps and header aliases were still required. |
| Typing ergonomics | Runtime serializer declarations are explicit but endpoint values need casts and typing is partly parallel to Python annotations. | Python annotations, enums and schemas are the primary endpoint contract; editor/static-analysis ergonomics were more direct. |
| Authorization hooks | `BaseAuthentication` installed the shared principal; a `BasePermission` made the requirement runtime/schema-explicit; services performed resource authorization. | `APIKeyHeader` installed the same principal at router scope; services performed resource authorization. |
| Pagination | Custom serializer plus shared service. drf-spectacular inferred defaults/min/max from the query serializer. | Typed query parameters plus the same shared service. Built-in Ninja pagination was deliberately not used so semantics stayed identical. |
| Filtering | Query serializer validates `status`, UUID and pagination, then shared service enforces Workspace context. | Typed query values validate the same inputs, then the same service enforces Workspace context. |
| Versioning | Explicit Django URL include under `/api/v1/drf/`; v2 can mount a new URLConf. DRF also offers framework-specific versioning, which was unnecessary here. | Explicit NinjaAPI mount under `/api/v1/ninja/`; a separate router/API can mount v2. No domain change is required. |
| Transaction integration | Calls the shared synchronous `transaction.atomic` service; framework adds no transaction constraint. | Calls the identical synchronous service; framework adds no transaction constraint. |
| Test ergonomics | Standard Django client exercised middleware, URL resolver, auth, parsers and errors; the shared test mixin passed all cases. DRF also offers APIClient, not required here. | The same standard Django client and shared mixin passed all cases. Ninja's faster isolated TestClient exists, but was not used because it would bypass common middleware/URL behavior. |
| Admin integration | No framework-specific effect; Django admin registered the shared models. | No framework-specific effect; Django admin registered the shared models. |
| Dependency footprint | Two direct comparison dependencies: DRF and drf-spectacular. Shared Django/psycopg excluded. | One direct comparison dependency: django-ninja. Its locked transitive Pydantic dependency was not imported directly by final spike code. |
| Boilerplate | 9 files and 385 nonblank/non-comment physical lines, including docstrings. Extra code mainly provides serializers, URL classes, permission and schema customization. | 4 files and 264 measured lines. Extra code mainly provides typed schemas, route functions and exception handlers. |
| Async support | This spike proves synchronous behavior only. DRF 3.18 core docs supplied no first-class async endpoint evidence; third-party async DRF would expand dependencies/risk. | This spike is sync, but Ninja officially supports native async operations/auth under ASGI. Django's no-async-transactions constraint still applies. |
| Maintainability | Mature, explicit separation and rich extension classes; more parallel declarations and schema machinery must remain synchronized. | Smaller, type-led surface with less schema duplication; Pydantic/Ninja behavior and a younger ecosystem require deliberate upgrade tests. |
| Security ergonomics | Explicit auth + permission classes are easy to audit. Strict extras and normalized errors required customization. | Router auth and strict schemas are concise. Exception coverage was more fragmented and one framework-external 405 required common middleware. |
| Workspace/RLS readiness | Framework-neutral service scoping proves an insertion point; future RLS lives below DRF in Django DB connection/migrations. No RLS was tested. | Same insertion point and same limitation; Ninja does not change the ORM/RLS boundary. |
| Keycloak readiness | Authentication class can validate a bearer token or consume a BFF session and return `RequestPrincipal`; service code remains unchanged. | Auth callable/security class can do the same; service code remains unchanged. |
| TypeScript-client readiness | Complete generated contract, stable operation IDs and reusable schemas. OpenAPI 3.0.3 has broad generator support; runtime unknown-field rejection is not represented by `additionalProperties:false`. | Complete generated contract and OpenAPI 3.1.0; stricter body schemas express `additionalProperties:false`. Specific TypeScript generator compatibility was not run. |
| Performance sanity | List 2.435 ms/410.7 rps; retrieve 1.689 ms/592.2 rps; create 2.812 ms/355.6 rps. | List 1.789 ms/558.9 rps; retrieve 1.278 ms/782.6 rps; create 2.541 ms/393.6 rps. |

## Measured complexity

`code-metrics.json` counts Python files and nonblank/non-comment physical lines;
docstrings count. It deliberately excludes the shared domain and tests. DRF's 121-line
difference is not treated as an automatic defect: much of it makes serialization,
permissions and schema adaptation explicit. It is still maintenance surface that must be
kept aligned with runtime behavior.

Custom adapter inventory:

- DRF: authentication adapter, permission adapter, global exception handler,
  unknown-field mixin, drf-spectacular annotations and authentication extension.
- Ninja: authentication adapter, strict Schema base, and five exception handlers.
- Shared/common: request-size and framework-external 405 normalization middleware.

## OpenAPI details

Both artifacts are generated from implementation, not handwritten. Both describe:

- required Project create fields and optional PATCH fields;
- non-null strings, UUID identifiers, Project status enum and date-time outputs;
- list pagination and status/Workspace filters;
- 201, 204, 401, 404, 409, 422 and 500 response models;
- deterministic operation IDs;
- synthetic actor security plus required `X-Workspace-ID`.

DRF's schema uses OpenAPI 3.0.3 and Ninja uses 3.1.0. Ninja expresses rejected extra body
properties directly. DRF produces broader generator compatibility today but required the
extra generator dependency and annotations. Neither artifact proves success with the
future chosen TypeScript generator; that remains an integration test.

## Performance interpretation

The final run used PostgreSQL 16.15, DEBUG false, concurrency 1 and Django's in-process
WSGI test client. Each list/retrieve measurement used 200 sequential requests and create
used 100; five warmups preceded each group. Ninja was 10–27% lower latency in this run.
The measurement excludes production server, sockets, TLS, proxies, multiple workers,
concurrent clients, connection pooling, response compression and realistic workloads.
It identifies no pathological overhead in either adapter and is not a selection basis.

## Outcome

Both frameworks pass the equivalent contract and remain viable. Django Ninja is the
stronger default candidate for this API-first, typed-client-oriented workload because it
achieved equivalent tested behavior with more directly inferred OpenAPI and less
framework-specific code. DRF remains the credible mature fallback, particularly if later
requirements depend on its broader ecosystem, browsable API, generic views, or established
team familiarity. Human architecture review must weigh those ecosystem factors before an
ADR.
