# Task 014 DEV runtime (reviewed, non-live)

This directory defines the production-owned synthetic Task 014 DEV deployment boundary. It is not installed and nothing invokes it automatically. DEV remains disabled; PR D must bind these bytes to this PR's eventual merge SHA. This Nginx selection is only for the synthetic Task 014 DEV deployment boundary, not a production-wide base-image decision.

## Qualified deployment Nginx

Read-only qualification on 2026-09-08 used `cgr.dev/chainguard/nginx:latest` for discovery only. It resolved to index `sha256:b91cf888522ed0cc1b6bddadfa8320ac2a131a1003b103ae340217a421f12fcc` both before and after qualification. Anonymous exact-digest retrieval passed. Active configuration uses only linux/amd64 manifest `sha256:af16298b4fd38b12be52aa913c158b530b83d85d567752f611508593d542b20a`, config `sha256:e8f6995729991de523ce7e0193cb184044d6e7a161711c8faa6eb980963d1a8a`. It runs as user `65532`, with entrypoint `[/usr/sbin/nginx]`, command `[-c,/etc/nginx/nginx.conf,-e,/dev/stderr,-g,daemon off;]`, and no declared exposed port. This deployment explicitly listens on container port 8080.

Cosign 3.1.2 supplier signature verification passed, including Fulcio and transparency-log checks, for issuer `https://token.actions.githubusercontent.com` and identity `https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main`. The signed SPDX 2.3 supplier SBOM passed and bound the exact amd64 manifest (86 packages). Grype **0.118.0** report SHA-256 `4fa048a9501015334d586b55352255145b0a687240a74cbe59f0f643b90f25c6` passed the unchanged policy SHA-256 `475ad38ef4ae8d89dcf7d4e03eeb76701085fdcd4ebdb8ae9aa41a7bce2cde8f`: Critical/High block, exceptions `[]`, `blocked_findings=[]` (one Medium). The valid DB was schema `v6.1.9`, built `2026-09-08T06:30:10Z`, checksum `sha256:3564b57fd65da3cba50174d9fdab8b4e8dab6f7f7b798ebd3cec3085ea10c7e6`.

Selected compressed layers (digest, bytes):

```text
sha256:60bbc66affbe44cdd34712c99032071b0e606fa682c4948c08e644d05153e851 2939084
sha256:62444e89bd1466da92757774fcc18ad8efbd77aab88a618547a2dbe745536364 3357623
sha256:7fbd4ff13dcf9ed438edfd61415c0022fe63766640739fd44b77c80cc8beae46 639541
sha256:c7d5351d313832b8536cdeb914ff607c0b4842f7c48894f296cdda41ab86f95c 307589
sha256:0e3a84f7427f59342d7be4787e01fad97fb26e0f084e961d1527e7ed1810a0a5 97913
sha256:b10d4a946640307a04381e8ff5b3dc262f7332586acb67ba29838d9b1d239cbc 95801
sha256:ed4725379a22e41b02806192aff768a5e11226d9511b806bf6138e8dfba5f24e 108111
sha256:bc0f2d8a7aba66a519a774a09300dc32043cd2a7483c19b9efef2345dd4cf48e 64401
sha256:086ef90c41ce61a410fa90c32b6c22550ec6ea96ae7ae1d44204e86d2201f709 11873
sha256:944f369a066cb187845bdf322c0a606fb52867bcbde8f51ec9bbee22f5c2220a 11724
```

Chainguard Free does not provide a sufficient old-digest retention guarantee. Exact-digest unavailability must fail closed; there is no mutable-tag fallback. No mirroring is implemented. Production retention/mirroring or a versioned supplier remains a separate decision.

## Runtime, migration, and switching

Compose project `omnilyzer-task014-dev` has exactly `canary-blue`, `canary-green`, and `deployment-nginx`, and no build directive. `CANARY_IMAGE` must be exactly `oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:<64 lowercase hex>`. Each adapter instance is constructed with one validated exact candidate and places that immutable reference in its minimal controlled environment for every command, including Compose-only Nginx validation and reload operations. Pull, local RepoDigest inspection, candidate start, and migration reject any different digest, even another syntactically valid Task 014 digest. PR B neither pulls nor runs release 0.14.2.

Application slots run as `10001:10001`, read-only, cap-drop ALL, no-new-privileges, hardened 16 MiB `/tmp`, 128 PID, 0.5 CPU and 128 MiB limits, bounded json-file logs, and no host port. The only network is internal `task014_frontend`; there is no backend network, Docker socket, registry credential, or application port publication. Deployment Nginx is likewise non-root/read-only/hardened and alone publishes `127.0.0.1:3020` to 8080.

`/var/lib/omnilyzer/deployment/dev/canary-runtime` is mounted read-only at `/run/omnilyzer-canary` in application slots. The explicit migration operation alone mounts it read-write and runs `/app/migration.py`; migration is never startup behavior. Identity is `task014-executable-canary-v1`, definition checksum is `b25e7d2d55bce3e233f58f9607e715daebc2a1a69c37603adbb569604ef76421`, and durable files are `migration.lock` and `migration.json`.

The Nginx base is valid with an empty directory-mounted `/var/lib/omnilyzer/deployment/dev/nginx-runtime` and returns JSON 503 maintenance. A generated `active.conf` can name only blue or green. The adapter atomically fsync/replaces it, validates deployment Nginx syntax, then reloads only `deployment-nginx`. Candidate routing follows separate `/livez`, `/readyz`, and exact `/metadata` gates. Validation/reload failure restores, validates, and reloads the previous fragment; running routing remains unchanged on failed reload. The adapter never modifies host Nginx. `host-nginx.conf` is review-only and uninstalled; PR C selects TLS.

### Closed candidate probing

C14 adds the reviewed concrete candidate HTTP client without changing these
runtime assets. A probe selects only the exact `canary-blue` or `canary-green`
Compose service and runs one fixed, bounded `/usr/bin/python` helper there. The
helper performs one GET to that candidate's own `127.0.0.1:8080` loopback and
accepts only `/livez`, `/readyz`, or `/metadata`. It has no proxy, DNS hostname,
arbitrary target, shell, or retry path, and returns only a bounded status/body
envelope to the host-side parser.

Neither candidate publishes a host probe port; `deployment-nginx` remains the
only service with the `127.0.0.1:3020:8080` host mapping. C14 is repository-only
and does not activate or execute a real probe. The concrete client is not yet
wired into C11's executor composition; that closure is reserved for a later
reviewed slice. `compose.yaml` is unchanged and its SHA-256 remains
`ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc`.

The canonical runtime configuration is exactly 99 bytes, SHA-256 `8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f`, and has a closed schema. No runtime secret exists. The accepted no-secrets reference remains `{"schema_version":1,"kind":"none","required":[],"reason":"task014-synthetic-canary-has-no-runtime-secrets"}`. OIDC/zot/Forgejo tokens are deployment credentials, never application configuration.

## Durable state and audit

State remains schema v1 at `/var/lib/omnilyzer/deployment/dev/state.json`, with directory/file modes 0700/0600, same-directory temporary creation, file fsync, atomic replace, and directory fsync; no container mounts it. The closed executor request already binds operation, actor ID, workflow ref/SHA, run ID/attempt, promotion-request hash, OIDC JTI, and timestamps. No state migration or duplicate authority fields are added; no Task 014 state is deployed.

PR B supplies the durable filesystem audit sink. It writes canonical one-record-per-line JSON to `/var/log/omnilyzer/deployment/dev/events.jsonl`, modes 0700/0600, using serialized `O_APPEND` and fsync. It rejects malformed, partial, noncanonical, duplicate, oversized (over 16 KiB), or chain-invalid history. `previous_event_sha256` links full records. This is tamper-evident and owner-controlled, not root-tamper-resistant; remote/WORM audit is deferred.

The complete broker/executor OIDC execution identity remains in the closed executor-request contract. The current `AuditEvent` does not persist every one of those fields. PR C **must** project and persist the actor ID, workflow ref/SHA, GitHub run ID/attempt, promotion-request SHA, OIDC JTI, and OIDC timestamps into live audit evidence before deployment activation. PR B does not implement that live broker/executor wiring.

Rotation occurs before crossing 10 MiB or on a new UTC day, uses atomic rename and never copytruncate, retains 14 rotations, and delays gzip until the following rotation. The next active record links to the renamed file's final record. After retention deletes old history, the oldest retained predecessor is an explicit anchor; continuity is verified across all retained files, not deleted history. Host ownership and live rotation/restart validation remain PR C work.

## Exact reference hashes

The future references require the real reviewed merge SHA; no placeholder `reviewed_commit` is accepted.

| Path | SHA-256 |
|---|---|
| `deployment/runtime/dev/canary-runtime.json` | `8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f` |
| `deployment/runtime/dev/compose.yaml` | `ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc` |
| `deployment/runtime/dev/host-nginx.conf` | `bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb` |
| `deployment/runtime/dev/nginx/nginx.conf` | `cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b` |

The ingress file set is exactly the final three paths.
