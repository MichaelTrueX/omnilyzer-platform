<!--
File: docs/operations/task014-dev-0146-acceptance.md
Purpose: Authoritative closure and live HTTP evidence for Task 014 DEV canary deployment.
Related: README.md; deployment/README.md; deployment/runtime/dev/compose.yaml;
         deployment/runtime/dev/nginx/nginx.conf; deployment/docker_runtime.py;
         .github/workflows/platform-release.yml; .github/workflows/platform-promote.yml.
Boundary: Synthetic DEV canary only. No public ingress, PROD or hosted product authorization.
-->

# Task 014 — signed DEV canary 0.14.6 ACCEPTED

**Acceptance: PASS — 20 October 2026; reconfirmed 21 October 2026 (Asia/Manila).**

Task 014 has delivered the signed release-to-DEV deployment path, including the real rootless Docker runtime, blue/green traffic switch and live host-local HTTP ingress. It has **not** deployed an actual customer SaaS product or a public website.

## 1. Immutable identities and confirmed CI results

| Item | Exact accepted value |
| --- | --- |
| Repository | `MichaelTrueX/omnilyzer-platform` |
| Protected source `main` and installed DEV generation | `8d321e12ff85d25bf1ea4b8ff4dd0adc7bb8dbf4` |
| Signed version | `0.14.6` |
| [Release run](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39448200369) | `39448200369` — SUCCESS (gate, build, zot, Forgejo) |
| OCI image digest | `sha256:81bd3b6e1b613cc1a89f8fc192cd78170ead6f8f5b321470f1833d610bffe30c` |
| Release-manifest SHA-256 | `c72a94e2305c03bac0243ab21067cf53d795f14b7011ff79e504137285b16bc4` |
| Release-provenance SHA-256 | `997e82b2bf2ae4849bc8a9a0b886071b2b9ce1a05f80a61d67b1819182b74af5` |
| [Promotion run](https://github.com/MichaelTrueX/omnilyzer-platform/actions/runs/39449223284) | `39449223284` — SUCCESS (gate, deploy_dev) |

The manifest/provenance hashes were independently reconstructed from the immutable release handoff and zot publication receipt, using the release's exact GitHub run identity before promotion. Previously failed or consumed requests were not replayed.

## 2. Direct live DEV HTTP acceptance

From `omnilyzerdev`, independent of the CI runner, the actual host-local Nginx proxy was queried with `Host: canary-dev.omnilyzer.ai` on `127.0.0.1:3020`. The full endpoint results were reconfirmed the next morning:

| Endpoint | HTTP | Relevant response |
| --- | --- | --- |
| `/livez` | 200 | `{"live":true}` |
| `/readyz` | 200 | `{"checks":{"dependency":true,"migration":true,"runtime_configuration":true},"ready":true}` |
| `/metadata` | 200 | `{"canary":true,"release_version":"0.14.6","source_sha":"8d321e12ff85d25bf1ea4b8ff4dd0adc7bb8dbf4"}` |
| `/` with expected Host | 404 | Expected: synthetic API has no home page |
| Default/unmatched Host | 503 | Expected maintenance-only default virtual host |

Run these read-only checks from the authorized laptop:

```bash
ssh trust@omnilyzerdev 'sudo -n /usr/local/sbin/omnilyzer-dev-ops status'
ssh trust@omnilyzerdev 'curl --fail --silent --show-error -H "Host: canary-dev.omnilyzer.ai" http://127.0.0.1:3020/metadata'
```

The DEV broker, executor socket and host Nginx services were active. The executor service is socket activated, and may correctly be inactive between requests.

## 3. Security and bounded operations retained

The `canary-blue` and `canary-green` workloads remain solely on the internal `task014_frontend` Docker network. Only digest-pinned Nginx also joins `task014_edge` for a **loopback-only** published port. Its filesystem remains read-only, process runs as non-root `65532:65532`, Linux capabilities are dropped, and its temporary files use the existing restricted tmpfs. The released image, Sigstore identity checks, short-lived OIDC, source digest checks, replay protection, audit and state recovery were retained.

A limited root-owned `/usr/local/sbin/omnilyzer-dev-ops` is installed for fixed DEV status, logs, restarts, source sync, image selection and rollback. Its `sudo -n` delegation is limited and does not grant arbitrary root execution, replay resets or PROD changes. Source/image rollback copies exist under `/opt/omnilyzer/deployment/.dev-ops-recovery/`.

## 4. Explicit limitations and remaining work

- **No public DNS / internet route accepted.** The canary hostname was not resolvable from DEV; private Tailscale Serve continues to protect the separate deployment ingress. Do not enable public DNS, Tailscale Funnel or external exposure as part of Task 014 closure.
- **Legacy status script defect.** The older root helper `/usr/local/sbin/omnilyzer-task014 status` prints `TASK014_HOLD ValueError` even when signed promotion and independently observed HTTP are successful. Do not use it as the current acceptance criterion. The new delegated helper and HTTP routes work.
- **No SaaS product shipped.** The runtime runs a synthetic release canary, not a tenant/workspace product. No real-product authentication flow, user interface, persisted business data or customer authorization was accepted.
- **No STAGING/PROD or unrelated app changes.** No independently hosted applications, including Sumlaude/Valoria, were modified.

## 5. Closure and next milestone

Task 014's scope — signed immutable release, actual DEV deployment, blue/green routing and live acceptance — is complete. The next development milestone is integrating **one real SaaS product workflow** using this established mechanism, with the existing owning repository, app identity/session model, tenant/workspace boundaries, data ownership, and deployment rollback reconciled first. Do not replace product implementation with another synthetic canary or governance-only project.
