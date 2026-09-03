# Task 008D zot deployment design

This directory contains the production-shaped Task 008D design for zot `v2.1.20`. The reviewed Linux/amd64 container alternative is `ghcr.io/project-zot/zot:v2.1.20@sha256:95a837a0afacf5b7edc0c92493f04beee6891989b8d2fd50a00cf65a1e6d4fd5`; the preferred dev-server installation is the verified single binary so the release registry does not depend on another registry at runtime.

`install-zot.sh` pins the release and the GitHub release API's SHA-256 for `checksums.sha256.txt` (`a9fe260d8259084d884f2135f33a6f63ce898665e2c1115b76c871a196df6653`). It verifies that manifest first, then verifies `zot-linux-amd64` using the verified official manifest, and installs only afterward. Review the release and script again before any server use.

The intended topology is HTTPS at `oci-dev.omnilyzer.ai`, transparent Nginx proxying, and zot bound only to `127.0.0.1:5000`. Host firewall policy must also prevent access to port 5000. The Nginx example deliberately blocks neither PUT nor DELETE: Task 008D measures zot's native authorization.

The zot configuration validates GitHub's exact OIDC issuer and audience, requires the exact repository owner and repository, and maps the exact `workflow_ref` to the zot username. These are ordinary workflows, so their workflow path and triggering ref are bound with `workflow_ref`. The publisher has exactly `read` and `create`; the consumer has exactly `read`; unknown and anonymous identities have no authority. The two permitted workflow-ref strings are branch-specific exact values and contain no wildcard.

Garbage collection is explicitly disabled. Current zot GC can remove untagged manifests; disabling it isolates authorization and immutability from cleanup and preserves historical digest rollback material. Storage growth is accepted for this spike. Capacity and lifecycle policy require a separate decision after correctness is demonstrated.

Publisher v1 run `33814063124` passed the gate, fixture build, GitHub OIDC acquisition, and authoritative direct Distribution API security probe. The separate Docker compatibility step failed because zot advertised the relative Bearer realm `zot`; Docker treats `realm` as the token-service URL and rejected it as an unsupported empty URL scheme. The example was corrected to advertise zot's OIDC registry token service at the absolute same-origin HTTPS URL `https://oci-dev.omnilyzer.ai/zot/auth/token`. This was an interoperability/configuration failure, not an immutability failure; this failed evidence remains recorded even though the subsequent run passed.

**TASK 008D — PASS.** Publisher v2 run `33814874276`, from commit `25cc080f2298d48830ed480b54735ff28245b485`, passed GitHub OIDC, the authoritative direct OCI probe, and standard Docker/OIDC interoperability. The publisher created and read the baseline; zot denied same-tag update, DELETE by digest, and DELETE by tag with exact HTTP 403 responses; and the original manifest, config, and layer remained unchanged and retrievable.

The retained baseline is:

- tag `task008d-33814874276-1`;
- manifest `sha256:869121fdf10de171eff2f2622fa4190939573abc1e5bb24e7502b8757d4f6059`;
- config `sha256:8ac6c44b9181a6d92469b5b701417f9ab13c5f0b8c462ffd68a7f4d098e9614d`;
- layer `sha256:6747a1b2afcb45cb4e398e8f08158b305575e98f78fefee20c14e415dccfc89b`.

The publisher completed at approximately 22:50:43 UTC. systemd stopped and successfully restarted `zot.service` at 22:51:39 UTC. Consumer run `33815051427`, from commit `3284aa442310c172149efe76406fa9fa3a1f5630`, started at 22:52:16 UTC and independently authenticated with its read-only GitHub OIDC identity. It verified the retained tag, manifest, config, and layer and passed Docker pulls by both tag and exact digest. Restart persistence, independent read-only retrieval, and exact-digest rollback readiness therefore pass for the tested restart with `gc=false`. This is not a claim of indefinite retention.

For deployment or redeployment, create the `zot` system account and `/etc/zot`, `/var/lib/zot`, and `/var/log/zot` with minimal ownership, install the reviewed config and unit, validate with `zot verify /etc/zot/config.json`, and install TLS/Nginx separately. Do not place secrets in this configuration.

## Live validation lifecycle

1. The implementation commit added both trigger paths and classified as `none`, so privileged jobs skipped.
2. The reviewed publisher trigger modification ran the publisher validation and recorded the baseline tag and digests.
3. The exact values were placed in a consumer-trigger-only modification.
4. zot was manually restarted and its successful systemd stop/start was observed.
5. The read-only consumer workflow verified tag, digest, config, layer, and Docker exact-digest pulls after restart.

All Task 008D acceptance rows pass. Production retention and lifecycle policy, backup/restore validation, capacity, monitoring, and disaster recovery remain separate operational decisions.
