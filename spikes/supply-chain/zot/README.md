# Task 008D zot deployment design

This directory is an unexecuted, production-shaped design for zot `v2.1.20`. It does not represent a deployment. The reviewed Linux/amd64 container alternative is `ghcr.io/project-zot/zot:v2.1.20@sha256:95a837a0afacf5b7edc0c92493f04beee6891989b8d2fd50a00cf65a1e6d4fd5`; the preferred dev-server installation is the verified single binary so the release registry does not depend on another registry at runtime.

`install-zot.sh` pins the release and the GitHub release API's SHA-256 for `checksums.sha256.txt` (`a9fe260d8259084d884f2135f33a6f63ce898665e2c1115b76c871a196df6653`). It verifies that manifest first, then verifies `zot-linux-amd64` using the verified official manifest, and installs only afterward. Review the release and script again before any server use.

The intended topology is HTTPS at `oci-dev.omnilyzer.ai`, transparent Nginx proxying, and zot bound only to `127.0.0.1:5000`. Host firewall policy must also prevent access to port 5000. The Nginx example deliberately blocks neither PUT nor DELETE: Task 008D measures zot's native authorization.

The zot configuration validates GitHub's exact OIDC issuer and audience, requires the exact repository owner and repository, and maps the exact `workflow_ref` to the zot username. These are ordinary workflows, so their workflow path and triggering ref are bound with `workflow_ref`. The publisher has exactly `read` and `create`; the consumer has exactly `read`; unknown and anonymous identities have no authority. The two permitted workflow-ref strings are branch-specific exact values and contain no wildcard.

Garbage collection is explicitly disabled. Current zot GC can remove untagged manifests; disabling it isolates authorization and immutability from cleanup and preserves historical digest rollback material. Storage growth is accepted for this spike. Capacity and lifecycle policy require a separate decision after correctness is demonstrated.

Before a future deployment, create the `zot` system account and `/etc/zot`, `/var/lib/zot`, and `/var/log/zot` with minimal ownership, install the reviewed config and unit, validate with `zot verify /etc/zot/config.json`, and install TLS/Nginx separately. Do not place secrets in this configuration.

## Live validation lifecycle

1. Push the implementation commit: both newly added trigger paths classify as `none`, so privileged jobs skip.
2. Review configuration, workflow, fixture, and probe locally.
3. Modify only `zot-publish.trigger` in a separate authorized commit. Record the published baseline tag and all digests from the summary.
4. Put those exact values into a trigger-only `zot-consume.trigger` modification.
5. Manually restart zot with `sudo systemctl restart zot` and inspect `sudo systemctl status zot --no-pager`.
6. Run only the read-only consumer workflow and require tag, digest, config, layer, and Docker exact-digest pulls to survive.

Restart persistence and exact-digest rollback remain **PENDING** until those live steps succeed.
