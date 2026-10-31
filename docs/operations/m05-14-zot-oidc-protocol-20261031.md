<!--
File: docs/operations/m05-14-zot-oidc-protocol-20261031.md
Purpose: Document the exact installed Zot OIDC protocol and avoid false exchange assumptions.
Related: deployment/private_registry_pull.py, deployment/release_consumer.py,
         release/analytics_task014_readonly_probe.py, task014-registry-stream-deadline.md.
Authority: Read-only protocol evidence, no authentication or deployment grant.
-->

# Zot OIDC protocol at the installed2.1.20 revision

The verified live binary is project-zot/zot commit3b5796d. Its
[pkg/api/token_exchange.go](https://github.com/project-zot/zot/blob/3b5796d/pkg/api/token_exchange.go)
returns the supplied OIDC token unchanged in both token/access_token, with
expires_in derived from that token's original exp. This corrects the earlier
assumption that this endpoint necessarily mints a separate scoped Bearer.

Docker answers the fixed registry challenge using the existing private0600
Basic oidc credential configuration and then uses the returned token. The
installed current HTTP evidence reader sends its verified OIDC token directly
as Bearer. Live signed requests have passed that evidence stage. Registry
repository permission is still independently necessary; authentication alone
does not grant Analytics read access.

Do not reintroduce the historical helper that rejected registry_token==token.
Do not assume token exchange extends the300s GitHub/FD lifetime. Verify the
actual deployed source and upstream version before changing either reader.

The existing platform-promote.yml auth_probe=true, product_id=analytics path
checks authenticated manifest/evidence and signatures without deployment.
Its success is not proof that all image layers can stream completely or that
an uncached image pull fits the runtime deadlines.

For the31 October truncated-layer failure, configuration/digest/proxy evidence,
native reproduction and the bounded completion policy, see
[registry streaming and deadlines](task014-registry-stream-deadline.md).
