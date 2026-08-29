#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPIKE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNTIME_ENV="/tmp/omnilyzer-auth-spike-runtime.env"
CONTAINER="omnilyzer-auth-spike-keycloak"

if [[ ! -f "$RUNTIME_ENV" ]]; then
    umask 077
    {
        echo "KC_BOOTSTRAP_ADMIN_USERNAME=auth-spike-admin"
        echo "KC_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 32)"
        echo "OMNILYZER_BFF_SECRET=$(openssl rand -hex 32)"
        echo "OMNILYZER_TEST_PASSWORD=$(openssl rand -hex 32)"
    } > "$RUNTIME_ENV"
    chmod 0600 "$RUNTIME_ENV"
fi

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" \
    --env-file "$RUNTIME_ENV" \
    -e KC_HOSTNAME=http://127.0.0.1:18080 \
    -p 127.0.0.1:18080:8080 \
    -v "$SPIKE_DIR/keycloak:/opt/keycloak/data/import:ro" \
    quay.io/keycloak/keycloak:26.7.2 \
    start-dev --import-realm >/dev/null

discovery="http://127.0.0.1:18080/realms/omnilyzer-auth-spike/.well-known/openid-configuration"
for _attempt in $(seq 1 90); do
    if curl --fail --silent --show-error "$discovery" >/dev/null 2>&1; then
        echo "Keycloak 26.7.2 discovery is ready on 127.0.0.1:18080."
        exit 0
    fi
    if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -qx true; then
        echo "Keycloak container stopped before discovery became ready." >&2
        docker logs --tail 80 "$CONTAINER" >&2
        exit 1
    fi
    sleep 1
done
echo "Timed out waiting for Keycloak OIDC discovery." >&2
docker logs --tail 80 "$CONTAINER" >&2
exit 1
