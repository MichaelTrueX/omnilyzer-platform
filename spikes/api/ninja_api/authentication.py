"""spikes/api/ninja_api/authentication.py: Adapt Ninja requests to the principal.

Related modules: domain.auth and ninja_api.api.
"""
from ninja.security import APIKeyHeader
from domain.auth import AuthenticationRejected, resolve_synthetic_principal


class SyntheticHeaderAuthentication(APIKeyHeader):
    """Describe and validate the synthetic actor header security scheme."""

    param_name = "X-Spike-Actor"

    def authenticate(self, request, key):
        """Return a shared principal only when actor and Workspace context match."""
        try:
            return resolve_synthetic_principal(
                key, request.headers.get("X-Workspace-ID")
            )
        except AuthenticationRejected:
            return None
