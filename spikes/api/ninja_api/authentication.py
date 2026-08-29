"""spikes/api/ninja_api/authentication.py: Adapt Ninja actor authentication.

Related modules: domain.auth and ninja_api.api.
"""
from ninja.security import APIKeyHeader
from domain.auth import AuthenticationRejected, authenticate_synthetic_actor


class SyntheticHeaderAuthentication(APIKeyHeader):
    """Describe and authenticate the synthetic actor header only."""

    param_name = "X-Spike-Actor"

    def authenticate(self, request, key):
        """Return an actor identity without deciding Workspace authorization."""
        try:
            return authenticate_synthetic_actor(key)
        except AuthenticationRejected:
            return None
