"""spikes/api/drf_api/authentication.py: Adapt DRF actor authentication.

Related modules: domain.auth and drf_api.permissions.
"""
from rest_framework import authentication, exceptions
from domain.auth import AuthenticationRejected, authenticate_synthetic_actor


class SyntheticHeaderAuthentication(authentication.BaseAuthentication):
    """Authenticate the actor header without deciding Workspace authorization."""

    def authenticate(self, request):
        """Authenticate every protected request or fail closed."""
        try:
            actor_id = authenticate_synthetic_actor(
                request.headers.get("X-Spike-Actor")
            )
        except AuthenticationRejected as error:
            raise exceptions.AuthenticationFailed(
                "Synthetic authentication failed."
            ) from error
        return actor_id, None

    def authenticate_header(self, request) -> str:
        """Advertise the synthetic scheme so failures correctly use HTTP 401."""
        return "Synthetic"
