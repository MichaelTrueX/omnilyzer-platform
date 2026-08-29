"""spikes/api/drf_api/authentication.py: Adapt DRF requests to the shared principal.

Related modules: domain.auth and drf_api.views.
"""
from rest_framework import authentication, exceptions
from domain.auth import AuthenticationRejected, resolve_synthetic_principal


class SyntheticHeaderAuthentication(authentication.BaseAuthentication):
    """Resolve the two explicit spike headers into a shared principal."""

    def authenticate(self, request):
        """Authenticate every protected request or fail closed."""
        try:
            principal = resolve_synthetic_principal(
                request.headers.get("X-Spike-Actor"),
                request.headers.get("X-Workspace-ID"),
            )
        except AuthenticationRejected as error:
            raise exceptions.AuthenticationFailed(
                "Synthetic authentication failed."
            ) from error
        return principal, None

    def authenticate_header(self, request) -> str:
        """Advertise the synthetic scheme so failures correctly use HTTP 401."""
        return "Synthetic"
