"""spikes/api/drf_api/permissions.py: Enforce the synthetic principal in DRF.

Related modules: domain.auth, drf_api.authentication, and drf_api.views.
"""
from rest_framework.permissions import BasePermission
from domain.auth import RequestPrincipal


class HasSyntheticPrincipal(BasePermission):
    """Require the framework-neutral principal installed by authentication."""

    message = "Authentication is required."

    def has_permission(self, request, view) -> bool:
        """Deny access when no valid synthetic principal was resolved."""
        return isinstance(request.user, RequestPrincipal)
