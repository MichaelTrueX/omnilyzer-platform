"""spikes/api/drf_api/permissions.py: Resolve Workspace context for DRF.

Related modules: domain.auth, drf_api.authentication, and drf_api.views.
"""
from rest_framework import exceptions
from rest_framework.permissions import BasePermission
from domain.auth import build_request_principal
from domain.exceptions import ValidationFailed


class HasSyntheticPrincipal(BasePermission):
    """Build a principal from authenticated identity and validated context."""

    message = "Authentication is required."

    def has_permission(self, request, view) -> bool:
        """Validate Workspace context independently after actor authentication."""
        if not isinstance(request.user, str):
            return False
        try:
            request.user = build_request_principal(
                request.user, request.headers.get("X-Workspace-ID")
            )
        except ValidationFailed as error:
            raise exceptions.ValidationError(error.details) from error
        return True
