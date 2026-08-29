"""spikes/api/domain/auth.py: Define a framework-neutral synthetic principal.

Related modules: domain.services, drf_api.authentication, and ninja_api.authentication.
The actor-to-Workspace convention is test-only and stores no real token or identity.
"""
from dataclasses import dataclass
import uuid


class AuthenticationRejected(Exception):
    """Indicate that synthetic authentication or context resolution failed."""


@dataclass(frozen=True, slots=True)
class RequestPrincipal:
    """Carry the authenticated actor and resolved Workspace context."""

    actor_id: str
    workspace_id: uuid.UUID


def synthetic_actor_id(workspace_id: uuid.UUID) -> str:
    """Return the deterministic synthetic actor identifier for a Workspace."""
    return f"actor:{workspace_id}"


def resolve_synthetic_principal(
    actor_id: str | None, workspace_value: str | None
) -> RequestPrincipal:
    """Authenticate an actor and bind a matching explicit Workspace context.

    A later BFF session or bearer-token adapter can replace this resolver while keeping
    the principal and service authorization boundary unchanged.
    """
    if not actor_id or not workspace_value:
        raise AuthenticationRejected("Synthetic actor and Workspace headers are required.")
    try:
        workspace_id = uuid.UUID(workspace_value)
    except (ValueError, TypeError) as error:
        raise AuthenticationRejected("Workspace context is malformed.") from error
    if actor_id != synthetic_actor_id(workspace_id):
        raise AuthenticationRejected("Actor is not authorized for this Workspace.")
    return RequestPrincipal(actor_id=actor_id, workspace_id=workspace_id)
