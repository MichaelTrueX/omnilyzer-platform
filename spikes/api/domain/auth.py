"""spikes/api/domain/auth.py: Define framework-neutral synthetic request identity.

Related modules: domain.services, drf_api.authentication, and ninja_api.authentication.
The actor-to-Workspace convention is test-only and stores no real token or identity.
"""
from dataclasses import dataclass
import uuid

from domain.exceptions import ValidationFailed


class AuthenticationRejected(Exception):
    """Indicate that synthetic actor authentication failed."""


@dataclass(frozen=True, slots=True)
class RequestPrincipal:
    """Carry the authenticated actor and resolved Workspace context."""

    actor_id: str
    workspace_id: uuid.UUID


def synthetic_actor_id(workspace_id: uuid.UUID) -> str:
    """Return the deterministic synthetic actor identifier for a Workspace."""
    return f"actor:{workspace_id}"


def authenticate_synthetic_actor(actor_value: str | None) -> str:
    """Authenticate only the deterministic synthetic actor credential."""
    if not actor_value or not actor_value.startswith("actor:"):
        raise AuthenticationRejected("Synthetic actor is missing or invalid.")
    try:
        actor_workspace_id = uuid.UUID(actor_value.removeprefix("actor:"))
    except (ValueError, TypeError) as error:
        raise AuthenticationRejected("Synthetic actor is missing or invalid.") from error
    return synthetic_actor_id(actor_workspace_id)


def resolve_workspace_context(workspace_value: str | None) -> uuid.UUID:
    """Resolve explicit Workspace context as validation, not authentication."""
    if not workspace_value:
        raise ValidationFailed({"X-Workspace-ID": ["This header is required."]})
    try:
        return uuid.UUID(workspace_value)
    except (ValueError, TypeError) as error:
        raise ValidationFailed({"X-Workspace-ID": ["Must be a valid UUID."]}) from error


def build_request_principal(
    actor_id: str, workspace_value: str | None
) -> RequestPrincipal:
    """Combine authenticated identity with independently resolved request context."""
    workspace_id = resolve_workspace_context(workspace_value)
    return RequestPrincipal(actor_id=actor_id, workspace_id=workspace_id)
