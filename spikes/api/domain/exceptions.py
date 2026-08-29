"""spikes/api/domain/exceptions.py: Define delivery-neutral application errors.

Related modules: domain.services, drf_api.errors, and ninja_api.api.
"""


class ApplicationError(Exception):
    """Base an expected service error with safe client-facing metadata."""

    code = "application_error"
    message = "The request could not be completed."
    status_code = 400

    def __init__(self, details: dict[str, object] | None = None) -> None:
        """Store only explicitly safe structured details."""
        super().__init__(self.message)
        self.details = details or {}


class ValidationFailed(ApplicationError):
    """Indicate invalid service input."""

    code = "validation_error"
    message = "Request validation failed."
    status_code = 422


class ResourceNotFound(ApplicationError):
    """Hide whether a resource exists outside the principal's Workspace."""

    code = "not_found"
    message = "Resource not found."
    status_code = 404


class ConflictDetected(ApplicationError):
    """Indicate a deterministic database uniqueness conflict."""

    code = "conflict"
    message = "A conflicting resource already exists."
    status_code = 409
