"""spikes/api/ninja_api/api.py: Expose shared Project services through Ninja.

Related modules: domain.services, ninja_api.schemas, and ninja_api.authentication.
"""
import logging
from typing import Any
import uuid
from django.http import HttpRequest, HttpResponse
from ninja import Header, NinjaAPI, Query, Router
from ninja.errors import AuthenticationError, HttpError, ValidationError
from domain.exceptions import ApplicationError
from domain.services import (
    archive_or_delete_project,
    create_project,
    get_project,
    list_projects,
    update_project,
)
from ninja_api.authentication import SyntheticHeaderAuthentication
from ninja_api.schemas import (
    ErrorEnvelope,
    HealthOut,
    ProjectCreate,
    ProjectOut,
    ProjectPageOut,
    ProjectPatch,
    ProjectStatus,
)

logger = logging.getLogger(__name__)
api = NinjaAPI(
    title="Omnilyzer API Spike - Django Ninja",
    version="1.0.0-spike",
    description="Experimental Ninja contract; not a production API.",
    urls_namespace="api-spike-ninja",
)
projects = Router(auth=SyntheticHeaderAuthentication(), tags=["projects"])

ERROR_RESPONSES = {
    401: ErrorEnvelope,
    404: ErrorEnvelope,
    409: ErrorEnvelope,
    422: ErrorEnvelope,
    500: ErrorEnvelope,
}


def _error(
    code: str, message: str, details: dict[str, Any] | list[Any] | None = None
) -> dict[str, object]:
    """Build the normalized experimental error envelope."""
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        }
    }


@api.exception_handler(ApplicationError)
def application_error_handler(request: HttpRequest, exc: ApplicationError) -> HttpResponse:
    """Map delivery-neutral service failures without exposing implementation details."""
    return api.create_response(
        request,
        _error(exc.code, exc.message, exc.details),
        status=exc.status_code,
    )


@api.exception_handler(ValidationError)
def validation_error_handler(request: HttpRequest, exc: ValidationError) -> HttpResponse:
    """Normalize Ninja/Pydantic validation failures."""
    return api.create_response(
        request,
        _error(
            "validation_error",
            "Request validation failed.",
            exc.errors,
        ),
        status=422,
    )


@api.exception_handler(AuthenticationError)
def authentication_error_handler(
    request: HttpRequest, exc: AuthenticationError
) -> HttpResponse:
    """Normalize missing or invalid synthetic authentication."""
    return api.create_response(
        request,
        _error("authentication_required", "Authentication is required."),
        status=401,
    )


@api.exception_handler(HttpError)
def http_error_handler(request: HttpRequest, exc: HttpError) -> HttpResponse:
    """Normalize malformed request and unsupported HTTP behavior."""
    code = "method_not_allowed" if exc.status_code == 405 else "malformed_request"
    message = (
        "HTTP method is not allowed."
        if exc.status_code == 405
        else "Request body is malformed."
    )
    return api.create_response(request, _error(code, message), status=exc.status_code)


@api.exception_handler(Exception)
def internal_error_handler(request: HttpRequest, exc: Exception) -> HttpResponse:
    """Return a generic 500 while preserving the exception only in server logs."""
    logger.exception("Unhandled Ninja spike API exception", exc_info=exc)
    return api.create_response(
        request,
        _error("internal_error", "An internal error occurred."),
        status=500,
    )


@api.get(
    "/health/",
    response={200: HealthOut},
    auth=None,
    operation_id="ninja_health",
    tags=["health"],
)
def health(request: HttpRequest) -> dict[str, str]:
    """Report only a static healthy status."""
    return {"status": "ok"}


@projects.get(
    "/",
    response={200: ProjectPageOut, **ERROR_RESPONSES},
    operation_id="ninja_list_projects",
)
def project_list(
    request: HttpRequest,
    x_workspace_id: str = Header(..., alias="X-Workspace-ID"),
    status: ProjectStatus | None = None,
    workspace_id: uuid.UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    """Validate filters and return a deterministic Project page."""
    return list_projects(
        principal=request.auth,
        status=status.value if status else None,
        workspace_id=workspace_id,
        page=page,
        page_size=page_size,
    )


@projects.post(
    "/",
    response={201: ProjectOut, **ERROR_RESPONSES},
    operation_id="ninja_create_project",
)
def project_create(
    request: HttpRequest,
    payload: ProjectCreate,
    x_workspace_id: str = Header(..., alias="X-Workspace-ID"),
):
    """Validate input and create a Workspace-scoped Project."""
    values = payload.model_dump(mode="python")
    values["status"] = payload.status.value
    return 201, create_project(principal=request.auth, **values)


@projects.get(
    "/{project_id}/",
    response={200: ProjectOut, **ERROR_RESPONSES},
    operation_id="ninja_retrieve_project",
)
def project_retrieve(
    request: HttpRequest,
    project_id: uuid.UUID,
    x_workspace_id: str = Header(..., alias="X-Workspace-ID"),
):
    """Retrieve a Project without revealing cross-Workspace existence."""
    return get_project(principal=request.auth, project_id=project_id)


@projects.patch(
    "/{project_id}/",
    response={200: ProjectOut, **ERROR_RESPONSES},
    operation_id="ninja_update_project",
)
def project_update(
    request: HttpRequest,
    project_id: uuid.UUID,
    payload: ProjectPatch,
    x_workspace_id: str = Header(..., alias="X-Workspace-ID"),
):
    """Apply a validated non-empty partial update."""
    changes = payload.model_dump(exclude_unset=True, mode="python")
    if "status" in changes:
        changes["status"] = changes["status"].value
    return update_project(
        principal=request.auth, project_id=project_id, changes=changes
    )


@projects.delete(
    "/{project_id}/",
    response={204: None, **ERROR_RESPONSES},
    operation_id="ninja_delete_project",
)
def project_delete(
    request: HttpRequest,
    project_id: uuid.UUID,
    x_workspace_id: str = Header(..., alias="X-Workspace-ID"),
):
    """Delete one authorized Project and return an empty 204 response."""
    archive_or_delete_project(principal=request.auth, project_id=project_id)
    return 204, None


api.add_router("/projects", projects)
