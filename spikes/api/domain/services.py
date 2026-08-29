"""spikes/api/domain/services.py: Implement shared Project application operations.

Related modules: domain.models, domain.auth, drf_api.views, and ninja_api.api.
Every Workspace-scoped lookup filters by the resolved principal before returning data.
This is application-layer simulation, not proof of database-enforced tenancy.
"""
from dataclasses import dataclass
from typing import Any
import uuid
from django.db import IntegrityError, transaction
from django.db.models import QuerySet
from domain.auth import RequestPrincipal
from domain.exceptions import ConflictDetected, ResourceNotFound, ValidationFailed
from domain.models import Project, Workspace


@dataclass(frozen=True, slots=True)
class ProjectPage:
    """Carry deterministic pagination results without framework-specific types."""

    items: list[Project]
    page: int
    page_size: int
    total: int


def _authorized_workspace(
    principal: RequestPrincipal, workspace_id: uuid.UUID
) -> Workspace:
    """Return an in-scope Workspace or the same opaque not-found error."""
    if workspace_id != principal.workspace_id:
        raise ResourceNotFound()
    try:
        return Workspace.objects.get(id=principal.workspace_id)
    except Workspace.DoesNotExist as error:
        raise ResourceNotFound() from error


def _authorized_projects(principal: RequestPrincipal) -> QuerySet[Project]:
    """Build the mandatory Workspace-scoped Project query."""
    return Project.objects.filter(workspace_id=principal.workspace_id)


def create_project(
    *,
    principal: RequestPrincipal,
    workspace_id: uuid.UUID,
    name: str,
    description: str = "",
    status: str = Project.Status.ACTIVE,
) -> Project:
    """Create a Project after resolving and authorizing its Workspace."""
    workspace = _authorized_workspace(principal, workspace_id)
    try:
        with transaction.atomic():
            return Project.objects.create(
                workspace=workspace,
                name=name,
                description=description,
                status=status,
            )
    except IntegrityError as error:
        raise ConflictDetected({"name": ["Must be unique within the Workspace."]}) from error


def get_project(*, principal: RequestPrincipal, project_id: uuid.UUID) -> Project:
    """Retrieve only a Project inside the principal's Workspace."""
    try:
        return _authorized_projects(principal).get(id=project_id)
    except Project.DoesNotExist as error:
        raise ResourceNotFound() from error


def list_projects(
    *,
    principal: RequestPrincipal,
    status: str | None,
    workspace_id: uuid.UUID | None,
    page: int,
    page_size: int,
) -> ProjectPage:
    """List safely filtered Projects using stable offset pagination."""
    if workspace_id is not None:
        _authorized_workspace(principal, workspace_id)
    if page < 1 or page_size < 1 or page_size > 100:
        raise ValidationFailed({
            "pagination": ["page must be >= 1 and page_size must be 1..100."]
        })
    projects = _authorized_projects(principal)
    if status is not None:
        projects = projects.filter(status=status)
    total = projects.count()
    start = (page - 1) * page_size
    return ProjectPage(
        items=list(projects[start : start + page_size]),
        page=page,
        page_size=page_size,
        total=total,
    )


def update_project(
    *,
    principal: RequestPrincipal,
    project_id: uuid.UUID,
    changes: dict[str, Any],
) -> Project:
    """Partially update explicitly allowed fields on an authorized Project."""
    if not changes:
        raise ValidationFailed({"body": ["At least one field is required."]})
    project = get_project(principal=principal, project_id=project_id)
    for field in ("name", "description", "status"):
        if field in changes:
            setattr(project, field, changes[field])
    try:
        with transaction.atomic():
            project.save(update_fields=[*changes.keys(), "updated_at"])
    except IntegrityError as error:
        raise ConflictDetected({"name": ["Must be unique within the Workspace."]}) from error
    return project


def archive_or_delete_project(
    *, principal: RequestPrincipal, project_id: uuid.UUID
) -> None:
    """Delete an authorized Project; both adapters expose identical semantics."""
    project = get_project(principal=principal, project_id=project_id)
    project.delete()


def create_workspace_with_first_project(
    *,
    workspace_name: str,
    workspace_type: str,
    project_name: str,
) -> tuple[Workspace, Project]:
    """Atomically create a Workspace and its first Project.

    A database constraint failure on either insert rolls back both records, providing a
    genuine transaction boundary independent of either API adapter.
    """
    if workspace_type not in Workspace.WorkspaceType.values:
        raise ValidationFailed({
            "workspace_type": ["Must be personal or organization."]
        })
    try:
        with transaction.atomic():
            workspace = Workspace.objects.create(
                name=workspace_name, workspace_type=workspace_type
            )
            project = Project.objects.create(
                workspace=workspace,
                name=project_name,
                description="Created in the transaction validation operation.",
            )
            return workspace, project
    except IntegrityError as error:
        raise ValidationFailed({
            "transaction": ["Workspace and first Project were rolled back."]
        }) from error
