"""spikes/api/domain/models.py: Define shared synthetic Workspace and Project data.

Related modules: domain.services, domain.admin, and domain.migrations.
These deliberately small models are evidence only, not the final tenancy model.
"""
import uuid
from django.db import models
from django.db.models import Q


class Workspace(models.Model):
    """Represent the simplified tenant boundary used only by Task 002."""

    class WorkspaceType(models.TextChoices):
        """Enumerate the only Workspace types accepted by this spike."""

        PERSONAL = "personal", "Personal"
        ORGANIZATION = "organization", "Organization"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    workspace_type = models.CharField(max_length=20, choices=WorkspaceType)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Declare deterministic ordering and representative integrity constraints."""

        ordering = ["created_at", "id"]
        constraints = [
            models.CheckConstraint(
                condition=~Q(name=""), name="workspace_name_not_empty"
            ),
            models.UniqueConstraint(
                fields=["workspace_type", "name"],
                name="workspace_type_name_unique",
            ),
            models.CheckConstraint(
                condition=Q(workspace_type__in=["personal", "organization"]),
                name="workspace_type_valid",
            ),
        ]

    def __str__(self) -> str:
        """Return a safe administrative label."""
        return self.name


class Project(models.Model):
    """Represent a Workspace-scoped synthetic project."""

    class Status(models.TextChoices):
        """Enumerate project lifecycle states used in the comparison."""

        ACTIVE = "active", "Active"
        ARCHIVED = "archived", "Archived"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workspace = models.ForeignKey(
        Workspace, on_delete=models.CASCADE, related_name="projects"
    )
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True, max_length=2_000)
    status = models.CharField(max_length=20, choices=Status, default=Status.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Declare scoped uniqueness, checks, indexes, and deterministic ordering."""

        ordering = ["created_at", "id"]
        constraints = [
            models.CheckConstraint(
                condition=~Q(name=""), name="project_name_not_empty"
            ),
            models.UniqueConstraint(
                fields=["workspace", "name"], name="project_workspace_name_unique"
            ),
            models.CheckConstraint(
                condition=Q(status__in=["active", "archived"]),
                name="project_status_valid",
            ),
        ]
        indexes = [
            models.Index(
                fields=["workspace", "status", "created_at"],
                name="project_ws_status_created_idx",
            )
        ]

    def __str__(self) -> str:
        """Return a safe administrative label."""
        return self.name
