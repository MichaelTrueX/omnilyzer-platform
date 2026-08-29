import uuid

from django.db import models


class Workspace(models.Model):
    class WorkspaceType(models.TextChoices):
        PERSONAL = "personal", "Personal"
        ORGANIZATION = "organization", "Organization"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    workspace_type = models.CharField(max_length=20, choices=WorkspaceType)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Project(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        ARCHIVED = "archived", "Archived"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status, default=Status.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("workspace", "name"), name="tenancy_project_workspace_name_uniq"
            )
        ]
        indexes = [
            models.Index(
                fields=("workspace", "status"), name="tenancy_project_ws_status_idx"
            )
        ]
