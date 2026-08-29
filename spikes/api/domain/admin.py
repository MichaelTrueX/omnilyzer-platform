"""spikes/api/domain/admin.py: Register spike records with Django admin.

Related modules: domain.models and config.urls.
The intentionally minimal configuration tests operational inspection, not end-user UX.
"""
from django.contrib import admin
from domain.models import Project, Workspace


@admin.register(Workspace)
class WorkspaceAdmin(admin.ModelAdmin):
    """Expose safe, basic Workspace inspection."""

    list_display = ("id", "name", "workspace_type", "created_at")
    list_filter = ("workspace_type",)
    search_fields = ("name",)


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    """Expose safe, basic Workspace-scoped Project inspection."""

    list_display = ("id", "name", "workspace", "status", "created_at")
    list_filter = ("status",)
    search_fields = ("name", "workspace__name")
    raw_id_fields = ("workspace",)
