"""spikes/api/tests/test_platform_capabilities.py: Validate shared Django evidence.

Related modules: domain.services, domain.admin, and scripts.generate_openapi.
"""
from django.contrib import admin
from django.db import IntegrityError, connection, transaction
from django.test import TestCase, TransactionTestCase
from drf_spectacular.generators import SchemaGenerator
from domain.exceptions import ValidationFailed
from domain.models import Project, Workspace
from domain.services import create_workspace_with_first_project
from ninja_api.api import api as ninja_api


class TransactionTests(TransactionTestCase):
    """Exercise genuine PostgreSQL commit and rollback behavior."""

    def test_workspace_and_first_project_commit_together(self) -> None:
        """Persist both records on a valid atomic workflow."""
        workspace, project = create_workspace_with_first_project(
            workspace_name="Atomic success",
            workspace_type="organization",
            project_name="First Project",
        )
        self.assertTrue(Workspace.objects.filter(id=workspace.id).exists())
        self.assertTrue(Project.objects.filter(id=project.id).exists())

    def test_workspace_rolls_back_when_project_constraint_fails(self) -> None:
        """Leave no Workspace row after the second insert violates a DB check."""
        with self.assertRaises(ValidationFailed):
            create_workspace_with_first_project(
                workspace_name="Atomic rollback",
                workspace_type="organization",
                project_name="",
            )
        self.assertFalse(
            Workspace.objects.filter(name="Atomic rollback").exists()
        )

    def test_invalid_workspace_type_is_rejected(self) -> None:
        """Reject Workspace types outside the deliberately small shared domain."""
        with self.assertRaises(ValidationFailed):
            create_workspace_with_first_project(
                workspace_name="Invalid type",
                workspace_type="invented",
                project_name="Never created",
            )
        self.assertFalse(Workspace.objects.filter(name="Invalid type").exists())

    def test_database_enum_constraints_reject_invalid_values(self) -> None:
        """Enforce allowed Workspace and Project values beneath API validation."""
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Workspace.objects.create(
                    name="DB invalid Workspace",
                    workspace_type="invented",
                )
        workspace = Workspace.objects.create(
            name="DB constraint Workspace",
            workspace_type=Workspace.WorkspaceType.ORGANIZATION,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Project.objects.create(
                    workspace=workspace,
                    name="DB invalid Project",
                    status="invented",
                )


class DjangoCapabilityTests(TestCase):
    """Check admin integration, database backend, and generated schemas."""

    def test_admin_registers_both_shared_models(self) -> None:
        """Make Workspace and Project available for internal operational inspection."""
        self.assertIn(Workspace, admin.site._registry)
        self.assertIn(Project, admin.site._registry)

    def test_postgresql_is_the_validation_backend(self) -> None:
        """Prevent accidental SQLite evidence in the primary validation run."""
        self.assertEqual(connection.vendor, "postgresql")

    def test_generated_openapi_contains_major_routes(self) -> None:
        """Generate both schemas from implementation and require all major paths."""
        drf_schema = SchemaGenerator().get_schema(request=None, public=True)
        ninja_schema = ninja_api.get_openapi_schema(path_prefix="/api/v1/ninja")
        expected_drf = {
            "/api/v1/drf/health/",
            "/api/v1/drf/projects/",
            "/api/v1/drf/projects/{project_id}/",
        }
        expected_ninja = {
            "/api/v1/ninja/health/",
            "/api/v1/ninja/projects/",
            "/api/v1/ninja/projects/{project_id}/",
        }
        self.assertTrue(expected_drf <= set(drf_schema["paths"]))
        self.assertTrue(expected_ninja <= set(ninja_schema["paths"]))
        self.assertEqual(drf_schema["openapi"], "3.0.3")
        self.assertTrue(ninja_schema["openapi"].startswith("3.1."))
