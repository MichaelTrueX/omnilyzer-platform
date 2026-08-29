"""spikes/api/tests/test_api_contracts.py: Compare equivalent API behavior.

Related modules: drf_api.views, ninja_api.api, domain.services, and config.middleware.
All records and principals are synthetic.
"""
from unittest.mock import patch
import json
import uuid
from django.test import Client, TestCase, override_settings
from domain.auth import synthetic_actor_id
from domain.models import Project, Workspace


class ApiContractMixin:
    """Run one behavioral contract against a framework-specific URL prefix."""

    prefix: str
    internal_patch_target: str

    def setUp(self) -> None:
        """Create two isolated synthetic Workspaces and one foreign Project."""
        self.workspace_a = Workspace.objects.create(
            name=f"{self.prefix} Workspace A",
            workspace_type=Workspace.WorkspaceType.ORGANIZATION,
        )
        self.workspace_b = Workspace.objects.create(
            name=f"{self.prefix} Workspace B",
            workspace_type=Workspace.WorkspaceType.PERSONAL,
        )
        self.foreign_project = Project.objects.create(
            workspace=self.workspace_b, name="Foreign Project"
        )
        self.client = Client(raise_request_exception=False)
        self.counter = 0

    def headers(self, workspace: Workspace | None = None) -> dict[str, str]:
        """Build valid synthetic authentication and Workspace context headers."""
        selected = workspace or self.workspace_a
        return {
            "HTTP_X_SPIKE_ACTOR": synthetic_actor_id(selected.id),
            "HTTP_X_WORKSPACE_ID": str(selected.id),
        }

    def json_request(
        self, method: str, path: str, payload: object, **headers: str
    ):
        """Issue a JSON request through Django's in-process client."""
        return getattr(self.client, method)(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def create_project(self, name: str | None = None, **changes: object):
        """Create a Project through the selected API and assert success."""
        self.counter += 1
        payload = {
            "workspace_id": str(self.workspace_a.id),
            "name": name or f"Project {self.counter}",
            "description": "Synthetic description",
            "status": "active",
            **changes,
        }
        response = self.json_request(
            "post", f"{self.prefix}/projects/", payload, **self.headers()
        )
        self.assertEqual(response.status_code, 201, response.content)
        return response.json()

    def assert_error(self, response, status: int, code: str) -> dict[str, object]:
        """Assert the normalized, non-leaking experimental error envelope."""
        self.assertEqual(response.status_code, status, response.content)
        body = response.json()
        self.assertEqual(set(body), {"error"})
        self.assertEqual(body["error"]["code"], code)
        self.assertEqual(
            set(body["error"]), {"code", "message", "details"}
        )
        return body

    def test_crud_contract(self) -> None:
        """Create, list, retrieve, update, and delete with equivalent semantics."""
        created = self.create_project("CRUD Project")
        project_id = created["id"]

        listed = self.client.get(
            f"{self.prefix}/projects/", **self.headers()
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()["total"], 1)
        self.assertEqual(listed.json()["items"][0]["id"], project_id)

        retrieved = self.client.get(
            f"{self.prefix}/projects/{project_id}/", **self.headers()
        )
        self.assertEqual(retrieved.status_code, 200)
        self.assertEqual(retrieved.json()["name"], "CRUD Project")

        updated = self.json_request(
            "patch",
            f"{self.prefix}/projects/{project_id}/",
            {"description": "Updated", "status": "archived"},
            **self.headers(),
        )
        self.assertEqual(updated.status_code, 200, updated.content)
        self.assertEqual(updated.json()["status"], "archived")

        deleted = self.client.delete(
            f"{self.prefix}/projects/{project_id}/", **self.headers()
        )
        self.assertEqual(deleted.status_code, 204, deleted.content)
        self.assertFalse(Project.objects.filter(id=project_id).exists())

    def test_validation_matrix(self) -> None:
        """Reject missing, invalid, overlong, unexpected, and unrelated input."""
        cases = [
            ({}, 422),
            ({
                "workspace_id": str(self.workspace_a.id),
                "name": "Bad status",
                "status": "invented",
            }, 422),
            ({
                "workspace_id": str(self.workspace_a.id),
                "name": "x" * 121,
            }, 422),
            ({
                "workspace_id": str(self.workspace_a.id),
                "name": "Mass assignment",
                "unexpected": True,
            }, 422),
            ({
                "workspace_id": str(self.workspace_b.id),
                "name": "Wrong relationship",
            }, 404),
        ]
        for payload, expected_status in cases:
            with self.subTest(payload=payload):
                response = self.json_request(
                    "post",
                    f"{self.prefix}/projects/",
                    payload,
                    **self.headers(),
                )
                expected_code = (
                    "not_found" if expected_status == 404 else "validation_error"
                )
                self.assert_error(response, expected_status, expected_code)

        malformed = self.client.get(
            f"{self.prefix}/projects/not-a-uuid/", **self.headers()
        )
        self.assert_error(malformed, 422, "validation_error")

        missing = self.client.get(
            f"{self.prefix}/projects/{uuid.uuid4()}/", **self.headers()
        )
        self.assert_error(missing, 404, "not_found")

        project = self.create_project("Empty Patch")
        empty_patch = self.json_request(
            "patch",
            f"{self.prefix}/projects/{project['id']}/",
            {},
            **self.headers(),
        )
        self.assert_error(empty_patch, 422, "validation_error")
        null_patch = self.json_request(
            "patch",
            f"{self.prefix}/projects/{project['id']}/",
            {"name": None},
            **self.headers(),
        )
        self.assert_error(null_patch, 422, "validation_error")

    def test_unknown_workspace_is_opaque(self) -> None:
        """Return not-found when an authenticated context has no Workspace row."""
        unknown_id = uuid.uuid4()
        headers = {
            "HTTP_X_SPIKE_ACTOR": synthetic_actor_id(unknown_id),
            "HTTP_X_WORKSPACE_ID": str(unknown_id),
        }
        response = self.json_request(
            "post",
            f"{self.prefix}/projects/",
            {"workspace_id": str(unknown_id), "name": "Unknown Workspace"},
            **headers,
        )
        self.assert_error(response, 404, "not_found")

    def test_cross_workspace_identifier_guessing_is_denied(self) -> None:
        """Deny read, update, and delete against a foreign Project identifier."""
        detail = f"{self.prefix}/projects/{self.foreign_project.id}/"
        read = self.client.get(detail, **self.headers())
        update = self.json_request(
            "patch", detail, {"name": "Stolen"}, **self.headers()
        )
        delete = self.client.delete(detail, **self.headers())
        for response in (read, update, delete):
            self.assert_error(response, 404, "not_found")
        self.foreign_project.refresh_from_db()
        self.assertEqual(self.foreign_project.name, "Foreign Project")

    def test_filtering_and_pagination_are_stable(self) -> None:
        """Apply status/Workspace filters and deterministic page boundaries."""
        for index in range(5):
            Project.objects.create(
                workspace=self.workspace_a,
                name=f"Page Project {index}",
                status="active" if index % 2 == 0 else "archived",
            )
        first = self.client.get(
            f"{self.prefix}/projects/?page=1&page_size=2", **self.headers()
        )
        second = self.client.get(
            f"{self.prefix}/projects/?page=2&page_size=2", **self.headers()
        )
        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(second.status_code, 200, second.content)
        self.assertEqual(first.json()["total"], 5)
        first_ids = {item["id"] for item in first.json()["items"]}
        second_ids = {item["id"] for item in second.json()["items"]}
        self.assertFalse(first_ids & second_ids)

        filtered = self.client.get(
            f"{self.prefix}/projects/?status=archived"
            f"&workspace_id={self.workspace_a.id}",
            **self.headers(),
        )
        self.assertEqual(filtered.status_code, 200, filtered.content)
        self.assertEqual(filtered.json()["total"], 2)
        self.assertTrue(
            all(item["status"] == "archived" for item in filtered.json()["items"])
        )

        foreign_filter = self.client.get(
            f"{self.prefix}/projects/?workspace_id={self.workspace_b.id}",
            **self.headers(),
        )
        self.assert_error(foreign_filter, 404, "not_found")

    def test_conflict_and_sql_style_input(self) -> None:
        """Normalize uniqueness conflicts and pass hostile strings safely via ORM."""
        self.create_project("Duplicate")
        duplicate = self.json_request(
            "post",
            f"{self.prefix}/projects/",
            {
                "workspace_id": str(self.workspace_a.id),
                "name": "Duplicate",
            },
            **self.headers(),
        )
        self.assert_error(duplicate, 409, "conflict")

        hostile_name = "x' OR 1=1 --"
        hostile = self.create_project(hostile_name)
        response = self.client.get(
            f"{self.prefix}/projects/{hostile['id']}/", **self.headers()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], hostile_name)
        self.assertEqual(
            Project.objects.filter(workspace=self.workspace_a).count(), 2
        )
        self.assertTrue(Project.objects.filter(workspace=self.workspace_b).exists())

    def test_missing_actor_is_authentication_failure(self) -> None:
        """Return 401 when the actor credential is absent."""
        response = self.client.get(
            f"{self.prefix}/projects/",
            HTTP_X_WORKSPACE_ID=str(self.workspace_a.id),
        )
        self.assert_error(response, 401, "authentication_required")

    def test_invalid_actor_is_authentication_failure(self) -> None:
        """Return 401 when the synthetic actor credential is malformed."""
        response = self.client.get(
            f"{self.prefix}/projects/",
            HTTP_X_SPIKE_ACTOR="actor:not-a-uuid",
            HTTP_X_WORKSPACE_ID=str(self.workspace_a.id),
        )
        self.assert_error(response, 401, "authentication_required")

    def test_workspace_context_is_validated_after_authentication(self) -> None:
        """Normalize missing and malformed Workspace context as validation errors."""
        actor_header = {
            "HTTP_X_SPIKE_ACTOR": synthetic_actor_id(self.workspace_a.id)
        }
        missing = self.client.get(f"{self.prefix}/projects/", **actor_header)
        malformed = self.client.get(
            f"{self.prefix}/projects/",
            HTTP_X_WORKSPACE_ID="not-a-uuid",
            **actor_header,
        )
        for response in (missing, malformed):
            self.assert_error(response, 422, "validation_error")

    def test_authorized_actor_and_workspace_succeed(self) -> None:
        """Allow an authenticated actor in its synthetic authorized Workspace."""
        response = self.client.get(f"{self.prefix}/projects/", **self.headers())
        self.assertEqual(response.status_code, 200, response.content)

    def test_authenticated_actor_is_denied_in_another_workspace(self) -> None:
        """Deny every operation when a valid actor targets another Workspace."""
        project = Project.objects.create(
            workspace=self.workspace_a, name="Authorization boundary"
        )
        headers = {
            "HTTP_X_SPIKE_ACTOR": synthetic_actor_id(self.workspace_b.id),
            "HTTP_X_WORKSPACE_ID": str(self.workspace_a.id),
        }
        detail = f"{self.prefix}/projects/{project.id}/"
        responses = [
            self.client.get(f"{self.prefix}/projects/", **headers),
            self.client.get(detail, **headers),
            self.json_request(
                "post",
                f"{self.prefix}/projects/",
                {"workspace_id": str(self.workspace_a.id), "name": "Denied create"},
                **headers,
            ),
            self.json_request("patch", detail, {"name": "Denied update"}, **headers),
            self.client.delete(detail, **headers),
            self.client.get(
                f"{self.prefix}/projects/?workspace_id={self.workspace_a.id}",
                **headers,
            ),
        ]
        for response in responses:
            self.assert_error(response, 404, "not_found")
        project.refresh_from_db()
        self.assertEqual(project.name, "Authorization boundary")

    def test_health_and_unsafe_method(self) -> None:
        """Expose minimal health and normalize unsupported routing behavior."""
        health = self.client.get(f"{self.prefix}/health/")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json(), {"status": "ok"})

        unsafe = self.json_request(
            "put", f"{self.prefix}/projects/", {}, **self.headers()
        )
        self.assert_error(unsafe, 405, "method_not_allowed")

    def test_malformed_and_oversized_json(self) -> None:
        """Reject malformed JSON and bodies over the common one-megabyte limit."""
        malformed = self.client.post(
            f"{self.prefix}/projects/",
            data="{",
            content_type="application/json",
            **self.headers(),
        )
        self.assert_error(malformed, 400, "malformed_request")

        oversized = self.client.post(
            f"{self.prefix}/projects/",
            data=json.dumps({"description": "x" * 1_048_577}),
            content_type="application/json",
            **self.headers(),
        )
        self.assert_error(oversized, 413, "request_too_large")

    @override_settings(DEBUG=False)
    def test_internal_error_is_normalized_without_traceback(self) -> None:
        """Hide exception types, messages, and traces when DEBUG is disabled."""
        with patch(self.internal_patch_target, side_effect=RuntimeError("sensitive")):
            response = self.client.get(
                f"{self.prefix}/projects/", **self.headers()
            )
        body = self.assert_error(response, 500, "internal_error")
        rendered = json.dumps(body).lower()
        self.assertNotIn("runtimeerror", rendered)
        self.assertNotIn("sensitive", rendered)
        self.assertNotIn("traceback", rendered)


class DrfContractTests(ApiContractMixin, TestCase):
    """Run the common contract against Django REST Framework."""

    prefix = "/api/v1/drf"
    internal_patch_target = "drf_api.views.list_projects"


class NinjaContractTests(ApiContractMixin, TestCase):
    """Run the common contract against Django Ninja."""

    prefix = "/api/v1/ninja"
    internal_patch_target = "ninja_api.api.list_projects"


class EquivalentErrorTests(TestCase):
    """Compare representative normalized errors across both adapters."""

    def test_equivalent_error_envelopes(self) -> None:
        """Emit the same status, code, message, and top-level fields."""
        workspace = Workspace.objects.create(
            name="Equivalent errors",
            workspace_type=Workspace.WorkspaceType.ORGANIZATION,
        )
        headers = {
            "HTTP_X_SPIKE_ACTOR": synthetic_actor_id(workspace.id),
            "HTTP_X_WORKSPACE_ID": str(workspace.id),
        }
        client = Client(raise_request_exception=False)
        responses = []
        for prefix in ("/api/v1/drf", "/api/v1/ninja"):
            responses.append(client.post(
                f"{prefix}/projects/",
                data=json.dumps({"workspace_id": str(workspace.id)}),
                content_type="application/json",
                **headers,
            ))
        self.assertEqual([response.status_code for response in responses], [422, 422])
        errors = [response.json()["error"] for response in responses]
        self.assertEqual([error["code"] for error in errors], ["validation_error"] * 2)
        self.assertEqual(errors[0]["message"], errors[1]["message"])
        self.assertEqual(set(errors[0]), set(errors[1]))
