"""spikes/api/drf_api/views.py: Expose shared Project services through DRF.

Related modules: domain.services, drf_api.serializers, and drf_api.authentication.
"""
from typing import cast
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from domain.auth import RequestPrincipal
from domain.services import (
    archive_or_delete_project,
    create_project,
    get_project,
    list_projects,
    update_project,
)
from drf_api.authentication import SyntheticHeaderAuthentication
from drf_api.permissions import HasSyntheticPrincipal
from drf_api.serializers import (
    ErrorEnvelopeSerializer,
    HealthSerializer,
    ProjectCreateSerializer,
    ProjectIdentifierSerializer,
    ProjectPageSerializer,
    ProjectPatchSerializer,
    ProjectQuerySerializer,
    ProjectSerializer,
)

ERROR_RESPONSES = {
    401: ErrorEnvelopeSerializer,
    404: ErrorEnvelopeSerializer,
    409: ErrorEnvelopeSerializer,
    422: ErrorEnvelopeSerializer,
    500: ErrorEnvelopeSerializer,
}
WORKSPACE_CONTEXT_PARAMETER = OpenApiParameter(
    "X-Workspace-ID",
    str,
    location=OpenApiParameter.HEADER,
    required=True,
)


def _principal(request: Request) -> RequestPrincipal:
    """Return the shared principal installed by DRF authentication."""
    return cast(RequestPrincipal, request.user)


def _project_id(value: str):
    """Validate a path identifier using the normalized DRF validation path."""
    serializer = ProjectIdentifierSerializer(data={"id": value})
    serializer.is_valid(raise_exception=True)
    return serializer.validated_data["id"]


class HealthView(APIView):
    """Return minimal liveness information without internals or database secrets."""

    authentication_classes: list[type] = []

    @extend_schema(
        operation_id="drf_health",
        responses={200: HealthSerializer},
        auth=[],
    )
    def get(self, request: Request) -> Response:
        """Report only a static healthy status."""
        return Response({"status": "ok"})


class ProjectListCreateView(APIView):
    """List and create Projects through the shared service boundary."""

    authentication_classes = [SyntheticHeaderAuthentication]
    permission_classes = [HasSyntheticPrincipal]

    @extend_schema(
        operation_id="drf_list_projects",
        parameters=[ProjectQuerySerializer, WORKSPACE_CONTEXT_PARAMETER],
        responses={200: ProjectPageSerializer, **ERROR_RESPONSES},
    )
    def get(self, request: Request) -> Response:
        """Validate query parameters and return a deterministic Project page."""
        query = ProjectQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        page = list_projects(principal=_principal(request), **query.validated_data)
        return Response(ProjectPageSerializer(page).data)

    @extend_schema(
        operation_id="drf_create_project",
        request=ProjectCreateSerializer,
        parameters=[WORKSPACE_CONTEXT_PARAMETER],
        responses={201: ProjectSerializer, **ERROR_RESPONSES},
    )
    def post(self, request: Request) -> Response:
        """Validate input and create a Workspace-scoped Project."""
        serializer = ProjectCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        project = create_project(
            principal=_principal(request), **serializer.validated_data
        )
        return Response(ProjectSerializer(project).data, status=201)


class ProjectDetailView(APIView):
    """Retrieve, partially update, or delete one authorized Project."""

    authentication_classes = [SyntheticHeaderAuthentication]
    permission_classes = [HasSyntheticPrincipal]

    @extend_schema(
        operation_id="drf_retrieve_project",
        parameters=[WORKSPACE_CONTEXT_PARAMETER],
        responses={200: ProjectSerializer, **ERROR_RESPONSES},
    )
    def get(self, request: Request, project_id: str) -> Response:
        """Retrieve a Project without revealing cross-Workspace existence."""
        project = get_project(
            principal=_principal(request), project_id=_project_id(project_id)
        )
        return Response(ProjectSerializer(project).data)

    @extend_schema(
        operation_id="drf_update_project",
        request=ProjectPatchSerializer,
        parameters=[WORKSPACE_CONTEXT_PARAMETER],
        responses={200: ProjectSerializer, **ERROR_RESPONSES},
    )
    def patch(self, request: Request, project_id: str) -> Response:
        """Apply a validated non-empty partial update."""
        serializer = ProjectPatchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        project = update_project(
            principal=_principal(request),
            project_id=_project_id(project_id),
            changes=serializer.validated_data,
        )
        return Response(ProjectSerializer(project).data)

    @extend_schema(
        operation_id="drf_delete_project",
        parameters=[WORKSPACE_CONTEXT_PARAMETER],
        responses={204: None, **ERROR_RESPONSES},
    )
    def delete(self, request: Request, project_id: str) -> Response:
        """Delete one authorized Project and return an empty 204 response."""
        archive_or_delete_project(
            principal=_principal(request), project_id=_project_id(project_id)
        )
        return Response(status=204)
