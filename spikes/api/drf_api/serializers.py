"""spikes/api/drf_api/serializers.py: Define DRF request and response contracts.

Related modules: drf_api.views, domain.models, and drf_api.errors.
"""
from collections.abc import Mapping
from rest_framework import serializers
from domain.models import Project


class RejectUnknownFieldsMixin:
    """Reject mass-assignment candidates instead of DRF's default ignore behavior."""

    def to_internal_value(self, data):
        """Raise a field-specific validation error for every unexpected key."""
        if isinstance(data, Mapping):
            unknown = sorted(set(data) - set(self.fields))
            if unknown:
                raise serializers.ValidationError(
                    {field: ["Unexpected field."] for field in unknown}
                )
        return super().to_internal_value(data)


class ProjectCreateSerializer(RejectUnknownFieldsMixin, serializers.Serializer):
    """Validate the shared Project creation contract."""

    workspace_id = serializers.UUIDField()
    name = serializers.CharField(max_length=120, allow_blank=False)
    description = serializers.CharField(
        max_length=2_000, allow_blank=True, required=False, default=""
    )
    status = serializers.ChoiceField(
        choices=Project.Status.choices, required=False, default=Project.Status.ACTIVE
    )


class ProjectPatchSerializer(RejectUnknownFieldsMixin, serializers.Serializer):
    """Validate an explicit, non-empty Project partial update."""

    name = serializers.CharField(max_length=120, allow_blank=False, required=False)
    description = serializers.CharField(
        max_length=2_000, allow_blank=True, required=False
    )
    status = serializers.ChoiceField(choices=Project.Status.choices, required=False)

    def validate(self, attrs):
        """Reject an empty PATCH because it represents no application operation."""
        if not attrs:
            raise serializers.ValidationError(
                {"body": ["At least one field is required."]}
            )
        return attrs


class ProjectQuerySerializer(RejectUnknownFieldsMixin, serializers.Serializer):
    """Validate filtering and deterministic pagination query parameters."""

    status = serializers.ChoiceField(
        choices=Project.Status.choices, required=False, default=None
    )
    workspace_id = serializers.UUIDField(required=False, default=None)
    page = serializers.IntegerField(min_value=1, required=False, default=1)
    page_size = serializers.IntegerField(
        min_value=1, max_value=100, required=False, default=20
    )


class ProjectIdentifierSerializer(serializers.Serializer):
    """Validate a path Project identifier into a UUID."""

    id = serializers.UUIDField()


class ProjectSerializer(serializers.ModelSerializer):
    """Render the common Project response shape."""

    workspace_id = serializers.UUIDField(read_only=True)

    class Meta:
        """Select the intentionally public Project fields."""

        model = Project
        fields = (
            "id",
            "workspace_id",
            "name",
            "description",
            "status",
            "created_at",
            "updated_at",
        )


class ProjectPageSerializer(serializers.Serializer):
    """Document the deterministic list response."""

    items = ProjectSerializer(many=True)
    page = serializers.IntegerField()
    page_size = serializers.IntegerField()
    total = serializers.IntegerField()


class ErrorObjectSerializer(serializers.Serializer):
    """Document normalized safe API error fields."""

    code = serializers.CharField()
    message = serializers.CharField()
    details = serializers.JSONField()


class ErrorEnvelopeSerializer(serializers.Serializer):
    """Document the normalized experimental error envelope."""

    error = ErrorObjectSerializer()


class HealthSerializer(serializers.Serializer):
    """Document the deliberately minimal health response."""

    status = serializers.CharField()
