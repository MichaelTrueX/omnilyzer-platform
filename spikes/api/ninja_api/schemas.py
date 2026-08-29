"""spikes/api/ninja_api/schemas.py: Define typed Ninja request/response models.

Related modules: ninja_api.api and domain.models.
"""
from datetime import datetime
from enum import Enum
from typing import Any
import uuid
from ninja import Field, Schema


class ProjectStatus(str, Enum):
    """Enumerate the public Project states."""

    ACTIVE = "active"
    ARCHIVED = "archived"


class StrictInputSchema(Schema):
    """Reject unexpected body fields for mass-assignment safety."""

    class Config:
        """Preserve Ninja defaults while rejecting unexpected body fields."""

        extra = "forbid"


class ProjectCreate(StrictInputSchema):
    """Validate the shared Project creation contract."""

    workspace_id: uuid.UUID
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2_000)
    status: ProjectStatus = ProjectStatus.ACTIVE


class ProjectPatch(StrictInputSchema):
    """Validate an explicit, non-empty Project partial update."""

    # None defaults encode omission; non-null annotations reject explicit JSON null.
    name: str = Field(default=None, min_length=1, max_length=120)  # type: ignore[assignment]
    description: str = Field(default=None, max_length=2_000)  # type: ignore[assignment]
    status: ProjectStatus = None  # type: ignore[assignment]



class ProjectOut(Schema):
    """Render the common Project response shape from Django model attributes."""

    id: uuid.UUID
    workspace_id: uuid.UUID
    name: str
    description: str
    status: ProjectStatus
    created_at: datetime
    updated_at: datetime


class ProjectPageOut(Schema):
    """Document the deterministic list response."""

    items: list[ProjectOut]
    page: int
    page_size: int
    total: int


class ErrorObject(Schema):
    """Document normalized safe API error fields."""

    code: str
    message: str
    details: dict[str, Any] | list[Any]


class ErrorEnvelope(Schema):
    """Document the normalized experimental error envelope."""

    error: ErrorObject


class HealthOut(Schema):
    """Document the deliberately minimal health response."""

    status: str
