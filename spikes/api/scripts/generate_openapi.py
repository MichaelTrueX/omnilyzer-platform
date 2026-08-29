"""spikes/api/scripts/generate_openapi.py: Generate both API schemas from code.

Related modules: drf_api.views, ninja_api.api, and config.urls.
"""
from pathlib import Path
import json
import os
import sys

SPIKE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SPIKE_ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django

django.setup()

from drf_spectacular.generators import SchemaGenerator
from ninja_api.api import api as ninja_api


def write_json(path: Path, document: dict[str, object]) -> None:
    """Write a deterministic, human-reviewable generated OpenAPI document."""
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> None:
    """Generate DRF and Ninja specifications without manually authored schema files."""
    results = SPIKE_ROOT / "results"
    results.mkdir(exist_ok=True)
    drf_schema = SchemaGenerator().get_schema(request=None, public=True)
    ninja_schema = ninja_api.get_openapi_schema(path_prefix="/api/v1/ninja")
    write_json(results / "drf-openapi.json", drf_schema)
    write_json(results / "ninja-openapi.json", ninja_schema)
    print("Generated DRF and Django Ninja OpenAPI artifacts.")


if __name__ == "__main__":
    main()
