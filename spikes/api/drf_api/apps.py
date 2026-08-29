"""spikes/api/drf_api/apps.py: Configure DRF schema extension discovery.

Related modules: drf_api.schema and config.settings.
"""
from django.apps import AppConfig


class DrfApiConfig(AppConfig):
    """Load the experimental authentication schema adapter."""

    name = "drf_api"

    def ready(self) -> None:
        """Import schema extensions after Django's application registry is ready."""
        from drf_api import schema

        assert schema
