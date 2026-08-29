"""spikes/api/domain/apps.py: Define Django application metadata for the domain.

Related modules: domain.models and config.settings.
"""
from django.apps import AppConfig


class DomainConfig(AppConfig):
    """Configure the shared Workspace and Project experiment."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "domain"
