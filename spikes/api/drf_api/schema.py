"""spikes/api/drf_api/schema.py: Describe synthetic DRF authentication in OpenAPI.

Related modules: drf_api.authentication and drf_api.views.
"""
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class SyntheticAuthenticationScheme(OpenApiAuthenticationExtension):
    """Expose the actor header as an experimental OpenAPI security scheme."""

    target_class = "drf_api.authentication.SyntheticHeaderAuthentication"
    name = "syntheticActor"

    def get_security_definition(self, auto_schema):
        """Return the API-key header definition used only by this spike."""
        return {
            "type": "apiKey",
            "in": "header",
            "name": "X-Spike-Actor",
            "description": (
                "Synthetic actor only. X-Workspace-ID is also required; neither "
                "header is a production authentication design."
            ),
        }
