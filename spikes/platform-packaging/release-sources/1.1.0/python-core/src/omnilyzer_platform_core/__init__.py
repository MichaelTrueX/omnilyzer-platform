"""Public API for the representative platform core fixture."""

from ._internal import normalize_workspace_label, workspace_slug

__version__ = "1.1.0"
__all__ = ["platform_release_version", "normalize_workspace_label", "workspace_slug"]


def platform_release_version():
    return __version__

