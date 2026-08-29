"""Public API for the representative platform core fixture."""

from ._internal import normalize_workspace_label

__version__ = "1.0.0"
__all__ = ["platform_release_version", "normalize_workspace_label"]


def platform_release_version():
    return __version__

