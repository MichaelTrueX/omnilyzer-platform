"""File: synthetic Python fixture exposing only coordinated release identity."""

__version__ = "0.0.0"


def report() -> str:
    """Return the prepared coordinated release version."""
    return __version__


__all__ = ["__version__", "report"]
