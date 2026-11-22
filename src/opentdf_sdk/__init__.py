"""Public API for the independent Python TDF SDK scaffold."""

from importlib import metadata as _metadata

__all__ = ["version"]


def version() -> str:
    """Return the installed SDK distribution version.

    Raise importlib.metadata.PackageNotFoundError if distribution metadata
    is missing.
    """
    return _metadata.version("opentdf-python-sdk")
