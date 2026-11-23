"""Python SDK for the Trusted Data Format."""

from importlib import metadata as _metadata

from ._assertions import AssertionConfig, AssertionStatement
from ._kas import AccessDenied, KasAlgorithm, KasConfig, TdfError
from ._tdf import create_tdf, open_tdf, open_tdf_with_metadata

__all__ = [
    "AccessDenied",
    "AssertionConfig",
    "AssertionStatement",
    "KasAlgorithm",
    "KasConfig",
    "TdfError",
    "create_tdf",
    "open_tdf",
    "open_tdf_with_metadata",
    "version",
]


def version() -> str:
    """Return the installed SDK distribution version.

    Raise importlib.metadata.PackageNotFoundError if distribution metadata
    is missing.
    """
    return _metadata.version("opentdf-python-sdk")
