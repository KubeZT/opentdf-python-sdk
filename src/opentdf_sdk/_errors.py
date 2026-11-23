class TdfError(ValueError):
    """A TDF could not be created or opened."""


class AccessDenied(TdfError):
    """KAS denied access to the TDF."""
