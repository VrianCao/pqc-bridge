"""Python bindings for PQC Bridge."""

__all__ = [
    "BackendUnavailableError",
    "__version__",
    "create_secure_session",
]

__version__ = "0.1.0"


class BackendUnavailableError(RuntimeError):
    """Raised when a cryptographic backend is not configured."""


def create_secure_session() -> None:
    """Create a high-level secure session.

    The v0.1 package is a scaffold and intentionally fails closed.
    """
    raise BackendUnavailableError(
        "SecureSession backend is not configured in the v0.1 scaffold"
    )
