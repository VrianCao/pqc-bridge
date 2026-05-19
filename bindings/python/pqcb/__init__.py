"""Python bindings for PQC Bridge."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Final

__version__ = "0.1.0"

_ALGORITHMS: Final = {
    "ML-KEM-768": 1,
    "ML-DSA-65": 2,
}

_STATUS_OK: Final = 0
_STATUS_NULL_POINTER: Final = 1
_STATUS_INVALID_LENGTH: Final = 2
_STATUS_INVALID_ALGORITHM: Final = 3
_STATUS_BACKEND_UNAVAILABLE: Final = 4
_STATUS_VERIFICATION_FAILED: Final = 5
_STATUS_CRYPTO_FAILURE: Final = 6
_STATUS_PANIC: Final = 255


class PqcbError(RuntimeError):
    """Base class for PQC Bridge binding errors."""


class NullPointerError(PqcbError):
    """Raised when the C ABI reports an unexpected null pointer."""


class InvalidLengthError(PqcbError):
    """Raised when a binary input has an invalid length."""


class InvalidAlgorithmError(PqcbError):
    """Raised when an algorithm name is unknown or unsupported."""


class BackendUnavailableError(PqcbError):
    """Raised when the native library or backend is unavailable."""


class VerificationFailedError(PqcbError):
    """Raised when signature verification fails."""


class CryptoFailureError(PqcbError):
    """Raised when the cryptographic provider reports failure."""


class PanicError(PqcbError):
    """Raised when the C ABI catches a panic."""


class _PqcbVersion(ctypes.Structure):
    _fields_ = [
        ("major", ctypes.c_uint16),
        ("minor", ctypes.c_uint16),
        ("patch", ctypes.c_uint16),
    ]


_library: ctypes.CDLL | None = None


def native_library_path() -> str:
    """Return the dynamic library path used by the binding."""

    configured = os.environ.get("PQCB_FFI_LIBRARY_PATH")
    if configured:
        return configured

    if sys.platform == "win32":
        library_name = "pqcb_ffi.dll"
    elif sys.platform == "darwin":
        library_name = "libpqcb_ffi.dylib"
    else:
        library_name = "libpqcb_ffi.so"

    return str(Path(__file__).resolve().parents[3] / "target" / "debug" / library_name)


def _native() -> ctypes.CDLL:
    global _library

    if _library is not None:
        return _library

    library_path = native_library_path()
    if not Path(library_path).exists():
        raise BackendUnavailableError("native library load backend is unavailable")

    try:
        library = ctypes.CDLL(library_path)
    except OSError as exc:
        raise BackendUnavailableError("native library load backend is unavailable") from exc

    library.pqcb_version.argtypes = []
    library.pqcb_version.restype = _PqcbVersion
    library.pqcb_backend_available.argtypes = [
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_bool),
    ]
    library.pqcb_backend_available.restype = ctypes.c_uint32

    _library = library
    return library


def abi_version() -> str:
    """Return the ABI-backed PQC Bridge crate version."""

    version = _native().pqcb_version()
    return f"{version.major}.{version.minor}.{version.patch}"


def backend_available(algorithm: str) -> bool:
    """Return whether the native backend supports an algorithm."""

    try:
        algorithm_id = _ALGORITHMS[algorithm]
    except KeyError as exc:
        raise InvalidAlgorithmError(f"unsupported or unknown algorithm: {algorithm}") from exc

    available = ctypes.c_bool(False)
    status = _native().pqcb_backend_available(
        ctypes.c_uint32(algorithm_id),
        ctypes.byref(available),
    )
    _raise_for_status(status, "backend availability", algorithm)
    return bool(available.value)


def _raise_for_status(status: int, operation: str, algorithm: str | None = None) -> None:
    if status == _STATUS_OK:
        return
    if status == _STATUS_NULL_POINTER:
        raise NullPointerError(f"{operation} returned a null pointer error")
    if status == _STATUS_INVALID_LENGTH:
        raise InvalidLengthError(f"{operation} received an invalid buffer length")
    if status == _STATUS_INVALID_ALGORITHM:
        raise InvalidAlgorithmError(
            f"unsupported or unknown algorithm: {algorithm or 'unknown'}"
        )
    if status == _STATUS_BACKEND_UNAVAILABLE:
        raise BackendUnavailableError(f"{operation} backend is unavailable")
    if status == _STATUS_VERIFICATION_FAILED:
        raise VerificationFailedError("signature verification failed")
    if status == _STATUS_CRYPTO_FAILURE:
        raise CryptoFailureError(f"{operation} cryptographic operation failed")
    if status == _STATUS_PANIC:
        raise PanicError(f"{operation} panic caught at FFI boundary")
    raise CryptoFailureError(f"{operation} cryptographic operation failed")


def create_secure_session() -> None:
    """Create a high-level secure session."""

    raise BackendUnavailableError("SecureSession backend is unavailable")


__all__ = [
    "BackendUnavailableError",
    "CryptoFailureError",
    "InvalidAlgorithmError",
    "InvalidLengthError",
    "NullPointerError",
    "PanicError",
    "PqcbError",
    "VerificationFailedError",
    "__version__",
    "abi_version",
    "backend_available",
    "create_secure_session",
    "native_library_path",
]
