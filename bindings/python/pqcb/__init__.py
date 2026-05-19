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


class _PqcbBuffer(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t),
    ]


class _PqcbOwnedBuffer(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t),
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
    library.pqcb_ml_kem_768_keypair.argtypes = [
        ctypes.POINTER(_PqcbOwnedBuffer),
        ctypes.POINTER(_PqcbOwnedBuffer),
    ]
    library.pqcb_ml_kem_768_keypair.restype = ctypes.c_uint32
    library.pqcb_ml_kem_768_encapsulate.argtypes = [
        _PqcbBuffer,
        ctypes.POINTER(_PqcbOwnedBuffer),
        ctypes.POINTER(_PqcbOwnedBuffer),
    ]
    library.pqcb_ml_kem_768_encapsulate.restype = ctypes.c_uint32
    library.pqcb_ml_kem_768_decapsulate.argtypes = [
        _PqcbBuffer,
        _PqcbBuffer,
        ctypes.POINTER(_PqcbOwnedBuffer),
    ]
    library.pqcb_ml_kem_768_decapsulate.restype = ctypes.c_uint32
    library.pqcb_ml_dsa_65_keypair.argtypes = [
        ctypes.POINTER(_PqcbOwnedBuffer),
        ctypes.POINTER(_PqcbOwnedBuffer),
    ]
    library.pqcb_ml_dsa_65_keypair.restype = ctypes.c_uint32
    library.pqcb_ml_dsa_65_sign.argtypes = [
        _PqcbBuffer,
        _PqcbBuffer,
        ctypes.POINTER(_PqcbOwnedBuffer),
    ]
    library.pqcb_ml_dsa_65_sign.restype = ctypes.c_uint32
    library.pqcb_ml_dsa_65_verify.argtypes = [
        _PqcbBuffer,
        _PqcbBuffer,
        _PqcbBuffer,
    ]
    library.pqcb_ml_dsa_65_verify.restype = ctypes.c_uint32
    library.pqcb_buffer_free.argtypes = [_PqcbOwnedBuffer]
    library.pqcb_buffer_free.restype = None

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


def kem_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-KEM-768 public and secret keypair."""

    public_key = _PqcbOwnedBuffer()
    secret_key = _PqcbOwnedBuffer()
    status = _native().pqcb_ml_kem_768_keypair(
        ctypes.byref(public_key),
        ctypes.byref(secret_key),
    )
    _raise_for_status(status, "ML-KEM-768 keypair", "ML-KEM-768")
    return (
        _take_owned_buffer(public_key, "ML-KEM-768 public key"),
        _take_owned_buffer(secret_key, "ML-KEM-768 secret key"),
    )


def kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate an ML-KEM-768 shared secret for a public key."""

    ciphertext = _PqcbOwnedBuffer()
    shared_secret = _PqcbOwnedBuffer()
    public_key_buffer = _borrow(public_key)
    status = _native().pqcb_ml_kem_768_encapsulate(
        public_key_buffer,
        ctypes.byref(ciphertext),
        ctypes.byref(shared_secret),
    )
    _raise_for_status(status, "ML-KEM-768 encapsulate", "ML-KEM-768")
    return (
        _take_owned_buffer(ciphertext, "ML-KEM-768 ciphertext"),
        _take_owned_buffer(shared_secret, "ML-KEM-768 shared secret"),
    )


def kem_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate an ML-KEM-768 shared secret."""

    shared_secret = _PqcbOwnedBuffer()
    status = _native().pqcb_ml_kem_768_decapsulate(
        _borrow(secret_key),
        _borrow(ciphertext),
        ctypes.byref(shared_secret),
    )
    _raise_for_status(status, "ML-KEM-768 decapsulate", "ML-KEM-768")
    return _take_owned_buffer(shared_secret, "ML-KEM-768 shared secret")


def signature_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-DSA-65 public and secret keypair."""

    public_key = _PqcbOwnedBuffer()
    secret_key = _PqcbOwnedBuffer()
    status = _native().pqcb_ml_dsa_65_keypair(
        ctypes.byref(public_key),
        ctypes.byref(secret_key),
    )
    _raise_for_status(status, "ML-DSA-65 keypair", "ML-DSA-65")
    return (
        _take_owned_buffer(public_key, "ML-DSA-65 public key"),
        _take_owned_buffer(secret_key, "ML-DSA-65 secret key"),
    )


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message with an ML-DSA-65 secret key."""

    signature = _PqcbOwnedBuffer()
    status = _native().pqcb_ml_dsa_65_sign(
        _borrow(secret_key),
        _borrow(message),
        ctypes.byref(signature),
    )
    _raise_for_status(status, "ML-DSA-65 sign", "ML-DSA-65")
    return _take_owned_buffer(signature, "ML-DSA-65 signature")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an ML-DSA-65 signature."""

    status = _native().pqcb_ml_dsa_65_verify(
        _borrow(public_key),
        _borrow(message),
        _borrow(signature),
    )
    _raise_for_status(status, "ML-DSA-65 verify", "ML-DSA-65")
    return True


def _borrow(data: bytes) -> _PqcbBuffer:
    if not isinstance(data, bytes):
        raise TypeError("binary inputs must be bytes")
    if not data:
        return _PqcbBuffer()

    array = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    buffer = _PqcbBuffer(array, len(data))
    setattr(buffer, "_keepalive", array)
    return buffer


def _take_owned_buffer(buffer: _PqcbOwnedBuffer, field: str) -> bytes:
    if not buffer.data or buffer.len == 0:
        raise NullPointerError(f"{field} returned an empty owned buffer")

    try:
        return ctypes.string_at(buffer.data, buffer.len)
    finally:
        _native().pqcb_buffer_free(buffer)


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
    "kem_decapsulate",
    "kem_encapsulate",
    "kem_keypair",
    "native_library_path",
    "sign",
    "signature_keypair",
    "verify",
]
