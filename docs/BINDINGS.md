# Language Bindings

PQC Bridge uses a shared Rust core and C ABI to avoid reimplementing
cryptography in each language.

## Binding Contract

Each language binding should provide:

- idiomatic package layout
- high-level developer API
- low-level primitive API
- explicit version reporting
- deterministic error mapping
- memory ownership documentation
- examples
- CI build or smoke test

Bindings must not:

- implement independent cryptographic algorithms
- weaken validation performed by the core
- expose secret material through string conversion or debug output
- silently downgrade algorithms

## ABI Ownership Expectations

Bindings must treat C ABI inputs as caller-owned borrowed buffers and outputs as
library-owned buffers that require `pqcb_buffer_free`. A binding may copy output
bytes into a language-owned object, but it must free the original ABI buffer
after the copy. Verification failure must remain distinct from transport,
allocation, and provider errors.

## Error Mapping

All bindings must map C ABI status codes into deterministic language-level
errors without embedding key, ciphertext, shared-secret, message, signature, or
provider-internal bytes in the error string. Error messages may include stable
algorithm names, field names, expected lengths, and actual lengths.

| Rust error | C ABI status | Node.js | Python | Go |
| --- | --- | --- | --- | --- |
| `PqcbError::InvalidAlgorithm` | `PQCB_STATUS_INVALID_ALGORITHM` / `InvalidAlgorithm` | `InvalidAlgorithmError` | `InvalidAlgorithmError` | `ErrInvalidAlgorithm` wrapped in `*Error` |
| `PqcbError::BackendUnavailable` | `PQCB_STATUS_BACKEND_UNAVAILABLE` / `BackendUnavailable` | `BackendUnavailableError` | `BackendUnavailableError` | `ErrBackendUnavailable` wrapped in `*Error` |
| `PqcbError::KeyAlgorithmMismatch` | `PQCB_STATUS_INVALID_LENGTH` / `InvalidLength` until the ABI grows a distinct code | `InvalidLengthError` | `InvalidLengthError` | `ErrInvalidLength` wrapped in `*Error` |
| `PqcbError::InvalidLength` | `PQCB_STATUS_INVALID_LENGTH` / `InvalidLength` | `InvalidLengthError` | `InvalidLengthError` | `ErrInvalidLength` wrapped in `*Error` |
| `PqcbError::InvalidEnvelope` | `PQCB_STATUS_CRYPTO_FAILURE` / `CryptoFailure` until envelope ABI functions grow a distinct code | `CryptoFailureError` | `CryptoFailureError` | `ErrCryptoFailure` wrapped in `*Error` |
| `PqcbError::VerificationFailed` | `PQCB_STATUS_VERIFICATION_FAILED` / `VerificationFailed` | `VerificationFailedError` | `VerificationFailedError` | `ErrVerificationFailed` wrapped in `*Error` |
| `PqcbError::CryptoFailure` | `PQCB_STATUS_CRYPTO_FAILURE` / `CryptoFailure` | `CryptoFailureError` | `CryptoFailureError` | `ErrCryptoFailure` wrapped in `*Error` |
| FFI null pointer guard | `PQCB_STATUS_NULL_POINTER` / `NullPointer` | `NullPointerError` | `NullPointerError` | `ErrNullPointer` wrapped in `*Error` |
| FFI panic guard | `PQCB_STATUS_PANIC` / `Panic` | `PanicError` | `PanicError` | `ErrPanic` wrapped in `*Error` |

Bindings should preserve machine-readable error identity:

- Node.js errors must use stable class names and `name` properties.
- Python errors must use stable exception classes.
- Go errors must support `errors.Is` against the exported sentinel error.

Binding smoke tests must include at least:

- a deterministic unavailable-backend or load-failure path where native loading
  is intentionally pointed at a missing library
- a signature verification failure path that maps to `VerificationFailed`

## Priority

1. Node.js
2. Python
3. Go
4. Java
5. Kotlin/Android
6. Swift/iOS
7. WASM
8. C++

## Distribution Notes

Native artifacts should be published only after:

- release signing is defined
- SBOM generation is available
- platform matrix is tested
- backend license review is complete
- security policy is active
