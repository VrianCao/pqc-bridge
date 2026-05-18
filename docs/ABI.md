# C ABI Policy

The C ABI is the stable boundary for most language bindings.

## v0.1 ABI

The v0.1 ABI exposes:

- ABI version
- package version

Cryptographic functions are intentionally not exposed until backend integration,
memory ownership rules, and tests are ready.

## v0.2 ABI Model

The v0.2 ABI uses explicit caller-owned input buffers and library-owned output
buffers. All exported symbols use `extern "C"`, `#[repr(C)]` data structures,
and the `pqcb_` symbol prefix.

### Buffer Types

Planned C header declarations:

```c
typedef enum PqcbStatus {
  PQCB_STATUS_OK = 0,
  PQCB_STATUS_NULL_POINTER = 1,
  PQCB_STATUS_INVALID_LENGTH = 2,
  PQCB_STATUS_INVALID_ALGORITHM = 3,
  PQCB_STATUS_BACKEND_UNAVAILABLE = 4,
  PQCB_STATUS_VERIFICATION_FAILED = 5,
  PQCB_STATUS_CRYPTO_FAILURE = 6,
  PQCB_STATUS_PANIC = 255
} PqcbStatus;

typedef struct PqcbBuffer {
  const uint8_t *data;
  size_t len;
} PqcbBuffer;

typedef struct PqcbOwnedBuffer {
  uint8_t *data;
  size_t len;
} PqcbOwnedBuffer;

const char *pqcb_status_message(PqcbStatus status);
void pqcb_buffer_free(PqcbOwnedBuffer buffer);
```

`PqcbBuffer` is caller-owned and borrowed only for the duration of the call.
`PqcbOwnedBuffer` is library-owned and must be released exactly once with
`pqcb_buffer_free`.

### Ownership Table

| Function | Inputs | Outputs | Ownership rule |
| --- | --- | --- | --- |
| `pqcb_abi_version` | none | integer ABI version | No heap ownership. |
| `pqcb_version` | none | `PqcbVersion` by value | No heap ownership. |
| `pqcb_backend_available` | algorithm ID by value | status/boolean by value | No heap ownership. |
| `pqcb_ml_kem_768_keypair` | none | public key and secret key `PqcbOwnedBuffer`s | Caller must free both output buffers. On error, outputs are null/zero. |
| `pqcb_ml_kem_768_encapsulate` | public key `PqcbBuffer` | ciphertext and shared secret `PqcbOwnedBuffer`s | Caller owns input. Caller frees both outputs. Shared secret is never printed or exposed as a string. |
| `pqcb_ml_kem_768_decapsulate` | secret key and ciphertext `PqcbBuffer`s | shared secret `PqcbOwnedBuffer` | Caller owns inputs. Caller frees output. |
| `pqcb_ml_dsa_65_keypair` | none | public key and secret key `PqcbOwnedBuffer`s | Caller must free both output buffers. On error, outputs are null/zero. |
| `pqcb_ml_dsa_65_sign` | secret key and message `PqcbBuffer`s | signature `PqcbOwnedBuffer` | Caller owns inputs. Caller frees output. |
| `pqcb_ml_dsa_65_verify` | public key, message, and signature `PqcbBuffer`s | verification status by value | No output allocation. Verification failure returns a distinct status, not success. |

### Error Mapping

| Rust error or condition | ABI status | Binding implication |
| --- | --- | --- |
| Success | `PQCB_STATUS_OK` | Return value or resolved result. |
| Null input pointer with nonzero length, null output pointer, or invalid output slot | `PQCB_STATUS_NULL_POINTER` | Raise binding argument error before exposing partial outputs. |
| `PqcbError::InvalidLength` | `PQCB_STATUS_INVALID_LENGTH` | Raise deterministic length/validation error. |
| `PqcbError::InvalidAlgorithm` or unknown algorithm ID | `PQCB_STATUS_INVALID_ALGORITHM` | Raise unsupported algorithm error. |
| `PqcbError::BackendUnavailable` | `PQCB_STATUS_BACKEND_UNAVAILABLE` | Expose capability error; callers should check feature discovery first. |
| `PqcbError::VerificationFailed` | `PQCB_STATUS_VERIFICATION_FAILED` | Return false or raise verification-specific error according to binding style. Never return success. |
| `PqcbError::CryptoFailure` | `PQCB_STATUS_CRYPTO_FAILURE` | Raise provider failure without leaking provider internals. |
| Rust panic caught at FFI boundary | `PQCB_STATUS_PANIC` | Treat as fatal operation failure; no panic may unwind into C. |

### Feature Detection

Bindings must call feature-detection functions before exposing provider-backed
operations:

| Function | Meaning |
| --- | --- |
| `pqcb_abi_version` | Packed ABI version for compatibility checks. |
| `pqcb_version` | PQC Bridge package semantic version. |
| `pqcb_backend_available(algorithm_id)` | Returns whether the current build can execute the requested primitive. |

Initial algorithm IDs:

| ID | Algorithm |
| ---: | --- |
| `1` | ML-KEM-768 |
| `2` | ML-DSA-65 |

Unknown algorithm IDs return `PQCB_STATUS_INVALID_ALGORITHM`.

### Thread Safety

- ABI functions must not mutate shared global cryptographic state.
- Library-owned buffers returned from one thread may be freed from another
  thread with `pqcb_buffer_free`.
- Callers must not mutate borrowed input memory while a function is executing.
- The ABI does not retain borrowed input pointers after a function returns.

### Binding Implications

- Bindings should wrap `PqcbOwnedBuffer` in language-native finalizers or
  deterministic close/free types.
- Secret buffers should avoid string conversion and debug printing.
- Bindings must copy caller inputs into stable native buffers when the language
  runtime can move memory during FFI calls.
- Bindings must convert every `PqcbStatus` into deterministic language-level
  results and tests.

## Naming

All exported C symbols use the `pqcb_` prefix.

## Compatibility

Before v1.0, ABI changes are allowed with changelog notes.

At v1.0, ABI major version changes should be reserved for breaking changes.
