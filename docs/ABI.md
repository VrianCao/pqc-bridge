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
void pqcb_buffer_free_parts(uint8_t *data, size_t len);
```

`PqcbBuffer` is caller-owned and borrowed only for the duration of the call.
`PqcbOwnedBuffer` is library-owned and must be released exactly once with
`pqcb_buffer_free` or `pqcb_buffer_free_parts`.

### Ownership Table

| Function | Inputs | Outputs | Ownership rule |
| --- | --- | --- | --- |
| `pqcb_abi_version` | none | integer ABI version | No heap ownership. |
| `pqcb_version` | none | `PqcbVersion` by value | No heap ownership. |
| `pqcb_backend_available` | algorithm ID by value | status/boolean by value | No heap ownership. |
| `pqcb_buffer_free` | `PqcbOwnedBuffer` by value | none | Releases one library-owned output buffer. |
| `pqcb_buffer_free_parts` | pointer and length from `PqcbOwnedBuffer` | none | Releases one library-owned output buffer for FFI layers that cannot safely pass structs by value. |
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
| `pqcb_abi_version_major` | ABI major version for breaking-change checks. |
| `pqcb_abi_version_minor` | ABI minor version for additive capability checks. |
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

### Sanitizer Plan

AddressSanitizer is not yet wired into CI. Until the sanitizer job lands, each
primitive ABI task must include null-pointer, invalid-length, success, and
free-path tests. A future hardening task should add an ASan/UBSan C harness for
`pqcb_buffer_free` and every primitive ABI entrypoint before v1.0.

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

At v1.0, the C ABI becomes a stable compatibility boundary. ABI versioning is
independent of package semantic versioning but release notes must report both
the package version and the ABI major/minor version.

ABI version rules after v1.0:

- The ABI major version changes for breaking symbol removals, incompatible
  `#[repr(C)]` layout changes, changed ownership rules, changed status-code
  meaning, or changed algorithm semantics.
- The ABI minor version changes for additive symbols, additive status codes,
  new algorithm IDs, or new feature-detection functions.
- Patch releases must not change exported symbol signatures, data layout,
  ownership, status-code semantics, or existing algorithm IDs.
- Unknown status codes, unknown algorithm IDs, and unsupported minor-version
  features must fail closed in bindings.
- Existing ABI symbols must remain available for the full ABI major support
  window unless a security issue makes continued support unsafe.

Breaking ABI changes require:

- a new ABI major version
- changelog entry under `Changed`, `Removed`, or `Security`
- migration notes naming removed or changed symbols
- binding smoke tests that reject unsupported ABI majors
- release notes describing compatibility impact

Additive ABI changes require:

- feature-detection behavior
- null-pointer and invalid-length tests where the new entrypoint accepts
  buffers
- binding mapping updates or an explicit note that the binding does not expose
  the new capability yet

Bindings must check `pqcb_abi_version_major` before calling primitive functions.
They may use `pqcb_abi_version_minor` and `pqcb_backend_available` to expose
new capabilities without requiring a major binding release.
