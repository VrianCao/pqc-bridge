# Key and Envelope Format

PQC Bridge will use explicit versioned envelopes for serialized SDK objects.

Pre-v1.0 releases define and parse the SDK-native envelope format, but they
must not be used to serialize production secrets until the stable release
checklist and security review scope are complete. This document keeps the
format contract explicit so bindings and future implementations do not invent
incompatible encodings independently.

## Goals

- Make algorithm and key type explicit.
- Prevent accidental use of one key type as another.
- Support future migration to standard encodings.
- Keep binary and text encodings deterministic.
- Avoid leaking secret material through debug or logs.

## v1 Binary Envelope

All SDK-native serialized objects use the same v1 binary envelope. Multi-byte
integer fields are unsigned big-endian. Parsers must reject truncated input,
trailing bytes, non-canonical lengths, unsupported versions, unsupported
object/algorithm combinations, and unknown required flags before exposing
material to callers.

Byte-level schema:

| Offset | Size | Field | Encoding | Required behavior |
| ---: | ---: | --- | --- | --- |
| 0 | 4 | `magic` | ASCII `PQCB` (`0x50 0x51 0x43 0x42`) | Reject any other value. |
| 4 | 1 | `version` | `0x01` for this format | Reject unsupported versions. |
| 5 | 1 | `object_type` | Numeric object type from the table below | Reject unknown values. |
| 6 | 2 | `algorithm` | Numeric algorithm/profile ID from the table below | Reject unknown values and invalid object combinations. |
| 8 | 2 | `flags` | Bit field, big-endian | Reject unknown required flags; ignore unknown advisory flags only when defined as advisory. |
| 10 | 4 | `material_length` | Big-endian byte length of `material` | Must equal the remaining material size implied by this header. |
| 14 | `material_length` | `material` | Object-specific bytes | Must be parsed according to `object_type` and `algorithm`. |
| 14 + `material_length` | 32 | `checksum_or_authentication` | SHA-256 checksum for public objects; authentication tag for encrypted/private objects | Must verify before accepting the envelope. |

The final field is always present. Public objects that are not confidential use
`SHA-256(header_without_checksum || material)` as corruption detection only; it
is not an authenticity claim. Secret-key and sealed-message envelopes must use
an authenticated construction defined by the high-level API that covers the same
header bytes and material bytes.

The canonical serialized length is:

```text
14 + material_length + 32
```

Parsers must compare the input length to this value exactly.

### Object Types

| ID | Object type | Material format |
| ---: | --- | --- |
| `0x01` | Public key | Raw public key bytes for the selected algorithm. |
| `0x02` | Secret key | Raw secret key bytes or an authenticated encrypted private-key payload when `encrypted` is set. |
| `0x03` | Ciphertext | Raw KEM ciphertext bytes for the selected KEM algorithm. |
| `0x04` | Signature | Raw signature bytes for the selected signature algorithm. |
| `0x05` | Sealed message | High-level sealed-message payload, including its own nonce and associated-data binding. |
| `0x06` | File envelope | High-level file-envelope payload, including chunking metadata when present. |

### Algorithm IDs

| ID | Algorithm/profile | Valid object types |
| ---: | --- | --- |
| `0x0001` | `ML-KEM-768` | Public key, secret key, ciphertext, sealed message. |
| `0x0002` | `ML-DSA-65` | Public key, secret key, signature. |
| `0x0101` | `X25519-ML-KEM-768` | Public key, secret key, sealed message, file envelope. |

Unknown algorithm IDs are reserved for future versions and must fail closed.

### Flags

| Bit | Name | Meaning | Parser behavior |
| ---: | --- | --- | --- |
| 0 | `encrypted` | `material` contains an authenticated encrypted payload rather than raw bytes. | Required for secret-key files at rest; optional for public objects only when explicitly documented. |
| 1 | `contains_secret` | Envelope material is secret or can derive secrets. | Must trigger debug redaction and restrictive file handling. |
| 2 | `detached_material` | Envelope authenticates material stored outside this byte string. | Reserved for later file-envelope work; v1 parsers must reject it. |
| 3-15 | Reserved | Future use. | v1 parsers must reject when nonzero. |

Secret-key envelopes must set `contains_secret`. Public keys, ciphertexts, and
signatures must not set it. Secret-key files written by CLI or bindings should
also set `encrypted`; unencrypted secret-key import/export may exist only behind
an explicit unsafe or development-only control.

### Canonical Material Lengths

Primitive objects have fixed material lengths:

| Object | Algorithm | Material length |
| --- | --- | ---: |
| Public key | `ML-KEM-768` | 1,184 bytes |
| Secret key | `ML-KEM-768` | 2,400 bytes before any private-key encryption wrapper |
| Ciphertext | `ML-KEM-768` | 1,088 bytes |
| Public key | `ML-DSA-65` | 1,952 bytes |
| Secret key | `ML-DSA-65` | 4,032 bytes before any private-key encryption wrapper |
| Signature | `ML-DSA-65` | 3,309 bytes |

High-level objects such as sealed messages and file envelopes are variable
length. Their inner material format must include enough authenticated metadata
to bind nonce, algorithm profile, associated data, and payload length; those
fields are not allowed to contradict the outer header.

### Unknown-Field Behavior

The v1 envelope has no extension area and therefore no unknown fields inside the
outer header. Additive metadata must be added either to an authenticated
high-level material format or to a future envelope version. A v1 parser must not
skip bytes that are not accounted for by `material_length` and the final
checksum/authentication field.

### File Permissions

Writers should create files with owner-only permissions for envelopes that set
`contains_secret`, for example `0600` on Unix-like systems. On platforms without
POSIX permissions, bindings must document the closest available private-file
behavior. Readers must not rely on file permissions as a substitute for
authenticated encryption.

### Text Encoding

Text encoding, when needed, is base64url without padding over the exact binary
envelope bytes. Pretty-printed or line-wrapped text encodings are display forms
only and must decode to the canonical binary representation before validation.

## Standard Format Interop

PQC Bridge should eventually support import/export for relevant standard
formats where practical:

- PEM
- DER
- COSE
- JWK
- X.509-related formats

The internal envelope should remain available for SDK-native workflows.

## Secret Handling

- Secret keys are zeroized on drop where language/runtime allows it.
- Debug output redacts secret bytes.
- File permissions should be restrictive by default.
- CLI output must not print secret material unless explicitly requested.
- Bindings must document runtime-specific memory limitations.

## Pre-v1.0 CLI Smoke Formats

The pre-v1.0 CLI smoke commands write raw primitive bytes to explicit file paths.
They are intended for backend smoke testing, not stable interchange.

```sh
pqcb keygen --kind kem --algorithm ML-KEM-768 \
  --public-out kem.pub --secret-out kem.sec

pqcb encapsulate --algorithm ML-KEM-768 \
  --public-key kem.pub \
  --ciphertext-out kem.ct \
  --shared-secret-out kem.ss.enc

pqcb decapsulate --algorithm ML-KEM-768 \
  --secret-key kem.sec \
  --ciphertext kem.ct \
  --shared-secret-out kem.ss.dec
```

Secret keys and shared secrets are never printed by these commands. They are
written only to the explicit file targets supplied by the caller.
