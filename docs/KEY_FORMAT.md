# Key and Envelope Format

PQC Bridge will use explicit versioned envelopes for serialized SDK objects.

The v0.1 scaffold does not yet serialize production keys. This document defines
the intended direction so future implementations do not invent incompatible
formats independently.

## Goals

- Make algorithm and key type explicit.
- Prevent accidental use of one key type as another.
- Support future migration to standard encodings.
- Keep binary and text encodings deterministic.
- Avoid leaking secret material through debug or logs.

## Envelope Fields

Planned binary envelope fields:

```text
magic
version
object_type
algorithm
flags
material_length
material
checksum_or_authentication
```

Planned object types:

- public key
- secret key
- ciphertext
- signature
- sealed message
- file envelope

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

## v0.2 CLI Smoke Formats

The v0.2 CLI smoke commands write raw primitive bytes to explicit file paths.
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
