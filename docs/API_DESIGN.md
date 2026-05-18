# API Design

PQC Bridge exposes two API layers.

## High-Level API

The high-level API is the default developer experience. It is intended for
application developers who know what they want to build but do not want to
compose cryptographic primitives manually.

Planned high-level types:

- `SecureSession`
- `SealedBox`
- `SignedMessage`
- `FileEnvelope`

### SecureSession

Purpose: establish a shared session key and encrypt multiple messages.

Default profile:

```text
X25519 + ML-KEM-768 -> HKDF -> AEAD keys
```

Target use cases:

- app-to-server communication
- service-to-service communication
- device pairing
- private messaging sessions

### SealedBox

Purpose: encrypt one message to a recipient public key.

Target use cases:

- one-shot encrypted payloads
- invitations
- secrets delivered to a known recipient
- small file envelopes

### SignedMessage

Purpose: sign and verify messages with ML-DSA.

Target use cases:

- API request signing
- software update signatures
- release artifact signatures
- audit log integrity

## Primitive API

The primitive API is the expert mode. It is intended for protocol implementors,
security engineers, researchers, and application teams that need precise control.

Planned primitive modules:

```text
kem.keypair(algorithm)
kem.encapsulate(public_key)
kem.decapsulate(secret_key, ciphertext)

signature.keypair(algorithm)
signature.sign(secret_key, message)
signature.verify(public_key, message, signature)
```

`pqcb-core` exposes these modules as provider-neutral fail-closed entrypoints:
without a backend they validate caller inputs and then return
`PqcbError::BackendUnavailable`. The default provider crate
`pqcb-backend-rustcrypto` exposes matching ergonomic modules backed by
RustCrypto:

```rust
let kem_keys = pqcb_backend_rustcrypto::kem::keypair()?;
let encapsulation = pqcb_backend_rustcrypto::kem::encapsulate(&kem_keys.public_key)?;
let shared = pqcb_backend_rustcrypto::kem::decapsulate(
    &kem_keys.secret_key,
    encapsulation.ciphertext(),
)?;

let signing_keys = pqcb_backend_rustcrypto::signature::keypair()?;
let signature = pqcb_backend_rustcrypto::signature::sign(
    &signing_keys.secret_key,
    b"message",
)?;
pqcb_backend_rustcrypto::signature::verify(
    &signing_keys.public_key,
    b"message",
    &signature,
)?;
# Ok::<(), pqcb_core::PqcbError>(())
```

The v0.2 CLI mirrors these primitive operations for smoke testing:

```sh
pqcb keygen --kind signature --algorithm ML-DSA-65 \
  --public-out dsa.pub --secret-out dsa.sec

pqcb sign --algorithm ML-DSA-65 \
  --secret-key dsa.sec \
  --message message.bin \
  --signature-out message.sig

pqcb verify --algorithm ML-DSA-65 \
  --public-key dsa.pub \
  --message message.bin \
  --signature message.sig
```

`verify` exits successfully only for a valid signature over the supplied message
and public key. Verification failure is returned as a non-zero command result.

## Default Algorithms

| API | Default |
| --- | --- |
| KEM | ML-KEM-768 |
| Signature | ML-DSA-65 |
| Hybrid session | X25519 + ML-KEM-768 |
| Backup signature | SLH-DSA in a later phase |

## API Safety Rules

- Defaults must be safe for general application use.
- Dangerous knobs must not appear in high-level APIs.
- Low-level APIs must use strong algorithm identifiers.
- Secret keys and shared secrets must redact debug output.
- Randomness must come from OS or backend-approved CSPRNGs.
- Key and ciphertext lengths must be checked before backend calls.
- Verification must return a clear success/failure result.

## Naming Rules

Public API names should prefer standard names:

- `ML-KEM-768`, not `Kyber768`
- `ML-DSA-65`, not `Dilithium3`
- `SLH-DSA`, not only `SPHINCS+`

Historical aliases may be accepted for migration ergonomics, but generated
metadata should use canonical names.
