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

Current status:

- core state machine skeleton exists
- hybrid composition is not yet implemented
- attempts to use the hybrid path fail closed until v0.5

Non-goals for v0.4:

- final migration composition
- downgrade to PQ-only or classical-only mode
- streaming message encryption

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

Default composition:

```text
ML-KEM-768 shared secret + KEM ciphertext -> HKDF-SHA256 -> XChaCha20-Poly1305
```

Minimal RustCrypto-backed workflow:

```rust
let keys = pqcb_backend_rustcrypto::kem::keypair()?;
let sealed = pqcb_backend_rustcrypto::sealed_box::seal(
    &keys.public_key,
    b"short secret",
)?;
let encoded = sealed.to_bytes()?;
let decoded = pqcb_backend_rustcrypto::sealed_box::from_bytes(&encoded)?;
let plaintext = pqcb_backend_rustcrypto::sealed_box::open(
    &keys.secret_key,
    &decoded,
)?;
assert_eq!(plaintext, b"short secret");
# Ok::<(), pqcb_core::PqcbError>(())
```

Non-goals:

- streaming encryption
- large file chunking
- sender authentication
- replay protection

### SignedMessage

Purpose: sign and verify messages with ML-DSA.

Target use cases:

- API request signing
- software update signatures
- release artifact signatures
- audit log integrity

Minimal RustCrypto-backed workflow:

```rust
let keys = pqcb_backend_rustcrypto::signature::keypair()?;
let signed = pqcb_backend_rustcrypto::signed_message::sign(
    &keys.secret_key,
    b"artifact digest",
)?;
let encoded = signed.to_bytes()?;
let decoded = pqcb_backend_rustcrypto::signed_message::from_bytes(&encoded)?;
pqcb_backend_rustcrypto::signed_message::verify(&keys.public_key, &decoded)?;
# Ok::<(), pqcb_core::PqcbError>(())
```

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
