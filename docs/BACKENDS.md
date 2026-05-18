# Backend Strategy

PQC Bridge is not an algorithm research project. It is an SDK and distribution
layer over reviewed cryptographic implementations.

## Backend Requirements

A backend must provide:

- clear upstream provenance
- version pinning
- known-answer tests
- constant-time implementation claims or review notes
- supported platform matrix
- memory safety notes
- license compatibility
- maintenance status

## Planned Backend Classes

### Rust-native backend

Primary long-term fit for the Rust core. Candidate sources include focused,
auditable Rust implementations and formally verified implementations where
available.

Use when:

- Rust-native distribution matters
- small dependency graphs matter
- memory safety is a priority
- WASM/mobile builds are important

### liboqs backend

Compatibility and experimentation backend.

Use when:

- broad algorithm coverage matters
- migration testing matters
- non-default PQC candidates are needed

Do not make liboqs-specific behavior part of the stable public API.

### OpenSSL/AWS-LC backend

System and enterprise backend.

Use when:

- deployment already depends on OpenSSL or AWS-LC
- server-side operations need mature platform integration
- enterprise security teams prefer established providers

### Focused C backend

Candidate for ML-KEM-only or narrow high-assurance deployments.

Use when:

- binary size matters
- the algorithm set is intentionally narrow
- C ABI integration is the priority

## Backend Selection Policy

v0.1 starts with contracts and no production crypto.

v0.2 should integrate one default backend for:

- ML-KEM-768
- ML-DSA-65

The accepted v0.2 default backend decision is recorded in
[`RFC 0002`](rfcs/0002-backend-selection.md): RustCrypto `ml-kem` and `ml-dsa`
behind a private `pqcb-backend-rustcrypto` adapter.

## v0.2 Backend Crate and Feature Layout

The selected backend is integrated through a dedicated workspace crate:

```text
crates/pqcb-backend-rustcrypto
```

The backend crate owns all direct RustCrypto dependencies and implements the
`pqcb-core` backend traits. `pqcb-core` remains provider-neutral and must not
depend on `ml-kem`, `ml-dsa`, or any provider type.

### Workspace Dependencies

The workspace dependency policy for v0.2 is:

| Dependency | Version | Owner | Notes |
| --- | --- | --- | --- |
| `ml-kem` | `=0.3.2` | `pqcb-backend-rustcrypto` | Enable `getrandom` and `zeroize`; avoid `pkcs8` until key-envelope policy needs it. |
| `ml-dsa` | `=0.1.0` | `pqcb-backend-rustcrypto` | Enable `getrandom` and `zeroize`; avoid `pkcs8` until serialization policy needs it. |
| `zeroize` | workspace | `pqcb-core`, backend crates | Shared-secret and secret-key material must remain redacted and zeroized where possible. |

Backend dependency versions are pinned exactly for the first integration. Any
version change must include changelog review, KAT verification, and cargo-deny
review.

### Cargo Features

Feature names are part of the public build contract:

| Crate | Feature | Default | Behavior |
| --- | --- | --- | --- |
| `pqcb-core` | none for providers | N/A | Defines provider-neutral traits, algorithm identifiers, key containers, and errors only. |
| `pqcb-backend-rustcrypto` | `std` | yes | Enables standard-library integration for the backend crate. |
| `pqcb-backend-rustcrypto` | `getrandom` | yes | Enables OS randomness through provider-supported RNG features. |
| `pqcb-backend-rustcrypto` | `zeroize` | yes | Enables provider zeroization support where available. |
| `pqcb-cli` | `backend-rustcrypto` | yes after adapter implementation | Uses the RustCrypto backend for smoke commands. |
| `pqcb-ffi` | `backend-rustcrypto` | no until C ABI primitives are implemented | Exposes backend availability and primitive C ABI functions. |

Before the adapter implementation lands, provider-backed features may exist as
mechanical wiring only and must fail closed with `BackendUnavailable`.

### API Isolation Rules

- Public Rust APIs expose `KemAlgorithm`, `SignatureAlgorithm`, `PublicKey`,
  `SecretKey`, `Encapsulation`, `Verification`, and `PqcbError` only.
- Public C ABI functions expose C-owned buffers, stable algorithm IDs, status
  codes, and explicit free functions only.
- Provider types such as RustCrypto `MlKem768`, `SigningKey`, `VerifyingKey`,
  `Signature`, ciphertext arrays, and fixed-size encoded arrays stay inside the
  backend crate.
- Invalid public key, secret key, ciphertext, and signature lengths are checked
  by PQC Bridge before provider calls.
- Backend errors are mapped to `PqcbError` variants before crossing crate, CLI,
  or C ABI boundaries.

v0.3 should add one optional compatibility backend.

v1.0 should define:

- default backend policy
- backend version support window
- KAT requirements
- fuzz requirements
- side-channel review expectations
