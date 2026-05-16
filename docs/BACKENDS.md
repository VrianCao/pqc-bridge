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

v0.3 should add one optional compatibility backend.

v1.0 should define:

- default backend policy
- backend version support window
- KAT requirements
- fuzz requirements
- side-channel review expectations
