# Roadmap

This roadmap is intentionally staged. PQC Bridge should become broad over time,
but the first release must prove the core safety model.

## v0.1 Developer Preview

Repository and SDK foundation:

- Rust workspace
- `pqcb-core`
- `pqcb-ffi`
- `pqcb-cli`
- C header scaffold
- Node/Python/Go binding scaffolds
- Java/Kotlin/Swift/WASM/C++ placeholders
- architecture and security documents
- CI baseline
- contribution and governance policies

No production cryptographic backend is enabled in v0.1.

## v0.2 First Crypto Backend

Deliver the first reviewed backend integration:

- ML-KEM-768 keygen/encapsulate/decapsulate
- ML-DSA-65 keygen/sign/verify
- KAT coverage
- CLI keygen/sign/verify prototypes
- primitive API in Rust
- C ABI memory ownership rules

## v0.3 Developer Bindings

Expose the first ergonomic bindings:

- Node.js package
- Python package
- Go package
- examples for common app workflows
- package publishing dry runs

## v0.4 High-Level APIs

Add developer-facing workflows:

- SecureSession
- SealedBox
- SignedMessage
- envelope serialization
- test vectors for SDK-level formats

## v0.5 Hybrid Migration

Add hybrid defaults:

- X25519 + ML-KEM-768
- HKDF composition
- AEAD integration
- secure session transcript binding
- interoperability tests

## v1.0 Stable

Production readiness target:

- stable API and ABI policy
- cross-platform CI matrix
- fuzzing baseline
- side-channel review notes
- release signing
- supply-chain policy
- security audit plan or completed review

## Later Phases

- OpenSSL/AWS-LC backend
- liboqs compatibility backend
- SLH-DSA support
- HQC support after final standardization
- FN-DSA/Falcon support after stable standardization and implementation review
- TLS/provider integrations
- mobile platform packages
- WASM browser package
- migration scanner
- enterprise KMS adapters
