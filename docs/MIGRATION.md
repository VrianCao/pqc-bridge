# Migration Guide

PQC Bridge is designed for incremental migration. Most applications should not
switch from classical cryptography to pure post-quantum cryptography in one
step.

## Recommended Migration Path

1. Inventory current cryptography.
2. Identify long-lived confidentiality risks.
3. Add hybrid key agreement where traffic can be recorded today.
4. Add post-quantum signatures for release artifacts and critical messages.
5. Keep classical algorithms during the transition.
6. Monitor standards, provider updates, and interoperability requirements.
7. Move to pure PQC only when the ecosystem and threat model justify it.

## Default Recommendation

Use hybrid key agreement:

```text
X25519 + ML-KEM-768
```

This keeps current classical security while adding post-quantum protection.

## Common Workflows

### API Client to Server

Use the `X25519-ML-KEM-768` hybrid profile for new SDK-managed session setup.
The RustCrypto backend exposes a runnable example:

```sh
cargo run -p pqcb-backend-rustcrypto --example hybrid_session
```

Bind protocol name, version, peer identity, and replay/freshness material into
the caller context passed to hybrid setup. Avoid manually composing KEM, HKDF,
and AEAD unless you are building a protocol.

### Software Release Signing

Use the implemented ML-DSA primitive signature API for protocol-level signing
tests. Use the high-level `SignedMessage` workflow only after its SDK-managed
format and binding ergonomics are finalized.

### File Encryption

Use `FileEnvelope` once available. Do not reuse raw KEM shared secrets directly
as file encryption keys.

## What Not To Do

- Do not invent custom hybrid combiners.
- Do not use raw shared secrets as encryption keys.
- Do not remove classical cryptography before interoperability is ready.
- Do not claim FIPS certification because an algorithm is standardized.
- Do not use pre-v1.0 releases for production secrets.
