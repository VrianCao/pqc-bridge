# PQC Bridge

PQC Bridge (`pqcb`) is a developer-friendly, cross-platform post-quantum
cryptography SDK.

The project goal is to make post-quantum security easy to adopt without asking
application developers to become cryptography specialists. PQC Bridge exposes
safe high-level APIs for common workflows while preserving low-level primitive
APIs for protocol engineers and security teams.

> Status: pre-v1.0 developer preview. The repository includes a selected
> RustCrypto backend path, KAT coverage, parser and FFI fuzzing, binding smoke
> tests, and release gates. Do not use it for production secrets until the
> stable release checklist and security review scope are complete.

## Design Principles

- Safe defaults first.
- No custom cryptography.
- NIST-standardized algorithms before experimental algorithms.
- Hybrid migration before abrupt replacement.
- One core implementation strategy, many language bindings.
- Stable wire formats and C ABI boundaries.
- Clear distinction between standards compatibility and FIPS certification.

## Initial Algorithm Profile

| Capability | Default | Standard | Purpose |
| --- | --- | --- | --- |
| KEM | ML-KEM-768 | NIST FIPS 203 | Post-quantum shared secret establishment |
| Signature | ML-DSA-65 | NIST FIPS 204 | Post-quantum signing and verification |
| Hybrid KEM | X25519 + ML-KEM-768 | IETF-style hybrid profile | Migration-safe key agreement |
| Backup signature | SLH-DSA | NIST FIPS 205 | Conservative hash-based fallback, later phase |

## Repository Layout

```text
crates/
  pqcb-core/        Core types, errors, traits, algorithm IDs
  pqcb-ffi/         Stable C ABI boundary
  pqcb-cli/         Developer CLI
bindings/
  node/             Node.js package and primitive smoke binding
  python/           Python package and primitive smoke binding
  go/               Go module and primitive smoke binding
  java/             Java binding baseline
  kotlin/           Android/Kotlin binding baseline
  swift/            Swift package baseline
  wasm/             WebAssembly package baseline
  cpp/              C/C++ headers
docs/
  API_DESIGN.md     High-level and primitive API blueprint
  ARCHITECTURE.md   System architecture
  BACKENDS.md       Backend strategy
  KEY_FORMAT.md     Envelope and serialization strategy
  ROADMAP.md        Product roadmap
  THREAT_MODEL.md   Security boundaries and threat model
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [API Design](docs/API_DESIGN.md)
- [Backend Strategy](docs/BACKENDS.md)
- [Bindings](docs/BINDINGS.md)
- [FAQ](docs/FAQ.md)
- [Glossary](docs/GLOSSARY.md)
- [Migration Guide](docs/MIGRATION.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Compliance Notes](docs/COMPLIANCE.md)
- [Supply Chain](docs/SUPPLY_CHAIN.md)
- [Roadmap](docs/ROADMAP.md)

## Quick Start

Build and test the Rust workspace:

```bash
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo run -p pqcb -- algorithms
```

The CLI includes metadata commands and pre-v1.0 primitive smoke workflows backed
by the selected RustCrypto adapter. Do not treat CLI-generated keys or messages
as production secrets before the stable release checklist and security review
scope are complete.

Runnable Rust examples for the high-level APIs are listed in
[examples/README.md](examples/README.md).

## API Shape

PQC Bridge will expose two API layers.

High-level developer API:

```ts
const session = await pqc.createSecureSession({
  peerPublicKey: serverPublicKey,
  mode: "hybrid"
})

const encrypted = await session.encrypt(message)
const plain = await session.decrypt(encrypted)
```

Low-level primitive API:

```ts
const keyPair = await pqc.kem.keypair("ML-KEM-768")
const result = await pqc.kem.encapsulate(keyPair.publicKey)
const secret = await pqc.kem.decapsulate(keyPair.secretKey, result.ciphertext)
```

## Language Strategy

PQC Bridge uses one core implementation strategy:

```text
Rust core -> C ABI -> language bindings
```

Priority order:

1. Rust core, C ABI, CLI
2. Node.js, Python, Go
3. Java, Kotlin/Android, Swift/iOS, WASM, C++

## Security Notice

PQC Bridge targets compatibility with NIST post-quantum cryptography standards,
but this repository is not FIPS 140-3 certified. Do not use pre-v1.0 releases
to protect production secrets until backend KAT coverage, fuzzing,
side-channel review scope, and release hardening are complete for the advertised
release.

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
