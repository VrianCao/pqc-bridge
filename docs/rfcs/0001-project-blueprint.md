# RFC 0001: Project Blueprint

## Summary

PQC Bridge is a cross-platform post-quantum cryptography SDK for ordinary
application developers and infrastructure teams.

## Motivation

Post-quantum cryptography is moving from research to deployment, but most
application developers still face three barriers:

- choosing safe algorithms
- composing primitives correctly
- distributing working implementations across languages and platforms

PQC Bridge addresses those barriers with safe defaults, high-level APIs,
low-level expert APIs, and a common core behind many language bindings.

## Decisions

- Project name: PQC Bridge.
- Package/CLI short name: `pqcb`.
- Core language: Rust.
- Cross-language boundary: C ABI.
- First binding targets: Node.js, Python, Go.
- Later binding targets: Java, Kotlin, Swift, WASM, C++.
- Default KEM: ML-KEM-768.
- Default signature: ML-DSA-65.
- Default migration mode: X25519 + ML-KEM-768 hybrid.
- License: Apache-2.0 OR MIT.

## API Model

PQC Bridge provides two layers:

- high-level scenario APIs for ordinary developers
- low-level primitive APIs for experts

The high-level API is recommended by default.

## Scope

v0.1 initializes repository structure, API contracts, governance, and CI.

v0.1 does not provide production cryptography.

## Alternatives Considered

### Algorithm library first

Rejected for v0.1. Existing projects already provide algorithm implementations.
PQC Bridge should focus on developer experience, safe composition, and
cross-platform distribution.

### Single-language SDK

Rejected. The project goal is broad adoption. A single-language implementation
would not match that goal.

### High-level API only

Rejected. It would help ordinary developers, but block protocol engineers and
security teams from adopting the SDK in infrastructure contexts.
