# Architecture

PQC Bridge is designed as a layered SDK rather than a single algorithm library.
The project owns the developer API, key envelopes, backend abstraction, tests,
language bindings, and distribution experience. Concrete cryptographic
implementations are provided by reviewed backends.

## Goals

- Provide safe and simple APIs for ordinary developers.
- Preserve low-level primitive access for advanced protocol work.
- Keep cryptographic implementations replaceable.
- Support cross-platform distribution without duplicating crypto logic.
- Make migration from classical cryptography to hybrid PQC practical.

## Non-Goals

- Implement novel cryptographic algorithms.
- Replace TLS stacks in v0.1.
- Provide FIPS 140-3 certification in v0.1.
- Become a kitchen-sink algorithm zoo.
- Store or escrow application private keys.

## Layer Model

```text
Developer APIs
  SecureSession, SealedBox, SignedMessage, FileEnvelope

Protocol APIs
  HybridKEM, KEM, Signature, AEAD composition, HKDF composition

Primitive APIs
  ML-KEM, ML-DSA, SLH-DSA, X25519, HKDF, AEAD

Backend adapters
  Rust-native, liboqs, OpenSSL/AWS-LC, platform providers

FFI boundary
  Stable C ABI and versioned envelope formats
```

## Core Crates

### pqcb-core

Defines shared SDK contracts:

- algorithm identifiers
- key containers
- backend traits
- error model
- version constants

`pqcb-core` must not contain placeholder cryptography. If no backend is
available, operations must fail closed.

### pqcb-ffi

Exposes the stable C ABI used by language bindings. The ABI starts small and
grows only after an API has tests, memory ownership rules, and compatibility
expectations.

### pqcb-cli

Provides developer tooling for:

- algorithm discovery
- key generation
- message sealing/opening
- signing/verification
- test vector validation
- future migration scans

v0.1 only exposes metadata and planned commands until cryptographic backends are
integrated.

## Backend Strategy

Backends are adapters. They must implement the core traits without leaking
provider-specific types into public SDK APIs.

Candidate backend classes:

- Rust-native backend for audited Rust implementations.
- liboqs backend for broad algorithm compatibility.
- OpenSSL 3.5 or AWS-LC backend for system and server deployments.
- mlkem-native/libcrux style backend for focused high-assurance ML-KEM.

The public API must remain stable even if the default backend changes.

## Language Bindings

All bindings call the same C ABI or a thin Rust-native layer where appropriate.
Language packages should provide idiomatic wrappers, but they must not reimplement
cryptography.

Priority:

1. Node.js
2. Python
3. Go
4. Java/Kotlin
5. Swift
6. WASM
7. C++

## Compatibility Rules

- Algorithm names use NIST names in public APIs.
- Historical names may be accepted as aliases only where helpful.
- Serialized envelope versions are explicit and monotonically upgraded.
- Breaking API changes before v1.0 are allowed but must be documented.
- v1.0 must define semantic versioning and ABI stability guarantees.

## Failure Policy

PQC Bridge must fail closed:

- Unknown algorithms return errors.
- Missing backends return errors.
- Invalid key lengths return errors.
- Verification failure is never silently accepted.
- Secret material is not printed by debug output.
