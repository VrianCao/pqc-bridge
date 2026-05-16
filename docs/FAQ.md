# FAQ

## Is PQC Bridge production-ready?

No. The v0.1 repository is a developer preview scaffold. It intentionally does
not include production cryptographic backends yet.

## Why not implement algorithms from scratch?

PQC Bridge is an SDK and infrastructure layer. Its job is to make safe
post-quantum adoption practical by wrapping reviewed implementations, providing
stable APIs, and reducing developer misuse.

## What should ordinary developers use first?

Once implemented, the recommended first API will be the high-level
`SecureSession` API using hybrid key agreement.

## What is KEM?

KEM means key encapsulation mechanism. It lets two parties establish a shared
secret over an untrusted network.

## What is ML-KEM?

ML-KEM is the NIST-standardized post-quantum KEM from FIPS 203. It is based on
module lattice assumptions and descends from the CRYSTALS-Kyber design.

## What is ML-DSA?

ML-DSA is the NIST-standardized post-quantum digital signature algorithm from
FIPS 204. It descends from the CRYSTALS-Dilithium design.

## What is hybrid mode?

Hybrid mode combines classical cryptography with post-quantum cryptography. The
default planned profile is:

```text
X25519 + ML-KEM-768
```

This protects deployments during the transition period by avoiding total
dependence on either classical or post-quantum assumptions alone.

## Does PQC Bridge claim FIPS 140-3 certification?

No. Implementing or wrapping a FIPS-standardized algorithm is not the same as
being a FIPS 140-3 validated cryptographic module.

## Why are the first defaults ML-KEM-768 and ML-DSA-65?

They are practical middle security profiles for general application use. Higher
security profiles can be added for users with long-lived or high-value secrets.

## Will PQC Bridge support all languages?

The architecture is designed for many bindings over a shared core. The first
targets are Rust, C ABI, Node.js, Python, and Go. Java, Kotlin, Swift, WASM, and
C++ are planned.
