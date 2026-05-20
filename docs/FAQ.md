# FAQ

## Is PQC Bridge production-ready?

No. Pre-v1.0 releases include a selected RustCrypto backend path, KAT coverage,
binding smoke tests, fuzz targets, and release gates, but they are still
developer previews. Do not use them for production secrets until the stable
release checklist and security review scope are complete for the advertised
release.

## Why not implement algorithms from scratch?

PQC Bridge is an SDK and infrastructure layer. Its job is to make safe
post-quantum adoption practical by wrapping reviewed implementations, providing
stable APIs, and reducing developer misuse.

## What should ordinary developers use first?

For protocol engineers, the implemented primitive APIs expose ML-KEM-768,
ML-DSA-65, and a tested X25519-ML-KEM-768 hybrid combiner. Ordinary application
developers should wait for the high-level `SecureSession` API to graduate from
its skeleton state before using SDK-managed sessions.

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
implemented migration profile is:

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

The architecture is designed for many bindings over a shared core. Rust, C ABI,
Node.js, Python, Go, Java, Swift, WASM, and C/C++ build or smoke gates exist in
the repository, with production support still gated on release readiness and
security review.
