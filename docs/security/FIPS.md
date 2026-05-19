# FIPS Position

PQC Bridge targets compatibility with NIST post-quantum cryptography standards,
including FIPS 203, FIPS 204, and FIPS 205 where implemented.

Compatibility with a FIPS algorithm standard is not the same as FIPS 140-3
module validation.

## Current Position

PQC Bridge is not FIPS 140-3 certified, validated, or listed as a validated
cryptographic module. The repository must not describe itself, its Rust crates,
its C ABI, or its language bindings as FIPS certified.

The default backend path uses pinned RustCrypto `ml-kem` and `ml-dsa` crates for
FIPS 203 and FIPS 204 algorithm compatibility. That statement is limited to the
implemented algorithm standards and does not extend to module validation,
operational environments, entropy sources, key management, or binding packages.

No PQC Bridge release has completed an independent FIPS lab review,
Cryptographic Module Validation Program validation, or project-sponsored
side-channel audit. Upstream implementation notes, project KAT results, parser
fuzzing, FFI fuzzing, and release attestations are supporting evidence for
engineering review, not certification.

## Claim Boundaries

Allowed language:

- "targets compatibility with FIPS 203 ML-KEM"
- "targets compatibility with FIPS 204 ML-DSA"
- "does not claim FIPS 140-3 validation"
- "uses pinned upstream RustCrypto crates through a PQC Bridge adapter"

Disallowed language unless a validated module and operating boundary are
documented:

- "FIPS certified"
- "FIPS validated"
- "FIPS compliant" for the SDK as a whole
- "validated module" for PQC Bridge crates or bindings
- "certified side-channel resistant"

Any customer, release, registry, or README wording that mentions FIPS must keep
this distinction visible.

## Audit Readiness

A future FIPS-oriented or side-channel review must define:

- exact crate, provider, and dependency versions
- enabled Cargo features and build profiles
- target triples, CPU feature assumptions, and operating environments
- entropy source assumptions for server, mobile, WASM, and embedded targets
- module boundaries for Rust core, backend adapter, C ABI, and language
  bindings
- KAT, negative-test, fuzz, and release-artifact evidence included in the review
- open risks and excluded threats

## Future Options

Potential paths:

- use a validated provider where possible
- expose provider metadata clearly
- separate FIPS-oriented backend builds
- document exact module boundaries
- avoid implying certification for the SDK as a whole

Any future FIPS-oriented claim must be reviewed by qualified specialists.
