# Release Process

PQC Bridge release maturity is staged.

## Developer Preview

Developer previews may change APIs and ABI. They are for feedback, integration
testing, and design validation.

Required:

- passing Rust CI
- changelog update
- roadmap update if scope changes
- security disclaimer retained

## Stable Release

Stable releases require:

- semantic versioning policy
- C ABI compatibility policy
- cross-platform CI
- KAT coverage
- fuzzing baseline
- dependency audit
- signed release tags
- generated checksums
- release notes with migration guidance

## Artifact Policy

Release artifacts should eventually include:

- Rust crates
- C headers and libraries
- Node.js package
- Python wheels
- Go module tag
- Java/Kotlin artifacts
- Swift package tag
- WASM package
- SBOM
- checksums
- signatures
