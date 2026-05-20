# Security Review Plan

PQC Bridge has not completed an independent security audit. This plan defines
the external review scope required before any release is advertised for
production secrets.

## Reporting Channel

GitHub Private Vulnerability Reporting is enabled for this repository. Reports
must use the repository Security tab or:

```text
https://github.com/VrianCao/pqc-bridge/security/advisories/new
```

Public issues are not an accepted vulnerability reporting channel.

## Review Scope

The first external review should cover:

- RustCrypto backend adapter calls for ML-KEM-768, ML-DSA-65, and
  X25519-ML-KEM-768 hybrid composition.
- Key envelope parsing, checksum handling, and fail-closed behavior for
  malformed input.
- C ABI status codes, fixed-width ABI types, buffer ownership, explicit free
  functions, and language binding marshaling.
- Node.js, Python, and Go primitive binding smoke paths, including unsupported
  ABI major-version rejection.
- Release workflow gates for signed tags, dependency audit, fuzz target build
  checks, checksums, SBOM generation, artifact upload, and attestations.
- Documentation claim boundaries for FIPS, side-channel posture, platform
  limitations, and supported versions.

## Evidence Package

Maintainers must provide reviewers with:

- exact git commit, release tag, and signed tag verification output
- `cargo test --workspace --all-targets --all-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- KAT manifests and harness output for ML-KEM-768, ML-DSA-65, and hybrid vectors
- bounded fuzz build and smoke-run output for `envelope_decode` and
  `ffi_primitives`
- Node.js, Python, Go, Java, Swift, and C/C++ binding gate output
- dependency audit, license review, SBOM, checksums, and provenance attestation
  verification output

## Exit Criteria

A production-supported release must not proceed until:

- all critical and high findings are fixed or explicitly accepted with a
  documented compensating control
- medium findings that affect memory safety, key material handling, release
  integrity, or certification claims are fixed or moved to release-blocking
  follow-up items
- release notes identify the review scope, reviewer, reviewed commit/tag,
  unresolved limitations, and excluded threats
- SECURITY.md contains an active private reporting process

## Non-Goals

This plan does not claim FIPS 140-3 validation, side-channel resistance, or a
completed audit. It defines the evidence and gates required for a future review.
