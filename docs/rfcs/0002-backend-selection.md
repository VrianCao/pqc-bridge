# RFC 0002: First Backend Selection Scoring Matrix

Status: Proposed

## Summary

PQC Bridge v0.2 needs one default production backend path for ML-KEM-768 and
ML-DSA-65. This RFC defines the decision framework used before adding provider
dependencies or exposing provider-backed APIs.

The selection process has two layers:

1. Pass/fail gates that a candidate must satisfy before scoring.
2. A weighted score that compares candidates that pass the gates.

## Candidate Backend Classes

The candidate classes are the backend classes documented in `docs/BACKENDS.md`:

| Class | Intended role | Initial v0.2 fit |
| --- | --- | --- |
| Rust-native backend | Default Rust core backend with small dependency graph and strong memory-safety fit. | Primary candidate class. |
| liboqs backend | Broad algorithm compatibility and experimentation. | Later compatibility backend, not the stable default. |
| OpenSSL/AWS-LC backend | Enterprise and system-provider integration. | Later server-focused backend unless ML-KEM and ML-DSA support is mature and easy to isolate. |
| Focused C backend | Narrow high-assurance or size-sensitive deployments. | Candidate only when provenance, KATs, platform support, and safe FFI ownership are clear. |

## Pass/Fail Gates

A candidate must pass every gate before it can be selected as the default v0.2
backend path.

| Gate | Requirement | Failure result |
| --- | --- | --- |
| Algorithm coverage | Provides ML-KEM-768 and ML-DSA-65, or supports a documented split-backend plan with both algorithms covered. | Candidate cannot be selected as the whole default path. |
| Upstream provenance | Upstream repository, package source, and maintainer ownership are reviewable. | Reject. |
| Version pinning | Integration can pin an exact crate version, release, or commit. | Reject until pinning is possible. |
| KAT availability | Known-answer tests are available from NIST, upstream, or a reproducible generator. | Reject for production default. |
| Constant-time claims | Constant-time claims, review notes, or limitations are documented without overclaiming. | Reject or require explicit risk acceptance. |
| Platform matrix | Supported targets are documented, including native Rust, Linux/macOS/Windows, WASM, and mobile implications. | Reject if project target platforms cannot be supported. |
| Memory safety | Rust-native code or C/FFI ownership and bounds rules are documented. | Reject if ownership cannot be made fail-closed. |
| License compatibility | License is compatible with `MIT OR Apache-2.0` distribution and recorded in supply-chain docs. | Reject. |
| Maintenance status | Recent release or maintainer activity is documented, or a vendoring/fork plan exists. | Reject for default if maintenance risk is unbounded. |
| Public API isolation | Provider-specific types do not appear in public Rust API or C ABI. | Reject implementation design. |

These gates cover every backend requirement listed in `docs/BACKENDS.md`: clear
upstream provenance, version pinning, known-answer tests, constant-time claims or
review notes, platform matrix, memory-safety notes, license compatibility, and
maintenance status.

## Weighted Criteria

Candidates that pass the gates are scored on a 0 to 5 scale for each criterion.
The weighted score is the sum of `score * weight`.

| Criterion | Weight | Scoring guidance |
| --- | ---: | --- |
| Security review and side-channel posture | 25 | FIPS-aligned implementation, documented constant-time design, review status, and clear limitation language. |
| KAT and reproducibility support | 15 | Availability of ML-KEM-768 and ML-DSA-65 KATs, deterministic fixtures, and reproducible generation metadata. |
| Maintenance and upstream health | 15 | Release cadence, issue response, maintainer identity, ecosystem trust, and compatibility with supported Rust versions. |
| Platform support | 12 | Linux, macOS, Windows, WASM, mobile, and `no_std` or allocator constraints where relevant. |
| Dependency footprint | 10 | Small, auditable dependency graph with minimal native build tooling. |
| License and supply-chain fit | 10 | Compatible license, clear package registry source, checksums, and cargo-deny compatibility. |
| API isolation and integration effort | 8 | Ease of hiding provider types behind `pqcb-core` traits and C ABI boundaries. |
| Performance suitability | 5 | Sufficient keygen, encapsulation, signing, and verification performance for SDK defaults. |

Security posture, KAT coverage, and maintenance together account for 55 percent
of the score because they are the highest-risk parts of selecting the first
backend. Performance is intentionally lower weight because the first backend
must be correct and reviewable before it is optimized.

## Scoring Rules

- Scores must cite reviewable evidence from upstream docs, package metadata,
  source code, or project-maintained KAT manifests.
- Unknown evidence scores `0`, not an assumed midpoint.
- A split-backend plan must score each provider separately and then record the
  combined operational risk.
- A candidate cannot override a failed gate with a high weighted score.
- Side-channel and FIPS language must distinguish upstream claims from PQC
  Bridge review status. PQC Bridge must not claim FIPS certification unless a
  validated module and exact operating boundary are documented.

## Candidate Evidence Required Before Decision

Before recording the accepted backend decision, the project must fill a
candidate table with these fields:

| Field | Required content |
| --- | --- |
| Candidate | Provider or split-provider name. |
| Backend class | Rust-native, liboqs, OpenSSL/AWS-LC, focused C, or split. |
| Upstream | Repository and package source. |
| Version policy | Exact crate version, release, commit, or pinning rule. |
| License | License identifier and review note. |
| Algorithms | ML-KEM-768, ML-DSA-65, or split responsibility. |
| KAT source | NIST, upstream, generated, or project fixture source. |
| Platform support | Native, WASM, mobile, and build-tool notes. |
| Maintenance status | Release cadence or maintainer activity summary. |
| Known limitations | Security, portability, API, or certification limitations. |
| Gate result | Pass, fail, or split-plan required. |

## Candidate Provenance Table

Evidence was collected from package metadata and upstream project pages on
2026-05-18. The table is intentionally conservative: unknown audit or
certification status is recorded as a limitation, not inferred.

| Candidate | Backend class | Upstream | Version policy | License | Algorithms | KAT source | Platform support | Maintenance status | Known limitations | Gate result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RustCrypto split provider (`ml-kem` + `ml-dsa`) | Rust-native split | `https://github.com/RustCrypto/KEMs`, `https://github.com/RustCrypto/signatures`, `https://crates.io/crates/ml-kem`, `https://crates.io/crates/ml-dsa` | Pin exact crate versions: `ml-kem = 0.3.2`, `ml-dsa = 0.1.0`; update only with KAT and API review. | `Apache-2.0 OR MIT` for both crates. | `ml-kem` covers ML-KEM, including ML-KEM-768; `ml-dsa` covers ML-DSA, including ML-DSA-65. | Use NIST FIPS 203/204 KAT vectors where available, plus upstream/project deterministic fixtures recorded under `tests/kat/`. | Pure Rust crates with `alloc`; `getrandom` feature for OS randomness; no native C build; WASM/mobile require RNG feature review. | RustCrypto-maintained crates with current crates.io releases and Rust 1.85 compatibility. | Split provider requires one adapter crate to hide two upstream APIs; PQC Bridge has not performed an independent side-channel audit; no FIPS certification claim. | Pass as primary candidate after KAT manifests and adapter isolation are implemented. |
| Open Quantum Safe (`oqs` / liboqs) | liboqs compatibility | `https://github.com/open-quantum-safe/liboqs`, `https://github.com/open-quantum-safe/liboqs-rust`, `https://crates.io/crates/oqs` | Pin Rust wrapper `oqs = 0.11.0` and the vendored/system liboqs release or commit used by `oqs-sys`; do not float C sources. | Rust wrapper is `MIT OR Apache-2.0`; liboqs license and bundled third-party notices must be reviewed before redistribution. | Wrapper exposes `ml_kem` and `ml_dsa` feature families for ML-KEM and ML-DSA parameter sets. | liboqs upstream KATs plus project manifests; project fixtures must record liboqs version and build flags. | Native C library via `oqs-sys`; supports common server platforms; WASM/mobile require separate build validation and toolchain notes. | Open Quantum Safe is active and broadly used for PQC experimentation and interoperability. | Larger native dependency and broad algorithm surface; C/FFI ownership and build reproducibility increase risk; compatibility behavior must not leak into stable public API. | Pass as later compatibility backend, not v0.2 default. |
| rustpq split provider (`pqcrypto-mlkem` + `pqcrypto-mldsa`) | Rust-native wrapper over PQClean-derived implementations | `https://github.com/rustpq/pqcrypto/`, `https://crates.io/crates/pqcrypto-mlkem`, `https://crates.io/crates/pqcrypto-mldsa` | Pin exact crate versions: `pqcrypto-mlkem = 0.1.1`, `pqcrypto-mldsa = 0.1.2`; record enabled SIMD features. | `MIT OR Apache-2.0` for both crates. | Separate crates cover ML-KEM and ML-DSA families, including ML-KEM-768 and ML-DSA-65. | PQClean-derived vectors and project KAT manifests; manifests must record SIMD feature state. | Rust crate surface with generated/native implementation details; default features include `avx2`, `neon`, and `std`; portability needs feature review. | Maintained in the rustpq ecosystem with current crates.io releases. | Default SIMD features may complicate reproducible cross-platform behavior; side-channel and generated-code provenance need deeper review than the RustCrypto path. | Pass as backup Rust-native candidate pending SIMD and provenance review. |
| AWS-LC via `aws-lc-rs` or direct AWS-LC FFI | OpenSSL/AWS-LC system backend | `https://github.com/aws/aws-lc`, `https://github.com/aws/aws-lc-rs`, `https://crates.io/crates/aws-lc-rs` | Pin `aws-lc-rs = 1.17.0` if Rust APIs expose the needed primitives, otherwise pin AWS-LC source release/commit and generated bindings. | `aws-lc-rs` is `ISC AND (Apache-2.0 OR ISC)`; AWS-LC notices must be reviewed for binary redistribution. | AWS-LC has PQC work, but PQC Bridge must verify stable ML-KEM-768 and ML-DSA-65 API exposure before implementation. | AWS-LC upstream tests plus project KAT manifests if APIs are exposed. | Native system/provider backend; server platforms are the main fit; WASM/mobile are not primary targets. | AWS-maintained project with active releases and enterprise deployment fit. | Rust wrapper may not expose all required PQC APIs; native build and provider boundary are heavier than the Rust-native default; FIPS claims require exact validated-module analysis. | Fail for v0.2 default until stable ML-KEM-768 and ML-DSA-65 API exposure is verified. |

## Decision Procedure

1. Populate the candidate evidence table.
2. Apply pass/fail gates.
3. Score all candidates that pass the gates.
4. Record the selected default or split-backend plan in this RFC.
5. Link the accepted decision from `docs/DECISIONS.md` and
   `docs/BACKENDS.md`.
6. Add implementation tasks only after feature names, crate layout, dependency
   pinning, KAT plan, and API isolation are documented.

## Open Follow-up

- Complete the candidate provenance table.
- Record the first production backend decision after evidence review.
- Keep liboqs and OpenSSL/AWS-LC as later compatibility or deployment backend
  candidates unless their v0.2 evidence beats the Rust-native path.
