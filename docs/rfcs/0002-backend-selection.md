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
