# Changelog

All notable changes to PQC Bridge will be documented in this file.

The format is based on Keep a Changelog, and this project intends to follow
Semantic Versioning once it reaches v1.0.

## [Unreleased]

### Breaking Changes

- Bumped pre-v1.0 package versions to `0.2.0` because the Rust-callable
  `pqcb-ffi` buffer free helpers now require `unsafe`. Rust callers must wrap
  `pqcb_buffer_free` and `pqcb_buffer_free_parts` calls in `unsafe` blocks and
  uphold the documented PQC Bridge-owned-buffer contract; the C ABI signatures
  are unchanged.

### Security

- Hardened the release workflow with SemVer signed-tag verification,
  dependency audit gates, fuzz target build gates, GitHub Release asset upload,
  and separated read-only source/SBOM generation from privileged artifact
  attestation.
- Documented the active GitHub Private Vulnerability Reporting channel and the
  external security review plan required before production-secret support.

### Added

- Added ABI-major guards to the Node.js, Python, and Go bindings so unsupported
  C ABI majors fail closed before primitive calls.
- Added FFI hardening tests for unknown status messages, aliased output slots,
  and worker-thread panic mapping.

### Changed

- Changed C `PqcbStatus` and `PqcbAlgorithm` declarations to fixed-width
  `uint32_t` typedefs with constants so compiler enum-size flags cannot alter
  the ABI.
- Changed `pqcb_status_message` to accept raw status values and return a stable
  message for unknown codes.

### Fixed

- Rejected aliased multi-output FFI slots before allocation to avoid overwritten
  output handles and leaks.
- Mapped worker-thread panics back to `PQCB_STATUS_PANIC` instead of
  `PQCB_STATUS_CRYPTO_FAILURE`.
- Marked Rust-callable buffer free helpers as `unsafe` and documented their
  ownership contract.

### Verification

- Recorded the v1.0 release readiness dry run for
  `v1-stable-release-hardening`, including local `./scripts/check.sh`,
  release workflow dry-run evidence, checksum/SBOM/provenance generation, and
  explicit dry-run non-publishing rationale. The PR or release notes must name
  the final head SHA and run URL because any later release-affecting commit
  invalidates older dry-run evidence.

## [0.1.0] - Unreleased

### Added

- Initial Rust workspace.
- Core algorithm identifiers and backend traits.
- C ABI version baseline.
- CLI command baseline.
- C/C++ header baseline.
- Architecture, roadmap, security, and governance documents.
