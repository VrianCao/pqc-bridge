# Quality Bar

PQC Bridge should be held to infrastructure-level quality before stable release.

## Required Before v1.0

- cross-platform CI
- backend KAT coverage
- parser fuzzing
- negative tests for malformed inputs
- debug redaction tests
- dependency audit
- license review
- release signing plan
- documented support window
- documented ABI compatibility policy

## Cryptography-Specific Checks

- no placeholder crypto
- no unreviewed default backend
- no secret material in logs
- no secret-dependent parsing shortcuts
- no downgrade without explicit caller consent
- no undocumented algorithm aliases
- KAT manifests include source, algorithm, parameter set, upstream version,
  generation method, license or redistribution terms, checksum, and positive
  and negative expected-result metadata

## Fuzzing

Envelope parsing has a `cargo-fuzz` target at
`fuzz/fuzz_targets/envelope_decode.rs`. It accepts arbitrary bytes and calls the
v1 envelope decoder without requiring secrets, network access, or backend
cryptographic operations.

FFI primitive boundary fuzzing has a target at
`fuzz/fuzz_targets/ffi_primitives.rs`. It exercises borrowed buffers, owned
output buffers, null output guards, length validation, status mapping, and
free-path behavior for ML-KEM-768 and ML-DSA-65 ABI entrypoints.

Seed corpus files live under `fuzz/corpus/`. The envelope corpus includes one
valid v1 public-key envelope and malformed envelope-like inputs. The FFI corpus
includes selector-prefixed inputs for backend availability, invalid primitive
lengths, null output handling, and signature verification status paths.

Install `cargo-fuzz` before running libFuzzer locally:

```sh
cargo install cargo-fuzz
cargo fuzz build envelope_decode
cargo fuzz build ffi_primitives
cargo fuzz run envelope_decode
cargo fuzz run ffi_primitives
```

When `cargo-fuzz` is not installed, the target can still be type-checked with:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bin envelope_decode
cargo check --manifest-path fuzz/Cargo.toml --bin ffi_primitives
```

Stable-release fuzz smoke runs should be bounded and reproducible:

```sh
cargo fuzz run envelope_decode -- -runs=256
cargo fuzz run ffi_primitives -- -runs=256
```

## Binding Checks

Each binding should include:

- package metadata
- version API
- backend availability behavior
- error mapping tests
- README
- release notes

## Documentation Checks

Public API docs should explain:

- when to use KEM
- when to use signatures
- when to use hybrid mode
- what the SDK does not protect against
- FIPS compatibility versus certification
