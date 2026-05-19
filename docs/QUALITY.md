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

Install `cargo-fuzz` before running libFuzzer locally:

```sh
cargo install cargo-fuzz
cargo fuzz build envelope_decode
cargo fuzz run envelope_decode
```

When `cargo-fuzz` is not installed, the target can still be type-checked with:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bin envelope_decode
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
