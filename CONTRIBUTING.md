# Contributing

PQC Bridge welcomes contributions that improve safety, portability,
documentation, testing, and developer ergonomics.

## Contribution Priorities

High-value contributions:

- test vectors
- backend adapter reviews
- FFI safety reviews
- language binding ergonomics
- cross-platform CI fixes
- documentation and examples
- fuzz targets
- serialization tests

Avoid:

- novel cryptographic algorithms
- unreviewed algorithm implementations
- API changes without threat-model discussion
- adding dependencies without justification

## Development Setup

```bash
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Pull Request Expectations

- Keep changes scoped.
- Update tests or explain why tests do not apply.
- Update documentation for public API or security behavior changes.
- Do not introduce placeholder cryptography.
- Do not print secret material in logs or debug output.

## Commit Style

Use clear, conventional prefixes where helpful:

- `core:`
- `ffi:`
- `cli:`
- `bindings:`
- `docs:`
- `ci:`
- `security:`

## Security-Sensitive Changes

Changes touching cryptographic operations, key handling, serialization, random
number generation, FFI memory ownership, or backend integration require extra
review before merging.
