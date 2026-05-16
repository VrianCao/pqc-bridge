# Language Bindings

PQC Bridge uses a shared Rust core and C ABI to avoid reimplementing
cryptography in each language.

## Binding Contract

Each language binding should provide:

- idiomatic package layout
- high-level developer API
- low-level primitive API
- explicit version reporting
- deterministic error mapping
- memory ownership documentation
- examples
- CI build or smoke test

Bindings must not:

- implement independent cryptographic algorithms
- weaken validation performed by the core
- expose secret material through string conversion or debug output
- silently downgrade algorithms

## Priority

1. Node.js
2. Python
3. Go
4. Java
5. Kotlin/Android
6. Swift/iOS
7. WASM
8. C++

## Distribution Notes

Native artifacts should be published only after:

- release signing is defined
- SBOM generation is available
- platform matrix is tested
- backend license review is complete
- security policy is active
