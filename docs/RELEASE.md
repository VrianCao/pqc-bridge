# Release Process

PQC Bridge release maturity is staged.

## Versioning Policy

PQC Bridge uses semantic versioning for stable releases beginning at `1.0.0`.
Before `1.0.0`, any public Rust API, C ABI, CLI, serialized envelope, binding
API, or package layout can change when the change is documented in the
changelog.

After `1.0.0`:

- Patch releases fix bugs, documentation, tests, packaging, and security issues
  without changing stable API or ABI behavior.
- Minor releases may add APIs, algorithms, binding features, optional backend
  capabilities, and non-breaking status codes.
- Major releases are required for breaking public Rust API changes, C ABI major
  changes, incompatible serialized envelope changes, changed default algorithm
  semantics, or binding API removals.
- Security releases may remove or disable a vulnerable algorithm or backend in a
  minor or patch release when continued support would be unsafe. The release
  notes must call out the compatibility impact and migration path.

The stable compatibility surface is:

- public Rust APIs exported by workspace crates intended for external callers
- exported C symbols, status codes, data layout, and ownership rules
- documented command-line behavior
- versioned serialized envelope formats
- first-priority language bindings that ship from this repository
- default algorithm identifiers and their documented semantics

Internal modules, test fixtures, examples, non-default experimental backends,
and undocumented helper functions are not a stable compatibility surface.

## Deprecation Policy

Stable APIs should be deprecated before removal. A deprecation notice must name
the replacement, the earliest removal release, and any security limitations that
made deprecation necessary.

Minimum removal windows after `1.0.0`:

- Public Rust APIs: at least one minor release before removal.
- C ABI symbols: removal only in a new ABI major version.
- CLI flags and commands: at least one minor release before removal unless the
  behavior is unsafe.
- Binding APIs: at least one minor release before removal and aligned with the
  C ABI support window.
- Serialized envelope versions: parsers may retain old readers, but writers
  must only emit the current documented version unless a migration profile says
  otherwise.

Deprecated cryptographic behavior may be disabled sooner if it is unsafe. Such
releases must document the risk, the disabled path, and the replacement.

## Binding Version Alignment

Bindings follow the Rust workspace release version once they are published from
this repository. A binding package must not claim support for a PQC Bridge core
version unless its smoke tests pass against that exact C ABI major version.

Binding compatibility rules:

- Binding major versions align with the supported C ABI major version.
- Binding minor versions may add wrappers for new additive C ABI functions.
- A binding must reject an unsupported C ABI major version at load time.
- A binding may support multiple C ABI minor versions by feature detection.
- Binding release notes must identify the tested Rust crate version, C ABI
  major/minor version, and enabled backend features.

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
- deprecation policy
- binding version alignment policy
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
