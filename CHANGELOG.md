# Changelog

All notable changes to PQC Bridge will be documented in this file.

The format is based on Keep a Changelog, and this project intends to follow
Semantic Versioning once it reaches v1.0.

## [Unreleased]

### Breaking Changes

- Use this section for any public Rust API break, C ABI major-version change,
  serialized envelope incompatibility, binding API removal, CLI incompatibility,
  or default algorithm semantic change. Each entry must include migration notes
  and the affected packages or ABI symbols.

### Security

- Use this section for vulnerability fixes, disabled unsafe algorithms or
  backends, side-channel guidance changes, and compatibility breaks required for
  safety.

### Added

- Use this section for new APIs, algorithms, bindings, commands, docs, tests,
  and additive C ABI symbols or status codes.

### Changed

- Use this section for behavior changes that keep the stable compatibility
  contract intact. Any potentially breaking change belongs in
  `Breaking Changes`.

### Deprecated

- Use this section for APIs, symbols, commands, or binding features scheduled
  for removal. Include the replacement and earliest removal release.

### Removed

- Use this section for removals. Stable removals after v1.0 must either be in a
  major release or be justified by a security issue.

### Fixed

- Use this section for bug fixes that preserve compatibility.

## [0.1.0] - Unreleased

### Added

- Initial Rust workspace.
- Core algorithm identifiers and backend traits.
- C ABI version scaffold.
- CLI command scaffold.
- C/C++ header scaffold.
- Architecture, roadmap, security, and governance documents.
