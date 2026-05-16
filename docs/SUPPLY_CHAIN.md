# Supply Chain

PQC Bridge should become a supply-chain-conscious cryptography project before
stable release.

## Current State

v0.1 includes:

- lockfiles for Rust and Node.js
- Dependabot configuration
- cargo-deny configuration
- GitHub Actions CI
- release workflow scaffold

## Required Before Stable Release

- SBOM generation
- release checksums
- signed git tags
- signed release artifacts
- provenance attestations where practical
- dependency review workflow
- documented package publishing ownership
- reproducible build notes for native artifacts

## Package Registries

Planned packages:

- crates.io: Rust crates and CLI
- npm: Node.js package
- PyPI: Python package
- Maven Central: Java/Kotlin artifacts
- Swift Package Manager: GitHub tag-based package
- GitHub Releases: native C/C++ artifacts

## Backend Provenance

Every backend integration must document:

- upstream repository
- exact version or commit
- license
- maintainer status
- KAT source
- platform support
- known limitations
