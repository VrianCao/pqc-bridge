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
