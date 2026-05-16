# Maintainers

PQC Bridge is currently maintained by:

| Maintainer | GitHub | Scope |
| --- | --- | --- |
| VrianCao | [@VrianCao](https://github.com/VrianCao) | Project owner, repository administration |

## Maintainer Responsibilities

Maintainers are responsible for:

- preserving the security model
- reviewing backend integrations
- reviewing API and ABI compatibility
- managing releases
- triaging vulnerability reports
- keeping documentation accurate

## Review Ownership

Security-sensitive areas require careful review:

- cryptographic backends
- FFI memory ownership
- key serialization
- randomness
- secret zeroization
- release signing
- dependency and build pipeline changes

## Adding Maintainers

Future maintainers should demonstrate sustained contributions in at least one
area:

- cryptography implementation review
- bindings and platform integration
- CI and release engineering
- documentation and developer experience
- security testing

Maintainer additions should be documented in this file and announced in the
project changelog.
