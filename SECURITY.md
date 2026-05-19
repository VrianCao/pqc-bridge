# Security Policy

PQC Bridge is security-sensitive software. Please do not report suspected
vulnerabilities through public issues.

## Supported Versions

| Version | Supported |
| --- | --- |
| pre-v1.0 releases | No production-secret support |

Production-secret support begins only after the selected backend, KAT coverage,
fuzzing, release hardening, side-channel notes, and audit readiness scope have
all been reviewed for the release being advertised.

## Reporting a Vulnerability

Send a private report to the maintainers once project security contacts are
published. Until then, do not use PQC Bridge for production secrets.

Reports should include:

- affected version or commit
- platform and build configuration
- vulnerability class
- reproduction steps
- impact assessment
- whether the issue is public elsewhere

## Security Claims

PQC Bridge may target compatibility with NIST standards such as FIPS 203,
FIPS 204, and FIPS 205. That is not the same as FIPS 140-3 module validation.

No FIPS 140-3 certification is claimed by this repository.

No independent side-channel audit is claimed unless a release note or advisory
identifies the reviewer, scope, version, platform, and remaining limitations.
Reports involving timing behavior, memory disclosure, RNG failure, FFI lifetime
issues, binding crashes, key material logging, dependency compromise, or release
artifact integrity are in scope for the private reporting process.

## Disclosure Process

The intended process for stable releases:

1. Acknowledge the report.
2. Triage severity and affected components.
3. Prepare a private fix.
4. Request reporter validation where appropriate.
5. Publish a patched release.
6. Publish an advisory with mitigation guidance.
