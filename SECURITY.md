# Security Policy

PQC Bridge is security-sensitive software. Please do not report suspected
vulnerabilities through public issues.

## Supported Versions

| Version | Supported |
| --- | --- |
| v0.1 developer preview | No production support |

The repository is in scaffold phase. Production support begins only after a real
cryptographic backend, known-answer tests, fuzzing, and release hardening are in
place.

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

## Disclosure Process

The intended process for stable releases:

1. Acknowledge the report.
2. Triage severity and affected components.
3. Prepare a private fix.
4. Request reporter validation where appropriate.
5. Publish a patched release.
6. Publish an advisory with mitigation guidance.
