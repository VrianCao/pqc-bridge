# Compliance Notes

This document gives project-level compliance guidance. It is not legal advice.

## Algorithm Standards

PQC Bridge targets NIST-standardized post-quantum algorithms where implemented:

- FIPS 203: ML-KEM
- FIPS 204: ML-DSA
- FIPS 205: SLH-DSA

## FIPS 140-3

PQC Bridge does not claim FIPS 140-3 validation.

Future FIPS-oriented work must clearly identify:

- validated module boundary
- validated provider version
- build configuration
- operating environment
- allowed algorithms
- non-validated code paths

## Export Controls

Cryptographic software may be subject to export-control rules in some
jurisdictions. Users and distributors are responsible for understanding their
own obligations.

## Licenses

The repository is licensed as:

```text
MIT OR Apache-2.0
```

Backend integrations must be reviewed for license compatibility before becoming
default or being distributed in release artifacts.

## Dependencies

Dependency policy:

- avoid unnecessary dependencies
- pin lockfiles for applications and developer tools
- run advisory checks
- review licenses
- document backend provenance

## Trademarks

The project should avoid implying endorsement by NIST, OpenSSL, AWS, Cloudflare,
or any backend provider unless an explicit relationship exists.
