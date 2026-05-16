# FIPS Position

PQC Bridge targets compatibility with NIST post-quantum cryptography standards,
including FIPS 203, FIPS 204, and FIPS 205 where implemented.

Compatibility with a FIPS algorithm standard is not the same as FIPS 140-3
module validation.

## v0.1 Position

PQC Bridge v0.1 is not FIPS 140-3 certified and does not include production
cryptographic backends.

## Future Options

Potential paths:

- use a validated provider where possible
- expose provider metadata clearly
- separate FIPS-oriented backend builds
- document exact module boundaries
- avoid implying certification for the SDK as a whole

Any future FIPS-oriented claim must be reviewed by qualified specialists.
