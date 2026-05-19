# Threat Model

This document defines the security boundaries for PQC Bridge.

## Assets

- long-term secret keys
- session shared secrets
- derived AEAD keys
- message plaintext
- signatures and verification results
- serialized key envelopes

## In-Scope Attackers

- network attackers recording traffic today for future decryption
- network attackers modifying ciphertexts, signatures, or public keys
- malicious clients sending malformed keys or ciphertexts
- dependency confusion and supply-chain attacks
- accidental developer misuse
- replay and downgrade attempts in SDK-managed protocols

## Out of Scope for v0.1

- fully compromised host operating systems
- malicious hardware
- compromised random number generators below the backend layer
- physical side-channel resistance claims
- FIPS 140-3 certification claims
- certificate authority trust decisions
- user identity and account recovery
- key custody and HSM/KMS policy

## Required Controls

- fail closed on unsupported algorithms
- explicit algorithm identifiers
- versioned envelopes
- no placeholder cryptography
- debug redaction for secret material
- KAT coverage for all backend algorithms
- fuzz tests for parsers and envelopes
- downgrade protection in high-level protocols
- dependency review before release

## Envelope Parser Failure Modes

Versioned envelope parsers are part of the security boundary. They must reject
malformed input before returning key, ciphertext, signature, or sealed-message
material to callers. Required rejection cases include:

- invalid magic or unsupported envelope version
- unknown object type, algorithm ID, or invalid object/algorithm pairing
- nonzero reserved flags or unknown required flags
- truncated input, trailing bytes, or `material_length` values that do not match
  the exact input length
- primitive material whose length differs from the canonical algorithm length
- checksum or authentication failure
- secret-key envelopes that omit the `contains_secret` handling signal

Unknown fields in the outer v1 envelope are not allowed. Future metadata must be
authenticated inside high-level material formats or placed in a new envelope
version. Parsers must fail closed instead of skipping unrecognized bytes.

Envelope checksums detect accidental corruption for public objects only. They do
not authenticate attacker-controlled data. Secret-key, sealed-message, and file
envelope material must use authenticated encryption or an equivalent
high-level construction before the envelope is accepted as confidential or
integrity-protected.

## Side-Channel Position

PQC Bridge must not claim side-channel resistance unless the backend and build
profile have been reviewed for that claim. Documentation should distinguish:

- constant-time design intent
- upstream implementation claims
- independent review
- platform-specific limitations

## Quantum Threat Position

PQC Bridge assumes classical public-key cryptography will become insufficient
for long-lived secrets. Hybrid key agreement is the default migration posture
because it reduces dependence on either classical or post-quantum assumptions
alone during the transition period.
