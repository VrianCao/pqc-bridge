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
