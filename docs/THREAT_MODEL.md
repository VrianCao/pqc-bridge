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

## SealedBox Security Notes

`SealedBox` is a one-shot encryption workflow for small payloads. It derives an
AEAD key from the ML-KEM-768 shared secret and KEM ciphertext with HKDF-SHA256,
then encrypts with XChaCha20-Poly1305. The raw KEM shared secret must not be
used directly as an encryption key.

Sealed boxes provide recipient confidentiality and ciphertext integrity for the
encoded payload. They do not provide sender authentication, replay protection,
large-file streaming, or application-level authorization. Wrong recipient keys,
malformed envelopes, and tampered AEAD ciphertexts must fail closed.

## SecureSession Skeleton Notes

The v0.4 `SecureSession` type is a state-machine skeleton only. It represents
setup, ready, and closed states so bindings can align on lifecycle semantics
before the v0.5 hybrid composition lands.

The skeleton must not silently downgrade to PQ-only or classical-only behavior.
Until X25519 + ML-KEM-768 composition is implemented and tested, hybrid session
setup returns `BackendUnavailable`.

## Hybrid Session Transcript Controls

The v0.5 `X25519-ML-KEM-768` profile binds the hybrid profile name, initiator
X25519 public key, responder X25519 public key, responder ML-KEM-768 public key,
ML-KEM-768 ciphertext, and caller context into the HKDF transcript salt. Tests
cover these downgrade and transcript cases:

- pure `X25519` and pure `ML-KEM-768` names are rejected by the hybrid profile
  parser
- an invalid X25519 public key that produces an all-zero shared secret fails
  closed
- swapping the responder public key fails closed before returning a secret
- altering the initiator public key changes the derived output
- changing caller context, including a replay/freshness value, changes the
  derived output
- tampering with the ML-KEM ciphertext does not authenticate as the original
  setup; ML-KEM implicit rejection produces a different derived output

Replay protection depends on the embedding protocol supplying fresh caller
context, such as a nonce, channel ID, or handshake hash. Replaying the same
setup with the same context is outside the combiner's standalone detection
boundary; replay-sensitive protocols must bind freshness into the context.

## Side-Channel Position

PQC Bridge must not claim side-channel resistance unless the backend, adapter,
FFI boundary, binding layer, and build profile have been reviewed for that
claim. Current claims are limited to the standards implemented, the selected
upstream packages, and the validation performed in this repository.

For the RustCrypto default backend, PQC Bridge records these distinctions:

- `ml-kem` and `ml-dsa` are upstream RustCrypto crates pinned by exact version.
- PQC Bridge has KAT, negative-test, parser fuzz, and FFI fuzz coverage for its
  integration surface.
- PQC Bridge has not completed an independent side-channel audit of the
  upstream crates, the adapter crate, the C ABI, or language bindings.
- FIPS algorithm compatibility does not imply FIPS 140-3 validation.

Platform and build limitations:

- Randomness comes from the configured provider and target OS integration.
  WASM, mobile, embedded, and restricted-sandbox targets need explicit RNG
  validation before being advertised as supported production targets.
- Native CPU features, compiler flags, linker choices, and dependency feature
  changes can affect side-channel posture. Release builds must record the exact
  crate versions, enabled features, target triples, and release profile.
- The C ABI and language bindings copy key, ciphertext, signature, and shared
  secret material across memory ownership boundaries. The FFI surface validates
  lengths and explicit frees, but it is still in audit scope for lifetime,
  zeroization, and accidental logging risks.
- Physical attacks, shared-host microarchitectural attacks, compromised hosts,
  and compromised random number generators below the backend remain outside the
  current security claim boundary.

Audit readiness scope:

- backend adapter calls for ML-KEM-768, ML-DSA-65, and hybrid
  X25519-ML-KEM-768 composition
- key envelope parsing, checksum behavior, and fail-closed error handling
- FFI ownership, buffer free functions, binding marshaling, and crash
  resistance for malformed inputs
- release supply-chain controls, including pinned dependencies, SBOMs,
  checksums, signed tags, and provenance attestations
- documentation language for standards compatibility, review status, platform
  limitations, and certification status

Open risks before a stable production claim:

- independent side-channel review has not been completed
- external audit findings, if any, have not yet been triaged and remediated
- WASM/mobile RNG and target-specific build posture require explicit validation
- optional future providers need the same KAT, fuzz, FFI, and documentation
  gates before being treated as production supported

## Quantum Threat Position

PQC Bridge assumes classical public-key cryptography will become insufficient
for long-lived secrets. Hybrid key agreement is the default migration posture
because it reduces dependence on either classical or post-quantum assumptions
alone during the transition period.
