# RFC 0003: Hybrid Composition for SecureSession

Status: Accepted

## Summary

PQC Bridge v0.5 uses a hybrid key agreement profile named
`X25519-ML-KEM-768`. The profile combines a classical X25519 Diffie-Hellman
shared secret with an ML-KEM-768 shared secret, binds both outputs to an
explicit transcript, and derives application traffic keys with HKDF-SHA256.

The profile is a migration construction. Both components must succeed. A
classical-only, post-quantum-only, reordered, or partially authenticated setup
must fail closed instead of silently downgrading.

## Goals

- Preserve classical X25519 interoperability during post-quantum migration.
- Add protection against store-now-decrypt-later attackers through ML-KEM-768.
- Make algorithm negotiation and public setup inputs transcript-bound.
- Keep the public API independent of provider-specific RustCrypto types.
- Avoid FIPS or side-channel overclaims.

## Non-Goals

- Define a full TLS replacement.
- Claim FIPS 140-3 certification.
- Support arbitrary hybrid algorithm negotiation in v0.5.
- Provide replay protection without a caller-supplied transcript value that is
  fresh for the protocol context.

## Profile

| Field | Value |
| --- | --- |
| Stable name | `X25519-ML-KEM-768` |
| Classical component | X25519 |
| Post-quantum component | ML-KEM-768 |
| KDF | HKDF-SHA256 |
| AEAD | XChaCha20-Poly1305 for SDK-managed examples |
| Output secret length | 32 bytes |

The profile name is part of the transcript and HKDF info string. No v0.5 API may
accept a caller-provided algorithm string that omits either component.

## Input Ordering

The combiner input order is fixed:

1. X25519 shared secret.
2. ML-KEM-768 shared secret.
3. Transcript hash.

The transcript hash input order is fixed:

1. Literal domain separator: `PQCB Hybrid v1 transcript`.
2. Hybrid profile name: `X25519-ML-KEM-768`.
3. Initiator X25519 public key.
4. Responder X25519 public key.
5. Responder ML-KEM-768 public key.
6. ML-KEM-768 ciphertext.
7. Caller-supplied context bytes.

The initiator is the party that performs X25519 agreement and ML-KEM
encapsulation. The responder is the party that owns the X25519 static or
ephemeral secret key and the ML-KEM decapsulation secret key. If a protocol uses
different role names, it must still map public inputs into this ordering.

## Transcript Binding

The transcript binds all public setup values that influence the derived secret:

- hybrid profile name
- both X25519 public keys
- ML-KEM-768 public key
- ML-KEM-768 ciphertext
- caller context

The caller context should include protocol name, protocol version, peer identity
binding, channel ID, and a nonce or handshake message hash when replay
protection is required. PQC Bridge can detect altered bound fields by deriving a
different secret, but it cannot detect replay without fresh context supplied by
the embedding protocol.

## HKDF

HKDF-SHA256 uses:

- input keying material: `x25519_shared || ml_kem_shared`
- salt: `SHA256(transcript)`
- info: `PQCB Hybrid v1 X25519-ML-KEM-768 shared secret`
- output length: 32 bytes

Raw X25519 and ML-KEM shared secrets must not be returned to callers by the
high-level hybrid API. They should be held in zeroizing containers where the
implementation can do so.

## AEAD Nonce Policy

The hybrid combiner produces a shared secret only. SDK-managed encrypted
examples derive an AEAD key from the hybrid secret and use XChaCha20-Poly1305.

For one-shot examples:

- nonce length is 24 bytes
- nonces are generated with the operating-system RNG
- nonces are never derived by truncating the hybrid secret
- nonce bytes are public and must be authenticated as AEAD associated data or
  serialized in an authenticated container

Future streaming session APIs must define directional keys and monotonically
increasing nonce state before encrypting multiple records.

## Failure Behavior

The implementation must fail closed when:

- either X25519 or ML-KEM-768 input validation fails
- ML-KEM decapsulation fails or returns an invalid-length secret
- X25519 public keys are malformed
- a caller attempts to use a profile other than `X25519-ML-KEM-768`
- a transcript-bound field is missing from the setup data
- derived output length cannot be produced by HKDF

Both components must succeed before any derived secret is returned. Partial
success must never return a usable secret.

## Downgrade Protection

Downgrade protection is provided by three controls:

1. The profile name includes both algorithms and is transcript-bound.
2. HKDF info includes the full hybrid profile name.
3. APIs expose the v0.5 profile as a single fixed construction rather than a
   negotiation surface.

Tests must show that changing the profile, swapping peer keys, changing the
ML-KEM ciphertext, or changing caller context changes the derived output or
returns an error. No downgrade path may return `Ok` for a classical-only or
post-quantum-only setup.

## Interoperability

Interoperability vectors must record:

- profile name
- initiator and responder X25519 public keys
- responder ML-KEM-768 public key
- ML-KEM-768 ciphertext
- caller context
- derived output checksum
- generation method and implementation version

The vectors should avoid publishing long-term secret keys unless they are
clearly marked test-only. When deterministic secret material is needed for
tests, it must live under `tests/kat/hybrid/` with metadata that prevents
production reuse.

## FIPS and Certification Position

X25519, HKDF-SHA256, XChaCha20-Poly1305, and ML-KEM-768 availability does not
make the hybrid profile FIPS certified. PQC Bridge must not claim FIPS 140-3
validation unless a validated module, version, operating boundary, and exact
configuration are documented.

ML-KEM-768 is standardized by NIST FIPS 203. The v0.5 hybrid composition itself
is a project-defined migration profile and must be described as compatibility
and migration support, not as a certified protocol.

## Risks

- Hybrid composition reduces dependence on any single assumption but does not
  remove implementation, RNG, transcript-design, or replay risks.
- X25519 is not post-quantum secure by itself.
- ML-KEM-768 is not a replacement for peer authentication.
- Caller context quality determines whether replayed setup messages are
  detected by the embedding protocol.

## Follow-up

- Implement the `X25519-ML-KEM-768` combiner behind provider-neutral types.
- Add unit tests for component failure, transcript changes, swapped keys, and
  downgrade attempts.
- Add deterministic interoperability vectors and a runnable example.
- Update `docs/THREAT_MODEL.md` and `docs/MIGRATION.md` with tested behavior.
