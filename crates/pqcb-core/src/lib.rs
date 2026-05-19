#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
//! Core contracts for PQC Bridge.
//!
//! This crate intentionally contains no placeholder cryptography. It defines
//! algorithm identifiers, key containers, error types, and backend traits that
//! concrete cryptographic providers must implement.

pub mod algorithms;
pub mod envelope;
pub mod errors;
pub mod hybrid;
pub mod kem;
pub mod keys;
pub mod prelude;
pub mod sealed_box;
pub mod secure_session;
pub mod signature;
pub mod signed_message;
pub mod traits;
pub mod version;

pub use algorithms::{HybridKemAlgorithm, KemAlgorithm, KeyAlgorithm, SignatureAlgorithm};
pub use envelope::{
    Envelope, EnvelopeAlgorithm, EnvelopeFlags, EnvelopeObjectType, encode_ml_dsa_65_public_key,
    encode_ml_dsa_65_secret_key, encode_ml_dsa_65_signature, encode_ml_kem_768_ciphertext,
    encode_ml_kem_768_public_key, encode_ml_kem_768_secret_key,
};
pub use errors::{PqcbError, Result};
pub use hybrid::{
    HYBRID_PROFILE_NAME, HYBRID_SHARED_SECRET_LEN, HybridEncapsulation, HybridKeyPair,
    HybridPublicKey, HybridSecretKey, X25519_PUBLIC_KEY_LEN, X25519_SECRET_KEY_LEN,
};
pub use keys::{PublicKey, SecretKey};
pub use sealed_box::{SEALED_BOX_NONCE_LEN, SEALED_BOX_TAG_LEN, SealedBox};
pub use secure_session::{SecureSession, SecureSessionState};
pub use signed_message::SignedMessage;
pub use traits::{
    Encapsulation, KemBackend, KemKeyPair, SignatureBackend, SignatureKeyPair, Verification,
    decapsulate_checked, encapsulate_checked, sign_checked, validate_kem_ciphertext,
    validate_kem_public_key, validate_kem_secret_key, validate_signature,
    validate_signature_public_key, validate_signature_secret_key, verify_checked,
};
