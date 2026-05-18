#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
//! Core contracts for PQC Bridge.
//!
//! This crate intentionally contains no placeholder cryptography. It defines
//! algorithm identifiers, key containers, error types, and backend traits that
//! concrete cryptographic providers must implement.

pub mod algorithms;
pub mod errors;
pub mod kem;
pub mod keys;
pub mod prelude;
pub mod signature;
pub mod traits;
pub mod version;

pub use algorithms::{HybridKemAlgorithm, KemAlgorithm, KeyAlgorithm, SignatureAlgorithm};
pub use errors::{PqcbError, Result};
pub use keys::{PublicKey, SecretKey};
pub use traits::{
    Encapsulation, KemBackend, KemKeyPair, SignatureBackend, SignatureKeyPair, Verification,
    decapsulate_checked, encapsulate_checked, sign_checked, validate_kem_ciphertext,
    validate_kem_public_key, validate_kem_secret_key, validate_signature,
    validate_signature_public_key, validate_signature_secret_key, verify_checked,
};
