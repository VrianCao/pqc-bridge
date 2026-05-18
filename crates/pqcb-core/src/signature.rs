//! Signature primitive facade.
//!
//! The core crate has no configured provider, so these functions validate
//! caller inputs and then fail closed with `BackendUnavailable`. Provider crates
//! expose matching ergonomic entrypoints backed by concrete implementations.

use crate::{
    KeyAlgorithm, PqcbError, PublicKey, Result, SecretKey, SignatureAlgorithm, SignatureKeyPair,
    Verification, validate_signature, validate_signature_public_key, validate_signature_secret_key,
};

/// Default signature algorithm.
pub const DEFAULT_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::MlDsa65;

/// Generates a signature keypair with the default algorithm.
///
/// # Errors
///
/// Returns `BackendUnavailable` because `pqcb-core` does not configure a
/// cryptographic provider.
///
/// ```
/// let error = pqcb_core::signature::keypair().expect_err("no backend in core");
/// assert!(matches!(error, pqcb_core::PqcbError::BackendUnavailable { .. }));
/// ```
pub fn keypair() -> Result<SignatureKeyPair> {
    keypair_with_algorithm(DEFAULT_ALGORITHM)
}

/// Generates a signature keypair for `algorithm`.
///
/// # Errors
///
/// Returns `BackendUnavailable` because `pqcb-core` does not configure a
/// cryptographic provider.
pub fn keypair_with_algorithm(algorithm: SignatureAlgorithm) -> Result<SignatureKeyPair> {
    Err(PqcbError::backend_unavailable(algorithm.as_str()))
}

/// Signs `message` with `secret_key` and the default algorithm.
///
/// # Errors
///
/// Returns input validation errors before returning `BackendUnavailable`.
pub fn sign(secret_key: &SecretKey, _message: &[u8]) -> Result<Vec<u8>> {
    validate_signature_secret_key(DEFAULT_ALGORITHM, secret_key)?;
    Err(PqcbError::backend_unavailable(DEFAULT_ALGORITHM.as_str()))
}

/// Verifies `signature` over `message` with `public_key` and the default
/// algorithm.
///
/// # Errors
///
/// Returns input validation errors before returning `BackendUnavailable`.
pub fn verify(public_key: &PublicKey, _message: &[u8], signature: &[u8]) -> Result<Verification> {
    validate_signature_public_key(DEFAULT_ALGORITHM, public_key)?;
    validate_signature(DEFAULT_ALGORITHM, signature)?;
    Err(PqcbError::backend_unavailable(DEFAULT_ALGORITHM.as_str()))
}

/// Creates a public key for the default signature algorithm.
pub fn public_key(material: impl Into<Vec<u8>>) -> PublicKey {
    PublicKey::new(KeyAlgorithm::Signature(DEFAULT_ALGORITHM), material)
}

/// Creates a secret key for the default signature algorithm.
pub fn secret_key(material: impl Into<Vec<u8>>) -> SecretKey {
    SecretKey::new(KeyAlgorithm::Signature(DEFAULT_ALGORITHM), material)
}

#[cfg(test)]
mod tests {
    use crate::algorithms::{
        ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SECRET_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
    };

    use super::*;

    #[test]
    fn no_backend_keypair_fails_closed() {
        assert_eq!(keypair(), Err(PqcbError::backend_unavailable("ML-DSA-65")));
    }

    #[test]
    fn no_backend_sign_validates_then_fails_closed() {
        let key = secret_key(vec![0; ML_DSA_65_SECRET_KEY_LEN]);

        assert_eq!(
            sign(&key, b"message"),
            Err(PqcbError::backend_unavailable("ML-DSA-65"))
        );
    }

    #[test]
    fn no_backend_verify_validates_then_fails_closed() {
        let key = public_key(vec![0; ML_DSA_65_PUBLIC_KEY_LEN]);
        let sig = vec![0; ML_DSA_65_SIGNATURE_LEN];

        assert_eq!(
            verify(&key, b"message", &sig),
            Err(PqcbError::backend_unavailable("ML-DSA-65"))
        );
    }
}
