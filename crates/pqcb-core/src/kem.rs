//! KEM primitive facade.
//!
//! The core crate has no configured provider, so these functions validate
//! caller inputs and then fail closed with `BackendUnavailable`. Provider crates
//! expose matching ergonomic entrypoints backed by concrete implementations.

use zeroize::Zeroizing;

use crate::{
    Encapsulation, KemAlgorithm, KemKeyPair, KeyAlgorithm, PqcbError, PublicKey, Result, SecretKey,
    validate_kem_ciphertext, validate_kem_public_key, validate_kem_secret_key,
};

/// Default KEM algorithm.
pub const DEFAULT_ALGORITHM: KemAlgorithm = KemAlgorithm::MlKem768;

/// Generates a KEM keypair with the default algorithm.
///
/// # Errors
///
/// Returns `BackendUnavailable` because `pqcb-core` does not configure a
/// cryptographic provider.
///
/// ```
/// let error = pqcb_core::kem::keypair().expect_err("no backend in core");
/// assert!(matches!(error, pqcb_core::PqcbError::BackendUnavailable { .. }));
/// ```
pub fn keypair() -> Result<KemKeyPair> {
    keypair_with_algorithm(DEFAULT_ALGORITHM)
}

/// Generates a KEM keypair for `algorithm`.
///
/// # Errors
///
/// Returns `BackendUnavailable` because `pqcb-core` does not configure a
/// cryptographic provider.
pub fn keypair_with_algorithm(algorithm: KemAlgorithm) -> Result<KemKeyPair> {
    Err(PqcbError::backend_unavailable(algorithm.as_str()))
}

/// Encapsulates a shared secret to `public_key` with the default algorithm.
///
/// # Errors
///
/// Returns input validation errors before returning `BackendUnavailable`.
pub fn encapsulate(public_key: &PublicKey) -> Result<Encapsulation> {
    validate_kem_public_key(DEFAULT_ALGORITHM, public_key)?;
    Err(PqcbError::backend_unavailable(DEFAULT_ALGORITHM.as_str()))
}

/// Decapsulates `ciphertext` with `secret_key` and the default algorithm.
///
/// # Errors
///
/// Returns input validation errors before returning `BackendUnavailable`.
pub fn decapsulate(secret_key: &SecretKey, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    validate_kem_secret_key(DEFAULT_ALGORITHM, secret_key)?;
    validate_kem_ciphertext(DEFAULT_ALGORITHM, ciphertext)?;
    Err(PqcbError::backend_unavailable(DEFAULT_ALGORITHM.as_str()))
}

/// Creates a public key for the default KEM algorithm.
pub fn public_key(material: impl Into<Vec<u8>>) -> PublicKey {
    PublicKey::new(KeyAlgorithm::Kem(DEFAULT_ALGORITHM), material)
}

/// Creates a secret key for the default KEM algorithm.
pub fn secret_key(material: impl Into<Vec<u8>>) -> SecretKey {
    SecretKey::new(KeyAlgorithm::Kem(DEFAULT_ALGORITHM), material)
}

#[cfg(test)]
mod tests {
    use crate::algorithms::{
        ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_PUBLIC_KEY_LEN, ML_KEM_768_SECRET_KEY_LEN,
    };

    use super::*;

    #[test]
    fn no_backend_keypair_fails_closed() {
        assert_eq!(keypair(), Err(PqcbError::backend_unavailable("ML-KEM-768")));
    }

    #[test]
    fn no_backend_encapsulate_validates_then_fails_closed() {
        let key = public_key(vec![0; ML_KEM_768_PUBLIC_KEY_LEN]);

        assert_eq!(
            encapsulate(&key),
            Err(PqcbError::backend_unavailable("ML-KEM-768"))
        );
    }

    #[test]
    fn no_backend_decapsulate_validates_then_fails_closed() {
        let key = secret_key(vec![0; ML_KEM_768_SECRET_KEY_LEN]);
        let ciphertext = vec![0; ML_KEM_768_CIPHERTEXT_LEN];

        assert_eq!(
            decapsulate(&key, &ciphertext),
            Err(PqcbError::backend_unavailable("ML-KEM-768"))
        );
    }
}
