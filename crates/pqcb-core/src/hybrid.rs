//! Provider-neutral hybrid key agreement containers.

use core::fmt;

use zeroize::Zeroizing;

use crate::{
    HybridKemAlgorithm, KemAlgorithm, PqcbError, PublicKey, Result, SecretKey,
    validate_kem_ciphertext, validate_kem_public_key, validate_kem_secret_key,
};

/// Stable v0.5 hybrid profile name.
pub const HYBRID_PROFILE_NAME: &str = "X25519-ML-KEM-768";
/// X25519 public key length in bytes.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
/// X25519 secret key length in bytes.
pub const X25519_SECRET_KEY_LEN: usize = 32;
/// Hybrid shared-secret output length in bytes.
pub const HYBRID_SHARED_SECRET_LEN: usize = 32;

/// Public inputs needed to encapsulate to a hybrid responder.
#[derive(Clone, Eq, PartialEq)]
pub struct HybridPublicKey {
    x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    kem_public_key: PublicKey,
}

impl HybridPublicKey {
    /// Creates a hybrid public key from X25519 and ML-KEM-768 public material.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the ML-KEM public key is not canonical.
    pub fn from_parts(
        x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
        kem_public_key: PublicKey,
    ) -> Result<Self> {
        validate_kem_public_key(KemAlgorithm::MlKem768, &kem_public_key)?;

        Ok(Self {
            x25519_public_key,
            kem_public_key,
        })
    }

    /// Returns the stable hybrid profile.
    pub const fn algorithm(&self) -> HybridKemAlgorithm {
        HybridKemAlgorithm::X25519MlKem768
    }

    /// Returns the X25519 public key bytes.
    pub const fn x25519_public_key(&self) -> &[u8; X25519_PUBLIC_KEY_LEN] {
        &self.x25519_public_key
    }

    /// Returns the ML-KEM-768 public key.
    pub const fn kem_public_key(&self) -> &PublicKey {
        &self.kem_public_key
    }
}

impl fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridPublicKey")
            .field("algorithm", &self.algorithm())
            .field("x25519_public_key_len", &self.x25519_public_key.len())
            .field("kem_public_key", &self.kem_public_key)
            .finish_non_exhaustive()
    }
}

/// Secret inputs needed to decapsulate a hybrid setup.
#[derive(Clone, Eq, PartialEq)]
pub struct HybridSecretKey {
    x25519_secret_key: Zeroizing<[u8; X25519_SECRET_KEY_LEN]>,
    kem_secret_key: SecretKey,
}

impl HybridSecretKey {
    /// Creates a hybrid secret key from X25519 and ML-KEM-768 secret material.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the ML-KEM secret key is not canonical.
    pub fn from_parts(
        x25519_secret_key: [u8; X25519_SECRET_KEY_LEN],
        kem_secret_key: SecretKey,
    ) -> Result<Self> {
        validate_kem_secret_key(KemAlgorithm::MlKem768, &kem_secret_key)?;

        Ok(Self {
            x25519_secret_key: Zeroizing::new(x25519_secret_key),
            kem_secret_key,
        })
    }

    /// Returns the stable hybrid profile.
    pub const fn algorithm(&self) -> HybridKemAlgorithm {
        HybridKemAlgorithm::X25519MlKem768
    }

    /// Exposes the X25519 secret key bytes to backend code.
    pub fn expose_x25519_secret(&self) -> &[u8; X25519_SECRET_KEY_LEN] {
        &self.x25519_secret_key
    }

    /// Returns the ML-KEM-768 secret key.
    pub const fn kem_secret_key(&self) -> &SecretKey {
        &self.kem_secret_key
    }
}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSecretKey")
            .field("algorithm", &self.algorithm())
            .field("x25519_secret_key", &"<redacted>")
            .field("kem_secret_key", &self.kem_secret_key)
            .finish_non_exhaustive()
    }
}

/// Hybrid public and secret key pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridKeyPair {
    /// Public material sent to the initiator.
    pub public_key: HybridPublicKey,
    /// Secret material kept by the responder.
    pub secret_key: HybridSecretKey,
}

/// Initiator setup message and derived hybrid shared secret.
#[derive(Clone, Eq, PartialEq)]
pub struct HybridEncapsulation {
    initiator_x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    kem_ciphertext: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
}

impl HybridEncapsulation {
    /// Creates a hybrid encapsulation result.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLength` when the ML-KEM ciphertext or derived secret is
    /// not canonical for the v0.5 profile.
    pub fn new(
        initiator_x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
        kem_ciphertext: impl Into<Vec<u8>>,
        shared_secret: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let kem_ciphertext = kem_ciphertext.into();
        validate_kem_ciphertext(KemAlgorithm::MlKem768, &kem_ciphertext)?;

        let shared_secret = shared_secret.into();
        if shared_secret.len() != HYBRID_SHARED_SECRET_LEN {
            return Err(PqcbError::invalid_length(
                "hybrid.shared_secret",
                HYBRID_SHARED_SECRET_LEN,
                shared_secret.len(),
            ));
        }

        Ok(Self {
            initiator_x25519_public_key,
            kem_ciphertext,
            shared_secret: Zeroizing::new(shared_secret),
        })
    }

    /// Returns the initiator X25519 public key.
    pub const fn initiator_x25519_public_key(&self) -> &[u8; X25519_PUBLIC_KEY_LEN] {
        &self.initiator_x25519_public_key
    }

    /// Returns the ML-KEM-768 ciphertext.
    pub fn kem_ciphertext(&self) -> &[u8] {
        &self.kem_ciphertext
    }

    /// Exposes the derived hybrid shared secret to key derivation code.
    pub fn expose_shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

impl fmt::Debug for HybridEncapsulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridEncapsulation")
            .field(
                "initiator_x25519_public_key_len",
                &self.initiator_x25519_public_key.len(),
            )
            .field("kem_ciphertext_len", &self.kem_ciphertext.len())
            .field("shared_secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        KeyAlgorithm,
        algorithms::{
            ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_PUBLIC_KEY_LEN, ML_KEM_768_SECRET_KEY_LEN,
        },
        kem,
    };

    use super::*;

    #[test]
    fn hybrid_key_parts_validate_ml_kem_material() {
        let public_key = kem::public_key(vec![0; ML_KEM_768_PUBLIC_KEY_LEN]);
        let secret_key = kem::secret_key(vec![0; ML_KEM_768_SECRET_KEY_LEN]);

        let public = HybridPublicKey::from_parts([1; X25519_PUBLIC_KEY_LEN], public_key)
            .expect("valid hybrid public key");
        let secret = HybridSecretKey::from_parts([2; X25519_SECRET_KEY_LEN], secret_key)
            .expect("valid hybrid secret key");

        assert_eq!(public.algorithm(), HybridKemAlgorithm::X25519MlKem768);
        assert_eq!(secret.algorithm(), HybridKemAlgorithm::X25519MlKem768);
    }

    #[test]
    fn hybrid_key_rejects_wrong_kem_algorithm() {
        let public_key = PublicKey::new(
            KeyAlgorithm::HybridKem(HybridKemAlgorithm::X25519MlKem768),
            vec![0; ML_KEM_768_PUBLIC_KEY_LEN],
        );

        assert!(matches!(
            HybridPublicKey::from_parts([1; X25519_PUBLIC_KEY_LEN], public_key),
            Err(PqcbError::KeyAlgorithmMismatch { .. })
        ));
    }

    #[test]
    fn hybrid_encapsulation_debug_redacts_secret() {
        let encapsulation = HybridEncapsulation::new(
            [1; X25519_PUBLIC_KEY_LEN],
            vec![2; ML_KEM_768_CIPHERTEXT_LEN],
            vec![3; HYBRID_SHARED_SECRET_LEN],
        )
        .expect("valid encapsulation");
        let debug = format!("{encapsulation:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("3, 3, 3"));
    }
}
