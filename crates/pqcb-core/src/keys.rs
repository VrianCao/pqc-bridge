//! Key containers used by backend and high-level APIs.

use core::fmt;

use zeroize::Zeroizing;

use crate::algorithms::KeyAlgorithm;

/// Public key bytes tagged with an algorithm identifier.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PublicKey {
    algorithm: KeyAlgorithm,
    material: Vec<u8>,
}

impl PublicKey {
    /// Creates a public key from algorithm-tagged key material.
    pub fn new(algorithm: KeyAlgorithm, material: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm,
            material: material.into(),
        }
    }

    /// Returns the key algorithm.
    pub const fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// Returns the public key material.
    pub fn as_bytes(&self) -> &[u8] {
        &self.material
    }

    /// Consumes the key and returns the raw public key bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.material
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("algorithm", &self.algorithm)
            .field("len", &self.material.len())
            .finish_non_exhaustive()
    }
}

/// Secret key bytes tagged with an algorithm identifier.
///
/// Secret material is zeroized on drop and never printed through `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretKey {
    algorithm: KeyAlgorithm,
    material: Zeroizing<Vec<u8>>,
}

impl SecretKey {
    /// Creates a secret key from algorithm-tagged key material.
    pub fn new(algorithm: KeyAlgorithm, material: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm,
            material: Zeroizing::new(material.into()),
        }
    }

    /// Returns the key algorithm.
    pub const fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// Exposes the raw secret key bytes to cryptographic backends.
    pub fn expose_secret(&self) -> &[u8] {
        &self.material
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("algorithm", &self.algorithm)
            .field("len", &self.material.len())
            .field("material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithms::{KemAlgorithm, KeyAlgorithm};

    use super::{PublicKey, SecretKey};

    #[test]
    fn secret_key_debug_redacts_material() {
        let key = SecretKey::new(
            KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
            b"secret".to_vec(),
        );
        let debug = format!("{key:?}");

        assert!(debug.contains("SecretKey"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn public_key_debug_displays_metadata_only() {
        let key = PublicKey::new(
            KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
            b"public".to_vec(),
        );
        let debug = format!("{key:?}");

        assert!(debug.contains("PublicKey"));
        assert!(debug.contains("len"));
        assert!(!debug.contains("public"));
    }
}
