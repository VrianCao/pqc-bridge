//! Algorithm identifiers supported by the PQC Bridge API surface.

use core::fmt;
use core::str::FromStr;

use crate::errors::PqcbError;

/// Raw ML-KEM-768 public key length in bytes.
pub const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1_184;
/// Raw ML-KEM-768 secret key length in bytes.
pub const ML_KEM_768_SECRET_KEY_LEN: usize = 2_400;
/// Raw ML-KEM-768 ciphertext length in bytes.
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1_088;
/// ML-KEM shared-secret length in bytes.
pub const ML_KEM_SHARED_SECRET_LEN: usize = 32;
/// Raw ML-DSA-65 public key length in bytes.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1_952;
/// Raw ML-DSA-65 secret key length in bytes.
pub const ML_DSA_65_SECRET_KEY_LEN: usize = 4_032;
/// Raw ML-DSA-65 signature length in bytes.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3_309;

/// Length metadata for a KEM parameter set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KemParameters {
    /// Public key length in bytes.
    pub public_key_len: usize,
    /// Secret key length in bytes.
    pub secret_key_len: usize,
    /// Ciphertext length in bytes.
    pub ciphertext_len: usize,
    /// Shared-secret length in bytes.
    pub shared_secret_len: usize,
}

/// Length metadata for a signature parameter set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureParameters {
    /// Public key length in bytes.
    pub public_key_len: usize,
    /// Secret key length in bytes.
    pub secret_key_len: usize,
    /// Signature length in bytes.
    pub signature_len: usize,
}

/// A post-quantum key encapsulation mechanism.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum KemAlgorithm {
    /// NIST FIPS 203 ML-KEM-768.
    MlKem768,
}

impl KemAlgorithm {
    /// Returns the stable wire/API name for this algorithm.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MlKem768 => "ML-KEM-768",
        }
    }

    /// Returns canonical byte-length metadata for this KEM parameter set.
    pub const fn parameters(self) -> KemParameters {
        match self {
            Self::MlKem768 => KemParameters {
                public_key_len: ML_KEM_768_PUBLIC_KEY_LEN,
                secret_key_len: ML_KEM_768_SECRET_KEY_LEN,
                ciphertext_len: ML_KEM_768_CIPHERTEXT_LEN,
                shared_secret_len: ML_KEM_SHARED_SECRET_LEN,
            },
        }
    }
}

impl fmt::Display for KemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KemAlgorithm {
    type Err = PqcbError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ML-KEM-768" | "ml-kem-768" | "MlKem768" | "kyber768" | "Kyber768" => {
                Ok(Self::MlKem768)
            }
            algorithm => Err(PqcbError::invalid_algorithm(algorithm)),
        }
    }
}

/// A post-quantum digital signature algorithm.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum SignatureAlgorithm {
    /// NIST FIPS 204 ML-DSA-65.
    MlDsa65,
}

impl SignatureAlgorithm {
    /// Returns the stable wire/API name for this algorithm.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
        }
    }

    /// Returns canonical byte-length metadata for this signature parameter set.
    pub const fn parameters(self) -> SignatureParameters {
        match self {
            Self::MlDsa65 => SignatureParameters {
                public_key_len: ML_DSA_65_PUBLIC_KEY_LEN,
                secret_key_len: ML_DSA_65_SECRET_KEY_LEN,
                signature_len: ML_DSA_65_SIGNATURE_LEN,
            },
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SignatureAlgorithm {
    type Err = PqcbError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ML-DSA-65" | "ml-dsa-65" | "MlDsa65" | "dilithium3" | "Dilithium3" => {
                Ok(Self::MlDsa65)
            }
            algorithm => Err(PqcbError::invalid_algorithm(algorithm)),
        }
    }
}

/// A hybrid key agreement profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum HybridKemAlgorithm {
    /// Hybrid profile combining X25519 and NIST FIPS 203 ML-KEM-768.
    X25519MlKem768,
}

impl HybridKemAlgorithm {
    /// Returns the stable wire/API name for this algorithm.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X25519MlKem768 => "X25519-ML-KEM-768",
        }
    }
}

impl fmt::Display for HybridKemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HybridKemAlgorithm {
    type Err = PqcbError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X25519-ML-KEM-768" | "x25519-ml-kem-768" | "X25519MLKEM768" | "x25519mlkem768" => {
                Ok(Self::X25519MlKem768)
            }
            algorithm => Err(PqcbError::invalid_algorithm(algorithm)),
        }
    }
}

/// Algorithm identifier attached to a key object.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum KeyAlgorithm {
    /// A key used with a KEM.
    Kem(KemAlgorithm),
    /// A key used with a digital signature algorithm.
    Signature(SignatureAlgorithm),
    /// A key used with a hybrid key agreement profile.
    HybridKem(HybridKemAlgorithm),
}

impl KeyAlgorithm {
    /// Returns the stable wire/API name for this algorithm.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kem(algorithm) => algorithm.as_str(),
            Self::Signature(algorithm) => algorithm.as_str(),
            Self::HybridKem(algorithm) => algorithm.as_str(),
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HybridKemAlgorithm, KemAlgorithm, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SECRET_KEY_LEN,
        ML_DSA_65_SIGNATURE_LEN, ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_PUBLIC_KEY_LEN,
        ML_KEM_768_SECRET_KEY_LEN, ML_KEM_SHARED_SECRET_LEN, SignatureAlgorithm,
    };

    #[test]
    fn accepts_canonical_and_legacy_algorithm_names() {
        assert_eq!(
            "ML-KEM-768".parse::<KemAlgorithm>(),
            Ok(KemAlgorithm::MlKem768)
        );
        assert_eq!(
            "kyber768".parse::<KemAlgorithm>(),
            Ok(KemAlgorithm::MlKem768)
        );
        assert_eq!(
            "ML-DSA-65".parse::<SignatureAlgorithm>(),
            Ok(SignatureAlgorithm::MlDsa65)
        );
        assert_eq!(
            "dilithium3".parse::<SignatureAlgorithm>(),
            Ok(SignatureAlgorithm::MlDsa65)
        );
        assert_eq!(
            "x25519mlkem768".parse::<HybridKemAlgorithm>(),
            Ok(HybridKemAlgorithm::X25519MlKem768)
        );
    }

    #[test]
    fn ml_kem_768_parameters_match_fips_lengths() {
        let parameters = KemAlgorithm::MlKem768.parameters();

        assert_eq!(parameters.public_key_len, ML_KEM_768_PUBLIC_KEY_LEN);
        assert_eq!(parameters.secret_key_len, ML_KEM_768_SECRET_KEY_LEN);
        assert_eq!(parameters.ciphertext_len, ML_KEM_768_CIPHERTEXT_LEN);
        assert_eq!(parameters.shared_secret_len, ML_KEM_SHARED_SECRET_LEN);
        assert_eq!(parameters.public_key_len, 1_184);
        assert_eq!(parameters.secret_key_len, 2_400);
        assert_eq!(parameters.ciphertext_len, 1_088);
        assert_eq!(parameters.shared_secret_len, 32);
    }

    #[test]
    fn ml_dsa_65_parameters_match_fips_lengths() {
        let parameters = SignatureAlgorithm::MlDsa65.parameters();

        assert_eq!(parameters.public_key_len, ML_DSA_65_PUBLIC_KEY_LEN);
        assert_eq!(parameters.secret_key_len, ML_DSA_65_SECRET_KEY_LEN);
        assert_eq!(parameters.signature_len, ML_DSA_65_SIGNATURE_LEN);
        assert_eq!(parameters.public_key_len, 1_952);
        assert_eq!(parameters.secret_key_len, 4_032);
        assert_eq!(parameters.signature_len, 3_309);
    }
}
