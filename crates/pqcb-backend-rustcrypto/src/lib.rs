#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
//! `RustCrypto` backend adapter for PQC Bridge.
//!
//! This crate keeps provider-specific types private and maps them into
//! `pqcb-core` traits, key containers, and errors.

#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{Decapsulate, Encapsulate, KeyExport, MlKem768, kem::Kem, kem::TryKeyInit};
use pqcb_core::{
    Encapsulation, KemAlgorithm, KemBackend, KemKeyPair, KeyAlgorithm, PqcbError, PublicKey,
    Result, SecretKey, SignatureAlgorithm, SignatureBackend, SignatureKeyPair, Verification,
    validate_kem_ciphertext, validate_kem_public_key, validate_kem_secret_key,
};
use zeroize::Zeroizing;

/// `RustCrypto` backend adapter.
///
/// The type is intentionally provider-neutral at its public boundary. Provider
/// types stay private to this crate.
#[derive(Clone, Copy, Debug, Default)]
pub struct RustCryptoBackend;

impl RustCryptoBackend {
    /// Creates a backend handle.
    pub const fn new() -> Self {
        Self
    }
}

impl KemBackend for RustCryptoBackend {
    fn algorithm(&self) -> KemAlgorithm {
        KemAlgorithm::MlKem768
    }

    fn keypair(&self) -> Result<KemKeyPair> {
        let (secret_key, public_key) = MlKem768::generate_keypair();

        #[allow(deprecated)]
        let secret_key = secret_key.to_expanded_bytes();
        let public_key = public_key.to_bytes();

        Ok(KemKeyPair {
            public_key: PublicKey::new(
                KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
                public_key.as_slice().to_vec(),
            ),
            secret_key: SecretKey::new(
                KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
                secret_key.as_slice().to_vec(),
            ),
        })
    }

    fn encapsulate(&self, public_key: &PublicKey) -> Result<Encapsulation> {
        validate_kem_public_key(KemAlgorithm::MlKem768, public_key)?;

        let public_key = ml_kem::ml_kem_768::EncapsulationKey::new_from_slice(
            public_key.as_bytes(),
        )
        .map_err(|_| PqcbError::CryptoFailure {
            reason: "invalid ML-KEM-768 public key",
        })?;
        let (ciphertext, shared_secret) = public_key.encapsulate();

        Ok(Encapsulation::new(
            ciphertext.as_slice().to_vec(),
            shared_secret.as_slice().to_vec(),
        ))
    }

    fn decapsulate(&self, secret_key: &SecretKey, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        validate_kem_secret_key(KemAlgorithm::MlKem768, secret_key)?;
        validate_kem_ciphertext(KemAlgorithm::MlKem768, ciphertext)?;

        #[allow(deprecated)]
        let secret_key_bytes: ml_kem::ml_kem_768::ExpandedDecapsulationKey = secret_key
            .expose_secret()
            .try_into()
            .map_err(|_| PqcbError::CryptoFailure {
                reason: "invalid ML-KEM-768 secret key",
            })?;
        #[allow(deprecated)]
        let secret_key = ml_kem::ml_kem_768::DecapsulationKey::from_expanded(&secret_key_bytes)
            .map_err(|_| PqcbError::CryptoFailure {
                reason: "invalid ML-KEM-768 secret key",
            })?;
        let ciphertext: ml_kem::ml_kem_768::Ciphertext =
            ciphertext
                .try_into()
                .map_err(|_| PqcbError::CryptoFailure {
                    reason: "invalid ML-KEM-768 ciphertext",
                })?;
        let shared_secret = secret_key.decapsulate(&ciphertext);

        Ok(Zeroizing::new(shared_secret.as_slice().to_vec()))
    }
}

impl SignatureBackend for RustCryptoBackend {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::MlDsa65
    }

    fn keypair(&self) -> Result<SignatureKeyPair> {
        Err(PqcbError::backend_unavailable(
            SignatureAlgorithm::MlDsa65.as_str(),
        ))
    }

    fn sign(&self, _secret_key: &SecretKey, _message: &[u8]) -> Result<Vec<u8>> {
        Err(PqcbError::backend_unavailable(
            SignatureAlgorithm::MlDsa65.as_str(),
        ))
    }

    fn verify(
        &self,
        _public_key: &PublicKey,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<Verification> {
        Err(PqcbError::backend_unavailable(
            SignatureAlgorithm::MlDsa65.as_str(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use pqcb_core::{
        KemAlgorithm, KemBackend, KeyAlgorithm, PqcbError, PublicKey, SecretKey,
        SignatureAlgorithm, SignatureBackend,
        algorithms::{
            ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_PUBLIC_KEY_LEN, ML_KEM_768_SECRET_KEY_LEN,
            ML_KEM_SHARED_SECRET_LEN,
        },
        decapsulate_checked, encapsulate_checked,
    };

    use super::RustCryptoBackend;

    #[test]
    fn skeleton_reports_algorithms() {
        let backend = RustCryptoBackend::new();

        assert_eq!(KemBackend::algorithm(&backend), KemAlgorithm::MlKem768);
        assert_eq!(
            SignatureBackend::algorithm(&backend),
            SignatureAlgorithm::MlDsa65
        );
    }

    #[test]
    fn ml_kem_keypair_returns_canonical_lengths() {
        let backend = RustCryptoBackend::new();
        let keypair = KemBackend::keypair(&backend).expect("generate ML-KEM keypair");

        assert_eq!(
            keypair.public_key.algorithm(),
            KeyAlgorithm::Kem(KemAlgorithm::MlKem768)
        );
        assert_eq!(
            keypair.public_key.as_bytes().len(),
            ML_KEM_768_PUBLIC_KEY_LEN
        );
        assert_eq!(
            keypair.secret_key.algorithm(),
            KeyAlgorithm::Kem(KemAlgorithm::MlKem768)
        );
        assert_eq!(
            keypair.secret_key.expose_secret().len(),
            ML_KEM_768_SECRET_KEY_LEN
        );
    }

    #[test]
    fn ml_kem_encapsulate_decapsulate_round_trip() {
        let backend = RustCryptoBackend::new();
        let keypair = KemBackend::keypair(&backend).expect("generate ML-KEM keypair");
        let encapsulation =
            encapsulate_checked(&backend, &keypair.public_key).expect("encapsulate");
        let decapsulated =
            decapsulate_checked(&backend, &keypair.secret_key, encapsulation.ciphertext())
                .expect("decapsulate");

        assert_eq!(encapsulation.ciphertext().len(), ML_KEM_768_CIPHERTEXT_LEN);
        assert_eq!(
            encapsulation.expose_shared_secret().len(),
            ML_KEM_SHARED_SECRET_LEN
        );
        assert_eq!(decapsulated.len(), ML_KEM_SHARED_SECRET_LEN);
        assert_eq!(
            encapsulation.expose_shared_secret(),
            decapsulated.as_slice()
        );
    }

    #[test]
    fn ml_kem_invalid_lengths_fail_before_provider_decode() {
        let backend = RustCryptoBackend::new();
        let public_key = PublicKey::new(
            KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
            vec![0; ML_KEM_768_PUBLIC_KEY_LEN - 1],
        );

        assert_eq!(
            backend.encapsulate(&public_key),
            Err(PqcbError::invalid_length(
                "ml_kem_768.public_key",
                ML_KEM_768_PUBLIC_KEY_LEN,
                ML_KEM_768_PUBLIC_KEY_LEN - 1,
            ))
        );
    }

    #[test]
    fn signature_operations_fail_closed_until_adapter_lands() {
        let backend = RustCryptoBackend::new();
        let public_key = PublicKey::new(
            KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
            Vec::new(),
        );
        let secret_key = SecretKey::new(
            KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
            Vec::new(),
        );

        assert_eq!(
            SignatureBackend::keypair(&backend),
            Err(PqcbError::backend_unavailable("ML-DSA-65"))
        );
        assert_eq!(
            backend.sign(&secret_key, b"message"),
            Err(PqcbError::backend_unavailable("ML-DSA-65"))
        );
        assert_eq!(
            backend.verify(&public_key, b"message", b"signature"),
            Err(PqcbError::backend_unavailable("ML-DSA-65"))
        );
    }
}
