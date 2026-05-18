#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
//! `RustCrypto` backend adapter for PQC Bridge.
//!
//! This crate keeps provider-specific types private and maps them into
//! `pqcb-core` traits, key containers, and errors.

#[allow(deprecated)]
use ml_dsa::ExpandedSigningKey;
use ml_dsa::{Generate, Keypair, MlDsa65, Signature, SigningKey, Verifier, VerifyingKey};
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{Decapsulate, Encapsulate, KeyExport, MlKem768, kem::Kem, kem::TryKeyInit};
use pqcb_core::{
    Encapsulation, KemAlgorithm, KemBackend, KemKeyPair, KeyAlgorithm, PqcbError, PublicKey,
    Result, SecretKey, SignatureAlgorithm, SignatureBackend, SignatureKeyPair, Verification,
    validate_kem_ciphertext, validate_kem_public_key, validate_kem_secret_key, validate_signature,
    validate_signature_public_key, validate_signature_secret_key,
};
use zeroize::Zeroizing;

/// KEM primitive facade backed by the default `RustCrypto` provider.
pub mod kem {
    use zeroize::Zeroizing;

    use pqcb_core::{Encapsulation, KemKeyPair, PublicKey, Result, SecretKey};

    use crate::RustCryptoBackend;
    use pqcb_core::{KemBackend, decapsulate_checked, encapsulate_checked};

    /// Generates an ML-KEM-768 keypair.
    ///
    /// # Errors
    ///
    /// Returns backend errors if provider key generation fails.
    pub fn keypair() -> Result<KemKeyPair> {
        KemBackend::keypair(&RustCryptoBackend::new())
    }

    /// Encapsulates a shared secret to `public_key`.
    ///
    /// # Errors
    ///
    /// Returns validation or backend errors.
    pub fn encapsulate(public_key: &PublicKey) -> Result<Encapsulation> {
        encapsulate_checked(&RustCryptoBackend::new(), public_key)
    }

    /// Decapsulates `ciphertext` with `secret_key`.
    ///
    /// # Errors
    ///
    /// Returns validation or backend errors.
    pub fn decapsulate(secret_key: &SecretKey, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decapsulate_checked(&RustCryptoBackend::new(), secret_key, ciphertext)
    }

    /// Creates an ML-KEM-768 public key from raw bytes.
    pub fn public_key(material: impl Into<Vec<u8>>) -> PublicKey {
        pqcb_core::kem::public_key(material)
    }

    /// Creates an ML-KEM-768 secret key from raw bytes.
    pub fn secret_key(material: impl Into<Vec<u8>>) -> SecretKey {
        pqcb_core::kem::secret_key(material)
    }
}

/// Signature primitive facade backed by the default `RustCrypto` provider.
pub mod signature {
    use pqcb_core::{PublicKey, Result, SecretKey, SignatureBackend, SignatureKeyPair};
    use pqcb_core::{Verification, sign_checked, verify_checked};

    use crate::RustCryptoBackend;

    /// Generates an ML-DSA-65 keypair.
    ///
    /// # Errors
    ///
    /// Returns backend errors if provider key generation fails.
    pub fn keypair() -> Result<SignatureKeyPair> {
        SignatureBackend::keypair(&RustCryptoBackend::new())
    }

    /// Signs `message` with `secret_key`.
    ///
    /// # Errors
    ///
    /// Returns validation or backend errors.
    pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>> {
        sign_checked(&RustCryptoBackend::new(), secret_key, message)
    }

    /// Verifies `signature` over `message` with `public_key`.
    ///
    /// # Errors
    ///
    /// Returns validation or backend errors.
    pub fn verify(
        public_key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<Verification> {
        verify_checked(&RustCryptoBackend::new(), public_key, message, signature)
    }
}

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
        let secret_key = SigningKey::<MlDsa65>::generate();
        let public_key = secret_key.verifying_key().encode();

        #[allow(deprecated)]
        let secret_key = secret_key.expanded_key().to_expanded();

        Ok(SignatureKeyPair {
            public_key: PublicKey::new(
                KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
                public_key.as_slice().to_vec(),
            ),
            secret_key: SecretKey::new(
                KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
                secret_key.as_slice().to_vec(),
            ),
        })
    }

    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>> {
        validate_signature_secret_key(SignatureAlgorithm::MlDsa65, secret_key)?;

        let secret_key = expanded_signing_key(secret_key.expose_secret())?;
        let signature =
            secret_key
                .sign_deterministic(message, &[])
                .map_err(|_| PqcbError::CryptoFailure {
                    reason: "ML-DSA-65 signing failed",
                })?;

        Ok(signature.encode().as_slice().to_vec())
    }

    fn verify(
        &self,
        public_key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<Verification> {
        validate_signature_public_key(SignatureAlgorithm::MlDsa65, public_key)?;
        validate_signature(SignatureAlgorithm::MlDsa65, signature)?;

        let public_key = verifying_key(public_key.as_bytes());
        let signature =
            Signature::<MlDsa65>::try_from(signature).map_err(|_| PqcbError::VerificationFailed)?;

        public_key
            .verify(message, &signature)
            .map(|()| Verification::Valid)
            .map_err(|_| PqcbError::VerificationFailed)
    }
}

fn expanded_signing_key(bytes: &[u8]) -> Result<ExpandedSigningKey<MlDsa65>> {
    let bytes: ml_dsa::ExpandedSigningKeyBytes<MlDsa65> =
        bytes.try_into().map_err(|_| PqcbError::CryptoFailure {
            reason: "invalid ML-DSA-65 secret key",
        })?;

    std::panic::catch_unwind(|| {
        #[allow(deprecated)]
        ExpandedSigningKey::<MlDsa65>::from_expanded(&bytes)
    })
    .map_err(|_| PqcbError::CryptoFailure {
        reason: "invalid ML-DSA-65 secret key",
    })
}

fn verifying_key(bytes: &[u8]) -> VerifyingKey<MlDsa65> {
    let bytes: ml_dsa::EncodedVerifyingKey<MlDsa65> = bytes
        .try_into()
        .expect("ML-DSA-65 public key length prevalidated");
    VerifyingKey::<MlDsa65>::decode(&bytes)
}

#[cfg(test)]
mod tests {
    use pqcb_core::{
        KemAlgorithm, KemBackend, KeyAlgorithm, PqcbError, PublicKey, SignatureAlgorithm,
        SignatureBackend, Verification,
        algorithms::{
            ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SECRET_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
            ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_PUBLIC_KEY_LEN, ML_KEM_768_SECRET_KEY_LEN,
            ML_KEM_SHARED_SECRET_LEN,
        },
        decapsulate_checked, encapsulate_checked, sign_checked, verify_checked,
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
    fn ml_dsa_keypair_returns_canonical_lengths() {
        let backend = RustCryptoBackend::new();
        let keypair = SignatureBackend::keypair(&backend).expect("generate ML-DSA keypair");

        assert_eq!(
            keypair.public_key.algorithm(),
            KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65)
        );
        assert_eq!(
            keypair.public_key.as_bytes().len(),
            ML_DSA_65_PUBLIC_KEY_LEN
        );
        assert_eq!(
            keypair.secret_key.algorithm(),
            KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65)
        );
        assert_eq!(
            keypair.secret_key.expose_secret().len(),
            ML_DSA_65_SECRET_KEY_LEN
        );
    }

    #[test]
    fn ml_dsa_sign_verify_round_trip() {
        let backend = RustCryptoBackend::new();
        let keypair = SignatureBackend::keypair(&backend).expect("generate ML-DSA keypair");
        let signature =
            sign_checked(&backend, &keypair.secret_key, b"message").expect("sign message");
        let verification = verify_checked(&backend, &keypair.public_key, b"message", &signature)
            .expect("verify signature");

        assert_eq!(signature.len(), ML_DSA_65_SIGNATURE_LEN);
        assert_eq!(verification, Verification::Valid);
    }

    #[test]
    fn ml_dsa_tampered_message_fails_verification() {
        let backend = RustCryptoBackend::new();
        let keypair = SignatureBackend::keypair(&backend).expect("generate ML-DSA keypair");
        let signature =
            sign_checked(&backend, &keypair.secret_key, b"message").expect("sign message");

        assert_eq!(
            verify_checked(&backend, &keypair.public_key, b"tampered", &signature),
            Err(PqcbError::VerificationFailed)
        );
    }

    #[test]
    fn ml_dsa_wrong_key_fails_verification() {
        let backend = RustCryptoBackend::new();
        let signer = SignatureBackend::keypair(&backend).expect("generate signing keypair");
        let verifier = SignatureBackend::keypair(&backend).expect("generate verifier keypair");
        let signature =
            sign_checked(&backend, &signer.secret_key, b"message").expect("sign message");

        assert_eq!(
            verify_checked(&backend, &verifier.public_key, b"message", &signature),
            Err(PqcbError::VerificationFailed)
        );
    }

    #[test]
    fn ml_dsa_malformed_signature_fails_closed() {
        let backend = RustCryptoBackend::new();
        let keypair = SignatureBackend::keypair(&backend).expect("generate ML-DSA keypair");
        let signature = vec![0; ML_DSA_65_SIGNATURE_LEN];

        assert_eq!(
            verify_checked(&backend, &keypair.public_key, b"message", &signature),
            Err(PqcbError::VerificationFailed)
        );
    }
}
