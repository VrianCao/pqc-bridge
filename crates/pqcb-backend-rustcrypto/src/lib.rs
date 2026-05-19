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

/// Sealed-box facade backed by ML-KEM-768 and XChaCha20-Poly1305.
pub mod sealed_box {
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    };
    use hkdf::Hkdf;
    use pqcb_core::{PqcbError, PublicKey, Result, SEALED_BOX_NONCE_LEN, SealedBox, SecretKey};
    use sha2::Sha256;
    use zeroize::Zeroizing;

    const AAD: &[u8] = b"PQCB SealedBox v1 ML-KEM-768 XChaCha20-Poly1305";
    const HKDF_INFO: &[u8] = b"PQCB SealedBox v1 ML-KEM-768 AEAD key";

    /// Seals `plaintext` to `public_key`.
    ///
    /// # Errors
    ///
    /// Returns validation, backend, KDF, or AEAD errors.
    pub fn seal(public_key: &PublicKey, plaintext: &[u8]) -> Result<SealedBox> {
        let encapsulation = crate::kem::encapsulate(public_key)?;
        let key = derive_key(
            encapsulation.ciphertext(),
            encapsulation.expose_shared_secret(),
        )?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: AAD,
                },
            )
            .map_err(|_| PqcbError::CryptoFailure {
                reason: "SealedBox encryption failed",
            })?;

        let mut nonce_bytes = [0u8; SEALED_BOX_NONCE_LEN];
        nonce_bytes.copy_from_slice(nonce.as_slice());

        SealedBox::from_parts(encapsulation.ciphertext(), &nonce_bytes, &ciphertext)
    }

    /// Opens `sealed_box` with `secret_key`.
    ///
    /// # Errors
    ///
    /// Returns validation, backend, KDF, or AEAD errors. Wrong keys and tampered
    /// ciphertexts fail closed.
    pub fn open(secret_key: &SecretKey, sealed_box: &SealedBox) -> Result<Vec<u8>> {
        let shared_secret = crate::kem::decapsulate(secret_key, sealed_box.kem_ciphertext())?;
        let key = derive_key(sealed_box.kem_ciphertext(), shared_secret.as_slice())?;
        let cipher = XChaCha20Poly1305::new((&*key).into());

        let nonce = chacha20poly1305::XNonce::from_slice(sealed_box.nonce());

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: sealed_box.ciphertext(),
                    aad: AAD,
                },
            )
            .map_err(|_| PqcbError::CryptoFailure {
                reason: "SealedBox open failed",
            })
    }

    /// Deserializes a sealed box from deterministic bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the sealed box envelope is malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<SealedBox> {
        SealedBox::from_bytes(bytes)
    }

    fn derive_key(kem_ciphertext: &[u8], shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let hkdf = Hkdf::<Sha256>::new(Some(kem_ciphertext), shared_secret);
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(HKDF_INFO, key.as_mut())
            .map_err(|_| PqcbError::CryptoFailure {
                reason: "SealedBox key derivation failed",
            })?;
        Ok(key)
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

    /// Creates an ML-DSA-65 public key from raw bytes.
    pub fn public_key(material: impl Into<Vec<u8>>) -> PublicKey {
        pqcb_core::signature::public_key(material)
    }

    /// Creates an ML-DSA-65 secret key from raw bytes.
    pub fn secret_key(material: impl Into<Vec<u8>>) -> SecretKey {
        pqcb_core::signature::secret_key(material)
    }
}

/// Signed-message facade backed by the default `RustCrypto` provider.
pub mod signed_message {
    use pqcb_core::{PublicKey, Result, SecretKey, SignedMessage, Verification};

    use crate::RustCryptoBackend;

    /// Signs `message` with `secret_key`.
    ///
    /// # Errors
    ///
    /// Returns validation or backend errors.
    pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<SignedMessage> {
        SignedMessage::sign(&RustCryptoBackend::new(), secret_key, message)
    }

    /// Verifies `signed_message` with `public_key`.
    ///
    /// # Errors
    ///
    /// Returns validation errors or `VerificationFailed`.
    pub fn verify(public_key: &PublicKey, signed_message: &SignedMessage) -> Result<Verification> {
        signed_message.verify(&RustCryptoBackend::new(), public_key)
    }

    /// Deserializes a signed message from deterministic bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the signed message is malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<SignedMessage> {
        SignedMessage::from_bytes(bytes)
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
    use crate::sealed_box;

    use pqcb_core::{
        KemAlgorithm, KemBackend, KeyAlgorithm, PqcbError, PublicKey, SealedBox,
        SignatureAlgorithm, SignatureBackend, SignedMessage, Verification,
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

    #[test]
    fn signed_message_sign_verify_and_serialize_round_trip() {
        let backend = RustCryptoBackend::new();
        let keypair = SignatureBackend::keypair(&backend).expect("generate ML-DSA keypair");
        let signed =
            SignedMessage::sign(&backend, &keypair.secret_key, b"message").expect("sign message");
        let encoded = signed.to_bytes().expect("serialize signed message");
        let decoded = SignedMessage::from_bytes(&encoded).expect("deserialize signed message");

        assert_eq!(decoded, signed);
        assert_eq!(
            signed
                .verify(&backend, &keypair.public_key)
                .expect("verify"),
            Verification::Valid
        );
    }

    #[test]
    fn signed_message_tampered_message_fails_verification() {
        let backend = RustCryptoBackend::new();
        let keypair = SignatureBackend::keypair(&backend).expect("generate ML-DSA keypair");
        let signed =
            SignedMessage::sign(&backend, &keypair.secret_key, b"message").expect("sign message");
        let tampered = SignedMessage::from_parts(b"tampered", signed.signature())
            .expect("rebuild signed message");

        assert_eq!(
            tampered.verify(&backend, &keypair.public_key),
            Err(PqcbError::VerificationFailed)
        );
    }

    #[test]
    fn signed_message_tampered_signature_fails_verification() {
        let backend = RustCryptoBackend::new();
        let keypair = SignatureBackend::keypair(&backend).expect("generate ML-DSA keypair");
        let signed =
            SignedMessage::sign(&backend, &keypair.secret_key, b"message").expect("sign message");
        let mut signature = signed.signature().to_vec();
        signature[0] ^= 0xff;
        let tampered = SignedMessage::from_parts(signed.message(), &signature)
            .expect("rebuild signed message");

        assert_eq!(
            tampered.verify(&backend, &keypair.public_key),
            Err(PqcbError::VerificationFailed)
        );
    }

    #[test]
    fn signed_message_wrong_key_fails_verification() {
        let backend = RustCryptoBackend::new();
        let signing_keypair = SignatureBackend::keypair(&backend).expect("generate signer keypair");
        let verifying_keypair =
            SignatureBackend::keypair(&backend).expect("generate verifier keypair");
        let signed = SignedMessage::sign(&backend, &signing_keypair.secret_key, b"message")
            .expect("sign message");

        assert_eq!(
            signed.verify(&backend, &verifying_keypair.public_key),
            Err(PqcbError::VerificationFailed)
        );
    }

    #[test]
    fn sealed_box_round_trip_and_tamper_detection() {
        let backend = RustCryptoBackend::new();
        let keypair = KemBackend::keypair(&backend).expect("generate ML-KEM keypair");
        let sealed = sealed_box::seal(&keypair.public_key, b"payload").expect("seal payload");
        let encoded = sealed.to_bytes().expect("serialize sealed box");
        let decoded = SealedBox::from_bytes(&encoded).expect("deserialize sealed box");
        let opened = sealed_box::open(&keypair.secret_key, &decoded).expect("open sealed box");

        assert_eq!(opened, b"payload");
        assert_eq!(decoded, sealed);
    }

    #[test]
    fn sealed_box_wrong_key_fails_closed() {
        let backend = RustCryptoBackend::new();
        let recipient = KemBackend::keypair(&backend).expect("generate recipient keypair");
        let wrong = KemBackend::keypair(&backend).expect("generate wrong keypair");
        let sealed = sealed_box::seal(&recipient.public_key, b"payload").expect("seal payload");

        assert!(matches!(
            sealed_box::open(&wrong.secret_key, &sealed),
            Err(PqcbError::CryptoFailure { .. })
        ));
    }

    #[test]
    fn sealed_box_tampered_ciphertext_fails_closed() {
        let backend = RustCryptoBackend::new();
        let keypair = KemBackend::keypair(&backend).expect("generate ML-KEM keypair");
        let sealed = sealed_box::seal(&keypair.public_key, b"payload").expect("seal payload");
        let mut tampered_ciphertext = sealed.ciphertext().to_vec();
        tampered_ciphertext[0] ^= 0xff;
        let tampered = SealedBox::from_parts(
            sealed.kem_ciphertext(),
            sealed.nonce(),
            &tampered_ciphertext,
        )
        .expect("rebuild tampered sealed box");

        assert!(matches!(
            sealed_box::open(&keypair.secret_key, &tampered),
            Err(PqcbError::CryptoFailure { .. })
        ));
    }

    #[test]
    fn sealed_box_rejects_malformed_envelope() {
        assert!(matches!(
            sealed_box::from_bytes(b"bad"),
            Err(PqcbError::InvalidEnvelope { .. })
        ));
    }
}
