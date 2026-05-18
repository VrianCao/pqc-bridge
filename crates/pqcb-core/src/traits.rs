//! Backend traits for concrete cryptographic implementations.

use core::fmt;

use zeroize::Zeroizing;

use crate::algorithms::{KemAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use crate::errors::{PqcbError, Result};
use crate::keys::{PublicKey, SecretKey};

/// Public and secret key pair returned by KEM backends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KemKeyPair {
    /// Public key used by peers for encapsulation.
    pub public_key: PublicKey,
    /// Secret key used locally for decapsulation.
    pub secret_key: SecretKey,
}

/// Public and secret key pair returned by signature backends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureKeyPair {
    /// Public key used by peers for verification.
    pub public_key: PublicKey,
    /// Secret key used locally for signing.
    pub secret_key: SecretKey,
}

/// Result of a KEM encapsulation operation.
#[derive(Clone, Eq, PartialEq)]
pub struct Encapsulation {
    ciphertext: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
}

impl Encapsulation {
    /// Creates a new encapsulation result.
    pub fn new(ciphertext: impl Into<Vec<u8>>, shared_secret: impl Into<Vec<u8>>) -> Self {
        Self {
            ciphertext: ciphertext.into(),
            shared_secret: Zeroizing::new(shared_secret.into()),
        }
    }

    /// Returns the ciphertext that must be delivered to the decapsulating peer.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Exposes the shared secret to key derivation code.
    pub fn expose_shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

impl fmt::Debug for Encapsulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encapsulation")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("shared_secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Result of a signature verification operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verification {
    /// The signature was accepted by the backend.
    Valid,
}

/// Interface implemented by ML-KEM capable backends.
pub trait KemBackend: Send + Sync {
    /// Returns the KEM algorithm this backend implements.
    fn algorithm(&self) -> KemAlgorithm;

    /// Generates a KEM key pair.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails or the backend is unavailable.
    fn keypair(&self) -> Result<KemKeyPair>;

    /// Encapsulates a shared secret for `public_key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is invalid, belongs to another
    /// algorithm, or encapsulation fails.
    fn encapsulate(&self, public_key: &PublicKey) -> Result<Encapsulation>;

    /// Decapsulates a shared secret from `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key or ciphertext is invalid, belongs to
    /// another algorithm, or decapsulation fails.
    fn decapsulate(&self, secret_key: &SecretKey, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

/// Validates a KEM public key before invoking a backend.
///
/// # Errors
///
/// Returns `KeyAlgorithmMismatch` or `InvalidLength` when the key is not usable
/// with the requested algorithm.
pub fn validate_kem_public_key(algorithm: KemAlgorithm, public_key: &PublicKey) -> Result<()> {
    let expected = KeyAlgorithm::Kem(algorithm);
    if public_key.algorithm() != expected {
        return Err(PqcbError::KeyAlgorithmMismatch {
            expected: expected.as_str(),
            actual: public_key.algorithm().as_str(),
        });
    }

    let expected_len = algorithm.parameters().public_key_len;
    let actual_len = public_key.as_bytes().len();
    if actual_len != expected_len {
        return Err(PqcbError::invalid_length(
            "ml_kem_768.public_key",
            expected_len,
            actual_len,
        ));
    }

    Ok(())
}

/// Validates a KEM secret key before invoking a backend.
///
/// # Errors
///
/// Returns `KeyAlgorithmMismatch` or `InvalidLength` when the key is not usable
/// with the requested algorithm.
pub fn validate_kem_secret_key(algorithm: KemAlgorithm, secret_key: &SecretKey) -> Result<()> {
    let expected = KeyAlgorithm::Kem(algorithm);
    if secret_key.algorithm() != expected {
        return Err(PqcbError::KeyAlgorithmMismatch {
            expected: expected.as_str(),
            actual: secret_key.algorithm().as_str(),
        });
    }

    let expected_len = algorithm.parameters().secret_key_len;
    let actual_len = secret_key.expose_secret().len();
    if actual_len != expected_len {
        return Err(PqcbError::invalid_length(
            "ml_kem_768.secret_key",
            expected_len,
            actual_len,
        ));
    }

    Ok(())
}

/// Validates a KEM ciphertext before invoking a backend.
///
/// # Errors
///
/// Returns `InvalidLength` when the ciphertext length is not canonical for the
/// requested algorithm.
pub fn validate_kem_ciphertext(algorithm: KemAlgorithm, ciphertext: &[u8]) -> Result<()> {
    let expected_len = algorithm.parameters().ciphertext_len;
    let actual_len = ciphertext.len();
    if actual_len != expected_len {
        return Err(PqcbError::invalid_length(
            "ml_kem_768.ciphertext",
            expected_len,
            actual_len,
        ));
    }

    Ok(())
}

/// Validates inputs and then invokes backend encapsulation.
///
/// # Errors
///
/// Returns validation errors before backend invocation, or backend errors after
/// validation succeeds.
pub fn encapsulate_checked(
    backend: &impl KemBackend,
    public_key: &PublicKey,
) -> Result<Encapsulation> {
    validate_kem_public_key(backend.algorithm(), public_key)?;
    backend.encapsulate(public_key)
}

/// Validates inputs and then invokes backend decapsulation.
///
/// # Errors
///
/// Returns validation errors before backend invocation, or backend errors after
/// validation succeeds.
pub fn decapsulate_checked(
    backend: &impl KemBackend,
    secret_key: &SecretKey,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let algorithm = backend.algorithm();
    validate_kem_secret_key(algorithm, secret_key)?;
    validate_kem_ciphertext(algorithm, ciphertext)?;
    backend.decapsulate(secret_key, ciphertext)
}

/// Interface implemented by ML-DSA capable backends.
pub trait SignatureBackend: Send + Sync {
    /// Returns the signature algorithm this backend implements.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Generates a signature key pair.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails or the backend is unavailable.
    fn keypair(&self) -> Result<SignatureKeyPair>;

    /// Signs `message` with `secret_key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key is invalid, belongs to another
    /// algorithm, or signing fails.
    fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>>;

    /// Verifies `signature` over `message` with `public_key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key or signature is invalid, belongs to
    /// another algorithm, verification fails, or the backend is unavailable.
    fn verify(
        &self,
        public_key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<Verification>;
}

/// Validates a signature public key before invoking a backend.
///
/// # Errors
///
/// Returns `KeyAlgorithmMismatch` or `InvalidLength` when the key is not usable
/// with the requested algorithm.
pub fn validate_signature_public_key(
    algorithm: SignatureAlgorithm,
    public_key: &PublicKey,
) -> Result<()> {
    let expected = KeyAlgorithm::Signature(algorithm);
    if public_key.algorithm() != expected {
        return Err(PqcbError::KeyAlgorithmMismatch {
            expected: expected.as_str(),
            actual: public_key.algorithm().as_str(),
        });
    }

    let expected_len = algorithm.parameters().public_key_len;
    let actual_len = public_key.as_bytes().len();
    if actual_len != expected_len {
        return Err(PqcbError::invalid_length(
            "ml_dsa_65.public_key",
            expected_len,
            actual_len,
        ));
    }

    Ok(())
}

/// Validates a signature secret key before invoking a backend.
///
/// # Errors
///
/// Returns `KeyAlgorithmMismatch` or `InvalidLength` when the key is not usable
/// with the requested algorithm.
pub fn validate_signature_secret_key(
    algorithm: SignatureAlgorithm,
    secret_key: &SecretKey,
) -> Result<()> {
    let expected = KeyAlgorithm::Signature(algorithm);
    if secret_key.algorithm() != expected {
        return Err(PqcbError::KeyAlgorithmMismatch {
            expected: expected.as_str(),
            actual: secret_key.algorithm().as_str(),
        });
    }

    let expected_len = algorithm.parameters().secret_key_len;
    let actual_len = secret_key.expose_secret().len();
    if actual_len != expected_len {
        return Err(PqcbError::invalid_length(
            "ml_dsa_65.secret_key",
            expected_len,
            actual_len,
        ));
    }

    Ok(())
}

/// Validates a signature byte string before invoking a backend.
///
/// # Errors
///
/// Returns `InvalidLength` when the signature length is not canonical for the
/// requested algorithm.
pub fn validate_signature(algorithm: SignatureAlgorithm, signature: &[u8]) -> Result<()> {
    let expected_len = algorithm.parameters().signature_len;
    let actual_len = signature.len();
    if actual_len != expected_len {
        return Err(PqcbError::invalid_length(
            "ml_dsa_65.signature",
            expected_len,
            actual_len,
        ));
    }

    Ok(())
}

/// Validates inputs and then invokes backend signing.
///
/// # Errors
///
/// Returns validation errors before backend invocation, or backend errors after
/// validation succeeds.
pub fn sign_checked(
    backend: &impl SignatureBackend,
    secret_key: &SecretKey,
    message: &[u8],
) -> Result<Vec<u8>> {
    validate_signature_secret_key(backend.algorithm(), secret_key)?;
    backend.sign(secret_key, message)
}

/// Validates inputs and then invokes backend verification.
///
/// # Errors
///
/// Returns validation errors before backend invocation, or backend errors after
/// validation succeeds. Invalid signatures from the backend are returned as
/// `PqcbError::VerificationFailed`.
pub fn verify_checked(
    backend: &impl SignatureBackend,
    public_key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<Verification> {
    let algorithm = backend.algorithm();
    validate_signature_public_key(algorithm, public_key)?;
    validate_signature(algorithm, signature)?;
    backend.verify(public_key, message, signature)
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::algorithms::{
        ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SECRET_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
        ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_PUBLIC_KEY_LEN, ML_KEM_768_SECRET_KEY_LEN,
    };

    use super::*;

    #[derive(Debug)]
    struct SpyKemBackend {
        encapsulate_calls: AtomicUsize,
        decapsulate_calls: AtomicUsize,
    }

    impl SpyKemBackend {
        fn new() -> Self {
            Self {
                encapsulate_calls: AtomicUsize::new(0),
                decapsulate_calls: AtomicUsize::new(0),
            }
        }
    }

    impl KemBackend for SpyKemBackend {
        fn algorithm(&self) -> KemAlgorithm {
            KemAlgorithm::MlKem768
        }

        fn keypair(&self) -> Result<KemKeyPair> {
            Err(PqcbError::backend_unavailable("ML-KEM-768"))
        }

        fn encapsulate(&self, _public_key: &PublicKey) -> Result<Encapsulation> {
            self.encapsulate_calls.fetch_add(1, Ordering::SeqCst);
            Err(PqcbError::CryptoFailure {
                reason: "spy encapsulate",
            })
        }

        fn decapsulate(
            &self,
            _secret_key: &SecretKey,
            _ciphertext: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>> {
            self.decapsulate_calls.fetch_add(1, Ordering::SeqCst);
            Err(PqcbError::CryptoFailure {
                reason: "spy decapsulate",
            })
        }
    }

    #[derive(Debug)]
    struct SpySignatureBackend {
        sign_calls: AtomicUsize,
        verify_calls: AtomicUsize,
    }

    impl SpySignatureBackend {
        fn new() -> Self {
            Self {
                sign_calls: AtomicUsize::new(0),
                verify_calls: AtomicUsize::new(0),
            }
        }
    }

    impl SignatureBackend for SpySignatureBackend {
        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::MlDsa65
        }

        fn keypair(&self) -> Result<SignatureKeyPair> {
            Err(PqcbError::backend_unavailable("ML-DSA-65"))
        }

        fn sign(&self, _secret_key: &SecretKey, _message: &[u8]) -> Result<Vec<u8>> {
            self.sign_calls.fetch_add(1, Ordering::SeqCst);
            Err(PqcbError::CryptoFailure { reason: "spy sign" })
        }

        fn verify(
            &self,
            _public_key: &PublicKey,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<Verification> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            Err(PqcbError::VerificationFailed)
        }
    }

    #[test]
    fn ml_kem_invalid_public_key_length_fails_before_backend_call() {
        let backend = SpyKemBackend::new();
        let public_key = PublicKey::new(
            KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
            vec![0; ML_KEM_768_PUBLIC_KEY_LEN - 1],
        );

        assert_eq!(
            encapsulate_checked(&backend, &public_key),
            Err(PqcbError::invalid_length(
                "ml_kem_768.public_key",
                ML_KEM_768_PUBLIC_KEY_LEN,
                ML_KEM_768_PUBLIC_KEY_LEN - 1,
            ))
        );
        assert_eq!(backend.encapsulate_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ml_kem_invalid_secret_key_length_fails_before_backend_call() {
        let backend = SpyKemBackend::new();
        let secret_key = SecretKey::new(
            KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
            vec![0; ML_KEM_768_SECRET_KEY_LEN - 1],
        );
        let ciphertext = vec![0; ML_KEM_768_CIPHERTEXT_LEN];

        assert_eq!(
            decapsulate_checked(&backend, &secret_key, &ciphertext),
            Err(PqcbError::invalid_length(
                "ml_kem_768.secret_key",
                ML_KEM_768_SECRET_KEY_LEN,
                ML_KEM_768_SECRET_KEY_LEN - 1,
            ))
        );
        assert_eq!(backend.decapsulate_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ml_kem_invalid_ciphertext_length_fails_before_backend_call() {
        let backend = SpyKemBackend::new();
        let secret_key = SecretKey::new(
            KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
            vec![0; ML_KEM_768_SECRET_KEY_LEN],
        );
        let ciphertext = vec![0; ML_KEM_768_CIPHERTEXT_LEN - 1];

        assert_eq!(
            decapsulate_checked(&backend, &secret_key, &ciphertext),
            Err(PqcbError::invalid_length(
                "ml_kem_768.ciphertext",
                ML_KEM_768_CIPHERTEXT_LEN,
                ML_KEM_768_CIPHERTEXT_LEN - 1,
            ))
        );
        assert_eq!(backend.decapsulate_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ml_dsa_invalid_secret_key_length_fails_before_backend_call() {
        let backend = SpySignatureBackend::new();
        let secret_key = SecretKey::new(
            KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
            vec![0; ML_DSA_65_SECRET_KEY_LEN - 1],
        );

        assert_eq!(
            sign_checked(&backend, &secret_key, b"message"),
            Err(PqcbError::invalid_length(
                "ml_dsa_65.secret_key",
                ML_DSA_65_SECRET_KEY_LEN,
                ML_DSA_65_SECRET_KEY_LEN - 1,
            ))
        );
        assert_eq!(backend.sign_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ml_dsa_invalid_public_key_length_fails_before_backend_call() {
        let backend = SpySignatureBackend::new();
        let public_key = PublicKey::new(
            KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
            vec![0; ML_DSA_65_PUBLIC_KEY_LEN - 1],
        );
        let signature = vec![0; ML_DSA_65_SIGNATURE_LEN];

        assert_eq!(
            verify_checked(&backend, &public_key, b"message", &signature),
            Err(PqcbError::invalid_length(
                "ml_dsa_65.public_key",
                ML_DSA_65_PUBLIC_KEY_LEN,
                ML_DSA_65_PUBLIC_KEY_LEN - 1,
            ))
        );
        assert_eq!(backend.verify_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ml_dsa_malformed_signature_fails_before_backend_call() {
        let backend = SpySignatureBackend::new();
        let public_key = PublicKey::new(
            KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
            vec![0; ML_DSA_65_PUBLIC_KEY_LEN],
        );
        let signature = vec![0; ML_DSA_65_SIGNATURE_LEN - 1];

        assert_eq!(
            verify_checked(&backend, &public_key, b"message", &signature),
            Err(PqcbError::invalid_length(
                "ml_dsa_65.signature",
                ML_DSA_65_SIGNATURE_LEN,
                ML_DSA_65_SIGNATURE_LEN - 1,
            ))
        );
        assert_eq!(backend.verify_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ml_dsa_verification_failure_is_explicit() {
        let backend = SpySignatureBackend::new();
        let public_key = PublicKey::new(
            KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
            vec![0; ML_DSA_65_PUBLIC_KEY_LEN],
        );
        let signature = vec![0; ML_DSA_65_SIGNATURE_LEN];

        assert_eq!(
            verify_checked(&backend, &public_key, b"wrong key behavior", &signature),
            Err(PqcbError::VerificationFailed)
        );
        assert_eq!(backend.verify_calls.load(Ordering::SeqCst), 1);
    }
}
