#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
//! `RustCrypto` backend adapter for PQC Bridge.
//!
//! This crate currently contains the mechanical backend boundary only. It does
//! not implement cryptographic operations until the ML-KEM and ML-DSA adapter
//! tasks add the pinned provider dependencies and KAT coverage.

use pqcb_core::{
    Encapsulation, KemAlgorithm, KemBackend, KemKeyPair, PqcbError, PublicKey, Result, SecretKey,
    SignatureAlgorithm, SignatureBackend, SignatureKeyPair, Verification,
};
use zeroize::Zeroizing;

/// Fail-closed `RustCrypto` backend skeleton.
///
/// The type is intentionally provider-neutral at its public boundary. Provider
/// types stay private to this crate once the real adapter is implemented.
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
        Err(PqcbError::backend_unavailable(
            KemAlgorithm::MlKem768.as_str(),
        ))
    }

    fn encapsulate(&self, _public_key: &PublicKey) -> Result<Encapsulation> {
        Err(PqcbError::backend_unavailable(
            KemAlgorithm::MlKem768.as_str(),
        ))
    }

    fn decapsulate(
        &self,
        _secret_key: &SecretKey,
        _ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(PqcbError::backend_unavailable(
            KemAlgorithm::MlKem768.as_str(),
        ))
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
    fn kem_operations_fail_closed_until_adapter_lands() {
        let backend = RustCryptoBackend::new();
        let public_key = PublicKey::new(KeyAlgorithm::Kem(KemAlgorithm::MlKem768), Vec::new());
        let secret_key = SecretKey::new(KeyAlgorithm::Kem(KemAlgorithm::MlKem768), Vec::new());

        assert_eq!(
            KemBackend::keypair(&backend),
            Err(PqcbError::backend_unavailable("ML-KEM-768"))
        );
        assert_eq!(
            backend.encapsulate(&public_key),
            Err(PqcbError::backend_unavailable("ML-KEM-768"))
        );
        assert_eq!(
            backend.decapsulate(&secret_key, &[]),
            Err(PqcbError::backend_unavailable("ML-KEM-768"))
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
