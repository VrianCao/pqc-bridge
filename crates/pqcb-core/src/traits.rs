//! Backend traits for concrete cryptographic implementations.

use core::fmt;

use zeroize::Zeroizing;

use crate::algorithms::{KemAlgorithm, SignatureAlgorithm};
use crate::errors::Result;
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
