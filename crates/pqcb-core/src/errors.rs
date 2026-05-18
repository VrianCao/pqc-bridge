//! Error types shared by PQC Bridge crates and bindings.

use thiserror::Error;

/// Convenient result alias for PQC Bridge operations.
pub type Result<T> = core::result::Result<T, PqcbError>;

/// Error returned by PQC Bridge APIs.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PqcbError {
    /// The requested algorithm is unknown to this SDK version.
    #[error("unsupported or unknown algorithm: {algorithm}")]
    InvalidAlgorithm {
        /// Algorithm string supplied by the caller.
        algorithm: String,
    },

    /// The requested algorithm is known, but no cryptographic backend is configured.
    #[error("no backend is available for {algorithm}")]
    BackendUnavailable {
        /// Stable algorithm name.
        algorithm: &'static str,
    },

    /// A key had the wrong algorithm identifier or was used for the wrong operation.
    #[error("key algorithm mismatch: expected {expected}, got {actual}")]
    KeyAlgorithmMismatch {
        /// Expected algorithm name.
        expected: &'static str,
        /// Actual algorithm name.
        actual: &'static str,
    },

    /// A byte buffer has an invalid length.
    #[error("invalid length for {field}: expected {expected} bytes, got {actual} bytes")]
    InvalidLength {
        /// Field name.
        field: &'static str,
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// The input envelope or serialized object could not be parsed.
    #[error("invalid envelope: {reason}")]
    InvalidEnvelope {
        /// Human-readable parse failure reason.
        reason: &'static str,
    },

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,

    /// A backend reported a cryptographic operation failure.
    #[error("cryptographic operation failed: {reason}")]
    CryptoFailure {
        /// Human-readable backend failure reason.
        reason: &'static str,
    },
}

impl PqcbError {
    /// Creates an invalid algorithm error from a caller-provided algorithm name.
    pub fn invalid_algorithm(algorithm: impl Into<String>) -> Self {
        Self::InvalidAlgorithm {
            algorithm: algorithm.into(),
        }
    }

    /// Creates a backend unavailable error.
    pub const fn backend_unavailable(algorithm: &'static str) -> Self {
        Self::BackendUnavailable { algorithm }
    }

    /// Creates an invalid-length error.
    pub const fn invalid_length(field: &'static str, expected: usize, actual: usize) -> Self {
        Self::InvalidLength {
            field,
            expected,
            actual,
        }
    }
}
