//! High-level signed-message workflow.

use core::fmt;

use crate::{
    Envelope, EnvelopeAlgorithm, EnvelopeFlags, EnvelopeObjectType, PqcbError, PublicKey, Result,
    SecretKey, SignatureBackend, Verification, sign_checked, verify_checked,
};

const MAGIC: &[u8; 4] = b"PQSM";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 9;

/// Message bytes bundled with an ML-DSA-65 signature envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedMessage {
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl SignedMessage {
    /// Signs `message` with the default ML-DSA-65 high-level workflow.
    ///
    /// # Errors
    ///
    /// Returns validation or backend errors from the configured signature
    /// backend.
    pub fn sign(
        backend: &impl SignatureBackend,
        secret_key: &SecretKey,
        message: &[u8],
    ) -> Result<Self> {
        let signature = sign_checked(backend, secret_key, message)?;
        Self::from_parts(message, &signature)
    }

    /// Creates a signed message from already-produced message and signature
    /// bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLength` when the signature length is not canonical for
    /// ML-DSA-65.
    pub fn from_parts(message: &[u8], signature: &[u8]) -> Result<Self> {
        Envelope::new(
            EnvelopeObjectType::Signature,
            EnvelopeAlgorithm::MlDsa65,
            EnvelopeFlags::default(),
            signature,
        )?;

        Ok(Self {
            message: message.to_vec(),
            signature: signature.to_vec(),
        })
    }

    /// Verifies this signed message with `public_key`.
    ///
    /// # Errors
    ///
    /// Returns validation errors or `VerificationFailed`; verification failure
    /// is never converted to success.
    pub fn verify(
        &self,
        backend: &impl SignatureBackend,
        public_key: &PublicKey,
    ) -> Result<Verification> {
        verify_checked(backend, public_key, &self.message, &self.signature)
    }

    /// Returns the signed message bytes.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Returns the ML-DSA-65 signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Serializes the signed message into deterministic bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLength` when the message is too large for the v1
    /// `u32` message-length field.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let message_len =
            u32::try_from(self.message.len()).map_err(|_| PqcbError::InvalidLength {
                field: "signed_message.message",
                expected: u32::MAX as usize,
                actual: self.message.len(),
            })?;
        let signature_envelope = Envelope::new(
            EnvelopeObjectType::Signature,
            EnvelopeAlgorithm::MlDsa65,
            EnvelopeFlags::default(),
            self.signature.clone(),
        )?
        .encode()?;

        let mut encoded =
            Vec::with_capacity(HEADER_LEN + self.message.len() + signature_envelope.len());
        encoded.extend_from_slice(MAGIC);
        encoded.push(VERSION);
        encoded.extend_from_slice(&message_len.to_be_bytes());
        encoded.extend_from_slice(&self.message);
        encoded.extend_from_slice(&signature_envelope);

        Ok(encoded)
    }

    /// Deserializes deterministic signed-message bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidEnvelope` or `InvalidLength` when the signed message or
    /// embedded signature envelope is malformed.
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        if input.len() < HEADER_LEN {
            return Err(PqcbError::InvalidEnvelope {
                reason: "truncated signed message",
            });
        }
        if &input[..4] != MAGIC {
            return Err(PqcbError::InvalidEnvelope {
                reason: "invalid signed message magic",
            });
        }
        if input[4] != VERSION {
            return Err(PqcbError::InvalidEnvelope {
                reason: "unsupported signed message version",
            });
        }

        let message_len = u32::from_be_bytes([input[5], input[6], input[7], input[8]]) as usize;
        let signature_offset =
            HEADER_LEN
                .checked_add(message_len)
                .ok_or(PqcbError::InvalidEnvelope {
                    reason: "signed message length overflow",
                })?;
        if input.len() < signature_offset {
            return Err(PqcbError::InvalidLength {
                field: "signed_message",
                expected: signature_offset,
                actual: input.len(),
            });
        }

        let message = &input[HEADER_LEN..signature_offset];
        let signature_envelope = Envelope::decode(&input[signature_offset..])?;
        if signature_envelope.object_type() != EnvelopeObjectType::Signature
            || signature_envelope.algorithm() != EnvelopeAlgorithm::MlDsa65
            || signature_envelope.flags() != EnvelopeFlags::default()
        {
            return Err(PqcbError::InvalidEnvelope {
                reason: "invalid signed message signature envelope",
            });
        }

        Self::from_parts(message, signature_envelope.material())
    }
}

impl fmt::Debug for SignedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedMessage")
            .field("message_len", &self.message.len())
            .field("signature_len", &self.signature.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithms::ML_DSA_65_SIGNATURE_LEN;

    use super::*;

    #[test]
    fn serializes_and_deserializes_signed_message() {
        let signed = SignedMessage::from_parts(b"message", &[7; ML_DSA_65_SIGNATURE_LEN]).unwrap();
        let encoded = signed.to_bytes().unwrap();

        assert_eq!(SignedMessage::from_bytes(&encoded), Ok(signed));
    }

    #[test]
    fn serialization_is_deterministic() {
        let signed = SignedMessage::from_parts(b"message", &[7; ML_DSA_65_SIGNATURE_LEN]).unwrap();

        assert_eq!(signed.to_bytes(), signed.to_bytes());
    }

    #[test]
    fn deserialization_rejects_bad_header() {
        assert_eq!(
            SignedMessage::from_bytes(b"bad"),
            Err(PqcbError::InvalidEnvelope {
                reason: "truncated signed message",
            })
        );

        let signed = SignedMessage::from_parts(b"message", &[7; ML_DSA_65_SIGNATURE_LEN]).unwrap();
        let mut encoded = signed.to_bytes().unwrap();
        encoded[0] = b'X';

        assert_eq!(
            SignedMessage::from_bytes(&encoded),
            Err(PqcbError::InvalidEnvelope {
                reason: "invalid signed message magic",
            })
        );
    }
}
