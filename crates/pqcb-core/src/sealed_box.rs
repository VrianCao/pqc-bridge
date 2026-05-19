//! High-level one-shot encrypted payload container.

use core::fmt;

use crate::{
    Envelope, EnvelopeAlgorithm, EnvelopeFlags, EnvelopeObjectType, PqcbError, Result,
    algorithms::ML_KEM_768_CIPHERTEXT_LEN,
};

/// XChaCha20-Poly1305 nonce length in bytes.
pub const SEALED_BOX_NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
pub const SEALED_BOX_TAG_LEN: usize = 16;
const MATERIAL_PREFIX_LEN: usize = 4 + ML_KEM_768_CIPHERTEXT_LEN + SEALED_BOX_NONCE_LEN;

/// One-shot encrypted payload sealed to an ML-KEM-768 recipient.
#[derive(Clone, Eq, PartialEq)]
pub struct SealedBox {
    kem_ciphertext: Vec<u8>,
    nonce: [u8; SEALED_BOX_NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl SealedBox {
    /// Creates a sealed box from raw material.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLength` when the KEM ciphertext, nonce, or AEAD
    /// ciphertext length is invalid.
    pub fn from_parts(kem_ciphertext: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Self> {
        if kem_ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN {
            return Err(PqcbError::InvalidLength {
                field: "sealed_box.kem_ciphertext",
                expected: ML_KEM_768_CIPHERTEXT_LEN,
                actual: kem_ciphertext.len(),
            });
        }
        if nonce.len() != SEALED_BOX_NONCE_LEN {
            return Err(PqcbError::InvalidLength {
                field: "sealed_box.nonce",
                expected: SEALED_BOX_NONCE_LEN,
                actual: nonce.len(),
            });
        }
        if ciphertext.len() < SEALED_BOX_TAG_LEN {
            return Err(PqcbError::InvalidLength {
                field: "sealed_box.ciphertext",
                expected: SEALED_BOX_TAG_LEN,
                actual: ciphertext.len(),
            });
        }

        let mut nonce_bytes = [0u8; SEALED_BOX_NONCE_LEN];
        nonce_bytes.copy_from_slice(nonce);

        Ok(Self {
            kem_ciphertext: kem_ciphertext.to_vec(),
            nonce: nonce_bytes,
            ciphertext: ciphertext.to_vec(),
        })
    }

    /// Returns the ML-KEM-768 ciphertext used to establish the AEAD key.
    pub fn kem_ciphertext(&self) -> &[u8] {
        &self.kem_ciphertext
    }

    /// Returns the XChaCha20-Poly1305 nonce.
    pub const fn nonce(&self) -> &[u8; SEALED_BOX_NONCE_LEN] {
        &self.nonce
    }

    /// Returns the AEAD ciphertext and tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Serializes the sealed box into deterministic v1 envelope bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the material length cannot be represented by the
    /// envelope format.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut material =
            Vec::with_capacity(MATERIAL_PREFIX_LEN.saturating_add(self.ciphertext.len()));
        let kem_ciphertext_len =
            u32::try_from(ML_KEM_768_CIPHERTEXT_LEN).map_err(|_| PqcbError::InvalidLength {
                field: "sealed_box.kem_ciphertext",
                expected: u32::MAX as usize,
                actual: ML_KEM_768_CIPHERTEXT_LEN,
            })?;
        material.extend_from_slice(&kem_ciphertext_len.to_be_bytes());
        material.extend_from_slice(&self.kem_ciphertext);
        material.extend_from_slice(&self.nonce);
        material.extend_from_slice(&self.ciphertext);

        Envelope::new(
            EnvelopeObjectType::SealedMessage,
            EnvelopeAlgorithm::MlKem768,
            EnvelopeFlags::default(),
            material,
        )?
        .encode()
    }

    /// Deserializes a sealed box from v1 envelope bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidEnvelope` or `InvalidLength` when the envelope or sealed
    /// box material is malformed.
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        let envelope = Envelope::decode(input)?;
        if envelope.object_type() != EnvelopeObjectType::SealedMessage
            || envelope.algorithm() != EnvelopeAlgorithm::MlKem768
            || envelope.flags() != EnvelopeFlags::default()
        {
            return Err(PqcbError::InvalidEnvelope {
                reason: "invalid sealed box envelope",
            });
        }

        let material = envelope.material();
        if material.len() < MATERIAL_PREFIX_LEN + SEALED_BOX_TAG_LEN {
            return Err(PqcbError::InvalidLength {
                field: "sealed_box.material",
                expected: MATERIAL_PREFIX_LEN + SEALED_BOX_TAG_LEN,
                actual: material.len(),
            });
        }

        let kem_ciphertext_len =
            u32::from_be_bytes([material[0], material[1], material[2], material[3]]) as usize;
        if kem_ciphertext_len != ML_KEM_768_CIPHERTEXT_LEN {
            return Err(PqcbError::InvalidLength {
                field: "sealed_box.kem_ciphertext",
                expected: ML_KEM_768_CIPHERTEXT_LEN,
                actual: kem_ciphertext_len,
            });
        }

        let kem_ciphertext_start = 4;
        let kem_ciphertext_end = kem_ciphertext_start + kem_ciphertext_len;
        let nonce_end = kem_ciphertext_end + SEALED_BOX_NONCE_LEN;

        Self::from_parts(
            &material[kem_ciphertext_start..kem_ciphertext_end],
            &material[kem_ciphertext_end..nonce_end],
            &material[nonce_end..],
        )
    }
}

impl fmt::Debug for SealedBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedBox")
            .field("kem_ciphertext_len", &self.kem_ciphertext.len())
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_and_deserializes_sealed_box() {
        let sealed = SealedBox::from_parts(
            &[1; ML_KEM_768_CIPHERTEXT_LEN],
            &[2; SEALED_BOX_NONCE_LEN],
            &[3; SEALED_BOX_TAG_LEN],
        )
        .unwrap();
        let encoded = sealed.to_bytes().unwrap();

        assert_eq!(SealedBox::from_bytes(&encoded), Ok(sealed));
    }

    #[test]
    fn deserialization_rejects_malformed_envelope() {
        assert_eq!(
            SealedBox::from_bytes(b"bad"),
            Err(PqcbError::InvalidEnvelope {
                reason: "truncated envelope",
            })
        );
    }
}
