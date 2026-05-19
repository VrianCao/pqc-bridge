//! Versioned binary envelopes for SDK-native serialized objects.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::{
    HybridKemAlgorithm, KemAlgorithm, PqcbError, Result, SignatureAlgorithm,
    algorithms::{
        ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SECRET_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
        ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_PUBLIC_KEY_LEN, ML_KEM_768_SECRET_KEY_LEN,
    },
};

const MAGIC: &[u8; 4] = b"PQCB";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 14;
const CHECKSUM_LEN: usize = 32;
const FLAG_ENCRYPTED: u16 = 1 << 0;
const FLAG_CONTAINS_SECRET: u16 = 1 << 1;
const RESERVED_FLAGS: u16 = !((1 << 0) | (1 << 1));

/// v1 envelope object type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum EnvelopeObjectType {
    /// Raw public key material.
    PublicKey,
    /// Raw or encrypted secret key material.
    SecretKey,
    /// Raw KEM ciphertext material.
    Ciphertext,
    /// Raw signature material.
    Signature,
    /// High-level sealed message material.
    SealedMessage,
    /// High-level file envelope material.
    FileEnvelope,
}

impl EnvelopeObjectType {
    const fn id(self) -> u8 {
        match self {
            Self::PublicKey => 0x01,
            Self::SecretKey => 0x02,
            Self::Ciphertext => 0x03,
            Self::Signature => 0x04,
            Self::SealedMessage => 0x05,
            Self::FileEnvelope => 0x06,
        }
    }

    const fn from_id(id: u8) -> Result<Self> {
        match id {
            0x01 => Ok(Self::PublicKey),
            0x02 => Ok(Self::SecretKey),
            0x03 => Ok(Self::Ciphertext),
            0x04 => Ok(Self::Signature),
            0x05 => Ok(Self::SealedMessage),
            0x06 => Ok(Self::FileEnvelope),
            _ => Err(PqcbError::InvalidEnvelope {
                reason: "unknown object type",
            }),
        }
    }
}

/// Algorithm or high-level profile attached to an envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum EnvelopeAlgorithm {
    /// NIST FIPS 203 ML-KEM-768.
    MlKem768,
    /// NIST FIPS 204 ML-DSA-65.
    MlDsa65,
    /// Hybrid X25519 + ML-KEM-768 high-level profile.
    X25519MlKem768,
}

impl EnvelopeAlgorithm {
    const fn id(self) -> u16 {
        match self {
            Self::MlKem768 => 0x0001,
            Self::MlDsa65 => 0x0002,
            Self::X25519MlKem768 => 0x0101,
        }
    }

    const fn from_id(id: u16) -> Result<Self> {
        match id {
            0x0001 => Ok(Self::MlKem768),
            0x0002 => Ok(Self::MlDsa65),
            0x0101 => Ok(Self::X25519MlKem768),
            _ => Err(PqcbError::InvalidEnvelope {
                reason: "unknown algorithm",
            }),
        }
    }
}

impl From<KemAlgorithm> for EnvelopeAlgorithm {
    fn from(algorithm: KemAlgorithm) -> Self {
        match algorithm {
            KemAlgorithm::MlKem768 => Self::MlKem768,
        }
    }
}

impl From<SignatureAlgorithm> for EnvelopeAlgorithm {
    fn from(algorithm: SignatureAlgorithm) -> Self {
        match algorithm {
            SignatureAlgorithm::MlDsa65 => Self::MlDsa65,
        }
    }
}

impl From<HybridKemAlgorithm> for EnvelopeAlgorithm {
    fn from(algorithm: HybridKemAlgorithm) -> Self {
        match algorithm {
            HybridKemAlgorithm::X25519MlKem768 => Self::X25519MlKem768,
        }
    }
}

/// Flags attached to an envelope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct EnvelopeFlags {
    /// Material is authenticated encrypted payload bytes.
    pub encrypted: bool,
    /// Material contains or can derive secret material.
    pub contains_secret: bool,
}

impl EnvelopeFlags {
    const fn bits(self) -> u16 {
        let mut bits = 0;
        if self.encrypted {
            bits |= FLAG_ENCRYPTED;
        }
        if self.contains_secret {
            bits |= FLAG_CONTAINS_SECRET;
        }
        bits
    }

    const fn from_bits(bits: u16) -> Result<Self> {
        if bits & RESERVED_FLAGS != 0 {
            return Err(PqcbError::InvalidEnvelope {
                reason: "unknown flags",
            });
        }

        Ok(Self {
            encrypted: bits & FLAG_ENCRYPTED != 0,
            contains_secret: bits & FLAG_CONTAINS_SECRET != 0,
        })
    }
}

/// Decoded v1 envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct Envelope {
    object_type: EnvelopeObjectType,
    algorithm: EnvelopeAlgorithm,
    flags: EnvelopeFlags,
    material: Vec<u8>,
}

impl Envelope {
    /// Creates an envelope after validating the object/algorithm/length contract.
    ///
    /// # Errors
    ///
    /// Returns `InvalidEnvelope` for invalid object and algorithm combinations or
    /// invalid flags, and `InvalidLength` for fixed-length primitive material
    /// with an unexpected length.
    pub fn new(
        object_type: EnvelopeObjectType,
        algorithm: EnvelopeAlgorithm,
        flags: EnvelopeFlags,
        material: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let material = material.into();
        validate_contract(object_type, algorithm, flags, material.len())?;

        Ok(Self {
            object_type,
            algorithm,
            flags,
            material,
        })
    }

    /// Returns the object type.
    pub const fn object_type(&self) -> EnvelopeObjectType {
        self.object_type
    }

    /// Returns the envelope algorithm/profile.
    pub const fn algorithm(&self) -> EnvelopeAlgorithm {
        self.algorithm
    }

    /// Returns the envelope flags.
    pub const fn flags(&self) -> EnvelopeFlags {
        self.flags
    }

    /// Returns the envelope material.
    pub fn material(&self) -> &[u8] {
        &self.material
    }

    /// Encodes the envelope into canonical v1 bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLength` when the material is too large for the v1
    /// `u32` material-length field.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let material_len =
            u32::try_from(self.material.len()).map_err(|_| PqcbError::InvalidLength {
                field: "material",
                expected: u32::MAX as usize,
                actual: self.material.len(),
            })?;
        let mut encoded = Vec::with_capacity(HEADER_LEN + self.material.len() + CHECKSUM_LEN);

        encoded.extend_from_slice(MAGIC);
        encoded.push(VERSION);
        encoded.push(self.object_type.id());
        encoded.extend_from_slice(&self.algorithm.id().to_be_bytes());
        encoded.extend_from_slice(&self.flags.bits().to_be_bytes());
        encoded.extend_from_slice(&material_len.to_be_bytes());
        encoded.extend_from_slice(&self.material);

        let checksum = checksum(&encoded);
        encoded.extend_from_slice(&checksum);

        Ok(encoded)
    }

    /// Decodes and validates canonical v1 envelope bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidEnvelope` or `InvalidLength` when the input is malformed,
    /// unsupported, non-canonical, or has an invalid checksum.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < HEADER_LEN + CHECKSUM_LEN {
            return Err(PqcbError::InvalidEnvelope {
                reason: "truncated envelope",
            });
        }
        if &input[..4] != MAGIC {
            return Err(PqcbError::InvalidEnvelope {
                reason: "invalid magic",
            });
        }
        if input[4] != VERSION {
            return Err(PqcbError::InvalidEnvelope {
                reason: "unsupported version",
            });
        }

        let object_type = EnvelopeObjectType::from_id(input[5])?;
        let algorithm = EnvelopeAlgorithm::from_id(u16::from_be_bytes([input[6], input[7]]))?;
        let flags = EnvelopeFlags::from_bits(u16::from_be_bytes([input[8], input[9]]))?;
        let material_len =
            u32::from_be_bytes([input[10], input[11], input[12], input[13]]) as usize;
        let expected_len = HEADER_LEN
            .checked_add(material_len)
            .and_then(|len| len.checked_add(CHECKSUM_LEN))
            .ok_or(PqcbError::InvalidEnvelope {
                reason: "envelope length overflow",
            })?;

        if input.len() != expected_len {
            return Err(PqcbError::InvalidLength {
                field: "envelope",
                expected: expected_len,
                actual: input.len(),
            });
        }

        let checksum_offset = HEADER_LEN + material_len;
        let expected_checksum = checksum(&input[..checksum_offset]);
        if expected_checksum.as_slice() != &input[checksum_offset..] {
            return Err(PqcbError::InvalidEnvelope {
                reason: "checksum mismatch",
            });
        }

        Self::new(
            object_type,
            algorithm,
            flags,
            input[HEADER_LEN..checksum_offset].to_vec(),
        )
    }
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Envelope");
        debug
            .field("object_type", &self.object_type)
            .field("algorithm", &self.algorithm)
            .field("flags", &self.flags)
            .field("material_len", &self.material.len());
        if self.flags.contains_secret {
            debug.field("material", &"<redacted>");
        }
        debug.finish_non_exhaustive()
    }
}

/// Encodes a raw ML-KEM-768 public key envelope.
///
/// # Errors
///
/// Returns `InvalidLength` when the public key length is not canonical.
pub fn encode_ml_kem_768_public_key(material: &[u8]) -> Result<Vec<u8>> {
    Envelope::new(
        EnvelopeObjectType::PublicKey,
        EnvelopeAlgorithm::MlKem768,
        EnvelopeFlags::default(),
        material,
    )?
    .encode()
}

/// Encodes a raw ML-KEM-768 secret key envelope.
///
/// # Errors
///
/// Returns `InvalidLength` when the secret key length is not canonical.
pub fn encode_ml_kem_768_secret_key(material: &[u8]) -> Result<Vec<u8>> {
    Envelope::new(
        EnvelopeObjectType::SecretKey,
        EnvelopeAlgorithm::MlKem768,
        EnvelopeFlags {
            encrypted: false,
            contains_secret: true,
        },
        material,
    )?
    .encode()
}

/// Encodes a raw ML-KEM-768 ciphertext envelope.
///
/// # Errors
///
/// Returns `InvalidLength` when the ciphertext length is not canonical.
pub fn encode_ml_kem_768_ciphertext(material: &[u8]) -> Result<Vec<u8>> {
    Envelope::new(
        EnvelopeObjectType::Ciphertext,
        EnvelopeAlgorithm::MlKem768,
        EnvelopeFlags::default(),
        material,
    )?
    .encode()
}

/// Encodes a raw ML-DSA-65 public key envelope.
///
/// # Errors
///
/// Returns `InvalidLength` when the public key length is not canonical.
pub fn encode_ml_dsa_65_public_key(material: &[u8]) -> Result<Vec<u8>> {
    Envelope::new(
        EnvelopeObjectType::PublicKey,
        EnvelopeAlgorithm::MlDsa65,
        EnvelopeFlags::default(),
        material,
    )?
    .encode()
}

/// Encodes a raw ML-DSA-65 secret key envelope.
///
/// # Errors
///
/// Returns `InvalidLength` when the secret key length is not canonical.
pub fn encode_ml_dsa_65_secret_key(material: &[u8]) -> Result<Vec<u8>> {
    Envelope::new(
        EnvelopeObjectType::SecretKey,
        EnvelopeAlgorithm::MlDsa65,
        EnvelopeFlags {
            encrypted: false,
            contains_secret: true,
        },
        material,
    )?
    .encode()
}

/// Encodes a raw ML-DSA-65 signature envelope.
///
/// # Errors
///
/// Returns `InvalidLength` when the signature length is not canonical.
pub fn encode_ml_dsa_65_signature(material: &[u8]) -> Result<Vec<u8>> {
    Envelope::new(
        EnvelopeObjectType::Signature,
        EnvelopeAlgorithm::MlDsa65,
        EnvelopeFlags::default(),
        material,
    )?
    .encode()
}

const fn validate_contract(
    object_type: EnvelopeObjectType,
    algorithm: EnvelopeAlgorithm,
    flags: EnvelopeFlags,
    material_len: usize,
) -> Result<()> {
    if matches!(object_type, EnvelopeObjectType::SecretKey) && !flags.contains_secret {
        return Err(PqcbError::InvalidEnvelope {
            reason: "secret envelope missing secret flag",
        });
    }
    if !matches!(object_type, EnvelopeObjectType::SecretKey) && flags.contains_secret {
        return Err(PqcbError::InvalidEnvelope {
            reason: "public envelope has secret flag",
        });
    }

    match (object_type, algorithm) {
        (EnvelopeObjectType::PublicKey, EnvelopeAlgorithm::MlKem768) => {
            expect_len("material", ML_KEM_768_PUBLIC_KEY_LEN, material_len)
        }
        (EnvelopeObjectType::SecretKey, EnvelopeAlgorithm::MlKem768) => {
            expect_len("material", ML_KEM_768_SECRET_KEY_LEN, material_len)
        }
        (EnvelopeObjectType::Ciphertext, EnvelopeAlgorithm::MlKem768) => {
            expect_len("material", ML_KEM_768_CIPHERTEXT_LEN, material_len)
        }
        (EnvelopeObjectType::PublicKey, EnvelopeAlgorithm::MlDsa65) => {
            expect_len("material", ML_DSA_65_PUBLIC_KEY_LEN, material_len)
        }
        (EnvelopeObjectType::SecretKey, EnvelopeAlgorithm::MlDsa65) => {
            expect_len("material", ML_DSA_65_SECRET_KEY_LEN, material_len)
        }
        (EnvelopeObjectType::Signature, EnvelopeAlgorithm::MlDsa65) => {
            expect_len("material", ML_DSA_65_SIGNATURE_LEN, material_len)
        }
        (
            EnvelopeObjectType::PublicKey
            | EnvelopeObjectType::SecretKey
            | EnvelopeObjectType::SealedMessage
            | EnvelopeObjectType::FileEnvelope,
            EnvelopeAlgorithm::X25519MlKem768,
        )
        | (EnvelopeObjectType::SealedMessage, EnvelopeAlgorithm::MlKem768) => Ok(()),
        _ => Err(PqcbError::InvalidEnvelope {
            reason: "invalid object and algorithm combination",
        }),
    }
}

const fn expect_len(field: &'static str, expected: usize, actual: usize) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(PqcbError::InvalidLength {
            field,
            expected,
            actual,
        })
    }
}

fn checksum(input: &[u8]) -> [u8; CHECKSUM_LEN] {
    Sha256::digest(input).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_all_v1_object_types() {
        let cases = [
            (
                EnvelopeObjectType::PublicKey,
                EnvelopeAlgorithm::MlKem768,
                EnvelopeFlags::default(),
                vec![1; ML_KEM_768_PUBLIC_KEY_LEN],
            ),
            (
                EnvelopeObjectType::SecretKey,
                EnvelopeAlgorithm::MlKem768,
                EnvelopeFlags {
                    encrypted: false,
                    contains_secret: true,
                },
                vec![2; ML_KEM_768_SECRET_KEY_LEN],
            ),
            (
                EnvelopeObjectType::Ciphertext,
                EnvelopeAlgorithm::MlKem768,
                EnvelopeFlags::default(),
                vec![3; ML_KEM_768_CIPHERTEXT_LEN],
            ),
            (
                EnvelopeObjectType::Signature,
                EnvelopeAlgorithm::MlDsa65,
                EnvelopeFlags::default(),
                vec![4; ML_DSA_65_SIGNATURE_LEN],
            ),
            (
                EnvelopeObjectType::SealedMessage,
                EnvelopeAlgorithm::X25519MlKem768,
                EnvelopeFlags::default(),
                b"sealed".to_vec(),
            ),
            (
                EnvelopeObjectType::FileEnvelope,
                EnvelopeAlgorithm::X25519MlKem768,
                EnvelopeFlags::default(),
                b"file".to_vec(),
            ),
        ];

        for (object_type, algorithm, flags, material) in cases {
            let envelope = Envelope::new(object_type, algorithm, flags, material).unwrap();
            let encoded = envelope.encode().unwrap();

            assert_eq!(Envelope::decode(&encoded), Ok(envelope));
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        let material = vec![9; ML_DSA_65_SIGNATURE_LEN];
        let first = encode_ml_dsa_65_signature(&material).unwrap();
        let second = encode_ml_dsa_65_signature(&material).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn typed_helpers_validate_lengths() {
        assert_eq!(
            encode_ml_kem_768_public_key(&[0; 1]),
            Err(PqcbError::InvalidLength {
                field: "material",
                expected: ML_KEM_768_PUBLIC_KEY_LEN,
                actual: 1,
            })
        );
    }

    #[test]
    fn rejects_malformed_headers_and_lengths() {
        let encoded = encode_ml_kem_768_ciphertext(&vec![0; ML_KEM_768_CIPHERTEXT_LEN]).unwrap();

        let mut invalid_magic = encoded.clone();
        invalid_magic[0] = b'X';
        assert_eq!(
            Envelope::decode(&invalid_magic),
            Err(PqcbError::InvalidEnvelope {
                reason: "invalid magic",
            })
        );

        let mut invalid_version = encoded.clone();
        invalid_version[4] = 2;
        assert_eq!(
            Envelope::decode(&invalid_version),
            Err(PqcbError::InvalidEnvelope {
                reason: "unsupported version",
            })
        );

        let mut unknown_algorithm = encoded.clone();
        unknown_algorithm[7] = 0xff;
        assert_eq!(
            Envelope::decode(&unknown_algorithm),
            Err(PqcbError::InvalidEnvelope {
                reason: "unknown algorithm",
            })
        );

        let mut unknown_flags = encoded.clone();
        unknown_flags[9] = 0x04;
        assert_eq!(
            Envelope::decode(&unknown_flags),
            Err(PqcbError::InvalidEnvelope {
                reason: "unknown flags",
            })
        );

        let mut truncated = encoded;
        truncated.pop();
        assert_eq!(
            Envelope::decode(&truncated),
            Err(PqcbError::InvalidLength {
                field: "envelope",
                expected: HEADER_LEN + ML_KEM_768_CIPHERTEXT_LEN + CHECKSUM_LEN,
                actual: HEADER_LEN + ML_KEM_768_CIPHERTEXT_LEN + CHECKSUM_LEN - 1,
            })
        );
    }

    #[test]
    fn rejects_checksum_mismatch() {
        let mut encoded = encode_ml_dsa_65_signature(&vec![0; ML_DSA_65_SIGNATURE_LEN]).unwrap();
        let last = encoded.last_mut().unwrap();
        *last ^= 0xff;

        assert_eq!(
            Envelope::decode(&encoded),
            Err(PqcbError::InvalidEnvelope {
                reason: "checksum mismatch",
            })
        );
    }

    #[test]
    fn rejects_invalid_object_algorithm_pairing() {
        let envelope = Envelope::new(
            EnvelopeObjectType::Signature,
            EnvelopeAlgorithm::MlKem768,
            EnvelopeFlags::default(),
            vec![0; ML_DSA_65_SIGNATURE_LEN],
        );

        assert_eq!(
            envelope,
            Err(PqcbError::InvalidEnvelope {
                reason: "invalid object and algorithm combination",
            })
        );
    }

    #[test]
    fn secret_envelope_debug_redacts_material() {
        let envelope = Envelope::new(
            EnvelopeObjectType::SecretKey,
            EnvelopeAlgorithm::MlDsa65,
            EnvelopeFlags {
                encrypted: false,
                contains_secret: true,
            },
            vec![7; ML_DSA_65_SECRET_KEY_LEN],
        )
        .unwrap();

        let debug = format!("{envelope:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("[7"));
    }
}
