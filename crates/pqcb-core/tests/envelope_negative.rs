//! Negative tests for v1 envelope parsing.

use pqcb_core::{
    Envelope, EnvelopeAlgorithm, EnvelopeFlags, EnvelopeObjectType, PqcbError,
    algorithms::{ML_DSA_65_SIGNATURE_LEN, ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_PUBLIC_KEY_LEN},
    encode_ml_kem_768_ciphertext, encode_ml_kem_768_public_key,
};

#[test]
fn envelope_parser_rejects_required_malformed_inputs() {
    let valid = encode_ml_kem_768_ciphertext(&vec![0; ML_KEM_768_CIPHERTEXT_LEN]).unwrap();

    let mut bad_magic = valid.clone();
    bad_magic[0] = b'X';
    assert_eq!(
        Envelope::decode(&bad_magic),
        Err(PqcbError::InvalidEnvelope {
            reason: "invalid magic"
        })
    );

    let mut unsupported_version = valid.clone();
    unsupported_version[4] = 0xff;
    assert_eq!(
        Envelope::decode(&unsupported_version),
        Err(PqcbError::InvalidEnvelope {
            reason: "unsupported version"
        })
    );

    let mut unknown_object_type = valid.clone();
    unknown_object_type[5] = 0xff;
    assert_eq!(
        Envelope::decode(&unknown_object_type),
        Err(PqcbError::InvalidEnvelope {
            reason: "unknown object type"
        })
    );

    let mut unknown_algorithm = valid.clone();
    unknown_algorithm[6] = 0xff;
    unknown_algorithm[7] = 0xff;
    assert_eq!(
        Envelope::decode(&unknown_algorithm),
        Err(PqcbError::InvalidEnvelope {
            reason: "unknown algorithm"
        })
    );

    let truncated = &valid[..valid.len() - 1];
    assert!(matches!(
        Envelope::decode(truncated),
        Err(PqcbError::InvalidLength {
            field: "envelope",
            ..
        })
    ));

    let mut wrong_length = valid;
    wrong_length[13] ^= 1;
    assert!(matches!(
        Envelope::decode(&wrong_length),
        Err(PqcbError::InvalidLength {
            field: "envelope",
            ..
        })
    ));
}

#[test]
fn envelope_parser_rejects_mismatched_algorithm_after_checksum_validation() {
    let bad_pair = Envelope::new(
        EnvelopeObjectType::Signature,
        EnvelopeAlgorithm::MlKem768,
        EnvelopeFlags::default(),
        vec![0; ML_DSA_65_SIGNATURE_LEN],
    );

    assert_eq!(
        bad_pair,
        Err(PqcbError::InvalidEnvelope {
            reason: "invalid object and algorithm combination"
        })
    );
}

#[test]
fn malformed_inputs_do_not_panic() {
    for len in 0..128 {
        let input = vec![0xa5; len];
        let _ = Envelope::decode(&input);
    }

    let mut valid = encode_ml_kem_768_public_key(&vec![1; ML_KEM_768_PUBLIC_KEY_LEN]).unwrap();
    for index in 0..valid.len() {
        valid[index] ^= 0xff;
        let _ = Envelope::decode(&valid);
        valid[index] ^= 0xff;
    }
}
