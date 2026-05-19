//! Hybrid `X25519-ML-KEM-768` deterministic vector coverage.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{FromSeed, KeyExport, MlKem768};
use pqcb_backend_rustcrypto::hybrid;
use pqcb_core::{
    HYBRID_SHARED_SECRET_LEN, HybridEncapsulation, HybridPublicKey, HybridSecretKey, KemAlgorithm,
    KeyAlgorithm, PublicKey, SecretKey,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const MANIFEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/hybrid/manifest.json"
);

#[derive(Debug, Deserialize)]
struct Manifest {
    cases: Vec<KatCase>,
}

#[derive(Debug, Deserialize)]
struct KatCase {
    id: String,
    #[serde(rename = "type")]
    case_type: String,
    operation: String,
    expected: String,
    inputs: serde_json::Map<String, serde_json::Value>,
    outputs: serde_json::Map<String, serde_json::Value>,
}

#[test]
fn hybrid_vectors_pass() {
    let manifest = read_manifest(Path::new(MANIFEST));
    let base_case = manifest
        .cases
        .iter()
        .find(|case| case.id == "hybrid-x25519-ml-kem-768-deterministic-session")
        .expect("base hybrid vector");

    run_positive_case(base_case);

    for case in &manifest.cases {
        if case.case_type == "negative" {
            run_context_change_case(base_case, case);
        }
    }
}

fn run_positive_case(case: &KatCase) {
    assert_eq!(case.case_type, "positive");
    assert_eq!(case.operation, "decapsulate");
    assert_eq!(case.expected, "success");

    let vector = deterministic_vector(case);
    let decapsulated = hybrid::decapsulate(
        &vector.responder_secret_key,
        &vector.responder_public_key,
        &vector.encapsulation,
        &vector.context,
    )
    .expect("decapsulate deterministic hybrid vector");

    assert_eq!(
        hex(vector.initiator_public_key.as_bytes()),
        output(case, "initiator_x25519_public_key_hex")
    );
    assert_eq!(
        hex(vector.responder_public_key.x25519_public_key()),
        output(case, "responder_x25519_public_key_hex")
    );
    assert_eq!(
        sha256_hex(vector.responder_public_key.kem_public_key().as_bytes()),
        output(case, "ml_kem_public_key_sha256")
    );
    assert_eq!(
        sha256_hex(vector.encapsulation.kem_ciphertext()),
        output(case, "ml_kem_ciphertext_sha256")
    );
    assert_eq!(decapsulated.len(), HYBRID_SHARED_SECRET_LEN);
    assert_eq!(
        sha256_hex(decapsulated.as_slice()),
        output(case, "derived_shared_secret_sha256")
    );
}

fn run_context_change_case(base_case: &KatCase, case: &KatCase) {
    assert_eq!(case.operation, "decapsulate");
    assert_eq!(case.expected, "changed-secret");

    let base = deterministic_vector(base_case);
    let changed_context = bytes(input(case, "context_hex"));
    let original = hybrid::decapsulate(
        &base.responder_secret_key,
        &base.responder_public_key,
        &base.encapsulation,
        &base.context,
    )
    .expect("decapsulate original context");
    let changed = hybrid::decapsulate(
        &base.responder_secret_key,
        &base.responder_public_key,
        &base.encapsulation,
        &changed_context,
    )
    .expect("decapsulate changed context");

    assert_ne!(original.as_slice(), changed.as_slice());
}

struct DeterministicVector {
    context: Vec<u8>,
    initiator_public_key: X25519PublicKey,
    responder_public_key: HybridPublicKey,
    responder_secret_key: HybridSecretKey,
    encapsulation: HybridEncapsulation,
}

fn deterministic_vector(case: &KatCase) -> DeterministicVector {
    let initiator_secret = StaticSecret::from(array_32(input(case, "initiator_x25519_secret_hex")));
    let responder_secret = StaticSecret::from(array_32(input(case, "responder_x25519_secret_hex")));
    let initiator_public_key = X25519PublicKey::from(&initiator_secret);
    let responder_x25519_public_key = X25519PublicKey::from(&responder_secret);
    let (kem_secret_key, kem_public_key, kem_ciphertext) = deterministic_ml_kem(case);

    DeterministicVector {
        context: bytes(input(case, "context_hex")),
        initiator_public_key,
        responder_public_key: HybridPublicKey::from_parts(
            responder_x25519_public_key.to_bytes(),
            kem_public_key,
        )
        .expect("hybrid public key"),
        responder_secret_key: HybridSecretKey::from_parts(
            responder_secret.to_bytes(),
            kem_secret_key,
        )
        .expect("hybrid secret key"),
        encapsulation: HybridEncapsulation::new(
            initiator_public_key.to_bytes(),
            kem_ciphertext,
            vec![0; HYBRID_SHARED_SECRET_LEN],
        )
        .expect("hybrid encapsulation setup"),
    }
}

fn deterministic_ml_kem(case: &KatCase) -> (SecretKey, PublicKey, Vec<u8>) {
    let seed = seed(case);
    let randomness: ml_kem::B32 = bytes(input(case, "ml_kem_encapsulation_randomness_hex"))
        .as_slice()
        .try_into()
        .expect("encapsulation randomness length");
    let (secret_key, public_key) = MlKem768::from_seed(&seed);
    let (ciphertext, _shared_secret) = public_key.encapsulate_deterministic(&randomness);

    #[allow(deprecated)]
    let secret_key = secret_key.to_expanded_bytes();

    (
        SecretKey::new(
            KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
            secret_key.as_slice().to_vec(),
        ),
        PublicKey::new(
            KeyAlgorithm::Kem(KemAlgorithm::MlKem768),
            public_key.to_bytes().as_slice().to_vec(),
        ),
        ciphertext.as_slice().to_vec(),
    )
}

fn seed(case: &KatCase) -> ml_kem::Seed {
    bytes(input(case, "ml_kem_seed_hex"))
        .as_slice()
        .try_into()
        .expect("seed length")
}

fn read_manifest(path: &Path) -> Manifest {
    let bytes = fs::read(path).expect("read hybrid manifest");
    serde_json::from_slice(&bytes).expect("parse hybrid manifest")
}

fn input<'a>(case: &'a KatCase, key: &str) -> &'a str {
    case.inputs
        .get(key)
        .and_then(serde_json::Value::as_str)
        .expect("manifest input")
}

fn output<'a>(case: &'a KatCase, key: &str) -> &'a str {
    case.outputs
        .get(key)
        .and_then(serde_json::Value::as_str)
        .expect("manifest output")
}

fn array_32(hex: &str) -> [u8; 32] {
    bytes(hex).try_into().expect("32-byte hex field")
}

fn bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "hex length must be even");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("write hex");
    }
    encoded
}
