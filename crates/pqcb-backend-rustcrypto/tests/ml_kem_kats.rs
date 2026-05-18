//! ML-KEM-768 KAT coverage for the `RustCrypto` backend.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{FromSeed, KeyExport, MlKem768};
use pqcb_core::{
    KemAlgorithm, KeyAlgorithm, PqcbError, PublicKey, SecretKey, decapsulate_checked,
    encapsulate_checked,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use pqcb_backend_rustcrypto::RustCryptoBackend;

const MANIFEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/ml-kem-768/manifest.json"
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
fn ml_kem_768_kats_pass() {
    let manifest = read_manifest(Path::new(MANIFEST));

    for case in &manifest.cases {
        match (case.case_type.as_str(), case.operation.as_str()) {
            ("positive", "keygen") => run_keygen_case(case),
            ("positive", "encapsulate") => run_encapsulate_case(case),
            ("positive", "decapsulate") => run_decapsulate_case(case),
            ("negative", "encapsulate") => run_invalid_public_key_case(case),
            ("negative", "decapsulate") if input(case, "field") == "ml_kem_768.secret_key" => {
                run_invalid_secret_key_case(case);
            }
            ("negative", "decapsulate") if input(case, "field") == "ml_kem_768.ciphertext" => {
                run_invalid_ciphertext_case(case);
            }
            _ => panic!("unsupported KAT case {}", case.id),
        }
    }
}

fn run_keygen_case(case: &KatCase) {
    let (secret_key, public_key) = deterministic_keypair(case);

    assert_eq!(case.expected, "success");
    assert_eq!(
        sha256_hex(public_key.as_bytes()),
        output(case, "public_key_sha256")
    );
    assert_eq!(
        sha256_hex(secret_key.expose_secret()),
        output(case, "secret_key_sha256")
    );
}

fn run_encapsulate_case(case: &KatCase) {
    let (secret_key, public_key) = deterministic_keypair(case);
    let (ciphertext, shared_secret) = deterministic_encapsulation(case);
    let backend = RustCryptoBackend::new();
    let encapsulation = encapsulate_checked(&backend, &public_key).expect("backend encapsulation");

    assert_eq!(case.expected, "success");
    assert_eq!(
        sha256_hex(ciphertext.as_slice()),
        output(case, "ciphertext_sha256")
    );
    assert_eq!(
        hex(shared_secret.as_slice()),
        output(case, "shared_secret_hex")
    );
    assert_eq!(
        decapsulate_checked(&backend, &secret_key, encapsulation.ciphertext())
            .expect("decapsulate backend ciphertext")
            .as_slice(),
        encapsulation.expose_shared_secret()
    );
}

fn run_decapsulate_case(case: &KatCase) {
    let (secret_key, _public_key) = deterministic_keypair(case);
    let (ciphertext, _shared_secret) = deterministic_encapsulation(case);
    let backend = RustCryptoBackend::new();
    let decapsulated =
        decapsulate_checked(&backend, &secret_key, ciphertext.as_slice()).expect("decapsulate KAT");

    assert_eq!(case.expected, "success");
    assert_eq!(
        hex(decapsulated.as_slice()),
        output(case, "shared_secret_hex")
    );
}

fn run_invalid_public_key_case(case: &KatCase) {
    let backend = RustCryptoBackend::new();
    let public_key = PublicKey::new(KeyAlgorithm::Kem(KemAlgorithm::MlKem768), Vec::new());

    assert_eq!(
        encapsulate_checked(&backend, &public_key),
        Err(PqcbError::invalid_length("ml_kem_768.public_key", 1_184, 0))
    );
    assert_eq!(case.expected, "invalid-length");
}

fn run_invalid_secret_key_case(case: &KatCase) {
    let backend = RustCryptoBackend::new();
    let secret_key = SecretKey::new(KeyAlgorithm::Kem(KemAlgorithm::MlKem768), Vec::new());

    assert_eq!(
        decapsulate_checked(&backend, &secret_key, &[0; 1_088]),
        Err(PqcbError::invalid_length("ml_kem_768.secret_key", 2_400, 0))
    );
    assert_eq!(case.expected, "invalid-length");
}

fn run_invalid_ciphertext_case(case: &KatCase) {
    let backend = RustCryptoBackend::new();
    let (secret_key, _public_key) = deterministic_keypair(case);

    assert_eq!(
        decapsulate_checked(&backend, &secret_key, &[]),
        Err(PqcbError::invalid_length("ml_kem_768.ciphertext", 1_088, 0))
    );
    assert_eq!(case.expected, "invalid-length");
}

fn deterministic_keypair(case: &KatCase) -> (SecretKey, PublicKey) {
    let seed = seed(case);
    let (secret_key, public_key) = MlKem768::from_seed(&seed);

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
    )
}

fn deterministic_encapsulation(case: &KatCase) -> (ml_kem::ml_kem_768::Ciphertext, ml_kem::B32) {
    let seed = seed(case);
    let randomness: ml_kem::B32 = bytes(input(case, "encapsulation_randomness_hex"))
        .as_slice()
        .try_into()
        .expect("encapsulation randomness length");
    let (_secret_key, public_key) = MlKem768::from_seed(&seed);

    public_key.encapsulate_deterministic(&randomness)
}

fn seed(case: &KatCase) -> ml_kem::Seed {
    bytes(input(case, "seed_hex"))
        .as_slice()
        .try_into()
        .expect("seed length")
}

fn read_manifest(path: &Path) -> Manifest {
    let bytes = fs::read(path).expect("read ML-KEM manifest");
    serde_json::from_slice(&bytes).expect("parse ML-KEM manifest")
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
