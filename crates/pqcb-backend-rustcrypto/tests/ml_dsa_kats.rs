//! ML-DSA-65 KAT coverage for the `RustCrypto` backend.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use ml_dsa::{Keypair, MlDsa65, SigningKey};
use pqcb_core::{
    KeyAlgorithm, PqcbError, PublicKey, SecretKey, SignatureAlgorithm, Verification, sign_checked,
    verify_checked,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use pqcb_backend_rustcrypto::RustCryptoBackend;

const MANIFEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/ml-dsa-65/manifest.json"
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
fn ml_dsa_65_kats_pass() {
    let manifest = read_manifest(Path::new(MANIFEST));

    for case in &manifest.cases {
        match (case.case_type.as_str(), case.operation.as_str()) {
            ("positive", "keygen") => run_keygen_case(case),
            ("positive", "sign") => run_sign_case(case),
            ("positive", "verify") => run_verify_case(case),
            ("negative", "verify") if case.id.ends_with("tampered-message") => {
                run_tampered_message_case(case);
            }
            ("negative", "verify") if case.id.ends_with("tampered-signature") => {
                run_tampered_signature_case(case);
            }
            ("negative", "verify") if case.id.ends_with("wrong-public-key") => {
                run_wrong_key_case(case);
            }
            _ => panic!("unsupported KAT case {}", case.id),
        }
    }
}

fn run_keygen_case(case: &KatCase) {
    let (secret_key, public_key) = deterministic_keypair(input(case, "seed_hex"));

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

fn run_sign_case(case: &KatCase) {
    let (secret_key, _public_key) = deterministic_keypair(input(case, "seed_hex"));
    let backend = RustCryptoBackend::new();
    let message = bytes(input(case, "message_hex"));
    let signature = sign_checked(&backend, &secret_key, &message).expect("sign KAT");

    assert_eq!(case.expected, "success");
    assert_eq!(sha256_hex(&signature), output(case, "signature_sha256"));
}

fn run_verify_case(case: &KatCase) {
    let (secret_key, public_key) = deterministic_keypair(input(case, "seed_hex"));
    let backend = RustCryptoBackend::new();
    let message = bytes(input(case, "message_hex"));
    let signature = sign_checked(&backend, &secret_key, &message).expect("sign KAT");
    let verification =
        verify_checked(&backend, &public_key, &message, &signature).expect("verify KAT");

    assert_eq!(verification, Verification::Valid);
    assert_eq!(output(case, "verification"), "valid");
}

fn run_tampered_message_case(case: &KatCase) {
    let (secret_key, public_key) = deterministic_keypair(input(case, "seed_hex"));
    let backend = RustCryptoBackend::new();
    let original_message = b"PQC Bridge ML-DSA-65 KAT";
    let tampered_message = bytes(input(case, "message_hex"));
    let signature = sign_checked(&backend, &secret_key, original_message).expect("sign KAT");

    assert_eq!(
        verify_checked(&backend, &public_key, &tampered_message, &signature),
        Err(PqcbError::VerificationFailed)
    );
}

fn run_tampered_signature_case(case: &KatCase) {
    let (_secret_key, public_key) = deterministic_keypair(input(case, "seed_hex"));
    let backend = RustCryptoBackend::new();
    let message = bytes(input(case, "message_hex"));
    let mut signature = bytes(input(case, "signature_hex"));
    signature.resize(3_309, 0);

    assert_eq!(
        verify_checked(&backend, &public_key, &message, &signature),
        Err(PqcbError::VerificationFailed)
    );
}

fn run_wrong_key_case(case: &KatCase) {
    let (secret_key, _public_key) = deterministic_keypair(input(case, "seed_hex"));
    let (_wrong_secret_key, wrong_public_key) =
        deterministic_keypair(input(case, "wrong_seed_hex"));
    let backend = RustCryptoBackend::new();
    let message = bytes(input(case, "message_hex"));
    let signature = sign_checked(&backend, &secret_key, &message).expect("sign KAT");

    assert_eq!(
        verify_checked(&backend, &wrong_public_key, &message, &signature),
        Err(PqcbError::VerificationFailed)
    );
}

fn deterministic_keypair(seed_hex: &str) -> (SecretKey, PublicKey) {
    let seed: ml_dsa::Seed = bytes(seed_hex).as_slice().try_into().expect("seed length");
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let public_key = signing_key.verifying_key().encode();

    #[allow(deprecated)]
    let secret_key = signing_key.expanded_key().to_expanded();

    (
        SecretKey::new(
            KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
            secret_key.as_slice().to_vec(),
        ),
        PublicKey::new(
            KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
            public_key.as_slice().to_vec(),
        ),
    )
}

fn read_manifest(path: &Path) -> Manifest {
    let bytes = fs::read(path).expect("read ML-DSA manifest");
    serde_json::from_slice(&bytes).expect("parse ML-DSA manifest")
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
