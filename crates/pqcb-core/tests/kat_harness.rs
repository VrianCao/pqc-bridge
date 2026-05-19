//! KAT manifest loader and dispatcher smoke tests.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const KAT_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/kat");

#[derive(Debug, Deserialize)]
struct Manifest {
    schema_version: String,
    algorithm: String,
    parameter_set: String,
    upstream: Upstream,
    source: Source,
    generation: Generation,
    checksum: Checksum,
    cases: Vec<KatCase>,
}

#[derive(Debug, Deserialize)]
struct Upstream {
    name: String,
    repository: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct Source {
    name: String,
    url: String,
    license: String,
    redistribution: String,
}

#[derive(Debug, Deserialize)]
struct Generation {
    method: String,
    command: String,
    date: String,
}

#[derive(Debug, Deserialize)]
struct Checksum {
    algorithm: String,
    value: String,
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
fn kat_harness_loads_and_dispatches_manifests() {
    let manifests = discover_manifests(Path::new(KAT_ROOT)).expect("discover KAT manifests");

    assert!(!manifests.is_empty(), "expected at least one KAT manifest");
    for path in manifests {
        let manifest = read_manifest(&path).expect("read valid KAT manifest");
        validate_manifest(&manifest).expect("validate KAT manifest");
        dispatch_manifest(&manifest).expect("dispatch KAT manifest");
    }
}

#[test]
fn malformed_manifest_fails_loudly() {
    let path = Path::new(KAT_ROOT).join("malformed-manifest.json");
    let error = read_manifest(&path)
        .and_then(|manifest| validate_manifest(&manifest))
        .expect_err("malformed fixture must fail validation");

    assert!(
        error.contains("missing field `cases`"),
        "unexpected validation error: {error}"
    );
}

#[test]
fn missing_manifest_fails_loudly() {
    let path = Path::new(KAT_ROOT).join("missing-manifest.json");
    let error = read_manifest(&path).expect_err("missing fixture must fail");

    assert!(
        error.contains("read") && error.contains("missing-manifest.json"),
        "unexpected missing-file error: {error}"
    );
}

fn discover_manifests(root: &Path) -> Result<Vec<PathBuf>, String> {
    let sample = root.join("sample-manifest.json");
    if !sample.is_file() {
        return Err(format!("missing sample manifest: {}", sample.display()));
    }

    let mut manifests = vec![sample];
    for entry in fs::read_dir(root).map_err(|error| format!("read {}: {error}", root.display()))? {
        let path = entry
            .map_err(|error| format!("read directory entry in {}: {error}", root.display()))?
            .path();
        let manifest = path.join("manifest.json");
        if manifest.is_file() {
            manifests.push(manifest);
        }
    }

    manifests.sort();
    manifests.dedup();
    Ok(manifests)
}

fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn validate_manifest(manifest: &Manifest) -> Result<(), String> {
    require_eq("schema_version", &manifest.schema_version, "1")?;
    require_present("algorithm", &manifest.algorithm)?;
    require_present("parameter_set", &manifest.parameter_set)?;
    require_present("upstream.name", &manifest.upstream.name)?;
    require_present("upstream.repository", &manifest.upstream.repository)?;
    require_present("upstream.version", &manifest.upstream.version)?;
    require_present("source.name", &manifest.source.name)?;
    require_present("source.url", &manifest.source.url)?;
    require_present("source.license", &manifest.source.license)?;
    require_present("source.redistribution", &manifest.source.redistribution)?;
    validate_generation(&manifest.generation)?;
    require_eq(
        "checksum.algorithm",
        &manifest.checksum.algorithm,
        "SHA-256",
    )?;
    validate_hex_digest(&manifest.checksum.value)?;

    if manifest.cases.is_empty() {
        return Err("cases must not be empty".to_owned());
    }

    let mut has_positive = false;
    let mut has_negative = false;
    for case in &manifest.cases {
        validate_case(case)?;
        has_positive |= case.case_type == "positive";
        has_negative |= case.case_type == "negative";
    }

    if !has_positive || !has_negative {
        return Err("manifest must include positive and negative cases".to_owned());
    }

    Ok(())
}

fn validate_generation(generation: &Generation) -> Result<(), String> {
    match generation.method.as_str() {
        "upstream" | "nist-acvp" | "wycheproof" | "project-generated" | "manual-negative" => {}
        method => return Err(format!("generation.method is unsupported: {method}")),
    }
    require_present("generation.command", &generation.command)?;
    validate_date(&generation.date)
}

fn validate_case(case: &KatCase) -> Result<(), String> {
    require_present("case.id", &case.id)?;
    match case.case_type.as_str() {
        "positive" | "negative" => {}
        case_type => {
            return Err(format!(
                "case {} has unsupported type: {case_type}",
                case.id
            ));
        }
    }
    require_present("case.operation", &case.operation)?;
    match case.expected.as_str() {
        "success"
        | "invalid-length"
        | "verification-failed"
        | "crypto-failure"
        | "changed-secret" => {}
        expected => {
            return Err(format!(
                "case {} has unsupported expected result: {expected}",
                case.id
            ));
        }
    }
    if case.inputs.is_empty() {
        return Err(format!("case {} inputs must not be empty", case.id));
    }
    if case.case_type == "positive" && case.outputs.is_empty() {
        return Err(format!("case {} outputs must not be empty", case.id));
    }
    if case.case_type == "negative" && case.expected == "success" {
        return Err(format!(
            "case {} negative case cannot expect success",
            case.id
        ));
    }

    Ok(())
}

fn dispatch_manifest(manifest: &Manifest) -> Result<(), String> {
    let dispatch = match (manifest.algorithm.as_str(), manifest.parameter_set.as_str()) {
        ("ML-KEM", "ML-KEM-768") => dispatch_ml_kem_case,
        ("ML-DSA", "ML-DSA-65") => dispatch_ml_dsa_case,
        ("Hybrid KEM", "X25519-ML-KEM-768") => dispatch_hybrid_case,
        (algorithm, parameter_set) => {
            return Err(format!(
                "unsupported KAT manifest target: {algorithm} {parameter_set}"
            ));
        }
    };

    for case in &manifest.cases {
        dispatch(case)?;
    }

    Ok(())
}

fn dispatch_ml_kem_case(case: &KatCase) -> Result<(), String> {
    match case.operation.as_str() {
        "keygen" | "encapsulate" | "decapsulate" => Ok(()),
        operation => Err(format!(
            "case {} unsupported ML-KEM operation: {operation}",
            case.id
        )),
    }
}

fn dispatch_ml_dsa_case(case: &KatCase) -> Result<(), String> {
    match case.operation.as_str() {
        "keygen" | "sign" | "verify" => Ok(()),
        operation => Err(format!(
            "case {} unsupported ML-DSA operation: {operation}",
            case.id
        )),
    }
}

fn dispatch_hybrid_case(case: &KatCase) -> Result<(), String> {
    match case.operation.as_str() {
        "decapsulate" => Ok(()),
        operation => Err(format!(
            "case {} unsupported hybrid operation: {operation}",
            case.id
        )),
    }
}

fn require_present(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_eq(field: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} must be {expected}, got {actual}"))
    }
}

fn validate_hex_digest(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("checksum.value must be a 64-character hex digest".to_owned())
    }
}

fn validate_date(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() == 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
    {
        Ok(())
    } else {
        Err(format!("generation.date must be YYYY-MM-DD, got {value}"))
    }
}
