//! Seals, serializes, deserializes, and opens a high-level sealed box.

use pqcb_backend_rustcrypto::{kem, sealed_box};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = kem::keypair()?;
    let sealed = sealed_box::seal(&keys.public_key, b"short secret")?;
    let encoded = sealed.to_bytes()?;
    let decoded = sealed_box::from_bytes(&encoded)?;
    let plaintext = sealed_box::open(&keys.secret_key, &decoded)?;

    assert_eq!(plaintext, b"short secret");
    println!("sealed box example ok");
    Ok(())
}
