//! Signs, serializes, deserializes, and verifies a high-level signed message.

use pqcb_backend_rustcrypto::{signature, signed_message};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = signature::keypair()?;
    let signed = signed_message::sign(&keys.secret_key, b"artifact digest")?;
    let encoded = signed.to_bytes()?;
    let decoded = signed_message::from_bytes(&encoded)?;

    signed_message::verify(&keys.public_key, &decoded)?;
    println!("signed message example ok");
    Ok(())
}
