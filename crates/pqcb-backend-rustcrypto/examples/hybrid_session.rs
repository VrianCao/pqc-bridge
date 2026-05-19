//! Hybrid `X25519-ML-KEM-768` session setup example.

use pqcb_backend_rustcrypto::hybrid;

fn main() -> pqcb_core::Result<()> {
    let responder = hybrid::keypair()?;
    let context = b"pqcb example hybrid session v1";
    let encapsulation = hybrid::encapsulate(&responder.public_key, context)?;
    let decapsulated = hybrid::decapsulate(
        &responder.secret_key,
        &responder.public_key,
        &encapsulation,
        context,
    )?;

    assert_eq!(
        encapsulation.expose_shared_secret(),
        decapsulated.as_slice()
    );
    println!(
        "hybrid profile established: ciphertext_len={}, shared_secret_len={}",
        encapsulation.kem_ciphertext().len(),
        decapsulated.len()
    );

    Ok(())
}
