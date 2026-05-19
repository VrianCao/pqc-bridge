//! Demonstrates the v0.4 secure-session state-machine skeleton.

use pqcb_core::{PqcbError, SecureSession};

fn main() -> Result<(), PqcbError> {
    let session = SecureSession::new();
    let ready = session.mark_ready()?;
    let closed = ready.close();

    assert!(closed.is_closed());
    assert!(matches!(
        SecureSession::hybrid_unavailable(),
        Err(PqcbError::BackendUnavailable { .. })
    ));

    println!("secure session skeleton example ok");
    Ok(())
}
