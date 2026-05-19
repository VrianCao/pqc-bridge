//! High-level session state skeleton.

use core::fmt;

use crate::{PqcbError, Result};

/// Session lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureSessionState {
    /// Session has been created but not yet fully established.
    Setup,
    /// Session is ready to encrypt or decrypt application traffic.
    Ready,
    /// Session is closed or has entered an error terminal state.
    Closed,
}

/// Session skeleton for future hybrid migration flows.
#[derive(Clone, Eq, PartialEq)]
pub struct SecureSession {
    state: SecureSessionState,
}

impl SecureSession {
    /// Creates a new session in setup state.
    pub const fn new() -> Self {
        Self {
            state: SecureSessionState::Setup,
        }
    }

    /// Returns the current lifecycle state.
    pub const fn state(&self) -> SecureSessionState {
        self.state
    }

    /// Returns whether the session is ready.
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, SecureSessionState::Ready)
    }

    /// Returns whether the session is closed.
    pub const fn is_closed(&self) -> bool {
        matches!(self.state, SecureSessionState::Closed)
    }

    /// Marks a setup session as ready.
    ///
    /// # Errors
    ///
    /// Returns `InvalidEnvelope` when called from a non-setup state.
    pub fn mark_ready(mut self) -> Result<Self> {
        match self.state {
            SecureSessionState::Setup => {
                self.state = SecureSessionState::Ready;
                Ok(self)
            }
            SecureSessionState::Ready => Err(PqcbError::InvalidEnvelope {
                reason: "session already ready",
            }),
            SecureSessionState::Closed => Err(PqcbError::InvalidEnvelope {
                reason: "session is closed",
            }),
        }
    }

    /// Closes the session and returns the terminal object.
    #[must_use]
    pub fn close(mut self) -> Self {
        self.state = SecureSessionState::Closed;
        self
    }

    /// Returns a fail-closed error for the not-yet-implemented hybrid path.
    ///
    /// # Errors
    ///
    /// Always returns `BackendUnavailable` until the v0.5 hybrid composition is
    /// implemented.
    pub fn hybrid_unavailable() -> Result<Self> {
        Err(PqcbError::backend_unavailable("X25519-ML-KEM-768"))
    }
}

impl Default for SecureSession {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecureSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureSession")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_setup_ready_closed() {
        let session = SecureSession::new();
        assert_eq!(session.state(), SecureSessionState::Setup);

        let session = session.mark_ready().expect("transition to ready");
        assert!(session.is_ready());

        let session = session.close();
        assert!(session.is_closed());
    }

    #[test]
    fn ready_and_closed_states_fail_closed_on_invalid_transition() {
        let ready = SecureSession::new().mark_ready().expect("ready session");
        assert_eq!(
            ready.clone().mark_ready(),
            Err(PqcbError::InvalidEnvelope {
                reason: "session already ready",
            })
        );
        let closed = ready.close();
        assert_eq!(
            closed.mark_ready(),
            Err(PqcbError::InvalidEnvelope {
                reason: "session is closed",
            })
        );
    }

    #[test]
    fn hybrid_path_is_fail_closed() {
        assert_eq!(
            SecureSession::hybrid_unavailable(),
            Err(PqcbError::backend_unavailable("X25519-ML-KEM-768"))
        );
    }
}
