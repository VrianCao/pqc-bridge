#![deny(missing_debug_implementations)]
//! C ABI layer for PQC Bridge.
//!
//! The ABI starts intentionally small. Cryptographic entry points will be added
//! once a concrete backend is integrated and covered by KAT/fuzz tests.

use pqcb_core::version::{ABI_VERSION, VERSION};

/// Semantic version exposed through the C ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PqcbVersion {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
}

/// Returns the current C ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn pqcb_abi_version() -> u32 {
    ABI_VERSION
}

/// Returns the current PQC Bridge crate version.
#[unsafe(no_mangle)]
pub extern "C" fn pqcb_version() -> PqcbVersion {
    let mut parts = VERSION
        .split('.')
        .map(|part| part.parse::<u16>().unwrap_or(0));

    PqcbVersion {
        major: parts.next().unwrap_or(0),
        minor: parts.next().unwrap_or(0),
        patch: parts.next().unwrap_or(0),
    }
}
