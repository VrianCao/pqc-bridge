//! Version and ABI constants.

/// Project name used in human-readable outputs.
pub const PROJECT_NAME: &str = "PQC Bridge";

/// Short package name used by crates, bindings, and CLI.
pub const PACKAGE_NAME: &str = "pqcb";

/// Current Rust crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initial C ABI major version.
pub const ABI_VERSION: u32 = 1;
