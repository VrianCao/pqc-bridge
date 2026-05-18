#![deny(missing_debug_implementations)]
//! C ABI layer for PQC Bridge.
//!
//! The ABI starts intentionally small. Cryptographic entry points will be added
//! once a concrete backend is integrated and covered by KAT/fuzz tests.

use core::ptr;

use pqcb_core::version::{ABI_VERSION, VERSION};

/// Status code returned by C ABI functions.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqcbStatus {
    /// Operation succeeded.
    Ok = 0,
    /// A required pointer was null.
    NullPointer = 1,
    /// A buffer length was invalid.
    InvalidLength = 2,
    /// An algorithm identifier was unknown or unsupported.
    InvalidAlgorithm = 3,
    /// No backend is available for the requested algorithm.
    BackendUnavailable = 4,
    /// Signature verification failed.
    VerificationFailed = 5,
    /// A cryptographic provider operation failed.
    CryptoFailure = 6,
    /// A panic was caught at the FFI boundary.
    Panic = 255,
}

/// Caller-owned borrowed byte buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PqcbBuffer {
    /// Borrowed pointer.
    pub data: *const u8,
    /// Buffer length in bytes.
    pub len: usize,
}

impl PqcbBuffer {
    /// Returns whether the buffer is null with a nonzero length.
    pub const fn has_invalid_null(self) -> bool {
        self.data.is_null() && self.len != 0
    }
}

/// Library-owned byte buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PqcbOwnedBuffer {
    /// Owned pointer allocated by PQC Bridge.
    pub data: *mut u8,
    /// Buffer length in bytes.
    pub len: usize,
}

/// Stable C ABI algorithm identifiers.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqcbAlgorithm {
    /// ML-KEM-768.
    MlKem768 = 1,
    /// ML-DSA-65.
    MlDsa65 = 2,
}

impl PqcbOwnedBuffer {
    /// Returns an empty owned buffer.
    pub const fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
        }
    }
}

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

/// Returns the current C ABI major version.
#[unsafe(no_mangle)]
pub extern "C" fn pqcb_abi_version_major() -> u16 {
    u16::try_from(ABI_VERSION).unwrap_or(u16::MAX)
}

/// Returns the current C ABI minor version.
#[unsafe(no_mangle)]
pub extern "C" fn pqcb_abi_version_minor() -> u16 {
    0
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

/// Returns a static status message for `status`.
#[unsafe(no_mangle)]
pub extern "C" fn pqcb_status_message(status: PqcbStatus) -> *const core::ffi::c_char {
    match status {
        PqcbStatus::Ok => c"ok",
        PqcbStatus::NullPointer => c"null pointer",
        PqcbStatus::InvalidLength => c"invalid length",
        PqcbStatus::InvalidAlgorithm => c"invalid algorithm",
        PqcbStatus::BackendUnavailable => c"backend unavailable",
        PqcbStatus::VerificationFailed => c"verification failed",
        PqcbStatus::CryptoFailure => c"cryptographic operation failed",
        PqcbStatus::Panic => c"panic caught at FFI boundary",
    }
    .as_ptr()
}

/// Reports whether a backend is available for `algorithm_id`.
///
/// # Safety
///
/// `available` must be a valid writable pointer to a `bool`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqcb_backend_available(
    algorithm_id: u32,
    available: *mut bool,
) -> PqcbStatus {
    if available.is_null() {
        return PqcbStatus::NullPointer;
    }

    let is_available = match algorithm_id {
        id if id == PqcbAlgorithm::MlKem768 as u32 => true,
        id if id == PqcbAlgorithm::MlDsa65 as u32 => true,
        _ => return PqcbStatus::InvalidAlgorithm,
    };

    // SAFETY: caller provided a non-null writable bool pointer per function contract.
    unsafe {
        *available = is_available;
    }

    PqcbStatus::Ok
}

/// Frees a library-owned buffer returned by PQC Bridge.
///
/// Passing a null/zero buffer is allowed. Passing a buffer not returned by PQC
/// Bridge is undefined behavior.
#[unsafe(no_mangle)]
pub extern "C" fn pqcb_buffer_free(buffer: PqcbOwnedBuffer) {
    if buffer.data.is_null() || buffer.len == 0 {
        return;
    }

    // SAFETY: buffers returned by `owned_buffer_from_vec` are allocated as boxed
    // slices with exactly `len` elements. The ABI contract requires callers to
    // pass each library-owned buffer back at most once.
    unsafe {
        drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
            buffer.data,
            buffer.len,
        )));
    }
}

/// Converts a vector into a C ABI owned buffer.
pub fn owned_buffer_from_vec(bytes: Vec<u8>) -> PqcbOwnedBuffer {
    if bytes.is_empty() {
        return PqcbOwnedBuffer::empty();
    }

    let mut boxed = bytes.into_boxed_slice();
    let buffer = PqcbOwnedBuffer {
        data: boxed.as_mut_ptr(),
        len: boxed.len(),
    };
    let _leaked = Box::into_raw(boxed);
    buffer
}

#[cfg(test)]
mod tests {
    use core::ffi::CStr;

    use super::*;

    #[test]
    fn status_messages_are_static_c_strings() {
        let message = pqcb_status_message(PqcbStatus::InvalidLength);

        // SAFETY: `pqcb_status_message` returns a static nul-terminated string.
        let message = unsafe { CStr::from_ptr(message) };
        assert_eq!(message.to_str(), Ok("invalid length"));
    }

    #[test]
    fn abi_major_minor_are_available() {
        assert_eq!(pqcb_abi_version(), 1);
        assert_eq!(pqcb_abi_version_major(), 1);
        assert_eq!(pqcb_abi_version_minor(), 0);
    }

    #[test]
    fn backend_availability_reports_supported_algorithms() {
        let mut available = false;

        // SAFETY: `available` is a valid writable bool pointer.
        let status =
            unsafe { pqcb_backend_available(PqcbAlgorithm::MlKem768 as u32, &raw mut available) };
        assert_eq!(status, PqcbStatus::Ok);
        assert!(available);

        available = false;
        // SAFETY: `available` is a valid writable bool pointer.
        let status =
            unsafe { pqcb_backend_available(PqcbAlgorithm::MlDsa65 as u32, &raw mut available) };
        assert_eq!(status, PqcbStatus::Ok);
        assert!(available);
    }

    #[test]
    fn backend_availability_rejects_unknown_algorithm() {
        let mut available = false;

        // SAFETY: `available` is a valid writable bool pointer.
        let status = unsafe { pqcb_backend_available(999, &raw mut available) };
        assert_eq!(status, PqcbStatus::InvalidAlgorithm);
        assert!(!available);
    }

    #[test]
    fn backend_availability_rejects_null_output() {
        // SAFETY: null pointer is intentionally tested and must be rejected.
        let status =
            unsafe { pqcb_backend_available(PqcbAlgorithm::MlKem768 as u32, ptr::null_mut()) };
        assert_eq!(status, PqcbStatus::NullPointer);
    }

    #[test]
    fn owned_buffer_round_trip_can_be_freed() {
        let buffer = owned_buffer_from_vec(vec![1, 2, 3]);

        assert!(!buffer.data.is_null());
        assert_eq!(buffer.len, 3);
        pqcb_buffer_free(buffer);
    }

    #[test]
    fn freeing_empty_buffer_is_noop() {
        pqcb_buffer_free(PqcbOwnedBuffer::empty());
    }

    #[test]
    fn borrowed_buffer_detects_invalid_null() {
        assert!(
            PqcbBuffer {
                data: ptr::null(),
                len: 1,
            }
            .has_invalid_null()
        );
        assert!(
            !PqcbBuffer {
                data: ptr::null(),
                len: 0,
            }
            .has_invalid_null()
        );
    }
}
