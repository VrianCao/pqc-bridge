#![no_main]

use core::ptr;

use libfuzzer_sys::fuzz_target;
use pqcb_ffi::{
    PqcbBuffer, PqcbOwnedBuffer, pqcb_backend_available, pqcb_buffer_free,
    pqcb_ml_dsa_65_sign, pqcb_ml_dsa_65_verify, pqcb_ml_kem_768_decapsulate,
    pqcb_ml_kem_768_encapsulate,
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let selector = data[0] % 6;
    let payload = &data[1..];

    match selector {
        0 => {
            let algorithm_id = payload
                .first()
                .copied()
                .map(u32::from)
                .unwrap_or_default();
            let mut available = false;
            // SAFETY: `available` is a valid writable bool pointer.
            let _ = unsafe { pqcb_backend_available(algorithm_id, &raw mut available) };
        }
        1 => {
            let mut ciphertext = PqcbOwnedBuffer::empty();
            let mut shared_secret = PqcbOwnedBuffer::empty();
            // SAFETY: inputs borrow fuzzer-owned memory for the duration of the call;
            // outputs are valid writable slots and are freed below.
            let _ = unsafe {
                pqcb_ml_kem_768_encapsulate(
                    borrow(payload),
                    &raw mut ciphertext,
                    &raw mut shared_secret,
                )
            };
            pqcb_buffer_free(ciphertext);
            pqcb_buffer_free(shared_secret);
        }
        2 => {
            let (secret_key, ciphertext) = split_once(payload);
            let mut shared_secret = PqcbOwnedBuffer::empty();
            // SAFETY: inputs borrow fuzzer-owned memory for the duration of the call;
            // output is a valid writable slot and is freed below.
            let _ = unsafe {
                pqcb_ml_kem_768_decapsulate(
                    borrow(secret_key),
                    borrow(ciphertext),
                    &raw mut shared_secret,
                )
            };
            pqcb_buffer_free(shared_secret);
        }
        3 => {
            let (secret_key, message) = split_once(payload);
            let mut signature = PqcbOwnedBuffer::empty();
            // SAFETY: inputs borrow fuzzer-owned memory for the duration of the call;
            // output is a valid writable slot and is freed below.
            let _ = unsafe {
                pqcb_ml_dsa_65_sign(borrow(secret_key), borrow(message), &raw mut signature)
            };
            pqcb_buffer_free(signature);
        }
        4 => {
            let (public_key, rest) = split_once(payload);
            let (message, signature) = split_once(rest);
            // SAFETY: inputs borrow fuzzer-owned memory for the duration of the call.
            let _ = unsafe {
                pqcb_ml_dsa_65_verify(borrow(public_key), borrow(message), borrow(signature))
            };
        }
        _ => {
            let mut out = PqcbOwnedBuffer::empty();
            // SAFETY: null output is intentionally exercised and must be rejected.
            let _ =
                unsafe { pqcb_ml_dsa_65_sign(borrow(payload), borrow(&[]), ptr::null_mut()) };
            pqcb_buffer_free(out);
            // SAFETY: null output is intentionally exercised and must be rejected.
            let _ = unsafe {
                pqcb_ml_kem_768_encapsulate(borrow(payload), ptr::null_mut(), &raw mut out)
            };
            pqcb_buffer_free(out);
        }
    }
});

fn borrow(data: &[u8]) -> PqcbBuffer {
    if data.is_empty() {
        return PqcbBuffer {
            data: ptr::null(),
            len: 0,
        };
    }

    PqcbBuffer {
        data: data.as_ptr(),
        len: data.len(),
    }
}

fn split_once(data: &[u8]) -> (&[u8], &[u8]) {
    if data.is_empty() {
        return (&[], &[]);
    }

    let split = usize::from(data[0]) % data.len();
    data.split_at(split)
}
