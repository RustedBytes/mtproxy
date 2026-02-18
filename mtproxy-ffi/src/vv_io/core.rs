//! FFI bindings for IP address formatting utilities.
//!
//! This module provides C-compatible FFI functions that replace the
//! functionality from `vv/vv-io.h`.
//!
//! # Buffer Semantics
//!
//! The formatting functions return pointers into thread-local scratch buffers.
//! Concurrent calls from different threads do not race; repeated calls on the
//! same thread overwrite the previous result, which matches the legacy
//! single-buffer usage contract.

use crate::ffi_util::{copy_bytes, mut_slice_from_ptr};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void};
use core::ptr;
use std::thread::LocalKey;

use mtproxy_core::runtime::collections::ip_format;

const VV_IPV4_FORMAT_BUFFER_LEN: usize = 16;
const VV_IPV6_FORMAT_BUFFER_LEN: usize = 100;

std::thread_local! {
    static VV_IPV4_FORMAT_BUFFER: UnsafeCell<[u8; VV_IPV4_FORMAT_BUFFER_LEN]> =
        const { UnsafeCell::new([0; VV_IPV4_FORMAT_BUFFER_LEN]) };
    static VV_IPV6_FORMAT_BUFFER: UnsafeCell<[u8; VV_IPV6_FORMAT_BUFFER_LEN]> =
        const { UnsafeCell::new([0; VV_IPV6_FORMAT_BUFFER_LEN]) };
}

fn write_tls_c_string<const N: usize>(
    tls_buffer: &'static LocalKey<UnsafeCell<[u8; N]>>,
    bytes: &[u8],
) -> *const c_char {
    tls_buffer.with(|cell| {
        // SAFETY: each thread gets its own buffer; writes are confined to this closure.
        let buffer = unsafe { &mut *cell.get() };
        let len = bytes.len().min(N - 1);
        buffer[..len].copy_from_slice(&bytes[..len]);
        buffer[len] = 0;
        buffer.as_ptr().cast::<c_char>()
    })
}

/// Formats an IPv4 address into a thread-local buffer.
///
/// The returned pointer is valid until the next `vv_format_ipv4` call on the
/// same thread.
///
/// # Arguments
/// * `addr` - IPv4 address as a 32-bit integer in host byte order
///
/// # Returns
/// A pointer to a null-terminated string in a thread-local buffer.
#[no_mangle]
pub extern "C" fn vv_format_ipv4(addr: u32) -> *const c_char {
    let formatted = ip_format::format_ipv4(addr);
    write_tls_c_string(&VV_IPV4_FORMAT_BUFFER, formatted.as_bytes())
}

/// Formats an IPv6 address into a thread-local buffer.
///
/// # Safety
/// - `ipv6_bytes` must point to a valid 16-byte array
/// - The returned pointer is valid until the next `vv_format_ipv6` call on the
///   same thread
///
/// # Arguments
/// * `ipv6_bytes` - Pointer to 16 bytes representing an IPv6 address
///
/// # Returns
/// A pointer to a null-terminated string in a thread-local buffer.
#[no_mangle]
pub unsafe extern "C" fn vv_format_ipv6(ipv6_bytes: *const c_void) -> *const c_char {
    let Some(addr) = (unsafe { copy_bytes::<16>(ipv6_bytes.cast::<u8>()) }) else {
        return ptr::null();
    };

    let formatted = ip_format::format_ipv6(&addr);
    write_tls_c_string(&VV_IPV6_FORMAT_BUFFER, formatted.as_bytes())
}

/// Extracts IPv4 octets for printf-style formatting.
///
/// # Safety
/// `out` must point to a valid array of at least 4 u8 values.
///
/// # Arguments
/// * `addr` - IPv4 address as a 32-bit integer in host byte order
/// * `out` - Output array for the 4 octets
#[no_mangle]
pub unsafe extern "C" fn vv_ipv4_to_octets(addr: u32, out: *mut u8) {
    let Some(out_bytes) = (unsafe { mut_slice_from_ptr(out, 4) }) else {
        return;
    };
    out_bytes.copy_from_slice(&addr.to_be_bytes());
}
