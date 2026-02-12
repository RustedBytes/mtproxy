//! FFI bindings for IP address formatting utilities.
//!
//! This module provides C-compatible FFI functions that replace the
//! functionality from `vv/vv-io.h`.
//!
//! # Thread Safety
//!
//! The FFI functions use static buffers to match the C implementation behavior.
//! **These functions are NOT thread-safe** and should only be called from a
//! single thread or with external synchronization. This matches the original
//! C implementation which also used static buffers.

use core::ffi::{c_char, c_void};
use core::ptr;

use mtproxy_core::runtime::collections::ip_format;

const VV_IPV4_FORMAT_BUFFER_LEN: usize = 16;
const VV_IPV6_FORMAT_BUFFER_LEN: usize = 100;

/// Thread-local buffer for IPv4 formatting to avoid heap allocation.
///
/// This matches the static buffer behavior of the C implementation.
/// **WARNING**: This is NOT thread-safe across multiple threads without
/// external synchronization.
#[no_mangle]
static mut VV_IPV4_FORMAT_BUFFER: [c_char; VV_IPV4_FORMAT_BUFFER_LEN] =
    [0; VV_IPV4_FORMAT_BUFFER_LEN];

/// Thread-local buffer for IPv6 formatting.
///
/// **WARNING**: This is NOT thread-safe across multiple threads without
/// external synchronization.
#[no_mangle]
static mut VV_IPV6_FORMAT_BUFFER: [c_char; VV_IPV6_FORMAT_BUFFER_LEN] =
    [0; VV_IPV6_FORMAT_BUFFER_LEN];

/// Formats an IPv4 address into a static buffer.
///
/// # Safety
/// - This function uses a mutable static buffer and is NOT thread-safe
/// - Multiple concurrent calls will cause undefined behavior (data races)
/// - The buffer is reused on each call, so the returned pointer is only
///   valid until the next call to this function
/// - This matches the behavior of the original C implementation
///
/// # Arguments
/// * `addr` - IPv4 address as a 32-bit integer in host byte order
///
/// # Returns
/// A pointer to a null-terminated string in a static buffer.
#[no_mangle]
pub unsafe extern "C" fn vv_format_ipv4(addr: u32) -> *const c_char {
    let formatted = ip_format::format_ipv4(addr);
    let bytes = formatted.as_bytes();

    let dst = ptr::addr_of_mut!(VV_IPV4_FORMAT_BUFFER).cast::<u8>();
    // Copy to static buffer
    let len = bytes.len().min(VV_IPV4_FORMAT_BUFFER_LEN - 1);
    ptr::copy_nonoverlapping(bytes.as_ptr(), dst, len);
    *dst.add(len) = 0; // Null terminate

    dst.cast::<c_char>()
}

/// Formats an IPv6 address into a static buffer.
///
/// # Safety
/// - `ipv6_bytes` must point to a valid 16-byte array
/// - This function uses a mutable static buffer and is NOT thread-safe
/// - Multiple concurrent calls will cause undefined behavior (data races)
/// - The buffer is reused on each call, so the returned pointer is only
///   valid until the next call to this function
/// - This matches the behavior of the original C implementation
///
/// # Arguments
/// * `ipv6_bytes` - Pointer to 16 bytes representing an IPv6 address
///
/// # Returns
/// A pointer to a null-terminated string in a static buffer.
#[no_mangle]
pub unsafe extern "C" fn vv_format_ipv6(ipv6_bytes: *const c_void) -> *const c_char {
    if ipv6_bytes.is_null() {
        return ptr::null();
    }

    // Read 16 bytes from the pointer
    let mut addr = [0u8; 16];
    ptr::copy_nonoverlapping(ipv6_bytes as *const u8, addr.as_mut_ptr(), 16);

    let formatted = ip_format::format_ipv6(&addr);
    let bytes = formatted.as_bytes();

    let dst = ptr::addr_of_mut!(VV_IPV6_FORMAT_BUFFER).cast::<u8>();
    // Copy to static buffer
    let len = bytes.len().min(VV_IPV6_FORMAT_BUFFER_LEN - 1);
    ptr::copy_nonoverlapping(bytes.as_ptr(), dst, len);
    *dst.add(len) = 0; // Null terminate

    dst.cast::<c_char>()
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
    if out.is_null() {
        return;
    }

    *out.add(0) = ((addr >> 24) & 0xff) as u8;
    *out.add(1) = ((addr >> 16) & 0xff) as u8;
    *out.add(2) = ((addr >> 8) & 0xff) as u8;
    *out.add(3) = (addr & 0xff) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;

    #[test]
    fn test_vv_format_ipv4() {
        unsafe {
            // Test localhost 127.0.0.1
            let ptr = vv_format_ipv4(0x7f000001);
            assert!(!ptr.is_null());
            
            let c_str = CStr::from_ptr(ptr);
            let rust_str = c_str.to_str().unwrap();
            assert_eq!(rust_str, "127.0.0.1");
            
            // Test 192.168.1.1
            let ptr = vv_format_ipv4(0xc0a80101);
            let c_str = CStr::from_ptr(ptr);
            let rust_str = c_str.to_str().unwrap();
            assert_eq!(rust_str, "192.168.1.1");
        }
    }

    #[test]
    fn test_vv_ipv4_to_octets() {
        unsafe {
            let mut octets = [0u8; 4];
            vv_ipv4_to_octets(0xc0a80101, octets.as_mut_ptr());
            assert_eq!(octets, [192, 168, 1, 1]);
        }
    }

    #[test]
    fn test_vv_format_ipv6() {
        unsafe {
            // Test loopback ::1
            let mut addr = [0u8; 16];
            addr[15] = 1;
            
            let ptr = vv_format_ipv6(addr.as_ptr() as *const c_void);
            assert!(!ptr.is_null());
            
            let c_str = CStr::from_ptr(ptr);
            let rust_str = c_str.to_str().unwrap();
            // Just verify it's non-empty and valid
            assert!(!rust_str.is_empty());
        }
    }
}
