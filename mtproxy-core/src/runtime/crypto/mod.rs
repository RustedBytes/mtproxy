//! Safe runtime crypto helpers extracted from FFI implementations.
//!
//! This module is intentionally Rust-only: no raw pointers, no C ABI surfaces.

/// Error type for runtime crypto helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// Input shape is not valid for the requested operation.
    InvalidInput,
}

/// CRC32 reflected polynomial used by legacy runtime code.
pub const CRC32_REFLECTED_POLY: u32 = 0xedb8_8320;
/// CRC32C reflected polynomial used by legacy runtime code.
pub const CRC32C_REFLECTED_POLY: u32 = 0x82f6_3b78;

/// Computes CRC32 over `data` with the provided initial `crc`.
#[must_use]
pub fn crc32_partial(data: &[u8], mut crc: u32) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ CRC32_REFLECTED_POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Computes CRC32C over `data` with the provided initial `crc`.
#[must_use]
pub fn crc32c_partial(data: &[u8], mut crc: u32) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ CRC32C_REFLECTED_POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Checks whether a DH binary value is in acceptable prefix range.
///
/// This mirrors the deterministic prefix comparison logic currently used by
/// the FFI layer.
#[must_use]
pub fn dh_is_good_prefix(data: &[u8], prime_prefix: &[u8]) -> Result<i32, CryptoError> {
    if data.len() < 8 || prime_prefix.len() < 8 {
        return Err(CryptoError::InvalidInput);
    }
    if data[..8].iter().all(|b| *b == 0) {
        return Ok(0);
    }
    for (&data_byte, &prefix_byte) in data.iter().zip(prime_prefix.iter()).take(8) {
        if data_byte > prefix_byte {
            return Ok(0);
        }
        if data_byte < prefix_byte {
            return Ok(1);
        }
    }
    Ok(0)
}
