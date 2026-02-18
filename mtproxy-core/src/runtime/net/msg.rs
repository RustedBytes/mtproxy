//! Runtime helpers.

pub const TL_MARKER_SHORT: i32 = 0;
pub const TL_MARKER_LONG: i32 = 1;
pub const TL_MARKER_INVALID: i32 = -1;

/// Classifies first TL string length marker byte.
///
/// Matches `rwm_from_tl_string()` behavior:
/// - `0xff` is invalid
/// - `0xfe` means 3-byte length follows
/// - otherwise short length
#[must_use]
pub const fn tl_string_marker_kind(marker: i32) -> i32 {
    if marker == 0xff {
        TL_MARKER_INVALID
    } else if marker == 0xfe {
        TL_MARKER_LONG
    } else {
        TL_MARKER_SHORT
    }
}

/// Computes TL string padding bytes (`(-len) & 3`).
#[must_use]
pub const fn tl_string_padding(total_bytes: i32) -> i32 {
    (-total_bytes) & 3
}

/// Computes effective bytes processed by `rwm_encrypt_decrypt_to`.
///
/// Clamp to available bytes, then align down to block size.
#[must_use]
pub const fn encrypt_decrypt_effective_bytes(
    requested_bytes: i32,
    total_bytes: i32,
    block_size: i32,
) -> i32 {
    if requested_bytes <= 0 || total_bytes <= 0 || block_size <= 0 {
        return 0;
    }
    let mut bytes = if requested_bytes > total_bytes {
        total_bytes
    } else {
        requested_bytes
    };
    if (block_size & (block_size - 1)) != 0 {
        return 0;
    }
    bytes &= -block_size;
    bytes
}

#[cfg(test)]
mod tests {
    use super::{
        encrypt_decrypt_effective_bytes, tl_string_marker_kind, tl_string_padding,
        TL_MARKER_INVALID, TL_MARKER_LONG, TL_MARKER_SHORT,
    };

    #[test]
    fn tl_marker_kind_matches_c_rules() {
        assert_eq!(tl_string_marker_kind(0), TL_MARKER_SHORT);
        assert_eq!(tl_string_marker_kind(0xfd), TL_MARKER_SHORT);
        assert_eq!(tl_string_marker_kind(0xfe), TL_MARKER_LONG);
        assert_eq!(tl_string_marker_kind(0xff), TL_MARKER_INVALID);
    }

    #[test]
    fn tl_padding_matches_bit_formula() {
        assert_eq!(tl_string_padding(0), 0);
        assert_eq!(tl_string_padding(1), 3);
        assert_eq!(tl_string_padding(2), 2);
        assert_eq!(tl_string_padding(3), 1);
        assert_eq!(tl_string_padding(4), 0);
    }

    #[test]
    fn encrypt_decrypt_effective_bytes_clamps_and_aligns() {
        assert_eq!(encrypt_decrypt_effective_bytes(100, 80, 16), 80);
        assert_eq!(encrypt_decrypt_effective_bytes(79, 200, 16), 64);
        assert_eq!(encrypt_decrypt_effective_bytes(7, 200, 16), 0);
        assert_eq!(encrypt_decrypt_effective_bytes(100, 80, 1), 80);
    }

    #[test]
    fn encrypt_decrypt_effective_bytes_rejects_invalid_inputs() {
        assert_eq!(encrypt_decrypt_effective_bytes(-1, 80, 16), 0);
        assert_eq!(encrypt_decrypt_effective_bytes(100, 0, 16), 0);
        assert_eq!(encrypt_decrypt_effective_bytes(100, 80, 0), 0);
        assert_eq!(encrypt_decrypt_effective_bytes(100, 80, 24), 0);
    }
}
