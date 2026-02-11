//! Helpers ported from `net/net-tcp-rpc-common.c`.

/// Encodes compact/medium tcp-rpc packet header prefix.
#[must_use]
pub fn encode_compact_header(payload_len: i32, is_medium: i32) -> (i32, i32) {
    if is_medium != 0 {
        return (payload_len, 4);
    }
    if payload_len <= 0x7e * 4 {
        return (payload_len >> 2, 1);
    }
    let len_u = u32::from_ne_bytes(payload_len.to_ne_bytes());
    let encoded = (len_u << 6) | 0x7f;
    (i32::from_ne_bytes(encoded.to_ne_bytes()), 4)
}

#[cfg(test)]
mod tests {
    use super::encode_compact_header;

    #[test]
    fn medium_mode_keeps_full_len() {
        assert_eq!(encode_compact_header(512, 1), (512, 4));
    }

    #[test]
    fn compact_short_len_uses_single_byte_prefix() {
        assert_eq!(encode_compact_header(64, 0), (16, 1));
    }

    #[test]
    fn compact_large_len_uses_wide_prefix() {
        let (word, bytes) = encode_compact_header(2_000, 0);
        let expected = (u32::from_ne_bytes(2_000_i32.to_ne_bytes()) << 6) | 0x7f;
        assert_eq!(u32::from_ne_bytes(word.to_ne_bytes()), expected);
        assert_eq!(bytes, 4);
    }
}
