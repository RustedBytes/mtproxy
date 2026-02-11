//! Helpers ported from `net/net-tcp-rpc-server.c`.

use super::tcp_rpc_client::{
    PACKET_LEN_STATE_INVALID, PACKET_LEN_STATE_READY, PACKET_LEN_STATE_SKIP,
};

const PACKET_HEADER_INVALID_MASK: i32 = i32::from_ne_bytes(0xc000_0003_u32.to_ne_bytes());

/// Returns `1` when tcp-rpc server packet header is malformed.
#[must_use]
pub fn packet_header_malformed(packet_len: i32) -> i32 {
    i32::from(packet_len <= 0 || (packet_len & PACKET_HEADER_INVALID_MASK) != 0)
}

/// Classifies non-compact tcp-rpc server packet length.
#[must_use]
pub fn packet_len_state(packet_len: i32, max_packet_len: i32) -> i32 {
    if max_packet_len > 0 && packet_len > max_packet_len {
        return PACKET_LEN_STATE_INVALID;
    }
    if packet_len == 4 {
        return PACKET_LEN_STATE_SKIP;
    }
    if packet_len < 16 {
        return PACKET_LEN_STATE_INVALID;
    }
    PACKET_LEN_STATE_READY
}

#[cfg(test)]
mod tests {
    use super::{packet_header_malformed, packet_len_state};
    use crate::runtime::net::tcp_rpc_client::{
        PACKET_LEN_STATE_INVALID, PACKET_LEN_STATE_READY, PACKET_LEN_STATE_SKIP,
    };

    #[test]
    fn detects_bad_headers() {
        assert_eq!(packet_header_malformed(0), 1);
        assert_eq!(
            packet_header_malformed(i32::from_ne_bytes(0xc000_0000_u32.to_ne_bytes())),
            1
        );
        assert_eq!(packet_header_malformed(16), 0);
    }

    #[test]
    fn classifies_packet_lengths() {
        assert_eq!(packet_len_state(4, 1024), PACKET_LEN_STATE_SKIP);
        assert_eq!(packet_len_state(16, 1024), PACKET_LEN_STATE_READY);
        assert_eq!(packet_len_state(2_048, 1_024), PACKET_LEN_STATE_INVALID);
    }
}
