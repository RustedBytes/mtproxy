//! Helpers ported from `net/net-tcp-rpc-client.c`.

pub const PACKET_LEN_STATE_SKIP: i32 = 0;
pub const PACKET_LEN_STATE_READY: i32 = 1;
pub const PACKET_LEN_STATE_INVALID: i32 = -1;
pub const PACKET_LEN_STATE_SHORT: i32 = -2;

/// Classifies non-compact tcp-rpc client packet length.
#[must_use]
pub fn packet_len_state(packet_len: i32, max_packet_len: i32) -> i32 {
    if packet_len <= 0
        || (packet_len & 3) != 0
        || (max_packet_len > 0 && packet_len > max_packet_len)
    {
        return PACKET_LEN_STATE_INVALID;
    }
    if packet_len == 4 {
        return PACKET_LEN_STATE_SKIP;
    }
    if packet_len < 16 {
        return PACKET_LEN_STATE_SHORT;
    }
    PACKET_LEN_STATE_READY
}

#[cfg(test)]
mod tests {
    use super::{
        packet_len_state, PACKET_LEN_STATE_INVALID, PACKET_LEN_STATE_READY, PACKET_LEN_STATE_SHORT,
        PACKET_LEN_STATE_SKIP,
    };

    #[test]
    fn classifies_known_lengths() {
        assert_eq!(packet_len_state(4, 1024), PACKET_LEN_STATE_SKIP);
        assert_eq!(packet_len_state(12, 1024), PACKET_LEN_STATE_SHORT);
        assert_eq!(packet_len_state(16, 1024), PACKET_LEN_STATE_READY);
        assert_eq!(packet_len_state(3, 1024), PACKET_LEN_STATE_INVALID);
        assert_eq!(packet_len_state(2048, 1024), PACKET_LEN_STATE_INVALID);
    }
}
