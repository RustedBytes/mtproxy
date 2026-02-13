//! Helpers ported from `net/net-tcp-rpc-common.c`.

/// RPC packet types used in protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcPacketType {
    /// Encryption negotiation packet.
    Nonce = 0x7acb_87aa,
    /// Process ID verification packet.
    Handshake = 0x7682_eef5,
    /// Handshake error response.
    HandshakeError = 0x6a27_beda,
    /// Ping request.
    Ping = 0x7bde_f2a4,
    /// Pong response (value needs cast from u32).
    Pong = -1_948_322_907,
}

impl RpcPacketType {
    /// Converts `i32` to `RpcPacketType` if it matches a known type.
    #[must_use]
    pub const fn from_i32(value: i32) -> Option<Self> {
        match value {
            0x7acb_87aa => Some(Self::Nonce),
            0x7682_eef5 => Some(Self::Handshake),
            0x6a27_beda => Some(Self::HandshakeError),
            0x7bde_f2a4 => Some(Self::Ping),
            -1_948_322_907 => Some(Self::Pong), // 0x8bde_f3a5 as i32
            _ => None,
        }
    }

    /// Converts `RpcPacketType` to `i32`.
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self as i32
    }
}

/// Process identifier for RPC connections (IP address + port + PID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessId {
    /// IPv4 address in network byte order.
    pub ip: u32,
    /// Port number.
    pub port: u16,
    /// Process ID.
    pub pid: i32,
    /// Unique instance ID.
    pub utime: i32,
}

impl ProcessId {
    /// Creates a new `ProcessId`.
    #[must_use]
    pub const fn new(ip: u32, port: u16, pid: i32, utime: i32) -> Self {
        Self { ip, port, pid, utime }
    }

    /// Checks if `ProcessId` is valid (non-zero).
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.ip != 0 || self.port != 0 || self.pid != 0
    }
}

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
    use super::{encode_compact_header, ProcessId, RpcPacketType};

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

    #[test]
    fn rpc_packet_type_conversion() {
        assert_eq!(RpcPacketType::from_i32(0x7acb_87aa), Some(RpcPacketType::Nonce));
        assert_eq!(RpcPacketType::from_i32(0x7682_eef5), Some(RpcPacketType::Handshake));
        assert_eq!(RpcPacketType::from_i32(0x6a27_beda), Some(RpcPacketType::HandshakeError));
        assert_eq!(RpcPacketType::from_i32(0x7bde_f2a4), Some(RpcPacketType::Ping));
        assert_eq!(RpcPacketType::from_i32(-1_948_322_907), Some(RpcPacketType::Pong)); // 0x8bde_f3a5
        assert_eq!(RpcPacketType::from_i32(0), None);
    }

    #[test]
    fn rpc_packet_type_roundtrip() {
        assert_eq!(RpcPacketType::Nonce.to_i32(), 0x7acb_87aa);
        assert_eq!(
            RpcPacketType::from_i32(RpcPacketType::Handshake.to_i32()),
            Some(RpcPacketType::Handshake)
        );
    }

    #[test]
    fn process_id_validation() {
        let pid = ProcessId::default();
        assert!(!pid.is_valid());

        let pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        assert!(pid.is_valid());
        assert_eq!(pid.ip, 0x7f00_0001);
        assert_eq!(pid.port, 8080);
        assert_eq!(pid.pid, 12345);
    }
}
