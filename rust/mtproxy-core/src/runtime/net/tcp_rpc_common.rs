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
    /// Pong response (`0x8bde_f3a5` as `i32` = `-1948322907`).
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
///
/// This matches the C `struct process_id` layout from `common/pid.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct ProcessId {
    /// IPv4 address in network byte order.
    pub ip: u32,
    /// Port number (signed to match C struct).
    pub port: i16,
    /// Process ID (unsigned 16-bit to match C struct).
    pub pid: u16,
    /// Unique instance ID.
    pub utime: i32,
}

impl ProcessId {
    /// Creates a new `ProcessId`.
    #[must_use]
    pub const fn new(ip: u32, port: i16, pid: u16, utime: i32) -> Self {
        Self { ip, port, pid, utime }
    }

    /// Checks if `ProcessId` is valid (non-zero).
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.ip != 0 || self.port != 0 || self.pid != 0
    }
}

/// Crypto schema types for RPC nonce negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CryptoSchema {
    /// No encryption.
    None = 0,
    /// AES encryption with single key.
    Aes = 1,
    /// AES encryption with extra key options.
    AesExt = 2,
    /// AES encryption with Diffie-Hellman key exchange.
    AesDh = 3,
}

impl CryptoSchema {
    /// Converts `i32` to `CryptoSchema`.
    #[must_use]
    pub const fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Aes),
            2 => Some(Self::AesExt),
            3 => Some(Self::AesDh),
            _ => None,
        }
    }

    /// Converts `CryptoSchema` to `i32`.
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self as i32
    }
}

/// Maximum number of extra keys supported.
pub const RPC_MAX_EXTRA_KEYS: usize = 8;

/// Basic RPC nonce packet (crypto schema 0 or 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed(4))]
pub struct NoncePacket {
    /// Packet type (`RPC_NONCE`).
    pub packet_type: i32,
    /// Least significant 32 bits of key to use.
    pub key_select: i32,
    /// Crypto schema (0 = NONE, 1 = AES).
    pub crypto_schema: i32,
    /// Crypto timestamp.
    pub crypto_ts: i32,
    /// 16-byte crypto nonce.
    pub crypto_nonce: [u8; 16],
}

impl NoncePacket {
    /// Creates a new nonce packet.
    #[must_use]
    pub const fn new(key_select: i32, schema: CryptoSchema, timestamp: i32, nonce: [u8; 16]) -> Self {
        Self {
            packet_type: RpcPacketType::Nonce as i32,
            key_select,
            crypto_schema: schema as i32,
            crypto_ts: timestamp,
            crypto_nonce: nonce,
        }
    }

    /// Returns the size of this packet in bytes.
    #[must_use]
    pub const fn size() -> usize {
        core::mem::size_of::<Self>()
    }
}

/// RPC nonce packet with extra keys (crypto schema 2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, packed(4))]
pub struct NonceExtPacket {
    /// Packet type (`RPC_NONCE`).
    pub packet_type: i32,
    /// Least significant 32 bits of key to use.
    pub key_select: i32,
    /// Crypto schema (2 = AES+extra keys).
    pub crypto_schema: i32,
    /// Crypto timestamp.
    pub crypto_ts: i32,
    /// 16-byte crypto nonce.
    pub crypto_nonce: [u8; 16],
    /// Number of extra keys.
    pub extra_keys_count: i32,
    /// Extra key selectors.
    pub extra_key_select: [i32; RPC_MAX_EXTRA_KEYS],
}

impl NonceExtPacket {
    /// Creates a new nonce packet with extra keys.
    #[must_use]
    pub fn new(
        key_select: i32,
        timestamp: i32,
        nonce: [u8; 16],
        extra_keys: &[i32],
    ) -> Option<Self> {
        if extra_keys.len() > RPC_MAX_EXTRA_KEYS {
            return None;
        }
        
        let mut extra_key_select = [0_i32; RPC_MAX_EXTRA_KEYS];
        extra_key_select[..extra_keys.len()].copy_from_slice(extra_keys);
        
        Some(Self {
            packet_type: RpcPacketType::Nonce as i32,
            key_select,
            crypto_schema: CryptoSchema::AesExt as i32,
            crypto_ts: timestamp,
            crypto_nonce: nonce,
            extra_keys_count: i32::try_from(extra_keys.len()).ok()?,
            extra_key_select,
        })
    }

    /// Returns the size of this packet in bytes.
    #[must_use]
    pub const fn size() -> usize {
        core::mem::size_of::<Self>()
    }
}

/// RPC nonce packet with Diffie-Hellman (crypto schema 3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, packed(4))]
pub struct NonceDhPacket {
    /// Packet type (`RPC_NONCE`).
    pub packet_type: i32,
    /// Least significant 32 bits of key to use.
    pub key_select: i32,
    /// Crypto schema (3 = AES+extra keys+DH).
    pub crypto_schema: i32,
    /// Crypto timestamp.
    pub crypto_ts: i32,
    /// 16-byte crypto nonce.
    pub crypto_nonce: [u8; 16],
    /// Number of extra keys.
    pub extra_keys_count: i32,
    /// Extra key selectors.
    pub extra_key_select: [i32; RPC_MAX_EXTRA_KEYS],
    /// DH params selector (least significant 32 bits of SHA1).
    pub dh_params_select: i32,
    /// DH public key g^a (256 bytes).
    pub g_a: [u8; 256],
}

impl NonceDhPacket {
    /// Creates a new nonce packet with Diffie-Hellman.
    #[must_use]
    pub fn new(
        key_select: i32,
        timestamp: i32,
        nonce: [u8; 16],
        extra_keys: &[i32],
        dh_params_select: i32,
        g_a: [u8; 256],
    ) -> Option<Self> {
        if extra_keys.len() > RPC_MAX_EXTRA_KEYS {
            return None;
        }
        
        let mut extra_key_select = [0_i32; RPC_MAX_EXTRA_KEYS];
        extra_key_select[..extra_keys.len()].copy_from_slice(extra_keys);
        
        Some(Self {
            packet_type: RpcPacketType::Nonce as i32,
            key_select,
            crypto_schema: CryptoSchema::AesDh as i32,
            crypto_ts: timestamp,
            crypto_nonce: nonce,
            extra_keys_count: i32::try_from(extra_keys.len()).ok()?,
            extra_key_select,
            dh_params_select,
            g_a,
        })
    }

    /// Returns the size of this packet in bytes.
    #[must_use]
    pub const fn size() -> usize {
        core::mem::size_of::<Self>()
    }
}

/// RPC handshake packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed(4))]
pub struct HandshakePacket {
    /// Packet type (`RPC_HANDSHAKE`).
    pub packet_type: i32,
    /// Handshake flags.
    pub flags: i32,
    /// Sender process ID.
    pub sender_pid: ProcessId,
    /// Peer process ID.
    pub peer_pid: ProcessId,
}

impl HandshakePacket {
    /// Creates a new handshake packet.
    #[must_use]
    pub const fn new(flags: i32, sender_pid: ProcessId, peer_pid: ProcessId) -> Self {
        Self {
            packet_type: RpcPacketType::Handshake as i32,
            flags,
            sender_pid,
            peer_pid,
        }
    }

    /// Returns the size of this packet in bytes.
    #[must_use]
    pub const fn size() -> usize {
        core::mem::size_of::<Self>()
    }
}

/// RPC handshake error packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed(4))]
pub struct HandshakeErrorPacket {
    /// Packet type (`RPC_HANDSHAKE_ERROR`).
    pub packet_type: i32,
    /// Error code.
    pub error_code: i32,
    /// Sender process ID.
    pub sender_pid: ProcessId,
}

impl HandshakeErrorPacket {
    /// Creates a new handshake error packet.
    #[must_use]
    pub const fn new(error_code: i32, sender_pid: ProcessId) -> Self {
        Self {
            packet_type: RpcPacketType::HandshakeError as i32,
            error_code,
            sender_pid,
        }
    }

    /// Returns the size of this packet in bytes.
    #[must_use]
    pub const fn size() -> usize {
        core::mem::size_of::<Self>()
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

/// Decodes compact tcp-rpc packet header.
///
/// Returns `(payload_len, header_bytes)` if valid, or `None` if invalid.
#[must_use]
pub fn decode_compact_header(first_byte: u8, remaining_bytes: Option<[u8; 3]>) -> Option<(i32, i32)> {
    match first_byte {
        0x7f => {
            // Wide format - need 4 bytes total
            let rem = remaining_bytes?;
            let mut full_bytes = [0_u8; 4];
            full_bytes[0] = first_byte;
            full_bytes[1..].copy_from_slice(&rem);
            let word = u32::from_ne_bytes(full_bytes);
            let payload_len = i32::try_from(word >> 6).ok()?;
            Some((payload_len, 4))
        }
        0x00..=0x7e => {
            // Compact format - 1 byte
            let payload_len = i32::from(first_byte) << 2;
            Some((payload_len, 1))
        }
        0x80..=0xff => None,
    }
}

/// Computes CRC32 checksum for packet validation.
///
/// This is a placeholder that would call into the actual CRC32 implementation.
/// The real implementation would use the crypto crate's CRC32 functions.
#[must_use]
pub fn compute_packet_crc32(_data: &[u8]) -> u32 {
    // Placeholder - in real implementation, this would call:
    // crate::crypto::crc32::compute(data)
    0
}

/// Validates a packet's CRC32 checksum.
#[must_use]
pub fn validate_packet_crc32(_data: &[u8], _expected_crc: u32) -> bool {
    // Placeholder - in real implementation, this would:
    // compute_packet_crc32(data) == expected_crc
    true
}

#[cfg(test)]
mod tests {
    use super::{
        decode_compact_header, encode_compact_header, CryptoSchema, HandshakeErrorPacket,
        HandshakePacket, NoncePacket, NonceExtPacket, NonceDhPacket, ProcessId, RpcPacketType,
        RPC_MAX_EXTRA_KEYS,
    };

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

    #[test]
    fn crypto_schema_conversion() {
        assert_eq!(CryptoSchema::from_i32(0), Some(CryptoSchema::None));
        assert_eq!(CryptoSchema::from_i32(1), Some(CryptoSchema::Aes));
        assert_eq!(CryptoSchema::from_i32(2), Some(CryptoSchema::AesExt));
        assert_eq!(CryptoSchema::from_i32(3), Some(CryptoSchema::AesDh));
        assert_eq!(CryptoSchema::from_i32(4), None);
        
        assert_eq!(CryptoSchema::None.to_i32(), 0);
        assert_eq!(CryptoSchema::Aes.to_i32(), 1);
    }

    #[test]
    fn nonce_packet_creation() {
        let nonce = [1_u8; 16];
        let packet = NoncePacket::new(12345, CryptoSchema::Aes, 1000, nonce);
        
        assert_eq!(packet.packet_type, RpcPacketType::Nonce as i32);
        assert_eq!(packet.key_select, 12345);
        assert_eq!(packet.crypto_schema, CryptoSchema::Aes as i32);
        assert_eq!(packet.crypto_ts, 1000);
        assert_eq!(packet.crypto_nonce, nonce);
        assert_eq!(NoncePacket::size(), 32);
    }

    #[test]
    fn nonce_ext_packet_creation() {
        let nonce = [2_u8; 16];
        let extra_keys = [100, 200, 300];
        let packet = NonceExtPacket::new(12345, 1000, nonce, &extra_keys).unwrap();
        
        assert_eq!(packet.packet_type, RpcPacketType::Nonce as i32);
        assert_eq!(packet.crypto_schema, CryptoSchema::AesExt as i32);
        assert_eq!(packet.extra_keys_count, 3);
        assert_eq!(packet.extra_key_select[0], 100);
        assert_eq!(packet.extra_key_select[1], 200);
        assert_eq!(packet.extra_key_select[2], 300);
    }

    #[test]
    fn nonce_ext_packet_rejects_too_many_keys() {
        let nonce = [2_u8; 16];
        let extra_keys = [0_i32; RPC_MAX_EXTRA_KEYS + 1];
        assert!(NonceExtPacket::new(12345, 1000, nonce, &extra_keys).is_none());
    }

    #[test]
    fn nonce_dh_packet_creation() {
        let nonce = [3_u8; 16];
        let extra_keys = [100, 200];
        let g_a = [4_u8; 256];
        let packet = NonceDhPacket::new(12345, 1000, nonce, &extra_keys, 999, g_a).unwrap();
        
        assert_eq!(packet.packet_type, RpcPacketType::Nonce as i32);
        assert_eq!(packet.crypto_schema, CryptoSchema::AesDh as i32);
        assert_eq!(packet.extra_keys_count, 2);
        assert_eq!(packet.dh_params_select, 999);
        assert_eq!(packet.g_a[0], 4);
    }

    #[test]
    fn handshake_packet_creation() {
        let sender = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        let peer = ProcessId::new(0x7f00_0002, 9090, 54321, 2000);
        let packet = HandshakePacket::new(0, sender, peer);
        
        assert_eq!(packet.packet_type, RpcPacketType::Handshake as i32);
        assert_eq!(packet.flags, 0);
        assert_eq!(packet.sender_pid, sender);
        assert_eq!(packet.peer_pid, peer);
    }

    #[test]
    fn handshake_error_packet_creation() {
        let sender = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        let packet = HandshakeErrorPacket::new(-1, sender);
        
        assert_eq!(packet.packet_type, RpcPacketType::HandshakeError as i32);
        assert_eq!(packet.error_code, -1);
        assert_eq!(packet.sender_pid, sender);
    }

    #[test]
    fn decode_compact_header_single_byte() {
        // Decode a compact format (< 0x7f)
        let (payload_len, header_bytes) = decode_compact_header(0x10, None).unwrap();
        assert_eq!(payload_len, 64); // 0x10 << 2
        assert_eq!(header_bytes, 1);
    }

    #[test]
    fn decode_compact_header_wide_format() {
        // Decode wide format (0x7f prefix)
        let remaining = [0x00, 0x01, 0x00]; // part of encoded value
        let result = decode_compact_header(0x7f, Some(remaining));
        assert!(result.is_some());
        let (payload_len, header_bytes) = result.unwrap();
        assert_eq!(header_bytes, 4);
        // Payload len is (0x0001007f >> 6)
        assert_eq!(payload_len, (0x0001_007f_u32 >> 6) as i32);
    }

    #[test]
    fn decode_compact_header_roundtrip() {
        // Test that encode/decode are compatible
        let original_len = 512;
        let (encoded, bytes) = encode_compact_header(original_len, 0);
        
        if bytes == 1 {
            let first_byte = (encoded & 0xff) as u8;
            let (decoded_len, decoded_bytes) = decode_compact_header(first_byte, None).unwrap();
            assert_eq!(decoded_len, original_len);
            assert_eq!(decoded_bytes, 1);
        }
    }

    #[test]
    fn decode_compact_header_rejects_invalid() {
        // Values >= 0x80 but != 0x7f should be invalid
        assert!(decode_compact_header(0x80, None).is_none());
        assert!(decode_compact_header(0xff, None).is_none());
    }
}
