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
        Self {
            ip,
            port,
            pid,
            utime,
        }
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

/// Trait for packet serialization/deserialization.
pub trait PacketSerialization: Sized {
    /// Expected packet type for this structure.
    fn expected_packet_type() -> i32;

    /// Size of the packet in bytes.
    fn packet_size() -> usize;

    /// Serializes the packet to a byte slice.
    fn to_bytes(&self) -> &[u8];

    /// Deserializes a packet from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
}

fn read_i16_ne(bytes: &[u8], offset: usize) -> i16 {
    let mut raw = [0_u8; 2];
    raw.copy_from_slice(&bytes[offset..offset + 2]);
    i16::from_ne_bytes(raw)
}

fn read_i32_ne(bytes: &[u8], offset: usize) -> i32 {
    let mut raw = [0_u8; 4];
    raw.copy_from_slice(&bytes[offset..offset + 4]);
    i32::from_ne_bytes(raw)
}

fn parse_process_id(bytes: &[u8], offset: usize) -> ProcessId {
    ProcessId {
        ip: u32::from_ne_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]),
        port: read_i16_ne(bytes, offset + 4),
        pid: u16::from_ne_bytes([bytes[offset + 6], bytes[offset + 7]]),
        utime: read_i32_ne(bytes, offset + 8),
    }
}

const TCP_RPC_NONCE_MIN_LEN: usize = 16;
const TCP_RPC_NONCE_BASE_LEN: usize = 32;
const TCP_RPC_NONCE_EXT_BASE_LEN: usize =
    core::mem::size_of::<NonceExtPacket>() - RPC_MAX_EXTRA_KEYS * 4;
const TCP_RPC_NONCE_DH_BASE_LEN: usize =
    core::mem::size_of::<NonceDhPacket>() - RPC_MAX_EXTRA_KEYS * 4;

/// Parsed RPC nonce packet with variable nonce payload layout (Aes+extra and Aes+DH).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedNoncePacket {
    /// Packet type, must be `RPC_NONCE`.
    pub packet_type: i32,
    /// Negotiated crypto schema.
    pub crypto_schema: CryptoSchema,
    /// Key selector provided by the peer.
    pub key_select: i32,
    /// Nonce timestamp.
    pub crypto_ts: i32,
    /// Negotiation nonce bytes.
    pub crypto_nonce: [u8; 16],
    /// Number of optional extra keys.
    pub extra_keys_count: i32,
    /// Extra key selectors (for `AES_EXT` and `AES_DH` schemas).
    pub extra_key_select: [i32; RPC_MAX_EXTRA_KEYS],
    /// DH parameter selector for `AES_DH`.
    pub dh_params_select: i32,
    /// Raw DH public key for `AES_DH` payloads.
    pub g_a: [u8; 256],
    /// Whether `dh_params_select` and `g_a` are valid.
    pub has_dh_params: bool,
}

impl ParsedNoncePacket {
    /// Creates a parsed packet instance from a base `NoncePacket`.
    #[must_use]
    pub fn from_nonce_packet(packet: &NoncePacket) -> Self {
        Self {
            packet_type: packet.packet_type,
            crypto_schema: CryptoSchema::from_i32(packet.crypto_schema)
                .unwrap_or(CryptoSchema::None),
            key_select: packet.key_select,
            crypto_ts: packet.crypto_ts,
            crypto_nonce: packet.crypto_nonce,
            extra_keys_count: 0,
            extra_key_select: [0; RPC_MAX_EXTRA_KEYS],
            dh_params_select: 0,
            g_a: [0; 256],
            has_dh_params: false,
        }
    }
}

/// Computes expected full nonce packet length for a given schema and extra key count.
#[must_use]
pub fn expected_nonce_length(schema: CryptoSchema, extra_keys_count: i32) -> Option<usize> {
    match schema {
        CryptoSchema::None | CryptoSchema::Aes => Some(TCP_RPC_NONCE_BASE_LEN),
        CryptoSchema::AesExt => {
            let extra = usize::try_from(extra_keys_count).ok()?;
            if extra_keys_count < 0 || extra > RPC_MAX_EXTRA_KEYS {
                return None;
            }
            Some(TCP_RPC_NONCE_EXT_BASE_LEN + extra * 4)
        }
        CryptoSchema::AesDh => {
            let extra = usize::try_from(extra_keys_count).ok()?;
            if extra_keys_count < 0 || extra > RPC_MAX_EXTRA_KEYS {
                return None;
            }
            Some(TCP_RPC_NONCE_DH_BASE_LEN + extra * 4)
        }
    }
}

/// Parses a nonce packet that may be in base/AES+ext/AES+DH form.
#[must_use]
pub fn parse_nonce_packet(packet_bytes: &[u8]) -> Option<ParsedNoncePacket> {
    if packet_bytes.len() < TCP_RPC_NONCE_MIN_LEN {
        return None;
    }

    let packet_type = read_i32_ne(packet_bytes, 0);
    if packet_type != RpcPacketType::Nonce as i32 {
        return None;
    }

    let key_select = read_i32_ne(packet_bytes, 4);
    let crypto_schema = CryptoSchema::from_i32(read_i32_ne(packet_bytes, 8))?;

    let mut out = ParsedNoncePacket {
        packet_type,
        crypto_schema,
        key_select,
        crypto_ts: read_i32_ne(packet_bytes, 12),
        crypto_nonce: [0_u8; 16],
        extra_keys_count: 0,
        extra_key_select: [0; RPC_MAX_EXTRA_KEYS],
        dh_params_select: 0,
        g_a: [0_u8; 256],
        has_dh_params: false,
    };

    out.crypto_nonce.copy_from_slice(&packet_bytes[16..32]);

    match crypto_schema {
        CryptoSchema::None | CryptoSchema::Aes => {
            if packet_bytes.len() != TCP_RPC_NONCE_BASE_LEN {
                return None;
            }
        }
        CryptoSchema::AesExt | CryptoSchema::AesDh => {
            if packet_bytes.len() < TCP_RPC_NONCE_EXT_BASE_LEN {
                return None;
            }

            out.extra_keys_count = read_i32_ne(packet_bytes, 32 + 4);
            let extra_keys_count = out.extra_keys_count;

            let expected_len = expected_nonce_length(crypto_schema, extra_keys_count)?;
            if packet_bytes.len() != expected_len {
                return None;
            }

            let extra_count = usize::try_from(extra_keys_count).ok()?;
            let mut cursor = 36;
            for idx in 0..extra_count {
                out.extra_key_select[idx] = read_i32_ne(packet_bytes, cursor);
                cursor += 4;
            }

            if crypto_schema == CryptoSchema::AesDh {
                out.has_dh_params = true;
                out.dh_params_select = read_i32_ne(packet_bytes, cursor);
                cursor += 4;
                out.g_a.copy_from_slice(&packet_bytes[cursor..cursor + 256]);
            }
        }
    }

    Some(out)
}

/// Selects the effective key signature for a parsed nonce packet.
///
/// Mirrors the C nonce-processing selection rules:
/// - schema `None` never selects a key (`0`)
/// - schema `Aes` checks only the main key
/// - schema `AesExt`/`AesDh` checks main + extra keys
#[must_use]
pub fn select_nonce_key_signature(
    parsed: &ParsedNoncePacket,
    main_secret_len: i32,
    main_key_signature: i32,
) -> i32 {
    match parsed.crypto_schema {
        CryptoSchema::None => 0,
        CryptoSchema::Aes => super::config::select_best_key_signature(
            main_secret_len,
            main_key_signature,
            parsed.key_select,
            &[],
        ),
        CryptoSchema::AesExt | CryptoSchema::AesDh => {
            let extra_count = usize::try_from(parsed.extra_keys_count).unwrap_or_default();
            super::config::select_best_key_signature(
                main_secret_len,
                main_key_signature,
                parsed.key_select,
                &parsed.extra_key_select[..extra_count],
            )
        }
    }
}

/// Parsed RPC handshake packet with strongly typed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedHandshakePacket {
    /// Packet type, must be `RPC_HANDSHAKE`.
    pub packet_type: i32,
    /// Handshake flags.
    pub flags: i32,
    /// Sender process identifier.
    pub sender_pid: ProcessId,
    /// Peer process identifier.
    pub peer_pid: ProcessId,
}

/// Parses a handshake packet.
#[must_use]
pub fn parse_handshake_packet(packet_bytes: &[u8]) -> Option<ParsedHandshakePacket> {
    if packet_bytes.len() != HandshakePacket::size() {
        return None;
    }

    let packet_type = read_i32_ne(packet_bytes, 0);
    if packet_type != RpcPacketType::Handshake as i32 {
        return None;
    }

    Some(ParsedHandshakePacket {
        packet_type,
        flags: read_i32_ne(packet_bytes, 4),
        sender_pid: parse_process_id(packet_bytes, 8),
        peer_pid: parse_process_id(packet_bytes, 20),
    })
}

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
    pub const fn new(
        key_select: i32,
        schema: CryptoSchema,
        timestamp: i32,
        nonce: [u8; 16],
    ) -> Self {
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

impl PacketSerialization for NoncePacket {
    fn expected_packet_type() -> i32 {
        RpcPacketType::Nonce as i32
    }

    fn packet_size() -> usize {
        core::mem::size_of::<Self>()
    }

    fn to_bytes(&self) -> &[u8] {
        // SAFETY: NoncePacket uses #[repr(C, packed(4))], making it safe to view as bytes
        #[allow(unsafe_code)]
        #[allow(clippy::ptr_as_ptr)]
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::addr_of!(*self).cast::<u8>(),
                Self::packet_size(),
            )
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::packet_size() {
            return None;
        }

        let mut packet = Self {
            packet_type: 0,
            key_select: 0,
            crypto_schema: 0,
            crypto_ts: 0,
            crypto_nonce: [0; 16],
        };

        // SAFETY: We've verified bytes.len() >= packet_size(), and NoncePacket is repr(C, packed(4))
        #[allow(unsafe_code)]
        #[allow(clippy::ptr_as_ptr)]
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                core::ptr::addr_of_mut!(packet).cast::<u8>(),
                Self::packet_size(),
            );
        }

        if packet.packet_type != Self::expected_packet_type() {
            return None;
        }

        Some(packet)
    }
}

impl PacketSerialization for HandshakePacket {
    fn expected_packet_type() -> i32 {
        RpcPacketType::Handshake as i32
    }

    fn packet_size() -> usize {
        core::mem::size_of::<Self>()
    }

    fn to_bytes(&self) -> &[u8] {
        // SAFETY: HandshakePacket uses #[repr(C, packed(4))], so raw access is safe.
        #[allow(unsafe_code)]
        #[allow(clippy::ptr_as_ptr)]
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::addr_of!(*self).cast::<u8>(),
                Self::packet_size(),
            )
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::size() {
            return None;
        }

        let mut packet = Self {
            packet_type: 0,
            flags: 0,
            sender_pid: ProcessId::default(),
            peer_pid: ProcessId::default(),
        };

        #[allow(unsafe_code)]
        #[allow(clippy::ptr_as_ptr)]
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                core::ptr::addr_of_mut!(packet).cast::<u8>(),
                Self::size(),
            );
        }

        if packet.packet_type != RpcPacketType::Handshake as i32 {
            return None;
        }

        Some(packet)
    }
}

impl PacketSerialization for HandshakeErrorPacket {
    fn expected_packet_type() -> i32 {
        RpcPacketType::HandshakeError as i32
    }

    fn packet_size() -> usize {
        core::mem::size_of::<Self>()
    }

    fn to_bytes(&self) -> &[u8] {
        // SAFETY: HandshakeErrorPacket uses #[repr(C, packed(4))], so raw access is safe.
        #[allow(unsafe_code)]
        #[allow(clippy::ptr_as_ptr)]
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::addr_of!(*self).cast::<u8>(),
                Self::packet_size(),
            )
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::size() {
            return None;
        }

        let mut packet = Self {
            packet_type: 0,
            error_code: 0,
            sender_pid: ProcessId::default(),
        };

        #[allow(unsafe_code)]
        #[allow(clippy::ptr_as_ptr)]
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                core::ptr::addr_of_mut!(packet).cast::<u8>(),
                Self::size(),
            );
        }

        if packet.packet_type != RpcPacketType::HandshakeError as i32 {
            return None;
        }

        Some(packet)
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

    /// Serializes the packet to a byte slice.
    ///
    /// # Safety
    /// The packet uses `#[repr(C, packed(4))]` so direct byte access is safe.
    #[must_use]
    pub fn to_bytes(&self) -> &[u8] {
        // SAFETY: HandshakeErrorPacket uses #[repr(C, packed(4))], making it safe to view as bytes
        #[allow(unsafe_code)]
        #[allow(clippy::ptr_as_ptr)]
        unsafe {
            core::slice::from_raw_parts(core::ptr::addr_of!(*self).cast::<u8>(), Self::size())
        }
    }

    /// Deserializes a packet from a byte slice.
    ///
    /// Returns `None` if the slice is too small or packet type is incorrect.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::size() {
            return None;
        }

        let mut packet = Self {
            packet_type: 0,
            error_code: 0,
            sender_pid: ProcessId::default(),
        };

        // SAFETY: We've verified bytes.len() >= size(), and packet is repr(C, packed(4))
        #[allow(unsafe_code)]
        #[allow(clippy::ptr_as_ptr)]
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                core::ptr::addr_of_mut!(packet).cast::<u8>(),
                Self::size(),
            );
        }

        if packet.packet_type != RpcPacketType::HandshakeError as i32 {
            return None;
        }

        Some(packet)
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
pub fn decode_compact_header(
    first_byte: u8,
    remaining_bytes: Option<[u8; 3]>,
) -> Option<(i32, i32)> {
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
/// Uses the standard CRC-32 algorithm (polynomial 0xEDB88320).
#[must_use]
pub fn compute_packet_crc32(data: &[u8]) -> u32 {
    const CRC32_TABLE: [u32; 256] = generate_crc32_table();

    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in data {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    !crc
}

/// Validates a packet's CRC32 checksum.
#[must_use]
pub fn validate_packet_crc32(data: &[u8], expected_crc: u32) -> bool {
    compute_packet_crc32(data) == expected_crc
}

/// Generates CRC32 lookup table at compile time.
#[must_use]
const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut i = 0_usize;
    while i < 256 {
        #[allow(clippy::cast_possible_truncation)]
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

use core::sync::atomic::{AtomicU32, Ordering};

/// Global storage for default RPC flags.
static DEFAULT_RPC_FLAGS: AtomicU32 = AtomicU32::new(0);

/// Sets default RPC flags using bitwise AND and OR operations.
///
/// Returns the new flags value after applying the operations.
/// This mirrors the C function `tcp_set_default_rpc_flags`.
#[must_use]
pub fn set_default_rpc_flags(and_flags: u32, or_flags: u32) -> u32 {
    // Use fetch_update for atomic read-modify-write
    // The closure returns the new value, and fetch_update returns the old value
    // We compute the new value from the old value to avoid race conditions
    match DEFAULT_RPC_FLAGS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some((old & and_flags) | or_flags)
    }) {
        Ok(old) => (old & and_flags) | or_flags, // Return the new value
        Err(_) => unreachable!(), // fetch_update with Some never fails
    }
}

/// Gets the current default RPC flags.
///
/// This mirrors the C function `tcp_get_default_rpc_flags`.
#[must_use]
pub fn get_default_rpc_flags() -> u32 {
    DEFAULT_RPC_FLAGS.load(Ordering::Relaxed)
}

/// Global maximum DH accept rate (shared across threads).
static MAX_DH_ACCEPT_RATE: AtomicU32 = AtomicU32::new(0);

/// Sets the maximum DH accept rate (rate per second).
///
/// This mirrors the C function `tcp_set_max_dh_accept_rate`.
/// 
/// NOTE: This Rust implementation provides a simplified version of DH rate limiting.
/// The C implementation uses thread-local state which cannot be directly replicated
/// in a no_std environment. The FFI layer should maintain thread-local state if needed.
pub fn set_max_dh_accept_rate(rate: i32) {
    #[allow(clippy::cast_sign_loss)]
    MAX_DH_ACCEPT_RATE.store(rate as u32, Ordering::Relaxed);
}

/// Gets the current maximum DH accept rate.
#[must_use]
#[allow(clippy::cast_possible_wrap)]
pub fn get_max_dh_accept_rate() -> i32 {
    MAX_DH_ACCEPT_RATE.load(Ordering::Relaxed) as i32
}

/// Constructs a ping packet with the given ping ID.
///
/// Returns a 12-byte array containing RPC_PING opcode and the ping ID.
/// This mirrors the logic from `tcp_rpc_send_ping`.
#[must_use]
pub fn construct_ping_packet(ping_id: i64) -> [u8; 12] {
    let mut packet = [0_u8; 12];
    let rpc_ping = RpcPacketType::Ping.to_i32();
    packet[0..4].copy_from_slice(&rpc_ping.to_le_bytes());
    packet[4..12].copy_from_slice(&ping_id.to_le_bytes());
    packet
}

#[cfg(test)]
mod tests {
    use super::{
        decode_compact_header, encode_compact_header, CryptoSchema, HandshakeErrorPacket,
        HandshakePacket, NonceDhPacket, NonceExtPacket, NoncePacket, ProcessId, RpcPacketType,
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
        assert_eq!(
            RpcPacketType::from_i32(0x7acb_87aa),
            Some(RpcPacketType::Nonce)
        );
        assert_eq!(
            RpcPacketType::from_i32(0x7682_eef5),
            Some(RpcPacketType::Handshake)
        );
        assert_eq!(
            RpcPacketType::from_i32(0x6a27_beda),
            Some(RpcPacketType::HandshakeError)
        );
        assert_eq!(
            RpcPacketType::from_i32(0x7bde_f2a4),
            Some(RpcPacketType::Ping)
        );
        assert_eq!(
            RpcPacketType::from_i32(-1_948_322_907),
            Some(RpcPacketType::Pong)
        ); // 0x8bde_f3a5
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
        assert_eq!(payload_len, 0x0401);
    }

    #[test]
    fn decode_compact_header_roundtrip() {
        // Test that encode/decode are compatible
        let original_len = 512;
        let (encoded, bytes) = encode_compact_header(original_len, 0);

        if bytes == 1 {
            let first_byte = encoded.to_le_bytes()[0];
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

    #[test]
    fn default_rpc_flags_operations() {
        use super::{get_default_rpc_flags, set_default_rpc_flags};

        // Set flags to 0x05
        let _ = set_default_rpc_flags(0xFFFF_FFFF, 0x05);
        assert_eq!(get_default_rpc_flags(), 0x05);

        // Apply AND mask (keep only bits 0,2) and OR with 0x08
        let result = set_default_rpc_flags(0x05, 0x08);
        assert_eq!(result, 0x0D); // (0x05 & 0x05) | 0x08 = 0x0D
        assert_eq!(get_default_rpc_flags(), 0x0D);
    }

    #[test]
    fn max_dh_accept_rate_get_set() {
        use super::{get_max_dh_accept_rate, set_max_dh_accept_rate};

        set_max_dh_accept_rate(100);
        assert_eq!(get_max_dh_accept_rate(), 100);

        set_max_dh_accept_rate(0);
        assert_eq!(get_max_dh_accept_rate(), 0);
    }

    #[test]
    fn construct_ping_packet_format() {
        use super::construct_ping_packet;

        let ping_id = 0x0123_4567_89AB_CDEF_i64;
        let packet = construct_ping_packet(ping_id);

        // First 4 bytes should be RPC_PING (0x7bdef2a4)
        let op = i32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(op, 0x7bde_f2a4);

        // Next 8 bytes should be the ping_id
        let id =
            i64::from_le_bytes([packet[4], packet[5], packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]]);
        assert_eq!(id, ping_id);
    }
}
