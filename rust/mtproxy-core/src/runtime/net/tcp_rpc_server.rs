//! RPC Server implementation ported from `net/net-tcp-rpc-server.c`.

use super::tcp_rpc_client::{
    PACKET_LEN_STATE_INVALID, PACKET_LEN_STATE_READY, PACKET_LEN_STATE_SKIP,
};
use super::tcp_rpc_common::{
    parse_handshake_packet, parse_nonce_packet, PacketSerialization, ParsedHandshakePacket,
    ParsedNoncePacket, ProcessId, RpcPacketType,
};

const PACKET_HEADER_INVALID_MASK: i32 = i32::from_ne_bytes(0xc000_0003_u32.to_ne_bytes());

/// Connection state for RPC server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Initial state, not yet accepted.
    Uninitialized,
    /// Connection accepted, waiting for client nonce.
    Accepted,
    /// Client nonce received, server nonce sent.
    NonceReceived,
    /// Client handshake received, server handshake sent.
    HandshakeReceived,
    /// Fully established and ready for RPC operations.
    Ready,
    /// Connection closed or failed.
    Closed,
}

/// RPC server connection data.
#[derive(Debug, Clone)]
pub struct RpcServerData {
    /// Current connection state.
    pub state: ServerState,
    /// Incoming packet sequence number (-2: initial, -1: handshake, 0+: data).
    pub in_packet_num: i32,
    /// Outgoing packet sequence number.
    pub out_packet_num: i32,
    /// Remote process identifier.
    pub remote_pid: ProcessId,
    /// Local process identifier.
    pub local_pid: ProcessId,
    /// Allow packet sequence number gaps.
    pub allow_seqno_holes: bool,
    /// Quick acknowledgment mode.
    pub quickack_enabled: bool,
    /// Selected crypto schema.
    pub crypto_schema: i32,
}

impl RpcServerData {
    /// Creates a new RPC server data structure in uninitialized state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ServerState::Uninitialized,
            in_packet_num: -2,
            out_packet_num: -2,
            remote_pid: ProcessId::default(),
            local_pid: ProcessId::default(),
            allow_seqno_holes: false,
            quickack_enabled: false,
            crypto_schema: 0,
        }
    }

    /// Initializes server for accepted connection.
    pub fn init_accepted(&mut self, local_pid: ProcessId) {
        self.state = ServerState::Accepted;
        self.local_pid = local_pid;
        self.in_packet_num = -2;
        self.out_packet_num = -2;
    }

    /// Initializes server without handshake (legacy mode).
    pub fn init_accepted_no_handshake(&mut self, local_pid: ProcessId) {
        self.state = ServerState::Ready;
        self.local_pid = local_pid;
        self.in_packet_num = 0;
        self.out_packet_num = 0;
    }

    /// Processes received client nonce.
    pub fn process_nonce_received(&mut self, crypto_schema: i32) -> Result<(), ServerError> {
        if self.state != ServerState::Accepted {
            return Err(ServerError::UnexpectedNonce);
        }
        self.state = ServerState::NonceReceived;
        self.crypto_schema = crypto_schema;
        self.in_packet_num = -1;
        Ok(())
    }

    /// Processes received client handshake.
    pub fn process_handshake_received(&mut self, remote_pid: ProcessId) -> Result<(), ServerError> {
        if self.state != ServerState::NonceReceived {
            return Err(ServerError::UnexpectedHandshake);
        }
        self.state = ServerState::HandshakeReceived;
        self.remote_pid = remote_pid;
        Ok(())
    }

    /// Transitions to ready state after sending server handshake.
    pub fn mark_ready(&mut self) {
        self.state = ServerState::Ready;
        self.in_packet_num = 0;
        self.out_packet_num = 0;
    }

    /// Validates and advances incoming packet number.
    pub fn advance_in_packet_num(&mut self, expected: i32) -> Result<(), ServerError> {
        if self.allow_seqno_holes {
            // Allow gaps in sequence numbers
            if expected < self.in_packet_num {
                return Err(ServerError::PacketSequenceError {
                    expected,
                    actual: self.in_packet_num,
                });
            }
            self.in_packet_num = expected + 1;
        } else {
            // Strict sequential validation
            if self.in_packet_num != expected {
                return Err(ServerError::PacketSequenceError {
                    expected,
                    actual: self.in_packet_num,
                });
            }
            self.in_packet_num += 1;
        }
        Ok(())
    }

    /// Checks if connection is ready for RPC operations.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, ServerState::Ready)
    }

    /// Gets the current crypto schema.
    #[must_use]
    pub const fn get_crypto_schema(&self) -> i32 {
        self.crypto_schema
    }

    /// Processes a parsed client nonce packet and determines response.
    fn process_parsed_client_nonce_packet(
        &mut self,
        packet: &ParsedNoncePacket,
        allow_unencrypted: bool,
        allow_encrypted: bool,
    ) -> Result<i32, ServerError> {
        if self.state != ServerState::Accepted {
            return Err(ServerError::UnexpectedNonce);
        }

        if packet.packet_type != RpcPacketType::Nonce as i32 {
            return Err(ServerError::InvalidPacketType(packet.packet_type));
        }

        let selected_schema = match packet.crypto_schema {
            super::tcp_rpc_common::CryptoSchema::None => {
                if packet.key_select != 0 {
                    return Err(ServerError::UnexpectedNonce);
                }
                if allow_unencrypted {
                    super::tcp_rpc_common::CryptoSchema::None
                } else {
                    return Err(ServerError::UnexpectedNonce);
                }
            }
            super::tcp_rpc_common::CryptoSchema::Aes
            | super::tcp_rpc_common::CryptoSchema::AesExt
            | super::tcp_rpc_common::CryptoSchema::AesDh => {
                if packet.key_select == 0 {
                    return Err(ServerError::UnexpectedNonce);
                }
                if allow_encrypted {
                    packet.crypto_schema
                } else if allow_unencrypted {
                    super::tcp_rpc_common::CryptoSchema::None
                } else {
                    return Err(ServerError::UnexpectedNonce);
                }
            }
        };

        self.state = ServerState::NonceReceived;
        self.crypto_schema = selected_schema.to_i32();
        self.in_packet_num = -1;
        Ok(selected_schema.to_i32())
    }

    /// Processes raw client nonce payload and determines response.
    pub fn process_client_nonce_packet_bytes(
        &mut self,
        packet_bytes: &[u8],
        allow_unencrypted: bool,
        allow_encrypted: bool,
    ) -> Result<i32, ServerError> {
        let packet =
            parse_nonce_packet(packet_bytes).ok_or_else(|| ServerError::InvalidPacketSize {
                size: packet_bytes.len(),
                expected: super::tcp_rpc_common::NoncePacket::size(),
            })?;
        self.process_parsed_client_nonce_packet(&packet, allow_unencrypted, allow_encrypted)
    }

    /// Processes a received client nonce packet and determines response.
    ///
    /// This validates the client's nonce packet and determines what crypto
    /// schema to use for the connection.
    pub fn process_client_nonce_packet(
        &mut self,
        packet: &super::tcp_rpc_common::NoncePacket,
        allow_unencrypted: bool,
        allow_encrypted: bool,
    ) -> Result<i32, ServerError> {
        self.process_client_nonce_packet_bytes(
            packet.to_bytes(),
            allow_unencrypted,
            allow_encrypted,
        )
    }

    fn process_parsed_client_handshake_packet(
        &mut self,
        packet: &ParsedHandshakePacket,
        expected_peer_pid: Option<super::tcp_rpc_common::ProcessId>,
    ) -> Result<(), ServerError> {
        if self.state != ServerState::NonceReceived {
            return Err(ServerError::UnexpectedHandshake);
        }

        self.remote_pid = packet.sender_pid;

        // Optionally validate against expected peer PID.
        if let Some(expected) = expected_peer_pid {
            if self.remote_pid != expected {
                return Err(ServerError::UnexpectedHandshake);
            }
        }

        self.state = ServerState::HandshakeReceived;
        Ok(())
    }

    /// Processes raw client handshake packet bytes.
    pub fn process_client_handshake_packet_bytes(
        &mut self,
        packet_bytes: &[u8],
        expected_peer_pid: Option<super::tcp_rpc_common::ProcessId>,
    ) -> Result<(), ServerError> {
        let packet =
            parse_handshake_packet(packet_bytes).ok_or_else(|| ServerError::InvalidPacketSize {
                size: packet_bytes.len(),
                expected: super::tcp_rpc_common::HandshakePacket::size(),
            })?;
        self.process_parsed_client_handshake_packet(&packet, expected_peer_pid)
    }

    /// Processes a received client handshake packet.
    ///
    /// This validates the client's handshake and extracts the remote PID.
    pub fn process_client_handshake_packet(
        &mut self,
        packet: &super::tcp_rpc_common::HandshakePacket,
        expected_peer_pid: Option<super::tcp_rpc_common::ProcessId>,
    ) -> Result<(), ServerError> {
        self.process_client_handshake_packet_bytes(packet.to_bytes(), expected_peer_pid)
    }

    /// Validates a packet number for the current connection state.
    pub fn validate_packet_number(&self, packet_num: i32) -> Result<(), ServerError> {
        match self.state {
            ServerState::Accepted if packet_num == -2 => Ok(()),
            ServerState::NonceReceived if packet_num == -1 => Ok(()),
            ServerState::Ready | ServerState::HandshakeReceived if packet_num >= 0 => {
                if self.allow_seqno_holes {
                    // Allow gaps but not going backwards
                    if packet_num >= self.in_packet_num {
                        Ok(())
                    } else {
                        Err(ServerError::PacketSequenceError {
                            expected: self.in_packet_num,
                            actual: packet_num,
                        })
                    }
                } else if packet_num == self.in_packet_num {
                    // Strict sequential validation
                    Ok(())
                } else {
                    Err(ServerError::PacketSequenceError {
                        expected: self.in_packet_num,
                        actual: packet_num,
                    })
                }
            }
            _ => Err(ServerError::PacketSequenceError {
                expected: self.in_packet_num,
                actual: packet_num,
            }),
        }
    }

    /// Prepares a nonce response packet for sending.
    #[must_use]
    pub fn prepare_nonce_response(
        &self,
        key_select: i32,
        schema: super::tcp_rpc_common::CryptoSchema,
        timestamp: i32,
        nonce: [u8; 16],
    ) -> super::tcp_rpc_common::NoncePacket {
        super::tcp_rpc_common::NoncePacket::new(key_select, schema, timestamp, nonce)
    }

    /// Prepares a handshake response packet for sending.
    #[must_use]
    pub fn prepare_handshake_response(&self, flags: i32) -> super::tcp_rpc_common::HandshakePacket {
        super::tcp_rpc_common::HandshakePacket::new(flags, self.local_pid, self.remote_pid)
    }

    /// Prepares a handshake error packet for sending.
    #[must_use]
    pub fn prepare_handshake_error(
        &self,
        error_code: i32,
    ) -> super::tcp_rpc_common::HandshakeErrorPacket {
        super::tcp_rpc_common::HandshakeErrorPacket::new(error_code, self.local_pid)
    }
}

impl Default for RpcServerData {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during RPC server operations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServerError {
    /// Received nonce in wrong state.
    UnexpectedNonce,
    /// Received handshake in wrong state.
    UnexpectedHandshake,
    /// Packet sequence number mismatch.
    PacketSequenceError { expected: i32, actual: i32 },
    /// Invalid packet type.
    InvalidPacketType(i32),
    /// Packet header is malformed.
    MalformedHeader,
    /// Connection timeout.
    Timeout { idle_seconds: f64 },
    /// Invalid packet size.
    InvalidPacketSize { size: usize, expected: usize },
}

impl core::fmt::Display for ServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedNonce => write!(f, "Received nonce packet in wrong state"),
            Self::UnexpectedHandshake => write!(f, "Received handshake packet in wrong state"),
            Self::PacketSequenceError { expected, actual } => {
                write!(
                    f,
                    "Packet sequence mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidPacketType(t) => write!(f, "Invalid packet type: {t:#x}"),
            Self::MalformedHeader => write!(f, "Malformed packet header"),
            Self::Timeout { idle_seconds } => {
                write!(f, "Connection timeout after {idle_seconds:.1}s idle")
            }
            Self::InvalidPacketSize { size, expected } => {
                write!(f, "Invalid packet size: {size} bytes, expected {expected}")
            }
        }
    }
}

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

/// C-compat nonce packet policy for `net-tcp-rpc-server.c`.
///
/// Return codes:
/// - `0` success
/// - `-1` parse failure
/// - `-3` key-selection mismatch
/// - `-5` schema disallowed by policy
/// - `-6` timestamp skew too large
pub fn process_nonce_packet_for_compat(
    packet: &[u8],
    allow_unencrypted: bool,
    allow_encrypted: bool,
    now_ts: i32,
    main_secret_len: i32,
    main_key_signature: i32,
    out_schema: &mut i32,
    out_key_select: &mut i32,
    out_has_dh_params: &mut i32,
) -> i32 {
    let Some(parsed) = parse_nonce_packet(packet) else {
        return -1;
    };

    let selected_key = super::tcp_rpc_common::select_nonce_key_signature(
        &parsed,
        main_secret_len,
        main_key_signature,
    );

    *out_schema = parsed.crypto_schema.to_i32();
    *out_key_select = 0;
    *out_has_dh_params = 0;

    match parsed.crypto_schema {
        super::tcp_rpc_common::CryptoSchema::None => {
            if parsed.key_select != 0 {
                return -3;
            }
            if !allow_unencrypted {
                return -5;
            }
        }
        super::tcp_rpc_common::CryptoSchema::Aes => {
            if selected_key == 0 {
                if allow_unencrypted {
                    *out_schema = super::tcp_rpc_common::CryptoSchema::None.to_i32();
                    return 0;
                }
                return -3;
            }
            if !allow_encrypted {
                if allow_unencrypted {
                    *out_schema = super::tcp_rpc_common::CryptoSchema::None.to_i32();
                    return 0;
                }
                return -5;
            }
            if (f64::from(parsed.crypto_ts) - f64::from(now_ts)).abs() > 30.0 {
                return -6;
            }
            *out_key_select = selected_key;
            *out_schema = super::tcp_rpc_common::CryptoSchema::Aes.to_i32();
        }
        super::tcp_rpc_common::CryptoSchema::AesExt
        | super::tcp_rpc_common::CryptoSchema::AesDh => {
            if selected_key == 0 {
                if allow_unencrypted {
                    *out_schema = super::tcp_rpc_common::CryptoSchema::None.to_i32();
                    return 0;
                }
                return -3;
            }
            if !allow_encrypted {
                if allow_unencrypted {
                    *out_schema = super::tcp_rpc_common::CryptoSchema::None.to_i32();
                    return 0;
                }
                return -5;
            }
            if (f64::from(parsed.crypto_ts) - f64::from(now_ts)).abs() > 30.0 {
                return -6;
            }
            if parsed.crypto_schema == super::tcp_rpc_common::CryptoSchema::AesDh
                && parsed.has_dh_params
                && parsed.dh_params_select != 0
            {
                *out_has_dh_params = 1;
            }
            *out_key_select = selected_key;
            *out_schema = parsed.crypto_schema.to_i32();
        }
    }

    0
}

/// Validates packet type for server connection.
pub fn validate_packet_type(
    packet_type: i32,
    state: ServerState,
) -> Result<RpcPacketType, ServerError> {
    match RpcPacketType::from_i32(packet_type) {
        Some(RpcPacketType::Nonce) if state == ServerState::Accepted => Ok(RpcPacketType::Nonce),
        Some(RpcPacketType::Handshake) if state == ServerState::NonceReceived => {
            Ok(RpcPacketType::Handshake)
        }
        Some(pkt @ (RpcPacketType::Ping | RpcPacketType::Pong)) if state == ServerState::Ready => {
            Ok(pkt)
        }
        _ => Err(ServerError::InvalidPacketType(packet_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        packet_header_malformed, packet_len_state, process_nonce_packet_for_compat, ProcessId,
        RpcServerData, ServerError, ServerState,
    };
    use crate::runtime::net::tcp_rpc_client::{
        PACKET_LEN_STATE_INVALID, PACKET_LEN_STATE_READY, PACKET_LEN_STATE_SKIP,
    };
    use crate::runtime::net::tcp_rpc_common::PacketSerialization;

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

    #[test]
    fn server_data_starts_uninitialized() {
        let server = RpcServerData::new();
        assert_eq!(server.state, ServerState::Uninitialized);
        assert_eq!(server.in_packet_num, -2);
        assert_eq!(server.out_packet_num, -2);
        assert!(!server.is_ready());
    }

    #[test]
    fn server_init_accepted_sets_state() {
        let mut server = RpcServerData::new();
        let pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        server.init_accepted(pid);

        assert_eq!(server.state, ServerState::Accepted);
        assert_eq!(server.local_pid, pid);
        assert_eq!(server.in_packet_num, -2);
    }

    #[test]
    fn server_no_handshake_mode() {
        let mut server = RpcServerData::new();
        let pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        server.init_accepted_no_handshake(pid);

        assert_eq!(server.state, ServerState::Ready);
        assert!(server.is_ready());
        assert_eq!(server.in_packet_num, 0);
        assert_eq!(server.out_packet_num, 0);
    }

    #[test]
    fn server_nonce_flow() {
        let mut server = RpcServerData::new();
        let pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        server.init_accepted(pid);

        assert!(server.process_nonce_received(1).is_ok());
        assert_eq!(server.state, ServerState::NonceReceived);
        assert_eq!(server.crypto_schema, 1);
        assert_eq!(server.in_packet_num, -1);
    }

    #[test]
    fn server_rejects_nonce_in_wrong_state() {
        let mut server = RpcServerData::new();
        assert_eq!(
            server.process_nonce_received(1),
            Err(ServerError::UnexpectedNonce)
        );
    }

    #[test]
    fn server_handshake_flow() {
        let mut server = RpcServerData::new();
        let local_pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        let remote_pid = ProcessId::new(0x7f00_0002, 9090, 54321, 2000);

        server.init_accepted(local_pid);
        server.process_nonce_received(1).unwrap();

        assert!(server.process_handshake_received(remote_pid).is_ok());
        assert_eq!(server.state, ServerState::HandshakeReceived);
        assert_eq!(server.remote_pid, remote_pid);

        server.mark_ready();
        assert_eq!(server.state, ServerState::Ready);
        assert!(server.is_ready());
        assert_eq!(server.in_packet_num, 0);
        assert_eq!(server.out_packet_num, 0);
    }

    #[test]
    fn server_rejects_handshake_in_wrong_state() {
        let mut server = RpcServerData::new();
        let pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        server.init_accepted(pid);

        assert_eq!(
            server.process_handshake_received(ProcessId::default()),
            Err(ServerError::UnexpectedHandshake)
        );
    }

    #[test]
    fn server_advances_packet_numbers_strict() {
        let mut server = RpcServerData::new();
        server.in_packet_num = 5;
        server.allow_seqno_holes = false;

        assert!(server.advance_in_packet_num(5).is_ok());
        assert_eq!(server.in_packet_num, 6);

        assert_eq!(
            server.advance_in_packet_num(5),
            Err(ServerError::PacketSequenceError {
                expected: 5,
                actual: 6
            })
        );
    }

    #[test]
    fn server_allows_seqno_holes() {
        let mut server = RpcServerData::new();
        server.in_packet_num = 5;
        server.allow_seqno_holes = true;

        // Can skip ahead
        assert!(server.advance_in_packet_num(10).is_ok());
        assert_eq!(server.in_packet_num, 11);

        // Cannot go backwards
        assert_eq!(
            server.advance_in_packet_num(5),
            Err(ServerError::PacketSequenceError {
                expected: 5,
                actual: 11
            })
        );
    }

    #[test]
    fn server_processes_client_nonce_packet() {
        use crate::runtime::net::tcp_rpc_common::{CryptoSchema, NoncePacket};

        let mut server = RpcServerData::new();
        let local_pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        server.init_accepted(local_pid);

        let nonce_packet = NoncePacket::new(12345, CryptoSchema::Aes, 100, [1_u8; 16]);
        let result = server.process_client_nonce_packet(&nonce_packet, true, true);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CryptoSchema::Aes.to_i32());
        assert_eq!(server.state, ServerState::NonceReceived);
        assert_eq!(server.crypto_schema, CryptoSchema::Aes.to_i32());
    }

    #[test]
    fn server_upgrades_to_encryption_when_required() {
        use crate::runtime::net::tcp_rpc_common::{CryptoSchema, NoncePacket};

        let mut server = RpcServerData::new();
        let local_pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        server.init_accepted(local_pid);

        // Client requests no encryption but server doesn't allow it
        let nonce_packet = NoncePacket::new(0, CryptoSchema::None, 100, [1_u8; 16]);
        let result = server.process_client_nonce_packet(&nonce_packet, false, true);

        assert!(result.is_ok());
        // Server upgrades to AES
        assert_eq!(result.unwrap(), CryptoSchema::Aes.to_i32());
    }

    #[test]
    fn server_processes_client_handshake_packet() {
        use crate::runtime::net::tcp_rpc_common::{CryptoSchema, HandshakePacket, NoncePacket};

        let mut server = RpcServerData::new();
        let local_pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        server.init_accepted(local_pid);

        let nonce_packet = NoncePacket::new(0, CryptoSchema::Aes, 100, [1_u8; 16]);
        server
            .process_client_nonce_packet(&nonce_packet, true, true)
            .unwrap();

        let client_pid = ProcessId::new(0x7f00_0002, 9090, 54321, 2000);
        let handshake = HandshakePacket::new(0, client_pid, local_pid);

        assert!(server
            .process_client_handshake_packet(&handshake, None)
            .is_ok());
        assert_eq!(server.state, ServerState::HandshakeReceived);
        assert_eq!(server.remote_pid, client_pid);
    }

    #[test]
    fn server_validates_packet_numbers() {
        let mut server = RpcServerData::new();
        let local_pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        server.init_accepted(local_pid);

        // In Accepted state, expect packet -2
        assert!(server.validate_packet_number(-2).is_ok());
        assert!(server.validate_packet_number(-1).is_err());

        // In NonceReceived state, expect packet -1
        server.state = ServerState::NonceReceived;
        assert!(server.validate_packet_number(-1).is_ok());
        assert!(server.validate_packet_number(-2).is_err());

        // In Ready state, validate sequence (strict mode)
        server.state = ServerState::Ready;
        server.in_packet_num = 5;
        server.allow_seqno_holes = false;
        assert!(server.validate_packet_number(5).is_ok());
        assert!(server.validate_packet_number(4).is_err());
        assert!(server.validate_packet_number(6).is_err());

        // With seqno holes allowed
        server.allow_seqno_holes = true;
        assert!(server.validate_packet_number(10).is_ok());
        assert!(server.validate_packet_number(4).is_err()); // Can't go backwards
    }

    #[test]
    fn compat_nonce_policy_falls_back_to_unencrypted() {
        use crate::runtime::net::tcp_rpc_common::{CryptoSchema, NoncePacket};

        let packet = NoncePacket::new(0, CryptoSchema::Aes, 100, [0_u8; 16]);
        let mut out_schema = 0;
        let mut out_key_select = 0;
        let mut out_has_dh_params = 0;

        let rc = process_nonce_packet_for_compat(
            packet.to_bytes(),
            true,
            false,
            100,
            32,
            12345,
            &mut out_schema,
            &mut out_key_select,
            &mut out_has_dh_params,
        );

        assert_eq!(rc, 0);
        assert_eq!(out_schema, CryptoSchema::None.to_i32());
        assert_eq!(out_key_select, 0);
        assert_eq!(out_has_dh_params, 0);
    }
}
