//! RPC Server implementation ported from `net/net-tcp-rpc-server.c`.

use super::tcp_rpc_client::{
    PACKET_LEN_STATE_INVALID, PACKET_LEN_STATE_READY, PACKET_LEN_STATE_SKIP,
};
use super::tcp_rpc_common::{ProcessId, RpcPacketType};

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
    pub fn prepare_handshake_response(
        &self,
        flags: i32,
    ) -> super::tcp_rpc_common::HandshakePacket {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Validates packet type for server connection.
pub fn validate_packet_type(packet_type: i32, state: ServerState) -> Result<RpcPacketType, ServerError> {
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
    use super::{packet_header_malformed, packet_len_state, ProcessId, RpcServerData, ServerError, ServerState};
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
}
