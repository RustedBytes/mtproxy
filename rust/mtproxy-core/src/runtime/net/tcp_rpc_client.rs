//! RPC Client implementation ported from `net/net-tcp-rpc-client.c`.

use super::tcp_rpc_common::{ProcessId, RpcPacketType};

pub const PACKET_LEN_STATE_SKIP: i32 = 0;
pub const PACKET_LEN_STATE_READY: i32 = 1;
pub const PACKET_LEN_STATE_INVALID: i32 = -1;
pub const PACKET_LEN_STATE_SHORT: i32 = -2;

/// RPC crypto flags for client connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoFlags {
    pub allow_unencrypted: bool,
    pub allow_encrypted: bool,
    pub require_dh: bool,
    pub skip_dh_allowed: bool,
    pub encryption_sent: bool,
    pub encryption_active: bool,
}

impl CryptoFlags {
    /// Creates default crypto flags allowing all modes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allow_unencrypted: true,
            allow_encrypted: true,
            require_dh: false,
            skip_dh_allowed: true,
            encryption_sent: false,
            encryption_active: false,
        }
    }

    /// Creates crypto flags requiring encryption.
    #[must_use]
    pub const fn require_encryption() -> Self {
        Self {
            allow_unencrypted: false,
            allow_encrypted: true,
            require_dh: true,
            skip_dh_allowed: false,
            encryption_sent: false,
            encryption_active: false,
        }
    }
}

impl Default for CryptoFlags {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection state for RPC client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Initial state, not yet connected.
    Uninitialized,
    /// Connected, waiting to send nonce.
    Connected,
    /// Nonce sent, waiting for server nonce.
    NonceSent,
    /// Server nonce received, encryption negotiated.
    NonceReceived,
    /// Handshake sent, waiting for server handshake.
    HandshakeSent,
    /// Fully established and ready for RPC operations.
    Ready,
    /// Connection closed or failed.
    Closed,
}

/// RPC client connection data.
#[derive(Debug, Clone)]
pub struct RpcClientData {
    /// Current connection state.
    pub state: ClientState,
    /// Encryption configuration flags.
    pub crypto_flags: CryptoFlags,
    /// Incoming packet sequence number (-2: initial, -1: handshake, 0+: data).
    pub in_packet_num: i32,
    /// Outgoing packet sequence number.
    pub out_packet_num: i32,
    /// Remote process identifier.
    pub remote_pid: ProcessId,
    /// Encryption nonce (16 bytes).
    pub nonce: [u8; 16],
    /// Timestamp when nonce was created.
    pub nonce_time: f64,
    /// Selected crypto schema.
    pub crypto_schema: i32,
}

impl RpcClientData {
    /// Creates a new RPC client data structure in uninitialized state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ClientState::Uninitialized,
            crypto_flags: CryptoFlags::new(),
            in_packet_num: -2,
            out_packet_num: -2,
            remote_pid: ProcessId::default(),
            nonce: [0_u8; 16],
            nonce_time: 0.0,
            crypto_schema: 0,
        }
    }

    /// Initializes client for outbound connection.
    pub fn init_outbound(&mut self, crypto_flags: CryptoFlags) {
        self.state = ClientState::Connected;
        self.crypto_flags = crypto_flags;
        self.in_packet_num = -2;
        self.out_packet_num = -2;
    }

    /// Transitions to nonce sent state.
    pub fn mark_nonce_sent(&mut self, nonce: [u8; 16], timestamp: f64) {
        self.state = ClientState::NonceSent;
        self.nonce = nonce;
        self.nonce_time = timestamp;
        self.crypto_flags.encryption_sent = true;
    }

    /// Processes received server nonce.
    pub fn process_nonce_received(&mut self, crypto_schema: i32) -> Result<(), ClientError> {
        if self.state != ClientState::NonceSent {
            return Err(ClientError::UnexpectedNonce);
        }
        self.state = ClientState::NonceReceived;
        self.crypto_schema = crypto_schema;
        self.in_packet_num = -1;
        Ok(())
    }

    /// Transitions to handshake sent state.
    pub fn mark_handshake_sent(&mut self) {
        self.state = ClientState::HandshakeSent;
        self.out_packet_num = -1;
    }

    /// Processes received handshake and transitions to ready state.
    pub fn process_handshake_received(&mut self, remote_pid: ProcessId) -> Result<(), ClientError> {
        if self.state != ClientState::HandshakeSent {
            return Err(ClientError::UnexpectedHandshake);
        }
        self.state = ClientState::Ready;
        self.remote_pid = remote_pid;
        self.in_packet_num = 0;
        self.out_packet_num = 0;
        Ok(())
    }

    /// Validates and advances incoming packet number.
    pub fn advance_in_packet_num(&mut self, expected: i32) -> Result<(), ClientError> {
        if self.in_packet_num != expected {
            return Err(ClientError::PacketSequenceError {
                expected,
                actual: self.in_packet_num,
            });
        }
        self.in_packet_num += 1;
        Ok(())
    }

    /// Checks if connection is ready for RPC operations.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, ClientState::Ready)
    }
}

impl Default for RpcClientData {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during RPC client operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    /// Received nonce in wrong state.
    UnexpectedNonce,
    /// Received handshake in wrong state.
    UnexpectedHandshake,
    /// Packet sequence number mismatch.
    PacketSequenceError { expected: i32, actual: i32 },
    /// Invalid packet type.
    InvalidPacketType(i32),
    /// Crypto negotiation failed.
    CryptoNegotiationFailed,
}

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

/// Validates packet type for client connection.
#[must_use]
pub fn validate_packet_type(packet_type: i32, state: ClientState) -> Result<RpcPacketType, ClientError> {
    match RpcPacketType::from_i32(packet_type) {
        Some(RpcPacketType::Nonce) if state == ClientState::NonceSent => Ok(RpcPacketType::Nonce),
        Some(RpcPacketType::Handshake) if state == ClientState::HandshakeSent => {
            Ok(RpcPacketType::Handshake)
        }
        Some(RpcPacketType::Ping) | Some(RpcPacketType::Pong) if state == ClientState::Ready => {
            Ok(RpcPacketType::from_i32(packet_type).unwrap())
        }
        _ => Err(ClientError::InvalidPacketType(packet_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        packet_len_state, ClientError, ClientState, CryptoFlags, ProcessId, RpcClientData,
        PACKET_LEN_STATE_INVALID, PACKET_LEN_STATE_READY, PACKET_LEN_STATE_SHORT,
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

    #[test]
    fn crypto_flags_default_allows_all() {
        let flags = CryptoFlags::default();
        assert!(flags.allow_unencrypted);
        assert!(flags.allow_encrypted);
        assert!(!flags.require_dh);
        assert!(flags.skip_dh_allowed);
    }

    #[test]
    fn crypto_flags_can_require_encryption() {
        let flags = CryptoFlags::require_encryption();
        assert!(!flags.allow_unencrypted);
        assert!(flags.allow_encrypted);
        assert!(flags.require_dh);
        assert!(!flags.skip_dh_allowed);
    }

    #[test]
    fn client_data_starts_uninitialized() {
        let client = RpcClientData::new();
        assert_eq!(client.state, ClientState::Uninitialized);
        assert_eq!(client.in_packet_num, -2);
        assert_eq!(client.out_packet_num, -2);
        assert!(!client.is_ready());
    }

    #[test]
    fn client_init_outbound_sets_connected_state() {
        let mut client = RpcClientData::new();
        let flags = CryptoFlags::require_encryption();
        client.init_outbound(flags);
        
        assert_eq!(client.state, ClientState::Connected);
        assert_eq!(client.crypto_flags, flags);
        assert_eq!(client.in_packet_num, -2);
    }

    #[test]
    fn client_nonce_flow() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new());
        
        let nonce = [1_u8; 16];
        client.mark_nonce_sent(nonce, 123.0);
        
        assert_eq!(client.state, ClientState::NonceSent);
        assert_eq!(client.nonce, nonce);
        assert_eq!(client.nonce_time, 123.0);
        assert!(client.crypto_flags.encryption_sent);
        
        assert!(client.process_nonce_received(1).is_ok());
        assert_eq!(client.state, ClientState::NonceReceived);
        assert_eq!(client.crypto_schema, 1);
        assert_eq!(client.in_packet_num, -1);
    }

    #[test]
    fn client_rejects_nonce_in_wrong_state() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new());
        
        assert_eq!(
            client.process_nonce_received(1),
            Err(ClientError::UnexpectedNonce)
        );
    }

    #[test]
    fn client_handshake_flow() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new());
        client.mark_nonce_sent([0_u8; 16], 0.0);
        client.process_nonce_received(1).unwrap();
        
        client.mark_handshake_sent();
        assert_eq!(client.state, ClientState::HandshakeSent);
        assert_eq!(client.out_packet_num, -1);
        
        let pid = ProcessId::default();
        assert!(client.process_handshake_received(pid).is_ok());
        assert_eq!(client.state, ClientState::Ready);
        assert_eq!(client.in_packet_num, 0);
        assert_eq!(client.out_packet_num, 0);
        assert!(client.is_ready());
    }

    #[test]
    fn client_rejects_handshake_in_wrong_state() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new());
        
        assert_eq!(
            client.process_handshake_received(ProcessId::default()),
            Err(ClientError::UnexpectedHandshake)
        );
    }

    #[test]
    fn client_advances_packet_numbers() {
        let mut client = RpcClientData::new();
        client.in_packet_num = 5;
        
        assert!(client.advance_in_packet_num(5).is_ok());
        assert_eq!(client.in_packet_num, 6);
        
        assert_eq!(
            client.advance_in_packet_num(5),
            Err(ClientError::PacketSequenceError {
                expected: 5,
                actual: 6
            })
        );
    }
}
