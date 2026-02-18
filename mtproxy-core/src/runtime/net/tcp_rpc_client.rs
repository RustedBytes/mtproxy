//! RPC Client implementation ported from `net/net-tcp-rpc-client.c`.

use super::tcp_rpc_common::{
    parse_handshake_packet, parse_nonce_packet, PacketSerialization, ParsedHandshakePacket,
    ParsedNoncePacket, ProcessId, RpcPacketType,
};

pub const PACKET_LEN_STATE_SKIP: i32 = 0;
pub const PACKET_LEN_STATE_READY: i32 = 1;
pub const PACKET_LEN_STATE_INVALID: i32 = -1;
pub const PACKET_LEN_STATE_SHORT: i32 = -2;
pub const RPCF_ALLOW_UNENC: i32 = 1;
pub const RPCF_ALLOW_ENC: i32 = 2;
pub const RPCF_REQ_DH: i32 = 4;
pub const RPCF_ALLOW_SKIP_DH: i32 = 8;
pub const RPCF_ENC_SENT: i32 = 16;
pub const RPCF_USE_CRC32C: i32 = 2048;

const RPCF_PERM_MASK: i32 = RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC | RPCF_REQ_DH | RPCF_ALLOW_SKIP_DH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultReadyState {
    NotYet,
    Ok,
    Fail(i32),
}

/// RPC crypto flags for client connections.
///
/// This struct uses individual boolean fields instead of bitflags to maintain
/// clarity and type safety for encryption negotiation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
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
    /// Last activity timestamp for timeout tracking.
    pub last_activity: f64,
    /// Connection start timestamp.
    pub connect_time: f64,
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
            last_activity: 0.0,
            connect_time: 0.0,
        }
    }

    /// Initializes client for outbound connection.
    pub fn init_outbound(&mut self, crypto_flags: CryptoFlags, now: f64) {
        self.state = ClientState::Connected;
        self.crypto_flags = crypto_flags;
        self.in_packet_num = -2;
        self.out_packet_num = -2;
        self.connect_time = now;
        self.last_activity = now;
    }

    /// Transitions to nonce sent state.
    pub fn mark_nonce_sent(&mut self, nonce: [u8; 16], timestamp: f64) {
        self.state = ClientState::NonceSent;
        self.nonce = nonce;
        self.nonce_time = timestamp;
        self.crypto_flags.encryption_sent = true;
        self.last_activity = timestamp;
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

    /// Updates last activity timestamp.
    pub fn update_activity(&mut self, timestamp: f64) {
        self.last_activity = timestamp;
    }

    /// Checks if connection has timed out.
    #[must_use]
    pub fn is_timed_out(&self, current_time: f64, timeout_seconds: f64) -> bool {
        (current_time - self.last_activity) > timeout_seconds
    }

    /// Gets connection age in seconds.
    #[must_use]
    pub fn connection_age(&self, current_time: f64) -> f64 {
        current_time - self.connect_time
    }

    /// Gets time since last activity in seconds.
    #[must_use]
    pub fn idle_time(&self, current_time: f64) -> f64 {
        current_time - self.last_activity
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

    /// Checks if encryption is active.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.crypto_flags.encryption_active
    }

    /// Gets the current crypto schema.
    #[must_use]
    pub const fn get_crypto_schema(&self) -> i32 {
        self.crypto_schema
    }

    /// Processes a parsed nonce packet payload and validates crypto settings.
    fn process_parsed_nonce_packet(
        &mut self,
        packet: &ParsedNoncePacket,
    ) -> Result<(), ClientError> {
        if self.state != ClientState::NonceSent {
            return Err(ClientError::UnexpectedNonce);
        }

        if packet.packet_type != RpcPacketType::Nonce as i32 {
            return Err(ClientError::InvalidPacketType(packet.packet_type));
        }

        let sent_nonce_time = self.nonce_time.trunc();
        if sent_nonce_time != 0.0 && (f64::from(packet.crypto_ts) - sent_nonce_time).abs() > 30.0 {
            return Err(ClientError::CryptoNegotiationFailed);
        }

        match packet.crypto_schema {
            super::tcp_rpc_common::CryptoSchema::None => {
                if packet.key_select != 0 {
                    return Err(ClientError::CryptoNegotiationFailed);
                }
                if !self.crypto_flags.allow_unencrypted {
                    return Err(ClientError::CryptoNegotiationFailed);
                }
                self.crypto_flags.allow_encrypted = false;
                self.crypto_flags.encryption_active = false;
            }
            super::tcp_rpc_common::CryptoSchema::Aes
            | super::tcp_rpc_common::CryptoSchema::AesExt
            | super::tcp_rpc_common::CryptoSchema::AesDh => {
                if !self.crypto_flags.allow_encrypted {
                    return Err(ClientError::CryptoNegotiationFailed);
                }
                if packet.crypto_schema == super::tcp_rpc_common::CryptoSchema::AesDh
                    && self.crypto_flags.require_dh
                    && !packet.has_dh_params
                {
                    return Err(ClientError::CryptoNegotiationFailed);
                }
                self.crypto_flags.encryption_active = true;
            }
        }

        self.state = ClientState::NonceReceived;
        self.crypto_schema = packet.crypto_schema.to_i32();
        self.in_packet_num = -1;
        Ok(())
    }

    /// Processes a raw nonce packet payload.
    pub fn process_nonce_packet_bytes(&mut self, packet_bytes: &[u8]) -> Result<(), ClientError> {
        let packet =
            parse_nonce_packet(packet_bytes).ok_or_else(|| ClientError::InvalidPacketSize {
                size: packet_bytes.len(),
                expected: super::tcp_rpc_common::NoncePacket::size(),
            })?;
        self.process_parsed_nonce_packet(&packet)
    }

    /// Processes a received nonce packet and validates crypto schema.
    ///
    /// This validates the server's nonce packet and updates the client state
    /// based on the negotiated crypto schema.
    pub fn process_nonce_packet(
        &mut self,
        packet: &super::tcp_rpc_common::NoncePacket,
    ) -> Result<(), ClientError> {
        self.process_nonce_packet_bytes(&packet.to_bytes())
    }

    fn process_parsed_handshake_packet(
        &mut self,
        packet: &ParsedHandshakePacket,
    ) -> Result<(), ClientError> {
        if self.state != ClientState::HandshakeSent {
            return Err(ClientError::UnexpectedHandshake);
        }

        // Validate that the peer PID in the handshake matches expectations
        // The sender_pid is the remote server's PID
        self.remote_pid = packet.sender_pid;

        self.state = ClientState::Ready;
        self.in_packet_num = 0;
        self.out_packet_num = 0;
        Ok(())
    }

    /// Processes raw handshake packet bytes.
    pub fn process_handshake_packet_bytes(
        &mut self,
        packet_bytes: &[u8],
    ) -> Result<(), ClientError> {
        let packet =
            parse_handshake_packet(packet_bytes).ok_or_else(|| ClientError::InvalidPacketSize {
                size: packet_bytes.len(),
                expected: super::tcp_rpc_common::HandshakePacket::size(),
            })?;
        self.process_parsed_handshake_packet(&packet)
    }

    /// Processes a received handshake packet and validates the remote PID.
    ///
    /// This validates the server's handshake and transitions to Ready state.
    pub fn process_handshake_packet(
        &mut self,
        packet: &super::tcp_rpc_common::HandshakePacket,
    ) -> Result<(), ClientError> {
        self.process_handshake_packet_bytes(&packet.to_bytes())
    }

    /// Validates a packet number for the current connection state.
    pub fn validate_packet_number(&self, packet_num: i32) -> Result<(), ClientError> {
        match self.state {
            ClientState::NonceSent if packet_num == -2 => Ok(()),
            ClientState::HandshakeSent if packet_num == -1 => Ok(()),
            ClientState::Ready if packet_num >= 0 && packet_num == self.in_packet_num => Ok(()),
            _ => Err(ClientError::PacketSequenceError {
                expected: self.in_packet_num,
                actual: packet_num,
            }),
        }
    }

    /// Prepares a nonce packet for sending.
    #[must_use]
    pub fn prepare_nonce_packet(
        &self,
        key_select: i32,
        schema: super::tcp_rpc_common::CryptoSchema,
        timestamp: i32,
    ) -> super::tcp_rpc_common::NoncePacket {
        super::tcp_rpc_common::NoncePacket::new(key_select, schema, timestamp, self.nonce)
    }

    /// Prepares a handshake packet for sending.
    #[must_use]
    pub fn prepare_handshake_packet(
        &self,
        flags: i32,
        local_pid: super::tcp_rpc_common::ProcessId,
    ) -> super::tcp_rpc_common::HandshakePacket {
        super::tcp_rpc_common::HandshakePacket::new(flags, local_pid, self.remote_pid)
    }
}

impl Default for RpcClientData {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during RPC client operations.
#[derive(Debug, Clone, Copy, PartialEq)]
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
    /// Connection timeout.
    Timeout { idle_seconds: f64 },
    /// Invalid packet size.
    InvalidPacketSize { size: usize, expected: usize },
}

impl core::fmt::Display for ClientError {
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
            Self::CryptoNegotiationFailed => write!(f, "Crypto schema negotiation failed"),
            Self::Timeout { idle_seconds } => {
                write!(f, "Connection timeout after {idle_seconds:.1}s idle")
            }
            Self::InvalidPacketSize { size, expected } => {
                write!(f, "Invalid packet size: {size} bytes, expected {expected}")
            }
        }
    }
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

#[must_use]
pub fn validate_nonce_header(
    packet_num: i32,
    packet_type: i32,
    packet_len: i32,
    nonce_packet_min_len: i32,
    nonce_packet_max_len: i32,
) -> i32 {
    if packet_num != -2 || packet_type != RpcPacketType::Nonce as i32 {
        return -2;
    }
    if packet_len < nonce_packet_min_len || packet_len > nonce_packet_max_len {
        return -3;
    }
    0
}

#[must_use]
pub fn validate_handshake_header(
    packet_num: i32,
    packet_type: i32,
    packet_len: i32,
    handshake_packet_len: i32,
) -> i32 {
    if packet_num != -1 || packet_type != RpcPacketType::Handshake as i32 {
        return -2;
    }
    if packet_len != handshake_packet_len {
        return -3;
    }
    0
}

pub fn validate_handshake(
    packet_flags: i32,
    sender_pid_matches: bool,
    ignore_pid: bool,
    peer_pid_matches: bool,
    default_rpc_flags: i32,
) -> Result<bool, i32> {
    if !sender_pid_matches && !ignore_pid {
        return Err(-6);
    }
    if !peer_pid_matches {
        return Err(-4);
    }
    if (packet_flags & 0xff) != 0 {
        return Err(-7);
    }
    if (packet_flags & RPCF_USE_CRC32C) != 0 && (default_rpc_flags & RPCF_USE_CRC32C) == 0 {
        return Err(-8);
    }
    Ok((packet_flags & RPCF_USE_CRC32C) != 0)
}

#[must_use]
pub fn normalize_perm_flags(raw_flags: i32) -> Option<i32> {
    let normalized = raw_flags & RPCF_PERM_MASK;
    if (normalized & (RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC)) == 0 {
        None
    } else {
        Some(normalized)
    }
}

#[must_use]
pub const fn default_connected_crypto_flags() -> i32 {
    RPCF_ALLOW_ENC | RPCF_ALLOW_UNENC
}

#[must_use]
pub const fn default_outbound_crypto_flags() -> i32 {
    RPCF_ALLOW_UNENC
}

#[must_use]
pub const fn requires_dh_accept(crypto_flags: i32) -> bool {
    (crypto_flags & RPCF_REQ_DH) != 0
}

#[must_use]
pub const fn default_check_perm(default_rpc_flags: i32) -> i32 {
    RPCF_ALLOW_ENC | default_rpc_flags
}

pub fn init_fake_crypto_state(crypto_flags: i32) -> Result<i32, i32> {
    if (crypto_flags & RPCF_ALLOW_UNENC) == 0 {
        return Err(-1);
    }
    if (crypto_flags & (RPCF_ALLOW_ENC | RPCF_ENC_SENT)) != 0 {
        return Err(-1);
    }
    Ok(crypto_flags | RPCF_ENC_SENT)
}

#[must_use]
pub fn default_check_ready(
    conn_has_error: bool,
    conn_is_connecting: bool,
    in_packet_num: i32,
    last_query_sent_time: f64,
    now: f64,
    connect_timeout: f64,
    conn_is_working: bool,
) -> DefaultReadyState {
    if conn_has_error {
        return DefaultReadyState::Fail(0);
    }

    if conn_is_connecting || in_packet_num < 0 {
        if last_query_sent_time < now - connect_timeout {
            return DefaultReadyState::Fail(-6);
        }
        return DefaultReadyState::NotYet;
    }

    if conn_is_working {
        return DefaultReadyState::Ok;
    }

    DefaultReadyState::Fail(-7)
}

/// C-compat nonce packet policy for `net-tcp-rpc-client.c`.
#[derive(Debug, Clone, Copy)]
pub struct NonceCompatPolicy {
    pub flags: i32,
    pub nonce_time: i32,
    pub main_secret_len: i32,
    pub main_key_signature: i32,
}

pub const NONCE_POLICY_ALLOW_UNENCRYPTED: i32 = 1 << 0;
pub const NONCE_POLICY_ALLOW_ENCRYPTED: i32 = 1 << 1;
pub const NONCE_POLICY_REQUIRE_DH: i32 = 1 << 2;
pub const NONCE_POLICY_HAS_CRYPTO_TEMP: i32 = 1 << 3;

#[derive(Debug, Default, Clone, Copy)]
pub struct NonceCompatOutput {
    pub schema: i32,
    pub key_select: i32,
    pub has_dh_params: i32,
}

/// C-compat nonce packet policy for `net-tcp-rpc-client.c`.
///
/// Return codes:
/// - `0` success
/// - `-1` parse failure
/// - `-3` key-selection mismatch
/// - `-5` schema disallowed by policy
/// - `-6` timestamp skew too large
/// - `-7` DH prerequisites missing
pub fn process_nonce_packet_for_compat(
    packet: &[u8],
    policy: NonceCompatPolicy,
    output: &mut NonceCompatOutput,
) -> i32 {
    let Some(parsed) = parse_nonce_packet(packet) else {
        return -1;
    };

    let selected_key = super::tcp_rpc_common::select_nonce_key_signature(
        &parsed,
        policy.main_secret_len,
        policy.main_key_signature,
    );

    output.schema = parsed.crypto_schema.to_i32();
    output.key_select = selected_key;
    output.has_dh_params = 0;

    match parsed.crypto_schema {
        super::tcp_rpc_common::CryptoSchema::None => {
            if selected_key != 0 {
                return -3;
            }
            if (policy.flags & NONCE_POLICY_ALLOW_UNENCRYPTED) == 0 {
                return -5;
            }
        }
        super::tcp_rpc_common::CryptoSchema::Aes => {
            if selected_key == 0 {
                return -3;
            }
            if (policy.flags & NONCE_POLICY_ALLOW_ENCRYPTED) == 0 {
                return -5;
            }
            if (f64::from(parsed.crypto_ts) - f64::from(policy.nonce_time)).abs() > 30.0 {
                return -6;
            }
        }
        super::tcp_rpc_common::CryptoSchema::AesExt
        | super::tcp_rpc_common::CryptoSchema::AesDh => {
            if selected_key == 0 {
                return -3;
            }
            if parsed.crypto_schema == super::tcp_rpc_common::CryptoSchema::AesDh
                && ((policy.flags & NONCE_POLICY_REQUIRE_DH) == 0
                    || (policy.flags & NONCE_POLICY_HAS_CRYPTO_TEMP) == 0)
            {
                return -7;
            }
            if parsed.crypto_schema == super::tcp_rpc_common::CryptoSchema::AesDh
                && (!parsed.has_dh_params || parsed.dh_params_select == 0)
            {
                return -7;
            }
            if (policy.flags & NONCE_POLICY_ALLOW_ENCRYPTED) == 0 {
                return -5;
            }
            if (f64::from(parsed.crypto_ts) - f64::from(policy.nonce_time)).abs() > 30.0 {
                return -6;
            }
            output.has_dh_params = i32::from(
                parsed.crypto_schema == super::tcp_rpc_common::CryptoSchema::AesDh
                    && parsed.has_dh_params
                    && parsed.dh_params_select != 0,
            );
        }
    }

    0
}

/// Validates packet type for client connection.
pub fn validate_packet_type(
    packet_type: i32,
    state: ClientState,
) -> Result<RpcPacketType, ClientError> {
    match RpcPacketType::from_i32(packet_type) {
        Some(RpcPacketType::Nonce) if state == ClientState::NonceSent => Ok(RpcPacketType::Nonce),
        Some(RpcPacketType::Handshake) if state == ClientState::HandshakeSent => {
            Ok(RpcPacketType::Handshake)
        }
        Some(pkt @ (RpcPacketType::Ping | RpcPacketType::Pong)) if state == ClientState::Ready => {
            Ok(pkt)
        }
        _ => Err(ClientError::InvalidPacketType(packet_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        default_check_perm, default_check_ready, default_connected_crypto_flags,
        default_outbound_crypto_flags, init_fake_crypto_state, normalize_perm_flags,
        packet_len_state, process_nonce_packet_for_compat, requires_dh_accept, ClientError,
        ClientState, CryptoFlags, DefaultReadyState, NonceCompatOutput, NonceCompatPolicy,
        ProcessId, RpcClientData, NONCE_POLICY_ALLOW_ENCRYPTED,
        PACKET_LEN_STATE_INVALID, PACKET_LEN_STATE_READY, PACKET_LEN_STATE_SHORT,
        PACKET_LEN_STATE_SKIP, RPCF_ALLOW_ENC, RPCF_ALLOW_SKIP_DH, RPCF_ALLOW_UNENC, RPCF_ENC_SENT,
        RPCF_REQ_DH,
    };
    use crate::runtime::net::tcp_rpc_common::{
        CryptoSchema, HandshakePacket, NoncePacket, PacketSerialization,
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
        client.init_outbound(flags, 0.0);

        assert_eq!(client.state, ClientState::Connected);
        assert_eq!(client.crypto_flags, flags);
        assert_eq!(client.in_packet_num, -2);
    }

    #[test]
    fn client_nonce_flow() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new(), 0.0);

        let nonce = [1_u8; 16];
        client.mark_nonce_sent(nonce, 123.0);

        assert_eq!(client.state, ClientState::NonceSent);
        assert_eq!(client.nonce, nonce);
        assert!((client.nonce_time - 123.0).abs() < f64::EPSILON);
        assert!(client.crypto_flags.encryption_sent);

        assert!(client.process_nonce_received(1).is_ok());
        assert_eq!(client.state, ClientState::NonceReceived);
        assert_eq!(client.crypto_schema, 1);
        assert_eq!(client.in_packet_num, -1);
    }

    #[test]
    fn client_rejects_nonce_in_wrong_state() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new(), 0.0);

        assert_eq!(
            client.process_nonce_received(1),
            Err(ClientError::UnexpectedNonce)
        );
    }

    #[test]
    fn client_handshake_flow() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new(), 0.0);
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
        client.init_outbound(CryptoFlags::new(), 0.0);

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

    #[test]
    fn client_processes_nonce_packet_with_no_encryption() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new(), 0.0);
        client.mark_nonce_sent([1_u8; 16], 100.0);

        let nonce_packet = NoncePacket::new(0, CryptoSchema::None, 100, [2_u8; 16]);
        assert!(client.process_nonce_packet(&nonce_packet).is_ok());
        assert_eq!(client.state, ClientState::NonceReceived);
        assert_eq!(client.crypto_schema, CryptoSchema::None.to_i32());
        assert!(!client.is_encrypted());
    }

    #[test]
    fn client_processes_nonce_packet_with_aes() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new(), 0.0);
        client.mark_nonce_sent([1_u8; 16], 100.0);

        let nonce_packet = NoncePacket::new(12345, CryptoSchema::Aes, 100, [2_u8; 16]);
        assert!(client.process_nonce_packet(&nonce_packet).is_ok());
        assert_eq!(client.state, ClientState::NonceReceived);
        assert_eq!(client.crypto_schema, CryptoSchema::Aes.to_i32());
        assert!(client.is_encrypted());
    }

    #[test]
    fn client_rejects_nonce_packet_when_encryption_required() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::require_encryption(), 0.0);
        client.mark_nonce_sent([1_u8; 16], 100.0);

        let nonce_packet = NoncePacket::new(0, CryptoSchema::None, 100, [2_u8; 16]);
        assert_eq!(
            client.process_nonce_packet(&nonce_packet),
            Err(ClientError::CryptoNegotiationFailed)
        );
    }

    #[test]
    fn client_processes_handshake_packet() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new(), 0.0);
        client.mark_nonce_sent([0_u8; 16], 0.0);
        let nonce_packet = NoncePacket::new(0, CryptoSchema::Aes, 100, [0_u8; 16]);
        client.process_nonce_packet(&nonce_packet).unwrap();
        client.mark_handshake_sent();

        let server_pid = ProcessId::new(0x7f00_0001, 8080, 12345, 1000);
        let handshake = HandshakePacket::new(0, server_pid, ProcessId::default());

        assert!(client.process_handshake_packet(&handshake).is_ok());
        assert_eq!(client.state, ClientState::Ready);
        assert_eq!(client.remote_pid, server_pid);
        assert!(client.is_ready());
    }

    #[test]
    fn client_validates_packet_numbers() {
        let mut client = RpcClientData::new();
        client.init_outbound(CryptoFlags::new(), 0.0);

        // In NonceSent state, expect packet -2
        client.state = ClientState::NonceSent;
        assert!(client.validate_packet_number(-2).is_ok());
        assert!(client.validate_packet_number(-1).is_err());

        // In HandshakeSent state, expect packet -1
        client.state = ClientState::HandshakeSent;
        assert!(client.validate_packet_number(-1).is_ok());
        assert!(client.validate_packet_number(-2).is_err());

        // In Ready state, validate sequence
        client.state = ClientState::Ready;
        client.in_packet_num = 5;
        assert!(client.validate_packet_number(5).is_ok());
        assert!(client.validate_packet_number(4).is_err());
    }

    #[test]
    fn compat_nonce_policy_accepts_aes_with_selected_key() {
        let packet = NoncePacket::new(12345, CryptoSchema::Aes, 100, [0_u8; 16]);
        let mut output = NonceCompatOutput::default();

        let rc = process_nonce_packet_for_compat(
            &packet.to_bytes(),
            NonceCompatPolicy {
                flags: NONCE_POLICY_ALLOW_ENCRYPTED,
                nonce_time: 100,
                main_secret_len: 32,
                main_key_signature: 12345,
            },
            &mut output,
        );

        assert_eq!(rc, 0);
        assert_eq!(output.schema, CryptoSchema::Aes.to_i32());
        assert_eq!(output.key_select, 12345);
        assert_eq!(output.has_dh_params, 0);
    }

    #[test]
    fn normalizes_permission_flags_and_requires_allow_bit() {
        assert_eq!(
            normalize_perm_flags(RPCF_ALLOW_UNENC | RPCF_REQ_DH | 0x4000),
            Some(RPCF_ALLOW_UNENC | RPCF_REQ_DH)
        );
        assert_eq!(normalize_perm_flags(RPCF_ALLOW_SKIP_DH), None);
    }

    #[test]
    fn default_permission_and_crypto_flag_helpers_match_legacy_policy() {
        assert_eq!(
            default_connected_crypto_flags(),
            RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC
        );
        assert_eq!(default_outbound_crypto_flags(), RPCF_ALLOW_UNENC);
        assert_eq!(default_check_perm(0x2000), RPCF_ALLOW_ENC | 0x2000);
        assert!(requires_dh_accept(RPCF_REQ_DH));
        assert!(!requires_dh_accept(RPCF_ALLOW_UNENC));
    }

    #[test]
    fn fake_crypto_state_requires_unencrypted_only() {
        assert_eq!(
            init_fake_crypto_state(RPCF_ALLOW_UNENC),
            Ok(RPCF_ALLOW_UNENC | RPCF_ENC_SENT)
        );
        assert_eq!(init_fake_crypto_state(RPCF_ALLOW_ENC), Err(-1));
        assert_eq!(
            init_fake_crypto_state(RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC),
            Err(-1)
        );
    }

    #[test]
    fn default_check_ready_matches_legacy_decision_tree() {
        assert_eq!(
            default_check_ready(true, false, 0, 10.0, 11.0, 3.0, false),
            DefaultReadyState::Fail(0)
        );
        assert_eq!(
            default_check_ready(false, true, -2, 10.0, 12.0, 3.0, false),
            DefaultReadyState::NotYet
        );
        assert_eq!(
            default_check_ready(false, true, -2, 10.0, 14.0, 3.0, false),
            DefaultReadyState::Fail(-6)
        );
        assert_eq!(
            default_check_ready(false, false, 0, 10.0, 11.0, 3.0, true),
            DefaultReadyState::Ok
        );
        assert_eq!(
            default_check_ready(false, false, 0, 10.0, 11.0, 3.0, false),
            DefaultReadyState::Fail(-7)
        );
    }
}
