# RPC Client and Server Implementation

## Overview

This module provides idiomatic Rust implementations of the RPC (Remote Procedure Call) client and server protocols used in MTProxy. The implementation is based on the C code in `net/net-tcp-rpc-{client,server,common}.c` but uses Rust idioms for safety and clarity.

## Architecture

### Core Components

1. **tcp_rpc_common**: Shared types and utilities
   - `RpcPacketType`: Enum for packet types (Nonce, Handshake, Ping, Pong)
   - `ProcessId`: Process identifier with IP, port, PID, and timestamp
   - `encode_compact_header()`: Packet header encoding

2. **tcp_rpc_client**: Client-side RPC implementation
   - `RpcClientData`: Client connection state machine
   - `ClientState`: Connection lifecycle states
   - `CryptoFlags`: Encryption negotiation flags
   - Helper functions for packet validation

3. **tcp_rpc_server**: Server-side RPC implementation
   - `RpcServerData`: Server connection state machine
   - `ServerState`: Server lifecycle states
   - Helper functions for packet validation and header checking

4. **tcp_rpc_ext_server**: TLS extension server helpers
   - Domain and client random bucket indexing
   - Server Hello profile selection

## State Machines

### Client Connection Lifecycle

```
Uninitialized
    ↓ init_outbound()
Connected
    ↓ mark_nonce_sent()
NonceSent
    ↓ process_nonce_received()
NonceReceived
    ↓ mark_handshake_sent()
HandshakeSent
    ↓ process_handshake_received()
Ready
    ↓ (connection active for RPC operations)
Closed
```

### Server Connection Lifecycle

```
Uninitialized
    ↓ init_accepted()
Accepted
    ↓ process_nonce_received()
NonceReceived
    ↓ process_handshake_received()
HandshakeReceived
    ↓ mark_ready()
Ready
    ↓ (connection active for RPC operations)
Closed
```

## Packet Protocol

### Packet Structure

All RPC packets follow this structure:
```
[length: 4 bytes] [packet_num: 4 bytes] [type: 4 bytes] [payload] [crc32: 4 bytes]
```

- **Length**: Total packet size (4-byte aligned)
- **Packet Number**: Sequence number (-2: nonce, -1: handshake, 0+: data)
- **Type**: RPC packet type (see `RpcPacketType`)
- **Payload**: Type-specific data
- **CRC32**: Checksum for integrity verification

### Packet Types

- **Nonce (0x7acb87aa)**: Encryption negotiation
- **Handshake (0x7682eef5)**: Process ID verification
- **HandshakeError (0x6a27beda)**: Handshake failure response
- **Ping (0x7bdeef2a4)**: Keep-alive request
- **Pong (-1948322907)**: Keep-alive response

## Encryption Modes

The RPC protocol supports multiple encryption modes:

1. **None**: No encryption (ALLOW_UNENCRYPTED)
2. **AES**: Simple AES with single key (ALLOW_ENCRYPTED)
3. **AES_EXT**: AES with extra key options
4. **AES_DH**: AES with Diffie-Hellman key exchange (REQUIRE_DH)

## Usage Example

```rust
use mtproxy_core::runtime::net::tcp_rpc_client::{RpcClientData, CryptoFlags};
use mtproxy_core::runtime::net::tcp_rpc_common::ProcessId;

// Initialize client
let mut client = RpcClientData::new();
client.init_outbound(CryptoFlags::require_encryption());

// Send nonce
let nonce = [1, 2, 3, ..., 16]; // 16-byte nonce
client.mark_nonce_sent(nonce, current_timestamp());

// Process server nonce
if let Ok(()) = client.process_nonce_received(crypto_schema) {
    // Send handshake
    client.mark_handshake_sent();
    
    // Process server handshake
    let remote_pid = ProcessId::new(server_ip, server_port, server_pid, server_utime);
    if let Ok(()) = client.process_handshake_received(remote_pid) {
        // Connection is ready for RPC operations
        assert!(client.is_ready());
    }
}
```

## FFI Integration

The RPC implementation is integrated with the C codebase through the FFI layer in `rust/mtproxy-ffi`. The following functions are exported:

- `mtproxy_ffi_tcp_rpc_encode_compact_header()`
- `mtproxy_ffi_tcp_rpc_client_packet_len_state()`
- `mtproxy_ffi_tcp_rpc_server_packet_header_malformed()`
- `mtproxy_ffi_tcp_rpc_server_packet_len_state()`

## Testing

Comprehensive tests are provided for all components:

- **Client tests**: 15 tests covering state transitions, error handling, and packet sequencing
- **Server tests**: 13 tests covering server lifecycle, sequence number gaps, and quick ACK mode
- **Common tests**: 6 tests for packet types, ProcessId, and header encoding

Run tests with:
```bash
cargo test --package mtproxy-core runtime::net::tcp_rpc
```

## Future Work

The current implementation provides the core data structures and state machines. Future enhancements could include:

1. Full packet I/O implementation (send/receive)
2. Crypto provider integration for AES-CBC and DH key exchange
3. Connection pool management
4. Rate limiting for DH accepts
5. HTTP/Memcache fallback protocol support
6. Complete migration of connection handlers from C to Rust

## References

- C Implementation: `net/net-tcp-rpc-client.c`, `net/net-tcp-rpc-server.c`
- Protocol Documentation: TBD
- FFI Boundary: `rust/mtproxy-ffi/BOUNDARY.md`
