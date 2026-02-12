# MTProxy Architecture Documentation

## Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Module Breakdown](#module-breakdown)
4. [Network Architecture](#network-architecture)
5. [Data Flow](#data-flow)
6. [Cryptography](#cryptography)
7. [C-Rust Integration](#c-rust-integration)
8. [Configuration & Initialization](#configuration--initialization)
9. [Threading & Job Model](#threading--job-model)
10. [Key Data Structures](#key-data-structures)
11. [Build System](#build-system)

---

## Overview

### What is MTProxy?

MTProxy is a **high-performance Telegram MTProto protocol proxy** that enables clients to connect to Telegram servers through an intermediary server. This is particularly useful for:

- **Censorship circumvention**: Accessing Telegram in regions where it's blocked
- **Privacy enhancement**: Hiding the direct connection to Telegram servers
- **Network optimization**: Potentially improving connection quality through better routing

### Key Features

- **MTProto protocol support**: Full compatibility with Telegram's custom protocol
- **Multi-worker architecture**: Horizontal scaling via process-based workers
- **Hybrid C/Rust implementation**: Performance-critical C code with gradual Rust migration for safety
- **AES hardware acceleration**: Leverages x86 AESNI instructions for encryption
- **Event-driven networking**: Efficient epoll-based I/O multiplexing
- **Job-based threading**: Sophisticated work distribution across thread pools
- **HTTP & TCP support**: Multiple protocol variants for different client types

---

## System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      MTProxy Process                         │
│                                                              │
│  ┌────────────┐   ┌──────────────┐   ┌─────────────────┐  │
│  │  Client    │──▶│   Network    │──▶│    Engine       │  │
│  │ Connections│   │   Layer      │   │  (Event Loop)   │  │
│  └────────────┘   └──────────────┘   └─────────────────┘  │
│         │                 │                    │            │
│         │                 │                    │            │
│         ▼                 ▼                    ▼            │
│  ┌────────────┐   ┌──────────────┐   ┌─────────────────┐  │
│  │   Crypto   │   │ Job Threads  │   │  Connection     │  │
│  │ (AES/SHA)  │   │ (IO/CPU/Eng) │   │   Mapping       │  │
│  └────────────┘   └──────────────┘   └─────────────────┘  │
│         │                 │                    │            │
│         └─────────────────┴────────────────────┘            │
│                           │                                 │
│                           ▼                                 │
│                  ┌──────────────────┐                      │
│                  │ Rust FFI Bridge  │                      │
│                  └──────────────────┘                      │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
               ┌────────────────────────┐
               │   Telegram Backends    │
               │  (DC1, DC2, DC3, ...)  │
               └────────────────────────┘
```

### Process Model

MTProxy supports two operational modes:

1. **Single-worker mode** (`-M 1` or default):
   - One process handles all connections
   - Simpler debugging and resource management

2. **Multi-worker mode** (`-M N` where N > 1):
   - Master process forks N worker children
   - Each worker runs independent event loop
   - Workers share listening sockets (SO_REUSEPORT)
   - Signal propagation from master to all workers

```c
// From mtproto-proxy.c: Worker initialization
if (workers > 1) {
  for (i = 0; i < workers; i++) {
    pid_t pid = fork();
    if (pid < 0) {
      kprintf("fork() failed: %m\n");
      exit(1);
    }
    if (pid == 0) {
      // Worker process
      worker_id = i;
      break;
    } else {
      // Master keeps track of worker PIDs
      worker_pids[i] = pid;
    }
  }
}
```

---

## Module Breakdown

### 1. `mtproto/` - Protocol Implementation

**Purpose**: Core MTProto proxy logic, packet inspection, forwarding

**Key Files**:
- `mtproto-proxy.c` (76KB): Main proxy implementation
- `mtproto-config.c`: Configuration parsing and management
- `mtproto-common.h`: Protocol constants and structures

**Responsibilities**:
- Parse MTProto packet headers
- Manage client-to-backend connection mapping
- Handle protocol-specific features (random padding, HTTP wrapping)
- Process proxy secrets and authentication

**Example: Packet Inspection**
```c
// Inspect incoming packet to determine type
struct mtproxy_ffi_mtproto_inspected inspected;
mtproxy_ffi_mtproto_inspect_packet_header(
  packet_header, 
  packet_size, 
  &len, 
  &inspected
);

switch (inspected.kind) {
  case MTPROTO_PACKET_KIND_ENCRYPTED:
    // Handle encrypted MTProto packet
    forward_mtproto_enc_packet(c, &inspected);
    break;
  case MTPROTO_PACKET_KIND_UNENCRYPTED:
    // Handle plaintext packet (e.g., DH handshake)
    forward_mtproto_plain_packet(c, &inspected);
    break;
  case MTPROTO_PACKET_KIND_INVALID:
    // Reject malformed packet
    fail_connection(c, -1);
    break;
}
```

---

### 2. `engine/` - Event Loop & Orchestration

**Purpose**: Main event loop, RPC dispatching, signal handling

**Key Files**:
- `engine.c` (19KB): Core event loop (`engine_main_loop`)
- `engine-net.c`: Network event integration
- `engine-rpc.c` (24KB): RPC message routing
- `engine-signals.c`: Signal handler setup

**Event Loop Architecture**:
```c
void engine_main_loop(void) {
  while (!pending_signals) {
    // Wait for events (37ms timeout)
    int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 37);
    
    for (int i = 0; i < n; i++) {
      struct connection *c = events[i].data.ptr;
      
      // Dispatch to connection type handler
      if (events[i].events & EPOLLIN) {
        c->type->reader(c);  // Read handler
      }
      if (events[i].events & EPOLLOUT) {
        c->type->writer(c);  // Write handler
      }
    }
    
    // Process timers, alarms
    process_pending_timers();
  }
  
  handle_pending_signals();
}
```

**Signal Handling**:
- `SIGTERM`, `SIGINT`: Graceful shutdown
- `SIGUSR1`: Reopen log files
- `SIGCHLD`: Worker process death detection (in master)

---

### 3. `net/` - Networking Layer

**Purpose**: TCP/HTTP connection management, message buffers, RPC protocols

**Key Files**:
- `net-connections.c` (59KB): Base connection management
- `net-tcp-rpc-ext-server.c` (50KB): Extended RPC server for clients
- `net-tcp-rpc-client.c` (21KB): RPC client to Telegram backends
- `net-http-server.c` (22KB): HTTP protocol handler
- `net-msg.c` (42KB): Message buffer management
- `net-events.c` (23KB): Event system integration

**Connection Type System**:

Each connection has a "type" defining its behavior:
```c
struct connection_type {
  const char *name;
  int (*reader)(struct connection *c);
  int (*writer)(struct connection *c);
  void (*close)(struct connection *c);
  int (*alarm)(struct connection *c);
  // ... other callbacks
};

// Example types
conn_type_t ct_tcp_rpc_ext_server_mtfront;  // Client connections
conn_type_t ct_tcp_rpc_client_mtfront;      // Backend connections
conn_type_t ct_http_server_mtfront;         // HTTP client connections
```

**Message Buffer Management**:
```c
// From net-msg.h
struct msg_buffer {
  void *chunk;          // Pointer to data chunk
  int pos;              // Current position in buffer
  int len;              // Length of data
  struct msg_buffer *next;
};

// Buffer operations
int write_out_msg_buffers(struct connection *c);
int advance_skip_read_ptr(struct msg_buffers *X, int offset);
void free_unused_msg_buffers(struct msg_buffers *X);
```

---

### 4. `crypto/` - Cryptographic Operations

**Purpose**: Encryption, hashing, checksums

**Key Files**:
- `aesni256.c`: AES-256 using x86 AESNI instructions
- `sha1.c`, `sha256.c`: SHA hash functions
- `md5.c`: MD5 hashing
- `crc32.c`, `crc32c.c`: CRC checksums

**AES Implementation**:
```c
// From aesni256.h
struct aes256_ctr_key {
  uint8_t key[32];
  uint8_t iv[16];
  uint8_t counter[16];
};

// Hardware-accelerated AES-CTR encryption
void aes256_ctr_crypt(
  struct aes256_ctr_key *key,
  const uint8_t *in,
  uint8_t *out,
  size_t len
);
```

**Cryptographic Modes Supported**:
- **AES-CTR128**: Default mode for client-proxy encryption
- **AES-256-CBC**: Legacy mode
- **AESNI hardware acceleration**: Detected at runtime via CPUID

---

### 5. `jobs/` - Job Threading System

**Purpose**: Thread pool management, async work distribution

**Key Files**:
- `jobs.c` (50KB): Job system implementation
- `jobs.h` (19KB): Job API and structures

**Job Classes**:
```c
// Job execution contexts (from jobs.h)
#define JC_MAIN    0  // Main epoll thread
#define JC_IO      1  // I/O operations thread pool
#define JC_CPU     2  // CPU-intensive (crypto) thread pool
#define JC_ENGINE  3  // Engine/forwarding logic thread

// Job signals
#define JS_RUN   0   // Execute job
#define JS_MSG   2   // Process message
#define JS_ALARM 4   // Timer alarm
#define JS_ABORT 5   // Error propagation
#define JS_KILL  6   // Termination
```

**Job Creation Example**:
```c
// Create job for crypto operation
struct job_thread *job = create_async_job(
  crypto_job_execute,           // Function to execute
  JSP_PARENT_RWE | JSC_ALLOW(JC_CPU, JS_RUN),  // Scheduling policy
  -2,                           // Connection FD
  sizeof(crypto_context),       // Context size
  JT_HAVE_TIMER,               // Job flags
  nullptr                       // Parent job
);

// Schedule to CPU thread pool
schedule_job(job);
```

---

### 6. `common/` - Shared Utilities

**Purpose**: Configuration, logging, stats, utilities

**Key Files**:
- `tl-parse.c` (32KB): TL (Type Language) protocol parser
- `parse-config.c`: Configuration file parser
- `server-functions.c` (19KB): Common server utilities
- `kprintf.c`: Logging functions
- `mp-queue.c` (19KB): Multi-producer queue
- `rust-ffi-bridge.c` (24KB): Rust FFI integration glue

**TL Parsing** (Telegram Type Language):
```c
// Parse TL-encoded configuration
int tl_fetch_lookup_int(void) {
  // Read 4-byte integer in little-endian
  int result = *(int32_t *)in_ptr;
  in_ptr += 4;
  return result;
}

// Parse server port configuration
int cfg_parse_server_port(const char *addr, int port_flags) {
  // Use Rust FFI for parsing
  struct parse_server_port_result result;
  mtproxy_ffi_parse_server_port(addr, port_flags, &result);
  
  if (result.success) {
    add_listening_port(result.port, result.flags);
  }
  return result.success;
}
```

---

### 7. `rust/` - Rust Migration Components

**Purpose**: Gradual Rust migration for safety-critical code

**Key Crates**:
- `mtproxy-core`: Core Rust implementations
- `mtproxy-ffi`: FFI boundary layer (C-callable)
- `mtproxy-bin`: Future standalone Rust binary

**FFI Interface Example**:
```rust
// From rust/mtproxy-ffi/src/mtproto.rs
#[no_mangle]
pub extern "C" fn mtproxy_ffi_mtproto_inspect_packet_header(
    header: *const u8,
    size: usize,
    len_out: *mut u32,
    result: *mut MtprotoInspected,
) -> bool {
    // Safe Rust implementation
    let header_slice = unsafe { 
        std::slice::from_raw_parts(header, size) 
    };
    
    match inspect_packet(header_slice) {
        Ok(inspected) => {
            unsafe { *result = inspected.into_ffi(); }
            true
        }
        Err(_) => false,
    }
}
```

---

## Network Architecture

### Connection Model

MTProxy manages two types of connections simultaneously:

1. **Internal Connections** (Client → Proxy):
   - TCP or HTTP connections from Telegram clients
   - Encrypted with client-chosen AES key
   - Managed by `ct_tcp_rpc_ext_server_mtfront`

2. **External Connections** (Proxy → Backend):
   - TCP RPC connections to Telegram datacenters
   - Multiplexed through connection mapping
   - Managed by `ct_tcp_rpc_client_mtfront`

### Connection Mapping

The proxy maintains bidirectional mapping between client and backend connections:

```
Client A ──────┐
               ├──▶ ext_connection #1 ──▶ Backend DC1
Client B ──────┘

Client C ───────▶ ext_connection #2 ──▶ Backend DC2
```

**Data Structure**:
```c
struct ext_connection {
  // Client side
  int in_fd;                    // Client socket FD
  int in_gen;                   // Generation number
  long long in_conn_id;         // MTProto connection ID
  
  // Backend side
  int out_fd;                   // Backend socket FD
  int out_gen;                  // Generation number
  long long out_conn_id;        // Proxy-assigned connection ID
  
  // Security
  long long auth_key_id;        // Encryption key ID
  
  // Bookkeeping
  struct ext_connection *h_next; // Hash table chain
  struct ext_connection *lru_prev, *lru_next; // LRU list
  int last_response_time;       // Timestamp
};
```

### Hash Table Lookups

Two hash tables enable fast bidirectional lookups:

```c
#define EXT_CONN_TABLE_SIZE (1 << 22)  // 4M entries
#define EXT_CONN_HASH_SIZE  (1 << 20)  // 1M buckets

// Lookup by client connection
struct ext_connection *InExtConnectionHash[EXT_CONN_HASH_SIZE];

// Lookup by proxy connection
struct ext_connection *OutExtConnections[EXT_CONN_TABLE_SIZE];

// Hash function for client lookups
unsigned ext_conn_hash(int fd, long long conn_id) {
  return (fd * 17239 + conn_id) & (EXT_CONN_HASH_SIZE - 1);
}
```

### Port Configuration

```c
// From mtproto-proxy.c
#define MAX_HTTP_LISTEN_PORTS 128

struct {
  int port;
  int flags;  // HTTP vs TCP, IPv4 vs IPv6
} http_ports[MAX_HTTP_LISTEN_PORTS];

// Add listening port
int add_http_port(int port, int flags) {
  http_ports[http_ports_count].port = port;
  http_ports[http_ports_count].flags = flags;
  http_ports_count++;
}
```

**Port Flags**:
- `0x01`: HTTP mode (otherwise TCP)
- `0x02`: IPv6 (otherwise IPv4)
- Combined: `0x03` = HTTP + IPv6

---

## Data Flow

### Complete Packet Journey: Client → Telegram Backend

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. CLIENT SENDS ENCRYPTED MTPROTO PACKET                         │
└────────────────────────┬─────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. TCP/HTTP RECEIVE (net-tcp-rpc-ext-server.c)                   │
│    - tcp_rpc_ext_server_reader() reads from socket               │
│    - Data accumulated in c->In message buffers                   │
└────────────────────────┬─────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 3. PACKET INSPECTION (mtproto-proxy.c)                           │
│    - mtproxy_ffi_mtproto_inspect_packet_header()                 │
│    - Determine: ENCRYPTED / UNENCRYPTED / INVALID                │
└────────────────────────┬─────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 4. CRYPTO PROCESSING (if encrypted)                              │
│    - Extract auth_key_id from packet header                      │
│    - Schedule JC_CPU job: cpu_tcp_aes_crypto_decrypt_input()    │
│    - AES-CTR128 or AES-256-CBC decryption                        │
└────────────────────────┬─────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 5. CONNECTION MAPPING (mtproto-proxy.c)                          │
│    - get_ext_connection_by_in_conn_id() lookup                   │
│    - If not exists: create new ext_connection                    │
│    - Choose backend: choose_proxy_target()                       │
└────────────────────────┬─────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 6. RPC WRAPPING (forward_tcp_query in mtproto-proxy.c)           │
│    - Build RPC_PROXY_REQ packet (type 0x36cef1ee)                │
│    - Include: out_conn_id, client_ip, proxy_tag                  │
│    - Append original packet payload                              │
└────────────────────────┬─────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 7. OUTBOUND TRANSMISSION (net-tcp-rpc-client.c)                  │
│    - tcp_rpc_client_writer() sends to backend                    │
│    - Connection established if needed                            │
└────────────────────────┬─────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 8. BACKEND PROCESSING                                            │
│    - Telegram datacenter processes request                       │
│    - Returns RPC_PROXY_ANS with same out_conn_id                 │
└────────────────────────┬─────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 9. RESPONSE ROUTING (mtproto-proxy.c)                            │
│    - Lookup ext_connection by out_conn_id                        │
│    - Forward to original client connection (in_fd)               │
└────────────────────────┬─────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ 10. ENCRYPTION & SEND (if needed)                                │
│    - Schedule JC_CPU job: cpu_tcp_aes_crypto_encrypt_output()   │
│    - tcp_rpc_ext_server_writer() sends to client                 │
└──────────────────────────────────────────────────────────────────┘
```

### RPC Packet Format

**Forward Request (Proxy → Backend)**:
```c
struct rpc_proxy_req {
  int type;              // 0x36cef1ee (RPC_PROXY_REQ)
  int flags;             // Bit flags:
                         //   0x01: Use proxy tag
                         //   0x02: Random padding enabled
                         //   0x04: Compact mode
                         //   0x08: HTTP headers present
  long long out_conn_id; // Proxy-assigned connection ID
  
  // Client info (20 bytes)
  int client_ipv6[4];    // IPv6 address (or IPv4 in first int)
  int client_port;       // Client port
  
  // Optional fields based on flags
  char proxy_tag[16];    // If flag 0x01
  int http_header_len;   // If flag 0x08
  char http_headers[];   // If flag 0x08
  
  // Original packet
  char payload[];        // MTProto packet from client
};
```

**Backend Response**:
```c
struct rpc_proxy_ans {
  int type;              // 0x3fa2773e (RPC_PROXY_ANS)
  int flags;             // Response flags
  long long out_conn_id; // Connection ID (matches request)
  char payload[];        // MTProto response
};
```

---

## Cryptography

### Encryption Algorithms

MTProxy supports multiple AES modes:

| Mode | Key Size | IV Size | Use Case |
|------|----------|---------|----------|
| AES-CTR128 | 32 bytes | 16 bytes | Default (CONFIG_AES_CRYPT_CTR128) |
| AES-256-CBC | 32 bytes | 16 bytes | Legacy compatibility |

### Key Derivation

**From Proxy Secret**:
```c
// Secret format: 32 hex characters (16 bytes)
// Example: "dd0123456789abcdef0123456789abcd"
//          ^^ prefix indicates random padding

uint8_t secret[16];
hex_to_bytes(secret_hex_string, secret, 16);

// Derive AES keys (simplified)
struct aes_key_data keys;
memcpy(keys.read_key, secret, 16);
memcpy(keys.read_key + 16, secret, 16);  // Double for 256-bit
generate_iv(&keys.read_iv, secret);      // IV derivation

// Write keys (reversed)
memcpy(keys.write_key, keys.read_key, 32);
reverse_bytes(keys.write_iv, keys.read_iv, 16);
```

### Hardware Acceleration

**AESNI Detection**:
```c
// From common/cpuid.c
int check_aesni_support(void) {
  uint32_t eax, ebx, ecx, edx;
  __cpuid(1, eax, ebx, ecx, edx);
  
  // Check AESNI bit (ECX bit 25)
  return (ecx & (1 << 25)) != 0;
}

// From crypto/aesni256.c
void aes256_load_key(struct aes256_key *key, const uint8_t *raw_key) {
  // Use AESNI instructions for key expansion
  __m128i temp = _mm_loadu_si128((__m128i *)raw_key);
  // ... key schedule using _mm_aeskeygenassist_si128()
}
```

### Packet Encryption/Decryption

**Async Crypto Job**:
```c
// Schedule decryption in CPU thread pool
struct job_thread *decrypt_job = create_async_job(
  cpu_tcp_aes_crypto_decrypt_input,
  JSP_PARENT_RWE | JSC_ALLOW(JC_CPU, JS_RUN),
  c->fd,
  sizeof(struct tcp_rpc_data),
  JT_HAVE_TIMER,
  nullptr
);

// Job execution (in CPU thread)
void cpu_tcp_aes_crypto_decrypt_input(struct job_thread *job) {
  struct connection *c = job->connection;
  struct aes_key_data *keys = &c->crypto_keys;
  
  // Decrypt in-place
  aes256_ctr_crypt(&keys->read_key, 
                   c->In.total_bytes, 
                   c->In.total_bytes,
                   c->In.unprocessed_bytes);
  
  // Signal main thread
  job_signal(job, JS_RUN);
}
```

---

## C-Rust Integration

### Migration Strategy

MTProxy uses a **gradual migration pattern** from C to Rust:

1. **Phase 1** (Current): Critical functions in Rust via FFI
2. **Phase 2** (Ongoing): Entire modules migrated to Rust
3. **Phase 3** (Future): Pure Rust binary with C compatibility layer

### FFI Boundary Contract

From `rust/mtproxy-ffi/BOUNDARY.md`:

**Safety Guarantees**:
- All C-callable functions marked `#[no_mangle]` and `extern "C"`
- Pointer parameters checked for null before dereferencing
- Slice conversions validate length
- No panics cross FFI boundary (all errors returned as `bool` or error codes)

**Example: MD5 FFI**:

**Rust side** (`rust/mtproxy-ffi/src/crypto.rs`):
```rust
#[repr(C)]
pub struct Md5Context {
    state: [u32; 4],
    count: [u32; 2],
    buffer: [u8; 64],
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_md5_init(ctx: *mut Md5Context) {
    if ctx.is_null() {
        return;
    }
    
    let ctx = unsafe { &mut *ctx };
    ctx.state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];
    ctx.count = [0, 0];
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_md5_update(
    ctx: *mut Md5Context,
    data: *const u8,
    len: usize,
) {
    if ctx.is_null() || data.is_null() {
        return;
    }
    
    let ctx = unsafe { &mut *ctx };
    let data_slice = unsafe { std::slice::from_raw_parts(data, len) };
    
    // Safe Rust MD5 implementation
    md5_update_internal(ctx, data_slice);
}
```

**C side** (`common/rust-ffi-bridge.h`):
```c
// C header for Rust functions
typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
} mtproxy_ffi_md5_context_t;

// Declared in Rust, callable from C
void mtproxy_ffi_md5_init(mtproxy_ffi_md5_context_t *ctx);
void mtproxy_ffi_md5_update(
    mtproxy_ffi_md5_context_t *ctx,
    const uint8_t *data,
    size_t len
);
void mtproxy_ffi_md5_finalize(
    mtproxy_ffi_md5_context_t *ctx,
    uint8_t output[16]
);

// C usage
mtproxy_ffi_md5_context_t md5;
mtproxy_ffi_md5_init(&md5);
mtproxy_ffi_md5_update(&md5, data, len);
uint8_t hash[16];
mtproxy_ffi_md5_finalize(&md5, hash);
```

### Build Integration

**Makefile coordination**:
```makefile
# Rust FFI static library
RUST_FFI_STATICLIB = target/debug/libmtproxy_ffi.a

# Build Rust components
${RUST_FFI_STATICLIB}: ${RUST_RS_SOURCES}
	cargo build -p mtproxy-ffi

# Link into C binary
${EXE}/mtproto-proxy: ${RUST_OBJECTS} ${LIB}/libkdb.a ${RUST_FFI_STATICLIB}
	${CC} -o $@ ${RUST_OBJECTS} ${LIB}/libkdb.a \
	      ${RUST_FFI_STATICLIB} ${LIB}/libkdb.a ${LDFLAGS} -ldl
```

**Key points**:
- Rust compiled to static library (`.a` archive)
- Linked with C objects in final binary
- `libkdb.a` linked twice (before and after Rust lib) to resolve circular deps

---

## Configuration & Initialization

### Command-Line Options

```bash
./mtproto-proxy [OPTIONS] <config-file>
```

**Essential Options**:

| Option | Description | Example |
|--------|-------------|---------|
| `-u <user>` | Drop privileges to user | `-u nobody` |
| `-p <port>` | Stats HTTP port (localhost) | `-p 8888` |
| `-H <port>` | Client listen port | `-H 443` |
| `-S <secret>` | Proxy secret (32 hex chars) | `-S dd0123...abcd` |
| `-P <tag>` | Proxy tag from @MTProxybot | `-P 0123456789abcdef` |
| `-M <workers>` | Worker processes | `-M 4` |
| `-C <max_conns>` | Max special connections | `-C 60000` |
| `--aes-pwd <file> <conf>` | Telegram secrets | `--aes-pwd proxy-secret proxy-multi.conf` |

**Advanced Options**:
- `-W <size>`: TCP window clamp (default 131072)
- `-N <threads>`: Thread pool size per class
- `-T <timeout>`: HTTP client timeout (default 96s)
- `--nice <value>`: Process nice level

### Configuration File Format

MTProxy uses a custom configuration format based on Telegram's Type Language (TL):

```
# Example config
port = 8888;
http_ports = 80, 443;
max_special_connections = 60000;

# Cluster configuration (from proxy-multi.conf)
proxy_multi = [
  { 
    proxy_tag = "abcd1234",
    proxies = [
      { ip = "149.154.175.50", port = 443 },
      { ip = "149.154.167.51", port = 443 }
    ]
  }
];
```

### Initialization Sequence

```c
int main(int argc, char *argv[]) {
  // 1. Parse command-line
  parse_usage();
  
  // 2. Initialize subsystems
  engine_init();          // Event loop, signals
  init_dh_params();       // Crypto params
  init_listening_tcpv6();  // Sockets
  
  // 3. Load configuration
  if (config_filename) {
    load_config();
  }
  
  // 4. Setup connection types
  init_ct_server_mtfront();
  
  // 5. Initialize job system
  if (use_job_workers) {
    init_async_jobs(
      job_workers_io,   // I/O threads
      job_workers_cpu,  // CPU threads
      job_workers_eng   // Engine threads
    );
  }
  
  // 6. Start listening
  mtfront_pre_loop();
  
  // 7. Drop privileges
  if (username) {
    change_user(username);
  }
  
  // 8. Fork workers (if multi-worker)
  if (workers > 1) {
    for (i = 0; i < workers; i++) {
      if (fork() == 0) break;  // Child exits loop
    }
  }
  
  // 9. Run event loop
  engine_main_loop();
  
  return 0;
}
```

---

## Threading & Job Model

### Job System Architecture

MTProxy uses a sophisticated job-based threading model for work distribution:

```
Main Thread (JC_MAIN)
    │
    ├─▶ I/O Thread Pool (JC_IO)
    │   ├─ Thread 1
    │   ├─ Thread 2
    │   └─ Thread N
    │
    ├─▶ CPU Thread Pool (JC_CPU)
    │   ├─ Thread 1 (crypto, compression)
    │   ├─ Thread 2
    │   └─ Thread N
    │
    └─▶ Engine Thread Pool (JC_ENGINE)
        ├─ Thread 1 (forwarding, routing)
        ├─ Thread 2
        └─ Thread N
```

### Job Classes

```c
// From jobs.h
enum job_class {
  JC_MAIN = 0,    // Main epoll thread (no workers)
  JC_IO = 1,      // I/O operations (socket read/write prep)
  JC_CPU = 2,     // CPU-intensive (AES encryption, compression)
  JC_ENGINE = 3,  // Engine logic (packet forwarding, routing)
  JC_CLASSES = 4  // Total number of classes
};
```

### Job Lifecycle

**1. Job Creation**:
```c
struct job_thread *create_async_job(
  void (*run)(struct job_thread *job),  // Execution function
  int policy,                           // Scheduling policy
  int fd,                               // Associated FD (-1 if none)
  int size,                             // Context data size
  int flags,                            // Job flags
  struct job_thread *parent             // Parent job (or nullptr)
);

// Policy bits:
// - JSP_PARENT_RWE: Inherit signals from parent
// - JSC_ALLOW(class, signal): Allow signal in class
```

**2. Job Scheduling**:
```c
// Add job to appropriate class queue
void schedule_job(struct job_thread *job) {
  int target_class = determine_job_class(job);
  
  // Lock-free multi-producer queue
  mp_queue_push(&job_queues[target_class], &job->queue_entry);
  
  // Wake worker thread if sleeping
  if (job_workers[target_class].sleeping) {
    pthread_cond_signal(&job_workers[target_class].cond);
  }
}
```

**3. Job Execution** (in worker thread):
```c
void job_worker_thread(void *arg) {
  struct job_class_info *jc = arg;
  
  while (!shutdown_requested) {
    // Pop job from lock-free queue
    struct mp_queue_entry *entry = mp_queue_pop(&jc->queue);
    
    if (!entry) {
      // Queue empty, sleep
      pthread_cond_wait(&jc->cond, &jc->mutex);
      continue;
    }
    
    struct job_thread *job = container_of(entry, struct job_thread, queue_entry);
    
    // Execute job
    job->run(job);
    
    // Send completion signal to parent
    if (job->parent) {
      job_signal(job->parent, JS_RUN);
    }
  }
}
```

**4. Job Signals**:
```c
// Send signal to job (cross-thread communication)
void job_signal(struct job_thread *job, int signal) {
  job->pending_signals |= (1 << signal);
  
  // If job in different class, reschedule
  if (job->current_class != this_thread_class) {
    schedule_job(job);
  }
}
```

### Example: Crypto Job Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Packet received (Main Thread - JC_MAIN)                  │
│    - tcp_rpc_ext_server_reader() reads encrypted data       │
└────────────┬────────────────────────────────────────────────┘
             ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Create crypto job                                         │
│    job = create_async_job(decrypt_job_run, JC_CPU, ...)    │
│    schedule_job(job);                                       │
└────────────┬────────────────────────────────────────────────┘
             ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. CPU Thread executes (JC_CPU)                             │
│    - decrypt_job_run(job)                                   │
│    - aes256_ctr_decrypt(keys, in_buffer, out_buffer, len)  │
└────────────┬────────────────────────────────────────────────┘
             ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Signal completion to parent                              │
│    job_signal(parent_job, JS_RUN);                          │
└────────────┬────────────────────────────────────────────────┘
             ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Main thread processes decrypted data (JC_MAIN)           │
│    - forward_mtproto_packet()                               │
└─────────────────────────────────────────────────────────────┘
```

### Lock-Free Queue

The job system uses a multi-producer queue (`mp-queue.c`) for thread-safe communication:

```c
// From mp-queue.h
struct mp_queue {
  struct mp_queue_entry *head;   // Consumer end (single reader)
  struct mp_queue_entry *tail;   // Producer end (multiple writers)
  pthread_spinlock_t lock;       // Spinlock for tail updates
};

// Push (multiple producers)
void mp_queue_push(struct mp_queue *q, struct mp_queue_entry *entry) {
  entry->next = nullptr;
  
  pthread_spin_lock(&q->lock);
  if (q->tail) {
    q->tail->next = entry;
  } else {
    q->head = entry;
  }
  q->tail = entry;
  pthread_spin_unlock(&q->lock);
}

// Pop (single consumer)
struct mp_queue_entry *mp_queue_pop(struct mp_queue *q) {
  if (!q->head) {
    return nullptr;
  }
  
  struct mp_queue_entry *entry = q->head;
  q->head = entry->next;
  
  if (!q->head) {
    q->tail = nullptr;  // Queue now empty
  }
  
  return entry;
}
```

---

## Key Data Structures

### 1. Connection Structure

```c
// From net-connections.h
struct connection {
  int fd;                       // File descriptor
  int type_flags;               // Connection type flags
  int status;                   // Connection status
  int generation;               // FD reuse detection
  
  struct connection_type *type; // Callback vtable
  
  void *extra;                  // Type-specific data
  
  // Message buffers
  struct msg_buffers In;        // Incoming data
  struct msg_buffers Out;       // Outgoing data
  
  // Timing
  double last_response_time;
  double query_start_time;
  
  // Crypto
  struct aes_key_data crypto;   // AES keys
  
  // Event loop
  int ev_flags;                 // Current epoll flags
  struct event_timer timer;     // Associated timer
  
  // Parent/target connections
  struct connection *target;    // Forward target
};
```

### 2. External Connection Mapping

```c
// From mtproto-proxy.c
struct ext_connection {
  // Client connection identifiers
  int in_fd;                    // Client socket FD
  int in_gen;                   // Generation (for FD reuse detection)
  long long in_conn_id;         // MTProto connection ID from client
  
  // Backend connection identifiers
  int out_fd;                   // Backend socket FD
  int out_gen;                  // Generation
  long long out_conn_id;        // Proxy-generated connection ID
  
  // Encryption
  long long auth_key_id;        // Client's auth key ID
  
  // Hash table chaining
  struct ext_connection *h_next;
  
  // LRU list for eviction
  struct ext_connection *lru_prev;
  struct ext_connection *lru_next;
  
  // Metadata
  int flags;                    // Connection flags
  int last_response_time;       // Timestamp
};
```

### 3. Job Thread Structure

```c
// From jobs.h
struct job_thread {
  // Execution
  void (*run)(struct job_thread *); // Main function
  void (*alarm)(struct job_thread *); // Timer callback
  
  // Hierarchy
  struct job_thread *parent;    // Parent job
  
  // Scheduling
  int status;                   // Job status
  int class;                    // Current execution class
  int pending_signals;          // Pending signal mask
  int allowed_signals[JC_CLASSES]; // Signal policy matrix
  
  // Context
  int fd;                       // Associated FD
  struct connection *connection; // Associated connection
  void *custom_data;            // Job-specific data
  
  // Queue linkage
  struct mp_queue_entry queue_entry;
  
  // Timing
  struct event_timer timer;     // Alarm timer
  
  // Reference counting
  int refcnt;
};
```

### 4. Message Buffers

```c
// From net-msg.h
#define MSG_CHUNK_SIZE 16384

struct msg_buffer {
  void *chunk;                  // Data chunk (16KB default)
  int pos;                      // Read/write position
  int len;                      // Data length in buffer
  struct msg_buffer *next;      // Next in chain
};

struct msg_buffers {
  struct msg_buffer *head;      // First buffer
  struct msg_buffer *tail;      // Last buffer
  int total_bytes;              // Total data across all buffers
  int unprocessed_bytes;        // Bytes not yet processed
  
  // Memory management
  int chunks_allocated;
  int max_chunks;
};
```

### 5. RPC Proxy Request/Answer

```c
// From mtproto-common.h
#define RPC_PROXY_REQ 0x36cef1ee
#define RPC_PROXY_ANS 0x3fa2773e

struct rpc_proxy_req {
  int type;                     // RPC_PROXY_REQ magic
  int flags;                    // Feature flags
  long long out_conn_id;        // Connection ID
  
  // Client addressing (20 bytes)
  unsigned char client_ipv6[16]; // IPv4/IPv6 address
  unsigned short client_port;   // Client port
  unsigned short padding;
  
  // Variable-length sections
  // - proxy_tag (16 bytes) if flags & 0x01
  // - http headers if flags & 0x08
  // - original packet payload
};

struct rpc_proxy_ans {
  int type;                     // RPC_PROXY_ANS magic
  int flags;                    // Response flags
  long long out_conn_id;        // Connection ID (matches req)
  
  // Payload follows
};
```

---

## Build System

### Build Targets

```bash
# Default build (debug Rust, optimized C)
make

# Release build (optimized Rust + C)
make release

# Clean all build artifacts
make clean

# Run tests
make test

# Rust quality checks
make rust-check        # cargo check
make rust-fmt          # cargo fmt
make rust-fmt-check    # cargo fmt --check
make rust-clippy       # cargo clippy
make rust-test         # cargo test
make rust-ci           # all Rust checks
```

### Compiler Flags

**C Compilation** (`CFLAGS`):
```makefile
CFLAGS = -O3 \
         -std=gnu2x \              # C23 standard with GNU extensions
         -Wall \                   # All warnings
         -Wno-array-bounds \       # Disable array bounds warnings
         -mpclmul \                # Enable PCLMULQDQ (for CRC)
         -march=core2 \            # Minimum CPU: Intel Core 2
         -mfpmath=sse \            # SSE floating-point
         -mssse3 \                 # SSSE3 instructions
         -fno-strict-aliasing \    # Disable strict aliasing
         -fno-strict-overflow \    # Disable overflow optimization
         -fwrapv \                 # Signed overflow wraps
         -DAES=1 \                 # Enable AES support
         -D_GNU_SOURCE=1 \         # GNU extensions
         -D_FILE_OFFSET_BITS=64    # 64-bit file offsets
```

**Linking** (`LDFLAGS`):
```makefile
LDFLAGS = -ggdb \        # GDB debug symbols
          -rdynamic \    # Export symbols for backtrace
          -lm \          # Math library
          -lrt \         # POSIX real-time
          -lz \          # zlib compression
          -lpthread \    # POSIX threads
          -ldl           # Dynamic linking
```

### Build Process

```
1. Create directory structure
   objs/, dep/, objs/bin/, objs/lib/

2. Compile Rust FFI library
   cargo build -p mtproxy-ffi
   → target/debug/libmtproxy_ffi.a

3. Compile C source files
   gcc -c mtproto-proxy.c → objs/mtproto/mtproto-proxy.rust.o
   gcc -c net-*.c → objs/net/*.o
   gcc -c crypto/*.c → objs/crypto/*.o
   ... (all C files)

4. Create static library
   ar rcs objs/lib/libkdb.a <all .o files except main>

5. Link final binary
   gcc -o objs/bin/mtproto-proxy \
       objs/mtproto/mtproto-proxy.rust.o \
       objs/lib/libkdb.a \
       target/debug/libmtproxy_ffi.a \
       objs/lib/libkdb.a \   # Linked twice for circular deps
       -lm -lrt -lz -lpthread -ldl
```

### Dependency Tracking

The Makefile uses automatic dependency generation:

```makefile
# Generate .d dependency files during compilation
${OBJ}/%.o: %.c
	${CC} ${CFLAGS} ${CINCLUDE} \
	      -c -MP -MD \
	      -MF ${DEP}/$*.d \    # Write dependencies
	      -MQ ${OBJ}/$*.o \    # Quote target
	      -o $@ $<

# Include all dependency files
-include ${DEPENDENCE_ALL}
```

Example dependency file (`dep/crypto/aesni256.d`):
```makefile
objs/crypto/aesni256.o: crypto/aesni256.c \
  crypto/aesni256.h \
  common/kprintf.h
```

---

## Performance Considerations

### Memory Management

**Buffer Limits**:
```c
#define MAX_CONNECTION_BUFFER_SPACE (1 << 25)  // 32MB per connection
#define MSG_CHUNK_SIZE 16384                    // 16KB chunks

// Global buffer tracking
long long total_buffer_bytes = 0;
int total_buffer_chunks = 0;

// LRU eviction when 75% full
if (total_buffer_bytes > MAX_CONNECTION_BUFFER_SPACE * 0.75) {
  evict_lru_connections();
}
```

**Connection Limits**:
```c
#define MAX_CONNECTIONS 100000
#define MAX_SPECIAL_CONNECTIONS 60000  // Configurable via -C

// Connection table size
#define EXT_CONN_TABLE_SIZE (1 << 22)  // 4 million
```

### Network Optimizations

**TCP Tuning**:
```c
// Set TCP_NODELAY (disable Nagle)
int flag = 1;
setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

// Set TCP window clamp
int clamp = window_clamp;  // Default 131072
setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &clamp, sizeof(clamp));

// Set SO_KEEPALIVE
flag = 1;
setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
```

**Event Loop Timing**:
```c
// epoll timeout: 37ms
// Balances latency vs CPU usage
int timeout_ms = 37;
int n = epoll_wait(epoll_fd, events, MAX_EVENTS, timeout_ms);
```

### Cryptography Performance

**AESNI Hardware Acceleration**:
```c
// From crypto/aesni256.c
// Uses x86 AESNI instructions for ~10x speedup

void aes256_ctr_encrypt(struct aes256_ctr_key *key,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len) {
  // Use __m128i vector operations
  __m128i counter = _mm_loadu_si128((__m128i *)key->counter);
  
  while (len >= 16) {
    __m128i block = _mm_aesenc_si128(counter, key->round_keys[0]);
    // ... 13 more rounds with _mm_aesenc_si128()
    block = _mm_aesenclast_si128(block, key->round_keys[14]);
    
    // XOR with plaintext
    __m128i plaintext = _mm_loadu_si128((__m128i *)in);
    __m128i ciphertext = _mm_xor_si128(block, plaintext);
    _mm_storeu_si128((__m128i *)out, ciphertext);
    
    // Increment counter
    counter = _mm_add_epi64(counter, _mm_set_epi64x(0, 1));
    
    in += 16;
    out += 16;
    len -= 16;
  }
}
```

---

## Security Considerations

### Secret Management

**Proxy Secrets**:
- Stored in memory only (not written to disk)
- Up to 16 secrets supported simultaneously
- 32 hex characters each (16 bytes)
- Optional `dd` prefix enables random padding

**Secret Rotation**:
```c
// Multiple secrets for gradual rollover
char *secrets[16];
int num_secrets = 0;

void add_proxy_secret(const char *secret_hex) {
  if (num_secrets >= 16) {
    kprintf("Too many secrets (max 16)\n");
    return;
  }
  
  // Validate format
  if (strlen(secret_hex) != 32 && strlen(secret_hex) != 34) {
    kprintf("Invalid secret length\n");
    return;
  }
  
  secrets[num_secrets++] = strdup(secret_hex);
}
```

### Random Padding

**DPI Evasion**:
```bash
# Enable random padding by prefixing secret with "dd"
-S ddcafe0123456789abcdef0123456789ab
```

Implementation:
```c
if (secret[0] == 'd' && secret[1] == 'd') {
  // Random padding mode
  add_random_padding = 1;
  actual_secret = secret + 2;  // Skip "dd" prefix
}

// Add 0-15 random bytes to packets
if (add_random_padding) {
  int padding_len = random() & 0x0F;  // 0-15 bytes
  for (int i = 0; i < padding_len; i++) {
    packet[packet_len++] = random() & 0xFF;
  }
}
```

### Privilege Dropping

```c
// Drop root privileges after binding to port 443
if (username) {
  struct passwd *pw = getpwnam(username);
  if (!pw) {
    kprintf("User %s not found\n", username);
    exit(1);
  }
  
  // Drop privileges
  if (setuid(pw->pw_uid) < 0) {
    kprintf("setuid() failed: %m\n");
    exit(1);
  }
  
  kprintf("Running as user %s (uid %d)\n", username, pw->pw_uid);
}
```

---

## Debugging & Monitoring

### Stats Endpoint

Access runtime statistics via HTTP:
```bash
curl http://localhost:8888/stats
```

**Output Example**:
```
mtproxy-0.02 compiled at Jan 15 2024 12:34:56
uptime: 3600s
connections: 1234
ext_connections: 567
buffer_usage: 12MB / 32MB
cpu_usage: 45%
```

### Logging

**Log Levels**:
```c
// From common/kprintf.h
#define LOG_ERROR   1
#define LOG_WARNING 2
#define LOG_INFO    3
#define LOG_DEBUG   4

void kprintf(const char *format, ...) {
  // Thread-safe logging
  static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
  
  pthread_mutex_lock(&log_mutex);
  vfprintf(stderr, format, args);
  pthread_mutex_unlock(&log_mutex);
}
```

### Signal Handling for Debugging

```bash
# Reopen log files (for logrotate)
kill -USR1 <pid>

# Graceful shutdown
kill -TERM <pid>

# Get core dump
kill -ABRT <pid>
```

---

## Conclusion

MTProxy is a sophisticated, high-performance proxy implementation that combines:

1. **Efficient Networking**: Event-driven I/O, connection pooling, buffer management
2. **Strong Cryptography**: Hardware-accelerated AES, multiple cipher modes
3. **Scalability**: Multi-worker processes, job-based threading
4. **Safety Migration**: Gradual C→Rust transition via FFI
5. **Production-Ready**: Privilege dropping, stats, monitoring, graceful shutdown

The codebase demonstrates advanced systems programming techniques including lock-free queues, epoll-based event loops, zero-copy buffer management, and careful memory management. The ongoing Rust migration improves safety without sacrificing performance.

**Key Takeaways for Developers**:

- **Modular Design**: Clear separation between networking, crypto, protocol, and engine layers
- **Performance Focus**: Hardware acceleration, efficient data structures, minimal allocations
- **Extensibility**: Plugin-like connection types, configurable job policies
- **Production Hardening**: Comprehensive error handling, resource limits, monitoring

For further exploration:
- Study `engine/engine.c` for event loop patterns
- Review `jobs/jobs.c` for lock-free queue implementation
- Examine `rust/mtproxy-ffi/` for safe FFI patterns
- Read `net/net-msg.c` for zero-copy buffer techniques
