# C-to-Rust Migration Status

This document tracks the progress of migrating the MTProxy C codebase to Rust (Step 15 of PLAN.md).

## Overview

**Goal**: Move all C runtime code to Rust, making `rust/mtproxy-bin` the authoritative runtime binary.

**Current Status**: 
- **Rust binary**: `mtproxy-rust` with full CLI interface ✅
- **C units migrated**: 15 complete + 25 partial of 44 total modules (91% in progress or complete)
- **Tests passing**: 246 (all Rust tests passing)
- **Build system**: Hybrid C/Rust with FFI bridge ✅

## Migration Strategy

### Phase 1: Infrastructure (COMPLETED)
- [x] Rust workspace setup (mtproxy-bin, mtproxy-core, mtproxy-ffi)
- [x] FFI boundary for C/Rust interop
- [x] Test harness and CI integration
- [x] Step 15 ownership map defining target Rust modules

### Phase 2: Entry Point (COMPLETED)
- [x] Rust main binary with full CLI parsing (mtproxy-rust)
- [x] Argument validation and processing
- [x] Runtime initialization sequence
- [x] Worker process management
- [x] Signal handling

### Phase 3: Core Runtime (IN PROGRESS)
- [x] Create Rust module structure for engine framework
- [x] Create Rust module structure for job system
- [x] Port engine initialization logic
- [x] Port job system core functionality
- [x] Port signal handling infrastructure
- [x] Port RPC integration
- [ ] Complete partial implementations (19 modules)
- [ ] Remove C object linkage from release binary
- [ ] Verify functional parity with integration tests

### Phase 4: Hardening (PLANNED)
- [ ] Security audit of Rust implementation
- [ ] Performance benchmarking vs C baseline
- [ ] Production deployment preparation

## Detailed Migration Status

### Entry Point & Main Runtime

| C File | Lines | Rust Module | Status | Priority | Notes |
|--------|-------|-------------|--------|----------|-------|
| `mtproto/mtproto-proxy.c` | 2531 | `mtproxy-bin::runtime::mtproto::proxy` | 🟡 Partial | **HIGH** | Main entry point; complex dependencies |
| `mtproto/mtproto-config.c` | 1200+ | `mtproxy-core::runtime::mtproto::config` | 🟡 Partial | HIGH | Config parsing mostly complete |

### Common Utilities

| C File | Lines | Rust Module | Status | Priority | Notes |
|--------|-------|-------------|--------|----------|-------|
| `common/server-functions.c` | ~750 | `mtproxy-bin::runtime::bootstrap::server_functions` | 🟡 Partial | HIGH | 6/15 functions ported |
| `common/kprintf.c` | 303 | `mtproxy-ffi::kprintf` | 🟢 Complete | HIGH | Logging infrastructure (FFI layer) |
| `common/pid.c` | ~200 | `mtproxy-core::runtime::common::pid` | 🟢 Complete | MED | FFI bridge active |
| `common/precise-time.c` | ~150 | `mtproxy-core::runtime::common::precise_time` | 🟢 Complete | MED | FFI bridge active |
| `common/cpuid.c` | ~100 | `mtproxy-core::runtime::common::cpuid` | 🟢 Complete | MED | FFI bridge active |
| `common/mp-queue.c` | 726 | `mtproxy-core::runtime::jobs::mp_queue` | 🔴 Not Started | MED | Multi-producer queue; complex |
| `common/parse-config.c` | ~500 | `mtproxy-core::runtime::config::parse_config` | 🔴 Not Started | MED | Generic config parser |
| `common/tl-parse.c` | ~400 | `mtproxy-core::runtime::config::tl_parse` | 🟢 Complete | MED | TL protocol parsing |
| `common/resolver.c` | ~600 | `mtproxy-core::runtime::net::resolver` | 🟡 Partial | MED | DNS resolution |
| `common/common-stats.c` | 96 | `mtproxy-ffi::stats` | 🟢 Complete | LOW | Statistics aggregation (FFI layer) |
| `common/proc-stat.c` | 85 | `mtproxy-ffi::time_cfg_observability` | 🟢 Complete | LOW | Process stats from /proc (FFI layer) |
| `common/rust-ffi-bridge.c` | ~300 | `mtproxy-bin::runtime::bootstrap::legacy_bridge` | 🔴 Not Started | LOW | FFI helpers; will be removed |

### Cryptography

| C File | Lines | Rust Module | Status | Priority | Notes |
|--------|-------|-------------|--------|----------|-------|
| `crypto/aesni256.c` | 58 | `mtproxy-ffi::crypto` | 🟢 Complete | HIGH | AES encryption (FFI layer) |
| `crypto/crc32.c` | ~100 | `mtproxy-core::runtime::common::crc32` | 🟢 Complete | MED | FFI bridge active |
| `crypto/crc32c.c` | ~100 | `mtproxy-core::runtime::common::crc32c` | 🟢 Complete | MED | FFI bridge active |
| `crypto/md5.c` | ~150 | `mtproxy-core::runtime::common::md5` | 🟢 Complete | MED | FFI bridge active |
| `crypto/sha1.c` | ~120 | `mtproxy-core::runtime::common::sha1` | 🟢 Complete | MED | FFI bridge active |
| `crypto/sha256.c` | ~150 | `mtproxy-core::runtime::common::sha256` | 🟢 Complete | MED | FFI bridge active |

### Network Stack

| C File | Lines | Rust Module | Status | Priority | Notes |
|--------|-------|-------------|--------|----------|-------|
| `net/net-events.c` | ~800 | `mtproxy-core::runtime::net::events` | 🟡 Partial | HIGH | epoll event loop |
| `net/net-connections.c` | ~600 | `mtproxy-core::runtime::net::connections` | 🟡 Partial | HIGH | Connection management |
| `net/net-tcp-connections.c` | ~900 | `mtproxy-core::runtime::net::tcp_connections` | 🟡 Partial | HIGH | TCP connection handling |
| `net/net-tcp-rpc-client.c` | ~500 | `mtproxy-core::runtime::net::tcp_rpc_client` | 🟡 Partial | HIGH | RPC client |
| `net/net-tcp-rpc-server.c` | ~600 | `mtproxy-core::runtime::net::tcp_rpc_server` | 🟡 Partial | HIGH | RPC server |
| `net/net-tcp-rpc-ext-server.c` | ~700 | `mtproxy-core::runtime::net::tcp_rpc_ext_server` | 🟡 Partial | HIGH | External RPC server |
| `net/net-tcp-rpc-common.c` | ~400 | `mtproxy-core::runtime::net::tcp_rpc_common` | 🟡 Partial | HIGH | RPC common code |
| `net/net-http-server.c` | ~1200 | `mtproxy-core::runtime::net::http_server` | 🟡 Partial | MED | HTTP server |
| `net/net-msg.c` | ~300 | `mtproxy-core::runtime::net::msg` | 🟡 Partial | MED | Message handling |
| `net/net-msg-buffers.c` | ~200 | `mtproxy-core::runtime::net::msg_buffers` | 🟡 Partial | MED | Buffer management |
| `net/net-rpc-targets.c` | ~400 | `mtproxy-core::runtime::net::rpc_targets` | 🟡 Partial | MED | RPC target management |
| `net/net-crypto-aes.c` | 132 | `mtproxy-ffi::crypto` | 🟢 Complete | HIGH | Network AES crypto (FFI layer) |
| `net/net-crypto-dh.c` | 102 | `mtproxy-ffi::crypto` | 🟢 Complete | HIGH | Diffie-Hellman (FFI layer) |
| `net/net-timers.c` | ~300 | `mtproxy-core::runtime::net::timers` | 🟡 Partial | MED | Timer management |
| `net/net-config.c` | ~200 | `mtproxy-core::runtime::net::config` | 🟡 Partial | LOW | Network configuration |
| `net/net-stats.c` | ~150 | `mtproxy-core::runtime::net::stats` | 🟡 Partial | LOW | Network statistics |
| `net/net-thread.c` | ~800 | `mtproxy-core::runtime::net::thread` | 🟡 Partial | MED | Network threading |

### Engine Framework

| C File | Lines | Rust Module | Status | Priority | Notes |
|--------|-------|-------------|--------|----------|-------|
| `engine/engine.c` | ~2000 | `mtproxy-core::runtime::engine` | 🟡 Partial | **CRITICAL** | Lifecycle + initialization flow ported; full event loop parity pending |
| `engine/engine-net.c` | ~800 | `mtproxy-core::runtime::engine::net` | 🟡 Partial | **CRITICAL** | Engine network bootstrap path implemented; socket parity pending |
| `engine/engine-rpc.c` | ~600 | `mtproxy-core::runtime::engine::rpc` | 🟡 Partial | HIGH | Custom op registration and RPC bootstrap ported |
| `engine/engine-rpc-common.c` | ~400 | `mtproxy-core::runtime::engine::rpc_common` | 🟡 Partial | HIGH | RPC common init path ported |
| `engine/engine-signals.c` | ~300 | `mtproxy-core::runtime::engine::signals` | 🟡 Partial | MED | Pending/allowed/installed signal tracking and processing ported |

### Job System

| C File | Lines | Rust Module | Status | Priority | Notes |
|--------|-------|-------------|--------|----------|-------|
| `jobs/jobs.c` | ~900 | `mtproxy-core::runtime::jobs` | 🟡 Partial | HIGH | Core class/timer bootstrap and validation logic ported; scheduler parity pending |

## Status Legend

- 🟢 **Complete**: Fully migrated to Rust, C code can be removed
- 🟡 **Partial**: Some functions ported, FFI bridge in use, or stub exists
- 🔴 **Not Started**: No Rust implementation yet

## Priority Legend

- **CRITICAL**: Core runtime, blocks all other work
- **HIGH**: Important for functionality, should be done soon
- **MED**: Useful but can wait
- **LOW**: Nice to have, low priority

## Next Steps

### Immediate (Week 1-2)
1. ✅ Complete Rust CLI argument parsing
2. ✅ Port logging infrastructure (`common/kprintf.c`) - Complete in FFI layer
3. ✅ Port critical engine framework bootstrap (`engine.c`, `engine-net.c`)
4. ✅ Port job system bootstrap (`jobs/jobs.c`)

### Short-term (Week 3-4)
5. Port remaining network stack modules
6. Port crypto modules (AES, DH)
7. Complete `mtproto-proxy.c` main runtime

### Medium-term (Month 2)
8. Integration testing and validation
9. Performance benchmarking
10. Remove C object linkage from release binary

### Long-term (Month 3+)
11. Security audit
12. Production deployment preparation
13. Remove legacy C files

## How to Contribute

1. Pick a module from the table above (preferably 🔴 Not Started with HIGH priority)
2. Create the Rust implementation in the designated module path
3. Add comprehensive tests (unit + integration)
4. Update this status document
5. Submit PR with migration notes

## Build Commands

```bash
# Build Rust binary
cargo build --release --bin mtproxy-rust

# Run Rust tests
cargo test --workspace

# Build C binary (legacy)
make

# Run all tests
make test
```

## References

- Full migration plan: `PLAN.md` (Step 15)
- Server functions migration example: `SERVER_FUNCTIONS_MIGRATION.md`
- Ownership map: `rust/mtproxy-core/src/step15.rs`
- Architecture docs: `ARCHITECTURE.md`
