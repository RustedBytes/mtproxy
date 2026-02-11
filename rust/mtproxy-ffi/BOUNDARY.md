# C/Rust FFI Boundary (Step 5)

## Boundary surface

C calls Rust through two versioned functions declared in:
- `rust/mtproxy-ffi/include/mtproxy_ffi.h`

Current exported API:
- `mtproxy_ffi_api_version()`
- `mtproxy_ffi_startup_handshake(uint32_t expected_api_version)`
- `mtproxy_ffi_crc32_partial(const uint8_t *data, size_t len, uint32_t crc)`
- `mtproxy_ffi_crc32c_partial(const uint8_t *data, size_t len, uint32_t crc)`
- PID helpers (`mtproxy_ffi_pid_*`, `mtproxy_ffi_matches_pid`, `mtproxy_ffi_process_id_is_newer`)
- `mtproxy_ffi_cpuid_fill(...)`
- MD5 helpers (`mtproxy_ffi_md5`, `mtproxy_ffi_md5_hex`, `mtproxy_ffi_md5_hmac`)
- SHA1 helpers (`mtproxy_ffi_sha1`, `mtproxy_ffi_sha1_two_chunks`)
- SHA256 helpers (`mtproxy_ffi_sha256`, `mtproxy_ffi_sha256_two_chunks`, `mtproxy_ffi_sha256_hmac`)
- precise-time helpers (`mtproxy_ffi_get_utime_monotonic`, `mtproxy_ffi_get_double_time`, `mtproxy_ffi_get_utime`, `mtproxy_ffi_get_precise_time`) and state mirrors (`mtproxy_ffi_precise_*_value`)
- parse-config helpers (`mtproxy_ffi_cfg_*` scanner/token/int primitives)
- TL header parser helpers (`mtproxy_ffi_tl_parse_query_header`, `mtproxy_ffi_tl_parse_answer_header`)
- observability helpers:
- proc-stat (`mtproxy_ffi_parse_proc_stat_line`, `mtproxy_ffi_read_proc_stat_file`)
- common-stats parsers (`mtproxy_ffi_parse_statm`, `mtproxy_ffi_parse_meminfo_summary`)
- kprintf formatter helper (`mtproxy_ffi_format_log_prefix`)
- Step 9 boundary contract probe:
- `mtproxy_ffi_get_concurrency_boundary(...)` (reports mp-queue/jobs operation contract vs implemented subsets)
- Step 10 boundary contract probe:
- `mtproxy_ffi_get_network_boundary(...)` (reports net-events/net-timers/net-msg-buffers operation contract vs implemented subsets)
- Step 10 net-core helpers:
- `mtproxy_ffi_net_epoll_conv_flags(...)`
- `mtproxy_ffi_net_epoll_unconv_flags(...)`
- `mtproxy_ffi_net_timers_wait_msec(...)`
- `mtproxy_ffi_msg_buffers_pick_size_index(...)`
- Step 11 boundary contract probe:
- `mtproxy_ffi_get_rpc_boundary(...)` (reports tcp-rpc/rpc-target operation contract vs implemented subsets)
- Step 11 rpc/tcp helpers:
- `mtproxy_ffi_tcp_rpc_encode_compact_header(...)`
- `mtproxy_ffi_tcp_rpc_client_packet_len_state(...)`
- `mtproxy_ffi_tcp_rpc_server_packet_header_malformed(...)`
- `mtproxy_ffi_tcp_rpc_server_packet_len_state(...)`
- `mtproxy_ffi_rpc_target_normalize_pid(...)`

## Call flow

- C startup path (`mtproto/mtproto-proxy.c`, mixed build only) calls `rust_ffi_startup_check()`.
- C startup then calls `rust_ffi_check_concurrency_boundary()` to validate extracted Step 9 mp-queue/jobs contract.
- C startup then calls `rust_ffi_check_network_boundary()` to validate extracted Step 10 net-core contract.
- C startup then calls `rust_ffi_check_rpc_boundary()` to validate extracted Step 11 rpc/tcp contract.
- C startup then calls `rust_ffi_enable_concurrency_bridges()` to install Step 9 adapter routing:
- mp-queue: `push`/`pop`/`is_empty`
- jobs lifecycle: `create_async_job`/`job_signal`/`job_incref`/`job_decref`
- Current adapter behavior: C fallback implementations are used, with install points ready for Rust-backed replacements.
- C startup then calls `rust_ffi_enable_crc32_bridge()` which runs differential checks and swaps CRC32 implementation.
- C startup then calls `rust_ffi_enable_crc32c_bridge()` which runs differential checks and swaps CRC32C implementation.
- `rust_ffi_startup_check()` and `rust_ffi_enable_crc32_bridge()` live in `common/rust-ffi-bridge.c`.
- PID/CPUID/hash/precise-time C modules delegate to Rust via weak-symbol calls when the mixed binary is linked.
- `common/parse-config.c` delegates scanner/int primitives to Rust when symbols are linked.
- `common/tl-parse.c` opportunistically delegates TL query/answer header parsing to Rust (with C fallback).
- `common/proc-stat.c` delegates `/proc/.../stat` parsing to Rust when symbols are linked.
- `common/common-stats.c` delegates `statm` and `meminfo` parsing helpers to Rust when symbols are linked.
- `common/kprintf.c` can delegate log-prefix formatting helper to Rust when symbols are linked.
- `net/net-events.c` can delegate epoll flag conversion helpers to Rust when symbols are linked.
- `net/net-timers.c` can delegate timer wait-ms conversion helper to Rust when symbols are linked.
- `net/net-msg-buffers.c` can delegate size-class index selection helper to Rust when symbols are linked.
- `net/net-tcp-rpc-common.c` can delegate compact/medium packet-length prefix encoding helper to Rust when symbols are linked.
- `net/net-tcp-rpc-client.c` can delegate non-compact packet-length classification helper to Rust when symbols are linked.
- `net/net-tcp-rpc-server.c` can delegate packet-header malformed check and packet-length classification helpers to Rust when symbols are linked.
- `net/net-rpc-targets.c` can delegate zero-ip PID normalization helper to Rust when symbols are linked.
- If handshake fails, startup aborts before config load.

## Ownership and memory rules

- For handshake/version APIs, no pointers cross the boundary.
- For CRC32 API, C passes a borrowed pointer and length; Rust never stores the pointer.
- For CRC32C API, C passes a borrowed pointer and length; Rust never stores the pointer.
- For PID/CPUID APIs, C passes pointers to POD structs with C layout compatibility.
- For hash APIs, C passes borrowed pointers for input/key/output buffers.
- For precise-time APIs, C calls Rust for clock reads and mirrors Rust-maintained timing state back into C globals.
- For parse-config helpers, C passes borrowed slices and Rust returns deterministic scan/token metadata.
- For TL parser helpers, C passes unread packet bytes and receives parsed header metadata or explicit error payload.
- For observability helpers, C passes borrowed textual `/proc` slices (or pid/tid) and Rust returns POD parsed structures.
- For concurrency boundary probe, C passes writable POD `mtproxy_ffi_concurrency_boundary_t` and Rust fills version/op masks.
- For network boundary probe, C passes writable POD `mtproxy_ffi_network_boundary_t` and Rust fills version/op masks.
- For rpc boundary probe, C passes writable POD `mtproxy_ffi_rpc_boundary_t` and Rust fills version/op masks.
- For net-core helpers, C passes plain integers and borrowed POD arrays (`buffer_sizes`) with no ownership transfer.
- For rpc/tcp helpers, C passes plain integers and POD struct pointers (`process_id`) with no ownership transfer.
- Boundary `*_implemented_ops` currently advertises routed Step 9, Step 10, and Step 11 slices listed above.
- No heap ownership is transferred between C and Rust.
- Return values are plain integer POD types.

## Threading rules

- Startup handshake is called on the main thread during pre-init.
- Hash and CRC helpers are pure for given inputs.
- precise-time helpers use thread-local and global cached state (`precise_now`, `precise_time` mirrors), matching existing C-side semantics.
- parse-config and TL parser helpers are deterministic for given byte input and do not retain caller memory.

## Error handling rules

- Rust returns explicit status codes (`0` success, `<0` failure).
- C bridge converts status codes into fatal startup diagnostics.
- No panics or exceptions are used for cross-language error propagation.

## Compatibility/versioning rules

- Version mismatch is treated as hard startup failure in mixed mode.
- API changes must bump the FFI API version and update bridge checks.
