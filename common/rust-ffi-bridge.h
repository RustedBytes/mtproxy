#pragma once

// Performs startup handshake against Rust FFI layer.
// Returns 0 on success, negative on incompatibility.
int rust_ffi_startup_check(void);

// Validates extracted mp-queue/jobs migration boundary contract from Rust.
// Returns 0 on success, negative on incompatibility.
int rust_ffi_check_concurrency_boundary(void);

// Validates extracted net-core migration boundary contract from Rust.
// Returns 0 on success, negative on incompatibility.
int rust_ffi_check_network_boundary(void);

// Validates extracted rpc/tcp migration boundary contract from Rust.
// Returns 0 on success, negative on incompatibility.
int rust_ffi_check_rpc_boundary(void);

// Installs Step 9 concurrency adapter routes for mp-queue/jobs in mixed mode.
// Returns 0 on success, negative on incompatibility.
int rust_ffi_enable_concurrency_bridges(void);

// Enables Rust-backed CRC32 partial implementation in mixed mode.
// Returns 0 on success, negative if differential self-check fails.
int rust_ffi_enable_crc32_bridge(void);

// Enables Rust-backed CRC32C partial implementation in mixed mode.
// Returns 0 on success, negative if differential self-check fails.
int rust_ffi_enable_crc32c_bridge(void);
