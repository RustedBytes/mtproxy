//! FFI-facing Rust crate for incremental C/Rust integration.
#![allow(
    clippy::bool_to_int_with_if,
    clippy::borrow_as_ptr,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::enum_variant_names,
    clippy::items_after_statements,
    clippy::manual_c_str_literals,
    clippy::manual_is_multiple_of,
    clippy::manual_let_else,
    clippy::manual_ok_err,
    clippy::manual_unwrap_or,
    clippy::missing_safety_doc,
    clippy::never_loop,
    clippy::pedantic,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::uninlined_format_args,
    clippy::wildcard_imports
)]

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};
use core::ffi::{c_char, c_double, c_int, c_long, c_void};
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use md5::Md5;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};
use rustls::crypto::ring::default_provider as rustls_default_provider;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::ffi::CStr;
use std::fs;
use std::io::Read;
use std::sync::Mutex;
use std::thread_local;
use std::vec::Vec;

/// Public FFI API version for compatibility checks.
pub const FFI_API_VERSION: u32 = mtproxy_core::CORE_API_VERSION;
const PID_LOCALHOST_IP: u32 = 0x7f00_0001;
const CPUID_MAGIC: i32 = 0x2801_47b8;
const CLOCK_REALTIME_ID: c_int = 0;
const CLOCK_MONOTONIC_ID: c_int = 1;
const DOUBLE_TIME_RDTSC_WINDOW: i64 = 1_000_000;
const DIGEST_MD5_LEN: usize = 16;
const DIGEST_SHA1_LEN: usize = 20;
const DIGEST_SHA256_LEN: usize = 32;
const MAX_PWD_CONFIG_LEN: usize = 16_384;
const MIN_PWD_LEN: usize = 32;
const MAX_PWD_LEN: usize = 256;
const DEFAULT_PWD_FILE: &str = "secret";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
#[cfg(test)]
const RPC_INVOKE_REQ: i32 = 0x2374_df3d;
#[cfg(test)]
const RPC_REQ_RESULT: i32 = 0x63ae_da4e;
const CONCURRENCY_BOUNDARY_VERSION: u32 = 1;
const NETWORK_BOUNDARY_VERSION: u32 = 1;
const RPC_BOUNDARY_VERSION: u32 = 1;
const CRYPTO_BOUNDARY_VERSION: u32 = 1;
const APPLICATION_BOUNDARY_VERSION: u32 = 1;
const MPQ_CONTRACT_OPS: u32 =
    (1u32 << 0) | (1u32 << 1) | (1u32 << 2) | (1u32 << 3) | (1u32 << 4) | (1u32 << 5);
const JOBS_CONTRACT_OPS: u32 =
    (1u32 << 0) | (1u32 << 1) | (1u32 << 2) | (1u32 << 3) | (1u32 << 4) | (1u32 << 5) | (1u32 << 6);
const MPQ_IMPLEMENTED_OPS: u32 = (1u32 << 0) | (1u32 << 1) | (1u32 << 2);
const JOBS_IMPLEMENTED_OPS: u32 =
    (1u32 << 0) | (1u32 << 1) | (1u32 << 2) | (1u32 << 3) | (1u32 << 4) | (1u32 << 5) | (1u32 << 6);
const NET_EVENTS_CONTRACT_OPS: u32 = (1u32 << 0) | (1u32 << 1);
const NET_TIMERS_CONTRACT_OPS: u32 = 1u32 << 0;
const NET_MSG_BUFFERS_CONTRACT_OPS: u32 = 1u32 << 0;
const NET_EVENTS_IMPLEMENTED_OPS: u32 = NET_EVENTS_CONTRACT_OPS;
const NET_TIMERS_IMPLEMENTED_OPS: u32 = NET_TIMERS_CONTRACT_OPS;
const NET_MSG_BUFFERS_IMPLEMENTED_OPS: u32 = NET_MSG_BUFFERS_CONTRACT_OPS;
const TCP_RPC_COMMON_CONTRACT_OPS: u32 = 1u32 << 0;
const TCP_RPC_CLIENT_CONTRACT_OPS: u32 = 1u32 << 0;
const TCP_RPC_SERVER_CONTRACT_OPS: u32 = (1u32 << 0) | (1u32 << 1);
const RPC_TARGETS_CONTRACT_OPS: u32 = 1u32 << 0;
const TCP_RPC_COMMON_IMPLEMENTED_OPS: u32 = TCP_RPC_COMMON_CONTRACT_OPS;
const TCP_RPC_CLIENT_IMPLEMENTED_OPS: u32 = TCP_RPC_CLIENT_CONTRACT_OPS;
const TCP_RPC_SERVER_IMPLEMENTED_OPS: u32 = TCP_RPC_SERVER_CONTRACT_OPS;
const RPC_TARGETS_IMPLEMENTED_OPS: u32 = RPC_TARGETS_CONTRACT_OPS;
const NET_CRYPTO_AES_CONTRACT_OPS: u32 = 1u32 << 0;
const NET_CRYPTO_DH_CONTRACT_OPS: u32 =
    (1u32 << 0) | (1u32 << 1) | (1u32 << 2) | (1u32 << 3) | (1u32 << 4);
const AESNI_CONTRACT_OPS: u32 = (1u32 << 0) | (1u32 << 1) | (1u32 << 2);
const NET_CRYPTO_AES_IMPLEMENTED_OPS: u32 = NET_CRYPTO_AES_CONTRACT_OPS;
const NET_CRYPTO_DH_IMPLEMENTED_OPS: u32 = NET_CRYPTO_DH_CONTRACT_OPS;
const AESNI_IMPLEMENTED_OPS: u32 = AESNI_CONTRACT_OPS;
const ENGINE_RPC_CONTRACT_OPS: u32 = (1u32 << 0) | (1u32 << 1);
const ENGINE_RPC_IMPLEMENTED_OPS: u32 = ENGINE_RPC_CONTRACT_OPS;
const MTPROTO_PROXY_CONTRACT_OPS: u32 = (1u32 << 0) | (1u32 << 1);
const MTPROTO_PROXY_IMPLEMENTED_OPS: u32 = MTPROTO_PROXY_CONTRACT_OPS;
const MTPROTO_CFG_GETLEX_EXT_OK: i32 = 0;
const MTPROTO_CFG_GETLEX_EXT_ERR_INVALID_ARGS: i32 = -1;
const MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK: i32 = 0;
const MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_ARGS: i32 = -1;
const MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TIMEOUT: i32 = -2;
const MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MAX_CONNECTIONS: i32 = -3;
const MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MIN_CONNECTIONS: i32 = -4;
const MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TARGET_ID: i32 = -5;
const MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_TARGET_ID_SPACE: i32 = -6;
const MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_PROXY_EXPECTED: i32 = -7;
const MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INTERNAL: i32 = -8;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK: i32 = 0;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS: i32 = -1;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TIMEOUT: i32 = -2;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MAX_CONNECTIONS: i32 = -3;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MIN_CONNECTIONS: i32 = -4;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TARGET_ID: i32 = -5;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TARGET_ID_SPACE: i32 = -6;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXY_EXPECTED: i32 = -7;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TOO_MANY_AUTH_CLUSTERS: i32 = -8;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXIES_INTERMIXED: i32 = -9;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_EXPECTED_SEMICOLON: i32 = -10;
const MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INTERNAL: i32 = -11;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK: i32 = 0;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS: i32 = -1;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_AUTH_CLUSTERS: i32 = -2;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PROXIES_INTERMIXED: i32 = -3;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_TARGETS: i32 = -4;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_HOSTNAME_EXPECTED: i32 = -5;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_EXPECTED: i32 = -6;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_RANGE: i32 = -7;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_EXPECTED_SEMICOLON: i32 = -8;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_CLUSTER_EXTEND_INVARIANT: i32 = -9;
const MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL: i32 = -10;
const MTPROTO_CFG_PARSE_FULL_PASS_OK: i32 = 0;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS: i32 = -1;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TIMEOUT: i32 = -2;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MAX_CONNECTIONS: i32 = -3;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MIN_CONNECTIONS: i32 = -4;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TARGET_ID: i32 = -5;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_TARGET_ID_SPACE: i32 = -6;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXY_EXPECTED: i32 = -7;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_AUTH_CLUSTERS: i32 = -8;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXIES_INTERMIXED: i32 = -9;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON: i32 = -10;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_TARGETS: i32 = -11;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_HOSTNAME_EXPECTED: i32 = -12;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_EXPECTED: i32 = -13;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_RANGE: i32 = -14;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_CLUSTER_EXTEND_INVARIANT: i32 = -15;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES: i32 = -16;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_NO_PROXY_SERVERS_DEFINED: i32 = -17;
const MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL: i32 = -18;
const MTPROTO_CFG_FULL_PASS_MAX_CLUSTERS: usize = 1024;
const MTPROTO_CFG_MAX_CLUSTERS: usize = 1024;
const MTPROTO_CFG_MAX_TARGETS: usize = 4096;
const MTPROTO_CFG_EXPECT_SEMICOLON_OK: i32 = 0;
const MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS: i32 = -1;
const MTPROTO_CFG_EXPECT_SEMICOLON_ERR_EXPECTED: i32 = -2;
const MTPROTO_DIRECTIVE_TOKEN_KIND_EOF: i32 = 0;
const MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT: i32 = 1;
const MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER: i32 = 2;
const MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR: i32 = 3;
const MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY: i32 = 4;
const MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS: i32 = 5;
const MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS: i32 = 6;
const MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING: i32 = 0;
const MTPROTO_CFG_CLUSTER_TARGETS_ACTION_CLEAR: i32 = 1;
const MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET: i32 = 2;
const MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK: i32 = 0;
const MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND: i32 = 1;
const MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS: i32 = -1;
const MTPROTO_CFG_FINALIZE_OK: i32 = 0;
const MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS: i32 = -1;
const MTPROTO_CFG_FINALIZE_ERR_MISSING_PROXY_DIRECTIVES: i32 = -2;
const MTPROTO_CFG_FINALIZE_ERR_NO_PROXY_SERVERS_DEFINED: i32 = -3;
const MTPROTO_CFG_FINALIZE_ERR_INTERNAL: i32 = -4;
const MTPROTO_CFG_PREINIT_OK: i32 = 0;
const MTPROTO_CFG_PREINIT_ERR_INVALID_ARGS: i32 = -1;
const MTPROTO_CFG_PREINIT_ERR_INTERNAL: i32 = -2;
const MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK: i32 = 0;
const MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS: i32 = -1;
const MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_TOO_MANY_AUTH_CLUSTERS: i32 = -2;
const MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_PROXIES_INTERMIXED: i32 = -3;
const MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INTERNAL: i32 = -4;
const MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW: i32 = 1;
const MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST: i32 = 2;
const MTPROTO_PACKET_KIND_INVALID: i32 = 0;
const MTPROTO_PACKET_KIND_ENCRYPTED: i32 = 1;
const MTPROTO_PACKET_KIND_UNENCRYPTED_DH: i32 = 2;
const MTPROTO_CLIENT_PACKET_KIND_INVALID: i32 = 0;
const MTPROTO_CLIENT_PACKET_KIND_PONG: i32 = 1;
const MTPROTO_CLIENT_PACKET_KIND_PROXY_ANS: i32 = 2;
const MTPROTO_CLIENT_PACKET_KIND_SIMPLE_ACK: i32 = 3;
const MTPROTO_CLIENT_PACKET_KIND_CLOSE_EXT: i32 = 4;
const MTPROTO_CLIENT_PACKET_KIND_UNKNOWN: i32 = 5;
const MTPROTO_CLIENT_PACKET_KIND_MALFORMED: i32 = 6;
const CRYPTO_TEMP_DH_PARAMS_MAGIC: i32 = i32::from_ne_bytes(0xab45_ccd3_u32.to_ne_bytes());

#[cfg(test)]
const TCP_RPC_PACKET_LEN_STATE_SKIP: i32 = 0;
#[cfg(test)]
const TCP_RPC_PACKET_LEN_STATE_READY: i32 = 1;
#[cfg(test)]
const TCP_RPC_PACKET_LEN_STATE_INVALID: i32 = -1;
#[cfg(test)]
const TCP_RPC_PACKET_LEN_STATE_SHORT: i32 = -2;

#[cfg(test)]
const EVT_SPEC: u32 = 1;
#[cfg(test)]
const EVT_WRITE: u32 = 2;
#[cfg(test)]
const EVT_READ: u32 = 4;
#[cfg(test)]
const EVT_LEVEL: u32 = 8;
#[cfg(test)]
const EVT_FROM_EPOLL: u32 = 0x400;

#[cfg(test)]
const EPOLLIN: u32 = 0x001;
#[cfg(test)]
const EPOLLPRI: u32 = 0x002;
#[cfg(test)]
const EPOLLOUT: u32 = 0x004;
#[cfg(test)]
const EPOLLERR: u32 = 0x008;
#[cfg(test)]
const EPOLLRDHUP: u32 = 0x2000;
#[cfg(test)]
const EPOLLET: u32 = 0x8000_0000;
const AES_CREATE_KEYS_MAX_STR_LEN: usize =
    16 + 16 + 4 + 4 + 2 + 6 + 4 + 2 + MAX_PWD_LEN + 16 + 16 + 4 + (16 * 2) + 256;
const DH_KEY_BYTES: usize = 256;
const DH_GOOD_PREFIX_BYTES: usize = 8;
const DH_PARAMS_SELECT: i32 = 0x0062_0b93;
const DH_MOD_MIN_LEN: usize = 241;
const DH_MOD_MAX_LEN: usize = 256;
const AESNI_CIPHER_AES_256_CBC: i32 = 1;
const AESNI_CIPHER_AES_256_CTR: i32 = 2;
const O_RDONLY_FLAG: c_int = 0;
const AES_ROLE_XOR_MASK: [u8; 6] = [
    b'C' ^ b'S',
    b'L' ^ b'E',
    b'I' ^ b'R',
    b'E' ^ b'V',
    b'N' ^ b'E',
    b'T' ^ b'R',
];
const TLS_X25519_MOD_HEX: &[u8] =
    b"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed\0";
const TLS_X25519_POW_HEX: &[u8] =
    b"3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6\0";
const TLS_REQUEST_PUBLIC_KEY_BYTES: usize = 32;
const RPC_DH_PRIME_BIN: [u8; DH_KEY_BYTES] = [
    0x89, 0x52, 0x13, 0x1b, 0x1e, 0x3a, 0x69, 0xba, 0x5f, 0x85, 0xcf, 0x8b, 0xd2, 0x66, 0xc1, 0x2b,
    0x13, 0x83, 0x16, 0x13, 0xbd, 0x2a, 0x4e, 0xf8, 0x35, 0xa4, 0xd5, 0x3f, 0x9d, 0xbb, 0x42, 0x48,
    0x2d, 0xbd, 0x46, 0x2b, 0x31, 0xd8, 0x6c, 0x81, 0x6c, 0x59, 0x77, 0x52, 0x0f, 0x11, 0x70, 0x73,
    0x9e, 0xd2, 0xdd, 0xd6, 0xd8, 0x1b, 0x9e, 0xb6, 0x5f, 0xaa, 0xac, 0x14, 0x87, 0x53, 0xc9, 0xe4,
    0xf0, 0x72, 0xdc, 0x11, 0xa4, 0x92, 0x73, 0x06, 0x83, 0xfa, 0x00, 0x67, 0x82, 0x6b, 0x18, 0xc5,
    0x1d, 0x7e, 0xcb, 0xa5, 0x2b, 0x82, 0x60, 0x75, 0xc0, 0xb9, 0x55, 0xe5, 0xac, 0xaf, 0xdd, 0x74,
    0xc3, 0x79, 0x5f, 0xd9, 0x52, 0x0b, 0x48, 0x0f, 0x3b, 0xe3, 0xba, 0x06, 0x65, 0x33, 0x8a, 0x49,
    0x8c, 0xa5, 0xda, 0xf1, 0x01, 0x76, 0x05, 0x09, 0xa3, 0x8c, 0x49, 0xe3, 0x00, 0x74, 0x64, 0x08,
    0x77, 0x4b, 0xb3, 0xed, 0x26, 0x18, 0x1a, 0x64, 0x55, 0x76, 0x6a, 0xe9, 0x49, 0x7b, 0xb9, 0xc3,
    0xa3, 0xad, 0x5c, 0xba, 0xf7, 0x6b, 0x73, 0x84, 0x5f, 0xbb, 0x96, 0xbb, 0x6d, 0x0f, 0x68, 0x4f,
    0x95, 0xd2, 0xd3, 0x9c, 0xcb, 0xb4, 0xa9, 0x04, 0xfa, 0xb1, 0xde, 0x43, 0x49, 0xce, 0x1c, 0x20,
    0x87, 0xb6, 0xc9, 0x51, 0xed, 0x99, 0xf9, 0x52, 0xe3, 0x4f, 0xd1, 0xa3, 0xfd, 0x14, 0x83, 0x35,
    0x75, 0x41, 0x47, 0x29, 0xa3, 0x8b, 0xe8, 0x68, 0xa4, 0xf9, 0xec, 0x62, 0x3a, 0x5d, 0x24, 0x62,
    0x1a, 0xba, 0x01, 0xb2, 0x55, 0xc7, 0xe8, 0x38, 0x5d, 0x16, 0xac, 0x93, 0xb0, 0x2d, 0x2a, 0x54,
    0x0a, 0x76, 0x42, 0x98, 0x2d, 0x22, 0xad, 0xa3, 0xcc, 0xde, 0x5c, 0x8d, 0x26, 0x6f, 0xaa, 0x25,
    0xdd, 0x2d, 0xe9, 0xf6, 0xd4, 0x91, 0x04, 0x16, 0x2f, 0x68, 0x5c, 0x45, 0xfe, 0x34, 0xdd, 0xab,
];

#[repr(C)]
#[allow(dead_code)]
struct Timespec {
    tv_sec: c_long,
    tv_nsec: c_long,
}

#[repr(C)]
#[allow(dead_code)]
struct Timeval {
    tv_sec: c_long,
    tv_usec: c_long,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyProcessId {
    pub ip: u32,
    pub port: i16,
    pub pid: u16,
    pub utime: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyAesKeyData {
    pub read_key: [u8; 32],
    pub read_iv: [u8; 16],
    pub write_key: [u8; 32],
    pub write_iv: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyAesSecret {
    pub refcnt: i32,
    pub secret_len: i32,
    pub secret: [u8; MAX_PWD_LEN + 4],
}

impl Default for MtproxyAesSecret {
    fn default() -> Self {
        Self {
            refcnt: 0,
            secret_len: 0,
            secret: [0u8; MAX_PWD_LEN + 4],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyCryptoTempDhParams {
    pub magic: i32,
    pub dh_params_select: i32,
    pub a: [u8; DH_KEY_BYTES],
}

impl Default for MtproxyCryptoTempDhParams {
    fn default() -> Self {
        Self {
            magic: 0,
            dh_params_select: 0,
            a: [0u8; DH_KEY_BYTES],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCpuid {
    pub magic: i32,
    pub ebx: i32,
    pub ecx: i32,
    pub edx: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCfgScanResult {
    pub advance: usize,
    pub line_no: i32,
    pub ch: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCfgIntResult {
    pub value: i64,
    pub consumed: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgGetlexExtResult {
    pub advance: usize,
    pub lex: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgDirectiveTokenResult {
    pub kind: i32,
    pub advance: usize,
    pub value: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgDirectiveStepResult {
    pub kind: i32,
    pub advance: usize,
    pub value: i64,
    pub cluster_decision_kind: i32,
    pub cluster_index: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgParseProxyTargetStepResult {
    pub advance: usize,
    pub target_index: u32,
    pub host_len: u8,
    pub port: u16,
    pub min_connections: i64,
    pub max_connections: i64,
    pub tot_targets_after: u32,
    pub cluster_decision_kind: i32,
    pub cluster_index: i32,
    pub auth_clusters_after: u32,
    pub auth_tot_clusters_after: u32,
    pub cluster_state_after: MtproxyMtprotoOldClusterState,
    pub cluster_targets_action: i32,
    pub cluster_targets_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgProxyAction {
    pub host_offset: usize,
    pub step: MtproxyMtprotoCfgParseProxyTargetStepResult,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MtproxyMtprotoCfgParseFullResult {
    pub tot_targets: u32,
    pub auth_clusters: u32,
    pub auth_tot_clusters: u32,
    pub min_connections: i64,
    pub max_connections: i64,
    pub timeout_seconds: f64,
    pub default_cluster_id: i32,
    pub have_proxy: i32,
    pub default_cluster_index: u32,
    pub has_default_cluster_index: i32,
    pub actions_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgFinalizeResult {
    pub default_cluster_index: u32,
    pub has_default_cluster_index: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MtproxyMtprotoCfgPreinitResult {
    pub tot_targets: i32,
    pub auth_clusters: i32,
    pub min_connections: i64,
    pub max_connections: i64,
    pub timeout_seconds: f64,
    pub default_cluster_id: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgClusterApplyDecisionResult {
    pub kind: i32,
    pub cluster_index: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoPacketInspectResult {
    pub kind: i32,
    pub auth_key_id: i64,
    pub inner_len: i32,
    pub function_id: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoClientPacketParseResult {
    pub kind: i32,
    pub op: i32,
    pub flags: i32,
    pub out_conn_id: i64,
    pub confirm: i32,
    pub payload_offset: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoOldClusterState {
    pub cluster_id: i32,
    pub targets_num: u32,
    pub write_targets_num: u32,
    pub flags: u32,
    pub first_target_index: u32,
    pub has_first_target_index: i32,
}

type MtproxyConnTargetJob = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct MtproxyMfCluster {
    targets_num: c_int,
    write_targets_num: c_int,
    targets_allocated: c_int,
    flags: c_int,
    cluster_id: c_int,
    cluster_targets: *mut MtproxyConnTargetJob,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MtproxyMfGroupStats {
    tot_clusters: c_int,
}

#[repr(C)]
struct MtproxyMfConfig {
    tot_targets: c_int,
    auth_clusters: c_int,
    default_cluster_id: c_int,
    min_connections: c_int,
    max_connections: c_int,
    timeout: f64,
    config_bytes: c_int,
    config_loaded_at: c_int,
    config_md5_hex: *mut c_char,
    auth_stats: MtproxyMfGroupStats,
    have_proxy: c_int,
    default_cluster: *mut MtproxyMfCluster,
    targets: [MtproxyConnTargetJob; MTPROTO_CFG_MAX_TARGETS],
    auth_cluster: [MtproxyMfCluster; MTPROTO_CFG_MAX_CLUSTERS],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MtproxyEventTimer {
    h_idx: c_int,
    flags: c_int,
    wakeup: Option<unsafe extern "C" fn(*mut MtproxyEventTimer) -> c_int>,
    wakeup_time: c_double,
    real_wakeup_time: c_double,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MtproxyInAddr {
    s_addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MtproxyConnTargetInfo {
    timer: MtproxyEventTimer,
    min_connections: c_int,
    max_connections: c_int,
    conn_tree: *mut c_void,
    type_: *mut c_void,
    extra: *mut c_void,
    target: MtproxyInAddr,
    target_ipv6: [u8; 16],
    port: c_int,
    active_outbound_connections: c_int,
    outbound_connections: c_int,
    ready_outbound_connections: c_int,
    next_reconnect: c_double,
    reconnect_timeout: c_double,
    next_reconnect_timeout: c_double,
    custom_field: c_int,
    next_target: MtproxyConnTargetJob,
    prev_target: MtproxyConnTargetJob,
    hnext: MtproxyConnTargetJob,
    global_refcnt: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MtproxyHostEnt {
    h_name: *mut c_char,
    h_aliases: *mut *mut c_char,
    h_addrtype: c_int,
    h_length: c_int,
    h_addr_list: *mut *mut c_char,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyTlHeaderParseResult {
    pub status: i32,
    pub consumed: i32,
    pub op: i32,
    pub real_op: i32,
    pub flags: i32,
    pub qid: i64,
    pub actor_id: i64,
    pub errnum: i32,
    pub error_len: i32,
    pub error: [c_char; 192],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyMtprotoParseFunctionResult {
    pub status: i32,
    pub consumed: i32,
    pub errnum: i32,
    pub error_len: i32,
    pub error: [c_char; 192],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyProcStats {
    pub pid: i32,
    pub comm: [c_char; 256],
    pub state: i8,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    pub tpgid: i32,
    pub flags: u64,
    pub minflt: u64,
    pub cminflt: u64,
    pub majflt: u64,
    pub cmajflt: u64,
    pub utime: u64,
    pub stime: u64,
    pub cutime: i64,
    pub cstime: i64,
    pub priority: i64,
    pub nice: i64,
    pub num_threads: i64,
    pub itrealvalue: i64,
    pub starttime: u64,
    pub vsize: u64,
    pub rss: i64,
    pub rlim: u64,
    pub startcode: u64,
    pub endcode: u64,
    pub startstack: u64,
    pub kstkesp: u64,
    pub kstkeip: u64,
    pub signal: u64,
    pub blocked: u64,
    pub sigignore: u64,
    pub sigcatch: u64,
    pub wchan: u64,
    pub nswap: u64,
    pub cnswap: u64,
    pub exit_signal: i32,
    pub processor: i32,
    pub rt_priority: u64,
    pub policy: u64,
    pub delayacct_blkio_ticks: u64,
}

impl Default for MtproxyProcStats {
    fn default() -> Self {
        Self {
            pid: 0,
            comm: [0; 256],
            state: 0,
            ppid: 0,
            pgrp: 0,
            session: 0,
            tty_nr: 0,
            tpgid: 0,
            flags: 0,
            minflt: 0,
            cminflt: 0,
            majflt: 0,
            cmajflt: 0,
            utime: 0,
            stime: 0,
            cutime: 0,
            cstime: 0,
            priority: 0,
            nice: 0,
            num_threads: 0,
            itrealvalue: 0,
            starttime: 0,
            vsize: 0,
            rss: 0,
            rlim: 0,
            startcode: 0,
            endcode: 0,
            startstack: 0,
            kstkesp: 0,
            kstkeip: 0,
            signal: 0,
            blocked: 0,
            sigignore: 0,
            sigcatch: 0,
            wchan: 0,
            nswap: 0,
            cnswap: 0,
            exit_signal: 0,
            processor: 0,
            rt_priority: 0,
            policy: 0,
            delayacct_blkio_ticks: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMeminfoSummary {
    pub mem_free: i64,
    pub mem_cached: i64,
    pub swap_total: i64,
    pub swap_free: i64,
    pub found_mask: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyConcurrencyBoundary {
    pub boundary_version: u32,
    pub mpq_contract_ops: u32,
    pub mpq_implemented_ops: u32,
    pub jobs_contract_ops: u32,
    pub jobs_implemented_ops: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyNetworkBoundary {
    pub boundary_version: u32,
    pub net_events_contract_ops: u32,
    pub net_events_implemented_ops: u32,
    pub net_timers_contract_ops: u32,
    pub net_timers_implemented_ops: u32,
    pub net_msg_buffers_contract_ops: u32,
    pub net_msg_buffers_implemented_ops: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyRpcBoundary {
    pub boundary_version: u32,
    pub tcp_rpc_common_contract_ops: u32,
    pub tcp_rpc_common_implemented_ops: u32,
    pub tcp_rpc_client_contract_ops: u32,
    pub tcp_rpc_client_implemented_ops: u32,
    pub tcp_rpc_server_contract_ops: u32,
    pub tcp_rpc_server_implemented_ops: u32,
    pub rpc_targets_contract_ops: u32,
    pub rpc_targets_implemented_ops: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCryptoBoundary {
    pub boundary_version: u32,
    pub net_crypto_aes_contract_ops: u32,
    pub net_crypto_aes_implemented_ops: u32,
    pub net_crypto_dh_contract_ops: u32,
    pub net_crypto_dh_implemented_ops: u32,
    pub aesni_contract_ops: u32,
    pub aesni_implemented_ops: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyApplicationBoundary {
    pub boundary_version: u32,
    pub engine_rpc_contract_ops: u32,
    pub engine_rpc_implemented_ops: u32,
    pub mtproto_proxy_contract_ops: u32,
    pub mtproto_proxy_implemented_ops: u32,
}

impl Default for MtproxyTlHeaderParseResult {
    fn default() -> Self {
        Self {
            status: 0,
            consumed: 0,
            op: 0,
            real_op: 0,
            flags: 0,
            qid: 0,
            actor_id: 0,
            errnum: 0,
            error_len: 0,
            error: [0; 192],
        }
    }
}

impl Default for MtproxyMtprotoParseFunctionResult {
    fn default() -> Self {
        Self {
            status: 0,
            consumed: 0,
            errnum: 0,
            error_len: 0,
            error: [0; 192],
        }
    }
}

unsafe extern "C" {
    fn getpid() -> c_int;
    fn time(timer: *mut c_long) -> c_long;
    fn clock_gettime(clock_id: c_int, tp: *mut Timespec) -> c_int;
    fn gettimeofday(tv: *mut Timeval, tz: *mut c_void) -> c_int;
    fn open(pathname: *const c_char, flags: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn exit(status: c_int) -> !;
    fn lrand48() -> c_long;
    fn drand48() -> c_double;
    fn srand48(seedval: c_long);
    fn malloc(size: usize) -> *mut c_void;
    fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn kprintf(format: *const c_char, ...);
    fn syntax(msg: *const c_char, ...);
    fn load_config(file: *const c_char, fd: c_int) -> c_int;
    fn reset_config();
    fn md5_hex_config(out: *mut c_char);
    fn cfg_gethost() -> *mut MtproxyHostEnt;
    fn destroy_target(ctj_tag_int: c_int, ctj: MtproxyConnTargetJob) -> c_int;
    fn create_target(
        source: *mut MtproxyConnTargetInfo,
        was_created: *mut c_int,
    ) -> MtproxyConnTargetJob;
    fn create_all_outbound_connections() -> c_int;
    fn kdb_load_hosts() -> c_int;

    static mut default_cfg_min_connections: c_int;
    static mut default_cfg_max_connections: c_int;
    static mut default_cfg_ct: MtproxyConnTargetInfo;
    static mut cfg_cur: *mut c_char;
    static mut cfg_end: *mut c_char;
    static mut config_filename: *mut c_char;
    static mut config_bytes: c_int;
    static mut CurConf: *mut MtproxyMfConfig;
    static mut NextConf: *mut MtproxyMfConfig;
    static mut verbosity: c_int;
}

type Aes256Ctr = Ctr128BE<Aes256>;
type HmacMd5 = Hmac<Md5>;
type HmacSha256 = Hmac<Sha256>;

#[repr(C, align(16))]
struct MtproxyAesCryptoCtx {
    read_aeskey: *mut c_void,
    write_aeskey: *mut c_void,
}

enum AesniCipherCtx {
    Aes256CbcEncrypt(cbc::Encryptor<Aes256>),
    Aes256CbcDecrypt(cbc::Decryptor<Aes256>),
    Aes256Ctr(Aes256Ctr),
}

impl AesniCipherCtx {
    fn crypt_in_place(&mut self, output: &mut [u8]) -> bool {
        if output.is_empty() {
            return true;
        }
        match self {
            Self::Aes256CbcEncrypt(cipher) => {
                if (output.len() & 15) != 0 {
                    return false;
                }
                for chunk in output.chunks_exact_mut(16) {
                    let block = cbc::cipher::Block::<Aes256>::from_mut_slice(chunk);
                    cipher.encrypt_block_mut(block);
                }
                true
            }
            Self::Aes256CbcDecrypt(cipher) => {
                if (output.len() & 15) != 0 {
                    return false;
                }
                for chunk in output.chunks_exact_mut(16) {
                    let block = cbc::cipher::Block::<Aes256>::from_mut_slice(chunk);
                    cipher.decrypt_block_mut(block);
                }
                true
            }
            Self::Aes256Ctr(cipher) => {
                cipher.apply_keystream(output);
                true
            }
        }
    }
}

thread_local! {
    static TLS_PRECISE_NOW: Cell<f64> = const { Cell::new(0.0) };
    static TLS_PRECISE_NOW_RDTSC: Cell<i64> = const { Cell::new(0) };
}

static PRECISE_TIME: AtomicI64 = AtomicI64::new(0);
static PRECISE_TIME_RDTSC: AtomicI64 = AtomicI64::new(0);
static DOUBLE_TIME_LAST_BITS: AtomicU64 = AtomicU64::new((-1.0f64).to_bits());
static DOUBLE_TIME_NEXT_RDTSC: AtomicI64 = AtomicI64::new(0);
static AES_ALLOCATED_CRYPTO: AtomicI64 = AtomicI64::new(0);
static AES_ALLOCATED_CRYPTO_TEMP: AtomicI64 = AtomicI64::new(0);
static DH_PARAMS_SELECT_INIT: AtomicI64 = AtomicI64::new(0);
static DH_TOT_ROUNDS_0: AtomicI64 = AtomicI64::new(0);
static DH_TOT_ROUNDS_1: AtomicI64 = AtomicI64::new(0);
static DH_TOT_ROUNDS_2: AtomicI64 = AtomicI64::new(0);
static AES_NONCE_RAND_BUF: Mutex<[u8; 64]> = Mutex::new([0u8; 64]);

mod compat;
mod crypto;
mod jobs;
mod kprintf;
mod mtproto;
mod server_functions;
mod stats;
mod tl_parse_methods;
mod time_cfg_observability;
pub mod vv_io;
pub mod vv_tree;

pub use compat::*;
pub use crypto::*;
pub use jobs::*;
pub use kprintf::*;
pub use mtproto::*;
pub use server_functions::*;
pub use stats::*;
pub use time_cfg_observability::*;

#[cfg(test)]
pub(crate) use crypto::{CRC32_REFLECTED_POLY, GF32_CLMUL_POWERS_LEN};

#[cfg(test)]
mod tests;
