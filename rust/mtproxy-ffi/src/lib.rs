//! FFI-facing Rust crate for incremental C/Rust integration.

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};
use core::ffi::{c_char, c_int, c_long, c_void};
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
const JOBS_IMPLEMENTED_OPS: u32 = (1u32 << 0) | (1u32 << 2) | (1u32 << 3) | (1u32 << 4);
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
const CRYPTO_TEMP_DH_PARAMS_MAGIC: i32 = i32::from_ne_bytes(0xab45_ccd3_u32.to_ne_bytes());

const TCP_RPC_PACKET_LEN_STATE_SKIP: i32 = 0;
const TCP_RPC_PACKET_LEN_STATE_READY: i32 = 1;
const TCP_RPC_PACKET_LEN_STATE_INVALID: i32 = -1;
const TCP_RPC_PACKET_LEN_STATE_SHORT: i32 = -2;

const EVT_SPEC: u32 = 1;
const EVT_WRITE: u32 = 2;
const EVT_READ: u32 = 4;
const EVT_LEVEL: u32 = 8;
const EVT_FROM_EPOLL: u32 = 0x400;

const EPOLLIN: u32 = 0x001;
const EPOLLPRI: u32 = 0x002;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLRDHUP: u32 = 0x2000;
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
pub struct MtproxyMtprotoOldClusterState {
    pub cluster_id: i32,
    pub targets_num: u32,
    pub write_targets_num: u32,
    pub flags: u32,
    pub first_target_index: u32,
    pub has_first_target_index: i32,
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
    fn lrand48_j() -> c_long;
    fn srand48(seedval: c_long);
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
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

/// Mirrors core API version for Rust callers.
#[must_use]
pub fn ffi_api_version() -> u32 {
    FFI_API_VERSION
}

/// Returns FFI API version to C callers.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_api_version() -> u32 {
    FFI_API_VERSION
}

/// Performs a minimal startup compatibility handshake.
///
/// Return codes:
/// - `0`: handshake accepted
/// - `-1`: incompatible API version
#[no_mangle]
pub extern "C" fn mtproxy_ffi_startup_handshake(expected_api_version: u32) -> i32 {
    if expected_api_version == FFI_API_VERSION {
        0
    } else {
        -1
    }
}

/// Returns extracted Step 9 boundary contract for mp-queue/jobs migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyConcurrencyBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_concurrency_boundary(
    out: *mut MtproxyConcurrencyBoundary,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyConcurrencyBoundary {
        boundary_version: CONCURRENCY_BOUNDARY_VERSION,
        mpq_contract_ops: MPQ_CONTRACT_OPS,
        mpq_implemented_ops: MPQ_IMPLEMENTED_OPS,
        jobs_contract_ops: JOBS_CONTRACT_OPS,
        jobs_implemented_ops: JOBS_IMPLEMENTED_OPS,
    };
    0
}

/// Returns extracted Step 10 boundary contract for net-core migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyNetworkBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_network_boundary(out: *mut MtproxyNetworkBoundary) -> i32 {
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyNetworkBoundary {
        boundary_version: NETWORK_BOUNDARY_VERSION,
        net_events_contract_ops: NET_EVENTS_CONTRACT_OPS,
        net_events_implemented_ops: NET_EVENTS_IMPLEMENTED_OPS,
        net_timers_contract_ops: NET_TIMERS_CONTRACT_OPS,
        net_timers_implemented_ops: NET_TIMERS_IMPLEMENTED_OPS,
        net_msg_buffers_contract_ops: NET_MSG_BUFFERS_CONTRACT_OPS,
        net_msg_buffers_implemented_ops: NET_MSG_BUFFERS_IMPLEMENTED_OPS,
    };
    0
}

/// Returns extracted Step 11 boundary contract for RPC/TCP migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyRpcBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_rpc_boundary(out: *mut MtproxyRpcBoundary) -> i32 {
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyRpcBoundary {
        boundary_version: RPC_BOUNDARY_VERSION,
        tcp_rpc_common_contract_ops: TCP_RPC_COMMON_CONTRACT_OPS,
        tcp_rpc_common_implemented_ops: TCP_RPC_COMMON_IMPLEMENTED_OPS,
        tcp_rpc_client_contract_ops: TCP_RPC_CLIENT_CONTRACT_OPS,
        tcp_rpc_client_implemented_ops: TCP_RPC_CLIENT_IMPLEMENTED_OPS,
        tcp_rpc_server_contract_ops: TCP_RPC_SERVER_CONTRACT_OPS,
        tcp_rpc_server_implemented_ops: TCP_RPC_SERVER_IMPLEMENTED_OPS,
        rpc_targets_contract_ops: RPC_TARGETS_CONTRACT_OPS,
        rpc_targets_implemented_ops: RPC_TARGETS_IMPLEMENTED_OPS,
    };
    0
}

/// Returns extracted Step 12 boundary contract for crypto integration migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyCryptoBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_crypto_boundary(out: *mut MtproxyCryptoBoundary) -> i32 {
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyCryptoBoundary {
        boundary_version: CRYPTO_BOUNDARY_VERSION,
        net_crypto_aes_contract_ops: NET_CRYPTO_AES_CONTRACT_OPS,
        net_crypto_aes_implemented_ops: NET_CRYPTO_AES_IMPLEMENTED_OPS,
        net_crypto_dh_contract_ops: NET_CRYPTO_DH_CONTRACT_OPS,
        net_crypto_dh_implemented_ops: NET_CRYPTO_DH_IMPLEMENTED_OPS,
        aesni_contract_ops: AESNI_CONTRACT_OPS,
        aesni_implemented_ops: AESNI_IMPLEMENTED_OPS,
    };
    0
}

/// Returns extracted Step 13 boundary contract for engine/mtproto app migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyApplicationBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_application_boundary(
    out: *mut MtproxyApplicationBoundary,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyApplicationBoundary {
        boundary_version: APPLICATION_BOUNDARY_VERSION,
        engine_rpc_contract_ops: ENGINE_RPC_CONTRACT_OPS,
        engine_rpc_implemented_ops: ENGINE_RPC_IMPLEMENTED_OPS,
        mtproto_proxy_contract_ops: MTPROTO_PROXY_CONTRACT_OPS,
        mtproto_proxy_implemented_ops: MTPROTO_PROXY_IMPLEMENTED_OPS,
    };
    0
}

fn net_epoll_conv_flags_impl(flags: i32) -> i32 {
    if flags == 0 {
        return 0;
    }
    let flags_u = u32::from_ne_bytes(flags.to_ne_bytes());
    let mut out = EPOLLERR;
    if (flags_u & EVT_READ) != 0 {
        out |= EPOLLIN;
    }
    if (flags_u & EVT_WRITE) != 0 {
        out |= EPOLLOUT;
    }
    if (flags_u & EVT_SPEC) != 0 {
        out |= EPOLLRDHUP | EPOLLPRI;
    }
    if (flags_u & EVT_LEVEL) == 0 {
        out |= EPOLLET;
    }
    i32::from_ne_bytes(out.to_ne_bytes())
}

fn net_epoll_unconv_flags_impl(epoll_flags: i32) -> i32 {
    let flags_u = u32::from_ne_bytes(epoll_flags.to_ne_bytes());
    let mut out = EVT_FROM_EPOLL;
    if (flags_u & (EPOLLIN | EPOLLERR)) != 0 {
        out |= EVT_READ;
    }
    if (flags_u & EPOLLOUT) != 0 {
        out |= EVT_WRITE;
    }
    if (flags_u & (EPOLLRDHUP | EPOLLPRI)) != 0 {
        out |= EVT_SPEC;
    }
    i32::from_ne_bytes(out.to_ne_bytes())
}

#[allow(clippy::cast_possible_truncation)]
fn net_timers_wait_msec_impl(wakeup_time: f64, now: f64) -> i32 {
    let wait_time = wakeup_time - now;
    if wait_time <= 0.0 {
        return 0;
    }
    let millis = (wait_time * 1000.0) + 1.0;
    if !millis.is_finite() || millis >= f64::from(i32::MAX) {
        i32::MAX
    } else {
        millis as i32
    }
}

fn msg_buffers_pick_size_index_impl(buffer_sizes: &[i32], size_hint: i32) -> i32 {
    if buffer_sizes.is_empty() {
        return -1;
    }
    let mut idx = i32::try_from(buffer_sizes.len()).unwrap_or(i32::MAX) - 1;
    if size_hint >= 0 {
        while idx > 0 {
            let prev_idx = usize::try_from(idx - 1).unwrap_or(0);
            if buffer_sizes[prev_idx] < size_hint {
                break;
            }
            idx -= 1;
        }
    }
    idx
}

fn tcp_rpc_encode_compact_header_impl(payload_len: i32, is_medium: i32) -> (i32, i32) {
    if is_medium != 0 {
        return (payload_len, 4);
    }
    if payload_len <= 0x7e * 4 {
        return (payload_len >> 2, 1);
    }
    let len_u = u32::from_ne_bytes(payload_len.to_ne_bytes());
    let encoded = (len_u << 6) | 0x7f;
    (i32::from_ne_bytes(encoded.to_ne_bytes()), 4)
}

fn tcp_rpc_client_packet_len_state_impl(packet_len: i32, max_packet_len: i32) -> i32 {
    if packet_len <= 0
        || (packet_len & 3) != 0
        || (max_packet_len > 0 && packet_len > max_packet_len)
    {
        return TCP_RPC_PACKET_LEN_STATE_INVALID;
    }
    if packet_len == 4 {
        return TCP_RPC_PACKET_LEN_STATE_SKIP;
    }
    if packet_len < 16 {
        return TCP_RPC_PACKET_LEN_STATE_SHORT;
    }
    TCP_RPC_PACKET_LEN_STATE_READY
}

fn tcp_rpc_server_packet_header_malformed_impl(packet_len: i32) -> i32 {
    i32::from(
        packet_len <= 0 || (packet_len & i32::from_ne_bytes(0xc000_0003_u32.to_ne_bytes())) != 0,
    )
}

fn tcp_rpc_server_packet_len_state_impl(packet_len: i32, max_packet_len: i32) -> i32 {
    if max_packet_len > 0 && packet_len > max_packet_len {
        return TCP_RPC_PACKET_LEN_STATE_INVALID;
    }
    if packet_len == 4 {
        return TCP_RPC_PACKET_LEN_STATE_SKIP;
    }
    if packet_len < 16 {
        return TCP_RPC_PACKET_LEN_STATE_INVALID;
    }
    TCP_RPC_PACKET_LEN_STATE_READY
}

fn rpc_target_normalize_pid_impl(pid: &mut MtproxyProcessId, default_ip: u32) {
    if pid.ip == 0 {
        pid.ip = default_ip;
    }
}

fn engine_rpc_result_new_flags_impl(old_flags: i32) -> i32 {
    old_flags & 0xffff
}

fn engine_rpc_result_header_len_impl(flags: i32) -> i32 {
    if flags == 0 {
        0
    } else {
        8
    }
}

fn mtproto_conn_tag_impl(generation: i32) -> i32 {
    mtproxy_core::runtime::mtproto::proxy::mtproto_conn_tag(generation)
}

fn mtproto_ext_conn_hash_impl(in_fd: i32, in_conn_id: i64, hash_shift: i32) -> i32 {
    mtproxy_core::runtime::mtproto::proxy::mtproto_ext_conn_hash(in_fd, in_conn_id, hash_shift)
}

/// Converts net event flags into Linux epoll flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_epoll_conv_flags(flags: i32) -> i32 {
    net_epoll_conv_flags_impl(flags)
}

/// Converts Linux epoll flags into net event flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_epoll_unconv_flags(epoll_flags: i32) -> i32 {
    net_epoll_unconv_flags_impl(epoll_flags)
}

/// Computes timeout in milliseconds until wakeup.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_timers_wait_msec(wakeup_time: f64, now: f64) -> i32 {
    net_timers_wait_msec_impl(wakeup_time, now)
}

/// Selects message-buffer size-class index matching C allocation policy.
///
/// # Safety
/// `buffer_sizes` must point to `buffer_size_values` readable `i32` values.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_msg_buffers_pick_size_index(
    buffer_sizes: *const i32,
    buffer_size_values: i32,
    size_hint: i32,
) -> i32 {
    if buffer_sizes.is_null() || buffer_size_values <= 0 {
        return -1;
    }
    let Ok(count) = usize::try_from(buffer_size_values) else {
        return -1;
    };
    let sizes = unsafe { core::slice::from_raw_parts(buffer_sizes, count) };
    msg_buffers_pick_size_index_impl(sizes, size_hint)
}

/// Encodes compact/medium tcp-rpc length prefix exactly like C path.
///
/// # Safety
/// `out_prefix_word` and `out_prefix_bytes` must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_encode_compact_header(
    payload_len: i32,
    is_medium: i32,
    out_prefix_word: *mut i32,
    out_prefix_bytes: *mut i32,
) -> i32 {
    if out_prefix_word.is_null() || out_prefix_bytes.is_null() {
        return -1;
    }
    let (prefix_word, prefix_bytes) = tcp_rpc_encode_compact_header_impl(payload_len, is_medium);
    let out_word = unsafe { &mut *out_prefix_word };
    let out_bytes = unsafe { &mut *out_prefix_bytes };
    *out_word = prefix_word;
    *out_bytes = prefix_bytes;
    0
}

/// Classifies packet length for non-compact tcp-rpc client parser path.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_client_packet_len_state(
    packet_len: i32,
    max_packet_len: i32,
) -> i32 {
    tcp_rpc_client_packet_len_state_impl(packet_len, max_packet_len)
}

/// Returns `1` when tcp-rpc server packet header is malformed before fallback.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_packet_header_malformed(packet_len: i32) -> i32 {
    tcp_rpc_server_packet_header_malformed_impl(packet_len)
}

/// Classifies packet length for non-compact tcp-rpc server parser path.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_packet_len_state(
    packet_len: i32,
    max_packet_len: i32,
) -> i32 {
    tcp_rpc_server_packet_len_state_impl(packet_len, max_packet_len)
}

/// Normalizes rpc-target PID (`ip=0` -> `default_ip`) to match C behavior.
///
/// # Safety
/// `pid` must be a valid writable pointer to `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_normalize_pid(
    pid: *mut MtproxyProcessId,
    default_ip: u32,
) -> i32 {
    if pid.is_null() {
        return -1;
    }
    let pid_ref = unsafe { &mut *pid };
    rpc_target_normalize_pid_impl(pid_ref, default_ip);
    0
}

/// Computes `engine-rpc` result flags normalization (`old_flags & 0xffff`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_result_new_flags(old_flags: i32) -> i32 {
    engine_rpc_result_new_flags_impl(old_flags)
}

/// Computes `engine-rpc` result header length from flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_result_header_len(flags: i32) -> i32 {
    engine_rpc_result_header_len_impl(flags)
}

/// Computes mtproto external-connection hash bucket.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_mtproto_ext_conn_hash(
    in_fd: i32,
    in_conn_id: i64,
    hash_shift: i32,
) -> i32 {
    mtproto_ext_conn_hash_impl(in_fd, in_conn_id, hash_shift)
}

/// Computes mtproto connection tag (`1 + (generation & 0xffffff)`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_mtproto_conn_tag(generation: i32) -> i32 {
    mtproto_conn_tag_impl(generation)
}

/// Parses dotted IPv4 text into host-order integer (`a<<24|b<<16|c<<8|d`).
///
/// # Safety
/// `str` must be a valid NUL-terminated C string, `out_ip` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_parse_text_ipv4(
    str: *const c_char,
    out_ip: *mut u32,
) -> i32 {
    if str.is_null() || out_ip.is_null() {
        return -1;
    }
    let input = unsafe { CStr::from_ptr(str) }.to_string_lossy();
    let parsed = mtproxy_core::runtime::mtproto::proxy::parse_text_ipv4(&input);
    let out_ref = unsafe { &mut *out_ip };
    *out_ref = parsed;
    0
}

/// Parses textual IPv6 and writes 16-byte network-order output.
///
/// # Safety
/// `str` must be a valid NUL-terminated C string,
/// `out_ip`/`out_consumed` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_parse_text_ipv6(
    str: *const c_char,
    out_ip: *mut u8,
    out_consumed: *mut i32,
) -> i32 {
    if str.is_null() || out_ip.is_null() || out_consumed.is_null() {
        return -1;
    }
    let input = unsafe { CStr::from_ptr(str) }.to_string_lossy();
    let mut parsed_ip = [0u8; 16];
    let consumed = mtproxy_core::runtime::mtproto::proxy::parse_text_ipv6(&mut parsed_ip, &input);
    let out_ip_slice = unsafe { core::slice::from_raw_parts_mut(out_ip, 16) };
    out_ip_slice.copy_from_slice(&parsed_ip);
    let out_consumed_ref = unsafe { &mut *out_consumed };
    *out_consumed_ref = consumed;
    0
}

/// Classifies MTProto packet shape from fixed unencrypted header bytes.
///
/// # Safety
/// `header` must point to `header_len` readable bytes when `header_len > 0`,
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_inspect_packet_header(
    header: *const u8,
    header_len: usize,
    packet_len: i32,
    out: *mut MtproxyMtprotoPacketInspectResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = slice_from_ptr(header, header_len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyMtprotoPacketInspectResult::default();

    match mtproxy_core::runtime::mtproto::proxy::inspect_mtproto_packet_header(bytes, packet_len) {
        Some(mtproxy_core::runtime::mtproto::proxy::MtprotoPacketKind::Encrypted {
            auth_key_id,
        }) => {
            out_ref.kind = MTPROTO_PACKET_KIND_ENCRYPTED;
            out_ref.auth_key_id = auth_key_id;
        }
        Some(mtproxy_core::runtime::mtproto::proxy::MtprotoPacketKind::UnencryptedDh {
            inner_len,
            function,
        }) => {
            out_ref.kind = MTPROTO_PACKET_KIND_UNENCRYPTED_DH;
            out_ref.inner_len = inner_len;
            out_ref.function_id = function;
        }
        None => {
            out_ref.kind = MTPROTO_PACKET_KIND_INVALID;
        }
    }
    0
}

fn mtproto_parse_function_impl(
    data: &[u8],
    actor_id: i64,
    out: &mut MtproxyMtprotoParseFunctionResult,
) {
    let mut in_state = mtproxy_core::runtime::config::tl_parse::TlInState::new(data);
    match mtproxy_core::runtime::mtproto::proxy::parse_mtfront_function(&mut in_state, actor_id) {
        Ok(()) => {
            out.status = 0;
            out.consumed = saturating_i32_from_usize(in_state.position());
        }
        Err(err) => {
            out.status = -1;
            out.consumed = saturating_i32_from_usize(in_state.position());
            out.errnum = err.errnum;
            copy_mtproto_parse_error_message(out, &err.message);
        }
    }
}

/// Parses mtfront function envelope from unread TL bytes.
///
/// # Safety
/// `data` must point to `len` readable bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_parse_function(
    data: *const u8,
    len: usize,
    actor_id: i64,
    out: *mut MtproxyMtprotoParseFunctionResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = slice_from_ptr(data, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyMtprotoParseFunctionResult::default();
    mtproto_parse_function_impl(bytes, actor_id, out_ref);
    0
}

/// Returns scalar config state initialized by `preinit_config()`.
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_preinit(
    default_min_connections: i64,
    default_max_connections: i64,
    out: *mut MtproxyMtprotoCfgPreinitResult,
) -> i32 {
    if out.is_null() {
        return MTPROTO_CFG_PREINIT_ERR_INVALID_ARGS;
    }
    let snapshot = mtproxy_core::runtime::mtproto::config::preinit_config_snapshot(
        mtproxy_core::runtime::mtproto::config::MtprotoConfigDefaults {
            min_connections: default_min_connections,
            max_connections: default_max_connections,
        },
    );
    let Ok(tot_targets) = i32::try_from(snapshot.tot_targets) else {
        return MTPROTO_CFG_PREINIT_ERR_INTERNAL;
    };
    let Ok(auth_clusters) = i32::try_from(snapshot.auth_clusters) else {
        return MTPROTO_CFG_PREINIT_ERR_INTERNAL;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyMtprotoCfgPreinitResult {
        tot_targets,
        auth_clusters,
        min_connections: snapshot.min_connections,
        max_connections: snapshot.max_connections,
        timeout_seconds: snapshot.timeout_seconds,
        default_cluster_id: snapshot.default_cluster_id,
    };
    MTPROTO_CFG_PREINIT_OK
}

/// Decides cluster-apply action for `proxy` / `proxy_for` directives.
///
/// # Safety
/// `cluster_ids` must be readable for `clusters_len` entries when `clusters_len > 0`;
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
    cluster_ids: *const i32,
    clusters_len: u32,
    cluster_id: i32,
    max_clusters: u32,
    out: *mut MtproxyMtprotoCfgClusterApplyDecisionResult,
) -> i32 {
    if out.is_null() {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    }
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    };
    let Ok(max_clusters_usize) = usize::try_from(max_clusters) else {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    };
    if clusters_len_usize > 0 && cluster_ids.is_null() {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    }
    let cluster_ids_slice = if clusters_len_usize == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(cluster_ids, clusters_len_usize) }
    };
    match mtproxy_core::runtime::mtproto::config::decide_proxy_cluster_apply(
        cluster_ids_slice,
        cluster_id,
        max_clusters_usize,
    ) {
        Ok(decision) => {
            let Ok(cluster_index) = i32::try_from(decision.cluster_index) else {
                return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INTERNAL;
            };
            let out_ref = unsafe { &mut *out };
            *out_ref = MtproxyMtprotoCfgClusterApplyDecisionResult {
                kind: mtproto_cfg_cluster_apply_decision_kind_to_ffi(decision.kind),
                cluster_index,
            };
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK
        }
        Err(err) => mtproto_cfg_cluster_apply_decision_err_to_code(err),
    }
}

fn mtproto_cfg_cluster_apply_decision_kind_to_ffi(
    kind: mtproxy_core::runtime::mtproto::config::MtprotoClusterApplyDecisionKind,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoClusterApplyDecisionKind;
    match kind {
        MtprotoClusterApplyDecisionKind::CreateNew => {
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW
        }
        MtprotoClusterApplyDecisionKind::AppendLast => {
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST
        }
    }
}

fn mtproto_cfg_cluster_apply_decision_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::TooManyAuthClusters(_) => {
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_TOO_MANY_AUTH_CLUSTERS
        }
        MtprotoDirectiveParseError::ProxiesIntermixed(_) => {
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_PROXIES_INTERMIXED
        }
        _ => MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INTERNAL,
    }
}

fn mtproto_cfg_cluster_targets_action_to_ffi(
    action: mtproxy_core::runtime::mtproto::config::MtprotoClusterTargetsAction,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoClusterTargetsAction;
    match action {
        MtprotoClusterTargetsAction::KeepExisting => {
            MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING
        }
        MtprotoClusterTargetsAction::Clear => MTPROTO_CFG_CLUSTER_TARGETS_ACTION_CLEAR,
        MtprotoClusterTargetsAction::SetToTargetIndex => {
            MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET
        }
    }
}

fn mtproto_cfg_parse_proxy_target_step_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::TooManyAuthClusters(_) => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_AUTH_CLUSTERS
        }
        MtprotoDirectiveParseError::ProxiesIntermixed(_) => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PROXIES_INTERMIXED
        }
        MtprotoDirectiveParseError::TooManyTargets(_) => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_TARGETS
        }
        MtprotoDirectiveParseError::HostnameExpected => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_HOSTNAME_EXPECTED
        }
        MtprotoDirectiveParseError::PortNumberExpected => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_EXPECTED
        }
        MtprotoDirectiveParseError::PortOutOfRange(_) => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_RANGE
        }
        MtprotoDirectiveParseError::ExpectedSemicolon(_) => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_EXPECTED_SEMICOLON
        }
        MtprotoDirectiveParseError::InternalClusterExtendInvariant => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_CLUSTER_EXTEND_INVARIANT
        }
        _ => MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL,
    }
}

fn mtproto_cfg_parse_full_pass_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::InvalidTimeout(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TIMEOUT
        }
        MtprotoDirectiveParseError::InvalidMaxConnections(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MAX_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidMinConnections(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MIN_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidTargetId(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TARGET_ID
        }
        MtprotoDirectiveParseError::SpaceExpectedAfterTargetId => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_TARGET_ID_SPACE
        }
        MtprotoDirectiveParseError::TooManyAuthClusters(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_AUTH_CLUSTERS
        }
        MtprotoDirectiveParseError::TooManyTargets(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_TARGETS
        }
        MtprotoDirectiveParseError::HostnameExpected => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_HOSTNAME_EXPECTED
        }
        MtprotoDirectiveParseError::PortNumberExpected => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_EXPECTED
        }
        MtprotoDirectiveParseError::PortOutOfRange(_) => MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_RANGE,
        MtprotoDirectiveParseError::ProxiesIntermixed(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXIES_INTERMIXED
        }
        MtprotoDirectiveParseError::ProxyDirectiveExpected => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXY_EXPECTED
        }
        MtprotoDirectiveParseError::ExpectedSemicolon(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON
        }
        MtprotoDirectiveParseError::MissingProxyDirectives => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES
        }
        MtprotoDirectiveParseError::NoProxyServersDefined => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_NO_PROXY_SERVERS_DEFINED
        }
        MtprotoDirectiveParseError::InternalClusterExtendInvariant => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_CLUSTER_EXTEND_INVARIANT
        }
    }
}

fn mtproto_directive_token_kind_to_ffi(
    kind: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveTokenKind,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveTokenKind;
    match kind {
        MtprotoDirectiveTokenKind::Eof => MTPROTO_DIRECTIVE_TOKEN_KIND_EOF,
        MtprotoDirectiveTokenKind::Timeout => MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT,
        MtprotoDirectiveTokenKind::DefaultCluster => MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER,
        MtprotoDirectiveTokenKind::ProxyFor => MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR,
        MtprotoDirectiveTokenKind::Proxy => MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY,
        MtprotoDirectiveTokenKind::MaxConnections => MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS,
        MtprotoDirectiveTokenKind::MinConnections => MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS,
    }
}

fn mtproto_cfg_scan_directive_token_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::InvalidTimeout(_) => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TIMEOUT
        }
        MtprotoDirectiveParseError::InvalidMaxConnections(_) => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MAX_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidMinConnections(_) => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MIN_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidTargetId(_) => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TARGET_ID
        }
        MtprotoDirectiveParseError::SpaceExpectedAfterTargetId => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_TARGET_ID_SPACE
        }
        MtprotoDirectiveParseError::ProxyDirectiveExpected => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_PROXY_EXPECTED
        }
        _ => MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INTERNAL,
    }
}

fn mtproto_cfg_parse_directive_step_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::InvalidTimeout(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TIMEOUT
        }
        MtprotoDirectiveParseError::InvalidMaxConnections(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MAX_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidMinConnections(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MIN_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidTargetId(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TARGET_ID
        }
        MtprotoDirectiveParseError::SpaceExpectedAfterTargetId => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TARGET_ID_SPACE
        }
        MtprotoDirectiveParseError::ProxyDirectiveExpected => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXY_EXPECTED
        }
        MtprotoDirectiveParseError::TooManyAuthClusters(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TOO_MANY_AUTH_CLUSTERS
        }
        MtprotoDirectiveParseError::ProxiesIntermixed(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXIES_INTERMIXED
        }
        MtprotoDirectiveParseError::ExpectedSemicolon(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_EXPECTED_SEMICOLON
        }
        _ => MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INTERNAL,
    }
}

fn mtproto_cfg_finalize_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::MissingProxyDirectives => {
            MTPROTO_CFG_FINALIZE_ERR_MISSING_PROXY_DIRECTIVES
        }
        MtprotoDirectiveParseError::NoProxyServersDefined => {
            MTPROTO_CFG_FINALIZE_ERR_NO_PROXY_SERVERS_DEFINED
        }
        _ => MTPROTO_CFG_FINALIZE_ERR_INTERNAL,
    }
}

fn mtproto_old_cluster_from_ffi(
    state: &MtproxyMtprotoOldClusterState,
) -> Option<mtproxy_core::runtime::mtproto::config::MtprotoClusterState> {
    let first_target_index = if state.has_first_target_index != 0 {
        Some(usize::try_from(state.first_target_index).ok()?)
    } else {
        None
    };
    Some(
        mtproxy_core::runtime::mtproto::config::MtprotoClusterState {
            cluster_id: state.cluster_id,
            targets_num: state.targets_num,
            write_targets_num: state.write_targets_num,
            flags: state.flags,
            first_target_index,
        },
    )
}

fn mtproto_old_cluster_to_ffi(
    state: &mtproxy_core::runtime::mtproto::config::MtprotoClusterState,
) -> Option<MtproxyMtprotoOldClusterState> {
    let (has_first_target_index, first_target_index) = if let Some(first) = state.first_target_index
    {
        (1, u32::try_from(first).ok()?)
    } else {
        (0, 0)
    };
    Some(MtproxyMtprotoOldClusterState {
        cluster_id: state.cluster_id,
        targets_num: state.targets_num,
        write_targets_num: state.write_targets_num,
        flags: state.flags,
        first_target_index,
        has_first_target_index,
    })
}

/// Parses one extended lexer token from `mtproto-config`.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_getlex_ext(
    cur: *const c_char,
    len: usize,
    out: *mut MtproxyMtprotoCfgGetlexExtResult,
) -> i32 {
    if out.is_null() {
        return MTPROTO_CFG_GETLEX_EXT_ERR_INVALID_ARGS;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_GETLEX_EXT_ERR_INVALID_ARGS;
    };
    let mut cursor = 0usize;
    let lex = mtproxy_core::runtime::mtproto::config::cfg_getlex_ext(bytes, &mut cursor);
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyMtprotoCfgGetlexExtResult {
        advance: cursor,
        lex,
    };
    MTPROTO_CFG_GETLEX_EXT_OK
}

/// Parses one directive token and scalar argument from `mtproto-config`.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_scan_directive_token(
    cur: *const c_char,
    len: usize,
    min_connections: i64,
    max_connections: i64,
    out: *mut MtproxyMtprotoCfgDirectiveTokenResult,
) -> i32 {
    if out.is_null() {
        return MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_ARGS;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_ARGS;
    };
    match mtproxy_core::runtime::mtproto::config::cfg_scan_directive_token(
        bytes,
        min_connections,
        max_connections,
    ) {
        Ok(preview) => {
            let out_ref = unsafe { &mut *out };
            *out_ref = MtproxyMtprotoCfgDirectiveTokenResult {
                kind: mtproto_directive_token_kind_to_ffi(preview.kind),
                advance: preview.advance,
                value: preview.value,
            };
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK
        }
        Err(err) => mtproto_cfg_scan_directive_token_err_to_code(err),
    }
}

/// Parses one directive step from `mtproto-config` control flow.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`;
/// `cluster_ids` must be readable for `clusters_len` entries when `clusters_len > 0`;
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_parse_directive_step(
    cur: *const c_char,
    len: usize,
    min_connections: i64,
    max_connections: i64,
    cluster_ids: *const i32,
    clusters_len: u32,
    max_clusters: u32,
    out: *mut MtproxyMtprotoCfgDirectiveStepResult,
) -> i32 {
    if out.is_null() {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    let Ok(max_clusters_usize) = usize::try_from(max_clusters) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    if clusters_len_usize > 0 && cluster_ids.is_null() {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    }
    let cluster_ids_slice = if clusters_len_usize == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(cluster_ids, clusters_len_usize) }
    };

    match mtproxy_core::runtime::mtproto::config::cfg_parse_directive_step(
        bytes,
        min_connections,
        max_connections,
        cluster_ids_slice,
        max_clusters_usize,
    ) {
        Ok(step) => {
            let (cluster_decision_kind, cluster_index) =
                if let Some(decision) = step.cluster_apply_decision {
                    let Ok(cluster_index) = i32::try_from(decision.cluster_index) else {
                        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INTERNAL;
                    };
                    (
                        mtproto_cfg_cluster_apply_decision_kind_to_ffi(decision.kind),
                        cluster_index,
                    )
                } else {
                    (0, -1)
                };
            let out_ref = unsafe { &mut *out };
            *out_ref = MtproxyMtprotoCfgDirectiveStepResult {
                kind: mtproto_directive_token_kind_to_ffi(step.kind),
                advance: step.advance,
                value: step.value,
                cluster_decision_kind,
                cluster_index,
            };
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK
        }
        Err(err) => mtproto_cfg_parse_directive_step_err_to_code(err),
    }
}

/// Parses proxy target payload (`host:port;`) and computes cluster/apply mutation.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`;
/// `cluster_ids` must be readable for `clusters_len` entries when `clusters_len > 0`;
/// `last_cluster_state` must be readable when `has_last_cluster_state != 0`;
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
    cur: *const c_char,
    len: usize,
    current_targets: u32,
    max_targets: u32,
    min_connections: i64,
    max_connections: i64,
    cluster_ids: *const i32,
    clusters_len: u32,
    target_dc: i32,
    max_clusters: u32,
    create_targets: i32,
    current_auth_tot_clusters: u32,
    last_cluster_state: *const MtproxyMtprotoOldClusterState,
    has_last_cluster_state: i32,
    out: *mut MtproxyMtprotoCfgParseProxyTargetStepResult,
) -> i32 {
    if out.is_null() {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Ok(current_targets_usize) = usize::try_from(current_targets) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Ok(max_targets_usize) = usize::try_from(max_targets) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Ok(max_clusters_usize) = usize::try_from(max_clusters) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Ok(current_auth_tot_clusters_usize) = usize::try_from(current_auth_tot_clusters) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    if clusters_len_usize > 0 && cluster_ids.is_null() {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    }
    let cluster_ids_slice = if clusters_len_usize == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(cluster_ids, clusters_len_usize) }
    };

    let last_cluster_state = if has_last_cluster_state != 0 {
        if last_cluster_state.is_null() {
            return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
        }
        let state_ref = unsafe { &*last_cluster_state };
        let Some(state) = mtproto_old_cluster_from_ffi(state_ref) else {
            return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
        };
        Some(state)
    } else {
        None
    };

    match mtproxy_core::runtime::mtproto::config::cfg_parse_proxy_target_step(
        bytes,
        current_targets_usize,
        max_targets_usize,
        min_connections,
        max_connections,
        cluster_ids_slice,
        target_dc,
        max_clusters_usize,
        create_targets != 0,
        current_auth_tot_clusters_usize,
        last_cluster_state,
    ) {
        Ok(step) => {
            let Ok(target_index) = u32::try_from(step.target_index) else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let Ok(tot_targets_after) = u32::try_from(step.tot_targets_after) else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let Ok(cluster_index) = i32::try_from(step.cluster_apply_decision.cluster_index) else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let Ok(auth_clusters_after) = u32::try_from(step.auth_clusters_after) else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let Ok(auth_tot_clusters_after) = u32::try_from(step.auth_tot_clusters_after) else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let Some(cluster_state_after) = mtproto_old_cluster_to_ffi(&step.cluster_state_after)
            else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let cluster_targets_action =
                mtproto_cfg_cluster_targets_action_to_ffi(step.cluster_targets_action);
            let cluster_targets_index = if step.cluster_targets_action
                == mtproxy_core::runtime::mtproto::config::MtprotoClusterTargetsAction::SetToTargetIndex
            {
                let Some(first) = step.cluster_state_after.first_target_index else {
                    return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
                };
                let Ok(idx) = u32::try_from(first) else {
                    return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
                };
                idx
            } else {
                0
            };

            let out_ref = unsafe { &mut *out };
            *out_ref = MtproxyMtprotoCfgParseProxyTargetStepResult {
                advance: step.advance,
                target_index,
                host_len: step.target.host_len,
                port: step.target.port,
                min_connections: step.target.min_connections,
                max_connections: step.target.max_connections,
                tot_targets_after,
                cluster_decision_kind: mtproto_cfg_cluster_apply_decision_kind_to_ffi(
                    step.cluster_apply_decision.kind,
                ),
                cluster_index,
                auth_clusters_after,
                auth_tot_clusters_after,
                cluster_state_after,
                cluster_targets_action,
                cluster_targets_index,
            };
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK
        }
        Err(err) => mtproto_cfg_parse_proxy_target_step_err_to_code(err),
    }
}

/// Executes one full `parse_config()` directive pass and returns proxy side-effect plan.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`;
/// `actions` must be writable for `actions_capacity` entries when `actions_capacity > 0`;
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_parse_full_pass(
    cur: *const c_char,
    len: usize,
    default_min_connections: i64,
    default_max_connections: i64,
    create_targets: i32,
    max_clusters: u32,
    max_targets: u32,
    actions: *mut MtproxyMtprotoCfgProxyAction,
    actions_capacity: u32,
    out: *mut MtproxyMtprotoCfgParseFullResult,
) -> i32 {
    if out.is_null() {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    };
    let Ok(max_clusters_usize) = usize::try_from(max_clusters) else {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    };
    let Ok(max_targets_usize) = usize::try_from(max_targets) else {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    };
    let Ok(actions_capacity_usize) = usize::try_from(actions_capacity) else {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    };
    if max_clusters_usize == 0 || max_clusters_usize > MTPROTO_CFG_FULL_PASS_MAX_CLUSTERS {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    }
    if actions_capacity_usize > 0 && actions.is_null() {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    }

    let mut planned_actions = vec![
        mtproxy_core::runtime::mtproto::config::MtprotoProxyTargetPassAction::default();
        actions_capacity_usize
    ];
    let defaults = mtproxy_core::runtime::mtproto::config::MtprotoConfigDefaults {
        min_connections: default_min_connections,
        max_connections: default_max_connections,
    };
    match mtproxy_core::runtime::mtproto::config::cfg_parse_config_full_pass::<
        MTPROTO_CFG_FULL_PASS_MAX_CLUSTERS,
    >(
        bytes,
        defaults,
        create_targets != 0,
        max_clusters_usize,
        max_targets_usize,
        &mut planned_actions,
    ) {
        Ok(result) => {
            if result.actions_len > actions_capacity_usize {
                return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
            }
            if result.actions_len > 0 {
                let out_actions =
                    unsafe { core::slice::from_raw_parts_mut(actions, actions_capacity_usize) };
                for idx in 0..result.actions_len {
                    let action = planned_actions[idx];
                    let step = action.step;
                    let Ok(target_index) = u32::try_from(step.target_index) else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let Ok(tot_targets_after) = u32::try_from(step.tot_targets_after) else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let Ok(cluster_index) =
                        i32::try_from(step.cluster_apply_decision.cluster_index)
                    else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let Ok(auth_clusters_after) = u32::try_from(step.auth_clusters_after) else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let Ok(auth_tot_clusters_after) = u32::try_from(step.auth_tot_clusters_after)
                    else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let Some(cluster_state_after) =
                        mtproto_old_cluster_to_ffi(&step.cluster_state_after)
                    else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let cluster_targets_action =
                        mtproto_cfg_cluster_targets_action_to_ffi(step.cluster_targets_action);
                    let cluster_targets_index = if step.cluster_targets_action
                        == mtproxy_core::runtime::mtproto::config::MtprotoClusterTargetsAction::SetToTargetIndex
                    {
                        let Some(first) = step.cluster_state_after.first_target_index else {
                            return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                        };
                        let Ok(idx) = u32::try_from(first) else {
                            return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                        };
                        idx
                    } else {
                        0
                    };
                    out_actions[idx] = MtproxyMtprotoCfgProxyAction {
                        host_offset: action.host_offset,
                        step: MtproxyMtprotoCfgParseProxyTargetStepResult {
                            advance: step.advance,
                            target_index,
                            host_len: step.target.host_len,
                            port: step.target.port,
                            min_connections: step.target.min_connections,
                            max_connections: step.target.max_connections,
                            tot_targets_after,
                            cluster_decision_kind: mtproto_cfg_cluster_apply_decision_kind_to_ffi(
                                step.cluster_apply_decision.kind,
                            ),
                            cluster_index,
                            auth_clusters_after,
                            auth_tot_clusters_after,
                            cluster_state_after,
                            cluster_targets_action,
                            cluster_targets_index,
                        },
                    };
                }
            }

            let Ok(tot_targets) = u32::try_from(result.tot_targets) else {
                return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
            };
            let Ok(auth_clusters) = u32::try_from(result.auth_clusters) else {
                return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
            };
            let Ok(auth_tot_clusters) = u32::try_from(result.auth_tot_clusters) else {
                return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
            };
            let Ok(actions_len) = u32::try_from(result.actions_len) else {
                return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
            };
            let (has_default_cluster_index, default_cluster_index) =
                if let Some(idx) = result.default_cluster_index {
                    let Ok(idx_u32) = u32::try_from(idx) else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    (1, idx_u32)
                } else {
                    (0, 0)
                };
            let out_ref = unsafe { &mut *out };
            *out_ref = MtproxyMtprotoCfgParseFullResult {
                tot_targets,
                auth_clusters,
                auth_tot_clusters,
                min_connections: result.min_connections,
                max_connections: result.max_connections,
                timeout_seconds: result.timeout_seconds,
                default_cluster_id: result.default_cluster_id,
                have_proxy: i32::from(result.have_proxy),
                default_cluster_index,
                has_default_cluster_index,
                actions_len,
            };
            MTPROTO_CFG_PARSE_FULL_PASS_OK
        }
        Err(err) => mtproto_cfg_parse_full_pass_err_to_code(err),
    }
}

/// Parses a required trailing semicolon from `mtproto-config`.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`; `out_advance` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_expect_semicolon(
    cur: *const c_char,
    len: usize,
    out_advance: *mut usize,
) -> i32 {
    if out_advance.is_null() {
        return MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS;
    };
    let mut cursor = 0usize;
    match mtproxy_core::runtime::mtproto::config::cfg_expect_semicolon(bytes, &mut cursor) {
        Ok(()) => {
            let out_ref = unsafe { &mut *out_advance };
            *out_ref = cursor;
            MTPROTO_CFG_EXPECT_SEMICOLON_OK
        }
        Err(
            mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError::ExpectedSemicolon(
                _,
            ),
        ) => MTPROTO_CFG_EXPECT_SEMICOLON_ERR_EXPECTED,
        Err(_) => MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS,
    }
}

/// Looks up a cluster index by `cluster_id` mirroring `mf_cluster_lookup()`.
///
/// # Safety
/// `cluster_ids` must be readable for `clusters_len` entries when `clusters_len > 0`;
/// `out_cluster_index` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
    cluster_ids: *const i32,
    clusters_len: u32,
    cluster_id: i32,
    force: i32,
    default_cluster_index: i32,
    has_default_cluster_index: i32,
    out_cluster_index: *mut i32,
) -> i32 {
    if out_cluster_index.is_null() {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    }
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    };
    if clusters_len_usize > 0 && cluster_ids.is_null() {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    }
    let default_idx = if has_default_cluster_index != 0 {
        let Ok(idx) = usize::try_from(default_cluster_index) else {
            return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
        };
        if idx >= clusters_len_usize {
            return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
        }
        Some(idx)
    } else {
        None
    };
    let cluster_ids_slice = if clusters_len_usize == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(cluster_ids, clusters_len_usize) }
    };
    let lookup = mtproxy_core::runtime::mtproto::config::mf_cluster_lookup_index(
        cluster_ids_slice,
        cluster_id,
        if force != 0 { default_idx } else { None },
    );
    let out_ref = unsafe { &mut *out_cluster_index };
    let Some(idx) = lookup else {
        *out_ref = -1;
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND;
    };
    let Ok(idx_i32) = i32::try_from(idx) else {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    };
    *out_ref = idx_i32;
    MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK
}

/// Finalizes parse-loop invariants and resolves optional default-cluster index.
///
/// # Safety
/// `cluster_ids` must be readable for `clusters_len` entries when `clusters_len > 0`;
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_finalize(
    have_proxy: i32,
    cluster_ids: *const i32,
    clusters_len: u32,
    default_cluster_id: i32,
    out: *mut MtproxyMtprotoCfgFinalizeResult,
) -> i32 {
    if out.is_null() {
        return MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS;
    }
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS;
    };
    if clusters_len_usize > 0 && cluster_ids.is_null() {
        return MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS;
    }
    let cluster_ids_slice = if clusters_len_usize == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(cluster_ids, clusters_len_usize) }
    };
    match mtproxy_core::runtime::mtproto::config::finalize_parse_config_state(
        have_proxy != 0,
        cluster_ids_slice,
        default_cluster_id,
    ) {
        Ok(default_cluster_index) => {
            let (has_default_cluster_index, default_cluster_index) =
                if let Some(idx) = default_cluster_index {
                    let Ok(idx_u32) = u32::try_from(idx) else {
                        return MTPROTO_CFG_FINALIZE_ERR_INTERNAL;
                    };
                    (1, idx_u32)
                } else {
                    (0, 0)
                };
            let out_ref = unsafe { &mut *out };
            *out_ref = MtproxyMtprotoCfgFinalizeResult {
                default_cluster_index,
                has_default_cluster_index,
            };
            MTPROTO_CFG_FINALIZE_OK
        }
        Err(err) => mtproto_cfg_finalize_err_to_code(err),
    }
}

fn md5_digest_impl(input: &[u8], out: &mut [u8; DIGEST_MD5_LEN]) -> bool {
    let mut hasher = Md5::new();
    hasher.update(input);
    out.copy_from_slice(&hasher.finalize());
    true
}

fn sha1_digest_impl(input: &[u8], out: &mut [u8; DIGEST_SHA1_LEN]) -> bool {
    let mut hasher = Sha1::new();
    hasher.update(input);
    out.copy_from_slice(&hasher.finalize());
    true
}

fn sha256_digest_impl(input: &[u8], out: &mut [u8; DIGEST_SHA256_LEN]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(input);
    out.copy_from_slice(&hasher.finalize());
    true
}

fn i64_to_i32_saturating(value: i64) -> i32 {
    if value > i64::from(i32::MAX) {
        i32::MAX
    } else if value < i64::from(i32::MIN) {
        i32::MIN
    } else {
        value as i32
    }
}

fn atomic_dec_saturating(counter: &AtomicI64) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        Some(if value > 0 { value - 1 } else { 0 })
    });
}

#[inline]
fn rdtsc_now() -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { core::arch::x86_64::_rdtsc() as i64 }
    }
    #[cfg(all(not(target_arch = "x86_64"), target_arch = "x86"))]
    {
        unsafe { core::arch::x86::_rdtsc() as i64 }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let mut ts = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { clock_gettime(CLOCK_MONOTONIC_ID, &raw mut ts) } < 0 {
            0
        } else {
            (ts.tv_sec as i64)
                .saturating_mul(1_000_000_000_i64)
                .saturating_add(ts.tv_nsec as i64)
        }
    }
}

fn refresh_aes_nonce_seed(rand_buf: &mut [u8; 64]) -> bool {
    let mut seeded = false;
    if let Ok(mut urandom) = fs::File::open("/dev/urandom") {
        if urandom.read_exact(&mut rand_buf[..16]).is_ok() {
            seeded = true;
        }
    }
    if !seeded && !crypto_rand_fill(&mut rand_buf[..16]) {
        return false;
    }

    let mut seed: c_long = 0;
    let seed_len = core::mem::size_of::<c_long>();
    unsafe {
        core::ptr::copy_nonoverlapping(rand_buf.as_ptr(), (&raw mut seed).cast::<u8>(), seed_len);
        seed ^= lrand48_j();
        core::ptr::copy_nonoverlapping(
            (&raw const seed).cast::<u8>(),
            rand_buf.as_mut_ptr(),
            seed_len,
        );
        srand48(seed);
    }
    true
}

fn write_md5_hex(input: &[u8], out: &mut [u8; 33]) -> bool {
    let mut digest = [0u8; DIGEST_MD5_LEN];
    if !md5_digest_impl(input, &mut digest) {
        return false;
    }
    for (idx, byte) in digest.iter().copied().enumerate() {
        out[idx * 2] = HEX_LOWER[usize::from(byte >> 4)];
        out[idx * 2 + 1] = HEX_LOWER[usize::from(byte & 0x0f)];
    }
    out[32] = 0;
    true
}

/// Fetches current net-crypto-aes allocation counters.
///
/// # Safety
/// Output pointers may be null; non-null pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_fetch_stat(
    allocated_aes_crypto: *mut i32,
    allocated_aes_crypto_temp: *mut i32,
) -> i32 {
    if !allocated_aes_crypto.is_null() {
        unsafe {
            *allocated_aes_crypto =
                i64_to_i32_saturating(AES_ALLOCATED_CRYPTO.load(Ordering::Acquire));
        }
    }
    if !allocated_aes_crypto_temp.is_null() {
        unsafe {
            *allocated_aes_crypto_temp =
                i64_to_i32_saturating(AES_ALLOCATED_CRYPTO_TEMP.load(Ordering::Acquire));
        }
    }
    0
}

/// Initializes per-connection AES state for CBC/CTR mode.
///
/// # Safety
/// `conn_crypto_slot` must be a writable pointer to a `void *` storage slot.
/// `key_data` must be readable for `key_data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_conn_init(
    conn_crypto_slot: *mut *mut c_void,
    key_data: *const MtproxyAesKeyData,
    key_data_len: i32,
    use_ctr_mode: i32,
) -> i32 {
    if conn_crypto_slot.is_null() || key_data.is_null() {
        return -1;
    }
    let Ok(expected_len) = i32::try_from(core::mem::size_of::<MtproxyAesKeyData>()) else {
        return -1;
    };
    if key_data_len != expected_len {
        return -1;
    }
    let slot = unsafe { &mut *conn_crypto_slot };
    if !slot.is_null() {
        return -1;
    }

    let key = unsafe { &*key_data };
    let cipher_kind = if use_ctr_mode != 0 {
        AESNI_CIPHER_AES_256_CTR
    } else {
        AESNI_CIPHER_AES_256_CBC
    };
    let read_is_encrypt = if use_ctr_mode != 0 { 1 } else { 0 };
    let write_is_encrypt = 1;

    let mut read_ctx: *mut c_void = core::ptr::null_mut();
    let mut write_ctx: *mut c_void = core::ptr::null_mut();
    let read_rc = unsafe {
        mtproxy_ffi_aesni_ctx_init(
            cipher_kind,
            key.read_key.as_ptr(),
            key.read_iv.as_ptr(),
            read_is_encrypt,
            &raw mut read_ctx,
        )
    };
    if read_rc != 0 {
        return -1;
    }
    let write_rc = unsafe {
        mtproxy_ffi_aesni_ctx_init(
            cipher_kind,
            key.write_key.as_ptr(),
            key.write_iv.as_ptr(),
            write_is_encrypt,
            &raw mut write_ctx,
        )
    };
    if write_rc != 0 {
        let _ = unsafe { mtproxy_ffi_aesni_ctx_free(read_ctx) };
        return -1;
    }

    let ctx = MtproxyAesCryptoCtx {
        read_aeskey: read_ctx,
        write_aeskey: write_ctx,
    };
    *slot = Box::into_raw(Box::new(ctx)).cast::<c_void>();
    AES_ALLOCATED_CRYPTO.fetch_add(1, Ordering::AcqRel);
    0
}

/// Releases per-connection AES state and optional temporary crypto blob.
///
/// # Safety
/// Non-null slot pointers must be writable and contain pointers allocated via Rust FFI exports.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_conn_free(
    conn_crypto_slot: *mut *mut c_void,
    conn_crypto_temp_slot: *mut *mut c_void,
) -> i32 {
    if !conn_crypto_slot.is_null() {
        let slot_ref = unsafe { &mut *conn_crypto_slot };
        let crypto_ptr = *slot_ref;
        if !crypto_ptr.is_null() {
            let ctx = unsafe { Box::from_raw(crypto_ptr.cast::<MtproxyAesCryptoCtx>()) };
            let _ = unsafe { mtproxy_ffi_aesni_ctx_free(ctx.read_aeskey) };
            let _ = unsafe { mtproxy_ffi_aesni_ctx_free(ctx.write_aeskey) };
            *slot_ref = core::ptr::null_mut();
            atomic_dec_saturating(&AES_ALLOCATED_CRYPTO);
        }
    }

    if !conn_crypto_temp_slot.is_null() {
        let temp_slot_ref = unsafe { &mut *conn_crypto_temp_slot };
        let temp_ptr = *temp_slot_ref;
        if !temp_ptr.is_null() {
            unsafe {
                free(temp_ptr);
            }
            *temp_slot_ref = core::ptr::null_mut();
            atomic_dec_saturating(&AES_ALLOCATED_CRYPTO_TEMP);
        }
    }

    0
}

/// Loads secret-file bytes and computes MD5 hex fingerprint used by C stats output.
///
/// # Safety
/// All non-null output pointers must reference writable storage matching argument sizes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_load_pwd_file(
    filename: *const c_char,
    pwd_config_buf: *mut u8,
    pwd_config_capacity: i32,
    pwd_config_len_out: *mut i32,
    pwd_config_md5_out: *mut c_char,
    main_secret: *mut MtproxyAesSecret,
) -> i32 {
    if pwd_config_buf.is_null()
        || pwd_config_len_out.is_null()
        || pwd_config_md5_out.is_null()
        || main_secret.is_null()
    {
        return -1;
    }

    let Ok(buf_capacity) = usize::try_from(pwd_config_capacity) else {
        return -1;
    };
    if buf_capacity < (MAX_PWD_CONFIG_LEN + 4) {
        return -1;
    }

    let file_name = if filename.is_null() {
        DEFAULT_PWD_FILE.to_owned()
    } else {
        unsafe { CStr::from_ptr(filename) }
            .to_string_lossy()
            .into_owned()
    };

    {
        let mut state = AES_NONCE_RAND_BUF
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !refresh_aes_nonce_seed(&mut state) {
            unsafe {
                (*main_secret).secret_len = 0;
            }
            return -1;
        }
    }

    let mut file = match fs::File::open(&file_name) {
        Ok(file) => file,
        Err(_) => return i32::MIN,
    };
    let mut read_buf = vec![0u8; MAX_PWD_CONFIG_LEN + 1];
    let read_len = match file.read(&mut read_buf) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };
    if read_len > MAX_PWD_CONFIG_LEN {
        unsafe {
            *pwd_config_len_out = 0;
        }
        return -1;
    }

    let cfg_out = unsafe { core::slice::from_raw_parts_mut(pwd_config_buf, buf_capacity) };
    cfg_out[..read_len].copy_from_slice(&read_buf[..read_len]);
    cfg_out[read_len..read_len + 4].fill(0);
    unsafe {
        *pwd_config_len_out = i32::try_from(read_len).unwrap_or(i32::MAX);
    }

    if !(MIN_PWD_LEN..=MAX_PWD_LEN).contains(&read_len) {
        return -1;
    }

    let md5_out = unsafe { core::slice::from_raw_parts_mut(pwd_config_md5_out.cast::<u8>(), 33) };
    let md5_out_ref = unsafe { &mut *md5_out.as_mut_ptr().cast::<[u8; 33]>() };
    if !write_md5_hex(&read_buf[..read_len], md5_out_ref) {
        return -1;
    }

    let secret_ref = unsafe { &mut *main_secret };
    secret_ref.secret.fill(0);
    secret_ref.secret[..read_len].copy_from_slice(&read_buf[..read_len]);
    secret_ref.secret_len = i32::try_from(read_len).unwrap_or(i32::MAX);

    1
}

/// Produces a 16-byte handshake nonce equivalent to C flow based on mutable random state.
///
/// # Safety
/// `out` must point to at least 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_generate_nonce(out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out.cast::<[u8; 16]>() };

    let mut rand_buf = AES_NONCE_RAND_BUF
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if rand_buf[..16].iter().all(|b| *b == 0) && !refresh_aes_nonce_seed(&mut rand_buf) {
        return -1;
    }

    let x = unsafe { lrand48_j() } as i32;
    rand_buf[16..20].copy_from_slice(&x.to_ne_bytes());
    let y = unsafe { lrand48_j() } as i32;
    rand_buf[20..24].copy_from_slice(&y.to_ne_bytes());
    rand_buf[24..32].copy_from_slice(&rdtsc_now().to_ne_bytes());

    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { clock_gettime(CLOCK_REALTIME_ID, &raw mut ts) } < 0 {
        return -1;
    }
    rand_buf[32..36].copy_from_slice(&(ts.tv_sec as i32).to_ne_bytes());
    rand_buf[36..40].copy_from_slice(&(ts.tv_nsec as i32).to_ne_bytes());

    let mut ctr = i32::from_ne_bytes([rand_buf[40], rand_buf[41], rand_buf[42], rand_buf[43]]);
    ctr = ctr.wrapping_add(1);
    rand_buf[40..44].copy_from_slice(&ctr.to_ne_bytes());

    let mut digest = [0u8; DIGEST_MD5_LEN];
    if !md5_digest_impl(&rand_buf[..44], &mut digest) {
        return -1;
    }
    out_ref.copy_from_slice(&digest);
    0
}

/// Allocates temporary crypto blob storage tracked by Rust-side stats.
///
/// # Safety
/// Returned pointer must be released by `mtproxy_ffi_crypto_free_temp`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_alloc_temp(len: i32) -> *mut c_void {
    if len < 0 {
        return core::ptr::null_mut();
    }
    let Ok(requested) = usize::try_from(len) else {
        return core::ptr::null_mut();
    };
    let alloc_len = requested.max(1);
    let ptr = unsafe { malloc(alloc_len) };
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    AES_ALLOCATED_CRYPTO_TEMP.fetch_add(1, Ordering::AcqRel);
    ptr
}

/// Zeroes (optionally) and frees temporary crypto blob storage.
///
/// # Safety
/// `ptr` must be null or returned by `mtproxy_ffi_crypto_alloc_temp`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_free_temp(ptr: *mut c_void, len: i32) -> i32 {
    if ptr.is_null() {
        return 0;
    }
    if len > 0 {
        let Ok(zero_len) = usize::try_from(len) else {
            return -1;
        };
        unsafe { core::ptr::write_bytes(ptr.cast::<u8>(), 0, zero_len) };
    }
    unsafe {
        free(ptr);
    }
    atomic_dec_saturating(&AES_ALLOCATED_CRYPTO_TEMP);
    0
}

/// Initializes shared DH params selector exactly once and returns C-compatible status.
///
/// # Safety
/// `out_dh_params_select` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_init_params(out_dh_params_select: *mut i32) -> i32 {
    if out_dh_params_select.is_null() {
        return -1;
    }
    let current = i64_to_i32_saturating(DH_PARAMS_SELECT_INIT.load(Ordering::Acquire));
    if current > 0 {
        unsafe {
            *out_dh_params_select = current;
        }
        return 0;
    }

    let select = mtproxy_ffi_crypto_dh_get_params_select();
    if select <= 0 {
        return -1;
    }
    match DH_PARAMS_SELECT_INIT.compare_exchange(
        0,
        i64::from(select),
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            unsafe {
                *out_dh_params_select = select;
            }
            1
        }
        Err(existing) => {
            unsafe {
                *out_dh_params_select = i64_to_i32_saturating(existing);
            }
            0
        }
    }
}

/// Returns cumulative DH round counters used by C stats output.
///
/// # Safety
/// `out_rounds` must be writable for three 64-bit integers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_fetch_tot_rounds(out_rounds: *mut i64) -> i32 {
    if out_rounds.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out_rounds.cast::<[i64; 3]>() };
    out_ref[0] = DH_TOT_ROUNDS_0.load(Ordering::Acquire);
    out_ref[1] = DH_TOT_ROUNDS_1.load(Ordering::Acquire);
    out_ref[2] = DH_TOT_ROUNDS_2.load(Ordering::Acquire);
    0
}

/// Performs DH first round and fills temporary DH state struct for C runtime.
///
/// # Safety
/// `g_a` and `dh_params` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_first_round_stateful(
    g_a: *mut u8,
    dh_params: *mut MtproxyCryptoTempDhParams,
    dh_params_select: i32,
) -> i32 {
    if g_a.is_null() || dh_params.is_null() || dh_params_select <= 0 {
        return -1;
    }
    let dh_params_ref = unsafe { &mut *dh_params };
    let rc = unsafe { mtproxy_ffi_crypto_dh_first_round(g_a, dh_params_ref.a.as_mut_ptr()) };
    if rc != 1 {
        return -1;
    }
    dh_params_ref.dh_params_select = dh_params_select;
    dh_params_ref.magic = CRYPTO_TEMP_DH_PARAMS_MAGIC;
    DH_TOT_ROUNDS_0.fetch_add(1, Ordering::AcqRel);
    1
}

/// Performs DH second round and updates cumulative round stats on success.
///
/// # Safety
/// `g_ab`, `g_a`, and `g_b` must point to readable/writable 256-byte buffers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_second_round_stateful(
    g_ab: *mut u8,
    g_a: *mut u8,
    g_b: *const u8,
) -> i32 {
    let rc = unsafe { mtproxy_ffi_crypto_dh_second_round(g_ab, g_a, g_b) };
    if rc > 0 {
        DH_TOT_ROUNDS_1.fetch_add(1, Ordering::AcqRel);
    }
    rc
}

/// Performs DH third round using stored temporary exponent and tracks successful rounds.
///
/// # Safety
/// `g_ab`, `g_b`, and `dh_params` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_third_round_stateful(
    g_ab: *mut u8,
    g_b: *const u8,
    dh_params: *const MtproxyCryptoTempDhParams,
) -> i32 {
    if dh_params.is_null() {
        return -1;
    }
    let dh_params_ref = unsafe { &*dh_params };
    let rc = unsafe { mtproxy_ffi_crypto_dh_third_round(g_ab, g_b, dh_params_ref.a.as_ptr()) };
    if rc > 0 {
        DH_TOT_ROUNDS_2.fetch_add(1, Ordering::AcqRel);
    }
    rc
}

fn crypto_dh_is_good_rpc_dh_bin_impl(data: &[u8], prime_prefix: &[u8]) -> i32 {
    if data.len() < 8 || prime_prefix.len() < 8 {
        return -1;
    }
    if data[..8].iter().all(|b| *b == 0) {
        return 0;
    }
    for i in 0..8 {
        if data[i] > prime_prefix[i] {
            return 0;
        }
        if data[i] < prime_prefix[i] {
            return 1;
        }
    }
    0
}

#[allow(clippy::too_many_arguments)]
fn crypto_aes_create_keys_impl(
    out: &mut MtproxyAesKeyData,
    am_client: i32,
    nonce_server: &[u8; 16],
    nonce_client: &[u8; 16],
    client_timestamp: i32,
    server_ip: u32,
    server_port: u16,
    server_ipv6: &[u8; 16],
    client_ip: u32,
    client_port: u16,
    client_ipv6: &[u8; 16],
    secret: &[u8],
    temp_key: &[u8],
) -> i32 {
    if secret.len() < MIN_PWD_LEN || secret.len() > MAX_PWD_LEN {
        return -1;
    }
    if server_ip == 0 {
        if client_ip != 0 {
            return -1;
        }
    } else if client_ip == 0 {
        return -1;
    }

    let mut material = [0u8; AES_CREATE_KEYS_MAX_STR_LEN];
    material[..16].copy_from_slice(nonce_server);
    material[16..32].copy_from_slice(nonce_client);
    material[32..36].copy_from_slice(&client_timestamp.to_ne_bytes());
    material[36..40].copy_from_slice(&server_ip.to_ne_bytes());
    material[40..42].copy_from_slice(&client_port.to_ne_bytes());
    material[42..48].copy_from_slice(if am_client != 0 { b"CLIENT" } else { b"SERVER" });
    material[48..52].copy_from_slice(&client_ip.to_ne_bytes());
    material[52..54].copy_from_slice(&server_port.to_ne_bytes());

    let secret_len = secret.len();
    material[54..54 + secret_len].copy_from_slice(secret);
    material[54 + secret_len..70 + secret_len].copy_from_slice(nonce_server);
    let mut str_len = 70 + secret_len;

    if server_ip == 0 {
        material[str_len..str_len + 16].copy_from_slice(client_ipv6);
        material[str_len + 16..str_len + 32].copy_from_slice(server_ipv6);
        str_len += 32;
    }

    material[str_len..str_len + 16].copy_from_slice(nonce_client);
    str_len += 16;

    let first_len = str_len.min(temp_key.len());
    for i in 0..first_len {
        material[i] ^= temp_key[i];
    }
    if temp_key.len() > first_len {
        material[first_len..temp_key.len()].copy_from_slice(&temp_key[first_len..]);
    }
    if str_len < temp_key.len() {
        str_len = temp_key.len();
    }

    let mut md5_out = [0u8; DIGEST_MD5_LEN];
    let mut sha1_out = [0u8; DIGEST_SHA1_LEN];
    if !md5_digest_impl(&material[1..str_len], &mut md5_out) {
        return -1;
    }
    out.write_key[..DIGEST_MD5_LEN].copy_from_slice(&md5_out);
    if !sha1_digest_impl(&material[..str_len], &mut sha1_out) {
        return -1;
    }
    out.write_key[12..32].copy_from_slice(&sha1_out);
    if !md5_digest_impl(&material[2..str_len], &mut md5_out) {
        return -1;
    }
    out.write_iv.copy_from_slice(&md5_out);

    for (i, mask) in AES_ROLE_XOR_MASK.iter().copied().enumerate() {
        material[42 + i] ^= mask;
    }

    if !md5_digest_impl(&material[1..str_len], &mut md5_out) {
        return -1;
    }
    out.read_key[..DIGEST_MD5_LEN].copy_from_slice(&md5_out);
    if !sha1_digest_impl(&material[..str_len], &mut sha1_out) {
        return -1;
    }
    out.read_key[12..32].copy_from_slice(&sha1_out);
    if !md5_digest_impl(&material[2..str_len], &mut md5_out) {
        return -1;
    }
    out.read_iv.copy_from_slice(&md5_out);

    material[..str_len].fill(0);
    1
}

/// Validates first bytes of peer DH value against canonical prime prefix.
///
/// # Safety
/// `data` and `prime_prefix` must point to readable slices when lengths are non-zero.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin(
    data: *const u8,
    len: usize,
    prime_prefix: *const u8,
    prime_prefix_len: usize,
) -> i32 {
    if data.is_null() || prime_prefix.is_null() {
        return -1;
    }
    if len < 8 || prime_prefix_len < 8 {
        return -1;
    }
    let data_ref = unsafe { core::slice::from_raw_parts(data, len) };
    let prime_ref = unsafe { core::slice::from_raw_parts(prime_prefix, prime_prefix_len) };
    crypto_dh_is_good_rpc_dh_bin_impl(data_ref, prime_ref)
}

/// Derives AES session keys and IVs exactly like C `aes_create_keys`.
///
/// # Safety
/// All pointer arguments must reference writable/readable buffers of the documented size.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_create_keys(
    out: *mut MtproxyAesKeyData,
    am_client: i32,
    nonce_server: *const u8,
    nonce_client: *const u8,
    client_timestamp: i32,
    server_ip: u32,
    server_port: u16,
    server_ipv6: *const u8,
    client_ip: u32,
    client_port: u16,
    client_ipv6: *const u8,
    secret: *const u8,
    secret_len: i32,
    temp_key: *const u8,
    temp_key_len: i32,
) -> i32 {
    if out.is_null()
        || nonce_server.is_null()
        || nonce_client.is_null()
        || server_ipv6.is_null()
        || client_ipv6.is_null()
    {
        return -1;
    }
    let Ok(secret_count) = usize::try_from(secret_len) else {
        return -1;
    };
    if !(MIN_PWD_LEN..=MAX_PWD_LEN).contains(&secret_count) || secret.is_null() {
        return -1;
    }
    let Ok(temp_count_raw) = usize::try_from(temp_key_len) else {
        return -1;
    };
    let temp_count = temp_count_raw.min(AES_CREATE_KEYS_MAX_STR_LEN);
    if temp_count > 0 && temp_key.is_null() {
        return -1;
    }

    let out_ref = unsafe { &mut *out };
    let nonce_server_ref = unsafe { &*nonce_server.cast::<[u8; 16]>() };
    let nonce_client_ref = unsafe { &*nonce_client.cast::<[u8; 16]>() };
    let server_ipv6_ref = unsafe { &*server_ipv6.cast::<[u8; 16]>() };
    let client_ipv6_ref = unsafe { &*client_ipv6.cast::<[u8; 16]>() };
    let secret_ref = unsafe { core::slice::from_raw_parts(secret, secret_count) };
    let temp_ref = if temp_count == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(temp_key, temp_count) }
    };

    crypto_aes_create_keys_impl(
        out_ref,
        am_client,
        nonce_server_ref,
        nonce_client_ref,
        client_timestamp,
        server_ip,
        server_port,
        server_ipv6_ref,
        client_ip,
        client_port,
        client_ipv6_ref,
        secret_ref,
        temp_ref,
    )
}

/// AES-CBC/CTR wrapper used by `crypto/aesni256.c`.
///
/// # Safety
/// `evp_ctx` must be a valid context returned by `mtproxy_ffi_aesni_ctx_init`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_aesni_crypt(
    evp_ctx: *mut c_void,
    input: *const u8,
    output: *mut u8,
    size: i32,
) -> i32 {
    if evp_ctx.is_null() || size < 0 {
        return -1;
    }
    let Ok(size_usize) = usize::try_from(size) else {
        return -1;
    };
    if size_usize > 0 && (input.is_null() || output.is_null()) {
        return -1;
    }
    if size_usize > 0 && input != output.cast_const() {
        unsafe { core::ptr::copy(input, output, size_usize) };
    }
    let output_ref = if size_usize == 0 {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(output, size_usize) }
    };
    let ctx = unsafe { &mut *evp_ctx.cast::<AesniCipherCtx>() };
    if ctx.crypt_in_place(output_ref) {
        0
    } else {
        -2
    }
}

#[derive(Clone)]
struct BnOwned(BigUint);

impl BnOwned {
    fn from_bin(bytes: &[u8]) -> Self {
        Self(BigUint::from_bytes_be(bytes))
    }

    fn from_hex_nul(hex_nul: &[u8]) -> Option<Self> {
        let Some((&0, hex_bytes)) = hex_nul.split_last() else {
            return None;
        };
        let hex = core::str::from_utf8(hex_bytes).ok()?;
        let value = BigUint::parse_bytes(hex.as_bytes(), 16)?;
        Some(Self(value))
    }

    fn as_biguint(&self) -> &BigUint {
        &self.0
    }
}

fn bn_num_bytes(value: &BnOwned) -> Option<usize> {
    let bits = value.as_biguint().bits();
    let bytes = bits.saturating_add(7) / 8;
    usize::try_from(bytes).ok()
}

fn bn_write_be_padded(value: &BnOwned, out: &mut [u8]) -> bool {
    let bytes = value.as_biguint().to_bytes_be();
    if bytes.len() > out.len() {
        return false;
    }
    let start = out.len() - bytes.len();
    out[..start].fill(0);
    out[start..].copy_from_slice(&bytes);
    true
}

fn mod_add(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    (a + b) % modulus
}

fn mod_sub(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % modulus
    } else {
        let diff = (b - a) % modulus;
        if diff.is_zero() {
            BigUint::zero()
        } else {
            modulus - diff
        }
    }
}

fn mod_mul(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    (a * b) % modulus
}

fn mod_inverse(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    if modulus.is_zero() {
        return None;
    }
    let modulus_i = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = modulus_i.clone();
    let mut new_r = BigInt::from_biguint(Sign::Plus, value.clone() % modulus);

    while !new_r.is_zero() {
        let quotient = &r / &new_r;
        let next_t = &t - (&quotient * &new_t);
        let next_r = &r - (&quotient * &new_r);
        t = new_t;
        new_t = next_t;
        r = new_r;
        new_r = next_r;
    }

    if r != BigInt::one() {
        return None;
    }

    let mut normalized = t % &modulus_i;
    if normalized.sign() == Sign::Minus {
        normalized += &modulus_i;
    }
    normalized.to_biguint()
}

fn crypto_dh_modexp(
    base_bytes: Option<&[u8; DH_KEY_BYTES]>,
    exponent: &[u8; DH_KEY_BYTES],
    out: &mut [u8; DH_KEY_BYTES],
) -> bool {
    let modulus = BnOwned::from_bin(&RPC_DH_PRIME_BIN);
    let exponent_bn = BigUint::from_bytes_be(exponent);
    let base_bn = if let Some(bytes) = base_bytes {
        BigUint::from_bytes_be(bytes)
    } else {
        BigUint::from(3u8)
    };
    let out_bn = BnOwned(base_bn.modpow(&exponent_bn, modulus.as_biguint()));
    let Some(out_len) = bn_num_bytes(&out_bn) else {
        return false;
    };
    if !(DH_MOD_MIN_LEN..=DH_MOD_MAX_LEN).contains(&out_len) {
        return false;
    }
    bn_write_be_padded(&out_bn, out)
}

fn crypto_rand_fill(out: &mut [u8]) -> bool {
    if out.is_empty() {
        return true;
    }
    rustls_default_provider().secure_random.fill(out).is_ok()
}

fn crypto_dh_first_round_impl(g_a: &mut [u8; DH_KEY_BYTES], a_out: &mut [u8; DH_KEY_BYTES]) -> i32 {
    loop {
        if !crypto_rand_fill(a_out) {
            return -1;
        }
        if !crypto_dh_modexp(None, a_out, g_a) {
            return -1;
        }
        let verdict =
            crypto_dh_is_good_rpc_dh_bin_impl(g_a, &RPC_DH_PRIME_BIN[..DH_GOOD_PREFIX_BYTES]);
        if verdict == 1 {
            return 1;
        }
        if verdict < 0 {
            return -1;
        }
    }
}

fn tls_get_y2(x: &BnOwned, modulus: &BnOwned) -> BnOwned {
    let p = modulus.as_biguint();
    let x_ref = x.as_biguint();
    let mut y = mod_add(x_ref, &BigUint::from(486_662_u32), p);
    y = mod_mul(&y, x_ref, p);
    y = mod_add(&y, &BigUint::one(), p);
    y = mod_mul(&y, x_ref, p);
    BnOwned(y)
}

fn tls_get_double_x(x: &BnOwned, modulus: &BnOwned) -> Option<BnOwned> {
    let p = modulus.as_biguint();
    let y2 = tls_get_y2(x, modulus);
    let denominator = mod_mul(y2.as_biguint(), &BigUint::from(4u8), p);
    let x_sq = mod_mul(x.as_biguint(), x.as_biguint(), p);
    let x_sq_minus_one = mod_sub(&x_sq, &BigUint::one(), p);
    let numerator = mod_mul(&x_sq_minus_one, &x_sq_minus_one, p);
    let denominator_inv = mod_inverse(&denominator, p)?;
    Some(BnOwned(mod_mul(&numerator, &denominator_inv, p)))
}

fn crypto_tls_generate_public_key_impl(out: &mut [u8; TLS_REQUEST_PUBLIC_KEY_BYTES]) -> i32 {
    let Some(modulus) = BnOwned::from_hex_nul(TLS_X25519_MOD_HEX) else {
        return -1;
    };
    let Some(pow) = BnOwned::from_hex_nul(TLS_X25519_POW_HEX) else {
        return -1;
    };
    let mut x;
    let p = modulus.as_biguint();
    let one = BigUint::one();

    loop {
        if !crypto_rand_fill(out) {
            return -1;
        }
        out[31] &= 127;
        let mut candidate = BnOwned(BigUint::from_bytes_be(out));
        candidate = BnOwned(mod_mul(candidate.as_biguint(), candidate.as_biguint(), p));
        let y = tls_get_y2(&candidate, &modulus);
        let r = y.as_biguint().modpow(pow.as_biguint(), p);
        if r == one {
            x = candidate;
            break;
        }
    }

    for _ in 0..3 {
        let Some(next_x) = tls_get_double_x(&x, &modulus) else {
            return -1;
        };
        x = next_x;
    }

    let Some(num_size) = bn_num_bytes(&x) else {
        return -1;
    };
    if num_size > TLS_REQUEST_PUBLIC_KEY_BYTES {
        return -1;
    }
    out[..TLS_REQUEST_PUBLIC_KEY_BYTES - num_size].fill(0);
    let bytes = x.as_biguint().to_bytes_be();
    out[TLS_REQUEST_PUBLIC_KEY_BYTES - num_size..].copy_from_slice(&bytes);
    for i in 0..(TLS_REQUEST_PUBLIC_KEY_BYTES / 2) {
        out.swap(i, TLS_REQUEST_PUBLIC_KEY_BYTES - 1 - i);
    }
    0
}

/// Fills output with cryptographically strong random bytes from Rustls provider.
///
/// # Safety
/// `out` must point to writable memory for `len` bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_rand_bytes(out: *mut u8, len: i32) -> i32 {
    if len < 0 {
        return -1;
    }
    let Ok(size) = usize::try_from(len) else {
        return -1;
    };
    if size > 0 && out.is_null() {
        return -1;
    }
    let out_ref = if size == 0 {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(out, size) }
    };
    if crypto_rand_fill(out_ref) {
        0
    } else {
        -1
    }
}

/// Generates a 32-byte public key used by TLS-obfuscated transport setup.
///
/// # Safety
/// `out` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_tls_generate_public_key(out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out.cast::<[u8; TLS_REQUEST_PUBLIC_KEY_BYTES]>() };
    crypto_tls_generate_public_key_impl(out_ref)
}

/// Returns current DH params selector hash used by C runtime checks.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crypto_dh_get_params_select() -> i32 {
    DH_PARAMS_SELECT
}

/// Performs DH first round: generates random exponent `a_out` and `g_a = g^a mod p`.
///
/// # Safety
/// `g_a` and `a_out` must point to writable 256-byte buffers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_first_round(g_a: *mut u8, a_out: *mut u8) -> i32 {
    if g_a.is_null() || a_out.is_null() {
        return -1;
    }
    let g_a_ref = unsafe { &mut *g_a.cast::<[u8; DH_KEY_BYTES]>() };
    let a_out_ref = unsafe { &mut *a_out.cast::<[u8; DH_KEY_BYTES]>() };
    crypto_dh_first_round_impl(g_a_ref, a_out_ref)
}

/// Performs DH second round for server mode.
///
/// # Safety
/// `g_ab`, `g_a`, `g_b` must point to 256-byte buffers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_second_round(
    g_ab: *mut u8,
    g_a: *mut u8,
    g_b: *const u8,
) -> i32 {
    if g_ab.is_null() || g_a.is_null() || g_b.is_null() {
        return -1;
    }
    let g_ab_ref = unsafe { &mut *g_ab.cast::<[u8; DH_KEY_BYTES]>() };
    let g_a_ref = unsafe { &mut *g_a.cast::<[u8; DH_KEY_BYTES]>() };
    let g_b_ref = unsafe { &*g_b.cast::<[u8; DH_KEY_BYTES]>() };
    let verdict =
        crypto_dh_is_good_rpc_dh_bin_impl(g_b_ref, &RPC_DH_PRIME_BIN[..DH_GOOD_PREFIX_BYTES]);
    if verdict <= 0 {
        return if verdict == 0 { 0 } else { -1 };
    }
    let mut a = [0u8; DH_KEY_BYTES];
    if crypto_dh_first_round_impl(g_a_ref, &mut a) < 0 {
        return -1;
    }
    let ok = crypto_dh_modexp(Some(g_b_ref), &a, g_ab_ref);
    a.fill(0);
    if ok {
        DH_KEY_BYTES as i32
    } else {
        -1
    }
}

/// Performs DH third round for client mode.
///
/// # Safety
/// `g_ab`, `g_b`, `a` must point to 256-byte buffers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_third_round(
    g_ab: *mut u8,
    g_b: *const u8,
    a: *const u8,
) -> i32 {
    if g_ab.is_null() || g_b.is_null() || a.is_null() {
        return -1;
    }
    let g_ab_ref = unsafe { &mut *g_ab.cast::<[u8; DH_KEY_BYTES]>() };
    let g_b_ref = unsafe { &*g_b.cast::<[u8; DH_KEY_BYTES]>() };
    let a_ref = unsafe { &*a.cast::<[u8; DH_KEY_BYTES]>() };
    let verdict =
        crypto_dh_is_good_rpc_dh_bin_impl(g_b_ref, &RPC_DH_PRIME_BIN[..DH_GOOD_PREFIX_BYTES]);
    if verdict <= 0 {
        return if verdict == 0 { 0 } else { -1 };
    }
    if crypto_dh_modexp(Some(g_b_ref), a_ref, g_ab_ref) {
        DH_KEY_BYTES as i32
    } else {
        -1
    }
}

/// Initializes AES context for AES-256-CBC/CTR with disabled padding.
///
/// # Safety
/// `key`, `iv`, and `out_ctx` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_aesni_ctx_init(
    cipher_kind: i32,
    key: *const u8,
    iv: *const u8,
    is_encrypt: i32,
    out_ctx: *mut *mut c_void,
) -> i32 {
    if key.is_null() || iv.is_null() || out_ctx.is_null() {
        return -1;
    }
    let key_ref = unsafe { &*key.cast::<[u8; 32]>() };
    let iv_ref = unsafe { &*iv.cast::<[u8; 16]>() };
    let ctx = match cipher_kind {
        AESNI_CIPHER_AES_256_CBC => {
            if is_encrypt != 0 {
                AesniCipherCtx::Aes256CbcEncrypt(cbc::Encryptor::<Aes256>::new(
                    key_ref.into(),
                    iv_ref.into(),
                ))
            } else {
                AesniCipherCtx::Aes256CbcDecrypt(cbc::Decryptor::<Aes256>::new(
                    key_ref.into(),
                    iv_ref.into(),
                ))
            }
        }
        AESNI_CIPHER_AES_256_CTR => {
            AesniCipherCtx::Aes256Ctr(Aes256Ctr::new(key_ref.into(), iv_ref.into()))
        }
        _ => return -2,
    };
    let raw_ctx = Box::into_raw(Box::new(ctx)).cast::<c_void>();
    unsafe { *out_ctx = raw_ctx };
    0
}

/// Frees AES context allocated by `mtproxy_ffi_aesni_ctx_init`.
///
/// # Safety
/// `evp_ctx` must be either null or a pointer returned by `mtproxy_ffi_aesni_ctx_init`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_aesni_ctx_free(evp_ctx: *mut c_void) -> i32 {
    if evp_ctx.is_null() {
        return 0;
    }
    let _ = unsafe { Box::from_raw(evp_ctx.cast::<AesniCipherCtx>()) };
    0
}

const CRC32_REFLECTED_POLY: u32 = 0xedb8_8320;
const CRC32C_REFLECTED_POLY: u32 = 0x82f6_3b78;
const CRC64_REFLECTED_POLY: u64 = 0xc96c_5795_d787_0f42;
const GF32_CLMUL_POWERS_LEN: usize = 252;
const GF32_GENERIC_POWERS_MAX_LEN: usize = 32 * 67;

#[inline]
fn crc32_partial_poly(data: &[u8], mut crc: u32, poly: u32) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

fn crc32_partial_impl(data: &[u8], crc: u32) -> u32 {
    crc32_partial_poly(data, crc, CRC32_REFLECTED_POLY)
}

fn crc32c_partial_impl(data: &[u8], crc: u32) -> u32 {
    crc32_partial_poly(data, crc, CRC32C_REFLECTED_POLY)
}

#[inline]
fn crc64_feed_byte_impl(mut crc: u64, b: u8) -> u64 {
    crc ^= u64::from(b);
    for _ in 0..8 {
        if (crc & 1) != 0 {
            crc = (crc >> 1) ^ CRC64_REFLECTED_POLY;
        } else {
            crc >>= 1;
        }
    }
    crc
}

fn crc64_partial_impl(data: &[u8], mut crc: u64) -> u64 {
    for &byte in data {
        crc = crc64_feed_byte_impl(crc, byte);
    }
    crc
}

fn gf2_matrix_times_u32(matrix: &[u32; 32], mut vector: u32) -> u32 {
    let mut sum = 0u32;
    let mut n = 0usize;
    while vector != 0 {
        if (vector & 1) != 0 {
            sum ^= matrix[n];
        }
        vector >>= 1;
        n += 1;
    }
    sum
}

fn gf2_matrix_square_u32(square: &mut [u32; 32], matrix: &[u32; 32]) {
    for n in 0..32 {
        square[n] = gf2_matrix_times_u32(matrix, matrix[n]);
    }
}

fn crc_combine_u32(mut crc1: u32, crc2: u32, len2: i64, poly: u32) -> u32 {
    if len2 <= 0 {
        return crc1;
    }

    let mut odd = [0u32; 32];
    let mut even = [0u32; 32];

    odd[0] = poly;
    let mut row = 1u32;
    for slot in odd.iter_mut().skip(1) {
        *slot = row;
        row <<= 1;
    }

    gf2_matrix_square_u32(&mut even, &odd);
    gf2_matrix_square_u32(&mut odd, &even);

    let mut n = len2 as u64;
    loop {
        gf2_matrix_square_u32(&mut even, &odd);
        if (n & 1) != 0 {
            crc1 = gf2_matrix_times_u32(&even, crc1);
        }
        n >>= 1;
        if n == 0 {
            break;
        }

        gf2_matrix_square_u32(&mut odd, &even);
        if (n & 1) != 0 {
            crc1 = gf2_matrix_times_u32(&odd, crc1);
        }
        n >>= 1;
        if n == 0 {
            break;
        }
    }

    crc1 ^ crc2
}

fn gf2_matrix_times_u64(matrix: &[u64; 64], mut vector: u64) -> u64 {
    let mut sum = 0u64;
    let mut n = 0usize;
    while vector != 0 {
        if (vector & 1) != 0 {
            sum ^= matrix[n];
        }
        vector >>= 1;
        n += 1;
    }
    sum
}

fn gf2_matrix_square_u64(square: &mut [u64; 64], matrix: &[u64; 64]) {
    for n in 0..64 {
        square[n] = gf2_matrix_times_u64(matrix, matrix[n]);
    }
}

fn crc_combine_u64(mut crc1: u64, crc2: u64, len2: i64, poly: u64) -> u64 {
    if len2 <= 0 {
        return crc1;
    }

    let mut odd = [0u64; 64];
    let mut even = [0u64; 64];

    odd[0] = poly;
    let mut row = 1u64;
    for slot in odd.iter_mut().skip(1) {
        *slot = row;
        row <<= 1;
    }

    gf2_matrix_square_u64(&mut even, &odd);
    gf2_matrix_square_u64(&mut odd, &even);

    let mut n = len2 as u64;
    loop {
        gf2_matrix_square_u64(&mut even, &odd);
        if (n & 1) != 0 {
            crc1 = gf2_matrix_times_u64(&even, crc1);
        }
        n >>= 1;
        if n == 0 {
            break;
        }

        gf2_matrix_square_u64(&mut odd, &even);
        if (n & 1) != 0 {
            crc1 = gf2_matrix_times_u64(&odd, crc1);
        }
        n >>= 1;
        if n == 0 {
            break;
        }
    }

    crc1 ^ crc2
}

#[inline]
fn gf32_mulx(a: u32, poly: u32) -> u32 {
    let mut r = a >> 1;
    if (a & 1) != 0 {
        r ^= poly;
    }
    r
}

fn gf32_mul(a: u32, mut b: u32, poly: u32) -> u32 {
    let mut x = 0u32;
    for _ in 0..32 {
        x = gf32_mulx(x, poly);
        if (b & 1) != 0 {
            x ^= a;
        }
        b >>= 1;
    }
    x
}

fn gf32_pow(a: u32, k: i32, poly: u32) -> u32 {
    if k == 0 {
        return 0x8000_0000;
    }
    let mut x = gf32_pow(gf32_mul(a, a, poly), k >> 1, poly);
    if (k & 1) != 0 {
        x = gf32_mul(x, a, poly);
    }
    x
}

fn gf32_matrix_times_slice(matrix: &[u32], mut vector: u32) -> u32 {
    let mut sum = 0u32;
    let mut n = 0usize;
    while vector != 0 {
        if (vector & 1) != 0 {
            if n >= matrix.len() {
                break;
            }
            sum ^= matrix[n];
        }
        vector >>= 1;
        n += 1;
    }
    sum
}

fn gf32_compute_powers_generic_impl(powers: &mut [u32], size: usize, poly: u32) {
    let usable = core::cmp::min(size, powers.len());
    if usable < 32 {
        return;
    }

    powers[0] = poly;
    for n in 0..31 {
        powers[n + 1] = 1u32 << n;
    }

    let mut n = 1usize;
    while (n << 5) < usable {
        let src_start = (n - 1) << 5;
        let dst_start = n << 5;
        if src_start + 32 > usable || dst_start + 32 > usable {
            break;
        }

        let mut src = [0u32; 32];
        let mut dst = [0u32; 32];
        src.copy_from_slice(&powers[src_start..src_start + 32]);
        gf2_matrix_square_u32(&mut dst, &src);
        powers[dst_start..dst_start + 32].copy_from_slice(&dst);

        n += 1;
    }
}

fn gf32_compute_powers_clmul_impl(powers: &mut [u32], poly: u32) {
    let groups = core::cmp::min(63, powers.len() / 4);
    let mut a = 1u32 << (31 - 7);
    let b = gf32_mul(poly, poly, poly);

    for idx in 0..groups {
        let base = idx * 4;
        powers[base] = 0;
        powers[base + 1] = gf32_mul(a, b, poly);
        powers[base + 2] = 0;
        powers[base + 3] = a;
        a = gf32_mulx(gf32_mul(a, a, poly), poly);
    }
}

fn gf32_combine_generic_impl(powers: &[u32], mut crc1: u32, mut len2: i64) -> u32 {
    if len2 <= 0 {
        return crc1;
    }

    let mut offset = 64usize;
    loop {
        offset = offset.saturating_add(32);
        if (len2 & 1) != 0 {
            if offset + 32 > powers.len() {
                break;
            }
            crc1 = gf32_matrix_times_slice(&powers[offset..offset + 32], crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
    }
    crc1
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn gf32_combine_clmul_hw_x86_64(powers: *const u32, crc1: u32, len2: u64) -> u64 {
    use core::arch::x86_64::{
        __m128i, _mm_clmulepi64_si128, _mm_cvtsi32_si128, _mm_loadu_si128, _mm_slli_si128,
        _mm_unpackhi_epi64, _mm_xor_si128,
    };

    let mut d = _mm_cvtsi32_si128(crc1 as i32);
    d = _mm_slli_si128(d, 12);

    let tz = len2.trailing_zeros() as usize;
    let mut p = powers.add(4 * tz).cast::<__m128i>();
    let mut rem = len2 >> (tz + 1);

    d = _mm_clmulepi64_si128(_mm_loadu_si128(p), d, 0x11);

    while rem != 0 {
        p = p.add(1);
        if (rem & 1) != 0 {
            let e = _mm_loadu_si128(p);
            d = _mm_xor_si128(
                _mm_clmulepi64_si128(e, d, 0x11),
                _mm_clmulepi64_si128(e, d, 0x00),
            );
        }
        rem >>= 1;
    }

    let base = powers.add(12).cast::<__m128i>();
    d = _mm_xor_si128(d, _mm_clmulepi64_si128(_mm_loadu_si128(base), d, 0x01));
    d = _mm_unpackhi_epi64(d, d);

    // SAFETY: __m128i and [u64; 2] are both 128-bit POD layouts.
    let lanes: [u64; 2] = unsafe { core::mem::transmute(d) };
    lanes[0]
}

fn gf32_combine_clmul_impl(powers: &[u32], crc1: u32, len2: i64) -> u64 {
    if len2 <= 0 {
        return u64::from(crc1);
    }

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("pclmulqdq") {
            // SAFETY: CPU feature is checked at runtime and table shape matches C contract.
            return unsafe { gf32_combine_clmul_hw_x86_64(powers.as_ptr(), crc1, len2 as u64) };
        }
    }

    u64::from(gf32_combine_generic_impl(powers, crc1, len2))
}

fn crc32_find_corrupted_bit_impl(size: i32, d: u32) -> i32 {
    let size = size.saturating_add(4);
    let n = size.saturating_mul(8);
    if n <= 0 {
        return -1;
    }

    let r = ((f64::from(n)).sqrt() + 0.5) as i32;
    if r <= 0 {
        return -1;
    }

    #[derive(Clone, Copy)]
    struct FcbTableEntry {
        p: u32,
        i: i32,
    }

    let mut table = vec![FcbTableEntry { p: 0, i: 0 }; usize::try_from(r).unwrap_or(0)];
    if table.is_empty() {
        return -1;
    }
    table[0] = FcbTableEntry {
        p: 0x8000_0000,
        i: 0,
    };
    for i in 1..r {
        let prev = table[usize::try_from(i - 1).unwrap_or(0)].p;
        table[usize::try_from(i).unwrap_or(0)] = FcbTableEntry {
            p: gf32_mulx(prev, CRC32_REFLECTED_POLY),
            i,
        };
    }
    table.sort_by(|x, y| x.p.cmp(&y.p).then(x.i.cmp(&y.i)));

    let q = gf32_pow(0xdb71_0641, r, CRC32_REFLECTED_POLY);
    let mut a = [0u32; 32];
    a[31] = q;
    for i in (0..31).rev() {
        a[i] = gf32_mulx(a[i + 1], CRC32_REFLECTED_POLY);
    }

    let max_j = n / r;
    let mut x = d;
    let mut res = -1;

    for j in 0..=max_j {
        let mut lo = -1;
        let mut hi = r;
        while hi - lo > 1 {
            let c = (lo + hi) >> 1;
            if table[usize::try_from(c).unwrap_or(0)].p <= x {
                lo = c;
            } else {
                hi = c;
            }
        }

        if lo >= 0 && table[usize::try_from(lo).unwrap_or(0)].p == x {
            res = table[usize::try_from(lo).unwrap_or(0)].i + r * j;
            break;
        }

        x = gf2_matrix_times_u32(&a, x);
    }

    res
}

fn crc32_repair_bit_impl(input: &mut [u8], k: i32) -> i32 {
    if k < 0 {
        return -1;
    }

    let l = i32::try_from(input.len()).unwrap_or(i32::MAX);
    let idx = k >> 5;
    let mut bit = k & 31;
    let mut i = (l - 1) - (idx - 1) * 4;
    while bit >= 8 {
        i -= 1;
        bit -= 8;
    }

    if i < 0 {
        return -2;
    }
    if i >= l {
        return -3;
    }

    let j = 7 - bit;
    if let Ok(pos) = usize::try_from(i) {
        input[pos] ^= 1u8 << j;
        return 0;
    }
    -3
}

fn compute_crc32_for_block(data: &[u8]) -> u32 {
    crc32_partial_impl(data, u32::MAX) ^ u32::MAX
}

fn crc32_check_and_repair_impl(input: &mut [u8], input_crc32: &mut u32) -> i32 {
    let computed_crc32 = compute_crc32_for_block(input);
    let crc32_diff = computed_crc32 ^ *input_crc32;
    if crc32_diff == 0 {
        return 0;
    }

    let bit =
        crc32_find_corrupted_bit_impl(i32::try_from(input.len()).unwrap_or(i32::MAX), crc32_diff);
    let repaired = crc32_repair_bit_impl(input, bit);
    if repaired == 0 {
        debug_assert_eq!(compute_crc32_for_block(input), *input_crc32);
        return 1;
    }

    if (crc32_diff & crc32_diff.wrapping_sub(1)) == 0 {
        *input_crc32 = computed_crc32;
        return 2;
    }

    *input_crc32 = computed_crc32;
    -1
}

/// Computes CRC32 partial update compatible with C `crc32_partial`.
///
/// # Safety
/// `data` must point to at least `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc32_partial(data: *const u8, len: usize, crc: u32) -> u32 {
    if data.is_null() || len == 0 {
        return crc;
    }

    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    crc32_partial_impl(bytes, crc)
}

/// Computes CRC32C partial update compatible with C `crc32c_partial`.
///
/// # Safety
/// `data` must point to at least `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc32c_partial(data: *const u8, len: usize, crc: u32) -> u32 {
    if data.is_null() || len == 0 {
        return crc;
    }

    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    crc32c_partial_impl(bytes, crc)
}

/// Computes CRC32 combine result for concatenated blocks.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crc32_combine(crc1: u32, crc2: u32, len2: i64) -> u32 {
    crc_combine_u32(crc1, crc2, len2, CRC32_REFLECTED_POLY)
}

/// Computes CRC32C combine result for concatenated blocks.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crc32c_combine(crc1: u32, crc2: u32, len2: i64) -> u32 {
    crc_combine_u32(crc1, crc2, len2, CRC32C_REFLECTED_POLY)
}

/// Computes CRC64 partial update.
///
/// # Safety
/// `data` must point to at least `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc64_partial(data: *const u8, len: usize, crc: u64) -> u64 {
    if data.is_null() || len == 0 {
        return crc;
    }

    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    crc64_partial_impl(bytes, crc)
}

/// Computes CRC64 combine result for concatenated blocks.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crc64_combine(crc1: u64, crc2: u64, len2: i64) -> u64 {
    crc_combine_u64(crc1, crc2, len2, CRC64_REFLECTED_POLY)
}

/// Feeds a single byte into reflected CRC64 state.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crc64_feed_byte(crc: u64, b: u8) -> u64 {
    crc64_feed_byte_impl(crc, b)
}

/// Computes GF32 powers table used by combine helpers.
///
/// # Safety
/// `powers` must point to at least `size` writable `u32` entries.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_gf32_compute_powers_generic(
    powers: *mut u32,
    size: usize,
    poly: u32,
) {
    if powers.is_null() || size == 0 {
        return;
    }
    let table = unsafe { core::slice::from_raw_parts_mut(powers, size) };
    gf32_compute_powers_generic_impl(table, size, poly);
}

/// Computes GF32 CLMUL-style powers table.
///
/// # Safety
/// `powers` must point to at least 252 writable `u32` entries.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_gf32_compute_powers_clmul(powers: *mut u32, poly: u32) {
    if powers.is_null() {
        return;
    }
    let table = unsafe { core::slice::from_raw_parts_mut(powers, GF32_CLMUL_POWERS_LEN) };
    gf32_compute_powers_clmul_impl(table, poly);
}

/// Applies GF32 combine using a precomputed powers table.
///
/// # Safety
/// `powers` must point to at least 2144 readable `u32` entries.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_gf32_combine_generic(
    powers: *const u32,
    crc1: u32,
    len2: i64,
) -> u32 {
    if powers.is_null() || len2 <= 0 {
        return crc1;
    }
    let table = unsafe { core::slice::from_raw_parts(powers, GF32_GENERIC_POWERS_MAX_LEN) };
    gf32_combine_generic_impl(table, crc1, len2)
}

/// Applies GF32 combine using a CLMUL powers table.
///
/// # Safety
/// `powers` must point to at least 252 readable `u32` entries.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_gf32_combine_clmul(
    powers: *const u32,
    crc1: u32,
    len2: i64,
) -> u64 {
    if powers.is_null() || len2 <= 0 {
        return u64::from(crc1);
    }
    let table = unsafe { core::slice::from_raw_parts(powers, GF32_CLMUL_POWERS_LEN) };
    gf32_combine_clmul_impl(table, crc1, len2)
}

/// Finds a candidate corrupted bit index by CRC32 syndrome.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crc32_find_corrupted_bit(size: i32, d: u32) -> i32 {
    crc32_find_corrupted_bit_impl(size, d)
}

/// Repairs one bit in place for the provided block.
///
/// # Safety
/// `input` must point to at least `len` writable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc32_repair_bit(input: *mut u8, len: usize, k: i32) -> i32 {
    if input.is_null() {
        return -3;
    }
    let bytes = unsafe { core::slice::from_raw_parts_mut(input, len) };
    crc32_repair_bit_impl(bytes, k)
}

/// Performs CRC32 check and single-bit repair attempt.
///
/// # Safety
/// `input` must point to at least `len` writable bytes when `len > 0`.
/// `input_crc32` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc32_check_and_repair(
    input: *mut u8,
    len: usize,
    input_crc32: *mut u32,
) -> i32 {
    if input.is_null() || input_crc32.is_null() {
        return -1;
    }
    let bytes = unsafe { core::slice::from_raw_parts_mut(input, len) };
    let crc_ref = unsafe { &mut *input_crc32 };
    crc32_check_and_repair_impl(bytes, crc_ref)
}

/// Initializes process id fields equivalent to `init_common_PID`.
///
/// # Safety
/// `pid` must be a valid pointer to writable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_pid_init_common(pid: *mut MtproxyProcessId) -> i32 {
    if pid.is_null() {
        return -1;
    }

    let pid_ref = unsafe { &mut *pid };

    if pid_ref.pid == 0 {
        let raw_pid = unsafe { getpid() };
        // Mirror C conversion semantics (`unsigned short` assignment): keep the
        // lower 16 bits instead of failing on systems with pid_max > 65535.
        let raw_pid_bits = u32::from_ne_bytes(raw_pid.to_ne_bytes());
        pid_ref.pid = u16::try_from(raw_pid_bits & u32::from(u16::MAX)).unwrap_or_default();
    }

    if pid_ref.utime == 0 {
        let raw_time = unsafe { time(core::ptr::null_mut()) };
        let Ok(time32) = i32::try_from(raw_time) else {
            return -1;
        };
        pid_ref.utime = time32;
    }

    0
}

/// Initializes process id fields equivalent to `init_client_PID`.
///
/// # Safety
/// `pid` must be a valid pointer to writable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_pid_init_client(pid: *mut MtproxyProcessId, ip: u32) -> i32 {
    if pid.is_null() {
        return -1;
    }

    let pid_ref = unsafe { &mut *pid };
    if ip != 0 && ip != PID_LOCALHOST_IP {
        pid_ref.ip = ip;
    }

    unsafe { mtproxy_ffi_pid_init_common(pid) }
}

/// Initializes process id fields equivalent to `init_server_PID`.
///
/// # Safety
/// `pid` must be a valid pointer to writable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_pid_init_server(
    pid: *mut MtproxyProcessId,
    ip: u32,
    port: i32,
) -> i32 {
    if pid.is_null() {
        return -1;
    }

    let pid_ref = unsafe { &mut *pid };
    if ip != 0 && ip != PID_LOCALHOST_IP {
        pid_ref.ip = ip;
    }
    if pid_ref.port == 0 {
        let bytes = port.to_ne_bytes();
        pid_ref.port = i16::from_ne_bytes([bytes[0], bytes[1]]);
    }

    unsafe { mtproxy_ffi_pid_init_common(pid) }
}

/// Equivalent to C `matches_pid`.
///
/// # Safety
/// `x` and `y` must be valid pointers to readable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_matches_pid(
    x: *const MtproxyProcessId,
    y: *const MtproxyProcessId,
) -> i32 {
    if x.is_null() || y.is_null() {
        return 0;
    }

    let x_ref = unsafe { &*x };
    let y_ref = unsafe { &*y };
    if x_ref == y_ref {
        return 2;
    }

    i32::from(
        (y_ref.ip == 0 || x_ref.ip == y_ref.ip)
            && (y_ref.port == 0 || x_ref.port == y_ref.port)
            && (y_ref.pid == 0 || x_ref.pid == y_ref.pid)
            && (y_ref.utime == 0 || x_ref.utime == y_ref.utime),
    )
}

/// Equivalent to C `process_id_is_newer`.
///
/// # Safety
/// `a` and `b` must be valid pointers to readable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_process_id_is_newer(
    a: *const MtproxyProcessId,
    b: *const MtproxyProcessId,
) -> i32 {
    if a.is_null() || b.is_null() {
        return 0;
    }

    let a_ref = unsafe { &*a };
    let b_ref = unsafe { &*b };
    if a_ref.ip != b_ref.ip || a_ref.port != b_ref.port {
        return 0;
    }
    if a_ref.utime < b_ref.utime {
        return 0;
    }
    if a_ref.utime > b_ref.utime {
        return 1;
    }

    let delta = (i32::from(a_ref.pid) - i32::from(b_ref.pid)) & 0x7fff;
    i32::from(delta != 0 && delta <= 0x3fff)
}

fn u32_bits_to_i32(v: u32) -> i32 {
    i32::from_ne_bytes(v.to_ne_bytes())
}

/// Fills CPUID fields equivalent to C `kdb_cpuid`.
///
/// # Safety
/// `out` must be a valid pointer to writable `MtproxyCpuid`.
#[no_mangle]
#[allow(clippy::needless_return)]
pub unsafe extern "C" fn mtproxy_ffi_cpuid_fill(out: *mut MtproxyCpuid) -> i32 {
    if out.is_null() {
        return -1;
    }

    let out_ref = unsafe { &mut *out };

    #[cfg(target_arch = "x86_64")]
    {
        let regs = unsafe { core::arch::x86_64::__cpuid(1) };
        out_ref.magic = CPUID_MAGIC;
        out_ref.ebx = u32_bits_to_i32(regs.ebx);
        out_ref.ecx = u32_bits_to_i32(regs.ecx);
        out_ref.edx = u32_bits_to_i32(regs.edx);
        return 0;
    }

    #[cfg(target_arch = "x86")]
    {
        let regs = unsafe { core::arch::x86::__cpuid(1) };
        out_ref.magic = CPUID_MAGIC;
        out_ref.ebx = u32_bits_to_i32(regs.ebx);
        out_ref.ecx = u32_bits_to_i32(regs.ecx);
        out_ref.edx = u32_bits_to_i32(regs.edx);
        return 0;
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = out_ref;
        -2
    }
}

fn as_input_ptr(input: *const u8, len: usize) -> Option<*const u8> {
    if len == 0 {
        Some(core::ptr::NonNull::<u8>::dangling().as_ptr().cast_const())
    } else if input.is_null() {
        None
    } else {
        Some(input)
    }
}

fn as_output_slice<const N: usize>(output: *mut u8) -> Option<*mut [u8; N]> {
    if output.is_null() {
        return None;
    }

    Some(output.cast::<[u8; N]>())
}

/// Computes MD5 digest.
///
/// # Safety
/// `output` must point to at least 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_md5(input: *const u8, len: usize, output: *mut u8) -> i32 {
    let Some(out) = as_output_slice::<DIGEST_MD5_LEN>(output) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    let Some(input_ptr) = as_input_ptr(input, len) else {
        return -1;
    };
    let input_ref = unsafe { core::slice::from_raw_parts(input_ptr, len) };
    if md5_digest_impl(input_ref, out_ref) {
        0
    } else {
        -1
    }
}

/// Computes MD5 digest and writes lowercase hex bytes (no `\\0` terminator).
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_md5_hex(
    input: *const u8,
    len: usize,
    output: *mut c_char,
) -> i32 {
    let mut digest = [0u8; DIGEST_MD5_LEN];
    if unsafe { mtproxy_ffi_md5(input, len, digest.as_mut_ptr()) } < 0 {
        return -1;
    }
    if output.is_null() {
        return -1;
    }

    let out = unsafe { core::slice::from_raw_parts_mut(output.cast::<u8>(), DIGEST_MD5_LEN * 2) };
    for (i, &byte) in digest.iter().enumerate() {
        out[i * 2] = HEX_LOWER[usize::from(byte >> 4)];
        out[i * 2 + 1] = HEX_LOWER[usize::from(byte & 0x0f)];
    }
    0
}

/// Computes HMAC-MD5.
///
/// # Safety
/// `output` must point to at least 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_md5_hmac(
    key: *const u8,
    key_len: usize,
    input: *const u8,
    len: usize,
    output: *mut u8,
) -> i32 {
    let Some(out) = as_output_slice::<DIGEST_MD5_LEN>(output) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    let Some(key_ptr) = as_input_ptr(key, key_len) else {
        return -1;
    };
    let Some(input_ptr) = as_input_ptr(input, len) else {
        return -1;
    };
    if c_int::try_from(key_len).is_err() {
        return -1;
    }
    let key_ref = unsafe { core::slice::from_raw_parts(key_ptr, key_len) };
    let input_ref = unsafe { core::slice::from_raw_parts(input_ptr, len) };
    let Ok(mut mac) = HmacMd5::new_from_slice(key_ref) else {
        return -1;
    };
    mac.update(input_ref);
    out_ref.copy_from_slice(&mac.finalize().into_bytes());
    0
}

/// Computes SHA1 digest.
///
/// # Safety
/// `output` must point to at least 20 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha1(input: *const u8, len: usize, output: *mut u8) -> i32 {
    let Some(out) = as_output_slice::<DIGEST_SHA1_LEN>(output) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    let Some(input_ptr) = as_input_ptr(input, len) else {
        return -1;
    };
    let input_ref = unsafe { core::slice::from_raw_parts(input_ptr, len) };
    if sha1_digest_impl(input_ref, out_ref) {
        0
    } else {
        -1
    }
}

/// Computes SHA1 digest for concatenated chunks.
///
/// # Safety
/// `output` must point to at least 20 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha1_two_chunks(
    input1: *const u8,
    len1: usize,
    input2: *const u8,
    len2: usize,
    output: *mut u8,
) -> i32 {
    let Some(input1_ptr) = as_input_ptr(input1, len1) else {
        return -1;
    };
    let Some(input2_ptr) = as_input_ptr(input2, len2) else {
        return -1;
    };
    let Some(total_len) = len1.checked_add(len2) else {
        return -1;
    };

    let first = unsafe { core::slice::from_raw_parts(input1_ptr, len1) };
    let second = unsafe { core::slice::from_raw_parts(input2_ptr, len2) };
    let mut merged = Vec::with_capacity(total_len);
    merged.extend_from_slice(first);
    merged.extend_from_slice(second);
    unsafe { mtproxy_ffi_sha1(merged.as_ptr(), merged.len(), output) }
}

/// Computes SHA256 digest.
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha256(input: *const u8, len: usize, output: *mut u8) -> i32 {
    let Some(out) = as_output_slice::<DIGEST_SHA256_LEN>(output) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    let Some(input_ptr) = as_input_ptr(input, len) else {
        return -1;
    };
    let input_ref = unsafe { core::slice::from_raw_parts(input_ptr, len) };
    if sha256_digest_impl(input_ref, out_ref) {
        0
    } else {
        -1
    }
}

/// Computes SHA256 digest for concatenated chunks.
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha256_two_chunks(
    input1: *const u8,
    len1: usize,
    input2: *const u8,
    len2: usize,
    output: *mut u8,
) -> i32 {
    let Some(input1_ptr) = as_input_ptr(input1, len1) else {
        return -1;
    };
    let Some(input2_ptr) = as_input_ptr(input2, len2) else {
        return -1;
    };
    let Some(total_len) = len1.checked_add(len2) else {
        return -1;
    };

    let first = unsafe { core::slice::from_raw_parts(input1_ptr, len1) };
    let second = unsafe { core::slice::from_raw_parts(input2_ptr, len2) };
    let mut merged = Vec::with_capacity(total_len);
    merged.extend_from_slice(first);
    merged.extend_from_slice(second);
    unsafe { mtproxy_ffi_sha256(merged.as_ptr(), merged.len(), output) }
}

/// Computes HMAC-SHA256.
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha256_hmac(
    key: *const u8,
    key_len: usize,
    input: *const u8,
    len: usize,
    output: *mut u8,
) -> i32 {
    let Some(out) = as_output_slice::<DIGEST_SHA256_LEN>(output) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    let Some(key_ptr) = as_input_ptr(key, key_len) else {
        return -1;
    };
    let Some(input_ptr) = as_input_ptr(input, len) else {
        return -1;
    };
    if c_int::try_from(key_len).is_err() {
        return -1;
    }
    let key_ref = unsafe { core::slice::from_raw_parts(key_ptr, key_len) };
    let input_ref = unsafe { core::slice::from_raw_parts(input_ptr, len) };
    let Ok(mut mac) = HmacSha256::new_from_slice(key_ref) else {
        return -1;
    };
    mac.update(input_ref);
    out_ref.copy_from_slice(&mac.finalize().into_bytes());
    0
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn rdtsc() -> i64 {
    #[cfg(target_arch = "x86_64")]
    let ticks = unsafe { core::arch::x86_64::_rdtsc() };
    #[cfg(target_arch = "x86")]
    let ticks = unsafe { core::arch::x86::_rdtsc() };

    i64::try_from(ticks).unwrap_or(i64::MAX)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
fn rdtsc() -> i64 {
    0
}

#[allow(clippy::cast_precision_loss)]
fn time_parts_to_f64(sec: c_long, subsec: c_long, scale: f64) -> f64 {
    sec as f64 + (subsec as f64) * scale
}

fn clock_gettime_f64(clock_id: c_int) -> Option<f64> {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { clock_gettime(clock_id, &raw mut ts) } < 0 {
        return None;
    }
    Some(time_parts_to_f64(ts.tv_sec, ts.tv_nsec, 1e-9))
}

fn gettimeofday_f64() -> Option<f64> {
    let mut tv = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    if unsafe { gettimeofday(&raw mut tv, core::ptr::null_mut()) } < 0 {
        return None;
    }
    Some(time_parts_to_f64(tv.tv_sec, tv.tv_usec, 1e-6))
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn seconds_to_precise_time(seconds: f64) -> i64 {
    (seconds * 4_294_967_296.0) as i64
}

fn update_precise_now(seconds: f64, ticks: i64) {
    TLS_PRECISE_NOW.with(|v| v.set(seconds));
    TLS_PRECISE_NOW_RDTSC.with(|v| v.set(ticks));
}

/// precise-time compatible monotonic clock read.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_get_utime_monotonic() -> f64 {
    let ticks = rdtsc();
    let seconds = clock_gettime_f64(CLOCK_MONOTONIC_ID)
        .unwrap_or_else(|| time_parts_to_f64(unsafe { time(core::ptr::null_mut()) }, 0, 0.0));
    update_precise_now(seconds, ticks);
    seconds
}

/// precise-time compatible realtime cache with coarse refresh cadence.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_get_double_time() -> f64 {
    let cur_ticks = rdtsc();
    let next_ticks = DOUBLE_TIME_NEXT_RDTSC.load(Ordering::Relaxed);
    if cur_ticks > next_ticks {
        let seconds = gettimeofday_f64()
            .unwrap_or_else(|| time_parts_to_f64(unsafe { time(core::ptr::null_mut()) }, 0, 0.0));
        let next = cur_ticks.saturating_add(DOUBLE_TIME_RDTSC_WINDOW);
        DOUBLE_TIME_NEXT_RDTSC.store(next, Ordering::Relaxed);
        DOUBLE_TIME_LAST_BITS.store(seconds.to_bits(), Ordering::Relaxed);
        seconds
    } else {
        f64::from_bits(DOUBLE_TIME_LAST_BITS.load(Ordering::Relaxed))
    }
}

/// precise-time compatible `get_utime(clock_id)`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_get_utime(clock_id: i32) -> f64 {
    let seconds = clock_gettime_f64(clock_id)
        .unwrap_or_else(|| time_parts_to_f64(unsafe { time(core::ptr::null_mut()) }, 0, 0.0));
    if clock_id == CLOCK_REALTIME_ID {
        PRECISE_TIME.store(seconds_to_precise_time(seconds), Ordering::Relaxed);
        PRECISE_TIME_RDTSC.store(rdtsc(), Ordering::Relaxed);
    }
    seconds
}

/// precise-time compatible cached precise-time reader.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_get_precise_time(precision: u32) -> i64 {
    let diff = rdtsc().saturating_sub(PRECISE_TIME_RDTSC.load(Ordering::Relaxed));
    if let Ok(diff_u64) = u64::try_from(diff) {
        if diff_u64 > u64::from(precision) {
            let _ = mtproxy_ffi_get_utime(CLOCK_REALTIME_ID);
        }
    } else {
        let _ = mtproxy_ffi_get_utime(CLOCK_REALTIME_ID);
    }

    PRECISE_TIME.load(Ordering::Relaxed)
}

/// Returns thread-local `precise_now` mirror.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_now_value() -> f64 {
    TLS_PRECISE_NOW.with(Cell::get)
}

/// Returns thread-local `precise_now_rdtsc` mirror.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_now_rdtsc_value() -> i64 {
    TLS_PRECISE_NOW_RDTSC.with(Cell::get)
}

/// Returns global `precise_time` mirror.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_time_value() -> i64 {
    PRECISE_TIME.load(Ordering::Relaxed)
}

/// Returns global `precise_time_rdtsc` mirror.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_time_rdtsc_value() -> i64 {
    PRECISE_TIME_RDTSC.load(Ordering::Relaxed)
}

fn cfg_take_while<F>(bytes: &[u8], mut i: usize, mut f: F) -> usize
where
    F: FnMut(u8) -> bool,
{
    while i < bytes.len() && f(bytes[i]) {
        i += 1;
    }
    i
}

fn cfg_is_word_char(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, b'.' | b'-' | b'_')
}

fn cfg_skipspc_impl(bytes: &[u8], mut line_no: i32) -> MtproxyCfgScanResult {
    let mut i = 0usize;
    loop {
        if i >= bytes.len() {
            return MtproxyCfgScanResult {
                advance: i,
                line_no,
                ch: 0,
            };
        }
        match bytes[i] {
            b' ' | b'\t' | b'\r' => {
                i += 1;
            }
            b'\n' => {
                line_no += 1;
                i += 1;
            }
            b'#' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            ch => {
                return MtproxyCfgScanResult {
                    advance: i,
                    line_no,
                    ch: i32::from(ch),
                };
            }
        }
    }
}

fn cfg_skspc_impl(bytes: &[u8], line_no: i32) -> MtproxyCfgScanResult {
    let i = cfg_take_while(bytes, 0, |ch| matches!(ch, b' ' | b'\t'));
    let ch = bytes.get(i).copied().unwrap_or(0);
    MtproxyCfgScanResult {
        advance: i,
        line_no,
        ch: i32::from(ch),
    }
}

fn cfg_getword_len_impl(bytes: &[u8]) -> i32 {
    let scan = cfg_skspc_impl(bytes, 0);
    let mut i = scan.advance;
    if i >= bytes.len() {
        return 0;
    }

    if bytes[i] != b'[' {
        let end = cfg_take_while(bytes, i, cfg_is_word_char);
        return i32::try_from(end - i).unwrap_or(i32::MAX);
    }

    i += 1;
    let end_inner = cfg_take_while(bytes, i, |ch| cfg_is_word_char(ch) || ch == b':');
    if end_inner < bytes.len() && bytes[end_inner] == b']' {
        i32::try_from(end_inner + 1 - scan.advance).unwrap_or(i32::MAX)
    } else {
        i32::try_from(end_inner - scan.advance).unwrap_or(i32::MAX)
    }
}

fn cfg_getstr_len_impl(bytes: &[u8]) -> i32 {
    let scan = cfg_skspc_impl(bytes, 0);
    let i = scan.advance;
    if i >= bytes.len() {
        return 0;
    }
    if bytes[i] == b'"' {
        return 1;
    }
    let end = cfg_take_while(bytes, i, |ch| ch > b' ' && ch != b';');
    i32::try_from(end - i).unwrap_or(i32::MAX)
}

fn cfg_parse_unsigned(bytes: &[u8]) -> MtproxyCfgIntResult {
    let scan = cfg_skspc_impl(bytes, 0);
    let mut i = scan.advance;
    let mut x: i64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        x = x
            .saturating_mul(10)
            .saturating_add(i64::from(bytes[i] - b'0'));
        i += 1;
    }
    MtproxyCfgIntResult {
        value: x,
        consumed: i - scan.advance,
    }
}

fn cfg_parse_signed_zero(bytes: &[u8]) -> MtproxyCfgIntResult {
    let scan = cfg_skspc_impl(bytes, 0);
    let mut i = scan.advance;
    let mut sign: i64 = 1;
    if i < bytes.len() && bytes[i] == b'-' {
        sign = -1;
        i += 1;
    }
    let start_digits = i;
    let mut x: i64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        x = x
            .saturating_mul(10)
            .saturating_add(sign.saturating_mul(i64::from(bytes[i] - b'0')));
        i += 1;
    }
    if i == start_digits {
        MtproxyCfgIntResult {
            value: i64::MIN,
            consumed: 0,
        }
    } else {
        MtproxyCfgIntResult {
            value: x,
            consumed: i - scan.advance,
        }
    }
}

fn slice_from_ptr<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if data.is_null() {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(data, len) })
}

fn cfg_bytes_from_cstr(cur: *const c_char, len: usize) -> Option<&'static [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if cur.is_null() {
        return None;
    }
    let ptr = cur.cast::<u8>();
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// parse-config: skip spaces/comments and report cursor movement.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_skipspc(
    cur: *const c_char,
    len: usize,
    line_no: i32,
    out: *mut MtproxyCfgScanResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = cfg_skipspc_impl(bytes, line_no);
    0
}

/// parse-config: skip horizontal spaces and report cursor movement.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_skspc(
    cur: *const c_char,
    len: usize,
    line_no: i32,
    out: *mut MtproxyCfgScanResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = cfg_skspc_impl(bytes, line_no);
    0
}

/// parse-config: word token length at current cursor.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getword_len(cur: *const c_char, len: usize) -> i32 {
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    cfg_getword_len_impl(bytes)
}

/// parse-config: generic string token length at current cursor.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getstr_len(cur: *const c_char, len: usize) -> i32 {
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    cfg_getstr_len_impl(bytes)
}

/// parse-config: unsigned integer scan.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getint(
    cur: *const c_char,
    len: usize,
    out: *mut MtproxyCfgIntResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = cfg_parse_unsigned(bytes);
    0
}

/// parse-config: unsigned integer scan with zero-digit sentinel.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getint_zero(
    cur: *const c_char,
    len: usize,
    out: *mut MtproxyCfgIntResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    let parsed = cfg_parse_unsigned(bytes);
    let out_ref = unsafe { &mut *out };
    if parsed.consumed == 0 {
        *out_ref = MtproxyCfgIntResult {
            value: -1,
            consumed: 0,
        };
    } else {
        *out_ref = parsed;
    }
    0
}

/// parse-config: signed integer scan with zero-digit sentinel.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getint_signed_zero(
    cur: *const c_char,
    len: usize,
    out: *mut MtproxyCfgIntResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = cfg_parse_signed_zero(bytes);
    0
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn copy_error_message(out: &mut MtproxyTlHeaderParseResult, message: &str) {
    let bytes = message.as_bytes();
    let cap = out.error.len().saturating_sub(1);
    let n = bytes.len().min(cap);
    for (dst, src) in out.error.iter_mut().take(n).zip(bytes.iter().copied()) {
        *dst = c_char::from_ne_bytes([src]);
    }
    if let Some(last) = out.error.get_mut(n) {
        *last = 0;
    }
    out.error_len = i32::try_from(n).unwrap_or(i32::MAX);
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn copy_mtproto_parse_error_message(out: &mut MtproxyMtprotoParseFunctionResult, message: &str) {
    let bytes = message.as_bytes();
    let cap = out.error.len().saturating_sub(1);
    let n = bytes.len().min(cap);
    for (dst, src) in out.error.iter_mut().take(n).zip(bytes.iter().copied()) {
        *dst = c_char::from_ne_bytes([src]);
    }
    if let Some(last) = out.error.get_mut(n) {
        *last = 0;
    }
    out.error_len = i32::try_from(n).unwrap_or(i32::MAX);
}

fn saturating_i32_from_usize(value: usize) -> i32 {
    match i32::try_from(value) {
        Ok(converted) => converted,
        Err(_) => i32::MAX,
    }
}

fn write_tl_parse_success(
    out: &mut MtproxyTlHeaderParseResult,
    parsed: mtproxy_core::runtime::config::tl_parse::TlParsedHeader,
) {
    out.status = 0;
    out.consumed = saturating_i32_from_usize(parsed.consumed);
    out.op = parsed.header.op;
    out.real_op = parsed.header.real_op;
    out.flags = parsed.header.flags;
    out.qid = parsed.header.qid;
    out.actor_id = parsed.header.actor_id;
}

fn write_tl_parse_error(
    out: &mut MtproxyTlHeaderParseResult,
    err: &mtproxy_core::runtime::config::tl_parse::TlError,
) {
    out.status = -1;
    out.errnum = err.errnum;
    copy_error_message(out, &err.message);
}

fn tl_parse_query_header_impl(data: &[u8], out: &mut MtproxyTlHeaderParseResult) {
    match mtproxy_core::runtime::config::tl_parse::parse_query_header(data) {
        Ok(parsed) => write_tl_parse_success(out, parsed),
        Err(err) => write_tl_parse_error(out, &err),
    }
}

fn tl_parse_answer_header_impl(data: &[u8], out: &mut MtproxyTlHeaderParseResult) {
    match mtproxy_core::runtime::config::tl_parse::parse_answer_header(data) {
        Ok(parsed) => write_tl_parse_success(out, parsed),
        Err(err) => write_tl_parse_error(out, &err),
    }
}

/// Parses TL query header bytes (`RPC_INVOKE_REQ` / `RPC_INVOKE_KPHP_REQ`).
///
/// # Safety
/// `data` must point to `len` readable bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_parse_query_header(
    data: *const u8,
    len: usize,
    out: *mut MtproxyTlHeaderParseResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = slice_from_ptr(data, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyTlHeaderParseResult::default();
    tl_parse_query_header_impl(bytes, out_ref);
    0
}

/// Parses TL answer header bytes (`RPC_REQ_ERROR` / `RPC_REQ_RESULT`).
///
/// # Safety
/// `data` must point to `len` readable bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_parse_answer_header(
    data: *const u8,
    len: usize,
    out: *mut MtproxyTlHeaderParseResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = slice_from_ptr(data, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyTlHeaderParseResult::default();
    tl_parse_answer_header_impl(bytes, out_ref);
    0
}

fn parse_i32(token: &str) -> Option<i32> {
    token.parse::<i32>().ok()
}

fn parse_i64(token: &str) -> Option<i64> {
    token.parse::<i64>().ok()
}

fn parse_u64(token: &str) -> Option<u64> {
    token.parse::<u64>().ok()
}

fn fill_comm(dst: &mut [c_char; 256], src: &str) {
    for v in dst.iter_mut() {
        *v = 0;
    }
    let bytes = src.as_bytes();
    let n = bytes.len().min(dst.len().saturating_sub(1));
    for (i, b) in bytes.iter().copied().take(n).enumerate() {
        dst[i] = c_char::from_ne_bytes([b]);
    }
}

#[allow(clippy::field_reassign_with_default)]
fn parse_proc_stat_line_impl(line: &str) -> Option<MtproxyProcStats> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 42 {
        return None;
    }

    let mut out = MtproxyProcStats::default();
    out.pid = parse_i32(tokens[0])?;
    fill_comm(&mut out.comm, tokens[1]);
    out.state = i8::from_ne_bytes([*tokens[2].as_bytes().first()?]);
    out.ppid = parse_i32(tokens[3])?;
    out.pgrp = parse_i32(tokens[4])?;
    out.session = parse_i32(tokens[5])?;
    out.tty_nr = parse_i32(tokens[6])?;
    out.tpgid = parse_i32(tokens[7])?;
    out.flags = parse_u64(tokens[8])?;
    out.minflt = parse_u64(tokens[9])?;
    out.cminflt = parse_u64(tokens[10])?;
    out.majflt = parse_u64(tokens[11])?;
    out.cmajflt = parse_u64(tokens[12])?;
    out.utime = parse_u64(tokens[13])?;
    out.stime = parse_u64(tokens[14])?;
    out.cutime = parse_i64(tokens[15])?;
    out.cstime = parse_i64(tokens[16])?;
    out.priority = parse_i64(tokens[17])?;
    out.nice = parse_i64(tokens[18])?;
    out.num_threads = parse_i64(tokens[19])?;
    out.itrealvalue = parse_i64(tokens[20])?;
    out.starttime = parse_u64(tokens[21])?;
    out.vsize = parse_u64(tokens[22])?;
    out.rss = parse_i64(tokens[23])?;
    out.rlim = parse_u64(tokens[24])?;
    out.startcode = parse_u64(tokens[25])?;
    out.endcode = parse_u64(tokens[26])?;
    out.startstack = parse_u64(tokens[27])?;
    out.kstkesp = parse_u64(tokens[28])?;
    out.kstkeip = parse_u64(tokens[29])?;
    out.signal = parse_u64(tokens[30])?;
    out.blocked = parse_u64(tokens[31])?;
    out.sigignore = parse_u64(tokens[32])?;
    out.sigcatch = parse_u64(tokens[33])?;
    out.wchan = parse_u64(tokens[34])?;
    out.nswap = parse_u64(tokens[35])?;
    out.cnswap = parse_u64(tokens[36])?;
    out.exit_signal = parse_i32(tokens[37])?;
    out.processor = parse_i32(tokens[38])?;
    out.rt_priority = parse_u64(tokens[39])?;
    out.policy = parse_u64(tokens[40])?;
    out.delayacct_blkio_ticks = parse_u64(tokens[41])?;
    Some(out)
}

/// Parses one `/proc/.../stat` line into a stable C ABI struct.
///
/// # Safety
/// `line` must point to `len` readable bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_parse_proc_stat_line(
    line: *const c_char,
    len: usize,
    out: *mut MtproxyProcStats,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(line, len) else {
        return -1;
    };
    let text = core::str::from_utf8(bytes).ok();
    let Some(parsed) = text.and_then(parse_proc_stat_line_impl) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = parsed;
    0
}

/// Reads `/proc/<pid>/stat` or `/proc/<pid>/task/<tid>/stat` and parses it.
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_read_proc_stat_file(
    pid: i32,
    tid: i32,
    out: *mut MtproxyProcStats,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let path = if tid <= 0 {
        format!("/proc/{pid}/stat")
    } else {
        format!("/proc/{pid}/task/{tid}/stat")
    };
    let Ok(text) = fs::read_to_string(path) else {
        return -1;
    };
    let Some(parsed) = parse_proc_stat_line_impl(&text) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = parsed;
    0
}

fn parse_statm_impl(text: &str, m: usize, page_size: i64, out_values: &mut [i64]) -> Option<()> {
    if m == 0 || m > out_values.len() {
        return None;
    }
    let mut iter = text.split_whitespace();
    for v in out_values.iter_mut().take(m) {
        let token = iter.next()?;
        let pages = parse_i64(token)?;
        *v = pages.saturating_mul(page_size);
    }
    Some(())
}

/// Parses `/proc/*/statm` textual content into byte counters.
///
/// # Safety
/// `buf` must point to `len` readable bytes, `out_values` must point to at least `m` writable `int64_t`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_parse_statm(
    buf: *const c_char,
    len: usize,
    m: i32,
    page_size: i64,
    out_values: *mut i64,
) -> i32 {
    if m <= 0 || m > 7 || out_values.is_null() || page_size <= 0 {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(buf, len) else {
        return -1;
    };
    let Some(text) = core::str::from_utf8(bytes).ok() else {
        return -1;
    };
    let count = usize::try_from(m).ok().unwrap_or(0);
    let out_slice = unsafe { core::slice::from_raw_parts_mut(out_values, count) };
    if parse_statm_impl(text, count, page_size, out_slice).is_none() {
        return -1;
    }
    0
}

fn parse_meminfo_line(line: &str) -> Option<(&str, i64, &str)> {
    let mut it = line.split_whitespace();
    let key = it.next()?;
    let val = parse_i64(it.next()?)?;
    let suffix = it.next().unwrap_or("");
    Some((key, val, suffix))
}

fn parse_meminfo_summary_impl(text: &str) -> Option<MtproxyMeminfoSummary> {
    let mut out = MtproxyMeminfoSummary::default();
    for line in text.lines() {
        let Some((key, value, suffix)) = parse_meminfo_line(line) else {
            continue;
        };
        if suffix != "kB" {
            continue;
        }
        let bytes = value.saturating_mul(1024);
        match key {
            "MemFree:" => {
                out.mem_free = bytes;
                out.found_mask |= 1;
            }
            "SwapTotal:" => {
                out.swap_total = bytes;
                out.found_mask |= 2;
            }
            "SwapFree:" => {
                out.swap_free = bytes;
                out.found_mask |= 4;
            }
            "Cached:" => {
                out.mem_cached = bytes;
                out.found_mask |= 8;
            }
            _ => {}
        }
    }
    if out.found_mask == 15 {
        Some(out)
    } else {
        None
    }
}

/// Parses `/proc/meminfo` and extracts stable summary fields.
///
/// # Safety
/// `buf` must point to `len` readable bytes and `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_parse_meminfo_summary(
    buf: *const c_char,
    len: usize,
    out: *mut MtproxyMeminfoSummary,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(buf, len) else {
        return -1;
    };
    let Some(text) = core::str::from_utf8(bytes).ok() else {
        return -1;
    };
    let Some(summary) = parse_meminfo_summary_impl(text) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = summary;
    0
}

/// Formats kprintf prefix: `[pid][YYYY-MM-DD HH:MM:SS.UUUUUU local] `.
///
/// # Safety
/// `out` must point to `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_format_log_prefix(
    pid: i32,
    year: i32,
    mon: i32,
    mday: i32,
    hour: i32,
    min: i32,
    sec: i32,
    usec: i32,
    out: *mut c_char,
    out_len: usize,
) -> i32 {
    if out.is_null() || out_len == 0 {
        return -1;
    }
    let text = format!(
        "[{pid}][{year:04}-{mon:02}-{mday:02} {hour:02}:{min:02}:{sec:02}.{usec:06} local] "
    );
    let bytes = text.as_bytes();
    let n = bytes.len().min(out_len.saturating_sub(1));
    let out_bytes = unsafe { core::slice::from_raw_parts_mut(out.cast::<u8>(), out_len) };
    out_bytes[..n].copy_from_slice(&bytes[..n]);
    out_bytes[n] = 0;
    i32::try_from(n).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        ffi_api_version, mtproxy_ffi_aesni_crypt, mtproxy_ffi_aesni_ctx_free,
        mtproxy_ffi_aesni_ctx_init, mtproxy_ffi_api_version, mtproxy_ffi_cfg_getint_signed_zero,
        mtproxy_ffi_cfg_getword_len, mtproxy_ffi_cfg_skipspc, mtproxy_ffi_cpuid_fill,
        mtproxy_ffi_crc32_check_and_repair, mtproxy_ffi_crc32_partial, mtproxy_ffi_crc32c_partial,
        mtproxy_ffi_crypto_aes_create_keys, mtproxy_ffi_crypto_dh_first_round,
        mtproxy_ffi_crypto_dh_get_params_select, mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin,
        mtproxy_ffi_crypto_dh_second_round, mtproxy_ffi_crypto_dh_third_round,
        mtproxy_ffi_crypto_rand_bytes, mtproxy_ffi_crypto_tls_generate_public_key,
        mtproxy_ffi_engine_rpc_result_header_len, mtproxy_ffi_engine_rpc_result_new_flags,
        mtproxy_ffi_get_application_boundary, mtproxy_ffi_get_concurrency_boundary,
        mtproxy_ffi_get_crypto_boundary, mtproxy_ffi_get_network_boundary,
        mtproxy_ffi_get_precise_time, mtproxy_ffi_get_rpc_boundary,
        mtproxy_ffi_get_utime_monotonic, mtproxy_ffi_gf32_combine_clmul,
        mtproxy_ffi_gf32_compute_powers_clmul, mtproxy_ffi_matches_pid, mtproxy_ffi_md5,
        mtproxy_ffi_md5_hex, mtproxy_ffi_msg_buffers_pick_size_index,
        mtproxy_ffi_mtproto_cfg_decide_cluster_apply, mtproxy_ffi_mtproto_cfg_expect_semicolon,
        mtproxy_ffi_mtproto_cfg_finalize, mtproxy_ffi_mtproto_cfg_getlex_ext,
        mtproxy_ffi_mtproto_cfg_lookup_cluster_index, mtproxy_ffi_mtproto_cfg_parse_directive_step,
        mtproxy_ffi_mtproto_cfg_parse_full_pass, mtproxy_ffi_mtproto_cfg_parse_proxy_target_step,
        mtproxy_ffi_mtproto_cfg_preinit, mtproxy_ffi_mtproto_cfg_scan_directive_token,
        mtproxy_ffi_mtproto_conn_tag, mtproxy_ffi_mtproto_ext_conn_hash,
        mtproxy_ffi_mtproto_inspect_packet_header, mtproxy_ffi_mtproto_parse_function,
        mtproxy_ffi_mtproto_parse_text_ipv4, mtproxy_ffi_mtproto_parse_text_ipv6,
        mtproxy_ffi_net_epoll_conv_flags, mtproxy_ffi_net_epoll_unconv_flags,
        mtproxy_ffi_net_timers_wait_msec, mtproxy_ffi_parse_meminfo_summary,
        mtproxy_ffi_parse_proc_stat_line, mtproxy_ffi_parse_statm, mtproxy_ffi_pid_init_common,
        mtproxy_ffi_precise_now_rdtsc_value, mtproxy_ffi_precise_now_value,
        mtproxy_ffi_process_id_is_newer, mtproxy_ffi_read_proc_stat_file,
        mtproxy_ffi_rpc_target_normalize_pid, mtproxy_ffi_sha1, mtproxy_ffi_sha1_two_chunks,
        mtproxy_ffi_sha256, mtproxy_ffi_sha256_hmac, mtproxy_ffi_sha256_two_chunks,
        mtproxy_ffi_startup_handshake, mtproxy_ffi_tcp_rpc_client_packet_len_state,
        mtproxy_ffi_tcp_rpc_encode_compact_header,
        mtproxy_ffi_tcp_rpc_server_packet_header_malformed,
        mtproxy_ffi_tcp_rpc_server_packet_len_state, mtproxy_ffi_tl_parse_answer_header,
        mtproxy_ffi_tl_parse_query_header, MtproxyAesKeyData, MtproxyApplicationBoundary,
        MtproxyCfgIntResult, MtproxyCfgScanResult, MtproxyConcurrencyBoundary, MtproxyCpuid,
        MtproxyCryptoBoundary, MtproxyMeminfoSummary, MtproxyMtprotoCfgClusterApplyDecisionResult,
        MtproxyMtprotoCfgDirectiveStepResult, MtproxyMtprotoCfgDirectiveTokenResult,
        MtproxyMtprotoCfgFinalizeResult, MtproxyMtprotoCfgGetlexExtResult,
        MtproxyMtprotoCfgParseFullResult, MtproxyMtprotoCfgParseProxyTargetStepResult,
        MtproxyMtprotoCfgPreinitResult, MtproxyMtprotoCfgProxyAction,
        MtproxyMtprotoOldClusterState, MtproxyMtprotoPacketInspectResult,
        MtproxyMtprotoParseFunctionResult, MtproxyNetworkBoundary, MtproxyProcStats,
        MtproxyProcessId, MtproxyRpcBoundary, MtproxyTlHeaderParseResult, AESNI_CIPHER_AES_256_CTR,
        AESNI_CONTRACT_OPS, AESNI_IMPLEMENTED_OPS, APPLICATION_BOUNDARY_VERSION,
        CONCURRENCY_BOUNDARY_VERSION, CPUID_MAGIC, CRC32_REFLECTED_POLY, CRYPTO_BOUNDARY_VERSION,
        DH_KEY_BYTES, DH_PARAMS_SELECT, ENGINE_RPC_CONTRACT_OPS, ENGINE_RPC_IMPLEMENTED_OPS,
        EPOLLERR, EPOLLET, EPOLLIN, EPOLLOUT, EPOLLPRI, EPOLLRDHUP, EVT_FROM_EPOLL, EVT_LEVEL,
        EVT_READ, EVT_SPEC, EVT_WRITE, FFI_API_VERSION, GF32_CLMUL_POWERS_LEN, JOBS_CONTRACT_OPS,
        JOBS_IMPLEMENTED_OPS, MPQ_CONTRACT_OPS, MPQ_IMPLEMENTED_OPS,
        MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_PROXIES_INTERMIXED,
        MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_TOO_MANY_AUTH_CLUSTERS,
        MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST,
        MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW, MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK,
        MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING,
        MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET, MTPROTO_CFG_EXPECT_SEMICOLON_ERR_EXPECTED,
        MTPROTO_CFG_EXPECT_SEMICOLON_OK, MTPROTO_CFG_FINALIZE_ERR_MISSING_PROXY_DIRECTIVES,
        MTPROTO_CFG_FINALIZE_ERR_NO_PROXY_SERVERS_DEFINED, MTPROTO_CFG_FINALIZE_OK,
        MTPROTO_CFG_GETLEX_EXT_OK, MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND,
        MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK,
        MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_EXPECTED_SEMICOLON,
        MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXIES_INTERMIXED,
        MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK, MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON,
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES, MTPROTO_CFG_PARSE_FULL_PASS_OK,
        MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_CLUSTER_EXTEND_INVARIANT,
        MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_EXPECTED_SEMICOLON,
        MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PROXIES_INTERMIXED,
        MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK, MTPROTO_CFG_PREINIT_ERR_INVALID_ARGS,
        MTPROTO_CFG_PREINIT_OK, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MAX_CONNECTIONS,
        MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MIN_CONNECTIONS,
        MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TARGET_ID,
        MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TIMEOUT,
        MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_TARGET_ID_SPACE, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK,
        MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER, MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS,
        MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS, MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR,
        MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT, MTPROTO_PACKET_KIND_ENCRYPTED,
        MTPROTO_PACKET_KIND_INVALID, MTPROTO_PACKET_KIND_UNENCRYPTED_DH,
        MTPROTO_PROXY_CONTRACT_OPS, MTPROTO_PROXY_IMPLEMENTED_OPS, NETWORK_BOUNDARY_VERSION,
        NET_CRYPTO_AES_CONTRACT_OPS, NET_CRYPTO_AES_IMPLEMENTED_OPS, NET_CRYPTO_DH_CONTRACT_OPS,
        NET_CRYPTO_DH_IMPLEMENTED_OPS, NET_EVENTS_CONTRACT_OPS, NET_EVENTS_IMPLEMENTED_OPS,
        NET_MSG_BUFFERS_CONTRACT_OPS, NET_MSG_BUFFERS_IMPLEMENTED_OPS, NET_TIMERS_CONTRACT_OPS,
        NET_TIMERS_IMPLEMENTED_OPS, RPC_BOUNDARY_VERSION, RPC_INVOKE_REQ, RPC_REQ_RESULT,
        RPC_TARGETS_CONTRACT_OPS, RPC_TARGETS_IMPLEMENTED_OPS, TCP_RPC_CLIENT_CONTRACT_OPS,
        TCP_RPC_CLIENT_IMPLEMENTED_OPS, TCP_RPC_COMMON_CONTRACT_OPS,
        TCP_RPC_COMMON_IMPLEMENTED_OPS, TCP_RPC_PACKET_LEN_STATE_INVALID,
        TCP_RPC_PACKET_LEN_STATE_READY, TCP_RPC_PACKET_LEN_STATE_SHORT,
        TCP_RPC_PACKET_LEN_STATE_SKIP, TCP_RPC_SERVER_CONTRACT_OPS, TCP_RPC_SERVER_IMPLEMENTED_OPS,
        TLS_REQUEST_PUBLIC_KEY_BYTES,
    };

    #[test]
    fn reports_same_api_version_for_rust_and_c_entrypoints() {
        assert_eq!(ffi_api_version(), FFI_API_VERSION);
        assert_eq!(mtproxy_ffi_api_version(), FFI_API_VERSION);
    }

    #[test]
    fn startup_handshake_accepts_expected_api() {
        assert_eq!(mtproxy_ffi_startup_handshake(FFI_API_VERSION), 0);
    }

    #[test]
    fn startup_handshake_rejects_incompatible_api() {
        assert_eq!(mtproxy_ffi_startup_handshake(FFI_API_VERSION + 1), -1);
    }

    #[test]
    fn concurrency_boundary_contract_is_reported() {
        let mut out = MtproxyConcurrencyBoundary::default();
        assert_eq!(
            unsafe { mtproxy_ffi_get_concurrency_boundary(&raw mut out) },
            0
        );
        assert_eq!(out.boundary_version, CONCURRENCY_BOUNDARY_VERSION);
        assert_eq!(out.mpq_contract_ops, MPQ_CONTRACT_OPS);
        assert_eq!(out.jobs_contract_ops, JOBS_CONTRACT_OPS);
        assert_eq!(out.mpq_implemented_ops, MPQ_IMPLEMENTED_OPS);
        assert_eq!(out.jobs_implemented_ops, JOBS_IMPLEMENTED_OPS);
    }

    #[test]
    fn network_boundary_contract_is_reported() {
        let mut out = MtproxyNetworkBoundary::default();
        assert_eq!(unsafe { mtproxy_ffi_get_network_boundary(&raw mut out) }, 0);
        assert_eq!(out.boundary_version, NETWORK_BOUNDARY_VERSION);
        assert_eq!(out.net_events_contract_ops, NET_EVENTS_CONTRACT_OPS);
        assert_eq!(out.net_events_implemented_ops, NET_EVENTS_IMPLEMENTED_OPS);
        assert_eq!(out.net_timers_contract_ops, NET_TIMERS_CONTRACT_OPS);
        assert_eq!(out.net_timers_implemented_ops, NET_TIMERS_IMPLEMENTED_OPS);
        assert_eq!(
            out.net_msg_buffers_contract_ops,
            NET_MSG_BUFFERS_CONTRACT_OPS
        );
        assert_eq!(
            out.net_msg_buffers_implemented_ops,
            NET_MSG_BUFFERS_IMPLEMENTED_OPS
        );
    }

    #[test]
    fn rpc_boundary_contract_is_reported() {
        let mut out = MtproxyRpcBoundary::default();
        assert_eq!(unsafe { mtproxy_ffi_get_rpc_boundary(&raw mut out) }, 0);
        assert_eq!(out.boundary_version, RPC_BOUNDARY_VERSION);
        assert_eq!(out.tcp_rpc_common_contract_ops, TCP_RPC_COMMON_CONTRACT_OPS);
        assert_eq!(
            out.tcp_rpc_common_implemented_ops,
            TCP_RPC_COMMON_IMPLEMENTED_OPS
        );
        assert_eq!(out.tcp_rpc_client_contract_ops, TCP_RPC_CLIENT_CONTRACT_OPS);
        assert_eq!(
            out.tcp_rpc_client_implemented_ops,
            TCP_RPC_CLIENT_IMPLEMENTED_OPS
        );
        assert_eq!(out.tcp_rpc_server_contract_ops, TCP_RPC_SERVER_CONTRACT_OPS);
        assert_eq!(
            out.tcp_rpc_server_implemented_ops,
            TCP_RPC_SERVER_IMPLEMENTED_OPS
        );
        assert_eq!(out.rpc_targets_contract_ops, RPC_TARGETS_CONTRACT_OPS);
        assert_eq!(out.rpc_targets_implemented_ops, RPC_TARGETS_IMPLEMENTED_OPS);
    }

    #[test]
    fn crypto_boundary_contract_is_reported() {
        let mut out = MtproxyCryptoBoundary::default();
        assert_eq!(unsafe { mtproxy_ffi_get_crypto_boundary(&raw mut out) }, 0);
        assert_eq!(out.boundary_version, CRYPTO_BOUNDARY_VERSION);
        assert_eq!(out.net_crypto_aes_contract_ops, NET_CRYPTO_AES_CONTRACT_OPS);
        assert_eq!(
            out.net_crypto_aes_implemented_ops,
            NET_CRYPTO_AES_IMPLEMENTED_OPS
        );
        assert_eq!(out.net_crypto_dh_contract_ops, NET_CRYPTO_DH_CONTRACT_OPS);
        assert_eq!(
            out.net_crypto_dh_implemented_ops,
            NET_CRYPTO_DH_IMPLEMENTED_OPS
        );
        assert_eq!(out.aesni_contract_ops, AESNI_CONTRACT_OPS);
        assert_eq!(out.aesni_implemented_ops, AESNI_IMPLEMENTED_OPS);
    }

    #[test]
    fn application_boundary_contract_is_reported() {
        let mut out = MtproxyApplicationBoundary::default();
        assert_eq!(
            unsafe { mtproxy_ffi_get_application_boundary(&raw mut out) },
            0
        );
        assert_eq!(out.boundary_version, APPLICATION_BOUNDARY_VERSION);
        assert_eq!(out.engine_rpc_contract_ops, ENGINE_RPC_CONTRACT_OPS);
        assert_eq!(out.engine_rpc_implemented_ops, ENGINE_RPC_IMPLEMENTED_OPS);
        assert_eq!(out.mtproto_proxy_contract_ops, MTPROTO_PROXY_CONTRACT_OPS);
        assert_eq!(
            out.mtproto_proxy_implemented_ops,
            MTPROTO_PROXY_IMPLEMENTED_OPS
        );
    }

    #[test]
    fn engine_rpc_result_helpers_match_current_rules() {
        assert_eq!(mtproxy_ffi_engine_rpc_result_new_flags(0), 0);
        assert_eq!(mtproxy_ffi_engine_rpc_result_new_flags(0x1234_5678), 0x5678);
        assert_eq!(
            mtproxy_ffi_engine_rpc_result_new_flags(i32::from_ne_bytes(
                0xffff_ffff_u32.to_ne_bytes()
            )),
            0xffff
        );
        assert_eq!(mtproxy_ffi_engine_rpc_result_header_len(0), 0);
        assert_eq!(mtproxy_ffi_engine_rpc_result_header_len(1), 8);
        assert_eq!(
            mtproxy_ffi_engine_rpc_result_header_len(i32::from_ne_bytes(
                0x8000_0000_u32.to_ne_bytes()
            )),
            8
        );
    }

    #[test]
    fn mtproto_helpers_match_current_rules() {
        assert_eq!(mtproxy_ffi_mtproto_conn_tag(0), 1);
        assert_eq!(mtproxy_ffi_mtproto_conn_tag(0x1234_5678), 0x0034_5679);
        assert_eq!(
            mtproxy_ffi_mtproto_conn_tag(i32::from_ne_bytes(0xffff_ffff_u32.to_ne_bytes())),
            0x0100_0000
        );

        let c_hash = |in_fd: i32, in_conn_id: i64, shift: i32| -> i32 {
            let in_fd_u = u64::from_ne_bytes(i64::from(in_fd).to_ne_bytes());
            let in_conn_id_u = u64::from_ne_bytes(in_conn_id.to_ne_bytes());
            let h = in_fd_u
                .wrapping_mul(11_400_714_819_323_198_485)
                .wrapping_add(in_conn_id_u.wrapping_mul(13_043_817_825_332_782_213));
            i32::try_from(h >> (64 - u32::try_from(shift).unwrap_or(0))).unwrap_or(-1)
        };
        assert_eq!(
            mtproxy_ffi_mtproto_ext_conn_hash(42, 0x1234_5678_9abc_def0_i64, 20),
            c_hash(42, 0x1234_5678_9abc_def0_i64, 20)
        );
        assert_eq!(
            mtproxy_ffi_mtproto_ext_conn_hash(-1, -17, 20),
            c_hash(-1, -17, 20)
        );
        assert_eq!(mtproxy_ffi_mtproto_ext_conn_hash(1, 2, 0), -1);
    }

    #[test]
    fn mtproto_text_parsers_are_wired_to_core_proxy_module() {
        let mut out_ip = 0u32;
        assert_eq!(
            unsafe {
                mtproxy_ffi_mtproto_parse_text_ipv4(b"127.0.0.1\0".as_ptr().cast(), &raw mut out_ip)
            },
            0
        );
        assert_eq!(out_ip, 0x7f00_0001);

        let mut out_ipv6 = [0u8; 16];
        let mut consumed = 0i32;
        assert_eq!(
            unsafe {
                mtproxy_ffi_mtproto_parse_text_ipv6(
                    b"::1\0".as_ptr().cast(),
                    out_ipv6.as_mut_ptr(),
                    &raw mut consumed,
                )
            },
            0
        );
        assert_eq!(consumed, 3);
        assert_eq!(out_ipv6, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn mtproto_packet_inspect_bridge_classifies_header_shapes() {
        let mut out = MtproxyMtprotoPacketInspectResult::default();
        let mut header = [0u8; 28];

        header[0..8].copy_from_slice(&0x1122_3344_5566_7788_i64.to_le_bytes());
        assert_eq!(
            unsafe {
                mtproxy_ffi_mtproto_inspect_packet_header(
                    header.as_ptr(),
                    header.len(),
                    64,
                    &raw mut out,
                )
            },
            0
        );
        assert_eq!(out.kind, MTPROTO_PACKET_KIND_ENCRYPTED);
        assert_eq!(out.auth_key_id, 0x1122_3344_5566_7788_i64);

        header.fill(0);
        header[16..20].copy_from_slice(&20_i32.to_le_bytes());
        header[20..24].copy_from_slice(&0x6046_9778_i32.to_le_bytes());
        assert_eq!(
            unsafe {
                mtproxy_ffi_mtproto_inspect_packet_header(
                    header.as_ptr(),
                    header.len(),
                    40,
                    &raw mut out,
                )
            },
            0
        );
        assert_eq!(out.kind, MTPROTO_PACKET_KIND_UNENCRYPTED_DH);
        assert_eq!(out.inner_len, 20);
        assert_eq!(out.function_id, 0x6046_9778_i32);

        header[20..24].copy_from_slice(&0_i32.to_le_bytes());
        assert_eq!(
            unsafe {
                mtproxy_ffi_mtproto_inspect_packet_header(
                    header.as_ptr(),
                    header.len(),
                    40,
                    &raw mut out,
                )
            },
            0
        );
        assert_eq!(out.kind, MTPROTO_PACKET_KIND_INVALID);
    }

    #[test]
    fn mtproto_parse_function_bridge_returns_core_errors_and_consumed_bytes() {
        let mut out = MtproxyMtprotoParseFunctionResult::default();
        let op = 0x1234_5678_i32.to_le_bytes();

        assert_eq!(
            unsafe { mtproxy_ffi_mtproto_parse_function(op.as_ptr(), op.len(), 1, &raw mut out) },
            0
        );
        assert_eq!(out.status, -1);
        assert_eq!(out.errnum, -2002);
        assert_eq!(out.consumed, 0);

        assert_eq!(
            unsafe { mtproxy_ffi_mtproto_parse_function(op.as_ptr(), op.len(), 0, &raw mut out) },
            0
        );
        assert_eq!(out.status, -1);
        assert_eq!(out.errnum, -2000);
        assert_eq!(out.consumed, 4);
    }

    #[test]
    fn mtproto_config_preinit_helper_returns_expected_defaults() {
        let mut out = MtproxyMtprotoCfgPreinitResult::default();
        let rc = unsafe { mtproxy_ffi_mtproto_cfg_preinit(3, 40, &raw mut out) };
        assert_eq!(rc, MTPROTO_CFG_PREINIT_OK);
        assert_eq!(out.tot_targets, 0);
        assert_eq!(out.auth_clusters, 0);
        assert_eq!(out.min_connections, 3);
        assert_eq!(out.max_connections, 40);
        assert!((out.timeout_seconds - 0.3).abs() < 1e-9);
        assert_eq!(out.default_cluster_id, 0);
    }

    #[test]
    fn mtproto_config_preinit_helper_rejects_null_output() {
        let rc = unsafe { mtproxy_ffi_mtproto_cfg_preinit(3, 40, core::ptr::null_mut()) };
        assert_eq!(rc, MTPROTO_CFG_PREINIT_ERR_INVALID_ARGS);
    }

    #[test]
    fn mtproto_config_cluster_apply_decision_helper_matches_c_rules() {
        let cluster_ids = [4, -2];
        let mut out = MtproxyMtprotoCfgClusterApplyDecisionResult::default();
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                7,
                8,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK);
        assert_eq!(out.kind, MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW);
        assert_eq!(out.cluster_index, 2);

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                -2,
                8,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK);
        assert_eq!(
            out.kind,
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST
        );
        assert_eq!(out.cluster_index, 1);
    }

    #[test]
    fn mtproto_config_cluster_apply_decision_helper_reports_errors() {
        let cluster_ids = [4, -2, 7];
        let mut out = MtproxyMtprotoCfgClusterApplyDecisionResult::default();
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                -2,
                8,
                &raw mut out,
            )
        };
        assert_eq!(
            rc,
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_PROXIES_INTERMIXED
        );

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                99,
                u32::try_from(cluster_ids.len()).expect("len fits"),
                &raw mut out,
            )
        };
        assert_eq!(
            rc,
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_TOO_MANY_AUTH_CLUSTERS
        );
    }

    #[test]
    fn mtproto_config_getlex_helper_returns_lexeme_and_advance() {
        let input = b"  proxy_for";
        let mut out = MtproxyMtprotoCfgGetlexExtResult::default();
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_getlex_ext(input.as_ptr().cast(), input.len(), &raw mut out)
        };
        assert_eq!(rc, MTPROTO_CFG_GETLEX_EXT_OK);
        assert_eq!(out.lex, i32::from(b'Y'));
        assert_eq!(out.advance, input.len());
    }

    #[test]
    fn mtproto_config_directive_token_helper_matches_parser_rules() {
        let mut out = MtproxyMtprotoCfgDirectiveTokenResult::default();

        let timeout = b"timeout 250";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_scan_directive_token(
                timeout.as_ptr().cast(),
                timeout.len(),
                2,
                64,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK);
        assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT);
        assert_eq!(out.value, 250);
        assert_eq!(out.advance, timeout.len());

        let default_cluster = b"default -2";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_scan_directive_token(
                default_cluster.as_ptr().cast(),
                default_cluster.len(),
                2,
                64,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK);
        assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER);
        assert_eq!(out.value, -2);

        let proxy_for = b"proxy_for -2   dc1:443";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_scan_directive_token(
                proxy_for.as_ptr().cast(),
                proxy_for.len(),
                2,
                64,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK);
        assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR);
        assert_eq!(out.value, -2);
        assert_eq!(out.advance, 15);

        let max_invalid = b"max_connections 1";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_scan_directive_token(
                max_invalid.as_ptr().cast(),
                max_invalid.len(),
                2,
                64,
                &raw mut out,
            )
        };
        assert_eq!(
            rc,
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MAX_CONNECTIONS
        );

        let min_invalid = b"min_connections 100";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_scan_directive_token(
                min_invalid.as_ptr().cast(),
                min_invalid.len(),
                2,
                64,
                &raw mut out,
            )
        };
        assert_eq!(
            rc,
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MIN_CONNECTIONS
        );

        let timeout_invalid = b"timeout 1";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_scan_directive_token(
                timeout_invalid.as_ptr().cast(),
                timeout_invalid.len(),
                2,
                64,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TIMEOUT);

        let target_id_invalid = b"default 40000";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_scan_directive_token(
                target_id_invalid.as_ptr().cast(),
                target_id_invalid.len(),
                2,
                64,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TARGET_ID);

        let target_space_missing = b"proxy_for 1dc1:443";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_scan_directive_token(
                target_space_missing.as_ptr().cast(),
                target_space_missing.len(),
                2,
                64,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_TARGET_ID_SPACE);

        let min_ok = b"min_connections 5";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_scan_directive_token(
                min_ok.as_ptr().cast(),
                min_ok.len(),
                2,
                64,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK);
        assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS);
        assert_eq!(out.value, 5);

        let max_ok = b"max_connections 64";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_scan_directive_token(
                max_ok.as_ptr().cast(),
                max_ok.len(),
                2,
                64,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK);
        assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS);
        assert_eq!(out.value, 64);
    }

    #[test]
    fn mtproto_config_parse_directive_step_helper_consumes_scalar_semicolon() {
        let mut out = MtproxyMtprotoCfgDirectiveStepResult::default();
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_directive_step(
                b"timeout 250;".as_ptr().cast(),
                12,
                2,
                64,
                core::ptr::null(),
                0,
                8,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK);
        assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT);
        assert_eq!(out.advance, 12);
        assert_eq!(out.value, 250);
        assert_eq!(out.cluster_decision_kind, 0);
        assert_eq!(out.cluster_index, -1);
    }

    #[test]
    fn mtproto_config_parse_directive_step_helper_returns_proxy_decision() {
        let cluster_ids = [4, -2];
        let mut out = MtproxyMtprotoCfgDirectiveStepResult::default();
        let input = b"proxy_for -2   dc1:443;";
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_directive_step(
                input.as_ptr().cast(),
                input.len(),
                2,
                64,
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                8,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK);
        assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR);
        assert_eq!(out.advance, 15);
        assert_eq!(out.value, -2);
        assert_eq!(
            out.cluster_decision_kind,
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST
        );
        assert_eq!(out.cluster_index, 1);
    }

    #[test]
    fn mtproto_config_parse_directive_step_helper_reports_expected_errors() {
        let mut out = MtproxyMtprotoCfgDirectiveStepResult::default();
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_directive_step(
                b"timeout 250".as_ptr().cast(),
                11,
                2,
                64,
                core::ptr::null(),
                0,
                8,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_EXPECTED_SEMICOLON);

        let cluster_ids = [4, -2, 7];
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_directive_step(
                b"proxy_for -2 dc1:443".as_ptr().cast(),
                20,
                2,
                64,
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                8,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXIES_INTERMIXED);
    }

    #[test]
    fn mtproto_config_parse_proxy_target_step_helper_returns_apply_mutation() {
        let cluster_ids = [-2];
        let last_cluster_state = MtproxyMtprotoOldClusterState {
            cluster_id: -2,
            targets_num: 2,
            write_targets_num: 2,
            flags: 1,
            first_target_index: 0,
            has_first_target_index: 1,
        };
        let mut out = MtproxyMtprotoCfgParseProxyTargetStepResult::default();
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
                b"dc3:445;".as_ptr().cast(),
                8,
                2,
                16,
                5,
                10,
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                -2,
                8,
                1,
                1,
                &raw const last_cluster_state,
                1,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK);
        assert_eq!(out.advance, 8);
        assert_eq!(out.target_index, 2);
        assert_eq!(out.port, 445);
        assert_eq!(out.cluster_index, 0);
        assert_eq!(
            out.cluster_decision_kind,
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST
        );
        assert_eq!(out.cluster_state_after.targets_num, 3);
        assert_eq!(
            out.cluster_targets_action,
            MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING
        );
    }

    #[test]
    fn mtproto_config_parse_proxy_target_step_helper_reports_expected_errors() {
        let cluster_ids = [4, -2, 7];
        let mut out = MtproxyMtprotoCfgParseProxyTargetStepResult::default();

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
                b"dc3:445;".as_ptr().cast(),
                8,
                2,
                16,
                5,
                10,
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                -2,
                8,
                1,
                1,
                core::ptr::null(),
                0,
                &raw mut out,
            )
        };
        assert_eq!(
            rc,
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PROXIES_INTERMIXED
        );

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
                b"dc3:445".as_ptr().cast(),
                7,
                2,
                16,
                5,
                10,
                core::ptr::null(),
                0,
                0,
                8,
                1,
                0,
                core::ptr::null(),
                0,
                &raw mut out,
            )
        };
        assert_eq!(
            rc,
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_EXPECTED_SEMICOLON
        );

        let last_cluster_state = MtproxyMtprotoOldClusterState {
            cluster_id: -2,
            targets_num: 2,
            write_targets_num: 2,
            flags: 1,
            first_target_index: 1,
            has_first_target_index: 1,
        };
        let cluster_ids = [-2];
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
                b"dc3:445;".as_ptr().cast(),
                8,
                2,
                16,
                5,
                10,
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                -2,
                8,
                1,
                1,
                &raw const last_cluster_state,
                1,
                &raw mut out,
            )
        };
        assert_eq!(
            rc,
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_CLUSTER_EXTEND_INVARIANT
        );
    }

    #[test]
    fn mtproto_config_parse_proxy_target_step_helper_create_new_reports_target_pointer_action() {
        let cluster_ids = [-2];
        let mut out = MtproxyMtprotoCfgParseProxyTargetStepResult::default();
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
                b"dc4:446;".as_ptr().cast(),
                8,
                2,
                16,
                5,
                10,
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                9,
                8,
                1,
                1,
                core::ptr::null(),
                0,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK);
        assert_eq!(out.cluster_index, 1);
        assert_eq!(
            out.cluster_decision_kind,
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW
        );
        assert_eq!(
            out.cluster_targets_action,
            MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET
        );
        assert_eq!(out.cluster_targets_index, out.target_index);
        assert_eq!(out.auth_clusters_after, 2);
        assert_eq!(out.auth_tot_clusters_after, 2);
    }

    #[test]
    fn mtproto_config_parse_full_pass_helper_returns_action_plan_and_final_state() {
        let input = b"min_connections 5; max_connections 10; timeout 250; default -2; proxy_for -2 dc1:443; proxy_for -2 dc2:444;";
        let mut actions = [MtproxyMtprotoCfgProxyAction::default(); 4];
        let mut out = MtproxyMtprotoCfgParseFullResult::default();
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_full_pass(
                input.as_ptr().cast(),
                input.len(),
                2,
                64,
                1,
                8,
                16,
                actions.as_mut_ptr(),
                u32::try_from(actions.len()).expect("len fits"),
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_PARSE_FULL_PASS_OK);
        assert_eq!(out.min_connections, 5);
        assert_eq!(out.max_connections, 10);
        assert!((out.timeout_seconds - 0.25).abs() < 1e-9);
        assert_eq!(out.default_cluster_id, -2);
        assert_eq!(out.have_proxy, 1);
        assert_eq!(out.tot_targets, 2);
        assert_eq!(out.auth_clusters, 1);
        assert_eq!(out.auth_tot_clusters, 1);
        assert_eq!(out.actions_len, 2);
        assert_eq!(out.has_default_cluster_index, 1);
        assert_eq!(out.default_cluster_index, 0);
        assert_eq!(actions[0].step.target_index, 0);
        assert_eq!(actions[0].step.port, 443);
        assert_eq!(actions[1].step.target_index, 1);
        assert_eq!(actions[1].step.port, 444);
    }

    #[test]
    fn mtproto_config_parse_full_pass_helper_reports_terminal_and_syntax_errors() {
        let mut actions = [MtproxyMtprotoCfgProxyAction::default(); 2];
        let mut out = MtproxyMtprotoCfgParseFullResult::default();

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_full_pass(
                b"timeout 100;".as_ptr().cast(),
                12,
                2,
                64,
                0,
                8,
                16,
                actions.as_mut_ptr(),
                u32::try_from(actions.len()).expect("len fits"),
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES);

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_full_pass(
                b"proxy dc1:443".as_ptr().cast(),
                13,
                2,
                64,
                0,
                8,
                16,
                actions.as_mut_ptr(),
                u32::try_from(actions.len()).expect("len fits"),
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON);
    }

    #[test]
    fn mtproto_config_expect_semicolon_helper_matches_parser_behavior() {
        let mut advance = 0usize;
        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_expect_semicolon(b";".as_ptr().cast(), 1, &raw mut advance)
        };
        assert_eq!(rc, MTPROTO_CFG_EXPECT_SEMICOLON_OK);
        assert_eq!(advance, 1);

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_expect_semicolon(b" ".as_ptr().cast(), 1, &raw mut advance)
        };
        assert_eq!(rc, MTPROTO_CFG_EXPECT_SEMICOLON_ERR_EXPECTED);
    }

    #[test]
    fn mtproto_config_cluster_lookup_helper_matches_c_rules() {
        let cluster_ids = [-2, 0, 7];
        let mut out_cluster_index = -1;

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                0,
                0,
                0,
                0,
                &raw mut out_cluster_index,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK);
        assert_eq!(out_cluster_index, 1);

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                42,
                0,
                0,
                0,
                &raw mut out_cluster_index,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND);
        assert_eq!(out_cluster_index, -1);

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                42,
                1,
                2,
                1,
                &raw mut out_cluster_index,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK);
        assert_eq!(out_cluster_index, 2);
    }

    #[test]
    fn mtproto_config_finalize_helper_enforces_terminal_checks() {
        let cluster_ids = [-2, 0];
        let mut out = MtproxyMtprotoCfgFinalizeResult::default();

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_finalize(
                1,
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                0,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_FINALIZE_OK);
        assert_eq!(out.has_default_cluster_index, 1);
        assert_eq!(out.default_cluster_index, 1);

        let rc = unsafe {
            mtproxy_ffi_mtproto_cfg_finalize(
                0,
                cluster_ids.as_ptr(),
                u32::try_from(cluster_ids.len()).expect("len fits"),
                0,
                &raw mut out,
            )
        };
        assert_eq!(rc, MTPROTO_CFG_FINALIZE_ERR_MISSING_PROXY_DIRECTIVES);

        let rc =
            unsafe { mtproxy_ffi_mtproto_cfg_finalize(1, core::ptr::null(), 0, 0, &raw mut out) };
        assert_eq!(rc, MTPROTO_CFG_FINALIZE_ERR_NO_PROXY_SERVERS_DEFINED);
    }

    #[test]
    fn crypto_dh_prefix_check_matches_current_rules() {
        let prime_prefix = [0x89u8, 0x52, 0x13, 0x1b, 0x1e, 0x3a, 0x69, 0xba];
        let mut data = [0u8; 256];
        assert_eq!(
            unsafe {
                mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin(
                    data.as_ptr(),
                    data.len(),
                    prime_prefix.as_ptr(),
                    prime_prefix.len(),
                )
            },
            0
        );
        data[7] = 1;
        assert_eq!(
            unsafe {
                mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin(
                    data.as_ptr(),
                    data.len(),
                    prime_prefix.as_ptr(),
                    prime_prefix.len(),
                )
            },
            1
        );
        data[0] = 0x90;
        assert_eq!(
            unsafe {
                mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin(
                    data.as_ptr(),
                    data.len(),
                    prime_prefix.as_ptr(),
                    prime_prefix.len(),
                )
            },
            0
        );
    }

    #[test]
    fn crypto_aes_create_keys_is_deterministic_for_fixed_input() {
        let nonce_server = [0x11u8; 16];
        let nonce_client = [0x22u8; 16];
        let server_ipv6 = [0x33u8; 16];
        let client_ipv6 = [0x44u8; 16];
        let secret = [0x55u8; 32];
        let temp_key = [0x66u8; 64];

        let mut out_a = MtproxyAesKeyData::default();
        let mut out_b = MtproxyAesKeyData::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_crypto_aes_create_keys(
                    &raw mut out_a,
                    1,
                    nonce_server.as_ptr(),
                    nonce_client.as_ptr(),
                    1_700_000_000,
                    0x0a00_0001,
                    443,
                    server_ipv6.as_ptr(),
                    0x0a00_0002,
                    32000,
                    client_ipv6.as_ptr(),
                    secret.as_ptr(),
                    i32::try_from(secret.len()).unwrap_or(i32::MAX),
                    temp_key.as_ptr(),
                    i32::try_from(temp_key.len()).unwrap_or(i32::MAX),
                )
            },
            1
        );
        assert_eq!(
            unsafe {
                mtproxy_ffi_crypto_aes_create_keys(
                    &raw mut out_b,
                    1,
                    nonce_server.as_ptr(),
                    nonce_client.as_ptr(),
                    1_700_000_000,
                    0x0a00_0001,
                    443,
                    server_ipv6.as_ptr(),
                    0x0a00_0002,
                    32000,
                    client_ipv6.as_ptr(),
                    secret.as_ptr(),
                    i32::try_from(secret.len()).unwrap_or(i32::MAX),
                    temp_key.as_ptr(),
                    i32::try_from(temp_key.len()).unwrap_or(i32::MAX),
                )
            },
            1
        );
        assert_eq!(out_a, out_b);
        assert_ne!(out_a.write_key, [0u8; 32]);
        assert_ne!(out_a.read_key, [0u8; 32]);
    }

    #[test]
    fn crypto_aes_create_keys_rejects_short_secret() {
        let nonce_server = [0x11u8; 16];
        let nonce_client = [0x22u8; 16];
        let server_ipv6 = [0x33u8; 16];
        let client_ipv6 = [0x44u8; 16];
        let secret = [0x55u8; 16];
        let temp_key = [0x66u8; 8];
        let mut out = MtproxyAesKeyData::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_crypto_aes_create_keys(
                    &raw mut out,
                    0,
                    nonce_server.as_ptr(),
                    nonce_client.as_ptr(),
                    1_700_000_000,
                    0,
                    443,
                    server_ipv6.as_ptr(),
                    0,
                    32000,
                    client_ipv6.as_ptr(),
                    secret.as_ptr(),
                    i32::try_from(secret.len()).unwrap_or(i32::MAX),
                    temp_key.as_ptr(),
                    i32::try_from(temp_key.len()).unwrap_or(i32::MAX),
                )
            },
            -1
        );
    }

    #[test]
    fn aesni_crypt_rejects_invalid_args() {
        assert_eq!(
            unsafe {
                mtproxy_ffi_aesni_crypt(
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    16,
                )
            },
            -1
        );
        assert_eq!(
            unsafe {
                mtproxy_ffi_aesni_crypt(
                    core::ptr::dangling_mut::<core::ffi::c_void>(),
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    -1,
                )
            },
            -1
        );
    }

    #[test]
    fn crypto_dh_roundtrip_exports_work() {
        assert_eq!(mtproxy_ffi_crypto_dh_get_params_select(), DH_PARAMS_SELECT);

        let mut g_a = [0u8; DH_KEY_BYTES];
        let mut a = [0u8; DH_KEY_BYTES];
        assert_eq!(
            unsafe { mtproxy_ffi_crypto_dh_first_round(g_a.as_mut_ptr(), a.as_mut_ptr()) },
            1
        );
        assert_ne!(g_a, [0u8; DH_KEY_BYTES]);
        assert_ne!(a, [0u8; DH_KEY_BYTES]);

        let mut g_ab = [0u8; DH_KEY_BYTES];
        assert_eq!(
            unsafe {
                mtproxy_ffi_crypto_dh_third_round(g_ab.as_mut_ptr(), g_a.as_ptr(), a.as_ptr())
            },
            i32::try_from(DH_KEY_BYTES).unwrap_or(i32::MAX)
        );
        assert_ne!(g_ab, [0u8; DH_KEY_BYTES]);

        let mut g_a_srv = [0u8; DH_KEY_BYTES];
        let mut g_ab_srv = [0u8; DH_KEY_BYTES];
        assert_eq!(
            unsafe {
                mtproxy_ffi_crypto_dh_second_round(
                    g_ab_srv.as_mut_ptr(),
                    g_a_srv.as_mut_ptr(),
                    g_a.as_ptr(),
                )
            },
            i32::try_from(DH_KEY_BYTES).unwrap_or(i32::MAX)
        );
        assert_ne!(g_a_srv, [0u8; DH_KEY_BYTES]);
        assert_ne!(g_ab_srv, [0u8; DH_KEY_BYTES]);
    }

    #[test]
    fn aesni_context_lifecycle_is_exported() {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        let mut input = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() {
            *b = u8::try_from(0x80 + i).unwrap_or(0);
        }
        for (i, b) in iv.iter_mut().enumerate() {
            *b = u8::try_from(0x90 + i).unwrap_or(0);
        }
        for (i, b) in input.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }

        let mut ctx: *mut core::ffi::c_void = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                mtproxy_ffi_aesni_ctx_init(
                    AESNI_CIPHER_AES_256_CTR,
                    key.as_ptr(),
                    iv.as_ptr(),
                    1,
                    &raw mut ctx,
                )
            },
            0
        );
        assert!(!ctx.is_null());
        let mut output = [0u8; 64];
        assert_eq!(
            unsafe { mtproxy_ffi_aesni_crypt(ctx, input.as_ptr(), output.as_mut_ptr(), 64) },
            0
        );
        assert_ne!(output, [0u8; 64]);
        assert_eq!(unsafe { mtproxy_ffi_aesni_ctx_free(ctx) }, 0);
    }

    #[test]
    fn tls_public_key_and_rand_exports_work() {
        let mut random = [0u8; 7];
        assert_eq!(
            unsafe {
                mtproxy_ffi_crypto_rand_bytes(
                    random.as_mut_ptr(),
                    i32::try_from(random.len()).unwrap_or(i32::MAX),
                )
            },
            0
        );
        assert_ne!(random, [0u8; 7]);

        let mut public_key = [0u8; TLS_REQUEST_PUBLIC_KEY_BYTES];
        assert_eq!(
            unsafe { mtproxy_ffi_crypto_tls_generate_public_key(public_key.as_mut_ptr()) },
            0
        );
        assert_ne!(public_key, [0u8; TLS_REQUEST_PUBLIC_KEY_BYTES]);
    }

    #[test]
    fn net_epoll_flag_conversions_match_c_semantics() {
        let evt_read = i32::from_ne_bytes(EVT_READ.to_ne_bytes());
        let evt_write = i32::from_ne_bytes(EVT_WRITE.to_ne_bytes());
        let evt_spec = i32::from_ne_bytes(EVT_SPEC.to_ne_bytes());
        let evt_level = i32::from_ne_bytes(EVT_LEVEL.to_ne_bytes());

        let conv = mtproxy_ffi_net_epoll_conv_flags(evt_read | evt_spec);
        let conv_u = u32::from_ne_bytes(conv.to_ne_bytes());
        assert_ne!(conv_u & EPOLLERR, 0);
        assert_ne!(conv_u & EPOLLIN, 0);
        assert_ne!(conv_u & EPOLLRDHUP, 0);
        assert_ne!(conv_u & EPOLLPRI, 0);
        assert_ne!(conv_u & EPOLLET, 0);

        let conv_level = mtproxy_ffi_net_epoll_conv_flags(evt_read | evt_write | evt_level);
        let conv_level_u = u32::from_ne_bytes(conv_level.to_ne_bytes());
        assert_ne!(conv_level_u & EPOLLIN, 0);
        assert_ne!(conv_level_u & EPOLLOUT, 0);
        assert_eq!(conv_level_u & EPOLLET, 0);

        let unconv = mtproxy_ffi_net_epoll_unconv_flags(i32::from_ne_bytes(
            (EPOLLIN | EPOLLOUT | EPOLLERR).to_ne_bytes(),
        ));
        let unconv_u = u32::from_ne_bytes(unconv.to_ne_bytes());
        assert_ne!(unconv_u & EVT_FROM_EPOLL, 0);
        assert_ne!(unconv_u & EVT_READ, 0);
        assert_ne!(unconv_u & EVT_WRITE, 0);
        assert_eq!(unconv_u & EVT_SPEC, 0);
    }

    #[test]
    fn net_timers_wait_msec_matches_current_formula() {
        assert_eq!(mtproxy_ffi_net_timers_wait_msec(10.125, 10.000), 126);
        assert_eq!(mtproxy_ffi_net_timers_wait_msec(10.000, 10.010), 0);
        assert_eq!(mtproxy_ffi_net_timers_wait_msec(10.000, 10.000), 0);
    }

    #[test]
    fn msg_buffers_pick_size_index_matches_c_policy() {
        let sizes = [48, 512, 2_048, 16_384, 262_144];
        let all_idx = unsafe {
            mtproxy_ffi_msg_buffers_pick_size_index(
                sizes.as_ptr(),
                i32::try_from(sizes.len()).unwrap_or(i32::MAX),
                -1,
            )
        };
        assert_eq!(all_idx, 4);

        let idx = unsafe {
            mtproxy_ffi_msg_buffers_pick_size_index(
                sizes.as_ptr(),
                i32::try_from(sizes.len()).unwrap_or(i32::MAX),
                3000,
            )
        };
        assert_eq!(idx, 3);

        let tiny = unsafe {
            mtproxy_ffi_msg_buffers_pick_size_index(
                sizes.as_ptr(),
                i32::try_from(sizes.len()).unwrap_or(i32::MAX),
                40,
            )
        };
        assert_eq!(tiny, 0);
    }

    #[test]
    fn tcp_rpc_compact_header_encoding_matches_c_logic() {
        let mut prefix_word = 0;
        let mut prefix_bytes = 0;
        assert_eq!(
            unsafe {
                mtproxy_ffi_tcp_rpc_encode_compact_header(
                    512,
                    1,
                    &raw mut prefix_word,
                    &raw mut prefix_bytes,
                )
            },
            0
        );
        assert_eq!(prefix_word, 512);
        assert_eq!(prefix_bytes, 4);

        assert_eq!(
            unsafe {
                mtproxy_ffi_tcp_rpc_encode_compact_header(
                    64,
                    0,
                    &raw mut prefix_word,
                    &raw mut prefix_bytes,
                )
            },
            0
        );
        assert_eq!(prefix_word, 16);
        assert_eq!(prefix_bytes, 1);

        assert_eq!(
            unsafe {
                mtproxy_ffi_tcp_rpc_encode_compact_header(
                    2000,
                    0,
                    &raw mut prefix_word,
                    &raw mut prefix_bytes,
                )
            },
            0
        );
        let expected_u = (u32::from_ne_bytes(2000_i32.to_ne_bytes()) << 6) | 0x7f;
        assert_eq!(u32::from_ne_bytes(prefix_word.to_ne_bytes()), expected_u);
        assert_eq!(prefix_bytes, 4);
    }

    #[test]
    fn tcp_rpc_packet_len_state_helpers_match_current_rules() {
        assert_eq!(
            mtproxy_ffi_tcp_rpc_client_packet_len_state(4, 1024),
            TCP_RPC_PACKET_LEN_STATE_SKIP
        );
        assert_eq!(
            mtproxy_ffi_tcp_rpc_client_packet_len_state(12, 1024),
            TCP_RPC_PACKET_LEN_STATE_SHORT
        );
        assert_eq!(
            mtproxy_ffi_tcp_rpc_client_packet_len_state(16, 1024),
            TCP_RPC_PACKET_LEN_STATE_READY
        );
        assert_eq!(
            mtproxy_ffi_tcp_rpc_client_packet_len_state(3, 1024),
            TCP_RPC_PACKET_LEN_STATE_INVALID
        );
        assert_eq!(
            mtproxy_ffi_tcp_rpc_client_packet_len_state(2048, 1024),
            TCP_RPC_PACKET_LEN_STATE_INVALID
        );

        assert_eq!(mtproxy_ffi_tcp_rpc_server_packet_header_malformed(0), 1);
        assert_eq!(
            mtproxy_ffi_tcp_rpc_server_packet_header_malformed(i32::from_ne_bytes(
                0xc000_0000_u32.to_ne_bytes()
            )),
            1
        );
        assert_eq!(mtproxy_ffi_tcp_rpc_server_packet_header_malformed(16), 0);
        assert_eq!(
            mtproxy_ffi_tcp_rpc_server_packet_len_state(4, 1024),
            TCP_RPC_PACKET_LEN_STATE_SKIP
        );
        assert_eq!(
            mtproxy_ffi_tcp_rpc_server_packet_len_state(16, 1024),
            TCP_RPC_PACKET_LEN_STATE_READY
        );
        assert_eq!(
            mtproxy_ffi_tcp_rpc_server_packet_len_state(2048, 1024),
            TCP_RPC_PACKET_LEN_STATE_INVALID
        );
    }

    #[test]
    fn rpc_target_pid_normalization_matches_c_fallback() {
        let mut pid = MtproxyProcessId {
            ip: 0,
            port: 443,
            pid: 10,
            utime: 100,
        };
        assert_eq!(
            unsafe { mtproxy_ffi_rpc_target_normalize_pid(&raw mut pid, 0x7f00_0001) },
            0
        );
        assert_eq!(pid.ip, 0x7f00_0001);
    }

    #[test]
    fn crc32_matches_known_vector() {
        let data = b"123456789";
        // compute_crc32 semantics: crc32_partial(seed=~0) ^ ~0
        let partial = unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), data.len(), u32::MAX) };
        let final_crc = partial ^ u32::MAX;
        assert_eq!(final_crc, 0xcbf4_3926);
    }

    #[test]
    fn crc32_is_incremental() {
        let data = b"incremental-crc32-test-vector";

        let full = unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), data.len(), 0x1234_5678) };

        let first = unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), 8, 0x1234_5678) };
        let rest_ptr = data[8..].as_ptr();
        let rest_len = data.len() - 8;
        let split = unsafe { mtproxy_ffi_crc32_partial(rest_ptr, rest_len, first) };

        assert_eq!(full, split);
    }

    #[test]
    fn crc32c_matches_known_vector() {
        let data = b"123456789";
        let partial = unsafe { mtproxy_ffi_crc32c_partial(data.as_ptr(), data.len(), u32::MAX) };
        let final_crc = partial ^ u32::MAX;
        assert_eq!(final_crc, 0xe306_9283);
    }

    #[test]
    fn crc32_check_and_repair_fixes_single_bit_flip() {
        let mut data = *b"abcdef012345";
        let original_crc =
            (unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), data.len(), u32::MAX) }) ^ u32::MAX;
        let mut stored_crc = original_crc;
        data[4] ^= 0x04;

        let rc = unsafe {
            mtproxy_ffi_crc32_check_and_repair(data.as_mut_ptr(), data.len(), &raw mut stored_crc)
        };
        assert_eq!(rc, 1);
        assert_eq!(stored_crc, original_crc);
        assert_eq!(&data, b"abcdef012345");
    }

    #[test]
    fn gf32_combine_clmul_matches_legacy_vector_when_supported() {
        #[cfg(target_arch = "x86_64")]
        {
            if !std::arch::is_x86_feature_detected!("pclmulqdq") {
                return;
            }
        }

        let mut powers = [0u32; GF32_CLMUL_POWERS_LEN];
        unsafe {
            mtproxy_ffi_gf32_compute_powers_clmul(powers.as_mut_ptr(), CRC32_REFLECTED_POLY);
        }
        let out = unsafe { mtproxy_ffi_gf32_combine_clmul(powers.as_ptr(), 0x89ab_cdef, 17) };
        assert_eq!(out, 0x7be9_6e74_df25_97cc);
    }

    #[test]
    fn pid_helpers_match_expected_semantics() {
        let mut pid = MtproxyProcessId::default();
        let rc = unsafe { mtproxy_ffi_pid_init_common(&raw mut pid) };
        assert_eq!(rc, 0);
        let raw_pid = unsafe { super::getpid() };
        let raw_pid_bits = u32::from_ne_bytes(raw_pid.to_ne_bytes());
        let expected_pid = u16::try_from(raw_pid_bits & u32::from(u16::MAX)).unwrap_or_default();
        assert_eq!(pid.pid, expected_pid);
        assert_ne!(pid.pid, 0);
        assert_ne!(pid.utime, 0);

        let mut y = pid;
        y.pid = 0;
        assert_eq!(
            unsafe { mtproxy_ffi_matches_pid(&raw const pid, &raw const y) },
            1
        );
        y.pid = pid.pid;
        assert_eq!(
            unsafe { mtproxy_ffi_matches_pid(&raw const pid, &raw const y) },
            2
        );
    }

    #[test]
    fn process_id_is_newer_follows_pid_window_rule() {
        let a = MtproxyProcessId {
            ip: 1,
            port: 80,
            pid: 1000,
            utime: 10,
        };
        let mut b = a;
        b.pid = 900;
        assert_eq!(
            unsafe { mtproxy_ffi_process_id_is_newer(&raw const a, &raw const b) },
            1
        );
    }

    #[test]
    fn cpuid_fill_produces_magic_on_x86() {
        let mut out = MtproxyCpuid::default();
        let rc = unsafe { mtproxy_ffi_cpuid_fill(&raw mut out) };
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            assert_eq!(rc, 0);
            assert_eq!(out.magic, CPUID_MAGIC);
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            assert_eq!(rc, -2);
        }
    }

    #[test]
    fn md5_and_md5_hex_match_known_vector() {
        let data = b"123456789";
        let mut digest = [0u8; 16];
        assert_eq!(
            unsafe { mtproxy_ffi_md5(data.as_ptr(), data.len(), digest.as_mut_ptr()) },
            0
        );
        assert_eq!(
            digest,
            [
                0x25, 0xf9, 0xe7, 0x94, 0x32, 0x3b, 0x45, 0x38, 0x85, 0xf5, 0x18, 0x1f, 0x1b, 0x62,
                0x4d, 0x0b,
            ]
        );

        let mut hex = [0i8; 32];
        assert_eq!(
            unsafe { mtproxy_ffi_md5_hex(data.as_ptr(), data.len(), hex.as_mut_ptr()) },
            0
        );
        let hex_bytes: Vec<u8> = hex
            .iter()
            .map(|v| u8::try_from(*v).unwrap_or_default())
            .collect();
        assert_eq!(&hex_bytes, b"25f9e794323b453885f5181f1b624d0b");
    }

    #[test]
    fn sha1_matches_known_vector_and_two_chunk_variant() {
        let data = b"abc";
        let mut digest = [0u8; 20];
        assert_eq!(
            unsafe { mtproxy_ffi_sha1(data.as_ptr(), data.len(), digest.as_mut_ptr()) },
            0
        );
        assert_eq!(
            digest,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        );

        let mut split_digest = [0u8; 20];
        assert_eq!(
            unsafe {
                mtproxy_ffi_sha1_two_chunks(
                    b"a".as_ptr(),
                    1,
                    b"bc".as_ptr(),
                    2,
                    split_digest.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(digest, split_digest);
    }

    #[test]
    fn sha256_and_hmac_match_known_vectors() {
        let data = b"abc";
        let mut digest = [0u8; 32];
        assert_eq!(
            unsafe { mtproxy_ffi_sha256(data.as_ptr(), data.len(), digest.as_mut_ptr()) },
            0
        );
        assert_eq!(
            digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );

        let mut split_digest = [0u8; 32];
        assert_eq!(
            unsafe {
                mtproxy_ffi_sha256_two_chunks(
                    b"a".as_ptr(),
                    1,
                    b"bc".as_ptr(),
                    2,
                    split_digest.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(digest, split_digest);

        let mut hmac = [0u8; 32];
        assert_eq!(
            unsafe {
                mtproxy_ffi_sha256_hmac(
                    b"key".as_ptr(),
                    3,
                    b"The quick brown fox jumps over the lazy dog".as_ptr(),
                    43,
                    hmac.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(
            hmac,
            [
                0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f,
                0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc,
                0x2d, 0x1a, 0x3c, 0xd8,
            ]
        );
    }

    #[test]
    fn precise_time_exports_update_thread_local_values() {
        let t = mtproxy_ffi_get_utime_monotonic();
        assert!(t > 0.0);
        assert!(mtproxy_ffi_precise_now_value() > 0.0);
        assert!(mtproxy_ffi_precise_now_rdtsc_value() >= 0);

        let p = mtproxy_ffi_get_precise_time(0);
        assert!(p >= 0);
    }

    #[test]
    fn cfg_primitives_scan_lengths_and_signed_int() {
        let src = b" \t# comment\nproxy_for -123;";
        let mut scan = MtproxyCfgScanResult::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_cfg_skipspc(
                    src.as_ptr().cast(),
                    src.len(),
                    0,
                    (&raw mut scan).cast::<MtproxyCfgScanResult>(),
                )
            },
            0
        );
        assert_eq!(scan.line_no, 1);
        assert_eq!(scan.ch, i32::from(b'p'));

        let word_ptr = unsafe { src.as_ptr().add(scan.advance) };
        assert_eq!(
            unsafe { mtproxy_ffi_cfg_getword_len(word_ptr.cast(), src.len() - scan.advance) },
            9
        );

        let int_ptr = unsafe { word_ptr.add(9) };
        let mut parsed = MtproxyCfgIntResult::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_cfg_getint_signed_zero(
                    int_ptr.cast(),
                    src.len() - scan.advance - 9,
                    &raw mut parsed,
                )
            },
            0
        );
        assert_eq!(parsed.value, -123);
        assert!(parsed.consumed >= 4);
    }

    #[test]
    fn tl_parse_query_and_answer_header_vectors() {
        let mut query = Vec::new();
        query.extend_from_slice(&RPC_INVOKE_REQ.to_le_bytes());
        query.extend_from_slice(&0x1122_3344_5566_7788_i64.to_le_bytes());
        query.extend_from_slice(&0x166b_b7c6_i32.to_le_bytes());

        let mut q = MtproxyTlHeaderParseResult::default();
        assert_eq!(
            unsafe { mtproxy_ffi_tl_parse_query_header(query.as_ptr(), query.len(), &raw mut q) },
            0
        );
        assert_eq!(q.status, 0);
        assert_eq!(q.consumed, 12);
        assert_eq!(q.op, RPC_INVOKE_REQ);

        let mut answer = Vec::new();
        answer.extend_from_slice(&RPC_REQ_RESULT.to_le_bytes());
        answer.extend_from_slice(&0x0102_0304_0506_0708_i64.to_le_bytes());
        answer.extend_from_slice(&0x166b_b7c6_i32.to_le_bytes());

        let mut a = MtproxyTlHeaderParseResult::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_tl_parse_answer_header(answer.as_ptr(), answer.len(), &raw mut a)
            },
            0
        );
        assert_eq!(a.status, 0);
        assert_eq!(a.consumed, 12);
        assert_eq!(a.op, RPC_REQ_RESULT);
    }

    #[test]
    fn observability_helpers_parse_and_format() {
        let statm = b"10 20 30 40 50 60";
        let mut out = [0i64; 6];
        assert_eq!(
            unsafe {
                mtproxy_ffi_parse_statm(
                    statm.as_ptr().cast(),
                    statm.len(),
                    6,
                    4096,
                    out.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(out[0], 10 * 4096);
        assert_eq!(out[5], 60 * 4096);

        let meminfo = b"MemFree: 1 kB\nCached: 2 kB\nSwapTotal: 3 kB\nSwapFree: 4 kB\n";
        let mut summary = MtproxyMeminfoSummary::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_parse_meminfo_summary(
                    meminfo.as_ptr().cast(),
                    meminfo.len(),
                    &raw mut summary,
                )
            },
            0
        );
        assert_eq!(summary.found_mask, 15);
        assert_eq!(summary.mem_free, 1024);

        let proc_line = b"1 (x) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39\n";
        let mut ps = MtproxyProcStats::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_parse_proc_stat_line(
                    proc_line.as_ptr().cast(),
                    proc_line.len(),
                    &raw mut ps,
                )
            },
            0
        );
        assert_eq!(ps.pid, 1);
        assert_eq!(ps.state, i8::from_ne_bytes([b'R']));

        let mut ps_live = MtproxyProcStats::default();
        let pid = unsafe { super::getpid() };
        assert_eq!(
            unsafe { mtproxy_ffi_read_proc_stat_file(pid, 0, &raw mut ps_live) },
            0
        );
        assert_eq!(ps_live.pid, pid);
    }
}
