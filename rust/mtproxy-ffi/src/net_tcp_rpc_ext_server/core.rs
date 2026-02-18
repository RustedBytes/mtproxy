//! Rust runtime implementation for selected large functions in
//! `net/net-tcp-rpc-ext-server.c`.

use core::ffi::{c_char, c_double, c_int, c_long, c_short, c_void};
use core::mem::size_of;
use core::ptr;
use core::slice;
use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

pub(super) type ConnectionJob = *mut c_void;

const CONN_CUSTOM_DATA_BYTES: usize = 256;
const NEED_MORE_BYTES: c_int = 0x7fff_ffff;

const C_ERROR: c_int = 8;
const C_STOPPARSE: c_int = 0x400000;
const C_IS_TLS: c_int = 0x8000000;

const RPCF_COMPACT_OFF: c_int = 1024;

const RPC_F_PAD: c_int = 0x0800_0000;
const RPC_F_MEDIUM: c_int = 0x2000_0000;
const RPC_F_COMPACT: c_int = 0x4000_0000;
const RPC_F_QUICKACK: c_int = c_int::MIN;
const RPC_F_EXTMODE1: c_int = 0x0001_0000;
const RPC_F_EXTMODE2: c_int = 0x0002_0000;

const RPC_PING: c_int = 0x5730_a2df_u32 as c_int;
const JS_RUN: c_int = 0;

const TCP_RPCS_ALLOW_UNOBFS: bool = false;

const TLS_REQUEST_LENGTH: usize = 517;
const MAX_GREASE: usize = 7;

const TLS_PROBE_TRIES: usize = 20;
const TLS_PROBE_TIMEOUT_SEC: c_double = 5.0;
const MAX_CLIENT_HELLO_READ: usize = 4096;
const DOMAIN_HASH_MOD: usize = 257;
const EXT_SECRET_LIMIT: usize = 16;

const SERVER_HELLO_PROFILE_FIXED: c_int = 0;
const SERVER_HELLO_PROFILE_RANDOM_NEAR: c_int = 1;
const SERVER_HELLO_PROFILE_RANDOM_AVG: c_int = 2;

const ERR_TOO_SHORT: &[u8] = b"Too short\0";
const ERR_NON_TLS_1: &[u8] = b"Non-TLS response or TLS <= 1.1\0";
const ERR_SERVER_HELLO_SHORT: &[u8] = b"Receive too short ServerHello\0";
const ERR_NON_TLS_2: &[u8] = b"Non-TLS response 2\0";
const ERR_NON_TLS_3: &[u8] = b"Non-TLS response 3\0";
const ERR_HELLO_RETRY: &[u8] = b"TLS 1.3 servers returning HelloRetryRequest are not supprted\0";
const ERR_TLS12_EMPTY_SESSION: &[u8] = b"TLS <= 1.2: empty session_id\0";
const ERR_NON_TLS_4: &[u8] = b"Non-TLS response 4\0";
const ERR_SERVER_HELLO_SHORT_2: &[u8] = b"Receive too short server hello 2\0";
const ERR_TLS12_EXPECTED_SESSION: &[u8] = b"TLS <= 1.2: expected mirrored session_id\0";
const ERR_TLS12_EXPECTED_CIPHER: &[u8] = b"TLS <= 1.2: expected x25519 as a chosen cipher\0";
const ERR_WRONG_EXT_LEN: &[u8] = b"Receive wrong extensions length\0";
const ERR_UNEXPECTED_EXT: &[u8] = b"Receive unexpected extension\0";
const ERR_WRONG_EXT_ITEM_LEN: &[u8] = b"Receive wrong extension length\0";
const ERR_UNEXPECTED_EXT_ITEM_LEN: &[u8] = b"Unexpected extension length\0";
const ERR_DUP_EXT: &[u8] = b"Receive duplicate extensions\0";
const ERR_WRONG_EXT_LIST: &[u8] = b"Receive wrong extensions list\0";
const ERR_EXPECTED_CCS: &[u8] = b"Expected dummy ChangeCipherSpec\0";
const ERR_EXPECTED_APP_DATA: &[u8] = b"Expected encrypted application data\0";
const ERR_EMPTY_APP_DATA: &[u8] = b"Receive empty encrypted application data\0";
const ERR_TOO_LONG: &[u8] = b"Too long\0";

const TLS_PARSE_FAIL_FMT: &[u8] = b"Failed to parse upstream TLS response: %s\n\0";

const PROBE_FAIL_RESOLVE_FMT: &[u8] = b"Failed to resolve host %s\n\0";
const PROBE_FAIL_SOCKET_FMT: &[u8] = b"Failed to open socket for %s: %s\n\0";
const PROBE_FAIL_NONBLOCK_FMT: &[u8] = b"Failed to make socket non-blocking: %s\n\0";
const PROBE_FAIL_CONNECT_FMT: &[u8] = b"Failed to connect to %s: %s\n\0";
const PROBE_FAIL_HEADER_FMT: &[u8] =
    b"Failed to read response header for checking domain %s: %s\n\0";
const PROBE_NON_TLS_FMT: &[u8] = b"Non-TLS response, or TLS <= 1.1, or unsuccessful request to %s: receive bytes %02x %02x %02x %02x %02x...\n\0";
const PROBE_FAIL_READ_FMT: &[u8] = b"Failed to read response from %s: %s\n\0";
const PROBE_NO_TLS13_FMT: &[u8] = b"Not found TLS 1.3 support on domain %s\n\0";
const PROBE_FAIL_EXCEPT_FMT: &[u8] = b"Failed to check domain %s: %s\n\0";
const PROBE_FAIL_WRITE_FMT: &[u8] = b"Failed to write request for checking domain %s: %s\n\0";
const PROBE_TIMEOUT_FMT: &[u8] = b"Failed to check domain %s in 5 seconds\n\0";
const PROBE_NON_DETERMINISTIC_EXT_FMT: &[u8] =
    b"Upstream server %s uses non-deterministic extension order\n\0";
const PROBE_UNRECOGNIZED_PATTERN_FMT: &[u8] =
    b"Unrecognized encrypted application data length pattern with min = %d, max = %d, mean = %.3lf\n\0";
const PROBE_SUCCESS_FMT: &[u8] =
    b"Successfully checked domain %s in %.3lf seconds: is_reversed_extension_order = %d, server_hello_encrypted_size = %d, use_random_encrypted_size = %d\n\0";
const PROBE_UNSUPPORTED_MULTI_PACKET_FMT: &[u8] =
    b"Multiple encrypted client data packets are unsupported, so handshake with %s will not be fully emulated\n\0";

const PARSE_TRY_TYPE_FMT: &[u8] = b"trying to determine type of connection from %s:%d\n\0";
const PARSE_TLS_ESTABLISHED_FMT: &[u8] = b"Established TLS connection from %s:%d\n\0";
const PARSE_BAD_CCS_FMT: &[u8] =
    b"error while parsing packet: bad client dummy ChangeCipherSpec\n\0";
const PARSE_TLS_FIRST_TOO_SHORT_FMT: &[u8] =
    b"error while parsing packet: too short first TLS packet: %d\n\0";
const PARSE_TLS_FIRST_PACKET_FMT: &[u8] = b"Receive first TLS packet of length %d\n\0";
const PARSE_TLS_DOMAIN_FMT: &[u8] = b"TLS type with domain %s from %s:%d\n\0";
const PARSE_TLS_PORT80_FMT: &[u8] = b"Receive TLS request on port %d, proxying to %s\n\0";
const PARSE_TLS_TOO_MUCH_DATA_FMT: &[u8] =
    b"Too much data in ClientHello, receive %d instead of %d\n\0";
const PARSE_TLS_TOO_BIG_FMT: &[u8] = b"Too big ClientHello: receive %d bytes\n\0";
const PARSE_TLS_DUP_RANDOM_FMT: &[u8] = b"Receive again request with the same client random\n\0";
const PARSE_TLS_UNMATCHED_RANDOM_FMT: &[u8] = b"Receive request with unmatched client random\n\0";
const PARSE_TLS_CIPHER_LIST_TOO_LONG_FMT: &[u8] = b"Too long cipher suites list of length %d\n\0";
const PARSE_TLS_NO_CIPHER_FMT: &[u8] = b"Can't find supported cipher suite\n\0";
const PARSE_EXPECT_TLS_FMT: &[u8] = b"Expected TLS-transport\n\0";
const PARSE_NEED_MORE_RANDOM_HEADER_FMT: &[u8] =
    b"\"random\" 64-byte header: have %d bytes, need %d more bytes to distinguish\n\0";
const PARSE_EXPECT_PAD_MODE_FMT: &[u8] = b"Expected random padding mode\n\0";
const PARSE_OPPORTUNISTIC_FMT: &[u8] =
    b"tcp opportunistic encryption mode detected, tag = %08x, target=%d\n\0";
const PARSE_INVALID_SKIP_FMT: &[u8] =
    b"invalid \"random\" 64-byte header, entering global skip mode\n\0";
const PARSE_BAD_PACKET_LEN_FMT: &[u8] = b"error while parsing packet: bad packet length %d\n\0";
const PARSE_OVERLONG_LEN_FMT: &[u8] =
    b"error while parsing compact packet: got length %d in overlong encoding\n\0";
const PARSE_RECEIVED_PACKET_FMT: &[u8] =
    b"received packet from connection %d (length %d, num %d, type %08x)\n\0";
const PROXY_PASS_FORWARD_FMT: &[u8] = b"proxying %d bytes to %s:%d\n\0";
const INIT_DOMAIN_FAIL_FMT: &[u8] =
    b"Failed to update response data about %s, so default response settings wiil be used\n\0";
const PROXY_FAIL_DOMAIN_FMT: &[u8] = b"failed to proxy request to %s\n\0";
const PROXY_FAIL_SOCKET_FMT: &[u8] = b"failed to create proxy pass connection: %d (%s)\n\0";
const PROXY_FAIL_CONN_FMT: &[u8] = b"failed to create proxy pass connection (2)\n\0";

const TLS_SERVER_HELLO_PREFIX: &[u8] = b"\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03";
const TLS_SERVER_HELLO_CIPHER_PREFIX: &[u8] = b"\x13\x01\x00\x00\x2e";
const TLS_SERVER_EXT_KEY_SHARE_PREFIX: &[u8] = b"\x00\x33\x00\x24\x00\x1d\x00\x20";
const TLS_SERVER_EXT_VERSIONS: &[u8] = b"\x00\x2b\x00\x02\x03\x04";
const TLS_SERVER_TRAILER: &[u8] = b"\x14\x03\x03\x00\x01\x01\x17\x03\x03";
const TLS_CLIENT_CCS_PREFIX: &[u8] = b"\x14\x03\x03\x00\x01\x01\x17\x03\x03";
const READ_LESS_BYTES: &[u8] = b"Read less bytes than expected\0";
const WRITTEN_LESS_BYTES: &[u8] = b"Written less bytes than expected\0";

const SM_IPV6: c_int = 2;
const CT_OUTBOUND: c_int = 3;
const MAX_CLIENT_RANDOM_CACHE_TIME: c_int = 2 * 86400;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct EventTimer {
    pub h_idx: c_int,
    pub flags: c_int,
    pub wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> c_int>,
    pub wakeup_time: c_double,
    pub real_wakeup_time: c_double,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct RawMessage {
    pub first: *mut c_void,
    pub last: *mut c_void,
    pub total_bytes: c_int,
    pub magic: c_int,
    pub first_offset: c_int,
    pub last_offset: c_int,
}

impl Default for RawMessage {
    fn default() -> Self {
        Self {
            first: ptr::null_mut(),
            last: ptr::null_mut(),
            total_bytes: 0,
            magic: 0,
            first_offset: 0,
            last_offset: 0,
        }
    }
}

#[repr(C)]
pub(super) struct MpQueue {
    _priv: [u8; 0],
}

type ConnLifecycleFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type ConnCloseFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnWakeupAioFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnPacketFn = Option<unsafe extern "C" fn(ConnectionJob, *mut RawMessage) -> c_int>;
type ConnCryptoInitFn = Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, c_int) -> c_int>;

#[repr(C)]
pub(super) struct ConnFunctions {
    pub magic: c_int,
    pub flags: c_int,
    pub title: *mut c_char,
    pub accept: ConnLifecycleFn,
    pub init_accepted: ConnLifecycleFn,
    pub reader: ConnLifecycleFn,
    pub writer: ConnLifecycleFn,
    pub close: ConnCloseFn,
    pub parse_execute: ConnLifecycleFn,
    pub init_outbound: ConnLifecycleFn,
    pub connected: ConnLifecycleFn,
    pub check_ready: ConnLifecycleFn,
    pub wakeup_aio: ConnWakeupAioFn,
    pub write_packet: ConnPacketFn,
    pub flush: ConnLifecycleFn,
    pub free: ConnLifecycleFn,
    pub free_buffers: ConnLifecycleFn,
    pub read_write: ConnLifecycleFn,
    pub wakeup: ConnLifecycleFn,
    pub alarm: ConnLifecycleFn,
    pub socket_read_write: ConnLifecycleFn,
    pub socket_reader: ConnLifecycleFn,
    pub socket_writer: ConnLifecycleFn,
    pub socket_connected: ConnLifecycleFn,
    pub socket_free: ConnLifecycleFn,
    pub socket_close: ConnLifecycleFn,
    pub data_received: ConnWakeupAioFn,
    pub data_sent: ConnWakeupAioFn,
    pub ready_to_write: ConnLifecycleFn,
    pub crypto_init: ConnCryptoInitFn,
    pub crypto_free: ConnLifecycleFn,
    pub crypto_encrypt_output: ConnLifecycleFn,
    pub crypto_decrypt_input: ConnLifecycleFn,
    pub crypto_needed_output_bytes: ConnLifecycleFn,
}

#[repr(C)]
pub(super) struct ConnectionInfo {
    pub timer: EventTimer,
    pub fd: c_int,
    pub generation: c_int,
    pub flags: c_int,
    pub type_: *mut ConnFunctions,
    pub extra: *mut c_void,
    pub target: ConnectionJob,
    pub io_conn: ConnectionJob,
    pub basic_type: c_int,
    pub status: c_int,
    pub error: c_int,
    pub unread_res_bytes: c_int,
    pub skip_bytes: c_int,
    pub pending_queries: c_int,
    pub queries_ok: c_int,
    pub custom_data: [c_char; CONN_CUSTOM_DATA_BYTES],
    pub our_ip: u32,
    pub remote_ip: u32,
    pub our_port: u32,
    pub remote_port: u32,
    pub our_ipv6: [u8; 16],
    pub remote_ipv6: [u8; 16],
    pub query_start_time: c_double,
    pub last_query_time: c_double,
    pub last_query_sent_time: c_double,
    pub last_response_time: c_double,
    pub last_query_timeout: c_double,
    pub limit_per_write: c_int,
    pub limit_per_sec: c_int,
    pub last_write_time: c_int,
    pub written_per_sec: c_int,
    pub unreliability: c_int,
    pub ready: c_int,
    pub write_low_watermark: c_int,
    pub crypto: *mut c_void,
    pub crypto_temp: *mut c_void,
    pub listening: c_int,
    pub listening_generation: c_int,
    pub window_clamp: c_int,
    pub left_tls_packet_length: c_int,
    pub in_u: RawMessage,
    pub in_data: RawMessage,
    pub out: RawMessage,
    pub out_p: RawMessage,
    pub in_queue: *mut MpQueue,
    pub out_queue: *mut MpQueue,
}

#[repr(C)]
pub(super) struct TcpRpcData {
    pub flags: c_int,
    pub in_packet_num: c_int,
    pub out_packet_num: c_int,
    pub crypto_flags: c_int,
    pub remote_pid: crate::MtproxyProcessId,
    pub nonce: [u8; 16],
    pub nonce_time: c_int,
    pub in_rpc_target: c_int,
    pub user_data: *mut c_void,
    pub extra_int: c_int,
    pub extra_int2: c_int,
    pub extra_int3: c_int,
    pub extra_int4: c_int,
    pub extra_double: c_double,
    pub extra_double2: c_double,
    pub custom_crc_partial: Option<unsafe extern "C" fn(*const c_void, c_long, u32) -> u32>,
}

type RpcExecuteFn = Option<unsafe extern "C" fn(ConnectionJob, c_int, *mut RawMessage) -> c_int>;

#[repr(C)]
pub(super) struct TcpRpcServerFunctions {
    pub info: *mut c_void,
    pub rpc_extra: *mut c_void,
    pub execute: RpcExecuteFn,
    pub check_ready: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    pub flush_packet: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    pub rpc_check_perm: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    pub rpc_init_crypto: Option<unsafe extern "C" fn(ConnectionJob, *mut c_void) -> c_int>,
    pub nop: *mut c_void,
    pub rpc_wakeup: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    pub rpc_alarm: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    pub rpc_ready: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    pub rpc_close: Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>,
    pub max_packet_len: c_int,
    pub mode_flags: c_int,
    pub memcache_fallback_type: *mut c_void,
    pub memcache_fallback_extra: *mut c_void,
    pub http_fallback_type: *mut c_void,
    pub http_fallback_extra: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct DomainInfo {
    pub domain: *const c_char,
    pub target: libc::in_addr,
    pub target_ipv6: [u8; 16],
    pub server_hello_encrypted_size: c_short,
    pub use_random_encrypted_size: c_char,
    pub is_reversed_extension_order: c_char,
    pub next: *mut DomainInfo,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
struct ClientRandomKey([u8; 16]);

#[derive(Clone, Copy)]
struct ClientRandomEntry {
    random: ClientRandomKey,
    time: c_int,
}

#[derive(Default)]
struct ClientRandomState {
    entries: VecDeque<ClientRandomEntry>,
    counts: HashMap<ClientRandomKey, usize>,
}

struct DomainNode {
    domain_storage: CString,
    info: DomainInfo,
}

struct ExtServerState {
    allow_only_tls: bool,
    default_domain_info: *const DomainInfo,
    buckets: [*mut DomainInfo; DOMAIN_HASH_MOD],
    domain_nodes: Vec<Box<DomainNode>>,
    ext_secret: [[u8; 16]; EXT_SECRET_LIMIT],
    ext_secret_cnt: usize,
}

unsafe impl Send for DomainNode {}
unsafe impl Send for ExtServerState {}

impl Default for ExtServerState {
    fn default() -> Self {
        Self {
            allow_only_tls: false,
            default_domain_info: ptr::null(),
            buckets: [ptr::null_mut(); DOMAIN_HASH_MOD],
            domain_nodes: Vec::new(),
            ext_secret: [[0; 16]; EXT_SECRET_LIMIT],
            ext_secret_cnt: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AesKeyData {
    read_key: [u8; 32],
    read_iv: [u8; 16],
    write_key: [u8; 32],
    write_iv: [u8; 16],
}

#[repr(C)]
struct AesCrypto {
    read_aeskey: *mut c_void,
    write_aeskey: *mut c_void,
}

unsafe extern "C" {
    fn mtproxy_ffi_net_tcp_rpc_ext_conn_info(c: ConnectionJob) -> *mut ConnectionInfo;
    fn mtproxy_ffi_net_tcp_rpc_ext_data(c: ConnectionJob) -> *mut TcpRpcData;
    fn mtproxy_ffi_net_tcp_rpc_ext_funcs(c: ConnectionJob) -> *mut TcpRpcServerFunctions;

    fn mtproxy_ffi_net_tcp_rpc_ext_have_client_random(random: *const u8) -> c_int;
    fn mtproxy_ffi_net_tcp_rpc_ext_add_client_random(random: *const u8);
    fn mtproxy_ffi_net_tcp_rpc_ext_delete_old_client_randoms();
    fn mtproxy_ffi_net_tcp_rpc_ext_is_allowed_timestamp_state(timestamp: c_int) -> c_int;

    fn mtproxy_ffi_crypto_rand_bytes(out: *mut u8, len: c_int) -> c_int;
    fn mtproxy_ffi_crypto_tls_generate_public_key(out: *mut u8) -> c_int;

    fn kdb_gethostbyname(name: *const c_char) -> *mut libc::hostent;
    fn client_socket(in_addr: u32, port: c_int, mode: c_int) -> c_int;
    fn client_socket_ipv6(in6_addr_ptr: *const u8, port: c_int, mode: c_int) -> c_int;
    fn alloc_new_connection(
        cfd: c_int,
        ctj: ConnectionJob,
        lcj: ConnectionJob,
        basic_type: c_int,
        conn_type: *mut ConnFunctions,
        conn_extra: *mut c_void,
        peer: u32,
        peer_ipv6: *mut u8,
        peer_port: c_int,
    ) -> ConnectionJob;

    fn rwm_fetch_lookup(raw: *mut RawMessage, buf: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_move(dest_raw: *mut RawMessage, src_raw: *mut RawMessage);
    fn rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn rwm_union(raw: *mut RawMessage, tail: *mut RawMessage) -> c_int;
    fn rwm_init(raw: *mut RawMessage, alloc_bytes: c_int) -> c_int;
    fn rwm_split_head(head: *mut RawMessage, raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn rwm_trunc(raw: *mut RawMessage, len: c_int) -> c_int;
    fn rwm_free(raw: *mut RawMessage) -> c_int;
    fn rwm_create(raw: *mut RawMessage, data: *const c_void, alloc_bytes: c_int) -> c_int;
    fn rwm_dump(raw: *mut RawMessage) -> c_int;

    fn mpq_push_w(mq: *mut MpQueue, val: *mut c_void, flags: c_int) -> c_long;

    fn job_incref(job: ConnectionJob) -> ConnectionJob;
    fn job_signal(job_tag_int: c_int, job: ConnectionJob, signo: c_int);
    fn job_timer_remove(job: ConnectionJob);
    fn mtproxy_ffi_net_tcp_rpc_ext_job_decref(c: ConnectionJob);
    fn mtproxy_ffi_net_tcp_rpc_ext_unlock_job(c: ConnectionJob) -> c_int;

    fn fail_connection(c: ConnectionJob, who: c_int);
    fn tcp_rpcs_parse_execute(c: ConnectionJob) -> c_int;
    fn tcp_rpcs_default_execute(c: ConnectionJob, op: c_int, msg: *mut RawMessage) -> c_int;

    fn aes_crypto_ctr128_init(
        c: ConnectionJob,
        key_data: *mut c_void,
        key_data_len: c_int,
    ) -> c_int;
    fn aes_crypto_free(c: ConnectionJob) -> c_int;
    fn aesni_crypt(ctx: *mut c_void, input: *const c_void, out: *mut c_void, size: c_int);

    fn get_utime_monotonic() -> c_double;
    fn mtproxy_ffi_net_tcp_rpc_ext_show_our_ip(c: ConnectionJob) -> *const c_char;
    fn mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(c: ConnectionJob) -> *const c_char;
    fn cpu_server_close_connection(c: ConnectionJob, who: c_int) -> c_int;

    fn sha256(input: *const u8, ilen: c_int, output: *mut u8);
    fn sha256_hmac(key: *mut u8, keylen: c_int, input: *mut u8, ilen: c_int, output: *mut u8);

    fn kprintf(format: *const c_char, ...);

    static mut ct_proxy_pass: ConnFunctions;
    static mut verbosity: c_int;
}

#[inline]
unsafe fn conn_info(c: ConnectionJob) -> *mut ConnectionInfo {
    let conn = unsafe { mtproxy_ffi_net_tcp_rpc_ext_conn_info(c) };
    assert!(!conn.is_null());
    conn
}

#[inline]
unsafe fn rpc_data(c: ConnectionJob) -> *mut TcpRpcData {
    let data = unsafe { mtproxy_ffi_net_tcp_rpc_ext_data(c) };
    assert!(!data.is_null());
    data
}

#[inline]
unsafe fn rpc_funcs(c: ConnectionJob) -> *mut TcpRpcServerFunctions {
    let funcs = unsafe { mtproxy_ffi_net_tcp_rpc_ext_funcs(c) };
    assert!(!funcs.is_null());
    funcs
}

#[inline]
unsafe fn precise_now_value() -> c_double {
    crate::net_connections::precise_now_rust()
}

#[inline]
unsafe fn allow_only_tls() -> bool {
    state_allow_only_tls()
}

#[inline]
unsafe fn default_domain_info() -> *const DomainInfo {
    state_default_domain_info()
}

#[inline]
unsafe fn ext_secret_count() -> c_int {
    state_ext_secret_count()
}

#[inline]
unsafe fn ext_secret_at(index: c_int) -> *const u8 {
    state_ext_secret_at(index)
}

#[inline]
fn ext_server_state() -> &'static Mutex<ExtServerState> {
    static STATE: OnceLock<Mutex<ExtServerState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(ExtServerState::default()))
}

#[inline]
fn domain_bucket_index(domain: &[u8]) -> usize {
    let index = mtproxy_core::runtime::net::tcp_rpc_ext_server::domain_bucket_index(domain);
    assert!(index >= 0);
    usize::try_from(index).unwrap_or(0) % DOMAIN_HASH_MOD
}

#[inline]
fn with_ext_server_state<T>(f: impl FnOnce(&ExtServerState) -> T) -> T {
    let state = ext_server_state();
    let guard = match state.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&guard)
}

#[inline]
fn with_ext_server_state_mut<T>(f: impl FnOnce(&mut ExtServerState) -> T) -> T {
    let state = ext_server_state();
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut guard)
}

#[inline]
fn state_allow_only_tls() -> bool {
    with_ext_server_state(|state| state.allow_only_tls)
}

#[inline]
fn state_default_domain_info() -> *const DomainInfo {
    with_ext_server_state(|state| state.default_domain_info)
}

#[inline]
fn state_ext_secret_count() -> c_int {
    with_ext_server_state(|state| c_int::try_from(state.ext_secret_cnt).unwrap_or(0))
}

#[inline]
fn state_ext_secret_at(index: c_int) -> *const u8 {
    if index < 0 {
        return ptr::null();
    }
    with_ext_server_state(|state| {
        let idx = usize::try_from(index).unwrap_or(EXT_SECRET_LIMIT);
        if idx >= state.ext_secret_cnt {
            ptr::null()
        } else {
            state.ext_secret[idx].as_ptr()
        }
    })
}

#[inline]
unsafe fn state_lookup_domain_info(domain: *const u8, len: c_int) -> *const DomainInfo {
    if domain.is_null() || len < 0 {
        return ptr::null();
    }
    let len_usize = usize::try_from(len).unwrap_or(0);
    let domain_slice = unsafe { slice::from_raw_parts(domain, len_usize) };
    let bucket = domain_bucket_index(domain_slice);
    with_ext_server_state(|state| {
        let mut info = state.buckets[bucket];
        while !info.is_null() {
            let info_domain = unsafe { CStr::from_ptr((*info).domain).to_bytes() };
            if info_domain == domain_slice {
                return info.cast_const();
            }
            info = unsafe { (*info).next };
        }
        if unsafe { verbosity } > 0 {
            unsafe {
                crate::kprintf_fmt!(
                    b"Receive request for unknown domain %.*s\n\0"
                        .as_ptr()
                        .cast(),
                    len,
                    domain.cast::<c_char>(),
                );
            }
        }
        ptr::null()
    })
}

#[inline]
unsafe fn state_add_proxy_domain(domain: *const c_char) {
    if domain.is_null() {
        return;
    }
    let domain_bytes = unsafe { CStr::from_ptr(domain).to_bytes() };
    let Ok(domain_storage) = CString::new(domain_bytes) else {
        return;
    };
    let bucket = domain_bucket_index(domain_bytes);
    with_ext_server_state_mut(|state| {
        let mut node = Box::new(DomainNode {
            domain_storage,
            info: DomainInfo {
                domain: ptr::null(),
                target: libc::in_addr { s_addr: 0 },
                target_ipv6: [0; 16],
                server_hello_encrypted_size: 0,
                use_random_encrypted_size: 0,
                is_reversed_extension_order: 0,
                next: ptr::null_mut(),
            },
        });
        node.info.domain = node.domain_storage.as_ptr();
        node.info.next = state.buckets[bucket];
        let info_ptr = ptr::addr_of_mut!(node.info);
        state.buckets[bucket] = info_ptr;
        if !state.allow_only_tls {
            state.allow_only_tls = true;
            state.default_domain_info = info_ptr.cast_const();
        }
        state.domain_nodes.push(node);
    });
}

#[inline]
fn client_random_state() -> &'static Mutex<ClientRandomState> {
    static STATE: OnceLock<Mutex<ClientRandomState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(ClientRandomState::default()))
}

#[inline]
unsafe fn read_client_random_key(random: *const u8) -> Option<ClientRandomKey> {
    if random.is_null() {
        return None;
    }
    let mut value = [0u8; 16];
    unsafe {
        ptr::copy_nonoverlapping(random, value.as_mut_ptr(), 16);
    }
    Some(ClientRandomKey(value))
}

#[inline]
unsafe fn read_length_buf(buffer: &[u8], pos: &mut usize) -> Option<c_int> {
    if *pos + 2 > buffer.len() {
        return None;
    }
    let len = i32::from(buffer[*pos]) * 256 + i32::from(buffer[*pos + 1]);
    *pos += 2;
    Some(len)
}

#[inline]
fn tls_has_bytes(pos: c_int, length: c_int, len: c_int) -> bool {
    pos >= 0 && length >= 0 && pos + length <= len
}

#[inline]
fn tls_expect_bytes(response: &[u8], pos: c_int, expected: &[u8]) -> bool {
    if pos < 0 {
        return false;
    }
    let start = pos as usize;
    let end = start.saturating_add(expected.len());
    end <= response.len() && &response[start..end] == expected
}

#[inline]
unsafe fn tls_fail_response_parse(error: &'static [u8]) -> c_int {
    unsafe {
        crate::kprintf_fmt!(
            TLS_PARSE_FAIL_FMT.as_ptr().cast(),
            error.as_ptr().cast::<c_char>(),
        );
    }
    0
}

#[inline]
fn add_string(buffer: &mut [u8], pos: &mut usize, data: &[u8]) -> bool {
    if *pos + data.len() > buffer.len() {
        return false;
    }
    buffer[*pos..*pos + data.len()].copy_from_slice(data);
    *pos += data.len();
    true
}

#[inline]
fn add_length(buffer: &mut [u8], pos: &mut usize, length: usize) -> bool {
    if length > usize::from(u16::MAX) || *pos + 2 > buffer.len() {
        return false;
    }
    let length_u16 = length as u16;
    let bytes = length_u16.to_be_bytes();
    buffer[*pos] = bytes[0];
    buffer[*pos + 1] = bytes[1];
    *pos += 2;
    true
}

#[inline]
unsafe fn add_random(buffer: &mut [u8], pos: &mut usize, random_len: usize) -> bool {
    if *pos + random_len > buffer.len() {
        return false;
    }
    let dst = &mut buffer[*pos..*pos + random_len];
    let random_len_i32 = c_int::try_from(random_len).unwrap_or(-1);
    if random_len_i32 < 0 {
        return false;
    }
    if unsafe { mtproxy_ffi_crypto_rand_bytes(dst.as_mut_ptr(), random_len_i32) } != 0 {
        return false;
    }
    *pos += random_len;
    true
}

#[inline]
unsafe fn add_public_key(buffer: &mut [u8], pos: &mut usize) -> bool {
    if *pos + 32 > buffer.len() {
        return false;
    }
    let dst = &mut buffer[*pos..*pos + 32];
    if unsafe { mtproxy_ffi_crypto_tls_generate_public_key(dst.as_mut_ptr()) } != 0 {
        return false;
    }
    *pos += 32;
    true
}

#[inline]
fn add_grease(buffer: &mut [u8], pos: &mut usize, greases: &[u8], num: usize) -> bool {
    if num >= greases.len() || *pos + 2 > buffer.len() {
        return false;
    }
    buffer[*pos] = greases[num];
    buffer[*pos + 1] = greases[num];
    *pos += 2;
    true
}

fn create_request_bytes(domain: &[u8]) -> Option<Vec<u8>> {
    let mut result = vec![0u8; TLS_REQUEST_LENGTH];
    let mut pos = 0usize;

    let mut greases = [0u8; MAX_GREASE];
    let greases_len_i32 = c_int::try_from(MAX_GREASE).ok()?;
    if unsafe { mtproxy_ffi_crypto_rand_bytes(greases.as_mut_ptr(), greases_len_i32) } != 0 {
        return None;
    }
    for grease in &mut greases {
        *grease = (*grease & 0xF0) + 0x0A;
    }
    let mut i = 1usize;
    while i < MAX_GREASE {
        if greases[i] == greases[i - 1] {
            greases[i] ^= 0x10;
        }
        i += 2;
    }

    let domain_length = domain.len();

    if !add_string(
        &mut result,
        &mut pos,
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
    ) {
        return None;
    }
    if !unsafe { add_random(&mut result, &mut pos, 32) } {
        return None;
    }
    if !add_string(&mut result, &mut pos, b"\x20") {
        return None;
    }
    if !unsafe { add_random(&mut result, &mut pos, 32) } {
        return None;
    }
    if !add_string(&mut result, &mut pos, b"\x00\x22") {
        return None;
    }
    if !add_grease(&mut result, &mut pos, &greases, 0) {
        return None;
    }
    if !add_string(
        &mut result,
        &mut pos,
        b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\
          \xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x01\x91",
    ) {
        return None;
    }
    if !add_grease(&mut result, &mut pos, &greases, 2) {
        return None;
    }
    if !add_string(&mut result, &mut pos, b"\x00\x00\x00\x00") {
        return None;
    }
    if !add_length(&mut result, &mut pos, domain_length + 5) {
        return None;
    }
    if !add_length(&mut result, &mut pos, domain_length + 3) {
        return None;
    }
    if !add_string(&mut result, &mut pos, b"\x00") {
        return None;
    }
    if !add_length(&mut result, &mut pos, domain_length) {
        return None;
    }
    if !add_string(&mut result, &mut pos, domain) {
        return None;
    }
    if !add_string(
        &mut result,
        &mut pos,
        b"\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08",
    ) {
        return None;
    }
    if !add_grease(&mut result, &mut pos, &greases, 4) {
        return None;
    }
    if !add_string(
        &mut result,
        &mut pos,
        b"\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\
          \x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05\
          \x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\
          \x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x00\x12\x00\x00\x00\
          \x33\x00\x2b\x00\x29",
    ) {
        return None;
    }
    if !add_grease(&mut result, &mut pos, &greases, 4) {
        return None;
    }
    if !add_string(&mut result, &mut pos, b"\x00\x01\x00\x00\x1d\x00\x20") {
        return None;
    }
    if !unsafe { add_public_key(&mut result, &mut pos) } {
        return None;
    }
    if !add_string(
        &mut result,
        &mut pos,
        b"\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x0b\x0a",
    ) {
        return None;
    }
    if !add_grease(&mut result, &mut pos, &greases, 6) {
        return None;
    }
    if !add_string(
        &mut result,
        &mut pos,
        b"\x03\x04\x03\x03\x03\x02\x03\x01\x00\x1b\x00\x03\x02\x00\x02",
    ) {
        return None;
    }
    if !add_grease(&mut result, &mut pos, &greases, 3) {
        return None;
    }
    if !add_string(&mut result, &mut pos, b"\x00\x01\x00\x00\x15") {
        return None;
    }

    if TLS_REQUEST_LENGTH < 2 + pos {
        return None;
    }
    let padding_length = TLS_REQUEST_LENGTH - 2 - pos;
    if !add_length(&mut result, &mut pos, padding_length) {
        return None;
    }
    while pos < TLS_REQUEST_LENGTH {
        result[pos] = 0;
        pos += 1;
    }

    Some(result)
}

unsafe fn check_response_inner(
    response: &[u8],
    request_session_id: &[u8],
    is_reversed_extension_order: &mut c_int,
    encrypted_application_data_length: &mut c_int,
) -> c_int {
    let len = c_int::try_from(response.len()).unwrap_or(c_int::MAX);
    let mut pos: c_int = 0;

    if !tls_has_bytes(pos, 3, len) {
        return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
    }
    if !tls_expect_bytes(response, 0, b"\x16\x03\x03") {
        return unsafe { tls_fail_response_parse(ERR_NON_TLS_1) };
    }
    pos += 3;
    if !tls_has_bytes(pos, 2, len) {
        return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
    }
    let mut pos_usize = usize::try_from(pos).unwrap_or(0);
    let Some(server_hello_length) = (unsafe { read_length_buf(response, &mut pos_usize) }) else {
        return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
    };
    pos = c_int::try_from(pos_usize).unwrap_or(c_int::MAX);
    if server_hello_length <= 39 {
        return unsafe { tls_fail_response_parse(ERR_SERVER_HELLO_SHORT) };
    }
    if !tls_has_bytes(pos, server_hello_length, len) {
        return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
    }

    if !tls_expect_bytes(response, 5, b"\x02\x00") {
        return unsafe { tls_fail_response_parse(ERR_NON_TLS_2) };
    }
    if !tls_expect_bytes(response, 9, b"\x03\x03") {
        return unsafe { tls_fail_response_parse(ERR_NON_TLS_3) };
    }

    if response.len() >= 43
        && &response[11..43]
            == b"\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\
               \xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c"
    {
        return unsafe { tls_fail_response_parse(ERR_HELLO_RETRY) };
    }
    if response.len() <= 43 || response[43] == 0 {
        return unsafe { tls_fail_response_parse(ERR_TLS12_EMPTY_SESSION) };
    }
    if !tls_expect_bytes(response, 43, b"\x20") {
        return unsafe { tls_fail_response_parse(ERR_NON_TLS_4) };
    }
    if server_hello_length <= 75 {
        return unsafe { tls_fail_response_parse(ERR_SERVER_HELLO_SHORT_2) };
    }
    if request_session_id.len() < 32
        || response.len() < 76
        || response[44..76] != request_session_id[..32]
    {
        return unsafe { tls_fail_response_parse(ERR_TLS12_EXPECTED_SESSION) };
    }
    if !tls_expect_bytes(response, 76, b"\x13\x01\x00") {
        return unsafe { tls_fail_response_parse(ERR_TLS12_EXPECTED_CIPHER) };
    }

    pos += 74;
    let mut pos_usize = usize::try_from(pos).unwrap_or(0);
    let Some(extensions_length) = (unsafe { read_length_buf(response, &mut pos_usize) }) else {
        return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
    };
    pos = c_int::try_from(pos_usize).unwrap_or(c_int::MAX);
    if extensions_length + 76 != server_hello_length {
        return unsafe { tls_fail_response_parse(ERR_WRONG_EXT_LEN) };
    }

    let mut sum = 0;
    while pos < 5 + server_hello_length - 4 {
        let mut pos_usize = usize::try_from(pos).unwrap_or(0);
        let Some(extension_id) = (unsafe { read_length_buf(response, &mut pos_usize) }) else {
            return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
        };
        pos = c_int::try_from(pos_usize).unwrap_or(c_int::MAX);
        if extension_id != 0x33 && extension_id != 0x2b {
            return unsafe { tls_fail_response_parse(ERR_UNEXPECTED_EXT) };
        }
        if pos == 83 {
            *is_reversed_extension_order = if extension_id == 0x2b { 1 } else { 0 };
        }
        sum += extension_id;

        let mut pos_usize = usize::try_from(pos).unwrap_or(0);
        let Some(extension_length) = (unsafe { read_length_buf(response, &mut pos_usize) }) else {
            return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
        };
        pos = c_int::try_from(pos_usize).unwrap_or(c_int::MAX);
        if pos + extension_length > 5 + server_hello_length {
            return unsafe { tls_fail_response_parse(ERR_WRONG_EXT_ITEM_LEN) };
        }
        if extension_length != if extension_id == 0x33 { 36 } else { 2 } {
            return unsafe { tls_fail_response_parse(ERR_UNEXPECTED_EXT_ITEM_LEN) };
        }
        pos += extension_length;
    }
    if sum != 0x33 + 0x2b {
        return unsafe { tls_fail_response_parse(ERR_DUP_EXT) };
    }
    if pos != 5 + server_hello_length {
        return unsafe { tls_fail_response_parse(ERR_WRONG_EXT_LIST) };
    }

    if !tls_has_bytes(pos, 9, len) {
        return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
    }
    if !tls_expect_bytes(response, pos, b"\x14\x03\x03\x00\x01\x01") {
        return unsafe { tls_fail_response_parse(ERR_EXPECTED_CCS) };
    }
    if !tls_expect_bytes(response, pos + 6, b"\x17\x03\x03") {
        return unsafe { tls_fail_response_parse(ERR_EXPECTED_APP_DATA) };
    }
    pos += 9;

    if !tls_has_bytes(pos, 2, len) {
        return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
    }
    let mut pos_usize = usize::try_from(pos).unwrap_or(0);
    let Some(app_data_len) = (unsafe { read_length_buf(response, &mut pos_usize) }) else {
        return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
    };
    *encrypted_application_data_length = app_data_len;
    pos = c_int::try_from(pos_usize).unwrap_or(c_int::MAX);
    if *encrypted_application_data_length == 0 {
        return unsafe { tls_fail_response_parse(ERR_EMPTY_APP_DATA) };
    }

    if !tls_has_bytes(pos, *encrypted_application_data_length, len) {
        return unsafe { tls_fail_response_parse(ERR_TOO_SHORT) };
    }
    pos += *encrypted_application_data_length;
    if pos != len {
        return unsafe { tls_fail_response_parse(ERR_TOO_LONG) };
    }

    1
}

unsafe fn get_sni_domain_info_inner(request: &[u8]) -> *const DomainInfo {
    let len = c_int::try_from(request.len()).unwrap_or(c_int::MAX);
    let mut pos = 11 + 32 + 1 + 32;
    if pos + 2 > len {
        return ptr::null();
    }

    let mut pos_usize = usize::try_from(pos).unwrap_or(0);
    let Some(cipher_suites_length) = (unsafe { read_length_buf(request, &mut pos_usize) }) else {
        return ptr::null();
    };
    pos = c_int::try_from(pos_usize).unwrap_or(c_int::MAX);
    if pos + cipher_suites_length + 4 > len {
        return ptr::null();
    }
    pos += cipher_suites_length + 4;

    loop {
        if pos + 4 > len {
            return ptr::null();
        }
        let mut pos_usize = usize::try_from(pos).unwrap_or(0);
        let Some(extension_id) = (unsafe { read_length_buf(request, &mut pos_usize) }) else {
            return ptr::null();
        };
        let Some(extension_length) = (unsafe { read_length_buf(request, &mut pos_usize) }) else {
            return ptr::null();
        };
        pos = c_int::try_from(pos_usize).unwrap_or(c_int::MAX);
        if pos + extension_length > len {
            return ptr::null();
        }

        if extension_id == 0 {
            if pos + 5 > len {
                return ptr::null();
            }
            let mut pos_usize = usize::try_from(pos).unwrap_or(0);
            let Some(inner_length) = (unsafe { read_length_buf(request, &mut pos_usize) }) else {
                return ptr::null();
            };
            pos = c_int::try_from(pos_usize).unwrap_or(c_int::MAX);
            if inner_length != extension_length - 2 {
                return ptr::null();
            }
            let Some(name_type) = request.get(pos as usize) else {
                return ptr::null();
            };
            if *name_type != 0 {
                return ptr::null();
            }
            pos += 1;

            let mut pos_usize = usize::try_from(pos).unwrap_or(0);
            let Some(domain_length) = (unsafe { read_length_buf(request, &mut pos_usize) }) else {
                return ptr::null();
            };
            pos = c_int::try_from(pos_usize).unwrap_or(c_int::MAX);
            if domain_length != extension_length - 5 {
                return ptr::null();
            }

            let start = usize::try_from(pos).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(domain_length).unwrap_or(usize::MAX));
            if end > request.len() {
                return ptr::null();
            }
            if request[start..end].contains(&0) {
                return ptr::null();
            }

            return unsafe {
                state_lookup_domain_info(request[start..end].as_ptr(), domain_length)
            };
        }

        pos += extension_length;
    }
}

#[inline]
unsafe fn errno_value() -> c_int {
    unsafe { *libc::__errno_location() }
}

#[inline]
unsafe fn strerror_ptr() -> *const c_char {
    unsafe { libc::strerror(errno_value()) }
}

#[inline]
unsafe fn close_sockets(sockets: &[c_int]) {
    for &fd in sockets {
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

unsafe fn update_domain_info_inner(info: *mut DomainInfo) -> c_int {
    if info.is_null() {
        return 0;
    }

    let domain_ptr = unsafe { (*info).domain };
    if domain_ptr.is_null() {
        return 0;
    }

    let host = unsafe { kdb_gethostbyname(domain_ptr) };
    let h_addr = if host.is_null() {
        ptr::null_mut()
    } else {
        unsafe {
            let list = (*host).h_addr_list;
            if list.is_null() {
                ptr::null_mut()
            } else {
                *list
            }
        }
    };
    if host.is_null() || h_addr.is_null() {
        unsafe {
            crate::kprintf_fmt!(PROBE_FAIL_RESOLVE_FMT.as_ptr().cast(), domain_ptr);
        }
        return 0;
    }

    let h_addrtype = unsafe { (*host).h_addrtype };
    if h_addrtype != libc::AF_INET && h_addrtype != libc::AF_INET6 {
        return 0;
    }

    let mut sockets = [-1; TLS_PROBE_TRIES];
    for slot in &mut sockets {
        let fd = unsafe { libc::socket(h_addrtype, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
        if fd < 0 {
            unsafe {
                crate::kprintf_fmt!(
                    PROBE_FAIL_SOCKET_FMT.as_ptr().cast(),
                    domain_ptr,
                    strerror_ptr(),
                );
                close_sockets(&sockets);
            }
            return 0;
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
            unsafe {
                crate::kprintf_fmt!(PROBE_FAIL_NONBLOCK_FMT.as_ptr().cast(), strerror_ptr());
                libc::close(fd);
                close_sockets(&sockets);
            }
            return 0;
        }

        let e_connect = if h_addrtype == libc::AF_INET {
            let mut addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 443u16.to_be(),
                sin_addr: unsafe { *(h_addr.cast::<libc::in_addr>()) },
                sin_zero: [0; 8],
            };

            unsafe {
                (*info).target = addr.sin_addr;
                (*info).target_ipv6 = [0u8; 16];
            }

            unsafe {
                libc::connect(
                    fd,
                    (&mut addr as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
                    c_int::try_from(size_of::<libc::sockaddr_in>()).unwrap_or(0) as libc::socklen_t,
                )
            }
        } else {
            let mut addr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: 443u16.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: unsafe { *(h_addr.cast::<libc::in6_addr>()) },
                sin6_scope_id: 0,
            };

            unsafe {
                (*info).target.s_addr = 0;
                ptr::copy_nonoverlapping(
                    addr.sin6_addr.s6_addr.as_ptr(),
                    (*info).target_ipv6.as_mut_ptr(),
                    16,
                );
            }

            unsafe {
                libc::connect(
                    fd,
                    (&mut addr as *mut libc::sockaddr_in6).cast::<libc::sockaddr>(),
                    c_int::try_from(size_of::<libc::sockaddr_in6>()).unwrap_or(0)
                        as libc::socklen_t,
                )
            }
        };

        if e_connect == -1 && unsafe { errno_value() } != libc::EINPROGRESS {
            unsafe {
                crate::kprintf_fmt!(
                    PROBE_FAIL_CONNECT_FMT.as_ptr().cast(),
                    domain_ptr,
                    strerror_ptr(),
                );
                libc::close(fd);
                close_sockets(&sockets);
            }
            return 0;
        }

        *slot = fd;
    }

    let domain_bytes = unsafe { CStr::from_ptr(domain_ptr).to_bytes() };
    let mut requests: Vec<Vec<u8>> = Vec::with_capacity(TLS_PROBE_TRIES);
    for _ in 0..TLS_PROBE_TRIES {
        let Some(req) = create_request_bytes(domain_bytes) else {
            unsafe {
                close_sockets(&sockets);
            }
            return 0;
        };
        requests.push(req);
    }

    let mut responses: Vec<Vec<u8>> = (0..TLS_PROBE_TRIES).map(|_| Vec::new()).collect();
    let mut response_len = [0i32; TLS_PROBE_TRIES];
    let mut is_encrypted_data_len_read = [false; TLS_PROBE_TRIES];
    let mut is_written = [false; TLS_PROBE_TRIES];
    let mut is_finished = [false; TLS_PROBE_TRIES];
    let mut read_pos = [0i32; TLS_PROBE_TRIES];

    let mut finished_count = 0usize;
    let start_time = unsafe { get_utime_monotonic() };
    let finish_time = start_time + TLS_PROBE_TIMEOUT_SEC;

    let mut encrypted_len_min = 0;
    let mut encrypted_len_sum = 0;
    let mut encrypted_len_max = 0;
    let mut reversed_min = 0;
    let mut reversed_max = 0;
    let mut have_error = false;

    while unsafe { get_utime_monotonic() } < finish_time
        && finished_count < TLS_PROBE_TRIES
        && !have_error
    {
        let mut pollfds: Vec<libc::pollfd> = Vec::new();
        let mut index: Vec<usize> = Vec::new();

        for i in 0..TLS_PROBE_TRIES {
            if is_finished[i] {
                continue;
            }
            let mut events = libc::POLLERR | libc::POLLHUP | libc::POLLNVAL;
            if is_written[i] {
                events |= libc::POLLIN;
            } else {
                events |= libc::POLLOUT;
            }
            pollfds.push(libc::pollfd {
                fd: sockets[i],
                events,
                revents: 0,
            });
            index.push(i);
        }

        if pollfds.is_empty() {
            break;
        }

        let time_left = finish_time - unsafe { get_utime_monotonic() };
        let timeout_ms = if time_left <= 0.0 {
            0
        } else {
            (time_left * 1000.0).ceil() as c_int
        };

        let poll_res = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                libc::nfds_t::try_from(pollfds.len()).unwrap_or(0),
                timeout_ms,
            )
        };
        if poll_res < 0 {
            if unsafe { errno_value() } == libc::EINTR {
                continue;
            }
            have_error = true;
            break;
        }

        for (j, pfd) in pollfds.iter().enumerate() {
            let i = index[j];
            if is_finished[i] {
                continue;
            }

            let revents = pfd.revents;

            if (revents & libc::POLLIN) != 0 {
                assert!(is_written[i]);

                if responses[i].is_empty() {
                    let mut header = [0u8; 5];
                    let read_res = unsafe {
                        libc::read(
                            sockets[i],
                            header.as_mut_ptr().cast::<c_void>(),
                            header.len(),
                        )
                    };
                    if read_res != 5 {
                        unsafe {
                            crate::kprintf_fmt!(
                                PROBE_FAIL_HEADER_FMT.as_ptr().cast(),
                                domain_ptr,
                                if read_res == -1 {
                                    strerror_ptr()
                                } else {
                                    READ_LESS_BYTES.as_ptr().cast()
                                },
                            );
                        }
                        have_error = true;
                        break;
                    }
                    if header[0..3] != [0x16, 0x03, 0x03] {
                        unsafe {
                            crate::kprintf_fmt!(
                                PROBE_NON_TLS_FMT.as_ptr().cast(),
                                domain_ptr,
                                i32::from(header[0]),
                                i32::from(header[1]),
                                i32::from(header[2]),
                                i32::from(header[3]),
                                i32::from(header[4]),
                            );
                        }
                        have_error = true;
                        break;
                    }

                    response_len[i] = 5 + i32::from(header[3]) * 256 + i32::from(header[4]) + 6 + 5;
                    let needed = usize::try_from(response_len[i]).unwrap_or(0);
                    responses[i].resize(needed, 0);
                    responses[i][0..5].copy_from_slice(&header);
                    read_pos[i] = 5;
                } else {
                    let cur_read_pos = usize::try_from(read_pos[i]).unwrap_or(0);
                    let cur_response_len = usize::try_from(response_len[i]).unwrap_or(0);
                    let read_res = unsafe {
                        libc::read(
                            sockets[i],
                            responses[i][cur_read_pos..cur_response_len]
                                .as_mut_ptr()
                                .cast::<c_void>(),
                            cur_response_len.saturating_sub(cur_read_pos),
                        )
                    };
                    if read_res == -1 {
                        unsafe {
                            crate::kprintf_fmt!(
                                PROBE_FAIL_READ_FMT.as_ptr().cast(),
                                domain_ptr,
                                strerror_ptr(),
                            );
                        }
                        have_error = true;
                        break;
                    }
                    read_pos[i] += c_int::try_from(read_res).unwrap_or(0);

                    if read_pos[i] == response_len[i] {
                        if !is_encrypted_data_len_read[i] {
                            let cur_len = usize::try_from(response_len[i]).unwrap_or(0);
                            if cur_len < 11
                                || responses[i][cur_len - 11..cur_len - 2]
                                    != TLS_CLIENT_CCS_PREFIX[..9]
                            {
                                unsafe {
                                    crate::kprintf_fmt!(PROBE_NO_TLS13_FMT.as_ptr().cast(), domain_ptr);
                                }
                                have_error = true;
                                break;
                            }

                            is_encrypted_data_len_read[i] = true;
                            let encrypted_len = i32::from(responses[i][cur_len - 2]) * 256
                                + i32::from(responses[i][cur_len - 1]);
                            response_len[i] += encrypted_len;
                            let new_len = usize::try_from(response_len[i]).unwrap_or(0);
                            responses[i].resize(new_len, 0);
                            continue;
                        }

                        let mut is_reversed = -1;
                        let mut encrypted_len = -1;
                        let request_session_id = &requests[i][44..76];
                        let ok = unsafe {
                            check_response_inner(
                                &responses[i],
                                request_session_id,
                                &mut is_reversed,
                                &mut encrypted_len,
                            )
                        };
                        if ok != 0 {
                            assert!(is_reversed != -1);
                            assert!(encrypted_len != -1);

                            if finished_count == 0 {
                                reversed_min = is_reversed;
                                reversed_max = is_reversed;
                                encrypted_len_min = encrypted_len;
                                encrypted_len_max = encrypted_len;
                            } else {
                                reversed_min = reversed_min.min(is_reversed);
                                reversed_max = reversed_max.max(is_reversed);
                                encrypted_len_min = encrypted_len_min.min(encrypted_len);
                                encrypted_len_max = encrypted_len_max.max(encrypted_len);
                            }
                            encrypted_len_sum += encrypted_len;
                            is_finished[i] = true;
                            finished_count += 1;
                        } else {
                            have_error = true;
                            break;
                        }
                    }
                }
            }

            if (revents & libc::POLLOUT) != 0 {
                assert!(!is_written[i]);
                let write_res = unsafe {
                    libc::write(
                        sockets[i],
                        requests[i].as_ptr().cast::<c_void>(),
                        TLS_REQUEST_LENGTH,
                    )
                };
                if write_res != TLS_REQUEST_LENGTH as isize {
                    unsafe {
                        crate::kprintf_fmt!(
                            PROBE_FAIL_WRITE_FMT.as_ptr().cast(),
                            domain_ptr,
                            if write_res == -1 {
                                strerror_ptr()
                            } else {
                                WRITTEN_LESS_BYTES.as_ptr().cast()
                            },
                        );
                    }
                    have_error = true;
                    break;
                }
                is_written[i] = true;
            }

            if (revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                unsafe {
                    crate::kprintf_fmt!(
                        PROBE_FAIL_EXCEPT_FMT.as_ptr().cast(),
                        domain_ptr,
                        strerror_ptr(),
                    );
                }
                have_error = true;
                break;
            }
        }
    }

    unsafe {
        close_sockets(&sockets);
    }

    if finished_count != TLS_PROBE_TRIES {
        if !have_error {
            unsafe {
                crate::kprintf_fmt!(PROBE_TIMEOUT_FMT.as_ptr().cast(), domain_ptr);
            }
        }
        return 0;
    }

    if reversed_min != reversed_max {
        unsafe {
            crate::kprintf_fmt!(PROBE_NON_DETERMINISTIC_EXT_FMT.as_ptr().cast(), domain_ptr);
        }
    }

    unsafe {
        (*info).is_reversed_extension_order = reversed_min as c_char;
    }

    let Some((selected_size, selected_profile)) =
        mtproxy_core::runtime::net::tcp_rpc_ext_server::select_server_hello_profile(
            encrypted_len_min,
            encrypted_len_max,
            encrypted_len_sum,
            TLS_PROBE_TRIES as c_int,
        )
    else {
        return 0;
    };

    if selected_profile == SERVER_HELLO_PROFILE_RANDOM_AVG {
        unsafe {
            crate::kprintf_fmt!(
                PROBE_UNRECOGNIZED_PATTERN_FMT.as_ptr().cast(),
                encrypted_len_min,
                encrypted_len_max,
                encrypted_len_sum as c_double / TLS_PROBE_TRIES as c_double,
            );
        }
    } else {
        assert!(
            selected_profile == SERVER_HELLO_PROFILE_FIXED
                || selected_profile == SERVER_HELLO_PROFILE_RANDOM_NEAR
        );
    }

    unsafe {
        (*info).server_hello_encrypted_size = selected_size as c_short;
        (*info).use_random_encrypted_size = if selected_profile == SERVER_HELLO_PROFILE_FIXED {
            0
        } else {
            1
        };

        crate::kprintf_fmt!(
            PROBE_SUCCESS_FMT.as_ptr().cast(),
            domain_ptr,
            get_utime_monotonic() - start_time,
            c_int::from((*info).is_reversed_extension_order),
            c_int::from((*info).server_hello_encrypted_size),
            c_int::from((*info).use_random_encrypted_size),
        );

        if (*info).is_reversed_extension_order != 0
            && c_int::from((*info).server_hello_encrypted_size) <= 1250
        {
            crate::kprintf_fmt!(
                PROBE_UNSUPPORTED_MULTI_PACKET_FMT.as_ptr().cast(),
                domain_ptr,
            );
        }
    }

    1
}

#[inline]
unsafe fn should_try_fake_tls_client_hello(
    packet_len: c_int,
    len: c_int,
    secret_cnt: c_int,
) -> bool {
    if len <= 0 || secret_cnt <= 0 || !unsafe { allow_only_tls() } {
        return false;
    }
    let packet = packet_len as u32;
    (packet & 0x00ff_ffff) == 0x0001_0316 && (packet >> 24) >= 2
}

unsafe fn parse_execute_inner(c: ConnectionJob) -> c_int {
    let d = unsafe { rpc_data(c) };
    let funcs = unsafe { rpc_funcs(c) };

    if unsafe { (*d).crypto_flags & RPCF_COMPACT_OFF } != 0 {
        if unsafe { (*d).in_packet_num } != -3 {
            unsafe {
                job_timer_remove(c);
            }
        }
        return unsafe { tcp_rpcs_parse_execute(c) };
    }

    let conn = unsafe { conn_info(c) };

    loop {
        if unsafe { (*d).in_packet_num } != -3 {
            unsafe {
                job_timer_remove(c);
            }
        }
        if unsafe { (*conn).flags & C_ERROR } != 0 {
            return NEED_MORE_BYTES;
        }
        if unsafe { (*conn).flags & C_STOPPARSE } != 0 {
            return NEED_MORE_BYTES;
        }

        let mut len = unsafe { (*conn).in_data.total_bytes };
        if len <= 0 {
            return NEED_MORE_BYTES;
        }

        let min_len = if unsafe { (*d).flags & RPC_F_MEDIUM } != 0 {
            4
        } else {
            1
        };
        if len < min_len + 8 {
            return min_len + 8 - len;
        }

        let mut packet_len: c_int = 0;
        assert!(
            unsafe {
                rwm_fetch_lookup(
                    &mut (*conn).in_data,
                    (&mut packet_len as *mut c_int).cast::<c_void>(),
                    4,
                )
            } == 4
        );

        if unsafe { (*d).in_packet_num } == -3 {
            unsafe {
                crate::kprintf_fmt!(
                    PARSE_TRY_TYPE_FMT.as_ptr().cast(),
                    mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(c),
                    (*conn).remote_port,
                );
            }

            if unsafe { (*conn).flags & C_IS_TLS } != 0 {
                if len < 11 {
                    return 11 - len;
                }

                unsafe {
                    crate::kprintf_fmt!(
                        PARSE_TLS_ESTABLISHED_FMT.as_ptr().cast(),
                        mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(c),
                        (*conn).remote_port,
                    );
                }

                let mut header = [0u8; 11];
                assert!(
                    unsafe {
                        rwm_fetch_lookup(
                            &mut (*conn).in_data,
                            header.as_mut_ptr().cast::<c_void>(),
                            11,
                        )
                    } == 11
                );
                if header[..9] != TLS_CLIENT_CCS_PREFIX[..9] {
                    unsafe {
                        crate::kprintf_fmt!(PARSE_BAD_CCS_FMT.as_ptr().cast());
                        fail_connection(c, -1);
                    }
                    return 0;
                }

                let new_min_len = 11 + i32::from(header[9]) * 256 + i32::from(header[10]);
                if len < new_min_len {
                    return new_min_len - len;
                }

                assert!(unsafe { rwm_skip_data(&mut (*conn).in_data, 11) } == 11);
                len -= 11;
                unsafe {
                    (*conn).left_tls_packet_length =
                        i32::from(header[9]) * 256 + i32::from(header[10]);
                    crate::kprintf_fmt!(
                        PARSE_TLS_FIRST_PACKET_FMT.as_ptr().cast(),
                        (*conn).left_tls_packet_length,
                    );
                }

                if unsafe { (*conn).left_tls_packet_length } < 64 {
                    unsafe {
                        crate::kprintf_fmt!(
                            PARSE_TLS_FIRST_TOO_SHORT_FMT.as_ptr().cast(),
                            (*conn).left_tls_packet_length,
                        );
                        fail_connection(c, -1);
                    }
                    return 0;
                }

                assert!(
                    unsafe {
                        rwm_fetch_lookup(
                            &mut (*conn).in_data,
                            (&mut packet_len as *mut c_int).cast::<c_void>(),
                            4,
                        )
                    } == 4
                );

                unsafe {
                    (*conn).left_tls_packet_length -= 64;
                }
            } else if unsafe {
                should_try_fake_tls_client_hello(packet_len, len, ext_secret_count())
            } {
                let mut header = [0u8; 5];
                assert!(
                    unsafe {
                        rwm_fetch_lookup(
                            &mut (*conn).in_data,
                            header.as_mut_ptr().cast::<c_void>(),
                            5,
                        )
                    } == 5
                );
                let min_len = 5 + i32::from(header[3]) * 256 + i32::from(header[4]);
                if len < min_len {
                    return min_len - len;
                }

                let read_len = usize::try_from(len).unwrap_or(0).min(MAX_CLIENT_HELLO_READ);
                let mut client_hello = vec![0u8; read_len];
                assert!(
                    unsafe {
                        rwm_fetch_lookup(
                            &mut (*conn).in_data,
                            client_hello.as_mut_ptr().cast::<c_void>(),
                            c_int::try_from(read_len).unwrap_or(0),
                        )
                    } == c_int::try_from(read_len).unwrap_or(0)
                );

                let info = unsafe { get_sni_domain_info_inner(&client_hello) };
                if info.is_null() {
                    return unsafe { proxy_connection_impl(c, default_domain_info()) };
                }

                unsafe {
                    crate::kprintf_fmt!(
                        PARSE_TLS_DOMAIN_FMT.as_ptr().cast(),
                        (*info).domain,
                        mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(c),
                        (*conn).remote_port,
                    );
                }

                if unsafe { (*conn).our_port } == 80 {
                    unsafe {
                        crate::kprintf_fmt!(
                            PARSE_TLS_PORT80_FMT.as_ptr().cast(),
                            (*conn).our_port,
                            (*info).domain,
                        );
                    }
                    return unsafe { proxy_connection_impl(c, info) };
                }

                if len > min_len {
                    unsafe {
                        crate::kprintf_fmt!(PARSE_TLS_TOO_MUCH_DATA_FMT.as_ptr().cast(), len, min_len);
                    }
                    return unsafe { proxy_connection_impl(c, info) };
                }
                if c_int::try_from(read_len).unwrap_or(-1) != len {
                    unsafe {
                        crate::kprintf_fmt!(PARSE_TLS_TOO_BIG_FMT.as_ptr().cast(), len);
                    }
                    return unsafe { proxy_connection_impl(c, info) };
                }

                if client_hello.len() < 43 {
                    return unsafe { proxy_connection_impl(c, info) };
                }

                let mut client_random = [0u8; 32];
                client_random.copy_from_slice(&client_hello[11..43]);
                client_hello[11..43].fill(0);

                if unsafe { mtproxy_ffi_net_tcp_rpc_ext_have_client_random(client_random.as_ptr()) }
                    != 0
                {
                    unsafe {
                        crate::kprintf_fmt!(PARSE_TLS_DUP_RANDOM_FMT.as_ptr().cast());
                    }
                    return unsafe { proxy_connection_impl(c, info) };
                }
                unsafe {
                    mtproxy_ffi_net_tcp_rpc_ext_add_client_random(client_random.as_ptr());
                    mtproxy_ffi_net_tcp_rpc_ext_delete_old_client_randoms();
                }

                let secret_cnt = unsafe { ext_secret_count() };
                let mut expected_random = [0u8; 32];
                let mut secret_id = secret_cnt;
                for i in 0..secret_cnt {
                    let secret_ptr = unsafe { ext_secret_at(i) };
                    if secret_ptr.is_null() {
                        continue;
                    }
                    let mut secret = [0u8; 16];
                    unsafe {
                        ptr::copy_nonoverlapping(secret_ptr, secret.as_mut_ptr(), 16);
                    }
                    unsafe {
                        sha256_hmac(
                            secret.as_mut_ptr(),
                            16,
                            client_hello.as_mut_ptr(),
                            len,
                            expected_random.as_mut_ptr(),
                        );
                    }
                    if expected_random[..28] == client_random[..28] {
                        secret_id = i;
                        break;
                    }
                }
                if secret_id == secret_cnt {
                    unsafe {
                        crate::kprintf_fmt!(PARSE_TLS_UNMATCHED_RANDOM_FMT.as_ptr().cast());
                    }
                    return unsafe { proxy_connection_impl(c, info) };
                }

                let timestamp =
                    i32::from_ne_bytes(expected_random[28..32].try_into().unwrap_or([0u8; 4]))
                        ^ i32::from_ne_bytes(client_random[28..32].try_into().unwrap_or([0u8; 4]));

                if unsafe { mtproxy_ffi_net_tcp_rpc_ext_is_allowed_timestamp_state(timestamp) } == 0
                {
                    return unsafe { proxy_connection_impl(c, info) };
                }

                let mut pos = 76usize;
                let Some(mut cipher_suites_length) =
                    (unsafe { read_length_buf(&client_hello, &mut pos) })
                else {
                    return unsafe { proxy_connection_impl(c, info) };
                };

                if pos + usize::try_from(cipher_suites_length).unwrap_or(usize::MAX) > read_len {
                    unsafe {
                        crate::kprintf_fmt!(
                            PARSE_TLS_CIPHER_LIST_TOO_LONG_FMT.as_ptr().cast(),
                            cipher_suites_length,
                        );
                    }
                    return unsafe { proxy_connection_impl(c, info) };
                }

                while cipher_suites_length >= 2
                    && (client_hello[pos] & 0x0f) == 0x0a
                    && (client_hello[pos + 1] & 0x0f) == 0x0a
                {
                    cipher_suites_length -= 2;
                    pos += 2;
                }

                if cipher_suites_length <= 1
                    || client_hello[pos] != 0x13
                    || !(0x01..=0x03).contains(&client_hello[pos + 1])
                {
                    unsafe {
                        crate::kprintf_fmt!(PARSE_TLS_NO_CIPHER_FMT.as_ptr().cast());
                    }
                    return unsafe { proxy_connection_impl(c, info) };
                }
                let cipher_suite_id = client_hello[pos + 1];

                assert!(unsafe { rwm_skip_data(&mut (*conn).in_data, len) } == len);
                unsafe {
                    (*conn).flags |= C_IS_TLS;
                    (*conn).left_tls_packet_length = -1;
                }

                let encrypted_size = unsafe { domain_server_hello_encrypted_size_impl(info) };
                let response_size = 127 + 6 + 5 + encrypted_size;
                let response_size_usize = usize::try_from(response_size).unwrap_or(0);
                let mut buffer = vec![0u8; 32 + response_size_usize];
                buffer[..32].copy_from_slice(&client_random);
                {
                    let response_buffer = &mut buffer[32..];
                    response_buffer[..11].copy_from_slice(TLS_SERVER_HELLO_PREFIX);
                    response_buffer[11..43].fill(0);
                    response_buffer[43] = 0x20;
                    response_buffer[44..76].copy_from_slice(&client_hello[44..76]);
                    response_buffer[76..81].copy_from_slice(TLS_SERVER_HELLO_CIPHER_PREFIX);
                    response_buffer[77] = cipher_suite_id;

                    let mut pos = 81usize;
                    let mut tls_server_extensions = [0x33i32, 0x2bi32];
                    if unsafe { (*info).is_reversed_extension_order } != 0 {
                        tls_server_extensions.swap(0, 1);
                    }
                    for ext in tls_server_extensions {
                        if ext == 0x33 {
                            assert!(pos + 40 <= response_size_usize);
                            response_buffer[pos..pos + 8]
                                .copy_from_slice(TLS_SERVER_EXT_KEY_SHARE_PREFIX);
                            assert!(
                                unsafe {
                                    mtproxy_ffi_crypto_tls_generate_public_key(
                                        response_buffer[pos + 8..pos + 40].as_mut_ptr(),
                                    )
                                } == 0
                            );
                            pos += 40;
                        } else if ext == 0x2b {
                            assert!(pos + 6 <= response_size_usize);
                            response_buffer[pos..pos + 6].copy_from_slice(TLS_SERVER_EXT_VERSIONS);
                            pos += 6;
                        } else {
                            unreachable!();
                        }
                    }
                    assert!(pos == 127);
                    response_buffer[127..136].copy_from_slice(TLS_SERVER_TRAILER);
                    pos += 9;
                    response_buffer[pos] = (encrypted_size / 256) as u8;
                    response_buffer[pos + 1] = (encrypted_size % 256) as u8;
                    pos += 2;
                    let encrypted_size_usize = usize::try_from(encrypted_size).unwrap_or(0);
                    assert!(pos + encrypted_size_usize == response_size_usize);
                    assert!(
                        unsafe {
                            mtproxy_ffi_crypto_rand_bytes(
                                response_buffer[pos..pos + encrypted_size_usize].as_mut_ptr(),
                                encrypted_size,
                            )
                        } == 0
                    );
                }

                let secret_ptr = unsafe { ext_secret_at(secret_id) };
                if secret_ptr.is_null() {
                    return unsafe { proxy_connection_impl(c, info) };
                }
                let mut secret = [0u8; 16];
                unsafe {
                    ptr::copy_nonoverlapping(secret_ptr, secret.as_mut_ptr(), 16);
                }

                let mut server_random = [0u8; 32];
                unsafe {
                    sha256_hmac(
                        secret.as_mut_ptr(),
                        16,
                        buffer.as_mut_ptr(),
                        c_int::try_from(32 + response_size_usize).unwrap_or(0),
                        server_random.as_mut_ptr(),
                    );
                }
                buffer[32 + 11..32 + 43].copy_from_slice(&server_random);

                let msg = unsafe { libc::calloc(1, size_of::<RawMessage>()) }.cast::<RawMessage>();
                assert!(!msg.is_null());
                assert!(
                    unsafe {
                        rwm_create(msg, buffer[32..].as_ptr().cast::<c_void>(), response_size)
                    } == response_size
                );
                unsafe {
                    mpq_push_w((*conn).out_queue, msg.cast::<c_void>(), 0);
                    let cref = job_incref(c);
                    job_signal(1, cref, JS_RUN);
                }
                return 11;
            }

            if unsafe { allow_only_tls() } && (unsafe { (*conn).flags & C_IS_TLS } == 0) {
                unsafe {
                    crate::kprintf_fmt!(PARSE_EXPECT_TLS_FMT.as_ptr().cast());
                }
                return unsafe { proxy_connection_impl(c, default_domain_info()) };
            }

            if len < 64 {
                unsafe {
                    crate::kprintf_fmt!(
                        PARSE_NEED_MORE_RANDOM_HEADER_FMT.as_ptr().cast(),
                        len,
                        64 - len,
                    );
                }
                return 64 - len;
            }

            let mut random_header = [0u8; 64];
            let mut k = [0u8; 48];
            assert!(
                unsafe {
                    rwm_fetch_lookup(
                        &mut (*conn).in_data,
                        random_header.as_mut_ptr().cast::<c_void>(),
                        64,
                    )
                } == 64
            );

            let random_header_sav = random_header;
            let mut key_data = AesKeyData {
                read_key: [0u8; 32],
                read_iv: [0u8; 16],
                write_key: [0u8; 32],
                write_iv: [0u8; 16],
            };

            let mut ok = false;
            let secret_cnt = unsafe { ext_secret_count() };
            let loop_count = if secret_cnt > 0 { secret_cnt } else { 1 };

            for secret_id in 0..loop_count {
                if secret_cnt > 0 {
                    let secret_ptr = unsafe { ext_secret_at(secret_id) };
                    if secret_ptr.is_null() {
                        continue;
                    }
                    k[..32].copy_from_slice(&random_header[8..40]);
                    unsafe {
                        ptr::copy_nonoverlapping(secret_ptr, k[32..48].as_mut_ptr(), 16);
                        sha256(k.as_ptr(), 48, key_data.read_key.as_mut_ptr());
                    }
                } else {
                    key_data.read_key.copy_from_slice(&random_header[8..40]);
                }
                key_data.read_iv.copy_from_slice(&random_header[40..56]);

                for i in 0..32 {
                    key_data.write_key[i] = random_header[55 - i];
                }
                for i in 0..16 {
                    key_data.write_iv[i] = random_header[23 - i];
                }

                if secret_cnt > 0 {
                    k[..32].copy_from_slice(&key_data.write_key);
                    unsafe {
                        sha256(k.as_ptr(), 48, key_data.write_key.as_mut_ptr());
                    }
                }

                assert!(
                    unsafe {
                        aes_crypto_ctr128_init(
                            c,
                            (&mut key_data as *mut AesKeyData).cast::<c_void>(),
                            c_int::try_from(size_of::<AesKeyData>()).unwrap_or(0),
                        )
                    } >= 0
                );
                assert!(!unsafe { (*conn).crypto }.is_null());

                let t = unsafe { (*conn).crypto.cast::<AesCrypto>() };
                unsafe {
                    aesni_crypt(
                        (*t).read_aeskey,
                        random_header.as_ptr().cast::<c_void>(),
                        random_header.as_mut_ptr().cast::<c_void>(),
                        64,
                    );
                }

                let tag = u32::from_ne_bytes(random_header[56..60].try_into().unwrap_or([0u8; 4]));
                if tag == 0xdddd_dddd || tag == 0xeeee_eeee || tag == 0xefef_efef {
                    if tag != 0xdddd_dddd && unsafe { allow_only_tls() } {
                        unsafe {
                            crate::kprintf_fmt!(PARSE_EXPECT_PAD_MODE_FMT.as_ptr().cast());
                        }
                        return unsafe { proxy_connection_impl(c, default_domain_info()) };
                    }

                    assert!(unsafe { rwm_skip_data(&mut (*conn).in_data, 64) } == 64);
                    unsafe {
                        rwm_union(&mut (*conn).in_u, &mut (*conn).in_data);
                        rwm_init(&mut (*conn).in_data, 0);
                        (*d).in_packet_num = 0;
                    }

                    match tag {
                        0xeeee_eeee => unsafe {
                            (*d).flags |= RPC_F_MEDIUM | RPC_F_EXTMODE2;
                        },
                        0xdddd_dddd => unsafe {
                            (*d).flags |= RPC_F_MEDIUM | RPC_F_EXTMODE2 | RPC_F_PAD;
                        },
                        0xefef_efef => unsafe {
                            (*d).flags |= RPC_F_COMPACT | RPC_F_EXTMODE2;
                        },
                        _ => {}
                    }

                    let decrypt = unsafe { (*(*conn).type_).crypto_decrypt_input };
                    if let Some(decrypt_fn) = decrypt {
                        assert!(unsafe { decrypt_fn(c) } >= 0);
                    } else {
                        return 0;
                    }

                    let target =
                        i16::from_ne_bytes(random_header[60..62].try_into().unwrap_or([0u8; 2]));
                    unsafe {
                        (*d).extra_int4 = c_int::from(target);
                        crate::kprintf_fmt!(
                            PARSE_OPPORTUNISTIC_FMT.as_ptr().cast(),
                            tag,
                            (*d).extra_int4,
                        );
                    }
                    ok = true;
                    break;
                } else {
                    unsafe {
                        aes_crypto_free(c);
                    }
                    random_header.copy_from_slice(&random_header_sav);
                }
            }

            if ok {
                continue;
            }

            if unsafe { ext_secret_count() } > 0 {
                unsafe {
                    crate::kprintf_fmt!(PARSE_INVALID_SKIP_FMT.as_ptr().cast());
                }
                return -268_435_456;
            }

            if TCP_RPCS_ALLOW_UNOBFS {
                unsafe {
                    (*d).flags |= RPC_F_COMPACT | RPC_F_EXTMODE1;
                    (*d).in_packet_num = 0;
                }
                assert!(len >= 64);
                assert!(unsafe { rwm_skip_data(&mut (*conn).in_data, 64) } == 64);
                continue;
            }

            unsafe {
                crate::kprintf_fmt!(PARSE_INVALID_SKIP_FMT.as_ptr().cast());
            }
            return -268_435_456;
        }

        let mut packet_len_bytes = 4;
        if unsafe { (*d).flags & RPC_F_MEDIUM } != 0 {
            unsafe {
                (*d).flags = ((*d).flags & !RPC_F_QUICKACK) | (packet_len & RPC_F_QUICKACK);
            }
            packet_len &= !RPC_F_QUICKACK;
        } else {
            if packet_len & 0x80 != 0 {
                unsafe {
                    (*d).flags |= RPC_F_QUICKACK;
                }
                packet_len &= !0x80;
            } else {
                unsafe {
                    (*d).flags &= !RPC_F_QUICKACK;
                }
            }

            if (packet_len & 0xff) == 0x7f {
                packet_len = ((packet_len as u32) >> 8) as c_int;
                if packet_len < 0x7f {
                    unsafe {
                        crate::kprintf_fmt!(PARSE_OVERLONG_LEN_FMT.as_ptr().cast(), packet_len);
                        fail_connection(c, -1);
                    }
                    return 0;
                }
            } else {
                packet_len &= 0x7f;
                packet_len_bytes = 1;
            }
            packet_len <<= 2;
        }

        if packet_len <= 0
            || ((packet_len as u32) & 0xc000_0000) != 0
            || (unsafe { (*d).flags & RPC_F_PAD } == 0 && (packet_len & 3) != 0)
        {
            unsafe {
                crate::kprintf_fmt!(PARSE_BAD_PACKET_LEN_FMT.as_ptr().cast(), packet_len);
                fail_connection(c, -1);
            }
            return 0;
        }

        if unsafe { (*funcs).max_packet_len > 0 && packet_len > (*funcs).max_packet_len } {
            unsafe {
                crate::kprintf_fmt!(PARSE_BAD_PACKET_LEN_FMT.as_ptr().cast(), packet_len);
                fail_connection(c, -1);
            }
            return 0;
        }

        if len < packet_len + packet_len_bytes {
            return packet_len + packet_len_bytes - len;
        }

        assert!(
            unsafe { rwm_skip_data(&mut (*conn).in_data, packet_len_bytes) } == packet_len_bytes
        );

        let mut msg = RawMessage::default();
        unsafe {
            rwm_split_head(&mut msg, &mut (*conn).in_data, packet_len);
        }
        if unsafe { (*d).flags & RPC_F_PAD } != 0 {
            unsafe {
                rwm_trunc(&mut msg, packet_len & -4);
            }
        }

        let mut packet_type: c_int = 0;
        assert!(
            unsafe {
                rwm_fetch_lookup(
                    &mut msg,
                    (&mut packet_type as *mut c_int).cast::<c_void>(),
                    4,
                )
            } == 4
        );

        if unsafe { (*d).in_packet_num } < 0 {
            assert!(unsafe { (*d).in_packet_num } == -3);
            unsafe {
                (*d).in_packet_num = 0;
            }
        }

        if unsafe { verbosity } > 2 {
            unsafe {
                crate::kprintf_fmt!(
                    PARSE_RECEIVED_PACKET_FMT.as_ptr().cast(),
                    (*conn).fd,
                    packet_len,
                    (*d).in_packet_num,
                    packet_type,
                );
                rwm_dump(&mut msg);
            }
        }

        unsafe {
            (*conn).last_response_time = precise_now_value();
        }
        let res = if packet_type == RPC_PING {
            unsafe { tcp_rpcs_default_execute(c, packet_type, &mut msg) }
        } else {
            let exec = unsafe { (*funcs).execute };
            if let Some(exec_fn) = exec {
                unsafe { exec_fn(c, packet_type, &mut msg) }
            } else {
                0
            }
        };
        if res <= 0 {
            unsafe {
                rwm_free(&mut msg);
            }
        }

        unsafe {
            (*d).in_packet_num += 1;
        }
    }
}

pub(super) unsafe fn tcp_proxy_pass_parse_execute_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let extra = unsafe { (*conn).extra };
    if extra.is_null() {
        unsafe {
            fail_connection(c, -1);
        }
        return 0;
    }

    let e = unsafe { job_incref(extra) };
    let e_conn = unsafe { conn_info(e) };

    let raw = unsafe { libc::malloc(size_of::<RawMessage>()) }.cast::<RawMessage>();
    if raw.is_null() {
        unsafe {
            mtproxy_ffi_net_tcp_rpc_ext_job_decref(e);
            fail_connection(c, -1);
        }
        return 0;
    }

    unsafe {
        rwm_move(raw, &mut (*conn).in_data);
        rwm_init(&mut (*conn).in_data, 0);
    }

    if unsafe { verbosity } > 2 {
        unsafe {
            crate::kprintf_fmt!(
                PROXY_PASS_FORWARD_FMT.as_ptr().cast(),
                (*raw).total_bytes,
                mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(e),
                (*e_conn).remote_port,
            );
        }
    }

    unsafe {
        mpq_push_w((*e_conn).out_queue, raw.cast::<c_void>(), 0);
        job_signal(1, e, JS_RUN);
    }
    0
}

pub(super) unsafe fn tcp_proxy_pass_close_impl(c: ConnectionJob, who: c_int) -> c_int {
    let conn = unsafe { conn_info(c) };
    if unsafe { verbosity } > 0 {
        unsafe {
            crate::kprintf_fmt!(
                b"closing proxy pass connection #%d %s:%d -> %s:%d\n\0"
                    .as_ptr()
                    .cast(),
                (*conn).fd,
                mtproxy_ffi_net_tcp_rpc_ext_show_our_ip(c),
                (*conn).our_port,
                mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(c),
                (*conn).remote_port,
            );
        }
    }
    let e = unsafe { (*conn).extra.cast::<c_void>() };
    if !e.is_null() {
        unsafe {
            (*conn).extra = ptr::null_mut();
            fail_connection(e, -23);
            mtproxy_ffi_net_tcp_rpc_ext_job_decref(e);
        }
    }
    unsafe { cpu_server_close_connection(c, who) }
}

pub(super) unsafe fn tcp_proxy_pass_write_packet_impl(
    c: ConnectionJob,
    raw: *mut RawMessage,
) -> c_int {
    if raw.is_null() {
        return -1;
    }
    let conn = unsafe { conn_info(c) };
    unsafe {
        rwm_union(&mut (*conn).out, raw);
    }
    0
}

unsafe fn update_domain_info_chain(mut info: *mut DomainInfo) {
    while !info.is_null() {
        if unsafe { update_domain_info_inner(info) } == 0 {
            unsafe {
                crate::kprintf_fmt!(INIT_DOMAIN_FAIL_FMT.as_ptr().cast(), (*info).domain);
                (*info).is_reversed_extension_order = 0;
                (*info).use_random_encrypted_size = 1;
                (*info).server_hello_encrypted_size = (2500 + libc::rand() % 1120) as c_short;
            }
        }
        info = unsafe { (*info).next };
    }
}

pub(super) unsafe fn tcp_rpc_init_proxy_domains_impl(
    domains: *mut *mut DomainInfo,
    buckets: c_int,
) {
    if domains.is_null() || buckets <= 0 {
        return;
    }

    for i in 0..buckets {
        let info = unsafe { *domains.add(usize::try_from(i).unwrap_or(0)) };
        unsafe {
            update_domain_info_chain(info);
        }
    }
}

pub(super) unsafe fn tcp_rpc_init_proxy_domains_state_impl() {
    with_ext_server_state(|state| {
        for &head in &state.buckets {
            unsafe {
                update_domain_info_chain(head);
            }
        }
    });
}

pub(super) unsafe fn proxy_connection_impl(c: ConnectionJob, info: *const DomainInfo) -> c_int {
    if info.is_null() {
        unsafe {
            fail_connection(c, -17);
        }
        return 0;
    }

    let conn = unsafe { conn_info(c) };
    assert!(
        unsafe {
            crate::net_connections::check_conn_functions_bridge(
                ptr::addr_of_mut!(ct_proxy_pass).cast::<c_void>(),
            )
        } >= 0
    );

    let info_ref = unsafe { &*info };
    if info_ref.target.s_addr == 0 && info_ref.target_ipv6.iter().all(|&x| x == 0) {
        unsafe {
            crate::kprintf_fmt!(PROXY_FAIL_DOMAIN_FMT.as_ptr().cast(), info_ref.domain);
            fail_connection(c, -17);
        }
        return 0;
    }

    let port = if unsafe { (*conn).our_port } == 80 {
        80
    } else {
        443
    };

    let cfd = if info_ref.target.s_addr != 0 {
        unsafe { client_socket(info_ref.target.s_addr, port, 0) }
    } else {
        unsafe { client_socket_ipv6(info_ref.target_ipv6.as_ptr(), port, SM_IPV6) }
    };

    if cfd < 0 {
        unsafe {
            crate::kprintf_fmt!(
                PROXY_FAIL_SOCKET_FMT.as_ptr().cast(),
                errno_value(),
                strerror_ptr(),
            );
            fail_connection(c, -27);
        }
        return 0;
    }

    if let Some(crypto_free_fn) = unsafe { (*(*conn).type_).crypto_free } {
        unsafe {
            crypto_free_fn(c);
        }
    }

    unsafe {
        job_incref(c);
    }
    let peer = u32::from_be(info_ref.target.s_addr);
    let ej = unsafe {
        alloc_new_connection(
            cfd,
            ptr::null_mut(),
            ptr::null_mut(),
            CT_OUTBOUND,
            ptr::addr_of_mut!(ct_proxy_pass),
            c,
            peer,
            info_ref.target_ipv6.as_ptr().cast_mut(),
            port,
        )
    };

    if ej.is_null() {
        unsafe {
            crate::kprintf_fmt!(PROXY_FAIL_CONN_FMT.as_ptr().cast());
            mtproxy_ffi_net_tcp_rpc_ext_job_decref(c);
            fail_connection(c, -37);
        }
        return 0;
    }

    unsafe {
        (*conn).type_ = ptr::addr_of_mut!(ct_proxy_pass);
        (*conn).extra = job_incref(ej);
    }

    let e_conn = unsafe { conn_info(ej) };
    assert!(!unsafe { (*e_conn).io_conn.is_null() });
    unsafe {
        mtproxy_ffi_net_tcp_rpc_ext_unlock_job(ej);
    }

    if let Some(parse_execute_fn) = unsafe { (*(*conn).type_).parse_execute } {
        unsafe { parse_execute_fn(c) }
    } else {
        0
    }
}

pub(super) unsafe fn have_client_random_state_impl(random: *const u8) -> c_int {
    let Some(key) = (unsafe { read_client_random_key(random) }) else {
        return 0;
    };
    let state = client_random_state();
    let guard = match state.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.counts.contains_key(&key) {
        1
    } else {
        0
    }
}

pub(super) unsafe fn add_client_random_state_impl(random: *const u8, now: c_int) {
    let Some(key) = (unsafe { read_client_random_key(random) }) else {
        return;
    };
    let state = client_random_state();
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.entries.push_back(ClientRandomEntry {
        random: key,
        time: now,
    });
    let count = guard.counts.entry(key).or_insert(0);
    *count += 1;
}

pub(super) unsafe fn delete_old_client_randoms_state_impl(now: c_int) {
    let state = client_random_state();
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    while guard.entries.len() > 1 {
        let Some(first) = guard.entries.front().copied() else {
            break;
        };
        if first.time > now - MAX_CLIENT_RANDOM_CACHE_TIME {
            break;
        }

        let removed = guard.entries.pop_front();
        if let Some(entry) = removed {
            if let Some(count) = guard.counts.get_mut(&entry.random) {
                if *count <= 1 {
                    guard.counts.remove(&entry.random);
                } else {
                    *count -= 1;
                }
            }
        }
    }
}

pub(super) unsafe fn is_allowed_timestamp_state_impl(timestamp: c_int, now: c_int) -> c_int {
    let state = client_random_state();
    let guard = match state.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let first_time = guard.entries.front().map(|entry| entry.time);
    if mtproxy_core::runtime::net::tcp_rpc_ext_server::is_allowed_timestamp(
        timestamp, now, first_time,
    ) {
        1
    } else {
        0
    }
}

pub(super) unsafe fn tcp_rpcs_set_ext_secret_impl(secret: *const u8) {
    if secret.is_null() {
        return;
    }
    let secret_slice = unsafe { slice::from_raw_parts(secret, 16) };
    with_ext_server_state_mut(|state| {
        assert!(state.ext_secret_cnt < EXT_SECRET_LIMIT);
        state.ext_secret[state.ext_secret_cnt].copy_from_slice(secret_slice);
        state.ext_secret_cnt += 1;
    });
}

pub(super) unsafe fn tcp_rpc_add_proxy_domain_state_impl(domain: *const c_char) {
    unsafe { state_add_proxy_domain(domain) }
}

pub(super) unsafe fn lookup_domain_info_state_impl(
    domain: *const u8,
    len: c_int,
) -> *const DomainInfo {
    unsafe { state_lookup_domain_info(domain, len) }
}

pub(super) fn default_domain_info_state_impl() -> *const DomainInfo {
    state_default_domain_info()
}

pub(super) fn allow_only_tls_state_impl() -> c_int {
    if state_allow_only_tls() {
        1
    } else {
        0
    }
}

pub(super) fn ext_secret_count_state_impl() -> c_int {
    state_ext_secret_count()
}

pub(super) fn ext_secret_at_state_impl(index: c_int) -> *const u8 {
    state_ext_secret_at(index)
}

pub(super) unsafe fn domain_server_hello_encrypted_size_impl(info: *const DomainInfo) -> c_int {
    if info.is_null() {
        return 0;
    }
    mtproxy_core::runtime::net::tcp_rpc_ext_server::get_domain_server_hello_encrypted_size(
        i32::from(unsafe { (*info).server_hello_encrypted_size }),
        unsafe { (*info).use_random_encrypted_size != 0 },
        unsafe { libc::rand() },
    )
}

pub(super) unsafe fn tcp_rpcs_ext_alarm_impl(c: ConnectionJob) -> c_int {
    let data = unsafe { rpc_data(c) };
    if unsafe { (*data).in_packet_num } != -3 {
        return 0;
    }
    let info = state_default_domain_info();
    if info.is_null() {
        return 0;
    }
    unsafe { proxy_connection_impl(c, info) }
}

pub(super) unsafe fn create_request_impl(domain: *const c_char) -> *mut u8 {
    if domain.is_null() {
        return ptr::null_mut();
    }
    let domain_bytes = unsafe { CStr::from_ptr(domain).to_bytes() };
    let Some(request) = create_request_bytes(domain_bytes) else {
        return ptr::null_mut();
    };

    let result = unsafe { libc::malloc(TLS_REQUEST_LENGTH) }.cast::<u8>();
    if result.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::copy_nonoverlapping(request.as_ptr(), result, TLS_REQUEST_LENGTH);
    }
    result
}

pub(super) unsafe fn check_response_impl(
    response: *const u8,
    len: c_int,
    request_session_id: *const u8,
    is_reversed_extension_order: *mut c_int,
    encrypted_application_data_length: *mut c_int,
) -> c_int {
    if response.is_null()
        || request_session_id.is_null()
        || is_reversed_extension_order.is_null()
        || encrypted_application_data_length.is_null()
        || len < 0
    {
        return 0;
    }

    let response_slice =
        unsafe { slice::from_raw_parts(response, usize::try_from(len).unwrap_or(0)) };
    let request_session_id_slice = unsafe { slice::from_raw_parts(request_session_id, 32) };
    unsafe {
        check_response_inner(
            response_slice,
            request_session_id_slice,
            &mut *is_reversed_extension_order,
            &mut *encrypted_application_data_length,
        )
    }
}

pub(super) unsafe fn update_domain_info_impl(info: *mut DomainInfo) -> c_int {
    unsafe { update_domain_info_inner(info) }
}

pub(super) unsafe fn get_sni_domain_info_impl(request: *const u8, len: c_int) -> *const DomainInfo {
    if request.is_null() || len < 0 {
        return ptr::null();
    }
    let request_slice =
        unsafe { slice::from_raw_parts(request, usize::try_from(len).unwrap_or(0)) };
    unsafe { get_sni_domain_info_inner(request_slice) }
}

pub(super) unsafe fn tcp_rpcs_compact_parse_execute_impl(c: ConnectionJob) -> c_int {
    unsafe { parse_execute_inner(c) }
}
