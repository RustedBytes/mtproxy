//! Rust runtime implementation for `net/net-tcp-rpc-server.c`.

use core::ffi::{c_char, c_double, c_int, c_long, c_uint, c_void};
use core::mem::{align_of, size_of, MaybeUninit};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};
use mtproxy_core::runtime::net::tcp_rpc_common::{
    parse_handshake_packet, parse_nonce_packet, HandshakeErrorPacket, HandshakePacket,
    PacketSerialization, ProcessId as CoreProcessId,
};
use mtproxy_core::runtime::net::tcp_rpc_server::{
    default_check_perm as core_default_check_perm,
    default_execute_set_pong as core_default_execute_set_pong,
    default_execute_should_pong as core_default_execute_should_pong, do_wakeup as core_do_wakeup,
    init_accepted_nohs_state as core_init_accepted_nohs_state,
    init_accepted_state as core_init_accepted_state,
    init_fake_crypto_state as core_init_fake_crypto_state,
    notification_pending_queries as core_notification_pending_queries,
    packet_header_malformed as core_packet_header_malformed,
    packet_len_state as core_packet_len_state, process_nonce_packet_for_compat,
    should_notify_close as core_should_notify_close, should_set_wantwr as core_should_set_wantwr,
    validate_handshake as core_validate_handshake,
    validate_handshake_header as core_validate_handshake_header,
    validate_nonce_header as core_validate_nonce_header,
};

pub(super) type ConnectionJob = *mut c_void;
type Job = *mut c_void;

const CONN_CUSTOM_DATA_BYTES: usize = 256;
const NEED_MORE_BYTES: c_int = 0x7fff_ffff;

const C_WANTWR: c_int = 2;
const C_ERROR: c_int = 8;
const C_STOPPARSE: c_int = 0x400000;
const C_ISDH: c_int = 0x800000;

const RPCF_ALLOW_UNENC: c_int = 1;
const RPCF_ALLOW_ENC: c_int = 2;
const RPCF_REQ_DH: c_int = 4;
const RPCF_ALLOW_SKIP_DH: c_int = 8;
const RPCF_ENC_SENT: c_int = 16;
const RPCF_SEQNO_HOLES: c_int = 256;
const RPCF_QUICKACK: c_int = 512;
const RPCF_USE_CRC32C: c_int = 2048;

const RPC_F_QUICKACK: c_int = c_int::MIN;

const TCP_RPC_IGNORE_PID: c_int = 4;

const RPC_NONCE: c_int = 0x7acb_87aa_u32 as i32;
const RPC_CRYPTO_NONE: c_int = 0;
const RPC_CRYPTO_AES: c_int = 1;
const RPC_CRYPTO_AES_EXT: c_int = 2;
const RPC_CRYPTO_AES_DH: c_int = 3;
const RPC_PING: c_int = 0x5730_a2df_u32 as i32;

const RPC_MAX_EXTRA_KEYS: usize = 8;

const NONCE_PACKET_LEN: usize = size_of::<TcpRpcNoncePacket>();
const NONCE_DH_PACKET_MIN_LEN: usize = size_of::<TcpRpcNonceDhPacket>() - 4 * RPC_MAX_EXTRA_KEYS;
const NONCE_DH_PACKET_MAX_LEN: usize = size_of::<TcpRpcNonceDhPacket>();
const HANDSHAKE_PACKET_LEN: usize = size_of::<TcpRpcHandshakePacket>();

const HTTP_HEAD_WORD: c_int = i32::from_ne_bytes(*b"HEAD");
const HTTP_POST_WORD: c_int = i32::from_ne_bytes(*b"POST");
const HTTP_GET_WORD: c_int = i32::from_ne_bytes(*b"GET ");
const HTTP_OPTI_WORD: c_int = i32::from_ne_bytes(*b"OPTI");

#[repr(C)]
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

#[repr(C)]
struct AsyncJob {
    j_flags: c_int,
    j_status: c_int,
    j_sigclass: c_int,
    j_refcnt: c_int,
    j_error: c_int,
    j_children: c_int,
    j_align: c_int,
    j_custom_bytes: c_int,
    j_type: c_uint,
    j_subclass: c_int,
    j_thread: *mut c_void,
    j_execute: Option<unsafe extern "C" fn(Job, c_int, *mut c_void) -> c_int>,
    j_parent: Job,
    j_custom: [i64; 0],
}

#[repr(C)]
pub(super) struct ConnectionInfo {
    pub timer: EventTimer,
    pub fd: c_int,
    pub generation: c_int,
    pub flags: c_int,
    pub type_: *mut c_void,
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

pub(super) type Crc32PartialFn =
    Option<unsafe extern "C" fn(*const c_void, c_long, c_uint) -> c_uint>;

pub(super) type ProcessId = crate::MtproxyProcessId;

#[repr(C)]
pub(super) struct TcpRpcData {
    pub flags: c_int,
    pub in_packet_num: c_int,
    pub out_packet_num: c_int,
    pub crypto_flags: c_int,
    pub remote_pid: ProcessId,
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
    pub custom_crc_partial: Crc32PartialFn,
}

type RpcExecuteFn = Option<unsafe extern "C" fn(ConnectionJob, c_int, *mut RawMessage) -> c_int>;
type RpcCheckReadyFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type RpcFlushPacketFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type RpcCheckPermFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type RpcInitCryptoFn = Option<unsafe extern "C" fn(ConnectionJob, *mut TcpRpcNoncePacket) -> c_int>;
type RpcWakeupFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type RpcCloseFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;

#[repr(C)]
pub(super) struct TcpRpcServerFunctions {
    pub info: *mut c_void,
    pub rpc_extra: *mut c_void,
    pub execute: RpcExecuteFn,
    pub check_ready: RpcCheckReadyFn,
    pub flush_packet: RpcFlushPacketFn,
    pub rpc_check_perm: RpcCheckPermFn,
    pub rpc_init_crypto: RpcInitCryptoFn,
    pub nop: *mut c_void,
    pub rpc_wakeup: RpcWakeupFn,
    pub rpc_alarm: RpcWakeupFn,
    pub rpc_ready: RpcWakeupFn,
    pub rpc_close: RpcCloseFn,
    pub max_packet_len: c_int,
    pub mode_flags: c_int,
    pub memcache_fallback_type: *mut c_void,
    pub memcache_fallback_extra: *mut c_void,
    pub http_fallback_type: *mut c_void,
    pub http_fallback_extra: *mut c_void,
}

type ConnLifecycleFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type ConnCloseFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;

#[repr(C)]
struct ConnFunctions {
    pub magic: c_int,
    pub flags: c_int,
    pub title: *mut c_char,
    pub accept: ConnLifecycleFn,
    pub init_accepted: ConnLifecycleFn,
    pub reader: ConnLifecycleFn,
    pub writer: ConnLifecycleFn,
    pub close: ConnCloseFn,
    pub parse_execute: ConnLifecycleFn,
}

#[repr(C)]
pub(super) struct TcpRpcNoncePacket {
    pub type_: c_int,
    pub key_select: c_int,
    pub crypto_schema: c_int,
    pub crypto_ts: c_int,
    pub crypto_nonce: [u8; 16],
}

#[repr(C)]
struct TcpRpcNonceDhPacket {
    pub type_: c_int,
    pub key_select: c_int,
    pub crypto_schema: c_int,
    pub crypto_ts: c_int,
    pub crypto_nonce: [u8; 16],
    pub extra_keys_count: c_int,
    pub extra_key_select: [c_int; RPC_MAX_EXTRA_KEYS],
    pub dh_params_select: c_int,
    pub g_a: [u8; 256],
}

#[repr(C)]
struct TcpRpcHandshakePacket {
    pub type_: c_int,
    pub flags: c_int,
    pub sender_pid: ProcessId,
    pub peer_pid: ProcessId,
}

#[repr(C)]
struct AesSecret {
    pub refcnt: c_int,
    pub secret_len: c_int,
    pub secret: [u8; 260],
}

#[repr(C)]
struct AesKeyData {
    pub read_key: [u8; 32],
    pub read_iv: [u8; 16],
    pub write_key: [u8; 32],
    pub write_iv: [u8; 16],
}

unsafe extern "C" {
    fn mtproxy_ffi_net_connections_precise_now() -> c_double;

    fn fail_connection(c: ConnectionJob, who: c_int);
    fn cpu_server_close_connection(c: ConnectionJob, who: c_int) -> c_int;
    fn job_incref(job: Job) -> Job;

    fn notification_event_insert_tcp_conn_ready(c: ConnectionJob);
    fn notification_event_insert_tcp_conn_close(c: ConnectionJob);
    fn notification_event_insert_tcp_conn_alarm(c: ConnectionJob);
    fn notification_event_insert_tcp_conn_wakeup(c: ConnectionJob);

    fn rwm_fetch_data(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn rwm_fetch_lookup(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_fetch_data_back(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_split_head(head: *mut RawMessage, raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn rwm_dump(raw: *mut RawMessage) -> c_int;
    fn rwm_free(raw: *mut RawMessage) -> c_int;
    fn rwm_custom_crc32(
        raw: *mut RawMessage,
        bytes: c_int,
        custom_crc32_partial: Crc32PartialFn,
    ) -> c_uint;
    fn tcp_rpc_conn_send_data(c_tag_int: c_int, c: ConnectionJob, len: c_int, q: *mut c_void);
    fn tcp_rpc_conn_send_data_im(c_tag_int: c_int, c: ConnectionJob, len: c_int, q: *mut c_void);
    fn tcp_rpc_conn_send_data_init(c: ConnectionJob, len: c_int, q: *mut c_void);

    fn init_server_PID(ip: c_uint, port: c_int);
    fn get_my_ipv4() -> c_uint;
    fn matches_pid(x: *mut ProcessId, y: *mut ProcessId) -> c_int;

    fn tcp_get_default_rpc_flags() -> c_uint;
    fn tcp_add_dh_accept() -> c_int;

    fn init_dh_params() -> c_int;
    fn dh_second_round(g_ab: *mut u8, g_a: *mut u8, g_b: *const u8) -> c_int;
    fn incr_active_dh_connections();

    fn aes_generate_nonce(res: *mut c_char) -> c_int;
    fn aes_create_keys(
        out: *mut AesKeyData,
        am_client: c_int,
        nonce_server: *const c_char,
        nonce_client: *const c_char,
        client_timestamp: c_int,
        server_ip: c_uint,
        server_port: u16,
        server_ipv6: *const u8,
        client_ip: c_uint,
        client_port: u16,
        client_ipv6: *const u8,
        key: *const AesSecret,
        temp_key: *const u8,
        temp_key_len: c_int,
    ) -> c_int;
    fn aes_crypto_init(c: ConnectionJob, key_data: *mut c_void, key_data_len: c_int) -> c_int;

    fn nat_translate_ip(local_ip: c_uint) -> c_uint;

    static mut main_secret: AesSecret;
    static mut dh_params_select: c_int;
    static mut PID: ProcessId;
    static mut verbosity: c_int;
    fn crc32_partial(data: *const c_void, len: c_long, crc: c_uint) -> c_uint;
    fn crc32c_partial(data: *const c_void, len: c_long, crc: c_uint) -> c_uint;
}

#[inline]
unsafe fn job_custom_ptr<T>(job: Job) -> *mut T {
    ptr::addr_of_mut!((*job.cast::<AsyncJob>()).j_custom).cast::<T>()
}

#[inline]
unsafe fn conn_info(c: ConnectionJob) -> *mut ConnectionInfo {
    let conn = unsafe { job_custom_ptr::<ConnectionInfo>(c) };
    assert!(!conn.is_null());
    conn
}

#[inline]
unsafe fn rpc_data(c: ConnectionJob) -> *mut TcpRpcData {
    let conn = unsafe { conn_info(c) };
    let base = unsafe { (*conn).custom_data.as_ptr() as usize };
    let align = align_of::<TcpRpcData>();
    let aligned = (base + align - 1) & !(align - 1);
    let data = aligned as *mut TcpRpcData;
    assert!(!data.is_null());
    data
}

#[inline]
unsafe fn rpc_funcs(c: ConnectionJob) -> *mut TcpRpcServerFunctions {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { (*conn).extra.cast::<TcpRpcServerFunctions>() };
    assert!(!funcs.is_null());
    funcs
}

#[inline]
unsafe fn main_secret_key_signature() -> c_int {
    let secret = ptr::addr_of!(main_secret);
    unsafe { ptr::read_unaligned((*secret).secret.as_ptr().cast::<c_int>()) }
}

#[inline]
fn precise_now_value() -> c_double {
    unsafe { mtproxy_ffi_net_connections_precise_now() }
}

#[inline]
fn unix_time_now() -> c_int {
    let unix_now = unsafe { libc::time(ptr::null_mut()) };
    c_int::try_from(unix_now).unwrap_or(c_int::MAX)
}

#[inline]
fn now_or_unix_time() -> c_int {
    unix_time_now()
}

#[inline]
unsafe fn send_data(c: ConnectionJob, data: *const u8, len: usize) {
    let len_i32 = c_int::try_from(len).unwrap_or(c_int::MAX);
    let c_ref = unsafe { job_incref(c) };
    unsafe { tcp_rpc_conn_send_data(1, c_ref, len_i32, data.cast_mut().cast()) };
}

#[inline]
unsafe fn send_data_im(c: ConnectionJob, data: *const u8, len: usize) {
    let len_i32 = c_int::try_from(len).unwrap_or(c_int::MAX);
    let c_ref = unsafe { job_incref(c) };
    unsafe { tcp_rpc_conn_send_data_im(1, c_ref, len_i32, data.cast_mut().cast()) };
}

#[inline]
unsafe fn send_data_init(c: ConnectionJob, data: *const u8, len: usize) {
    let len_i32 = c_int::try_from(len).unwrap_or(c_int::MAX);
    unsafe { tcp_rpc_conn_send_data_init(c, len_i32, data.cast_mut().cast()) };
}

#[inline]
fn write_i32_ne(buf: &mut [u8], offset: usize, value: c_int) {
    buf[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

#[inline]
fn is_http_fallback_prefix(packet_len: c_int) -> bool {
    packet_len == HTTP_HEAD_WORD
        || packet_len == HTTP_POST_WORD
        || packet_len == HTTP_GET_WORD
        || packet_len == HTTP_OPTI_WORD
}

#[inline]
fn ffi_pid_to_core(pid: ProcessId) -> CoreProcessId {
    CoreProcessId {
        ip: pid.ip,
        port: pid.port,
        pid: pid.pid,
        utime: pid.utime,
    }
}

#[inline]
fn core_pid_to_ffi(pid: CoreProcessId) -> ProcessId {
    ProcessId {
        ip: pid.ip,
        port: pid.port,
        pid: pid.pid,
        utime: pid.utime,
    }
}

pub(super) unsafe fn tcp_rpcs_default_execute_impl(
    c: ConnectionJob,
    op: c_int,
    raw: *mut RawMessage,
) -> c_int {
    let conn = unsafe { conn_info(c) };

    if core_default_execute_should_pong(op, unsafe { (*raw).total_bytes }) {
        unsafe {
            (*conn).last_response_time = precise_now_value();
        }
        let mut words = [0_i32; 3];
        assert_eq!(
            unsafe { rwm_fetch_data(raw, words.as_mut_ptr().cast(), 12) },
            12
        );
        core_default_execute_set_pong(&mut words);
        unsafe { send_data(c, words.as_ptr().cast(), 12) };
    }

    0
}

unsafe fn tcp_rpcs_process_nonce_packet_impl(c: ConnectionJob, msg: *mut RawMessage) -> c_int {
    let funcs = unsafe { rpc_funcs(c) };
    let data = unsafe { rpc_data(c) };

    let packet_num = unsafe { (*data).in_packet_num };
    let mut packet_type = 0;
    assert_eq!(
        unsafe { rwm_fetch_lookup(msg, ptr::addr_of_mut!(packet_type).cast(), 4) },
        4
    );
    let packet_len = unsafe { (*msg).total_bytes };

    let nonce_header_state = core_validate_nonce_header(
        packet_num,
        packet_type,
        packet_len,
        c_int::try_from(NONCE_PACKET_LEN).unwrap_or(c_int::MAX),
        c_int::try_from(NONCE_DH_PACKET_MAX_LEN).unwrap_or(c_int::MAX),
    );
    if nonce_header_state < 0 {
        return nonce_header_state;
    }

    let mut packet = [0_u8; NONCE_DH_PACKET_MAX_LEN];
    assert_eq!(
        unsafe { rwm_fetch_data(msg, packet.as_mut_ptr().cast(), packet_len) },
        packet_len
    );

    let packet_len_usize = match usize::try_from(packet_len) {
        Ok(v) => v,
        Err(_) => return -3,
    };
    let packet_slice = &packet[..packet_len_usize];
    let Some(parsed) = parse_nonce_packet(packet_slice) else {
        return -3;
    };

    let mut processed_schema = parsed.crypto_schema.to_i32();
    let mut processed_key_select = parsed.key_select;
    let mut processed_has_dh_params = 0;

    if process_nonce_packet_for_compat(
        packet_slice,
        (unsafe { (*data).crypto_flags } & RPCF_ALLOW_UNENC) != 0,
        (unsafe { (*data).crypto_flags } & RPCF_ALLOW_ENC) != 0,
        now_or_unix_time(),
        main_secret.secret_len,
        main_secret_key_signature(),
        &mut processed_schema,
        &mut processed_key_select,
        &mut processed_has_dh_params,
    ) < 0
    {
        return -3;
    }

    write_i32_ne(&mut packet, 8, processed_schema);
    write_i32_ne(&mut packet, 4, processed_key_select);

    let mut dh_ok = false;

    match processed_schema {
        RPC_CRYPTO_NONE => {
            if processed_key_select != 0 {
                return -3;
            }
            if unsafe { ((*data).crypto_flags & RPCF_ALLOW_UNENC) == 0 } {
                return -5;
            }
            unsafe {
                (*data).crypto_flags = RPCF_ALLOW_UNENC;
            }
        }
        RPC_CRYPTO_AES_DH => {
            if processed_has_dh_params == 0 || unsafe { dh_params_select } == 0 {
                let _ = unsafe { init_dh_params() };
            }
            if processed_has_dh_params != 0
                && parsed.dh_params_select != 0
                && parsed.dh_params_select == unsafe { dh_params_select }
            {
                dh_ok = true;
            }
            unsafe {
                (*data).crypto_flags &= !RPCF_ALLOW_UNENC;
            }
        }
        RPC_CRYPTO_AES_EXT | RPC_CRYPTO_AES => unsafe {
            (*data).crypto_flags &= !RPCF_ALLOW_UNENC;
        },
        _ => {
            if unsafe { ((*data).crypto_flags & RPCF_ALLOW_UNENC) != 0 } {
                unsafe {
                    (*data).crypto_flags = RPCF_ALLOW_UNENC;
                }
            } else {
                return -4;
            }
        }
    }

    if processed_schema != RPC_CRYPTO_NONE {
        unsafe {
            (*data).nonce_time = now_or_unix_time();
        }
    }

    if unsafe { (*data).crypto_flags & (RPCF_REQ_DH | RPCF_ALLOW_ENC) }
        == (RPCF_REQ_DH | RPCF_ALLOW_ENC)
        && !dh_ok
    {
        if unsafe { ((*data).crypto_flags & RPCF_ALLOW_SKIP_DH) != 0 } {
            unsafe {
                (*data).crypto_flags &= !(RPCF_REQ_DH | RPCF_ALLOW_SKIP_DH);
            }
        } else {
            return -7;
        }
    }

    let Some(rpc_init_crypto) = (unsafe { (*funcs).rpc_init_crypto }) else {
        return -6;
    };

    let res = unsafe { rpc_init_crypto(c, packet.as_mut_ptr().cast::<TcpRpcNoncePacket>()) };
    if res < 0 {
        return -6;
    }

    0
}

unsafe fn tcp_rpcs_send_handshake_packet_impl(c: ConnectionJob) -> c_int {
    let data = unsafe { rpc_data(c) };
    let packet = HandshakePacket::new(
        unsafe { (*data).crypto_flags } & RPCF_USE_CRC32C,
        ffi_pid_to_core(unsafe { PID }),
        ffi_pid_to_core(unsafe { (*data).remote_pid }),
    );
    let bytes = packet.to_bytes();

    unsafe { send_data_im(c, bytes.as_ptr(), bytes.len()) };
    0
}

unsafe fn tcp_rpcs_send_handshake_error_packet_impl(c: ConnectionJob, error_code: c_int) -> c_int {
    let packet = HandshakeErrorPacket::new(error_code, ffi_pid_to_core(unsafe { PID }));
    let bytes = packet.to_bytes();

    unsafe { send_data(c, bytes.as_ptr(), bytes.len()) };
    0
}

unsafe fn tcp_rpcs_process_handshake_packet_impl(c: ConnectionJob, msg: *mut RawMessage) -> c_int {
    let funcs = unsafe { rpc_funcs(c) };
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };

    if unsafe { PID.ip } == 0 {
        unsafe {
            init_server_PID((*conn).our_ip, (*conn).our_port as c_int);
            if PID.ip == 0 {
                PID.ip = get_my_ipv4();
            }
        }
    }

    let packet_num = unsafe { (*data).in_packet_num };
    let mut packet_type = 0;
    assert_eq!(
        unsafe { rwm_fetch_lookup(msg, ptr::addr_of_mut!(packet_type).cast(), 4) },
        4
    );
    let packet_len = unsafe { (*msg).total_bytes };

    let handshake_header_state = core_validate_handshake_header(
        packet_num,
        packet_type,
        packet_len,
        c_int::try_from(HANDSHAKE_PACKET_LEN).unwrap_or(c_int::MAX),
    );
    if handshake_header_state == -2 {
        return -2;
    }
    if handshake_header_state == -3 {
        let _ = unsafe { tcp_rpcs_send_handshake_error_packet_impl(c, -3) };
        return -3;
    }

    let mut packet = [0_u8; HANDSHAKE_PACKET_LEN];
    assert_eq!(
        unsafe { rwm_fetch_data(msg, packet.as_mut_ptr().cast(), packet_len) },
        packet_len
    );

    let packet_len_usize = match usize::try_from(packet_len) {
        Ok(v) => v,
        Err(_) => {
            let _ = unsafe { tcp_rpcs_send_handshake_error_packet_impl(c, -3) };
            return -3;
        }
    };
    let Some(parsed) = parse_handshake_packet(&packet[..packet_len_usize]) else {
        let _ = unsafe { tcp_rpcs_send_handshake_error_packet_impl(c, -3) };
        return -3;
    };

    unsafe {
        (*data).remote_pid = core_pid_to_ffi(parsed.sender_pid);
    }

    let enable_crc32c;
    let mut local_pid = unsafe { PID };
    let mut expected_peer_pid = core_pid_to_ffi(parsed.peer_pid);
    let peer_pid_matches = unsafe {
        matches_pid(
            ptr::addr_of_mut!(local_pid),
            ptr::addr_of_mut!(expected_peer_pid),
        )
    };

    let packet_flags = parsed.flags;
    match core_validate_handshake(
        packet_flags,
        peer_pid_matches != 0,
        (unsafe { (*funcs).mode_flags } & TCP_RPC_IGNORE_PID) != 0,
        unsafe { tcp_get_default_rpc_flags() as c_int },
    ) {
        Ok(value) => {
            enable_crc32c = i32::from(value);
        }
        Err(code) => {
            let _ = unsafe { tcp_rpcs_send_handshake_error_packet_impl(c, code) };
            return code;
        }
    }

    if enable_crc32c != 0 {
        unsafe {
            (*data).crypto_flags |= RPCF_USE_CRC32C;
        }
    }

    0
}

pub(super) unsafe fn tcp_rpcs_parse_execute_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { rpc_funcs(c) };
    let data = unsafe { rpc_data(c) };

    loop {
        if (unsafe { (*conn).flags } & C_ERROR) != 0 {
            return NEED_MORE_BYTES;
        }
        if (unsafe { (*conn).flags } & C_STOPPARSE) != 0 {
            return NEED_MORE_BYTES;
        }

        let len = unsafe { (*conn).in_data.total_bytes };
        if len <= 0 {
            return NEED_MORE_BYTES;
        }
        if len < 4 {
            return 4 - len;
        }

        let mut packet_len = 0;
        assert_eq!(
            unsafe {
                rwm_fetch_lookup(
                    ptr::addr_of_mut!((*conn).in_data),
                    ptr::addr_of_mut!(packet_len).cast(),
                    4,
                )
            },
            4
        );

        if (unsafe { (*data).crypto_flags } & RPCF_QUICKACK) != 0 {
            unsafe {
                (*data).flags = ((*data).flags & !RPC_F_QUICKACK) | (packet_len & RPC_F_QUICKACK);
            }
            packet_len &= !RPC_F_QUICKACK;
        }

        if core_packet_header_malformed(packet_len) != 0 {
            if unsafe { (*data).in_packet_num } <= -2
                && is_http_fallback_prefix(packet_len)
                && !unsafe { (*funcs).http_fallback_type.is_null() }
            {
                unsafe {
                    ptr::write_bytes(
                        (*conn).custom_data.as_mut_ptr().cast::<u8>(),
                        0,
                        CONN_CUSTOM_DATA_BYTES,
                    );
                    (*conn).type_ = (*funcs).http_fallback_type;
                    (*conn).extra = (*funcs).http_fallback_extra;
                }

                let ctype = unsafe { (*conn).type_.cast::<ConnFunctions>() };
                let Some(init_accepted) = (unsafe { (*ctype).init_accepted }) else {
                    unsafe { fail_connection(c, -33) };
                    return 0;
                };

                if unsafe { init_accepted(c) } < 0 {
                    unsafe { fail_connection(c, -33) };
                    return 0;
                }

                let Some(parse_execute) = (unsafe { (*ctype).parse_execute }) else {
                    unsafe { fail_connection(c, -33) };
                    return 0;
                };

                return unsafe { parse_execute(c) };
            }

            unsafe { fail_connection(c, -1) };
            return 0;
        }

        let packet_len_state =
            core_packet_len_state(packet_len, unsafe { (*funcs).max_packet_len });

        if packet_len_state == -1 {
            unsafe { fail_connection(c, -1) };
            return 0;
        }

        if packet_len_state == 0 {
            assert_eq!(
                unsafe { rwm_skip_data(ptr::addr_of_mut!((*conn).in_data), 4) },
                4
            );
            continue;
        }

        if len < packet_len {
            return packet_len - len;
        }

        let mut msg = RawMessage::default();
        let _ = unsafe {
            rwm_split_head(
                ptr::addr_of_mut!(msg),
                ptr::addr_of_mut!((*conn).in_data),
                packet_len,
            )
        };

        let mut crc32: c_uint = 0;
        assert_eq!(
            unsafe {
                rwm_fetch_data_back(ptr::addr_of_mut!(msg), ptr::addr_of_mut!(crc32).cast(), 4)
            },
            4
        );

        let packet_crc32 = unsafe {
            rwm_custom_crc32(
                ptr::addr_of_mut!(msg),
                packet_len - 4,
                (*data).custom_crc_partial,
            )
        };

        if crc32 != packet_crc32 {
            let _ = unsafe { rwm_dump(ptr::addr_of_mut!(msg)) };
            unsafe {
                fail_connection(c, -1);
                let _ = rwm_free(ptr::addr_of_mut!(msg));
            }
            return 0;
        }

        let mut packet_num = 0;
        let mut packet_type = 0;
        assert_eq!(unsafe { rwm_skip_data(ptr::addr_of_mut!(msg), 4) }, 4);
        assert_eq!(
            unsafe {
                rwm_fetch_data(
                    ptr::addr_of_mut!(msg),
                    ptr::addr_of_mut!(packet_num).cast(),
                    4,
                )
            },
            4
        );
        assert_eq!(
            unsafe {
                rwm_fetch_lookup(
                    ptr::addr_of_mut!(msg),
                    ptr::addr_of_mut!(packet_type).cast(),
                    4,
                )
            },
            4
        );

        if unsafe { verbosity > 2 } {
            let _ = unsafe { rwm_dump(ptr::addr_of_mut!(msg)) };
        }

        let mut res = -1;

        if unsafe { (*data).in_packet_num } == -3 {
            unsafe {
                (*data).in_packet_num = 0;
            }
        }

        if (unsafe { (*data).crypto_flags } & RPCF_SEQNO_HOLES) == 0
            && packet_num != unsafe { (*data).in_packet_num }
        {
            unsafe {
                fail_connection(c, -1);
                let _ = rwm_free(ptr::addr_of_mut!(msg));
            }
            return 0;
        } else if packet_num < 0 {
            if packet_num == -2 {
                res = unsafe { tcp_rpcs_process_nonce_packet_impl(c, ptr::addr_of_mut!(msg)) };
            } else if packet_num == -1 {
                res = unsafe { tcp_rpcs_process_handshake_packet_impl(c, ptr::addr_of_mut!(msg)) };
                if res >= 0 {
                    res = unsafe { tcp_rpcs_send_handshake_packet_impl(c) };
                    if (unsafe { (*data).crypto_flags } & RPCF_USE_CRC32C) != 0 {
                        unsafe {
                            (*data).custom_crc_partial = Some(crc32c_partial);
                        }
                    }
                    unsafe { notification_event_insert_tcp_conn_ready(c) };
                }
            }

            let _ = unsafe { rwm_free(ptr::addr_of_mut!(msg)) };
            if res < 0 {
                unsafe { fail_connection(c, res) };
                return 0;
            }
        } else {
            unsafe {
                (*conn).last_response_time = precise_now_value();
            }

            if packet_type == RPC_PING {
                res = unsafe {
                    tcp_rpcs_default_execute_impl(c, packet_type, ptr::addr_of_mut!(msg))
                };
            } else if let Some(execute) = unsafe { (*funcs).execute } {
                res = unsafe { execute(c, packet_type, ptr::addr_of_mut!(msg)) };
            }

            if res <= 0 {
                let _ = unsafe { rwm_free(ptr::addr_of_mut!(msg)) };
            }
        }

        unsafe {
            (*data).in_packet_num += 1;
        }
    }
}

pub(super) unsafe fn tcp_rpcs_wakeup_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };

    unsafe { notification_event_insert_tcp_conn_wakeup(c) };

    if core_should_set_wantwr(unsafe { (*conn).out_p.total_bytes }) {
        unsafe { (&*((&raw mut (*conn).flags).cast::<AtomicI32>())).fetch_or(C_WANTWR, Ordering::SeqCst) };
    }

    unsafe {
        (*conn).pending_queries = core_notification_pending_queries();
    }

    0
}

pub(super) unsafe fn tcp_rpcs_alarm_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };

    unsafe { notification_event_insert_tcp_conn_alarm(c) };

    if core_should_set_wantwr(unsafe { (*conn).out_p.total_bytes }) {
        unsafe { (&*((&raw mut (*conn).flags).cast::<AtomicI32>())).fetch_or(C_WANTWR, Ordering::SeqCst) };
    }

    unsafe {
        (*conn).pending_queries = core_notification_pending_queries();
    }

    0
}

pub(super) unsafe fn tcp_rpcs_close_connection_impl(c: ConnectionJob, who: c_int) -> c_int {
    let funcs = unsafe { rpc_funcs(c) };

    if core_should_notify_close(unsafe { (*funcs).rpc_close.is_some() }) {
        unsafe { notification_event_insert_tcp_conn_close(c) };
    }

    unsafe { cpu_server_close_connection(c, who) }
}

pub(super) unsafe fn tcp_rpcs_do_wakeup_impl(_c: ConnectionJob) -> c_int {
    core_do_wakeup()
}

pub(super) unsafe fn tcp_rpcs_init_accepted_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { rpc_funcs(c) };
    let data = unsafe { rpc_data(c) };

    let has_perm_callback = i32::from(unsafe { (*funcs).rpc_check_perm.is_some() });
    let mut perm_flags = 0;

    unsafe {
        (*conn).last_query_sent_time = precise_now_value();
        (*data).custom_crc_partial = Some(crc32_partial);
    }

    if let Some(rpc_check_perm) = unsafe { (*funcs).rpc_check_perm } {
        perm_flags = unsafe { rpc_check_perm(c) };
        if perm_flags < 0 {
            return perm_flags;
        }
    }

    match core_init_accepted_state(has_perm_callback != 0, perm_flags) {
        Ok((crypto_flags, in_packet_num, out_packet_num)) => unsafe {
            (*data).crypto_flags = crypto_flags;
            (*data).in_packet_num = in_packet_num;
            (*data).out_packet_num = out_packet_num;
        },
        Err(code) => return code,
    }

    0
}

pub(super) unsafe fn tcp_rpcs_init_accepted_nohs_impl(c: ConnectionJob) -> c_int {
    let funcs = unsafe { rpc_funcs(c) };
    let data = unsafe { rpc_data(c) };

    let (crypto_flags, in_packet_num) = core_init_accepted_nohs_state();
    unsafe {
        (*data).crypto_flags = crypto_flags;
        (*data).in_packet_num = in_packet_num;
    }

    unsafe {
        (*data).custom_crc_partial = Some(crc32_partial);
    }

    if unsafe { (*funcs).rpc_ready.is_some() } {
        unsafe { notification_event_insert_tcp_conn_ready(c) };
    }

    0
}

unsafe fn tcp_rpcs_init_fake_crypto_impl(c: ConnectionJob) -> c_int {
    let data = unsafe { rpc_data(c) };

    let current_flags = unsafe { (*data).crypto_flags };
    let updated_flags = match core_init_fake_crypto_state(current_flags) {
        Ok(value) => value,
        Err(code) => return code,
    };

    let packet = TcpRpcNoncePacket {
        type_: RPC_NONCE,
        key_select: 0,
        crypto_schema: RPC_CRYPTO_NONE,
        crypto_ts: 0,
        crypto_nonce: [0_u8; 16],
    };

    unsafe {
        (*data).crypto_flags = updated_flags;
    }

    unsafe { send_data_init(c, ptr::addr_of!(packet).cast::<u8>(), NONCE_PACKET_LEN) };

    1
}

pub(super) unsafe fn tcp_rpcs_default_check_perm_impl(_c: ConnectionJob) -> c_int {
    core_default_check_perm(unsafe { tcp_get_default_rpc_flags() as c_int })
}

pub(super) unsafe fn tcp_rpcs_init_crypto_impl(
    c: ConnectionJob,
    packet: *mut TcpRpcNoncePacket,
) -> c_int {
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };

    if packet.is_null() {
        return -1;
    }

    if unsafe { !(*conn).crypto.is_null() } {
        return -1;
    }

    if unsafe { (*data).crypto_flags & (RPCF_ALLOW_ENC | RPCF_ALLOW_UNENC) } == RPCF_ALLOW_UNENC {
        return unsafe { tcp_rpcs_init_fake_crypto_impl(c) };
    }

    if unsafe { (*data).crypto_flags & (RPCF_ALLOW_ENC | RPCF_ALLOW_UNENC) } != RPCF_ALLOW_ENC {
        return -1;
    }

    if unsafe { main_secret_key_signature() } != unsafe { (*packet).key_select } {
        return -1;
    }

    let mut temp_dh = [0_u8; 256];
    let mut temp_dh_len = 0;
    let mut out_dh_public = [0_u8; 256];
    let mut use_dh = false;

    if (unsafe { (*data).crypto_flags } & RPCF_REQ_DH) != 0 {
        if unsafe { (*packet).crypto_schema } != RPC_CRYPTO_AES_DH {
            return -1;
        }

        let packet_dh = packet.cast::<TcpRpcNonceDhPacket>();
        let extra_keys_count = unsafe { (*packet_dh).extra_keys_count };

        let dh_shift = 4 * (extra_keys_count - c_int::try_from(RPC_MAX_EXTRA_KEYS).unwrap_or(8));
        let old_dh = unsafe {
            packet
                .cast::<u8>()
                .offset(dh_shift as isize)
                .cast::<TcpRpcNonceDhPacket>()
        };

        if unsafe { (*old_dh).dh_params_select != dh_params_select || dh_params_select == 0 } {
            return -1;
        }

        if unsafe { tcp_add_dh_accept() } < 0 {
            return -1;
        }

        temp_dh_len = unsafe {
            dh_second_round(
                temp_dh.as_mut_ptr(),
                out_dh_public.as_mut_ptr(),
                (*old_dh).g_a.as_ptr(),
            )
        };
        assert_eq!(temp_dh_len, 256);

        unsafe {
            incr_active_dh_connections();
            (&*((&raw mut (*conn).flags).cast::<AtomicI32>())).fetch_or(C_ISDH, Ordering::SeqCst);
        }

        use_dh = true;
    }

    unsafe {
        let _ = aes_generate_nonce((*data).nonce.as_mut_ptr().cast::<c_char>());
    }

    let mut aes_keys = MaybeUninit::<AesKeyData>::uninit();

    if unsafe {
        aes_create_keys(
            aes_keys.as_mut_ptr(),
            0,
            (*data).nonce.as_ptr().cast::<c_char>(),
            (*packet).crypto_nonce.as_ptr().cast::<c_char>(),
            (*packet).crypto_ts,
            nat_translate_ip((*conn).our_ip),
            (*conn).our_port as u16,
            (*conn).our_ipv6.as_ptr(),
            nat_translate_ip((*conn).remote_ip),
            (*conn).remote_port as u16,
            (*conn).remote_ipv6.as_ptr(),
            ptr::addr_of!(main_secret),
            if temp_dh_len > 0 {
                temp_dh.as_ptr()
            } else {
                ptr::null()
            },
            temp_dh_len,
        )
    } < 0
    {
        return -1;
    }

    let mut aes_keys = unsafe { aes_keys.assume_init() };
    if unsafe {
        aes_crypto_init(
            c,
            ptr::addr_of_mut!(aes_keys).cast(),
            c_int::try_from(size_of::<AesKeyData>()).unwrap_or(c_int::MAX),
        )
    } < 0
    {
        return -1;
    }

    assert_eq!(
        unsafe { (*data).crypto_flags & (RPCF_ALLOW_ENC | RPCF_ENC_SENT) },
        RPCF_ALLOW_ENC
    );
    unsafe {
        (*data).crypto_flags |= RPCF_ENC_SENT;
    }

    if !use_dh {
        let out_packet = TcpRpcNoncePacket {
            type_: RPC_NONCE,
            key_select: unsafe { main_secret_key_signature() },
            crypto_schema: RPC_CRYPTO_AES,
            crypto_ts: unsafe { (*data).nonce_time },
            crypto_nonce: unsafe { (*data).nonce },
        };

        unsafe { send_data_init(c, ptr::addr_of!(out_packet).cast::<u8>(), NONCE_PACKET_LEN) };
        return 1;
    }

    let mut out_packet = [0_u8; NONCE_DH_PACKET_MIN_LEN];
    write_i32_ne(&mut out_packet, 0, RPC_NONCE);
    write_i32_ne(&mut out_packet, 4, unsafe { main_secret_key_signature() });
    write_i32_ne(&mut out_packet, 8, RPC_CRYPTO_AES_DH);
    write_i32_ne(&mut out_packet, 12, unsafe { (*data).nonce_time });
    out_packet[16..32].copy_from_slice(unsafe { &(*data).nonce });
    write_i32_ne(&mut out_packet, 32, 0);
    write_i32_ne(&mut out_packet, 36, unsafe { dh_params_select });
    out_packet[40..40 + 256].copy_from_slice(&out_dh_public);

    unsafe { send_data_init(c, out_packet.as_ptr(), out_packet.len()) };

    1
}
