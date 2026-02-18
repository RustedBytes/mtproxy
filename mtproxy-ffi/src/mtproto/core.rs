pub(super) use crate::ffi_util::{
    mut_ref_from_ptr, mut_slice_from_ptr, ref_from_ptr, slice_from_ptr,
};
use crate::*;
use std::ffi::c_longlong;
use std::ffi::CString;

pub(super) fn mtproto_proxy_collect_argv(
    argc: i32,
    argv: *const *const c_char,
) -> Option<Vec<String>> {
    if argc < 0 {
        return None;
    }
    if argc == 0 {
        return Some(vec!["mtproto-proxy".to_owned()]);
    }
    if argv.is_null() {
        return None;
    }

    let count = usize::try_from(argc).ok()?;
    let raw = unsafe { slice_from_ptr(argv, count) }?;
    let mut out = Vec::with_capacity(count.max(1));
    for &arg_ptr in raw {
        out.push(cstr_to_owned(arg_ptr)?);
    }
    if out.is_empty() {
        out.push("mtproto-proxy".to_owned());
    }
    Some(out)
}

pub(super) fn cstr_to_owned(ptr: *const c_char) -> Option<String> {
    let ptr_ref = unsafe { ref_from_ptr(ptr) }?;
    let owned = unsafe { CStr::from_ptr(ptr_ref) }
        .to_string_lossy()
        .into_owned();
    Some(owned)
}

pub(super) fn cfg_bytes_from_cstr(cur: *const c_char, len: usize) -> Option<&'static [u8]> {
    unsafe { slice_from_ptr(cur.cast::<u8>(), len) }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(super) fn copy_mtproto_parse_error_message(
    out: &mut MtproxyMtprotoParseFunctionResult,
    message: &str,
) {
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

pub(super) fn saturating_i32_from_usize(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

pub(super) const AF_INET: c_int = 2;
pub(super) const AF_INET6: c_int = 10;
const RPC_F_PAD: c_int = 0x0800_0000;
const RPC_F_DROPPED: c_int = 0x1000_0000_u32 as c_int;
const RPC_F_COMPACT_MEDIUM: c_int = 0x6000_0000_u32 as c_int;
const RPC_F_QUICKACK: c_int = 0x8000_0000_u32 as c_int;
const RPC_F_EXTMODE3: c_int = 0x30000;
const RPC_F_COMPACT: c_int = 0x4000_0000_u32 as c_int;
const HTQT_GET: c_int = 2;
const HTQT_OPTIONS: c_int = 4;
const QF_KEEPALIVE: c_int = 0x100;
const QF_EXTRA_HEADERS: c_int = 0x200;
const HTQT_POST: c_int = 3;
const NO_ARGUMENT: c_int = 0;
const REQUIRED_ARGUMENT: c_int = 1;
const JS_RUN: c_int = 0;
const JS_ALARM: c_int = 4;
const JS_ABORT: c_int = 5;
const JS_FINISH: c_int = 7;
const JOB_COMPLETED: c_int = 0x100;
const JOB_ERROR: c_int = -1;
const JF_COMPLETED: c_int = 0x40000;
const SKIP_ALL_BYTES: c_int = c_int::MIN;
const JC_CONNECTION: c_int = 4;
const JC_ENGINE: c_int = 8;
const JSP_PARENT_RWE: u64 = 7;
const JT_HAVE_TIMER: u64 = 1;
const OPT_C: c_int = b'C' as c_int;
const OPT_W: c_int = b'W' as c_int;
const OPT_H: c_int = b'H' as c_int;
const OPT_M: c_int = b'M' as c_int;
const OPT_T: c_int = b'T' as c_int;
const OPT_D: c_int = b'D' as c_int;
const OPT_S: c_int = b'S' as c_int;
const OPT_P: c_int = b'P' as c_int;
const AM_GET_MEMORY_USAGE_SELF: c_int = 1;
const MAX_HTTP_HEADER_SIZE: c_int = 16384;
const MAX_POST_SIZE: c_int = 262_144 * 4 - 4096;
const STATS_BUFF_SIZE: usize = 1 << 20;
const MAX_CONNECTION_BUFFER_SPACE: c_int = 1 << 25;
const MAX_HTTP_LISTEN_PORTS: usize = 128;
const MAX_CONNECTIONS: usize = 65536;
const MAX_WORKERS: usize = 256;
const MAX_EVENTS: usize = 1 << 19;
const ENGINE_NO_PORT: u64 = 4;
const OUR_SIGRTMAX: c_int = 64;
const ENGINE_ENABLE_IPV6: u64 = 0x4;
const ENGINE_ENABLE_SLAVE_MODE: u64 = 0x20_00000;
const DEFAULT_PING_INTERVAL: c_double = 5.0;
const DEFAULT_CFG_MIN_CONNECTIONS: c_int = 4;
const DEFAULT_CFG_MAX_CONNECTIONS: c_int = 8;
const DEFAULT_WINDOW_CLAMP: c_int = 131_072;
const SM_IPV6: c_int = 2;
const SM_LOWPRIO: c_int = 8;
const SM_SPECIAL: c_int = 0x1_0000;
const SM_NOQACK: c_int = 0x2_0000;
const FORWARD_FLAG_PROXY_TAG: c_int = 8;
const FORWARD_HTTP_TIMEOUT_SECONDS: c_double = 960.0;
const PROXY_MODE_OUT: c_int = 2;
const TCP_RPC_IGNORE_PID: c_int = 4;
const C_EXTERNAL: c_int = 0x8000;
const CONN_CUSTOM_DATA_BYTES: usize = 256;
const MSG_BUFFERS_CHUNK_SIZE: i64 = (1 << 21) - 64;
const ENCRYPTED_MESSAGE_MIN_LEN: c_int = 56; // offsetof(struct encrypted_message, message)
const PROCESS_HTTP_URI_MAX_LEN: usize = 20;
const PROCESS_HTTP_OPTIONS_CORS_HEADERS: &str = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: origin, content-type\r\nAccess-Control-Max-Age: 1728000\r\n";
const CONN_STATUS_WORKING: c_int = 2;
const SHORT_VERSION_STR: &[u8] = b"mtproxy\0";
const FULL_VERSION_STR: &[u8] = b"mtproxy-rust-ffi\0";
const MTPROXY_CORS_HTTP_HEADERS: &[u8] = b"Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: origin, content-type\r\nAccess-Control-Max-Age: 1728000\r\n\0";
const TL_ERROR_NOT_ENOUGH_DATA: c_int =
    mtproxy_core::runtime::config::tl_parse::TL_ERROR_NOT_ENOUGH_DATA;
const TL_ERROR_INTERNAL: c_int = mtproxy_core::runtime::config::tl_parse::TL_ERROR_INTERNAL;

type ConnectionJob = *mut c_void;
type ConnTargetJob = *mut c_void;

type MtprotoJobExecuteFn = Option<unsafe extern "C" fn(ConnectionJob, c_int, *mut c_void) -> c_int>;
type MtprotoJobCallbackFn = Option<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>;

#[repr(C, align(64))]
struct MtprotoAsyncJobPrefix {
    j_flags: c_int,
    j_status: c_int,
    j_sigclass: c_int,
    j_refcnt: c_int,
    j_error: c_int,
    j_children: c_int,
    j_align: c_int,
    j_custom_bytes: c_int,
    j_type: u32,
    j_subclass: c_int,
    j_thread: *mut c_void,
    j_execute: MtprotoJobExecuteFn,
    j_parent: ConnectionJob,
    j_custom: [i64; 0],
}

#[repr(C)]
struct MtprotoEventTimer {
    h_idx: c_int,
    flags: c_int,
    wakeup: Option<unsafe extern "C" fn(*mut MtprotoEventTimer) -> c_int>,
    wakeup_time: c_double,
    real_wakeup_time: c_double,
}

#[repr(C)]
struct MtprotoConnInfoPrefix {
    timer: MtprotoEventTimer,
    fd: c_int,
    generation: c_int,
    flags: c_int,
    type_: *mut c_void,
    extra: *mut c_void,
    target: ConnTargetJob,
    io_conn: ConnectionJob,
    basic_type: c_int,
    status: c_int,
    error: c_int,
    unread_res_bytes: c_int,
    skip_bytes: c_int,
    pending_queries: c_int,
    queries_ok: c_int,
    custom_data: [c_char; CONN_CUSTOM_DATA_BYTES],
    our_ip: u32,
    remote_ip: u32,
    our_port: u32,
    remote_port: u32,
    our_ipv6: [u8; 16],
    remote_ipv6: [u8; 16],
    query_start_time: c_double,
    last_query_time: c_double,
    last_query_sent_time: c_double,
    last_response_time: c_double,
    last_query_timeout: c_double,
    limit_per_write: c_int,
    limit_per_sec: c_int,
    last_write_time: c_int,
    written_per_sec: c_int,
    unreliability: c_int,
    ready: c_int,
    write_low_watermark: c_int,
    crypto: *mut c_void,
    crypto_temp: *mut c_void,
    listening: c_int,
    listening_generation: c_int,
    window_clamp: c_int,
    left_tls_packet_length: c_int,
    in_u: MtprotoRawMessage,
    in_: MtprotoRawMessage,
    out: MtprotoRawMessage,
    out_p: MtprotoRawMessage,
    in_queue: *mut c_void,
    out_queue: *mut c_void,
}

#[repr(C)]
struct MtprotoTcpRpcDataPrefix {
    flags: c_int,
    in_packet_num: c_int,
    out_packet_num: c_int,
    crypto_flags: c_int,
    remote_pid: MtproxyProcessId,
    nonce: [u8; 16],
    nonce_time: c_int,
    in_rpc_target: c_int,
    user_data: *mut c_void,
    extra_int: c_int,
    extra_int2: c_int,
    extra_int3: c_int,
    extra_int4: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MtprotoRawMessage {
    first: *mut c_void,
    last: *mut c_void,
    total_bytes: c_int,
    magic: c_int,
    first_offset: c_int,
    last_offset: c_int,
}

#[repr(C)]
struct MtprotoHttpQueryInfo {
    ev: MtprotoEventTimer,
    conn: ConnectionJob,
    msg: MtprotoRawMessage,
    conn_fd: c_int,
    conn_generation: c_int,
    flags: c_int,
    query_type: c_int,
    header_size: c_int,
    data_size: c_int,
    first_line_size: c_int,
    host_offset: c_int,
    host_size: c_int,
    uri_offset: c_int,
    uri_size: c_int,
    header: [c_char; 0],
}

#[repr(C)]
struct MtprotoListeningConnInfoPrefix {
    timer: MtprotoEventTimer,
    fd: c_int,
    generation: c_int,
    flags: c_int,
    current_epoll_status: c_int,
    type_: *mut c_void,
    ev: *mut c_void,
    extra: *mut c_void,
    window_clamp: c_int,
}

#[repr(C)]
struct MtprotoEventDescr {
    fd: c_int,
    state: c_int,
    ready: c_int,
    epoll_state: c_int,
    epoll_ready: c_int,
    timeout: c_int,
    priority: c_int,
    in_queue: c_int,
    timestamp: i64,
    refcnt: i64,
    work: *mut c_void,
    data: *mut c_void,
}

#[repr(C)]
struct MtprotoJobThreadPrefix {
    _pthread_id: usize,
    _id: c_int,
    _thread_class: c_int,
    job_class_mask: c_int,
}

#[repr(C)]
struct MtprotoClientPacketInfo {
    ev: MtprotoEventTimer,
    msg: MtprotoRawMessage,
    conn: ConnectionJob,
}

#[repr(C)]
struct MtprotoJobCallbackInfo {
    func: MtprotoJobCallbackFn,
    data: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MtprotoRpcsExecData {
    msg: MtprotoRawMessage,
    conn: ConnectionJob,
    op: c_int,
    rpc_flags: c_int,
}

#[repr(C)]
struct MtprotoHtsData {
    query_type: c_int,
    query_flags: c_int,
    query_words: c_int,
    header_size: c_int,
    first_line_size: c_int,
    data_size: c_int,
    host_offset: c_int,
    host_size: c_int,
    uri_offset: c_int,
    uri_size: c_int,
    http_ver: c_int,
    wlen: c_int,
    word: [u8; 16],
    extra: *mut c_void,
    extra_int: c_int,
    extra_int2: c_int,
    extra_int3: c_int,
    extra_int4: c_int,
    extra_double: c_double,
    extra_double2: c_double,
    parse_state: c_int,
    query_seqno: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct MtprotoConnType {
    magic: c_int,
    flags: c_int,
    title: *mut c_char,
    accept: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    init_accepted: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    reader: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    writer: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    close: Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>,
    parse_execute: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    init_outbound: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    connected: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    check_ready: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    wakeup_aio: Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>,
    write_packet: Option<unsafe extern "C" fn(ConnectionJob, *mut MtprotoRawMessage) -> c_int>,
    flush: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    free: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    free_buffers: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    read_write: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    wakeup: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    alarm: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    socket_read_write: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    socket_reader: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    socket_writer: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    socket_connected: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    socket_free: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    socket_close: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    data_received: Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>,
    data_sent: Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>,
    ready_to_write: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    crypto_init: Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, c_int) -> c_int>,
    crypto_free: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    crypto_encrypt_output: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    crypto_decrypt_input: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    crypto_needed_output_bytes: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct MtprotoTcpRpcClientFunctions {
    info: *mut c_void,
    rpc_extra: *mut c_void,
    execute: *mut c_void,
    check_ready: *mut c_void,
    flush_packet: *mut c_void,
    rpc_check_perm: *mut c_void,
    rpc_init_crypto: *mut c_void,
    rpc_start_crypto: *mut c_void,
    rpc_wakeup: *mut c_void,
    rpc_alarm: *mut c_void,
    rpc_ready: *mut c_void,
    rpc_close: *mut c_void,
    max_packet_len: c_int,
    mode_flags: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct MtprotoHttpServerFunctions {
    info: *mut c_void,
    execute: Option<unsafe extern "C" fn(ConnectionJob, *mut MtprotoRawMessage, c_int) -> c_int>,
    ht_wakeup: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    ht_alarm: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    ht_close: Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct MtprotoTcpRpcServerFunctions {
    info: *mut c_void,
    rpc_extra: *mut c_void,
    execute: Option<unsafe extern "C" fn(ConnectionJob, c_int, *mut MtprotoRawMessage) -> c_int>,
    check_ready: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    flush_packet: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    rpc_check_perm: *mut c_void,
    rpc_init_crypto: *mut c_void,
    nop: *mut c_void,
    rpc_wakeup: *mut c_void,
    rpc_alarm: *mut c_void,
    rpc_ready: Option<unsafe extern "C" fn(ConnectionJob) -> c_int>,
    rpc_close: Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>,
    max_packet_len: c_int,
    mode_flags: c_int,
    memcache_fallback_type: *mut c_void,
    memcache_fallback_extra: *mut c_void,
    http_fallback_type: *mut c_void,
    http_fallback_extra: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MtprotoBuffersStat {
    total_used_buffers_size: i64,
    allocated_buffer_bytes: i64,
    buffer_chunk_alloc_ops: i64,
    total_used_buffers: c_int,
    allocated_buffer_chunks: c_int,
    max_allocated_buffer_chunks: c_int,
    max_buffer_chunks: c_int,
    max_allocated_buffer_bytes: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MtprotoConnectionsStat {
    active_connections: c_int,
    active_dh_connections: c_int,
    outbound_connections: c_int,
    active_outbound_connections: c_int,
    ready_outbound_connections: c_int,
    active_special_connections: c_int,
    max_special_connections: c_int,
    allocated_connections: c_int,
    allocated_outbound_connections: c_int,
    allocated_inbound_connections: c_int,
    allocated_socket_connections: c_int,
    allocated_targets: c_int,
    ready_targets: c_int,
    active_targets: c_int,
    inactive_targets: c_int,
    tcp_readv_calls: i64,
    tcp_readv_intr: i64,
    tcp_readv_bytes: i64,
    tcp_writev_calls: i64,
    tcp_writev_intr: i64,
    tcp_writev_bytes: i64,
    accept_calls_failed: i64,
    accept_nonblock_set_failed: i64,
    accept_rate_limit_failed: i64,
    accept_init_accepted_failed: i64,
    accept_connection_limit_failed: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct MtprotoWorkerStats {
    cnt: c_int,
    updated_at: c_int,
    bufs: MtprotoBuffersStat,
    conn: MtprotoConnectionsStat,
    allocated_aes_crypto: c_int,
    allocated_aes_crypto_temp: c_int,
    tot_dh_rounds: [i64; 3],
    ev_heap_size: c_int,
    http_connections: c_int,
    get_queries: i64,
    pending_http_queries: c_int,
    accept_calls_failed: i64,
    accept_nonblock_set_failed: i64,
    accept_connection_limit_failed: i64,
    accept_rate_limit_failed: i64,
    accept_init_accepted_failed: i64,
    active_rpcs: i64,
    active_rpcs_created: i64,
    rpc_dropped_running: i64,
    rpc_dropped_answers: i64,
    tot_forwarded_queries: i64,
    expired_forwarded_queries: i64,
    tot_forwarded_responses: i64,
    dropped_queries: i64,
    dropped_responses: i64,
    tot_forwarded_simple_acks: i64,
    dropped_simple_acks: i64,
    mtproto_proxy_errors: i64,
    connections_failed_lru: i64,
    connections_failed_flood: i64,
    ext_connections: i64,
    ext_connections_created: i64,
    http_queries: i64,
    http_bad_headers: i64,
}

#[repr(C)]
struct MtprotoStatsBuffer {
    buff: *mut c_char,
    pos: c_int,
    size: c_int,
    flags: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MtprotoServerFunctions {
    cron: Option<unsafe extern "C" fn()>,
    precise_cron: Option<unsafe extern "C" fn()>,
    on_exit: Option<unsafe extern "C" fn()>,
    on_waiting_exit: Option<unsafe extern "C" fn() -> c_int>,
    on_safe_quit: Option<unsafe extern "C" fn()>,
    close_net_sockets: Option<unsafe extern "C" fn()>,
    flags: u64,
    allowed_signals: u64,
    forbidden_signals: u64,
    default_modules: u64,
    default_modules_disabled: u64,
    prepare_stats: Option<unsafe extern "C" fn(*mut MtprotoStatsBuffer)>,
    prepare_parse_options: Option<unsafe extern "C" fn()>,
    parse_option: Option<unsafe extern "C" fn(c_int) -> c_int>,
    parse_extra_args: Option<unsafe extern "C" fn(c_int, *mut *mut c_char)>,
    pre_init: Option<unsafe extern "C" fn()>,
    pre_start: Option<unsafe extern "C" fn()>,
    pre_loop: Option<unsafe extern "C" fn()>,
    run_script: Option<unsafe extern "C" fn() -> c_int>,
    full_version_str: *const c_char,
    short_version_str: *const c_char,
    epoll_timeout: c_int,
    aio_timeout: c_double,
    parse_function: Option<unsafe extern "C" fn(*mut c_void, i64) -> *mut c_void>,
    get_op: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    signal_handlers: [Option<unsafe extern "C" fn()>; 65],
    custom_ops: *mut c_void,
    tcp_methods: *mut c_void,
    http_type: *mut MtprotoConnType,
    http_functions: *mut c_void,
    cron_subclass: c_int,
    precise_cron_subclass: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MtprotoEngineStatePrefix {
    settings_addr: MtproxyInAddr,
    do_not_open_port: c_int,
    epoll_wait_timeout: c_int,
    sfd: c_int,
    modules: u64,
    port: c_int,
    start_port: c_int,
    end_port: c_int,
    backlog: c_int,
}

const ZERO_CONN_TYPE: MtprotoConnType = unsafe { core::mem::zeroed() };
const ZERO_TCP_RPC_CLIENT_FUNCTIONS: MtprotoTcpRpcClientFunctions = unsafe { core::mem::zeroed() };
const ZERO_HTTP_SERVER_FUNCTIONS: MtprotoHttpServerFunctions = unsafe { core::mem::zeroed() };
const ZERO_TCP_RPC_SERVER_FUNCTIONS: MtprotoTcpRpcServerFunctions = unsafe { core::mem::zeroed() };
const ZERO_WORKER_STATS: MtprotoWorkerStats = unsafe { core::mem::zeroed() };
const ZERO_SERVER_FUNCTIONS: MtprotoServerFunctions = unsafe { core::mem::zeroed() };

#[no_mangle]
pub static mut FullVersionStr: *const c_char = FULL_VERSION_STR.as_ptr().cast::<c_char>();

#[no_mangle]
pub static mut ping_interval: c_double = DEFAULT_PING_INTERVAL;
#[no_mangle]
pub static mut window_clamp: c_int = 0;
#[no_mangle]
pub static mut proxy_mode: c_int = 0;
#[no_mangle]
pub static mut ct_http_server_mtfront: MtprotoConnType = MtprotoConnType { ..ZERO_CONN_TYPE };
#[no_mangle]
pub static mut ct_tcp_rpc_ext_server_mtfront: MtprotoConnType =
    MtprotoConnType { ..ZERO_CONN_TYPE };
#[no_mangle]
pub static mut ct_tcp_rpc_server_mtfront: MtprotoConnType = MtprotoConnType { ..ZERO_CONN_TYPE };
#[no_mangle]
pub static mut connections_failed_lru: i64 = 0;
#[no_mangle]
pub static mut connections_failed_flood: i64 = 0;
#[no_mangle]
pub static mut api_invoke_requests: i64 = 0;
#[no_mangle]
pub static mut sigpoll_cnt: c_int = 0;
#[no_mangle]
pub static mut stats_buff_len: c_int = 0;
#[no_mangle]
pub static mut stats_buff: [u8; STATS_BUFF_SIZE] = [0; STATS_BUFF_SIZE];
#[no_mangle]
pub static mut cur_http_origin: [c_char; 1024] = [0; 1024];
#[no_mangle]
pub static mut cur_http_referer: [c_char; 1024] = [0; 1024];
#[no_mangle]
pub static mut cur_http_user_agent: [c_char; 1024] = [0; 1024];
#[no_mangle]
pub static mut cur_http_origin_len: c_int = 0;
#[no_mangle]
pub static mut cur_http_referer_len: c_int = 0;
#[no_mangle]
pub static mut cur_http_user_agent_len: c_int = 0;
#[no_mangle]
pub static mut default_cfg_min_connections: c_int = DEFAULT_CFG_MIN_CONNECTIONS;
#[no_mangle]
pub static mut default_cfg_max_connections: c_int = DEFAULT_CFG_MAX_CONNECTIONS;
#[no_mangle]
pub static mut mtfront_rpc_client: MtprotoTcpRpcClientFunctions = MtprotoTcpRpcClientFunctions {
    ..ZERO_TCP_RPC_CLIENT_FUNCTIONS
};
#[no_mangle]
pub static mut ct_tcp_rpc_client_mtfront: MtprotoConnType = MtprotoConnType { ..ZERO_CONN_TYPE };
#[no_mangle]
pub static mut default_cfg_ct: MtproxyConnTargetInfo = MtproxyConnTargetInfo {
    timer: MtproxyEventTimer {
        h_idx: 0,
        flags: 0,
        wakeup: None,
        wakeup_time: 0.0,
        real_wakeup_time: 0.0,
    },
    min_connections: DEFAULT_CFG_MIN_CONNECTIONS,
    max_connections: DEFAULT_CFG_MAX_CONNECTIONS,
    conn_tree: core::ptr::null_mut(),
    type_: core::ptr::null_mut(),
    extra: core::ptr::null_mut(),
    target: MtproxyInAddr { s_addr: 0 },
    target_ipv6: [0; 16],
    port: 0,
    active_outbound_connections: 0,
    outbound_connections: 0,
    ready_outbound_connections: 0,
    next_reconnect: 0.0,
    reconnect_timeout: 17.0,
    next_reconnect_timeout: 0.0,
    custom_field: 0,
    next_target: core::ptr::null_mut(),
    prev_target: core::ptr::null_mut(),
    hnext: core::ptr::null_mut(),
    global_refcnt: 0,
};
#[no_mangle]
pub static mut WStats: *mut MtprotoWorkerStats = core::ptr::null_mut();
#[no_mangle]
pub static mut SumStats: MtprotoWorkerStats = MtprotoWorkerStats {
    ..ZERO_WORKER_STATS
};
#[no_mangle]
pub static mut worker_id: c_int = 0;
#[no_mangle]
pub static mut workers: c_int = 0;
#[no_mangle]
pub static mut slave_mode: c_int = 0;
#[no_mangle]
pub static mut parent_pid: c_int = 0;
#[no_mangle]
pub static mut pids: [c_int; MAX_WORKERS] = [0; MAX_WORKERS];
#[no_mangle]
pub static mut get_queries: i64 = 0;
#[no_mangle]
pub static mut pending_http_queries: c_int = 0;
#[no_mangle]
pub static mut active_rpcs: i64 = 0;
#[no_mangle]
pub static mut active_rpcs_created: i64 = 0;
#[no_mangle]
pub static mut rpc_dropped_running: i64 = 0;
#[no_mangle]
pub static mut rpc_dropped_answers: i64 = 0;
#[no_mangle]
pub static mut tot_forwarded_queries: i64 = 0;
#[no_mangle]
pub static mut expired_forwarded_queries: i64 = 0;
#[no_mangle]
pub static mut dropped_queries: i64 = 0;
#[no_mangle]
pub static mut tot_forwarded_responses: i64 = 0;
#[no_mangle]
pub static mut dropped_responses: i64 = 0;
#[no_mangle]
pub static mut tot_forwarded_simple_acks: i64 = 0;
#[no_mangle]
pub static mut dropped_simple_acks: i64 = 0;
#[no_mangle]
pub static mut mtproto_proxy_errors: i64 = 0;
#[no_mangle]
pub static mut proxy_tag: [c_char; 16] = [0; 16];
#[no_mangle]
pub static mut proxy_tag_set: c_int = 0;
#[no_mangle]
pub static mut rpcc_exists: c_int = 0;
#[no_mangle]
pub static mut http_methods: MtprotoHttpServerFunctions = MtprotoHttpServerFunctions {
    ..ZERO_HTTP_SERVER_FUNCTIONS
};
#[no_mangle]
pub static mut http_methods_stats: MtprotoHttpServerFunctions = MtprotoHttpServerFunctions {
    ..ZERO_HTTP_SERVER_FUNCTIONS
};
#[no_mangle]
pub static mut ext_rpc_methods: MtprotoTcpRpcServerFunctions = MtprotoTcpRpcServerFunctions {
    ..ZERO_TCP_RPC_SERVER_FUNCTIONS
};
#[no_mangle]
pub static mut mtproto_cors_http_headers: *mut c_char = MTPROXY_CORS_HTTP_HEADERS
    .as_ptr()
    .cast_mut()
    .cast::<c_char>();
#[no_mangle]
pub static mut sfd: c_int = 0;
#[no_mangle]
pub static mut http_ports_num: c_int = 0;
#[no_mangle]
pub static mut http_sfd: [c_int; MAX_HTTP_LISTEN_PORTS] = [0; MAX_HTTP_LISTEN_PORTS];
#[no_mangle]
pub static mut http_port: [c_int; MAX_HTTP_LISTEN_PORTS] = [0; MAX_HTTP_LISTEN_PORTS];
#[no_mangle]
pub static mut domain_count: c_int = 0;
#[no_mangle]
pub static mut secret_count: c_int = 0;
#[no_mangle]
pub static mut mtproto_front_functions: MtprotoServerFunctions = MtprotoServerFunctions {
    ..ZERO_SERVER_FUNCTIONS
};

unsafe extern "C" {
    fn init_listening_tcpv6_connection(
        fd: c_int,
        type_: *mut c_void,
        extra: *mut c_void,
        mode: c_int,
    ) -> c_int;
    fn connection_get_by_fd_generation(fd: c_int, generation: c_int) -> ConnectionJob;
    fn job_incref(job: ConnectionJob) -> ConnectionJob;
    fn job_free(job_tag_int: c_int, job: ConnectionJob) -> c_int;
    fn rpc_target_choose_random_connections(
        s: ConnTargetJob,
        pid: *mut c_void,
        limit: c_int,
        buf: *mut ConnectionJob,
    ) -> c_int;
    fn fail_connection(c: ConnectionJob, who: c_int);
    fn set_connection_timeout(c: ConnectionJob, timeout: c_double) -> c_int;
    fn clear_connection_timeout(c: ConnectionJob) -> c_int;
    fn nat_translate_ip(local_ip: u32) -> u32;
    fn job_decref(job_tag_int: c_int, job: ConnectionJob);
    fn get_utime_monotonic() -> c_double;

    #[link_name = "tl_out_state_alloc"]
    fn c_tl_out_state_alloc() -> *mut c_void;
    #[link_name = "tl_out_state_free"]
    fn c_tl_out_state_free(tlio_out: *mut c_void);
    #[link_name = "tls_init_tcp_raw_msg"]
    fn c_tls_init_tcp_raw_msg(
        tlio_out: *mut c_void,
        c_tag_int: c_int,
        c: ConnectionJob,
        qid: c_longlong,
    ) -> c_int;
    fn tls_init_tcp_raw_msg_unaligned(
        tlio_out: *mut crate::tl_parse::abi::TlOutState,
        c_tag_int: c_int,
        c: ConnectionJob,
        qid: i64,
    ) -> c_int;
    fn job_signal(job_tag_int: c_int, job: ConnectionJob, signo: c_int);
    fn lrand48_j() -> c_long;
    fn mtproxy_ffi_net_http_get_header(
        q_headers: *const c_char,
        q_headers_len: c_int,
        buffer: *mut c_char,
        b_len: c_int,
        arg_name: *const c_char,
        arg_len: c_int,
    ) -> c_int;
    fn rwm_create(raw: *mut MtprotoRawMessage, data: *const c_void, alloc_bytes: c_int) -> c_int;
    fn rwm_free(raw: *mut MtprotoRawMessage) -> c_int;
    fn rwm_init(raw: *mut MtprotoRawMessage, alloc_bytes: c_int) -> c_int;
    fn rwm_push_data(raw: *mut MtprotoRawMessage, data: *const c_void, bytes: c_int) -> c_int;
    fn rwm_move(dest_raw: *mut MtprotoRawMessage, src_raw: *mut MtprotoRawMessage);
    fn rwm_clone(dest_raw: *mut MtprotoRawMessage, src_raw: *mut MtprotoRawMessage);
    fn rwm_fetch_data(raw: *mut MtprotoRawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_dump(raw: *mut MtprotoRawMessage) -> c_int;
    fn mtproxy_ffi_net_connections_mpq_push_w(mq: *mut c_void, x: *mut c_void, flags: c_int);
    fn tcp_rpc_conn_send(
        c_tag_int: c_int,
        c: ConnectionJob,
        raw: *mut MtprotoRawMessage,
        flags: c_int,
    );
    fn http_flush(c: ConnectionJob, raw: *mut MtprotoRawMessage);
    fn write_basic_http_header_raw(
        c: ConnectionJob,
        raw: *mut MtprotoRawMessage,
        code: c_int,
        date: c_int,
        len: c_int,
        add_header: *const c_char,
        content_type: *const c_char,
    ) -> c_int;
    fn write_http_error(c: ConnectionJob, code: c_int) -> c_int;
    fn mtproxy_ffi_net_connections_job_free(job: ConnectionJob) -> c_int;
    fn connection_write_close(c: ConnectionJob);
    #[link_name = "tlf_init_raw_message"]
    fn c_tlf_init_raw_message(
        tlio_in: *mut c_void,
        msg: *mut c_void,
        size: c_int,
        dup: c_int,
    ) -> c_int;
    #[link_name = "tl_in_state_alloc"]
    fn c_tl_in_state_alloc() -> *mut c_void;
    #[link_name = "tl_in_state_free"]
    fn c_tl_in_state_free(tlio_in: *mut c_void);
    fn create_async_job(
        run_job: MtprotoJobExecuteFn,
        job_signals: u64,
        job_subclass: c_int,
        custom_bytes: c_int,
        job_type: u64,
        parent_job_tag_int: c_int,
        parent_job: ConnectionJob,
    ) -> ConnectionJob;
    fn schedule_job(job_tag_int: c_int, job: ConnectionJob) -> c_int;
    fn mtproxy_ffi_net_tcp_rpc_ext_show_our_ip(c: ConnectionJob) -> *const c_char;
    fn mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(c: ConnectionJob) -> *const c_char;
    fn fetch_connections_stat(st: *mut MtprotoConnectionsStat);
    #[link_name = "mtproxy_ffi_net_msg_buffers_fetch_buffers_stat"]
    fn fetch_buffers_stat(bs: *mut MtprotoBuffersStat);
    fn fetch_tot_dh_rounds_stat(rounds: *mut i64);
    fn fetch_aes_crypto_stat(
        allocated_aes_crypto_ptr: *mut c_int,
        allocated_aes_crypto_temp_ptr: *mut c_int,
    );
    fn sb_prepare(sb: *mut MtprotoStatsBuffer);
    fn sb_alloc(sb: *mut MtprotoStatsBuffer, size: c_int);
    fn sb_memory(sb: *mut MtprotoStatsBuffer, flags: c_int);
    fn sb_release(sb: *mut MtprotoStatsBuffer);
    fn engine_set_http_fallback(http_type: *mut c_void, http_functions: *mut c_void);
    fn tcp_rpc_add_proxy_domain(domain: *const c_char);
    fn tcp_rpcs_set_ext_secret(secret: *mut u8);
    fn rust_sf_register_parse_option_or_die(
        name: *const c_char,
        arg: c_int,
        val: c_int,
        help: *const c_char,
    );
    fn parse_usage() -> c_int;
    fn reopen_logs_ext(slave_mode: c_int);
    fn signal_check_pending(sig: c_int) -> c_int;
    fn tcp_rpc_init_proxy_domains();
    fn server_socket(port: c_int, in_addr: MtproxyInAddr, backlog: c_int, mode: c_int) -> c_int;
    fn tcp_rpc_flush_packet(c: ConnectionJob) -> c_int;
    fn tcp_rpcc_default_check_perm(c: ConnectionJob) -> c_int;
    fn tcp_rpcc_init_crypto(c: ConnectionJob) -> c_int;
    fn tcp_rpcc_start_crypto(
        c: ConnectionJob,
        nonce: *mut c_char,
        key_select: c_int,
        temp_key: *mut u8,
        temp_key_len: c_int,
    ) -> c_int;
    fn tcp_rpcc_default_check_ready(c: ConnectionJob) -> c_int;
    fn server_check_ready(c: ConnectionJob) -> c_int;
    fn kdb_load_hosts() -> c_int;
    fn default_main(f: *mut MtprotoServerFunctions, argc: c_int, argv: *mut *mut c_char) -> c_int;

    static mut ct_http_server: MtprotoConnType;
    static mut ct_tcp_rpc_ext_server: MtprotoConnType;
    static mut ct_tcp_rpc_server: MtprotoConnType;
    static mut ct_tcp_rpc_client: MtprotoConnType;
    static mut progname: *const c_char;
    static mut engine_state: *mut MtprotoEngineStatePrefix;
    static mut optarg: *mut c_char;
    static mut max_special_connections: c_int;
    static mut active_special_connections: c_int;
    static mut kdb_hosts_loaded: c_int;
    static mut Events: [MtprotoEventDescr; MAX_EVENTS];
    static mut tcp_maximize_buffers: c_int;

    static mut http_queries: i64;
    static mut http_bad_headers: i64;
    static mut http_connections: c_int;
    static mut ev_heap_size: c_int;
    static mut extra_http_response_headers: *mut c_char;
    static mut start_time: c_int;
    static mut verbosity: c_int;
}

static MTPROTO_EXT_CONN_TABLE: std::sync::LazyLock<
    Mutex<mtproxy_core::runtime::mtproto::proxy::ExtConnectionTable>,
> = std::sync::LazyLock::new(|| {
    Mutex::new(mtproxy_core::runtime::mtproto::proxy::ExtConnectionTable::new())
});

fn ext_conn_lock(
) -> std::sync::MutexGuard<'static, mtproxy_core::runtime::mtproto::proxy::ExtConnectionTable> {
    MTPROTO_EXT_CONN_TABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ext_conn_to_ffi(
    conn: mtproxy_core::runtime::mtproto::proxy::ExtConnection,
) -> MtproxyMtprotoExtConnection {
    MtproxyMtprotoExtConnection {
        in_fd: conn.in_fd,
        in_gen: conn.in_gen,
        out_fd: conn.out_fd,
        out_gen: conn.out_gen,
        in_conn_id: conn.in_conn_id,
        out_conn_id: conn.out_conn_id,
        auth_key_id: conn.auth_key_id,
    }
}

pub(super) fn mtproto_ext_conn_reset_ffi() {
    let mut table = ext_conn_lock();
    *table = mtproxy_core::runtime::mtproto::proxy::ExtConnectionTable::new();
}

pub(super) fn mtproto_ext_conn_create_ffi(
    in_fd: c_int,
    in_gen: c_int,
    in_conn_id: i64,
    out_fd: c_int,
    out_gen: c_int,
    auth_key_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    let created = match table.get_ext_connection_by_in_conn_id(
        in_fd,
        in_gen,
        in_conn_id,
        mtproxy_core::runtime::mtproto::proxy::ExtConnLookupMode::CreateIfMissing,
    ) {
        Ok(mtproxy_core::runtime::mtproto::proxy::ExtConnLookupOutcome::Created(conn)) => conn,
        Ok(mtproxy_core::runtime::mtproto::proxy::ExtConnLookupOutcome::AlreadyExists)
        | Ok(mtproxy_core::runtime::mtproto::proxy::ExtConnLookupOutcome::Found(_)) => return 0,
        Ok(_) => return 0,
        Err(_) => return -1,
    };
    let bind_target = if out_fd != 0 {
        Some((out_fd, out_gen))
    } else {
        None
    };
    match table.bind_ext_connection(created.in_fd, created.in_conn_id, bind_target, auth_key_id) {
        Ok(conn) => {
            *out_ref = ext_conn_to_ffi(conn);
            1
        }
        Err(_) => {
            let _ = table.remove_ext_connection_by_in_conn_id(created.in_fd, created.in_conn_id);
            -1
        }
    }
}

pub(super) fn mtproto_ext_conn_get_by_in_fd_ffi(
    in_fd: c_int,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let table = ext_conn_lock();
    match table.get_ext_connection_by_in_fd(in_fd) {
        Ok(Some(conn)) => {
            *out_ref = ext_conn_to_ffi(conn);
            1
        }
        Ok(None) => 0,
        Err(_) => -1,
    }
}

pub(super) fn mtproto_ext_conn_get_by_out_conn_id_ffi(
    out_conn_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let table = ext_conn_lock();
    if let Some(conn) = table.find_ext_connection_by_out_conn_id(out_conn_id) {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) fn mtproto_ext_conn_update_auth_key_ffi(
    in_fd: c_int,
    in_conn_id: i64,
    auth_key_id: i64,
) -> i32 {
    let mut table = ext_conn_lock();
    if table
        .update_auth_key(in_fd, in_conn_id, auth_key_id)
        .is_ok()
    {
        1
    } else {
        0
    }
}

pub(super) fn mtproto_ext_conn_remove_by_out_conn_id_ffi(
    out_conn_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    if let Some(conn) = table.take_ext_connection_by_out_conn_id(out_conn_id) {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) fn mtproto_ext_conn_remove_by_in_conn_id_ffi(
    in_fd: c_int,
    in_conn_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    if let Some(conn) = table.take_ext_connection_by_in_conn_id(in_fd, in_conn_id) {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) fn mtproto_ext_conn_remove_any_by_out_fd_ffi(
    out_fd: c_int,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    if let Some(conn) = table.pop_any_ext_connection_by_out_fd(out_fd) {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) fn mtproto_ext_conn_remove_any_by_in_fd_ffi(
    in_fd: c_int,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    if let Some(conn) = table.pop_any_ext_connection_by_in_fd(in_fd) {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) fn mtproto_ext_conn_lru_insert_ffi(in_fd: c_int, in_gen: c_int) -> i32 {
    let mut table = ext_conn_lock();
    match table.lru_insert_by_in_fd_gen(in_fd, in_gen) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

pub(super) fn mtproto_ext_conn_lru_delete_ffi(in_fd: c_int) -> i32 {
    let mut table = ext_conn_lock();
    match table.lru_delete_by_in_fd(in_fd) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

pub(super) fn mtproto_ext_conn_lru_pop_oldest_ffi(out: *mut MtproxyMtprotoExtConnection) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    if let Some(conn) = table.lru_pop_oldest() {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) fn mtproto_ext_conn_counts_ffi(out_current: *mut i64, out_created: *mut i64) -> i32 {
    let Some(out_current_ref) = (unsafe { mut_ref_from_ptr(out_current) }) else {
        return -1;
    };
    let Some(out_created_ref) = (unsafe { mut_ref_from_ptr(out_created) }) else {
        return -1;
    };
    let table = ext_conn_lock();
    *out_current_ref = i64::try_from(table.ext_connections()).unwrap_or(i64::MAX);
    *out_created_ref = i64::try_from(table.ext_connections_created()).unwrap_or(i64::MAX);
    0
}

pub(super) fn mtproto_notify_ext_connection_runtime_ffi(
    ex: *const MtproxyMtprotoExtConnection,
    send_notifications: c_int,
) {
    let Some(ex_ref) = (unsafe { ref_from_ptr(ex) }) else {
        return;
    };
    assert!(ex_ref.out_conn_id != 0);

    if ex_ref.out_fd != 0 {
        assert!((ex_ref.out_fd as u32) < MAX_CONNECTIONS as u32);
        if (send_notifications & 1) != 0 {
            let co = unsafe { connection_get_by_fd_generation(ex_ref.out_fd, ex_ref.out_gen) };
            if !co.is_null() {
                mtproto_notify_remote_closed_owned(co, ex_ref.out_conn_id);
            }
        }
    }

    if ex_ref.in_fd != 0 {
        assert!((ex_ref.in_fd as u32) < MAX_CONNECTIONS as u32);
        if (send_notifications & 2) != 0 {
            let ci = unsafe { connection_get_by_fd_generation(ex_ref.in_fd, ex_ref.in_gen) };
            if ex_ref.in_conn_id != 0 {
                assert!(false);
            } else if !ci.is_null() {
                unsafe {
                    fail_connection(ci, -33);
                    mtproto_job_decref(ci);
                }
            }
        }
    }
}

pub(super) fn mtproto_remove_ext_connection_runtime_ffi(
    ex: *const MtproxyMtprotoExtConnection,
    send_notifications: c_int,
) {
    let Some(ex_ref) = (unsafe { ref_from_ptr(ex) }) else {
        return;
    };
    assert!(ex_ref.out_conn_id != 0);

    let mut cur = MtproxyMtprotoExtConnection::default();
    let lookup_rc = mtproto_ext_conn_get_by_out_conn_id_ffi(ex_ref.out_conn_id, &mut cur);
    assert!(lookup_rc >= 0);
    if lookup_rc <= 0 {
        return;
    }

    mtproto_notify_ext_connection_runtime_ffi(&cur, send_notifications);

    let mut removed = MtproxyMtprotoExtConnection::default();
    let remove_rc = mtproto_ext_conn_remove_by_out_conn_id_ffi(cur.out_conn_id, &mut removed);
    assert!(remove_rc >= 0);
}

#[allow(clippy::too_many_arguments)]
pub(super) fn mtproto_build_rpc_proxy_req_ffi(
    flags: c_int,
    out_conn_id: i64,
    remote_ipv6: *const u8,
    remote_port: c_int,
    our_ipv6: *const u8,
    our_port: c_int,
    proxy_tag_ptr: *const u8,
    proxy_tag_len: usize,
    http_origin: *const u8,
    http_origin_len: usize,
    http_referer: *const u8,
    http_referer_len: usize,
    http_user_agent: *const u8,
    http_user_agent_len: usize,
    payload: *const u8,
    payload_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let Some(out_len_ref) = (unsafe { mut_ref_from_ptr(out_len) }) else {
        return -1;
    };
    let Some(remote_ipv6_slice) = (unsafe { slice_from_ptr(remote_ipv6, 16) }) else {
        return -1;
    };
    let Some(our_ipv6_slice) = (unsafe { slice_from_ptr(our_ipv6, 16) }) else {
        return -1;
    };
    let Some(payload_slice) = (unsafe { slice_from_ptr(payload, payload_len) }) else {
        return -1;
    };

    let mut remote_ipv6_arr = [0u8; 16];
    remote_ipv6_arr.copy_from_slice(remote_ipv6_slice);
    let mut our_ipv6_arr = [0u8; 16];
    our_ipv6_arr.copy_from_slice(our_ipv6_slice);

    let proxy_tag_bytes = if (flags & 8) != 0 {
        let Some(tag) = (unsafe { slice_from_ptr(proxy_tag_ptr, proxy_tag_len) }) else {
            return -1;
        };
        Some(tag)
    } else {
        None
    };
    let http_query_info = if (flags & 4) != 0 {
        let Some(origin) = (unsafe { slice_from_ptr(http_origin, http_origin_len) }) else {
            return -1;
        };
        let Some(referer) = (unsafe { slice_from_ptr(http_referer, http_referer_len) }) else {
            return -1;
        };
        let Some(user_agent) = (unsafe { slice_from_ptr(http_user_agent, http_user_agent_len) })
        else {
            return -1;
        };
        Some(mtproxy_core::runtime::mtproto::proxy::HttpQueryInfo {
            origin,
            referer,
            user_agent,
        })
    } else {
        None
    };

    let input = mtproxy_core::runtime::mtproto::proxy::ProxyReqBuildInput {
        flags,
        out_conn_id,
        remote_ipv6: remote_ipv6_arr,
        remote_port,
        our_ipv6: our_ipv6_arr,
        our_port,
        proxy_tag: proxy_tag_bytes,
        http_query_info,
        payload: payload_slice,
    };

    let mut scratch_cap = payload_len
        .saturating_add(proxy_tag_len)
        .saturating_add(http_origin_len)
        .saturating_add(http_referer_len)
        .saturating_add(http_user_agent_len)
        .saturating_add(256)
        .max(64);

    loop {
        let mut scratch = vec![0u8; scratch_cap];
        match mtproxy_core::runtime::mtproto::proxy::build_rpc_proxy_req(&mut scratch, &input) {
            Ok(used) => {
                *out_len_ref = used;
                if out_buf.is_null() || out_cap < used {
                    return 1;
                }
                let Some(out_slice) = (unsafe { mut_slice_from_ptr(out_buf, out_cap) }) else {
                    return -1;
                };
                out_slice[..used].copy_from_slice(&scratch[..used]);
                return 0;
            }
            Err(err) => {
                if err.errnum != mtproxy_core::runtime::config::tl_parse::TL_ERROR_NOT_ENOUGH_DATA {
                    return -2;
                }
                let next = scratch_cap.saturating_mul(2);
                if next <= scratch_cap {
                    return -2;
                }
                scratch_cap = next;
            }
        }
    }
}

pub(super) fn mtproto_build_http_ok_header_ffi(
    keep_alive: c_int,
    extra_headers: c_int,
    content_len: c_int,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if content_len < 0 {
        return -2;
    }
    let Some(out_len_ref) = (unsafe { mut_ref_from_ptr(out_len) }) else {
        return -1;
    };

    let connection = if keep_alive != 0 {
        "keep-alive"
    } else {
        "close"
    };
    let extra = if extra_headers != 0 {
        "Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: POST, OPTIONS\r\n\
Access-Control-Allow-Headers: origin, content-type\r\n\
Access-Control-Max-Age: 1728000\r\n"
    } else {
        ""
    };
    let header = format!(
        "HTTP/1.1 200 OK\r\nConnection: {connection}\r\nContent-type: application/octet-stream\r\nPragma: no-cache\r\nCache-control: no-store\r\n{extra}Content-length: {content_len}\r\n\r\n"
    );
    let bytes = header.as_bytes();
    *out_len_ref = bytes.len();
    if out_buf.is_null() || out_cap < bytes.len() {
        return 1;
    }
    let Some(out_slice) = (unsafe { mut_slice_from_ptr(out_buf, out_cap) }) else {
        return -1;
    };
    out_slice[..bytes.len()].copy_from_slice(bytes);
    0
}

pub(super) fn mtproto_client_send_non_http_wrap_ffi(
    tlio_in: *mut c_void,
    tlio_out: *mut c_void,
) -> i32 {
    let tlio_in = tlio_in.cast::<crate::tl_parse::abi::TlInState>();
    let tlio_out = tlio_out.cast::<crate::tl_parse::abi::TlOutState>();
    let unread = unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_fetch_unread(tlio_in) };
    if unread < 0 {
        return -1;
    }
    let copy_rc =
        unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_copy_through(tlio_in, tlio_out, unread, 1) };
    if copy_rc < 0 {
        return -1;
    }
    let mut sent_kind = 0;
    let end_rc =
        unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_store_end_ext(tlio_out, 0, &mut sent_kind) };
    if end_rc < 0 {
        return -1;
    }
    0
}

pub(super) fn mtproto_http_send_message_ffi(
    c: *mut c_void,
    tlio_in: *mut c_void,
    flags: c_int,
) -> c_int {
    if c.is_null() || tlio_in.is_null() {
        return 0;
    }
    let tlio_in = tlio_in.cast::<crate::tl_parse::abi::TlInState>();

    unsafe {
        clear_connection_timeout(c);
    }
    let d = mtproto_hts_data_ptr(c);
    if d.is_null() {
        return 0;
    }

    let unread = unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_fetch_unread(tlio_in) };
    if (flags & 0x10) != 0 && unread == 4 {
        let error_code = unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_fetch_int(tlio_in) };
        unsafe {
            (*d).query_flags &= !QF_KEEPALIVE;
            write_http_error(c, -error_code);
        }
    } else {
        let len = unread;
        let mut header_len = 0_usize;
        let rc = mtproto_build_http_ok_header_ffi(
            unsafe { (*d).query_flags & QF_KEEPALIVE },
            unsafe { (*d).query_flags & QF_EXTRA_HEADERS },
            len,
            core::ptr::null_mut(),
            0,
            &mut header_len,
        );
        if rc < 0 || header_len > i32::MAX as usize {
            return 0;
        }

        let mut header = vec![0_u8; header_len];
        let rc = mtproto_build_http_ok_header_ffi(
            unsafe { (*d).query_flags & QF_KEEPALIVE },
            unsafe { (*d).query_flags & QF_EXTRA_HEADERS },
            len,
            header.as_mut_ptr(),
            header.len(),
            &mut header_len,
        );
        if rc != 0 {
            return 0;
        }

        let tlio_out = unsafe { c_tl_out_state_alloc() }.cast::<crate::tl_parse::abi::TlOutState>();
        if tlio_out.is_null() {
            return 0;
        }
        unsafe {
            let c_ref = job_incref(c);
            tls_init_tcp_raw_msg_unaligned(tlio_out, 1, c_ref, 0);
            crate::tl_parse::abi::mtproxy_ffi_tl_store_raw_data(
                tlio_out,
                header.as_ptr().cast(),
                saturating_i32_from_usize(header_len),
            );
            assert!(
                crate::tl_parse::abi::mtproxy_ffi_tl_copy_through(tlio_in, tlio_out, len, 1) == len
            );
            let mut sent_kind = 0;
            let _ = crate::tl_parse::abi::mtproxy_ffi_tl_store_end_ext(tlio_out, 0, &mut sent_kind);
            c_tl_out_state_free(tlio_out.cast());
        }
    }

    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return 0;
    }
    assert!(unsafe { (*conn).status == CONN_STATUS_WORKING && (*conn).pending_queries == 1 });

    unsafe {
        if verbosity >= 3 {
            crate::kprintf_fmt!(
                b"detaching http connection (%d)\n\0".as_ptr().cast(),
                (*conn).fd,
            );
        }
    }

    let mut ex = MtproxyMtprotoExtConnection::default();
    let ext_rc = mtproto_ext_conn_get_by_in_fd_ffi(unsafe { (*conn).fd }, &mut ex);
    assert!(ext_rc >= 0);
    if ext_rc > 0 {
        mtproto_remove_ext_connection_runtime_ffi(&ex, 1);
    }

    let mut c_copy = c;
    unsafe {
        mtproto_schedule_job_callback_local(
            JC_CONNECTION,
            Some(mtproto_finish_postponed_http_response_bridge),
            core::ptr::addr_of_mut!(c_copy).cast(),
            saturating_i32_from_usize(core::mem::size_of::<ConnectionJob>()),
        );
    }

    1
}

pub(super) fn mtproto_finish_postponed_http_response_ffi(data: *mut c_void, len: c_int) -> c_int {
    assert!(len == saturating_i32_from_usize(core::mem::size_of::<ConnectionJob>()));
    let conn_ptr = data.cast::<ConnectionJob>();
    assert!(!conn_ptr.is_null());
    let c = unsafe { *conn_ptr };
    assert!(!c.is_null());

    let conn = mtproto_conn_info_ptr(c);
    assert!(!conn.is_null());

    if unsafe { ((*c.cast::<MtprotoAsyncJobPrefix>()).j_flags & JF_COMPLETED) == 0 } {
        assert!(unsafe { (*conn).pending_queries >= 0 });
        assert!(unsafe { (*conn).pending_queries > 0 });
        assert!(unsafe { (*conn).pending_queries == 1 });
        unsafe {
            (*conn).pending_queries = 0;
            pending_http_queries = pending_http_queries.wrapping_sub(1);
            http_flush(c, core::ptr::null_mut());
        }
    } else {
        assert!(unsafe { (*conn).pending_queries == 0 });
    }
    mtproto_job_decref(c);
    JOB_COMPLETED
}

unsafe extern "C" fn mtproto_finish_postponed_http_response_bridge(
    data: *mut c_void,
    len: c_int,
) -> c_int {
    mtproto_finish_postponed_http_response_ffi(data, len)
}

pub(super) fn mtproto_client_send_message_runtime_ffi(
    c_tag_int: c_int,
    c: *mut c_void,
    in_conn_id: i64,
    tlio_in: *mut c_void,
    flags: c_int,
) -> c_int {
    if mtproto_check_conn_buffers_runtime_ffi(c) < 0 {
        mtproto_job_decref(c);
        return -1;
    }
    if in_conn_id != 0 {
        assert!(in_conn_id == 0);
        return 1;
    }

    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        mtproto_job_decref(c);
        return -1;
    }

    let http_type_ptr = core::ptr::addr_of_mut!(ct_http_server_mtfront).cast::<c_void>();
    if unsafe { (*conn).type_ == http_type_ptr } {
        return mtproto_http_send_message_ffi(c, tlio_in, flags);
    }

    let tlio_out = unsafe { c_tl_out_state_alloc() }.cast::<crate::tl_parse::abi::TlOutState>();
    assert!(!tlio_out.is_null());
    unsafe {
        c_tls_init_tcp_raw_msg(tlio_out.cast(), c_tag_int, job_incref(c), 0);
        let rc = mtproto_client_send_non_http_wrap_ffi(tlio_in, tlio_out.cast::<c_void>());
        assert!(rc == 0);
        c_tl_out_state_free(tlio_out.cast());
    }

    if mtproto_check_conn_buffers_runtime_ffi(c) < 0 {
        mtproto_job_decref(c);
        -1
    } else {
        mtproto_job_decref(c);
        1
    }
}

#[inline]
fn mtproto_conn_info_ptr(c: ConnectionJob) -> *mut MtprotoConnInfoPrefix {
    if c.is_null() {
        return core::ptr::null_mut();
    }
    let job = c.cast::<MtprotoAsyncJobPrefix>();
    let custom = unsafe { (*job).j_custom.as_ptr().cast_mut() };
    custom.cast::<MtprotoConnInfoPrefix>()
}

#[inline]
fn mtproto_rpc_data_ptr(c: ConnectionJob) -> *mut MtprotoTcpRpcDataPrefix {
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return core::ptr::null_mut();
    }
    let base = unsafe { core::ptr::addr_of!((*conn).custom_data).cast::<u8>() as usize };
    let align = core::mem::align_of::<MtprotoTcpRpcDataPrefix>();
    let aligned = (base + align - 1) & !(align - 1);
    aligned as *mut MtprotoTcpRpcDataPrefix
}

#[inline]
fn mtproto_conn_tag(c: ConnectionJob) -> c_int {
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return 0;
    }
    let generation = unsafe { (*conn).generation };
    mtproxy_core::runtime::mtproto::proxy::mtproto_conn_tag(generation)
}

#[inline]
fn mtproto_job_decref(c: ConnectionJob) {
    if !c.is_null() {
        unsafe { job_decref(1, c) };
    }
}

#[inline]
fn mtproto_http_query_flags_ptr(c: ConnectionJob) -> *mut c_int {
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return core::ptr::null_mut();
    }
    let base = unsafe { core::ptr::addr_of_mut!((*conn).custom_data).cast::<u8>() };
    unsafe { base.add(core::mem::size_of::<c_int>()).cast::<c_int>() }
}

#[inline]
fn mtproto_http_query_flags_get(c: ConnectionJob) -> c_int {
    let ptr = mtproto_http_query_flags_ptr(c);
    if ptr.is_null() {
        return 0;
    }
    unsafe { ptr.read_unaligned() }
}

#[inline]
fn mtproto_http_query_flags_set(c: ConnectionJob, value: c_int) {
    let ptr = mtproto_http_query_flags_ptr(c);
    if ptr.is_null() {
        return;
    }
    unsafe { ptr.write_unaligned(value) };
}

#[inline]
fn mtproto_hts_data_ptr(c: ConnectionJob) -> *mut MtprotoHtsData {
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { core::ptr::addr_of_mut!((*conn).custom_data).cast::<MtprotoHtsData>() }
}

#[inline]
fn mtproto_http_query_info_ptr(job: *mut c_void) -> *mut MtprotoHttpQueryInfo {
    if job.is_null() {
        return core::ptr::null_mut();
    }
    let async_job = job.cast::<MtprotoAsyncJobPrefix>();
    let custom = unsafe { (*async_job).j_custom.as_ptr().cast_mut() };
    custom.cast::<MtprotoHttpQueryInfo>()
}

#[inline]
fn mtproto_listening_conn_info_ptr(c: ConnectionJob) -> *mut MtprotoListeningConnInfoPrefix {
    if c.is_null() {
        return core::ptr::null_mut();
    }
    let job = c.cast::<MtprotoAsyncJobPrefix>();
    let custom = unsafe { (*job).j_custom.as_ptr().cast_mut() };
    custom.cast::<MtprotoListeningConnInfoPrefix>()
}

#[inline]
fn mtproto_client_packet_info_ptr(job: *mut c_void) -> *mut MtprotoClientPacketInfo {
    if job.is_null() {
        return core::ptr::null_mut();
    }
    let async_job = job.cast::<MtprotoAsyncJobPrefix>();
    let custom = unsafe { (*async_job).j_custom.as_ptr().cast_mut() };
    custom.cast::<MtprotoClientPacketInfo>()
}

#[inline]
fn mtproto_safe_div(x: f64, y: f64) -> f64 {
    if y > 0.0 {
        x / y
    } else {
        0.0
    }
}

#[inline]
fn mtproto_jss_allow(sig: c_int) -> u64 {
    0x0100_0000_u64 << u32::try_from(sig).unwrap_or(0)
}

#[inline]
fn mtproto_jss_allow_fast(sig: c_int) -> u64 {
    0x0101_0000_u64 << u32::try_from(sig).unwrap_or(0)
}

#[inline]
fn mtproto_jsc_allow(class: c_int, sig: c_int) -> u64 {
    let shift = u32::try_from(sig.saturating_mul(4).saturating_add(32)).unwrap_or(0);
    ((u64::try_from(class).unwrap_or(0)) << shift) | mtproto_jss_allow(sig)
}

#[inline]
fn mtproto_jsc_fast(class: c_int, sig: c_int) -> u64 {
    let shift = u32::try_from(sig.saturating_mul(4).saturating_add(32)).unwrap_or(0);
    ((u64::try_from(class).unwrap_or(0)) << shift) | mtproto_jss_allow_fast(sig)
}

fn mtproto_schedule_job_callback_local(
    context: c_int,
    func: MtprotoJobCallbackFn,
    data: *mut c_void,
    len: c_int,
) {
    assert!(len >= 0);
    let payload_len = usize::try_from(len).unwrap_or(0);
    let custom_bytes = core::mem::size_of::<MtprotoJobCallbackFn>().saturating_add(payload_len);
    let job = unsafe {
        create_async_job(
            Some(mtproto_callback_job_run_bridge),
            JSP_PARENT_RWE | mtproto_jsc_allow(context, JS_RUN) | mtproto_jsc_fast(0, JS_FINISH),
            -2,
            saturating_i32_from_usize(custom_bytes),
            0,
            -1,
            core::ptr::null_mut(),
        )
    };
    assert!(!job.is_null());
    let d = unsafe {
        (*job.cast::<MtprotoAsyncJobPrefix>())
            .j_custom
            .as_ptr()
            .cast_mut()
            .cast::<MtprotoJobCallbackInfo>()
    };
    assert!(!d.is_null());
    unsafe {
        (*d).func = func;
    }
    if payload_len > 0 {
        assert!(!data.is_null());
        let data_ptr = unsafe { core::ptr::addr_of_mut!((*d).data).cast::<u8>() };
        unsafe {
            core::ptr::copy_nonoverlapping(data.cast::<u8>(), data_ptr, payload_len);
        }
    }
    unsafe {
        schedule_job(1, job);
    }
}

fn mtproto_lru_insert_conn_local(c: ConnectionJob) {
    let conn = mtproto_conn_info_ptr(c);
    assert!(!conn.is_null());
    let rc = mtproto_ext_conn_lru_insert_ffi(unsafe { (*conn).fd }, unsafe { (*conn).generation });
    assert!(rc >= 0);
}

fn mtproto_check_thread_class_local(class: c_int) {
    let jt = unsafe { crate::jobs_get_this_job_thread_c_impl() };
    assert!(!jt.is_null());
    let jt_prefix = jt.cast::<MtprotoJobThreadPrefix>();
    assert!((unsafe { (*jt_prefix).job_class_mask } & (1 << class)) != 0);
}

#[inline]
fn mtproto_parse_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn mtproto_choose_proxy_target_impl(target_dc: c_int) -> ConnTargetJob {
    const PICK_BATCH: c_int = 64;
    let cur_conf = unsafe { CurConf };
    if cur_conf.is_null() {
        return core::ptr::null_mut();
    }
    assert!(unsafe { (*cur_conf).auth_clusters } > 0);

    let mfc = unsafe { mf_cluster_lookup_ffi(cur_conf, target_dc, 1) };
    if mfc.is_null() {
        return core::ptr::null_mut();
    }

    let targets_num = unsafe { (*mfc).targets_num };
    assert!(targets_num > 0);
    let Some(targets_len) = usize::try_from(targets_num).ok() else {
        return core::ptr::null_mut();
    };
    let targets = unsafe { (*mfc).cluster_targets };
    assert!(!targets.is_null());

    let rand = unsafe { lrand48() };
    let start_idx = usize::try_from(rand).unwrap_or(0) % targets_len;
    for off in 0..targets_len {
        let idx = (start_idx + off) % targets_len;
        let s = unsafe { *targets.add(idx) };

        let mut candidates = [core::ptr::null_mut(); PICK_BATCH as usize];
        let picked = unsafe {
            rpc_target_choose_random_connections(
                s,
                core::ptr::null_mut(),
                PICK_BATCH,
                candidates.as_mut_ptr(),
            )
        };
        let count = picked.max(0).min(PICK_BATCH) as usize;
        let mut i = 0;
        while i < count {
            let c = candidates[i];
            if !c.is_null() {
                let data = mtproto_rpc_data_ptr(c);
                let is_match = if !data.is_null() {
                    let tag = mtproto_conn_tag(c);
                    let marker = unsafe { (*data).extra_int };
                    marker == tag || marker == -tag
                } else {
                    false
                };
                mtproto_job_decref(c);
                if is_match {
                    return s;
                }
            }
            i = i.saturating_add(1);
        }
    }

    core::ptr::null_mut()
}

pub(super) fn mtproto_choose_proxy_target_ffi(target_dc: c_int) -> ConnTargetJob {
    mtproto_choose_proxy_target_impl(target_dc)
}

#[inline]
fn mtproto_forward_pick_connection(target: ConnTargetJob) -> ConnectionJob {
    const PICK_BATCH: c_int = 64;
    let mut attempts = 3;
    while !target.is_null() && attempts > 0 {
        attempts -= 1;
        let mut candidates = [core::ptr::null_mut(); PICK_BATCH as usize];
        let picked = unsafe {
            rpc_target_choose_random_connections(
                target,
                core::ptr::null_mut(),
                PICK_BATCH,
                candidates.as_mut_ptr(),
            )
        };
        let count = picked.max(0).min(PICK_BATCH) as usize;
        let mut i = 0;
        while i < count {
            let d = candidates[i];
            if !d.is_null() {
                let data = mtproto_rpc_data_ptr(d);
                let is_match = if !data.is_null() {
                    let tag = mtproto_conn_tag(d);
                    let marker = unsafe { (*data).extra_int };
                    marker == tag || marker == -tag
                } else {
                    false
                };
                if is_match {
                    return d;
                }
                mtproto_job_decref(d);
            }
            i = i.saturating_add(1);
        }
    }
    core::ptr::null_mut()
}

#[inline]
fn mtproto_forward_endpoint(
    conn: *const MtprotoConnInfoPrefix,
    ip_port_override: *const c_int,
    nat_our_ip: bool,
    out_ipv6: &mut [u8; 16],
) -> c_int {
    if !ip_port_override.is_null() {
        if let Some(values) = unsafe { slice_from_ptr(ip_port_override, 5) } {
            if let Some(ipv6_src) = unsafe { slice_from_ptr(ip_port_override.cast::<u8>(), 16) } {
                out_ipv6.copy_from_slice(ipv6_src);
            }
            return values[4];
        }
    }

    let conn_ref = unsafe { &*conn };
    let ip = if nat_our_ip {
        conn_ref.our_ip
    } else {
        conn_ref.remote_ip
    };
    if ip != 0 {
        out_ipv6.fill(0);
        out_ipv6[10] = 0xff;
        out_ipv6[11] = 0xff;
        let translated = if nat_our_ip {
            unsafe { nat_translate_ip(ip) }
        } else {
            ip
        };
        out_ipv6[12..].copy_from_slice(&translated.to_be_bytes());
    } else if nat_our_ip {
        out_ipv6.copy_from_slice(&conn_ref.our_ipv6);
    } else {
        out_ipv6.copy_from_slice(&conn_ref.remote_ipv6);
    }

    if nat_our_ip {
        c_int::try_from(conn_ref.our_port).unwrap_or(c_int::MAX)
    } else {
        c_int::try_from(conn_ref.remote_port).unwrap_or(c_int::MAX)
    }
}

#[allow(clippy::too_many_arguments)]
fn mtproto_forward_build_req(
    flags: c_int,
    out_conn_id: i64,
    remote_ipv6: &[u8; 16],
    remote_port: c_int,
    our_ipv6: &[u8; 16],
    our_port: c_int,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let proxy_tag_slice = if (flags & FORWARD_FLAG_PROXY_TAG) != 0 {
        unsafe { slice_from_ptr(core::ptr::addr_of!(proxy_tag).cast::<u8>(), 16) }?
    } else {
        &[]
    };
    let http_origin_len = unsafe { cur_http_origin_len.max(0) as usize };
    let http_referer_len = unsafe { cur_http_referer_len.max(0) as usize };
    let http_user_agent_len = unsafe { cur_http_user_agent_len.max(0) as usize };
    let http_origin_slice = if (flags & 4) != 0 {
        unsafe {
            slice_from_ptr(
                core::ptr::addr_of!(cur_http_origin).cast::<u8>(),
                http_origin_len,
            )
        }?
    } else {
        &[]
    };
    let http_referer_slice = if (flags & 4) != 0 {
        unsafe {
            slice_from_ptr(
                core::ptr::addr_of!(cur_http_referer).cast::<u8>(),
                http_referer_len,
            )
        }?
    } else {
        &[]
    };
    let http_user_agent_slice = if (flags & 4) != 0 {
        unsafe {
            slice_from_ptr(
                core::ptr::addr_of!(cur_http_user_agent).cast::<u8>(),
                http_user_agent_len,
            )
        }?
    } else {
        &[]
    };

    let proxy_tag_ptr = if proxy_tag_slice.is_empty() {
        core::ptr::null()
    } else {
        proxy_tag_slice.as_ptr()
    };
    let http_origin_ptr = if (flags & 4) != 0 {
        http_origin_slice.as_ptr()
    } else {
        core::ptr::null()
    };
    let http_referer_ptr = if (flags & 4) != 0 {
        http_referer_slice.as_ptr()
    } else {
        core::ptr::null()
    };
    let http_user_agent_ptr = if (flags & 4) != 0 {
        http_user_agent_slice.as_ptr()
    } else {
        core::ptr::null()
    };

    let mut req_len = 0usize;
    let rc = mtproto_build_rpc_proxy_req_ffi(
        flags,
        out_conn_id,
        remote_ipv6.as_ptr(),
        remote_port,
        our_ipv6.as_ptr(),
        our_port,
        proxy_tag_ptr,
        proxy_tag_slice.len(),
        http_origin_ptr,
        http_origin_slice.len(),
        http_referer_ptr,
        http_referer_slice.len(),
        http_user_agent_ptr,
        http_user_agent_slice.len(),
        payload.as_ptr(),
        payload.len(),
        core::ptr::null_mut(),
        0,
        &mut req_len,
    );
    if rc < 0 {
        return None;
    }
    if req_len > 0x7fff_ffffusize {
        return None;
    }

    let mut req = vec![0u8; req_len];
    let rc = mtproto_build_rpc_proxy_req_ffi(
        flags,
        out_conn_id,
        remote_ipv6.as_ptr(),
        remote_port,
        our_ipv6.as_ptr(),
        our_port,
        proxy_tag_ptr,
        proxy_tag_slice.len(),
        http_origin_ptr,
        http_origin_slice.len(),
        http_referer_ptr,
        http_referer_slice.len(),
        http_user_agent_ptr,
        http_user_agent_slice.len(),
        payload.as_ptr(),
        payload.len(),
        req.as_mut_ptr(),
        req.len(),
        &mut req_len,
    );
    if rc != 0 || req_len > 0x7fff_ffffusize {
        return None;
    }
    req.truncate(req_len);
    Some(req)
}

fn mtproto_forward_send_req(d: ConnectionJob, req: &[u8]) -> bool {
    let tlio_out = unsafe { c_tl_out_state_alloc() }.cast::<crate::tl_parse::abi::TlOutState>();
    if tlio_out.is_null() {
        return false;
    }
    unsafe {
        c_tls_init_tcp_raw_msg(tlio_out.cast(), 1, d, 0);
    }
    let req_len = c_int::try_from(req.len()).unwrap_or(c_int::MAX);
    unsafe {
        crate::tl_parse::abi::mtproxy_ffi_tl_store_raw_data(tlio_out, req.as_ptr().cast(), req_len);
    }
    let mut sent_kind = 0;
    unsafe {
        crate::tl_parse::abi::mtproxy_ffi_tl_store_end_ext(tlio_out, 0, &mut sent_kind);
        c_tl_out_state_free(tlio_out.cast());
    }
    true
}

fn mtproto_forward_mtproto_enc_packet_impl(
    tlio_in: *mut crate::tl_parse::abi::TlInState,
    c: ConnectionJob,
    auth_key_id: i64,
    len: c_int,
    remote_ip_port: *const c_int,
    rpc_flags: c_int,
) -> c_int {
    if len < ENCRYPTED_MESSAGE_MIN_LEN {
        return 0;
    }

    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return 0;
    }
    unsafe {
        (*conn).query_start_time = get_utime_monotonic();
    }
    let data = mtproto_rpc_data_ptr(c);
    if data.is_null() {
        return 0;
    }
    let target_dc = unsafe { (*data).extra_int4 };
    let s = mtproto_choose_proxy_target_impl(target_dc);

    let unread = unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_fetch_unread(tlio_in) };
    assert_eq!(unread, len);
    mtproto_forward_tcp_query_ffi(
        tlio_in.cast::<c_void>(),
        c,
        s,
        rpc_flags,
        auth_key_id,
        remote_ip_port,
        core::ptr::null(),
    )
}

pub(super) fn mtproto_forward_mtproto_packet_ffi(
    tlio_in: *mut c_void,
    c: ConnectionJob,
    len: c_int,
    remote_ip_port: *const c_int,
    rpc_flags: c_int,
) -> c_int {
    if tlio_in.is_null() || c.is_null() {
        return 0;
    }
    if len < 28 || (len & 3) != 0 {
        return 0;
    }
    let tlio_in = tlio_in.cast::<crate::tl_parse::abi::TlInState>();
    let mut header = [0u8; 28];
    let looked_up = unsafe {
        crate::tl_parse::abi::mtproxy_ffi_tl_fetch_lookup_data(
            tlio_in,
            header.as_mut_ptr().cast(),
            28,
        )
    };
    if looked_up != 28 {
        return 0;
    }

    let mut inspected = MtproxyMtprotoPacketInspectResult::default();
    let inspect_rc = mtproto_inspect_packet_header_ffi(
        header.as_ptr(),
        header.len(),
        len,
        core::ptr::addr_of_mut!(inspected),
    );
    if inspect_rc < 0 {
        return 0;
    }

    if inspected.kind == MTPROTO_PACKET_KIND_ENCRYPTED {
        return mtproto_forward_mtproto_enc_packet_impl(
            tlio_in,
            c,
            inspected.auth_key_id,
            len,
            remote_ip_port,
            rpc_flags,
        );
    }
    if inspected.kind != MTPROTO_PACKET_KIND_UNENCRYPTED_DH {
        return 0;
    }

    let data = mtproto_rpc_data_ptr(c);
    if data.is_null() {
        return 0;
    }
    let target_dc = unsafe { (*data).extra_int4 };
    let s = mtproto_choose_proxy_target_impl(target_dc);
    let unread = unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_fetch_unread(tlio_in) };
    assert_eq!(unread, len);
    mtproto_forward_tcp_query_ffi(
        tlio_in.cast::<c_void>(),
        c,
        s,
        2 | rpc_flags,
        0,
        remote_ip_port,
        core::ptr::null(),
    )
}

fn mtproto_notify_remote_closed(c: ConnectionJob, out_conn_id: i64) {
    if c.is_null() {
        return;
    }
    let tlio_out = unsafe { c_tl_out_state_alloc() }.cast::<crate::tl_parse::abi::TlOutState>();
    if tlio_out.is_null() {
        return;
    }
    let c_ref = unsafe { job_incref(c) };
    if c_ref.is_null() {
        unsafe { c_tl_out_state_free(tlio_out.cast()) };
        return;
    }
    unsafe {
        c_tls_init_tcp_raw_msg(tlio_out.cast(), 1, c_ref, 0);
        crate::tl_parse::abi::mtproxy_ffi_tl_store_int(
            tlio_out,
            mtproxy_core::runtime::mtproto::proxy::RPC_CLOSE_CONN,
        );
        crate::tl_parse::abi::mtproxy_ffi_tl_store_long(tlio_out, out_conn_id);
    }
    let mut sent_kind = 0;
    unsafe {
        crate::tl_parse::abi::mtproxy_ffi_tl_store_end_ext(tlio_out, 0, &mut sent_kind);
        c_tl_out_state_free(tlio_out.cast());
    }
}

fn mtproto_notify_remote_closed_owned(c: ConnectionJob, out_conn_id: i64) {
    if c.is_null() {
        return;
    }
    let tlio_out = unsafe { c_tl_out_state_alloc() }.cast::<crate::tl_parse::abi::TlOutState>();
    if tlio_out.is_null() {
        return;
    }
    unsafe {
        c_tls_init_tcp_raw_msg(tlio_out.cast(), 1, c, 0);
        crate::tl_parse::abi::mtproxy_ffi_tl_store_int(
            tlio_out,
            mtproxy_core::runtime::mtproto::proxy::RPC_CLOSE_CONN,
        );
        crate::tl_parse::abi::mtproxy_ffi_tl_store_long(tlio_out, out_conn_id);
    }
    let mut sent_kind = 0;
    unsafe {
        crate::tl_parse::abi::mtproxy_ffi_tl_store_end_ext(tlio_out, 0, &mut sent_kind);
        c_tl_out_state_free(tlio_out.cast());
    }
}

pub(super) fn mtproto_push_rpc_confirmation_runtime_ffi(
    c_tag_int: c_int,
    c: ConnectionJob,
    confirm: c_int,
) {
    if c.is_null() {
        return;
    }
    let d = mtproto_rpc_data_ptr(c);
    if d.is_null() {
        return;
    }
    if (unsafe { lrand48_j() } & 1) != 0 || (unsafe { (*d).flags } & RPC_F_PAD) == 0 {
        let msg = unsafe { libc::malloc(core::mem::size_of::<MtprotoRawMessage>()) }
            .cast::<MtprotoRawMessage>();
        if msg.is_null() {
            return;
        }
        let prefix = [0xdd_u8; 1];
        assert!(unsafe { rwm_create(msg, prefix.as_ptr().cast(), 1) } == 1);
        assert!(unsafe { rwm_push_data(msg, core::ptr::addr_of!(confirm).cast(), 4) } == 4);
        let conn = mtproto_conn_info_ptr(c);
        if conn.is_null() || unsafe { (*conn).out_queue.is_null() } {
            unsafe {
                rwm_free(msg);
                libc::free(msg.cast::<c_void>());
            }
            return;
        }
        unsafe {
            mtproxy_ffi_net_connections_mpq_push_w((*conn).out_queue, msg.cast(), 0);
            job_signal(c_tag_int, c, JS_RUN);
        }
        return;
    }

    let mut x = -1_i32;
    let mut m = MtprotoRawMessage::default();
    assert!(
        unsafe { rwm_create(core::ptr::addr_of_mut!(m), core::ptr::addr_of!(x).cast(), 4) } == 4
    );
    assert!(
        unsafe {
            rwm_push_data(
                core::ptr::addr_of_mut!(m),
                core::ptr::addr_of!(confirm).cast(),
                4,
            )
        } == 4
    );

    let mut z = unsafe { lrand48_j() } & 1;
    while z > 0 {
        let t = unsafe { lrand48_j() as c_int };
        assert!(
            unsafe { rwm_push_data(core::ptr::addr_of_mut!(m), core::ptr::addr_of!(t).cast(), 4) }
                == 4
        );
        z -= 1;
    }

    let c_ref = unsafe { job_incref(c) };
    if !c_ref.is_null() {
        unsafe {
            tcp_rpc_conn_send(1, c_ref, core::ptr::addr_of_mut!(m), 0);
        }
    }

    x = 0;
    assert!(
        unsafe { rwm_create(core::ptr::addr_of_mut!(m), core::ptr::addr_of!(x).cast(), 4) } == 4
    );

    z = unsafe { lrand48_j() } & 1;
    while z > 0 {
        let t = unsafe { lrand48_j() as c_int };
        assert!(
            unsafe { rwm_push_data(core::ptr::addr_of_mut!(m), core::ptr::addr_of!(t).cast(), 4) }
                == 4
        );
        z -= 1;
    }

    unsafe {
        tcp_rpc_conn_send(c_tag_int, c, core::ptr::addr_of_mut!(m), 0);
    }
}

pub(super) fn mtproto_process_client_packet_runtime_ffi(
    tlio_in: *mut c_void,
    c: ConnectionJob,
) -> c_int {
    if tlio_in.is_null() || c.is_null() {
        return 0;
    }
    let tlio_in = tlio_in.cast::<crate::tl_parse::abi::TlInState>();
    let len = unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_fetch_unread(tlio_in) };
    if len < 0 {
        return 0;
    }
    let payload_len = usize::try_from(len).unwrap_or(0);
    let mut payload = vec![0u8; payload_len];
    if len > 0 {
        let got = unsafe {
            crate::tl_parse::abi::mtproxy_ffi_tl_fetch_lookup_data(
                tlio_in,
                payload.as_mut_ptr().cast(),
                len,
            )
        };
        if got != len {
            return 0;
        }
    }

    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return 0;
    }
    let conn_fd = unsafe { (*conn).fd };
    let conn_gen = unsafe { (*conn).generation };
    let mut planned = MtproxyMtprotoClientPacketProcessResult::default();
    mtproto_process_client_packet_impl(&payload, conn_fd, conn_gen, &mut planned);

    match planned.kind {
        MTPROTO_CLIENT_PACKET_ACTION_PROXY_ANS_FORWARD => {
            if planned.payload_offset < 0 || planned.payload_offset > len {
                return 0;
            }
            if planned.payload_offset > 0 {
                unsafe {
                    crate::tl_parse::abi::mtproxy_ffi_tl_fetch_skip(
                        tlio_in,
                        planned.payload_offset,
                    );
                }
            }
            let d = unsafe { connection_get_by_fd_generation(planned.in_fd, planned.in_gen) };
            if !d.is_null() {
                unsafe {
                    tot_forwarded_responses = tot_forwarded_responses.wrapping_add(1);
                    mtproto_client_send_message_runtime_ffi(
                        1,
                        d,
                        planned.in_conn_id,
                        tlio_in.cast::<c_void>(),
                        planned.flags,
                    );
                }
            } else {
                unsafe {
                    dropped_responses = dropped_responses.wrapping_add(1);
                    mtproto_notify_remote_closed(c, planned.out_conn_id);
                }
            }
            1
        }
        MTPROTO_CLIENT_PACKET_ACTION_PROXY_ANS_NOTIFY_CLOSE => {
            unsafe {
                dropped_responses = dropped_responses.wrapping_add(1);
                mtproto_notify_remote_closed(c, planned.out_conn_id);
            }
            1
        }
        MTPROTO_CLIENT_PACKET_ACTION_SIMPLE_ACK_FORWARD => {
            let d = unsafe { connection_get_by_fd_generation(planned.in_fd, planned.in_gen) };
            if !d.is_null() {
                let mut confirm = planned.confirm;
                assert!(planned.in_conn_id == 0);
                let d_data = mtproto_rpc_data_ptr(d);
                if !d_data.is_null() && (unsafe { (*d_data).flags } & RPC_F_COMPACT) != 0 {
                    confirm = confirm.swap_bytes();
                }
                unsafe {
                    mtproto_push_rpc_confirmation_runtime_ffi(1, d, confirm);
                    tot_forwarded_simple_acks = tot_forwarded_simple_acks.wrapping_add(1);
                }
            } else {
                unsafe {
                    dropped_simple_acks = dropped_simple_acks.wrapping_add(1);
                    mtproto_notify_remote_closed(c, planned.out_conn_id);
                }
            }
            1
        }
        MTPROTO_CLIENT_PACKET_ACTION_SIMPLE_ACK_NOTIFY_CLOSE => {
            unsafe {
                dropped_simple_acks = dropped_simple_acks.wrapping_add(1);
                mtproto_notify_remote_closed(c, planned.out_conn_id);
            }
            1
        }
        MTPROTO_CLIENT_PACKET_ACTION_CLOSE_EXT_REMOVED => {
            assert!(planned.in_conn_id == 0);
            let ci = unsafe { connection_get_by_fd_generation(planned.in_fd, planned.in_gen) };
            if !ci.is_null() {
                unsafe {
                    fail_connection(ci, -33);
                    mtproto_job_decref(ci);
                }
            }
            1
        }
        MTPROTO_CLIENT_PACKET_ACTION_CLOSE_EXT_NOOP => 1,
        _ => 0,
    }
}

pub(super) fn mtproto_process_http_query_ffi(tlio_in: *mut c_void, hqj: *mut c_void) -> c_int {
    if tlio_in.is_null() || hqj.is_null() {
        return -404;
    }
    let tlio_in = tlio_in.cast::<crate::tl_parse::abi::TlInState>();
    let d = mtproto_http_query_info_ptr(hqj);
    if d.is_null() {
        return -404;
    }
    let c = unsafe { (*d).conn };
    if c.is_null() {
        return -404;
    }

    let header_size = unsafe { (*d).header_size };
    let first_line_size = unsafe { (*d).first_line_size };
    if header_size < 0 || first_line_size <= 0 || first_line_size > header_size {
        return -404;
    }
    let Some(header_len) = usize::try_from(header_size).ok() else {
        return -404;
    };
    let Some(first_line_len) = usize::try_from(first_line_size).ok() else {
        return -404;
    };
    let header_ptr = unsafe { core::ptr::addr_of_mut!((*d).header).cast::<u8>() };
    let Some(header) = (unsafe { slice_from_ptr(header_ptr, header_len) }) else {
        return -404;
    };
    let q_headers = &header[first_line_len..];
    let q_headers_len = header_size - first_line_size;
    let q_headers_ptr = q_headers.as_ptr().cast::<c_char>();

    let uri_offset = unsafe { (*d).uri_offset };
    let uri_size = unsafe { (*d).uri_size };
    if uri_offset < 0 || uri_size < 0 || uri_offset.saturating_add(uri_size) > header_size {
        return -404;
    }
    let Some(uri_offset_usize) = usize::try_from(uri_offset).ok() else {
        return -404;
    };
    let Some(uri_size_usize) = usize::try_from(uri_size).ok() else {
        return -404;
    };
    let q_uri = &header[uri_offset_usize..uri_offset_usize + uri_size_usize];
    let mut q_uri_len = q_uri.len();
    if let Some(pos) = q_uri.iter().position(|b| *b == b'?') {
        q_uri_len = pos;
    }

    if q_uri_len >= PROCESS_HTTP_URI_MAX_LEN {
        return -414;
    }

    if q_uri_len >= 4 && &q_uri[..4] == b"/api" {
        let mut query_flags = mtproto_http_query_flags_get(c);
        if q_uri_len >= 5 && q_uri[4] == b'w' {
            query_flags |= QF_EXTRA_HEADERS;
            unsafe {
                mtproto_http_query_flags_set(c, query_flags);
                extra_http_response_headers = mtproto_cors_http_headers;
            }
        } else {
            query_flags &= !QF_EXTRA_HEADERS;
            unsafe {
                mtproto_http_query_flags_set(c, query_flags);
            }
        }

        if unsafe { (*d).query_type } == HTQT_OPTIONS {
            let connection = if (query_flags & QF_KEEPALIVE) != 0 {
                "keep-alive"
            } else {
                "close"
            };
            let extra = if (query_flags & QF_EXTRA_HEADERS) != 0 {
                PROCESS_HTTP_OPTIONS_CORS_HEADERS
            } else {
                ""
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nConnection: {connection}\r\nContent-type: text/plain\r\nPragma: no-cache\r\nCache-control: no-store\r\n{extra}Content-length: 0\r\n\r\n"
            );
            let raw = unsafe { calloc(1, core::mem::size_of::<MtprotoRawMessage>()) }
                .cast::<MtprotoRawMessage>();
            if !raw.is_null() {
                let len = c_int::try_from(response.len()).unwrap_or(c_int::MAX);
                let rc = unsafe { rwm_create(raw, response.as_ptr().cast(), len) };
                if rc == len {
                    unsafe { http_flush(c, raw) };
                } else {
                    unsafe { free(raw.cast()) };
                }
            }
            return 0;
        }

        if (unsafe { (*d).data_size } & 3) != 0 {
            return -404;
        }

        unsafe {
            cur_http_origin_len = mtproxy_ffi_net_http_get_header(
                q_headers_ptr,
                q_headers_len,
                core::ptr::addr_of_mut!(cur_http_origin).cast::<c_char>(),
                1023,
                b"Origin\0".as_ptr().cast(),
                6,
            );
            cur_http_referer_len = mtproxy_ffi_net_http_get_header(
                q_headers_ptr,
                q_headers_len,
                core::ptr::addr_of_mut!(cur_http_referer).cast::<c_char>(),
                1023,
                b"Referer\0".as_ptr().cast(),
                7,
            );
            cur_http_user_agent_len = mtproxy_ffi_net_http_get_header(
                q_headers_ptr,
                q_headers_len,
                core::ptr::addr_of_mut!(cur_http_user_agent).cast::<c_char>(),
                1023,
                b"User-Agent\0".as_ptr().cast(),
                10,
            );
        }

        let mut tmp_ip_port = [0 as c_int; 5];
        let mut remote_ip_port = core::ptr::null::<c_int>();
        let conn = mtproto_conn_info_ptr(c);
        if conn.is_null() {
            return -404;
        }
        let remote_ip = unsafe { (*conn).remote_ip };
        if (remote_ip & 0xff00_0000) == 0x0a00_0000 || (remote_ip & 0xff00_0000) == 0x7f00_0000 {
            let mut x_real_ip = [0 as c_char; 64];
            let mut x_real_port = [0 as c_char; 16];
            let x_real_ip_len = unsafe {
                mtproxy_ffi_net_http_get_header(
                    q_headers_ptr,
                    q_headers_len,
                    x_real_ip.as_mut_ptr(),
                    c_int::try_from(x_real_ip.len().saturating_sub(1)).unwrap_or(c_int::MAX),
                    b"X-Real-IP\0".as_ptr().cast(),
                    9,
                )
            };
            let x_real_port_len = unsafe {
                mtproxy_ffi_net_http_get_header(
                    q_headers_ptr,
                    q_headers_len,
                    x_real_port.as_mut_ptr(),
                    c_int::try_from(x_real_port.len().saturating_sub(1)).unwrap_or(c_int::MAX),
                    b"X-Real-Port\0".as_ptr().cast(),
                    11,
                )
            };
            if x_real_ip_len > 0 {
                let mut real_ip = 0u32;
                let mut parsed_ipv6_len = -1;
                let parse_ipv4_rc = mtproto_parse_text_ipv4_ffi(x_real_ip.as_ptr(), &mut real_ip);
                let parse_ipv6_rc = mtproto_parse_text_ipv6_ffi(
                    x_real_ip.as_ptr(),
                    tmp_ip_port.as_mut_ptr().cast::<u8>(),
                    &mut parsed_ipv6_len,
                );
                if (parse_ipv4_rc == 0 && real_ip >= (1u32 << 24))
                    || (parse_ipv6_rc == 0 && parsed_ipv6_len > 0)
                {
                    if parse_ipv4_rc == 0 && real_ip >= (1u32 << 24) {
                        tmp_ip_port[0] = 0;
                        tmp_ip_port[1] = 0;
                        tmp_ip_port[2] = 0xffff_0000_u32 as c_int;
                        tmp_ip_port[3] = real_ip.to_be() as c_int;
                    }
                    let port = if x_real_port_len > 0 {
                        unsafe { libc::atoi(x_real_port.as_ptr()) }
                    } else {
                        0
                    };
                    tmp_ip_port[4] = if (1..65536).contains(&port) { port } else { 0 };
                    remote_ip_port = tmp_ip_port.as_ptr();
                }
            }
        }

        let res = mtproto_forward_mtproto_packet_ffi(
            tlio_in.cast::<c_void>(),
            c,
            unsafe { (*d).data_size },
            remote_ip_port,
            0,
        );
        return if res != 0 { 1 } else { -404 };
    }

    -404
}

pub(super) fn mtproto_callback_job_run_ffi(job: *mut c_void, op: c_int, _jt: *mut c_void) -> c_int {
    if job.is_null() {
        return JOB_ERROR;
    }
    let job_prefix = job.cast::<MtprotoAsyncJobPrefix>();
    let d = unsafe {
        (*job_prefix)
            .j_custom
            .as_ptr()
            .cast_mut()
            .cast::<MtprotoJobCallbackInfo>()
    };
    if d.is_null() {
        return JOB_ERROR;
    }

    match op {
        JS_RUN => {
            let Some(func) = (unsafe { (*d).func }) else {
                assert!(false);
                return JOB_ERROR;
            };
            let custom_bytes = unsafe { (*job_prefix).j_custom_bytes };
            let payload_offset =
                saturating_i32_from_usize(core::mem::size_of::<MtprotoJobCallbackFn>());
            assert!(custom_bytes >= payload_offset);
            let data_ptr = unsafe { d.cast::<u8>().add(payload_offset as usize).cast::<c_void>() };
            unsafe { func(data_ptr, custom_bytes - payload_offset) }
        }
        JS_FINISH => unsafe { job_free(1, job.cast::<c_void>()) },
        _ => {
            assert!(false);
            JOB_ERROR
        }
    }
}

unsafe extern "C" fn mtproto_callback_job_run_bridge(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    mtproto_callback_job_run_ffi(job, op, jt)
}

pub(super) fn mtproto_http_query_job_run_ffi(
    job: *mut c_void,
    op: c_int,
    _jt: *mut c_void,
) -> c_int {
    if job.is_null() {
        return JOB_ERROR;
    }
    let hq = mtproto_http_query_info_ptr(job);
    if hq.is_null() {
        return JOB_ERROR;
    }
    let job_prefix = job.cast::<MtprotoAsyncJobPrefix>();

    match op {
        JS_RUN => {
            let conn = unsafe { (*hq).conn };
            unsafe {
                mtproto_lru_insert_conn_local(conn);
            }
            let tlio_in =
                unsafe { c_tl_in_state_alloc() }.cast::<crate::tl_parse::abi::TlInState>();
            if tlio_in.is_null() {
                return JOB_COMPLETED;
            }
            unsafe {
                c_tlf_init_raw_message(
                    tlio_in.cast(),
                    core::ptr::addr_of_mut!((*hq).msg).cast(),
                    (*hq).msg.total_bytes,
                    0,
                );
            }
            let res = mtproto_process_http_query_ffi(tlio_in.cast::<c_void>(), job);
            unsafe {
                c_tl_in_state_free(tlio_in.cast());
            }
            assert!(unsafe { (*hq).msg.magic } == 0);
            if res < 0 {
                unsafe {
                    write_http_error((*hq).conn, -res);
                }
            } else if res > 0 {
                assert!((unsafe { (*hq).flags } & 1) != 0);
                unsafe {
                    (*hq).flags &= !1;
                }
            }
            JOB_COMPLETED
        }
        JS_ALARM => {
            if unsafe { (*job_prefix).j_error } == 0 {
                unsafe {
                    (*job_prefix).j_error = libc::ETIMEDOUT;
                }
            }
            JOB_COMPLETED
        }
        JS_ABORT => {
            if unsafe { (*job_prefix).j_error } == 0 {
                unsafe {
                    (*job_prefix).j_error = libc::ECANCELED;
                }
            }
            JOB_COMPLETED
        }
        JS_FINISH => {
            if (unsafe { (*hq).flags } & 1) != 0 {
                let c = if !unsafe { (*hq).conn }.is_null() {
                    unsafe { job_incref((*hq).conn) }
                } else {
                    unsafe { connection_get_by_fd_generation((*hq).conn_fd, (*hq).conn_generation) }
                };
                if !c.is_null() {
                    let c_conn = mtproto_conn_info_ptr(c);
                    if !c_conn.is_null() {
                        assert!(unsafe { (*c_conn).pending_queries } == 1);
                        unsafe {
                            (*c_conn).pending_queries -= 1;
                        }
                        let query_flags = mtproto_http_query_flags_get(c);
                        if (query_flags & QF_KEEPALIVE) == 0
                            && unsafe { (*c_conn).status } == CONN_STATUS_WORKING
                        {
                            unsafe {
                                connection_write_close(c);
                            }
                        }
                    }
                    mtproto_job_decref(c);
                }
                unsafe {
                    pending_http_queries -= 1;
                    (*hq).flags &= !1;
                }
            }
            if !unsafe { (*hq).conn }.is_null() {
                unsafe {
                    mtproto_job_decref((*hq).conn);
                }
            }
            if unsafe { (*hq).msg.magic } != 0 {
                unsafe {
                    rwm_free(core::ptr::addr_of_mut!((*hq).msg));
                }
            }
            unsafe { mtproxy_ffi_net_connections_job_free(job) }
        }
        _ => JOB_ERROR,
    }
}

unsafe extern "C" fn mtproto_http_query_job_run_bridge(
    job: ConnectionJob,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    mtproto_http_query_job_run_ffi(job.cast::<c_void>(), op, jt)
}

pub(super) fn mtproto_client_packet_job_run_ffi(
    job: *mut c_void,
    op: c_int,
    _jt: *mut c_void,
) -> c_int {
    if job.is_null() {
        return JOB_ERROR;
    }
    let d = mtproto_client_packet_info_ptr(job);
    if d.is_null() {
        return JOB_ERROR;
    }
    let job_prefix = job.cast::<MtprotoAsyncJobPrefix>();

    match op {
        JS_RUN => {
            let tlio_in =
                unsafe { c_tl_in_state_alloc() }.cast::<crate::tl_parse::abi::TlInState>();
            if !tlio_in.is_null() {
                unsafe {
                    c_tlf_init_raw_message(
                        tlio_in.cast(),
                        core::ptr::addr_of_mut!((*d).msg).cast(),
                        (*d).msg.total_bytes,
                        0,
                    );
                    mtproto_process_client_packet_runtime_ffi(tlio_in.cast::<c_void>(), (*d).conn);
                    c_tl_in_state_free(tlio_in.cast());
                }
            }
            JOB_COMPLETED
        }
        JS_ALARM => {
            if unsafe { (*job_prefix).j_error } == 0 {
                unsafe {
                    (*job_prefix).j_error = libc::ETIMEDOUT;
                }
            }
            JOB_COMPLETED
        }
        JS_ABORT => {
            if unsafe { (*job_prefix).j_error } == 0 {
                unsafe {
                    (*job_prefix).j_error = libc::ECANCELED;
                }
            }
            JOB_COMPLETED
        }
        JS_FINISH => {
            if !unsafe { (*d).conn }.is_null() {
                unsafe {
                    mtproto_job_decref((*d).conn);
                }
            }
            if unsafe { (*d).msg.magic } != 0 {
                unsafe {
                    rwm_free(core::ptr::addr_of_mut!((*d).msg));
                }
            }
            unsafe { mtproxy_ffi_net_connections_job_free(job.cast::<c_void>()) }
        }
        _ => JOB_ERROR,
    }
}

unsafe extern "C" fn mtproto_client_packet_job_run_bridge(
    job: ConnectionJob,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    mtproto_client_packet_job_run_ffi(job.cast::<c_void>(), op, jt)
}

pub(super) fn mtproto_rpcc_execute_ffi(c: ConnectionJob, op: c_int, msg: *mut c_void) -> c_int {
    if c.is_null() || msg.is_null() {
        return 0;
    }
    let msg = msg.cast::<MtprotoRawMessage>();
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return 0;
    }

    if unsafe { verbosity } >= 2 {
        unsafe {
            crate::kprintf_fmt!(
                b"rpcc_execute: fd=%d, op=%08x, len=%d\n\0".as_ptr().cast(),
                (*conn).fd,
                op,
                (*msg).total_bytes,
            );
        }
    }
    unsafe {
        (*conn).last_response_time = get_utime_monotonic();
    }

    match op {
        mtproxy_core::runtime::mtproto::proxy::RPC_PONG => {}
        mtproxy_core::runtime::mtproto::proxy::RPC_PROXY_ANS
        | mtproxy_core::runtime::mtproto::proxy::RPC_SIMPLE_ACK
        | mtproxy_core::runtime::mtproto::proxy::RPC_CLOSE_EXT => {
            let job_signals = JSP_PARENT_RWE
                | mtproto_jsc_allow(JC_ENGINE, JS_RUN)
                | mtproto_jsc_allow(JC_ENGINE, JS_ABORT)
                | mtproto_jsc_allow(JC_ENGINE, JS_ALARM)
                | mtproto_jsc_allow(JC_ENGINE, JS_FINISH);
            let custom_bytes =
                saturating_i32_from_usize(core::mem::size_of::<MtprotoClientPacketInfo>());
            let job = unsafe {
                create_async_job(
                    Some(mtproto_client_packet_job_run_bridge),
                    job_signals,
                    -2,
                    custom_bytes,
                    JT_HAVE_TIMER,
                    1,
                    core::ptr::null_mut(),
                )
            };
            assert!(!job.is_null());
            let d = mtproto_client_packet_info_ptr(job.cast::<c_void>());
            assert!(!d.is_null());

            unsafe {
                (*d).msg = *msg;
                (*d).conn = job_incref(c);
                schedule_job(1, job);
            }
            return 1;
        }
        _ => {
            if unsafe { verbosity } >= 1 {
                unsafe {
                    crate::kprintf_fmt!(
                        b"unknown RPC operation %08x, ignoring\n\0".as_ptr().cast(),
                        op,
                    );
                }
            }
        }
    }

    0
}

pub(super) fn mtproto_mtfront_client_ready_ffi(c: *mut c_void) -> c_int {
    unsafe {
        mtproto_check_thread_class_local(JC_ENGINE);
    }
    if c.is_null() {
        return 0;
    }
    let c = c.cast::<c_void>();
    let d = mtproto_rpc_data_ptr(c);
    let conn = mtproto_conn_info_ptr(c);
    if d.is_null() || conn.is_null() {
        return 0;
    }

    let fd = unsafe { (*conn).fd };
    assert!((fd as u32) < MAX_CONNECTIONS as u32);
    assert!(unsafe { (*d).extra_int == 0 });
    let tag = mtproto_conn_tag(c);
    assert!((tag as u32) > 0 && (tag as u32) <= 0x0100_0000);
    unsafe {
        (*d).extra_int = tag;
    }

    if unsafe { verbosity } >= 1 {
        unsafe {
            crate::kprintf_fmt!(
                b"Connected to RPC Middle-End (fd=%d)\n\0".as_ptr().cast(),
                fd,
            );
        }
    }
    unsafe {
        rpcc_exists = rpcc_exists.wrapping_add(1);
        (*conn).last_response_time = get_utime_monotonic();
    }
    0
}

pub(super) fn mtproto_mtfront_client_close_ffi(c: *mut c_void, _who: c_int) -> c_int {
    unsafe {
        mtproto_check_thread_class_local(JC_ENGINE);
    }
    if c.is_null() {
        return 0;
    }
    let c = c.cast::<c_void>();
    let d = mtproto_rpc_data_ptr(c);
    let conn = mtproto_conn_info_ptr(c);
    if d.is_null() || conn.is_null() {
        return 0;
    }

    let fd = unsafe { (*conn).fd };
    assert!((fd as u32) < MAX_CONNECTIONS as u32);

    if unsafe { verbosity } >= 1 {
        unsafe {
            crate::kprintf_fmt!(
                b"Disconnected from RPC Middle-End (fd=%d)\n\0"
                    .as_ptr()
                    .cast(),
                fd,
            );
        }
    }

    if unsafe { (*d).extra_int } != 0 {
        assert!(unsafe { (*d).extra_int == mtproto_conn_tag(c) });
        loop {
            let mut ex = MtproxyMtprotoExtConnection::default();
            let rc = mtproto_ext_conn_remove_any_by_out_fd_ffi(fd, &mut ex);
            assert!(rc >= 0);
            if rc <= 0 {
                break;
            }
            mtproto_notify_ext_connection_runtime_ffi(&ex, 2);
        }
    }
    unsafe {
        (*d).extra_int = 0;
    }
    0
}

pub(super) fn mtproto_do_close_in_ext_conn_ffi(data: *mut c_void, s_len: c_int) -> c_int {
    assert!(s_len == saturating_i32_from_usize(core::mem::size_of::<c_int>()));
    let fd_ptr = data.cast::<c_int>();
    assert!(!fd_ptr.is_null());
    let fd = unsafe { *fd_ptr };
    let mut ex = MtproxyMtprotoExtConnection::default();
    let rc = mtproto_ext_conn_get_by_in_fd_ffi(fd, &mut ex);
    assert!(rc >= 0);
    if rc > 0 {
        mtproto_remove_ext_connection_runtime_ffi(&ex, 1);
    }
    JOB_COMPLETED
}

unsafe extern "C" fn mtproto_do_close_in_ext_conn_bridge(data: *mut c_void, s_len: c_int) -> c_int {
    mtproto_do_close_in_ext_conn_ffi(data, s_len)
}

pub(super) fn mtproto_ext_rpc_ready_ffi(c: *mut c_void) -> c_int {
    if c.is_null() {
        return 0;
    }
    let c = c.cast::<c_void>();
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return 0;
    }
    let fd = unsafe { (*conn).fd };
    assert!((fd as u32) < MAX_CONNECTIONS as u32);
    if unsafe { verbosity } >= 1 {
        unsafe {
            crate::kprintf_fmt!(
                b"Client connected to proxy (fd=%d, %s:%d -> %s:%d)\n\0"
                    .as_ptr()
                    .cast(),
                fd,
                mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(c),
                (*conn).remote_port as c_int,
                mtproxy_ffi_net_tcp_rpc_ext_show_our_ip(c),
                (*conn).our_port as c_int,
            );
        }
    }
    if unsafe { verbosity } >= 3 {
        unsafe {
            crate::kprintf_fmt!(b"ext_rpc connection ready (%d)\n\0".as_ptr().cast(), fd);
        }
    }
    unsafe {
        mtproto_lru_insert_conn_local(c);
    }
    0
}

pub(super) fn mtproto_ext_rpc_close_ffi(c: *mut c_void, who: c_int) -> c_int {
    if c.is_null() {
        return 0;
    }
    let c = c.cast::<c_void>();
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return 0;
    }
    let fd = unsafe { (*conn).fd };
    assert!((fd as u32) < MAX_CONNECTIONS as u32);
    if unsafe { verbosity } >= 3 {
        unsafe {
            crate::kprintf_fmt!(
                b"ext_rpc connection closing (%d) by %d\n\0".as_ptr().cast(),
                fd,
                who,
            );
        }
    }
    let mut ex = MtproxyMtprotoExtConnection::default();
    let rc = mtproto_ext_conn_get_by_in_fd_ffi(fd, &mut ex);
    assert!(rc >= 0);
    if rc > 0 {
        mtproto_remove_ext_connection_runtime_ffi(&ex, 1);
    }
    0
}

pub(super) fn mtproto_proxy_rpc_ready_ffi(c: *mut c_void) -> c_int {
    unsafe {
        mtproto_check_thread_class_local(JC_ENGINE);
    }
    if c.is_null() {
        return 0;
    }
    let c = c.cast::<c_void>();
    let d = mtproto_rpc_data_ptr(c);
    let conn = mtproto_conn_info_ptr(c);
    if d.is_null() || conn.is_null() {
        return 0;
    }
    let fd = unsafe { (*conn).fd };
    assert!((fd as u32) < MAX_CONNECTIONS as u32);
    if unsafe { verbosity } >= 3 {
        unsafe {
            crate::kprintf_fmt!(b"proxy_rpc connection ready (%d)\n\0".as_ptr().cast(), fd);
        }
    }
    assert!(unsafe { (*d).extra_int == 0 });
    let tag = mtproto_conn_tag(c);
    assert!((tag as u32) > 0 && (tag as u32) <= 0x0100_0000);
    unsafe {
        (*d).extra_int = -tag;
        mtproto_lru_insert_conn_local(c);
    }
    0
}

pub(super) fn mtproto_http_close_ffi(c: *mut c_void, who: c_int) -> c_int {
    if c.is_null() {
        return 0;
    }
    let c = c.cast::<c_void>();
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return 0;
    }
    let fd = unsafe { (*conn).fd };
    assert!((fd as u32) < MAX_CONNECTIONS as u32);

    if unsafe { verbosity } >= 3 {
        unsafe {
            crate::kprintf_fmt!(
                b"http connection closing (%d) by %d, %d queries pending\n\0"
                    .as_ptr()
                    .cast(),
                fd,
                who,
                (*conn).pending_queries,
            );
        }
    }

    if unsafe { (*conn).pending_queries } != 0 {
        assert!(unsafe { (*conn).pending_queries == 1 });
        unsafe {
            pending_http_queries = pending_http_queries.wrapping_sub(1);
            (*conn).pending_queries = 0;
        }
    }

    let mut fd_copy = fd;
    unsafe {
        mtproto_schedule_job_callback_local(
            JC_ENGINE,
            Some(mtproto_do_close_in_ext_conn_bridge),
            core::ptr::addr_of_mut!(fd_copy).cast::<c_void>(),
            saturating_i32_from_usize(core::mem::size_of::<c_int>()),
        );
    }
    0
}

pub(super) fn mtproto_proxy_rpc_close_ffi(c: *mut c_void, who: c_int) -> c_int {
    unsafe {
        mtproto_check_thread_class_local(JC_ENGINE);
    }
    if c.is_null() {
        return 0;
    }
    let c = c.cast::<c_void>();
    let d = mtproto_rpc_data_ptr(c);
    let conn = mtproto_conn_info_ptr(c);
    if d.is_null() || conn.is_null() {
        return 0;
    }

    let fd = unsafe { (*conn).fd };
    assert!((fd as u32) < MAX_CONNECTIONS as u32);

    if unsafe { verbosity } >= 3 {
        unsafe {
            crate::kprintf_fmt!(
                b"proxy_rpc connection closing (%d) by %d\n\0"
                    .as_ptr()
                    .cast(),
                fd,
                who,
            );
        }
    }

    if unsafe { (*d).extra_int } != 0 {
        assert!(unsafe { (*d).extra_int == -mtproto_conn_tag(c) });
        loop {
            let mut ex = MtproxyMtprotoExtConnection::default();
            let rc = mtproto_ext_conn_remove_any_by_in_fd_ffi(fd, &mut ex);
            assert!(rc >= 0);
            if rc <= 0 {
                break;
            }
            mtproto_notify_ext_connection_runtime_ffi(&ex, 1);
        }
    }
    unsafe {
        (*d).extra_int = 0;
    }
    0
}

pub(super) fn mtproto_do_rpcs_execute_ffi(data: *mut c_void, s_len: c_int) -> c_int {
    assert!(s_len == saturating_i32_from_usize(core::mem::size_of::<MtprotoRpcsExecData>()));
    let data = data.cast::<MtprotoRpcsExecData>();
    assert!(!data.is_null());

    let conn = unsafe { (*data).conn };
    mtproto_lru_insert_conn_local(conn);

    let len = unsafe { (*data).msg.total_bytes };
    let tlio_in = unsafe { c_tl_in_state_alloc() }.cast::<crate::tl_parse::abi::TlInState>();
    assert!(!tlio_in.is_null());
    unsafe {
        c_tlf_init_raw_message(
            tlio_in.cast(),
            core::ptr::addr_of_mut!((*data).msg).cast(),
            len,
            0,
        );
    }

    let res = mtproto_forward_mtproto_packet_ffi(
        tlio_in.cast::<c_void>(),
        conn,
        len,
        core::ptr::null(),
        unsafe { (*data).rpc_flags },
    );
    unsafe {
        c_tl_in_state_free(tlio_in.cast());
        mtproto_job_decref(conn);
    }

    if res == 0 && unsafe { verbosity } >= 1 {
        unsafe {
            crate::kprintf_fmt!(b"ext_rpcs_execute: cannot forward mtproto packet\n\0"
                .as_ptr()
                .cast(),);
        }
    }
    JOB_COMPLETED
}

unsafe extern "C" fn mtproto_do_rpcs_execute_bridge(data: *mut c_void, s_len: c_int) -> c_int {
    mtproto_do_rpcs_execute_ffi(data, s_len)
}

pub(super) fn mtproto_ext_rpcs_execute_ffi(c: ConnectionJob, op: c_int, msg: *mut c_void) -> c_int {
    if c.is_null() || msg.is_null() {
        return 0;
    }
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return 0;
    }
    let msg = msg.cast::<MtprotoRawMessage>();
    let len = unsafe { (*msg).total_bytes };

    if unsafe { verbosity } >= 2 {
        unsafe {
            crate::kprintf_fmt!(
                b"ext_rpcs_execute: fd=%d, op=%08x, len=%d\n\0"
                    .as_ptr()
                    .cast(),
                (*conn).fd,
                op,
                len,
            );
        }
    }

    if len > MAX_POST_SIZE {
        if unsafe { verbosity } >= 1 {
            unsafe {
                crate::kprintf_fmt!(
                    b"ext_rpcs_execute: packet too long (%d bytes), skipping\n\0"
                        .as_ptr()
                        .cast(),
                    len,
                );
            }
        }
        return SKIP_ALL_BYTES;
    }

    if mtproto_check_conn_buffers_runtime_ffi(c) < 0 {
        return SKIP_ALL_BYTES;
    }

    let c_data = mtproto_rpc_data_ptr(c);
    assert!(!c_data.is_null());

    let mut data = MtprotoRpcsExecData::default();
    unsafe {
        rwm_move(core::ptr::addr_of_mut!(data.msg), msg);
        data.conn = job_incref(c);
        data.op = op;
        data.rpc_flags = (*c_data).flags
            & (RPC_F_QUICKACK | RPC_F_DROPPED | RPC_F_COMPACT_MEDIUM | RPC_F_EXTMODE3);
        mtproto_schedule_job_callback_local(
            JC_ENGINE,
            Some(mtproto_do_rpcs_execute_bridge),
            core::ptr::addr_of_mut!(data).cast::<c_void>(),
            saturating_i32_from_usize(core::mem::size_of::<MtprotoRpcsExecData>()),
        );
    }

    1
}

pub(super) fn mtproto_update_local_stats_copy_ffi(s: *mut c_void) {
    let s = s.cast::<MtprotoWorkerStats>();
    if s.is_null() {
        return;
    }

    unsafe {
        (*s).cnt = (*s).cnt.wrapping_add(1);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    unsafe {
        (*s).updated_at = libc::time(core::ptr::null_mut()) as c_int;
        fetch_tot_dh_rounds_stat((*s).tot_dh_rounds.as_mut_ptr());
        fetch_connections_stat(core::ptr::addr_of_mut!((*s).conn));
        fetch_aes_crypto_stat(
            core::ptr::addr_of_mut!((*s).allocated_aes_crypto),
            core::ptr::addr_of_mut!((*s).allocated_aes_crypto_temp),
        );
        fetch_buffers_stat(core::ptr::addr_of_mut!((*s).bufs));

        (*s).ev_heap_size = ev_heap_size;
        (*s).get_queries = get_queries;
        (*s).http_connections = http_connections;
        (*s).pending_http_queries = pending_http_queries;
        (*s).active_rpcs = active_rpcs;
        (*s).active_rpcs_created = active_rpcs_created;
        (*s).rpc_dropped_running = rpc_dropped_running;
        (*s).rpc_dropped_answers = rpc_dropped_answers;
        (*s).tot_forwarded_queries = tot_forwarded_queries;
        (*s).expired_forwarded_queries = expired_forwarded_queries;
        (*s).dropped_queries = dropped_queries;
        (*s).tot_forwarded_responses = tot_forwarded_responses;
        (*s).dropped_responses = dropped_responses;
        (*s).tot_forwarded_simple_acks = tot_forwarded_simple_acks;
        (*s).dropped_simple_acks = dropped_simple_acks;
        (*s).mtproto_proxy_errors = mtproto_proxy_errors;
        (*s).connections_failed_lru = connections_failed_lru;
        (*s).connections_failed_flood = connections_failed_flood;
    }

    let mut ext_connections = 0_i64;
    let mut ext_connections_created = 0_i64;
    if mtproto_ext_conn_counts_ffi(&mut ext_connections, &mut ext_connections_created) < 0 {
        ext_connections = 0;
        ext_connections_created = 0;
    }

    unsafe {
        (*s).ext_connections = ext_connections;
        (*s).ext_connections_created = ext_connections_created;
        (*s).http_queries = http_queries;
        (*s).http_bad_headers = http_bad_headers;
    }

    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    unsafe {
        (*s).cnt = (*s).cnt.wrapping_add(1);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

pub(super) fn mtproto_update_local_stats_ffi() {
    if unsafe { slave_mode } == 0 {
        return;
    }
    let base = unsafe { WStats };
    if base.is_null() {
        return;
    }
    let worker_index = unsafe { worker_id };
    if worker_index < 0 {
        return;
    }
    let worker_index = usize::try_from(worker_index).unwrap_or(0);
    let offset = worker_index.saturating_mul(2);
    unsafe {
        mtproto_update_local_stats_copy_ffi(base.add(offset).cast::<c_void>());
        mtproto_update_local_stats_copy_ffi(base.add(offset + 1).cast::<c_void>());
    }
}

fn mtproto_sig2int(sig: c_int) -> u64 {
    if sig == OUR_SIGRTMAX {
        1
    } else {
        1_u64 << u32::try_from(sig).unwrap_or(0)
    }
}

pub(super) fn mtproto_init_ct_server_mtfront_ffi() {
    unsafe {
        ct_http_server_mtfront = ct_http_server;
        ct_tcp_rpc_ext_server_mtfront = ct_tcp_rpc_ext_server;
        ct_tcp_rpc_server_mtfront = ct_tcp_rpc_server;
        ct_tcp_rpc_client_mtfront = ct_tcp_rpc_client;

        ct_http_server_mtfront.data_received = Some(mtproto_data_received_ffi);
        ct_tcp_rpc_ext_server_mtfront.data_received = Some(mtproto_data_received_ffi);
        ct_tcp_rpc_server_mtfront.data_received = Some(mtproto_data_received_ffi);

        ct_http_server_mtfront.data_sent = Some(mtproto_data_sent_ffi);
        ct_tcp_rpc_ext_server_mtfront.data_sent = Some(mtproto_data_sent_ffi);
        ct_tcp_rpc_server_mtfront.data_sent = Some(mtproto_data_sent_ffi);
    }
}

pub(super) fn mtproto_precise_cron_ffi() {
    mtproto_update_local_stats_ffi();
}

pub(super) unsafe extern "C" fn mtproto_on_child_termination_handler_ffi() {}

pub(super) unsafe extern "C" fn mtproto_data_received_ffi(
    _c: ConnectionJob,
    _bytes_received: c_int,
) -> c_int {
    0
}

pub(super) unsafe extern "C" fn mtproto_data_sent_ffi(
    _c: ConnectionJob,
    _bytes_sent: c_int,
) -> c_int {
    0
}

unsafe extern "C" fn mtproto_rpcc_execute_bridge(
    c: ConnectionJob,
    op: c_int,
    raw: *mut MtprotoRawMessage,
) -> c_int {
    mtproto_rpcc_execute_ffi(c, op, raw.cast::<c_void>())
}

unsafe extern "C" fn mtproto_mtfront_client_ready_bridge(c: ConnectionJob) -> c_int {
    mtproto_mtfront_client_ready_ffi(c)
}

unsafe extern "C" fn mtproto_mtfront_client_close_bridge(c: ConnectionJob, who: c_int) -> c_int {
    mtproto_mtfront_client_close_ffi(c, who)
}

unsafe extern "C" fn mtproto_hts_execute_bridge(
    c: ConnectionJob,
    raw: *mut MtprotoRawMessage,
    op: c_int,
) -> c_int {
    mtproto_hts_execute_ffi(c, raw.cast::<c_void>(), op)
}

unsafe extern "C" fn mtproto_hts_stats_execute_bridge(
    c: ConnectionJob,
    raw: *mut MtprotoRawMessage,
    op: c_int,
) -> c_int {
    mtproto_hts_stats_execute_ffi(c, raw.cast::<c_void>(), op)
}

unsafe extern "C" fn mtproto_http_alarm_bridge(c: ConnectionJob) -> c_int {
    mtproto_http_alarm_ffi(c)
}

unsafe extern "C" fn mtproto_http_close_bridge(c: ConnectionJob, who: c_int) -> c_int {
    mtproto_http_close_ffi(c, who)
}

unsafe extern "C" fn mtproto_ext_rpcs_execute_bridge(
    c: ConnectionJob,
    op: c_int,
    raw: *mut MtprotoRawMessage,
) -> c_int {
    mtproto_ext_rpcs_execute_ffi(c, op, raw.cast::<c_void>())
}

unsafe extern "C" fn mtproto_ext_rpc_ready_bridge(c: ConnectionJob) -> c_int {
    mtproto_ext_rpc_ready_ffi(c)
}

unsafe extern "C" fn mtproto_ext_rpc_close_bridge(c: ConnectionJob, who: c_int) -> c_int {
    mtproto_ext_rpc_close_ffi(c, who)
}

pub(super) fn mtproto_init_runtime_globals_ffi() {
    unsafe {
        mtfront_rpc_client = MtprotoTcpRpcClientFunctions {
            execute: mtproto_rpcc_execute_bridge as *mut c_void,
            check_ready: tcp_rpcc_default_check_ready as *mut c_void,
            flush_packet: tcp_rpc_flush_packet as *mut c_void,
            rpc_check_perm: tcp_rpcc_default_check_perm as *mut c_void,
            rpc_init_crypto: tcp_rpcc_init_crypto as *mut c_void,
            rpc_start_crypto: tcp_rpcc_start_crypto as *mut c_void,
            rpc_ready: mtproto_mtfront_client_ready_bridge as *mut c_void,
            rpc_close: mtproto_mtfront_client_close_bridge as *mut c_void,
            ..MtprotoTcpRpcClientFunctions::default()
        };

        http_methods = MtprotoHttpServerFunctions {
            execute: Some(mtproto_hts_execute_bridge),
            ht_alarm: Some(mtproto_http_alarm_bridge),
            ht_close: Some(mtproto_http_close_bridge),
            ..MtprotoHttpServerFunctions::default()
        };

        http_methods_stats = MtprotoHttpServerFunctions {
            execute: Some(mtproto_hts_stats_execute_bridge),
            ..MtprotoHttpServerFunctions::default()
        };

        ext_rpc_methods = MtprotoTcpRpcServerFunctions {
            execute: Some(mtproto_ext_rpcs_execute_bridge),
            check_ready: Some(server_check_ready),
            flush_packet: Some(tcp_rpc_flush_packet),
            rpc_ready: Some(mtproto_ext_rpc_ready_bridge),
            rpc_close: Some(mtproto_ext_rpc_close_bridge),
            max_packet_len: MAX_POST_SIZE,
            ..MtprotoTcpRpcServerFunctions::default()
        };

        default_cfg_ct.min_connections = default_cfg_min_connections;
        default_cfg_ct.max_connections = default_cfg_max_connections;
        default_cfg_ct.type_ = core::ptr::addr_of_mut!(ct_tcp_rpc_client_mtfront).cast::<c_void>();
        default_cfg_ct.extra = core::ptr::addr_of_mut!(mtfront_rpc_client).cast::<c_void>();
        default_cfg_ct.reconnect_timeout = 17.0;
    }
}

unsafe extern "C" fn mtproto_cron_bridge() {
    mtproto_cron_ffi();
}

unsafe extern "C" fn mtproto_precise_cron_bridge() {
    mtproto_precise_cron_ffi();
}

unsafe extern "C" fn mtproto_on_exit_bridge() {
    mtproto_mtfront_on_exit_ffi();
}

unsafe extern "C" fn mtproto_prepare_stats_bridge(sb: *mut MtprotoStatsBuffer) {
    mtproto_mtfront_prepare_stats_ffi(sb.cast::<c_void>());
}

unsafe extern "C" fn mtproto_prepare_parse_options_bridge() {
    mtproto_mtfront_prepare_parse_options_ffi();
}

unsafe extern "C" fn mtproto_parse_option_bridge(val: c_int) -> c_int {
    mtproto_f_parse_option_ffi(val)
}

unsafe extern "C" fn mtproto_parse_extra_args_bridge(argc: c_int, argv: *mut *mut c_char) {
    mtproto_mtfront_parse_extra_args_ffi(argc, argv);
}

unsafe extern "C" fn mtproto_pre_init_bridge() {
    mtproto_mtfront_pre_init_ffi();
}

unsafe extern "C" fn mtproto_pre_start_bridge() {
    mtproto_mtfront_pre_start_ffi();
}

unsafe extern "C" fn mtproto_pre_loop_bridge() {
    mtproto_mtfront_pre_loop_ffi();
}

unsafe extern "C" fn mtproto_parse_function_bridge(
    tlio_in: *mut c_void,
    actor_id: i64,
) -> *mut c_void {
    mtproto_mtfront_parse_function_runtime_ffi(tlio_in, actor_id)
}

unsafe extern "C" fn mtproto_sigusr1_handler_bridge() {
    mtproto_mtfront_sigusr1_handler_ffi();
}

pub(super) fn mtproto_setup_front_functions_ffi() {
    mtproto_init_runtime_globals_ffi();

    let mut f = MtprotoServerFunctions {
        cron: Some(mtproto_cron_bridge),
        precise_cron: Some(mtproto_precise_cron_bridge),
        on_exit: Some(mtproto_on_exit_bridge),
        on_waiting_exit: None,
        on_safe_quit: None,
        close_net_sockets: None,
        flags: ENGINE_NO_PORT,
        allowed_signals: 0,
        forbidden_signals: 0,
        default_modules: 0,
        default_modules_disabled: 0,
        prepare_stats: Some(mtproto_prepare_stats_bridge),
        prepare_parse_options: Some(mtproto_prepare_parse_options_bridge),
        parse_option: Some(mtproto_parse_option_bridge),
        parse_extra_args: Some(mtproto_parse_extra_args_bridge),
        pre_init: Some(mtproto_pre_init_bridge),
        pre_start: Some(mtproto_pre_start_bridge),
        pre_loop: Some(mtproto_pre_loop_bridge),
        run_script: None,
        full_version_str: unsafe { FullVersionStr },
        short_version_str: SHORT_VERSION_STR.as_ptr().cast::<c_char>(),
        epoll_timeout: 1,
        aio_timeout: 0.0,
        parse_function: Some(mtproto_parse_function_bridge),
        get_op: None,
        signal_handlers: [None; 65],
        custom_ops: core::ptr::null_mut(),
        tcp_methods: core::ptr::null_mut(),
        http_type: core::ptr::addr_of_mut!(ct_http_server),
        http_functions: core::ptr::addr_of_mut!(http_methods_stats).cast::<c_void>(),
        cron_subclass: 0,
        precise_cron_subclass: 0,
    };

    f.allowed_signals |= mtproto_sig2int(libc::SIGCHLD);
    if let Ok(sigchld_idx) = usize::try_from(libc::SIGCHLD) {
        if sigchld_idx < f.signal_handlers.len() {
            f.signal_handlers[sigchld_idx] = Some(mtproto_on_child_termination_handler_ffi);
        }
    }
    if let Ok(sigusr1_idx) = usize::try_from(libc::SIGUSR1) {
        if sigusr1_idx < f.signal_handlers.len() {
            f.signal_handlers[sigusr1_idx] = Some(mtproto_sigusr1_handler_bridge);
        }
    }

    unsafe {
        mtproto_front_functions = f;
    }
}

pub(super) fn mtproto_legacy_main_ffi(argc: c_int, argv: *mut *mut c_char) -> c_int {
    unsafe {
        mtproto_setup_front_functions_ffi();
        default_main(core::ptr::addr_of_mut!(mtproto_front_functions), argc, argv)
    }
}

pub(super) fn mtproto_check_all_conn_buffers_ffi() {
    let mut bufs = MtprotoBuffersStat::default();
    unsafe {
        fetch_buffers_stat(core::ptr::addr_of_mut!(bufs));
    }
    let max_buffer_memory = i64::from(bufs.max_buffer_chunks) * MSG_BUFFERS_CHUNK_SIZE;
    let mut to_free = bufs.total_used_buffers_size - max_buffer_memory * 3 / 4;
    while to_free > 0 {
        let mut ext = MtproxyMtprotoExtConnection::default();
        let pop_rc = mtproto_ext_conn_lru_pop_oldest_ffi(core::ptr::addr_of_mut!(ext));
        assert!(pop_rc >= 0);
        if pop_rc <= 0 {
            break;
        }
        if unsafe { verbosity } >= 2 {
            unsafe {
                crate::kprintf_fmt!(
                    b"check_all_conn_buffers(): closing connection %d because of %lld total used buffer vytes (%lld max, %lld bytes to free)\n\0"
                        .as_ptr()
                        .cast(),
                    ext.in_fd,
                    bufs.total_used_buffers_size,
                    max_buffer_memory,
                    to_free,
                );
            }
        }
        let d = unsafe { connection_get_by_fd_generation(ext.in_fd, ext.in_gen) };
        if !d.is_null() {
            let conn = mtproto_conn_info_ptr(d);
            if !conn.is_null() {
                let tot_used_bytes = unsafe {
                    (*conn).in_.total_bytes
                        + (*conn).in_u.total_bytes
                        + (*conn).out.total_bytes
                        + (*conn).out_p.total_bytes
                };
                to_free -= i64::from(tot_used_bytes) * 2;
            }
            unsafe {
                fail_connection(d, -500);
                mtproto_job_decref(d);
            }
        }
        unsafe {
            connections_failed_lru = connections_failed_lru.wrapping_add(1);
        }
    }
}

pub(super) fn mtproto_check_conn_buffers_runtime_ffi(c: *mut c_void) -> c_int {
    if c.is_null() {
        return -1;
    }
    let c = c.cast::<c_void>();
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return -1;
    }
    let tot_used_bytes = unsafe {
        (*conn).in_.total_bytes
            + (*conn).in_u.total_bytes
            + (*conn).out.total_bytes
            + (*conn).out_p.total_bytes
    };
    if tot_used_bytes > MAX_CONNECTION_BUFFER_SPACE {
        if unsafe { verbosity } >= 2 {
            unsafe {
                crate::kprintf_fmt!(
                    b"check_conn_buffers(): closing connection %d because of %d buffer bytes used (%d max)\n\0"
                        .as_ptr()
                        .cast(),
                    (*conn).fd,
                    tot_used_bytes,
                    MAX_CONNECTION_BUFFER_SPACE,
                );
            }
        }
        unsafe {
            fail_connection(c, -429);
            connections_failed_flood = connections_failed_flood.wrapping_add(1);
        }
        return -1;
    }
    0
}

pub(super) fn mtproto_add_stats_ffi(w: *mut c_void) {
    let w = w.cast::<MtprotoWorkerStats>();
    if w.is_null() {
        return;
    }

    unsafe {
        let w = &*w;
        SumStats.tot_dh_rounds[0] = SumStats.tot_dh_rounds[0].wrapping_add(w.tot_dh_rounds[0]);
        SumStats.tot_dh_rounds[1] = SumStats.tot_dh_rounds[1].wrapping_add(w.tot_dh_rounds[1]);
        SumStats.tot_dh_rounds[2] = SumStats.tot_dh_rounds[2].wrapping_add(w.tot_dh_rounds[2]);

        SumStats.conn.active_connections = SumStats
            .conn
            .active_connections
            .wrapping_add(w.conn.active_connections);
        SumStats.conn.active_dh_connections = SumStats
            .conn
            .active_dh_connections
            .wrapping_add(w.conn.active_dh_connections);
        SumStats.conn.outbound_connections = SumStats
            .conn
            .outbound_connections
            .wrapping_add(w.conn.outbound_connections);
        SumStats.conn.active_outbound_connections = SumStats
            .conn
            .active_outbound_connections
            .wrapping_add(w.conn.active_outbound_connections);
        SumStats.conn.ready_outbound_connections = SumStats
            .conn
            .ready_outbound_connections
            .wrapping_add(w.conn.ready_outbound_connections);
        SumStats.conn.active_special_connections = SumStats
            .conn
            .active_special_connections
            .wrapping_add(w.conn.active_special_connections);
        SumStats.conn.max_special_connections = SumStats
            .conn
            .max_special_connections
            .wrapping_add(w.conn.max_special_connections);
        SumStats.conn.allocated_connections = SumStats
            .conn
            .allocated_connections
            .wrapping_add(w.conn.allocated_connections);
        SumStats.conn.allocated_outbound_connections = SumStats
            .conn
            .allocated_outbound_connections
            .wrapping_add(w.conn.allocated_outbound_connections);
        SumStats.conn.allocated_inbound_connections = SumStats
            .conn
            .allocated_inbound_connections
            .wrapping_add(w.conn.allocated_inbound_connections);
        SumStats.conn.allocated_socket_connections = SumStats
            .conn
            .allocated_socket_connections
            .wrapping_add(w.conn.allocated_socket_connections);
        SumStats.conn.allocated_targets = SumStats
            .conn
            .allocated_targets
            .wrapping_add(w.conn.allocated_targets);
        SumStats.conn.ready_targets = SumStats
            .conn
            .ready_targets
            .wrapping_add(w.conn.ready_targets);
        SumStats.conn.active_targets = SumStats
            .conn
            .active_targets
            .wrapping_add(w.conn.active_targets);
        SumStats.conn.inactive_targets = SumStats
            .conn
            .inactive_targets
            .wrapping_add(w.conn.inactive_targets);
        SumStats.conn.tcp_readv_calls = SumStats
            .conn
            .tcp_readv_calls
            .wrapping_add(w.conn.tcp_readv_calls);
        SumStats.conn.tcp_readv_intr = SumStats
            .conn
            .tcp_readv_intr
            .wrapping_add(w.conn.tcp_readv_intr);
        SumStats.conn.tcp_readv_bytes = SumStats
            .conn
            .tcp_readv_bytes
            .wrapping_add(w.conn.tcp_readv_bytes);
        SumStats.conn.tcp_writev_calls = SumStats
            .conn
            .tcp_writev_calls
            .wrapping_add(w.conn.tcp_writev_calls);
        SumStats.conn.tcp_writev_intr = SumStats
            .conn
            .tcp_writev_intr
            .wrapping_add(w.conn.tcp_writev_intr);
        SumStats.conn.tcp_writev_bytes = SumStats
            .conn
            .tcp_writev_bytes
            .wrapping_add(w.conn.tcp_writev_bytes);
        SumStats.conn.accept_calls_failed = SumStats
            .conn
            .accept_calls_failed
            .wrapping_add(w.conn.accept_calls_failed);
        SumStats.conn.accept_nonblock_set_failed = SumStats
            .conn
            .accept_nonblock_set_failed
            .wrapping_add(w.conn.accept_nonblock_set_failed);
        SumStats.conn.accept_rate_limit_failed = SumStats
            .conn
            .accept_rate_limit_failed
            .wrapping_add(w.conn.accept_rate_limit_failed);
        SumStats.conn.accept_init_accepted_failed = SumStats
            .conn
            .accept_init_accepted_failed
            .wrapping_add(w.conn.accept_init_accepted_failed);

        SumStats.allocated_aes_crypto = SumStats
            .allocated_aes_crypto
            .wrapping_add(w.allocated_aes_crypto);
        SumStats.allocated_aes_crypto_temp = SumStats
            .allocated_aes_crypto_temp
            .wrapping_add(w.allocated_aes_crypto_temp);

        SumStats.bufs.total_used_buffers_size = SumStats
            .bufs
            .total_used_buffers_size
            .wrapping_add(w.bufs.total_used_buffers_size);
        SumStats.bufs.allocated_buffer_bytes = SumStats
            .bufs
            .allocated_buffer_bytes
            .wrapping_add(w.bufs.allocated_buffer_bytes);
        SumStats.bufs.total_used_buffers = SumStats
            .bufs
            .total_used_buffers
            .wrapping_add(w.bufs.total_used_buffers);
        SumStats.bufs.allocated_buffer_chunks = SumStats
            .bufs
            .allocated_buffer_chunks
            .wrapping_add(w.bufs.allocated_buffer_chunks);
        SumStats.bufs.max_allocated_buffer_chunks = SumStats
            .bufs
            .max_allocated_buffer_chunks
            .wrapping_add(w.bufs.max_allocated_buffer_chunks);
        SumStats.bufs.max_allocated_buffer_bytes = SumStats
            .bufs
            .max_allocated_buffer_bytes
            .wrapping_add(w.bufs.max_allocated_buffer_bytes);
        SumStats.bufs.max_buffer_chunks = SumStats
            .bufs
            .max_buffer_chunks
            .wrapping_add(w.bufs.max_buffer_chunks);
        SumStats.bufs.buffer_chunk_alloc_ops = SumStats
            .bufs
            .buffer_chunk_alloc_ops
            .wrapping_add(w.bufs.buffer_chunk_alloc_ops);

        SumStats.ev_heap_size = SumStats.ev_heap_size.wrapping_add(w.ev_heap_size);
        SumStats.get_queries = SumStats.get_queries.wrapping_add(w.get_queries);
        SumStats.http_connections = SumStats.http_connections.wrapping_add(w.http_connections);
        SumStats.pending_http_queries = SumStats
            .pending_http_queries
            .wrapping_add(w.pending_http_queries);
        SumStats.active_rpcs = SumStats.active_rpcs.wrapping_add(w.active_rpcs);
        SumStats.active_rpcs_created = SumStats
            .active_rpcs_created
            .wrapping_add(w.active_rpcs_created);
        SumStats.rpc_dropped_running = SumStats
            .rpc_dropped_running
            .wrapping_add(w.rpc_dropped_running);
        SumStats.rpc_dropped_answers = SumStats
            .rpc_dropped_answers
            .wrapping_add(w.rpc_dropped_answers);
        SumStats.tot_forwarded_queries = SumStats
            .tot_forwarded_queries
            .wrapping_add(w.tot_forwarded_queries);
        SumStats.expired_forwarded_queries = SumStats
            .expired_forwarded_queries
            .wrapping_add(w.expired_forwarded_queries);
        SumStats.dropped_queries = SumStats.dropped_queries.wrapping_add(w.dropped_queries);
        SumStats.tot_forwarded_responses = SumStats
            .tot_forwarded_responses
            .wrapping_add(w.tot_forwarded_responses);
        SumStats.dropped_responses = SumStats.dropped_responses.wrapping_add(w.dropped_responses);
        SumStats.tot_forwarded_simple_acks = SumStats
            .tot_forwarded_simple_acks
            .wrapping_add(w.tot_forwarded_simple_acks);
        SumStats.dropped_simple_acks = SumStats
            .dropped_simple_acks
            .wrapping_add(w.dropped_simple_acks);
        SumStats.mtproto_proxy_errors = SumStats
            .mtproto_proxy_errors
            .wrapping_add(w.mtproto_proxy_errors);
        SumStats.connections_failed_lru = SumStats
            .connections_failed_lru
            .wrapping_add(w.connections_failed_lru);
        SumStats.connections_failed_flood = SumStats
            .connections_failed_flood
            .wrapping_add(w.connections_failed_flood);
        SumStats.ext_connections = SumStats.ext_connections.wrapping_add(w.ext_connections);
        SumStats.ext_connections_created = SumStats
            .ext_connections_created
            .wrapping_add(w.ext_connections_created);
        SumStats.http_queries = SumStats.http_queries.wrapping_add(w.http_queries);
        SumStats.http_bad_headers = SumStats.http_bad_headers.wrapping_add(w.http_bad_headers);
    }
}

pub(super) fn mtproto_compute_stats_sum_ffi() {
    if unsafe { workers } == 0 {
        return;
    }

    unsafe {
        SumStats = MtprotoWorkerStats::default();
    }

    let workers_count = usize::try_from(unsafe { workers }).unwrap_or(0);
    let mut i = 0_usize;
    while i < workers_count {
        let mut w = MtprotoWorkerStats::default();
        let mut f: *mut MtprotoWorkerStats;
        let mut s_cnt: c_int;
        loop {
            f = unsafe { WStats.add(i.saturating_mul(2)) };
            loop {
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                f = unsafe { f.add(1) };
                s_cnt = unsafe { (*f).cnt };
                if (s_cnt & 1) == 0 {
                    break;
                }
                f = unsafe { f.sub(1) };
                s_cnt = unsafe { (*f).cnt };
                if (s_cnt & 1) == 0 {
                    break;
                }
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            unsafe {
                core::ptr::copy_nonoverlapping(f, core::ptr::addr_of_mut!(w), 1);
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            if s_cnt == unsafe { (*f).cnt } {
                break;
            }
        }
        unsafe {
            mtproto_add_stats_ffi(core::ptr::addr_of_mut!(w).cast::<c_void>());
        }
        i += 1;
    }
}

pub(super) fn mtproto_mtfront_prepare_stats_ffi(sb: *mut c_void) {
    let sb = sb.cast::<MtprotoStatsBuffer>();
    if sb.is_null() {
        return;
    }

    let cur_conf = unsafe { CurConf };
    if cur_conf.is_null() {
        return;
    }

    let mut conn = MtprotoConnectionsStat::default();
    let mut bufs = MtprotoBuffersStat::default();
    let mut tot_dh_rounds = [0_i64; 3];
    let mut allocated_aes_crypto = 0;
    let mut allocated_aes_crypto_temp = 0;
    let now_unix = unsafe { libc::time(core::ptr::null_mut()) } as c_int;
    let uptime = now_unix.wrapping_sub(unsafe { start_time });
    let mut ext_connections = 0_i64;
    let mut ext_connections_created = 0_i64;

    unsafe {
        mtproto_compute_stats_sum_ffi();
        fetch_connections_stat(&mut conn);
        fetch_buffers_stat(&mut bufs);
        fetch_tot_dh_rounds_stat(tot_dh_rounds.as_mut_ptr());
        fetch_aes_crypto_stat(&mut allocated_aes_crypto, &mut allocated_aes_crypto_temp);
    }
    if mtproto_ext_conn_counts_ffi(&mut ext_connections, &mut ext_connections_created) < 0 {
        ext_connections = 0;
        ext_connections_created = 0;
    }

    unsafe {
        sb_prepare(sb);
        sb_memory(sb, AM_GET_MEMORY_USAGE_SELF);
    }

    let use_worker_totals = unsafe { workers != 0 };
    let total_get_queries = unsafe { get_queries.wrapping_add(SumStats.get_queries) };
    let total_http_queries = unsafe { http_queries.wrapping_add(SumStats.http_queries) };

    let total_ready_targets = if use_worker_totals {
        unsafe { SumStats.conn.ready_targets }
    } else {
        conn.ready_targets
            .wrapping_add(unsafe { SumStats.conn.ready_targets })
    };
    let total_allocated_targets = if use_worker_totals {
        unsafe { SumStats.conn.allocated_targets }
    } else {
        conn.allocated_targets
            .wrapping_add(unsafe { SumStats.conn.allocated_targets })
    };
    let total_declared_targets = if use_worker_totals {
        unsafe { SumStats.conn.active_targets }
    } else {
        conn.active_targets
            .wrapping_add(unsafe { SumStats.conn.active_targets })
    };
    let total_inactive_targets = if use_worker_totals {
        unsafe { SumStats.conn.inactive_targets }
    } else {
        conn.inactive_targets
            .wrapping_add(unsafe { SumStats.conn.inactive_targets })
    };
    let total_special_connections = if use_worker_totals {
        unsafe { SumStats.conn.active_special_connections }
    } else {
        conn.active_special_connections
            .wrapping_add(unsafe { SumStats.conn.active_special_connections })
    };
    let total_max_special_connections = if use_worker_totals {
        unsafe { SumStats.conn.max_special_connections }
    } else {
        conn.max_special_connections
            .wrapping_add(unsafe { SumStats.conn.max_special_connections })
    };
    let total_network_buffers_used_size = if use_worker_totals {
        unsafe { SumStats.bufs.total_used_buffers_size }
    } else {
        bufs.total_used_buffers_size
            .wrapping_add(unsafe { SumStats.bufs.total_used_buffers_size })
    };
    let total_network_buffers_allocated_bytes = if use_worker_totals {
        unsafe { SumStats.bufs.allocated_buffer_bytes }
    } else {
        bufs.allocated_buffer_bytes
            .wrapping_add(unsafe { SumStats.bufs.allocated_buffer_bytes })
    };
    let total_network_buffers_used = if use_worker_totals {
        unsafe { SumStats.bufs.total_used_buffers }
    } else {
        bufs.total_used_buffers
            .wrapping_add(unsafe { SumStats.bufs.total_used_buffers })
    };
    let total_network_buffer_chunks_allocated = if use_worker_totals {
        unsafe { SumStats.bufs.allocated_buffer_chunks }
    } else {
        bufs.allocated_buffer_chunks
            .wrapping_add(unsafe { SumStats.bufs.allocated_buffer_chunks })
    };
    let total_network_buffer_chunks_allocated_max = if use_worker_totals {
        unsafe { SumStats.bufs.max_allocated_buffer_chunks }
    } else {
        bufs.max_allocated_buffer_chunks
            .wrapping_add(unsafe { SumStats.bufs.max_allocated_buffer_chunks })
    };
    let cfg_filename = unsafe {
        if config_filename.is_null() {
            b"\0".as_ptr().cast::<c_char>()
        } else {
            config_filename.cast_const()
        }
    };
    let cfg_md5 = unsafe {
        if (*cur_conf).config_md5_hex.is_null() {
            b"\0".as_ptr().cast::<c_char>()
        } else {
            (*cur_conf).config_md5_hex.cast_const()
        }
    };

    unsafe {
        crate::sb_printf_fmt!(
            sb,
            b"config_filename\t%s\n\
config_loaded_at\t%d\n\
config_size\t%d\n\
config_md5\t%s\n\
config_auth_clusters\t%d\n\
workers\t%d\n\
queries_get\t%lld\n\
qps_get\t%.3f\n\
tot_forwarded_queries\t%lld\n\
expired_forwarded_queries\t%lld\n\
dropped_queries\t%lld\n\
tot_forwarded_responses\t%lld\n\
dropped_responses\t%lld\n\
tot_forwarded_simple_acks\t%lld\n\
dropped_simple_acks\t%lld\n\
active_rpcs_created\t%lld\n\
active_rpcs\t%lld\n\
rpc_dropped_answers\t%lld\n\
rpc_dropped_running\t%lld\n\
window_clamp\t%d\n\
total_ready_targets\t%d\n\
total_allocated_targets\t%d\n\
total_declared_targets\t%d\n\
total_inactive_targets\t%d\n\
total_connections\t%d\n\
total_encrypted_connections\t%d\n\
total_allocated_connections\t%d\n\
total_allocated_outbound_connections\t%d\n\
total_allocated_inbound_connections\t%d\n\
total_allocated_socket_connections\t%d\n\
total_dh_connections\t%d\n\
total_dh_rounds\t%lld %lld %lld\n\
total_special_connections\t%d\n\
total_max_special_connections\t%d\n\
total_accept_connections_failed\t%lld %lld %lld %lld %lld\n\
ext_connections\t%lld\n\
ext_connections_created\t%lld\n\
total_active_network_events\t%d\n\
total_network_buffers_used_size\t%lld\n\
total_network_buffers_allocated_bytes\t%lld\n\
total_network_buffers_used\t%d\n\
total_network_buffer_chunks_allocated\t%d\n\
total_network_buffer_chunks_allocated_max\t%d\n\
mtproto_proxy_errors\t%lld\n\
connections_failed_lru\t%lld\n\
connections_failed_flood\t%lld\n\
http_connections\t%d\n\
pending_http_queries\t%d\n\
http_queries\t%lld\n\
http_bad_headers\t%lld\n\
http_qps\t%.6f\n\
proxy_mode\t%d\n\
proxy_tag_set\t%d\n\0"
                .as_ptr()
                .cast(),
            cfg_filename,
            (*cur_conf).config_loaded_at,
            (*cur_conf).config_bytes,
            cfg_md5,
            (*cur_conf).auth_stats.tot_clusters,
            workers,
            total_get_queries,
            mtproto_safe_div(total_get_queries as f64, f64::from(uptime)),
            tot_forwarded_queries.wrapping_add(SumStats.tot_forwarded_queries),
            expired_forwarded_queries.wrapping_add(SumStats.expired_forwarded_queries),
            dropped_queries.wrapping_add(SumStats.dropped_queries),
            tot_forwarded_responses.wrapping_add(SumStats.tot_forwarded_responses),
            dropped_responses.wrapping_add(SumStats.dropped_responses),
            tot_forwarded_simple_acks.wrapping_add(SumStats.tot_forwarded_simple_acks),
            dropped_simple_acks.wrapping_add(SumStats.dropped_simple_acks),
            active_rpcs_created.wrapping_add(SumStats.active_rpcs_created),
            active_rpcs.wrapping_add(SumStats.active_rpcs),
            rpc_dropped_answers.wrapping_add(SumStats.rpc_dropped_answers),
            rpc_dropped_running.wrapping_add(SumStats.rpc_dropped_running),
            window_clamp,
            total_ready_targets,
            total_allocated_targets,
            total_declared_targets,
            total_inactive_targets,
            conn.active_connections
                .wrapping_add(SumStats.conn.active_connections),
            allocated_aes_crypto.wrapping_add(SumStats.allocated_aes_crypto),
            conn.allocated_connections
                .wrapping_add(SumStats.conn.allocated_connections),
            conn.allocated_outbound_connections
                .wrapping_add(SumStats.conn.allocated_outbound_connections),
            conn.allocated_inbound_connections
                .wrapping_add(SumStats.conn.allocated_inbound_connections),
            conn.allocated_socket_connections
                .wrapping_add(SumStats.conn.allocated_socket_connections),
            conn.active_dh_connections
                .wrapping_add(SumStats.conn.active_dh_connections),
            tot_dh_rounds[0].wrapping_add(SumStats.tot_dh_rounds[0]),
            tot_dh_rounds[1].wrapping_add(SumStats.tot_dh_rounds[1]),
            tot_dh_rounds[2].wrapping_add(SumStats.tot_dh_rounds[2]),
            total_special_connections,
            total_max_special_connections,
            conn.accept_init_accepted_failed
                .wrapping_add(SumStats.conn.accept_init_accepted_failed),
            conn.accept_calls_failed
                .wrapping_add(SumStats.conn.accept_calls_failed),
            conn.accept_connection_limit_failed
                .wrapping_add(SumStats.conn.accept_connection_limit_failed),
            conn.accept_rate_limit_failed
                .wrapping_add(SumStats.conn.accept_rate_limit_failed),
            conn.accept_nonblock_set_failed
                .wrapping_add(SumStats.conn.accept_nonblock_set_failed),
            ext_connections.wrapping_add(SumStats.ext_connections),
            ext_connections_created.wrapping_add(SumStats.ext_connections_created),
            ev_heap_size.wrapping_add(SumStats.ev_heap_size),
            total_network_buffers_used_size,
            total_network_buffers_allocated_bytes,
            total_network_buffers_used,
            total_network_buffer_chunks_allocated,
            total_network_buffer_chunks_allocated_max,
            mtproto_proxy_errors.wrapping_add(SumStats.mtproto_proxy_errors),
            connections_failed_lru.wrapping_add(SumStats.connections_failed_lru),
            connections_failed_flood.wrapping_add(SumStats.connections_failed_flood),
            http_connections.wrapping_add(SumStats.http_connections),
            pending_http_queries.wrapping_add(SumStats.pending_http_queries),
            total_http_queries,
            http_bad_headers.wrapping_add(SumStats.http_bad_headers),
            mtproto_safe_div(total_http_queries as f64, f64::from(uptime)),
            proxy_mode,
            proxy_tag_set,
        );
        crate::sb_printf_fmt!(sb, b"version\t%s\n\0".as_ptr().cast(), FullVersionStr,);
    }
}

pub(super) fn mtproto_hts_stats_execute_ffi(c: *mut c_void, msg: *mut c_void, _op: c_int) -> c_int {
    let c = c.cast::<c_void>();
    let msg = msg.cast::<MtprotoRawMessage>();
    if c.is_null() || msg.is_null() {
        return -501;
    }
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return -501;
    }

    if mtproto_check_conn_buffers_runtime_ffi(c) < 0 {
        return -429;
    }

    let remote_ip = unsafe { (*conn).remote_ip };
    let remote_ip_host = u32::from_be(remote_ip);
    if (remote_ip & 0xff00_0000) != 0x7f00_0000 && (remote_ip_host & 0xff00_0000) != 0x7f00_0000 {
        return -404;
    }

    let total_bytes = unsafe { (*msg).total_bytes };
    if total_bytes <= 0 {
        return -501;
    }
    let header_size = total_bytes.min(MAX_HTTP_HEADER_SIZE);
    if header_size <= 0 {
        return -404;
    }
    let mut req_hdr = [0_u8; MAX_HTTP_HEADER_SIZE as usize];
    if unsafe { rwm_fetch_data(msg, req_hdr.as_mut_ptr().cast(), header_size) } != header_size {
        return -404;
    }

    let header_size_usize = usize::try_from(header_size).unwrap_or(0);
    let first_line_end = req_hdr[..header_size_usize]
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(header_size_usize);
    let first_line = &req_hdr[..first_line_end];
    let is_stats_get = first_line == b"GET /stats"
        || first_line.starts_with(b"GET /stats ")
        || first_line.starts_with(b"GET /stats?");
    if !is_stats_get {
        return -404;
    }

    let mut sb = MtprotoStatsBuffer {
        buff: core::ptr::null_mut(),
        pos: 0,
        size: 0,
        flags: 0,
    };
    unsafe {
        sb_alloc(core::ptr::addr_of_mut!(sb), 1 << 20);
        mtproto_mtfront_prepare_stats_ffi(core::ptr::addr_of_mut!(sb).cast::<c_void>());
    }

    let raw = unsafe { libc::calloc(1, core::mem::size_of::<MtprotoRawMessage>()) }
        .cast::<MtprotoRawMessage>();
    if raw.is_null() {
        unsafe {
            sb_release(core::ptr::addr_of_mut!(sb));
        }
        return -500;
    }
    unsafe {
        rwm_init(raw, 0);
        write_basic_http_header_raw(
            c,
            raw,
            200,
            0,
            sb.pos,
            core::ptr::null(),
            b"text/plain\0".as_ptr().cast(),
        );
        assert!(rwm_push_data(raw, sb.buff.cast(), sb.pos) == sb.pos);
        assert!(!(*conn).out_queue.is_null());
        mtproxy_ffi_net_connections_mpq_push_w((*conn).out_queue, raw.cast(), 0);
        job_signal(1, job_incref(c), JS_RUN);
        sb_release(core::ptr::addr_of_mut!(sb));
    }

    0
}

pub(super) fn mtproto_hts_execute_ffi(c: *mut c_void, msg: *mut c_void, op: c_int) -> c_int {
    let c = c.cast::<c_void>();
    let msg = msg.cast::<MtprotoRawMessage>();
    if c.is_null() || msg.is_null() {
        return 0;
    }
    let d = mtproto_hts_data_ptr(c);
    let conn = mtproto_conn_info_ptr(c);
    if d.is_null() || conn.is_null() {
        return 0;
    }

    // Serve local stats from the main HTTP execute path as well, so it works
    // even if runtime fallback wiring selects generic mtproto HTTP callbacks.
    if op == HTQT_GET {
        let stats_rc = mtproto_hts_stats_execute_ffi(c, msg.cast::<c_void>(), op);
        if stats_rc != -404 && stats_rc != -501 {
            return stats_rc;
        }
    }

    unsafe {
        crate::kprintf_fmt!(
            b"in hts_execute: connection #%d, op=%d, header_size=%d, data_size=%d, http_version=%d\n\0"
                .as_ptr()
                .cast(),
            (*conn).fd,
            op,
            (*d).header_size,
            (*d).data_size,
            (*d).http_ver,
        );
        rwm_dump(msg);
    }

    let hard_fail_now = core::hint::black_box(true);
    if hard_fail_now {
        unsafe {
            fail_connection(c, -1);
        }
        return 0;
    }

    if mtproto_check_conn_buffers_runtime_ffi(c) < 0 {
        return -429;
    }
    if unsafe { (*d).data_size } >= MAX_POST_SIZE {
        return -413;
    }

    if !((unsafe { (*d).query_type } == HTQT_POST && unsafe { (*d).data_size } > 0)
        || (unsafe { (*d).query_type } == HTQT_OPTIONS && unsafe { (*d).data_size } < 0))
    {
        unsafe {
            (*d).query_flags &= !QF_KEEPALIVE;
        }
        return -501;
    }

    if unsafe { (*d).data_size } < 0 {
        unsafe {
            (*d).data_size = 0;
        }
    }

    if unsafe {
        (*d).uri_size > 14 || (*d).header_size > MAX_HTTP_HEADER_SIZE || (*d).header_size < 0
    } {
        return -414;
    }

    if unsafe { (*d).data_size } > 0 {
        let need_bytes = unsafe { (*d).data_size + (*d).header_size - (*msg).total_bytes };
        if need_bytes > 0 {
            unsafe {
                crate::kprintf_fmt!(
                    b"-- need %d more bytes, waiting\n\0".as_ptr().cast(),
                    need_bytes,
                );
            }
            return need_bytes;
        }
    }

    assert!(unsafe { (*msg).total_bytes } == unsafe { (*d).header_size + (*d).data_size });

    let job_signals = JSP_PARENT_RWE
        | mtproto_jsc_allow(JC_ENGINE, JS_RUN)
        | mtproto_jsc_allow(JC_ENGINE, JS_ABORT)
        | mtproto_jsc_allow(JC_ENGINE, JS_ALARM)
        | mtproto_jsc_allow(JC_CONNECTION, JS_FINISH);
    let custom_bytes = core::mem::size_of::<MtprotoHttpQueryInfo>()
        .saturating_add(usize::try_from(unsafe { (*d).header_size }).unwrap_or(0))
        .saturating_add(1);
    let job = unsafe {
        create_async_job(
            Some(mtproto_http_query_job_run_bridge),
            job_signals,
            -2,
            saturating_i32_from_usize(custom_bytes),
            JT_HAVE_TIMER,
            1,
            core::ptr::null_mut(),
        )
    };
    assert!(!job.is_null());
    let hq = mtproto_http_query_info_ptr(job.cast());
    assert!(!hq.is_null());

    unsafe {
        rwm_clone(core::ptr::addr_of_mut!((*hq).msg), msg);
        (*hq).conn = job_incref(c);
        (*hq).conn_fd = (*conn).fd;
        (*hq).conn_generation = (*conn).generation;
        (*hq).flags = 1;
        assert!((*conn).pending_queries == 0);
        (*conn).pending_queries = (*conn).pending_queries.wrapping_add(1);
        pending_http_queries = pending_http_queries.wrapping_add(1);
        (*hq).query_type = (*d).query_type;
        (*hq).header_size = (*d).header_size;
        (*hq).data_size = (*d).data_size;
        (*hq).first_line_size = (*d).first_line_size;
        (*hq).host_offset = (*d).host_offset;
        (*hq).host_size = (*d).host_size;
        (*hq).uri_offset = (*d).uri_offset;
        (*hq).uri_size = (*d).uri_size;
        let header_ptr = core::ptr::addr_of_mut!((*hq).header).cast::<c_char>();
        assert!(
            rwm_fetch_data(
                core::ptr::addr_of_mut!((*hq).msg),
                header_ptr.cast(),
                (*hq).header_size,
            ) == (*hq).header_size
        );
        *header_ptr.add(usize::try_from((*hq).header_size).unwrap_or(0)) = 0;
        assert!((*hq).msg.total_bytes == (*hq).data_size);
        schedule_job(1, job);
    }

    0
}

pub(super) fn mtproto_http_alarm_ffi(c: *mut c_void) -> c_int {
    if c.is_null() {
        return 0;
    }
    let c = c.cast::<c_void>();
    let conn = mtproto_conn_info_ptr(c);
    let d = mtproto_hts_data_ptr(c);
    if conn.is_null() || d.is_null() {
        return 0;
    }

    if unsafe { verbosity } >= 2 {
        unsafe {
            crate::kprintf_fmt!(
                b"http_alarm() for connection %d\n\0".as_ptr().cast(),
                (*conn).fd,
            );
        }
    }

    assert!(unsafe { (*conn).status == CONN_STATUS_WORKING });
    unsafe {
        (*d).query_flags &= !QF_KEEPALIVE;
        write_http_error(c, 500);
    }

    if unsafe { (*conn).pending_queries } != 0 {
        assert!(unsafe { (*conn).pending_queries == 1 });
        unsafe {
            pending_http_queries = pending_http_queries.wrapping_sub(1);
            (*conn).pending_queries = 0;
        }
    }

    unsafe {
        (*d).parse_state = -1;
        connection_write_close(c);
    }
    0
}

pub(super) fn mtproto_mtfront_prepare_parse_options_ffi() {
    unsafe {
        rust_sf_register_parse_option_or_die(
            b"http-stats\0".as_ptr().cast(),
            NO_ARGUMENT,
            2000,
            b"allow http server to answer on stats queries\0"
                .as_ptr()
                .cast(),
        );
        rust_sf_register_parse_option_or_die(
            b"mtproto-secret\0".as_ptr().cast(),
            REQUIRED_ARGUMENT,
            OPT_S,
            b"16-byte secret in hex mode\0".as_ptr().cast(),
        );
        rust_sf_register_parse_option_or_die(
            b"proxy-tag\0".as_ptr().cast(),
            REQUIRED_ARGUMENT,
            OPT_P,
            b"16-byte proxy tag in hex mode to be passed along with all forwarded queries\0"
                .as_ptr()
                .cast(),
        );
        rust_sf_register_parse_option_or_die(
            b"domain\0".as_ptr().cast(),
            REQUIRED_ARGUMENT,
            OPT_D,
            b"adds allowed domain for TLS-transport mode, disables other transports; can be specified more than once\0"
                .as_ptr()
                .cast(),
        );
        rust_sf_register_parse_option_or_die(
            b"max-special-connections\0".as_ptr().cast(),
            REQUIRED_ARGUMENT,
            OPT_C,
            b"sets maximal number of accepted client connections per worker\0"
                .as_ptr()
                .cast(),
        );
        rust_sf_register_parse_option_or_die(
            b"window-clamp\0".as_ptr().cast(),
            REQUIRED_ARGUMENT,
            OPT_W,
            b"sets window clamp for client TCP connections\0"
                .as_ptr()
                .cast(),
        );
        rust_sf_register_parse_option_or_die(
            b"http-ports\0".as_ptr().cast(),
            REQUIRED_ARGUMENT,
            OPT_H,
            b"comma-separated list of client (HTTP) ports to listen\0"
                .as_ptr()
                .cast(),
        );
        rust_sf_register_parse_option_or_die(
            b"slaves\0".as_ptr().cast(),
            REQUIRED_ARGUMENT,
            OPT_M,
            b"spawn several slave workers; not recommended for TLS-transport mode for better replay protection\0"
                .as_ptr()
                .cast(),
        );
        let ping_help = format!(
            "sets ping interval in second for local TCP connections (default {:.3})",
            DEFAULT_PING_INTERVAL
        );
        let ping_help_c =
            CString::new(ping_help).expect("ping option help must not contain interior NUL bytes");
        rust_sf_register_parse_option_or_die(
            b"ping-interval\0".as_ptr().cast(),
            REQUIRED_ARGUMENT,
            OPT_T,
            ping_help_c.as_ptr(),
        );
    }
}

pub(super) fn mtproto_f_parse_option_ffi(val: c_int) -> c_int {
    match val {
        OPT_C => unsafe {
            max_special_connections = libc::atoi(optarg.cast_const());
            if max_special_connections < 0 {
                max_special_connections = 0;
            }
        },
        OPT_W => unsafe {
            window_clamp = libc::atoi(optarg.cast_const());
        },
        OPT_H => unsafe {
            let mut ptr = optarg;
            if ptr.is_null() || *ptr == 0 {
                mtproto_usage_ffi();
                return 2;
            }
            while (*ptr as u8) >= b'1'
                && (*ptr as u8) <= b'9'
                && http_ports_num < MAX_HTTP_LISTEN_PORTS as c_int
            {
                let mut colon: *mut c_char = core::ptr::null_mut();
                let i = libc::strtol(ptr.cast_const(), &mut colon, 10) as c_int;
                let idx = usize::try_from(http_ports_num).unwrap_or(0);
                http_port[idx] = i;
                http_ports_num = http_ports_num.wrapping_add(1);
                assert!(colon > ptr && i > 0 && i < 65_536);
                ptr = colon;
                if *ptr != c_char::from_ne_bytes([b',']) {
                    break;
                }
                ptr = ptr.add(1);
            }
            if *ptr != 0 {
                mtproto_usage_ffi();
                return 2;
            }
        },
        OPT_M => unsafe {
            workers = libc::atoi(optarg.cast_const());
            assert!(workers >= 0 && workers <= MAX_WORKERS as c_int);
        },
        OPT_T => unsafe {
            ping_interval = libc::atof(optarg.cast_const());
            if ping_interval <= 0.0 {
                ping_interval = DEFAULT_PING_INTERVAL;
            }
        },
        2000 => unsafe {
            engine_set_http_fallback(
                core::ptr::addr_of_mut!(ct_http_server).cast(),
                core::ptr::addr_of_mut!(http_methods_stats).cast(),
            );
            mtproto_front_functions.flags &= !ENGINE_NO_PORT;
        },
        OPT_D => unsafe {
            tcp_rpc_add_proxy_domain(optarg.cast_const());
            domain_count = domain_count.wrapping_add(1);
        },
        OPT_S | OPT_P => unsafe {
            if libc::strlen(optarg.cast_const()) != 32 {
                crate::kprintf_fmt!(
                    b"'%c' option requires exactly 32 hex digits\n\0"
                        .as_ptr()
                        .cast(),
                    val,
                );
                mtproto_usage_ffi();
                return 2;
            }
            let Some(hex) = slice_from_ptr(optarg.cast::<u8>(), 32) else {
                mtproto_usage_ffi();
                return 2;
            };
            let mut secret = [0_u8; 16];
            let mut b = 0_u8;
            for (i, ch) in hex.iter().copied().enumerate() {
                let Some(nib) = mtproto_parse_hex_nibble(ch) else {
                    crate::kprintf_fmt!(
                        b"'S' option requires exactly 32 hex digits. '%c' is not hexdigit\n\0"
                            .as_ptr()
                            .cast(),
                        c_int::from(ch),
                    );
                    mtproto_usage_ffi();
                    return 2;
                };
                b = b.wrapping_mul(16).wrapping_add(nib);
                if (i & 1) != 0 {
                    secret[i / 2] = b;
                    b = 0;
                }
            }
            if val == OPT_S {
                tcp_rpcs_set_ext_secret(secret.as_mut_ptr());
                secret_count = secret_count.wrapping_add(1);
            } else {
                core::ptr::copy_nonoverlapping(
                    secret.as_ptr().cast::<c_char>(),
                    core::ptr::addr_of_mut!(proxy_tag).cast::<c_char>(),
                    16,
                );
                proxy_tag_set = 1;
            }
        },
        _ => return -1,
    }

    0
}

pub(super) fn mtproto_check_children_dead_ffi() {
    let workers_count = usize::try_from(unsafe { workers })
        .unwrap_or(0)
        .min(MAX_WORKERS);
    let mut j = 0;
    while j < 11 {
        let mut i = 0;
        while i < workers_count {
            if unsafe { pids[i] } != 0 {
                let mut status = 0;
                let res = unsafe {
                    libc::waitpid(pids[i], core::ptr::addr_of_mut!(status), libc::WNOHANG)
                };
                if res == unsafe { pids[i] } {
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        unsafe {
                            pids[i] = 0;
                        }
                    } else {
                        break;
                    }
                } else if res == 0 {
                    break;
                } else if res != -1 || unsafe { *libc::__errno_location() } != libc::EINTR {
                    unsafe {
                        pids[i] = 0;
                    }
                } else {
                    break;
                }
            }
            i += 1;
        }
        if i == workers_count {
            break;
        }
        if j < 10 {
            unsafe {
                libc::usleep(100_000);
            }
        }
        j += 1;
    }

    if j == 11 {
        let mut cnt = 0;
        for i in 0..workers_count {
            if unsafe { pids[i] } != 0 {
                cnt += 1;
                unsafe {
                    libc::kill(pids[i], libc::SIGKILL);
                }
            }
        }
        unsafe {
            crate::kprintf_fmt!(
                b"WARNING: %d children unfinished --> they are now killed\n\0"
                    .as_ptr()
                    .cast(),
                cnt,
            );
        }
    }
}

pub(super) fn mtproto_check_children_status_ffi() {
    if unsafe { workers } != 0 {
        let workers_count = usize::try_from(unsafe { workers })
            .unwrap_or(0)
            .min(MAX_WORKERS);
        for i in 0..workers_count {
            let mut status = 0;
            let res =
                unsafe { libc::waitpid(pids[i], core::ptr::addr_of_mut!(status), libc::WNOHANG) };
            if res == unsafe { pids[i] } {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    unsafe {
                        crate::kprintf_fmt!(
                            b"Child %d terminated, aborting\n\0".as_ptr().cast(),
                            pids[i],
                        );
                        pids[i] = 0;
                    }
                    for j in 0..workers_count {
                        if unsafe { pids[j] } != 0 {
                            unsafe {
                                libc::kill(pids[j], libc::SIGTERM);
                            }
                        }
                    }
                    unsafe {
                        mtproto_check_children_dead_ffi();
                        libc::exit(libc::EXIT_FAILURE);
                    }
                }
            } else if res == 0 {
            } else if res != -1 || unsafe { *libc::__errno_location() } != libc::EINTR {
                unsafe {
                    crate::kprintf_fmt!(
                        b"Child %d: unknown result during wait (%d, %m), aborting\n\0"
                            .as_ptr()
                            .cast(),
                        pids[i],
                        res,
                    );
                    pids[i] = 0;
                }
                for j in 0..workers_count {
                    if unsafe { pids[j] } != 0 {
                        unsafe {
                            libc::kill(pids[j], libc::SIGTERM);
                        }
                    }
                }
                unsafe {
                    mtproto_check_children_dead_ffi();
                    libc::exit(libc::EXIT_FAILURE);
                }
            }
        }
    } else if unsafe { slave_mode } != 0 {
        let ppid = unsafe { libc::getppid() };
        if ppid != unsafe { parent_pid } {
            unsafe {
                crate::kprintf_fmt!(
                    b"Parent %d is changed to %d, aborting\n\0".as_ptr().cast(),
                    parent_pid,
                    ppid,
                );
                libc::exit(libc::EXIT_FAILURE);
            }
        }
    }
}

pub(super) fn mtproto_check_special_connections_overflow_ffi() {
    if unsafe { max_special_connections == 0 || slave_mode != 0 } {
        return;
    }
    let max_user_conn = if unsafe { workers } != 0 {
        unsafe { SumStats.conn.max_special_connections }
    } else {
        unsafe { max_special_connections }
    };
    let cur_user_conn = if unsafe { workers } != 0 {
        unsafe { SumStats.conn.active_special_connections }
    } else {
        unsafe { active_special_connections }
    };
    if i64::from(cur_user_conn) * 10 > i64::from(max_user_conn) * 9 {
        unsafe {
            crate::kprintf_fmt!(
                b"CRITICAL: used %d user connections out of %d\n\0"
                    .as_ptr()
                    .cast(),
                cur_user_conn,
                max_user_conn,
            );
        }
    }
}

pub(super) fn mtproto_kill_children_ffi(signal: c_int) {
    let workers_count = unsafe { workers };
    assert!(workers_count != 0);
    let limit = usize::try_from(workers_count).unwrap_or(0).min(MAX_WORKERS);
    for i in 0..limit {
        let pid = unsafe { pids[i] };
        if pid != 0 {
            unsafe {
                libc::kill(pid, signal);
            }
        }
    }
}

pub(super) fn mtproto_cron_ffi() {
    unsafe {
        mtproto_check_children_status_ffi();
        mtproto_compute_stats_sum_ffi();
        mtproto_check_special_connections_overflow_ffi();
        mtproto_check_all_conn_buffers_ffi();
    }
}

pub(super) fn mtproto_usage_ffi() {
    unsafe {
        libc::printf(
            b"usage: %s [-v] [-6] [-p<port>] [-H<http-port>{,<http-port>}] [-M<workers>] [-u<username>] [-b<backlog>] [-c<max-conn>] [-l<log-name>] [-W<window-size>] <config-file>\n\0"
                .as_ptr()
                .cast(),
            progname,
        );
        libc::printf(b"%s\n\0".as_ptr().cast(), FullVersionStr);
        libc::printf(b"\tSimple MT-Proto proxy\n\0".as_ptr().cast());
        parse_usage();
        libc::exit(2);
    }
}

#[no_mangle]
pub extern "C" fn usage() {
    mtproto_usage_ffi();
}

pub(super) fn mtproto_mtfront_parse_extra_args_ffi(argc: c_int, argv: *mut *mut c_char) {
    if argc != 1 || argv.is_null() || unsafe { (*argv).is_null() } {
        mtproto_usage_ffi();
    }
    unsafe {
        config_filename = *argv;
        crate::kprintf_fmt!(
            b"config_filename = '%s'\n\0".as_ptr().cast(),
            config_filename,
        );
    }
}

pub(super) fn mtproto_mtfront_sigusr1_handler_ffi() {
    unsafe {
        reopen_logs_ext(slave_mode);
        if workers != 0 {
            mtproto_kill_children_ffi(libc::SIGUSR1);
        }
    }
}

pub(super) fn mtproto_mtfront_on_exit_ffi() {
    if unsafe { workers } != 0 {
        if unsafe { signal_check_pending(libc::SIGTERM) } != 0 {
            mtproto_kill_children_ffi(libc::SIGTERM);
        }
        mtproto_check_children_dead_ffi();
    }
}

pub(super) fn mtproto_mtfront_pre_init_ffi() {
    unsafe {
        mtproto_init_ct_server_mtfront_ffi();
        mtproto_ext_conn_reset_ffi();
    }

    let checks: [unsafe extern "C" fn() -> c_int; 9] = [
        mtproxy_ffi_rust_bridge_startup_check,
        mtproxy_ffi_rust_bridge_check_concurrency_boundary,
        mtproxy_ffi_rust_bridge_check_network_boundary,
        mtproxy_ffi_rust_bridge_check_rpc_boundary,
        mtproxy_ffi_rust_bridge_check_crypto_boundary,
        mtproxy_ffi_rust_bridge_check_application_boundary,
        mtproxy_ffi_rust_bridge_enable_concurrency_bridges,
        mtproxy_ffi_rust_bridge_enable_crc32_bridge,
        mtproxy_ffi_rust_bridge_enable_crc32c_bridge,
    ];
    for check in checks {
        if unsafe { check() } < 0 {
            unsafe {
                libc::exit(1);
            }
        }
    }

    let res = mtproto_cfg_do_reload_config_ffi(0x26);
    if res < 0 {
        eprintln!("config check failed! (code {res})");
        unsafe { libc::exit(-res) };
    }

    unsafe { crate::kprintf_fmt!(b"config loaded!\n\0".as_ptr().cast()) };

    if unsafe { domain_count != 0 } {
        unsafe {
            tcp_rpc_init_proxy_domains();
            if workers != 0 {
                crate::kprintf_fmt!(b"It is recommended to not use workers with TLS-transport\0"
                    .as_ptr()
                    .cast(),);
            }
            if secret_count == 0 {
                crate::kprintf_fmt!(
                    b"You must specify at least one mtproto-secret to use when using TLS-transport\0"
                        .as_ptr()
                        .cast(),
                );
                libc::exit(2);
            }
        }
    }

    let enable_ipv6 = unsafe {
        if !engine_state.is_null() && ((*engine_state).modules & ENGINE_ENABLE_IPV6) != 0 {
            SM_IPV6
        } else {
            0
        }
    };

    let settings_addr = unsafe {
        if engine_state.is_null() {
            MtproxyInAddr { s_addr: 0 }
        } else {
            (*engine_state).settings_addr
        }
    };
    let backlog = unsafe {
        if engine_state.is_null() {
            0
        } else {
            (*engine_state).backlog
        }
    };
    let http_ports_count = unsafe { http_ports_num };

    let mut i = 0;
    while i < http_ports_count {
        let idx = usize::try_from(i).unwrap_or(0);
        unsafe {
            http_sfd[idx] = server_socket(http_port[idx], settings_addr, backlog, enable_ipv6);
            if http_sfd[idx] < 0 {
                crate::kprintf_fmt!(
                    b"cannot open http/tcp server socket at port %d: %m\n\0"
                        .as_ptr()
                        .cast(),
                    http_port[idx],
                );
                libc::exit(1);
            }
        }
        i += 1;
    }

    let workers_count = unsafe { workers };
    if workers_count != 0 {
        unsafe {
            if kdb_hosts_loaded == 0 {
                kdb_load_hosts();
            }
            let w = usize::try_from(workers_count).unwrap_or(0);
            let map_len = 2_usize
                .saturating_mul(w)
                .saturating_mul(core::mem::size_of::<MtprotoWorkerStats>());
            WStats = libc::mmap(
                core::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
            .cast::<MtprotoWorkerStats>();
            assert!(!WStats.is_null());
            let real_parent_pid = libc::getpid();
            crate::kprintf_fmt!(b"creating %d workers\n\0".as_ptr().cast(), workers_count);
            let mut j = 0;
            while j < workers_count {
                let pid = libc::fork();
                assert!(pid >= 0);
                if pid == 0 {
                    worker_id = j;
                    workers = 0;
                    slave_mode = 1;
                    parent_pid = libc::getppid();
                    assert!(parent_pid == real_parent_pid);
                    if !engine_state.is_null() {
                        (*engine_state).modules |= ENGINE_ENABLE_SLAVE_MODE;
                        (*engine_state).do_not_open_port = 1;
                    }
                    break;
                }
                let pidx = usize::try_from(j).unwrap_or(0);
                pids[pidx] = pid;
                j += 1;
            }
        }
    }
}

pub(super) fn mtproto_mtfront_pre_start_ffi() {
    let res = mtproto_cfg_do_reload_config_ffi(0x17);
    if res < 0 {
        eprintln!("config check failed! (code {res})");
        unsafe { libc::exit(-res) };
    }

    let cur_conf = unsafe { CurConf };
    assert!(!cur_conf.is_null());
    assert!(unsafe { (*cur_conf).have_proxy != 0 });

    unsafe {
        proxy_mode |= PROXY_MODE_OUT;
        mtfront_rpc_client.mode_flags |= TCP_RPC_IGNORE_PID;
        ct_tcp_rpc_client_mtfront.flags |= C_EXTERNAL;
        assert!(proxy_mode == PROXY_MODE_OUT);
    }
}

pub(super) fn mtproto_mtfront_pre_loop_ffi() {
    let enable_ipv6 = unsafe {
        if !engine_state.is_null() && ((*engine_state).modules & ENGINE_ENABLE_IPV6) != 0 {
            SM_IPV6
        } else {
            0
        }
    };

    if unsafe { domain_count } == 0 {
        unsafe {
            tcp_maximize_buffers = 1;
            if window_clamp == 0 {
                window_clamp = DEFAULT_WINDOW_CLAMP;
            }
        }
    }

    if unsafe { workers } == 0 {
        let ports_count = usize::try_from(unsafe { http_ports_num })
            .unwrap_or(0)
            .min(MAX_HTTP_LISTEN_PORTS);
        for i in 0..ports_count {
            let mode = enable_ipv6
                | SM_LOWPRIO
                | if unsafe { domain_count } == 0 {
                    SM_NOQACK
                } else {
                    0
                }
                | if unsafe { max_special_connections } != 0 {
                    SM_SPECIAL
                } else {
                    0
                };
            unsafe {
                init_listening_tcpv6_connection(
                    http_sfd[i],
                    core::ptr::addr_of_mut!(ct_tcp_rpc_ext_server_mtfront).cast::<c_void>(),
                    core::ptr::addr_of_mut!(ext_rpc_methods).cast::<c_void>(),
                    mode,
                );
            }

            let clamp = unsafe { window_clamp };
            if clamp != 0 {
                let fd = unsafe { http_sfd[i] };
                let fd_u = usize::try_from(fd).unwrap_or(usize::MAX);
                assert!(fd_u < MAX_EVENTS);
                let lc = unsafe { Events[fd_u].data };
                assert!(!lc.is_null());
                let lc_info = mtproto_listening_conn_info_ptr(lc);
                assert!(!lc_info.is_null());
                unsafe {
                    (*lc_info).window_clamp = clamp;
                }
                let set_rc = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_WINDOW_CLAMP,
                        core::ptr::addr_of!(window_clamp).cast::<c_void>(),
                        core::mem::size_of::<c_int>() as libc::socklen_t,
                    )
                };
                if set_rc < 0 && unsafe { verbosity } >= 0 {
                    unsafe {
                        crate::kprintf_fmt!(
                            b"error while setting window size for socket #%d to %d: %m\n\0"
                                .as_ptr()
                                .cast(),
                            fd,
                            clamp,
                        );
                    }
                }
            }
        }
    }
}

pub(super) fn mtproto_forward_tcp_query_ffi(
    tlio_in: *mut c_void,
    c: ConnectionJob,
    target: ConnTargetJob,
    mut flags: c_int,
    auth_key_id: i64,
    remote_ip_port: *const c_int,
    our_ip_port: *const c_int,
) -> c_int {
    if c.is_null() || tlio_in.is_null() {
        return 0;
    }
    let tlio_in = tlio_in.cast::<crate::tl_parse::abi::TlInState>();
    let conn = mtproto_conn_info_ptr(c);
    if conn.is_null() {
        return 0;
    }

    let http_type_ptr = core::ptr::addr_of_mut!(ct_http_server_mtfront).cast::<c_void>();
    let ext_type_ptr = core::ptr::addr_of_mut!(ct_tcp_rpc_ext_server_mtfront).cast::<c_void>();
    let is_ext_server = unsafe { (*conn).type_ == ext_type_ptr };
    let is_http_server = unsafe { (*conn).type_ == http_type_ptr };

    if is_ext_server {
        let c_data = mtproto_rpc_data_ptr(c);
        if c_data.is_null() {
            return 0;
        }
        flags |= unsafe { (*c_data).flags & RPC_F_DROPPED };
        flags |= 0x1000;
    } else if is_http_server {
        flags |= 0x3005;
    }

    let c_fd = unsafe { (*conn).fd };
    let mut ex = MtproxyMtprotoExtConnection::default();
    let ex_lookup_rc = mtproto_ext_conn_get_by_in_fd_ffi(c_fd, &mut ex);
    if ex_lookup_rc < 0 {
        return 0;
    }
    let mut have_ex = ex_lookup_rc > 0;

    if have_ex && ex.auth_key_id != auth_key_id {
        let update_rc = mtproto_ext_conn_update_auth_key_ffi(ex.in_fd, ex.in_conn_id, auth_key_id);
        if update_rc < 0 {
            return 0;
        }
        ex.auth_key_id = auth_key_id;
    }

    let mut d: ConnectionJob = core::ptr::null_mut();
    if have_ex {
        d = unsafe { connection_get_by_fd_generation(ex.out_fd, ex.out_gen) };
        if !d.is_null() {
            let d_conn = mtproto_conn_info_ptr(d);
            if d_conn.is_null() || unsafe { (*d_conn).target.is_null() } {
                mtproto_job_decref(d);
                d = core::ptr::null_mut();
            }
        }
        if d.is_null() {
            mtproto_remove_ext_connection_runtime_ffi(&ex, 1);
            have_ex = false;
        }
    }

    if d.is_null() {
        d = mtproto_forward_pick_connection(target);
        if d.is_null() {
            unsafe {
                dropped_queries = dropped_queries.wrapping_add(1);
            }
            if is_ext_server {
                let c_data = mtproto_rpc_data_ptr(c);
                if !c_data.is_null() {
                    let flags_atomic = unsafe { core::ptr::addr_of_mut!((*c_data).flags) }
                        .cast::<core::sync::atomic::AtomicI32>();
                    unsafe {
                        (*flags_atomic)
                            .fetch_or(RPC_F_DROPPED, core::sync::atomic::Ordering::SeqCst);
                    }
                }
            }
            return 0;
        }

        if (flags & RPC_F_DROPPED) != 0 {
            unsafe { fail_connection(c, -35) };
            return 0;
        }

        let d_conn = mtproto_conn_info_ptr(d);
        if d_conn.is_null() {
            mtproto_job_decref(d);
            unsafe {
                dropped_queries = dropped_queries.wrapping_add(1);
            }
            return 0;
        }
        let create_rc = mtproto_ext_conn_create_ffi(
            unsafe { (*conn).fd },
            unsafe { (*conn).generation },
            0,
            unsafe { (*d_conn).fd },
            unsafe { (*d_conn).generation },
            auth_key_id,
            &mut ex,
        );
        if create_rc <= 0 {
            mtproto_job_decref(d);
            unsafe {
                dropped_queries = dropped_queries.wrapping_add(1);
            }
            return 0;
        }
        have_ex = true;
    }

    unsafe {
        tot_forwarded_queries = tot_forwarded_queries.wrapping_add(1);
    }
    if unsafe { proxy_tag_set } != 0 {
        flags |= FORWARD_FLAG_PROXY_TAG;
    }

    let payload_len = unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_fetch_unread(tlio_in) };
    if payload_len < 0 {
        mtproto_job_decref(d);
        return 0;
    }
    let payload_len_usize = usize::try_from(payload_len).unwrap_or(0);
    let mut payload = vec![0u8; payload_len_usize];
    if payload_len > 0 {
        let fetched = unsafe {
            crate::tl_parse::abi::mtproxy_ffi_tl_fetch_lookup_data(
                tlio_in,
                payload.as_mut_ptr().cast(),
                payload_len,
            )
        };
        if fetched != payload_len {
            mtproto_job_decref(d);
            return 0;
        }
    }

    let mut remote_ipv6 = [0u8; 16];
    let remote_port = mtproto_forward_endpoint(conn, remote_ip_port, false, &mut remote_ipv6);
    let mut our_ipv6 = [0u8; 16];
    let our_port = mtproto_forward_endpoint(conn, our_ip_port, true, &mut our_ipv6);

    if !have_ex {
        mtproto_job_decref(d);
        return 0;
    }
    let Some(req) = mtproto_forward_build_req(
        flags,
        ex.out_conn_id,
        &remote_ipv6,
        remote_port,
        &our_ipv6,
        our_port,
        &payload,
    ) else {
        mtproto_job_decref(d);
        return 0;
    };

    if !mtproto_forward_send_req(d, &req) {
        mtproto_job_decref(d);
        return 0;
    }

    if is_http_server {
        let conn_after = mtproto_conn_info_ptr(c);
        if !conn_after.is_null() && unsafe { (*conn_after).pending_queries == 1 } {
            unsafe {
                set_connection_timeout(c, FORWARD_HTTP_TIMEOUT_SECONDS);
            }
        }
    }

    1
}

pub(super) fn mtproto_cfg_collect_auth_cluster_ids(
    mc: &MtproxyMfConfig,
    out: &mut [i32; MTPROTO_CFG_MAX_CLUSTERS],
) -> usize {
    let count = usize::try_from(mc.auth_clusters).unwrap_or(0);
    let bounded = count.min(MTPROTO_CFG_MAX_CLUSTERS);
    for (idx, slot) in out.iter_mut().enumerate().take(bounded) {
        *slot = mc.auth_cluster[idx].cluster_id;
    }
    bounded
}

pub(super) fn mtproto_cfg_default_cluster_index(
    mc: &MtproxyMfConfig,
    auth_clusters: usize,
) -> Option<usize> {
    if mc.default_cluster.is_null() {
        return None;
    }
    let base = mc.auth_cluster.as_ptr().cast::<u8>() as usize;
    let ptr = mc.default_cluster.cast::<u8>() as usize;
    let elem = core::mem::size_of::<MtproxyMfCluster>();
    let span = auth_clusters.checked_mul(elem)?;
    if ptr < base || ptr >= base.saturating_add(span) {
        return None;
    }
    let offset = ptr - base;
    if (offset % elem) != 0 {
        return None;
    }
    Some(offset / elem)
}

pub(super) fn mtproto_cfg_forget_cluster_targets(cluster: &mut MtproxyMfCluster) {
    if !cluster.cluster_targets.is_null() {
        cluster.cluster_targets = core::ptr::null_mut();
    }
    cluster.targets_num = 0;
    cluster.write_targets_num = 0;
    cluster.targets_allocated = 0;
}

pub(super) fn mtproto_cfg_clear_cluster(
    group_stats: &mut MtproxyMfGroupStats,
    cluster: &mut MtproxyMfCluster,
) {
    mtproto_cfg_forget_cluster_targets(cluster);
    cluster.flags = 0;
    group_stats.tot_clusters = group_stats.tot_clusters.wrapping_sub(1);
}

pub(super) fn mtproto_parse_client_packet_impl(
    data: &[u8],
    out: &mut MtproxyMtprotoClientPacketParseResult,
) {
    use mtproxy_core::runtime::mtproto::proxy::RpcClientPacket;

    match mtproxy_core::runtime::mtproto::proxy::parse_client_packet(data) {
        RpcClientPacket::Pong => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_PONG;
            out.op = mtproxy_core::runtime::mtproto::proxy::RPC_PONG;
        }
        RpcClientPacket::ProxyAns {
            flags,
            out_conn_id,
            payload,
        } => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_PROXY_ANS;
            out.op = mtproxy_core::runtime::mtproto::proxy::RPC_PROXY_ANS;
            out.flags = flags;
            out.out_conn_id = out_conn_id;
            let payload_offset = data.len().saturating_sub(payload.len());
            out.payload_offset = saturating_i32_from_usize(payload_offset);
        }
        RpcClientPacket::SimpleAck {
            out_conn_id,
            confirm,
        } => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_SIMPLE_ACK;
            out.op = mtproxy_core::runtime::mtproto::proxy::RPC_SIMPLE_ACK;
            out.out_conn_id = out_conn_id;
            out.confirm = confirm;
        }
        RpcClientPacket::CloseExt { out_conn_id } => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_CLOSE_EXT;
            out.op = mtproxy_core::runtime::mtproto::proxy::RPC_CLOSE_EXT;
            out.out_conn_id = out_conn_id;
        }
        RpcClientPacket::Unknown { op } => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_UNKNOWN;
            out.op = op;
        }
        RpcClientPacket::Malformed { op } => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_MALFORMED;
            out.op = op;
        }
    }
}

fn mtproto_client_packet_fill_ext_fields(
    out: &mut MtproxyMtprotoClientPacketProcessResult,
    ext: mtproxy_core::runtime::mtproto::proxy::ExtConnection,
) {
    out.in_fd = ext.in_fd;
    out.in_gen = ext.in_gen;
    out.in_conn_id = ext.in_conn_id;
    out.out_fd = ext.out_fd;
    out.out_gen = ext.out_gen;
    out.auth_key_id = ext.auth_key_id;
}

pub(super) fn mtproto_process_client_packet_impl(
    data: &[u8],
    conn_fd: i32,
    conn_gen: i32,
    out: &mut MtproxyMtprotoClientPacketProcessResult,
) {
    use mtproxy_core::runtime::mtproto::proxy::RpcClientPacket;

    *out = MtproxyMtprotoClientPacketProcessResult::default();

    match mtproxy_core::runtime::mtproto::proxy::parse_client_packet(data) {
        RpcClientPacket::ProxyAns {
            flags,
            out_conn_id,
            payload,
        } => {
            let payload_offset = data.len().saturating_sub(payload.len());
            let payload_offset_i32 = saturating_i32_from_usize(payload_offset);
            if payload_offset_i32 < 0 {
                out.kind = MTPROTO_CLIENT_PACKET_ACTION_INVALID;
                return;
            }
            out.payload_offset = payload_offset_i32;
            out.flags = flags;
            out.out_conn_id = out_conn_id;

            let table = ext_conn_lock();
            if let Some(ext) = table.find_ext_connection_by_out_conn_id(out_conn_id) {
                if ext.out_fd == conn_fd && ext.out_gen == conn_gen {
                    out.kind = MTPROTO_CLIENT_PACKET_ACTION_PROXY_ANS_FORWARD;
                    mtproto_client_packet_fill_ext_fields(out, ext);
                } else {
                    out.kind = MTPROTO_CLIENT_PACKET_ACTION_PROXY_ANS_NOTIFY_CLOSE;
                }
            } else {
                out.kind = MTPROTO_CLIENT_PACKET_ACTION_PROXY_ANS_NOTIFY_CLOSE;
            }
        }
        RpcClientPacket::SimpleAck {
            out_conn_id,
            confirm,
        } => {
            out.confirm = confirm;
            out.out_conn_id = out_conn_id;
            let table = ext_conn_lock();
            if let Some(ext) = table.find_ext_connection_by_out_conn_id(out_conn_id) {
                if ext.out_fd == conn_fd && ext.out_gen == conn_gen {
                    out.kind = MTPROTO_CLIENT_PACKET_ACTION_SIMPLE_ACK_FORWARD;
                    mtproto_client_packet_fill_ext_fields(out, ext);
                } else {
                    out.kind = MTPROTO_CLIENT_PACKET_ACTION_SIMPLE_ACK_NOTIFY_CLOSE;
                }
            } else {
                out.kind = MTPROTO_CLIENT_PACKET_ACTION_SIMPLE_ACK_NOTIFY_CLOSE;
            }
        }
        RpcClientPacket::CloseExt { out_conn_id } => {
            out.out_conn_id = out_conn_id;
            let mut table = ext_conn_lock();
            if let Some(ext) = table.take_ext_connection_by_out_conn_id(out_conn_id) {
                out.kind = MTPROTO_CLIENT_PACKET_ACTION_CLOSE_EXT_REMOVED;
                mtproto_client_packet_fill_ext_fields(out, ext);
            } else {
                out.kind = MTPROTO_CLIENT_PACKET_ACTION_CLOSE_EXT_NOOP;
            }
        }
        RpcClientPacket::Pong
        | RpcClientPacket::Unknown { .. }
        | RpcClientPacket::Malformed { .. } => {
            out.kind = MTPROTO_CLIENT_PACKET_ACTION_INVALID;
        }
    }
}

pub(super) fn mtproto_parse_function_impl(
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

pub(super) fn mtproto_cfg_cluster_apply_decision_kind_to_ffi(
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

pub(super) fn mtproto_cfg_cluster_apply_decision_err_to_code(
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

pub(super) fn mtproto_cfg_cluster_targets_action_to_ffi(
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

pub(super) fn mtproto_cfg_parse_proxy_target_step_err_to_code(
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

pub(super) fn mtproto_cfg_parse_full_pass_err_to_code(
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

pub(super) fn mtproto_directive_token_kind_to_ffi(
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

pub(super) fn mtproto_cfg_scan_directive_token_err_to_code(
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

pub(super) fn mtproto_cfg_parse_directive_step_err_to_code(
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

pub(super) fn mtproto_cfg_finalize_err_to_code(
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

pub(super) fn mtproto_old_cluster_from_ffi(
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

pub(super) fn mtproto_old_cluster_to_ffi(
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

pub(super) fn mtproto_cfg_syntax_literal(msg: &[u8]) {
    unsafe { cfg_syntax_report_cstr(msg.as_ptr().cast()) };
}

pub(super) fn mtproto_cfg_report_parse_full_pass_error(pass_rc: i32, tot_targets: c_int) {
    match pass_rc {
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TIMEOUT => {
            mtproto_cfg_syntax_literal(b"invalid timeout\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MAX_CONNECTIONS => {
            mtproto_cfg_syntax_literal(b"invalid max connections\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MIN_CONNECTIONS => {
            mtproto_cfg_syntax_literal(b"invalid min connections\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TARGET_ID => {
            mtproto_cfg_syntax_literal(b"invalid target id (integer -32768..32767 expected)\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_TARGET_ID_SPACE => {
            mtproto_cfg_syntax_literal(b"space expected after target id\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_AUTH_CLUSTERS => {
            mtproto_cfg_syntax_literal(b"too many auth clusters\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXIES_INTERMIXED => {
            mtproto_cfg_syntax_literal(b"proxies for dc intermixed\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON => {
            mtproto_cfg_syntax_literal(b"';' expected\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXY_EXPECTED => {
            mtproto_cfg_syntax_literal(b"'proxy <ip>:<port>;' expected\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_TARGETS => {
            unsafe { cfg_syntax_report(&format!("too many targets ({tot_targets})")) };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_HOSTNAME_EXPECTED => {
            mtproto_cfg_syntax_literal(b"hostname expected\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_EXPECTED => {
            mtproto_cfg_syntax_literal(b"port number expected\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_RANGE => {
            mtproto_cfg_syntax_literal(b"port number out of range\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_CLUSTER_EXTEND_INVARIANT => {
            mtproto_cfg_syntax_literal(b"IMPOSSIBLE\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES => {
            mtproto_cfg_syntax_literal(
                b"expected to find a mtproto-proxy configuration with `proxy' directives\0",
            );
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_NO_PROXY_SERVERS_DEFINED => {
            mtproto_cfg_syntax_literal(
                b"no MTProto next proxy servers defined to forward queries to\0",
            );
        }
        _ => mtproto_cfg_syntax_literal(b"internal parser full-pass failure\0"),
    }
}

pub(super) fn mtproto_proxy_usage_ffi(program_name: *const c_char) -> i32 {
    let program_name = if program_name.is_null() {
        "mtproto-proxy".to_owned()
    } else {
        let Some(program_name_ref) = cstr_to_owned(program_name) else {
            return -1;
        };
        program_name_ref
    };

    let usage = mtproxy_bin::entrypoint::usage_text(&program_name);
    eprint!("{usage}");
    0
}

pub(super) fn mtproto_proxy_main_ffi(argc: i32, argv: *const *const c_char) -> i32 {
    let Some(args) = mtproto_proxy_collect_argv(argc, argv) else {
        eprintln!("ERROR: invalid argv passed to mtproxy_ffi_mtproto_proxy_main");
        return 1;
    };
    mtproxy_bin::entrypoint::run_from_argv(&args)
}

#[allow(private_interfaces)]
pub(super) fn clear_config_ffi(mc: *mut MtproxyMfConfig, do_destroy_targets: c_int) {
    let Some(mc_ref) = (unsafe { mut_ref_from_ptr(mc) }) else {
        return;
    };
    let tot_targets = usize::try_from(mc_ref.tot_targets)
        .unwrap_or(0)
        .min(MTPROTO_CFG_MAX_TARGETS);
    if do_destroy_targets != 0 {
        for idx in 0..tot_targets {
            let target = mc_ref.targets[idx];
            if unsafe { verbosity } >= 1 {
                unsafe { crate::kprintf_fmt!(b"destroying target %p\n\0".as_ptr().cast(), target) };
            }
            unsafe {
                destroy_target(1, target);
            }
        }
        for idx in 0..tot_targets {
            mc_ref.targets[idx] = core::ptr::null_mut();
        }
    }

    let auth_clusters = usize::try_from(mc_ref.auth_clusters)
        .unwrap_or(0)
        .min(MTPROTO_CFG_MAX_CLUSTERS);
    for idx in 0..auth_clusters {
        mtproto_cfg_clear_cluster(&mut mc_ref.auth_stats, &mut mc_ref.auth_cluster[idx]);
    }
    mc_ref.tot_targets = 0;
    mc_ref.auth_clusters = 0;
    mc_ref.auth_stats = MtproxyMfGroupStats { tot_clusters: 0 };
}

#[allow(private_interfaces)]
pub(super) fn mf_cluster_lookup_ffi(
    mc: *mut MtproxyMfConfig,
    cluster_id: c_int,
    force: c_int,
) -> *mut MtproxyMfCluster {
    let Some(mc_ref) = (unsafe { mut_ref_from_ptr(mc) }) else {
        return core::ptr::null_mut();
    };
    let mut cluster_ids = [0i32; MTPROTO_CFG_MAX_CLUSTERS];
    let auth_clusters = mtproto_cfg_collect_auth_cluster_ids(mc_ref, &mut cluster_ids);
    let default_cluster_index = mtproto_cfg_default_cluster_index(mc_ref, auth_clusters);
    let lookup = mtproxy_core::runtime::mtproto::config::mf_cluster_lookup_index(
        &cluster_ids[..auth_clusters],
        cluster_id,
        if force != 0 {
            default_cluster_index
        } else {
            None
        },
    );
    if let Some(idx) = lookup {
        if idx < auth_clusters {
            return &mut mc_ref.auth_cluster[idx];
        }
    }
    if force != 0 {
        mc_ref.default_cluster
    } else {
        core::ptr::null_mut()
    }
}

pub(super) fn mtproto_cfg_resolve_default_target_from_cfg_cur_ffi() -> c_int {
    let host = unsafe { cfg_gethost() };
    if host.is_null() {
        return -1;
    }
    let host_ref = unsafe { &*host };
    if host_ref.h_addr_list.is_null() {
        return -1;
    }
    let addr = unsafe { *host_ref.h_addr_list };
    if addr.is_null() {
        return -1;
    }

    if host_ref.h_addrtype == AF_INET {
        let in_addr = unsafe { *(addr.cast::<MtproxyInAddr>()) };
        unsafe {
            default_cfg_ct.target = in_addr;
            default_cfg_ct.target_ipv6 = [0; 16];
        }
        return 0;
    }
    if host_ref.h_addrtype == AF_INET6 {
        unsafe {
            default_cfg_ct.target.s_addr = 0;
            core::ptr::copy_nonoverlapping(
                addr.cast::<u8>(),
                core::ptr::addr_of_mut!(default_cfg_ct.target_ipv6).cast::<u8>(),
                16,
            );
        }
        return 0;
    }

    mtproto_cfg_syntax_literal(b"cannot resolve hostname\0");
    -1
}

pub(super) fn mtproto_cfg_set_default_target_endpoint_ffi(
    port: u16,
    min_connections: i64,
    max_connections: i64,
    reconnect_timeout: c_double,
) {
    unsafe {
        default_cfg_ct.port = c_int::from(port);
        default_cfg_ct.min_connections = min_connections as c_int;
        default_cfg_ct.max_connections = max_connections as c_int;
        default_cfg_ct.reconnect_timeout = reconnect_timeout;
    }
}

#[allow(private_interfaces)]
pub(super) fn mtproto_cfg_create_target_ffi(mc: *mut MtproxyMfConfig, target_index: u32) {
    let Some(mc_ref) = (unsafe { mut_ref_from_ptr(mc) }) else {
        return;
    };
    let Ok(target_index_usize) = usize::try_from(target_index) else {
        return;
    };
    if target_index_usize >= MTPROTO_CFG_MAX_TARGETS {
        return;
    }
    let mut was_created = -1;
    let target = unsafe { create_target(&raw mut default_cfg_ct, &raw mut was_created) };
    mc_ref.targets[target_index_usize] = target;

    if unsafe { verbosity } >= 3 {
        let ipv4 = unsafe { default_cfg_ct.target.s_addr.to_ne_bytes() };
        unsafe {
            crate::kprintf_fmt!(
                b"new target %p created (%d): ip %d.%d.%d.%d, port %d\n\0"
                    .as_ptr()
                    .cast(),
                target,
                was_created,
                c_int::from(ipv4[0]),
                c_int::from(ipv4[1]),
                c_int::from(ipv4[2]),
                c_int::from(ipv4[3]),
                default_cfg_ct.port,
            );
        }
    }
}

pub(super) fn mtproto_cfg_now_or_time_ffi() -> c_int {
    unsafe { time(core::ptr::null_mut()) as c_int }
}

pub(super) fn mtproto_parse_text_ipv4_ffi(str: *const c_char, out_ip: *mut u32) -> i32 {
    let Some(input) = cstr_to_owned(str) else {
        return -1;
    };
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_ip) }) else {
        return -1;
    };
    let parsed = mtproxy_core::runtime::mtproto::proxy::parse_text_ipv4(&input);
    *out_ref = parsed;
    0
}

pub(super) fn mtproto_parse_text_ipv6_ffi(
    str: *const c_char,
    out_ip: *mut u8,
    out_consumed: *mut i32,
) -> i32 {
    let Some(input) = cstr_to_owned(str) else {
        return -1;
    };
    let Some(out_ip_slice) = (unsafe { mut_slice_from_ptr(out_ip, 16) }) else {
        return -1;
    };
    let Some(out_consumed_ref) = (unsafe { mut_ref_from_ptr(out_consumed) }) else {
        return -1;
    };
    let mut parsed_ip = [0u8; 16];
    let consumed = mtproxy_core::runtime::mtproto::proxy::parse_text_ipv6(&mut parsed_ip, &input);
    out_ip_slice.copy_from_slice(&parsed_ip);
    *out_consumed_ref = consumed;
    0
}

pub(super) fn mtproto_inspect_packet_header_ffi(
    header: *const u8,
    header_len: usize,
    packet_len: i32,
    out: *mut MtproxyMtprotoPacketInspectResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = (unsafe { slice_from_ptr(header, header_len) }) else {
        return -1;
    };
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

pub(super) fn mtproto_parse_client_packet_ffi(
    data: *const u8,
    len: usize,
    out: *mut MtproxyMtprotoClientPacketParseResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = (unsafe { slice_from_ptr(data, len) }) else {
        return -1;
    };
    *out_ref = MtproxyMtprotoClientPacketParseResult {
        kind: MTPROTO_CLIENT_PACKET_KIND_INVALID,
        ..MtproxyMtprotoClientPacketParseResult::default()
    };
    mtproto_parse_client_packet_impl(bytes, out_ref);
    0
}

pub(super) fn mtproto_process_client_packet_ffi(
    data: *const u8,
    len: usize,
    conn_fd: c_int,
    conn_gen: c_int,
    out: *mut MtproxyMtprotoClientPacketProcessResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = (unsafe { slice_from_ptr(data, len) }) else {
        return -1;
    };
    *out_ref = MtproxyMtprotoClientPacketProcessResult::default();
    mtproto_process_client_packet_impl(bytes, conn_fd, conn_gen, out_ref);
    0
}

pub(super) fn mtproto_mtfront_parse_function_runtime_ffi(
    tlio_in: *mut c_void,
    actor_id: i64,
) -> *mut c_void {
    let tlio_in = tlio_in.cast::<crate::tl_parse::abi::TlInState>();
    if tlio_in.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        api_invoke_requests = api_invoke_requests.wrapping_add(1);
    }
    let unread = unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_fetch_unread(tlio_in) };
    if unread < 0 {
        unsafe {
            crate::tl_parse::abi::mtproxy_ffi_tl_set_error(
                tlio_in,
                TL_ERROR_NOT_ENOUGH_DATA,
                b"Unable to inspect TL query\0".as_ptr().cast(),
            );
        }
        return core::ptr::null_mut();
    }

    let unread_usize = usize::try_from(unread).unwrap_or(0);
    let mut buf = Vec::<u8>::new();
    if unread_usize > 0 {
        if buf.try_reserve_exact(unread_usize).is_err() {
            unsafe {
                crate::tl_parse::abi::mtproxy_ffi_tl_set_error(
                    tlio_in,
                    TL_ERROR_INTERNAL,
                    b"Unable to allocate parser buffer\0".as_ptr().cast(),
                );
            }
            return core::ptr::null_mut();
        }
        buf.resize(unread_usize, 0);
        let got = unsafe {
            crate::tl_parse::abi::mtproxy_ffi_tl_fetch_lookup_data(
                tlio_in,
                buf.as_mut_ptr().cast(),
                unread,
            )
        };
        if got != unread {
            unsafe {
                crate::tl_parse::abi::mtproxy_ffi_tl_set_error(
                    tlio_in,
                    TL_ERROR_INTERNAL,
                    b"Unable to read parser buffer\0".as_ptr().cast(),
                );
            }
            return core::ptr::null_mut();
        }
    }

    let mut result = MtproxyMtprotoParseFunctionResult::default();
    let rc = unsafe {
        mtproto_parse_function_ffi(
            if unread_usize > 0 {
                buf.as_ptr()
            } else {
                core::ptr::null()
            },
            unread_usize,
            actor_id,
            core::ptr::addr_of_mut!(result),
        )
    };
    if rc < 0 {
        unsafe {
            crate::tl_parse::abi::mtproxy_ffi_tl_set_error(
                tlio_in,
                TL_ERROR_INTERNAL,
                b"Rust mtfront parser bridge failed\0".as_ptr().cast(),
            );
        }
        return core::ptr::null_mut();
    }

    if result.consumed > 0 {
        let mut skip = result.consumed;
        if skip > unread {
            skip = unread;
        }
        unsafe {
            crate::tl_parse::abi::mtproxy_ffi_tl_fetch_skip(tlio_in, skip);
        }
    }

    if result.status < 0 {
        let mut len = result.error_len;
        if len < 0 {
            len = 0;
        }
        if len > i32::try_from(result.error.len()).unwrap_or(i32::MAX) {
            len = i32::try_from(result.error.len()).unwrap_or(i32::MAX);
        }
        let errnum = if result.errnum != 0 {
            result.errnum
        } else {
            TL_ERROR_INTERNAL
        };
        if len == 0 {
            unsafe {
                crate::tl_parse::abi::mtproxy_ffi_tl_set_error(
                    tlio_in,
                    errnum,
                    b"MTProxy parse error\0".as_ptr().cast(),
                );
            }
            return core::ptr::null_mut();
        }
        let len = usize::try_from(len).unwrap_or(0);
        let mut msg = [0_u8; 193];
        for (i, src) in result.error.iter().take(len).enumerate() {
            msg[i] = src.to_ne_bytes()[0];
        }
        msg[len] = 0;
        unsafe {
            crate::tl_parse::abi::mtproxy_ffi_tl_set_error(tlio_in, errnum, msg.as_ptr().cast());
        }
    }

    core::ptr::null_mut()
}

pub(super) fn mtproto_parse_function_ffi(
    data: *const u8,
    len: usize,
    actor_id: i64,
    out: *mut MtproxyMtprotoParseFunctionResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = (unsafe { slice_from_ptr(data, len) }) else {
        return -1;
    };
    *out_ref = MtproxyMtprotoParseFunctionResult::default();
    mtproto_parse_function_impl(bytes, actor_id, out_ref);
    0
}

pub(super) fn mtproto_cfg_preinit_ffi(
    default_min_connections: i64,
    default_max_connections: i64,
    out: *mut MtproxyMtprotoCfgPreinitResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_PREINIT_ERR_INVALID_ARGS;
    };
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

pub(super) fn mtproto_cfg_decide_cluster_apply_ffi(
    cluster_ids: *const i32,
    clusters_len: u32,
    cluster_id: i32,
    max_clusters: u32,
    out: *mut MtproxyMtprotoCfgClusterApplyDecisionResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    };
    let Ok(max_clusters_usize) = usize::try_from(max_clusters) else {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    };
    let Some(cluster_ids_slice) = (unsafe { slice_from_ptr(cluster_ids, clusters_len_usize) })
    else {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
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
            *out_ref = MtproxyMtprotoCfgClusterApplyDecisionResult {
                kind: mtproto_cfg_cluster_apply_decision_kind_to_ffi(decision.kind),
                cluster_index,
            };
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK
        }
        Err(err) => mtproto_cfg_cluster_apply_decision_err_to_code(err),
    }
}

pub(super) fn mtproto_cfg_getlex_ext_ffi(
    cur: *const c_char,
    len: usize,
    out: *mut MtproxyMtprotoCfgGetlexExtResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_GETLEX_EXT_ERR_INVALID_ARGS;
    };
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_GETLEX_EXT_ERR_INVALID_ARGS;
    };
    let mut cursor = 0usize;
    let lex = mtproxy_core::runtime::mtproto::config::cfg_getlex_ext(bytes, &mut cursor);
    *out_ref = MtproxyMtprotoCfgGetlexExtResult {
        advance: cursor,
        lex,
    };
    MTPROTO_CFG_GETLEX_EXT_OK
}

pub(super) fn mtproto_cfg_scan_directive_token_ffi(
    cur: *const c_char,
    len: usize,
    min_connections: i64,
    max_connections: i64,
    out: *mut MtproxyMtprotoCfgDirectiveTokenResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_ARGS;
    };
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_ARGS;
    };
    match mtproxy_core::runtime::mtproto::config::cfg_scan_directive_token(
        bytes,
        min_connections,
        max_connections,
    ) {
        Ok(preview) => {
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

pub(super) fn mtproto_cfg_parse_directive_step_ffi(
    cur: *const c_char,
    len: usize,
    min_connections: i64,
    max_connections: i64,
    cluster_ids: *const i32,
    clusters_len: u32,
    max_clusters: u32,
    out: *mut MtproxyMtprotoCfgDirectiveStepResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    let Ok(max_clusters_usize) = usize::try_from(max_clusters) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    let Some(cluster_ids_slice) = (unsafe { slice_from_ptr(cluster_ids, clusters_len_usize) })
    else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
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

#[allow(clippy::too_many_arguments)]
pub(super) fn mtproto_cfg_parse_proxy_target_step_ffi(
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
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
    let Some(cluster_ids_slice) = (unsafe { slice_from_ptr(cluster_ids, clusters_len_usize) })
    else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };

    let last_cluster_state = if has_last_cluster_state != 0 {
        let Some(state_ref) = (unsafe { ref_from_ptr(last_cluster_state) }) else {
            return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
        };
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

#[allow(clippy::too_many_arguments)]
pub(super) fn mtproto_cfg_parse_full_pass_ffi(
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    };
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
                let Some(out_actions) =
                    (unsafe { mut_slice_from_ptr(actions, actions_capacity_usize) })
                else {
                    return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
                };
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

pub(super) fn mtproto_cfg_expect_semicolon_ffi(
    cur: *const c_char,
    len: usize,
    out_advance: *mut usize,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_advance) }) else {
        return MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS;
    };
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS;
    };
    let mut cursor = 0usize;
    match mtproxy_core::runtime::mtproto::config::cfg_expect_semicolon(bytes, &mut cursor) {
        Ok(()) => {
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

#[allow(clippy::too_many_arguments)]
pub(super) fn mtproto_cfg_lookup_cluster_index_ffi(
    cluster_ids: *const i32,
    clusters_len: u32,
    cluster_id: i32,
    force: i32,
    default_cluster_index: i32,
    has_default_cluster_index: i32,
    out_cluster_index: *mut i32,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_cluster_index) }) else {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    };
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
    let Some(cluster_ids_slice) = (unsafe { slice_from_ptr(cluster_ids, clusters_len_usize) })
    else {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    };
    let lookup = mtproxy_core::runtime::mtproto::config::mf_cluster_lookup_index(
        cluster_ids_slice,
        cluster_id,
        if force != 0 { default_idx } else { None },
    );
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

pub(super) fn mtproto_cfg_finalize_ffi(
    have_proxy: i32,
    cluster_ids: *const i32,
    clusters_len: u32,
    default_cluster_id: i32,
    out: *mut MtproxyMtprotoCfgFinalizeResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS;
    };
    let Some(cluster_ids_slice) = (unsafe { slice_from_ptr(cluster_ids, clusters_len_usize) })
    else {
        return MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS;
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
            *out_ref = MtproxyMtprotoCfgFinalizeResult {
                default_cluster_index,
                has_default_cluster_index,
            };
            MTPROTO_CFG_FINALIZE_OK
        }
        Err(err) => mtproto_cfg_finalize_err_to_code(err),
    }
}

pub(super) fn mtproto_cfg_parse_config_ffi(mc: *mut c_void, flags: i32, config_fd: i32) -> i32 {
    if (flags & 4) == 0 {
        return -1;
    }
    let Some(mc_ref) = (unsafe { mut_ref_from_ptr(mc.cast::<MtproxyMfConfig>()) }) else {
        return -1;
    };
    let mc_ptr = mc_ref as *mut MtproxyMfConfig;

    if (flags & 17) == 0 && unsafe { load_config(config_filename.cast_const(), config_fd) } < 0 {
        return -2;
    }

    unsafe { reset_config() };
    let parse_start = unsafe { cfg_cur };
    let parse_end = unsafe { cfg_end };
    if parse_start.is_null() || parse_end.is_null() {
        mtproto_cfg_syntax_literal(b"internal parser cursor mismatch\0");
        return -1;
    }
    let parse_delta = unsafe { parse_end.offset_from(parse_start) };
    if parse_delta < 0 {
        mtproto_cfg_syntax_literal(b"internal parser cursor mismatch\0");
        return -1;
    }
    let parse_len = parse_delta as usize;

    let actions = unsafe {
        calloc(
            MTPROTO_CFG_MAX_TARGETS,
            core::mem::size_of::<MtproxyMtprotoCfgProxyAction>(),
        )
    }
    .cast::<MtproxyMtprotoCfgProxyAction>();
    if actions.is_null() {
        mtproto_cfg_syntax_literal(b"out of memory while parsing configuration\0");
        return -1;
    }

    let mut res = -1;
    let mut parsed = MtproxyMtprotoCfgParseFullResult::default();
    'parse: loop {
        let pass_rc = unsafe {
            mtproto_cfg_parse_full_pass_ffi(
                parse_start.cast_const(),
                parse_len,
                i64::from(default_cfg_min_connections),
                i64::from(default_cfg_max_connections),
                if (flags & 1) != 0 { 1 } else { 0 },
                MTPROTO_CFG_MAX_CLUSTERS as u32,
                MTPROTO_CFG_MAX_TARGETS as u32,
                actions,
                MTPROTO_CFG_MAX_TARGETS as u32,
                &raw mut parsed,
            )
        };
        if pass_rc != MTPROTO_CFG_PARSE_FULL_PASS_OK {
            mtproto_cfg_report_parse_full_pass_error(pass_rc, mc_ref.tot_targets);
            break 'parse;
        }

        mc_ref.tot_targets = parsed.tot_targets as c_int;
        mc_ref.auth_clusters = parsed.auth_clusters as c_int;
        mc_ref.auth_stats.tot_clusters = parsed.auth_tot_clusters as c_int;
        mc_ref.min_connections = parsed.min_connections as c_int;
        mc_ref.max_connections = parsed.max_connections as c_int;
        mc_ref.timeout = parsed.timeout_seconds;
        mc_ref.default_cluster_id = parsed.default_cluster_id;
        mc_ref.have_proxy = if parsed.have_proxy != 0 { 1 } else { 0 };
        mc_ref.default_cluster = core::ptr::null_mut();

        let Ok(actions_len) = usize::try_from(parsed.actions_len) else {
            mtproto_cfg_syntax_literal(b"internal parser action count mismatch\0");
            break 'parse;
        };
        if actions_len > MTPROTO_CFG_MAX_TARGETS {
            mtproto_cfg_syntax_literal(b"internal parser action count mismatch\0");
            break 'parse;
        }

        for i in 0..actions_len {
            let action = unsafe { *actions.add(i) };
            if action.host_offset > parse_len {
                mtproto_cfg_syntax_literal(b"internal parser host offset mismatch\0");
                break 'parse;
            }
            let Some(host_advance) = action.host_offset.checked_add(action.step.advance) else {
                mtproto_cfg_syntax_literal(b"internal parser target advance mismatch\0");
                break 'parse;
            };
            if host_advance > parse_len {
                mtproto_cfg_syntax_literal(b"internal parser target advance mismatch\0");
                break 'parse;
            }

            let host_cur = unsafe { parse_start.add(action.host_offset) };
            unsafe { cfg_cur = host_cur };
            if mtproto_cfg_resolve_default_target_from_cfg_cur_ffi() < 0 {
                break 'parse;
            }

            if action.step.target_index >= MTPROTO_CFG_MAX_TARGETS as u32
                || action.step.target_index >= parsed.tot_targets
            {
                mtproto_cfg_syntax_literal(b"internal parser target index mismatch\0");
                break 'parse;
            }
            unsafe { cfg_cur = host_cur.add(action.step.advance) };
            unsafe {
                mtproto_cfg_set_default_target_endpoint_ffi(
                    action.step.port,
                    action.step.min_connections,
                    action.step.max_connections,
                    1.0 + 0.1 * drand48(),
                );
            }

            if (flags & 1) != 0 {
                mtproto_cfg_create_target_ffi(mc_ptr, action.step.target_index);
            }

            if action.step.cluster_index < 0
                || action.step.cluster_index >= MTPROTO_CFG_MAX_CLUSTERS as i32
            {
                mtproto_cfg_syntax_literal(b"internal parser cluster decision mismatch\0");
                break 'parse;
            }
            if action.step.auth_clusters_after > MTPROTO_CFG_MAX_CLUSTERS as u32 {
                mtproto_cfg_syntax_literal(b"internal parser auth cluster count mismatch\0");
                break 'parse;
            }

            let Ok(cluster_index) = usize::try_from(action.step.cluster_index) else {
                mtproto_cfg_syntax_literal(b"internal parser cluster decision mismatch\0");
                break 'parse;
            };
            let mfc = &mut mc_ref.auth_cluster[cluster_index];
            mfc.flags = action.step.cluster_state_after.flags as c_int;
            mfc.targets_num = action.step.cluster_state_after.targets_num as c_int;
            mfc.write_targets_num = action.step.cluster_state_after.write_targets_num as c_int;
            mfc.targets_allocated = 0;
            mfc.cluster_id = action.step.cluster_state_after.cluster_id;
            match action.step.cluster_targets_action {
                MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING => {}
                MTPROTO_CFG_CLUSTER_TARGETS_ACTION_CLEAR => {
                    mfc.cluster_targets = core::ptr::null_mut();
                }
                MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET => {
                    if (flags & 1) == 0 {
                        mtproto_cfg_syntax_literal(
                            b"internal parser cluster target action mismatch\0",
                        );
                        break 'parse;
                    }
                    if action.step.cluster_targets_index >= MTPROTO_CFG_MAX_TARGETS as u32
                        || action.step.cluster_targets_index >= action.step.tot_targets_after
                    {
                        mtproto_cfg_syntax_literal(
                            b"internal parser cluster target index mismatch\0",
                        );
                        break 'parse;
                    }
                    let target_index = action.step.cluster_targets_index as usize;
                    mfc.cluster_targets = &mut mc_ref.targets[target_index];
                }
                _ => {
                    mtproto_cfg_syntax_literal(b"internal parser cluster target action mismatch\0");
                    break 'parse;
                }
            }

            if action.step.cluster_decision_kind
                == MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW
            {
                if unsafe { verbosity } >= 3 {
                    unsafe {
                        crate::kprintf_fmt!(
                            b"-> added target to new auth_cluster #%d\n\0"
                                .as_ptr()
                                .cast(),
                            action.step.cluster_index,
                        );
                    }
                }
            } else if action.step.cluster_decision_kind
                == MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST
                && unsafe { verbosity } >= 3
            {
                unsafe {
                    crate::kprintf_fmt!(
                        b"-> added target to old auth_cluster #%d\n\0"
                            .as_ptr()
                            .cast(),
                        action.step.cluster_index,
                    );
                }
            }
        }

        mc_ref.tot_targets = parsed.tot_targets as c_int;
        mc_ref.auth_clusters = parsed.auth_clusters as c_int;
        mc_ref.auth_stats.tot_clusters = parsed.auth_tot_clusters as c_int;
        mc_ref.have_proxy = if parsed.have_proxy != 0 { 1 } else { 0 };
        if parsed.has_default_cluster_index != 0 {
            if parsed.default_cluster_index >= parsed.auth_clusters
                || parsed.default_cluster_index >= MTPROTO_CFG_MAX_CLUSTERS as u32
            {
                mtproto_cfg_syntax_literal(b"internal parser default cluster index mismatch\0");
                break 'parse;
            }
            let default_index = parsed.default_cluster_index as usize;
            mc_ref.default_cluster = &mut mc_ref.auth_cluster[default_index];
        } else {
            mc_ref.default_cluster = core::ptr::null_mut();
        }

        res = 0;
        break 'parse;
    }

    unsafe { free(actions.cast()) };
    res
}

pub(super) fn mtproto_cfg_do_reload_config_ffi(flags: i32) -> i32 {
    if (flags & 4) == 0 {
        return -1;
    }

    let mut fd = -1;
    if (flags & 16) == 0 {
        fd = unsafe { open(config_filename.cast_const(), O_RDONLY_FLAG) };
        if fd < 0 {
            unsafe {
                crate::kprintf_fmt!(
                    b"cannot re-read config file %s: %m\n\0".as_ptr().cast(),
                    config_filename,
                );
            }
            return -1;
        }

        let reload_hosts = unsafe { kdb_load_hosts() };
        if reload_hosts > 0 && unsafe { verbosity } >= 1 {
            unsafe { crate::kprintf_fmt!(b"/etc/hosts changed, reloaded\n\0".as_ptr().cast()) };
        }
    }

    let mut res = mtproto_cfg_parse_config_ffi(unsafe { NextConf.cast() }, flags & !1, fd);

    if fd >= 0 {
        unsafe { close(fd) };
    }

    if res < 0 {
        unsafe {
            crate::kprintf_fmt!(
                b"error while re-reading config file %s, new configuration NOT applied\n\0"
                    .as_ptr()
                    .cast(),
                config_filename,
            );
        }
        return res;
    }

    if (flags & 32) != 0 {
        return 0;
    }

    res = mtproto_cfg_parse_config_ffi(unsafe { NextConf.cast() }, flags | 1, -1);
    if res < 0 {
        unsafe { clear_config_ffi(NextConf, 0) };
        unsafe {
            crate::kprintf_fmt!(
                b"fatal error while re-reading config file %s\n\0"
                    .as_ptr()
                    .cast(),
                config_filename,
            )
        };
        unsafe { exit(-res) };
    }

    let old_cur_conf = unsafe { CurConf };
    unsafe {
        CurConf = NextConf;
        NextConf = old_cur_conf;
    }

    unsafe { clear_config_ffi(NextConf, 1) };
    if (flags & 1) != 0 {
        unsafe { create_all_outbound_connections() };
    }

    let cur_conf = unsafe { CurConf };
    if !cur_conf.is_null() {
        let cur_conf_ref = unsafe { &mut *cur_conf };
        let cur_now = mtproto_cfg_now_or_time_ffi();
        cur_conf_ref.config_loaded_at = cur_now;
        cur_conf_ref.config_bytes = unsafe { config_bytes };
        cur_conf_ref.config_md5_hex = unsafe { malloc(33).cast() };
        if !cur_conf_ref.config_md5_hex.is_null() {
            unsafe {
                md5_hex_config(cur_conf_ref.config_md5_hex);
                *cur_conf_ref.config_md5_hex.add(32) = 0;
            }
        }
    }

    unsafe {
        crate::kprintf_fmt!(
            b"configuration file %s re-read successfully (%d bytes parsed), new configuration active\n\0"
                .as_ptr()
                .cast(),
            config_filename,
            config_bytes,
        );
    }

    0
}
