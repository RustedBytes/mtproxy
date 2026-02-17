//! Rust runtime implementation for selected large functions in
//! `engine/engine-rpc.c`.

use core::ffi::{c_char, c_double, c_int, c_long, c_longlong, c_uint, c_ulonglong, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use std::ffi::{CStr, CString};

const JS_RUN: c_int = 0;
const JS_ALARM: c_int = 4;
const JS_ABORT: c_int = 5;
const JS_FINISH: c_int = 7;

const JOB_COMPLETED: c_int = 0x100;
const JOB_ERROR: c_int = -1;

const JC_ENGINE: c_int = 8;
const JSP_PARENT_ERROR: c_int = 1;
const JSP_PARENT_INCOMPLETE: c_int = 0x10;
const JSP_PARENT_RWE: c_int = 7;
const JF_COMPLETED: c_int = 0x40000;
const JT_HAVE_TIMER: u64 = 1;

const TL_TYPE_RAW_MSG: c_int = 2;
const TL_TYPE_TCP_RAW_MSG: c_int = 3;
const TL_TRUE: c_int = 0x3fedd339_u32 as c_int;

const TL_ERROR_UNKNOWN_FUNCTION_ID: c_int = -2000;
const TL_ERROR_AIO_TIMEOUT: c_int = -3005;
const TL_ERROR_AIO_MAX_RETRY_EXCEEDED: c_int = -3007;
const TL_ERROR_BAD_METAFILE: c_int = -3009;
const TL_ERROR_UNKNOWN: c_int = -4000;

const RPC_REQ_RESULT: c_int = 0x63aeda4e_u32 as c_int;

const MTPROXY_FFI_ENGINE_RPC_QJ_INVOKE_PARSE: c_int = 0;
const MTPROXY_FFI_ENGINE_RPC_QJ_CUSTOM: c_int = 1;
const MTPROXY_FFI_ENGINE_RPC_QJ_IGNORE: c_int = 2;
const MTPROXY_FFI_ENGINE_RPC_QR_DISPATCH: c_int = 1;
const MTPROXY_FFI_ENGINE_RPC_QR_SKIP_UNKNOWN: c_int = 2;
const CONN_CUSTOM_DATA_BYTES: usize = 256;

const UNKNOWN_QUERY_TYPE_FMT: &[u8] =
    b"Unknown query type %d (qid = 0x%016llx). Skipping query result.\n\0";
const ERR_MAX_RETRIES: &[u8] = b"Maximum number of retries exceeded\0";
const ERR_BAD_METAFILE: &[u8] = b"Error loading metafile\0";
const ERR_UNKNOWN: &[u8] = b"Unknown error\0";
const ERR_JOB_CANCELLED: &[u8] = b"Job cancelled\0";
const ERR_CANCELLED: &[u8] = b"Cancelled\0";
const ERR_BINLOG_WAIT: &[u8] = b"Binlog wait error\0";
const ERR_AIO_WAIT: &[u8] = b"Aio wait error\0";
const PERCENT_S_FMT: &[u8] = b"%s\0";
const TL_STAT: c_int = 0x9d56e6b2_u32 as c_int;
const RPC_REQ_RESULT_FLAGS: c_int = 0x8cc84ce1_u32 as c_int;

static LAST_QID: AtomicU32 = AtomicU32::new(0);
const QUERY_RESULT_TYPES: usize = 16;

pub(super) type Job = *mut AsyncJob;
type ConnectionJob = *mut c_void;
type OpaqueJob = *mut c_void;
type OpaqueJobFunction = Option<unsafe extern "C" fn(*mut c_void, c_int, *mut c_void) -> c_int>;

type JobFunction = Option<unsafe extern "C" fn(Job, c_int, *mut c_void) -> c_int>;
type TlActFn = Option<unsafe extern "C" fn(Job, *mut TlActExtra) -> c_int>;
type TlActFreeFn = Option<unsafe extern "C" fn(*mut TlActExtra)>;
type TlActDupFn = Option<unsafe extern "C" fn(*mut TlActExtra) -> *mut TlActExtra>;
pub(super) type TlParseFn =
    Option<unsafe extern "C" fn(*mut TlInState, c_longlong) -> *mut TlActExtra>;
pub(super) type TlGetOpFn = Option<unsafe extern "C" fn(*mut TlInState) -> c_int>;
pub(super) type TlStatFn = Option<unsafe extern "C" fn(*mut c_void)>;
pub(super) type TlQueryResultFn = Option<unsafe extern "C" fn(*mut TlInState, *mut TlQueryHeader)>;
pub(super) type CustomOpFn = Option<unsafe extern "C" fn(*mut TlInState, *mut QueryWorkParams)>;

static mut TL_PARSE_FUNCTION: TlParseFn = None;
static mut TL_GET_OP_FUNCTION: TlGetOpFn = None;
static mut TL_STAT_FUNCTION: TlStatFn = None;
static mut TL_AIO_TIMEOUT: c_double = 0.0;
static mut TL_QUERY_RESULT_TABLE_ALLOCATED: bool = false;
static mut TL_QUERY_RESULT_FUNCTIONS: [TlQueryResultFn; QUERY_RESULT_TYPES] =
    [None; QUERY_RESULT_TYPES];

#[repr(C)]
#[derive(Clone, Copy)]
struct EventTimer {
    h_idx: c_int,
    flags: c_int,
    wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> c_int>,
    wakeup_time: c_double,
    real_wakeup_time: c_double,
}

#[repr(C, packed(4))]
#[derive(Clone, Copy)]
pub(super) struct ProcessId {
    ip: u32,
    port: i16,
    pid: u16,
    utime: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct RawMessage {
    first: *mut c_void,
    last: *mut c_void,
    total_bytes: c_int,
    magic: c_int,
    first_offset: c_int,
    last_offset: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct TlQueryHeader {
    qid: c_longlong,
    actor_id: c_longlong,
    flags: c_int,
    op: c_int,
    real_op: c_int,
    ref_cnt: c_int,
    qw_params: *mut QueryWorkParams,
}

#[repr(C)]
pub(super) struct TlInState {
    in_type: c_int,
    in_methods: *const c_void,
    in_: *mut c_void,
    in_mark: *mut c_void,
    in_remaining: c_int,
    in_pos: c_int,
    in_mark_pos: c_int,
    in_flags: c_int,
    pub error: *mut c_char,
    pub errnum: c_int,
    in_pid_buf: ProcessId,
    in_pid: *mut ProcessId,
}

#[repr(C)]
struct TlOutState {
    out_type: c_int,
    out_methods: *const c_void,
    out: *mut c_void,
    out_extra: *mut c_void,
    out_pos: c_int,
    out_remaining: c_int,
    out_size: *mut c_int,
    error: *mut c_char,
    errnum: c_int,
    out_qid: c_longlong,
    out_pid_buf: ProcessId,
    out_pid: *mut ProcessId,
}

#[repr(C)]
pub(super) struct TlActExtra {
    size: c_int,
    flags: c_int,
    attempt: c_int,
    type_: c_int,
    op: c_int,
    subclass: c_int,
    hash: u64,
    start_rdtsc: c_longlong,
    cpu_rdtsc: c_longlong,
    tlio_out: *mut TlOutState,
    act: TlActFn,
    free: TlActFreeFn,
    dup: TlActDupFn,
    header: *mut TlQueryHeader,
    raw: *mut *mut RawMessage,
    error: *mut *mut c_char,
    extra_ref: Job,
    error_code: *mut c_int,
}

#[repr(C)]
pub(super) struct QueryWorkParams {
    ev: EventTimer,
    type_: c_int,
    pid: ProcessId,
    src: RawMessage,
    h: *mut TlQueryHeader,
    result: *mut RawMessage,
    error_code: c_int,
    answer_sent: c_int,
    wait_coord: c_int,
    error: *mut c_char,
    wait_pos: *mut c_void,
    p: *mut c_void,
    start_rdtsc: c_longlong,
    total_work_rdtsc: c_longlong,
    all_list: Job,
    fd: c_int,
    generation: c_int,
}

#[repr(C)]
struct QueryInfo {
    ev: EventTimer,
    raw: RawMessage,
    src_type: c_int,
    src_pid: ProcessId,
    conn: *mut c_void,
}

type Crc32PartialFn = Option<unsafe extern "C" fn(*const c_void, c_long, c_uint) -> c_uint>;

#[repr(C)]
struct ConnectionInfo {
    timer: EventTimer,
    fd: c_int,
    generation: c_int,
    flags: c_int,
    type_: *mut c_void,
    extra: *mut c_void,
    target: ConnectionJob,
    io_conn: ConnectionJob,
    basic_type: c_int,
    status: c_int,
    error: c_int,
    unread_res_bytes: c_int,
    skip_bytes: c_int,
    pending_queries: c_int,
    queries_ok: c_int,
    custom_data: [u8; CONN_CUSTOM_DATA_BYTES],
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
    in_u: RawMessage,
    in_data: RawMessage,
    out: RawMessage,
    out_p: RawMessage,
    in_queue: *mut c_void,
    out_queue: *mut c_void,
}

#[repr(C)]
struct TcpRpcData {
    flags: c_int,
    in_packet_num: c_int,
    out_packet_num: c_int,
    crypto_flags: c_int,
    remote_pid: ProcessId,
    nonce: [u8; 16],
    nonce_time: c_int,
    in_rpc_target: c_int,
    user_data: *mut c_void,
    extra_int: c_int,
    extra_int2: c_int,
    extra_int3: c_int,
    extra_int4: c_int,
    extra_double: c_double,
    extra_double2: c_double,
    custom_crc_partial: Crc32PartialFn,
}

#[repr(C, packed(4))]
struct RpcCustomOp {
    op: c_uint,
    func: CustomOpFn,
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[inline]
fn rdtsc_now() -> c_longlong {
    #[cfg(target_arch = "x86_64")]
    let ticks = unsafe { core::arch::x86_64::_rdtsc() };
    #[cfg(target_arch = "x86")]
    let ticks = unsafe { core::arch::x86::_rdtsc() };

    c_longlong::try_from(ticks).unwrap_or(c_longlong::MAX)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
#[inline]
fn rdtsc_now() -> c_longlong {
    0
}

#[repr(C, align(64))]
pub(super) struct AsyncJob {
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
    j_execute: JobFunction,
    j_parent: Job,
    j_custom: [i64; 0],
}

unsafe extern "C" {
    fn mtproxy_ffi_engine_rpc_query_job_dispatch_decision(
        op: c_int,
        has_custom_tree: c_int,
    ) -> c_int;
    fn mtproxy_ffi_engine_rpc_query_result_type_id_from_qid(qid: c_longlong) -> c_int;
    fn mtproxy_ffi_engine_rpc_query_result_dispatch_decision(
        has_table: c_int,
        has_handler: c_int,
    ) -> c_int;
    fn mtproxy_ffi_engine_rpc_tcp_should_hold_conn(op: c_int) -> c_int;
    fn mtproxy_ffi_engine_rpc_custom_op_insert(op: c_uint, entry: *mut c_void) -> c_int;
    fn mtproxy_ffi_engine_rpc_custom_op_lookup(op: c_uint) -> *mut c_void;

    fn tl_query_header_dup(h: *mut TlQueryHeader) -> *mut TlQueryHeader;
    fn prepare_stats(buff: *mut c_char, buff_size: c_int) -> c_int;
    fn kprintf(format: *const c_char, ...);
    static mut verbosity: c_int;

    fn tlf_error_rust(tlio_in: *mut c_void) -> c_int;
    fn tlf_set_error(tlio_in: *mut c_void, errnum: c_int, s: *const c_char) -> c_int;
    fn tlf_int_rust(tlio_in: *mut c_void) -> c_int;
    fn tlf_end_rust(tlio_in: *mut c_void) -> c_int;
    fn tlf_lookup_int_rust(tlio_in: *mut c_void) -> c_int;
    #[link_name = "tlf_query_answer_header"]
    fn c_tlf_query_answer_header(tlio_in: *mut c_void, header: *mut TlQueryHeader) -> c_int;

    #[link_name = "create_async_job"]
    fn c_create_async_job(
        run_job: OpaqueJobFunction,
        job_signals: u64,
        job_subclass: c_int,
        custom_bytes: c_int,
        job_type: u64,
        parent_tag_int: c_int,
        parent_job: OpaqueJob,
    ) -> OpaqueJob;
    #[link_name = "insert_job_into_job_list"]
    fn c_insert_job_into_job_list(
        list_job: OpaqueJob,
        job_tag_int: c_int,
        job: OpaqueJob,
        mode: c_int,
    ) -> c_int;
    #[link_name = "job_incref"]
    fn c_job_incref(job: OpaqueJob) -> OpaqueJob;
    #[link_name = "job_decref"]
    fn c_job_decref(job_tag_int: c_int, job: OpaqueJob);
    #[link_name = "job_signal"]
    fn c_job_signal(job_tag_int: c_int, job: OpaqueJob, signo: c_int);
    #[link_name = "schedule_job"]
    fn c_schedule_job(job_tag_int: c_int, job: OpaqueJob) -> c_int;
    #[link_name = "job_timer_check"]
    fn c_job_timer_check(job: OpaqueJob) -> c_int;
    #[link_name = "job_timer_remove"]
    fn c_job_timer_remove(job: OpaqueJob);
    #[link_name = "job_timer_insert"]
    fn c_job_timer_insert(job: OpaqueJob, timeout: c_double);
    #[link_name = "job_timer_active"]
    fn c_job_timer_active(job: OpaqueJob) -> c_int;
    #[link_name = "job_free"]
    fn c_job_free(job_tag_int: c_int, job: OpaqueJob) -> c_int;

    #[link_name = "tl_out_state_alloc"]
    fn c_tl_out_state_alloc() -> *mut c_void;
    #[link_name = "tl_out_state_free"]
    fn c_tl_out_state_free(tlio_out: *mut c_void);
    #[link_name = "tls_init_raw_msg_nosend"]
    fn c_tls_init_raw_msg_nosend(tlio_out: *mut c_void) -> c_int;
    #[link_name = "tls_init_raw_msg"]
    fn c_tls_init_raw_msg(tlio_out: *mut c_void, pid: *mut ProcessId, qid: c_longlong) -> c_int;
    #[link_name = "tls_init_tcp_raw_msg"]
    fn c_tls_init_tcp_raw_msg(
        tlio_out: *mut c_void,
        c_tag_int: c_int,
        c: ConnectionJob,
        qid: c_longlong,
    ) -> c_int;
    #[link_name = "tls_int_rust"]
    fn c_tls_int_rust(tlio_out: *mut c_void, value: c_int) -> c_int;
    #[link_name = "tls_string_rust"]
    fn c_tls_string_rust(tlio_out: *mut c_void, s: *const c_char, len: c_int) -> c_int;
    #[link_name = "tls_set_error_format"]
    fn c_tls_set_error_format(
        tlio_out: *mut c_void,
        errnum: c_int,
        format: *const c_char,
        ...
    ) -> c_int;
    #[link_name = "tls_get_ptr_rust"]
    fn c_tls_get_ptr_rust(tlio_out: *mut c_void, size: c_int) -> *mut c_void;
    #[link_name = "tls_raw_msg_rust"]
    fn c_tls_raw_msg_rust(tlio_out: *mut c_void, raw: *mut RawMessage, dup: c_int) -> c_int;
    #[link_name = "tls_end_ext"]
    fn c_tls_end_ext(tlio_out: *mut c_void, op: c_int) -> c_int;

    fn rwm_clone(dest_raw: *mut RawMessage, src_raw: *mut RawMessage);
    fn rwm_free(raw: *mut RawMessage) -> c_int;

    #[link_name = "tl_in_state_alloc"]
    fn c_tl_in_state_alloc() -> *mut c_void;
    #[link_name = "tl_in_state_free"]
    fn c_tl_in_state_free(tlio_in: *mut c_void);
    #[link_name = "tlf_init_raw_message"]
    fn c_tlf_init_raw_message(
        tlio_in: *mut c_void,
        msg: *mut c_void,
        size: c_int,
        dup: c_int,
    ) -> c_int;
    #[link_name = "tlf_query_header"]
    fn c_tlf_query_header(tlio_in: *mut c_void, header: *mut TlQueryHeader) -> c_int;
    fn tl_query_header_delete(h: *mut TlQueryHeader);

    fn mtproxy_ffi_engine_rpc_custom_op_has_any() -> c_int;

    fn connection_get_by_fd(fd: c_int) -> ConnectionJob;
    fn rpc_target_lookup(pid: *mut ProcessId) -> *mut c_void;
    fn rpc_target_choose_connection(s: *mut c_void, pid: *mut ProcessId) -> ConnectionJob;
    fn rpc_target_insert_conn(conn: *mut c_void);
    fn rpc_target_delete_conn(conn: *mut c_void);

    fn paramed_type_free(p: *mut c_void);
    fn lrand48_j() -> c_long;
}

#[inline]
const fn jss_allow(sig: c_int) -> u64 {
    0x0100_0000_u64 << (sig as u32)
}

#[inline]
const fn jsc_type(class: c_int, sig: c_int) -> u64 {
    (class as u64) << ((sig as u32) * 4 + 32)
}

#[inline]
const fn jsc_allow(class: c_int, sig: c_int) -> u64 {
    jsc_type(class, sig) | jss_allow(sig)
}

#[inline]
unsafe fn parent_job_aborted(job: Job) -> bool {
    (unsafe { (*job).j_status } & JSP_PARENT_INCOMPLETE) != 0
        && !unsafe { (*job).j_parent }.is_null()
        && (unsafe { (*(*job).j_parent).j_flags } & JF_COMPLETED) != 0
}

#[inline]
unsafe fn job_fatal(job: Job, error: c_int) -> c_int {
    if unsafe { (*job).j_error } == 0 {
        unsafe {
            (*job).j_error = error;
        }
    }
    JOB_COMPLETED
}

#[inline]
unsafe fn job_custom_ptr<T>(job: Job) -> *mut T {
    unsafe { (*job).j_custom.as_mut_ptr().cast::<T>() }
}

#[inline]
unsafe fn query_work_params(job: Job) -> *mut QueryWorkParams {
    unsafe { job_custom_ptr::<QueryWorkParams>(job) }
}

#[inline]
unsafe fn query_info(job: Job) -> *mut QueryInfo {
    unsafe { job_custom_ptr::<QueryInfo>(job) }
}

#[inline]
unsafe fn conn_info(conn: *mut c_void) -> *mut ConnectionInfo {
    assert!(!conn.is_null());
    let info = unsafe { job_custom_ptr::<ConnectionInfo>(conn.cast::<AsyncJob>()) };
    assert!(!info.is_null());
    info
}

#[inline]
unsafe fn conn_fd(conn: *mut c_void) -> c_int {
    unsafe { (*conn_info(conn)).fd }
}

#[inline]
unsafe fn conn_generation(conn: *mut c_void) -> c_int {
    unsafe { (*conn_info(conn)).generation }
}

#[inline]
unsafe fn precise_now_value() -> c_double {
    crate::mtproxy_ffi_precise_now_value()
}

#[inline]
unsafe fn touch_conn_last_response_time(conn: *mut c_void) {
    unsafe {
        (*conn_info(conn)).last_response_time = precise_now_value();
    }
}

#[inline]
unsafe fn tcp_rpc_data(conn: *mut c_void) -> *mut TcpRpcData {
    let info = unsafe { conn_info(conn) };
    let base = ptr::addr_of!((*info).custom_data).cast::<u8>() as usize;
    let align = core::mem::align_of::<TcpRpcData>();
    let aligned = (base + align - 1) & !(align - 1);
    assert!(aligned + size_of::<TcpRpcData>() <= base + CONN_CUSTOM_DATA_BYTES);
    aligned as *mut TcpRpcData
}

#[inline]
unsafe fn copy_tcp_remote_pid(conn: *mut c_void, pid: *mut ProcessId) {
    assert!(!pid.is_null());
    let remote = unsafe { ptr::read_unaligned(ptr::addr_of!((*tcp_rpc_data(conn)).remote_pid)) };
    unsafe {
        ptr::write_unaligned(pid, remote);
    }
}

#[inline]
unsafe fn call_default_parse_function(
    tlio_in: *mut TlInState,
    actor_id: c_longlong,
) -> *mut TlActExtra {
    unsafe { default_parse_function_impl(tlio_in, actor_id) }
}

unsafe extern "C" fn default_tl_act_nop(_job: Job, extra: *mut TlActExtra) -> c_int {
    assert!(!extra.is_null());
    unsafe {
        c_tls_int_rust((*extra).tlio_out.cast(), TL_TRUE);
    }
    0
}

unsafe extern "C" fn default_tl_act_stat(_job: Job, extra: *mut TlActExtra) -> c_int {
    assert!(!extra.is_null());
    unsafe {
        tl_engine_store_stats_impl((*extra).tlio_out.cast());
    }
    0
}

unsafe fn default_tl_simple_parse_function(
    tlio_in: *mut TlInState,
    act: TlActFn,
) -> *mut TlActExtra {
    unsafe {
        tlf_int_rust(tlio_in.cast());
        tlf_end_rust(tlio_in.cast());
    }
    if unsafe { tlf_error_rust(tlio_in.cast()) } != 0 {
        return ptr::null_mut();
    }

    let extra = unsafe { libc::calloc(1, size_of::<TlActExtra>()) }.cast::<TlActExtra>();
    if extra.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        (*extra).flags = 3;
        (*extra).start_rdtsc = rdtsc_now();
        (*extra).size = size_of::<TlActExtra>() as c_int;
        (*extra).act = act;
        (*extra).type_ = mtproxy_core::runtime::engine::rpc_common::default_query_type_mask();
    }

    extra
}

pub(super) unsafe fn default_parse_function_impl(
    tlio_in: *mut TlInState,
    actor_id: c_longlong,
) -> *mut TlActExtra {
    let op = unsafe { tlf_lookup_int_rust(tlio_in.cast()) };
    if unsafe { tlf_error_rust(tlio_in.cast()) } != 0 {
        return ptr::null_mut();
    }

    use mtproxy_core::runtime::engine::rpc_common::DefaultParseDecision;
    match mtproxy_core::runtime::engine::rpc_common::default_parse_decision(actor_id, op) {
        DefaultParseDecision::Stat => {
            unsafe { default_tl_simple_parse_function(tlio_in, Some(default_tl_act_stat)) }
        }
        DefaultParseDecision::Nop => {
            unsafe { default_tl_simple_parse_function(tlio_in, Some(default_tl_act_nop)) }
        }
        DefaultParseDecision::None => ptr::null_mut(),
    }
}

#[inline]
unsafe fn log_unknown_query_type(query_type_id: c_int, qid: c_longlong) {
    if unsafe { verbosity } >= 1 {
        unsafe {
            kprintf(
                UNKNOWN_QUERY_TYPE_FMT.as_ptr().cast(),
                query_type_id,
                qid as c_ulonglong,
            );
        }
    }
}

#[inline]
unsafe fn dup_error_or_null(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        ptr::null_mut()
    } else {
        unsafe { libc::strdup(s) }
    }
}

pub(super) unsafe fn tl_aio_init_store_impl(
    type_: c_int,
    pid: *mut ProcessId,
    qid: c_longlong,
) -> *mut c_void {
    if type_ == TL_TYPE_RAW_MSG {
        let io = unsafe { c_tl_out_state_alloc() }.cast::<TlOutState>();
        assert!(!io.is_null());
        unsafe {
            c_tls_init_raw_msg(io.cast(), pid, qid);
        }
        return io.cast();
    }
    if type_ == TL_TYPE_TCP_RAW_MSG {
        let d = unsafe { rpc_target_choose_connection(rpc_target_lookup(pid), pid) };
        if d.is_null() {
            return ptr::null_mut();
        }
        let io = unsafe { c_tl_out_state_alloc() }.cast::<TlOutState>();
        assert!(!io.is_null());
        unsafe {
            c_tls_init_tcp_raw_msg(io.cast(), 1, d, qid);
        }
        return io.cast();
    }

    assert!(false, "invalid tl_type value in tl_aio_init_store");
    ptr::null_mut()
}

pub(super) unsafe fn register_custom_op_cb_impl(op: c_uint, func: CustomOpFn) {
    let entry = unsafe { libc::malloc(size_of::<RpcCustomOp>()) }.cast::<RpcCustomOp>();
    assert!(!entry.is_null());

    unsafe {
        ptr::addr_of_mut!((*entry).op).write_unaligned(op);
        ptr::addr_of_mut!((*entry).func).write_unaligned(func);
    }

    let rc = unsafe { mtproxy_ffi_engine_rpc_custom_op_insert(op, entry.cast()) };
    assert_eq!(rc, 0);
}

pub(super) unsafe fn tl_result_new_flags_impl(old_flags: c_int) -> c_int {
    let new_flags = old_flags & 0xffff;
    assert!((new_flags & !0xffff) == 0);
    new_flags
}

pub(super) unsafe fn tl_result_get_header_len_impl(h: *mut TlQueryHeader) -> c_int {
    assert!(!h.is_null());
    let len = if unsafe { (*h).flags } == 0 { 0 } else { 8 };
    assert!(len == 0 || len == 8);
    len
}

pub(super) unsafe fn tl_result_make_header_impl(ptr: *mut c_int, h: *mut TlQueryHeader) -> c_int {
    assert!(!ptr.is_null());
    assert!(!h.is_null());
    if unsafe { (*h).flags } == 0 {
        return 0;
    }

    let mut p = ptr;
    let new_flags = unsafe { tl_result_new_flags_impl((*h).flags) };
    unsafe {
        *p = RPC_REQ_RESULT_FLAGS;
        p = p.add(1);
        *p = new_flags;
        p = p.add(1);
    }
    ((p as usize) - (ptr as usize)) as c_int
}

pub(super) unsafe extern "C" fn tl_default_act_free_impl(extra: *mut TlActExtra) {
    assert!(!extra.is_null());
    if !unsafe { (*extra).header }.is_null() {
        unsafe {
            tl_query_header_delete((*extra).header);
        }
    }
    if (unsafe { (*extra).flags } & 1) == 0 {
        return;
    }
    unsafe {
        libc::free(extra.cast());
    }
}

pub(super) unsafe extern "C" fn tl_default_act_dup_impl(extra: *mut TlActExtra) -> *mut TlActExtra {
    assert!(!extra.is_null());
    let size = unsafe { (*extra).size };
    assert!(size >= size_of::<TlActExtra>() as c_int);

    let new_extra = unsafe { libc::malloc(size as usize) }.cast::<TlActExtra>();
    assert!(!new_extra.is_null());
    unsafe {
        ptr::copy_nonoverlapping(extra.cast::<u8>(), new_extra.cast::<u8>(), size as usize);
        (*new_extra).flags |= 3;
    }
    new_extra
}

pub(super) unsafe fn engine_work_rpc_req_result_impl(
    tlio_in: *mut TlInState,
    params: *mut QueryWorkParams,
) {
    let h = unsafe { libc::malloc(size_of::<TlQueryHeader>()) }.cast::<TlQueryHeader>();
    assert!(!h.is_null());

    if unsafe { c_tlf_query_answer_header(tlio_in.cast(), h) } < 0 {
        unsafe {
            tl_query_header_delete(h);
        }
        return;
    }

    unsafe {
        (*h).qw_params = params;
    }
    let query_type_id = unsafe { mtproxy_ffi_engine_rpc_query_result_type_id_from_qid((*h).qid) };
    let has_table = c_int::from(unsafe { TL_QUERY_RESULT_TABLE_ALLOCATED });
    let handler = if query_type_id >= 0 {
        let idx = query_type_id as usize;
        if idx < QUERY_RESULT_TYPES {
            unsafe { TL_QUERY_RESULT_FUNCTIONS[idx] }
        } else {
            None
        }
    } else {
        None
    };
    let has_handler = c_int::from(handler.is_some());
    let dispatch_decision =
        unsafe { mtproxy_ffi_engine_rpc_query_result_dispatch_decision(has_table, has_handler) };

    if dispatch_decision == MTPROXY_FFI_ENGINE_RPC_QR_DISPATCH {
        if let Some(dispatch) = handler {
            unsafe {
                dispatch(tlio_in, h);
            }
        }
    } else if dispatch_decision == MTPROXY_FFI_ENGINE_RPC_QR_SKIP_UNKNOWN {
        unsafe { log_unknown_query_type(query_type_id, (*h).qid) };
    }

    unsafe {
        tl_query_header_delete(h);
    }
}

unsafe fn query_act_custom_impl(tlio_in: *mut TlInState, p: *mut QueryWorkParams) {
    let op = unsafe { tlf_lookup_int_rust(tlio_in.cast()) } as c_uint;
    let custom = unsafe { mtproxy_ffi_engine_rpc_custom_op_lookup(op) }.cast::<RpcCustomOp>();
    if custom.is_null() {
        return;
    }
    let func = unsafe { ptr::read_unaligned(ptr::addr_of!((*custom).func)) };
    if let Some(custom_fn) = func {
        unsafe {
            custom_fn(tlio_in, p);
        }
    }
}

pub(super) unsafe fn process_query_custom_subjob_impl(
    job: Job,
    op: c_int,
    _jt: *mut c_void,
) -> c_int {
    let p = unsafe { query_work_params(job) };
    assert!(!p.is_null());

    if op == JS_RUN {
        let io = unsafe { c_tl_in_state_alloc() }.cast::<TlInState>();
        assert!(!io.is_null());
        unsafe {
            c_tlf_init_raw_message(
                io.cast(),
                (&raw mut (*p).src).cast(),
                (*p).src.total_bytes,
                0,
            );
            query_act_custom_impl(io, p);
            c_tl_in_state_free(io.cast());
            c_job_timer_remove(job.cast());
        }
        return JOB_COMPLETED;
    }

    match op {
        JS_ABORT => {
            unsafe {
                c_job_timer_remove(job.cast());
                if (*job).j_error == 0 {
                    (*job).j_error = libc::ECANCELED;
                }
            }
            JOB_COMPLETED
        }
        JS_ALARM => {
            unsafe {
                if (*job).j_error == 0 {
                    (*job).j_error = libc::ETIMEDOUT;
                }
            }
            JOB_COMPLETED
        }
        JS_FINISH => {
            assert!(unsafe { (*job).j_refcnt } == 1);
            if unsafe { (*p).src.magic } != 0 {
                unsafe {
                    rwm_free(&raw mut (*p).src);
                }
            }
            unsafe { c_job_free(1, job.cast()) }
        }
        _ => JOB_ERROR,
    }
}

unsafe fn fetch_all_queries_impl(parent: Job, tlio_in: *mut TlInState) -> c_int {
    let p = unsafe { query_work_params(parent) };
    assert!(!p.is_null());
    assert!(!unsafe { (*p).h }.is_null());

    let root = unsafe {
        fetch_query_impl(
            parent,
            tlio_in,
            &raw mut (*p).result,
            &raw mut (*p).error,
            &raw mut (*p).error_code,
            (*(*p).h).actor_id,
            ptr::null_mut(),
            (*p).all_list,
            JSP_PARENT_RWE,
        )
    };
    if root.is_null() {
        -1
    } else {
        unsafe {
            c_schedule_job(1, root.cast());
        }
        0
    }
}

pub(super) unsafe fn process_parse_subjob_impl(job: Job, op: c_int, jt: *mut c_void) -> c_int {
    let p = unsafe { query_work_params(job) };
    assert!(!p.is_null());

    match op {
        JS_RUN => {
            unsafe {
                (*job).j_execute = Some(process_query_job_callback);
            }
            let io = unsafe { c_tl_in_state_alloc() }.cast::<TlInState>();
            assert!(!io.is_null());

            let rc = unsafe {
                c_tlf_init_raw_message(
                    io.cast(),
                    (&raw mut (*p).src).cast(),
                    (*p).src.total_bytes,
                    0,
                );
                fetch_all_queries_impl(job, io)
            };
            unsafe {
                c_tl_in_state_free(io.cast());
            }
            if rc < 0 {
                1 << JS_ABORT
            } else {
                0
            }
        }
        JS_ABORT | JS_ALARM | JS_FINISH => unsafe { process_query_job_impl(job, op, jt) },
        _ => JOB_ERROR,
    }
}

pub(super) unsafe fn create_query_job_impl(
    job: Job,
    raw: *mut RawMessage,
    h: *mut TlQueryHeader,
    timeout: c_double,
    remote_pid: *mut ProcessId,
    out_type: c_int,
    fd: c_int,
    generation: c_int,
) -> c_int {
    unsafe {
        (*job).j_execute = Some(process_parse_subjob_callback);
    }

    let pd = unsafe { ptr::read_unaligned(remote_pid) };
    let p = unsafe { query_work_params(job) };
    assert!(!p.is_null());

    unsafe {
        libc::memset(p.cast(), 0, size_of::<QueryWorkParams>());
        (*p).h = tl_query_header_dup(h);
        (*p).start_rdtsc = rdtsc_now();
        (*p).fd = fd;
        (*p).generation = generation;
        (*p).pid = pd;
        (*p).type_ = out_type;
        c_job_timer_insert(job.cast(), precise_now_value() + timeout);
        rwm_clone(&raw mut (*p).src, raw);
    }

    1 << JS_RUN
}

pub(super) unsafe fn create_query_custom_job_impl(
    job: Job,
    raw: *mut RawMessage,
    timeout: c_double,
    fd: c_int,
    generation: c_int,
) -> c_int {
    unsafe {
        (*job).j_execute = Some(process_query_custom_subjob_callback);
    }

    let q = unsafe { query_info(job) };
    assert!(!q.is_null());
    let p = unsafe { query_work_params(job) };
    assert!(!p.is_null());

    unsafe {
        libc::memset(p.cast(), 0, size_of::<QueryWorkParams>());
        (*p).pid = ptr::read_unaligned(ptr::addr_of!((*q).src_pid));
        (*p).type_ = (*q).src_type;
        (*p).fd = fd;
        (*p).generation = generation;
        if timeout > 0.0 {
            c_job_timer_insert(job.cast(), precise_now_value() + timeout);
        }
        rwm_clone(&raw mut (*p).src, raw);
    }

    1 << JS_RUN
}

pub(super) unsafe fn do_create_query_job_impl(
    raw: *mut RawMessage,
    type_: c_int,
    pid: *mut ProcessId,
    conn: *mut c_void,
) -> c_int {
    let job_signals = (JSP_PARENT_RWE as u64)
        | jsc_allow(JC_ENGINE, JS_RUN)
        | jsc_allow(JC_ENGINE, JS_ABORT)
        | jsc_allow(JC_ENGINE, JS_ALARM)
        | jsc_allow(JC_ENGINE, JS_FINISH);

    let job = unsafe {
        c_create_async_job(
            Some(do_query_job_run_callback),
            job_signals,
            -2,
            size_of::<QueryWorkParams>() as c_int,
            JT_HAVE_TIMER,
            1,
            ptr::null_mut(),
        )
    }
    .cast::<AsyncJob>();
    assert!(!job.is_null());

    let q = unsafe { query_info(job) };
    assert!(!q.is_null());
    unsafe {
        (*q).raw = ptr::read(raw);
        (*q).src_type = type_;
        (*q).src_pid = ptr::read_unaligned(pid);
        (*q).conn = conn;
        c_schedule_job(1, job.cast());
    }
    0
}

pub(super) unsafe fn default_tl_close_conn_impl(c: *mut c_void) -> c_int {
    unsafe {
        rpc_target_delete_conn(c);
    }
    0
}

pub(super) unsafe fn default_tl_tcp_rpcs_execute_impl(
    c: *mut c_void,
    op: c_int,
    raw: *mut RawMessage,
) -> c_int {
    unsafe { touch_conn_last_response_time(c) };

    let mut remote_pid: ProcessId = unsafe { core::mem::zeroed() };
    unsafe { copy_tcp_remote_pid(c, &raw mut remote_pid) };
    let conn_ref = if unsafe { mtproxy_ffi_engine_rpc_tcp_should_hold_conn(op) } != 0 {
        unsafe { c_job_incref(c) }
    } else {
        ptr::null_mut()
    };
    unsafe {
        do_create_query_job_impl(raw, TL_TYPE_TCP_RAW_MSG, &raw mut remote_pid, conn_ref);
    }
    1
}

pub(super) unsafe fn tl_generate_next_qid_impl(query_type_id: c_int) -> c_longlong {
    assert!((query_type_id as u32) < 16);

    if LAST_QID.load(Ordering::Relaxed) == 0 {
        let initial = unsafe { lrand48_j() } as u32;
        let _ = LAST_QID.compare_exchange(0, initial, Ordering::Relaxed, Ordering::Relaxed);
    }

    let low = LAST_QID.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    let high_random = (unsafe { lrand48_j() } as c_int) & 0x0fff_ffff;
    let high = (((query_type_id << 28) + high_random) as u64) << 32;
    let qid = high | u64::from(low);
    i64::from_ne_bytes(qid.to_ne_bytes())
}

pub(super) unsafe fn tl_query_result_fun_set_impl(func: TlQueryResultFn, query_type_id: c_int) {
    assert!((query_type_id as u32) < QUERY_RESULT_TYPES as u32);
    unsafe {
        TL_QUERY_RESULT_TABLE_ALLOCATED = true;
        TL_QUERY_RESULT_FUNCTIONS[query_type_id as usize] = func;
    }
}

pub(super) unsafe fn engine_tl_init_impl(
    parse: TlParseFn,
    stat: TlStatFn,
    get_op: TlGetOpFn,
    timeout: c_double,
) {
    unsafe {
        TL_PARSE_FUNCTION = parse;
        TL_STAT_FUNCTION = stat;
        TL_GET_OP_FUNCTION = get_op;
        TL_AIO_TIMEOUT = timeout;
    }
}

pub(super) unsafe fn tl_engine_store_stats_impl(tlio_out: *mut c_void) {
    let stat = unsafe { TL_STAT_FUNCTION };
    if let Some(stat_fn) = stat {
        unsafe {
            stat_fn(tlio_out);
        }
        return;
    }

    let mut buf = [0 as c_char; 1 << 12];
    unsafe {
        prepare_stats(buf.as_mut_ptr(), ((1 << 12) - 2) as c_int);
        tl_store_stats_impl(tlio_out, buf.as_ptr(), 0);
    }
}

pub(super) unsafe fn tl_store_stats_impl(
    tlio_out: *mut c_void,
    s: *const c_char,
    raw: c_int,
) -> c_int {
    if s.is_null() {
        return 0;
    }
    if raw == 0 {
        unsafe {
            c_tls_int_rust(tlio_out, TL_STAT);
        }
    }

    let cnt_ptr = unsafe { c_tls_get_ptr_rust(tlio_out, 4) }.cast::<c_int>();
    assert!(!cnt_ptr.is_null());
    unsafe {
        *cnt_ptr = 0;
    }

    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    let mut key_start: usize = 0;
    let mut value_start: isize = -1;

    for (i, ch) in bytes.iter().enumerate() {
        if *ch == b'\n' {
            if value_start - key_start as isize > 1 && (value_start as usize) < i {
                let key_len = value_start as c_int - key_start as c_int - 1;
                let value_len = i as c_int - value_start as c_int;
                unsafe {
                    c_tls_string_rust(tlio_out, s.add(key_start), key_len);
                    c_tls_string_rust(tlio_out, s.add(value_start as usize), value_len);
                    *cnt_ptr += 1;
                }
            }
            key_start = i + 1;
            value_start = -1;
        } else if *ch == b'\t' {
            value_start = if value_start == -1 {
                (i + 1) as isize
            } else {
                -2
            };
        }
    }

    unsafe { *cnt_ptr }
}

unsafe extern "C" fn process_act_atom_subjob_callback(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { process_act_atom_subjob_impl(job.cast::<AsyncJob>(), op, jt) }
}

unsafe extern "C" fn process_query_job_callback(job: Job, op: c_int, jt: *mut c_void) -> c_int {
    unsafe { process_query_job_impl(job, op, jt) }
}

unsafe extern "C" fn process_parse_subjob_callback(job: Job, op: c_int, jt: *mut c_void) -> c_int {
    unsafe { process_parse_subjob_impl(job, op, jt) }
}

unsafe extern "C" fn process_query_custom_subjob_callback(
    job: Job,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { process_query_custom_subjob_impl(job, op, jt) }
}

unsafe extern "C" fn do_query_job_run_callback(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { do_query_job_run_impl(job.cast::<AsyncJob>(), op, jt) }
}

pub(super) unsafe fn fetch_query_impl(
    parent: Job,
    tlio_in: *mut TlInState,
    raw: *mut *mut RawMessage,
    error: *mut *mut c_char,
    error_code: *mut c_int,
    actor_id: c_longlong,
    extra_ref: Job,
    all_list: Job,
    status: c_int,
) -> Job {
    let get_op = unsafe { TL_GET_OP_FUNCTION }.expect("tl_get_op_function must be initialized");
    let fop = unsafe { get_op(tlio_in) };

    let mut extra = unsafe { call_default_parse_function(tlio_in, actor_id) };
    if extra.is_null() && unsafe { tlf_error_rust(tlio_in.cast()) } != 0 {
        unsafe {
            *error = dup_error_or_null((*tlio_in).error);
            *error_code = (*tlio_in).errnum;
        }
        return ptr::null_mut();
    }
    if extra.is_null() {
        if let Some(parse_fn) = unsafe { TL_PARSE_FUNCTION } {
            extra = unsafe { parse_fn(tlio_in, actor_id) };
        }
    }
    if extra.is_null() {
        let unknown_op = unsafe { tlf_lookup_int_rust(tlio_in.cast()) };
        let msg =
            CString::new(format!("Unknown op 0x{unknown_op:08x}")).expect("NUL-free format string");
        unsafe {
            tlf_set_error(tlio_in.cast(), TL_ERROR_UNKNOWN_FUNCTION_ID, msg.as_ptr());
            *error = dup_error_or_null((*tlio_in).error);
            *error_code = (*tlio_in).errnum;
        }
        return ptr::null_mut();
    }

    unsafe {
        if (*extra).free.is_none() {
            (*extra).free = Some(tl_default_act_free_impl);
        }
        if (*extra).dup.is_none() {
            (*extra).dup = Some(tl_default_act_dup_impl);
        }
        (*extra).op = fop;
        assert!((*extra).act.is_some());
        assert!((*extra).free.is_some());
        assert!((*extra).dup.is_some());
        (*extra).error = error;
        (*extra).error_code = error_code;
        (*extra).raw = raw;
        (*extra).extra_ref = if extra_ref.is_null() {
            ptr::null_mut()
        } else {
            c_job_incref(extra_ref.cast()).cast::<AsyncJob>()
        };

        if ((*extra).flags & 1) == 0 {
            let dup = (*extra)
                .dup
                .expect("tl_act_extra::dup must be set before use");
            extra = dup(extra);
        }
    }

    let parent_ref = if parent.is_null() {
        ptr::null_mut()
    } else {
        unsafe { c_job_incref(parent.cast()) }
    };

    let job = unsafe {
        c_create_async_job(
            Some(process_act_atom_subjob_callback),
            (status as u64)
                | jsc_allow(JC_ENGINE, JS_RUN)
                | jsc_allow(JC_ENGINE, JS_ABORT)
                | jsc_allow(JC_ENGINE, JS_FINISH),
            (*extra).subclass,
            size_of::<*mut c_void>() as c_int,
            0,
            1,
            parent_ref,
        )
    }
    .cast::<AsyncJob>();
    assert!(!job.is_null());

    unsafe {
        *job_custom_ptr::<*mut TlActExtra>(job) = extra;
    }

    if !all_list.is_null() {
        let job_ref = unsafe { c_job_incref(job.cast()) };
        unsafe {
            c_insert_job_into_job_list(all_list.cast(), 1, job_ref, JSP_PARENT_ERROR);
        }
    }

    job
}

pub(super) unsafe fn process_act_atom_subjob_impl(job: Job, op: c_int, _jt: *mut c_void) -> c_int {
    if op != JS_FINISH && unsafe { parent_job_aborted(job) } {
        return unsafe { job_fatal(job, libc::ECANCELED) };
    }

    let e = unsafe { *job_custom_ptr::<*mut TlActExtra>(job) };
    assert!(!e.is_null());

    match op {
        JS_RUN => {
            if unsafe { (*e).raw }.is_null() {
                if !unsafe { (*e).extra_ref }.is_null() {
                    unsafe {
                        c_job_decref(1, (*e).extra_ref.cast());
                    }
                }
                return JOB_COMPLETED;
            }

            let io = unsafe { c_tl_out_state_alloc() }.cast::<TlOutState>();
            assert!(!io.is_null());
            unsafe {
                c_tls_init_raw_msg_nosend(io.cast());
                (*e).tlio_out = io;
            }

            let old_rdtsc = rdtsc_now();
            let act = unsafe { (*e).act }.expect("tl_act_extra::act must be set");
            let res = unsafe { act(job, e) };
            unsafe {
                (*e).tlio_out = ptr::null_mut();
                (*e).cpu_rdtsc += rdtsc_now() - old_rdtsc;
            }

            if res >= 0 && unsafe { (*io).error }.is_null() {
                let raw = unsafe { libc::malloc(size_of::<RawMessage>()) }.cast::<RawMessage>();
                assert!(!raw.is_null());
                unsafe {
                    rwm_clone(raw, (*io).out.cast::<RawMessage>());
                    c_tl_out_state_free(io.cast());
                }

                if !unsafe { (*e).raw }.is_null() {
                    unsafe {
                        *(*e).raw = raw;
                        (*e).raw = ptr::null_mut();
                    }
                    if !unsafe { (*e).extra_ref }.is_null() {
                        unsafe {
                            c_job_decref(1, (*e).extra_ref.cast());
                        }
                    }
                }

                JOB_COMPLETED
            } else if res == -2
                && unsafe { (*e).attempt } < 5
                && unsafe { (*io).error }.is_null()
                && unsafe { (*job).j_children } > 0
            {
                unsafe {
                    c_tl_out_state_free(io.cast());
                    (*e).attempt += 1;
                }
                0
            } else {
                if unsafe { (*io).error }.is_null() {
                    unsafe {
                        if res == -2 && (*e).attempt >= 5 {
                            c_tls_set_error_format(
                                io.cast(),
                                TL_ERROR_AIO_MAX_RETRY_EXCEEDED,
                                ERR_MAX_RETRIES.as_ptr().cast(),
                            );
                        } else if res == -2 {
                            c_tls_set_error_format(
                                io.cast(),
                                TL_ERROR_BAD_METAFILE,
                                ERR_BAD_METAFILE.as_ptr().cast(),
                            );
                        } else {
                            c_tls_set_error_format(
                                io.cast(),
                                TL_ERROR_UNKNOWN,
                                ERR_UNKNOWN.as_ptr().cast(),
                            );
                        }
                    }
                }

                assert!(!unsafe { (*io).error }.is_null());

                if !unsafe { (*e).raw }.is_null() {
                    unsafe {
                        *(*e).error = libc::strdup((*io).error);
                        *(*e).error_code = (*io).errnum;
                        (*e).raw = ptr::null_mut();
                    }
                    if !unsafe { (*e).extra_ref }.is_null() {
                        unsafe {
                            c_job_decref(1, (*e).extra_ref.cast());
                        }
                    }
                }

                unsafe {
                    c_tl_out_state_free(io.cast());
                }
                unsafe { job_fatal(job, libc::EIO) }
            }
        }
        JS_ABORT => {
            if unsafe { (*job).j_error } == 0 {
                unsafe {
                    (*job).j_error = libc::ECANCELED;
                }

                if !unsafe { (*e).raw }.is_null() {
                    unsafe {
                        *(*e).error = libc::strdup(ERR_JOB_CANCELLED.as_ptr().cast());
                        *(*e).error_code = TL_ERROR_UNKNOWN;
                        (*e).raw = ptr::null_mut();
                    }
                }
            }
            if !unsafe { (*e).extra_ref }.is_null() {
                unsafe {
                    c_job_decref(1, (*e).extra_ref.cast());
                }
            }
            JOB_COMPLETED
        }
        JS_FINISH => {
            if !unsafe { (*e).extra_ref }.is_null() {
                unsafe {
                    c_job_decref(1, (*e).extra_ref.cast());
                }
            }
            let free_fn = unsafe { (*e).free }.expect("tl_act_extra::free must be set");
            unsafe {
                free_fn(e);
                assert!((*job).j_refcnt == 1);
                c_job_free(1, job.cast())
            }
        }
        _ => JOB_ERROR,
    }
}

pub(super) unsafe fn process_query_job_impl(job: Job, op: c_int, _jt: *mut c_void) -> c_int {
    let p = unsafe { query_work_params(job) };
    assert!(!p.is_null());

    let mut io: *mut TlOutState = ptr::null_mut();

    match op {
        JS_RUN => {
            assert!(unsafe { (*job).j_children } == 0);
            assert!(unsafe { (*p).wait_pos }.is_null());

            if unsafe { (*p).result }.is_null() && unsafe { (*p).error }.is_null() {
                unsafe {
                    (*p).error = libc::strdup(ERR_UNKNOWN.as_ptr().cast());
                    (*p).error_code = TL_ERROR_UNKNOWN;
                }
            }

            if unsafe { (*p).answer_sent } == 0 {
                if unsafe { (*p).fd } != 0 && unsafe { (*p).type_ } == TL_TYPE_RAW_MSG {
                    let c = unsafe { connection_get_by_fd((*p).fd) };
                    if !c.is_null() && unsafe { conn_generation(c) } != unsafe { (*p).generation } {
                        unsafe {
                            c_job_decref(1, c);
                        }
                    }
                    if !c.is_null() {
                        io = unsafe { c_tl_out_state_alloc() }.cast::<TlOutState>();
                        assert!(!io.is_null());
                        unsafe {
                            c_tls_init_tcp_raw_msg(io.cast(), 1, c, (*(*p).h).qid);
                        }
                    }
                }
                if io.is_null() {
                    io = unsafe {
                        tl_aio_init_store_impl((*p).type_, &raw mut (*p).pid, (*(*p).h).qid)
                    }
                    .cast::<TlOutState>();
                }
            }

            if !io.is_null() {
                assert!(unsafe { (*p).answer_sent } == 0);
                if unsafe { (*p).error_code } != 0 {
                    unsafe {
                        c_tls_set_error_format(
                            io.cast(),
                            (*p).error_code,
                            PERCENT_S_FMT.as_ptr().cast(),
                            (*p).error,
                        );
                        libc::free((*p).error.cast());
                        (*p).error = ptr::null_mut();
                    }
                } else {
                    let z = unsafe { tl_result_get_header_len_impl((*p).h) };
                    let hptr = unsafe { c_tls_get_ptr_rust(io.cast(), z) }.cast::<c_int>();
                    assert_eq!(z, unsafe { tl_result_make_header_impl(hptr, (*p).h) });
                    unsafe {
                        c_tls_raw_msg_rust(io.cast(), (*p).result, 0);
                        libc::free((*p).result.cast());
                        (*p).result = ptr::null_mut();
                    }
                }
                unsafe {
                    c_tls_end_ext(io.cast(), RPC_REQ_RESULT);
                    c_tl_out_state_free(io.cast());
                }
            }

            unsafe {
                (*p).answer_sent += 1;
                c_job_timer_remove(job.cast());
                if !(*p).all_list.is_null() {
                    c_job_signal(1, (*p).all_list.cast(), JS_ABORT);
                }
            }
            JOB_COMPLETED
        }
        JS_ALARM => {
            if unsafe { c_job_timer_check(job.cast()) } == 0 {
                return 0;
            }
            if unsafe { (*p).answer_sent } == 0 {
                io =
                    unsafe { tl_aio_init_store_impl((*p).type_, &raw mut (*p).pid, (*(*p).h).qid) }
                        .cast::<TlOutState>();
            }
            if !io.is_null() {
                if unsafe { (*p).error_code } != 0 {
                    unsafe {
                        c_tls_set_error_format(
                            io.cast(),
                            (*p).error_code,
                            PERCENT_S_FMT.as_ptr().cast(),
                            (*p).error,
                        );
                        libc::free((*p).error.cast());
                        (*p).error = ptr::null_mut();
                    }
                } else if !unsafe { (*p).wait_pos }.is_null() {
                    unsafe {
                        c_tls_set_error_format(
                            io.cast(),
                            TL_ERROR_AIO_TIMEOUT,
                            ERR_BINLOG_WAIT.as_ptr().cast(),
                        );
                    }
                } else {
                    unsafe {
                        c_tls_set_error_format(
                            io.cast(),
                            TL_ERROR_AIO_TIMEOUT,
                            ERR_AIO_WAIT.as_ptr().cast(),
                        );
                    }
                }

                unsafe {
                    c_tls_end_ext(io.cast(), RPC_REQ_RESULT);
                    c_tl_out_state_free(io.cast());
                    (*p).answer_sent += 1;
                }
            }
            if unsafe { (*job).j_error } == 0 {
                unsafe {
                    (*job).j_error = libc::ETIMEDOUT;
                }
            }
            if !unsafe { (*p).all_list }.is_null() {
                unsafe {
                    c_job_signal(1, (*p).all_list.cast(), JS_ABORT);
                }
            }
            JOB_COMPLETED
        }
        JS_ABORT => {
            if unsafe { (*p).answer_sent } == 0 {
                io =
                    unsafe { tl_aio_init_store_impl((*p).type_, &raw mut (*p).pid, (*(*p).h).qid) }
                        .cast::<TlOutState>();
            }
            if !io.is_null() {
                if unsafe { (*p).error_code } != 0 {
                    unsafe {
                        c_tls_set_error_format(
                            io.cast(),
                            (*p).error_code,
                            PERCENT_S_FMT.as_ptr().cast(),
                            (*p).error,
                        );
                        libc::free((*p).error.cast());
                        (*p).error = ptr::null_mut();
                    }
                } else {
                    unsafe {
                        c_tls_set_error_format(
                            io.cast(),
                            TL_ERROR_UNKNOWN,
                            ERR_CANCELLED.as_ptr().cast(),
                        );
                    }
                }
                unsafe {
                    c_tls_end_ext(io.cast(), RPC_REQ_RESULT);
                    (*p).answer_sent += 1;
                    c_tl_out_state_free(io.cast());
                }
            }
            unsafe {
                c_job_timer_remove(job.cast());
                if !(*p).all_list.is_null() {
                    c_job_signal(1, (*p).all_list.cast(), JS_ABORT);
                }
            }
            JOB_COMPLETED
        }
        JS_FINISH => {
            assert!(unsafe { (*p).wait_pos }.is_null());
            assert!(unsafe { (*p).all_list }.is_null());
            assert!(unsafe { (*job).j_refcnt } == 1);

            if !unsafe { (*p).p }.is_null() {
                unsafe {
                    paramed_type_free((*p).p);
                    (*p).p = ptr::null_mut();
                }
            }
            if !unsafe { (*p).error }.is_null() {
                unsafe {
                    libc::free((*p).error.cast());
                }
            }
            if !unsafe { (*p).result }.is_null() {
                unsafe {
                    rwm_free((*p).result);
                    libc::free((*p).result.cast());
                }
            }
            if unsafe { (*p).src.magic } != 0 {
                unsafe {
                    rwm_free(&raw mut (*p).src);
                }
            }
            unsafe {
                tl_query_header_delete((*p).h);
                c_job_free(1, job.cast())
            }
        }
        _ => JOB_ERROR,
    }
}

pub(super) unsafe fn query_job_run_impl(job: Job, fd: c_int, generation: c_int) -> c_int {
    let q = unsafe { query_info(job) };
    assert!(!q.is_null());

    let io = unsafe { c_tl_in_state_alloc() }.cast::<TlInState>();
    assert!(!io.is_null());
    unsafe {
        c_tlf_init_raw_message(
            io.cast(),
            (&raw mut (*q).raw).cast(),
            (*q).raw.total_bytes,
            0,
        );
    }

    let op = unsafe { tlf_lookup_int_rust(io.cast()) };
    let mut h: *mut TlQueryHeader = ptr::null_mut();
    let res: c_int;

    let has_custom_ops = unsafe { mtproxy_ffi_engine_rpc_custom_op_has_any() };
    let dispatch_decision =
        unsafe { mtproxy_ffi_engine_rpc_query_job_dispatch_decision(op, has_custom_ops) };

    if dispatch_decision == MTPROXY_FFI_ENGINE_RPC_QJ_CUSTOM {
        let mut r = RawMessage {
            first: ptr::null_mut(),
            last: ptr::null_mut(),
            total_bytes: 0,
            magic: 0,
            first_offset: 0,
            last_offset: 0,
        };
        unsafe {
            rwm_clone(&raw mut r, (*io).in_.cast::<RawMessage>());
            res = create_query_custom_job_impl(job.cast(), &raw mut r, 0.0, fd, generation);
            rwm_free(&raw mut r);
        }
    } else if dispatch_decision == MTPROXY_FFI_ENGINE_RPC_QJ_IGNORE {
        res = JOB_COMPLETED;
    } else {
        assert_eq!(dispatch_decision, MTPROXY_FFI_ENGINE_RPC_QJ_INVOKE_PARSE);
        h = unsafe { libc::malloc(size_of::<TlQueryHeader>()) }.cast::<TlQueryHeader>();
        assert!(!h.is_null());
        unsafe {
            c_tlf_query_header(io.cast(), h);
        }

        if unsafe { tlf_error_rust(io.cast()) } != 0 {
            let out =
                unsafe { tl_aio_init_store_impl((*q).src_type, &raw mut (*q).src_pid, (*h).qid) }
                    .cast::<TlOutState>();
            if !out.is_null() {
                unsafe {
                    c_tls_set_error_format(
                        out.cast(),
                        (*io).errnum,
                        PERCENT_S_FMT.as_ptr().cast(),
                        (*io).error,
                    );
                    c_tls_end_ext(out.cast(), RPC_REQ_RESULT);
                    c_tl_out_state_free(out.cast());
                }
            }
            res = JOB_COMPLETED;
        } else {
            let mut r = RawMessage {
                first: ptr::null_mut(),
                last: ptr::null_mut(),
                total_bytes: 0,
                magic: 0,
                first_offset: 0,
                last_offset: 0,
            };
            unsafe {
                rwm_clone(&raw mut r, (*io).in_.cast::<RawMessage>());
                res = create_query_job_impl(
                    job.cast(),
                    &raw mut r,
                    h,
                    TL_AIO_TIMEOUT,
                    &raw mut (*q).src_pid,
                    (*q).src_type,
                    fd,
                    generation,
                );
                rwm_free(&raw mut r);
            }
        }
    }

    if !h.is_null() {
        unsafe {
            tl_query_header_delete(h);
        }
    }
    unsafe {
        c_tl_in_state_free(io.cast());
    }
    res
}

pub(super) unsafe fn do_query_job_run_impl(job: Job, op: c_int, _jt: *mut c_void) -> c_int {
    let q = unsafe { query_info(job) };
    assert!(!q.is_null());

    let mut fd = 0;
    let mut generation = 0;

    if !unsafe { (*q).conn }.is_null() {
        unsafe {
            rpc_target_insert_conn((*q).conn);
            fd = conn_fd((*q).conn);
            generation = conn_generation((*q).conn);
            c_job_decref(1, (*q).conn);
        }
    }

    if op == JS_RUN {
        return unsafe { query_job_run_impl(job, fd, generation) };
    }

    assert_eq!(unsafe { c_job_timer_active(job.cast()) }, 0);

    match op {
        JS_ALARM => {
            if unsafe { (*job).j_error } == 0 {
                unsafe {
                    (*job).j_error = libc::ETIMEDOUT;
                }
            }
            JOB_COMPLETED
        }
        JS_ABORT => {
            if unsafe { (*job).j_error } == 0 {
                unsafe {
                    (*job).j_error = libc::ECANCELED;
                }
            }
            JOB_COMPLETED
        }
        JS_FINISH => {
            if unsafe { (*q).raw.magic } != 0 {
                unsafe {
                    rwm_free(&raw mut (*q).raw);
                }
            }
            unsafe { c_job_free(1, job.cast()) }
        }
        _ => JOB_ERROR,
    }
}
