//! Runtime-side FFI implementations migrated from `net/net-connections.c`.

use super::abi::*;
use ::core::ffi::{c_char, c_double, c_int, c_longlong, c_uint, c_void};
use ::core::mem::size_of;
use ::core::ptr;
use ::core::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use libc::in_addr;

const MAX_EVENTS: usize = 1 << 19;
const PRIME_TARGETS: usize = 99_961;

const C_ERROR: c_int = 0x8;
const C_NORD: c_int = 0x10;
const C_NOWR: c_int = 0x20;
const C_FAILED: c_int = 0x80;
const C_ALARM: c_int = 0x100;
const C_STOPREAD: c_int = 0x800;
const C_IPV6: c_int = 0x4000;
const C_EXTERNAL: c_int = 0x8000;
const C_SPECIAL: c_int = 0x1_0000;
const C_NOQACK: c_int = 0x2_0000;
const C_RAWMSG: c_int = 0x40_000;
const C_NET_FAILED: c_int = 0x80_000;
const C_ISDH: c_int = 0x80_0000;
const C_PERMANENT: c_int = 0x44_000;
const C_WANTRD: c_int = 1;
const C_CONNECTED: c_int = 0x0200_0000;
const C_READY_PENDING: c_int = 0x0100_0000;
const C_WANTWR: c_int = 2;
const C_STOPWRITE: c_int = 0x0400_0000;
const CT_NONE: c_int = 0;
const CONN_NONE: c_int = 0;
const CT_OUTBOUND: c_int = 3;

const CONN_FUNC_MAGIC: c_int = 0x11ef55aa_u32 as c_int;
const CONN_ERROR: c_int = 3;

const CR_NOTYET: c_int = 0;
const CR_FAILED: c_int = 4;
const CONN_CONNECTING: c_int = 1;
const CONN_WORKING: c_int = 2;

const JS_RUN: c_int = 0;
const JS_AUX: c_int = 1;
const JS_ALARM: c_int = 4;
const JS_ABORT: c_int = 5;
const JS_FINISH: c_int = 7;

const JOB_COMPLETED: c_int = 0x100;
const JOB_ERROR: c_int = -1;
const JF_LOCKED: c_int = 0x10000;
const JF_COMPLETED: c_int = 0x40000;
const JC_EPOLL: c_int = 3;
const JC_CONNECTION: c_int = 4;
const JC_CONNECTION_IO: c_int = 5;
const JT_HAVE_TIMER: u64 = 1;

const EVT_RWX: c_int = 7;
const EVT_IN_EPOLL: c_int = 0x20;
const EVT_FROM_EPOLL: c_int = 0x400;
const EVA_CONTINUE: c_int = 0;
const EVA_REMOVE: c_int = -3;
const JOB_SENDSIG_AUX: c_int = 1 << JS_AUX;
const CT_INBOUND: c_int = 2;
const SM_LOWPRIO: c_int = 8;
const SM_SPECIAL: c_int = 0x1_0000;
const SM_NOQACK: c_int = 0x2_0000;
const SM_IPV6: c_int = 2;
const SM_RAWMSG: c_int = 0x4_0000;

const CONNECTION_WRITE_CLOSE_ACTION_SET_IO_STOPREAD: c_int = 1 << 0;
const CONNECTION_WRITE_CLOSE_ACTION_SET_CONN_STOPREAD: c_int = 1 << 1;
const CONNECTION_WRITE_CLOSE_ACTION_SET_STATUS_WRITE_CLOSE: c_int = 1 << 2;
const CONNECTION_WRITE_CLOSE_ACTION_SIGNAL_RUN: c_int = 1 << 3;

const FAIL_CONNECTION_ACTION_SET_STATUS_ERROR: c_int = 1 << 0;
const FAIL_CONNECTION_ACTION_SET_ERROR_CODE: c_int = 1 << 1;
const FAIL_CONNECTION_ACTION_SIGNAL_ABORT: c_int = 1 << 2;

const CHECK_CONN_DEFAULT_SET_TITLE: c_int = 1 << 0;
const CHECK_CONN_DEFAULT_SET_SOCKET_READ_WRITE: c_int = 1 << 1;
const CHECK_CONN_DEFAULT_SET_SOCKET_READER: c_int = 1 << 2;
const CHECK_CONN_DEFAULT_SET_SOCKET_WRITER: c_int = 1 << 3;
const CHECK_CONN_DEFAULT_SET_SOCKET_CLOSE: c_int = 1 << 4;
const CHECK_CONN_DEFAULT_SET_CLOSE: c_int = 1 << 5;
const CHECK_CONN_DEFAULT_SET_INIT_OUTBOUND: c_int = 1 << 6;
const CHECK_CONN_DEFAULT_SET_WAKEUP: c_int = 1 << 7;
const CHECK_CONN_DEFAULT_SET_ALARM: c_int = 1 << 8;
const CHECK_CONN_DEFAULT_SET_CONNECTED: c_int = 1 << 9;
const CHECK_CONN_DEFAULT_SET_FLUSH: c_int = 1 << 10;
const CHECK_CONN_DEFAULT_SET_CHECK_READY: c_int = 1 << 11;
const CHECK_CONN_DEFAULT_SET_READ_WRITE: c_int = 1 << 12;
const CHECK_CONN_DEFAULT_SET_FREE: c_int = 1 << 13;
const CHECK_CONN_DEFAULT_SET_SOCKET_CONNECTED: c_int = 1 << 14;
const CHECK_CONN_DEFAULT_SET_SOCKET_FREE: c_int = 1 << 15;

const CHECK_CONN_ACCEPT_SET_ACCEPT_LISTEN: c_int = 1 << 0;
const CHECK_CONN_ACCEPT_SET_ACCEPT_FAILED: c_int = 1 << 1;
const CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_NOOP: c_int = 1 << 2;
const CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_FAILED: c_int = 1 << 3;

const CHECK_CONN_RAW_SET_FREE_BUFFERS: c_int = 1 << 0;
const CHECK_CONN_RAW_SET_READER: c_int = 1 << 1;
const CHECK_CONN_RAW_SET_WRITER: c_int = 1 << 2;

const CHECK_CONN_NONRAW_ASSERT_FREE_BUFFERS: c_int = 1 << 0;
const CHECK_CONN_NONRAW_ASSERT_READER: c_int = 1 << 1;
const CHECK_CONN_NONRAW_ASSERT_WRITER: c_int = 1 << 2;

const CONN_GET_BY_FD_ACTION_RETURN_SELF: c_int = 1;
const CONN_GET_BY_FD_ACTION_RETURN_NULL: c_int = 2;
const CONN_GET_BY_FD_ACTION_RETURN_CONN: c_int = 3;
const SOCKET_JOB_ACTION_ABORT: c_int = 1;
const SOCKET_JOB_ACTION_RUN: c_int = 2;
const SOCKET_JOB_ACTION_AUX: c_int = 3;
const SOCKET_JOB_ACTION_FINISH: c_int = 4;
const CONNECTION_JOB_ACTION_ERROR: c_int = 0;
const CONNECTION_JOB_ACTION_RUN: c_int = 1;
const CONNECTION_JOB_ACTION_ALARM: c_int = 2;
const CONNECTION_JOB_ACTION_ABORT: c_int = 3;
const CONNECTION_JOB_ACTION_FINISH: c_int = 4;
const LISTENING_JOB_ACTION_RUN: c_int = 1;
const LISTENING_JOB_ACTION_AUX: c_int = 2;
const LISTENING_INIT_FD_OK: c_int = 0;
const LISTENING_INIT_FD_REJECT: c_int = 1;
const LISTENING_MODE_LOWPRIO: c_int = 1;
const LISTENING_MODE_SPECIAL: c_int = 1 << 1;
const LISTENING_MODE_NOQACK: c_int = 1 << 2;
const LISTENING_MODE_IPV6: c_int = 1 << 3;
const LISTENING_MODE_RAWMSG: c_int = 1 << 4;
const TARGET_JOB_UPDATE_INACTIVE_CLEANUP: c_int = 0;
const TARGET_JOB_UPDATE_CREATE_CONNECTIONS: c_int = 1;
const SOCKET_READ_WRITE_CONNECT_RETURN_ZERO: c_int = 0;
const SOCKET_READ_WRITE_CONNECT_RETURN_COMPUTE_EVENTS: c_int = 1;
const SOCKET_READ_WRITE_CONNECT_MARK_CONNECTED: c_int = 2;
const SOCKET_READ_WRITE_CONNECT_CONTINUE_IO: c_int = 3;
const SOCKET_GATEWAY_ABORT_NONE: c_int = 0;
const SOCKET_FREE_ACTION_NONE: c_int = 0;
const SOCKET_FREE_ACTION_FAIL_CONN: c_int = 1;
const SOCKET_READER_IO_HAVE_DATA: c_int = 0;
const SOCKET_READER_IO_BREAK: c_int = 1;
const SOCKET_READER_IO_CONTINUE_INTR: c_int = 2;
const SOCKET_READER_IO_FATAL_ABORT: c_int = 3;
const SOCKET_WRITER_IO_HAVE_DATA: c_int = 0;
const SOCKET_WRITER_IO_BREAK_EAGAIN: c_int = 1;
const SOCKET_WRITER_IO_CONTINUE_INTR: c_int = 2;
const SOCKET_WRITER_IO_FATAL_EAGAIN_LIMIT: c_int = 3;
const SOCKET_WRITER_IO_FATAL_OTHER: c_int = 4;
const ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL1: c_int = 1 << 0;
const ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL0: c_int = 1 << 1;
const ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE: c_int = 1 << 2;
const ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED: c_int = 1 << 0;
const ALLOC_CONNECTION_FAILURE_ACTION_FREE_RAWMSG: c_int = 1 << 1;
const ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE: c_int = 1 << 2;
const ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE: c_int = 1 << 3;
const MAX_TCP_RECV_BUFFERS: usize = 128;
const TCP_RECV_BUFFER_SIZE: c_int = 1024;
const SOCKET_WRITER_MAX_IOVEC: usize = 384;

const UNKNOWN_TITLE: &[u8] = b"(unknown)\0";
const SERVER_FAILED_MSG: &[u8] = b"connection %d: call to pure virtual method\n\0";
const LISTENING_FD_REJECT_MSG: &[u8] = b"TOO big fd for listening connection %d (max %d)\n\0";
const FREE_UNUSED_TARGET_IPV4_MSG: &[u8] = b"Freeing unused target to %s:%d\n\0";
const FREE_UNUSED_TARGET_IPV6_MSG: &[u8] = b"Freeing unused ipv6 target to [%s]:%d\n\0";
const ACCEPT_NONBLOCK_FAIL_MSG: &[u8] = b"cannot set O_NONBLOCK on accepted socket #%d: %m\n\0";
const FATAL_TCP_RECV_BUFFER_MSG: &[u8] = b"**FATAL**: cannot allocate tcp receive buffer\n\0";
const TOO_MUCH_EAGAIN_MSG: &[u8] = b"Too much EAGAINs for connection %d, dropping\n\0";
const CONN_JOB_RUN_DO_READ_WRITE: c_int = 1;
const CONN_JOB_RUN_HANDLE_READY_PENDING: c_int = 2;

static mut FREE_LATER_QUEUE: *mut MpQueue = ptr::null_mut();
static mut TCP_RECV_BUFFERS_NUM: c_int = 0;
static mut TCP_RECV_BUFFERS_TOTAL_SIZE: c_int = 0;
static mut TCP_RECV_IOVEC: [libc::iovec; MAX_TCP_RECV_BUFFERS + 1] = [libc::iovec {
    iov_base: ptr::null_mut(),
    iov_len: 0,
}; MAX_TCP_RECV_BUFFERS + 1];
static mut TCP_RECV_BUFFERS: [*mut MsgBuffer; MAX_TCP_RECV_BUFFERS] =
    [ptr::null_mut(); MAX_TCP_RECV_BUFFERS];

#[inline]
const fn jss_allow(signo: c_int) -> u64 {
    0x0100_0000_u64 << (signo as u32)
}

#[inline]
const fn jsc_type(class: c_int, signo: c_int) -> u64 {
    (class as u64) << ((signo as u32 * 4) + 32)
}

#[inline]
const fn jsc_allow(class: c_int, signo: c_int) -> u64 {
    jsc_type(class, signo) | jss_allow(signo)
}

#[repr(C)]
struct ConnTargetPickCtx {
    selected: *mut ConnectionJob,
    allow_stopped: c_int,
}

unsafe extern "C" {
    static mut HTarget: [ConnTargetJob; PRIME_TARGETS];
    static mut TargetsLock: libc::pthread_mutex_t;
    static mut epoll_fd: c_int;
    static mut Events: [EventDescr; MAX_EVENTS];

    #[allow(clashing_extern_declarations)]
    fn create_async_job(
        run_job: JobFunction,
        job_signals: u64,
        job_subclass: c_int,
        custom_bytes: c_int,
        job_type: u64,
        parent_job_tag_int: c_int,
        parent_job: Job,
    ) -> Job;
    #[allow(clashing_extern_declarations)]
    fn unlock_job(job_tag_int: c_int, job: Job) -> c_int;
    fn job_incref(job: Job) -> Job;
    fn job_decref(job_tag_int: c_int, job: Job);
    fn job_signal(job_tag_int: c_int, job: Job, signo: c_int);
    #[allow(clashing_extern_declarations)]
    fn schedule_job(job_tag_int: c_int, job: Job) -> c_int;
    fn job_timer_insert(job: Job, timeout: c_double);
    fn job_timer_remove(job: Job);
    fn job_timer_check(job: Job) -> c_int;
    #[allow(clashing_extern_declarations)]
    fn job_timer_init(job: Job);
    fn mtproxy_ffi_net_connections_job_free(job: Job) -> c_int;

    fn kprintf(format: *const c_char, ...);
    fn show_ipv6(ipv6: *const u8) -> *const c_char;
    fn inet_ntoa(in_addr: in_addr) -> *mut c_char;

    fn do_connection_job(job: Job, op: c_int, jt: *mut c_void) -> c_int;
    fn do_listening_connection_job(job: Job, op: c_int, jt: *mut c_void) -> c_int;
    fn do_socket_connection_job(job: Job, op: c_int, jt: *mut c_void) -> c_int;
    fn do_conn_target_job(job: Job, op: c_int, jt: *mut c_void) -> c_int;

    fn net_server_socket_read_write(c: ConnectionJob) -> c_int;
    fn net_server_socket_reader(c: ConnectionJob) -> c_int;
    fn net_server_socket_writer(c: ConnectionJob) -> c_int;
    fn net_server_socket_free(c: ConnectionJob) -> c_int;
    fn net_accept_new_connections(c: ConnectionJob) -> c_int;
    fn net_server_socket_read_write_gateway(
        fd: c_int,
        data: *mut c_void,
        ev: *mut EventDescr,
    ) -> c_int;
    fn alloc_mp_queue_w() -> *mut MpQueue;
    fn free_mp_queue(mq: *mut MpQueue);
    fn mtproxy_ffi_net_connections_mpq_push_w(mq: *mut MpQueue, x: *mut c_void, flags: c_int);
    #[allow(clashing_extern_declarations)]
    #[link_name = "mtproxy_ffi_net_msg_buffers_alloc"]
    fn alloc_msg_buffer(neighbor: *mut MsgBuffer, size_hint: c_int) -> *mut MsgBuffer;
    fn new_msg_part(neighbor: *mut MsgPart, x: *mut MsgBuffer) -> *mut MsgPart;
    fn rwm_init(raw: *mut RawMessage, alloc_bytes: c_int) -> c_int;
    fn rwm_free(raw: *mut RawMessage) -> c_int;
    fn rwm_prepare_iovec(
        raw: *const RawMessage,
        iov: *mut libc::iovec,
        iov_len: c_int,
        bytes: c_int,
    ) -> c_int;
    fn rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn epoll_sethandler(fd: c_int, prio: c_int, handler: EventHandler, data: *mut c_void) -> c_int;
    fn epoll_insert(fd: c_int, flags: c_int) -> c_int;
    fn epoll_remove(fd: c_int) -> c_int;
    fn remove_event_from_heap(ev: *mut EventDescr, allow_hole: c_int) -> c_int;
    fn mtproxy_ffi_net_connections_mpq_pop_nw(mq: *mut MpQueue, flags: c_int) -> *mut c_void;
    fn mtproxy_ffi_net_connections_rwm_union(raw: *mut RawMessage, tail: *mut RawMessage) -> c_int;

    fn server_noop(c: ConnectionJob) -> c_int;
    fn server_failed(c: ConnectionJob) -> c_int;
    fn server_flush(c: ConnectionJob) -> c_int;
    fn server_check_ready(c: ConnectionJob) -> c_int;

    fn cpu_server_close_connection(c: ConnectionJob, who: c_int) -> c_int;
    fn cpu_server_read_write(c: ConnectionJob) -> c_int;
    fn cpu_server_free_connection(c: ConnectionJob) -> c_int;
    #[link_name = "mtproxy_ffi_net_tcp_connections_cpu_tcp_free_connection_buffers"]
    fn cpu_tcp_free_connection_buffers(c: ConnectionJob) -> c_int;
    #[link_name = "mtproxy_ffi_net_tcp_connections_cpu_tcp_server_reader"]
    fn cpu_tcp_server_reader(c: ConnectionJob) -> c_int;
    #[link_name = "mtproxy_ffi_net_tcp_connections_cpu_tcp_server_writer"]
    fn cpu_tcp_server_writer(c: ConnectionJob) -> c_int;

    fn mtproxy_ffi_net_connections_precise_now() -> c_double;
    fn drand48_j() -> c_double;
    fn mtproxy_ffi_net_connections_stats_add(
        allocated_socket_connections_delta: c_int,
        accept_calls_failed_delta: c_longlong,
        inbound_connections_accepted_delta: c_longlong,
        accept_rate_limit_failed_delta: c_longlong,
    );
    fn mtproxy_ffi_net_connections_accept_rate_get_max() -> c_int;
    fn mtproxy_ffi_net_connections_accept_rate_get_state(
        out_remaining: *mut c_double,
        out_time: *mut c_double,
    );
    fn mtproxy_ffi_net_connections_accept_rate_set_state(remaining: c_double, time: c_double);
    fn mtproxy_ffi_net_connections_get_max_connection_fd() -> c_int;
    fn mtproxy_ffi_net_connections_get_max_connection() -> c_int;
    fn mtproxy_ffi_net_connections_set_max_connection(value: c_int);
    fn mtproxy_ffi_net_connections_register_special_listen_socket(fd: c_int, generation: c_int);
    fn mtproxy_ffi_net_connections_stat_inc_listening();
    fn mtproxy_ffi_net_connections_stats_add_ready(
        ready_outbound_delta: c_int,
        ready_targets_delta: c_int,
    );
    fn mtproxy_ffi_net_connections_stats_add_targets(
        active_targets_delta: c_int,
        inactive_targets_delta: c_int,
    );
    fn mtproxy_ffi_net_connections_stat_add_allocated_targets(delta: c_int);
    fn mtproxy_ffi_net_connections_stat_target_freed();
    fn mtproxy_ffi_net_connections_stat_free_later_enqueued();
    fn mtproxy_ffi_net_connections_stat_free_later_dequeued();
    fn mtproxy_ffi_net_connections_free_target(ctj: ConnTargetJob) -> c_int;
    fn new_conn_generation() -> c_int;
    fn client_socket(in_addr: u32, port: c_int, mode: c_int) -> c_int;
    fn client_socket_ipv6(in6_addr_ptr: *const u8, port: c_int, mode: c_int) -> c_int;
    fn lrand48_j() -> libc::c_long;
    static mut tcp_maximize_buffers: c_int;
    static mut verbosity: c_int;
    static mut active_special_connections: c_int;
    static mut max_special_connections: c_int;
    fn maximize_sndbuf(socket_fd: c_int, max: c_int);
    fn maximize_rcvbuf(socket_fd: c_int, max: c_int);

    fn get_tree_ptr_connection(tree: *mut *mut TreeConnection) -> *mut TreeConnection;
    fn tree_act_ex_connection(
        tree: *mut TreeConnection,
        act: Option<unsafe extern "C" fn(ConnectionJob, *mut c_void)>,
        ex: *mut c_void,
    );
    fn tree_act_ex3_connection(
        tree: *mut TreeConnection,
        act: Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, *mut c_void, *mut c_void)>,
        ex: *mut c_void,
        ex2: *mut c_void,
        ex3: *mut c_void,
    );
    fn tree_act_connection(
        tree: *mut TreeConnection,
        act: Option<unsafe extern "C" fn(ConnectionJob)>,
    );
    fn tree_insert_connection(
        tree: *mut TreeConnection,
        conn: ConnectionJob,
        priority: c_int,
    ) -> *mut TreeConnection;
    fn tree_delete_connection(
        tree: *mut TreeConnection,
        conn: ConnectionJob,
    ) -> *mut TreeConnection;
    fn tree_free_connection(tree: *mut TreeConnection);
    fn free_tree_ptr_connection(tree: *mut TreeConnection);
    fn mtproxy_ffi_net_connections_stat_inc_accept_nonblock_set_failed();
    fn mtproxy_ffi_net_connections_stat_inc_accept_connection_limit_failed();
    fn mtproxy_ffi_net_connections_stats_add_alloc_connection_success(
        outbound_delta: c_int,
        allocated_outbound_delta: c_int,
        outbound_created_delta: c_int,
        inbound_accepted_delta: c_int,
        allocated_inbound_delta: c_int,
        inbound_delta: c_int,
        active_inbound_delta: c_int,
        active_connections_delta: c_int,
    );
    fn mtproxy_ffi_net_connections_stat_inc_allocated_connections();
    fn mtproxy_ffi_net_connections_stat_inc_accept_init_accepted_failed();
    fn mtproxy_ffi_net_connections_job_thread_dec_jobs_active();
    fn mtproxy_ffi_net_connections_stats_add_tcp_read(
        calls_delta: c_longlong,
        intr_delta: c_longlong,
        bytes_delta: c_longlong,
    );
    fn mtproxy_ffi_net_connections_stats_add_tcp_write(
        calls_delta: c_longlong,
        intr_delta: c_longlong,
        bytes_delta: c_longlong,
    );
    fn mtproxy_ffi_net_connections_stats_add_close_failure(
        total_failed_delta: c_int,
        total_connect_failures_delta: c_int,
        unused_closed_delta: c_int,
    );
    fn mtproxy_ffi_net_connections_stat_dec_active_dh();
    fn mtproxy_ffi_net_connections_stats_add_close_basic(
        outbound_delta: c_int,
        inbound_delta: c_int,
        active_outbound_delta: c_int,
        active_inbound_delta: c_int,
        active_connections_delta: c_int,
    );
    fn mtproxy_ffi_net_connections_close_connection_signal_special_aux();
    fn mtproxy_ffi_net_connections_stats_add_free_connection_counts(
        allocated_outbound_delta: c_int,
        allocated_inbound_delta: c_int,
    );
}

#[inline]
unsafe fn job_custom_ptr<T>(job: Job) -> *mut T {
    ptr::addr_of_mut!((*job.cast::<AsyncJob>()).j_custom).cast::<T>()
}

#[inline]
unsafe fn conn_info(c: ConnectionJob) -> *mut ConnectionInfo {
    unsafe { job_custom_ptr(c) }
}

#[inline]
pub(super) unsafe fn conn_crypto_slots(
    c: ConnectionJob,
) -> (*mut *mut c_void, *mut *mut c_void) {
    let conn = unsafe { conn_info(c) };
    if conn.is_null() {
        return (ptr::null_mut(), ptr::null_mut());
    }
    (ptr::addr_of_mut!((*conn).crypto), ptr::addr_of_mut!((*conn).crypto_temp))
}

#[inline]
unsafe fn socket_conn_info(c: SocketConnectionJob) -> *mut SocketConnectionInfo {
    unsafe { job_custom_ptr(c) }
}

#[inline]
unsafe fn listen_conn_info(c: SocketConnectionJob) -> *mut ListeningConnectionInfo {
    unsafe { job_custom_ptr(c) }
}

#[inline]
unsafe fn conn_target_info(c: ConnTargetJob) -> *mut ConnTargetInfo {
    unsafe { job_custom_ptr(c) }
}

#[inline]
unsafe fn atomic_i32<'a>(ptr: *mut c_int) -> &'a AtomicI32 {
    unsafe { &*ptr.cast::<AtomicI32>() }
}

#[inline]
unsafe fn atomic_i64<'a>(ptr: *mut c_longlong) -> &'a AtomicI64 {
    unsafe { &*ptr.cast::<AtomicI64>() }
}

#[inline]
unsafe fn job_signal_create_pass(job: Job, signo: c_int) {
    unsafe { job_signal(1, job_incref(job), signo) };
}

#[inline]
unsafe fn job_decref_pass(job: Job) {
    unsafe { job_decref(1, job) };
}

#[inline]
fn is_4in6(ipv6: &[u8; 16]) -> bool {
    let hi = u64::from_ne_bytes(ipv6[0..8].try_into().unwrap_or([0; 8]));
    let mid = i32::from_ne_bytes(ipv6[8..12].try_into().unwrap_or([0; 4]));
    hi == 0 && mid == -0x10000
}

#[inline]
fn extract_4in6(ipv6: &[u8; 16]) -> u32 {
    u32::from_ne_bytes(ipv6[12..16].try_into().unwrap_or([0; 4]))
}

unsafe fn prealloc_tcp_buffers_impl() -> c_int {
    assert_eq!(unsafe { TCP_RECV_BUFFERS_NUM }, 0);

    for i in (0..MAX_TCP_RECV_BUFFERS).rev() {
        let neighbor = if unsafe { TCP_RECV_BUFFERS_NUM } != 0 {
            unsafe { TCP_RECV_BUFFERS[i + 1] }
        } else {
            ptr::null_mut()
        };
        let x = unsafe { alloc_msg_buffer(neighbor, TCP_RECV_BUFFER_SIZE) };
        if x.is_null() {
            unsafe { crate::kprintf_fmt!(FATAL_TCP_RECV_BUFFER_MSG.as_ptr().cast()) };
            unsafe { libc::exit(2) };
        }

        let chunk = unsafe { (*x).chunk };
        assert!(!chunk.is_null());
        let buffer_size = unsafe { (*chunk).buffer_size };
        assert!(buffer_size > 0);

        unsafe {
            TCP_RECV_BUFFERS[i] = x;
            TCP_RECV_IOVEC[i + 1].iov_base = ptr::addr_of_mut!((*x).data).cast::<c_void>();
            TCP_RECV_IOVEC[i + 1].iov_len = usize::try_from(buffer_size).unwrap_or(0);
            TCP_RECV_BUFFERS_NUM += 1;
            TCP_RECV_BUFFERS_TOTAL_SIZE += buffer_size;
        }
    }
    unsafe { TCP_RECV_BUFFERS_NUM }
}

unsafe fn tcp_prepare_iovec_impl(
    iov: *mut libc::iovec,
    iovcnt: *mut c_int,
    maxcnt: c_int,
    raw: *mut RawMessage,
) -> c_int {
    let t = unsafe { rwm_prepare_iovec(raw, iov, maxcnt, (*raw).total_bytes) };
    if t < 0 {
        unsafe {
            *iovcnt = maxcnt;
        }
        let mut total = 0_i32;
        let maxcnt_u = usize::try_from(maxcnt).unwrap_or(0);
        for i in 0..maxcnt_u {
            total += c_int::try_from(unsafe { (*iov.add(i)).iov_len }).unwrap_or(c_int::MAX);
        }
        assert!(total < unsafe { (*raw).total_bytes });
        total
    } else {
        unsafe {
            *iovcnt = t;
            (*raw).total_bytes
        }
    }
}

pub(super) unsafe fn connection_write_close_impl(c: ConnectionJob) {
    let conn = unsafe { conn_info(c) };
    let io_conn = unsafe { (*conn).io_conn };
    let action = mtproxy_core::runtime::net::connections::connection_write_close_action(
        unsafe { (*conn).status },
        !io_conn.is_null(),
    );
    if action == 0 {
        return;
    }

    if (action & CONNECTION_WRITE_CLOSE_ACTION_SET_IO_STOPREAD) != 0 {
        let io = unsafe { socket_conn_info(io_conn) };
        unsafe { atomic_i32(ptr::addr_of_mut!((*io).flags)) }
            .fetch_or(C_STOPREAD, Ordering::SeqCst);
    }
    if (action & CONNECTION_WRITE_CLOSE_ACTION_SET_CONN_STOPREAD) != 0 {
        unsafe { atomic_i32(ptr::addr_of_mut!((*conn).flags)) }
            .fetch_or(C_STOPREAD, Ordering::SeqCst);
    }
    if (action & CONNECTION_WRITE_CLOSE_ACTION_SET_STATUS_WRITE_CLOSE) != 0 {
        unsafe {
            (*conn).status = 5;
        }
    }
    if (action & CONNECTION_WRITE_CLOSE_ACTION_SIGNAL_RUN) != 0 {
        unsafe { job_signal_create_pass(c, JS_RUN) };
    }
}

pub(super) unsafe fn fail_socket_connection_impl(c: SocketConnectionJob, who: c_int) {
    let socket = unsafe { socket_conn_info(c) };
    assert!((unsafe { (*c.cast::<AsyncJob>()).j_flags } & JF_LOCKED) != 0);

    let previous_flags = unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
        .fetch_or(C_ERROR, Ordering::SeqCst);
    let action =
        mtproxy_core::runtime::net::connections::fail_socket_connection_action(previous_flags);
    if action == 0 {
        return;
    }

    unsafe {
        job_timer_remove(c);
        remove_event_from_heap((*socket).ev, 0);
        connection_event_incref_impl((*socket).fd, -1);
        epoll_insert((*socket).fd, 0);
        (*socket).ev = ptr::null_mut();
    }

    let type_ = unsafe { (*socket).type_ };
    assert!(!type_.is_null());
    if let Some(socket_close) = unsafe { (*type_).socket_close } {
        unsafe { socket_close(c) };
    }

    unsafe { fail_connection_impl((*socket).conn, who) };
}

pub(super) unsafe fn net_server_socket_free_impl(c: SocketConnectionJob) -> c_int {
    let socket = unsafe { socket_conn_info(c) };
    assert!(unsafe { (*socket).ev.is_null() });
    assert!((unsafe { (*socket).flags } & C_ERROR) != 0);

    let (socket_free_action, fail_error, allocated_socket_delta) =
        mtproxy_core::runtime::net::connections::socket_free_plan(unsafe {
            !(*socket).conn.is_null()
        });
    assert!(
        socket_free_action == SOCKET_FREE_ACTION_NONE
            || socket_free_action == SOCKET_FREE_ACTION_FAIL_CONN
    );

    if socket_free_action == SOCKET_FREE_ACTION_FAIL_CONN {
        let conn = unsafe { (*socket).conn };
        assert!(!conn.is_null());
        unsafe {
            fail_connection_impl(conn, fail_error);
            job_decref_pass(conn);
        }
    }

    loop {
        let raw = unsafe { mtproxy_ffi_net_connections_mpq_pop_nw((*socket).out_packet_queue, 4) }
            .cast::<RawMessage>();
        if raw.is_null() {
            break;
        }
        unsafe {
            rwm_free(raw);
            libc::free(raw.cast());
        }
    }

    unsafe {
        free_mp_queue((*socket).out_packet_queue);
        rwm_free(ptr::addr_of_mut!((*socket).out));
        mtproxy_ffi_net_connections_stats_add(allocated_socket_delta, 0, 0, 0);
    }
    0
}

pub(super) unsafe fn net_server_socket_reader_impl(c: SocketConnectionJob) -> c_int {
    let socket = unsafe { socket_conn_info(c) };

    loop {
        if !mtproxy_core::runtime::net::connections::socket_reader_should_run(unsafe {
            (*socket).flags
        }) {
            break;
        }
        if unsafe { TCP_RECV_BUFFERS_NUM } == 0 {
            unsafe { prealloc_tcp_buffers_impl() };
        }

        let in_msg = unsafe { libc::malloc(size_of::<RawMessage>()).cast::<RawMessage>() };
        assert!(!in_msg.is_null());
        unsafe {
            rwm_init(in_msg, 0);
        }

        let s = unsafe { TCP_RECV_BUFFERS_TOTAL_SIZE };
        assert!(s > 0);
        let mut p = 1_usize;

        unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
            .fetch_or(C_NORD, Ordering::SeqCst);
        let r_isize = unsafe {
            libc::readv(
                (*socket).fd,
                ptr::addr_of_mut!(TCP_RECV_IOVEC[p]),
                c_int::try_from(MAX_TCP_RECV_BUFFERS + 1 - p).unwrap_or(0),
            )
        };
        let read_errno = if r_isize < 0 {
            unsafe { *libc::__errno_location() }
        } else {
            0
        };
        unsafe {
            mtproxy_ffi_net_connections_stats_add_tcp_read(1, 0, 0);
        }

        let r = c_int::try_from(r_isize).unwrap_or(if r_isize < 0 { -1 } else { c_int::MAX });
        let io_action = mtproxy_core::runtime::net::connections::socket_reader_io_action(
            r,
            read_errno,
            libc::EAGAIN,
            libc::EINTR,
        );
        assert!(
            io_action == SOCKET_READER_IO_HAVE_DATA
                || io_action == SOCKET_READER_IO_BREAK
                || io_action == SOCKET_READER_IO_CONTINUE_INTR
                || io_action == SOCKET_READER_IO_FATAL_ABORT
        );

        if io_action == SOCKET_READER_IO_CONTINUE_INTR {
            unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
                .fetch_and(!C_NORD, Ordering::SeqCst);
            unsafe {
                mtproxy_ffi_net_connections_stats_add_tcp_read(0, 1, 0);
            }
            continue;
        }
        if io_action == SOCKET_READER_IO_FATAL_ABORT {
            unsafe {
                job_signal_create_pass(c, JS_ABORT);
                atomic_i32(ptr::addr_of_mut!((*socket).flags))
                    .fetch_or(C_NET_FAILED, Ordering::SeqCst);
            }
            return 0;
        }
        if io_action == SOCKET_READER_IO_HAVE_DATA {
            unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
                .fetch_and(!C_NORD, Ordering::SeqCst);
        }

        let _ = s;
        if io_action == SOCKET_READER_IO_BREAK {
            unsafe {
                rwm_free(in_msg);
                libc::free(in_msg.cast());
            }
            break;
        }
        assert_eq!(io_action, SOCKET_READER_IO_HAVE_DATA);
        unsafe {
            mtproxy_ffi_net_connections_stats_add_tcp_read(0, 0, c_longlong::from(r));
        }

        let mut mp = unsafe { new_msg_part(ptr::null_mut(), TCP_RECV_BUFFERS[p - 1]) };
        assert!(!mp.is_null());
        let first_len = c_int::try_from(unsafe { TCP_RECV_IOVEC[p].iov_len }).unwrap_or(c_int::MAX);
        unsafe {
            (*mp).offset = 0;
            (*mp).data_end = if r > first_len { first_len } else { r };
        }
        let mut rem = r - unsafe { (*mp).data_end };
        unsafe {
            (*in_msg).first = mp.cast();
            (*in_msg).last = mp.cast();
            (*in_msg).total_bytes = (*mp).data_end;
            (*in_msg).first_offset = 0;
            (*in_msg).last_offset = (*mp).data_end;
        }
        p += 1;

        while rem > 0 {
            let next = unsafe { new_msg_part(ptr::null_mut(), TCP_RECV_BUFFERS[p - 1]) };
            assert!(!next.is_null());
            let next_len =
                c_int::try_from(unsafe { TCP_RECV_IOVEC[p].iov_len }).unwrap_or(c_int::MAX);
            unsafe {
                (*next).offset = 0;
                (*next).data_end = if rem > next_len { next_len } else { rem };
                rem -= (*next).data_end;
                (*mp).next = next;
                mp = next;
                (*in_msg).last = mp.cast();
                (*in_msg).last_offset = (*mp).data_end;
                (*in_msg).total_bytes += (*mp).data_end;
            }
            p += 1;
        }
        assert_eq!(rem, 0);

        for i in 0..(p - 1) {
            let x = unsafe { alloc_msg_buffer(TCP_RECV_BUFFERS[i], TCP_RECV_BUFFER_SIZE) };
            if x.is_null() {
                unsafe {
                    crate::kprintf_fmt!(FATAL_TCP_RECV_BUFFER_MSG.as_ptr().cast());
                }
                assert!(false);
            }
            let chunk = unsafe { (*x).chunk };
            assert!(!chunk.is_null());
            let buffer_size = unsafe { (*chunk).buffer_size };
            assert!(buffer_size > 0);
            unsafe {
                TCP_RECV_BUFFERS[i] = x;
                TCP_RECV_IOVEC[i + 1].iov_base = ptr::addr_of_mut!((*x).data).cast::<c_void>();
                TCP_RECV_IOVEC[i + 1].iov_len = usize::try_from(buffer_size).unwrap_or(0);
            }
        }

        let conn_job = unsafe { (*socket).conn };
        assert!(!conn_job.is_null());
        let conn = unsafe { conn_info(conn_job) };
        unsafe {
            mtproxy_ffi_net_connections_mpq_push_w((*conn).in_queue, in_msg.cast(), 0);
            job_signal_create_pass(conn_job, JS_RUN);
        }
    }
    0
}

pub(super) unsafe fn net_server_socket_writer_impl(c: SocketConnectionJob) -> c_int {
    let socket = unsafe { socket_conn_info(c) };
    let out = unsafe { ptr::addr_of_mut!((*socket).out) };
    let check_watermark = unsafe { (*out).total_bytes >= (*socket).write_low_watermark };
    let mut written_total = 0;
    let stop = unsafe { (*socket).flags & C_STOPWRITE };

    loop {
        if !mtproxy_core::runtime::net::connections::socket_writer_should_run(unsafe {
            (*socket).flags
        }) {
            break;
        }

        if unsafe { (*out).total_bytes } == 0 {
            unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
                .fetch_and(!C_WANTWR, Ordering::SeqCst);
            break;
        }

        let mut iov = [libc::iovec {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        }; SOCKET_WRITER_MAX_IOVEC];
        let mut iovcnt: c_int = -1;
        let s = unsafe {
            tcp_prepare_iovec_impl(
                iov.as_mut_ptr(),
                ptr::addr_of_mut!(iovcnt),
                c_int::try_from(SOCKET_WRITER_MAX_IOVEC).unwrap_or(0),
                out,
            )
        };
        assert!(iovcnt > 0 && s > 0);

        unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
            .fetch_or(C_NOWR, Ordering::SeqCst);
        let r_isize = unsafe { libc::writev((*socket).fd, iov.as_ptr(), iovcnt) };
        unsafe {
            mtproxy_ffi_net_connections_stats_add_tcp_write(1, 0, 0);
        }

        let write_errno = if r_isize < 0 {
            unsafe { *libc::__errno_location() }
        } else {
            0
        };
        let r = c_int::try_from(r_isize).unwrap_or(if r_isize < 0 { -1 } else { c_int::MAX });
        let (io_action, next_eagain_count) =
            mtproxy_core::runtime::net::connections::socket_writer_io_action(
                r,
                write_errno,
                unsafe { (*socket).eagain_count },
                libc::EAGAIN,
                libc::EINTR,
                100,
            );
        assert!(
            io_action == SOCKET_WRITER_IO_HAVE_DATA
                || io_action == SOCKET_WRITER_IO_BREAK_EAGAIN
                || io_action == SOCKET_WRITER_IO_CONTINUE_INTR
                || io_action == SOCKET_WRITER_IO_FATAL_EAGAIN_LIMIT
                || io_action == SOCKET_WRITER_IO_FATAL_OTHER
        );
        unsafe {
            (*socket).eagain_count = next_eagain_count;
        }

        if io_action == SOCKET_WRITER_IO_CONTINUE_INTR {
            unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
                .fetch_and(!C_NOWR, Ordering::SeqCst);
            unsafe {
                mtproxy_ffi_net_connections_stats_add_tcp_write(0, 1, 0);
            }
            continue;
        }
        if io_action == SOCKET_WRITER_IO_FATAL_EAGAIN_LIMIT {
            unsafe {
                crate::kprintf_fmt!(TOO_MUCH_EAGAIN_MSG.as_ptr().cast(), (*socket).fd);
                job_signal_create_pass(c, JS_ABORT);
                atomic_i32(ptr::addr_of_mut!((*socket).flags))
                    .fetch_or(C_NET_FAILED, Ordering::SeqCst);
            }
            return 0;
        }
        if io_action == SOCKET_WRITER_IO_FATAL_OTHER {
            unsafe {
                job_signal_create_pass(c, JS_ABORT);
                atomic_i32(ptr::addr_of_mut!((*socket).flags))
                    .fetch_or(C_NET_FAILED, Ordering::SeqCst);
            }
            return 0;
        }
        if io_action == SOCKET_WRITER_IO_HAVE_DATA {
            unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
                .fetch_and(!C_NOWR, Ordering::SeqCst);
            unsafe {
                mtproxy_ffi_net_connections_stats_add_tcp_write(0, 0, c_longlong::from(r));
            }
            written_total += r;
        }

        if unsafe { verbosity > 0 && r < 0 && write_errno != libc::EAGAIN } {
            unsafe {
                libc::perror(c"writev()".as_ptr());
            }
        }
        let _ = s;
        let _ = iovcnt;

        if r > 0 {
            unsafe {
                rwm_skip_data(out, r);
            }
            let data_sent = unsafe { (*(*socket).type_).data_sent };
            if let Some(cb) = data_sent {
                unsafe {
                    cb(c, r);
                }
            }
        }
    }

    let should_call_ready_to_write =
        mtproxy_core::runtime::net::connections::socket_writer_should_call_ready_to_write(
            check_watermark,
            unsafe { (*out).total_bytes },
            unsafe { (*socket).write_low_watermark },
        );
    if should_call_ready_to_write {
        if let Some(ready_to_write) = unsafe { (*(*socket).type_).ready_to_write } {
            unsafe { ready_to_write(c) };
        }
    }

    let should_abort_on_stop =
        mtproxy_core::runtime::net::connections::socket_writer_should_abort_on_stop(
            stop != 0,
            unsafe { (*socket).flags },
        );
    if should_abort_on_stop {
        unsafe {
            job_signal_create_pass(c, JS_ABORT);
            atomic_i32(ptr::addr_of_mut!((*socket).flags)).fetch_or(C_NET_FAILED, Ordering::SeqCst);
        }
    }

    let _ = written_total;
    unsafe { (*out).total_bytes }
}

pub(super) unsafe fn do_socket_connection_job_impl(job: Job, op: c_int, _jt: *mut c_void) -> c_int {
    let c = job;
    let socket = unsafe { socket_conn_info(c) };
    let action = mtproxy_core::runtime::net::connections::socket_job_action(
        op, JS_ABORT, JS_RUN, JS_AUX, JS_FINISH,
    );

    if action == SOCKET_JOB_ACTION_ABORT {
        let abort_who = mtproxy_core::runtime::net::connections::socket_job_abort_error();
        unsafe { fail_socket_connection_impl(c, abort_who) };
        return JOB_COMPLETED;
    }

    if action == SOCKET_JOB_ACTION_RUN {
        let run_flags = unsafe { (*socket).flags };
        if mtproxy_core::runtime::net::connections::socket_job_run_should_call_read_write(run_flags)
        {
            let type_ = unsafe { (*socket).type_ };
            assert!(!type_.is_null());
            let read_write = unsafe { (*type_).socket_read_write };
            assert!(read_write.is_some());
            let res = unsafe { read_write.unwrap()(job) };
            if mtproxy_core::runtime::net::connections::socket_job_run_should_signal_aux(
                run_flags,
                res,
                unsafe { (*socket).current_epoll_status },
            ) {
                unsafe {
                    (*socket).current_epoll_status = res;
                }
                return JOB_SENDSIG_AUX;
            }
        }
        return 0;
    }

    if action == SOCKET_JOB_ACTION_AUX {
        if mtproxy_core::runtime::net::connections::socket_job_aux_should_update_epoll(unsafe {
            (*socket).flags
        }) {
            let events = mtproxy_core::runtime::net::connections::compute_conn_events(
                unsafe { (*socket).flags },
                true,
            );
            unsafe {
                epoll_insert((*socket).fd, events);
            }
        }
        return 0;
    }

    if action == SOCKET_JOB_ACTION_FINISH {
        assert_eq!(unsafe { (*c.cast::<AsyncJob>()).j_refcnt }, 1);
        let type_ = unsafe { (*socket).type_ };
        assert!(!type_.is_null());
        let socket_free = unsafe { (*type_).socket_free };
        assert!(socket_free.is_some());
        unsafe {
            socket_free.unwrap()(c);
            return mtproxy_ffi_net_connections_job_free(c);
        }
    }

    JOB_ERROR
}

pub(super) unsafe fn alloc_new_socket_connection_impl(c: ConnectionJob) -> SocketConnectionJob {
    let conn = unsafe { conn_info(c) };
    let job_signals = jsc_allow(JC_CONNECTION_IO, JS_RUN)
        | jsc_allow(JC_CONNECTION_IO, JS_ALARM)
        | jsc_allow(JC_EPOLL, JS_ABORT)
        | jsc_allow(JC_CONNECTION_IO, JS_FINISH)
        | jsc_allow(JC_EPOLL, JS_AUX);
    let s = unsafe {
        create_async_job(
            Some(do_socket_connection_job),
            job_signals,
            -2,
            c_int::try_from(size_of::<SocketConnectionInfo>()).unwrap_or(c_int::MAX),
            JT_HAVE_TIMER,
            1,
            ptr::null_mut(),
        )
    };
    assert!(!s.is_null());
    unsafe {
        (*s.cast::<AsyncJob>()).j_refcnt = 2;
    }
    let socket = unsafe { socket_conn_info(s) };

    let (socket_flags, initial_epoll_status, allocated_socket_delta) =
        mtproxy_core::runtime::net::connections::alloc_socket_connection_plan(
            unsafe { (*conn).flags },
            true,
        );

    unsafe {
        (*socket).fd = (*conn).fd;
        (*socket).type_ = (*conn).type_;
        (*socket).conn = job_incref(c);
        (*socket).flags = socket_flags;
        (*socket).our_ip = (*conn).our_ip;
        (*socket).our_port = (*conn).our_port;
        (*socket).our_ipv6 = (*conn).our_ipv6;
        (*socket).remote_ip = (*conn).remote_ip;
        (*socket).remote_port = (*conn).remote_port;
        (*socket).remote_ipv6 = (*conn).remote_ipv6;
        (*socket).out_packet_queue = alloc_mp_queue_w();
    }

    let fd_u = usize::try_from(unsafe { (*socket).fd }).unwrap_or(MAX_EVENTS);
    assert!(fd_u < MAX_EVENTS);
    let ev = unsafe { ptr::addr_of_mut!(Events[fd_u]) };
    assert!(unsafe { (*ev).data }.is_null());
    assert_eq!(unsafe { (*ev).refcnt }, 0);
    unsafe {
        (*socket).ev = ev;
        epoll_sethandler(
            (*socket).fd,
            0,
            Some(net_server_socket_read_write_gateway),
            s.cast(),
        );
        (*socket).current_epoll_status = initial_epoll_status;
        epoll_insert((*socket).fd, (*socket).current_epoll_status);
        (*conn).io_conn = s;
        rwm_init(ptr::addr_of_mut!((*socket).out), 0);
        // Keep both logical owners alive after unlock: `conn.io_conn` and `Events[fd].data`.
        // Legacy C path used `unlock_job(JOB_REF_CREATE_PASS(S))`.
        unlock_job(1, job_incref(s));
        mtproxy_ffi_net_connections_stats_add(allocated_socket_delta, 0, 0, 0);
    }

    s
}

pub(super) unsafe fn alloc_new_connection_impl(
    cfd: c_int,
    ctj: ConnTargetJob,
    lcj: Job,
    basic_type: c_int,
    conn_type: *mut ConnType,
    conn_extra: *mut c_void,
    peer: c_uint,
    peer_ipv6: *mut u8,
    peer_port: c_int,
) -> ConnectionJob {
    if cfd < 0 {
        return ptr::null_mut();
    }

    let ct = if ctj.is_null() {
        ptr::null_mut()
    } else {
        unsafe { conn_target_info(ctj) }
    };
    let lc = if lcj.is_null() {
        ptr::null_mut()
    } else {
        unsafe { listen_conn_info(lcj) }
    };

    let mut flags = if unsafe { libc::fcntl(cfd, libc::F_GETFL, 0) } < 0 {
        1
    } else {
        0
    };
    if flags != 0 || unsafe { libc::fcntl(cfd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        unsafe {
            crate::kprintf_fmt!(ACCEPT_NONBLOCK_FAIL_MSG.as_ptr().cast(), cfd);
            mtproxy_ffi_net_connections_stat_inc_accept_nonblock_set_failed();
            libc::close(cfd);
        }
        return ptr::null_mut();
    }

    flags = 1;
    unsafe {
        libc::setsockopt(
            cfd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(size_of::<c_int>()).unwrap_or(0),
        );
    }
    if unsafe { tcp_maximize_buffers } != 0 {
        unsafe {
            maximize_sndbuf(cfd, 0);
            maximize_rcvbuf(cfd, 0);
        }
    }

    let max_connection_fd = unsafe { mtproxy_ffi_net_connections_get_max_connection_fd() };
    let fd_action =
        mtproxy_core::runtime::net::connections::listening_init_fd_action(cfd, max_connection_fd);
    assert!(fd_action == 0 || fd_action == 1);
    if fd_action != 0 {
        unsafe {
            mtproxy_ffi_net_connections_stat_inc_accept_connection_limit_failed();
            libc::close(cfd);
        }
        return ptr::null_mut();
    }

    let updated_max = mtproxy_core::runtime::net::connections::listening_init_update_max_connection(
        cfd,
        unsafe { mtproxy_ffi_net_connections_get_max_connection() },
    );
    unsafe { mtproxy_ffi_net_connections_set_max_connection(updated_max) };

    let c = unsafe {
        create_async_job(
            Some(do_connection_job),
            jsc_allow(JC_CONNECTION, JS_RUN)
                | jsc_allow(JC_CONNECTION, JS_ALARM)
                | jsc_allow(JC_CONNECTION, JS_ABORT)
                | jsc_allow(JC_CONNECTION, JS_FINISH),
            -2,
            c_int::try_from(size_of::<ConnectionInfo>()).unwrap_or(c_int::MAX),
            JT_HAVE_TIMER,
            1,
            ptr::null_mut(),
        )
    };
    assert!(!c.is_null());

    let conn = unsafe { conn_info(c) };
    unsafe {
        (*conn).fd = cfd;
        (*conn).target = ctj;
        (*conn).generation = new_conn_generation();
    }

    let (initial_flags, initial_status, is_outbound_path) =
        mtproxy_core::runtime::net::connections::alloc_connection_basic_type_policy(basic_type);
    unsafe {
        (*conn).flags = initial_flags;
        (*conn).flags |= C_RAWMSG;
        rwm_init(ptr::addr_of_mut!((*conn).in_data), 0);
        rwm_init(ptr::addr_of_mut!((*conn).out), 0);
        rwm_init(ptr::addr_of_mut!((*conn).in_u), 0);
        rwm_init(ptr::addr_of_mut!((*conn).out_p), 0);
        (*conn).type_ = conn_type;
        (*conn).extra = conn_extra;
        (*conn).basic_type = basic_type;
        (*conn).status = initial_status;
    }
    assert!(!unsafe { (*conn).type_ }.is_null());

    unsafe {
        (*conn).flags |= (*(*conn).type_).flags & C_EXTERNAL;
        if !lc.is_null() {
            (*conn).flags |= (*lc).flags & C_EXTERNAL;
        }
    }

    let mut self_addr = SockAddrIn46 {
        a4: unsafe { core::mem::zeroed() },
    };
    let mut self_addrlen = libc::socklen_t::try_from(size_of::<SockAddrIn46>()).unwrap_or(0);
    unsafe {
        libc::memset(
            ptr::addr_of_mut!(self_addr).cast(),
            0,
            size_of::<SockAddrIn46>(),
        );
        libc::getsockname(
            cfd,
            ptr::addr_of_mut!(self_addr).cast::<libc::sockaddr>(),
            ptr::addr_of_mut!(self_addrlen),
        );
    }

    let mut peer_ipv6_v = [0_u8; 16];
    if !peer_ipv6.is_null() {
        unsafe {
            ptr::copy_nonoverlapping(peer_ipv6, peer_ipv6_v.as_mut_ptr(), 16);
        }
    }

    if unsafe { self_addr.a4.sin_family as c_int } == libc::AF_INET {
        unsafe {
            (*conn).our_ip = u32::from_be(self_addr.a4.sin_addr.s_addr);
            (*conn).our_port = u32::from(u16::from_be(self_addr.a4.sin_port));
            (*conn).remote_ip = peer;
        }
    } else {
        assert_eq!(unsafe { self_addr.a6.sin6_family as c_int }, libc::AF_INET6);
        if is_4in6(unsafe { &self_addr.a6.sin6_addr.s6_addr }) && is_4in6(&peer_ipv6_v) {
            unsafe {
                (*conn).our_ip = u32::from_be(extract_4in6(&self_addr.a6.sin6_addr.s6_addr));
                (*conn).our_port = u32::from(u16::from_be(self_addr.a6.sin6_port));
                (*conn).remote_ip = u32::from_be(extract_4in6(&peer_ipv6_v));
            }
        } else {
            unsafe {
                (*conn).our_ipv6 = self_addr.a6.sin6_addr.s6_addr;
                (*conn).our_port = u32::from(u16::from_be(self_addr.a6.sin6_port));
                (*conn).flags |= C_IPV6;
                (*conn).remote_ipv6 = peer_ipv6_v;
            }
        }
    }
    unsafe {
        (*conn).remote_port = c_uint::try_from(peer_port).unwrap_or(0);
        (*conn).in_queue = alloc_mp_queue_w();
        (*conn).out_queue = alloc_mp_queue_w();
    }

    let init_fn = if is_outbound_path {
        unsafe { (*(*conn).type_).init_outbound }
    } else {
        unsafe { (*(*conn).type_).init_accepted }
    };
    assert!(init_fn.is_some());

    if unsafe { init_fn.unwrap()(c) } >= 0 {
        let (
            outbound_delta,
            allocated_outbound_delta,
            outbound_created_delta,
            inbound_accepted_delta,
            allocated_inbound_delta,
            inbound_delta,
            active_inbound_delta,
            active_connections_delta,
            target_outbound_delta,
            should_incref_target,
        ) = mtproxy_core::runtime::net::connections::alloc_connection_success_deltas(
            basic_type,
            !ctj.is_null(),
        );
        unsafe {
            mtproxy_ffi_net_connections_stats_add_alloc_connection_success(
                outbound_delta,
                allocated_outbound_delta,
                outbound_created_delta,
                inbound_accepted_delta,
                allocated_inbound_delta,
                inbound_delta,
                active_inbound_delta,
                active_connections_delta,
            );
        }

        if should_incref_target {
            assert!(!ctj.is_null() && !ct.is_null());
            unsafe {
                job_incref(ctj);
            }
        }
        if target_outbound_delta != 0 {
            assert!(!ct.is_null());
            unsafe {
                (*ct).outbound_connections += target_outbound_delta;
            }
        }

        if !is_outbound_path {
            if !lc.is_null() {
                unsafe {
                    (*conn).listening = (*lc).fd;
                    (*conn).listening_generation = (*lc).generation;
                }
                let listener_flags =
                    mtproxy_core::runtime::net::connections::alloc_connection_listener_flags(
                        unsafe { (*lc).flags },
                    );
                unsafe {
                    (*conn).flags |= listener_flags;
                    (*conn).window_clamp = (*lc).window_clamp;
                }

                if (listener_flags & C_SPECIAL) != 0 {
                    let special_connections =
                        unsafe { atomic_i32(ptr::addr_of_mut!(active_special_connections)) }
                            .fetch_add(1, Ordering::SeqCst)
                            + 1;
                    let special_action =
                        mtproxy_core::runtime::net::connections::alloc_connection_special_action(
                            special_connections,
                            unsafe { max_special_connections },
                        );
                    assert!(
                        (special_action
                            & !(ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL1
                                | ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL0
                                | ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE))
                            == 0
                    );
                    if (special_action & ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE) != 0 {
                        unsafe {
                            epoll_remove((*lc).fd);
                        }
                    }
                }
            }

            if unsafe { (*conn).window_clamp } != 0 {
                let clamp = unsafe { (*conn).window_clamp };
                unsafe {
                    libc::setsockopt(
                        cfd,
                        libc::IPPROTO_TCP,
                        libc::TCP_WINDOW_CLAMP,
                        ptr::addr_of!(clamp).cast(),
                        libc::socklen_t::try_from(size_of::<c_int>()).unwrap_or(0),
                    );
                }
            }
        }

        unsafe {
            alloc_new_socket_connection_impl(c);
            mtproxy_ffi_net_connections_stat_inc_allocated_connections();
        }
        return c;
    }

    let failure_action =
        mtproxy_core::runtime::net::connections::alloc_connection_failure_action(unsafe {
            (*conn).flags
        });
    assert!(failure_action != 0);
    assert!(
        (failure_action
            & !(ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED
                | ALLOC_CONNECTION_FAILURE_ACTION_FREE_RAWMSG
                | ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE
                | ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE))
            == 0
    );

    if (failure_action & ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED) != 0 {
        unsafe {
            mtproxy_ffi_net_connections_stat_inc_accept_init_accepted_failed();
        }
    }
    if (failure_action & ALLOC_CONNECTION_FAILURE_ACTION_FREE_RAWMSG) != 0 {
        unsafe {
            rwm_free(ptr::addr_of_mut!((*conn).in_data));
            rwm_free(ptr::addr_of_mut!((*conn).out));
            rwm_free(ptr::addr_of_mut!((*conn).in_u));
            rwm_free(ptr::addr_of_mut!((*conn).out_p));
        }
    }
    if (failure_action & ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE) != 0 {
        unsafe {
            (*conn).basic_type = CT_NONE;
            (*conn).status = CONN_NONE;
        }
    }

    unsafe {
        libc::close(cfd);
        free_mp_queue((*conn).in_queue);
        free_mp_queue((*conn).out_queue);
        mtproxy_ffi_net_connections_job_free(c);
    }
    if (failure_action & ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE) != 0 {
        unsafe { mtproxy_ffi_net_connections_job_thread_dec_jobs_active() };
    }
    ptr::null_mut()
}

pub(super) unsafe fn net_accept_new_connections_impl(lcj: Job) -> c_int {
    let listening = unsafe { listen_conn_info(lcj) };

    loop {
        let fd_u = usize::try_from(unsafe { (*listening).fd }).unwrap_or(MAX_EVENTS);
        assert!(fd_u < MAX_EVENTS);
        if (unsafe { Events[fd_u].state } & EVT_IN_EPOLL) == 0 {
            break;
        }

        let mut peer = SockAddrIn46 {
            a4: unsafe { core::mem::zeroed() },
        };
        let mut peer_addrlen = libc::socklen_t::try_from(size_of::<SockAddrIn46>()).unwrap_or(0);
        let cfd = unsafe {
            libc::accept(
                (*listening).fd,
                ptr::addr_of_mut!(peer).cast::<libc::sockaddr>(),
                ptr::addr_of_mut!(peer_addrlen),
            )
        };
        if cfd < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err != libc::EAGAIN {
                unsafe { mtproxy_ffi_net_connections_stats_add(0, 1, 0, 0) };
            }
            break;
        }

        unsafe { mtproxy_ffi_net_connections_stats_add(0, 0, 1, 0) };

        let max_accept_rate = unsafe { mtproxy_ffi_net_connections_accept_rate_get_max() };
        if max_accept_rate != 0 {
            let mut current_remaining = 0.0;
            let mut current_time = 0.0;
            unsafe {
                mtproxy_ffi_net_connections_accept_rate_get_state(
                    ptr::addr_of_mut!(current_remaining),
                    ptr::addr_of_mut!(current_time),
                );
            }
            let (allow, new_remaining, new_time) =
                mtproxy_core::runtime::net::connections::accept_rate_decide(
                    max_accept_rate,
                    unsafe { mtproxy_ffi_net_connections_precise_now() },
                    current_remaining,
                    current_time,
                );
            unsafe { mtproxy_ffi_net_connections_accept_rate_set_state(new_remaining, new_time) };
            if !allow {
                unsafe {
                    mtproxy_ffi_net_connections_stats_add(0, 0, 0, 1);
                    libc::close(cfd);
                }
                continue;
            }
        }

        if (unsafe { (*listening).flags } & C_IPV6) != 0 {
            assert_eq!(
                usize::try_from(peer_addrlen).unwrap_or(0),
                size_of::<libc::sockaddr_in6>()
            );
            assert_eq!(unsafe { peer.a6.sin6_family as c_int }, libc::AF_INET6);
        } else {
            assert_eq!(
                usize::try_from(peer_addrlen).unwrap_or(0),
                size_of::<libc::sockaddr_in>()
            );
            assert_eq!(unsafe { peer.a4.sin_family as c_int }, libc::AF_INET);
        }

        let family = unsafe { peer.a4.sin_family as c_int };
        let conn = if family == libc::AF_INET {
            let peer_a4 = unsafe { peer.a4 };
            let peer_ip = u32::from_be(peer_a4.sin_addr.s_addr);
            let peer_port = c_int::from(u16::from_be(peer_a4.sin_port));
            unsafe {
                alloc_new_connection_impl(
                    cfd,
                    ptr::null_mut(),
                    lcj,
                    CT_INBOUND,
                    (*listening).type_,
                    (*listening).extra,
                    peer_ip,
                    ptr::null_mut(),
                    peer_port,
                )
            }
        } else {
            let peer_a6 = unsafe { peer.a6 };
            let mut peer_ipv6 = peer_a6.sin6_addr.s6_addr;
            let peer_port = c_int::from(u16::from_be(peer_a6.sin6_port));
            unsafe {
                alloc_new_connection_impl(
                    cfd,
                    ptr::null_mut(),
                    lcj,
                    CT_INBOUND,
                    (*listening).type_,
                    (*listening).extra,
                    0,
                    peer_ipv6.as_mut_ptr(),
                    peer_port,
                )
            }
        };

        if !conn.is_null() {
            let conn_info_ptr = unsafe { conn_info(conn) };
            assert!(!unsafe { (*conn_info_ptr).io_conn }.is_null());
            unsafe {
                unlock_job(1, conn);
            }
        }
    }

    0
}

pub(super) unsafe fn init_listening_connection_ext_impl(
    fd: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
    mode: c_int,
    prio: c_int,
) -> c_int {
    if unsafe { check_conn_functions_impl(type_, 1) } < 0 {
        return -1;
    }

    let max_connection_fd = unsafe { mtproxy_ffi_net_connections_get_max_connection_fd() };
    let fd_action =
        mtproxy_core::runtime::net::connections::listening_init_fd_action(fd, max_connection_fd);
    assert!(fd_action == LISTENING_INIT_FD_OK || fd_action == LISTENING_INIT_FD_REJECT);
    if fd_action == LISTENING_INIT_FD_REJECT {
        unsafe {
            crate::kprintf_fmt!(
                LISTENING_FD_REJECT_MSG.as_ptr().cast(),
                fd,
                max_connection_fd,
            );
        }
        return -1;
    }

    let max_connection = unsafe { mtproxy_ffi_net_connections_get_max_connection() };
    let updated_max = mtproxy_core::runtime::net::connections::listening_init_update_max_connection(
        fd,
        max_connection,
    );
    unsafe { mtproxy_ffi_net_connections_set_max_connection(updated_max) };

    let job_signals =
        jsc_allow(JC_EPOLL, JS_RUN) | jsc_allow(JC_EPOLL, JS_AUX) | jsc_allow(JC_EPOLL, JS_FINISH);
    let lcj = unsafe {
        create_async_job(
            Some(do_listening_connection_job),
            job_signals,
            -2,
            c_int::try_from(size_of::<ListeningConnectionInfo>()).unwrap_or(c_int::MAX),
            JT_HAVE_TIMER,
            1,
            ptr::null_mut(),
        )
    };
    assert!(!lcj.is_null());
    unsafe {
        (*lcj.cast::<AsyncJob>()).j_refcnt = 2;
    }

    let listening = unsafe { listen_conn_info(lcj) };
    unsafe {
        ptr::write_bytes(listening, 0, 1);
        (*listening).fd = fd;
        (*listening).type_ = type_;
        (*listening).extra = extra;
    }

    let fd_u = usize::try_from(fd).unwrap_or(MAX_EVENTS);
    assert!(fd_u < MAX_EVENTS);
    let ev = unsafe { ptr::addr_of_mut!(Events[fd_u]) };
    assert!(unsafe { (*ev).data }.is_null());
    assert_eq!(unsafe { (*ev).refcnt }, 0);
    unsafe {
        (*listening).ev = ev;
        (*listening).generation = new_conn_generation();
    }

    let mode_policy = mtproxy_core::runtime::net::connections::listening_init_mode_policy(
        mode, SM_LOWPRIO, SM_SPECIAL, SM_NOQACK, SM_IPV6, SM_RAWMSG,
    );
    let mode_known = LISTENING_MODE_LOWPRIO
        | LISTENING_MODE_SPECIAL
        | LISTENING_MODE_NOQACK
        | LISTENING_MODE_IPV6
        | LISTENING_MODE_RAWMSG;
    assert_eq!(mode_policy & !mode_known, 0);

    let mut effective_prio = prio;
    if (mode_policy & LISTENING_MODE_LOWPRIO) != 0 {
        effective_prio = 10;
    }

    if (mode_policy & LISTENING_MODE_SPECIAL) != 0 {
        unsafe {
            (*listening).flags |= C_SPECIAL;
            mtproxy_ffi_net_connections_register_special_listen_socket(
                (*listening).fd,
                (*listening).generation,
            );
        }
    }
    if (mode_policy & LISTENING_MODE_NOQACK) != 0 {
        unsafe {
            (*listening).flags |= C_NOQACK;
        }
        let qack_off: c_int = 0;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                ptr::addr_of!(qack_off).cast(),
                libc::socklen_t::try_from(size_of::<c_int>()).unwrap_or(0),
            )
        };
        assert!(rc >= 0);
    }
    if (mode_policy & LISTENING_MODE_IPV6) != 0 {
        unsafe {
            (*listening).flags |= C_IPV6;
        }
    }
    if (mode_policy & LISTENING_MODE_RAWMSG) != 0 {
        unsafe {
            (*listening).flags |= C_RAWMSG;
        }
    }

    unsafe {
        epoll_sethandler(
            fd,
            effective_prio,
            Some(net_server_socket_read_write_gateway),
            lcj.cast(),
        );
        epoll_insert(fd, EVT_RWX);
        mtproxy_ffi_net_connections_stat_inc_listening();
        unlock_job(1, lcj);
    }
    0
}

pub(super) unsafe fn init_listening_connection_impl(
    fd: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
) -> c_int {
    unsafe { init_listening_connection_ext_impl(fd, type_, extra, 0, -10) }
}

pub(super) unsafe fn init_listening_tcpv6_connection_impl(
    fd: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
    mode: c_int,
) -> c_int {
    unsafe { init_listening_connection_ext_impl(fd, type_, extra, mode, -10) }
}

pub(super) unsafe fn do_listening_connection_job_impl(
    job: Job,
    op: c_int,
    _jt: *mut c_void,
) -> c_int {
    let listening = unsafe { listen_conn_info(job) };
    let action = mtproxy_core::runtime::net::connections::listening_job_action(op, JS_RUN, JS_AUX);

    if action == LISTENING_JOB_ACTION_RUN {
        unsafe { net_accept_new_connections_impl(job) };
        return 0;
    }
    if action == LISTENING_JOB_ACTION_AUX {
        unsafe {
            epoll_insert((*listening).fd, EVT_RWX);
        }
        return 0;
    }
    JOB_ERROR
}

#[inline]
unsafe fn conn_job_ready_pending_activate(c: ConnectionJob) {
    let conn = unsafe { conn_info(c) };
    unsafe { atomic_i32(ptr::addr_of_mut!((*conn).flags)) }.fetch_and(!C_READY_PENDING, Ordering::SeqCst);
    unsafe { mtproxy_ffi_net_connections_stats_add_close_basic(0, 0, 1, 0, 1) };
    let target_job = unsafe { (*conn).target };
    if !target_job.is_null() {
        let target = unsafe { conn_target_info(target_job) };
        unsafe { atomic_i32(ptr::addr_of_mut!((*target).active_outbound_connections)) }
            .fetch_add(1, Ordering::SeqCst);
    }
}

pub(super) unsafe fn do_connection_job_impl(job: Job, op: c_int, _jt: *mut c_void) -> c_int {
    let c = job;
    let conn = unsafe { conn_info(c) };
    let action = mtproxy_core::runtime::net::connections::connection_job_action(
        op, JS_RUN, JS_ALARM, JS_ABORT, JS_FINISH,
    );

    if action == CONNECTION_JOB_ACTION_RUN {
        let run_actions =
            mtproxy_core::runtime::net::connections::conn_job_run_actions(unsafe { (*conn).flags });
        if run_actions != 0 {
            if (run_actions & CONN_JOB_RUN_HANDLE_READY_PENDING) != 0 {
                assert!((unsafe { (*conn).flags } & C_CONNECTED) != 0);
                unsafe { conn_job_ready_pending_activate(c) };

                if mtproxy_core::runtime::net::connections::conn_job_ready_pending_should_promote_status(
                    unsafe { (*conn).status },
                ) {
                    let status_atomic = unsafe { atomic_i32(ptr::addr_of_mut!((*conn).status)) };
                    if let Err(actual_status) = status_atomic.compare_exchange(
                        CONN_CONNECTING,
                        CONN_WORKING,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        assert!(
                            mtproxy_core::runtime::net::connections::conn_job_ready_pending_cas_failure_expected(
                                actual_status,
                            )
                        );
                    }
                }

                let type_ = unsafe { (*conn).type_ };
                if !type_.is_null() {
                    if let Some(connected) = unsafe { (*type_).connected } {
                        unsafe { connected(c) };
                    }
                }
            }

            assert!((run_actions & CONN_JOB_RUN_DO_READ_WRITE) != 0);
            let type_ = unsafe { (*conn).type_ };
            if type_.is_null() {
                return 0;
            }
            if let Some(read_write) = unsafe { (*type_).read_write } {
                unsafe { read_write(c) };
            }
        }
        return 0;
    }

    if action == CONNECTION_JOB_ACTION_ALARM {
        let timer_check_ok = unsafe { job_timer_check(job) != 0 };
        if mtproxy_core::runtime::net::connections::conn_job_alarm_should_call(
            timer_check_ok,
            unsafe { (*conn).flags },
        ) {
            let type_ = unsafe { (*conn).type_ };
            if !type_.is_null() {
                if let Some(alarm) = unsafe { (*type_).alarm } {
                    unsafe { alarm(c) };
                }
            }
        }
        return 0;
    }

    if action == CONNECTION_JOB_ACTION_ABORT {
        assert!(
            mtproxy_core::runtime::net::connections::conn_job_abort_has_error(unsafe {
                (*conn).flags
            },)
        );
        let old_flags = unsafe { atomic_i32(ptr::addr_of_mut!((*conn).flags)) }
            .fetch_or(C_FAILED, Ordering::SeqCst);
        if mtproxy_core::runtime::net::connections::conn_job_abort_should_close(old_flags) {
            let type_ = unsafe { (*conn).type_ };
            if !type_.is_null() {
                if let Some(close) = unsafe { (*type_).close } {
                    unsafe { close(c, 0) };
                }
            }
        }
        return JOB_COMPLETED;
    }

    if action == CONNECTION_JOB_ACTION_FINISH {
        assert_eq!(unsafe { (*c.cast::<AsyncJob>()).j_refcnt }, 1);
        let type_ = unsafe { (*conn).type_ };
        if !type_.is_null() {
            if let Some(free_cb) = unsafe { (*type_).free } {
                unsafe { free_cb(c) };
            }
        }
        return unsafe { mtproxy_ffi_net_connections_job_free(c) };
    }

    assert_eq!(action, CONNECTION_JOB_ACTION_ERROR);
    JOB_ERROR
}

pub(super) unsafe fn net_server_socket_read_write_impl(c: SocketConnectionJob) -> c_int {
    let socket = unsafe { socket_conn_info(c) };

    let connect_action =
        mtproxy_core::runtime::net::connections::socket_read_write_connect_action(unsafe {
            (*socket).flags
        });
    if connect_action == SOCKET_READ_WRITE_CONNECT_RETURN_ZERO {
        return 0;
    }
    if connect_action == SOCKET_READ_WRITE_CONNECT_RETURN_COMPUTE_EVENTS {
        return mtproxy_core::runtime::net::connections::compute_conn_events(
            unsafe { (*socket).flags },
            true,
        );
    }
    if connect_action == SOCKET_READ_WRITE_CONNECT_MARK_CONNECTED {
        unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
            .fetch_and(C_PERMANENT, Ordering::SeqCst);
        unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
            .fetch_or(C_WANTRD | C_CONNECTED, Ordering::SeqCst);
        let conn = unsafe { conn_info((*socket).conn) };
        unsafe { atomic_i32(ptr::addr_of_mut!((*conn).flags)) }
            .fetch_or(C_READY_PENDING | C_CONNECTED, Ordering::SeqCst);

        let type_ = unsafe { (*socket).type_ };
        assert!(!type_.is_null());
        if let Some(socket_connected) = unsafe { (*type_).socket_connected } {
            unsafe { socket_connected(c) };
        }
        unsafe { job_signal_create_pass((*socket).conn, JS_RUN) };
    }
    assert!(
        connect_action == SOCKET_READ_WRITE_CONNECT_MARK_CONNECTED
            || connect_action == SOCKET_READ_WRITE_CONNECT_CONTINUE_IO
    );

    while mtproxy_core::runtime::net::connections::socket_reader_should_run(unsafe {
        (*socket).flags
    }) {
        let type_ = unsafe { (*socket).type_ };
        assert!(!type_.is_null());
        let socket_reader = unsafe { (*type_).socket_reader };
        assert!(socket_reader.is_some());
        unsafe { socket_reader.unwrap()(c) };
    }

    loop {
        let raw = unsafe { mtproxy_ffi_net_connections_mpq_pop_nw((*socket).out_packet_queue, 4) }
            .cast::<RawMessage>();
        if raw.is_null() {
            break;
        }
        unsafe {
            mtproxy_ffi_net_connections_rwm_union(ptr::addr_of_mut!((*socket).out), raw);
            libc::free(raw.cast());
        }
    }

    if unsafe { (*socket).out.total_bytes } != 0 {
        unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
            .fetch_or(C_WANTWR, Ordering::SeqCst);
    }

    while mtproxy_core::runtime::net::connections::socket_writer_should_run(unsafe {
        (*socket).flags
    }) {
        let type_ = unsafe { (*socket).type_ };
        assert!(!type_.is_null());
        let socket_writer = unsafe { (*type_).socket_writer };
        assert!(socket_writer.is_some());
        unsafe { socket_writer.unwrap()(c) };
    }

    mtproxy_core::runtime::net::connections::compute_conn_events(unsafe { (*socket).flags }, true)
}

pub(super) unsafe fn net_server_socket_read_write_gateway_impl(
    _fd: c_int,
    data: *mut c_void,
    ev: *mut c_void,
) -> c_int {
    if data.is_null() {
        return EVA_REMOVE;
    }

    let c = data;
    let socket = unsafe { socket_conn_info(c) };
    let event = ev.cast::<EventDescr>();
    assert!(!event.is_null());
    assert!(!unsafe { (*socket).type_ }.is_null());

    if (unsafe { (*event).ready } & EVT_FROM_EPOLL) != 0 {
        unsafe {
            (*event).ready &= !EVT_FROM_EPOLL;
        }

        let clear_flags = mtproxy_core::runtime::net::connections::socket_gateway_clear_flags(
            unsafe { (*event).state },
            unsafe { (*event).ready },
        );
        assert!((clear_flags & !(C_NORD | C_NOWR)) == 0);
        unsafe { atomic_i32(ptr::addr_of_mut!((*socket).flags)) }
            .fetch_and(!clear_flags, Ordering::SeqCst);

        let abort_action = mtproxy_core::runtime::net::connections::socket_gateway_abort_action(
            (unsafe { (*event).epoll_ready } & libc::EPOLLERR as c_int) != 0,
            (unsafe { (*event).epoll_ready }
                & (libc::EPOLLHUP as c_int
                    | libc::EPOLLERR as c_int
                    | libc::EPOLLRDHUP as c_int
                    | libc::EPOLLPRI as c_int))
                != 0,
        );
        if abort_action != SOCKET_GATEWAY_ABORT_NONE {
            unsafe { job_signal_create_pass(c, JS_ABORT) };
            return EVA_REMOVE;
        }
    }

    unsafe { job_signal_create_pass(c, JS_RUN) };
    EVA_CONTINUE
}

pub(super) unsafe fn set_connection_timeout_impl(c: ConnectionJob, timeout: c_double) -> c_int {
    let conn = unsafe { conn_info(c) };
    let timeout_action = mtproxy_core::runtime::net::connections::connection_timeout_action(
        unsafe { (*conn).flags },
        timeout,
    );
    if timeout_action == 0 {
        return 0;
    }

    unsafe { atomic_i32(ptr::addr_of_mut!((*conn).flags)) }.fetch_and(!C_ALARM, Ordering::SeqCst);
    if timeout_action == 1 {
        unsafe { job_timer_insert(c, mtproxy_ffi_net_connections_precise_now() + timeout) };
    } else {
        unsafe { job_timer_remove(c) };
    }
    0
}

pub(super) unsafe fn clear_connection_timeout_impl(c: ConnectionJob) -> c_int {
    unsafe { set_connection_timeout_impl(c, 0.0) }
}

pub(super) unsafe fn fail_connection_impl(c: ConnectionJob, err: c_int) {
    let conn = unsafe { conn_info(c) };
    let previous_flags =
        unsafe { atomic_i32(ptr::addr_of_mut!((*conn).flags)) }.fetch_or(C_ERROR, Ordering::SeqCst);
    let action =
        mtproxy_core::runtime::net::connections::fail_connection_action(previous_flags, unsafe {
            (*conn).error
        });

    if (action & FAIL_CONNECTION_ACTION_SET_STATUS_ERROR) != 0 {
        unsafe {
            (*conn).status = CONN_ERROR;
        }
    }
    if (action & FAIL_CONNECTION_ACTION_SET_ERROR_CODE) != 0 {
        unsafe {
            (*conn).error = err;
        }
    }
    if (action & FAIL_CONNECTION_ACTION_SIGNAL_ABORT) != 0 {
        unsafe { job_signal_create_pass(c, JS_ABORT) };
    }
}

pub(super) unsafe fn cpu_server_free_connection_impl(c: ConnectionJob) -> c_int {
    assert_eq!(unsafe { (*c.cast::<AsyncJob>()).j_refcnt }, 1);
    let conn = unsafe { conn_info(c) };

    assert!((unsafe { (*conn).flags } & C_ERROR) != 0);
    assert!((unsafe { (*conn).flags } & C_FAILED) != 0);
    assert!(unsafe { (*conn).target.is_null() });
    assert!(unsafe { (*conn).io_conn.is_null() });

    loop {
        let raw = unsafe { mtproxy_ffi_net_connections_mpq_pop_nw((*conn).out_queue, 4) }
            .cast::<RawMessage>();
        if raw.is_null() {
            break;
        }
        unsafe {
            rwm_free(raw);
            libc::free(raw.cast());
        }
    }
    unsafe {
        free_mp_queue((*conn).out_queue);
        (*conn).out_queue = ptr::null_mut();
    }

    loop {
        let raw = unsafe { mtproxy_ffi_net_connections_mpq_pop_nw((*conn).in_queue, 4) }
            .cast::<RawMessage>();
        if raw.is_null() {
            break;
        }
        unsafe {
            rwm_free(raw);
            libc::free(raw.cast());
        }
    }
    unsafe {
        free_mp_queue((*conn).in_queue);
        (*conn).in_queue = ptr::null_mut();
    }

    let type_ = unsafe { (*conn).type_ };
    assert!(!type_.is_null());
    if let Some(crypto_free) = unsafe { (*type_).crypto_free } {
        unsafe { crypto_free(c) };
    }

    unsafe {
        libc::close((*conn).fd);
        (*conn).fd = -1;
    }

    let (allocated_outbound_delta, allocated_inbound_delta) =
        mtproxy_core::runtime::net::connections::free_connection_allocated_deltas(unsafe {
            (*conn).basic_type
        });
    unsafe {
        mtproxy_ffi_net_connections_stats_add_free_connection_counts(
            allocated_outbound_delta,
            allocated_inbound_delta,
        );
    }

    let free_buffers = unsafe { (*type_).free_buffers };
    assert!(free_buffers.is_some());
    unsafe { free_buffers.unwrap()(c) }
}

pub(super) unsafe fn cpu_server_close_connection_impl(c: ConnectionJob, _who: c_int) -> c_int {
    let conn = unsafe { conn_info(c) };

    assert!((unsafe { (*conn).flags } & C_ERROR) != 0);
    assert_eq!(unsafe { (*conn).status }, CONN_ERROR);
    assert!((unsafe { (*conn).flags } & C_FAILED) != 0);

    let (total_failed_delta, total_connect_failures_delta, unused_closed_delta) =
        mtproxy_core::runtime::net::connections::close_connection_failure_deltas(
            unsafe { (*conn).error },
            unsafe { (*conn).flags },
        );
    unsafe {
        mtproxy_ffi_net_connections_stats_add_close_failure(
            total_failed_delta,
            total_connect_failures_delta,
            unused_closed_delta,
        );
    }

    if mtproxy_core::runtime::net::connections::close_connection_has_isdh(unsafe { (*conn).flags })
    {
        unsafe {
            mtproxy_ffi_net_connections_stat_dec_active_dh();
            atomic_i32(ptr::addr_of_mut!((*conn).flags)).fetch_and(!C_ISDH, Ordering::SeqCst);
        }
    }

    let io_conn = unsafe { (*conn).io_conn };
    assert!(!io_conn.is_null());
    unsafe {
        (*conn).io_conn = ptr::null_mut();
        job_signal(1, io_conn, JS_ABORT);
    }

    let (
        outbound_delta,
        inbound_delta,
        active_outbound_delta,
        active_inbound_delta,
        active_connections_delta,
        signal_target,
    ) = mtproxy_core::runtime::net::connections::close_connection_basic_deltas(
        unsafe { (*conn).basic_type },
        unsafe { (*conn).flags },
        unsafe { !(*conn).target.is_null() },
    );
    unsafe {
        mtproxy_ffi_net_connections_stats_add_close_basic(
            outbound_delta,
            inbound_delta,
            active_outbound_delta,
            active_inbound_delta,
            active_connections_delta,
        );
    }

    if signal_target {
        let target = unsafe { (*conn).target };
        assert!(!target.is_null());
        unsafe {
            (*conn).target = ptr::null_mut();
            job_signal(1, target, JS_RUN);
        }
    }

    if mtproxy_core::runtime::net::connections::close_connection_has_special(unsafe {
        (*conn).flags
    }) {
        unsafe {
            (*conn).flags &= !C_SPECIAL;
        }
        let orig_special_connections =
            unsafe { atomic_i32(ptr::addr_of_mut!(active_special_connections)) }
                .fetch_sub(1, Ordering::SeqCst);
        if mtproxy_core::runtime::net::connections::close_connection_should_signal_special_aux(
            orig_special_connections,
            unsafe { max_special_connections },
        ) {
            unsafe {
                mtproxy_ffi_net_connections_close_connection_signal_special_aux();
            }
        }
    }

    unsafe { job_timer_remove(c) };
    0
}

pub(super) unsafe fn cpu_server_read_write_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let type_ = unsafe { (*conn).type_ };
    assert!(!type_.is_null());
    let reader = unsafe { (*type_).reader };
    let writer = unsafe { (*type_).writer };
    assert!(reader.is_some());
    assert!(writer.is_some());
    unsafe { reader.unwrap()(c) };
    unsafe { writer.unwrap()(c) };
    0
}

pub(super) unsafe fn connection_event_incref_impl(fd: c_int, val: c_longlong) {
    let fd_u = usize::try_from(fd).unwrap_or(MAX_EVENTS);
    assert!(fd_u < MAX_EVENTS);
    let ev = unsafe { ptr::addr_of_mut!(Events[fd_u]) };

    let new_refcnt = unsafe { atomic_i64(ptr::addr_of_mut!((*ev).refcnt)) }
        .fetch_add(val, Ordering::SeqCst)
        + val;

    if mtproxy_core::runtime::net::connections::connection_event_should_release(
        new_refcnt,
        unsafe { !(*ev).data.is_null() },
    ) {
        let socket_job = unsafe { (*ev).data };
        unsafe {
            (*ev).data = ptr::null_mut();
            job_decref_pass(socket_job);
        }
    }
}

#[allow(unpredictable_function_pointer_comparisons)]
pub(super) unsafe fn connection_get_by_fd_impl(fd: c_int) -> ConnectionJob {
    const CLAIM_DELTA: i64 = 1_i64 << 32;

    let fd_u = usize::try_from(fd).unwrap_or(MAX_EVENTS);
    if fd_u >= MAX_EVENTS {
        return ptr::null_mut();
    }
    let ev = unsafe { ptr::addr_of_mut!(Events[fd_u]) };
    if (unsafe { (*ev).refcnt as c_int }) == 0 || unsafe { (*ev).data.is_null() } {
        return ptr::null_mut();
    }

    let refcnt = unsafe { atomic_i64(ptr::addr_of_mut!((*ev).refcnt)) };
    loop {
        let v = refcnt.fetch_add(CLAIM_DELTA, Ordering::SeqCst);
        if (v as c_int) != 0 {
            break;
        }
        let v2 = refcnt.fetch_add(-CLAIM_DELTA, Ordering::SeqCst);
        if (v2 as c_int) != 0 {
            continue;
        }
        return ptr::null_mut();
    }
    refcnt.fetch_add(1 - CLAIM_DELTA, Ordering::SeqCst);

    let socket_job = unsafe { job_incref((*ev).data) };
    let socket_job_struct = socket_job.cast::<AsyncJob>();
    unsafe { connection_event_incref_impl(fd, -1) };

    let is_listening_job =
        unsafe { (*socket_job_struct).j_execute == Some(do_listening_connection_job) };
    let is_socket_job = unsafe { (*socket_job_struct).j_execute == Some(do_socket_connection_job) };
    let socket_flags = if is_socket_job {
        unsafe { (*socket_conn_info(socket_job)).flags }
    } else {
        0
    };

    let action = mtproxy_core::runtime::net::connections::connection_get_by_fd_action(
        is_listening_job,
        is_socket_job,
        socket_flags,
    );
    if action == CONN_GET_BY_FD_ACTION_RETURN_SELF {
        return socket_job;
    }

    assert!(is_socket_job);
    let socket = unsafe { socket_conn_info(socket_job) };
    if action == CONN_GET_BY_FD_ACTION_RETURN_NULL {
        unsafe { job_decref_pass(socket_job) };
        return ptr::null_mut();
    }

    assert_eq!(action, CONN_GET_BY_FD_ACTION_RETURN_CONN);
    let conn = unsafe { (*socket).conn };
    assert!(!conn.is_null());
    let out = unsafe { job_incref(conn) };
    unsafe { job_decref_pass(socket_job) };
    out
}

pub(super) unsafe fn connection_get_by_fd_generation_impl(
    fd: c_int,
    generation: c_int,
) -> ConnectionJob {
    let conn = unsafe { connection_get_by_fd_impl(fd) };
    if conn.is_null() {
        return conn;
    }

    let c = unsafe { conn_info(conn) };
    let ok = mtproxy_core::runtime::net::connections::connection_generation_matches(
        unsafe { (*c).generation },
        generation,
    );
    if !ok {
        unsafe { job_decref_pass(conn) };
        return ptr::null_mut();
    }
    conn
}

pub(super) unsafe fn server_check_ready_conn_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let ready = mtproxy_core::runtime::net::connections::server_check_ready(
        unsafe { (*conn).status },
        unsafe { (*conn).ready },
    );
    assert!((CR_NOTYET..=CR_FAILED).contains(&ready));
    unsafe {
        (*conn).ready = ready;
    }
    ready
}

pub(super) unsafe fn server_noop_impl(_c: ConnectionJob) -> c_int {
    0
}

pub(super) unsafe fn server_failed_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    unsafe {
        crate::kprintf_fmt!(SERVER_FAILED_MSG.as_ptr().cast(), (*conn).fd);
    }
    assert!(false);
    -1
}

pub(super) unsafe fn server_flush_impl(_c: ConnectionJob) -> c_int {
    0
}

pub(super) unsafe fn check_conn_functions_impl(type_: *mut ConnType, listening: c_int) -> c_int {
    if type_.is_null() || unsafe { (*type_).magic != CONN_FUNC_MAGIC } {
        return -1;
    }

    let default_mask = mtproxy_core::runtime::net::connections::check_conn_functions_default_mask(
        unsafe { !(*type_).title.is_null() },
        unsafe { (*type_).socket_read_write.is_some() },
        unsafe { (*type_).socket_reader.is_some() },
        unsafe { (*type_).socket_writer.is_some() },
        unsafe { (*type_).socket_close.is_some() },
        unsafe { (*type_).close.is_some() },
        unsafe { (*type_).init_outbound.is_some() },
        unsafe { (*type_).wakeup.is_some() },
        unsafe { (*type_).alarm.is_some() },
        unsafe { (*type_).connected.is_some() },
        unsafe { (*type_).flush.is_some() },
        unsafe { (*type_).check_ready.is_some() },
        unsafe { (*type_).read_write.is_some() },
        unsafe { (*type_).free.is_some() },
        unsafe { (*type_).socket_connected.is_some() },
        unsafe { (*type_).socket_free.is_some() },
    );

    if (default_mask & CHECK_CONN_DEFAULT_SET_TITLE) != 0 {
        unsafe {
            (*type_).title = UNKNOWN_TITLE.as_ptr().cast::<c_char>().cast_mut();
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_READ_WRITE) != 0 {
        unsafe {
            (*type_).socket_read_write = Some(net_server_socket_read_write);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_READER) != 0 {
        unsafe {
            (*type_).socket_reader = Some(net_server_socket_reader);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_WRITER) != 0 {
        unsafe {
            (*type_).socket_writer = Some(net_server_socket_writer);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_CLOSE) != 0 {
        unsafe {
            (*type_).socket_close = Some(server_noop);
        }
    }

    let accept_mask = mtproxy_core::runtime::net::connections::check_conn_functions_accept_mask(
        listening != 0,
        unsafe { (*type_).accept.is_some() },
        unsafe { (*type_).init_accepted.is_some() },
    );

    if (accept_mask & CHECK_CONN_ACCEPT_SET_ACCEPT_LISTEN) != 0 {
        unsafe {
            (*type_).accept = Some(net_accept_new_connections);
        }
    }
    if (accept_mask & CHECK_CONN_ACCEPT_SET_ACCEPT_FAILED) != 0 {
        unsafe {
            (*type_).accept = Some(server_failed);
        }
    }
    if (accept_mask & CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_NOOP) != 0 {
        unsafe {
            (*type_).init_accepted = Some(server_noop);
        }
    }
    if (accept_mask & CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_FAILED) != 0 {
        unsafe {
            (*type_).init_accepted = Some(server_failed);
        }
    }

    if (default_mask & CHECK_CONN_DEFAULT_SET_CLOSE) != 0 {
        unsafe {
            (*type_).close = Some(cpu_server_close_connection);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_INIT_OUTBOUND) != 0 {
        unsafe {
            (*type_).init_outbound = Some(server_noop);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_WAKEUP) != 0 {
        unsafe {
            (*type_).wakeup = Some(server_noop);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_ALARM) != 0 {
        unsafe {
            (*type_).alarm = Some(server_noop);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_CONNECTED) != 0 {
        unsafe {
            (*type_).connected = Some(server_noop);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_FLUSH) != 0 {
        unsafe {
            (*type_).flush = Some(server_flush);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_CHECK_READY) != 0 {
        unsafe {
            (*type_).check_ready = Some(server_check_ready);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_READ_WRITE) != 0 {
        unsafe {
            (*type_).read_write = Some(cpu_server_read_write);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_FREE) != 0 {
        unsafe {
            (*type_).free = Some(cpu_server_free_connection);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_CONNECTED) != 0 {
        unsafe {
            (*type_).socket_connected = Some(server_noop);
        }
    }
    if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_FREE) != 0 {
        unsafe {
            (*type_).socket_free = Some(net_server_socket_free);
        }
    }

    let (raw_rc, raw_assign_mask, nonraw_assert_mask) =
        mtproxy_core::runtime::net::connections::check_conn_functions_raw_policy(
            (unsafe { (*type_).flags } & C_RAWMSG) != 0,
            unsafe { (*type_).free_buffers.is_some() },
            unsafe { (*type_).reader.is_some() },
            unsafe { (*type_).writer.is_some() },
            unsafe { (*type_).parse_execute.is_some() },
        );

    if (unsafe { (*type_).flags } & C_RAWMSG) != 0 {
        if (raw_assign_mask & CHECK_CONN_RAW_SET_FREE_BUFFERS) != 0 {
            unsafe {
                (*type_).free_buffers = Some(cpu_tcp_free_connection_buffers);
            }
        }
        if (raw_assign_mask & CHECK_CONN_RAW_SET_READER) != 0 {
            unsafe {
                (*type_).reader = Some(cpu_tcp_server_reader);
            }
        }
        if raw_rc < 0 {
            return -1;
        }
        if (raw_assign_mask & CHECK_CONN_RAW_SET_WRITER) != 0 {
            unsafe {
                (*type_).writer = Some(cpu_tcp_server_writer);
            }
        }
    } else {
        if (nonraw_assert_mask & CHECK_CONN_NONRAW_ASSERT_FREE_BUFFERS) != 0 {
            assert!(false);
        }
        if (nonraw_assert_mask & CHECK_CONN_NONRAW_ASSERT_READER) != 0 {
            assert!(false);
        }
        if (nonraw_assert_mask & CHECK_CONN_NONRAW_ASSERT_WRITER) != 0 {
            assert!(false);
        }
    }

    0
}

pub(super) unsafe fn compute_next_reconnect_target_impl(ct: ConnTargetJob) {
    let target = unsafe { conn_target_info(ct) };
    let (next_reconnect, timeout) = mtproxy_core::runtime::net::connections::compute_next_reconnect(
        unsafe { (*target).reconnect_timeout },
        unsafe { (*target).next_reconnect_timeout },
        unsafe { (*target).active_outbound_connections },
        unsafe { mtproxy_ffi_net_connections_precise_now() },
        unsafe { drand48_j() },
    );
    unsafe {
        (*target).next_reconnect = next_reconnect;
        (*target).next_reconnect_timeout = timeout;
    }
}

unsafe extern "C" fn target_pick_policy_callback(c: ConnectionJob, x: *mut c_void) {
    let ctx = x.cast::<ConnTargetPickCtx>();
    let selected_slot = unsafe { (*ctx).selected };
    let allow_stopped = unsafe { (*ctx).allow_stopped != 0 };
    let has_selected = unsafe { !(*selected_slot).is_null() };
    let selected = if has_selected {
        unsafe { conn_info(*selected_slot) }
    } else {
        ptr::null_mut()
    };
    let selected_ready = if has_selected {
        unsafe { (*selected).ready }
    } else {
        0
    };

    let candidate = unsafe { conn_info(c) };
    let type_ = unsafe { (*candidate).type_ };
    assert!(!type_.is_null());
    let check_ready = unsafe { (*type_).check_ready };
    assert!(check_ready.is_some());
    let candidate_ready = unsafe { check_ready.unwrap()(c) };

    let selected_unreliability = if has_selected {
        unsafe { (*selected).unreliability }
    } else {
        0
    };
    let decision = mtproxy_core::runtime::net::connections::target_pick_decision(
        allow_stopped,
        has_selected,
        selected_ready,
        candidate_ready,
        selected_unreliability,
        unsafe { (*candidate).unreliability },
    );
    if decision == mtproxy_core::runtime::net::connections::TargetPickDecision::SkipCandidate
        || decision == mtproxy_core::runtime::net::connections::TargetPickDecision::KeepSelected
    {
        return;
    }
    assert_eq!(
        decision,
        mtproxy_core::runtime::net::connections::TargetPickDecision::SelectCandidate
    );
    {
        unsafe {
            *selected_slot = c;
        }
    }
}

unsafe extern "C" fn target_count_connection_num_callback(
    c: ConnectionJob,
    good_c: *mut c_void,
    stopped_c: *mut c_void,
    bad_c: *mut c_void,
) {
    let conn = unsafe { conn_info(c) };
    let type_ = unsafe { (*conn).type_ };
    assert!(!type_.is_null());
    let check_ready = unsafe { (*type_).check_ready };
    assert!(check_ready.is_some());
    let cr = unsafe { check_ready.unwrap()(c) };
    let deltas = mtproxy_core::runtime::net::connections::target_ready_bucket_deltas(cr);
    assert!(deltas.is_some());
    let (good_delta, stopped_delta, bad_delta) = deltas.unwrap_or((0, 0, 0));
    unsafe {
        *good_c.cast::<c_int>() += good_delta;
        *stopped_c.cast::<c_int>() += stopped_delta;
        *bad_c.cast::<c_int>() += bad_delta;
    }
}

unsafe extern "C" fn target_find_bad_connection_callback(c: ConnectionJob, x: *mut c_void) {
    let selected = x.cast::<ConnectionJob>();
    let conn = unsafe { conn_info(c) };
    let should_select = mtproxy_core::runtime::net::connections::target_find_bad_should_select(
        unsafe { !(*selected).is_null() },
        unsafe { (*conn).flags },
    );
    if should_select {
        unsafe {
            *selected = c;
        }
    }
}

unsafe fn target_lookup_ipv4_impl(
    ad_s_addr: u32,
    port: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
    mode: c_int,
    new_target: ConnTargetJob,
) -> ConnTargetJob {
    assert!(ad_s_addr != 0);
    let bucket_i32 = mtproxy_core::runtime::net::connections::target_bucket_ipv4(
        type_ as usize,
        ad_s_addr,
        port,
        PRIME_TARGETS as u32,
    );
    assert!(
        bucket_i32 >= 0 && usize::try_from(bucket_i32).unwrap_or(PRIME_TARGETS) < PRIME_TARGETS
    );
    let bucket = usize::try_from(bucket_i32).unwrap_or(0);

    let mut prev: *mut ConnTargetJob = unsafe { ptr::addr_of_mut!(HTarget[bucket]) };
    loop {
        let cur = unsafe { *prev };
        if cur.is_null() {
            break;
        }
        let s = unsafe { conn_target_info(cur) };
        if unsafe {
            (*s).target.s_addr == ad_s_addr
                && (*s).port == port
                && (*s).type_ == type_
                && (*s).extra == extra
        } {
            let decision =
                mtproxy_core::runtime::net::connections::target_lookup_decision(mode, true);
            if decision
                == mtproxy_core::runtime::net::connections::TargetLookupDecision::RemoveAndReturn
            {
                unsafe {
                    *prev = (*s).hnext;
                    (*s).hnext = ptr::null_mut();
                }
                return cur;
            }
            if decision
                == mtproxy_core::runtime::net::connections::TargetLookupDecision::ReturnFound
            {
                return cur;
            }
            assert_eq!(
                decision,
                mtproxy_core::runtime::net::connections::TargetLookupDecision::AssertInvalid
            );
            assert!(
                mtproxy_core::runtime::net::connections::target_lookup_assert_mode_ok(mode, true)
            );
            return ptr::null_mut();
        }
        prev = unsafe { ptr::addr_of_mut!((*s).hnext) };
    }

    let decision = mtproxy_core::runtime::net::connections::target_lookup_decision(mode, false);
    if decision == mtproxy_core::runtime::net::connections::TargetLookupDecision::InsertNew {
        let new_target_info = unsafe { conn_target_info(new_target) };
        unsafe {
            (*new_target_info).hnext = HTarget[bucket];
            HTarget[bucket] = new_target;
        }
        return new_target;
    }
    if decision == mtproxy_core::runtime::net::connections::TargetLookupDecision::ReturnNull {
        return ptr::null_mut();
    }
    assert_eq!(
        decision,
        mtproxy_core::runtime::net::connections::TargetLookupDecision::AssertInvalid
    );
    assert!(mtproxy_core::runtime::net::connections::target_lookup_assert_mode_ok(mode, false));
    ptr::null_mut()
}

unsafe fn target_lookup_ipv6_impl(
    ad_ipv6: &[u8; 16],
    port: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
    mode: c_int,
    new_target: ConnTargetJob,
) -> ConnTargetJob {
    assert!(ad_ipv6.iter().any(|&b| b != 0));
    let bucket_i32 = mtproxy_core::runtime::net::connections::target_bucket_ipv6(
        type_ as usize,
        ad_ipv6,
        port,
        PRIME_TARGETS as u32,
    );
    assert!(
        bucket_i32 >= 0 && usize::try_from(bucket_i32).unwrap_or(PRIME_TARGETS) < PRIME_TARGETS
    );
    let bucket = usize::try_from(bucket_i32).unwrap_or(0);

    let mut prev: *mut ConnTargetJob = unsafe { ptr::addr_of_mut!(HTarget[bucket]) };
    loop {
        let cur = unsafe { *prev };
        if cur.is_null() {
            break;
        }
        let s = unsafe { conn_target_info(cur) };
        if unsafe {
            (*s).target_ipv6 == *ad_ipv6
                && (*s).port == port
                && (*s).type_ == type_
                && (*s).target.s_addr == 0
                && (*s).extra == extra
        } {
            let decision =
                mtproxy_core::runtime::net::connections::target_lookup_decision(mode, true);
            if decision
                == mtproxy_core::runtime::net::connections::TargetLookupDecision::RemoveAndReturn
            {
                unsafe {
                    *prev = (*s).hnext;
                    (*s).hnext = ptr::null_mut();
                }
                return cur;
            }
            if decision
                == mtproxy_core::runtime::net::connections::TargetLookupDecision::ReturnFound
            {
                return cur;
            }
            assert_eq!(
                decision,
                mtproxy_core::runtime::net::connections::TargetLookupDecision::AssertInvalid
            );
            assert!(
                mtproxy_core::runtime::net::connections::target_lookup_assert_mode_ok(mode, true)
            );
            return ptr::null_mut();
        }
        prev = unsafe { ptr::addr_of_mut!((*s).hnext) };
    }

    let decision = mtproxy_core::runtime::net::connections::target_lookup_decision(mode, false);
    if decision == mtproxy_core::runtime::net::connections::TargetLookupDecision::InsertNew {
        let new_target_info = unsafe { conn_target_info(new_target) };
        unsafe {
            (*new_target_info).hnext = HTarget[bucket];
            HTarget[bucket] = new_target;
        }
        return new_target;
    }
    if decision == mtproxy_core::runtime::net::connections::TargetLookupDecision::ReturnNull {
        return ptr::null_mut();
    }
    assert_eq!(
        decision,
        mtproxy_core::runtime::net::connections::TargetLookupDecision::AssertInvalid
    );
    assert!(mtproxy_core::runtime::net::connections::target_lookup_assert_mode_ok(mode, false));
    ptr::null_mut()
}

unsafe extern "C" fn target_fail_connection_callback(c: ConnectionJob) {
    unsafe { fail_connection_impl(c, -17) };
}

pub(super) unsafe fn destroy_dead_target_connections_impl(ctj: ConnTargetJob) {
    let target = unsafe { conn_target_info(ctj) };
    let mut tree = unsafe { get_tree_ptr_connection(ptr::addr_of_mut!((*target).conn_tree)) };

    loop {
        let mut bad_conn: ConnectionJob = ptr::null_mut();
        unsafe {
            tree_act_ex_connection(
                tree,
                Some(target_find_bad_connection_callback),
                ptr::addr_of_mut!(bad_conn).cast(),
            );
        }
        if bad_conn.is_null() {
            break;
        }

        let conn = unsafe { conn_info(bad_conn) };
        let (active_outbound_delta, outbound_delta) =
            mtproxy_core::runtime::net::connections::target_remove_dead_connection_deltas(unsafe {
                (*conn).flags
            });
        unsafe {
            atomic_i32(ptr::addr_of_mut!((*target).active_outbound_connections))
                .fetch_add(active_outbound_delta, Ordering::SeqCst);
            atomic_i32(ptr::addr_of_mut!((*target).outbound_connections))
                .fetch_add(outbound_delta, Ordering::SeqCst);
            tree = tree_delete_connection(tree, bad_conn);
        }
    }

    let mut good_c: c_int = 0;
    let mut stopped_c: c_int = 0;
    let mut bad_c: c_int = 0;
    unsafe {
        tree_act_ex3_connection(
            tree,
            Some(target_count_connection_num_callback),
            ptr::addr_of_mut!(good_c).cast(),
            ptr::addr_of_mut!(stopped_c).cast(),
            ptr::addr_of_mut!(bad_c).cast(),
        );
    }
    let _ = bad_c;

    let was_ready = unsafe { (*target).ready_outbound_connections };
    unsafe {
        (*target).ready_outbound_connections = good_c;
    }
    let (ready_outbound_delta, ready_targets_delta) =
        mtproxy_core::runtime::net::connections::target_ready_transition(was_ready, unsafe {
            (*target).ready_outbound_connections
        });
    unsafe {
        mtproxy_ffi_net_connections_stats_add_ready(ready_outbound_delta, ready_targets_delta);
    }

    let tree_update_decision = mtproxy_core::runtime::net::connections::target_tree_update_decision(
        tree != unsafe { (*target).conn_tree },
    );
    if tree_update_decision
        == mtproxy_core::runtime::net::connections::TargetTreeUpdateDecision::FreeSnapshotOnly
    {
        unsafe { tree_free_connection(tree) };
    } else {
        assert_eq!(
            tree_update_decision,
            mtproxy_core::runtime::net::connections::TargetTreeUpdateDecision::ReplaceAndFreeOld
        );
        let old = unsafe { (*target).conn_tree };
        unsafe {
            (*target).conn_tree = tree;
            core::sync::atomic::fence(Ordering::SeqCst);
            free_tree_ptr_connection(old);
        }
    }
}

pub(super) unsafe fn clean_unused_target_impl(ctj: ConnTargetJob) -> c_int {
    assert!(!ctj.is_null());
    let target = unsafe { conn_target_info(ctj) };
    assert!(!unsafe { (*target).type_ }.is_null());
    let decision = mtproxy_core::runtime::net::connections::target_clean_unused_decision(
        unsafe { (*target).global_refcnt },
        unsafe { !(*target).conn_tree.is_null() },
    );
    if decision == mtproxy_core::runtime::net::connections::TargetCleanUnusedDecision::Keep {
        return 0;
    }
    if decision
        == mtproxy_core::runtime::net::connections::TargetCleanUnusedDecision::FailConnections
    {
        unsafe { tree_act_connection((*target).conn_tree, Some(target_fail_connection_callback)) };
        return 0;
    }
    assert_eq!(
        decision,
        mtproxy_core::runtime::net::connections::TargetCleanUnusedDecision::RemoveTimer
    );
    unsafe { job_timer_remove(ctj) };
    0
}

pub(super) unsafe fn create_new_connections_impl(ctj: ConnTargetJob) -> c_int {
    unsafe { destroy_dead_target_connections_impl(ctj) };
    let target = unsafe { conn_target_info(ctj) };

    let mut count: c_int = 0;
    let mut good_c: c_int = 0;
    let mut bad_c: c_int = 0;
    let mut stopped_c: c_int = 0;
    unsafe {
        tree_act_ex3_connection(
            (*target).conn_tree,
            Some(target_count_connection_num_callback),
            ptr::addr_of_mut!(good_c).cast(),
            ptr::addr_of_mut!(stopped_c).cast(),
            ptr::addr_of_mut!(bad_c).cast(),
        );
    }

    let was_ready = unsafe { (*target).ready_outbound_connections };
    unsafe {
        (*target).ready_outbound_connections = good_c;
    }
    let (ready_outbound_delta, ready_targets_delta) =
        mtproxy_core::runtime::net::connections::target_ready_transition(was_ready, unsafe {
            (*target).ready_outbound_connections
        });
    unsafe {
        mtproxy_ffi_net_connections_stats_add_ready(ready_outbound_delta, ready_targets_delta);
    }

    let need_c = mtproxy_core::runtime::net::connections::target_needed_connections(
        unsafe { (*target).min_connections },
        unsafe { (*target).max_connections },
        bad_c,
        stopped_c,
    );
    assert!(need_c <= unsafe { (*target).max_connections });

    if mtproxy_core::runtime::net::connections::target_should_attempt_reconnect(
        unsafe { mtproxy_ffi_net_connections_precise_now() },
        unsafe { (*target).next_reconnect },
        unsafe { (*target).active_outbound_connections },
    ) {
        let mut tree = unsafe { get_tree_ptr_connection(ptr::addr_of_mut!((*target).conn_tree)) };

        while unsafe { (*target).outbound_connections < need_c } {
            let connect_action =
                mtproxy_core::runtime::net::connections::target_connect_socket_action(unsafe {
                    (*target).target.s_addr != 0
                });
            assert!(connect_action == 1 || connect_action == 2);

            let cfd = if connect_action == 1 {
                unsafe { client_socket((*target).target.s_addr, (*target).port, 0) }
            } else {
                unsafe {
                    client_socket_ipv6((*target).target_ipv6.as_ptr(), (*target).port, SM_IPV6)
                }
            };
            if cfd < 0 {
                break;
            }

            let conn = unsafe {
                alloc_new_connection_impl(
                    cfd,
                    ctj,
                    ptr::null_mut(),
                    CT_OUTBOUND,
                    (*target).type_,
                    (*target).extra,
                    u32::from_be((*target).target.s_addr),
                    (*target).target_ipv6.as_mut_ptr(),
                    (*target).port,
                )
            };

            let should_insert =
                mtproxy_core::runtime::net::connections::target_create_insert_should_insert(
                    !conn.is_null(),
                );
            if !should_insert {
                break;
            }

            let conn_info_ptr = unsafe { conn_info(conn) };
            assert!(!unsafe { (*conn_info_ptr).io_conn }.is_null());
            count += 1;
            unsafe {
                unlock_job(1, job_incref(conn));
                tree = tree_insert_connection(tree, conn, lrand48_j() as c_int);
            }
        }

        let tree_update_decision =
            mtproxy_core::runtime::net::connections::target_tree_update_decision(
                tree != unsafe { (*target).conn_tree },
            );
        if tree_update_decision
            == mtproxy_core::runtime::net::connections::TargetTreeUpdateDecision::FreeSnapshotOnly
        {
            unsafe { tree_free_connection(tree) };
        } else {
            assert_eq!(
                tree_update_decision,
                mtproxy_core::runtime::net::connections::TargetTreeUpdateDecision::ReplaceAndFreeOld
            );
            let old = unsafe { (*target).conn_tree };
            unsafe {
                (*target).conn_tree = tree;
                core::sync::atomic::fence(Ordering::SeqCst);
                free_tree_ptr_connection(old);
            }
        }

        unsafe { compute_next_reconnect_target_impl(ctj) };
    }

    count
}

pub(super) unsafe fn destroy_target_impl(ctj_tag_int: c_int, ctj: ConnTargetJob) -> c_int {
    let target = unsafe { conn_target_info(ctj) };
    assert!(!target.is_null());
    assert!(!unsafe { (*target).type_ }.is_null());
    assert!(unsafe { (*target).global_refcnt } > 0);

    let r = unsafe { atomic_i32(ptr::addr_of_mut!((*target).global_refcnt)) }
        .fetch_sub(1, Ordering::SeqCst)
        - 1;
    let (active_targets_delta, inactive_targets_delta, signal_run) =
        mtproxy_core::runtime::net::connections::destroy_target_transition(r);
    unsafe {
        mtproxy_ffi_net_connections_stats_add_targets(active_targets_delta, inactive_targets_delta);
    }

    if signal_run {
        unsafe {
            job_signal(ctj_tag_int, ctj, JS_RUN);
        }
    } else {
        unsafe {
            job_decref(ctj_tag_int, ctj);
        }
    }
    r
}

pub(super) unsafe fn create_target_impl(
    source: *mut ConnTargetInfo,
    was_created: *mut c_int,
) -> ConnTargetJob {
    if source.is_null() {
        return ptr::null_mut();
    }
    if unsafe { check_conn_functions_impl((*source).type_, 0) } < 0 {
        return ptr::null_mut();
    }

    let lock_rc = unsafe { libc::pthread_mutex_lock(ptr::addr_of_mut!(TargetsLock)) };
    assert_eq!(lock_rc, 0);

    let source_ref = unsafe { &*source };
    let lookup_plan = mtproxy_core::runtime::net::connections::target_create_lookup_plan(
        source_ref.target.s_addr != 0,
        false,
    );
    let lookup_mode =
        mtproxy_core::runtime::net::connections::target_lookup_mode_value(lookup_plan.mode);
    let t = match lookup_plan.family {
        mtproxy_core::runtime::net::connections::TargetLookupFamily::Ipv4 => unsafe {
            target_lookup_ipv4_impl(
                source_ref.target.s_addr,
                source_ref.port,
                source_ref.type_,
                source_ref.extra,
                lookup_mode,
                ptr::null_mut(),
            )
        },
        mtproxy_core::runtime::net::connections::TargetLookupFamily::Ipv6 => unsafe {
            target_lookup_ipv6_impl(
                &source_ref.target_ipv6,
                source_ref.port,
                source_ref.type_,
                source_ref.extra,
                lookup_mode,
                ptr::null_mut(),
            )
        },
    };

    let lifecycle_decision =
        mtproxy_core::runtime::net::connections::create_target_lifecycle_decision(!t.is_null());
    let out = if lifecycle_decision
        == mtproxy_core::runtime::net::connections::CreateTargetLifecycleDecision::ReuseExisting
    {
        let t_info = unsafe { conn_target_info(t) };
        unsafe {
            (*t_info).min_connections = source_ref.min_connections;
            (*t_info).max_connections = source_ref.max_connections;
            (*t_info).reconnect_timeout = source_ref.reconnect_timeout;
        }

        let old_global_refcnt = unsafe { atomic_i32(ptr::addr_of_mut!((*t_info).global_refcnt)) }
            .fetch_add(1, Ordering::SeqCst);
        let (active_targets_delta, inactive_targets_delta, created_state) =
            mtproxy_core::runtime::net::connections::create_target_transition(
                true,
                old_global_refcnt,
            );
        unsafe {
            mtproxy_ffi_net_connections_stats_add_targets(
                active_targets_delta,
                inactive_targets_delta,
            );
        }
        if !was_created.is_null() {
            unsafe {
                *was_created = created_state;
            }
        }
        unsafe {
            job_incref(t);
        }
        t
    } else {
        assert_eq!(
            lifecycle_decision,
            mtproxy_core::runtime::net::connections::CreateTargetLifecycleDecision::AllocateNew
        );
        let job_signals = jsc_allow(JC_EPOLL, JS_RUN)
            | jsc_allow(JC_EPOLL, JS_ABORT)
            | jsc_allow(JC_EPOLL, JS_ALARM)
            | jsc_allow(JC_EPOLL, JS_FINISH);
        let t_new = unsafe {
            create_async_job(
                Some(do_conn_target_job),
                job_signals,
                -2,
                c_int::try_from(size_of::<ConnTargetInfo>()).unwrap_or(c_int::MAX),
                JT_HAVE_TIMER,
                1,
                ptr::null_mut(),
            )
        };
        assert!(!t_new.is_null());
        unsafe {
            (*t_new.cast::<AsyncJob>()).j_refcnt = 2;
        }

        let t_info = unsafe { conn_target_info(t_new) };
        unsafe {
            ptr::copy_nonoverlapping(source, t_info, 1);
            job_timer_init(t_new);
        }

        let (active_targets_delta, inactive_targets_delta, created_state) =
            mtproxy_core::runtime::net::connections::create_target_transition(false, 0);
        unsafe {
            mtproxy_ffi_net_connections_stats_add_targets(
                active_targets_delta,
                inactive_targets_delta,
            );
            mtproxy_ffi_net_connections_stat_add_allocated_targets(1);
        }

        let insert_lookup_plan = mtproxy_core::runtime::net::connections::target_create_lookup_plan(
            source_ref.target.s_addr != 0,
            true,
        );
        let insert_lookup_mode = mtproxy_core::runtime::net::connections::target_lookup_mode_value(
            insert_lookup_plan.mode,
        );
        match insert_lookup_plan.family {
            mtproxy_core::runtime::net::connections::TargetLookupFamily::Ipv4 => unsafe {
                target_lookup_ipv4_impl(
                    source_ref.target.s_addr,
                    source_ref.port,
                    source_ref.type_,
                    source_ref.extra,
                    insert_lookup_mode,
                    t_new,
                );
            },
            mtproxy_core::runtime::net::connections::TargetLookupFamily::Ipv6 => unsafe {
                target_lookup_ipv6_impl(
                    &source_ref.target_ipv6,
                    source_ref.port,
                    source_ref.type_,
                    source_ref.extra,
                    insert_lookup_mode,
                    t_new,
                );
            },
        }

        if !was_created.is_null() {
            unsafe {
                *was_created = created_state;
            }
        }
        unsafe {
            (*t_info).global_refcnt = 1;
            schedule_job(1, job_incref(t_new));
        }
        t_new
    };

    let unlock_rc = unsafe { libc::pthread_mutex_unlock(ptr::addr_of_mut!(TargetsLock)) };
    assert_eq!(unlock_rc, 0);
    out
}

pub(super) unsafe fn free_target_impl(ctj: ConnTargetJob) -> c_int {
    let lock_rc = unsafe { libc::pthread_mutex_lock(ptr::addr_of_mut!(TargetsLock)) };
    assert_eq!(lock_rc, 0);

    let target = unsafe { conn_target_info(ctj) };
    let free_action = mtproxy_core::runtime::net::connections::target_free_decision(
        unsafe { (*target).global_refcnt },
        unsafe { !(*target).conn_tree.is_null() },
        unsafe { (*target).target.s_addr != 0 },
    );
    if free_action == mtproxy_core::runtime::net::connections::TargetFreeDecision::Reject {
        let unlock_rc = unsafe { libc::pthread_mutex_unlock(ptr::addr_of_mut!(TargetsLock)) };
        assert_eq!(unlock_rc, 0);
        return -1;
    }
    let Some(free_lookup_plan) =
        mtproxy_core::runtime::net::connections::target_free_lookup_plan(free_action)
    else {
        unreachable!("reject free action returned above")
    };
    let free_lookup_mode =
        mtproxy_core::runtime::net::connections::target_lookup_mode_value(free_lookup_plan.mode);

    assert!(!target.is_null());
    assert!(!unsafe { (*target).type_ }.is_null());
    assert_eq!(unsafe { (*target).global_refcnt }, 0);
    assert!(unsafe { (*target).conn_tree.is_null() });

    match free_lookup_plan.family {
        mtproxy_core::runtime::net::connections::TargetLookupFamily::Ipv4 => {
            let ad = unsafe { (*target).target };
            let port = unsafe { (*target).port };
            let type_ = unsafe { (*target).type_ };
            let extra = unsafe { (*target).extra };
            unsafe {
                crate::kprintf_fmt!(
                    FREE_UNUSED_TARGET_IPV4_MSG.as_ptr().cast(),
                    inet_ntoa(ad),
                    port,
                )
            };
            let removed = unsafe {
                target_lookup_ipv4_impl(
                    ad.s_addr,
                    port,
                    type_,
                    extra,
                    free_lookup_mode,
                    ptr::null_mut(),
                )
            };
            assert_eq!(removed, ctj);
        }
        mtproxy_core::runtime::net::connections::TargetLookupFamily::Ipv6 => {
            let ad_ipv6 = unsafe { (*target).target_ipv6 };
            let port = unsafe { (*target).port };
            let type_ = unsafe { (*target).type_ };
            let extra = unsafe { (*target).extra };
            unsafe {
                crate::kprintf_fmt!(
                    FREE_UNUSED_TARGET_IPV6_MSG.as_ptr().cast(),
                    show_ipv6(ad_ipv6.as_ptr()),
                    port,
                )
            };
            let removed = unsafe {
                target_lookup_ipv6_impl(
                    &ad_ipv6,
                    port,
                    type_,
                    extra,
                    free_lookup_mode,
                    ptr::null_mut(),
                )
            };
            assert_eq!(removed, ctj);
        }
    }

    let unlock_rc = unsafe { libc::pthread_mutex_unlock(ptr::addr_of_mut!(TargetsLock)) };
    assert_eq!(unlock_rc, 0);

    unsafe {
        mtproxy_ffi_net_connections_stat_target_freed();
        job_decref_pass(ctj);
    }
    1
}

pub(super) unsafe fn do_conn_target_job_impl(job: Job, op: c_int, _jt: *mut c_void) -> c_int {
    if unsafe { epoll_fd } <= 0 {
        unsafe {
            job_timer_insert(
                job,
                mtproxy_ffi_net_connections_precise_now()
                    + mtproxy_core::runtime::net::connections::target_job_boot_delay(),
            );
        }
        return 0;
    }

    let ctj = job;
    let target = unsafe { conn_target_info(ctj) };
    let dispatch = mtproxy_core::runtime::net::connections::target_job_dispatch(
        op, JS_RUN, JS_ALARM, JS_FINISH,
    );
    if dispatch == mtproxy_core::runtime::net::connections::TargetJobDispatch::Run
        || dispatch == mtproxy_core::runtime::net::connections::TargetJobDispatch::Alarm
    {
        let is_alarm =
            dispatch == mtproxy_core::runtime::net::connections::TargetJobDispatch::Alarm;
        let timer_check_ok = if is_alarm {
            unsafe { job_timer_check(job) != 0 }
        } else {
            true
        };
        if !mtproxy_core::runtime::net::connections::target_job_should_run_tick(
            is_alarm,
            timer_check_ok,
        ) {
            return 0;
        }

        let update_mode = mtproxy_core::runtime::net::connections::target_job_update_mode(unsafe {
            (*target).global_refcnt
        });
        if update_mode == TARGET_JOB_UPDATE_INACTIVE_CLEANUP {
            unsafe { destroy_dead_target_connections_impl(ctj) };
            unsafe { clean_unused_target_impl(ctj) };
            unsafe { compute_next_reconnect_target_impl(ctj) };
        } else {
            assert_eq!(update_mode, TARGET_JOB_UPDATE_CREATE_CONNECTIONS);
            unsafe { create_new_connections_impl(ctj) };
        }

        let post_action = mtproxy_core::runtime::net::connections::target_job_post_tick_decision(
            (unsafe { (*ctj.cast::<AsyncJob>()).j_flags } & JF_COMPLETED) != 0,
            unsafe { (*target).global_refcnt },
            unsafe { !(*target).conn_tree.is_null() },
        );
        if post_action == mtproxy_core::runtime::net::connections::TargetJobPostTick::ReturnZero {
            return 0;
        }

        let retry_delay = mtproxy_core::runtime::net::connections::target_job_retry_delay();
        if post_action == mtproxy_core::runtime::net::connections::TargetJobPostTick::ScheduleRetry
        {
            unsafe {
                job_timer_insert(ctj, mtproxy_ffi_net_connections_precise_now() + retry_delay);
            }
            return 0;
        }

        assert_eq!(
            post_action,
            mtproxy_core::runtime::net::connections::TargetJobPostTick::AttemptFree
        );
        let finalize_action =
            mtproxy_core::runtime::net::connections::target_job_finalize_decision(unsafe {
                mtproxy_ffi_net_connections_free_target(ctj)
            });
        if finalize_action == mtproxy_core::runtime::net::connections::TargetJobFinalize::Completed
        {
            return JOB_COMPLETED;
        }
        unsafe {
            job_timer_insert(ctj, mtproxy_ffi_net_connections_precise_now() + retry_delay);
        }
        return 0;
    }

    if dispatch == mtproxy_core::runtime::net::connections::TargetJobDispatch::Finish {
        assert!((unsafe { (*ctj.cast::<AsyncJob>()).j_flags } & JF_COMPLETED) != 0);
        unsafe {
            mtproxy_ffi_net_connections_stat_add_allocated_targets(-1);
            return mtproxy_ffi_net_connections_job_free(job);
        }
    }

    assert_eq!(
        dispatch,
        mtproxy_core::runtime::net::connections::TargetJobDispatch::Error
    );
    JOB_ERROR
}

pub(super) unsafe fn conn_target_get_connection_impl(
    ct: ConnTargetJob,
    allow_stopped: c_int,
) -> ConnectionJob {
    if ct.is_null() {
        return ptr::null_mut();
    }
    let target = unsafe { conn_target_info(ct) };
    let tree = unsafe { get_tree_ptr_connection(ptr::addr_of_mut!((*target).conn_tree)) };

    let mut selected: ConnectionJob = ptr::null_mut();
    let mut ctx = ConnTargetPickCtx {
        selected: ptr::addr_of_mut!(selected),
        allow_stopped: if allow_stopped != 0 { 1 } else { 0 },
    };
    unsafe {
        tree_act_ex_connection(
            tree,
            Some(target_pick_policy_callback),
            ptr::addr_of_mut!(ctx).cast(),
        );
    }

    if mtproxy_core::runtime::net::connections::target_pick_should_incref(!selected.is_null()) {
        unsafe {
            job_incref(selected);
        }
    }
    unsafe {
        tree_free_connection(tree);
    }

    selected
}

pub(super) unsafe fn insert_free_later_struct_impl(f: *mut FreeLater) {
    if unsafe { FREE_LATER_QUEUE.is_null() } {
        unsafe {
            FREE_LATER_QUEUE = alloc_mp_queue_w();
        }
        assert!(!unsafe { FREE_LATER_QUEUE }.is_null());
    }
    unsafe {
        mtproxy_ffi_net_connections_mpq_push_w(FREE_LATER_QUEUE, f.cast(), 0);
        mtproxy_ffi_net_connections_stat_free_later_enqueued();
    }
}

pub(super) unsafe fn free_later_act_impl() {
    if unsafe { FREE_LATER_QUEUE.is_null() } {
        return;
    }
    loop {
        let f = unsafe { mtproxy_ffi_net_connections_mpq_pop_nw(FREE_LATER_QUEUE, 4) }
            .cast::<FreeLater>();
        if f.is_null() {
            return;
        }
        unsafe {
            mtproxy_ffi_net_connections_stat_free_later_dequeued();
        }
        let free_fn = unsafe { (*f).free };
        assert!(free_fn.is_some());
        unsafe {
            free_fn.unwrap()((*f).ptr);
            libc::free(f.cast());
        }
    }
}
