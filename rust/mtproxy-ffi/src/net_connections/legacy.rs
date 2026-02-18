//! Legacy symbol glue for migrated `net/net-connections.c` wrappers.

use super::abi::*;
use super::runtime::*;
use core::ffi::{c_char, c_double, c_int, c_long, c_longlong, c_uint, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU64, Ordering};
use libc::in_addr;

const LEGACY_MAX_EVENTS: usize = 1 << 19;
const LEGACY_PRIME_TARGETS: usize = 99_961;

unsafe extern "C" {
    fn mtproxy_ffi_net_add_nat_info(rule_text: *const c_char) -> c_int;
    fn mtproxy_ffi_net_translate_ip(local_ip: c_uint) -> c_uint;
    fn sb_printf(sb: *mut StatsBuffer, format: *const c_char, ...);
    fn mpq_push_w(mq: *mut MpQueue, val: *mut c_void, flags: c_int) -> c_long;
    fn mpq_pop_nw(mq: *mut MpQueue, flags: c_int) -> *mut c_void;
    fn rwm_union(raw: *mut RawMessage, tail: *mut RawMessage) -> c_int;
    #[allow(clashing_extern_declarations)]
    #[link_name = "create_async_job"]
    fn ffi_create_async_job(
        run_job: JobFunction,
        job_signals: u64,
        job_subclass: c_int,
        custom_bytes: c_int,
        job_type: u64,
        parent_job_tag_int: c_int,
        parent_job: Job,
    ) -> Job;
    #[allow(clashing_extern_declarations)]
    #[link_name = "unlock_job"]
    fn ffi_unlock_job(job_tag_int: c_int, job: Job) -> c_int;
    #[link_name = "job_incref"]
    fn ffi_job_incref(job: Job) -> Job;
    #[link_name = "job_decref"]
    fn ffi_job_decref(job_tag_int: c_int, job: Job);
    #[link_name = "job_signal"]
    fn ffi_job_signal(job_tag_int: c_int, job: Job, signal: c_int);
    #[allow(clashing_extern_declarations)]
    #[link_name = "schedule_job"]
    fn ffi_schedule_job(job_tag_int: c_int, job: Job) -> c_int;
    #[link_name = "job_timer_insert"]
    fn ffi_job_timer_insert(job: Job, timeout: c_double);
    #[link_name = "job_timer_remove"]
    fn ffi_job_timer_remove(job: Job);
    #[link_name = "job_timer_check"]
    fn ffi_job_timer_check(job: Job) -> c_int;
    #[allow(clashing_extern_declarations)]
    #[link_name = "job_timer_init"]
    fn ffi_job_timer_init(job: Job);
    #[link_name = "mtproxy_ffi_net_connections_job_free"]
    fn ffi_net_connections_job_free(job: Job) -> c_int;
    #[link_name = "mtproxy_ffi_net_connections_job_thread_dec_jobs_active"]
    fn ffi_net_connections_job_thread_dec_jobs_active();
    #[link_name = "rwm_init"]
    fn ffi_rwm_init(raw: *mut RawMessage, alloc_bytes: c_int) -> c_int;
    #[link_name = "rwm_free"]
    fn ffi_rwm_free(raw: *mut RawMessage) -> c_int;
    #[link_name = "rwm_prepare_iovec"]
    fn ffi_rwm_prepare_iovec(
        raw: *const RawMessage,
        iov: *mut libc::iovec,
        iov_len: c_int,
        bytes: c_int,
    ) -> c_int;
    #[link_name = "rwm_skip_data"]
    fn ffi_rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int;
    #[link_name = "show_ipv6"]
    fn ffi_show_ipv6(ipv6: *const u8) -> *const c_char;
    #[link_name = "inet_ntoa"]
    fn ffi_inet_ntoa(addr: in_addr) -> *mut c_char;
    #[link_name = "client_socket"]
    fn ffi_client_socket(in_addr: c_uint, port: c_int, mode: c_int) -> c_int;
    #[link_name = "client_socket_ipv6"]
    fn ffi_client_socket_ipv6(in6_addr_ptr: *const u8, port: c_int, mode: c_int) -> c_int;
    #[allow(clashing_extern_declarations)]
    #[link_name = "mtproxy_ffi_net_msg_buffers_alloc"]
    fn ffi_alloc_msg_buffer(neighbor: *mut MsgBuffer, size_hint: c_int) -> *mut MsgBuffer;
    #[link_name = "new_msg_part"]
    fn ffi_new_msg_part(neighbor: *mut MsgPart, x: *mut MsgBuffer) -> *mut MsgPart;
    #[link_name = "epoll_sethandler"]
    fn ffi_epoll_sethandler(
        fd: c_int,
        prio: c_int,
        handler: EventHandler,
        data: *mut c_void,
    ) -> c_int;
    #[link_name = "epoll_insert"]
    fn ffi_epoll_insert(fd: c_int, flags: c_int) -> c_int;
    #[link_name = "epoll_remove"]
    fn ffi_epoll_remove(fd: c_int) -> c_int;
    #[link_name = "remove_event_from_heap"]
    fn ffi_remove_event_from_heap(ev: *mut EventDescr, allow_hole: c_int) -> c_int;
    #[link_name = "mtproxy_ffi_net_tcp_connections_cpu_tcp_free_connection_buffers"]
    fn ffi_cpu_tcp_free_connection_buffers(c: ConnectionJob) -> c_int;
    #[link_name = "mtproxy_ffi_net_tcp_connections_cpu_tcp_server_reader"]
    fn ffi_cpu_tcp_server_reader(c: ConnectionJob) -> c_int;
    #[link_name = "mtproxy_ffi_net_tcp_connections_cpu_tcp_server_writer"]
    fn ffi_cpu_tcp_server_writer(c: ConnectionJob) -> c_int;
    #[link_name = "maximize_sndbuf"]
    fn ffi_maximize_sndbuf(socket_fd: c_int, max: c_int);
    #[link_name = "maximize_rcvbuf"]
    fn ffi_maximize_rcvbuf(socket_fd: c_int, max: c_int);
    #[link_name = "get_tree_ptr_connection"]
    fn ffi_get_tree_ptr_connection(tree: *mut *mut TreeConnection) -> *mut TreeConnection;
    #[link_name = "tree_act_ex_connection"]
    fn ffi_tree_act_ex_connection(
        tree: *mut TreeConnection,
        act: Option<unsafe extern "C" fn(ConnectionJob, *mut c_void)>,
        ex: *mut c_void,
    );
    #[link_name = "tree_act_ex3_connection"]
    fn ffi_tree_act_ex3_connection(
        tree: *mut TreeConnection,
        act: Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, *mut c_void, *mut c_void)>,
        ex: *mut c_void,
        ex2: *mut c_void,
        ex3: *mut c_void,
    );
    #[link_name = "tree_act_connection"]
    fn ffi_tree_act_connection(
        tree: *mut TreeConnection,
        act: Option<unsafe extern "C" fn(ConnectionJob)>,
    );
    #[link_name = "tree_insert_connection"]
    fn ffi_tree_insert_connection(
        tree: *mut TreeConnection,
        conn: ConnectionJob,
        priority: c_int,
    ) -> *mut TreeConnection;
    #[link_name = "tree_delete_connection"]
    fn ffi_tree_delete_connection(
        tree: *mut TreeConnection,
        conn: ConnectionJob,
    ) -> *mut TreeConnection;
    #[link_name = "tree_free_connection"]
    fn ffi_tree_free_connection(tree: *mut TreeConnection);
    #[link_name = "free_tree_ptr_connection"]
    fn ffi_free_tree_ptr_connection(tree: *mut TreeConnection);
    #[link_name = "HTarget"]
    static mut ffi_htarget: [ConnTargetJob; LEGACY_PRIME_TARGETS];
    #[link_name = "TargetsLock"]
    static mut ffi_targets_lock: libc::pthread_mutex_t;
    #[link_name = "epoll_fd"]
    static mut ffi_epoll_fd: c_int;
    #[link_name = "Events"]
    static mut ffi_events: [EventDescr; LEGACY_MAX_EVENTS];
    #[link_name = "tcp_maximize_buffers"]
    static mut ffi_tcp_maximize_buffers: c_int;
    #[link_name = "verbosity"]
    static mut ffi_verbosity: c_int;
    #[link_name = "active_special_connections"]
    static mut ffi_active_special_connections: c_int;
    #[link_name = "max_special_connections"]
    static mut ffi_max_special_connections: c_int;
    static mut active_special_connections: c_int;
    static mut max_special_connections: c_int;
}

#[inline]
pub(super) unsafe fn create_async_job(
    run_job: JobFunction,
    job_signals: u64,
    job_subclass: c_int,
    custom_bytes: c_int,
    job_type: u64,
    parent_job_tag_int: c_int,
    parent_job: Job,
) -> Job {
    unsafe {
        ffi_create_async_job(
            run_job,
            job_signals,
            job_subclass,
            custom_bytes,
            job_type,
            parent_job_tag_int,
            parent_job,
        )
    }
}

#[inline]
pub(super) unsafe fn unlock_job(job_tag_int: c_int, job: Job) -> c_int {
    unsafe { ffi_unlock_job(job_tag_int, job) }
}

#[inline]
pub(super) unsafe fn job_incref(job: Job) -> Job {
    unsafe { ffi_job_incref(job) }
}

#[inline]
pub(super) unsafe fn job_decref(job_tag_int: c_int, job: Job) {
    unsafe { ffi_job_decref(job_tag_int, job) };
}

#[inline]
pub(super) unsafe fn job_signal(job_tag_int: c_int, job: Job, signal: c_int) {
    unsafe { ffi_job_signal(job_tag_int, job, signal) };
}

#[inline]
pub(super) unsafe fn schedule_job(job_tag_int: c_int, job: Job) -> c_int {
    unsafe { ffi_schedule_job(job_tag_int, job) }
}

#[inline]
pub(super) unsafe fn job_timer_insert(job: Job, timeout: c_double) {
    unsafe { ffi_job_timer_insert(job, timeout) };
}

#[inline]
pub(super) unsafe fn job_timer_remove(job: Job) {
    unsafe { ffi_job_timer_remove(job) };
}

#[inline]
pub(super) unsafe fn job_timer_check(job: Job) -> c_int {
    unsafe { ffi_job_timer_check(job) }
}

#[inline]
pub(super) unsafe fn job_timer_init(job: Job) {
    unsafe { ffi_job_timer_init(job) };
}

#[inline]
pub(super) unsafe fn mtproxy_ffi_net_connections_job_free(job: Job) -> c_int {
    unsafe { ffi_net_connections_job_free(job) }
}

#[inline]
pub(super) unsafe fn mtproxy_ffi_net_connections_job_thread_dec_jobs_active() {
    unsafe { ffi_net_connections_job_thread_dec_jobs_active() };
}

#[inline]
pub(super) unsafe fn alloc_mp_queue_w() -> *mut MpQueue {
    unsafe { crate::alloc_mp_queue_w().cast::<MpQueue>() }
}

#[inline]
pub(super) unsafe fn free_mp_queue(mq: *mut MpQueue) {
    unsafe { crate::free_mp_queue(mq.cast::<c_void>()) };
}

#[inline]
pub(super) unsafe fn rwm_init(raw: *mut RawMessage, alloc_bytes: c_int) -> c_int {
    unsafe { ffi_rwm_init(raw, alloc_bytes) }
}

#[inline]
pub(super) unsafe fn rwm_free(raw: *mut RawMessage) -> c_int {
    unsafe { ffi_rwm_free(raw) }
}

#[inline]
pub(super) unsafe fn rwm_prepare_iovec(
    raw: *const RawMessage,
    iov: *mut libc::iovec,
    iov_len: c_int,
    bytes: c_int,
) -> c_int {
    unsafe { ffi_rwm_prepare_iovec(raw, iov, iov_len, bytes) }
}

#[inline]
pub(super) unsafe fn rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int {
    unsafe { ffi_rwm_skip_data(raw, bytes) }
}

#[inline]
pub(super) unsafe fn show_ipv6(ipv6: *const u8) -> *const c_char {
    unsafe { ffi_show_ipv6(ipv6) }
}

#[inline]
pub(super) unsafe fn inet_ntoa(addr: in_addr) -> *mut c_char {
    unsafe { ffi_inet_ntoa(addr) }
}

#[inline]
pub(super) unsafe fn client_socket(in_addr: c_uint, port: c_int, mode: c_int) -> c_int {
    unsafe { ffi_client_socket(in_addr, port, mode) }
}

#[inline]
pub(super) unsafe fn client_socket_ipv6(in6_addr_ptr: *const u8, port: c_int, mode: c_int) -> c_int {
    unsafe { ffi_client_socket_ipv6(in6_addr_ptr, port, mode) }
}

#[inline]
pub(super) unsafe fn drand48_j() -> c_double {
    unsafe { crate::drand48_j() }
}

#[inline]
pub(super) unsafe fn lrand48_j() -> c_long {
    unsafe { crate::lrand48_j() }
}

#[inline]
pub(super) unsafe fn alloc_msg_buffer(neighbor: *mut MsgBuffer, size_hint: c_int) -> *mut MsgBuffer {
    unsafe { ffi_alloc_msg_buffer(neighbor, size_hint) }
}

#[inline]
pub(super) unsafe fn new_msg_part(neighbor: *mut MsgPart, x: *mut MsgBuffer) -> *mut MsgPart {
    unsafe { ffi_new_msg_part(neighbor, x) }
}

#[inline]
pub(super) unsafe fn epoll_sethandler(
    fd: c_int,
    prio: c_int,
    handler: EventHandler,
    data: *mut c_void,
) -> c_int {
    unsafe { ffi_epoll_sethandler(fd, prio, handler, data) }
}

#[inline]
pub(super) unsafe fn epoll_insert(fd: c_int, flags: c_int) -> c_int {
    unsafe { ffi_epoll_insert(fd, flags) }
}

#[inline]
pub(super) unsafe fn epoll_remove(fd: c_int) -> c_int {
    unsafe { ffi_epoll_remove(fd) }
}

#[inline]
pub(super) unsafe fn remove_event_from_heap(ev: *mut EventDescr, allow_hole: c_int) -> c_int {
    unsafe { ffi_remove_event_from_heap(ev, allow_hole) }
}

#[inline]
pub(super) unsafe extern "C" fn cpu_tcp_free_connection_buffers(c: ConnectionJob) -> c_int {
    unsafe { ffi_cpu_tcp_free_connection_buffers(c) }
}

#[inline]
pub(super) unsafe extern "C" fn cpu_tcp_server_reader(c: ConnectionJob) -> c_int {
    unsafe { ffi_cpu_tcp_server_reader(c) }
}

#[inline]
pub(super) unsafe extern "C" fn cpu_tcp_server_writer(c: ConnectionJob) -> c_int {
    unsafe { ffi_cpu_tcp_server_writer(c) }
}

#[inline]
pub(super) unsafe fn maximize_sndbuf(socket_fd: c_int, max: c_int) {
    unsafe { ffi_maximize_sndbuf(socket_fd, max) };
}

#[inline]
pub(super) unsafe fn maximize_rcvbuf(socket_fd: c_int, max: c_int) {
    unsafe { ffi_maximize_rcvbuf(socket_fd, max) };
}

#[inline]
pub(super) unsafe fn get_tree_ptr_connection(tree: *mut *mut TreeConnection) -> *mut TreeConnection {
    unsafe { ffi_get_tree_ptr_connection(tree) }
}

#[inline]
pub(super) unsafe fn tree_act_ex_connection(
    tree: *mut TreeConnection,
    act: Option<unsafe extern "C" fn(ConnectionJob, *mut c_void)>,
    ex: *mut c_void,
) {
    unsafe { ffi_tree_act_ex_connection(tree, act, ex) };
}

#[inline]
pub(super) unsafe fn tree_act_ex3_connection(
    tree: *mut TreeConnection,
    act: Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, *mut c_void, *mut c_void)>,
    ex: *mut c_void,
    ex2: *mut c_void,
    ex3: *mut c_void,
) {
    unsafe { ffi_tree_act_ex3_connection(tree, act, ex, ex2, ex3) };
}

#[inline]
pub(super) unsafe fn tree_act_connection(
    tree: *mut TreeConnection,
    act: Option<unsafe extern "C" fn(ConnectionJob)>,
) {
    unsafe { ffi_tree_act_connection(tree, act) };
}

#[inline]
pub(super) unsafe fn tree_insert_connection(
    tree: *mut TreeConnection,
    conn: ConnectionJob,
    priority: c_int,
) -> *mut TreeConnection {
    unsafe { ffi_tree_insert_connection(tree, conn, priority) }
}

#[inline]
pub(super) unsafe fn tree_delete_connection(
    tree: *mut TreeConnection,
    conn: ConnectionJob,
) -> *mut TreeConnection {
    unsafe { ffi_tree_delete_connection(tree, conn) }
}

#[inline]
pub(super) unsafe fn tree_free_connection(tree: *mut TreeConnection) {
    unsafe { ffi_tree_free_connection(tree) };
}

#[inline]
pub(super) unsafe fn free_tree_ptr_connection(tree: *mut TreeConnection) {
    unsafe { ffi_free_tree_ptr_connection(tree) };
}

#[inline]
pub(super) unsafe fn htarget_bucket_ptr(bucket: usize) -> *mut ConnTargetJob {
    unsafe { ptr::addr_of_mut!(ffi_htarget[bucket]) }
}

#[inline]
pub(super) unsafe fn targets_lock_ptr() -> *mut libc::pthread_mutex_t {
    &raw mut ffi_targets_lock
}

#[inline]
pub(super) unsafe fn epoll_fd_get() -> c_int {
    unsafe { ffi_epoll_fd }
}

#[inline]
pub(super) unsafe fn event_ptr(fd: usize) -> *mut EventDescr {
    unsafe { ptr::addr_of_mut!(ffi_events[fd]) }
}

#[inline]
pub(super) unsafe fn tcp_maximize_buffers_get() -> c_int {
    unsafe { ffi_tcp_maximize_buffers }
}

#[inline]
pub(super) unsafe fn verbosity_get() -> c_int {
    unsafe { ffi_verbosity }
}

#[inline]
pub(super) unsafe fn active_special_connections_ptr() -> *mut c_int {
    &raw mut ffi_active_special_connections
}

#[inline]
pub(super) unsafe fn max_special_connections_get() -> c_int {
    unsafe { ffi_max_special_connections }
}

#[inline]
pub(super) unsafe extern "C" fn net_server_socket_read_write_gateway_event_descr(
    fd: c_int,
    data: *mut c_void,
    ev: *mut EventDescr,
) -> c_int {
    unsafe { net_server_socket_read_write_gateway(fd, data, ev.cast::<c_void>()) }
}

#[repr(C)]
pub(super) struct StatsBuffer {
    buff: *mut c_char,
    pos: c_int,
    size: c_int,
    flags: c_int,
}

static ACTIVE_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static ACTIVE_DH_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static OUTBOUND_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static ACTIVE_OUTBOUND_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static READY_OUTBOUND_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static LISTENING_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static ALLOCATED_OUTBOUND_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static ALLOCATED_INBOUND_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static INBOUND_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static ACTIVE_INBOUND_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static OUTBOUND_CONNECTIONS_CREATED: AtomicI64 = AtomicI64::new(0);
static INBOUND_CONNECTIONS_ACCEPTED: AtomicI64 = AtomicI64::new(0);
static READY_TARGETS: AtomicI32 = AtomicI32::new(0);
static TOTAL_FAILED_CONNECTIONS: AtomicI64 = AtomicI64::new(0);
static TOTAL_CONNECT_FAILURES: AtomicI64 = AtomicI64::new(0);
static UNUSED_CONNECTIONS_CLOSED: AtomicI64 = AtomicI64::new(0);
static ALLOCATED_TARGETS: AtomicI32 = AtomicI32::new(0);
static ACTIVE_TARGETS: AtomicI32 = AtomicI32::new(0);
static INACTIVE_TARGETS: AtomicI32 = AtomicI32::new(0);
static FREE_TARGETS: AtomicI32 = AtomicI32::new(0);
static ALLOCATED_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static ALLOCATED_SOCKET_CONNECTIONS: AtomicI32 = AtomicI32::new(0);
static ACCEPT_CALLS_FAILED: AtomicI64 = AtomicI64::new(0);
static ACCEPT_NONBLOCK_SET_FAILED: AtomicI64 = AtomicI64::new(0);
static ACCEPT_CONNECTION_LIMIT_FAILED: AtomicI64 = AtomicI64::new(0);
static ACCEPT_RATE_LIMIT_FAILED: AtomicI64 = AtomicI64::new(0);
static ACCEPT_INIT_ACCEPTED_FAILED: AtomicI64 = AtomicI64::new(0);
static TCP_READV_CALLS: AtomicI64 = AtomicI64::new(0);
static TCP_WRITEV_CALLS: AtomicI64 = AtomicI64::new(0);
static TCP_READV_INTR: AtomicI64 = AtomicI64::new(0);
static TCP_WRITEV_INTR: AtomicI64 = AtomicI64::new(0);
static TCP_READV_BYTES: AtomicI64 = AtomicI64::new(0);
static TCP_WRITEV_BYTES: AtomicI64 = AtomicI64::new(0);
static FREE_LATER_SIZE: AtomicI32 = AtomicI32::new(0);
static FREE_LATER_TOTAL: AtomicI64 = AtomicI64::new(0);
static MAX_ACCEPT_RATE: AtomicI32 = AtomicI32::new(0);
static CUR_ACCEPT_RATE_REMAINING_BITS: AtomicU64 = AtomicU64::new(0);
static CUR_ACCEPT_RATE_TIME_BITS: AtomicU64 = AtomicU64::new(0);
static MAX_CONNECTION: AtomicI32 = AtomicI32::new(0);
static CONN_GENERATION: AtomicI32 = AtomicI32::new(0);
static MAX_CONNECTION_FD: AtomicI32 = AtomicI32::new(65_536);
static SPECIAL_LISTEN_SOCKETS: AtomicI32 = AtomicI32::new(0);
static SPECIAL_SOCKET_FD: [AtomicI32; 64] = [const { AtomicI32::new(0) }; 64];
static SPECIAL_SOCKET_GENERATION: [AtomicI32; 64] = [const { AtomicI32::new(0) }; 64];

const JS_AUX: c_int = 1;
const MAX_SPECIAL_LISTEN_SOCKETS: usize = 64;

#[inline]
unsafe fn atomic_i32_ref(ptr: *mut c_int) -> &'static AtomicI32 {
    unsafe { &*ptr.cast::<AtomicI32>() }
}

#[inline]
unsafe fn atomic_i32_load(ptr: *mut c_int) -> c_int {
    unsafe { atomic_i32_ref(ptr).load(Ordering::Relaxed) }
}

#[inline]
fn atomic_f64_load(bits: &AtomicU64) -> c_double {
    c_double::from_bits(bits.load(Ordering::Relaxed))
}

#[inline]
fn atomic_f64_store(bits: &AtomicU64, value: c_double) {
    bits.store(value.to_bits(), Ordering::Relaxed);
}

#[inline]
unsafe fn sb_print_i32_key(sb: *mut StatsBuffer, key: *const c_char, value: c_int) {
    unsafe { crate::sb_printf_fmt!(sb, c"%s\t%d\n".as_ptr(), key, value) };
}

#[inline]
unsafe fn sb_print_i64_key(sb: *mut StatsBuffer, key: *const c_char, value: c_longlong) {
    unsafe { crate::sb_printf_fmt!(sb, c"%s\t%lld\n".as_ptr(), key, value) };
}

#[inline]
unsafe fn sb_print_double_key(sb: *mut StatsBuffer, key: *const c_char, value: c_double) {
    unsafe { crate::sb_printf_fmt!(sb, c"%s\t%.6lf\n".as_ptr(), key, value) };
}

#[no_mangle]
pub unsafe extern "C" fn connection_write_close(c: ConnectionJob) {
    unsafe { connection_write_close_impl(c) };
}

#[no_mangle]
pub unsafe extern "C" fn set_connection_timeout(c: ConnectionJob, timeout: c_double) -> c_int {
    unsafe { set_connection_timeout_impl(c, timeout) }
}

#[no_mangle]
pub unsafe extern "C" fn clear_connection_timeout(c: ConnectionJob) -> c_int {
    unsafe { clear_connection_timeout_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn fail_connection(c: ConnectionJob, err: c_int) {
    unsafe { fail_connection_impl(c, err) };
}

#[no_mangle]
pub unsafe extern "C" fn cpu_server_free_connection(c: ConnectionJob) -> c_int {
    unsafe { cpu_server_free_connection_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn cpu_server_close_connection(c: ConnectionJob, who: c_int) -> c_int {
    unsafe { cpu_server_close_connection_impl(c, who) }
}

#[no_mangle]
pub unsafe extern "C" fn cpu_server_read_write(c: ConnectionJob) -> c_int {
    unsafe { cpu_server_read_write_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn do_connection_job(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { do_connection_job_impl(job, op, jt) }
}

#[no_mangle]
pub unsafe extern "C" fn alloc_new_connection(
    cfd: c_int,
    ctj: ConnTargetJob,
    lcj: *mut c_void,
    basic_type: c_int,
    conn_type: *mut ConnType,
    conn_extra: *mut c_void,
    peer: c_uint,
    peer_ipv6: *mut u8,
    peer_port: c_int,
) -> ConnectionJob {
    unsafe {
        alloc_new_connection_impl(
            cfd, ctj, lcj, basic_type, conn_type, conn_extra, peer, peer_ipv6, peer_port,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn fail_socket_connection(c: *mut c_void, who: c_int) {
    unsafe { fail_socket_connection_impl(c, who) };
}

#[no_mangle]
pub unsafe extern "C" fn net_server_socket_free(c: *mut c_void) -> c_int {
    unsafe { net_server_socket_free_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn net_server_socket_reader(c: *mut c_void) -> c_int {
    unsafe { net_server_socket_reader_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn net_server_socket_writer(c: *mut c_void) -> c_int {
    unsafe { net_server_socket_writer_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn net_server_socket_read_write(c: *mut c_void) -> c_int {
    unsafe { net_server_socket_read_write_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn net_server_socket_read_write_gateway(
    fd: c_int,
    data: *mut c_void,
    ev: *mut c_void,
) -> c_int {
    unsafe { net_server_socket_read_write_gateway_impl(fd, data, ev) }
}

#[no_mangle]
pub unsafe extern "C" fn do_socket_connection_job(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { do_socket_connection_job_impl(job, op, jt) }
}

#[no_mangle]
pub unsafe extern "C" fn alloc_new_socket_connection(c: ConnectionJob) -> *mut c_void {
    unsafe { alloc_new_socket_connection_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn net_accept_new_connections(lcj: *mut c_void) -> c_int {
    unsafe { net_accept_new_connections_impl(lcj) }
}

#[no_mangle]
pub unsafe extern "C" fn do_listening_connection_job(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { do_listening_connection_job_impl(job, op, jt) }
}

#[no_mangle]
pub unsafe extern "C" fn init_listening_connection_ext(
    fd: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
    mode: c_int,
    prio: c_int,
) -> c_int {
    unsafe { init_listening_connection_ext_impl(fd, type_, extra, mode, prio) }
}

#[no_mangle]
pub unsafe extern "C" fn init_listening_connection(
    fd: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
) -> c_int {
    unsafe { init_listening_connection_impl(fd, type_, extra) }
}

#[no_mangle]
pub unsafe extern "C" fn init_listening_tcpv6_connection(
    fd: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
    mode: c_int,
) -> c_int {
    unsafe { init_listening_tcpv6_connection_impl(fd, type_, extra, mode) }
}

#[no_mangle]
pub unsafe extern "C" fn connection_event_incref(fd: c_int, val: c_longlong) {
    unsafe { connection_event_incref_impl(fd, val) };
}

#[no_mangle]
pub unsafe extern "C" fn connection_get_by_fd(fd: c_int) -> ConnectionJob {
    unsafe { connection_get_by_fd_impl(fd) }
}

#[no_mangle]
pub unsafe extern "C" fn connection_get_by_fd_generation(
    fd: c_int,
    generation: c_int,
) -> ConnectionJob {
    unsafe { connection_get_by_fd_generation_impl(fd, generation) }
}

#[no_mangle]
pub unsafe extern "C" fn server_check_ready(c: ConnectionJob) -> c_int {
    unsafe { server_check_ready_conn_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn server_noop(c: ConnectionJob) -> c_int {
    unsafe { server_noop_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn server_failed(c: ConnectionJob) -> c_int {
    unsafe { server_failed_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn server_flush(c: ConnectionJob) -> c_int {
    unsafe { server_flush_impl(c) }
}

#[no_mangle]
#[cfg(feature = "c-abi")]
pub unsafe extern "C" fn check_conn_functions(type_: *mut ConnType, listening: c_int) -> c_int {
    unsafe { check_conn_functions_impl(type_, listening) }
}

#[no_mangle]
pub unsafe extern "C" fn compute_next_reconnect(ct: ConnTargetJob) {
    unsafe { compute_next_reconnect_target_impl(ct) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_free_target(ctj: ConnTargetJob) -> c_int {
    unsafe { free_target_impl(ctj) }
}

#[no_mangle]
pub unsafe extern "C" fn clean_unused_target(ctj: ConnTargetJob) -> c_int {
    unsafe { clean_unused_target_impl(ctj) }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_target(ctj_tag_int: c_int, ctj: ConnTargetJob) -> c_int {
    unsafe { destroy_target_impl(ctj_tag_int, ctj) }
}

#[no_mangle]
pub unsafe extern "C" fn do_conn_target_job(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { do_conn_target_job_impl(job, op, jt) }
}

#[no_mangle]
pub unsafe extern "C" fn create_target(
    source: *mut ConnTargetInfo,
    was_created: *mut c_int,
) -> ConnTargetJob {
    unsafe { create_target_impl(source, was_created) }
}

#[no_mangle]
pub unsafe extern "C" fn conn_target_get_connection(
    ct: ConnTargetJob,
    allow_stopped: c_int,
) -> ConnectionJob {
    unsafe { conn_target_get_connection_impl(ct, allow_stopped) }
}

#[no_mangle]
pub unsafe extern "C" fn free_later_act() {
    unsafe { free_later_act_impl() };
}

#[no_mangle]
pub extern "C" fn create_all_outbound_connections_limited(_limit: c_int) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn create_all_outbound_connections() -> c_int {
    create_all_outbound_connections_limited(i32::MAX)
}

#[no_mangle]
pub unsafe extern "C" fn net_add_nat_info(str_: *mut c_char) -> c_int {
    unsafe { mtproxy_ffi_net_add_nat_info(str_.cast_const()) }
}

#[no_mangle]
pub unsafe extern "C" fn nat_translate_ip(local_ip: c_uint) -> c_uint {
    unsafe { mtproxy_ffi_net_translate_ip(local_ip) }
}

#[no_mangle]
pub extern "C" fn tcp_set_max_accept_rate(rate: c_int) {
    MAX_ACCEPT_RATE.store(rate, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_accept_rate_get_max() -> c_int {
    MAX_ACCEPT_RATE.load(Ordering::Relaxed)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_accept_rate_get_state(
    out_remaining: *mut c_double,
    out_time: *mut c_double,
) {
    unsafe {
        if !out_remaining.is_null() {
            *out_remaining = atomic_f64_load(&CUR_ACCEPT_RATE_REMAINING_BITS);
        }
        if !out_time.is_null() {
            *out_time = atomic_f64_load(&CUR_ACCEPT_RATE_TIME_BITS);
        }
    }
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_accept_rate_set_state(
    remaining: c_double,
    time: c_double,
) {
    atomic_f64_store(&CUR_ACCEPT_RATE_REMAINING_BITS, remaining);
    atomic_f64_store(&CUR_ACCEPT_RATE_TIME_BITS, time);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_get_max_connection_fd() -> c_int {
    MAX_CONNECTION_FD.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_get_max_connection() -> c_int {
    MAX_CONNECTION.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_set_max_connection(value: c_int) {
    MAX_CONNECTION.store(value, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn tcp_set_max_connections(maxconn: c_int) {
    MAX_CONNECTION_FD.store(maxconn, Ordering::Relaxed);
    unsafe {
        let max_special = atomic_i32_ref(ptr::addr_of_mut!(max_special_connections));
        let mut current = max_special.load(Ordering::SeqCst);
        while current == 0 || current > maxconn {
            match max_special.compare_exchange(
                current,
                maxconn,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn new_conn_generation() -> c_int {
    CONN_GENERATION.fetch_add(1, Ordering::SeqCst)
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_register_special_listen_socket(
    fd: c_int,
    generation: c_int,
) {
    let idx = SPECIAL_LISTEN_SOCKETS.fetch_add(1, Ordering::SeqCst);
    let idx_usize = usize::try_from(idx).unwrap_or(MAX_SPECIAL_LISTEN_SOCKETS);
    assert!(idx_usize < MAX_SPECIAL_LISTEN_SOCKETS);
    SPECIAL_SOCKET_FD[idx_usize].store(fd, Ordering::Relaxed);
    SPECIAL_SOCKET_GENERATION[idx_usize].store(generation, Ordering::Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_close_connection_signal_special_aux() {
    let count = SPECIAL_LISTEN_SOCKETS.load(Ordering::SeqCst);
    let limit = usize::try_from(count).unwrap_or(MAX_SPECIAL_LISTEN_SOCKETS);
    let limit = limit.min(MAX_SPECIAL_LISTEN_SOCKETS);
    for i in 0..limit {
        let fd = SPECIAL_SOCKET_FD[i].load(Ordering::Relaxed);
        let generation = SPECIAL_SOCKET_GENERATION[i].load(Ordering::Relaxed);
        let lc = unsafe { connection_get_by_fd_generation(fd, generation) };
        assert!(!lc.is_null());
        let lc_ref = unsafe { job_incref(lc.cast::<c_void>()) };
        unsafe { job_signal(1, lc_ref, JS_AUX) };
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_mpq_push_w(
    mq: *mut MpQueue,
    x: *mut c_void,
    flags: c_int,
) {
    let _ = unsafe { mpq_push_w(mq, x, flags) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_mpq_pop_nw(
    mq: *mut MpQueue,
    flags: c_int,
) -> *mut c_void {
    unsafe { mpq_pop_nw(mq, flags) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_rwm_union(
    raw: *mut RawMessage,
    tail: *mut RawMessage,
) -> c_int {
    unsafe { rwm_union(raw, tail) }
}

#[no_mangle]
pub unsafe extern "C" fn connections_prepare_stat(sb: *mut StatsBuffer) -> c_int {
    let max_accept_rate = MAX_ACCEPT_RATE.load(Ordering::Relaxed);
    let cur_accept_rate_remaining = atomic_f64_load(&CUR_ACCEPT_RATE_REMAINING_BITS);

    unsafe {
        sb_print_i32_key(
            sb,
            c"active_connections".as_ptr(),
            ACTIVE_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"active_dh_connections".as_ptr(),
            ACTIVE_DH_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"outbound_connections".as_ptr(),
            OUTBOUND_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"ready_outbound_connections".as_ptr(),
            READY_OUTBOUND_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"active_outbound_connections".as_ptr(),
            ACTIVE_OUTBOUND_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"outbound_connections_created".as_ptr(),
            OUTBOUND_CONNECTIONS_CREATED.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"total_connect_failures".as_ptr(),
            TOTAL_CONNECT_FAILURES.load(Ordering::Relaxed),
        );

        sb_print_i32_key(
            sb,
            c"inbound_connections".as_ptr(),
            INBOUND_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"active_inbound_connections".as_ptr(),
            ACTIVE_INBOUND_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"inbound_connections_accepted".as_ptr(),
            INBOUND_CONNECTIONS_ACCEPTED.load(Ordering::Relaxed),
        );

        sb_print_i32_key(
            sb,
            c"listening_connections".as_ptr(),
            LISTENING_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"unused_connections_closed".as_ptr(),
            UNUSED_CONNECTIONS_CLOSED.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"ready_targets".as_ptr(),
            READY_TARGETS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"allocated_targets".as_ptr(),
            ALLOCATED_TARGETS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"active_targets".as_ptr(),
            ACTIVE_TARGETS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"inactive_targets".as_ptr(),
            INACTIVE_TARGETS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"free_targets".as_ptr(),
            FREE_TARGETS.load(Ordering::Relaxed),
        );

            crate::sb_printf_fmt!(
                sb,
                c"max_connections\t%d\nactive_special_connections\t%d\nmax_special_connections\t%d\n"
                    .as_ptr(),
                MAX_CONNECTION_FD.load(Ordering::Relaxed),
                atomic_i32_load(&raw mut active_special_connections),
                atomic_i32_load(&raw mut max_special_connections),
            );
        sb_print_i32_key(sb, c"max_accept_rate".as_ptr(), max_accept_rate);
        sb_print_double_key(
            sb,
            c"cur_accept_rate_remaining".as_ptr(),
            cur_accept_rate_remaining,
        );
        sb_print_i32_key(
            sb,
            c"max_connection".as_ptr(),
            MAX_CONNECTION.load(Ordering::Relaxed),
        );
        sb_print_i32_key(sb, c"conn_generation".as_ptr(), CONN_GENERATION.load(Ordering::SeqCst));

        sb_print_i32_key(
            sb,
            c"allocated_connections".as_ptr(),
            ALLOCATED_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"allocated_outbound_connections".as_ptr(),
            ALLOCATED_OUTBOUND_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"allocated_inbound_connections".as_ptr(),
            ALLOCATED_INBOUND_CONNECTIONS.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"allocated_socket_connections".as_ptr(),
            ALLOCATED_SOCKET_CONNECTIONS.load(Ordering::Relaxed),
        );

        sb_print_i64_key(
            sb,
            c"tcp_readv_calls".as_ptr(),
            TCP_READV_CALLS.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"tcp_readv_intr".as_ptr(),
            TCP_READV_INTR.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"tcp_readv_bytes".as_ptr(),
            TCP_READV_BYTES.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"tcp_writev_calls".as_ptr(),
            TCP_WRITEV_CALLS.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"tcp_writev_intr".as_ptr(),
            TCP_WRITEV_INTR.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"tcp_writev_bytes".as_ptr(),
            TCP_WRITEV_BYTES.load(Ordering::Relaxed),
        );
        sb_print_i32_key(
            sb,
            c"free_later_size".as_ptr(),
            FREE_LATER_SIZE.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"free_later_total".as_ptr(),
            FREE_LATER_TOTAL.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"accept_calls_failed".as_ptr(),
            ACCEPT_CALLS_FAILED.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"accept_nonblock_set_failed".as_ptr(),
            ACCEPT_NONBLOCK_SET_FAILED.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"accept_connection_limit_failed".as_ptr(),
            ACCEPT_CONNECTION_LIMIT_FAILED.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"accept_rate_limit_failed".as_ptr(),
            ACCEPT_RATE_LIMIT_FAILED.load(Ordering::Relaxed),
        );
        sb_print_i64_key(
            sb,
            c"accept_init_accepted_failed".as_ptr(),
            ACCEPT_INIT_ACCEPTED_FAILED.load(Ordering::Relaxed),
        );
        (*sb).pos
    }
}

#[no_mangle]
pub unsafe extern "C" fn fetch_connections_stat(st: *mut ConnectionsStat) {
    unsafe {
        (*st).active_connections = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
        (*st).active_dh_connections = ACTIVE_DH_CONNECTIONS.load(Ordering::Relaxed);
        (*st).outbound_connections = OUTBOUND_CONNECTIONS.load(Ordering::Relaxed);
        (*st).active_outbound_connections = ACTIVE_OUTBOUND_CONNECTIONS.load(Ordering::Relaxed);
        (*st).ready_outbound_connections = READY_OUTBOUND_CONNECTIONS.load(Ordering::Relaxed);
        (*st).max_special_connections = atomic_i32_load(&raw mut max_special_connections);
        (*st).active_special_connections = atomic_i32_load(&raw mut active_special_connections);
        (*st).allocated_connections = ALLOCATED_CONNECTIONS.load(Ordering::Relaxed);
        (*st).allocated_outbound_connections =
            ALLOCATED_OUTBOUND_CONNECTIONS.load(Ordering::Relaxed);
        (*st).allocated_inbound_connections = ALLOCATED_INBOUND_CONNECTIONS.load(Ordering::Relaxed);
        (*st).allocated_socket_connections = ALLOCATED_SOCKET_CONNECTIONS.load(Ordering::Relaxed);
        (*st).allocated_targets = ALLOCATED_TARGETS.load(Ordering::Relaxed);
        (*st).ready_targets = READY_TARGETS.load(Ordering::Relaxed);
        (*st).active_targets = ACTIVE_TARGETS.load(Ordering::Relaxed);
        (*st).inactive_targets = INACTIVE_TARGETS.load(Ordering::Relaxed);
        (*st).tcp_readv_calls = TCP_READV_CALLS.load(Ordering::Relaxed);
        (*st).tcp_readv_intr = TCP_READV_INTR.load(Ordering::Relaxed);
        (*st).tcp_readv_bytes = TCP_READV_BYTES.load(Ordering::Relaxed);
        (*st).tcp_writev_calls = TCP_WRITEV_CALLS.load(Ordering::Relaxed);
        (*st).tcp_writev_intr = TCP_WRITEV_INTR.load(Ordering::Relaxed);
        (*st).tcp_writev_bytes = TCP_WRITEV_BYTES.load(Ordering::Relaxed);
        (*st).accept_calls_failed = ACCEPT_CALLS_FAILED.load(Ordering::Relaxed);
        (*st).accept_nonblock_set_failed = ACCEPT_NONBLOCK_SET_FAILED.load(Ordering::Relaxed);
        (*st).accept_rate_limit_failed = ACCEPT_RATE_LIMIT_FAILED.load(Ordering::Relaxed);
        (*st).accept_init_accepted_failed = ACCEPT_INIT_ACCEPTED_FAILED.load(Ordering::Relaxed);
        (*st).accept_connection_limit_failed =
            ACCEPT_CONNECTION_LIMIT_FAILED.load(Ordering::Relaxed);
    }
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stats_add(
    allocated_socket_connections_delta: c_int,
    accept_calls_failed_delta: c_longlong,
    inbound_accepted_delta: c_longlong,
    accept_rate_limit_failed_delta: c_longlong,
) {
    ALLOCATED_SOCKET_CONNECTIONS.fetch_add(allocated_socket_connections_delta, Ordering::Relaxed);
    ACCEPT_CALLS_FAILED.fetch_add(accept_calls_failed_delta, Ordering::Relaxed);
    INBOUND_CONNECTIONS_ACCEPTED.fetch_add(inbound_accepted_delta, Ordering::Relaxed);
    ACCEPT_RATE_LIMIT_FAILED.fetch_add(accept_rate_limit_failed_delta, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stat_inc_listening() {
    LISTENING_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stats_add_ready(
    ready_outbound_delta: c_int,
    ready_targets_delta: c_int,
) {
    READY_OUTBOUND_CONNECTIONS.fetch_add(ready_outbound_delta, Ordering::Relaxed);
    READY_TARGETS.fetch_add(ready_targets_delta, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stats_add_targets(
    active_targets_delta: c_int,
    inactive_targets_delta: c_int,
) {
    ACTIVE_TARGETS.fetch_add(active_targets_delta, Ordering::Relaxed);
    INACTIVE_TARGETS.fetch_add(inactive_targets_delta, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stat_add_allocated_targets(delta: c_int) {
    ALLOCATED_TARGETS.fetch_add(delta, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stat_target_freed() {
    INACTIVE_TARGETS.fetch_sub(1, Ordering::Relaxed);
    FREE_TARGETS.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stat_free_later_enqueued() {
    FREE_LATER_SIZE.fetch_add(1, Ordering::Relaxed);
    FREE_LATER_TOTAL.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stat_free_later_dequeued() {
    FREE_LATER_SIZE.fetch_sub(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stat_inc_accept_nonblock_set_failed() {
    ACCEPT_NONBLOCK_SET_FAILED.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stat_inc_accept_connection_limit_failed() {
    ACCEPT_CONNECTION_LIMIT_FAILED.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stats_add_alloc_connection_success(
    outbound_delta: c_int,
    allocated_outbound_delta: c_int,
    outbound_created_delta: c_int,
    inbound_accepted_delta: c_int,
    allocated_inbound_delta: c_int,
    inbound_delta: c_int,
    active_inbound_delta: c_int,
    active_connections_delta: c_int,
) {
    OUTBOUND_CONNECTIONS.fetch_add(outbound_delta, Ordering::Relaxed);
    ALLOCATED_OUTBOUND_CONNECTIONS.fetch_add(allocated_outbound_delta, Ordering::Relaxed);
    OUTBOUND_CONNECTIONS_CREATED.fetch_add(c_longlong::from(outbound_created_delta), Ordering::Relaxed);
    INBOUND_CONNECTIONS_ACCEPTED.fetch_add(c_longlong::from(inbound_accepted_delta), Ordering::Relaxed);
    ALLOCATED_INBOUND_CONNECTIONS.fetch_add(allocated_inbound_delta, Ordering::Relaxed);
    INBOUND_CONNECTIONS.fetch_add(inbound_delta, Ordering::Relaxed);
    ACTIVE_INBOUND_CONNECTIONS.fetch_add(active_inbound_delta, Ordering::Relaxed);
    ACTIVE_CONNECTIONS.fetch_add(active_connections_delta, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stat_inc_allocated_connections() {
    ALLOCATED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stat_inc_accept_init_accepted_failed() {
    ACCEPT_INIT_ACCEPTED_FAILED.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stats_add_tcp_read(
    calls_delta: c_longlong,
    intr_delta: c_longlong,
    bytes_delta: c_longlong,
) {
    TCP_READV_CALLS.fetch_add(calls_delta, Ordering::Relaxed);
    TCP_READV_INTR.fetch_add(intr_delta, Ordering::Relaxed);
    TCP_READV_BYTES.fetch_add(bytes_delta, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stats_add_tcp_write(
    calls_delta: c_longlong,
    intr_delta: c_longlong,
    bytes_delta: c_longlong,
) {
    TCP_WRITEV_CALLS.fetch_add(calls_delta, Ordering::Relaxed);
    TCP_WRITEV_INTR.fetch_add(intr_delta, Ordering::Relaxed);
    TCP_WRITEV_BYTES.fetch_add(bytes_delta, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stats_add_close_failure(
    total_failed_delta: c_int,
    total_connect_failures_delta: c_int,
    unused_closed_delta: c_int,
) {
    TOTAL_FAILED_CONNECTIONS.fetch_add(c_longlong::from(total_failed_delta), Ordering::Relaxed);
    TOTAL_CONNECT_FAILURES.fetch_add(c_longlong::from(total_connect_failures_delta), Ordering::Relaxed);
    UNUSED_CONNECTIONS_CLOSED.fetch_add(c_longlong::from(unused_closed_delta), Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stat_dec_active_dh() {
    ACTIVE_DH_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn incr_active_dh_connections() {
    ACTIVE_DH_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stats_add_close_basic(
    outbound_delta: c_int,
    inbound_delta: c_int,
    active_outbound_delta: c_int,
    active_inbound_delta: c_int,
    active_connections_delta: c_int,
) {
    OUTBOUND_CONNECTIONS.fetch_add(outbound_delta, Ordering::Relaxed);
    INBOUND_CONNECTIONS.fetch_add(inbound_delta, Ordering::Relaxed);
    ACTIVE_OUTBOUND_CONNECTIONS.fetch_add(active_outbound_delta, Ordering::Relaxed);
    ACTIVE_INBOUND_CONNECTIONS.fetch_add(active_inbound_delta, Ordering::Relaxed);
    ACTIVE_CONNECTIONS.fetch_add(active_connections_delta, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_stats_add_free_connection_counts(
    allocated_outbound_delta: c_int,
    allocated_inbound_delta: c_int,
) {
    ALLOCATED_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    ALLOCATED_OUTBOUND_CONNECTIONS.fetch_add(allocated_outbound_delta, Ordering::Relaxed);
    ALLOCATED_INBOUND_CONNECTIONS.fetch_add(allocated_inbound_delta, Ordering::Relaxed);
}

// ============================================================================
// Bridge function migrated from net/net-connections.c  
// ============================================================================

/// Returns thread-local precise_now value (migrated from net/net-connections.c)
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_precise_now() -> c_double {
    crate::mtproxy_ffi_precise_time_get_precise_now()
}
