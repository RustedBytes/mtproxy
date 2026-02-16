//! Rust runtime implementation for selected large functions in
//! `net/net-rpc-targets.c`.

use crate::vv_tree::{
    free_tree_ptr_connection, get_tree_ptr_connection, mtproxy_ffi_rpc_target_tree,
    mtproxy_ffi_rpc_target_tree_acquire, mtproxy_ffi_rpc_target_tree_insert,
    mtproxy_ffi_rpc_target_tree_lookup, mtproxy_ffi_rpc_target_tree_release,
    tree_act_ex2_connection, tree_act_ex3_connection, tree_connection as TreeConnection,
    tree_delete_connection, tree_free_connection, tree_insert_connection,
    tree_lookup_ptr_connection,
};
use crate::MtproxyProcessId;
use core::ffi::{c_char, c_double, c_int, c_long, c_uint, c_void};
use core::mem::{align_of, size_of};
use core::ptr;
use core::sync::atomic::{fence, Ordering};

pub(super) type Job = *mut c_void;
pub(super) type ConnectionJob = Job;
pub(super) type ConnTargetJob = Job;
pub(super) type RpcTargetJob = Job;

const CONN_CUSTOM_DATA_BYTES: usize = 256;

const C_ERROR: c_int = 0x8;
const C_FAILED: c_int = 0x80;
const C_NET_FAILED: c_int = 0x80_000;

const CR_OK: c_int = 1;
const CR_STOPPED: c_int = 2;

const RPC_TARGET_INSERT_LOG_FMT: &[u8] =
    b"rpc_target_insert_conn: ip = %d.%d.%d.%d, port = %d, fd = %d\n\0";
const RPC_TARGETS_TOTAL_FMT: &[u8] = b"total_rpc_targets\t%lld\n\0";
const RPC_TARGETS_TOTAL_CONNECTIONS_FMT: &[u8] = b"total_connections_in_rpc_targets\t%lld\n\0";

type ConnFn1 = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type ConnFn2 = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnWakeupAioFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnWritePacketFn = Option<unsafe extern "C" fn(ConnectionJob, *mut RawMessage) -> c_int>;
type ConnCryptoInitFn = Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, c_int) -> c_int>;

#[repr(C)]
struct EventTimer {
    h_idx: c_int,
    flags: c_int,
    wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> c_int>,
    wakeup_time: c_double,
    real_wakeup_time: c_double,
}

#[repr(C)]
struct RawMessage {
    first: *mut c_void,
    last: *mut c_void,
    total_bytes: c_int,
    magic: c_int,
    first_offset: c_int,
    last_offset: c_int,
}

#[repr(C)]
struct MpQueue {
    _priv: [u8; 0],
}

#[repr(C)]
struct ConnType {
    magic: c_int,
    flags: c_int,
    title: *mut c_char,
    accept: ConnFn1,
    init_accepted: ConnFn1,
    reader: ConnFn1,
    writer: ConnFn1,
    close: ConnFn2,
    parse_execute: ConnFn1,
    init_outbound: ConnFn1,
    connected: ConnFn1,
    check_ready: ConnFn1,
    wakeup_aio: ConnWakeupAioFn,
    write_packet: ConnWritePacketFn,
    flush: ConnFn1,
    free: ConnFn1,
    free_buffers: ConnFn1,
    read_write: ConnFn1,
    wakeup: ConnFn1,
    alarm: ConnFn1,
    socket_read_write: ConnFn1,
    socket_reader: ConnFn1,
    socket_writer: ConnFn1,
    socket_connected: ConnFn1,
    socket_free: ConnFn1,
    socket_close: ConnFn1,
    data_received: ConnFn2,
    data_sent: ConnFn2,
    ready_to_write: ConnFn1,
    crypto_init: ConnCryptoInitFn,
    crypto_free: ConnFn1,
    crypto_encrypt_output: ConnFn1,
    crypto_decrypt_input: ConnFn1,
    crypto_needed_output_bytes: ConnFn1,
}

#[repr(C)]
struct ConnectionInfo {
    timer: EventTimer,
    fd: c_int,
    generation: c_int,
    flags: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
    target: Job,
    io_conn: Job,
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
    in_u: RawMessage,
    in_data: RawMessage,
    out: RawMessage,
    out_p: RawMessage,
    in_queue: *mut MpQueue,
    out_queue: *mut MpQueue,
}

type Crc32PartialFn = Option<unsafe extern "C" fn(*const c_void, c_long, c_uint) -> c_uint>;

#[repr(C)]
struct TcpRpcData {
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
    extra_double: c_double,
    extra_double2: c_double,
    custom_crc_partial: Crc32PartialFn,
}

#[repr(C)]
struct RpcTargetInfo {
    timer: EventTimer,
    a: c_int,
    b: c_int,
    conn_tree: *mut TreeConnection,
    pid: MtproxyProcessId,
}

#[repr(C)]
pub(super) struct RpcTargetsModuleStat {
    pub total_rpc_targets: i64,
    pub total_connections_in_rpc_targets: i64,
}

#[repr(C)]
struct ConnTargetInfo {
    timer: EventTimer,
    min_connections: c_int,
    max_connections: c_int,
    conn_tree: *mut TreeConnection,
    type_: *mut ConnType,
    extra: *mut c_void,
    target: libc::in_addr,
    target_ipv6: [u8; 16],
    port: c_int,
    active_outbound_connections: c_int,
    outbound_connections: c_int,
    ready_outbound_connections: c_int,
    next_reconnect: c_double,
    reconnect_timeout: c_double,
    next_reconnect_timeout: c_double,
    custom_field: c_int,
}

#[repr(C)]
struct StatsBuffer {
    buff: *mut c_char,
    pos: c_int,
    size: c_int,
    flags: c_int,
}

#[repr(C, align(64))]
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
struct ConnectionChooseExtra {
    arr: *mut ConnectionJob,
    limit: c_int,
    pos: c_int,
    count: c_int,
}

unsafe extern "C" {
    static mut verbosity: c_int;

    fn assert_engine_thread();
    fn assert_net_cpu_thread();

    fn mtproxy_ffi_rpc_target_is_fast_thread() -> c_int;
    fn lrand48_j() -> c_long;
    fn job_incref(job: Job) -> Job;
    fn job_decref(job_tag_int: c_int, job: Job);
    fn matches_pid(x: *mut MtproxyProcessId, y: *mut MtproxyProcessId) -> c_int;
    fn kprintf(format: *const c_char, ...);
    fn sb_printf(sb: *mut StatsBuffer, format: *const c_char, ...);
}

#[inline]
fn abort_now() -> ! {
    unsafe { libc::abort() }
}

#[inline]
fn assert_or_abort(cond: bool) {
    if !cond {
        abort_now();
    }
}

#[inline]
fn normalize_pid(pid: &mut MtproxyProcessId, default_ip: u32) {
    if pid.ip == 0 {
        pid.ip = default_ip;
    }
}

#[inline]
unsafe fn job_custom_ptr<T>(job: Job) -> *mut T {
    unsafe { ptr::addr_of_mut!((*job.cast::<AsyncJob>()).j_custom).cast::<T>() }
}

#[inline]
unsafe fn conn_info(c: ConnectionJob) -> *mut ConnectionInfo {
    unsafe { job_custom_ptr(c) }
}

#[inline]
unsafe fn rpc_data(c: ConnectionJob) -> *mut TcpRpcData {
    let conn = unsafe { conn_info(c) };
    let base = ptr::addr_of!((*conn).custom_data).cast::<u8>() as usize;
    let align = align_of::<TcpRpcData>();
    let aligned = (base + align - 1) & !(align - 1);
    aligned as *mut TcpRpcData
}

#[inline]
unsafe fn rpc_target_info(target: RpcTargetJob) -> *mut RpcTargetInfo {
    unsafe { job_custom_ptr(target) }
}

#[inline]
unsafe fn conn_target_info(target: ConnTargetJob) -> *mut ConnTargetInfo {
    unsafe { job_custom_ptr(target) }
}

#[inline]
fn is_fast_engine_thread() -> bool {
    unsafe { mtproxy_ffi_rpc_target_is_fast_thread() != 0 }
}

#[inline]
unsafe fn pid_matches_filter(
    remote_pid: *mut MtproxyProcessId,
    pid: *const MtproxyProcessId,
) -> bool {
    pid.is_null() || unsafe { matches_pid(remote_pid, pid as *mut MtproxyProcessId) } >= 1
}

#[inline]
unsafe fn rpc_target_log(pid: &MtproxyProcessId, fd: c_int) {
    if unsafe { verbosity } < 2 {
        return;
    }

    unsafe {
        kprintf(
            RPC_TARGET_INSERT_LOG_FMT.as_ptr().cast(),
            ((pid.ip >> 24) & 0xff) as c_int,
            ((pid.ip >> 16) & 0xff) as c_int,
            ((pid.ip >> 8) & 0xff) as c_int,
            (pid.ip & 0xff) as c_int,
            pid.port as c_int,
            fd,
        )
    };
}

unsafe fn rpc_target_alloc(
    tree_slot: *mut *mut mtproxy_ffi_rpc_target_tree,
    module_stat_tls: *mut RpcTargetsModuleStat,
    mut pid: MtproxyProcessId,
    default_ip: u32,
) -> RpcTargetJob {
    unsafe { assert_engine_thread() };
    normalize_pid(&mut pid, default_ip);

    let total_bytes = size_of::<AsyncJob>() + size_of::<RpcTargetInfo>();
    let target = unsafe { libc::calloc(total_bytes, 1) };
    assert_or_abort(!target.is_null());

    let info = unsafe { rpc_target_info(target) };
    unsafe {
        (*info).pid = pid;
    }

    let old = unsafe { mtproxy_ffi_rpc_target_tree_acquire(*tree_slot) };
    unsafe {
        *tree_slot = mtproxy_ffi_rpc_target_tree_insert(*tree_slot, &pid, target);
        (*module_stat_tls).total_rpc_targets += 1;
    }
    unsafe { mtproxy_ffi_rpc_target_tree_release(old) };

    target
}

unsafe extern "C" fn check_connection_cb(
    c: ConnectionJob,
    ex: *mut c_void,
    ex2: *mut c_void,
    ex3: *mut c_void,
) {
    let best_unr = ex2.cast::<c_int>();
    let result = ex.cast::<ConnectionJob>();
    assert_or_abort(!best_unr.is_null());
    assert_or_abort(!result.is_null());

    if unsafe { *best_unr } < 0 {
        return;
    }

    let pid = ex3.cast::<MtproxyProcessId>();
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };

    let type_ = unsafe { (*conn).type_ };
    assert_or_abort(!type_.is_null());
    let Some(check_ready) = (unsafe { (*type_).check_ready }) else {
        abort_now();
    };
    let ready = unsafe { check_ready(c) };

    if (unsafe { (*conn).flags } & (C_ERROR | C_FAILED | C_NET_FAILED)) != 0
        || unsafe { (*conn).error } != 0
    {
        return;
    }

    if ready == CR_OK {
        if unsafe { pid_matches_filter(ptr::addr_of_mut!((*data).remote_pid), pid) } {
            unsafe {
                *best_unr = -1;
                *result = c;
            }
        }
    } else if ready == CR_STOPPED && unsafe { (*conn).unreliability } < unsafe { *best_unr } {
        if unsafe { pid_matches_filter(ptr::addr_of_mut!((*data).remote_pid), pid) } {
            unsafe {
                *best_unr = (*conn).unreliability;
                *result = c;
            }
        }
    }
}

unsafe extern "C" fn check_connection_arr_cb(c: ConnectionJob, ex: *mut c_void, ex2: *mut c_void) {
    let extra = ex.cast::<ConnectionChooseExtra>();
    assert_or_abort(!extra.is_null());

    let pid = ex2.cast::<MtproxyProcessId>();
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };

    let type_ = unsafe { (*conn).type_ };
    assert_or_abort(!type_.is_null());
    let Some(check_ready) = (unsafe { (*type_).check_ready }) else {
        abort_now();
    };
    let ready = unsafe { check_ready(c) };

    if (unsafe { (*conn).flags } & (C_ERROR | C_FAILED | C_NET_FAILED)) != 0
        || unsafe { (*conn).error } != 0
        || ready != CR_OK
    {
        return;
    }
    if !pid.is_null() && unsafe { matches_pid(ptr::addr_of_mut!((*data).remote_pid), pid) } < 1 {
        return;
    }

    if unsafe { (*extra).pos } < unsafe { (*extra).limit } {
        unsafe {
            *(*extra).arr.add((*extra).pos as usize) = c;
            (*extra).pos += 1;
        }
    } else {
        let t = unsafe { lrand48_j() } % (unsafe { (*extra).count + 1 }) as c_long;
        if (t as c_int) < unsafe { (*extra).limit } {
            unsafe {
                *(*extra).arr.add(t as usize) = c;
            }
        }
    }
    unsafe {
        (*extra).count += 1;
    }
}

pub(super) unsafe fn rpc_target_insert_conn_impl(
    c: ConnectionJob,
    tree_slot: *mut *mut mtproxy_ffi_rpc_target_tree,
    module_stat_tls: *mut RpcTargetsModuleStat,
    default_ip: u32,
) -> c_int {
    if c.is_null() || tree_slot.is_null() || module_stat_tls.is_null() {
        return -1;
    }

    unsafe { assert_engine_thread() };
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };

    if (unsafe { (*conn).flags } & (C_ERROR | C_NET_FAILED | C_FAILED)) != 0 {
        return 0;
    }
    if unsafe { (*data).in_rpc_target } != 0 {
        return 0;
    }

    unsafe { assert_net_cpu_thread() };

    let mut pid = unsafe { (*data).remote_pid };
    normalize_pid(&mut pid, default_ip);
    unsafe { rpc_target_log(&pid, (*conn).fd) };

    let mut target = unsafe { mtproxy_ffi_rpc_target_tree_lookup(*tree_slot, &pid) };
    if target.is_null() {
        target = unsafe { rpc_target_alloc(tree_slot, module_stat_tls, pid, default_ip) };
    }

    let info = unsafe { rpc_target_info(target) };
    let existing_conn = unsafe { tree_lookup_ptr_connection((*info).conn_tree, c) };
    assert_or_abort(existing_conn.is_null());

    let old = unsafe { get_tree_ptr_connection(ptr::addr_of_mut!((*info).conn_tree)) };
    unsafe {
        (*info).conn_tree =
            tree_insert_connection((*info).conn_tree, job_incref(c), lrand48_j() as c_int);
        (*module_stat_tls).total_connections_in_rpc_targets += 1;
    }

    fence(Ordering::SeqCst);
    unsafe { free_tree_ptr_connection(old) };

    unsafe {
        (*data).in_rpc_target = 1;
    }

    0
}

pub(super) unsafe fn rpc_target_delete_conn_impl(
    c: ConnectionJob,
    tree_slot: *mut *mut mtproxy_ffi_rpc_target_tree,
    module_stat_tls: *mut RpcTargetsModuleStat,
    default_ip: u32,
) -> c_int {
    if c.is_null() || tree_slot.is_null() || module_stat_tls.is_null() {
        return -1;
    }

    unsafe { assert_engine_thread() };
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };

    if unsafe { (*data).in_rpc_target } == 0 {
        return 0;
    }

    unsafe { assert_net_cpu_thread() };

    let mut pid = unsafe { (*data).remote_pid };
    normalize_pid(&mut pid, default_ip);
    unsafe { rpc_target_log(&pid, (*conn).fd) };

    let mut target = unsafe { mtproxy_ffi_rpc_target_tree_lookup(*tree_slot, &pid) };
    if target.is_null() {
        target = unsafe { rpc_target_alloc(tree_slot, module_stat_tls, pid, default_ip) };
    }

    let info = unsafe { rpc_target_info(target) };
    let existing_conn = unsafe { tree_lookup_ptr_connection((*info).conn_tree, c) };
    assert_or_abort(!existing_conn.is_null());

    let old = unsafe { get_tree_ptr_connection(ptr::addr_of_mut!((*info).conn_tree)) };
    unsafe {
        (*info).conn_tree = tree_delete_connection((*info).conn_tree, c);
        (*module_stat_tls).total_connections_in_rpc_targets -= 1;
    }

    fence(Ordering::SeqCst);
    unsafe { free_tree_ptr_connection(old) };

    unsafe {
        (*data).in_rpc_target = 0;
    }

    0
}

pub(super) unsafe fn rpc_target_lookup_runtime_impl(
    tree: *mut mtproxy_ffi_rpc_target_tree,
    pid: *const MtproxyProcessId,
    default_ip: u32,
) -> RpcTargetJob {
    assert_or_abort(!pid.is_null());

    let mut normalized = unsafe { *pid };
    normalize_pid(&mut normalized, default_ip);

    let fast = is_fast_engine_thread();
    let active_tree = if fast {
        tree
    } else {
        unsafe { mtproxy_ffi_rpc_target_tree_acquire(tree) }
    };

    let target = unsafe { mtproxy_ffi_rpc_target_tree_lookup(active_tree, &normalized) };
    if !fast {
        unsafe { mtproxy_ffi_rpc_target_tree_release(active_tree) };
    }
    target
}

pub(super) unsafe fn rpc_target_choose_connection_runtime_impl(
    target: RpcTargetJob,
    pid: *const MtproxyProcessId,
) -> ConnectionJob {
    if target.is_null() {
        return ptr::null_mut();
    }

    let fast = is_fast_engine_thread();
    let info = unsafe { rpc_target_info(target) };
    let tree = if fast {
        unsafe { (*info).conn_tree }
    } else {
        unsafe { get_tree_ptr_connection(ptr::addr_of_mut!((*info).conn_tree)) }
    };
    if tree.is_null() {
        if !fast {
            unsafe { tree_free_connection(tree) };
        }
        return ptr::null_mut();
    }

    let mut result: ConnectionJob = ptr::null_mut();
    let mut best_unr: c_int = 10_000;
    unsafe {
        tree_act_ex3_connection(
            tree,
            check_connection_cb,
            ptr::addr_of_mut!(result).cast(),
            ptr::addr_of_mut!(best_unr).cast(),
            pid as *mut c_void,
        );
    }

    if !result.is_null() {
        unsafe { job_incref(result) };
    }
    if !fast {
        unsafe { tree_free_connection(tree) };
    }

    result
}

pub(super) unsafe fn rpc_target_choose_random_connections_runtime_impl(
    target: RpcTargetJob,
    pid: *const MtproxyProcessId,
    limit: c_int,
    buf: *mut ConnectionJob,
) -> c_int {
    if target.is_null() {
        return 0;
    }

    let mut extra = ConnectionChooseExtra {
        arr: buf,
        limit,
        pos: 0,
        count: 0,
    };

    let fast = is_fast_engine_thread();
    let info = unsafe { rpc_target_info(target) };
    let tree = if fast {
        unsafe { (*info).conn_tree }
    } else {
        unsafe { get_tree_ptr_connection(ptr::addr_of_mut!((*info).conn_tree)) }
    };
    if tree.is_null() {
        if !fast {
            unsafe { tree_free_connection(tree) };
        }
        return 0;
    }

    unsafe {
        tree_act_ex2_connection(
            tree,
            check_connection_arr_cb,
            ptr::addr_of_mut!(extra).cast(),
            pid as *mut c_void,
        );
    }

    let mut i = 0;
    while i < extra.pos {
        unsafe {
            job_incref(*buf.add(i as usize));
        }
        i += 1;
    }

    if !fast {
        unsafe { tree_free_connection(tree) };
    }

    extra.pos
}

unsafe fn rpc_targets_stats_totals(
    module_stat_array: *mut *mut c_void,
    module_stat_len: c_int,
) -> (i64, i64) {
    if module_stat_array.is_null() || module_stat_len <= 0 {
        return (0, 0);
    }

    let mut total_rpc_targets = 0_i64;
    let mut total_connections = 0_i64;
    let mut i = 0;
    while i < module_stat_len {
        let stat_ptr = unsafe { *module_stat_array.add(i as usize) };
        if !stat_ptr.is_null() {
            let stat = stat_ptr.cast::<RpcTargetsModuleStat>();
            total_rpc_targets += unsafe { (*stat).total_rpc_targets };
            total_connections += unsafe { (*stat).total_connections_in_rpc_targets };
        }
        i += 1;
    }

    (total_rpc_targets, total_connections)
}

pub(super) unsafe fn rpc_targets_prepare_stat_runtime_impl(
    sb: *mut c_void,
    module_stat_array: *mut *mut c_void,
    module_stat_len: c_int,
) -> c_int {
    if sb.is_null() {
        return -1;
    }

    let sb = sb.cast::<StatsBuffer>();
    let (total_rpc_targets, total_connections) =
        unsafe { rpc_targets_stats_totals(module_stat_array, module_stat_len) };
    unsafe {
        sb_printf(sb, RPC_TARGETS_TOTAL_FMT.as_ptr().cast(), total_rpc_targets);
        sb_printf(
            sb,
            RPC_TARGETS_TOTAL_CONNECTIONS_FMT.as_ptr().cast(),
            total_connections,
        );
    }
    unsafe { (*sb).pos }
}

pub(super) unsafe fn rpc_target_lookup_impl(
    tree: *mut mtproxy_ffi_rpc_target_tree,
    pid: *const MtproxyProcessId,
    default_ip: u32,
) -> RpcTargetJob {
    unsafe { rpc_target_lookup_runtime_impl(tree, pid, default_ip) }
}

pub(super) unsafe fn rpc_target_lookup_hp_impl(
    tree: *mut mtproxy_ffi_rpc_target_tree,
    ip: u32,
    port: c_int,
    default_ip: u32,
) -> RpcTargetJob {
    let pid = MtproxyProcessId {
        ip,
        port: port as i16,
        pid: 0,
        utime: 0,
    };
    unsafe { rpc_target_lookup_runtime_impl(tree, ptr::addr_of!(pid), default_ip) }
}

pub(super) unsafe fn rpc_target_lookup_target_runtime_impl(
    target: ConnTargetJob,
    tree: *mut mtproxy_ffi_rpc_target_tree,
    default_ip: u32,
) -> RpcTargetJob {
    if target.is_null() {
        return ptr::null_mut();
    }

    let info = unsafe { conn_target_info(target) };
    let ip = unsafe { (*info).custom_field };
    if ip == -1 {
        return ptr::null_mut();
    }

    unsafe { rpc_target_lookup_hp_impl(tree, ip as u32, (*info).port, default_ip) }
}

pub(super) unsafe fn rpc_target_get_state_runtime_impl(
    target: RpcTargetJob,
    pid: *const MtproxyProcessId,
) -> c_int {
    let connection = unsafe { rpc_target_choose_connection_runtime_impl(target, pid) };
    if connection.is_null() {
        return -1;
    }

    let conn = unsafe { conn_info(connection) };
    let type_ = unsafe { (*conn).type_ };
    assert_or_abort(!type_.is_null());

    let Some(check_ready) = (unsafe { (*type_).check_ready }) else {
        abort_now();
    };
    let ready = unsafe { check_ready(connection) };
    unsafe { job_decref(1, connection) };

    if ready == CR_OK {
        1
    } else {
        0
    }
}
