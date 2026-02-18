//! Legacy `net/net-rpc-targets.c` compatibility exports.

use crate::vv_tree::mtproxy_ffi_rpc_target_tree;
use crate::MtproxyProcessId;
use core::ffi::{c_int, c_void};
use core::ptr;
use std::cell::Cell;
use std::thread_local;

type Job = *mut c_void;
type ConnectionJob = Job;
type RpcTargetJob = Job;

const MAX_JOB_THREADS: usize = 256;
const JC_ENGINE: c_int = 8;

#[repr(C)]
struct JobThread {
    pthread_id: usize,
    id: c_int,
    thread_class: c_int,
}

#[repr(C)]
struct RpcTargetsModuleStat {
    total_rpc_targets: i64,
    total_connections_in_rpc_targets: i64,
}

const ZERO_RPC_TARGETS_MODULE_STAT: RpcTargetsModuleStat = RpcTargetsModuleStat {
    total_rpc_targets: 0,
    total_connections_in_rpc_targets: 0,
};

thread_local! {
    static RPC_TARGETS_MODULE_STAT_TLS: Cell<*mut RpcTargetsModuleStat> = const { Cell::new(ptr::null_mut()) };
}

static mut RPC_TARGET_TREE: *mut mtproxy_ffi_rpc_target_tree = ptr::null_mut();
static mut RPC_TARGETS_MODULE_STAT_STORAGE: [RpcTargetsModuleStat; MAX_JOB_THREADS] =
    [ZERO_RPC_TARGETS_MODULE_STAT; MAX_JOB_THREADS];
static mut RPC_TARGETS_MODULE_STAT_ARRAY: [*mut RpcTargetsModuleStat; MAX_JOB_THREADS] =
    [ptr::null_mut(); MAX_JOB_THREADS];

unsafe extern "C" {
    fn get_this_thread_id() -> c_int;
    #[allow(clashing_extern_declarations)]
    fn jobs_get_this_job_thread_c_impl() -> *mut JobThread;
    static mut max_job_thread_id: c_int;
    static mut PID: MtproxyProcessId;

    fn mtproxy_ffi_rpc_target_insert_conn(
        c: ConnectionJob,
        tree_slot: *mut *mut mtproxy_ffi_rpc_target_tree,
        module_stat_tls: *mut c_void,
        default_ip: u32,
    ) -> c_int;
    fn mtproxy_ffi_rpc_target_delete_conn(
        c: ConnectionJob,
        tree_slot: *mut *mut mtproxy_ffi_rpc_target_tree,
        module_stat_tls: *mut c_void,
        default_ip: u32,
    ) -> c_int;
    fn mtproxy_ffi_rpc_target_lookup(
        tree: *mut mtproxy_ffi_rpc_target_tree,
        pid: *const MtproxyProcessId,
        default_ip: u32,
    ) -> RpcTargetJob;
    fn mtproxy_ffi_rpc_target_choose_connection_runtime(
        target: RpcTargetJob,
        pid: *const MtproxyProcessId,
    ) -> ConnectionJob;
    fn mtproxy_ffi_rpc_target_choose_random_connections_runtime(
        target: RpcTargetJob,
        pid: *const MtproxyProcessId,
        limit: c_int,
        buf: *mut ConnectionJob,
    ) -> c_int;
    fn mtproxy_ffi_rpc_targets_prepare_stat_runtime(
        sb: *mut c_void,
        module_stat_array: *mut *mut c_void,
        module_stat_len: c_int,
    ) -> c_int;
}

#[inline]
unsafe fn rpc_targets_module_stat_tls() -> *mut RpcTargetsModuleStat {
    let mut tls_ptr = RPC_TARGETS_MODULE_STAT_TLS.with(Cell::get);
    if !tls_ptr.is_null() {
        return tls_ptr;
    }

    let id = unsafe { get_this_thread_id() };
    assert!((0..MAX_JOB_THREADS as c_int).contains(&id));
    let idx = usize::try_from(id).unwrap_or(0);
    let slot = unsafe { ptr::addr_of_mut!(RPC_TARGETS_MODULE_STAT_STORAGE[idx]) };
    unsafe { *slot = ZERO_RPC_TARGETS_MODULE_STAT };
    unsafe { RPC_TARGETS_MODULE_STAT_ARRAY[idx] = slot };
    RPC_TARGETS_MODULE_STAT_TLS.with(|cell| cell.set(slot));
    tls_ptr = slot;
    tls_ptr
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_is_fast_thread() -> c_int {
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    if !thread.is_null() && unsafe { (*thread).thread_class == JC_ENGINE } {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn rpc_targets_prepare_stat(sb: *mut c_void) -> c_int {
    let len = unsafe { max_job_thread_id.saturating_add(1) };
    unsafe {
        mtproxy_ffi_rpc_targets_prepare_stat_runtime(
            sb,
            ptr::addr_of_mut!(RPC_TARGETS_MODULE_STAT_ARRAY).cast::<*mut c_void>(),
            len,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn rpc_target_insert_conn(c: ConnectionJob) {
    let rc = unsafe {
        mtproxy_ffi_rpc_target_insert_conn(
            c,
            ptr::addr_of_mut!(RPC_TARGET_TREE),
            rpc_targets_module_stat_tls().cast::<c_void>(),
            PID.ip,
        )
    };
    assert_eq!(rc, 0);
}

#[no_mangle]
pub unsafe extern "C" fn rpc_target_delete_conn(c: ConnectionJob) {
    let rc = unsafe {
        mtproxy_ffi_rpc_target_delete_conn(
            c,
            ptr::addr_of_mut!(RPC_TARGET_TREE),
            rpc_targets_module_stat_tls().cast::<c_void>(),
            PID.ip,
        )
    };
    assert_eq!(rc, 0);
}

#[no_mangle]
pub unsafe extern "C" fn rpc_target_lookup(pid: *mut MtproxyProcessId) -> RpcTargetJob {
    unsafe { mtproxy_ffi_rpc_target_lookup(RPC_TARGET_TREE, pid.cast_const(), PID.ip) }
}

#[no_mangle]
pub unsafe extern "C" fn rpc_target_choose_connection(
    target: RpcTargetJob,
    pid: *mut MtproxyProcessId,
) -> ConnectionJob {
    unsafe { mtproxy_ffi_rpc_target_choose_connection_runtime(target, pid.cast_const()) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_choose_connection_by_pid(
    pid: *mut MtproxyProcessId,
) -> ConnectionJob {
    if pid.is_null() {
        return ptr::null_mut();
    }
    let target = unsafe { rpc_target_lookup(pid) };
    unsafe { rpc_target_choose_connection(target, pid) }
}

#[no_mangle]
pub unsafe extern "C" fn rpc_target_choose_random_connections(
    target: RpcTargetJob,
    pid: *mut MtproxyProcessId,
    limit: c_int,
    buf: *mut ConnectionJob,
) -> c_int {
    unsafe {
        mtproxy_ffi_rpc_target_choose_random_connections_runtime(
            target,
            pid.cast_const(),
            limit,
            buf,
        )
    }
}
