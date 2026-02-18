//! FFI export surface for selected `net-rpc-targets` runtime functions.

use super::core::*;
use crate::vv_tree::mtproxy_ffi_rpc_target_tree;
use crate::MtproxyProcessId;
use core::ffi::{c_int, c_void};

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_insert_conn(
    c: ConnectionJob,
    tree_slot: *mut *mut mtproxy_ffi_rpc_target_tree,
    module_stat_tls: *mut RpcTargetsModuleStat,
    default_ip: u32,
) -> c_int {
    unsafe { rpc_target_insert_conn_impl(c, tree_slot, module_stat_tls, default_ip) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_delete_conn(
    c: ConnectionJob,
    tree_slot: *mut *mut mtproxy_ffi_rpc_target_tree,
    module_stat_tls: *mut RpcTargetsModuleStat,
    default_ip: u32,
) -> c_int {
    unsafe { rpc_target_delete_conn_impl(c, tree_slot, module_stat_tls, default_ip) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_lookup_runtime(
    tree: *mut mtproxy_ffi_rpc_target_tree,
    pid: *const MtproxyProcessId,
    default_ip: u32,
) -> *mut c_void {
    unsafe { rpc_target_lookup_runtime_impl(tree, pid, default_ip) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_choose_connection_runtime(
    target: RpcTargetJob,
    pid: *const MtproxyProcessId,
) -> ConnectionJob {
    unsafe { rpc_target_choose_connection_runtime_impl(target, pid) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_choose_random_connections_runtime(
    target: RpcTargetJob,
    pid: *const MtproxyProcessId,
    limit: c_int,
    buf: *mut ConnectionJob,
) -> c_int {
    unsafe { rpc_target_choose_random_connections_runtime_impl(target, pid, limit, buf) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_targets_prepare_stat_runtime(
    sb: *mut c_void,
    module_stat_array: *mut *mut c_void,
    module_stat_len: c_int,
) -> c_int {
    unsafe { rpc_targets_prepare_stat_runtime_impl(sb, module_stat_array, module_stat_len) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_lookup(
    tree: *mut mtproxy_ffi_rpc_target_tree,
    pid: *const MtproxyProcessId,
    default_ip: u32,
) -> RpcTargetJob {
    unsafe { rpc_target_lookup_impl(tree, pid, default_ip) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_lookup_hp(
    tree: *mut mtproxy_ffi_rpc_target_tree,
    ip: u32,
    port: c_int,
    default_ip: u32,
) -> RpcTargetJob {
    unsafe { rpc_target_lookup_hp_impl(tree, ip, port, default_ip) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_lookup_target_runtime(
    target: ConnTargetJob,
    tree: *mut mtproxy_ffi_rpc_target_tree,
    default_ip: u32,
) -> RpcTargetJob {
    unsafe { rpc_target_lookup_target_runtime_impl(target, tree, default_ip) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_get_state_runtime(
    target: RpcTargetJob,
    pid: *const MtproxyProcessId,
) -> c_int {
    unsafe { rpc_target_get_state_runtime_impl(target, pid) }
}
