//! Rust-backed replacements for legacy vv tree usages.

use crate::ffi_util::{mut_ref_from_ptr, ref_from_ptr};
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};
use mtproxy_core::runtime::collections::vv_tree::{
    ConnectionTree as CoreConnectionTree, VvTreeMap as CoreVvTreeMap,
};
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::MtproxyProcessId;

#[inline]
fn rw_read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[inline]
fn rw_write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[inline]
fn mutex_lock<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[repr(C)]
pub struct VvTreeHandle {
    _private: [u8; 0],
}

struct VvTree {
    values: RwLock<CoreVvTreeMap>,
}

unsafe fn vv_tree_as_ref<'a>(handle: *mut VvTreeHandle) -> Option<&'a VvTree> {
    // SAFETY: caller upholds handle validity.
    unsafe { ref_from_ptr(handle.cast::<VvTree>().cast_const()) }
}

#[no_mangle]
pub unsafe extern "C" fn vv_tree_create() -> *mut VvTreeHandle {
    let tree = Box::new(VvTree {
        values: RwLock::new(CoreVvTreeMap::default()),
    });
    Box::into_raw(tree) as *mut VvTreeHandle
}

#[no_mangle]
pub unsafe extern "C" fn vv_tree_destroy(handle: *mut VvTreeHandle) {
    if handle.is_null() {
        return;
    }
    let _ = Box::from_raw(handle as *mut VvTree);
}

#[no_mangle]
pub unsafe extern "C" fn vv_tree_insert(
    handle: *mut VvTreeHandle,
    key: *const c_void,
    priority: c_int,
) {
    let Some(tree) = (unsafe { vv_tree_as_ref(handle) }) else {
        return;
    };

    rw_write(&tree.values).insert_if_absent(key as usize, priority);
}

#[no_mangle]
pub unsafe extern "C" fn vv_tree_lookup(
    handle: *mut VvTreeHandle,
    key: *const c_void,
) -> *const c_void {
    let Some(tree) = (unsafe { vv_tree_as_ref(handle) }) else {
        return core::ptr::null();
    };

    let values = rw_read(&tree.values);
    if values.contains(key as usize) {
        key
    } else {
        core::ptr::null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn vv_tree_delete(handle: *mut VvTreeHandle, key: *const c_void) -> c_int {
    let Some(tree) = (unsafe { vv_tree_as_ref(handle) }) else {
        return 0;
    };

    i32::from(rw_write(&tree.values).remove(key as usize))
}

#[no_mangle]
pub unsafe extern "C" fn vv_tree_clear(handle: *mut VvTreeHandle) {
    let Some(tree) = (unsafe { vv_tree_as_ref(handle) }) else {
        return;
    };

    rw_write(&tree.values).clear();
}

#[no_mangle]
pub unsafe extern "C" fn vv_tree_count(handle: *mut VvTreeHandle) -> c_int {
    let Some(tree) = (unsafe { vv_tree_as_ref(handle) }) else {
        return 0;
    };

    rw_read(&tree.values).len() as c_int
}

#[no_mangle]
pub unsafe extern "C" fn vv_tree_traverse(
    handle: *mut VvTreeHandle,
    callback: unsafe extern "C" fn(*const c_void),
) {
    let Some(tree) = (unsafe { vv_tree_as_ref(handle) }) else {
        return;
    };

    let keys = rw_read(&tree.values).keys_sorted();
    for key in keys {
        callback(key as *const c_void);
    }
}

#[repr(C)]
pub struct tree_connection {
    _private: [u8; 0],
}

struct ConnectionTree {
    refs: AtomicUsize,
    values: RwLock<CoreConnectionTree>,
}

fn conn_tree_from_raw(tree: *mut tree_connection) -> *mut ConnectionTree {
    tree as *mut ConnectionTree
}

unsafe fn conn_tree_acquire_raw(tree: *mut tree_connection) -> *mut tree_connection {
    if !tree.is_null() {
        let state = conn_tree_from_raw(tree);
        (*state).refs.fetch_add(1, Ordering::Relaxed);
    }
    tree
}

unsafe fn conn_tree_release_raw(tree: *mut tree_connection) {
    if tree.is_null() {
        return;
    }
    let state = conn_tree_from_raw(tree);
    if (*state).refs.fetch_sub(1, Ordering::AcqRel) == 1 {
        let _ = Box::from_raw(state);
    }
}

unsafe fn conn_tree_create_with(value: usize) -> *mut tree_connection {
    let mut set = CoreConnectionTree::default();
    set.insert(value);
    let state = Box::new(ConnectionTree {
        refs: AtomicUsize::new(1),
        values: RwLock::new(set),
    });
    Box::into_raw(state) as *mut tree_connection
}

#[no_mangle]
pub unsafe extern "C" fn tree_insert_connection(
    tree: *mut tree_connection,
    conn: *mut c_void,
    _priority: c_int,
) -> *mut tree_connection {
    if tree.is_null() {
        return conn_tree_create_with(conn as usize);
    }

    let state = conn_tree_from_raw(tree);
    rw_write(&(*state).values).insert(conn as usize);
    tree
}

#[no_mangle]
pub unsafe extern "C" fn tree_delete_connection(
    tree: *mut tree_connection,
    conn: *mut c_void,
) -> *mut tree_connection {
    if tree.is_null() {
        return core::ptr::null_mut();
    }

    let state = conn_tree_from_raw(tree);
    let empty = rw_write(&(*state).values).remove_and_is_empty(conn as usize);

    if empty {
        conn_tree_release_raw(tree);
        core::ptr::null_mut()
    } else {
        tree
    }
}

#[no_mangle]
pub unsafe extern "C" fn tree_lookup_ptr_connection(
    tree: *mut tree_connection,
    conn: *mut c_void,
) -> *mut c_void {
    if tree.is_null() {
        return core::ptr::null_mut();
    }

    let state = conn_tree_from_raw(tree);
    if rw_read(&(*state).values).contains(conn as usize) {
        conn
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn tree_act_connection(
    tree: *mut tree_connection,
    act: unsafe extern "C" fn(*mut c_void),
) {
    if tree.is_null() {
        return;
    }

    let state = conn_tree_from_raw(tree);
    let values = rw_read(&(*state).values).values_sorted();
    for value in values {
        act(value as *mut c_void);
    }
}

#[no_mangle]
pub unsafe extern "C" fn tree_act_ex_connection(
    tree: *mut tree_connection,
    act: unsafe extern "C" fn(*mut c_void, *mut c_void),
    ex: *mut c_void,
) {
    if tree.is_null() {
        return;
    }

    let state = conn_tree_from_raw(tree);
    let values = rw_read(&(*state).values).values_sorted();
    for value in values {
        act(value as *mut c_void, ex);
    }
}

#[no_mangle]
pub unsafe extern "C" fn tree_act_ex2_connection(
    tree: *mut tree_connection,
    act: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void),
    ex: *mut c_void,
    ex2: *mut c_void,
) {
    if tree.is_null() {
        return;
    }

    let state = conn_tree_from_raw(tree);
    let values = rw_read(&(*state).values).values_sorted();
    for value in values {
        act(value as *mut c_void, ex, ex2);
    }
}

#[no_mangle]
pub unsafe extern "C" fn tree_act_ex3_connection(
    tree: *mut tree_connection,
    act: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void),
    ex: *mut c_void,
    ex2: *mut c_void,
    ex3: *mut c_void,
) {
    if tree.is_null() {
        return;
    }

    let state = conn_tree_from_raw(tree);
    let values = rw_read(&(*state).values).values_sorted();
    for value in values {
        act(value as *mut c_void, ex, ex2, ex3);
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_tree_ptr_connection(
    tree: *mut *mut tree_connection,
) -> *mut tree_connection {
    let Some(tree_ref) = (unsafe { mut_ref_from_ptr(tree) }) else {
        return core::ptr::null_mut();
    };

    unsafe { conn_tree_acquire_raw(*tree_ref) }
}

#[no_mangle]
pub unsafe extern "C" fn tree_free_connection(tree: *mut tree_connection) {
    conn_tree_release_raw(tree);
}

#[no_mangle]
pub unsafe extern "C" fn free_tree_ptr_connection(tree: *mut tree_connection) {
    conn_tree_release_raw(tree);
}

#[repr(C)]
pub struct mtproxy_ffi_rpc_target_tree {
    _private: [u8; 0],
}

struct RpcTargetTree {
    refs: AtomicUsize,
    values: RwLock<BTreeMap<[u8; 8], usize>>,
}

fn rpc_target_tree_from_raw(tree: *mut mtproxy_ffi_rpc_target_tree) -> *mut RpcTargetTree {
    tree as *mut RpcTargetTree
}

fn rpc_target_key(pid: &MtproxyProcessId) -> [u8; 8] {
    let mut out = [0_u8; 8];
    out[0..4].copy_from_slice(&pid.ip.to_ne_bytes());
    out[4..6].copy_from_slice(&pid.port.to_ne_bytes());
    if pid.port == 0 {
        out[6..8].copy_from_slice(&pid.pid.to_ne_bytes());
    }
    out
}

unsafe fn rpc_target_tree_acquire_raw(
    tree: *mut mtproxy_ffi_rpc_target_tree,
) -> *mut mtproxy_ffi_rpc_target_tree {
    if !tree.is_null() {
        let state = rpc_target_tree_from_raw(tree);
        (*state).refs.fetch_add(1, Ordering::Relaxed);
    }
    tree
}

unsafe fn rpc_target_tree_release_raw(tree: *mut mtproxy_ffi_rpc_target_tree) {
    if tree.is_null() {
        return;
    }
    let state = rpc_target_tree_from_raw(tree);
    if (*state).refs.fetch_sub(1, Ordering::AcqRel) == 1 {
        let _ = Box::from_raw(state);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_tree_acquire(
    tree: *mut mtproxy_ffi_rpc_target_tree,
) -> *mut mtproxy_ffi_rpc_target_tree {
    rpc_target_tree_acquire_raw(tree)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_tree_release(
    tree: *mut mtproxy_ffi_rpc_target_tree,
) {
    rpc_target_tree_release_raw(tree);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_tree_insert(
    tree: *mut mtproxy_ffi_rpc_target_tree,
    pid: *const MtproxyProcessId,
    target: *mut c_void,
) -> *mut mtproxy_ffi_rpc_target_tree {
    let Some(pid_ref) = (unsafe { ref_from_ptr(pid) }) else {
        return tree;
    };

    if tree.is_null() {
        let mut values = BTreeMap::new();
        values.insert(rpc_target_key(pid_ref), target as usize);
        let state = Box::new(RpcTargetTree {
            refs: AtomicUsize::new(1),
            values: RwLock::new(values),
        });
        return Box::into_raw(state) as *mut mtproxy_ffi_rpc_target_tree;
    }

    let state = rpc_target_tree_from_raw(tree);
    rw_write(&(*state).values).insert(rpc_target_key(pid_ref), target as usize);
    tree
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_tree_lookup(
    tree: *mut mtproxy_ffi_rpc_target_tree,
    pid: *const MtproxyProcessId,
) -> *mut c_void {
    if tree.is_null() {
        return core::ptr::null_mut();
    }
    let Some(pid_ref) = (unsafe { ref_from_ptr(pid) }) else {
        return core::ptr::null_mut();
    };

    let state = rpc_target_tree_from_raw(tree);
    rw_read(&(*state).values)
        .get(&rpc_target_key(pid_ref))
        .copied()
        .map_or(core::ptr::null_mut(), |value| value as *mut c_void)
}

static RPC_CUSTOM_OPS: Mutex<BTreeMap<u32, usize>> = Mutex::new(BTreeMap::new());

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_custom_op_insert(
    op: u32,
    entry: *mut c_void,
) -> c_int {
    if entry.is_null() {
        return -1;
    }

    let mut guard = mutex_lock(&RPC_CUSTOM_OPS);
    if let Some(previous) = guard.insert(op, entry as usize) {
        if previous != entry as usize {
            unsafe {
                libc::free(previous as *mut c_void);
            }
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_custom_op_lookup(op: u32) -> *mut c_void {
    let guard = mutex_lock(&RPC_CUSTOM_OPS);
    guard
        .get(&op)
        .copied()
        .map_or(core::ptr::null_mut(), |value| value as *mut c_void)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_custom_op_has_any() -> c_int {
    let guard = mutex_lock(&RPC_CUSTOM_OPS);
    i32::from(!guard.is_empty())
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_custom_op_clear() {
    let mut guard = mutex_lock(&RPC_CUSTOM_OPS);
    let to_free: Vec<usize> = guard.values().copied().collect();
    guard.clear();
    drop(guard);

    for entry in to_free {
        unsafe {
            libc::free(entry as *mut c_void);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_tree_roundtrip() {
        unsafe {
            let mut tree: *mut tree_connection = core::ptr::null_mut();
            tree = tree_insert_connection(tree, 0x10 as *mut c_void, 1);
            tree = tree_insert_connection(tree, 0x20 as *mut c_void, 1);
            assert_eq!(
                tree_lookup_ptr_connection(tree, 0x10 as *mut c_void) as usize,
                0x10
            );
            assert!(tree_lookup_ptr_connection(tree, 0x30 as *mut c_void).is_null());

            tree = tree_delete_connection(tree, 0x10 as *mut c_void);
            assert!(tree_lookup_ptr_connection(tree, 0x10 as *mut c_void).is_null());

            tree = tree_delete_connection(tree, 0x20 as *mut c_void);
            assert!(tree.is_null());
        }
    }

    #[test]
    fn rpc_target_tree_keys_match_pid_rules() {
        unsafe {
            let mut tree: *mut mtproxy_ffi_rpc_target_tree = core::ptr::null_mut();
            let pid_a = MtproxyProcessId {
                ip: 0x0102_0304,
                port: 443,
                pid: 1,
                utime: 0,
            };
            let pid_b = MtproxyProcessId {
                ip: 0x0102_0304,
                port: 0,
                pid: 2,
                utime: 0,
            };
            tree = mtproxy_ffi_rpc_target_tree_insert(tree, &pid_a, 0x1111 as *mut c_void);
            tree = mtproxy_ffi_rpc_target_tree_insert(tree, &pid_b, 0x2222 as *mut c_void);

            assert_eq!(
                mtproxy_ffi_rpc_target_tree_lookup(tree, &pid_a) as usize,
                0x1111
            );
            assert_eq!(
                mtproxy_ffi_rpc_target_tree_lookup(tree, &pid_b) as usize,
                0x2222
            );

            mtproxy_ffi_rpc_target_tree_release(tree);
        }
    }

    #[test]
    fn custom_op_registry_roundtrip() {
        unsafe {
            mtproxy_ffi_engine_rpc_custom_op_clear();
            let op = 0x1234_5678;
            let entry1 = libc::malloc(1);
            let entry2 = libc::malloc(1);
            assert!(!entry1.is_null());
            assert!(!entry2.is_null());

            assert_eq!(mtproxy_ffi_engine_rpc_custom_op_insert(op, entry1), 0);
            assert_eq!(mtproxy_ffi_engine_rpc_custom_op_lookup(op), entry1);
            assert_eq!(mtproxy_ffi_engine_rpc_custom_op_insert(op, entry2), 0);
            assert_eq!(mtproxy_ffi_engine_rpc_custom_op_lookup(op), entry2);
            assert_eq!(mtproxy_ffi_engine_rpc_custom_op_has_any(), 1);
            mtproxy_ffi_engine_rpc_custom_op_clear();
            assert_eq!(mtproxy_ffi_engine_rpc_custom_op_has_any(), 0);
        }
    }
}
