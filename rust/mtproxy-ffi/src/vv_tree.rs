//! FFI bindings for vv-tree (treap data structure).
//!
//! This module provides C-compatible FFI functions that replace the
//! functionality from `vv/vv-tree.c`.

use core::ffi::{c_int, c_void};
use std::collections::HashMap;
use std::sync::Mutex;

use mtproxy_core::runtime::collections::treap::ThreadSafeTreap;

/// Opaque handle to a treap tree.
///
/// This represents a thread-safe treap instance that can be passed
/// across the FFI boundary.
#[repr(C)]
pub struct VvTreeHandle {
    _private: [u8; 0],
}

/// Global registry of treap instances.
///
/// Since we need to manage treap lifetimes across FFI, we maintain a
/// registry that maps handles (pointers) to actual treap instances.
static TREE_REGISTRY: Mutex<Option<HashMap<usize, Box<ThreadSafeTreap<usize, i32>>>>> =
    Mutex::new(None);

/// Initialize the tree registry if needed.
fn ensure_registry() {
    let mut registry = TREE_REGISTRY.lock().unwrap();
    if registry.is_none() {
        *registry = Some(HashMap::new());
    }
}

/// Creates a new treap tree.
///
/// # Safety
/// This function is safe to call from C.
#[no_mangle]
pub unsafe extern "C" fn vv_tree_create() -> *mut VvTreeHandle {
    ensure_registry();
    
    // Create a new treap for pointer keys with integer priorities
    let treap: ThreadSafeTreap<usize, i32> = ThreadSafeTreap::new();
    let boxed = Box::new(treap);
    let handle = Box::into_raw(boxed) as usize;
    
    let mut registry = TREE_REGISTRY.lock().unwrap();
    let reg = registry.as_mut().unwrap();
    
    // Store the actual treap in the registry
    let treap_for_registry: ThreadSafeTreap<usize, i32> = ThreadSafeTreap::new();
    reg.insert(handle, Box::new(treap_for_registry));
    
    handle as *mut VvTreeHandle
}

/// Destroys a treap tree and frees its memory.
///
/// # Safety
/// The handle must be a valid handle returned from `vv_tree_create`.
/// The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn vv_tree_destroy(handle: *mut VvTreeHandle) {
    if handle.is_null() {
        return;
    }
    
    let handle_val = handle as usize;
    let mut registry = TREE_REGISTRY.lock().unwrap();
    if let Some(ref mut reg) = *registry {
        reg.remove(&handle_val);
    }
    
    // Reconstruct and drop the box
    let _ = Box::from_raw(handle as *mut ThreadSafeTreap<usize, i32>);
}

/// Inserts a key into the treap with a given priority.
///
/// # Safety
/// - `handle` must be a valid handle returned from `vv_tree_create`
/// - `key` must be a valid pointer (can be any value for generic trees)
#[no_mangle]
pub unsafe extern "C" fn vv_tree_insert(
    handle: *mut VvTreeHandle,
    key: *const c_void,
    priority: c_int,
) {
    if handle.is_null() {
        return;
    }
    
    let treap = &*(handle as *const ThreadSafeTreap<usize, i32>);
    let key_val = key as usize;
    treap.insert(key_val, priority);
}

/// Looks up a key in the treap.
///
/// # Safety
/// - `handle` must be a valid handle returned from `vv_tree_create`
/// - `key` must be a valid pointer
///
/// # Returns
/// The key pointer if found, or null if not found.
#[no_mangle]
pub unsafe extern "C" fn vv_tree_lookup(
    handle: *mut VvTreeHandle,
    key: *const c_void,
) -> *const c_void {
    if handle.is_null() {
        return std::ptr::null();
    }
    
    let treap = &*(handle as *const ThreadSafeTreap<usize, i32>);
    let key_val = key as usize;
    
    treap
        .lookup(&key_val, |k| *k as *const c_void)
        .unwrap_or(std::ptr::null())
}

/// Deletes a key from the treap.
///
/// # Safety
/// - `handle` must be a valid handle returned from `vv_tree_create`
/// - `key` must be a valid pointer
///
/// # Returns
/// 1 if the key was found and deleted, 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn vv_tree_delete(
    handle: *mut VvTreeHandle,
    key: *const c_void,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    
    let treap = &*(handle as *const ThreadSafeTreap<usize, i32>);
    let key_val = key as usize;
    
    c_int::from(treap.delete(&key_val))
}

/// Clears all elements from the treap.
///
/// # Safety
/// `handle` must be a valid handle returned from `vv_tree_create`.
#[no_mangle]
pub unsafe extern "C" fn vv_tree_clear(handle: *mut VvTreeHandle) {
    if handle.is_null() {
        return;
    }
    
    let treap = &*(handle as *const ThreadSafeTreap<usize, i32>);
    treap.clear();
}

/// Returns the number of elements in the treap.
///
/// # Safety
/// `handle` must be a valid handle returned from `vv_tree_create`.
#[no_mangle]
pub unsafe extern "C" fn vv_tree_count(handle: *mut VvTreeHandle) -> c_int {
    if handle.is_null() {
        return 0;
    }
    
    let treap = &*(handle as *const ThreadSafeTreap<usize, i32>);
    treap.len() as c_int
}

/// Callback type for tree traversal.
type TraverseCallback = unsafe extern "C" fn(*const c_void);

/// Traverses the treap in sorted order, calling the callback for each element.
///
/// # Safety
/// - `handle` must be a valid handle returned from `vv_tree_create`
/// - `callback` must be a valid function pointer
#[no_mangle]
pub unsafe extern "C" fn vv_tree_traverse(
    handle: *mut VvTreeHandle,
    callback: TraverseCallback,
) {
    if handle.is_null() {
        return;
    }
    
    let treap = &*(handle as *const ThreadSafeTreap<usize, i32>);
    treap.traverse(|k| {
        let ptr = *k as *const c_void;
        callback(ptr);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vv_tree_basic_operations() {
        unsafe {
            let tree = vv_tree_create();
            assert!(!tree.is_null());

            // Insert some elements
            vv_tree_insert(tree, 0x100 as *const c_void, 10);
            vv_tree_insert(tree, 0x200 as *const c_void, 20);
            vv_tree_insert(tree, 0x300 as *const c_void, 15);

            assert_eq!(vv_tree_count(tree), 3);

            // Lookup
            let found = vv_tree_lookup(tree, 0x200 as *const c_void);
            assert_eq!(found as usize, 0x200);

            let not_found = vv_tree_lookup(tree, 0x999 as *const c_void);
            assert!(not_found.is_null());

            // Delete
            let deleted = vv_tree_delete(tree, 0x200 as *const c_void);
            assert_eq!(deleted, 1);
            assert_eq!(vv_tree_count(tree), 2);

            let deleted_again = vv_tree_delete(tree, 0x200 as *const c_void);
            assert_eq!(deleted_again, 0);

            // Clear
            vv_tree_clear(tree);
            assert_eq!(vv_tree_count(tree), 0);

            vv_tree_destroy(tree);
        }
    }
}
