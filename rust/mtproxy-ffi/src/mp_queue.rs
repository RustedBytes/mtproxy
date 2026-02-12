use core::ffi::c_void;
use core::ptr;
use mtproxy_core::runtime::jobs::mp_queue::{self, MpQueue, MpQueueError};

const MPQ_FFI_ERR_INVALID_ARGS: i32 = -1;
const MPQ_FFI_ERR_NOT_WAITABLE: i32 = -2;
const MPQ_FFI_ERR_NULL_VALUE: i32 = -3;

type MpQueueValue = usize;

struct MpQueueHandle {
    queue: MpQueue<MpQueueValue>,
}

#[inline]
const fn i32_to_u32_bits(value: i32) -> u32 {
    u32::from_ne_bytes(value.to_ne_bytes())
}

#[inline]
const fn map_waitable_error(error: MpQueueError) -> i32 {
    match error {
        MpQueueError::NotWaitable => MPQ_FFI_ERR_NOT_WAITABLE,
    }
}

#[inline]
unsafe fn handle_ref<'a>(handle: *mut c_void) -> Option<&'a mut MpQueueHandle> {
    // SAFETY: caller validates `handle` and ownership contract.
    unsafe { handle.cast::<MpQueueHandle>().as_mut() }
}

/// Creates a Rust-backed MPQ handle.
///
/// Return values:
/// - `0`: handle created
/// - `-1`: invalid arguments
///
/// # Safety
/// `out_handle` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mpq_handle_create(
    waitable: i32,
    out_handle: *mut *mut c_void,
) -> i32 {
    if out_handle.is_null() {
        return MPQ_FFI_ERR_INVALID_ARGS;
    }
    // SAFETY: validated above.
    unsafe {
        *out_handle = ptr::null_mut();
    }

    let queue = if waitable != 0 {
        mp_queue::alloc_mp_queue_w::<MpQueueValue>()
    } else {
        mp_queue::alloc_mp_queue::<MpQueueValue>()
    };
    let handle = Box::new(MpQueueHandle { queue });
    // SAFETY: validated above.
    unsafe {
        *out_handle = Box::into_raw(handle).cast::<c_void>();
    }
    0
}

/// Destroys one Rust-backed MPQ handle.
///
/// Return values:
/// - `0`: destroyed
/// - `-1`: invalid arguments
///
/// # Safety
/// `handle` must be created by `mtproxy_ffi_mpq_handle_create` and destroyed exactly once.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mpq_handle_destroy(handle: *mut c_void) -> i32 {
    if handle.is_null() {
        return MPQ_FFI_ERR_INVALID_ARGS;
    }
    // SAFETY: validated above.
    unsafe {
        drop(Box::from_raw(handle.cast::<MpQueueHandle>()));
    }
    0
}

/// Clears queue contents.
///
/// Return values:
/// - `0`: cleared
/// - `-1`: invalid arguments
///
/// # Safety
/// `handle` must be a valid queue handle.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mpq_handle_clear(handle: *mut c_void) -> i32 {
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    handle_ref.queue.clear();
    0
}

/// Pushes one pointer into queue (`mpq_push` equivalent).
///
/// Return values:
/// - `0`: pushed (`out_pos` filled)
/// - `-1`: invalid arguments
/// - `-3`: null value pointer
///
/// # Safety
/// `handle` and `out_pos` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mpq_handle_push(
    handle: *mut c_void,
    value: *mut c_void,
    flags: i32,
    out_pos: *mut i64,
) -> i32 {
    if value.is_null() {
        return MPQ_FFI_ERR_NULL_VALUE;
    }
    if out_pos.is_null() {
        return MPQ_FFI_ERR_INVALID_ARGS;
    }
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    let pos = mp_queue::mpq_push(
        &handle_ref.queue,
        value as MpQueueValue,
        i32_to_u32_bits(flags),
    );
    // SAFETY: validated above.
    unsafe {
        *out_pos = pos;
    }
    0
}

/// Pops one pointer from queue (`mpq_pop` equivalent).
///
/// Return values:
/// - `1`: one value dequeued into `out_value`
/// - `0`: queue is currently empty
/// - `-1`: invalid arguments
///
/// # Safety
/// `handle` and `out_value` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mpq_handle_pop(
    handle: *mut c_void,
    flags: i32,
    out_value: *mut *mut c_void,
) -> i32 {
    if out_value.is_null() {
        return MPQ_FFI_ERR_INVALID_ARGS;
    }
    // SAFETY: validated above.
    unsafe {
        *out_value = ptr::null_mut();
    }
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    match mp_queue::mpq_pop(&handle_ref.queue, i32_to_u32_bits(flags)) {
        Some(value) => {
            // SAFETY: validated above.
            unsafe {
                *out_value = value as *mut c_void;
            }
            1
        }
        None => 0,
    }
}

/// Returns whether queue is currently empty (`mpq_is_empty` equivalent).
///
/// Return values:
/// - `1`: queue is empty
/// - `0`: queue is non-empty
/// - `-1`: invalid arguments
///
/// # Safety
/// `handle` must be a valid queue handle.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mpq_handle_is_empty(handle: *mut c_void) -> i32 {
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    if mp_queue::mpq_is_empty(&handle_ref.queue) {
        1
    } else {
        0
    }
}

/// Pushes one pointer into waitable queue and wakes one waiter (`mpq_push_w` equivalent).
///
/// Return values:
/// - `0`: pushed (`out_pos` filled)
/// - `-1`: invalid arguments
/// - `-2`: queue is not waitable
/// - `-3`: null value pointer
///
/// # Safety
/// `handle` and `out_pos` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mpq_handle_push_w(
    handle: *mut c_void,
    value: *mut c_void,
    flags: i32,
    out_pos: *mut i64,
) -> i32 {
    if value.is_null() {
        return MPQ_FFI_ERR_NULL_VALUE;
    }
    if out_pos.is_null() {
        return MPQ_FFI_ERR_INVALID_ARGS;
    }
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    match mp_queue::mpq_push_w(
        &handle_ref.queue,
        value as MpQueueValue,
        i32_to_u32_bits(flags),
    ) {
        Ok(pos) => {
            // SAFETY: validated above.
            unsafe {
                *out_pos = pos;
            }
            0
        }
        Err(error) => map_waitable_error(error),
    }
}

/// Pops one pointer from waitable queue (`mpq_pop_w` equivalent).
///
/// Return values:
/// - `1`: one value dequeued into `out_value`
/// - `-1`: invalid arguments
/// - `-2`: queue is not waitable
///
/// # Safety
/// `handle` and `out_value` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mpq_handle_pop_w(
    handle: *mut c_void,
    flags: i32,
    out_value: *mut *mut c_void,
) -> i32 {
    if out_value.is_null() {
        return MPQ_FFI_ERR_INVALID_ARGS;
    }
    // SAFETY: validated above.
    unsafe {
        *out_value = ptr::null_mut();
    }
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    match mp_queue::mpq_pop_w(&handle_ref.queue, i32_to_u32_bits(flags)) {
        Ok(value) => {
            // SAFETY: validated above.
            unsafe {
                *out_value = value as *mut c_void;
            }
            1
        }
        Err(error) => map_waitable_error(error),
    }
}

/// Attempts to pop one pointer from waitable queue without blocking (`mpq_pop_nw` equivalent).
///
/// Return values:
/// - `1`: one value dequeued into `out_value`
/// - `0`: queue produced no value in requested try-window
/// - `-1`: invalid arguments
/// - `-2`: queue is not waitable
///
/// # Safety
/// `handle` and `out_value` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mpq_handle_pop_nw(
    handle: *mut c_void,
    flags: i32,
    out_value: *mut *mut c_void,
) -> i32 {
    if out_value.is_null() {
        return MPQ_FFI_ERR_INVALID_ARGS;
    }
    // SAFETY: validated above.
    unsafe {
        *out_value = ptr::null_mut();
    }
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    match mp_queue::mpq_pop_nw(&handle_ref.queue, i32_to_u32_bits(flags)) {
        Ok(Some(value)) => {
            // SAFETY: validated above.
            unsafe {
                *out_value = value as *mut c_void;
            }
            1
        }
        Ok(None) => 0,
        Err(error) => map_waitable_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        mtproxy_ffi_mpq_handle_create, mtproxy_ffi_mpq_handle_destroy,
        mtproxy_ffi_mpq_handle_is_empty, mtproxy_ffi_mpq_handle_pop, mtproxy_ffi_mpq_handle_pop_nw,
        mtproxy_ffi_mpq_handle_pop_w, mtproxy_ffi_mpq_handle_push, mtproxy_ffi_mpq_handle_push_w,
        MPQ_FFI_ERR_NOT_WAITABLE,
    };
    use core::{ffi::c_void, ptr};
    use std::{thread, time::Duration};

    #[test]
    fn mpq_handle_plain_push_pop_roundtrip() {
        let mut handle: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_create(0, &raw mut handle) },
            0
        );
        assert!(!handle.is_null());
        assert_eq!(unsafe { mtproxy_ffi_mpq_handle_is_empty(handle) }, 1);

        let mut out_pos = -1_i64;
        let value = 0x1111_usize as *mut c_void;
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_push(handle, value, 0, &raw mut out_pos) },
            0
        );
        assert_eq!(out_pos, 0);
        assert_eq!(unsafe { mtproxy_ffi_mpq_handle_is_empty(handle) }, 0);

        let mut out_value: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_pop(handle, 0, &raw mut out_value) },
            1
        );
        assert_eq!(out_value, value);
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_pop(handle, 0, &raw mut out_value) },
            0
        );
        assert!(out_value.is_null());
        assert_eq!(unsafe { mtproxy_ffi_mpq_handle_destroy(handle) }, 0);
    }

    #[test]
    fn mpq_handle_waitable_operations_work() {
        let mut handle: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_create(1, &raw mut handle) },
            0
        );
        assert!(!handle.is_null());

        let value = 0x2222_usize as *mut c_void;
        let mut out_pos = -1_i64;
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_push_w(handle, value, 0, &raw mut out_pos) },
            0
        );
        assert_eq!(out_pos, 0);

        let mut out_value: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_pop_nw(handle, 0, &raw mut out_value) },
            0
        );
        assert!(out_value.is_null());
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_pop_nw(handle, 1, &raw mut out_value) },
            1
        );
        assert_eq!(out_value, value);
        assert_eq!(unsafe { mtproxy_ffi_mpq_handle_destroy(handle) }, 0);
    }

    #[test]
    fn mpq_handle_waitable_calls_fail_for_plain_queue() {
        let mut handle: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_create(0, &raw mut handle) },
            0
        );

        let mut out_pos = -1_i64;
        let value = 0x3333_usize as *mut c_void;
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_push_w(handle, value, 0, &raw mut out_pos) },
            MPQ_FFI_ERR_NOT_WAITABLE
        );

        let mut out_value: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_pop_w(handle, 0, &raw mut out_value) },
            MPQ_FFI_ERR_NOT_WAITABLE
        );
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_pop_nw(handle, 0, &raw mut out_value) },
            MPQ_FFI_ERR_NOT_WAITABLE
        );
        assert_eq!(unsafe { mtproxy_ffi_mpq_handle_destroy(handle) }, 0);
    }

    #[test]
    fn mpq_handle_pop_w_blocks_until_push_w() {
        let mut handle: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_create(1, &raw mut handle) },
            0
        );
        let handle_bits = handle as usize;

        let join = thread::spawn(move || {
            let mut out: *mut c_void = ptr::null_mut();
            let rc = unsafe {
                mtproxy_ffi_mpq_handle_pop_w(handle_bits as *mut c_void, 0, &raw mut out)
            };
            (rc, out as usize)
        });

        thread::sleep(Duration::from_millis(20));
        let mut out_pos = -1_i64;
        let value = 0x4444_usize as *mut c_void;
        assert_eq!(
            unsafe { mtproxy_ffi_mpq_handle_push_w(handle, value, 0, &raw mut out_pos) },
            0
        );
        let result = join.join();
        assert!(result.is_ok());
        let (rc, out) = result.unwrap_or((-1, 0));
        assert_eq!(rc, 1);
        assert_eq!(out, value as usize);
        assert_eq!(unsafe { mtproxy_ffi_mpq_handle_destroy(handle) }, 0);
    }
}
