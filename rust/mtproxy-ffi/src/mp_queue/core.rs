use crate::ffi_util::mut_ref_from_ptr;
use core::ffi::{c_int, c_long, c_void};
use core::ptr;
use mtproxy_core::runtime::jobs::mp_queue::{self, MpQueue, MpQueueError};
use std::cell::Cell;
use std::sync::atomic::{AtomicI32, Ordering};

const MPQ_FFI_ERR_INVALID_ARGS: i32 = -1;
const MPQ_FFI_ERR_NOT_WAITABLE: i32 = -2;
const MPQ_FFI_ERR_NULL_VALUE: i32 = -3;

type MpQueueValue = usize;
const MAX_JOB_THREADS: i32 = 256;

// struct mp_queue {
//   struct mp_queue_block *mq_head __attribute__((aligned(64)));
//   int mq_magic;
//   struct mp_queue_block *mq_tail __attribute__((aligned(64)));
// };
#[repr(C, align(64))]
struct MpQueueC {
    mq_head: *mut c_void,
    mq_magic: c_int,
    _pad: [u8; 64 - core::mem::size_of::<*mut c_void>() - core::mem::size_of::<c_int>()],
    mq_tail: *mut c_void,
}

thread_local! {
    static MPQ_THIS_THREAD_ID: Cell<i32> = const { Cell::new(0) };
}

static MPQ_THREADS: AtomicI32 = AtomicI32::new(0);
static MPQ_ACTIVE: AtomicI32 = AtomicI32::new(0);
static MPQ_ALLOCATED: AtomicI32 = AtomicI32::new(0);

struct MpQueueHandle {
    queue: MpQueue<MpQueueValue>,
}

#[repr(C)]
struct MpQueueStatsBufferC {
    buff: *mut i8,
    pos: c_int,
    size: c_int,
    flags: c_int,
}

unsafe extern "C" {
    fn abort() -> !;
    fn posix_memalign(memptr: *mut *mut c_void, alignment: usize, size: usize) -> c_int;
    fn free(ptr: *mut c_void);

    fn mpq_rust_init_queue(mq: *mut MpQueueC, waitable: c_int) -> c_int;
    fn mpq_rust_clear_queue(mq: *mut MpQueueC);
    fn mpq_rust_queue_attached(mq: *mut MpQueueC) -> c_int;
    fn mpq_rust_queue_waitable(mq: *mut MpQueueC) -> c_int;
    fn mpq_rust_is_empty(mq: *mut MpQueueC) -> c_int;
    fn mpq_rust_push_w(mq: *mut MpQueueC, value: *mut c_void, flags: c_int) -> c_long;
    fn mpq_rust_pop_nw(mq: *mut MpQueueC, flags: c_int) -> *mut c_void;

    static mpq_rust_attached_queues: c_int;
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
    unsafe { mut_ref_from_ptr(handle.cast::<MpQueueHandle>()) }
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
    let Some(out_handle_ref) = (unsafe { mut_ref_from_ptr(out_handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    *out_handle_ref = ptr::null_mut();

    let queue = if waitable != 0 {
        mp_queue::alloc_mp_queue_w::<MpQueueValue>()
    } else {
        mp_queue::alloc_mp_queue::<MpQueueValue>()
    };
    let handle = Box::new(MpQueueHandle { queue });
    *out_handle_ref = Box::into_raw(handle).cast::<c_void>();
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
    let Some(out_pos_ref) = (unsafe { mut_ref_from_ptr(out_pos) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    let pos = mp_queue::mpq_push(
        &handle_ref.queue,
        value as MpQueueValue,
        i32_to_u32_bits(flags),
    );
    *out_pos_ref = pos;
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
    let Some(out_value_ref) = (unsafe { mut_ref_from_ptr(out_value) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    *out_value_ref = ptr::null_mut();
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    match mp_queue::mpq_pop(&handle_ref.queue, i32_to_u32_bits(flags)) {
        Some(value) => {
            *out_value_ref = value as *mut c_void;
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
    let Some(out_pos_ref) = (unsafe { mut_ref_from_ptr(out_pos) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    match mp_queue::mpq_push_w(
        &handle_ref.queue,
        value as MpQueueValue,
        i32_to_u32_bits(flags),
    ) {
        Ok(pos) => {
            *out_pos_ref = pos;
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
    let Some(out_value_ref) = (unsafe { mut_ref_from_ptr(out_value) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    *out_value_ref = ptr::null_mut();
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    match mp_queue::mpq_pop_w(&handle_ref.queue, i32_to_u32_bits(flags)) {
        Ok(value) => {
            *out_value_ref = value as *mut c_void;
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
    let Some(out_value_ref) = (unsafe { mut_ref_from_ptr(out_value) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    *out_value_ref = ptr::null_mut();
    let Some(handle_ref) = (unsafe { handle_ref(handle) }) else {
        return MPQ_FFI_ERR_INVALID_ARGS;
    };
    match mp_queue::mpq_pop_nw(&handle_ref.queue, i32_to_u32_bits(flags)) {
        Ok(Some(value)) => {
            *out_value_ref = value as *mut c_void;
            1
        }
        Ok(None) => 0,
        Err(error) => map_waitable_error(error),
    }
}

#[inline]
unsafe fn abort_if(condition: bool) {
    if condition {
        // SAFETY: immediate process abort preserves C-side assert semantics.
        unsafe { abort() };
    }
}

#[inline]
unsafe fn queue_ref<'a>(mq: *mut c_void) -> &'a mut MpQueueC {
    // SAFETY: C ABI contract requires valid pointer; violations abort.
    unsafe { abort_if(mq.is_null()) };
    // SAFETY: validated above.
    unsafe { &mut *mq.cast::<MpQueueC>() }
}

#[inline]
unsafe fn append_stats_line(sb: *mut c_void, line: &str) {
    if sb.is_null() {
        return;
    }
    // SAFETY: caller provides valid stats buffer pointer by ABI contract.
    let sb_ref = unsafe { &mut *sb.cast::<MpQueueStatsBufferC>() };
    if sb_ref.buff.is_null() || sb_ref.size <= 0 || sb_ref.pos >= sb_ref.size {
        return;
    }
    let line_bytes = line.as_bytes();
    let remaining = (sb_ref.size - sb_ref.pos) as usize;
    let to_copy = remaining.saturating_sub(1).min(line_bytes.len());
    if to_copy == 0 {
        return;
    }
    // SAFETY: destination range is in-bounds and non-overlapping with source.
    unsafe {
        core::ptr::copy_nonoverlapping(
            line_bytes.as_ptr(),
            sb_ref.buff.add(sb_ref.pos as usize).cast::<u8>(),
            to_copy,
        );
    }
    sb_ref.pos += to_copy as c_int;
    if sb_ref.pos < sb_ref.size {
        // SAFETY: `pos < size` checked above.
        unsafe {
            *sb_ref.buff.add(sb_ref.pos as usize) = 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_this_thread_id() -> c_int {
    let cached = MPQ_THIS_THREAD_ID.with(Cell::get);
    if cached != 0 {
        return cached;
    }
    let id = MPQ_THREADS.fetch_add(1, Ordering::AcqRel) + 1;
    // SAFETY: preserve old C assert bound checks.
    unsafe { abort_if(id <= 0 || id >= MAX_JOB_THREADS) };
    MPQ_THIS_THREAD_ID.with(|cell| cell.set(id));
    id
}

#[no_mangle]
pub unsafe extern "C" fn init_mp_queue_w(mq: *mut c_void) {
    // SAFETY: assert legacy pointer contract before calling C bridge.
    let mq = unsafe { queue_ref(mq) };
    MPQ_ACTIVE.fetch_add(1, Ordering::AcqRel);
    // SAFETY: C bridge validates queue state and initializes handle.
    let rc = unsafe { mpq_rust_init_queue(mq, 1) };
    unsafe { abort_if(rc < 0) };
}

#[no_mangle]
pub unsafe extern "C" fn alloc_mp_queue_w() -> *mut c_void {
    let mut out: *mut c_void = ptr::null_mut();
    // SAFETY: writes allocated pointer to `out`.
    let alloc_rc = unsafe {
        posix_memalign(
            &raw mut out,
            64,
            core::mem::size_of::<MpQueueC>(),
        )
    };
    unsafe { abort_if(alloc_rc != 0 || out.is_null()) };
    // SAFETY: newly allocated memory is writable for full object size.
    unsafe {
        ptr::write_bytes(out.cast::<u8>(), 0, core::mem::size_of::<MpQueueC>());
    }
    MPQ_ALLOCATED.fetch_add(1, Ordering::AcqRel);
    let mq = out.cast::<MpQueueC>();
    // SAFETY: queue pointer came from successful allocation.
    unsafe { init_mp_queue_w(mq.cast::<c_void>()) };
    mq.cast::<c_void>()
}

#[no_mangle]
pub unsafe extern "C" fn clear_mp_queue(mq: *mut c_void) {
    // SAFETY: assert legacy pointer contract before bridge calls.
    let mq = unsafe { queue_ref(mq) };
    // SAFETY: C bridge only reads queue metadata.
    if unsafe { mpq_rust_queue_waitable(mq) } != 0 {
        MPQ_ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
    // SAFETY: maintain legacy assert that queue must be attached.
    unsafe { abort_if(mpq_rust_queue_attached(mq) == 0) };
    // SAFETY: bridge detaches and destroys underlying Rust handle.
    unsafe { mpq_rust_clear_queue(mq) };
}

#[no_mangle]
pub unsafe extern "C" fn free_mp_queue(mq: *mut c_void) {
    MPQ_ALLOCATED.fetch_sub(1, Ordering::AcqRel);
    // SAFETY: preserves previous behavior: clear then free.
    unsafe { clear_mp_queue(mq) };
    // SAFETY: pointer originates from posix_memalign in alloc_mp_queue_w.
    unsafe { free(mq) };
}

#[no_mangle]
pub unsafe extern "C" fn mpq_is_empty(mq: *mut c_void) -> c_int {
    // SAFETY: assert legacy pointer contract before bridge calls.
    let mq = unsafe { queue_ref(mq) };
    // SAFETY: maintain legacy assert that queue must be attached.
    unsafe { abort_if(mpq_rust_queue_attached(mq) == 0) };
    // SAFETY: bridge reads queue state and returns 0/1.
    unsafe { mpq_rust_is_empty(mq) }
}

#[no_mangle]
pub unsafe extern "C" fn mpq_pop_nw(mq: *mut c_void, flags: c_int) -> *mut c_void {
    // SAFETY: assert legacy pointer contract before bridge calls.
    let mq = unsafe { queue_ref(mq) };
    // SAFETY: maintain legacy assert that queue must be attached.
    unsafe { abort_if(mpq_rust_queue_attached(mq) == 0) };
    // SAFETY: bridge executes non-blocking pop for waitable queue.
    unsafe { mpq_rust_pop_nw(mq, flags) }
}

#[no_mangle]
pub unsafe extern "C" fn mpq_push_w(mq: *mut c_void, value: *mut c_void, flags: c_int) -> c_long {
    // SAFETY: assert legacy pointer contract before bridge calls.
    let mq = unsafe { queue_ref(mq) };
    // SAFETY: maintain legacy assert that queue must be attached.
    unsafe { abort_if(mpq_rust_queue_attached(mq) == 0) };
    // SAFETY: bridge executes waitable push.
    unsafe { mpq_rust_push_w(mq, value, flags) }
}

#[no_mangle]
pub unsafe extern "C" fn mp_queue_prepare_stat(sb: *mut c_void) -> c_int {
    // SAFETY: volatile read mirrors C-side access semantics.
    let attached = unsafe { core::ptr::read_volatile(&raw const mpq_rust_attached_queues) };
    let active = MPQ_ACTIVE.load(Ordering::Acquire);
    let allocated = MPQ_ALLOCATED.load(Ordering::Acquire);

    let header = ">>>>>>mp_queue>>>>>>\tstart\n";
    let attached_line = format!("mpq_rust_attached_queues\t{attached}\n");
    let active_line = format!("mpq_active\t{active}\n");
    let allocated_line = format!("mpq_allocated\t{allocated}\n");
    let footer = "<<<<<<mp_queue<<<<<<\tend\n";

    // SAFETY: appender guards all bounds and null-pointer checks.
    unsafe {
        append_stats_line(sb, header);
        append_stats_line(sb, &attached_line);
        append_stats_line(sb, &active_line);
        append_stats_line(sb, &allocated_line);
        append_stats_line(sb, footer);
    }

    if sb.is_null() {
        0
    } else {
        // SAFETY: checked above.
        unsafe { (*sb.cast::<MpQueueStatsBufferC>()).pos }
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
