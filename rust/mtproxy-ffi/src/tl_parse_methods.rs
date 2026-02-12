use super::MtproxyProcessId;
use core::ffi::{c_int, c_void};
use core::mem::size_of;
use core::ptr;

const RM_INIT_MAGIC: c_int = 0x2351_3473;
const TLF_PERMANENT: c_int = 2;
const TLF_ALLOW_PREPEND: c_int = 4;
const TLF_NOALIGN: c_int = 16;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawMessage {
    first: *mut c_void,
    last: *mut c_void,
    total_bytes: c_int,
    magic: c_int,
    first_offset: c_int,
    last_offset: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlInMethods {
    fetch_raw_data: Option<unsafe extern "C" fn(*mut TlInState, *mut c_void, c_int)>,
    fetch_move: Option<unsafe extern "C" fn(*mut TlInState, c_int)>,
    fetch_lookup: Option<unsafe extern "C" fn(*mut TlInState, *mut c_void, c_int)>,
    fetch_clear: Option<unsafe extern "C" fn(*mut TlInState)>,
    fetch_mark: Option<unsafe extern "C" fn(*mut TlInState)>,
    fetch_mark_restore: Option<unsafe extern "C" fn(*mut TlInState)>,
    fetch_mark_delete: Option<unsafe extern "C" fn(*mut TlInState)>,
    fetch_raw_message: Option<unsafe extern "C" fn(*mut TlInState, *mut RawMessage, c_int)>,
    fetch_lookup_raw_message:
        Option<unsafe extern "C" fn(*mut TlInState, *mut RawMessage, c_int)>,
    flags: c_int,
    prepend_bytes: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlOutMethods {
    store_get_ptr: Option<unsafe extern "C" fn(*mut TlOutState, c_int) -> *mut c_void>,
    store_get_prepend_ptr: Option<unsafe extern "C" fn(*mut TlOutState, c_int) -> *mut c_void>,
    store_raw_data: Option<unsafe extern "C" fn(*mut TlOutState, *const c_void, c_int)>,
    store_raw_msg: Option<unsafe extern "C" fn(*mut TlOutState, *mut RawMessage)>,
    store_read_back: Option<unsafe extern "C" fn(*mut TlOutState, c_int)>,
    store_read_back_nondestruct:
        Option<unsafe extern "C" fn(*mut TlOutState, *mut c_void, c_int)>,
    store_crc32_partial: Option<unsafe extern "C" fn(*mut TlOutState, c_int, u32) -> u32>,
    store_flush: Option<unsafe extern "C" fn(*mut TlOutState)>,
    store_clear: Option<unsafe extern "C" fn(*mut TlOutState)>,
    copy_through: [
        Option<unsafe extern "C" fn(*mut TlInState, *mut TlOutState, c_int, c_int)>;
        10
    ],
    store_prefix: Option<unsafe extern "C" fn(*mut TlOutState)>,
    flags: c_int,
    prepend_bytes: c_int,
}

#[repr(C)]
struct TlInState {
    in_type: c_int,
    in_methods: *const TlInMethods,
    in_ptr: *mut c_void,
    in_mark: *mut c_void,
    in_remaining: c_int,
    in_pos: c_int,
    in_mark_pos: c_int,
    in_flags: c_int,
    error: *mut i8,
    errnum: c_int,
    in_pid_buf: MtproxyProcessId,
    in_pid: *mut MtproxyProcessId,
}

#[repr(C)]
struct TlOutState {
    out_type: c_int,
    out_methods: *const TlOutMethods,
    out_ptr: *mut c_void,
    out_extra: *mut c_void,
    out_pos: c_int,
    out_remaining: c_int,
    out_size: *mut c_int,
    error: *mut i8,
    errnum: c_int,
    out_qid: i64,
    out_pid_buf: MtproxyProcessId,
    out_pid: *mut MtproxyProcessId,
}

unsafe extern "C" {
    fn rwm_fetch_data(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn rwm_fetch_lookup(raw: *mut RawMessage, buf: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_split_head(head: *mut RawMessage, raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn rwm_clone(dest_raw: *mut RawMessage, src_raw: *mut RawMessage);
    fn rwm_trunc(raw: *mut RawMessage, len: c_int) -> c_int;
    fn rwm_union(raw: *mut RawMessage, tail: *mut RawMessage) -> c_int;
    fn rwm_free(raw: *mut RawMessage) -> c_int;
    fn rwm_postpone_alloc(raw: *mut RawMessage, alloc_bytes: c_int) -> *mut c_void;
    fn rwm_prepend_alloc(raw: *mut RawMessage, alloc_bytes: c_int) -> *mut c_void;
    fn rwm_push_data(raw: *mut RawMessage, data: *const c_void, alloc_bytes: c_int) -> c_int;
    fn rwm_fetch_data_back(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;

    fn tcp_rpc_conn_send(c_tag_int: c_int, c: *mut c_void, raw: *mut RawMessage, flags: c_int);
    fn job_decref(job_tag_int: c_int, job: *mut c_void);
}

unsafe fn add_bytes(ptr_: *mut c_void, len: c_int) -> *mut c_void {
    if len <= 0 {
        return ptr_;
    }
    (ptr_ as *mut u8).add(len as usize).cast::<c_void>()
}

unsafe fn sub_bytes(ptr_: *mut c_void, len: c_int) -> *mut c_void {
    if len <= 0 {
        return ptr_;
    }
    (ptr_ as *mut u8).sub(len as usize).cast::<c_void>()
}

unsafe fn in_raw(state: *mut TlInState) -> *mut RawMessage {
    (*state).in_ptr.cast::<RawMessage>()
}

unsafe fn out_raw(state: *mut TlOutState) -> *mut RawMessage {
    (*state).out_ptr.cast::<RawMessage>()
}

unsafe extern "C" fn tl_raw_msg_fetch_raw_data(
    tlio_in: *mut TlInState,
    buf: *mut c_void,
    len: c_int,
) {
    debug_assert!(rwm_fetch_data(in_raw(tlio_in), buf, len) == len);
}

unsafe extern "C" fn tl_raw_msg_fetch_move(tlio_in: *mut TlInState, len: c_int) {
    debug_assert!(len >= 0);
    debug_assert!(rwm_skip_data(in_raw(tlio_in), len) == len);
}

unsafe extern "C" fn tl_raw_msg_fetch_lookup(
    tlio_in: *mut TlInState,
    buf: *mut c_void,
    len: c_int,
) {
    debug_assert!(rwm_fetch_lookup(in_raw(tlio_in), buf, len) == len);
}

unsafe extern "C" fn tl_raw_msg_fetch_raw_message(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    len: c_int,
) {
    let _ = rwm_split_head(raw, in_raw(tlio_in), len);
}

unsafe extern "C" fn tl_raw_msg_fetch_lookup_raw_message(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    len: c_int,
) {
    rwm_clone(raw, in_raw(tlio_in));
    let _ = rwm_trunc(raw, len);
}

unsafe extern "C" fn tl_raw_msg_fetch_mark(tlio_in: *mut TlInState) {
    debug_assert!((*tlio_in).in_mark.is_null());
    let mark = libc::malloc(size_of::<RawMessage>()).cast::<RawMessage>();
    debug_assert!(!mark.is_null());
    rwm_clone(mark, in_raw(tlio_in));
    (*tlio_in).in_mark = mark.cast::<c_void>();
    (*tlio_in).in_mark_pos = (*tlio_in).in_pos;
}

unsafe extern "C" fn tl_raw_msg_fetch_mark_restore(tlio_in: *mut TlInState) {
    debug_assert!(!(*tlio_in).in_mark.is_null());
    let mark = (*tlio_in).in_mark.cast::<RawMessage>();
    let raw = in_raw(tlio_in);
    let _ = rwm_free(raw);
    *raw = *mark;
    libc::free(mark.cast::<c_void>());
    (*tlio_in).in_mark = ptr::null_mut();
    let delta = (*tlio_in).in_pos - (*tlio_in).in_mark_pos;
    (*tlio_in).in_pos -= delta;
    (*tlio_in).in_remaining += delta;
}

unsafe extern "C" fn tl_raw_msg_fetch_mark_delete(tlio_in: *mut TlInState) {
    debug_assert!(!(*tlio_in).in_mark.is_null());
    let mark = (*tlio_in).in_mark.cast::<RawMessage>();
    let _ = rwm_free(mark);
    libc::free(mark.cast::<c_void>());
    (*tlio_in).in_mark = ptr::null_mut();
}

unsafe extern "C" fn tl_raw_msg_store_get_ptr(
    tlio_out: *mut TlOutState,
    len: c_int,
) -> *mut c_void {
    rwm_postpone_alloc(out_raw(tlio_out), len)
}

unsafe extern "C" fn tl_raw_msg_store_get_prepend_ptr(
    tlio_out: *mut TlOutState,
    len: c_int,
) -> *mut c_void {
    rwm_prepend_alloc(out_raw(tlio_out), len)
}

unsafe extern "C" fn tl_raw_msg_store_raw_data(
    tlio_out: *mut TlOutState,
    buf: *const c_void,
    len: c_int,
) {
    debug_assert!(rwm_push_data(out_raw(tlio_out), buf, len) == len);
}

unsafe extern "C" fn tl_raw_msg_store_raw_msg(tlio_out: *mut TlOutState, raw: *mut RawMessage) {
    let _ = rwm_union(out_raw(tlio_out), raw);
}

unsafe extern "C" fn tl_raw_msg_store_read_back(tlio_out: *mut TlOutState, len: c_int) {
    debug_assert!(rwm_fetch_data_back(out_raw(tlio_out), ptr::null_mut(), len) == len);
}

unsafe extern "C" fn tl_raw_msg_store_read_back_nondestruct(
    tlio_out: *mut TlOutState,
    buf: *mut c_void,
    len: c_int,
) {
    let mut r = RawMessage {
        first: ptr::null_mut(),
        last: ptr::null_mut(),
        total_bytes: 0,
        magic: 0,
        first_offset: 0,
        last_offset: 0,
    };
    rwm_clone(&mut r, out_raw(tlio_out));
    debug_assert!(rwm_fetch_data_back(&mut r, buf, len) == len);
    let _ = rwm_free(&mut r);
}

unsafe extern "C" fn tl_raw_msg_raw_msg_copy_through(
    tlio_in: *mut TlInState,
    tlio_out: *mut TlOutState,
    len: c_int,
    advance: c_int,
) {
    if advance == 0 {
        let mut r = RawMessage {
            first: ptr::null_mut(),
            last: ptr::null_mut(),
            total_bytes: 0,
            magic: 0,
            first_offset: 0,
            last_offset: 0,
        };
        rwm_clone(&mut r, in_raw(tlio_in));
        let _ = rwm_trunc(&mut r, len);
        let _ = rwm_union(out_raw(tlio_out), &mut r);
    } else {
        let mut r = RawMessage {
            first: ptr::null_mut(),
            last: ptr::null_mut(),
            total_bytes: 0,
            magic: 0,
            first_offset: 0,
            last_offset: 0,
        };
        let _ = rwm_split_head(&mut r, in_raw(tlio_in), len);
        let _ = rwm_union(out_raw(tlio_out), &mut r);
        debug_assert!((*in_raw(tlio_in)).magic == RM_INIT_MAGIC);
    }
}

unsafe extern "C" fn tl_raw_msg_str_copy_through(
    tlio_in: *mut TlInState,
    tlio_out: *mut TlOutState,
    len: c_int,
    advance: c_int,
) {
    let out_ptr = (*tlio_out).out_ptr;
    if advance != 0 {
        debug_assert!(rwm_fetch_data(in_raw(tlio_in), out_ptr, len) == len);
    } else {
        debug_assert!(rwm_fetch_lookup(in_raw(tlio_in), out_ptr, len) == len);
    }
    (*tlio_out).out_ptr = add_bytes((*tlio_out).out_ptr, len);
}

unsafe extern "C" fn tl_raw_msg_fetch_clear(tlio_in: *mut TlInState) {
    if !(*tlio_in).in_ptr.is_null() {
        let raw = in_raw(tlio_in);
        let _ = rwm_free(raw);
        libc::free(raw.cast::<c_void>());
        (*tlio_in).in_ptr = ptr::null_mut();
    }
}

unsafe extern "C" fn tl_raw_msg_store_clear(tlio_out: *mut TlOutState) {
    if !(*tlio_out).out_ptr.is_null() {
        let raw = out_raw(tlio_out);
        let _ = rwm_free(raw);
        libc::free(raw.cast::<c_void>());
        (*tlio_out).out_ptr = ptr::null_mut();
    }
}

unsafe extern "C" fn tl_raw_msg_store_flush(tlio_out: *mut TlOutState) {
    if !(*tlio_out).out_ptr.is_null() {
        let raw = out_raw(tlio_out);
        let _ = rwm_free(raw);
        libc::free(raw.cast::<c_void>());
        (*tlio_out).out_ptr = ptr::null_mut();
    }
}

unsafe extern "C" fn tl_tcp_raw_msg_store_clear(tlio_out: *mut TlOutState) {
    if !(*tlio_out).out_ptr.is_null() {
        let raw = out_raw(tlio_out);
        let _ = rwm_free(raw);
        libc::free(raw.cast::<c_void>());
        if !(*tlio_out).out_extra.is_null() {
            job_decref(1, (*tlio_out).out_extra);
        }
        (*tlio_out).out_ptr = ptr::null_mut();
        (*tlio_out).out_extra = ptr::null_mut();
    }
}

unsafe extern "C" fn tl_tcp_raw_msg_store_flush(tlio_out: *mut TlOutState) {
    debug_assert!(!(*tlio_out).out_ptr.is_null());
    debug_assert!(!(*tlio_out).out_extra.is_null());
    tcp_rpc_conn_send(1, (*tlio_out).out_extra, out_raw(tlio_out), 4);
    (*tlio_out).out_ptr = ptr::null_mut();
}

unsafe extern "C" fn tl_tcp_raw_msg_store_flush_unaligned(tlio_out: *mut TlOutState) {
    debug_assert!(!(*tlio_out).out_ptr.is_null());
    debug_assert!(!(*tlio_out).out_extra.is_null());
    tcp_rpc_conn_send(1, (*tlio_out).out_extra, out_raw(tlio_out), 12);
    (*tlio_out).out_ptr = ptr::null_mut();
}

unsafe extern "C" fn tl_str_fetch_raw_data(
    tlio_in: *mut TlInState,
    buf: *mut c_void,
    len: c_int,
) {
    ptr::copy_nonoverlapping((*tlio_in).in_ptr.cast::<u8>(), buf.cast::<u8>(), len as usize);
    (*tlio_in).in_ptr = add_bytes((*tlio_in).in_ptr, len);
}

unsafe extern "C" fn tl_str_fetch_move(tlio_in: *mut TlInState, len: c_int) {
    (*tlio_in).in_ptr = add_bytes((*tlio_in).in_ptr, len);
}

unsafe extern "C" fn tl_str_fetch_lookup(
    tlio_in: *mut TlInState,
    buf: *mut c_void,
    len: c_int,
) {
    ptr::copy_nonoverlapping((*tlio_in).in_ptr.cast::<u8>(), buf.cast::<u8>(), len as usize);
}

unsafe extern "C" fn tl_str_fetch_raw_message(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    len: c_int,
) {
    let _ = rwm_push_data(raw, (*tlio_in).in_ptr, len);
    (*tlio_in).in_ptr = add_bytes((*tlio_in).in_ptr, len);
}

unsafe extern "C" fn tl_str_fetch_lookup_raw_message(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    len: c_int,
) {
    let _ = rwm_push_data(raw, (*tlio_in).in_ptr, len);
}

unsafe extern "C" fn tl_str_store_get_ptr(tlio_out: *mut TlOutState, len: c_int) -> *mut c_void {
    let r = (*tlio_out).out_ptr;
    (*tlio_out).out_ptr = add_bytes((*tlio_out).out_ptr, len);
    r
}

unsafe extern "C" fn tl_str_store_get_prepend_ptr(
    tlio_out: *mut TlOutState,
    len: c_int,
) -> *mut c_void {
    sub_bytes((*tlio_out).out_ptr, (*tlio_out).out_pos + len)
}

unsafe extern "C" fn tl_str_store_raw_data(
    tlio_out: *mut TlOutState,
    buf: *const c_void,
    len: c_int,
) {
    ptr::copy_nonoverlapping(buf.cast::<u8>(), (*tlio_out).out_ptr.cast::<u8>(), len as usize);
    (*tlio_out).out_ptr = add_bytes((*tlio_out).out_ptr, len);
}

unsafe extern "C" fn tl_str_store_raw_msg(tlio_out: *mut TlOutState, raw: *mut RawMessage) {
    let len = (*raw).total_bytes;
    let _ = rwm_fetch_data(raw, (*tlio_out).out_ptr, len);
    (*tlio_out).out_ptr = add_bytes((*tlio_out).out_ptr, len);
}

unsafe extern "C" fn tl_str_store_read_back(tlio_out: *mut TlOutState, len: c_int) {
    (*tlio_out).out_ptr = sub_bytes((*tlio_out).out_ptr, len);
}

unsafe extern "C" fn tl_str_store_read_back_nondestruct(
    tlio_out: *mut TlOutState,
    buf: *mut c_void,
    len: c_int,
) {
    ptr::copy_nonoverlapping(
        buf.cast::<u8>(),
        sub_bytes((*tlio_out).out_ptr, len).cast::<u8>(),
        len as usize,
    );
}

unsafe extern "C" fn tl_str_raw_msg_copy_through(
    tlio_in: *mut TlInState,
    tlio_out: *mut TlOutState,
    len: c_int,
    advance: c_int,
) {
    debug_assert!(rwm_push_data(out_raw(tlio_out), (*tlio_in).in_ptr, len) == len);
    if advance != 0 {
        (*tlio_in).in_ptr = add_bytes((*tlio_in).in_ptr, advance);
    }
}

unsafe extern "C" fn tl_str_str_copy_through(
    tlio_in: *mut TlInState,
    tlio_out: *mut TlOutState,
    len: c_int,
    advance: c_int,
) {
    ptr::copy_nonoverlapping(
        (*tlio_in).in_ptr.cast::<u8>(),
        (*tlio_out).out_ptr.cast::<u8>(),
        len as usize,
    );
    (*tlio_out).out_ptr = add_bytes((*tlio_out).out_ptr, len);
    if advance != 0 {
        (*tlio_in).in_ptr = add_bytes((*tlio_in).in_ptr, advance);
    }
}

unsafe extern "C" fn tl_str_fetch_mark(tlio_in: *mut TlInState) {
    debug_assert!((*tlio_in).in_mark.is_null());
    (*tlio_in).in_mark = (*tlio_in).in_ptr;
    (*tlio_in).in_mark_pos = (*tlio_in).in_pos;
}

unsafe extern "C" fn tl_str_fetch_mark_restore(tlio_in: *mut TlInState) {
    (*tlio_in).in_ptr = (*tlio_in).in_mark;
    (*tlio_in).in_mark = ptr::null_mut();
    let delta = (*tlio_in).in_pos - (*tlio_in).in_mark_pos;
    (*tlio_in).in_pos -= delta;
    (*tlio_in).in_remaining += delta;
}

unsafe extern "C" fn tl_str_fetch_mark_delete(tlio_in: *mut TlInState) {
    (*tlio_in).in_mark = ptr::null_mut();
}

unsafe extern "C" fn tl_str_store_clear(tlio_out: *mut TlOutState) {
    (*tlio_out).out_ptr = ptr::null_mut();
}

unsafe extern "C" fn tl_str_store_flush(tlio_out: *mut TlOutState) {
    (*tlio_out).out_ptr = ptr::null_mut();
}

#[no_mangle]
pub static tl_in_raw_msg_methods: TlInMethods = TlInMethods {
    fetch_raw_data: Some(tl_raw_msg_fetch_raw_data),
    fetch_move: Some(tl_raw_msg_fetch_move),
    fetch_lookup: Some(tl_raw_msg_fetch_lookup),
    fetch_clear: Some(tl_raw_msg_fetch_clear),
    fetch_mark: Some(tl_raw_msg_fetch_mark),
    fetch_mark_restore: Some(tl_raw_msg_fetch_mark_restore),
    fetch_mark_delete: Some(tl_raw_msg_fetch_mark_delete),
    fetch_raw_message: Some(tl_raw_msg_fetch_raw_message),
    fetch_lookup_raw_message: Some(tl_raw_msg_fetch_lookup_raw_message),
    flags: 0,
    prepend_bytes: 0,
};

#[no_mangle]
pub static tl_in_str_methods: TlInMethods = TlInMethods {
    fetch_raw_data: Some(tl_str_fetch_raw_data),
    fetch_move: Some(tl_str_fetch_move),
    fetch_lookup: Some(tl_str_fetch_lookup),
    fetch_clear: None,
    fetch_mark: Some(tl_str_fetch_mark),
    fetch_mark_restore: Some(tl_str_fetch_mark_restore),
    fetch_mark_delete: Some(tl_str_fetch_mark_delete),
    fetch_raw_message: Some(tl_str_fetch_raw_message),
    fetch_lookup_raw_message: Some(tl_str_fetch_lookup_raw_message),
    flags: 0,
    prepend_bytes: 0,
};

#[no_mangle]
pub static tl_out_raw_msg_methods: TlOutMethods = TlOutMethods {
    store_get_ptr: Some(tl_raw_msg_store_get_ptr),
    store_get_prepend_ptr: Some(tl_raw_msg_store_get_prepend_ptr),
    store_raw_data: Some(tl_raw_msg_store_raw_data),
    store_raw_msg: Some(tl_raw_msg_store_raw_msg),
    store_read_back: Some(tl_raw_msg_store_read_back),
    store_read_back_nondestruct: Some(tl_raw_msg_store_read_back_nondestruct),
    store_crc32_partial: None,
    store_flush: Some(tl_raw_msg_store_flush),
    store_clear: Some(tl_raw_msg_store_clear),
    copy_through: [
        None,
        Some(tl_str_raw_msg_copy_through),
        Some(tl_raw_msg_raw_msg_copy_through),
        Some(tl_raw_msg_raw_msg_copy_through),
        None,
        None,
        None,
        None,
        None,
        None,
    ],
    store_prefix: None,
    flags: TLF_ALLOW_PREPEND,
    prepend_bytes: 0,
};

#[no_mangle]
pub static tl_out_raw_msg_methods_nosend: TlOutMethods = TlOutMethods {
    store_get_ptr: Some(tl_raw_msg_store_get_ptr),
    store_get_prepend_ptr: Some(tl_raw_msg_store_get_prepend_ptr),
    store_raw_data: Some(tl_raw_msg_store_raw_data),
    store_raw_msg: Some(tl_raw_msg_store_raw_msg),
    store_read_back: Some(tl_raw_msg_store_read_back),
    store_read_back_nondestruct: Some(tl_raw_msg_store_read_back_nondestruct),
    store_crc32_partial: None,
    store_flush: None,
    store_clear: Some(tl_raw_msg_store_clear),
    copy_through: [
        None,
        Some(tl_str_raw_msg_copy_through),
        Some(tl_raw_msg_raw_msg_copy_through),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ],
    store_prefix: None,
    flags: TLF_ALLOW_PREPEND,
    prepend_bytes: 0,
};

#[no_mangle]
pub static tl_out_tcp_raw_msg_methods: TlOutMethods = TlOutMethods {
    store_get_ptr: Some(tl_raw_msg_store_get_ptr),
    store_get_prepend_ptr: Some(tl_raw_msg_store_get_prepend_ptr),
    store_raw_data: Some(tl_raw_msg_store_raw_data),
    store_raw_msg: Some(tl_raw_msg_store_raw_msg),
    store_read_back: Some(tl_raw_msg_store_read_back),
    store_read_back_nondestruct: Some(tl_raw_msg_store_read_back_nondestruct),
    store_crc32_partial: None,
    store_flush: Some(tl_tcp_raw_msg_store_flush),
    store_clear: Some(tl_tcp_raw_msg_store_clear),
    copy_through: [
        None,
        Some(tl_str_raw_msg_copy_through),
        Some(tl_raw_msg_raw_msg_copy_through),
        Some(tl_raw_msg_raw_msg_copy_through),
        None,
        None,
        None,
        None,
        None,
        None,
    ],
    store_prefix: None,
    flags: TLF_ALLOW_PREPEND,
    prepend_bytes: 0,
};

#[no_mangle]
pub static tl_out_tcp_raw_msg_unaligned_methods: TlOutMethods = TlOutMethods {
    store_get_ptr: Some(tl_raw_msg_store_get_ptr),
    store_get_prepend_ptr: Some(tl_raw_msg_store_get_prepend_ptr),
    store_raw_data: Some(tl_raw_msg_store_raw_data),
    store_raw_msg: Some(tl_raw_msg_store_raw_msg),
    store_read_back: Some(tl_raw_msg_store_read_back),
    store_read_back_nondestruct: Some(tl_raw_msg_store_read_back_nondestruct),
    store_crc32_partial: None,
    store_flush: Some(tl_tcp_raw_msg_store_flush_unaligned),
    store_clear: Some(tl_tcp_raw_msg_store_clear),
    copy_through: [
        None,
        Some(tl_str_raw_msg_copy_through),
        Some(tl_raw_msg_raw_msg_copy_through),
        Some(tl_raw_msg_raw_msg_copy_through),
        None,
        None,
        None,
        None,
        None,
        None,
    ],
    store_prefix: None,
    flags: TLF_ALLOW_PREPEND | TLF_NOALIGN,
    prepend_bytes: 0,
};

#[no_mangle]
pub static tl_out_str_methods: TlOutMethods = TlOutMethods {
    store_get_ptr: Some(tl_str_store_get_ptr),
    store_get_prepend_ptr: Some(tl_str_store_get_prepend_ptr),
    store_raw_data: Some(tl_str_store_raw_data),
    store_raw_msg: Some(tl_str_store_raw_msg),
    store_read_back: Some(tl_str_store_read_back),
    store_read_back_nondestruct: Some(tl_str_store_read_back_nondestruct),
    store_crc32_partial: None,
    store_flush: Some(tl_str_store_flush),
    store_clear: Some(tl_str_store_clear),
    copy_through: [
        None,
        Some(tl_str_str_copy_through),
        Some(tl_raw_msg_str_copy_through),
        Some(tl_raw_msg_str_copy_through),
        None,
        None,
        None,
        None,
        None,
        None,
    ],
    store_prefix: None,
    flags: TLF_PERMANENT | TLF_ALLOW_PREPEND,
    prepend_bytes: 0,
};
