use super::MtproxyProcessId;
use core::ffi::{c_int, c_void};
use core::mem::size_of;
use core::ptr;
use std::ffi::CString;

const RM_INIT_MAGIC: c_int = 0x2351_3473;
const TLF_PERMANENT: c_int = 2;
const TLF_ALLOW_PREPEND: c_int = 4;
const TLF_DISABLE_PREPEND: c_int = 8;
const TLF_NOALIGN: c_int = 16;
const TLF_NO_AUTOFLUSH: c_int = 32;
const TL_TYPE_NONE: c_int = 0;
const TL_TYPE_STR: c_int = 1;
const TL_TYPE_RAW_MSG: c_int = 2;
const TL_TYPE_TCP_RAW_MSG: c_int = 3;
const RPC_INVOKE_REQ: c_int = mtproxy_core::runtime::config::tl_parse::RPC_INVOKE_REQ;
const RPC_REQ_ERROR: c_int = mtproxy_core::runtime::config::tl_parse::RPC_REQ_ERROR;
const RPC_REQ_RESULT: c_int = mtproxy_core::runtime::config::tl_parse::RPC_REQ_RESULT;
const RPC_REQ_ERROR_WRAPPED: c_int = mtproxy_core::runtime::config::tl_parse::RPC_REQ_ERROR_WRAPPED;
const RPC_DEST_ACTOR: c_int = mtproxy_core::runtime::config::tl_parse::RPC_DEST_ACTOR;
const RPC_DEST_ACTOR_FLAGS: c_int = mtproxy_core::runtime::config::tl_parse::RPC_DEST_ACTOR_FLAGS;
const RPC_REQ_RESULT_FLAGS: c_int = mtproxy_core::runtime::config::tl_parse::RPC_REQ_RESULT_FLAGS;
const TL_SENT_KIND_NONE: c_int = 0;
const TL_SENT_KIND_ERROR: c_int = 1;
const TL_SENT_KIND_ANSWER: c_int = 2;
const TL_SENT_KIND_QUERY: c_int = 3;
const TL_FETCH_FLAG_ALLOW_DATA_AFTER_QUERY: c_int =
    mtproxy_core::runtime::config::tl_parse::TL_FETCH_FLAG_ALLOW_DATA_AFTER_QUERY;
const TL_ERROR_SYNTAX: c_int = mtproxy_core::runtime::config::tl_parse::TL_ERROR_SYNTAX;
const TL_ERROR_EXTRA_DATA: c_int = mtproxy_core::runtime::config::tl_parse::TL_ERROR_EXTRA_DATA;
const TL_ERROR_HEADER: c_int = mtproxy_core::runtime::config::tl_parse::TL_ERROR_HEADER;
const TL_ERROR_NOT_ENOUGH_DATA: c_int =
    mtproxy_core::runtime::config::tl_parse::TL_ERROR_NOT_ENOUGH_DATA;
const TL_ERROR_TOO_LONG_STRING: c_int =
    mtproxy_core::runtime::config::tl_parse::TL_ERROR_TOO_LONG_STRING;
const TL_ERROR_VALUE_NOT_IN_RANGE: c_int =
    mtproxy_core::runtime::config::tl_parse::TL_ERROR_VALUE_NOT_IN_RANGE;
const TL_ERROR_INTERNAL: c_int = mtproxy_core::runtime::config::tl_parse::TL_ERROR_INTERNAL;

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
#[derive(Clone, Copy)]
pub struct TlQueryHeader {
    qid: i64,
    actor_id: i64,
    flags: c_int,
    op: c_int,
    real_op: c_int,
    ref_cnt: c_int,
    qw_params: *mut c_void,
}

#[repr(C)]
pub struct TlInState {
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
pub struct TlOutState {
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
    fn rwm_move(dest_raw: *mut RawMessage, src_raw: *mut RawMessage);
    fn rwm_init(raw: *mut RawMessage, alloc_bytes: c_int) -> c_int;

    fn tcp_rpc_conn_send(c_tag_int: c_int, c: *mut c_void, raw: *mut RawMessage, flags: c_int);
    fn job_decref(job_tag_int: c_int, job: *mut c_void);
    fn strdup(src: *const i8) -> *mut i8;
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

unsafe fn tl_fetch_init_impl(
    tlio_in: *mut TlInState,
    in_ptr: *mut c_void,
    type_: c_int,
    methods: *const TlInMethods,
    size: c_int,
) -> c_int {
    if tlio_in.is_null() || in_ptr.is_null() || methods.is_null() {
        return -1;
    }
    if (*tlio_in).in_type != TL_TYPE_NONE {
        return -1;
    }
    (*tlio_in).in_type = type_;
    (*tlio_in).in_ptr = in_ptr;
    (*tlio_in).in_remaining = size;
    (*tlio_in).in_pos = 0;
    (*tlio_in).in_flags = 0;
    (*tlio_in).in_methods = methods;
    if !(*tlio_in).error.is_null() {
        libc::free((*tlio_in).error.cast::<c_void>());
        (*tlio_in).error = ptr::null_mut();
    }
    (*tlio_in).errnum = 0;
    0
}

unsafe fn tl_set_error_once(tlio_in: *mut TlInState, errnum: c_int, message: &str) {
    if tlio_in.is_null() || !(*tlio_in).error.is_null() {
        return;
    }
    let msg = CString::new(message)
        .ok()
        .unwrap_or_else(|| CString::new("TL parse error").expect("valid static c string"));
    (*tlio_in).error = strdup(msg.as_ptr());
    (*tlio_in).errnum = errnum;
}

unsafe fn tl_in_skip(tlio_in: *mut TlInState, len: c_int) -> c_int {
    if tlio_in.is_null() || len < 0 || (*tlio_in).in_remaining < len || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_move) = methods.fetch_move else {
        return -1;
    };
    fetch_move(tlio_in, len);
    (*tlio_in).in_pos += len;
    (*tlio_in).in_remaining -= len;
    len
}

unsafe fn tl_in_fetch_raw_any(tlio_in: *mut TlInState, dst: *mut c_void, len: c_int) -> c_int {
    if tlio_in.is_null()
        || dst.is_null()
        || len < 0
        || (*tlio_in).in_remaining < len
        || (*tlio_in).in_methods.is_null()
    {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_raw_data) = methods.fetch_raw_data else {
        return -1;
    };
    fetch_raw_data(tlio_in, dst, len);
    (*tlio_in).in_pos += len;
    (*tlio_in).in_remaining -= len;
    len
}

unsafe fn tl_in_lookup_data(tlio_in: *mut TlInState, dst: *mut c_void, len: c_int) -> c_int {
    if tlio_in.is_null()
        || dst.is_null()
        || len < 0
        || (*tlio_in).in_remaining < len
        || (*tlio_in).in_methods.is_null()
    {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_lookup) = methods.fetch_lookup else {
        return -1;
    };
    fetch_lookup(tlio_in, dst, len);
    len
}

unsafe fn tl_query_header_parse_impl(
    tlio_in: *mut TlInState,
    header: *mut TlQueryHeader,
    is_answer: bool,
) -> c_int {
    if tlio_in.is_null() || header.is_null() || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    ptr::write_bytes(header.cast::<u8>(), 0, size_of::<TlQueryHeader>());
    let total_unread = (*tlio_in).in_remaining;
    let prepend = (*(*tlio_in).in_methods).prepend_bytes;
    if prepend > 0 && tl_in_skip(tlio_in, prepend) < 0 {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_HEADER,
            if is_answer {
                "Expected RPC_REQ_ERROR or RPC_REQ_RESULT"
            } else {
                "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ"
            },
        );
        return -1;
    }

    let unread = (*tlio_in).in_remaining;
    if unread < 0 {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_HEADER,
            if is_answer {
                "Expected RPC_REQ_ERROR or RPC_REQ_RESULT"
            } else {
                "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ"
            },
        );
        return -1;
    }
    let unread_usize = usize::try_from(unread).unwrap_or(0);
    let mut buf = vec![0u8; unread_usize];
    if unread > 0
        && tl_in_lookup_data(tlio_in, buf.as_mut_ptr().cast::<c_void>(), unread) != unread
    {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_HEADER,
            if is_answer {
                "Expected RPC_REQ_ERROR or RPC_REQ_RESULT"
            } else {
                "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ"
            },
        );
        return -1;
    }

    let parsed = if is_answer {
        mtproxy_core::runtime::config::tl_parse::parse_answer_header(&buf)
    } else {
        mtproxy_core::runtime::config::tl_parse::parse_query_header(&buf)
    };
    let parsed = match parsed {
        Ok(v) => v,
        Err(err) => {
            tl_set_error_once(tlio_in, err.errnum, &err.message);
            return -1;
        }
    };

    let consumed = c_int::try_from(parsed.consumed).unwrap_or(c_int::MAX);
    if consumed <= 0 || consumed > unread || tl_in_skip(tlio_in, consumed) < 0 {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_HEADER,
            if is_answer {
                "Expected RPC_REQ_ERROR or RPC_REQ_RESULT"
            } else {
                "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ"
            },
        );
        return -1;
    }

    (*header).op = parsed.header.op;
    (*header).real_op = parsed.header.real_op;
    (*header).flags = parsed.header.flags;
    (*header).qid = parsed.header.qid;
    (*header).actor_id = parsed.header.actor_id;
    (*header).ref_cnt = 1;
    total_unread - (*tlio_in).in_remaining
}

unsafe fn tl_store_init_impl(
    tlio_out: *mut TlOutState,
    out: *mut c_void,
    out_extra: *mut c_void,
    type_: c_int,
    methods: *const TlOutMethods,
    size: c_int,
    qid: i64,
) -> c_int {
    if tlio_out.is_null() {
        return -1;
    }
    if !(*tlio_out).out_methods.is_null() {
        return -1;
    }

    (*tlio_out).out_ptr = out;
    (*tlio_out).out_extra = out_extra;

    if !out.is_null() {
        if methods.is_null() {
            return -1;
        }
        (*tlio_out).out_methods = methods;
        (*tlio_out).out_type = type_;
        if type_ != TL_TYPE_NONE && (((*methods).flags & (TLF_ALLOW_PREPEND | TLF_DISABLE_PREPEND)) == 0)
        {
            let reserve = (*methods).prepend_bytes + if qid != 0 { 12 } else { 0 };
            let Some(store_get_ptr) = (*methods).store_get_ptr else {
                return -1;
            };
            (*tlio_out).out_size = store_get_ptr(tlio_out, reserve).cast::<c_int>();
        }
    } else {
        (*tlio_out).out_type = TL_TYPE_NONE;
    }

    (*tlio_out).out_pos = 0;
    (*tlio_out).out_qid = qid;
    (*tlio_out).out_remaining = size;
    (*tlio_out).errnum = 0;
    (*tlio_out).error = ptr::null_mut();
    0
}

unsafe fn tl_out_store_raw_data(
    tlio_out: *mut TlOutState,
    data: *const c_void,
    len: c_int,
) -> c_int {
    if tlio_out.is_null() || len < 0 {
        return -1;
    }
    if len == 0 {
        return 0;
    }
    if data.is_null() {
        return -1;
    }
    if (*tlio_out).out_type == TL_TYPE_NONE || (*tlio_out).out_methods.is_null() {
        return -1;
    }
    if (*tlio_out).out_remaining < len {
        return -1;
    }
    let methods = &*(*tlio_out).out_methods;
    let Some(store_raw_data) = methods.store_raw_data else {
        return -1;
    };
    store_raw_data(tlio_out, data, len);
    (*tlio_out).out_pos += len;
    (*tlio_out).out_remaining -= len;
    0
}

unsafe fn tl_out_store_int(tlio_out: *mut TlOutState, value: c_int) -> c_int {
    let bytes = value.to_le_bytes();
    tl_out_store_raw_data(tlio_out, bytes.as_ptr().cast::<c_void>(), 4)
}

unsafe fn tl_out_store_long(tlio_out: *mut TlOutState, value: i64) -> c_int {
    let bytes = value.to_le_bytes();
    tl_out_store_raw_data(tlio_out, bytes.as_ptr().cast::<c_void>(), 8)
}

unsafe fn tl_out_store_string_len(tlio_out: *mut TlOutState, len: usize) -> c_int {
    if len < 254 {
        let b = [u8::try_from(len).unwrap_or(0)];
        return tl_out_store_raw_data(tlio_out, b.as_ptr().cast::<c_void>(), 1);
    }
    if len >= (1usize << 24) {
        return -1;
    }
    let low = u8::try_from(len & 0xff).unwrap_or(0);
    let mid = u8::try_from((len >> 8) & 0xff).unwrap_or(0);
    let high = u8::try_from((len >> 16) & 0xff).unwrap_or(0);
    let bytes = [0xfe, low, mid, high];
    tl_out_store_raw_data(tlio_out, bytes.as_ptr().cast::<c_void>(), 4)
}

unsafe fn tl_out_store_pad(tlio_out: *mut TlOutState) -> c_int {
    let pad = (4 - ((*tlio_out).out_pos & 3)) & 3;
    if pad == 0 {
        return 0;
    }
    let zeros = [0u8; 3];
    tl_out_store_raw_data(
        tlio_out,
        zeros.as_ptr().cast::<c_void>(),
        c_int::try_from(pad).unwrap_or(0),
    )
}

unsafe fn tl_out_store_string0(tlio_out: *mut TlOutState, s: *const i8) -> c_int {
    if s.is_null() {
        return -1;
    }
    let len = libc::strlen(s);
    if tl_out_store_string_len(tlio_out, len) < 0 {
        return -1;
    }
    if len > 0 {
        if tl_out_store_raw_data(
            tlio_out,
            s.cast::<c_void>(),
            c_int::try_from(len).unwrap_or(c_int::MAX),
        ) < 0
        {
            return -1;
        }
    }
    tl_out_store_pad(tlio_out)
}

unsafe fn tl_out_clean(tlio_out: *mut TlOutState) -> c_int {
    if tlio_out.is_null() || (*tlio_out).out_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_out).out_methods;
    let Some(store_read_back) = methods.store_read_back else {
        return -1;
    };
    store_read_back(tlio_out, (*tlio_out).out_pos);
    (*tlio_out).out_remaining += (*tlio_out).out_pos;
    (*tlio_out).out_pos = 0;
    0
}

unsafe fn tl_in_check(tlio_in: *mut TlInState, nbytes: c_int) -> c_int {
    if tlio_in.is_null() {
        return -1;
    }
    if (*tlio_in).in_type == TL_TYPE_NONE {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_INTERNAL,
            "Trying to read from unitialized in buffer",
        );
        return -1;
    }
    if !(*tlio_in).error.is_null() {
        return -1;
    }
    if nbytes >= 0 {
        if (*tlio_in).in_remaining < nbytes {
            let size = (*tlio_in).in_pos + (*tlio_in).in_remaining;
            tl_set_error_once(
                tlio_in,
                TL_ERROR_NOT_ENOUGH_DATA,
                &format!(
                    "Trying to read {nbytes} bytes at position {} (size = {size})",
                    (*tlio_in).in_pos
                ),
            );
            return -1;
        }
    } else if (*tlio_in).in_pos < -nbytes {
        let size = (*tlio_in).in_pos + (*tlio_in).in_remaining;
        tl_set_error_once(
            tlio_in,
            TL_ERROR_NOT_ENOUGH_DATA,
            &format!(
                "Trying to read {nbytes} bytes at position {} (size = {size})",
                (*tlio_in).in_pos
            ),
        );
        return -1;
    }
    0
}

unsafe fn tl_out_check(tlio_out: *mut TlOutState, size: c_int) -> c_int {
    if tlio_out.is_null() || size < 0 {
        return -1;
    }
    if (*tlio_out).out_type == TL_TYPE_NONE {
        return -1;
    }
    if (*tlio_out).out_remaining < size {
        return -1;
    }
    0
}

unsafe fn tl_fetch_string_len_impl(tlio_in: *mut TlInState, max_len: c_int) -> c_int {
    if max_len < 0 || tl_in_check(tlio_in, 4) < 0 {
        return -1;
    }
    let mut first: u8 = 0;
    if tl_in_fetch_raw_any(tlio_in, (&raw mut first).cast::<c_void>(), 1) < 0 {
        return -1;
    }
    if first == 0xff {
        tl_set_error_once(tlio_in, TL_ERROR_SYNTAX, "String len can not start with 0xff");
        return -1;
    }
    let mut len: c_int = c_int::from(first);
    if first == 0xfe {
        let mut ext = [0u8; 3];
        if tl_in_fetch_raw_any(tlio_in, ext.as_mut_ptr().cast::<c_void>(), 3) < 0 {
            return -1;
        }
        len = c_int::from(ext[0]) | (c_int::from(ext[1]) << 8) | (c_int::from(ext[2]) << 16);
    }
    if len > max_len {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_TOO_LONG_STRING,
            &format!("string is too long: max_len = {max_len}, len = {len}"),
        );
        return -1;
    }
    if len > (*tlio_in).in_remaining {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_NOT_ENOUGH_DATA,
            &format!(
                "string is too long: remaining_bytes = {}, len = {len}",
                (*tlio_in).in_remaining
            ),
        );
        return -1;
    }
    len
}

unsafe fn tl_fetch_pad_impl(tlio_in: *mut TlInState) -> c_int {
    if tlio_in.is_null() {
        return -1;
    }
    let pad = (-(*tlio_in).in_pos) & 3;
    if tl_in_check(tlio_in, pad) < 0 {
        return -1;
    }
    if pad == 0 {
        return 0;
    }
    let mut buf = [0u8; 3];
    if tl_in_fetch_raw_any(tlio_in, buf.as_mut_ptr().cast::<c_void>(), pad) < 0 {
        return -1;
    }
    if buf[..usize::try_from(pad).unwrap_or(0)].iter().any(|b| *b != 0) {
        tl_set_error_once(tlio_in, TL_ERROR_SYNTAX, "Padding with non-zeroes");
        return -1;
    }
    pad
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_header(
    tlio_out: *mut TlOutState,
    header: *const TlQueryHeader,
) -> c_int {
    if tlio_out.is_null() || header.is_null() {
        return -1;
    }
    if (*tlio_out).out_type == TL_TYPE_NONE {
        return -1;
    }
    let h = &*header;
    if h.op != RPC_REQ_ERROR
        && h.op != RPC_REQ_RESULT
        && h.op != RPC_INVOKE_REQ
        && h.op != RPC_REQ_ERROR_WRAPPED
    {
        return -1;
    }

    if h.op == RPC_INVOKE_REQ {
        if h.flags != 0 {
            if tl_out_store_int(tlio_out, RPC_DEST_ACTOR_FLAGS) < 0 {
                return -1;
            }
            if tl_out_store_long(tlio_out, h.actor_id) < 0 {
                return -1;
            }
            if tl_out_store_int(tlio_out, h.flags) < 0 {
                return -1;
            }
        } else if h.actor_id != 0 {
            if tl_out_store_int(tlio_out, RPC_DEST_ACTOR) < 0 {
                return -1;
            }
            if tl_out_store_long(tlio_out, h.actor_id) < 0 {
                return -1;
            }
        }
    } else if h.op == RPC_REQ_ERROR_WRAPPED {
        if tl_out_store_int(tlio_out, RPC_REQ_ERROR) < 0 {
            return -1;
        }
        if tl_out_store_long(tlio_out, (*tlio_out).out_qid) < 0 {
            return -1;
        }
    } else if h.op == RPC_REQ_RESULT && h.flags != 0 {
        if tl_out_store_int(tlio_out, RPC_REQ_RESULT_FLAGS) < 0 {
            return -1;
        }
        if tl_out_store_int(tlio_out, h.flags) < 0 {
            return -1;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_end_ext(
    tlio_out: *mut TlOutState,
    op: c_int,
    out_sent_kind: *mut c_int,
) -> c_int {
    if tlio_out.is_null() {
        return -1;
    }
    if !out_sent_kind.is_null() {
        *out_sent_kind = TL_SENT_KIND_NONE;
    }
    if (*tlio_out).out_type == TL_TYPE_NONE {
        return 0;
    }
    if (*tlio_out).out_ptr.is_null() || (*tlio_out).out_methods.is_null() {
        return -1;
    }

    let methods = &*(*tlio_out).out_methods;

    let sent_kind = if !(*tlio_out).error.is_null() {
        if tl_out_clean(tlio_out) < 0 {
            return -1;
        }
        if tl_out_store_int(tlio_out, RPC_REQ_ERROR) < 0 {
            return -1;
        }
        if tl_out_store_long(tlio_out, (*tlio_out).out_qid) < 0 {
            return -1;
        }
        if tl_out_store_int(tlio_out, (*tlio_out).errnum) < 0 {
            return -1;
        }
        if tl_out_store_string0(tlio_out, (*tlio_out).error.cast::<i8>()) < 0 {
            return -1;
        }
        TL_SENT_KIND_ERROR
    } else if op == RPC_REQ_RESULT {
        TL_SENT_KIND_ANSWER
    } else {
        TL_SENT_KIND_QUERY
    };

    if (methods.flags & TLF_NOALIGN) == 0 && ((*tlio_out).out_pos & 3) != 0 {
        return -1;
    }

    let mut p: *mut c_int = if (methods.flags & TLF_ALLOW_PREPEND) != 0 {
        let reserve = methods.prepend_bytes + if (*tlio_out).out_qid != 0 { 12 } else { 0 };
        let Some(store_get_prepend_ptr) = methods.store_get_prepend_ptr else {
            return -1;
        };
        if (*tlio_out).out_remaining < reserve {
            return -1;
        }
        let ptr_ = store_get_prepend_ptr(tlio_out, reserve).cast::<c_int>();
        (*tlio_out).out_pos += reserve;
        (*tlio_out).out_remaining -= reserve;
        (*tlio_out).out_size = ptr_;
        ptr_
    } else {
        (*tlio_out).out_size
    };

    if (*tlio_out).out_qid != 0 {
        if op == 0 || p.is_null() {
            return -1;
        }
        p = p.add(usize::try_from(methods.prepend_bytes / 4).unwrap_or(0));
        ptr::write_unaligned(p, op);
        ptr::write_unaligned(p.add(1).cast::<i64>(), (*tlio_out).out_qid);
    }

    if let Some(store_prefix) = methods.store_prefix {
        store_prefix(tlio_out);
    }
    if (methods.flags & TLF_NO_AUTOFLUSH) == 0 {
        let Some(store_flush) = methods.store_flush else {
            return -1;
        };
        store_flush(tlio_out);
    }

    (*tlio_out).out_ptr = ptr::null_mut();
    (*tlio_out).out_type = TL_TYPE_NONE;
    (*tlio_out).out_methods = ptr::null();
    (*tlio_out).out_extra = ptr::null_mut();

    if !out_sent_kind.is_null() {
        *out_sent_kind = sent_kind;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_query_header_delete(h: *mut TlQueryHeader) {
    if h.is_null() {
        return;
    }
    let refcnt = (&(*h).ref_cnt as *const c_int).cast::<core::sync::atomic::AtomicI32>();
    if (*refcnt).fetch_sub(1, core::sync::atomic::Ordering::SeqCst) > 1 {
        return;
    }
    libc::free(h.cast::<c_void>());
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_query_header_dup(
    h: *mut TlQueryHeader,
) -> *mut TlQueryHeader {
    if h.is_null() {
        return ptr::null_mut();
    }
    let refcnt = (&(*h).ref_cnt as *const c_int).cast::<core::sync::atomic::AtomicI32>();
    let _ = (*refcnt).fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    h
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_query_header_clone(
    h_old: *const TlQueryHeader,
) -> *mut TlQueryHeader {
    if h_old.is_null() {
        return ptr::null_mut();
    }
    let h = libc::malloc(size_of::<TlQueryHeader>()).cast::<TlQueryHeader>();
    if h.is_null() {
        return ptr::null_mut();
    }
    *h = *h_old;
    (*h).ref_cnt = 1;
    h
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_set_error(
    tlio_in: *mut TlInState,
    errnum: c_int,
    s: *const i8,
) -> c_int {
    if tlio_in.is_null() || s.is_null() {
        return -1;
    }
    if !(*tlio_in).error.is_null() {
        return 0;
    }
    (*tlio_in).error = strdup(s);
    (*tlio_in).errnum = errnum;
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_init(
    tlio_in: *mut TlInState,
    in_ptr: *mut c_void,
    type_: c_int,
    methods: *const TlInMethods,
    size: c_int,
) -> c_int {
    tl_fetch_init_impl(tlio_in, in_ptr, type_, methods, size)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_raw_message(
    tlio_in: *mut TlInState,
    msg: *mut RawMessage,
    size: c_int,
    dup: c_int,
) -> c_int {
    if msg.is_null() {
        return -1;
    }
    let r = libc::malloc(size_of::<RawMessage>()).cast::<RawMessage>();
    if r.is_null() {
        return -1;
    }
    if dup == 0 {
        rwm_move(r, msg);
    } else if dup == 1 {
        rwm_move(r, msg);
        let _ = rwm_init(msg, 0);
    } else {
        rwm_clone(r, msg);
    }
    tl_fetch_init_impl(
        tlio_in,
        r.cast::<c_void>(),
        TL_TYPE_RAW_MSG,
        core::ptr::addr_of!(tl_in_raw_msg_methods),
        size,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_str(
    tlio_in: *mut TlInState,
    s: *const i8,
    size: c_int,
) -> c_int {
    if s.is_null() {
        return -1;
    }
    tl_fetch_init_impl(
        tlio_in,
        s.cast_mut().cast::<c_void>(),
        TL_TYPE_STR,
        core::ptr::addr_of!(tl_in_str_methods),
        size,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_init(
    tlio_out: *mut TlOutState,
    out: *mut c_void,
    out_extra: *mut c_void,
    type_: c_int,
    methods: *const TlOutMethods,
    size: c_int,
    qid: i64,
) -> c_int {
    tl_store_init_impl(tlio_out, out, out_extra, type_, methods, size, qid)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_raw_msg(
    tlio_out: *mut TlOutState,
    pid: *const MtproxyProcessId,
    qid: i64,
) -> c_int {
    if tlio_out.is_null() {
        return -1;
    }
    if !pid.is_null() {
        (*tlio_out).out_pid_buf = *pid;
        (*tlio_out).out_pid = &raw mut (*tlio_out).out_pid_buf;
    } else {
        (*tlio_out).out_pid = ptr::null_mut();
    }
    let mut d: *mut RawMessage = ptr::null_mut();
    if !pid.is_null() {
        d = libc::malloc(size_of::<RawMessage>()).cast::<RawMessage>();
        if d.is_null() {
            return -1;
        }
        let _ = rwm_init(d, 0);
    }
    tl_store_init_impl(
        tlio_out,
        d.cast::<c_void>(),
        ptr::null_mut(),
        TL_TYPE_RAW_MSG,
        core::ptr::addr_of!(tl_out_raw_msg_methods),
        1 << 27,
        qid,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_raw_msg_nosend(tlio_out: *mut TlOutState) -> c_int {
    if tlio_out.is_null() {
        return -1;
    }
    let d = libc::malloc(size_of::<RawMessage>()).cast::<RawMessage>();
    if d.is_null() {
        return -1;
    }
    let _ = rwm_init(d, 0);
    tl_store_init_impl(
        tlio_out,
        d.cast::<c_void>(),
        d.cast::<c_void>(),
        TL_TYPE_RAW_MSG,
        core::ptr::addr_of!(tl_out_raw_msg_methods_nosend),
        1 << 27,
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_str_out(
    tlio_out: *mut TlOutState,
    s: *mut i8,
    qid: i64,
    size: c_int,
) -> c_int {
    if tlio_out.is_null() || s.is_null() {
        return -1;
    }
    (*tlio_out).out_pid = ptr::null_mut();
    tl_store_init_impl(
        tlio_out,
        s.cast::<c_void>(),
        s.cast::<c_void>(),
        TL_TYPE_STR,
        core::ptr::addr_of!(tl_out_str_methods),
        size,
        qid,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_tcp_raw_msg(
    tlio_out: *mut TlOutState,
    remote_pid: *const MtproxyProcessId,
    conn: *mut c_void,
    qid: i64,
    unaligned: c_int,
) -> c_int {
    if tlio_out.is_null() {
        return -1;
    }
    if !remote_pid.is_null() {
        (*tlio_out).out_pid_buf = *remote_pid;
        (*tlio_out).out_pid = &raw mut (*tlio_out).out_pid_buf;
    } else {
        (*tlio_out).out_pid = ptr::null_mut();
    }
    let mut d: *mut RawMessage = ptr::null_mut();
    if !conn.is_null() {
        d = libc::malloc(size_of::<RawMessage>()).cast::<RawMessage>();
        if d.is_null() {
            return -1;
        }
        let _ = rwm_init(d, 0);
    }
    let methods = if unaligned != 0 {
        core::ptr::addr_of!(tl_out_tcp_raw_msg_unaligned_methods)
    } else {
        core::ptr::addr_of!(tl_out_tcp_raw_msg_methods)
    };
    tl_store_init_impl(
        tlio_out,
        d.cast::<c_void>(),
        conn,
        TL_TYPE_TCP_RAW_MSG,
        methods,
        1 << 27,
        qid,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_query_header_parse(
    tlio_in: *mut TlInState,
    header: *mut TlQueryHeader,
) -> c_int {
    tl_query_header_parse_impl(tlio_in, header, false)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_query_answer_header_parse(
    tlio_in: *mut TlInState,
    header: *mut TlQueryHeader,
) -> c_int {
    tl_query_header_parse_impl(tlio_in, header, true)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_check(
    tlio_in: *mut TlInState,
    nbytes: c_int,
) -> c_int {
    tl_in_check(tlio_in, nbytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_lookup_int(tlio_in: *mut TlInState) -> c_int {
    if tl_in_check(tlio_in, 4) < 0 || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_lookup) = methods.fetch_lookup else {
        return -1;
    };
    let mut value: c_int = -1;
    fetch_lookup(tlio_in, (&raw mut value).cast::<c_void>(), 4);
    value
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_lookup_second_int(
    tlio_in: *mut TlInState,
) -> c_int {
    if tl_in_check(tlio_in, 8) < 0 || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_lookup) = methods.fetch_lookup else {
        return -1;
    };
    let mut values = [0_i32; 2];
    fetch_lookup(tlio_in, values.as_mut_ptr().cast::<c_void>(), 8);
    values[1]
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_lookup_long(tlio_in: *mut TlInState) -> i64 {
    if tl_in_check(tlio_in, 8) < 0 || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_lookup) = methods.fetch_lookup else {
        return -1;
    };
    let mut value: i64 = -1;
    fetch_lookup(tlio_in, (&raw mut value).cast::<c_void>(), 8);
    value
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_lookup_data(
    tlio_in: *mut TlInState,
    data: *mut c_void,
    len: c_int,
) -> c_int {
    if len < 0 {
        return -1;
    }
    if len == 0 {
        return 0;
    }
    if data.is_null() {
        return -1;
    }
    if tl_in_check(tlio_in, len) < 0 || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_lookup) = methods.fetch_lookup else {
        return -1;
    };
    fetch_lookup(tlio_in, data, len);
    len
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_int(tlio_in: *mut TlInState) -> c_int {
    if tl_in_check(tlio_in, 4) < 0 || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_raw_data) = methods.fetch_raw_data else {
        return -1;
    };
    let mut value: c_int = -1;
    fetch_raw_data(tlio_in, (&raw mut value).cast::<c_void>(), 4);
    (*tlio_in).in_pos += 4;
    (*tlio_in).in_remaining -= 4;
    value
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_double(tlio_in: *mut TlInState) -> f64 {
    if tl_in_check(tlio_in, 8) < 0 || (*tlio_in).in_methods.is_null() {
        return -1.0;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_raw_data) = methods.fetch_raw_data else {
        return -1.0;
    };
    let mut value: f64 = -1.0;
    fetch_raw_data(tlio_in, (&raw mut value).cast::<c_void>(), 8);
    (*tlio_in).in_pos += 8;
    (*tlio_in).in_remaining -= 8;
    value
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_long(tlio_in: *mut TlInState) -> i64 {
    if tl_in_check(tlio_in, 8) < 0 || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_raw_data) = methods.fetch_raw_data else {
        return -1;
    };
    let mut value: i64 = -1;
    fetch_raw_data(tlio_in, (&raw mut value).cast::<c_void>(), 8);
    (*tlio_in).in_pos += 8;
    (*tlio_in).in_remaining -= 8;
    value
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_raw_data(
    tlio_in: *mut TlInState,
    buf: *mut c_void,
    len: c_int,
) -> c_int {
    if len < 0 || (len & 3) != 0 {
        return -1;
    }
    if len == 0 {
        return 0;
    }
    if buf.is_null() || tl_in_check(tlio_in, len) < 0 || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_raw_data) = methods.fetch_raw_data else {
        return -1;
    };
    fetch_raw_data(tlio_in, buf, len);
    (*tlio_in).in_pos += len;
    (*tlio_in).in_remaining -= len;
    len
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_mark(tlio_in: *mut TlInState) {
    if tlio_in.is_null() || (*tlio_in).in_methods.is_null() {
        return;
    }
    let methods = &*(*tlio_in).in_methods;
    if let Some(fetch_mark) = methods.fetch_mark {
        fetch_mark(tlio_in);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_mark_restore(tlio_in: *mut TlInState) {
    if tlio_in.is_null() || (*tlio_in).in_methods.is_null() {
        return;
    }
    let methods = &*(*tlio_in).in_methods;
    if let Some(fetch_mark_restore) = methods.fetch_mark_restore {
        fetch_mark_restore(tlio_in);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_mark_delete(tlio_in: *mut TlInState) {
    if tlio_in.is_null() || (*tlio_in).in_methods.is_null() {
        return;
    }
    let methods = &*(*tlio_in).in_methods;
    if let Some(fetch_mark_delete) = methods.fetch_mark_delete {
        fetch_mark_delete(tlio_in);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_string_len(
    tlio_in: *mut TlInState,
    max_len: c_int,
) -> c_int {
    tl_fetch_string_len_impl(tlio_in, max_len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_pad(tlio_in: *mut TlInState) -> c_int {
    tl_fetch_pad_impl(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_string_data(
    tlio_in: *mut TlInState,
    buf: *mut i8,
    len: c_int,
) -> c_int {
    if len < 0 {
        return -1;
    }
    if len > 0 && buf.is_null() {
        return -1;
    }
    if tl_in_check(tlio_in, len) < 0 {
        return -1;
    }
    if len > 0 && tl_in_fetch_raw_any(tlio_in, buf.cast::<c_void>(), len) < 0 {
        return -1;
    }
    if tl_fetch_pad_impl(tlio_in) < 0 {
        return -1;
    }
    len
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_skip_string_data(
    tlio_in: *mut TlInState,
    len: c_int,
) -> c_int {
    if len < 0 || tl_in_check(tlio_in, len) < 0 || tl_in_skip(tlio_in, len) < 0 {
        return -1;
    }
    if tl_fetch_pad_impl(tlio_in) < 0 {
        return -1;
    }
    len
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_string(
    tlio_in: *mut TlInState,
    buf: *mut i8,
    max_len: c_int,
) -> c_int {
    let len = tl_fetch_string_len_impl(tlio_in, max_len);
    if len < 0 {
        return -1;
    }
    mtproxy_ffi_tl_fetch_string_data(tlio_in, buf, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_skip_string(
    tlio_in: *mut TlInState,
    max_len: c_int,
) -> c_int {
    let len = tl_fetch_string_len_impl(tlio_in, max_len);
    if len < 0 {
        return -1;
    }
    mtproxy_ffi_tl_fetch_skip_string_data(tlio_in, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_string0(
    tlio_in: *mut TlInState,
    buf: *mut i8,
    max_len: c_int,
) -> c_int {
    let len = tl_fetch_string_len_impl(tlio_in, max_len);
    if len < 0 {
        return -1;
    }
    if mtproxy_ffi_tl_fetch_string_data(tlio_in, buf, len) < 0 {
        return -1;
    }
    if buf.is_null() {
        return -1;
    }
    *buf.add(usize::try_from(len).unwrap_or(0)) = 0;
    len
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_check_str_end(
    tlio_in: *mut TlInState,
    size: c_int,
) -> c_int {
    if tlio_in.is_null() || size < 0 {
        return -1;
    }
    let expected = size + ((-size - (*tlio_in).in_pos) & 3);
    if (*tlio_in).in_remaining != expected {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_EXTRA_DATA,
            &format!(
                "extra {} bytes after query",
                (*tlio_in).in_remaining - expected
            ),
        );
        return -1;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_unread(tlio_in: *mut TlInState) -> c_int {
    if tlio_in.is_null() {
        return -1;
    }
    (*tlio_in).in_remaining
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_skip(tlio_in: *mut TlInState, len: c_int) -> c_int {
    if len < 0 || tl_in_check(tlio_in, len) < 0 {
        return -1;
    }
    tl_in_skip(tlio_in, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_end(tlio_in: *mut TlInState) -> c_int {
    if tlio_in.is_null() {
        return -1;
    }
    if (*tlio_in).in_remaining != 0
        && ((*tlio_in).in_flags & TL_FETCH_FLAG_ALLOW_DATA_AFTER_QUERY) == 0
    {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_EXTRA_DATA,
            &format!("extra {} bytes after query", (*tlio_in).in_remaining),
        );
        return -1;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_error(tlio_in: *mut TlInState) -> c_int {
    if tlio_in.is_null() {
        return 1;
    }
    if (*tlio_in).error.is_null() { 0 } else { 1 }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_int_range(
    tlio_in: *mut TlInState,
    min: c_int,
    max: c_int,
) -> c_int {
    let value = mtproxy_ffi_tl_fetch_int(tlio_in);
    if value < min || value > max {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_VALUE_NOT_IN_RANGE,
            &format!("Expected int32 in range [{min},{max}], {value} presented"),
        );
    }
    value
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_positive_int(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_int_range(tlio_in, 1, 0x7fff_ffff)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_nonnegative_int(
    tlio_in: *mut TlInState,
) -> c_int {
    mtproxy_ffi_tl_fetch_int_range(tlio_in, 0, 0x7fff_ffff)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_int_subset(
    tlio_in: *mut TlInState,
    set: c_int,
) -> c_int {
    let value = mtproxy_ffi_tl_fetch_int(tlio_in);
    if (value & !set) != 0 {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_VALUE_NOT_IN_RANGE,
            &format!(
                "Expected int32 with only bits 0x{set:02x} allowed, 0x{value:02x} presented"
            ),
        );
    }
    value
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_long_range(
    tlio_in: *mut TlInState,
    min: i64,
    max: i64,
) -> i64 {
    let value = mtproxy_ffi_tl_fetch_long(tlio_in);
    if value < min || value > max {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_VALUE_NOT_IN_RANGE,
            &format!("Expected int64 in range [{min},{max}], {value} presented"),
        );
    }
    value
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_positive_long(tlio_in: *mut TlInState) -> i64 {
    mtproxy_ffi_tl_fetch_long_range(tlio_in, 1, 0x7fff_ffff_ffff_ffff_i64)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_nonnegative_long(
    tlio_in: *mut TlInState,
) -> i64 {
    mtproxy_ffi_tl_fetch_long_range(tlio_in, 0, 0x7fff_ffff_ffff_ffff_i64)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_raw_message(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    if raw.is_null() || tl_in_check(tlio_in, bytes) < 0 || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_raw_message) = methods.fetch_raw_message else {
        return -1;
    };
    fetch_raw_message(tlio_in, raw, bytes);
    (*tlio_in).in_pos += bytes;
    (*tlio_in).in_remaining -= bytes;
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_lookup_raw_message(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    if raw.is_null() || tl_in_check(tlio_in, bytes) < 0 || (*tlio_in).in_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_in).in_methods;
    let Some(fetch_lookup_raw_message) = methods.fetch_lookup_raw_message else {
        return -1;
    };
    fetch_lookup_raw_message(tlio_in, raw, bytes);
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_get_ptr(
    tlio_out: *mut TlOutState,
    size: c_int,
) -> *mut c_void {
    if size <= 0 || tl_out_check(tlio_out, size) < 0 || (*tlio_out).out_methods.is_null() {
        return ptr::null_mut();
    }
    let methods = &*(*tlio_out).out_methods;
    let Some(store_get_ptr) = methods.store_get_ptr else {
        return ptr::null_mut();
    };
    let p = store_get_ptr(tlio_out, size);
    if p.is_null() {
        return ptr::null_mut();
    }
    (*tlio_out).out_pos += size;
    (*tlio_out).out_remaining -= size;
    p
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_get_prepend_ptr(
    tlio_out: *mut TlOutState,
    size: c_int,
) -> *mut c_void {
    if size <= 0 || tl_out_check(tlio_out, size) < 0 || (*tlio_out).out_methods.is_null() {
        return ptr::null_mut();
    }
    let methods = &*(*tlio_out).out_methods;
    let Some(store_get_prepend_ptr) = methods.store_get_prepend_ptr else {
        return ptr::null_mut();
    };
    let p = store_get_prepend_ptr(tlio_out, size);
    if p.is_null() {
        return ptr::null_mut();
    }
    (*tlio_out).out_pos += size;
    (*tlio_out).out_remaining -= size;
    p
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_int(tlio_out: *mut TlOutState, x: c_int) -> c_int {
    tl_out_store_int(tlio_out, x)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_long(tlio_out: *mut TlOutState, x: i64) -> c_int {
    tl_out_store_long(tlio_out, x)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_double(tlio_out: *mut TlOutState, x: f64) -> c_int {
    let bytes = x.to_le_bytes();
    tl_out_store_raw_data(tlio_out, bytes.as_ptr().cast::<c_void>(), 8)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_raw_data(
    tlio_out: *mut TlOutState,
    data: *const c_void,
    len: c_int,
) -> c_int {
    tl_out_store_raw_data(tlio_out, data, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_raw_msg(
    tlio_out: *mut TlOutState,
    raw: *mut RawMessage,
    dup: c_int,
) -> c_int {
    if raw.is_null() || (*raw).total_bytes < 0 {
        return -1;
    }
    let len = (*raw).total_bytes;
    if tl_out_check(tlio_out, len) < 0 || (*tlio_out).out_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_out).out_methods;
    let Some(store_raw_msg) = methods.store_raw_msg else {
        return -1;
    };
    if dup == 0 {
        store_raw_msg(tlio_out, raw);
    } else {
        let mut cloned = RawMessage {
            first: ptr::null_mut(),
            last: ptr::null_mut(),
            total_bytes: 0,
            magic: 0,
            first_offset: 0,
            last_offset: 0,
        };
        rwm_clone(&mut cloned, raw);
        store_raw_msg(tlio_out, &mut cloned);
    }
    (*tlio_out).out_pos += len;
    (*tlio_out).out_remaining -= len;
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_string_len(
    tlio_out: *mut TlOutState,
    len: c_int,
) -> c_int {
    if len < 0 {
        return -1;
    }
    tl_out_store_string_len(tlio_out, usize::try_from(len).unwrap_or(0))
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_pad(tlio_out: *mut TlOutState) -> c_int {
    tl_out_store_pad(tlio_out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_string_data(
    tlio_out: *mut TlOutState,
    s: *const i8,
    len: c_int,
) -> c_int {
    if len < 0 {
        return -1;
    }
    if len > 0 && s.is_null() {
        return -1;
    }
    if len > 0 && tl_out_store_raw_data(tlio_out, s.cast::<c_void>(), len) < 0 {
        return -1;
    }
    tl_out_store_pad(tlio_out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_string(
    tlio_out: *mut TlOutState,
    s: *const i8,
    len: c_int,
) -> c_int {
    if len < 0 {
        return -1;
    }
    let len_usize = usize::try_from(len).unwrap_or(0);
    if len_usize > 0 && s.is_null() {
        return -1;
    }
    if tl_out_store_string_len(tlio_out, len_usize) < 0 {
        return -1;
    }
    if len_usize > 0
        && tl_out_store_raw_data(tlio_out, s.cast::<c_void>(), c_int::try_from(len_usize).unwrap_or(c_int::MAX))
            < 0
    {
        return -1;
    }
    tl_out_store_pad(tlio_out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_clear(tlio_out: *mut TlOutState) -> c_int {
    if tlio_out.is_null() || (*tlio_out).out_ptr.is_null() || (*tlio_out).out_methods.is_null() {
        return -1;
    }
    let methods = &*(*tlio_out).out_methods;
    let Some(store_clear) = methods.store_clear else {
        return -1;
    };
    store_clear(tlio_out);
    (*tlio_out).out_ptr = ptr::null_mut();
    (*tlio_out).out_type = TL_TYPE_NONE;
    (*tlio_out).out_extra = ptr::null_mut();
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_clean(tlio_out: *mut TlOutState) -> c_int {
    tl_out_clean(tlio_out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_pos(tlio_out: *mut TlOutState) -> c_int {
    if tlio_out.is_null() {
        return -1;
    }
    (*tlio_out).out_pos
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_copy_through(
    tlio_in: *mut TlInState,
    tlio_out: *mut TlOutState,
    len: c_int,
    advance: c_int,
) -> c_int {
    if tlio_in.is_null()
        || tlio_out.is_null()
        || len < 0
        || (*tlio_in).in_type == TL_TYPE_NONE
        || (*tlio_out).out_type == TL_TYPE_NONE
        || (*tlio_out).out_methods.is_null()
        || tl_in_check(tlio_in, len) < 0
        || tl_out_check(tlio_out, len) < 0
    {
        return -1;
    }

    let in_type = usize::try_from((*tlio_in).in_type).unwrap_or(usize::MAX);
    let methods = &*(*tlio_out).out_methods;
    if in_type >= methods.copy_through.len() {
        return -1;
    }
    let Some(copy_through) = methods.copy_through[in_type] else {
        return -1;
    };
    copy_through(tlio_in, tlio_out, len, advance);
    if advance != 0 {
        (*tlio_in).in_pos += len;
        (*tlio_in).in_remaining -= len;
    }
    (*tlio_out).out_pos += len;
    (*tlio_out).out_remaining -= len;
    len
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
