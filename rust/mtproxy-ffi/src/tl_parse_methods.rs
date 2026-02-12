use super::MtproxyProcessId;
use core::ffi::{c_int, c_void};
use core::mem::size_of;
use core::ptr;

const RM_INIT_MAGIC: c_int = 0x2351_3473;
const TLF_PERMANENT: c_int = 2;
const TLF_ALLOW_PREPEND: c_int = 4;
const TLF_DISABLE_PREPEND: c_int = 8;
const TLF_NOALIGN: c_int = 16;
const TLF_NO_AUTOFLUSH: c_int = 32;
const TL_TYPE_NONE: c_int = 0;
const TL_TYPE_STR: c_int = 1;
const TL_TYPE_RAW_MSG: c_int = 2;
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
    if tlio_out.is_null() || data.is_null() || len < 0 {
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
