use crate::MtproxyProcessId;
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
const TL_PARSE_ERROR_FALLBACK: &[u8] = b"TL parse error\0";
const ABI_ERROR: c_int = -1;

#[inline]
fn expected_query_header_message(is_answer: bool) -> &'static str {
    if is_answer {
        "Expected RPC_REQ_ERROR or RPC_REQ_RESULT"
    } else {
        "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ"
    }
}

type AbiResult<T> = Result<T, c_int>;

#[inline]
fn abi_i32(result: AbiResult<c_int>) -> c_int {
    result.unwrap_or(ABI_ERROR)
}

#[inline]
fn abi_i64(result: AbiResult<i64>) -> i64 {
    result.unwrap_or(-1)
}

#[inline]
fn abi_f64(result: AbiResult<f64>) -> f64 {
    result.unwrap_or(-1.0)
}

#[inline]
fn abi_ptr(result: AbiResult<*mut c_void>) -> *mut c_void {
    result.unwrap_or(ptr::null_mut())
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
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
    fetch_lookup_raw_message: Option<unsafe extern "C" fn(*mut TlInState, *mut RawMessage, c_int)>,
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
    store_read_back_nondestruct: Option<unsafe extern "C" fn(*mut TlOutState, *mut c_void, c_int)>,
    store_crc32_partial: Option<unsafe extern "C" fn(*mut TlOutState, c_int, u32) -> u32>,
    store_flush: Option<unsafe extern "C" fn(*mut TlOutState)>,
    store_clear: Option<unsafe extern "C" fn(*mut TlOutState)>,
    copy_through: [Option<unsafe extern "C" fn(*mut TlInState, *mut TlOutState, c_int, c_int)>; 10],
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

fn add_bytes(ptr_: *mut c_void, len: c_int) -> *mut c_void {
    if len <= 0 {
        return ptr_;
    }
    (ptr_ as *mut u8)
        .wrapping_add(len as usize)
        .cast::<c_void>()
}

fn sub_bytes(ptr_: *mut c_void, len: c_int) -> *mut c_void {
    if len <= 0 {
        return ptr_;
    }
    (ptr_ as *mut u8)
        .wrapping_sub(len as usize)
        .cast::<c_void>()
}

#[inline]
fn ptr_mut<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
    unsafe { crate::ffi_util::mut_ref_from_ptr(ptr) }
}

#[inline]
fn ptr_ref<'a, T>(ptr: *const T) -> Option<&'a T> {
    unsafe { crate::ffi_util::ref_from_ptr(ptr) }
}

#[inline]
fn in_state_mut<'a>(state: *mut TlInState) -> Option<&'a mut TlInState> {
    ptr_mut(state)
}

#[inline]
fn out_state_mut<'a>(state: *mut TlOutState) -> Option<&'a mut TlOutState> {
    ptr_mut(state)
}

#[inline]
fn in_methods_ref(state: &TlInState) -> Option<&TlInMethods> {
    ptr_ref(state.in_methods)
}

#[inline]
fn out_methods_ref(state: &TlOutState) -> Option<&TlOutMethods> {
    ptr_ref(state.out_methods)
}

#[derive(Clone, Copy)]
struct InCursor {
    in_type: c_int,
    in_pos: c_int,
    in_remaining: c_int,
    in_flags: c_int,
    has_error: bool,
}

#[inline]
fn in_cursor(state: *mut TlInState) -> Option<InCursor> {
    let state_ref = in_state_mut(state)?;
    Some(InCursor {
        in_type: state_ref.in_type,
        in_pos: state_ref.in_pos,
        in_remaining: state_ref.in_remaining,
        in_flags: state_ref.in_flags,
        has_error: !state_ref.error.is_null(),
    })
}

#[inline]
fn in_fetch_move_cb(state: *mut TlInState) -> Option<unsafe extern "C" fn(*mut TlInState, c_int)> {
    let state_ref = in_state_mut(state)?;
    in_methods_ref(state_ref).and_then(|methods| methods.fetch_move)
}

#[inline]
fn in_fetch_raw_data_cb(
    state: *mut TlInState,
) -> Option<unsafe extern "C" fn(*mut TlInState, *mut c_void, c_int)> {
    let state_ref = in_state_mut(state)?;
    in_methods_ref(state_ref).and_then(|methods| methods.fetch_raw_data)
}

#[inline]
fn in_fetch_lookup_cb(
    state: *mut TlInState,
) -> Option<unsafe extern "C" fn(*mut TlInState, *mut c_void, c_int)> {
    let state_ref = in_state_mut(state)?;
    in_methods_ref(state_ref).and_then(|methods| methods.fetch_lookup)
}

#[inline]
fn in_fetch_raw_message_cb(
    state: *mut TlInState,
) -> Option<unsafe extern "C" fn(*mut TlInState, *mut RawMessage, c_int)> {
    let state_ref = in_state_mut(state)?;
    in_methods_ref(state_ref).and_then(|methods| methods.fetch_raw_message)
}

#[inline]
fn in_fetch_lookup_raw_message_cb(
    state: *mut TlInState,
) -> Option<unsafe extern "C" fn(*mut TlInState, *mut RawMessage, c_int)> {
    let state_ref = in_state_mut(state)?;
    in_methods_ref(state_ref).and_then(|methods| methods.fetch_lookup_raw_message)
}

#[inline]
fn in_fetch_mark_cb(state: *mut TlInState) -> Option<unsafe extern "C" fn(*mut TlInState)> {
    let state_ref = in_state_mut(state)?;
    in_methods_ref(state_ref).and_then(|methods| methods.fetch_mark)
}

#[inline]
fn in_fetch_mark_restore_cb(state: *mut TlInState) -> Option<unsafe extern "C" fn(*mut TlInState)> {
    let state_ref = in_state_mut(state)?;
    in_methods_ref(state_ref).and_then(|methods| methods.fetch_mark_restore)
}

#[inline]
fn in_fetch_mark_delete_cb(state: *mut TlInState) -> Option<unsafe extern "C" fn(*mut TlInState)> {
    let state_ref = in_state_mut(state)?;
    in_methods_ref(state_ref).and_then(|methods| methods.fetch_mark_delete)
}

#[derive(Clone, Copy)]
struct OutCursor {
    out_type: c_int,
    out_pos: c_int,
    out_remaining: c_int,
    out_ptr_is_null: bool,
    out_methods_is_set: bool,
}

#[inline]
fn out_cursor(state: *mut TlOutState) -> Option<OutCursor> {
    let state_ref = out_state_mut(state)?;
    Some(OutCursor {
        out_type: state_ref.out_type,
        out_pos: state_ref.out_pos,
        out_remaining: state_ref.out_remaining,
        out_ptr_is_null: state_ref.out_ptr.is_null(),
        out_methods_is_set: !state_ref.out_methods.is_null(),
    })
}

#[inline]
fn out_store_raw_data_cb(
    state: *mut TlOutState,
) -> Option<unsafe extern "C" fn(*mut TlOutState, *const c_void, c_int)> {
    let state_ref = out_state_mut(state)?;
    out_methods_ref(state_ref).and_then(|methods| methods.store_raw_data)
}

#[inline]
fn out_store_read_back_cb(
    state: *mut TlOutState,
) -> Option<unsafe extern "C" fn(*mut TlOutState, c_int)> {
    let state_ref = out_state_mut(state)?;
    out_methods_ref(state_ref).and_then(|methods| methods.store_read_back)
}

#[inline]
fn out_store_clear_cb(state: *mut TlOutState) -> Option<unsafe extern "C" fn(*mut TlOutState)> {
    let state_ref = out_state_mut(state)?;
    out_methods_ref(state_ref).and_then(|methods| methods.store_clear)
}

#[inline]
fn out_store_get_ptr_cb(
    state: *mut TlOutState,
) -> Option<unsafe extern "C" fn(*mut TlOutState, c_int) -> *mut c_void> {
    let state_ref = out_state_mut(state)?;
    out_methods_ref(state_ref).and_then(|methods| methods.store_get_ptr)
}

#[inline]
fn out_store_get_prepend_ptr_cb(
    state: *mut TlOutState,
) -> Option<unsafe extern "C" fn(*mut TlOutState, c_int) -> *mut c_void> {
    let state_ref = out_state_mut(state)?;
    out_methods_ref(state_ref).and_then(|methods| methods.store_get_prepend_ptr)
}

#[inline]
fn out_store_raw_msg_cb(
    state: *mut TlOutState,
) -> Option<unsafe extern "C" fn(*mut TlOutState, *mut RawMessage)> {
    let state_ref = out_state_mut(state)?;
    out_methods_ref(state_ref).and_then(|methods| methods.store_raw_msg)
}

#[inline]
fn out_copy_through_cb(
    state: *mut TlOutState,
    in_type: usize,
) -> Option<unsafe extern "C" fn(*mut TlInState, *mut TlOutState, c_int, c_int)> {
    let state_ref = out_state_mut(state)?;
    let methods = out_methods_ref(state_ref)?;
    methods.copy_through.get(in_type).and_then(|cb| *cb)
}

#[derive(Clone, Copy)]
struct OutEndCtx {
    flags: c_int,
    prepend_bytes: c_int,
    store_get_prepend_ptr: Option<unsafe extern "C" fn(*mut TlOutState, c_int) -> *mut c_void>,
    store_prefix: Option<unsafe extern "C" fn(*mut TlOutState)>,
    store_flush: Option<unsafe extern "C" fn(*mut TlOutState)>,
    out_qid: i64,
    out_size: *mut c_int,
    errnum: c_int,
    error: *mut i8,
}

#[inline]
fn out_end_ctx(state: *mut TlOutState) -> Option<OutEndCtx> {
    let state_ref = out_state_mut(state)?;
    let methods = out_methods_ref(state_ref)?;
    Some(OutEndCtx {
        flags: methods.flags,
        prepend_bytes: methods.prepend_bytes,
        store_get_prepend_ptr: methods.store_get_prepend_ptr,
        store_prefix: methods.store_prefix,
        store_flush: methods.store_flush,
        out_qid: state_ref.out_qid,
        out_size: state_ref.out_size,
        errnum: state_ref.errnum,
        error: state_ref.error,
    })
}

#[inline]
fn in_raw(state: *mut TlInState) -> *mut RawMessage {
    let Some(state_ref) = in_state_mut(state) else {
        return ptr::null_mut();
    };
    state_ref.in_ptr.cast::<RawMessage>()
}

#[inline]
fn out_raw(state: *mut TlOutState) -> *mut RawMessage {
    let Some(state_ref) = out_state_mut(state) else {
        return ptr::null_mut();
    };
    state_ref.out_ptr.cast::<RawMessage>()
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
    if mark.is_null() {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_INTERNAL,
            "Out of memory while creating TL mark",
        );
        return;
    }
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
    let mut r = RawMessage::default();
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
        let mut r = RawMessage::default();
        rwm_clone(&mut r, in_raw(tlio_in));
        let _ = rwm_trunc(&mut r, len);
        let _ = rwm_union(out_raw(tlio_out), &mut r);
    } else {
        let mut r = RawMessage::default();
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

unsafe extern "C" fn tl_str_fetch_raw_data(tlio_in: *mut TlInState, buf: *mut c_void, len: c_int) {
    ptr::copy(
        (*tlio_in).in_ptr.cast::<u8>(),
        buf.cast::<u8>(),
        len as usize,
    );
    (*tlio_in).in_ptr = add_bytes((*tlio_in).in_ptr, len);
}

unsafe extern "C" fn tl_str_fetch_move(tlio_in: *mut TlInState, len: c_int) {
    (*tlio_in).in_ptr = add_bytes((*tlio_in).in_ptr, len);
}

unsafe extern "C" fn tl_str_fetch_lookup(tlio_in: *mut TlInState, buf: *mut c_void, len: c_int) {
    ptr::copy(
        (*tlio_in).in_ptr.cast::<u8>(),
        buf.cast::<u8>(),
        len as usize,
    );
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
    ptr::copy(
        buf.cast::<u8>(),
        (*tlio_out).out_ptr.cast::<u8>(),
        len as usize,
    );
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
    ptr::copy(
        sub_bytes((*tlio_out).out_ptr, len).cast::<u8>(),
        buf.cast::<u8>(),
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
    ptr::copy(
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
    let Some(tlio_in_ref) = in_state_mut(tlio_in) else {
        return -1;
    };
    if in_ptr.is_null() || methods.is_null() {
        return -1;
    }
    if tlio_in_ref.in_type != TL_TYPE_NONE {
        return -1;
    }
    tlio_in_ref.in_type = type_;
    tlio_in_ref.in_ptr = in_ptr;
    tlio_in_ref.in_remaining = size;
    tlio_in_ref.in_pos = 0;
    tlio_in_ref.in_flags = 0;
    tlio_in_ref.in_methods = methods;
    if !tlio_in_ref.error.is_null() {
        libc::free(tlio_in_ref.error.cast::<c_void>());
        tlio_in_ref.error = ptr::null_mut();
    }
    tlio_in_ref.errnum = 0;
    0
}

unsafe fn tl_set_error_once(tlio_in: *mut TlInState, errnum: c_int, message: &str) {
    let Some(tlio_in_ref) = in_state_mut(tlio_in) else {
        return;
    };
    if !tlio_in_ref.error.is_null() {
        return;
    }
    let msg = CString::new(message).ok();
    let msg_ptr = msg
        .as_ref()
        .map_or(TL_PARSE_ERROR_FALLBACK.as_ptr().cast(), |value| {
            value.as_ptr()
        });
    tlio_in_ref.error = strdup(msg_ptr);
    tlio_in_ref.errnum = errnum;
}

unsafe fn tl_in_skip(tlio_in: *mut TlInState, len: c_int) -> c_int {
    let Some(cursor) = in_cursor(tlio_in) else {
        return -1;
    };
    if len < 0 || cursor.in_remaining < len {
        return -1;
    }
    let Some(fetch_move) = in_fetch_move_cb(tlio_in) else {
        return -1;
    };
    fetch_move(tlio_in, len);
    let Some(tlio_in_ref) = in_state_mut(tlio_in) else {
        return -1;
    };
    tlio_in_ref.in_pos += len;
    tlio_in_ref.in_remaining -= len;
    len
}

unsafe fn tl_in_fetch_raw_any(tlio_in: *mut TlInState, dst: *mut c_void, len: c_int) -> c_int {
    let Some(cursor) = in_cursor(tlio_in) else {
        return -1;
    };
    if dst.is_null() || len < 0 || cursor.in_remaining < len {
        return -1;
    }
    let Some(fetch_raw_data) = in_fetch_raw_data_cb(tlio_in) else {
        return -1;
    };
    fetch_raw_data(tlio_in, dst, len);
    let Some(tlio_in_ref) = in_state_mut(tlio_in) else {
        return -1;
    };
    tlio_in_ref.in_pos += len;
    tlio_in_ref.in_remaining -= len;
    len
}

unsafe fn tl_in_lookup_data(tlio_in: *mut TlInState, dst: *mut c_void, len: c_int) -> c_int {
    let Some(cursor) = in_cursor(tlio_in) else {
        return -1;
    };
    if dst.is_null() || len < 0 || cursor.in_remaining < len {
        return -1;
    }
    let Some(fetch_lookup) = in_fetch_lookup_cb(tlio_in) else {
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
    let header_error_message = expected_query_header_message(is_answer);
    let Some(header_ref) = ptr_mut(header) else {
        return -1;
    };
    let Some(cursor_before) = in_cursor(tlio_in) else {
        return -1;
    };
    *header_ref = TlQueryHeader {
        qid: 0,
        actor_id: 0,
        flags: 0,
        op: 0,
        real_op: 0,
        ref_cnt: 0,
        qw_params: ptr::null_mut(),
    };
    let total_unread = cursor_before.in_remaining;
    let prepend = {
        let Some(tlio_in_ref) = in_state_mut(tlio_in) else {
            return -1;
        };
        let Some(methods) = in_methods_ref(tlio_in_ref) else {
            return -1;
        };
        methods.prepend_bytes
    };
    if prepend > 0 && tl_in_skip(tlio_in, prepend) < 0 {
        tl_set_error_once(tlio_in, TL_ERROR_HEADER, header_error_message);
        return -1;
    }

    let Some(cursor_after_prepend) = in_cursor(tlio_in) else {
        return -1;
    };
    let unread = cursor_after_prepend.in_remaining;
    if unread < 0 {
        tl_set_error_once(tlio_in, TL_ERROR_HEADER, header_error_message);
        return -1;
    }
    let unread_usize = usize::try_from(unread).unwrap_or(0);
    let mut buf = vec![0u8; unread_usize];
    if unread > 0 && tl_in_lookup_data(tlio_in, buf.as_mut_ptr().cast::<c_void>(), unread) != unread
    {
        tl_set_error_once(tlio_in, TL_ERROR_HEADER, header_error_message);
        return -1;
    }

    let parsed = if is_answer {
        super::core::parse_answer_header(&buf)
    } else {
        super::core::parse_query_header(&buf)
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
        tl_set_error_once(tlio_in, TL_ERROR_HEADER, header_error_message);
        return -1;
    }

    header_ref.op = parsed.header.op;
    header_ref.real_op = parsed.header.real_op;
    header_ref.flags = parsed.header.flags;
    header_ref.qid = parsed.header.qid;
    header_ref.actor_id = parsed.header.actor_id;
    header_ref.ref_cnt = 1;
    let Some(cursor_final) = in_cursor(tlio_in) else {
        return -1;
    };
    total_unread - cursor_final.in_remaining
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
    let Some(cursor) = out_cursor(tlio_out) else {
        return -1;
    };
    if cursor.out_methods_is_set {
        return -1;
    }
    let mut computed_out_size: *mut c_int = ptr::null_mut();

    if !out.is_null() {
        let Some(methods_ref) = ptr_ref(methods) else {
            return -1;
        };
        {
            let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
                return -1;
            };
            tlio_out_ref.out_methods = methods;
            tlio_out_ref.out_type = type_;
        }
        if type_ != TL_TYPE_NONE
            && ((methods_ref.flags & (TLF_ALLOW_PREPEND | TLF_DISABLE_PREPEND)) == 0)
        {
            let reserve = methods_ref.prepend_bytes + if qid != 0 { 12 } else { 0 };
            let Some(store_get_ptr) = methods_ref.store_get_ptr else {
                return -1;
            };
            computed_out_size = store_get_ptr(tlio_out, reserve).cast::<c_int>();
        }
    } else if let Some(tlio_out_ref) = out_state_mut(tlio_out) {
        tlio_out_ref.out_type = TL_TYPE_NONE;
    } else {
        return -1;
    }

    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return -1;
    };
    tlio_out_ref.out_ptr = out;
    tlio_out_ref.out_extra = out_extra;
    if !computed_out_size.is_null() {
        tlio_out_ref.out_size = computed_out_size;
    }
    tlio_out_ref.out_pos = 0;
    tlio_out_ref.out_qid = qid;
    tlio_out_ref.out_remaining = size;
    tlio_out_ref.errnum = 0;
    tlio_out_ref.error = ptr::null_mut();
    0
}

unsafe fn tl_out_store_raw_data(
    tlio_out: *mut TlOutState,
    data: *const c_void,
    len: c_int,
) -> c_int {
    let Some(cursor) = out_cursor(tlio_out) else {
        return -1;
    };
    if len < 0 {
        return -1;
    }
    if len == 0 {
        return 0;
    }
    if data.is_null() {
        return -1;
    }
    if cursor.out_type == TL_TYPE_NONE {
        return -1;
    }
    if cursor.out_remaining < len {
        return -1;
    }
    let Some(store_raw_data) = out_store_raw_data_cb(tlio_out) else {
        return -1;
    };
    store_raw_data(tlio_out, data, len);
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return -1;
    };
    tlio_out_ref.out_pos += len;
    tlio_out_ref.out_remaining -= len;
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
    let Some(cursor) = out_cursor(tlio_out) else {
        return -1;
    };
    let pad = (4 - (cursor.out_pos & 3)) & 3;
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
    if len > 0
        && tl_out_store_raw_data(
            tlio_out,
            s.cast::<c_void>(),
            c_int::try_from(len).unwrap_or(c_int::MAX),
        ) < 0
    {
        return -1;
    }
    tl_out_store_pad(tlio_out)
}

unsafe fn tl_out_clean(tlio_out: *mut TlOutState) -> c_int {
    let Some(cursor) = out_cursor(tlio_out) else {
        return -1;
    };
    let Some(store_read_back) = out_store_read_back_cb(tlio_out) else {
        return -1;
    };
    store_read_back(tlio_out, cursor.out_pos);
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return -1;
    };
    tlio_out_ref.out_remaining += cursor.out_pos;
    tlio_out_ref.out_pos = 0;
    0
}

unsafe fn tl_in_check(tlio_in: *mut TlInState, nbytes: c_int) -> c_int {
    let Some(cursor) = in_cursor(tlio_in) else {
        return -1;
    };
    if cursor.in_type == TL_TYPE_NONE {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_INTERNAL,
            "Trying to read from unitialized in buffer",
        );
        return -1;
    }
    if cursor.has_error {
        return -1;
    }
    if nbytes >= 0 {
        if cursor.in_remaining < nbytes {
            let size = cursor.in_pos + cursor.in_remaining;
            tl_set_error_once(
                tlio_in,
                TL_ERROR_NOT_ENOUGH_DATA,
                &format!(
                    "Trying to read {nbytes} bytes at position {} (size = {size})",
                    cursor.in_pos
                ),
            );
            return -1;
        }
    } else if cursor.in_pos < -nbytes {
        let size = cursor.in_pos + cursor.in_remaining;
        tl_set_error_once(
            tlio_in,
            TL_ERROR_NOT_ENOUGH_DATA,
            &format!(
                "Trying to read {nbytes} bytes at position {} (size = {size})",
                cursor.in_pos
            ),
        );
        return -1;
    }
    0
}

unsafe fn tl_out_check(tlio_out: *mut TlOutState, size: c_int) -> c_int {
    let Some(cursor) = out_cursor(tlio_out) else {
        return -1;
    };
    if size < 0 {
        return -1;
    }
    if cursor.out_type == TL_TYPE_NONE {
        return -1;
    }
    if cursor.out_remaining < size {
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
        tl_set_error_once(
            tlio_in,
            TL_ERROR_SYNTAX,
            "String len can not start with 0xff",
        );
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
    let Some(cursor) = in_cursor(tlio_in) else {
        return -1;
    };
    if len > cursor.in_remaining {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_NOT_ENOUGH_DATA,
            &format!(
                "string is too long: remaining_bytes = {}, len = {len}",
                cursor.in_remaining
            ),
        );
        return -1;
    }
    len
}

unsafe fn tl_fetch_pad_impl(tlio_in: *mut TlInState) -> c_int {
    let Some(cursor) = in_cursor(tlio_in) else {
        return -1;
    };
    let pad = (-cursor.in_pos) & 3;
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
    if buf[..usize::try_from(pad).unwrap_or(0)]
        .iter()
        .any(|b| *b != 0)
    {
        tl_set_error_once(tlio_in, TL_ERROR_SYNTAX, "Padding with non-zeroes");
        return -1;
    }
    pad
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_header(
    tlio_out: *mut TlOutState,
    header: *const TlQueryHeader,
) -> c_int {
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return -1;
    };
    let Some(h) = ptr_ref(header) else {
        return -1;
    };
    if tlio_out_ref.out_type == TL_TYPE_NONE {
        return -1;
    }
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
        if tl_out_store_long(tlio_out, tlio_out_ref.out_qid) < 0 {
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

pub(crate) unsafe fn mtproxy_ffi_tl_store_end_ext(
    tlio_out: *mut TlOutState,
    op: c_int,
    out_sent_kind: *mut c_int,
) -> c_int {
    tl_store_end_ext_impl(tlio_out, op, out_sent_kind).unwrap_or(ABI_ERROR)
}

fn tl_store_end_ext_impl(
    tlio_out: *mut TlOutState,
    op: c_int,
    out_sent_kind: *mut c_int,
) -> AbiResult<c_int> {
    if let Some(out_sent_kind_ref) = ptr_mut(out_sent_kind) {
        *out_sent_kind_ref = TL_SENT_KIND_NONE;
    }
    let Some(out_cur) = out_cursor(tlio_out) else {
        return Err(ABI_ERROR);
    };
    if out_cur.out_type == TL_TYPE_NONE {
        return Ok(0);
    }
    if out_cur.out_ptr_is_null {
        return Err(ABI_ERROR);
    }

    let Some(ctx) = out_end_ctx(tlio_out) else {
        return Err(ABI_ERROR);
    };

    let sent_kind = if !ctx.error.is_null() {
        if unsafe { tl_out_clean(tlio_out) } < 0 {
            return Err(ABI_ERROR);
        }
        if unsafe { tl_out_store_int(tlio_out, RPC_REQ_ERROR) } < 0 {
            return Err(ABI_ERROR);
        }
        if unsafe { tl_out_store_long(tlio_out, ctx.out_qid) } < 0 {
            return Err(ABI_ERROR);
        }
        if unsafe { tl_out_store_int(tlio_out, ctx.errnum) } < 0 {
            return Err(ABI_ERROR);
        }
        if unsafe { tl_out_store_string0(tlio_out, ctx.error.cast::<i8>()) } < 0 {
            return Err(ABI_ERROR);
        }
        TL_SENT_KIND_ERROR
    } else if op == RPC_REQ_RESULT {
        TL_SENT_KIND_ANSWER
    } else {
        TL_SENT_KIND_QUERY
    };

    let Some(out_cur_after_payload) = out_cursor(tlio_out) else {
        return Err(ABI_ERROR);
    };
    if (ctx.flags & TLF_NOALIGN) == 0 && (out_cur_after_payload.out_pos & 3) != 0 {
        return Err(ABI_ERROR);
    }

    let mut p: *mut c_int = if (ctx.flags & TLF_ALLOW_PREPEND) != 0 {
        let reserve = ctx.prepend_bytes + if ctx.out_qid != 0 { 12 } else { 0 };
        let Some(store_get_prepend_ptr_fn) = ctx.store_get_prepend_ptr else {
            return Err(ABI_ERROR);
        };
        if out_cur_after_payload.out_remaining < reserve {
            return Err(ABI_ERROR);
        }
        let ptr_ = unsafe { store_get_prepend_ptr_fn(tlio_out, reserve) }.cast::<c_int>();
        let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
            return Err(ABI_ERROR);
        };
        tlio_out_ref.out_pos += reserve;
        tlio_out_ref.out_remaining -= reserve;
        tlio_out_ref.out_size = ptr_;
        ptr_
    } else {
        ctx.out_size
    };

    if ctx.out_qid != 0 {
        if op == 0 || p.is_null() {
            return Err(ABI_ERROR);
        }
        p = p.wrapping_add(usize::try_from(ctx.prepend_bytes / 4).unwrap_or(0));
        unsafe {
            ptr::write_unaligned(p, op);
            ptr::write_unaligned(p.wrapping_add(1).cast::<i64>(), ctx.out_qid);
        }
    }

    if let Some(store_prefix_fn) = ctx.store_prefix {
        unsafe { store_prefix_fn(tlio_out) };
    }
    if (ctx.flags & TLF_NO_AUTOFLUSH) == 0 {
        let Some(store_flush_fn) = ctx.store_flush else {
            return Err(ABI_ERROR);
        };
        unsafe { store_flush_fn(tlio_out) };
    }

    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return Err(ABI_ERROR);
    };
    tlio_out_ref.out_ptr = ptr::null_mut();
    tlio_out_ref.out_type = TL_TYPE_NONE;
    tlio_out_ref.out_methods = ptr::null();
    tlio_out_ref.out_extra = ptr::null_mut();

    if let Some(out_sent_kind_ref) = ptr_mut(out_sent_kind) {
        *out_sent_kind_ref = sent_kind;
    }
    Ok(0)
}

pub(crate) unsafe fn mtproxy_ffi_tl_query_header_delete(h: *mut TlQueryHeader) {
    let Some(h_ref) = ptr_mut(h) else {
        return;
    };
    let refcnt = (&h_ref.ref_cnt as *const c_int).cast::<core::sync::atomic::AtomicI32>();
    if (*refcnt).fetch_sub(1, core::sync::atomic::Ordering::SeqCst) > 1 {
        return;
    }
    libc::free(h.cast::<c_void>());
}

pub(crate) unsafe fn mtproxy_ffi_tl_query_header_dup(h: *mut TlQueryHeader) -> *mut TlQueryHeader {
    let Some(h_ref) = ptr_mut(h) else {
        return ptr::null_mut();
    };
    let refcnt = (&h_ref.ref_cnt as *const c_int).cast::<core::sync::atomic::AtomicI32>();
    let _ = (*refcnt).fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    h
}

pub(crate) unsafe fn mtproxy_ffi_tl_query_header_clone(
    h_old: *const TlQueryHeader,
) -> *mut TlQueryHeader {
    let Some(h_old_ref) = ptr_ref(h_old) else {
        return ptr::null_mut();
    };
    let h = libc::malloc(size_of::<TlQueryHeader>()).cast::<TlQueryHeader>();
    if h.is_null() {
        return ptr::null_mut();
    }
    *h = *h_old_ref;
    (*h).ref_cnt = 1;
    h
}

pub(crate) unsafe fn mtproxy_ffi_tl_set_error(
    tlio_in: *mut TlInState,
    errnum: c_int,
    s: *const i8,
) -> c_int {
    let Some(tlio_in_ref) = in_state_mut(tlio_in) else {
        return -1;
    };
    let Some(s_ref) = ptr_ref(s) else {
        return -1;
    };
    if !tlio_in_ref.error.is_null() {
        return 0;
    }
    tlio_in_ref.error = strdup(s_ref as *const i8);
    tlio_in_ref.errnum = errnum;
    0
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_init(
    tlio_in: *mut TlInState,
    in_ptr: *mut c_void,
    type_: c_int,
    methods: *const TlInMethods,
    size: c_int,
) -> c_int {
    tl_fetch_init_impl(tlio_in, in_ptr, type_, methods, size)
}

pub(crate) unsafe fn mtproxy_ffi_tl_init_raw_message(
    tlio_in: *mut TlInState,
    msg: *mut RawMessage,
    size: c_int,
    dup: c_int,
) -> c_int {
    let Some(msg_ref) = ptr_mut(msg) else {
        return -1;
    };
    let msg_ptr = msg_ref as *mut RawMessage;
    let r = libc::malloc(size_of::<RawMessage>()).cast::<RawMessage>();
    if r.is_null() {
        return -1;
    }
    if dup == 0 {
        rwm_move(r, msg_ptr);
    } else if dup == 1 {
        rwm_move(r, msg_ptr);
        let _ = rwm_init(msg_ptr, 0);
    } else {
        rwm_clone(r, msg_ptr);
    }
    let rc = tl_fetch_init_impl(
        tlio_in,
        r.cast::<c_void>(),
        TL_TYPE_RAW_MSG,
        core::ptr::addr_of!(TL_IN_RAW_MSG_METHODS),
        size,
    );
    if rc < 0 {
        let _ = rwm_free(r);
        libc::free(r.cast::<c_void>());
    }
    rc
}

pub(crate) unsafe fn mtproxy_ffi_tl_init_str(
    tlio_in: *mut TlInState,
    s: *const i8,
    size: c_int,
) -> c_int {
    let Some(s_ref) = ptr_ref(s) else {
        return -1;
    };
    tl_fetch_init_impl(
        tlio_in,
        (s_ref as *const i8).cast_mut().cast::<c_void>(),
        TL_TYPE_STR,
        core::ptr::addr_of!(TL_IN_STR_METHODS),
        size,
    )
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_init(
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

pub(crate) unsafe fn mtproxy_ffi_tl_init_raw_msg(
    tlio_out: *mut TlOutState,
    pid: *const MtproxyProcessId,
    qid: i64,
) -> c_int {
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return -1;
    };
    let pid_ref = ptr_ref(pid);
    if let Some(pid_ref) = pid_ref {
        tlio_out_ref.out_pid_buf = *pid_ref;
        tlio_out_ref.out_pid = &raw mut tlio_out_ref.out_pid_buf;
    } else {
        tlio_out_ref.out_pid = ptr::null_mut();
    }
    let mut d: *mut RawMessage = ptr::null_mut();
    if pid_ref.is_some() {
        d = libc::malloc(size_of::<RawMessage>()).cast::<RawMessage>();
        if d.is_null() {
            return -1;
        }
        let _ = rwm_init(d, 0);
    }
    let rc = tl_store_init_impl(
        tlio_out,
        d.cast::<c_void>(),
        ptr::null_mut(),
        TL_TYPE_RAW_MSG,
        core::ptr::addr_of!(TL_OUT_RAW_MSG_METHODS),
        1 << 27,
        qid,
    );
    if rc < 0 && !d.is_null() {
        let _ = rwm_free(d);
        libc::free(d.cast::<c_void>());
    }
    rc
}

pub(crate) unsafe fn mtproxy_ffi_tl_init_raw_msg_nosend(tlio_out: *mut TlOutState) -> c_int {
    if out_state_mut(tlio_out).is_none() {
        return -1;
    }
    let d = libc::malloc(size_of::<RawMessage>()).cast::<RawMessage>();
    if d.is_null() {
        return -1;
    }
    let _ = rwm_init(d, 0);
    let rc = tl_store_init_impl(
        tlio_out,
        d.cast::<c_void>(),
        d.cast::<c_void>(),
        TL_TYPE_RAW_MSG,
        core::ptr::addr_of!(TL_OUT_RAW_MSG_METHODS_NOSEND),
        1 << 27,
        0,
    );
    if rc < 0 {
        let _ = rwm_free(d);
        libc::free(d.cast::<c_void>());
    }
    rc
}

pub(crate) unsafe fn mtproxy_ffi_tl_init_str_out(
    tlio_out: *mut TlOutState,
    s: *mut i8,
    qid: i64,
    size: c_int,
) -> c_int {
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return -1;
    };
    let Some(s_ref) = ptr_ref(s) else {
        return -1;
    };
    tlio_out_ref.out_pid = ptr::null_mut();
    tl_store_init_impl(
        tlio_out,
        (s_ref as *const i8).cast_mut().cast::<c_void>(),
        (s_ref as *const i8).cast_mut().cast::<c_void>(),
        TL_TYPE_STR,
        core::ptr::addr_of!(TL_OUT_STR_METHODS),
        size,
        qid,
    )
}

pub(crate) unsafe fn mtproxy_ffi_tl_init_tcp_raw_msg(
    tlio_out: *mut TlOutState,
    remote_pid: *const MtproxyProcessId,
    conn: *mut c_void,
    qid: i64,
    unaligned: c_int,
) -> c_int {
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return -1;
    };
    let remote_pid_ref = ptr_ref(remote_pid);
    if let Some(remote_pid_ref) = remote_pid_ref {
        tlio_out_ref.out_pid_buf = *remote_pid_ref;
        tlio_out_ref.out_pid = &raw mut tlio_out_ref.out_pid_buf;
    } else {
        tlio_out_ref.out_pid = ptr::null_mut();
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
        core::ptr::addr_of!(TL_OUT_TCP_RAW_MSG_UNALIGNED_METHODS)
    } else {
        core::ptr::addr_of!(TL_OUT_TCP_RAW_MSG_METHODS)
    };
    let rc = tl_store_init_impl(
        tlio_out,
        d.cast::<c_void>(),
        conn,
        TL_TYPE_TCP_RAW_MSG,
        methods,
        1 << 27,
        qid,
    );
    if rc < 0 && !d.is_null() {
        let _ = rwm_free(d);
        libc::free(d.cast::<c_void>());
    }
    rc
}

pub(crate) unsafe fn mtproxy_ffi_tl_query_header_parse(
    tlio_in: *mut TlInState,
    header: *mut TlQueryHeader,
) -> c_int {
    tl_query_header_parse_impl(tlio_in, header, false)
}

pub(crate) unsafe fn mtproxy_ffi_tl_query_answer_header_parse(
    tlio_in: *mut TlInState,
    header: *mut TlQueryHeader,
) -> c_int {
    tl_query_header_parse_impl(tlio_in, header, true)
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_check(tlio_in: *mut TlInState, nbytes: c_int) -> c_int {
    abi_i32(fetch_check_impl(tlio_in, nbytes))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_lookup_int(tlio_in: *mut TlInState) -> c_int {
    abi_i32(fetch_lookup_int_impl(tlio_in))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_lookup_second_int(tlio_in: *mut TlInState) -> c_int {
    abi_i32(fetch_lookup_second_int_impl(tlio_in))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_lookup_long(tlio_in: *mut TlInState) -> i64 {
    abi_i64(fetch_lookup_long_impl(tlio_in))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_lookup_data(
    tlio_in: *mut TlInState,
    data: *mut c_void,
    len: c_int,
) -> c_int {
    abi_i32(fetch_lookup_data_impl(tlio_in, data, len))
}

fn fetch_check_impl(tlio_in: *mut TlInState, nbytes: c_int) -> AbiResult<c_int> {
    let checked = unsafe { tl_in_check(tlio_in, nbytes) };
    if checked < 0 {
        return Err(ABI_ERROR);
    }
    Ok(checked)
}

fn fetch_lookup_int_impl(tlio_in: *mut TlInState) -> AbiResult<c_int> {
    if unsafe { tl_in_check(tlio_in, 4) } < 0 {
        return Err(ABI_ERROR);
    }
    let mut value: c_int = -1;
    if unsafe { tl_in_lookup_data(tlio_in, (&raw mut value).cast::<c_void>(), 4) } < 0 {
        return Err(ABI_ERROR);
    }
    Ok(value)
}

fn fetch_lookup_second_int_impl(tlio_in: *mut TlInState) -> AbiResult<c_int> {
    if unsafe { tl_in_check(tlio_in, 8) } < 0 {
        return Err(ABI_ERROR);
    }
    let mut values = [0_i32; 2];
    if unsafe { tl_in_lookup_data(tlio_in, values.as_mut_ptr().cast::<c_void>(), 8) } < 0 {
        return Err(ABI_ERROR);
    }
    Ok(values[1])
}

fn fetch_lookup_long_impl(tlio_in: *mut TlInState) -> AbiResult<i64> {
    if unsafe { tl_in_check(tlio_in, 8) } < 0 {
        return Err(ABI_ERROR);
    }
    let mut value: i64 = -1;
    if unsafe { tl_in_lookup_data(tlio_in, (&raw mut value).cast::<c_void>(), 8) } < 0 {
        return Err(ABI_ERROR);
    }
    Ok(value)
}

fn fetch_lookup_data_impl(
    tlio_in: *mut TlInState,
    data: *mut c_void,
    len: c_int,
) -> AbiResult<c_int> {
    if len < 0 {
        return Err(ABI_ERROR);
    }
    if len == 0 {
        return Ok(0);
    }
    if data.is_null() {
        return Err(ABI_ERROR);
    }
    if unsafe { tl_in_check(tlio_in, len) } < 0 {
        return Err(ABI_ERROR);
    }
    let looked = unsafe { tl_in_lookup_data(tlio_in, data, len) };
    if looked < 0 {
        return Err(ABI_ERROR);
    }
    Ok(looked)
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_int(tlio_in: *mut TlInState) -> c_int {
    abi_i32(fetch_int_impl(tlio_in))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_double(tlio_in: *mut TlInState) -> f64 {
    abi_f64(fetch_double_impl(tlio_in))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_long(tlio_in: *mut TlInState) -> i64 {
    abi_i64(fetch_long_impl(tlio_in))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_raw_data(
    tlio_in: *mut TlInState,
    buf: *mut c_void,
    len: c_int,
) -> c_int {
    abi_i32(fetch_raw_data_impl(tlio_in, buf, len))
}

fn fetch_int_impl(tlio_in: *mut TlInState) -> AbiResult<c_int> {
    if unsafe { tl_in_check(tlio_in, 4) } < 0 {
        return Err(ABI_ERROR);
    }
    let mut value: c_int = -1;
    if unsafe { tl_in_fetch_raw_any(tlio_in, (&raw mut value).cast::<c_void>(), 4) } < 0 {
        return Err(ABI_ERROR);
    }
    Ok(value)
}

fn fetch_double_impl(tlio_in: *mut TlInState) -> AbiResult<f64> {
    if unsafe { tl_in_check(tlio_in, 8) } < 0 {
        return Err(ABI_ERROR);
    }
    let mut value: f64 = -1.0;
    if unsafe { tl_in_fetch_raw_any(tlio_in, (&raw mut value).cast::<c_void>(), 8) } < 0 {
        return Err(ABI_ERROR);
    }
    Ok(value)
}

fn fetch_long_impl(tlio_in: *mut TlInState) -> AbiResult<i64> {
    if unsafe { tl_in_check(tlio_in, 8) } < 0 {
        return Err(ABI_ERROR);
    }
    let mut value: i64 = -1;
    if unsafe { tl_in_fetch_raw_any(tlio_in, (&raw mut value).cast::<c_void>(), 8) } < 0 {
        return Err(ABI_ERROR);
    }
    Ok(value)
}

fn fetch_raw_data_impl(tlio_in: *mut TlInState, buf: *mut c_void, len: c_int) -> AbiResult<c_int> {
    if len < 0 || (len & 3) != 0 {
        return Err(ABI_ERROR);
    }
    if len == 0 {
        return Ok(0);
    }
    if buf.is_null() || unsafe { tl_in_check(tlio_in, len) } < 0 {
        return Err(ABI_ERROR);
    }
    let fetched = unsafe { tl_in_fetch_raw_any(tlio_in, buf, len) };
    if fetched < 0 {
        return Err(ABI_ERROR);
    }
    Ok(fetched)
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_mark(tlio_in: *mut TlInState) {
    let _ = fetch_mark_impl(tlio_in);
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_mark_restore(tlio_in: *mut TlInState) {
    let _ = fetch_mark_restore_impl(tlio_in);
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_mark_delete(tlio_in: *mut TlInState) {
    let _ = fetch_mark_delete_impl(tlio_in);
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_string_len(
    tlio_in: *mut TlInState,
    max_len: c_int,
) -> c_int {
    abi_i32(fetch_string_len_impl(tlio_in, max_len))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_pad(tlio_in: *mut TlInState) -> c_int {
    abi_i32(fetch_pad_impl(tlio_in))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_string_data(
    tlio_in: *mut TlInState,
    buf: *mut i8,
    len: c_int,
) -> c_int {
    abi_i32(fetch_string_data_impl(tlio_in, buf, len))
}

fn fetch_mark_impl(tlio_in: *mut TlInState) -> AbiResult<()> {
    let Some(fetch_mark) = in_fetch_mark_cb(tlio_in) else {
        return Ok(());
    };
    unsafe { fetch_mark(tlio_in) };
    Ok(())
}

fn fetch_mark_restore_impl(tlio_in: *mut TlInState) -> AbiResult<()> {
    let Some(fetch_mark_restore) = in_fetch_mark_restore_cb(tlio_in) else {
        return Ok(());
    };
    unsafe { fetch_mark_restore(tlio_in) };
    Ok(())
}

fn fetch_mark_delete_impl(tlio_in: *mut TlInState) -> AbiResult<()> {
    let Some(fetch_mark_delete) = in_fetch_mark_delete_cb(tlio_in) else {
        return Ok(());
    };
    unsafe { fetch_mark_delete(tlio_in) };
    Ok(())
}

fn fetch_string_len_impl(tlio_in: *mut TlInState, max_len: c_int) -> AbiResult<c_int> {
    let len = unsafe { tl_fetch_string_len_impl(tlio_in, max_len) };
    if len < 0 {
        return Err(ABI_ERROR);
    }
    Ok(len)
}

fn fetch_pad_impl(tlio_in: *mut TlInState) -> AbiResult<c_int> {
    let pad = unsafe { tl_fetch_pad_impl(tlio_in) };
    if pad < 0 {
        return Err(ABI_ERROR);
    }
    Ok(pad)
}

fn fetch_string_data_impl(tlio_in: *mut TlInState, buf: *mut i8, len: c_int) -> AbiResult<c_int> {
    if len < 0 {
        return Err(ABI_ERROR);
    }
    if len > 0 && buf.is_null() {
        return Err(ABI_ERROR);
    }
    if unsafe { tl_in_check(tlio_in, len) } < 0 {
        return Err(ABI_ERROR);
    }
    if len > 0 && unsafe { tl_in_fetch_raw_any(tlio_in, buf.cast::<c_void>(), len) } < 0 {
        return Err(ABI_ERROR);
    }
    if unsafe { tl_fetch_pad_impl(tlio_in) } < 0 {
        return Err(ABI_ERROR);
    }
    Ok(len)
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_skip_string_data(
    tlio_in: *mut TlInState,
    len: c_int,
) -> c_int {
    abi_i32(fetch_skip_string_data_impl(tlio_in, len))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_string(
    tlio_in: *mut TlInState,
    buf: *mut i8,
    max_len: c_int,
) -> c_int {
    abi_i32(fetch_string_impl(tlio_in, buf, max_len))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_skip_string(
    tlio_in: *mut TlInState,
    max_len: c_int,
) -> c_int {
    abi_i32(fetch_skip_string_impl(tlio_in, max_len))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_string0(
    tlio_in: *mut TlInState,
    buf: *mut i8,
    max_len: c_int,
) -> c_int {
    abi_i32(fetch_string0_impl(tlio_in, buf, max_len))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_check_str_end(
    tlio_in: *mut TlInState,
    size: c_int,
) -> c_int {
    abi_i32(fetch_check_str_end_impl(tlio_in, size))
}

fn fetch_skip_string_data_impl(tlio_in: *mut TlInState, len: c_int) -> AbiResult<c_int> {
    if len < 0
        || unsafe { tl_in_check(tlio_in, len) } < 0
        || unsafe { tl_in_skip(tlio_in, len) } < 0
    {
        return Err(ABI_ERROR);
    }
    if unsafe { tl_fetch_pad_impl(tlio_in) } < 0 {
        return Err(ABI_ERROR);
    }
    Ok(len)
}

fn fetch_string_impl(tlio_in: *mut TlInState, buf: *mut i8, max_len: c_int) -> AbiResult<c_int> {
    let len = unsafe { tl_fetch_string_len_impl(tlio_in, max_len) };
    if len < 0 {
        return Err(ABI_ERROR);
    }
    fetch_string_data_impl(tlio_in, buf, len)
}

fn fetch_skip_string_impl(tlio_in: *mut TlInState, max_len: c_int) -> AbiResult<c_int> {
    let len = unsafe { tl_fetch_string_len_impl(tlio_in, max_len) };
    if len < 0 {
        return Err(ABI_ERROR);
    }
    fetch_skip_string_data_impl(tlio_in, len)
}

fn fetch_string0_impl(tlio_in: *mut TlInState, buf: *mut i8, max_len: c_int) -> AbiResult<c_int> {
    let len = unsafe { tl_fetch_string_len_impl(tlio_in, max_len) };
    if len < 0 {
        return Err(ABI_ERROR);
    }
    fetch_string_data_impl(tlio_in, buf, len)?;
    if buf.is_null() {
        return Err(ABI_ERROR);
    }
    unsafe {
        *buf.wrapping_add(usize::try_from(len).unwrap_or(0)) = 0;
    }
    Ok(len)
}

fn fetch_check_str_end_impl(tlio_in: *mut TlInState, size: c_int) -> AbiResult<c_int> {
    let Some(cursor) = in_cursor(tlio_in) else {
        return Err(ABI_ERROR);
    };
    if size < 0 {
        return Err(ABI_ERROR);
    }
    let expected = size + ((-size - cursor.in_pos) & 3);
    if cursor.in_remaining != expected {
        unsafe {
            tl_set_error_once(
                tlio_in,
                TL_ERROR_EXTRA_DATA,
                &format!("extra {} bytes after query", cursor.in_remaining - expected),
            );
        }
        return Err(ABI_ERROR);
    }
    Ok(1)
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_unread(tlio_in: *mut TlInState) -> c_int {
    abi_i32(fetch_unread_impl(tlio_in))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_skip(tlio_in: *mut TlInState, len: c_int) -> c_int {
    abi_i32(fetch_skip_impl(tlio_in, len))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_end(tlio_in: *mut TlInState) -> c_int {
    abi_i32(fetch_end_impl(tlio_in))
}

fn fetch_unread_impl(tlio_in: *mut TlInState) -> AbiResult<c_int> {
    let Some(cursor) = in_cursor(tlio_in) else {
        return Err(ABI_ERROR);
    };
    Ok(cursor.in_remaining)
}

fn fetch_skip_impl(tlio_in: *mut TlInState, len: c_int) -> AbiResult<c_int> {
    if len < 0 || unsafe { tl_in_check(tlio_in, len) } < 0 {
        return Err(ABI_ERROR);
    }
    let skipped = unsafe { tl_in_skip(tlio_in, len) };
    if skipped < 0 {
        return Err(ABI_ERROR);
    }
    Ok(skipped)
}

fn fetch_end_impl(tlio_in: *mut TlInState) -> AbiResult<c_int> {
    let Some(cursor) = in_cursor(tlio_in) else {
        return Err(ABI_ERROR);
    };
    if cursor.in_remaining != 0 && (cursor.in_flags & TL_FETCH_FLAG_ALLOW_DATA_AFTER_QUERY) == 0 {
        unsafe {
            tl_set_error_once(
                tlio_in,
                TL_ERROR_EXTRA_DATA,
                &format!("extra {} bytes after query", cursor.in_remaining),
            );
        }
        return Err(ABI_ERROR);
    }
    Ok(1)
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_error(tlio_in: *mut TlInState) -> c_int {
    abi_i32(fetch_error_impl(tlio_in))
}

fn fetch_error_impl(tlio_in: *mut TlInState) -> AbiResult<c_int> {
    let Some(cursor) = in_cursor(tlio_in) else {
        return Ok(1);
    };
    if cursor.has_error {
        Ok(1)
    } else {
        Ok(0)
    }
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_int_range(
    tlio_in: *mut TlInState,
    min: c_int,
    max: c_int,
) -> c_int {
    let value = abi_i32(fetch_int_impl(tlio_in));
    if value < min || value > max {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_VALUE_NOT_IN_RANGE,
            &format!("Expected int32 in range [{min},{max}], {value} presented"),
        );
    }
    value
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_positive_int(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_int_range(tlio_in, 1, 0x7fff_ffff)
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_nonnegative_int(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_int_range(tlio_in, 0, 0x7fff_ffff)
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_int_subset(tlio_in: *mut TlInState, set: c_int) -> c_int {
    let value = abi_i32(fetch_int_impl(tlio_in));
    if (value & !set) != 0 {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_VALUE_NOT_IN_RANGE,
            &format!("Expected int32 with only bits 0x{set:02x} allowed, 0x{value:02x} presented"),
        );
    }
    value
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_long_range(
    tlio_in: *mut TlInState,
    min: i64,
    max: i64,
) -> i64 {
    let value = abi_i64(fetch_long_impl(tlio_in));
    if value < min || value > max {
        tl_set_error_once(
            tlio_in,
            TL_ERROR_VALUE_NOT_IN_RANGE,
            &format!("Expected int64 in range [{min},{max}], {value} presented"),
        );
    }
    value
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_positive_long(tlio_in: *mut TlInState) -> i64 {
    mtproxy_ffi_tl_fetch_long_range(tlio_in, 1, 0x7fff_ffff_ffff_ffff_i64)
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_nonnegative_long(tlio_in: *mut TlInState) -> i64 {
    mtproxy_ffi_tl_fetch_long_range(tlio_in, 0, 0x7fff_ffff_ffff_ffff_i64)
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_raw_message(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    abi_i32(fetch_raw_message_impl(tlio_in, raw, bytes))
}

pub(crate) unsafe fn mtproxy_ffi_tl_fetch_lookup_raw_message(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    abi_i32(fetch_lookup_raw_message_impl(tlio_in, raw, bytes))
}

fn fetch_raw_message_impl(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    bytes: c_int,
) -> AbiResult<c_int> {
    if unsafe { tl_in_check(tlio_in, bytes) } < 0 {
        return Err(ABI_ERROR);
    }
    let Some(raw_ref) = ptr_mut(raw) else {
        return Err(ABI_ERROR);
    };
    let Some(tlio_in_ref) = in_state_mut(tlio_in) else {
        return Err(ABI_ERROR);
    };
    let Some(fetch_raw_message) = in_fetch_raw_message_cb(tlio_in) else {
        return Err(ABI_ERROR);
    };
    unsafe { fetch_raw_message(tlio_in, raw_ref as *mut RawMessage, bytes) };
    tlio_in_ref.in_pos += bytes;
    tlio_in_ref.in_remaining -= bytes;
    Ok(0)
}

fn fetch_lookup_raw_message_impl(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    bytes: c_int,
) -> AbiResult<c_int> {
    if unsafe { tl_in_check(tlio_in, bytes) } < 0 {
        return Err(ABI_ERROR);
    }
    let Some(raw_ref) = ptr_mut(raw) else {
        return Err(ABI_ERROR);
    };
    let Some(fetch_lookup_raw_message) = in_fetch_lookup_raw_message_cb(tlio_in) else {
        return Err(ABI_ERROR);
    };
    unsafe { fetch_lookup_raw_message(tlio_in, raw_ref as *mut RawMessage, bytes) };
    Ok(0)
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_get_ptr(
    tlio_out: *mut TlOutState,
    size: c_int,
) -> *mut c_void {
    abi_ptr(store_get_ptr_impl(tlio_out, size))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_get_prepend_ptr(
    tlio_out: *mut TlOutState,
    size: c_int,
) -> *mut c_void {
    abi_ptr(store_get_prepend_ptr_impl(tlio_out, size))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_int(tlio_out: *mut TlOutState, x: c_int) -> c_int {
    abi_i32(store_int_impl(tlio_out, x))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_long(tlio_out: *mut TlOutState, x: i64) -> c_int {
    abi_i32(store_long_impl(tlio_out, x))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_double(tlio_out: *mut TlOutState, x: f64) -> c_int {
    abi_i32(store_double_impl(tlio_out, x))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_raw_data(
    tlio_out: *mut TlOutState,
    data: *const c_void,
    len: c_int,
) -> c_int {
    abi_i32(store_raw_data_impl(tlio_out, data, len))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_raw_msg(
    tlio_out: *mut TlOutState,
    raw: *mut RawMessage,
    dup: c_int,
) -> c_int {
    abi_i32(store_raw_msg_impl(tlio_out, raw, dup))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_string_len(
    tlio_out: *mut TlOutState,
    len: c_int,
) -> c_int {
    abi_i32(store_string_len_impl(tlio_out, len))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_pad(tlio_out: *mut TlOutState) -> c_int {
    abi_i32(store_pad_impl(tlio_out))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_string_data(
    tlio_out: *mut TlOutState,
    s: *const i8,
    len: c_int,
) -> c_int {
    abi_i32(store_string_data_impl(tlio_out, s, len))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_string(
    tlio_out: *mut TlOutState,
    s: *const i8,
    len: c_int,
) -> c_int {
    abi_i32(store_string_impl(tlio_out, s, len))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_clear(tlio_out: *mut TlOutState) -> c_int {
    abi_i32(store_clear_impl(tlio_out))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_clean(tlio_out: *mut TlOutState) -> c_int {
    abi_i32(store_clean_impl(tlio_out))
}

pub(crate) unsafe fn mtproxy_ffi_tl_store_pos(tlio_out: *mut TlOutState) -> c_int {
    abi_i32(store_pos_impl(tlio_out))
}

fn store_get_ptr_impl(tlio_out: *mut TlOutState, size: c_int) -> AbiResult<*mut c_void> {
    if size <= 0 || unsafe { tl_out_check(tlio_out, size) } < 0 {
        return Err(ABI_ERROR);
    }
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return Err(ABI_ERROR);
    };
    let Some(store_get_ptr) = out_store_get_ptr_cb(tlio_out) else {
        return Err(ABI_ERROR);
    };
    let p = unsafe { store_get_ptr(tlio_out, size) };
    if p.is_null() {
        return Err(ABI_ERROR);
    }
    tlio_out_ref.out_pos += size;
    tlio_out_ref.out_remaining -= size;
    Ok(p)
}

fn store_get_prepend_ptr_impl(tlio_out: *mut TlOutState, size: c_int) -> AbiResult<*mut c_void> {
    if size <= 0 || unsafe { tl_out_check(tlio_out, size) } < 0 {
        return Err(ABI_ERROR);
    }
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return Err(ABI_ERROR);
    };
    let Some(store_get_prepend_ptr) = out_store_get_prepend_ptr_cb(tlio_out) else {
        return Err(ABI_ERROR);
    };
    let p = unsafe { store_get_prepend_ptr(tlio_out, size) };
    if p.is_null() {
        return Err(ABI_ERROR);
    }
    tlio_out_ref.out_pos += size;
    tlio_out_ref.out_remaining -= size;
    Ok(p)
}

fn store_int_impl(tlio_out: *mut TlOutState, x: c_int) -> AbiResult<c_int> {
    let rc = unsafe { tl_out_store_int(tlio_out, x) };
    if rc < 0 {
        return Err(ABI_ERROR);
    }
    Ok(rc)
}

fn store_long_impl(tlio_out: *mut TlOutState, x: i64) -> AbiResult<c_int> {
    let rc = unsafe { tl_out_store_long(tlio_out, x) };
    if rc < 0 {
        return Err(ABI_ERROR);
    }
    Ok(rc)
}

fn store_double_impl(tlio_out: *mut TlOutState, x: f64) -> AbiResult<c_int> {
    let bytes = x.to_le_bytes();
    store_raw_data_impl(tlio_out, bytes.as_ptr().cast::<c_void>(), 8)
}

fn store_raw_data_impl(
    tlio_out: *mut TlOutState,
    data: *const c_void,
    len: c_int,
) -> AbiResult<c_int> {
    let rc = unsafe { tl_out_store_raw_data(tlio_out, data, len) };
    if rc < 0 {
        return Err(ABI_ERROR);
    }
    Ok(rc)
}

fn store_raw_msg_impl(
    tlio_out: *mut TlOutState,
    raw: *mut RawMessage,
    dup: c_int,
) -> AbiResult<c_int> {
    let Some(raw_ref) = ptr_mut(raw) else {
        return Err(ABI_ERROR);
    };
    let len = raw_ref.total_bytes;
    if len < 0 || unsafe { tl_out_check(tlio_out, len) } < 0 {
        return Err(ABI_ERROR);
    }
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return Err(ABI_ERROR);
    };
    let Some(store_raw_msg) = out_store_raw_msg_cb(tlio_out) else {
        return Err(ABI_ERROR);
    };
    if dup == 0 {
        unsafe { store_raw_msg(tlio_out, raw_ref as *mut RawMessage) };
    } else {
        let mut cloned = RawMessage::default();
        unsafe { rwm_clone(&mut cloned, raw_ref as *mut RawMessage) };
        unsafe { store_raw_msg(tlio_out, &mut cloned) };
    }
    tlio_out_ref.out_pos += len;
    tlio_out_ref.out_remaining -= len;
    Ok(0)
}

fn store_string_len_impl(tlio_out: *mut TlOutState, len: c_int) -> AbiResult<c_int> {
    if len < 0 {
        return Err(ABI_ERROR);
    }
    let rc = unsafe { tl_out_store_string_len(tlio_out, usize::try_from(len).unwrap_or(0)) };
    if rc < 0 {
        return Err(ABI_ERROR);
    }
    Ok(rc)
}

fn store_pad_impl(tlio_out: *mut TlOutState) -> AbiResult<c_int> {
    let rc = unsafe { tl_out_store_pad(tlio_out) };
    if rc < 0 {
        return Err(ABI_ERROR);
    }
    Ok(rc)
}

fn store_string_data_impl(tlio_out: *mut TlOutState, s: *const i8, len: c_int) -> AbiResult<c_int> {
    if len < 0 {
        return Err(ABI_ERROR);
    }
    if len > 0 && s.is_null() {
        return Err(ABI_ERROR);
    }
    if len > 0 && unsafe { tl_out_store_raw_data(tlio_out, s.cast::<c_void>(), len) } < 0 {
        return Err(ABI_ERROR);
    }
    store_pad_impl(tlio_out)
}

fn store_string_impl(tlio_out: *mut TlOutState, s: *const i8, len: c_int) -> AbiResult<c_int> {
    if len < 0 {
        return Err(ABI_ERROR);
    }
    let len_usize = usize::try_from(len).unwrap_or(0);
    if len_usize > 0 && s.is_null() {
        return Err(ABI_ERROR);
    }
    if unsafe { tl_out_store_string_len(tlio_out, len_usize) } < 0 {
        return Err(ABI_ERROR);
    }
    if len_usize > 0
        && unsafe {
            tl_out_store_raw_data(
                tlio_out,
                s.cast::<c_void>(),
                c_int::try_from(len_usize).unwrap_or(c_int::MAX),
            )
        } < 0
    {
        return Err(ABI_ERROR);
    }
    store_pad_impl(tlio_out)
}

fn store_clear_impl(tlio_out: *mut TlOutState) -> AbiResult<c_int> {
    let Some(cursor) = out_cursor(tlio_out) else {
        return Err(ABI_ERROR);
    };
    if cursor.out_ptr_is_null {
        return Err(ABI_ERROR);
    }
    let Some(store_clear) = out_store_clear_cb(tlio_out) else {
        return Err(ABI_ERROR);
    };
    unsafe { store_clear(tlio_out) };
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return Err(ABI_ERROR);
    };
    tlio_out_ref.out_ptr = ptr::null_mut();
    tlio_out_ref.out_type = TL_TYPE_NONE;
    tlio_out_ref.out_extra = ptr::null_mut();
    Ok(0)
}

fn store_clean_impl(tlio_out: *mut TlOutState) -> AbiResult<c_int> {
    let rc = unsafe { tl_out_clean(tlio_out) };
    if rc < 0 {
        return Err(ABI_ERROR);
    }
    Ok(rc)
}

fn store_pos_impl(tlio_out: *mut TlOutState) -> AbiResult<c_int> {
    let Some(cursor) = out_cursor(tlio_out) else {
        return Err(ABI_ERROR);
    };
    Ok(cursor.out_pos)
}

pub(crate) unsafe fn mtproxy_ffi_tl_copy_through(
    tlio_in: *mut TlInState,
    tlio_out: *mut TlOutState,
    len: c_int,
    advance: c_int,
) -> c_int {
    let Some(in_cur) = in_cursor(tlio_in) else {
        return -1;
    };
    let Some(out_cur) = out_cursor(tlio_out) else {
        return -1;
    };
    if len < 0
        || in_cur.in_type == TL_TYPE_NONE
        || out_cur.out_type == TL_TYPE_NONE
        || tl_in_check(tlio_in, len) < 0
        || tl_out_check(tlio_out, len) < 0
    {
        return -1;
    }

    let in_type = usize::try_from(in_cur.in_type).unwrap_or(usize::MAX);
    let Some(copy_through) = out_copy_through_cb(tlio_out, in_type) else {
        return -1;
    };
    copy_through(tlio_in, tlio_out, len, advance);

    let Some(tlio_in_ref) = in_state_mut(tlio_in) else {
        return -1;
    };
    let Some(tlio_out_ref) = out_state_mut(tlio_out) else {
        return -1;
    };
    if advance != 0 {
        tlio_in_ref.in_pos += len;
        tlio_in_ref.in_remaining -= len;
    }
    tlio_out_ref.out_pos += len;
    tlio_out_ref.out_remaining -= len;
    len
}

pub(crate) static TL_IN_RAW_MSG_METHODS: TlInMethods = TlInMethods {
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

pub(crate) static TL_IN_STR_METHODS: TlInMethods = TlInMethods {
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

pub(crate) static TL_OUT_RAW_MSG_METHODS: TlOutMethods = TlOutMethods {
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

pub(crate) static TL_OUT_RAW_MSG_METHODS_NOSEND: TlOutMethods = TlOutMethods {
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

pub(crate) static TL_OUT_TCP_RAW_MSG_METHODS: TlOutMethods = TlOutMethods {
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

pub(crate) static TL_OUT_TCP_RAW_MSG_UNALIGNED_METHODS: TlOutMethods = TlOutMethods {
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

pub(crate) static TL_OUT_STR_METHODS: TlOutMethods = TlOutMethods {
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
