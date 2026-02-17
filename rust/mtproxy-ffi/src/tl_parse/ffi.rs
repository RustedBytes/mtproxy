use super::abi as tl_abi;
use crate::MtproxyProcessId;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicI64, Ordering};

pub use tl_abi::{RawMessage, TlInMethods, TlInState, TlOutMethods, TlOutState, TlQueryHeader};

static TL_RPC_QUERIES_RECEIVED: AtomicI64 = AtomicI64::new(0);
static TL_RPC_ANSWERS_ERROR: AtomicI64 = AtomicI64::new(0);
static TL_RPC_ANSWERS_RECEIVED: AtomicI64 = AtomicI64::new(0);
static TL_RPC_SENT_ERRORS: AtomicI64 = AtomicI64::new(0);
static TL_RPC_SENT_ANSWERS: AtomicI64 = AtomicI64::new(0);
static TL_RPC_SENT_QUERIES: AtomicI64 = AtomicI64::new(0);
static TL_IN_ALLOCATED: AtomicI32 = AtomicI32::new(0);
static TL_OUT_ALLOCATED: AtomicI32 = AtomicI32::new(0);
const TL_TYPE_NONE: c_int = 0;
const TL_TYPE_RAW_MSG: c_int = 2;
const TL_TYPE_TCP_RAW_MSG: c_int = 3;

#[repr(C)]
pub struct TlParseStatsBuffer {
    pub buff: *mut c_char,
    pub pos: c_int,
    pub size: c_int,
    pub flags: c_int,
}

#[no_mangle]
pub static tl_in_raw_msg_methods: TlInMethods = tl_abi::TL_IN_RAW_MSG_METHODS;
#[no_mangle]
pub static tl_in_str_methods: TlInMethods = tl_abi::TL_IN_STR_METHODS;
#[no_mangle]
pub static tl_out_raw_msg_methods: TlOutMethods = tl_abi::TL_OUT_RAW_MSG_METHODS;
#[no_mangle]
pub static tl_out_raw_msg_methods_nosend: TlOutMethods = tl_abi::TL_OUT_RAW_MSG_METHODS_NOSEND;
#[no_mangle]
pub static tl_out_tcp_raw_msg_methods: TlOutMethods = tl_abi::TL_OUT_TCP_RAW_MSG_METHODS;
#[no_mangle]
pub static tl_out_tcp_raw_msg_unaligned_methods: TlOutMethods =
    tl_abi::TL_OUT_TCP_RAW_MSG_UNALIGNED_METHODS;
#[no_mangle]
pub static tl_out_str_methods: TlOutMethods = tl_abi::TL_OUT_STR_METHODS;

unsafe extern "C" {
    fn mtproxy_ffi_net_tcp_rpc_common_copy_remote_pid(
        c: *mut c_void,
        out_pid: *mut MtproxyProcessId,
    ) -> c_int;
    fn mtproxy_ffi_rpc_target_choose_connection_by_pid(pid: *mut MtproxyProcessId) -> *mut c_void;
    static mut start_time: c_int;
    fn tcp_get_default_rpc_flags() -> u32;
}

unsafe fn append_to_sb(sb: *mut TlParseStatsBuffer, text: &str) {
    if sb.is_null() {
        return;
    }

    let sb_ref = unsafe { &mut *sb };
    if sb_ref.buff.is_null() || sb_ref.size <= 0 || sb_ref.pos >= sb_ref.size {
        return;
    }

    let remaining = (sb_ref.size - sb_ref.pos) as usize;
    if remaining <= 1 {
        return;
    }

    let bytes = text.as_bytes();
    let to_copy = core::cmp::min(remaining - 1, bytes.len());
    if to_copy == 0 {
        return;
    }

    let dest = unsafe { sb_ref.buff.add(sb_ref.pos as usize) as *mut u8 };
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dest, to_copy) };
    sb_ref.pos += to_copy as c_int;
    if sb_ref.pos < sb_ref.size {
        unsafe { *sb_ref.buff.add(sb_ref.pos as usize) = 0 };
    }
}

#[inline]
fn safe_div(x: f64, y: f64) -> f64 {
    if y > 0.0 { x / y } else { 0.0 }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_header(
    tlio_out: *mut TlOutState,
    header: *const TlQueryHeader,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_header(tlio_out, header)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_end_ext(
    tlio_out: *mut TlOutState,
    op: c_int,
    out_sent_kind: *mut c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_end_ext(tlio_out, op, out_sent_kind)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_query_header_delete(h: *mut TlQueryHeader) {
    tl_abi::mtproxy_ffi_tl_query_header_delete(h);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_query_header_dup(
    h: *mut TlQueryHeader,
) -> *mut TlQueryHeader {
    tl_abi::mtproxy_ffi_tl_query_header_dup(h)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_query_header_clone(
    h_old: *const TlQueryHeader,
) -> *mut TlQueryHeader {
    tl_abi::mtproxy_ffi_tl_query_header_clone(h_old)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_set_error(
    tlio_in: *mut TlInState,
    errnum: c_int,
    s: *const i8,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_set_error(tlio_in, errnum, s)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_init(
    tlio_in: *mut TlInState,
    in_ptr: *mut c_void,
    type_: c_int,
    methods: *const TlInMethods,
    size: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_init(tlio_in, in_ptr, type_, methods, size)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_raw_message(
    tlio_in: *mut TlInState,
    msg: *mut RawMessage,
    size: c_int,
    dup: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_init_raw_message(tlio_in, msg, size, dup)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_str(
    tlio_in: *mut TlInState,
    s: *const i8,
    size: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_init_str(tlio_in, s, size)
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
    tl_abi::mtproxy_ffi_tl_store_init(tlio_out, out, out_extra, type_, methods, size, qid)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_raw_msg(
    tlio_out: *mut TlOutState,
    pid: *const MtproxyProcessId,
    qid: i64,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_init_raw_msg(tlio_out, pid, qid)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_raw_msg_nosend(tlio_out: *mut TlOutState) -> c_int {
    tl_abi::mtproxy_ffi_tl_init_raw_msg_nosend(tlio_out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_str_out(
    tlio_out: *mut TlOutState,
    s: *mut i8,
    qid: i64,
    size: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_init_str_out(tlio_out, s, qid, size)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_init_tcp_raw_msg(
    tlio_out: *mut TlOutState,
    remote_pid: *const MtproxyProcessId,
    conn: *mut c_void,
    qid: i64,
    unaligned: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_init_tcp_raw_msg(tlio_out, remote_pid, conn, qid, unaligned)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_query_header_parse(
    tlio_in: *mut TlInState,
    header: *mut TlQueryHeader,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_query_header_parse(tlio_in, header)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_query_answer_header_parse(
    tlio_in: *mut TlInState,
    header: *mut TlQueryHeader,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_query_answer_header_parse(tlio_in, header)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_check(
    tlio_in: *mut TlInState,
    nbytes: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_check(tlio_in, nbytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_lookup_int(tlio_in: *mut TlInState) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_lookup_int(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_lookup_second_int(tlio_in: *mut TlInState) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_lookup_second_int(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_lookup_long(tlio_in: *mut TlInState) -> i64 {
    tl_abi::mtproxy_ffi_tl_fetch_lookup_long(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_lookup_data(
    tlio_in: *mut TlInState,
    data: *mut c_void,
    len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_lookup_data(tlio_in, data, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_int(tlio_in: *mut TlInState) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_int(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_double(tlio_in: *mut TlInState) -> f64 {
    tl_abi::mtproxy_ffi_tl_fetch_double(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_long(tlio_in: *mut TlInState) -> i64 {
    tl_abi::mtproxy_ffi_tl_fetch_long(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_raw_data(
    tlio_in: *mut TlInState,
    buf: *mut c_void,
    len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_raw_data(tlio_in, buf, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_mark(tlio_in: *mut TlInState) {
    tl_abi::mtproxy_ffi_tl_fetch_mark(tlio_in);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_mark_restore(tlio_in: *mut TlInState) {
    tl_abi::mtproxy_ffi_tl_fetch_mark_restore(tlio_in);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_mark_delete(tlio_in: *mut TlInState) {
    tl_abi::mtproxy_ffi_tl_fetch_mark_delete(tlio_in);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_string_len(
    tlio_in: *mut TlInState,
    max_len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_string_len(tlio_in, max_len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_pad(tlio_in: *mut TlInState) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_pad(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_string_data(
    tlio_in: *mut TlInState,
    buf: *mut i8,
    len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_string_data(tlio_in, buf, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_skip_string_data(
    tlio_in: *mut TlInState,
    len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_skip_string_data(tlio_in, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_string(
    tlio_in: *mut TlInState,
    buf: *mut i8,
    max_len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_string(tlio_in, buf, max_len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_skip_string(
    tlio_in: *mut TlInState,
    max_len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_skip_string(tlio_in, max_len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_string0(
    tlio_in: *mut TlInState,
    buf: *mut i8,
    max_len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_string0(tlio_in, buf, max_len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_check_str_end(
    tlio_in: *mut TlInState,
    size: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_check_str_end(tlio_in, size)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_unread(tlio_in: *mut TlInState) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_unread(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_skip(tlio_in: *mut TlInState, len: c_int) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_skip(tlio_in, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_end(tlio_in: *mut TlInState) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_end(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_error(tlio_in: *mut TlInState) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_error(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_int_range(
    tlio_in: *mut TlInState,
    min: c_int,
    max: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_int_range(tlio_in, min, max)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_positive_int(tlio_in: *mut TlInState) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_positive_int(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_nonnegative_int(tlio_in: *mut TlInState) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_nonnegative_int(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_int_subset(
    tlio_in: *mut TlInState,
    set: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_int_subset(tlio_in, set)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_long_range(
    tlio_in: *mut TlInState,
    min: i64,
    max: i64,
) -> i64 {
    tl_abi::mtproxy_ffi_tl_fetch_long_range(tlio_in, min, max)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_positive_long(tlio_in: *mut TlInState) -> i64 {
    tl_abi::mtproxy_ffi_tl_fetch_positive_long(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_nonnegative_long(tlio_in: *mut TlInState) -> i64 {
    tl_abi::mtproxy_ffi_tl_fetch_nonnegative_long(tlio_in)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_raw_message(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_raw_message(tlio_in, raw, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_fetch_lookup_raw_message(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_fetch_lookup_raw_message(tlio_in, raw, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_get_ptr(
    tlio_out: *mut TlOutState,
    size: c_int,
) -> *mut c_void {
    tl_abi::mtproxy_ffi_tl_store_get_ptr(tlio_out, size)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_get_prepend_ptr(
    tlio_out: *mut TlOutState,
    size: c_int,
) -> *mut c_void {
    tl_abi::mtproxy_ffi_tl_store_get_prepend_ptr(tlio_out, size)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_int(tlio_out: *mut TlOutState, x: c_int) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_int(tlio_out, x)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_long(tlio_out: *mut TlOutState, x: i64) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_long(tlio_out, x)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_double(tlio_out: *mut TlOutState, x: f64) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_double(tlio_out, x)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_raw_data(
    tlio_out: *mut TlOutState,
    data: *const c_void,
    len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_raw_data(tlio_out, data, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_raw_msg(
    tlio_out: *mut TlOutState,
    raw: *mut RawMessage,
    dup: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_raw_msg(tlio_out, raw, dup)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_string_len(
    tlio_out: *mut TlOutState,
    len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_string_len(tlio_out, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_pad(tlio_out: *mut TlOutState) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_pad(tlio_out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_string_data(
    tlio_out: *mut TlOutState,
    s: *const i8,
    len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_string_data(tlio_out, s, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_string(
    tlio_out: *mut TlOutState,
    s: *const i8,
    len: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_string(tlio_out, s, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_clear(tlio_out: *mut TlOutState) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_clear(tlio_out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_clean(tlio_out: *mut TlOutState) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_clean(tlio_out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_store_pos(tlio_out: *mut TlOutState) -> c_int {
    tl_abi::mtproxy_ffi_tl_store_pos(tlio_out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_copy_through(
    tlio_in: *mut TlInState,
    tlio_out: *mut TlOutState,
    len: c_int,
    advance: c_int,
) -> c_int {
    tl_abi::mtproxy_ffi_tl_copy_through(tlio_in, tlio_out, len, advance)
}

#[export_name = "tl_query_header_delete"]
pub unsafe extern "C" fn c_tl_query_header_delete(h: *mut TlQueryHeader) {
    mtproxy_ffi_tl_query_header_delete(h);
}

#[export_name = "tl_query_header_dup"]
pub unsafe extern "C" fn c_tl_query_header_dup(h: *mut TlQueryHeader) -> *mut TlQueryHeader {
    mtproxy_ffi_tl_query_header_dup(h)
}

#[export_name = "tl_query_header_clone"]
pub unsafe extern "C" fn c_tl_query_header_clone(
    h_old: *const TlQueryHeader,
) -> *mut TlQueryHeader {
    mtproxy_ffi_tl_query_header_clone(h_old)
}

#[export_name = "tlf_set_error"]
pub unsafe extern "C" fn c_tlf_set_error(
    tlio_in: *mut TlInState,
    errnum: c_int,
    s: *const c_char,
) -> c_int {
    mtproxy_ffi_tl_set_error(tlio_in, errnum, s)
}

#[export_name = "tlf_check_rust"]
pub unsafe extern "C" fn c_tlf_check_rust(tlio_in: *mut TlInState, nbytes: c_int) -> c_int {
    mtproxy_ffi_tl_fetch_check(tlio_in, nbytes)
}

#[export_name = "tlf_lookup_int_rust"]
pub unsafe extern "C" fn c_tlf_lookup_int_rust(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_lookup_int(tlio_in)
}

#[export_name = "tlf_lookup_second_int_rust"]
pub unsafe extern "C" fn c_tlf_lookup_second_int_rust(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_lookup_second_int(tlio_in)
}

#[export_name = "tlf_lookup_long_rust"]
pub unsafe extern "C" fn c_tlf_lookup_long_rust(tlio_in: *mut TlInState) -> i64 {
    mtproxy_ffi_tl_fetch_lookup_long(tlio_in)
}

#[export_name = "tlf_lookup_data_rust"]
pub unsafe extern "C" fn c_tlf_lookup_data_rust(
    tlio_in: *mut TlInState,
    data: *mut c_void,
    len: c_int,
) -> c_int {
    mtproxy_ffi_tl_fetch_lookup_data(tlio_in, data, len)
}

#[export_name = "tlf_int_rust"]
pub unsafe extern "C" fn c_tlf_int_rust(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_int(tlio_in)
}

#[export_name = "tlf_double_rust"]
pub unsafe extern "C" fn c_tlf_double_rust(tlio_in: *mut TlInState) -> f64 {
    mtproxy_ffi_tl_fetch_double(tlio_in)
}

#[export_name = "tlf_long_rust"]
pub unsafe extern "C" fn c_tlf_long_rust(tlio_in: *mut TlInState) -> i64 {
    mtproxy_ffi_tl_fetch_long(tlio_in)
}

#[export_name = "tlf_mark_rust"]
pub unsafe extern "C" fn c_tlf_mark_rust(tlio_in: *mut TlInState) {
    mtproxy_ffi_tl_fetch_mark(tlio_in);
}

#[export_name = "tlf_mark_restore_rust"]
pub unsafe extern "C" fn c_tlf_mark_restore_rust(tlio_in: *mut TlInState) {
    mtproxy_ffi_tl_fetch_mark_restore(tlio_in);
}

#[export_name = "tlf_mark_delete_rust"]
pub unsafe extern "C" fn c_tlf_mark_delete_rust(tlio_in: *mut TlInState) {
    mtproxy_ffi_tl_fetch_mark_delete(tlio_in);
}

#[export_name = "tlf_string_len_rust"]
pub unsafe extern "C" fn c_tlf_string_len_rust(tlio_in: *mut TlInState, max_len: c_int) -> c_int {
    mtproxy_ffi_tl_fetch_string_len(tlio_in, max_len)
}

#[export_name = "tlf_pad_rust"]
pub unsafe extern "C" fn c_tlf_pad_rust(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_pad(tlio_in)
}

#[export_name = "tlf_raw_data_rust"]
pub unsafe extern "C" fn c_tlf_raw_data_rust(
    tlio_in: *mut TlInState,
    buf: *mut c_void,
    len: c_int,
) -> c_int {
    mtproxy_ffi_tl_fetch_raw_data(tlio_in, buf, len)
}

#[export_name = "tlf_string_data_rust"]
pub unsafe extern "C" fn c_tlf_string_data_rust(
    tlio_in: *mut TlInState,
    buf: *mut c_char,
    len: c_int,
) -> c_int {
    mtproxy_ffi_tl_fetch_string_data(tlio_in, buf, len)
}

#[export_name = "tlf_skip_string_data_rust"]
pub unsafe extern "C" fn c_tlf_skip_string_data_rust(
    tlio_in: *mut TlInState,
    len: c_int,
) -> c_int {
    mtproxy_ffi_tl_fetch_skip_string_data(tlio_in, len)
}

#[export_name = "tlf_string_rust"]
pub unsafe extern "C" fn c_tlf_string_rust(
    tlio_in: *mut TlInState,
    buf: *mut c_char,
    max_len: c_int,
) -> c_int {
    mtproxy_ffi_tl_fetch_string(tlio_in, buf, max_len)
}

#[export_name = "tlf_skip_string_rust"]
pub unsafe extern "C" fn c_tlf_skip_string_rust(tlio_in: *mut TlInState, max_len: c_int) -> c_int {
    mtproxy_ffi_tl_fetch_skip_string(tlio_in, max_len)
}

#[export_name = "tlf_string0_rust"]
pub unsafe extern "C" fn c_tlf_string0_rust(
    tlio_in: *mut TlInState,
    buf: *mut c_char,
    max_len: c_int,
) -> c_int {
    mtproxy_ffi_tl_fetch_string0(tlio_in, buf, max_len)
}

#[export_name = "tlf_check_str_end_rust"]
pub unsafe extern "C" fn c_tlf_check_str_end_rust(tlio_in: *mut TlInState, size: c_int) -> c_int {
    mtproxy_ffi_tl_fetch_check_str_end(tlio_in, size)
}

#[export_name = "tlf_unread_rust"]
pub unsafe extern "C" fn c_tlf_unread_rust(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_unread(tlio_in)
}

#[export_name = "tlf_skip_rust"]
pub unsafe extern "C" fn c_tlf_skip_rust(tlio_in: *mut TlInState, len: c_int) -> c_int {
    mtproxy_ffi_tl_fetch_skip(tlio_in, len)
}

#[export_name = "tlf_end_rust"]
pub unsafe extern "C" fn c_tlf_end_rust(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_end(tlio_in)
}

#[export_name = "tlf_error_rust"]
pub unsafe extern "C" fn c_tlf_error_rust(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_error(tlio_in)
}

#[export_name = "tlf_int_range_rust"]
pub unsafe extern "C" fn c_tlf_int_range_rust(
    tlio_in: *mut TlInState,
    min: c_int,
    max: c_int,
) -> c_int {
    mtproxy_ffi_tl_fetch_int_range(tlio_in, min, max)
}

#[export_name = "tlf_positive_int_rust"]
pub unsafe extern "C" fn c_tlf_positive_int_rust(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_positive_int(tlio_in)
}

#[export_name = "tlf_nonnegative_int_rust"]
pub unsafe extern "C" fn c_tlf_nonnegative_int_rust(tlio_in: *mut TlInState) -> c_int {
    mtproxy_ffi_tl_fetch_nonnegative_int(tlio_in)
}

#[export_name = "tlf_int_subset_rust"]
pub unsafe extern "C" fn c_tlf_int_subset_rust(tlio_in: *mut TlInState, set: c_int) -> c_int {
    mtproxy_ffi_tl_fetch_int_subset(tlio_in, set)
}

#[export_name = "tlf_long_range_rust"]
pub unsafe extern "C" fn c_tlf_long_range_rust(
    tlio_in: *mut TlInState,
    min: i64,
    max: i64,
) -> i64 {
    mtproxy_ffi_tl_fetch_long_range(tlio_in, min, max)
}

#[export_name = "tlf_positive_long_rust"]
pub unsafe extern "C" fn c_tlf_positive_long_rust(tlio_in: *mut TlInState) -> i64 {
    mtproxy_ffi_tl_fetch_positive_long(tlio_in)
}

#[export_name = "tlf_nonnegative_long_rust"]
pub unsafe extern "C" fn c_tlf_nonnegative_long_rust(tlio_in: *mut TlInState) -> i64 {
    mtproxy_ffi_tl_fetch_nonnegative_long(tlio_in)
}

#[export_name = "tlf_raw_message_rust"]
pub unsafe extern "C" fn c_tlf_raw_message_rust(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    mtproxy_ffi_tl_fetch_raw_message(tlio_in, raw, bytes)
}

#[export_name = "tlf_lookup_raw_message_rust"]
pub unsafe extern "C" fn c_tlf_lookup_raw_message_rust(
    tlio_in: *mut TlInState,
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    mtproxy_ffi_tl_fetch_lookup_raw_message(tlio_in, raw, bytes)
}

#[export_name = "tls_get_ptr_rust"]
pub unsafe extern "C" fn c_tls_get_ptr_rust(tlio_out: *mut TlOutState, size: c_int) -> *mut c_void {
    mtproxy_ffi_tl_store_get_ptr(tlio_out, size)
}

#[export_name = "tls_get_prepend_ptr_rust"]
pub unsafe extern "C" fn c_tls_get_prepend_ptr_rust(
    tlio_out: *mut TlOutState,
    size: c_int,
) -> *mut c_void {
    mtproxy_ffi_tl_store_get_prepend_ptr(tlio_out, size)
}

#[export_name = "tls_int_rust"]
pub unsafe extern "C" fn c_tls_int_rust(tlio_out: *mut TlOutState, value: c_int) -> c_int {
    mtproxy_ffi_tl_store_int(tlio_out, value)
}

#[export_name = "tls_long_rust"]
pub unsafe extern "C" fn c_tls_long_rust(tlio_out: *mut TlOutState, value: i64) -> c_int {
    mtproxy_ffi_tl_store_long(tlio_out, value)
}

#[export_name = "tls_double_rust"]
pub unsafe extern "C" fn c_tls_double_rust(tlio_out: *mut TlOutState, value: f64) -> c_int {
    mtproxy_ffi_tl_store_double(tlio_out, value)
}

#[export_name = "tls_string_len_rust"]
pub unsafe extern "C" fn c_tls_string_len_rust(tlio_out: *mut TlOutState, len: c_int) -> c_int {
    mtproxy_ffi_tl_store_string_len(tlio_out, len)
}

#[export_name = "tls_raw_data_rust"]
pub unsafe extern "C" fn c_tls_raw_data_rust(
    tlio_out: *mut TlOutState,
    data: *const c_void,
    len: c_int,
) -> c_int {
    mtproxy_ffi_tl_store_raw_data(tlio_out, data, len)
}

#[export_name = "tls_raw_msg_rust"]
pub unsafe extern "C" fn c_tls_raw_msg_rust(
    tlio_out: *mut TlOutState,
    raw: *mut RawMessage,
    dup: c_int,
) -> c_int {
    mtproxy_ffi_tl_store_raw_msg(tlio_out, raw, dup)
}

#[export_name = "tls_pad_rust"]
pub unsafe extern "C" fn c_tls_pad_rust(tlio_out: *mut TlOutState) -> c_int {
    mtproxy_ffi_tl_store_pad(tlio_out)
}

#[export_name = "tls_string_data_rust"]
pub unsafe extern "C" fn c_tls_string_data_rust(
    tlio_out: *mut TlOutState,
    s: *const c_char,
    len: c_int,
) -> c_int {
    mtproxy_ffi_tl_store_string_data(tlio_out, s, len)
}

#[export_name = "tls_string_rust"]
pub unsafe extern "C" fn c_tls_string_rust(
    tlio_out: *mut TlOutState,
    s: *const c_char,
    len: c_int,
) -> c_int {
    mtproxy_ffi_tl_store_string(tlio_out, s, len)
}

#[export_name = "tls_clear_rust"]
pub unsafe extern "C" fn c_tls_clear_rust(tlio_out: *mut TlOutState) -> c_int {
    mtproxy_ffi_tl_store_clear(tlio_out)
}

#[export_name = "tls_clean_rust"]
pub unsafe extern "C" fn c_tls_clean_rust(tlio_out: *mut TlOutState) -> c_int {
    mtproxy_ffi_tl_store_clean(tlio_out)
}

#[export_name = "tls_pos_rust"]
pub unsafe extern "C" fn c_tls_pos_rust(tlio_out: *mut TlOutState) -> c_int {
    mtproxy_ffi_tl_store_pos(tlio_out)
}

#[export_name = "tl_copy_through_rust"]
pub unsafe extern "C" fn c_tl_copy_through_rust(
    tlio_in: *mut TlInState,
    tlio_out: *mut TlOutState,
    len: c_int,
    advance: c_int,
) -> c_int {
    mtproxy_ffi_tl_copy_through(tlio_in, tlio_out, len, advance)
}

#[export_name = "__tl_fetch_init"]
pub unsafe extern "C" fn c_tl_fetch_init_legacy(
    tlio_in: *mut TlInState,
    in_ptr: *mut c_void,
    _in_extra: *mut c_void,
    type_: c_int,
    methods: *const TlInMethods,
    size: c_int,
) -> c_int {
    mtproxy_ffi_tl_fetch_init(tlio_in, in_ptr, type_, methods, size)
}

#[export_name = "tlf_init_raw_message"]
pub unsafe extern "C" fn c_tlf_init_raw_message(
    tlio_in: *mut TlInState,
    msg: *mut RawMessage,
    size: c_int,
    dup: c_int,
) -> c_int {
    mtproxy_ffi_tl_init_raw_message(tlio_in, msg, size, dup)
}

#[export_name = "tlf_init_str"]
pub unsafe extern "C" fn c_tlf_init_str(
    tlio_in: *mut TlInState,
    s: *const c_char,
    size: c_int,
) -> c_int {
    mtproxy_ffi_tl_init_str(tlio_in, s, size)
}

#[export_name = "tls_init_raw_msg"]
pub unsafe extern "C" fn c_tls_init_raw_msg(
    tlio_out: *mut TlOutState,
    pid: *const MtproxyProcessId,
    qid: i64,
) -> c_int {
    mtproxy_ffi_tl_init_raw_msg(tlio_out, pid, qid)
}

#[export_name = "tls_init_tcp_raw_msg"]
pub unsafe extern "C" fn c_tls_init_tcp_raw_msg(
    tlio_out: *mut TlOutState,
    _c_tag_int: c_int,
    c: *mut c_void,
    qid: i64,
) -> c_int {
    let mut remote_pid = MtproxyProcessId::default();
    let pid_ptr = if !c.is_null()
        && unsafe {
            mtproxy_ffi_net_tcp_rpc_common_copy_remote_pid(c, &raw mut remote_pid)
        } == 0
    {
        &raw const remote_pid
    } else {
        core::ptr::null()
    };
    mtproxy_ffi_tl_init_tcp_raw_msg(tlio_out, pid_ptr, c, qid, 0)
}

#[export_name = "tls_init_tcp_raw_msg_unaligned"]
pub unsafe extern "C" fn c_tls_init_tcp_raw_msg_unaligned(
    tlio_out: *mut TlOutState,
    _c_tag_int: c_int,
    c: *mut c_void,
    qid: i64,
) -> c_int {
    let mut remote_pid = MtproxyProcessId::default();
    let pid_ptr = if !c.is_null()
        && unsafe {
            mtproxy_ffi_net_tcp_rpc_common_copy_remote_pid(c, &raw mut remote_pid)
        } == 0
    {
        &raw const remote_pid
    } else {
        core::ptr::null()
    };
    mtproxy_ffi_tl_init_tcp_raw_msg(tlio_out, pid_ptr, c, qid, 1)
}

#[export_name = "tls_init"]
pub unsafe extern "C" fn c_tls_init(
    tlio_out: *mut TlOutState,
    type_: c_int,
    pid: *mut MtproxyProcessId,
    qid: i64,
) -> c_int {
    match type_ {
        TL_TYPE_RAW_MSG => {
            c_tls_init_raw_msg(tlio_out, pid.cast_const(), qid);
            1
        }
        TL_TYPE_TCP_RAW_MSG => {
            let d = unsafe { mtproxy_ffi_rpc_target_choose_connection_by_pid(pid) };
            if d.is_null() {
                -1
            } else {
                c_tls_init_tcp_raw_msg(tlio_out, 1, d, qid);
                1
            }
        }
        TL_TYPE_NONE => -1,
        _ => 0,
    }
}

#[export_name = "tls_init_str"]
pub unsafe extern "C" fn c_tls_init_str(
    tlio_out: *mut TlOutState,
    s: *mut c_char,
    qid: i64,
    size: c_int,
) -> c_int {
    mtproxy_ffi_tl_init_str_out(tlio_out, s, qid, size)
}

#[export_name = "tls_init_raw_msg_nosend"]
pub unsafe extern "C" fn c_tls_init_raw_msg_nosend(tlio_out: *mut TlOutState) -> c_int {
    mtproxy_ffi_tl_init_raw_msg_nosend(tlio_out)
}

#[export_name = "tls_header"]
pub unsafe extern "C" fn c_tls_header(
    tlio_out: *mut TlOutState,
    header: *const TlQueryHeader,
) -> c_int {
    mtproxy_ffi_tl_store_header(tlio_out, header)
}

#[export_name = "tlf_query_header"]
pub unsafe extern "C" fn c_tlf_query_header(
    tlio_in: *mut TlInState,
    header: *mut TlQueryHeader,
) -> c_int {
    let rc = mtproxy_ffi_tl_query_header_parse(tlio_in, header);
    if rc <= 0 {
        return -1;
    }
    mtproxy_ffi_tl_parse_note_query_received();
    rc
}

#[export_name = "tlf_query_answer_header"]
pub unsafe extern "C" fn c_tlf_query_answer_header(
    tlio_in: *mut TlInState,
    header: *mut TlQueryHeader,
) -> c_int {
    let rc = mtproxy_ffi_tl_query_answer_header_parse(tlio_in, header);
    if rc <= 0 {
        return -1;
    }
    if tl_abi::mtproxy_ffi_tl_query_answer_is_error(header) != 0 {
        mtproxy_ffi_tl_parse_note_answer_error();
    } else {
        mtproxy_ffi_tl_parse_note_answer_received();
    }
    rc
}

#[export_name = "tls_end_ext"]
pub unsafe extern "C" fn c_tls_end_ext(tlio_out: *mut TlOutState, op: c_int) -> c_int {
    let mut sent_kind = 0;
    let rc = mtproxy_ffi_tl_store_end_ext(tlio_out, op, &raw mut sent_kind);
    if rc < 0 {
        return rc;
    }
    mtproxy_ffi_tl_parse_note_sent_kind(sent_kind);
    0
}

#[export_name = "tl_in_state_alloc"]
pub unsafe extern "C" fn c_tl_in_state_alloc() -> *mut TlInState {
    mtproxy_ffi_tl_parse_note_tl_in_alloc_delta(1);
    tl_abi::mtproxy_ffi_tl_in_state_alloc_zeroed()
}

#[export_name = "tl_in_state_free"]
pub unsafe extern "C" fn c_tl_in_state_free(tlio_in: *mut TlInState) {
    if tlio_in.is_null() {
        return;
    }
    mtproxy_ffi_tl_parse_note_tl_in_alloc_delta(-1);
    tl_abi::mtproxy_ffi_tl_in_state_free_legacy(tlio_in);
}

#[export_name = "tl_out_state_alloc"]
pub unsafe extern "C" fn c_tl_out_state_alloc() -> *mut TlOutState {
    mtproxy_ffi_tl_parse_note_tl_out_alloc_delta(1);
    tl_abi::mtproxy_ffi_tl_out_state_alloc_zeroed()
}

#[export_name = "tl_out_state_free"]
pub unsafe extern "C" fn c_tl_out_state_free(tlio_out: *mut TlOutState) {
    if tlio_out.is_null() {
        return;
    }
    mtproxy_ffi_tl_parse_note_tl_out_alloc_delta(-1);
    tl_abi::mtproxy_ffi_tl_out_state_free_legacy(tlio_out);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_tl_parse_note_query_received() {
    TL_RPC_QUERIES_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_tl_parse_note_answer_error() {
    TL_RPC_ANSWERS_ERROR.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_tl_parse_note_answer_received() {
    TL_RPC_ANSWERS_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_tl_parse_note_sent_kind(sent_kind: c_int) {
    match sent_kind {
        1 => {
            TL_RPC_SENT_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
        2 => {
            TL_RPC_SENT_ANSWERS.fetch_add(1, Ordering::Relaxed);
        }
        3 => {
            TL_RPC_SENT_QUERIES.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_tl_parse_note_tl_in_alloc_delta(delta: c_int) {
    TL_IN_ALLOCATED.fetch_add(delta, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_tl_parse_note_tl_out_alloc_delta(delta: c_int) {
    TL_OUT_ALLOCATED.fetch_add(delta, Ordering::Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_parse_prepare_stat(
    sb: *mut TlParseStatsBuffer,
) -> c_int {
    if sb.is_null() {
        return -1;
    }

    let rpc_queries_received = TL_RPC_QUERIES_RECEIVED.load(Ordering::Relaxed);
    let rpc_answers_error = TL_RPC_ANSWERS_ERROR.load(Ordering::Relaxed);
    let rpc_answers_received = TL_RPC_ANSWERS_RECEIVED.load(Ordering::Relaxed);
    let rpc_sent_errors = TL_RPC_SENT_ERRORS.load(Ordering::Relaxed);
    let rpc_sent_answers = TL_RPC_SENT_ANSWERS.load(Ordering::Relaxed);
    let rpc_sent_queries = TL_RPC_SENT_QUERIES.load(Ordering::Relaxed);
    let tl_in_allocated = TL_IN_ALLOCATED.load(Ordering::Relaxed);
    let tl_out_allocated = TL_OUT_ALLOCATED.load(Ordering::Relaxed);

    let now = libc::time(ptr::null_mut()) as i64;
    let uptime = (now - i64::from(unsafe { start_time })) as f64;
    let default_rpc_flags = unsafe { tcp_get_default_rpc_flags() };
    let rpc_qps = safe_div(rpc_queries_received as f64, uptime);

    let formatted = format!(
        "rpc_queries_received\t{rpc_queries_received}\n\
rpc_answers_error\t{rpc_answers_error}\n\
rpc_answers_received\t{rpc_answers_received}\n\
rpc_sent_errors\t{rpc_sent_errors}\n\
rpc_sent_answers\t{rpc_sent_answers}\n\
rpc_sent_queries\t{rpc_sent_queries}\n\
tl_in_allocated\t{tl_in_allocated}\n\
tl_out_allocated\t{tl_out_allocated}\n\
rpc_qps\t{rpc_qps:.6}\n\
default_rpc_flags\t{default_rpc_flags}\n"
    );
    unsafe { append_to_sb(sb, &formatted) };
    unsafe { (*sb).pos }
}
