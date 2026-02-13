use super::abi as tl_abi;
use crate::MtproxyProcessId;
use core::ffi::{c_int, c_void};

pub use tl_abi::{RawMessage, TlInMethods, TlInState, TlOutMethods, TlOutState, TlQueryHeader};

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
