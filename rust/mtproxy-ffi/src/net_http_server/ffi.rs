//! FFI export surface for `net-http-server` runtime.

use super::core::*;
use core::ffi::{c_char, c_int};

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_default_execute(
    c: ConnectionJob,
    raw: *mut RawMessage,
    op: c_int,
) -> c_int {
    unsafe { hts_default_execute_impl(c, raw, op) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_init_accepted(c: ConnectionJob) -> c_int {
    unsafe { hts_init_accepted_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_close_connection(
    c: ConnectionJob,
    who: c_int,
) -> c_int {
    unsafe { hts_close_connection_impl(c, who) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_write_http_error_raw(
    c: ConnectionJob,
    raw: *mut RawMessage,
    code: c_int,
) -> c_int {
    unsafe { write_http_error_raw_impl(c, raw, code) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_write_http_error(
    c: ConnectionJob,
    code: c_int,
) -> c_int {
    unsafe { write_http_error_impl(c, code) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_write_packet(
    c: ConnectionJob,
    raw: *mut RawMessage,
) -> c_int {
    unsafe { hts_write_packet_impl(c, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_parse_execute(c: ConnectionJob) -> c_int {
    unsafe { hts_parse_execute_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_std_wakeup(c: ConnectionJob) -> c_int {
    unsafe { hts_std_wakeup_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_std_alarm(c: ConnectionJob) -> c_int {
    unsafe { hts_std_alarm_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_do_wakeup(c: ConnectionJob) -> c_int {
    unsafe { hts_do_wakeup_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_gen_http_date(
    date_buffer: *mut c_char,
    time: c_int,
) {
    unsafe { gen_http_date_impl(date_buffer, time) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_cur_http_date() -> *mut c_char {
    unsafe { cur_http_date_impl() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_get_http_header(
    q_headers: *const c_char,
    q_headers_len: c_int,
    buffer: *mut c_char,
    b_len: c_int,
    arg_name: *const c_char,
    arg_len: c_int,
) -> c_int {
    unsafe { get_http_header_impl(q_headers, q_headers_len, buffer, b_len, arg_name, arg_len) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_write_basic_http_header_raw(
    c: ConnectionJob,
    raw: *mut RawMessage,
    code: c_int,
    date: c_int,
    len: c_int,
    add_header: *const c_char,
    content_type: *const c_char,
) -> c_int {
    unsafe { write_basic_http_header_raw_impl(c, raw, code, date, len, add_header, content_type) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_http_flush(
    c: ConnectionJob,
    raw: *mut RawMessage,
) {
    unsafe { http_flush_impl(c, raw) }
}
