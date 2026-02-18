//! FFI export surface for `net-http-server` runtime.

use super::core::*;
use core::ffi::{c_char, c_int, c_void};

const CONN_FUNC_MAGIC: c_int = 0x11ef55aa_u32 as c_int;
const C_RAWMSG: c_int = 0x40000;

type ConnLifecycleFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type ConnCloseFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnPacketFn = Option<unsafe extern "C" fn(ConnectionJob, *mut RawMessage) -> c_int>;

#[repr(C)]
pub struct ConnType {
    pub magic: c_int,
    pub flags: c_int,
    pub title: *mut c_char,
    pub accept: ConnLifecycleFn,
    pub init_accepted: ConnLifecycleFn,
    pub reader: ConnLifecycleFn,
    pub writer: ConnLifecycleFn,
    pub close: ConnCloseFn,
    pub parse_execute: ConnLifecycleFn,
    pub init_outbound: ConnLifecycleFn,
    pub connected: ConnLifecycleFn,
    pub check_ready: ConnLifecycleFn,
    pub wakeup_aio: Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>,
    pub write_packet: ConnPacketFn,
    pub flush: ConnLifecycleFn,
    pub free: ConnLifecycleFn,
    pub free_buffers: ConnLifecycleFn,
    pub read_write: ConnLifecycleFn,
    pub wakeup: ConnLifecycleFn,
    pub alarm: ConnLifecycleFn,
    pub socket_read_write: ConnLifecycleFn,
    pub socket_reader: ConnLifecycleFn,
    pub socket_writer: ConnLifecycleFn,
    pub socket_connected: ConnLifecycleFn,
    pub socket_free: ConnLifecycleFn,
    pub socket_close: ConnLifecycleFn,
    pub data_received: Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>,
    pub data_sent: Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>,
    pub ready_to_write: ConnLifecycleFn,
    pub crypto_init: Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, c_int) -> c_int>,
    pub crypto_free: ConnLifecycleFn,
    pub crypto_encrypt_output: ConnLifecycleFn,
    pub crypto_decrypt_input: ConnLifecycleFn,
    pub crypto_needed_output_bytes: ConnLifecycleFn,
}

unsafe extern "C" {
    fn net_accept_new_connections(c: ConnectionJob) -> c_int;
    fn server_failed(c: ConnectionJob) -> c_int;
}

#[no_mangle]
pub static mut http_connections: c_int = 0;

#[no_mangle]
pub static mut http_queries: i64 = 0;

#[no_mangle]
pub static mut http_bad_headers: i64 = 0;

#[no_mangle]
pub static mut http_queries_size: i64 = 0;

static mut EMPTY_HTTP_RESPONSE_HEADERS: [u8; 1] = [0];

#[no_mangle]
pub static mut extra_http_response_headers: *mut c_char =
    core::ptr::addr_of_mut!(EMPTY_HTTP_RESPONSE_HEADERS).cast::<c_char>();

#[no_mangle]
pub static mut ct_http_server: ConnType = ConnType {
    magic: CONN_FUNC_MAGIC,
    flags: C_RAWMSG,
    title: b"http_server\0".as_ptr().cast_mut().cast(),
    accept: Some(net_accept_new_connections),
    init_accepted: Some(hts_init_accepted),
    reader: None,
    writer: None,
    close: Some(hts_close_connection),
    parse_execute: Some(hts_parse_execute),
    init_outbound: Some(server_failed),
    connected: Some(server_failed),
    check_ready: None,
    wakeup_aio: None,
    write_packet: Some(hts_write_packet),
    flush: None,
    free: None,
    free_buffers: None,
    read_write: None,
    wakeup: Some(hts_std_wakeup),
    alarm: Some(hts_std_alarm),
    socket_read_write: None,
    socket_reader: None,
    socket_writer: None,
    socket_connected: None,
    socket_free: None,
    socket_close: None,
    data_received: None,
    data_sent: None,
    ready_to_write: None,
    crypto_init: None,
    crypto_free: None,
    crypto_encrypt_output: None,
    crypto_decrypt_input: None,
    crypto_needed_output_bytes: None,
};

#[no_mangle]
pub static mut default_http_server: HttpServerFunctions = HttpServerFunctions {
    info: core::ptr::null_mut(),
    execute: Some(hts_default_execute),
    ht_wakeup: Some(hts_do_wakeup),
    ht_alarm: Some(hts_do_wakeup),
    ht_close: None,
};

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_default_execute(
    c: ConnectionJob,
    raw: *mut RawMessage,
    op: c_int,
) -> c_int {
    unsafe { hts_default_execute_impl(c, raw, op) }
}

#[no_mangle]
pub unsafe extern "C" fn hts_default_execute(
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
pub unsafe extern "C" fn hts_init_accepted(c: ConnectionJob) -> c_int {
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
pub unsafe extern "C" fn hts_close_connection(c: ConnectionJob, who: c_int) -> c_int {
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
pub unsafe extern "C" fn write_http_error(c: ConnectionJob, code: c_int) -> c_int {
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
pub unsafe extern "C" fn hts_write_packet(c: ConnectionJob, raw: *mut RawMessage) -> c_int {
    unsafe { hts_write_packet_impl(c, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_parse_execute(c: ConnectionJob) -> c_int {
    unsafe { hts_parse_execute_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn hts_parse_execute(c: ConnectionJob) -> c_int {
    unsafe { hts_parse_execute_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_std_wakeup(c: ConnectionJob) -> c_int {
    unsafe { hts_std_wakeup_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn hts_std_wakeup(c: ConnectionJob) -> c_int {
    unsafe { hts_std_wakeup_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_std_alarm(c: ConnectionJob) -> c_int {
    unsafe { hts_std_alarm_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn hts_std_alarm(c: ConnectionJob) -> c_int {
    unsafe { hts_std_alarm_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_hts_do_wakeup(c: ConnectionJob) -> c_int {
    unsafe { hts_do_wakeup_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn hts_do_wakeup(c: ConnectionJob) -> c_int {
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
pub unsafe extern "C" fn gen_http_date(date_buffer: *mut c_char, time: c_int) {
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
pub unsafe extern "C" fn get_http_header(
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
pub unsafe extern "C" fn write_basic_http_header_raw(
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
pub unsafe extern "C" fn mtproxy_ffi_net_http_server_http_flush(c: ConnectionJob, raw: *mut RawMessage) {
    unsafe { http_flush_impl(c, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn http_flush(c: ConnectionJob, raw: *mut RawMessage) {
    unsafe { http_flush_impl(c, raw) }
}
