//! FFI export surface for selected `net-tcp-rpc-common` runtime functions.

use super::core::*;
use core::ffi::c_int;

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_conn_send_init(
    c: ConnectionJob,
    raw: *mut RawMessage,
    flags: c_int,
) {
    unsafe { tcp_rpc_conn_send_init_impl(c, raw, flags) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_conn_send_im(
    c_tag_int: c_int,
    c: ConnectionJob,
    raw: *mut RawMessage,
    flags: c_int,
) {
    unsafe { tcp_rpc_conn_send_im_impl(c_tag_int, c, raw, flags) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_conn_send(
    c_tag_int: c_int,
    c: ConnectionJob,
    raw: *mut RawMessage,
    flags: c_int,
) {
    unsafe { tcp_rpc_conn_send_impl(c_tag_int, c, raw, flags) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_conn_send_data(
    c_tag_int: c_int,
    c: ConnectionJob,
    len: c_int,
    data: *mut core::ffi::c_void,
) {
    unsafe { tcp_rpc_conn_send_data_impl(c_tag_int, c, len, data) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_conn_send_data_init(
    c: ConnectionJob,
    len: c_int,
    data: *mut core::ffi::c_void,
) {
    unsafe { tcp_rpc_conn_send_data_init_impl(c, len, data) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_conn_send_data_im(
    c_tag_int: c_int,
    c: ConnectionJob,
    len: c_int,
    data: *mut core::ffi::c_void,
) {
    unsafe { tcp_rpc_conn_send_data_im_impl(c_tag_int, c, len, data) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_default_execute(
    c: ConnectionJob,
    op: c_int,
    raw: *mut RawMessage,
) -> c_int {
    unsafe { tcp_rpc_default_execute_impl(c, op, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_write_packet(
    c: ConnectionJob,
    raw: *mut RawMessage,
) -> c_int {
    unsafe { tcp_rpc_write_packet_impl(c, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_write_packet_compact(
    c: ConnectionJob,
    raw: *mut RawMessage,
) -> c_int {
    unsafe { tcp_rpc_write_packet_compact_impl(c, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_send_ping(c: ConnectionJob, ping_id: i64) {
    unsafe { tcp_rpc_send_ping_impl(c, ping_id) }
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_rpc_common_set_default_rpc_flags(
    and_flags: u32,
    or_flags: u32,
) -> u32 {
    tcp_set_default_rpc_flags_impl(and_flags, or_flags)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_common_copy_remote_pid(
    c: ConnectionJob,
    out_pid: *mut ProcessId,
) -> c_int {
    unsafe { copy_remote_pid_impl(c, out_pid) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_conn_send(
    c_tag_int: c_int,
    c: ConnectionJob,
    raw: *mut RawMessage,
    flags: c_int,
) {
    unsafe { tcp_rpc_conn_send_impl(c_tag_int, c, raw, flags) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_conn_send_data(
    c_tag_int: c_int,
    c: ConnectionJob,
    len: c_int,
    data: *mut core::ffi::c_void,
) {
    unsafe { tcp_rpc_conn_send_data_impl(c_tag_int, c, len, data) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_conn_send_data_init(
    c: ConnectionJob,
    len: c_int,
    data: *mut core::ffi::c_void,
) {
    unsafe { tcp_rpc_conn_send_data_init_impl(c, len, data) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_conn_send_data_im(
    c_tag_int: c_int,
    c: ConnectionJob,
    len: c_int,
    data: *mut core::ffi::c_void,
) {
    unsafe { tcp_rpc_conn_send_data_im_impl(c_tag_int, c, len, data) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_default_execute(
    c: ConnectionJob,
    op: c_int,
    raw: *mut RawMessage,
) -> c_int {
    unsafe { tcp_rpc_default_execute_impl(c, op, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_write_packet(c: ConnectionJob, raw: *mut RawMessage) -> c_int {
    unsafe { tcp_rpc_write_packet_impl(c, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_write_packet_compact(
    c: ConnectionJob,
    raw: *mut RawMessage,
) -> c_int {
    unsafe { tcp_rpc_write_packet_compact_impl(c, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_flush(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpc_flush_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_flush_packet(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpc_flush_packet_impl(c) }
}

#[no_mangle]
pub extern "C" fn tcp_set_default_rpc_flags(and_flags: u32, or_flags: u32) -> u32 {
    tcp_set_default_rpc_flags_impl(and_flags, or_flags)
}

#[no_mangle]
pub extern "C" fn tcp_get_default_rpc_flags() -> u32 {
    tcp_get_default_rpc_flags_impl()
}

#[no_mangle]
pub extern "C" fn tcp_set_max_dh_accept_rate(rate: c_int) {
    tcp_set_max_dh_accept_rate_impl(rate)
}

#[no_mangle]
pub unsafe extern "C" fn tcp_add_dh_accept() -> c_int {
    unsafe { tcp_add_dh_accept_impl() }
}
