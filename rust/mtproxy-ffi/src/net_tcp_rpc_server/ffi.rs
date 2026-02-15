//! FFI export surface for `net-tcp-rpc-server` runtime.

use super::core::*;
use core::ffi::c_int;

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_server_default_execute(
    c: ConnectionJob,
    op: c_int,
    raw: *mut RawMessage,
) -> c_int {
    unsafe { tcp_rpcs_default_execute_impl(c, op, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_server_parse_execute(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcs_parse_execute_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_server_wakeup(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcs_wakeup_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_server_alarm(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcs_alarm_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_server_do_wakeup(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcs_do_wakeup_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_server_init_accepted(
    c: ConnectionJob,
) -> c_int {
    unsafe { tcp_rpcs_init_accepted_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_server_close_connection(
    c: ConnectionJob,
    who: c_int,
) -> c_int {
    unsafe { tcp_rpcs_close_connection_impl(c, who) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_server_init_accepted_nohs(
    c: ConnectionJob,
) -> c_int {
    unsafe { tcp_rpcs_init_accepted_nohs_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_server_default_check_perm(
    c: ConnectionJob,
) -> c_int {
    unsafe { tcp_rpcs_default_check_perm_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_server_init_crypto(
    c: ConnectionJob,
    packet: *mut TcpRpcNoncePacket,
) -> c_int {
    unsafe { tcp_rpcs_init_crypto_impl(c, packet) }
}
