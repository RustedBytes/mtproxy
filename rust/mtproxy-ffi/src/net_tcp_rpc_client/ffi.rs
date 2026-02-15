//! FFI export surface for `net-tcp-rpc-client` runtime.

use super::core::*;
use core::ffi::{c_char, c_int};

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_client_parse_execute(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcc_parse_execute_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_client_connected(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcc_connected_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_client_close_connection(
    c: ConnectionJob,
    who: c_int,
) -> c_int {
    unsafe { tcp_rpcc_close_connection_impl(c, who) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_client_check_ready(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpc_client_check_ready_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_client_default_check_ready(
    c: ConnectionJob,
) -> c_int {
    unsafe { tcp_rpcc_default_check_ready_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_client_init_outbound(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcc_init_outbound_impl(c) }
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_rpc_client_force_enable_dh() {
    tcp_force_enable_dh_impl();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_client_default_check_perm(
    c: ConnectionJob,
) -> c_int {
    unsafe { tcp_rpcc_default_check_perm_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_client_init_crypto(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcc_init_crypto_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_client_start_crypto(
    c: ConnectionJob,
    nonce: *mut c_char,
    key_select: c_int,
    temp_key: *mut u8,
    temp_key_len: c_int,
) -> c_int {
    unsafe { tcp_rpcc_start_crypto_impl(c, nonce, key_select, temp_key, temp_key_len) }
}
