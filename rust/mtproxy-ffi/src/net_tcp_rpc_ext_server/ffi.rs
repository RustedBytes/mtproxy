//! FFI export surface for selected `net-tcp-rpc-ext-server` functions.

use super::core::*;
use core::ffi::{c_char, c_int};

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_create_request(
    domain: *const c_char,
) -> *mut u8 {
    unsafe { create_request_impl(domain) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_check_response(
    response: *const u8,
    len: c_int,
    request_session_id: *const u8,
    is_reversed_extension_order: *mut c_int,
    encrypted_application_data_length: *mut c_int,
) -> c_int {
    unsafe {
        check_response_impl(
            response,
            len,
            request_session_id,
            is_reversed_extension_order,
            encrypted_application_data_length,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_update_domain_info(
    info: *mut DomainInfo,
) -> c_int {
    unsafe { update_domain_info_impl(info) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_get_sni_domain_info(
    request: *const u8,
    len: c_int,
) -> *const DomainInfo {
    unsafe { get_sni_domain_info_impl(request, len) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_compact_parse_execute(
    c: ConnectionJob,
) -> c_int {
    unsafe { tcp_rpcs_compact_parse_execute_impl(c) }
}
