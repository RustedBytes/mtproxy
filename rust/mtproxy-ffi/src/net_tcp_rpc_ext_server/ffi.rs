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

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_proxy_pass_parse_execute(
    c: ConnectionJob,
) -> c_int {
    unsafe { tcp_proxy_pass_parse_execute_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_proxy_pass_close(
    c: ConnectionJob,
    who: c_int,
) -> c_int {
    unsafe { tcp_proxy_pass_close_impl(c, who) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_proxy_pass_write_packet(
    c: ConnectionJob,
    raw: *mut RawMessage,
) -> c_int {
    unsafe { tcp_proxy_pass_write_packet_impl(c, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_init_proxy_domains(
    domains: *mut *mut DomainInfo,
    buckets: c_int,
) {
    unsafe { tcp_rpc_init_proxy_domains_impl(domains, buckets) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_init_proxy_domains_state() {
    unsafe { tcp_rpc_init_proxy_domains_state_impl() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_proxy_connection(
    c: ConnectionJob,
    info: *const DomainInfo,
) -> c_int {
    unsafe { proxy_connection_impl(c, info) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_set_ext_secret(secret: *const u8) {
    unsafe { tcp_rpcs_set_ext_secret_impl(secret) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_add_proxy_domain(
    domain: *const c_char,
) {
    unsafe { tcp_rpc_add_proxy_domain_state_impl(domain) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_lookup_domain_info(
    domain: *const u8,
    len: c_int,
) -> *const DomainInfo {
    unsafe { lookup_domain_info_state_impl(domain, len) }
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_default_domain_info() -> *const DomainInfo {
    default_domain_info_state_impl()
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_allow_only_tls() -> c_int {
    allow_only_tls_state_impl()
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_ext_secret_count() -> c_int {
    ext_secret_count_state_impl()
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_ext_secret_at(index: c_int) -> *const u8 {
    ext_secret_at_state_impl(index)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_domain_server_hello_encrypted_size(
    info: *const DomainInfo,
) -> c_int {
    unsafe { domain_server_hello_encrypted_size_impl(info) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_ext_alarm(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcs_ext_alarm_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_have_client_random(
    random: *const u8,
) -> c_int {
    unsafe { have_client_random_state_impl(random) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_add_client_random(
    random: *const u8,
    now: c_int,
) {
    unsafe { add_client_random_state_impl(random, now) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_delete_old_client_randoms(now: c_int) {
    unsafe { delete_old_client_randoms_state_impl(now) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_server_is_allowed_timestamp(
    timestamp: c_int,
    now: c_int,
) -> c_int {
    unsafe { is_allowed_timestamp_state_impl(timestamp, now) }
}
