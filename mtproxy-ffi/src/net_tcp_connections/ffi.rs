//! FFI export surface for `net-tcp-connections` runtime.

use super::core::*;
use core::ffi::c_int;

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_connections_cpu_tcp_free_connection_buffers(
    c: ConnectionJob,
) -> c_int {
    unsafe { cpu_tcp_free_connection_buffers_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_connections_cpu_tcp_server_writer(
    c: ConnectionJob,
) -> c_int {
    unsafe { cpu_tcp_server_writer_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_connections_cpu_tcp_server_reader(
    c: ConnectionJob,
) -> c_int {
    unsafe { cpu_tcp_server_reader_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_encrypt_output(
    c: ConnectionJob,
) -> c_int {
    unsafe { cpu_tcp_aes_crypto_encrypt_output_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_decrypt_input(
    c: ConnectionJob,
) -> c_int {
    unsafe { cpu_tcp_aes_crypto_decrypt_input_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_needed_output_bytes(
    c: ConnectionJob,
) -> c_int {
    unsafe { cpu_tcp_aes_crypto_needed_output_bytes_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_encrypt_output(
    c: ConnectionJob,
) -> c_int {
    unsafe { cpu_tcp_aes_crypto_ctr128_encrypt_output_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_decrypt_input(
    c: ConnectionJob,
) -> c_int {
    unsafe { cpu_tcp_aes_crypto_ctr128_decrypt_input_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_needed_output_bytes(
    c: ConnectionJob,
) -> c_int {
    unsafe { cpu_tcp_aes_crypto_ctr128_needed_output_bytes_impl(c) }
}
