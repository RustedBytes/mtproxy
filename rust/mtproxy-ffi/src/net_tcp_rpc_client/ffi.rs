//! FFI export surface for `net-tcp-rpc-client` runtime.

use super::core::*;
use core::ffi::{c_char, c_int, c_void};

const CONN_FUNC_MAGIC: c_int = 0x11ef55aa_u32 as c_int;
const C_RAWMSG: c_int = 0x40000;

type ConnLifecycleFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type ConnCloseFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnWakeupAioFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnPacketFn = Option<unsafe extern "C" fn(ConnectionJob, *mut RawMessage) -> c_int>;
type ConnCryptoInitFn = Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, c_int) -> c_int>;

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
    pub wakeup_aio: ConnWakeupAioFn,
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
    pub data_received: ConnWakeupAioFn,
    pub data_sent: ConnWakeupAioFn,
    pub ready_to_write: ConnLifecycleFn,
    pub crypto_init: ConnCryptoInitFn,
    pub crypto_free: ConnLifecycleFn,
    pub crypto_encrypt_output: ConnLifecycleFn,
    pub crypto_decrypt_input: ConnLifecycleFn,
    pub crypto_needed_output_bytes: ConnLifecycleFn,
}

unsafe extern "C" {
    fn server_failed(c: ConnectionJob) -> c_int;
    fn server_noop(c: ConnectionJob) -> c_int;
    fn tcp_rpc_flush(c: ConnectionJob) -> c_int;
    fn tcp_rpc_write_packet(c: ConnectionJob, raw: *mut RawMessage) -> c_int;
    fn tcp_rpc_default_execute(c: ConnectionJob, op: c_int, raw: *mut RawMessage) -> c_int;
    fn tcp_rpc_flush_packet(c: ConnectionJob) -> c_int;
    fn aes_crypto_init(c: ConnectionJob, key_data: *mut c_void, key_data_len: c_int) -> c_int;
    fn aes_crypto_free(c: ConnectionJob) -> c_int;
    #[link_name = "mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_encrypt_output"]
    fn cpu_tcp_aes_crypto_encrypt_output(c: ConnectionJob) -> c_int;
    #[link_name = "mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_decrypt_input"]
    fn cpu_tcp_aes_crypto_decrypt_input(c: ConnectionJob) -> c_int;
    #[link_name = "mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_needed_output_bytes"]
    fn cpu_tcp_aes_crypto_needed_output_bytes(c: ConnectionJob) -> c_int;
}

#[no_mangle]
pub static mut ct_tcp_rpc_client: ConnType = ConnType {
    magic: CONN_FUNC_MAGIC,
    flags: C_RAWMSG,
    title: b"rpc_client\0".as_ptr().cast_mut().cast(),
    accept: Some(server_failed),
    init_accepted: Some(server_failed),
    reader: None,
    writer: None,
    close: Some(mtproxy_ffi_net_tcp_rpc_client_close_connection),
    parse_execute: Some(mtproxy_ffi_net_tcp_rpc_client_parse_execute),
    init_outbound: Some(mtproxy_ffi_net_tcp_rpc_client_init_outbound),
    connected: Some(mtproxy_ffi_net_tcp_rpc_client_connected),
    check_ready: Some(mtproxy_ffi_net_tcp_rpc_client_check_ready),
    wakeup_aio: None,
    write_packet: Some(tcp_rpc_write_packet),
    flush: Some(tcp_rpc_flush),
    free: None,
    free_buffers: None,
    read_write: None,
    wakeup: Some(server_noop),
    alarm: None,
    socket_read_write: None,
    socket_reader: None,
    socket_writer: None,
    socket_connected: None,
    socket_free: None,
    socket_close: None,
    data_received: None,
    data_sent: None,
    ready_to_write: None,
    crypto_init: Some(aes_crypto_init),
    crypto_free: Some(aes_crypto_free),
    crypto_encrypt_output: Some(cpu_tcp_aes_crypto_encrypt_output),
    crypto_decrypt_input: Some(cpu_tcp_aes_crypto_decrypt_input),
    crypto_needed_output_bytes: Some(cpu_tcp_aes_crypto_needed_output_bytes),
};

#[no_mangle]
pub static mut default_tcp_rpc_client: TcpRpcClientFunctions = TcpRpcClientFunctions {
    info: core::ptr::null_mut(),
    rpc_extra: core::ptr::null_mut(),
    execute: Some(tcp_rpc_default_execute),
    check_ready: Some(mtproxy_ffi_net_tcp_rpc_client_default_check_ready),
    flush_packet: Some(tcp_rpc_flush_packet),
    rpc_check_perm: Some(mtproxy_ffi_net_tcp_rpc_client_default_check_perm),
    rpc_init_crypto: Some(mtproxy_ffi_net_tcp_rpc_client_init_crypto),
    rpc_start_crypto: Some(mtproxy_ffi_net_tcp_rpc_client_start_crypto),
    rpc_wakeup: None,
    rpc_alarm: None,
    rpc_ready: Some(server_noop),
    rpc_close: None,
    max_packet_len: 0,
    mode_flags: 0,
};

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

#[no_mangle]
pub unsafe extern "C" fn tcp_rpcc_default_check_ready(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcc_default_check_ready_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpcc_init_outbound(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcc_init_outbound_impl(c) }
}

#[no_mangle]
pub extern "C" fn tcp_force_enable_dh() {
    tcp_force_enable_dh_impl();
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpcc_default_check_perm(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcc_default_check_perm_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpcc_init_crypto(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcc_init_crypto_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpcc_start_crypto(
    c: ConnectionJob,
    nonce: *mut c_char,
    key_select: c_int,
    temp_key: *mut u8,
    temp_key_len: c_int,
) -> c_int {
    unsafe { tcp_rpcc_start_crypto_impl(c, nonce, key_select, temp_key, temp_key_len) }
}
