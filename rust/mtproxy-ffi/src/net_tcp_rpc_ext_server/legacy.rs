//! Legacy symbol glue for `net/net-tcp-rpc-ext-server.c`.

use super::core::*;
use core::ffi::{c_char, c_double, c_int, c_uint, c_void};
use core::mem::align_of;
use core::ptr;

type Job = ConnectionJob;

const CONN_FUNC_MAGIC: c_int = 0x11ef_55aa_u32 as c_int;
const C_RAWMSG: c_int = 0x40000;
const JOB_REF_TAG: c_int = 1;
const EXT_ALARM_TIMEOUT_SEC: c_double = 10.0;

#[repr(C)]
struct AsyncJob {
    j_flags: c_int,
    j_status: c_int,
    j_sigclass: c_int,
    j_refcnt: c_int,
    j_error: c_int,
    j_children: c_int,
    j_align: c_int,
    j_custom_bytes: c_int,
    j_type: c_uint,
    j_subclass: c_int,
    j_thread: *mut c_void,
    j_execute: *mut c_void,
    j_parent: Job,
    j_custom: [i64; 0],
}

#[allow(clashing_extern_declarations)]
unsafe extern "C" {
    fn unlock_job(job_tag_int: c_int, job: Job) -> c_int;
    fn job_decref(job_tag_int: c_int, job: Job);
    fn job_timer_insert(job: Job, timeout: c_double);

    fn server_failed(c: ConnectionJob) -> c_int;
    fn server_noop(c: ConnectionJob) -> c_int;
    fn tcp_rpcs_wakeup(c: ConnectionJob) -> c_int;
    fn tcp_rpcs_close_connection(c: ConnectionJob, who: c_int) -> c_int;
    fn tcp_rpcs_init_accepted_nohs(c: ConnectionJob) -> c_int;
    fn tcp_rpc_flush(c: ConnectionJob) -> c_int;
    fn tcp_rpc_write_packet_compact(c: ConnectionJob, raw: *mut RawMessage) -> c_int;

    fn aes_crypto_ctr128_init(c: ConnectionJob, key_data: *mut c_void, key_data_len: c_int)
        -> c_int;
    fn aes_crypto_free(c: ConnectionJob) -> c_int;
    fn mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_encrypt_output(
        c: ConnectionJob,
    ) -> c_int;
    fn mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_decrypt_input(
        c: ConnectionJob,
    ) -> c_int;
    fn mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_needed_output_bytes(
        c: ConnectionJob,
    ) -> c_int;

    fn mtproxy_ffi_net_connections_precise_now() -> c_double;
    fn mtproxy_ffi_precise_time_get_now() -> c_int;
    fn show_ip(ip: u32) -> *const c_char;
    fn show_ipv6(ipv6: *const u8) -> *const c_char;
}

#[inline]
unsafe fn job_custom_ptr<T>(job: Job) -> *mut T {
    ptr::addr_of_mut!((*job.cast::<AsyncJob>()).j_custom).cast::<T>()
}

#[inline]
unsafe fn conn_info_ptr(c: ConnectionJob) -> *mut ConnectionInfo {
    let conn = unsafe { job_custom_ptr::<ConnectionInfo>(c) };
    assert!(!conn.is_null());
    conn
}

#[inline]
unsafe fn rpc_data_ptr(c: ConnectionJob) -> *mut TcpRpcData {
    let conn = unsafe { conn_info_ptr(c) };
    let base = unsafe { (*conn).custom_data.as_ptr() as usize };
    let align = align_of::<TcpRpcData>();
    let aligned = (base + align - 1) & !(align - 1);
    let data = aligned as *mut TcpRpcData;
    assert!(!data.is_null());
    data
}

#[inline]
unsafe fn rpc_funcs_ptr(c: ConnectionJob) -> *mut TcpRpcServerFunctions {
    let conn = unsafe { conn_info_ptr(c) };
    let funcs = unsafe { (*conn).extra.cast::<TcpRpcServerFunctions>() };
    assert!(!funcs.is_null());
    funcs
}

#[inline]
unsafe fn show_ip46(ip: u32, ipv6: *const u8) -> *const c_char {
    if ip != 0 {
        unsafe { show_ip(ip) }
    } else {
        unsafe { show_ipv6(ipv6) }
    }
}

#[inline]
unsafe fn now_value() -> c_int {
    unsafe { mtproxy_ffi_precise_time_get_now() }
}

unsafe extern "C" fn tcp_rpcs_compact_parse_execute(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcs_compact_parse_execute_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_proxy_pass_parse_execute(c: ConnectionJob) -> c_int {
    unsafe { tcp_proxy_pass_parse_execute_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_proxy_pass_close(c: ConnectionJob, who: c_int) -> c_int {
    unsafe { tcp_proxy_pass_close_impl(c, who) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_proxy_pass_write_packet(c: ConnectionJob, raw: *mut RawMessage) -> c_int {
    unsafe { tcp_proxy_pass_write_packet_impl(c, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpcs_ext_alarm(c: ConnectionJob) -> c_int {
    unsafe { tcp_rpcs_ext_alarm_impl(c) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpcs_ext_init_accepted(c: ConnectionJob) -> c_int {
    unsafe {
        job_timer_insert(c, mtproxy_ffi_net_connections_precise_now() + EXT_ALARM_TIMEOUT_SEC);
        tcp_rpcs_init_accepted_nohs(c)
    }
}

#[no_mangle]
pub static mut ct_tcp_rpc_ext_server: ConnFunctions = ConnFunctions {
    magic: CONN_FUNC_MAGIC,
    flags: C_RAWMSG,
    title: b"rpc_ext_server\0".as_ptr().cast::<c_char>().cast_mut(),
    accept: None,
    init_accepted: Some(tcp_rpcs_ext_init_accepted),
    reader: None,
    writer: None,
    close: Some(tcp_rpcs_close_connection),
    parse_execute: Some(tcp_rpcs_compact_parse_execute),
    init_outbound: None,
    connected: Some(server_failed),
    check_ready: None,
    wakeup_aio: None,
    write_packet: Some(tcp_rpc_write_packet_compact),
    flush: Some(tcp_rpc_flush),
    free: None,
    free_buffers: None,
    read_write: None,
    wakeup: Some(tcp_rpcs_wakeup),
    alarm: Some(tcp_rpcs_ext_alarm),
    socket_read_write: None,
    socket_reader: None,
    socket_writer: None,
    socket_connected: None,
    socket_free: None,
    socket_close: None,
    data_received: None,
    data_sent: None,
    ready_to_write: None,
    crypto_init: Some(aes_crypto_ctr128_init),
    crypto_free: Some(aes_crypto_free),
    crypto_encrypt_output: Some(mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_encrypt_output),
    crypto_decrypt_input: Some(mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_decrypt_input),
    crypto_needed_output_bytes: Some(
        mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
    ),
};

#[no_mangle]
pub static mut ct_proxy_pass: ConnFunctions = ConnFunctions {
    magic: CONN_FUNC_MAGIC,
    flags: C_RAWMSG,
    title: b"proxypass\0".as_ptr().cast::<c_char>().cast_mut(),
    accept: None,
    init_accepted: Some(server_failed),
    reader: None,
    writer: None,
    close: Some(tcp_proxy_pass_close),
    parse_execute: Some(tcp_proxy_pass_parse_execute),
    init_outbound: None,
    connected: Some(server_noop),
    check_ready: None,
    wakeup_aio: None,
    write_packet: Some(tcp_proxy_pass_write_packet),
    flush: None,
    free: None,
    free_buffers: None,
    read_write: None,
    wakeup: None,
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
    crypto_init: None,
    crypto_free: None,
    crypto_encrypt_output: None,
    crypto_decrypt_input: None,
    crypto_needed_output_bytes: None,
};

#[no_mangle]
pub unsafe extern "C" fn tcp_rpcs_set_ext_secret(secret: *mut u8) {
    unsafe { tcp_rpcs_set_ext_secret_impl(secret.cast_const()) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_add_proxy_domain(domain: *const c_char) {
    unsafe { tcp_rpc_add_proxy_domain_state_impl(domain) }
}

#[no_mangle]
pub unsafe extern "C" fn tcp_rpc_init_proxy_domains() {
    unsafe { tcp_rpc_init_proxy_domains_state_impl() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_conn_info(c: ConnectionJob) -> *mut ConnectionInfo {
    unsafe { conn_info_ptr(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_data(c: ConnectionJob) -> *mut TcpRpcData {
    unsafe { rpc_data_ptr(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_funcs(c: ConnectionJob) -> *mut TcpRpcServerFunctions {
    unsafe { rpc_funcs_ptr(c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_job_decref(c: ConnectionJob) {
    unsafe { job_decref(JOB_REF_TAG, c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_unlock_job(c: ConnectionJob) -> c_int {
    unsafe { unlock_job(JOB_REF_TAG, c) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_show_our_ip(c: ConnectionJob) -> *const c_char {
    let conn = unsafe { conn_info_ptr(c) };
    unsafe { show_ip46((*conn).our_ip, (*conn).our_ipv6.as_ptr()) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(c: ConnectionJob) -> *const c_char {
    let conn = unsafe { conn_info_ptr(c) };
    unsafe { show_ip46((*conn).remote_ip, (*conn).remote_ipv6.as_ptr()) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_lookup_domain_info(
    domain: *const u8,
    len: c_int,
) -> *const DomainInfo {
    unsafe { lookup_domain_info_state_impl(domain, len) }
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_default_domain_info() -> *const DomainInfo {
    default_domain_info_state_impl()
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_ext_secret_at(index: c_int) -> *const u8 {
    ext_secret_at_state_impl(index)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_have_client_random(random: *const u8) -> c_int {
    unsafe { have_client_random_state_impl(random) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_add_client_random(random: *const u8) {
    unsafe { add_client_random_state_impl(random, now_value()) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_delete_old_client_randoms() {
    unsafe { delete_old_client_randoms_state_impl(now_value()) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_is_allowed_timestamp_state(timestamp: c_int) -> c_int {
    unsafe { is_allowed_timestamp_state_impl(timestamp, now_value()) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_proxy_connection(
    c: ConnectionJob,
    info: *const DomainInfo,
) -> c_int {
    unsafe { proxy_connection_impl(c, info) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_domain_server_hello_encrypted_size(
    info: *const DomainInfo,
) -> c_int {
    unsafe { domain_server_hello_encrypted_size_impl(info) }
}
