//! Legacy symbol glue for `net/net-tcp-rpc-server.c`.

use super::core::*;
use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

unsafe extern "C" {
    #[link_name = "fail_connection"]
    fn ffi_fail_connection(c: ConnectionJob, who: c_int);
    #[link_name = "cpu_server_close_connection"]
    fn ffi_cpu_server_close_connection(c: ConnectionJob, who: c_int) -> c_int;
    #[link_name = "job_incref"]
    fn ffi_job_incref(job: Job) -> Job;

    #[link_name = "notification_event_insert_tcp_conn_ready"]
    fn ffi_notification_event_insert_tcp_conn_ready(c: ConnectionJob);
    #[link_name = "notification_event_insert_tcp_conn_close"]
    fn ffi_notification_event_insert_tcp_conn_close(c: ConnectionJob);
    #[link_name = "notification_event_insert_tcp_conn_alarm"]
    fn ffi_notification_event_insert_tcp_conn_alarm(c: ConnectionJob);
    #[link_name = "notification_event_insert_tcp_conn_wakeup"]
    fn ffi_notification_event_insert_tcp_conn_wakeup(c: ConnectionJob);

    #[link_name = "rwm_fetch_data"]
    fn ffi_rwm_fetch_data(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    #[link_name = "rwm_skip_data"]
    fn ffi_rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int;
    #[link_name = "rwm_fetch_lookup"]
    fn ffi_rwm_fetch_lookup(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    #[link_name = "rwm_fetch_data_back"]
    fn ffi_rwm_fetch_data_back(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    #[link_name = "rwm_split_head"]
    fn ffi_rwm_split_head(head: *mut RawMessage, raw: *mut RawMessage, bytes: c_int) -> c_int;
    #[link_name = "rwm_dump"]
    fn ffi_rwm_dump(raw: *mut RawMessage) -> c_int;
    #[link_name = "rwm_free"]
    fn ffi_rwm_free(raw: *mut RawMessage) -> c_int;
    #[link_name = "rwm_custom_crc32"]
    fn ffi_rwm_custom_crc32(
        raw: *mut RawMessage,
        bytes: c_int,
        custom_crc32_partial: Crc32PartialFn,
    ) -> c_uint;
    #[link_name = "tcp_rpc_conn_send_data"]
    fn ffi_tcp_rpc_conn_send_data(c_tag_int: c_int, c: ConnectionJob, len: c_int, q: *mut c_void);
    #[link_name = "tcp_rpc_conn_send_data_im"]
    fn ffi_tcp_rpc_conn_send_data_im(
        c_tag_int: c_int,
        c: ConnectionJob,
        len: c_int,
        q: *mut c_void,
    );
    #[link_name = "tcp_rpc_conn_send_data_init"]
    fn ffi_tcp_rpc_conn_send_data_init(c: ConnectionJob, len: c_int, q: *mut c_void);

    #[link_name = "init_server_PID"]
    fn ffi_init_server_pid(ip: c_uint, port: c_int);
    #[link_name = "get_my_ipv4"]
    fn ffi_get_my_ipv4() -> c_uint;
    #[link_name = "matches_pid"]
    fn ffi_matches_pid(x: *mut ProcessId, y: *mut ProcessId) -> c_int;

    #[link_name = "tcp_get_default_rpc_flags"]
    fn ffi_tcp_get_default_rpc_flags() -> c_uint;
    #[link_name = "tcp_add_dh_accept"]
    fn ffi_tcp_add_dh_accept() -> c_int;

    #[link_name = "init_dh_params"]
    fn ffi_init_dh_params() -> c_int;
    #[link_name = "dh_second_round"]
    fn ffi_dh_second_round(g_ab: *mut u8, g_a: *mut u8, g_b: *const u8) -> c_int;
    #[link_name = "incr_active_dh_connections"]
    fn ffi_incr_active_dh_connections();

    #[link_name = "aes_generate_nonce"]
    fn ffi_aes_generate_nonce(res: *mut c_char) -> c_int;
    #[link_name = "aes_create_keys"]
    fn ffi_aes_create_keys(
        out: *mut AesKeyData,
        am_client: c_int,
        nonce_server: *const c_char,
        nonce_client: *const c_char,
        client_timestamp: c_int,
        server_ip: c_uint,
        server_port: u16,
        server_ipv6: *const u8,
        client_ip: c_uint,
        client_port: u16,
        client_ipv6: *const u8,
        key: *const AesSecret,
        temp_key: *const u8,
        temp_key_len: c_int,
    ) -> c_int;
    #[link_name = "aes_crypto_init"]
    fn ffi_aes_crypto_init(c: ConnectionJob, key_data: *mut c_void, key_data_len: c_int) -> c_int;

    #[link_name = "nat_translate_ip"]
    fn ffi_nat_translate_ip(local_ip: c_uint) -> c_uint;

    #[link_name = "crc32_partial"]
    fn ffi_crc32_partial(data: *const c_void, len: c_long, crc: c_uint) -> c_uint;
    #[link_name = "crc32c_partial"]
    fn ffi_crc32c_partial(data: *const c_void, len: c_long, crc: c_uint) -> c_uint;

    #[link_name = "main_secret"]
    static mut ffi_main_secret: AesSecret;
    #[link_name = "dh_params_select"]
    static mut ffi_dh_params_select: c_int;
    #[link_name = "PID"]
    static mut ffi_pid: ProcessId;
    #[link_name = "verbosity"]
    static mut ffi_verbosity: c_int;
}

#[inline]
pub(super) unsafe fn fail_connection(c: ConnectionJob, who: c_int) {
    unsafe { ffi_fail_connection(c, who) };
}

#[inline]
pub(super) unsafe fn cpu_server_close_connection(c: ConnectionJob, who: c_int) -> c_int {
    unsafe { ffi_cpu_server_close_connection(c, who) }
}

#[inline]
pub(super) unsafe fn job_incref(job: Job) -> Job {
    unsafe { ffi_job_incref(job) }
}

#[inline]
pub(super) unsafe fn notification_event_insert_tcp_conn_ready(c: ConnectionJob) {
    unsafe { ffi_notification_event_insert_tcp_conn_ready(c) };
}

#[inline]
pub(super) unsafe fn notification_event_insert_tcp_conn_close(c: ConnectionJob) {
    unsafe { ffi_notification_event_insert_tcp_conn_close(c) };
}

#[inline]
pub(super) unsafe fn notification_event_insert_tcp_conn_alarm(c: ConnectionJob) {
    unsafe { ffi_notification_event_insert_tcp_conn_alarm(c) };
}

#[inline]
pub(super) unsafe fn notification_event_insert_tcp_conn_wakeup(c: ConnectionJob) {
    unsafe { ffi_notification_event_insert_tcp_conn_wakeup(c) };
}

#[inline]
pub(super) unsafe fn rwm_fetch_data(
    raw: *mut RawMessage,
    data: *mut c_void,
    bytes: c_int,
) -> c_int {
    unsafe { ffi_rwm_fetch_data(raw, data, bytes) }
}

#[inline]
pub(super) unsafe fn rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int {
    unsafe { ffi_rwm_skip_data(raw, bytes) }
}

#[inline]
pub(super) unsafe fn rwm_fetch_lookup(
    raw: *mut RawMessage,
    data: *mut c_void,
    bytes: c_int,
) -> c_int {
    unsafe { ffi_rwm_fetch_lookup(raw, data, bytes) }
}

#[inline]
pub(super) unsafe fn rwm_fetch_data_back(
    raw: *mut RawMessage,
    data: *mut c_void,
    bytes: c_int,
) -> c_int {
    unsafe { ffi_rwm_fetch_data_back(raw, data, bytes) }
}

#[inline]
pub(super) unsafe fn rwm_split_head(
    head: *mut RawMessage,
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    unsafe { ffi_rwm_split_head(head, raw, bytes) }
}

#[inline]
pub(super) unsafe fn rwm_dump(raw: *mut RawMessage) -> c_int {
    unsafe { ffi_rwm_dump(raw) }
}

#[inline]
pub(super) unsafe fn rwm_free(raw: *mut RawMessage) -> c_int {
    unsafe { ffi_rwm_free(raw) }
}

#[inline]
pub(super) unsafe fn rwm_custom_crc32(
    raw: *mut RawMessage,
    bytes: c_int,
    custom_crc32_partial: Crc32PartialFn,
) -> c_uint {
    unsafe { ffi_rwm_custom_crc32(raw, bytes, custom_crc32_partial) }
}

#[inline]
pub(super) unsafe fn tcp_rpc_conn_send_data(
    c_tag_int: c_int,
    c: ConnectionJob,
    len: c_int,
    q: *mut c_void,
) {
    unsafe { ffi_tcp_rpc_conn_send_data(c_tag_int, c, len, q) };
}

#[inline]
pub(super) unsafe fn tcp_rpc_conn_send_data_im(
    c_tag_int: c_int,
    c: ConnectionJob,
    len: c_int,
    q: *mut c_void,
) {
    unsafe { ffi_tcp_rpc_conn_send_data_im(c_tag_int, c, len, q) };
}

#[inline]
pub(super) unsafe fn tcp_rpc_conn_send_data_init(c: ConnectionJob, len: c_int, q: *mut c_void) {
    unsafe { ffi_tcp_rpc_conn_send_data_init(c, len, q) };
}

#[inline]
pub(super) unsafe fn init_server_pid(ip: c_uint, port: c_int) {
    unsafe { ffi_init_server_pid(ip, port) };
}

#[inline]
pub(super) unsafe fn get_my_ipv4() -> c_uint {
    unsafe { ffi_get_my_ipv4() }
}

#[inline]
pub(super) unsafe fn matches_pid(x: *mut ProcessId, y: *mut ProcessId) -> c_int {
    unsafe { ffi_matches_pid(x, y) }
}

#[inline]
pub(super) unsafe fn tcp_get_default_rpc_flags() -> c_uint {
    unsafe { ffi_tcp_get_default_rpc_flags() }
}

#[inline]
pub(super) unsafe fn tcp_add_dh_accept() -> c_int {
    unsafe { ffi_tcp_add_dh_accept() }
}

#[inline]
pub(super) unsafe fn init_dh_params() -> c_int {
    unsafe { ffi_init_dh_params() }
}

#[inline]
pub(super) unsafe fn dh_second_round(g_ab: *mut u8, g_a: *mut u8, g_b: *const u8) -> c_int {
    unsafe { ffi_dh_second_round(g_ab, g_a, g_b) }
}

#[inline]
pub(super) unsafe fn incr_active_dh_connections() {
    unsafe { ffi_incr_active_dh_connections() };
}

#[inline]
pub(super) unsafe fn aes_generate_nonce(res: *mut c_char) -> c_int {
    unsafe { ffi_aes_generate_nonce(res) }
}

#[inline]
pub(super) unsafe fn aes_create_keys(
    out: *mut AesKeyData,
    am_client: c_int,
    nonce_server: *const c_char,
    nonce_client: *const c_char,
    client_timestamp: c_int,
    server_ip: c_uint,
    server_port: u16,
    server_ipv6: *const u8,
    client_ip: c_uint,
    client_port: u16,
    client_ipv6: *const u8,
    key: *const AesSecret,
    temp_key: *const u8,
    temp_key_len: c_int,
) -> c_int {
    unsafe {
        ffi_aes_create_keys(
            out,
            am_client,
            nonce_server,
            nonce_client,
            client_timestamp,
            server_ip,
            server_port,
            server_ipv6,
            client_ip,
            client_port,
            client_ipv6,
            key,
            temp_key,
            temp_key_len,
        )
    }
}

#[inline]
pub(super) unsafe extern "C" fn aes_crypto_init(
    c: ConnectionJob,
    key_data: *mut c_void,
    key_data_len: c_int,
) -> c_int {
    unsafe { ffi_aes_crypto_init(c, key_data, key_data_len) }
}

#[inline]
pub(super) unsafe fn nat_translate_ip(local_ip: c_uint) -> c_uint {
    unsafe { ffi_nat_translate_ip(local_ip) }
}

#[inline]
pub(super) unsafe extern "C" fn crc32_partial(
    data: *const c_void,
    len: c_long,
    crc: c_uint,
) -> c_uint {
    unsafe { ffi_crc32_partial(data, len, crc) }
}

#[inline]
pub(super) unsafe extern "C" fn crc32c_partial(
    data: *const c_void,
    len: c_long,
    crc: c_uint,
) -> c_uint {
    unsafe { ffi_crc32c_partial(data, len, crc) }
}

#[inline]
pub(super) unsafe fn main_secret_ptr() -> *mut AesSecret {
    &raw mut ffi_main_secret
}

#[inline]
pub(super) unsafe fn dh_params_select_get() -> c_int {
    unsafe { ffi_dh_params_select }
}

#[inline]
pub(super) unsafe fn pid_get() -> ProcessId {
    unsafe { ffi_pid }
}

#[inline]
pub(super) unsafe fn pid_ptr() -> *mut ProcessId {
    &raw mut ffi_pid
}

#[inline]
pub(super) unsafe fn verbosity_get() -> c_int {
    unsafe { ffi_verbosity }
}
