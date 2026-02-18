//! FFI export surface for mtproto runtime.

use super::core::*;
use crate::*;

/// Prints CLI usage/help for the Rust MTProxy entrypoint.
///
/// # Safety
/// `program_name` may be null; otherwise it must point to a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_proxy_usage(program_name: *const c_char) -> i32 {
    mtproto_proxy_usage_ffi(program_name)
}

/// Runs the Rust MTProxy entrypoint using C `argc`/`argv`.
///
/// # Safety
/// `argv` must point to `argc` valid NUL-terminated C strings when `argc > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_proxy_main(
    argc: i32,
    argv: *const *const c_char,
) -> i32 {
    mtproto_proxy_main_ffi(argc, argv)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_legacy_main(
    argc: c_int,
    argv: *mut *mut c_char,
) -> i32 {
    mtproto_legacy_main_ffi(argc, argv)
}

/// Clears runtime config snapshot and optionally destroys target objects.
///
/// # Safety
/// `mc` must point to a writable `struct mf_config` when non-null.
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn clear_config(mc: *mut MtproxyMfConfig, do_destroy_targets: c_int) {
    clear_config_ffi(mc, do_destroy_targets);
}

/// Resolves and returns auth cluster by `cluster_id`.
///
/// # Safety
/// `mc` must point to a valid `struct mf_config` when non-null.
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn mf_cluster_lookup(
    mc: *mut MtproxyMfConfig,
    cluster_id: c_int,
    force: c_int,
) -> *mut MtproxyMfCluster {
    mf_cluster_lookup_ffi(mc, cluster_id, force)
}

/// Resolves target hostname from parser cursor and stores it into `default_cfg_ct`.
///
/// # Safety
/// Uses global parser cursors from C runtime and mutates `default_cfg_ct`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_resolve_default_target_from_cfg_cur() -> c_int {
    mtproto_cfg_resolve_default_target_from_cfg_cur_ffi()
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_set_default_target_endpoint(
    port: u16,
    min_connections: i64,
    max_connections: i64,
    reconnect_timeout: c_double,
) {
    mtproto_cfg_set_default_target_endpoint_ffi(
        port,
        min_connections,
        max_connections,
        reconnect_timeout,
    );
}

/// Creates one target from `default_cfg_ct` and stores it into config slots.
///
/// # Safety
/// `mc` must point to writable `struct mf_config`; `target_index` must be in range.
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_create_target(
    mc: *mut MtproxyMfConfig,
    target_index: u32,
) {
    mtproto_cfg_create_target_ffi(mc, target_index);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_now_or_time() -> c_int {
    mtproto_cfg_now_or_time_ffi()
}

/// Parses dotted IPv4 text into host-order integer (`a<<24|b<<16|c<<8|d`).
///
/// # Safety
/// `str` must be a valid NUL-terminated C string, `out_ip` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_parse_text_ipv4(
    str: *const c_char,
    out_ip: *mut u32,
) -> i32 {
    mtproto_parse_text_ipv4_ffi(str, out_ip)
}

/// Parses textual IPv6 and writes 16-byte network-order output.
///
/// # Safety
/// `str` must be a valid NUL-terminated C string,
/// `out_ip`/`out_consumed` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_parse_text_ipv6(
    str: *const c_char,
    out_ip: *mut u8,
    out_consumed: *mut i32,
) -> i32 {
    mtproto_parse_text_ipv6_ffi(str, out_ip, out_consumed)
}

/// Classifies MTProto packet shape from fixed unencrypted header bytes.
///
/// # Safety
/// `header` must point to `header_len` readable bytes when `header_len > 0`,
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_inspect_packet_header(
    header: *const u8,
    header_len: usize,
    packet_len: i32,
    out: *mut MtproxyMtprotoPacketInspectResult,
) -> i32 {
    mtproto_inspect_packet_header_ffi(header, header_len, packet_len, out)
}

/// Parses RPC client packet TL envelope for `mtproto-proxy` dispatch.
///
/// # Safety
/// `data` must point to `len` readable bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_parse_client_packet(
    data: *const u8,
    len: usize,
    out: *mut MtproxyMtprotoClientPacketParseResult,
) -> i32 {
    mtproto_parse_client_packet_ffi(data, len, out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_process_client_packet(
    data: *const u8,
    len: usize,
    conn_fd: c_int,
    conn_gen: c_int,
    out: *mut MtproxyMtprotoClientPacketProcessResult,
) -> i32 {
    mtproto_process_client_packet_ffi(data, len, conn_fd, conn_gen, out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_process_client_packet_runtime(
    tlio_in: *mut c_void,
    c: *mut c_void,
) -> i32 {
    mtproto_process_client_packet_runtime_ffi(tlio_in, c)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_push_rpc_confirmation_runtime(
    c_tag_int: c_int,
    c: *mut c_void,
    confirm: c_int,
) {
    mtproto_push_rpc_confirmation_runtime_ffi(c_tag_int, c, confirm);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_parse_function_runtime(
    tlio_in: *mut c_void,
    actor_id: i64,
) -> *mut c_void {
    mtproto_mtfront_parse_function_runtime_ffi(tlio_in, actor_id)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_process_http_query(
    tlio_in: *mut c_void,
    hqj: *mut c_void,
) -> i32 {
    mtproto_process_http_query_ffi(tlio_in, hqj)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_http_query_job_run(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> i32 {
    mtproto_http_query_job_run_ffi(job, op, jt)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_callback_job_run(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> i32 {
    mtproto_callback_job_run_ffi(job, op, jt)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_client_packet_job_run(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> i32 {
    mtproto_client_packet_job_run_ffi(job, op, jt)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_client_send_message_runtime(
    c_tag_int: c_int,
    c: *mut c_void,
    in_conn_id: i64,
    tlio_in: *mut c_void,
    flags: c_int,
) -> i32 {
    mtproto_client_send_message_runtime_ffi(c_tag_int, c, in_conn_id, tlio_in, flags)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_add_stats(w: *mut c_void) {
    mtproto_add_stats_ffi(w);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_compute_stats_sum() {
    mtproto_compute_stats_sum_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_check_all_conn_buffers() {
    mtproto_check_all_conn_buffers_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_check_conn_buffers_runtime(c: *mut c_void) -> i32 {
    mtproto_check_conn_buffers_runtime_ffi(c)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_update_local_stats_copy(s: *mut c_void) {
    mtproto_update_local_stats_copy_ffi(s);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_precise_cron() {
    mtproto_precise_cron_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_on_child_termination_handler() {
    mtproto_on_child_termination_handler_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_data_received(
    c: *mut c_void,
    bytes_received: c_int,
) -> i32 {
    mtproto_data_received_ffi(c, bytes_received)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_data_sent(c: *mut c_void, bytes_sent: c_int) -> i32 {
    mtproto_data_sent_ffi(c, bytes_sent)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_prepare_stats(sb: *mut c_void) {
    mtproto_mtfront_prepare_stats_ffi(sb);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_hts_stats_execute(
    c: *mut c_void,
    msg: *mut c_void,
    op: c_int,
) -> i32 {
    mtproto_hts_stats_execute_ffi(c, msg, op)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_hts_execute(
    c: *mut c_void,
    msg: *mut c_void,
    op: c_int,
) -> i32 {
    mtproto_hts_execute_ffi(c, msg, op)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_rpcc_execute(
    c: *mut c_void,
    op: c_int,
    msg: *mut c_void,
) -> i32 {
    mtproto_rpcc_execute_ffi(c, op, msg)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_client_ready(c: *mut c_void) -> i32 {
    mtproto_mtfront_client_ready_ffi(c)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_rpcs_execute(
    c: *mut c_void,
    op: c_int,
    msg: *mut c_void,
) -> i32 {
    mtproto_ext_rpcs_execute_ffi(c, op, msg)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_client_close(
    c: *mut c_void,
    who: c_int,
) -> i32 {
    mtproto_mtfront_client_close_ffi(c, who)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_do_close_in_ext_conn(
    data: *mut c_void,
    s_len: c_int,
) -> i32 {
    mtproto_do_close_in_ext_conn_ffi(data, s_len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_rpc_ready(c: *mut c_void) -> i32 {
    mtproto_ext_rpc_ready_ffi(c)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_rpc_close(c: *mut c_void, who: c_int) -> i32 {
    mtproto_ext_rpc_close_ffi(c, who)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_proxy_rpc_ready(c: *mut c_void) -> i32 {
    mtproto_proxy_rpc_ready_ffi(c)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_proxy_rpc_close(c: *mut c_void, who: c_int) -> i32 {
    mtproto_proxy_rpc_close_ffi(c, who)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_do_rpcs_execute(
    data: *mut c_void,
    s_len: c_int,
) -> i32 {
    mtproto_do_rpcs_execute_ffi(data, s_len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_finish_postponed_http_response(
    data: *mut c_void,
    len: c_int,
) -> i32 {
    mtproto_finish_postponed_http_response_ffi(data, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_http_alarm(c: *mut c_void) -> i32 {
    mtproto_http_alarm_ffi(c)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_http_close(c: *mut c_void, who: c_int) -> i32 {
    mtproto_http_close_ffi(c, who)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_f_parse_option(val: c_int) -> i32 {
    mtproto_f_parse_option_ffi(val)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_prepare_parse_options() {
    mtproto_mtfront_prepare_parse_options_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_check_children_dead() {
    mtproto_check_children_dead_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_check_children_status() {
    mtproto_check_children_status_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_check_special_connections_overflow() {
    mtproto_check_special_connections_overflow_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_kill_children(signal: c_int) {
    mtproto_kill_children_ffi(signal);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cron() {
    mtproto_cron_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_usage() {
    mtproto_usage_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_parse_extra_args(
    argc: c_int,
    argv: *mut *mut c_char,
) {
    mtproto_mtfront_parse_extra_args_ffi(argc, argv);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_sigusr1_handler() {
    mtproto_mtfront_sigusr1_handler_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_on_exit() {
    mtproto_mtfront_on_exit_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_pre_init() {
    mtproto_mtfront_pre_init_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_pre_start() {
    mtproto_mtfront_pre_start_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_mtfront_pre_loop() {
    mtproto_mtfront_pre_loop_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_reset() {
    mtproto_ext_conn_reset_ffi();
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_create(
    in_fd: c_int,
    in_gen: c_int,
    in_conn_id: i64,
    out_fd: c_int,
    out_gen: c_int,
    auth_key_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    mtproto_ext_conn_create_ffi(in_fd, in_gen, in_conn_id, out_fd, out_gen, auth_key_id, out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_get_by_in_fd(
    in_fd: c_int,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    mtproto_ext_conn_get_by_in_fd_ffi(in_fd, out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_get_by_out_conn_id(
    out_conn_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    mtproto_ext_conn_get_by_out_conn_id_ffi(out_conn_id, out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_update_auth_key(
    in_fd: c_int,
    in_conn_id: i64,
    auth_key_id: i64,
) -> i32 {
    mtproto_ext_conn_update_auth_key_ffi(in_fd, in_conn_id, auth_key_id)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_remove_by_out_conn_id(
    out_conn_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    mtproto_ext_conn_remove_by_out_conn_id_ffi(out_conn_id, out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_remove_by_in_conn_id(
    in_fd: c_int,
    in_conn_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    mtproto_ext_conn_remove_by_in_conn_id_ffi(in_fd, in_conn_id, out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_remove_any_by_out_fd(
    out_fd: c_int,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    mtproto_ext_conn_remove_any_by_out_fd_ffi(out_fd, out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_remove_any_by_in_fd(
    in_fd: c_int,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    mtproto_ext_conn_remove_any_by_in_fd_ffi(in_fd, out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_lru_insert(
    in_fd: c_int,
    in_gen: c_int,
) -> i32 {
    mtproto_ext_conn_lru_insert_ffi(in_fd, in_gen)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_lru_delete(in_fd: c_int) -> i32 {
    mtproto_ext_conn_lru_delete_ffi(in_fd)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_lru_pop_oldest(
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    mtproto_ext_conn_lru_pop_oldest_ffi(out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_ext_conn_counts(
    out_current: *mut i64,
    out_created: *mut i64,
) -> i32 {
    mtproto_ext_conn_counts_ffi(out_current, out_created)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_notify_ext_connection_runtime(
    ex: *const MtproxyMtprotoExtConnection,
    send_notifications: c_int,
) {
    mtproto_notify_ext_connection_runtime_ffi(ex, send_notifications);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_remove_ext_connection_runtime(
    ex: *const MtproxyMtprotoExtConnection,
    send_notifications: c_int,
) {
    mtproto_remove_ext_connection_runtime_ffi(ex, send_notifications);
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_build_rpc_proxy_req(
    flags: c_int,
    out_conn_id: i64,
    remote_ipv6: *const u8,
    remote_port: c_int,
    our_ipv6: *const u8,
    our_port: c_int,
    proxy_tag_ptr: *const u8,
    proxy_tag_len: usize,
    http_origin: *const u8,
    http_origin_len: usize,
    http_referer: *const u8,
    http_referer_len: usize,
    http_user_agent: *const u8,
    http_user_agent_len: usize,
    payload: *const u8,
    payload_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    mtproto_build_rpc_proxy_req_ffi(
        flags,
        out_conn_id,
        remote_ipv6,
        remote_port,
        our_ipv6,
        our_port,
        proxy_tag_ptr,
        proxy_tag_len,
        http_origin,
        http_origin_len,
        http_referer,
        http_referer_len,
        http_user_agent,
        http_user_agent_len,
        payload,
        payload_len,
        out_buf,
        out_cap,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_build_http_ok_header(
    keep_alive: c_int,
    extra_headers: c_int,
    content_len: c_int,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    mtproto_build_http_ok_header_ffi(
        keep_alive,
        extra_headers,
        content_len,
        out_buf,
        out_cap,
        out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_client_send_non_http_wrap(
    tlio_in: *mut c_void,
    tlio_out: *mut c_void,
) -> i32 {
    mtproto_client_send_non_http_wrap_ffi(tlio_in, tlio_out)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_http_send_message(
    c: *mut c_void,
    tlio_in: *mut c_void,
    flags: c_int,
) -> i32 {
    mtproto_http_send_message_ffi(c, tlio_in, flags)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_forward_tcp_query(
    tlio_in: *mut c_void,
    c: *mut c_void,
    target: *mut c_void,
    flags: c_int,
    auth_key_id: i64,
    remote_ip_port: *const c_int,
    our_ip_port: *const c_int,
) -> i32 {
    mtproto_forward_tcp_query_ffi(
        tlio_in,
        c,
        target,
        flags,
        auth_key_id,
        remote_ip_port,
        our_ip_port,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_forward_mtproto_packet(
    tlio_in: *mut c_void,
    c: *mut c_void,
    len: c_int,
    remote_ip_port: *const c_int,
    rpc_flags: c_int,
) -> i32 {
    mtproto_forward_mtproto_packet_ffi(tlio_in, c, len, remote_ip_port, rpc_flags)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_choose_proxy_target(target_dc: c_int) -> *mut c_void {
    mtproto_choose_proxy_target_ffi(target_dc)
}

/// Parses mtfront function envelope from unread TL bytes.
///
/// # Safety
/// `data` must point to `len` readable bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_parse_function(
    data: *const u8,
    len: usize,
    actor_id: i64,
    out: *mut MtproxyMtprotoParseFunctionResult,
) -> i32 {
    mtproto_parse_function_ffi(data, len, actor_id, out)
}

/// Returns scalar config state initialized by `preinit_config()`.
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_preinit(
    default_min_connections: i64,
    default_max_connections: i64,
    out: *mut MtproxyMtprotoCfgPreinitResult,
) -> i32 {
    mtproto_cfg_preinit_ffi(default_min_connections, default_max_connections, out)
}

/// Decides cluster-apply action for `proxy` / `proxy_for` directives.
///
/// # Safety
/// `cluster_ids` must be readable for `clusters_len` entries when `clusters_len > 0`;
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
    cluster_ids: *const i32,
    clusters_len: u32,
    cluster_id: i32,
    max_clusters: u32,
    out: *mut MtproxyMtprotoCfgClusterApplyDecisionResult,
) -> i32 {
    mtproto_cfg_decide_cluster_apply_ffi(cluster_ids, clusters_len, cluster_id, max_clusters, out)
}

/// Parses one extended lexer token from `mtproto-config`.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_getlex_ext(
    cur: *const c_char,
    len: usize,
    out: *mut MtproxyMtprotoCfgGetlexExtResult,
) -> i32 {
    mtproto_cfg_getlex_ext_ffi(cur, len, out)
}

/// Parses one directive token and scalar argument from `mtproto-config`.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_scan_directive_token(
    cur: *const c_char,
    len: usize,
    min_connections: i64,
    max_connections: i64,
    out: *mut MtproxyMtprotoCfgDirectiveTokenResult,
) -> i32 {
    mtproto_cfg_scan_directive_token_ffi(cur, len, min_connections, max_connections, out)
}

/// Parses one directive step from `mtproto-config` control flow.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`;
/// `cluster_ids` must be readable for `clusters_len` entries when `clusters_len > 0`;
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_parse_directive_step(
    cur: *const c_char,
    len: usize,
    min_connections: i64,
    max_connections: i64,
    cluster_ids: *const i32,
    clusters_len: u32,
    max_clusters: u32,
    out: *mut MtproxyMtprotoCfgDirectiveStepResult,
) -> i32 {
    mtproto_cfg_parse_directive_step_ffi(
        cur,
        len,
        min_connections,
        max_connections,
        cluster_ids,
        clusters_len,
        max_clusters,
        out,
    )
}

/// Parses proxy target payload (`host:port;`) and computes cluster/apply mutation.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`;
/// `cluster_ids` must be readable for `clusters_len` entries when `clusters_len > 0`;
/// `last_cluster_state` must be readable when `has_last_cluster_state != 0`;
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
    cur: *const c_char,
    len: usize,
    current_targets: u32,
    max_targets: u32,
    min_connections: i64,
    max_connections: i64,
    cluster_ids: *const i32,
    clusters_len: u32,
    target_dc: i32,
    max_clusters: u32,
    create_targets: i32,
    current_auth_tot_clusters: u32,
    last_cluster_state: *const MtproxyMtprotoOldClusterState,
    has_last_cluster_state: i32,
    out: *mut MtproxyMtprotoCfgParseProxyTargetStepResult,
) -> i32 {
    mtproto_cfg_parse_proxy_target_step_ffi(
        cur,
        len,
        current_targets,
        max_targets,
        min_connections,
        max_connections,
        cluster_ids,
        clusters_len,
        target_dc,
        max_clusters,
        create_targets,
        current_auth_tot_clusters,
        last_cluster_state,
        has_last_cluster_state,
        out,
    )
}

/// Executes one full `parse_config()` directive pass and returns proxy side-effect plan.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`;
/// `actions` must be writable for `actions_capacity` entries when `actions_capacity > 0`;
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_parse_full_pass(
    cur: *const c_char,
    len: usize,
    default_min_connections: i64,
    default_max_connections: i64,
    create_targets: i32,
    max_clusters: u32,
    max_targets: u32,
    actions: *mut MtproxyMtprotoCfgProxyAction,
    actions_capacity: u32,
    out: *mut MtproxyMtprotoCfgParseFullResult,
) -> i32 {
    mtproto_cfg_parse_full_pass_ffi(
        cur,
        len,
        default_min_connections,
        default_max_connections,
        create_targets,
        max_clusters,
        max_targets,
        actions,
        actions_capacity,
        out,
    )
}

/// Parses a required trailing semicolon from `mtproto-config`.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`; `out_advance` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_expect_semicolon(
    cur: *const c_char,
    len: usize,
    out_advance: *mut usize,
) -> i32 {
    mtproto_cfg_expect_semicolon_ffi(cur, len, out_advance)
}

/// Looks up a cluster index by `cluster_id` mirroring `mf_cluster_lookup()`.
///
/// # Safety
/// `cluster_ids` must be readable for `clusters_len` entries when `clusters_len > 0`;
/// `out_cluster_index` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
    cluster_ids: *const i32,
    clusters_len: u32,
    cluster_id: i32,
    force: i32,
    default_cluster_index: i32,
    has_default_cluster_index: i32,
    out_cluster_index: *mut i32,
) -> i32 {
    mtproto_cfg_lookup_cluster_index_ffi(
        cluster_ids,
        clusters_len,
        cluster_id,
        force,
        default_cluster_index,
        has_default_cluster_index,
        out_cluster_index,
    )
}

/// Finalizes parse-loop invariants and resolves optional default-cluster index.
///
/// # Safety
/// `cluster_ids` must be readable for `clusters_len` entries when `clusters_len > 0`;
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_finalize(
    have_proxy: i32,
    cluster_ids: *const i32,
    clusters_len: u32,
    default_cluster_id: i32,
    out: *mut MtproxyMtprotoCfgFinalizeResult,
) -> i32 {
    mtproto_cfg_finalize_ffi(
        have_proxy,
        cluster_ids,
        clusters_len,
        default_cluster_id,
        out,
    )
}

/// Full `parse_config()` runtime path extracted from C implementation.
///
/// # Safety
/// `mc` must point to a writable `struct mf_config`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_parse_config(
    mc: *mut c_void,
    flags: i32,
    config_fd: i32,
) -> i32 {
    mtproto_cfg_parse_config_ffi(mc, flags, config_fd)
}

/// Full `do_reload_config()` runtime path extracted from C implementation.
///
/// # Safety
/// Uses and mutates process-global C runtime state (`CurConf`, `NextConf`, parser globals).
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_do_reload_config(flags: i32) -> i32 {
    mtproto_cfg_do_reload_config_ffi(flags)
}
