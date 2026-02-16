//! FFI export surface for compatibility/runtime shims.

use super::core::*;
use crate::*;

/// Returns FFI API version to C callers.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_api_version() -> u32 {
    ffi_api_version()
}

/// Performs a minimal startup compatibility handshake.
///
/// Return codes:
/// - `0`: handshake accepted
/// - `-1`: incompatible API version
#[no_mangle]
pub extern "C" fn mtproxy_ffi_startup_handshake(expected_api_version: u32) -> i32 {
    startup_handshake_impl(expected_api_version)
}

/// Returns extracted Step 9 boundary contract for mp-queue/jobs migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyConcurrencyBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_concurrency_boundary(
    out: *mut MtproxyConcurrencyBoundary,
) -> i32 {
    unsafe { get_concurrency_boundary_ffi(out) }
}

/// Returns extracted Step 10 boundary contract for net-core migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyNetworkBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_network_boundary(out: *mut MtproxyNetworkBoundary) -> i32 {
    unsafe { get_network_boundary_ffi(out) }
}

/// Returns extracted Step 11 boundary contract for RPC/TCP migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyRpcBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_rpc_boundary(out: *mut MtproxyRpcBoundary) -> i32 {
    unsafe { get_rpc_boundary_ffi(out) }
}

/// Returns extracted Step 12 boundary contract for crypto integration migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyCryptoBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_crypto_boundary(out: *mut MtproxyCryptoBoundary) -> i32 {
    unsafe { get_crypto_boundary_ffi(out) }
}

/// Returns extracted Step 13 boundary contract for engine/mtproto app migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyApplicationBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_application_boundary(
    out: *mut MtproxyApplicationBoundary,
) -> i32 {
    unsafe { get_application_boundary_ffi(out) }
}

/// Converts net event flags into Linux epoll flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_epoll_conv_flags(flags: i32) -> i32 {
    net_epoll_conv_flags_impl(flags)
}

/// Reloads `/etc/hosts` into resolver cache and mirrors `kdb_load_hosts()`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_resolver_kdb_load_hosts() -> i32 {
    resolver_kdb_load_hosts_impl()
}

/// Returns current resolver cache load state (`kdb_hosts_loaded`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_resolver_kdb_hosts_loaded() -> i32 {
    resolver_kdb_hosts_loaded_impl()
}

/// Returns lookup plan for `kdb_gethostbyname()`.
///
/// # Safety
/// `name` must be a NUL-terminated C string. `out_kind` and `out_ipv4` must
/// be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_resolver_gethostbyname_plan(
    name: *const c_char,
    out_kind: *mut i32,
    out_ipv4: *mut u32,
) -> i32 {
    unsafe { resolver_gethostbyname_plan_ffi(name, out_kind, out_ipv4) }
}

/// Converts Linux epoll flags into net event flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_epoll_unconv_flags(epoll_flags: i32) -> i32 {
    net_epoll_unconv_flags_impl(epoll_flags)
}

/// Computes timeout in milliseconds until wakeup.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_timers_wait_msec(wakeup_time: f64, now: f64) -> i32 {
    net_timers_wait_msec_impl(wakeup_time, now)
}

/// Selects best key signature from main and extra key list.
///
/// # Safety
/// `extra_key_signatures` must point to `extra_num` readable `i32` values
/// when `extra_num > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_select_best_key_signature(
    main_secret_len: i32,
    main_key_signature: i32,
    key_signature: i32,
    extra_num: i32,
    extra_key_signatures: *const i32,
) -> i32 {
    unsafe {
        net_select_best_key_signature_ffi(
            main_secret_len,
            main_key_signature,
            key_signature,
            extra_num,
            extra_key_signatures,
        )
    }
}

/// Returns whether a connection is active (`C_CONNECTED && !C_READY_PENDING`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connection_is_active(flags: i32) -> i32 {
    net_connection_is_active_impl(flags)
}

/// Computes `compute_conn_events` result from connection flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_compute_conn_events(flags: i32, use_epollet: i32) -> i32 {
    net_compute_conn_events_impl(flags, use_epollet)
}

/// Adds one NAT rule from `--nat-info` payload (`<local-addr>:<global-addr>`).
///
/// # Safety
/// `rule_text` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_add_nat_info(rule_text: *const c_char) -> i32 {
    unsafe { net_add_nat_info_ffi(rule_text) }
}

/// Applies NAT translation for IPv4 host-order address.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_translate_ip(local_ip: u32) -> u32 {
    net_translate_ip_impl(local_ip)
}

/// Classifies first TL-string marker byte from `net-msg.c`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_msg_tl_marker_kind(marker: i32) -> i32 {
    net_msg_tl_marker_kind_impl(marker)
}

/// Computes TL-string padding bytes (`(-len) & 3`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_msg_tl_padding(total_bytes: i32) -> i32 {
    net_msg_tl_padding_impl(total_bytes)
}

/// Computes effective byte count for `rwm_encrypt_decrypt_to`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_msg_encrypt_decrypt_effective_bytes(
    requested_bytes: i32,
    total_bytes: i32,
    block_size: i32,
) -> i32 {
    net_msg_encrypt_decrypt_effective_bytes_impl(requested_bytes, total_bytes, block_size)
}

/// Computes net-stats recent idle percent helper.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_stats_recent_idle_percent(
    a_idle_time: c_double,
    a_idle_quotient: c_double,
) -> c_double {
    net_stats_recent_idle_percent_impl(a_idle_time, a_idle_quotient)
}

/// Computes net-stats average idle percent helper.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_stats_average_idle_percent(
    tot_idle_time: c_double,
    uptime: i32,
) -> c_double {
    net_stats_average_idle_percent_impl(tot_idle_time, uptime)
}

/// Returns AES-aligned byte count for `net-tcp-connections` block ciphers.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_aes_aligned_len(total_bytes: i32) -> i32 {
    net_tcp_aes_aligned_len_impl(total_bytes)
}

/// Returns pending AES block padding bytes for `net-tcp-connections`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_aes_needed_output_bytes(total_bytes: i32) -> i32 {
    net_tcp_aes_needed_output_bytes_impl(total_bytes)
}

/// Computes CTR encrypt chunk length (TLS-aware cap at 1425).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_tls_encrypt_chunk_len(total_bytes: i32, is_tls: i32) -> i32 {
    net_tcp_tls_encrypt_chunk_len_impl(total_bytes, is_tls)
}

/// Returns bytes still required to parse a TLS record header.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_tls_header_needed_bytes(available: i32) -> i32 {
    net_tcp_tls_header_needed_bytes_impl(available)
}

/// Parses TLS record header (`17 03 03 xx xx`) and outputs payload length.
///
/// # Safety
/// `header` must point to at least 5 readable bytes, `out_payload_len` writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_tls_parse_header(
    header: *const u8,
    out_payload_len: *mut i32,
) -> i32 {
    unsafe { net_tcp_tls_parse_header_ffi(header, out_payload_len) }
}

/// Clamps decrypt chunk length to remaining TLS payload bytes.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_tls_decrypt_chunk_len(
    available: i32,
    left_tls_packet_length: i32,
) -> i32 {
    net_tcp_tls_decrypt_chunk_len_impl(available, left_tls_packet_length)
}

/// Computes byte count to consume when `skip_bytes < 0`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_reader_negative_skip_take(
    skip_bytes: i32,
    available_bytes: i32,
) -> i32 {
    net_tcp_reader_negative_skip_take_impl(skip_bytes, available_bytes)
}

/// Computes next negative skip state after consuming bytes.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_reader_negative_skip_next(
    skip_bytes: i32,
    taken_bytes: i32,
) -> i32 {
    net_tcp_reader_negative_skip_next_impl(skip_bytes, taken_bytes)
}

/// Computes next positive skip state after receiving bytes.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_reader_positive_skip_next(
    skip_bytes: i32,
    available_bytes: i32,
) -> i32 {
    net_tcp_reader_positive_skip_next_impl(skip_bytes, available_bytes)
}

/// Converts `parse_execute` result into updated `skip_bytes` when required.
///
/// Returns:
/// - `1` when `out_skip_bytes` is written
/// - `0` when no update is needed (`res == 0 || res == need_more_bytes`)
/// - `-1` on invalid args
///
/// # Safety
/// `out_skip_bytes` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_reader_skip_from_parse_result(
    parse_res: i32,
    buffered_bytes: i32,
    need_more_bytes: i32,
    out_skip_bytes: *mut i32,
) -> i32 {
    unsafe {
        net_tcp_reader_skip_from_parse_result_ffi(
            parse_res,
            buffered_bytes,
            need_more_bytes,
            out_skip_bytes,
        )
    }
}

/// Classifies reader precheck outcome from connection flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_reader_precheck_result(flags: i32) -> i32 {
    net_tcp_reader_precheck_result_impl(flags)
}

/// Evaluates the main reader-loop continuation guard.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_tcp_reader_should_continue(
    skip_bytes: i32,
    flags: i32,
    status_is_conn_error: i32,
) -> i32 {
    net_tcp_reader_should_continue_impl(skip_bytes, flags, status_is_conn_error)
}

/// Computes proxy-domain hash bucket index (`mod 257`).
///
/// # Safety
/// `domain` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_domain_bucket_index(
    domain: *const u8,
    len: i32,
) -> i32 {
    unsafe { net_tcp_rpc_ext_domain_bucket_index_ffi(domain, len) }
}

/// Computes 16-byte client-random cache hash bucket index (`14` bits).
///
/// # Safety
/// `random` must point to at least `16` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_client_random_bucket_index(
    random: *const u8,
) -> i32 {
    unsafe { net_tcp_rpc_ext_client_random_bucket_index_ffi(random) }
}

/// Selects server-hello encrypted-size profile from probe stats.
///
/// # Safety
/// `out_size` and `out_profile` must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_select_server_hello_profile(
    min_len: i32,
    max_len: i32,
    sum_len: i32,
    sample_count: i32,
    out_size: *mut i32,
    out_profile: *mut i32,
) -> i32 {
    unsafe {
        net_tcp_rpc_ext_select_server_hello_profile_ffi(
            min_len,
            max_len,
            sum_len,
            sample_count,
            out_size,
            out_profile,
        )
    }
}

/// Runs one net-thread notification event via Rust dispatcher.
///
/// # Safety
/// All callback pointers must be valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_thread_run_notification_event(
    event_type: i32,
    who: *mut c_void,
    event: *mut c_void,
    rpc_ready: Option<NetThreadRpcReadyFn>,
    rpc_close: Option<NetThreadRpcFn>,
    rpc_alarm: Option<NetThreadRpcFn>,
    rpc_wakeup: Option<NetThreadRpcFn>,
    fail_connection: Option<NetThreadFailConnectionFn>,
    job_decref: Option<NetThreadRpcFn>,
    event_free: Option<NetThreadRpcFn>,
) -> i32 {
    unsafe {
        net_thread_run_notification_event_ffi(
            event_type,
            who,
            event,
            rpc_ready,
            rpc_close,
            rpc_alarm,
            rpc_wakeup,
            fail_connection,
            job_decref,
            event_free,
        )
    }
}

/// Returns HTTP status text and normalizes unknown status code to `500`.
///
/// # Safety
/// `code` must be a valid writable pointer to `i32`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_error_msg_text(code: *mut i32) -> *const c_char {
    unsafe { net_http_error_msg_text_ffi(code) }
}

/// Formats unix time as legacy HTTP date (`29` bytes, no trailing NUL required).
///
/// # Safety
/// `out` must be writable for at least `out_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_gen_date(
    out: *mut c_char,
    out_len: i32,
    time: i32,
) -> i32 {
    unsafe { net_http_gen_date_ffi(out, out_len, time) }
}

/// Parses legacy HTTP date into unix time.
///
/// # Safety
/// `date_text` must be a valid NUL-terminated C string and `out_time` writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_gen_time(
    date_text: *const c_char,
    out_time: *mut i32,
) -> i32 {
    unsafe { net_http_gen_time_ffi(date_text, out_time) }
}

/// Extracts one HTTP header value from raw header block.
///
/// # Safety
/// - `q_headers` must point to `q_headers_len` readable bytes.
/// - `buffer` must be writable for `b_len` bytes.
/// - `arg_name` must point to `arg_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_get_header(
    q_headers: *const c_char,
    q_headers_len: i32,
    buffer: *mut c_char,
    b_len: i32,
    arg_name: *const c_char,
    arg_len: i32,
) -> i32 {
    unsafe { net_http_get_header_ffi(q_headers, q_headers_len, buffer, b_len, arg_name, arg_len) }
}

/// Selects message-buffer size-class index matching C allocation policy.
///
/// # Safety
/// `buffer_sizes` must point to `buffer_size_values` readable `i32` values.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_msg_buffers_pick_size_index(
    buffer_sizes: *const i32,
    buffer_size_values: i32,
    size_hint: i32,
) -> i32 {
    unsafe { msg_buffers_pick_size_index_ffi(buffer_sizes, buffer_size_values, size_hint) }
}

/// Encodes compact/medium tcp-rpc length prefix exactly like C path.
///
/// # Safety
/// `out_prefix_word` and `out_prefix_bytes` must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_encode_compact_header(
    payload_len: i32,
    is_medium: i32,
    out_prefix_word: *mut i32,
    out_prefix_bytes: *mut i32,
) -> i32 {
    unsafe {
        tcp_rpc_encode_compact_header_ffi(payload_len, is_medium, out_prefix_word, out_prefix_bytes)
    }
}

/// Decodes compact tcp-rpc packet header.
///
/// Returns 0 on success with decoded values in output parameters, -1 on error.
///
/// # Safety
/// `out_payload_len` and `out_header_bytes` must be valid writable pointers.
/// `remaining_bytes` can be null if `first_byte` < 0x7f (compact format).
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_decode_compact_header(
    first_byte: u8,
    remaining_bytes: *const u8,
    out_payload_len: *mut i32,
    out_header_bytes: *mut i32,
) -> i32 {
    unsafe {
        tcp_rpc_decode_compact_header_ffi(
            first_byte,
            remaining_bytes,
            out_payload_len,
            out_header_bytes,
        )
    }
}

/// Sets default RPC flags using bitwise AND and OR operations.
///
/// Returns the new flags value after the operations.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_set_default_rpc_flags(and_flags: u32, or_flags: u32) -> u32 {
    tcp_rpc_set_default_rpc_flags_impl(and_flags, or_flags)
}

/// Gets the current default RPC flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_get_default_rpc_flags() -> u32 {
    tcp_rpc_get_default_rpc_flags_impl()
}

/// Sets the maximum DH accept rate (rate per second).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_set_max_dh_accept_rate(rate: i32) {
    tcp_rpc_set_max_dh_accept_rate_impl(rate);
}

/// Gets the current maximum DH accept rate.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_get_max_dh_accept_rate() -> i32 {
    tcp_rpc_get_max_dh_accept_rate_impl()
}

/// Constructs a ping packet with the given ping ID.
///
/// # Safety
/// `out_packet` must be a valid writable pointer to a 12-byte buffer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_construct_ping_packet(
    ping_id: i64,
    out_packet: *mut u8,
) -> i32 {
    let Some(out) = (unsafe { mut_ref_from_ptr(out_packet.cast::<[u8; 12]>()) }) else {
        return -1;
    };
    *out = tcp_rpc_construct_ping_packet_impl(ping_id);
    0
}

/// Attempts to add a DH accept operation under rate limiting.
///
/// Returns 0 if allowed, -1 if rate limit exceeded.
/// Updates the state parameters (remaining and last_time) with new values.
///
/// # Safety
/// `out_remaining` and `out_last_time` must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_add_dh_accept(
    remaining: f64,
    last_time: f64,
    max_rate: i32,
    precise_now: f64,
    out_remaining: *mut f64,
    out_last_time: *mut f64,
) -> i32 {
    let Some(out_rem) = (unsafe { mut_ref_from_ptr(out_remaining) }) else {
        return -1;
    };
    let Some(out_time) = (unsafe { mut_ref_from_ptr(out_last_time) }) else {
        return -1;
    };
    tcp_rpc_add_dh_accept_impl(remaining, last_time, max_rate, precise_now, out_rem, out_time)
}

/// Parses a tcp-rpc nonce packet into normalized fields.
///
/// # Safety
/// All output pointers must be writable and valid for the provided capacity.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_parse_nonce_packet(
    packet: *const u8,
    packet_len: i32,
    out_schema: *mut i32,
    out_key_select: *mut i32,
    out_crypto_ts: *mut i32,
    out_nonce: *mut u8,
    out_nonce_len: i32,
    out_extra_keys_count: *mut i32,
    out_extra_key_signatures: *mut i32,
    out_extra_key_signatures_len: i32,
    out_dh_params_select: *mut i32,
    out_has_dh_params: *mut i32,
) -> i32 {
    unsafe {
        tcp_rpc_parse_nonce_packet_ffi(
            packet,
            packet_len,
            out_schema,
            out_key_select,
            out_crypto_ts,
            out_nonce,
            out_nonce_len,
            out_extra_keys_count,
            out_extra_key_signatures,
            out_extra_key_signatures_len,
            out_dh_params_select,
            out_has_dh_params,
        )
    }
}

/// Validates one nonce packet against C/RPC client policy and crypto selector context.
///
/// Returns 0 on success or negative on parse/policy failure.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_client_process_nonce_packet(
    packet: *const u8,
    packet_len: i32,
    allow_unencrypted: i32,
    allow_encrypted: i32,
    require_dh: i32,
    has_crypto_temp: i32,
    nonce_time: i32,
    main_secret_len: i32,
    main_key_signature: i32,
    out_schema: *mut i32,
    out_key_select: *mut i32,
    out_has_dh_params: *mut i32,
) -> i32 {
    unsafe {
        tcp_rpc_client_process_nonce_packet_ffi(
            packet,
            packet_len,
            allow_unencrypted,
            allow_encrypted,
            require_dh,
            has_crypto_temp,
            nonce_time,
            main_secret_len,
            main_key_signature,
            out_schema,
            out_key_select,
            out_has_dh_params,
        )
    }
}

/// Validates one nonce packet against C/RPC server policy and crypto selector context.
///
/// Returns 0 on success or negative on parse/policy failure.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_server_process_nonce_packet(
    packet: *const u8,
    packet_len: i32,
    allow_unencrypted: i32,
    allow_encrypted: i32,
    now_ts: i32,
    main_secret_len: i32,
    main_key_signature: i32,
    out_schema: *mut i32,
    out_key_select: *mut i32,
    out_has_dh_params: *mut i32,
) -> i32 {
    unsafe {
        tcp_rpc_server_process_nonce_packet_ffi(
            packet,
            packet_len,
            allow_unencrypted,
            allow_encrypted,
            now_ts,
            main_secret_len,
            main_key_signature,
            out_schema,
            out_key_select,
            out_has_dh_params,
        )
    }
}

/// Parses a tcp-rpc handshake packet into normalized fields.
///
/// # Safety
/// All output pointers must be writable and valid for the provided structures.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_parse_handshake_packet(
    packet: *const u8,
    packet_len: i32,
    out_flags: *mut i32,
    out_sender_pid: *mut MtproxyProcessId,
    out_peer_pid: *mut MtproxyProcessId,
) -> i32 {
    unsafe {
        tcp_rpc_parse_handshake_packet_ffi(
            packet,
            packet_len,
            out_flags,
            out_sender_pid,
            out_peer_pid,
        )
    }
}

/// Classifies packet length for non-compact tcp-rpc client parser path.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_client_packet_len_state(
    packet_len: i32,
    max_packet_len: i32,
) -> i32 {
    tcp_rpc_client_packet_len_state_impl(packet_len, max_packet_len)
}

/// Returns `1` when tcp-rpc server packet header is malformed before fallback.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_packet_header_malformed(packet_len: i32) -> i32 {
    tcp_rpc_server_packet_header_malformed_impl(packet_len)
}

/// Classifies packet length for non-compact tcp-rpc server parser path.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_packet_len_state(
    packet_len: i32,
    max_packet_len: i32,
) -> i32 {
    tcp_rpc_server_packet_len_state_impl(packet_len, max_packet_len)
}

/// Returns whether `tcp_rpcs_default_execute` should handle packet as ping->pong.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_default_execute_should_pong(
    op: i32,
    raw_total_bytes: i32,
) -> i32 {
    tcp_rpc_server_default_execute_should_pong_impl(op, raw_total_bytes)
}

/// Overwrites packet word[0] with `RPC_PONG` for ping response payload.
///
/// # Safety
/// `packet_words` must point to exactly 3 writable `i32` values.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_server_default_execute_set_pong(
    packet_words: *mut i32,
    packet_words_len: i32,
) -> i32 {
    unsafe { tcp_rpc_server_default_execute_set_pong_ffi(packet_words, packet_words_len) }
}

/// Serializes one tcp-rpc handshake packet into caller-provided buffer.
///
/// # Safety
/// - `sender_pid` and `peer_pid` must be valid readable pointers.
/// - `out_packet` must be writable for `out_packet_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_server_build_handshake_packet(
    crypto_flags: i32,
    sender_pid: *const MtproxyProcessId,
    peer_pid: *const MtproxyProcessId,
    out_packet: *mut u8,
    out_packet_len: i32,
) -> i32 {
    unsafe {
        tcp_rpc_server_build_handshake_packet_ffi(
            crypto_flags,
            sender_pid,
            peer_pid,
            out_packet,
            out_packet_len,
        )
    }
}

/// Serializes one tcp-rpc handshake-error packet into caller-provided buffer.
///
/// # Safety
/// - `sender_pid` must be a valid readable pointer.
/// - `out_packet` must be writable for `out_packet_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_server_build_handshake_error_packet(
    error_code: i32,
    sender_pid: *const MtproxyProcessId,
    out_packet: *mut u8,
    out_packet_len: i32,
) -> i32 {
    unsafe {
        tcp_rpc_server_build_handshake_error_packet_ffi(
            error_code,
            sender_pid,
            out_packet,
            out_packet_len,
        )
    }
}

/// Validates server-side handshake header triplet (seqno/type/size).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_validate_handshake_header(
    packet_num: i32,
    packet_type: i32,
    packet_len: i32,
    handshake_packet_len: i32,
) -> i32 {
    tcp_rpc_server_validate_handshake_header_impl(
        packet_num,
        packet_type,
        packet_len,
        handshake_packet_len,
    )
}

/// Validates server-side nonce header triplet (seqno/type/size-range).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_validate_nonce_header(
    packet_num: i32,
    packet_type: i32,
    packet_len: i32,
    nonce_packet_min_len: i32,
    nonce_packet_max_len: i32,
) -> i32 {
    tcp_rpc_server_validate_nonce_header_impl(
        packet_num,
        packet_type,
        packet_len,
        nonce_packet_min_len,
        nonce_packet_max_len,
    )
}

/// Validates parsed handshake payload and computes crc32c activation flag.
///
/// # Safety
/// `out_enable_crc32c` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_server_validate_handshake(
    packet_flags: i32,
    peer_pid_matches: i32,
    ignore_pid: i32,
    default_rpc_flags: i32,
    out_enable_crc32c: *mut i32,
) -> i32 {
    unsafe {
        tcp_rpc_server_validate_handshake_ffi(
            packet_flags,
            peer_pid_matches,
            ignore_pid,
            default_rpc_flags,
            out_enable_crc32c,
        )
    }
}

/// Returns `1` when `C_WANTWR` should be set after wakeup/alarm callback.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_should_set_wantwr(out_total_bytes: i32) -> i32 {
    tcp_rpc_server_should_set_wantwr_impl(out_total_bytes)
}

/// Returns whether close notification should be queued.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_should_notify_close(has_rpc_close: i32) -> i32 {
    tcp_rpc_server_should_notify_close_impl(has_rpc_close)
}

/// Returns `tcp_rpcs_do_wakeup()` result.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_do_wakeup() -> i32 {
    tcp_rpc_server_do_wakeup_impl()
}

/// Returns post-notification `pending_queries` value.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_notification_pending_queries() -> i32 {
    tcp_rpc_server_notification_pending_queries_impl()
}

/// Computes tcp-rpc server initial state values for accepted connection.
///
/// # Safety
/// All output pointers must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_server_init_accepted_state(
    has_perm_callback: i32,
    perm_flags: i32,
    out_crypto_flags: *mut i32,
    out_in_packet_num: *mut i32,
    out_out_packet_num: *mut i32,
) -> i32 {
    unsafe {
        tcp_rpc_server_init_accepted_state_ffi(
            has_perm_callback,
            perm_flags,
            out_crypto_flags,
            out_in_packet_num,
            out_out_packet_num,
        )
    }
}

/// Computes tcp-rpc server initial state values for accepted-nohs mode.
///
/// # Safety
/// `out_crypto_flags` and `out_in_packet_num` must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_server_init_accepted_nohs_state(
    out_crypto_flags: *mut i32,
    out_in_packet_num: *mut i32,
) -> i32 {
    unsafe { tcp_rpc_server_init_accepted_nohs_state_ffi(out_crypto_flags, out_in_packet_num) }
}

/// Computes fake-crypto state transition.
///
/// # Safety
/// `out_crypto_flags` must be a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tcp_rpc_server_init_fake_crypto_state(
    crypto_flags: i32,
    out_crypto_flags: *mut i32,
) -> i32 {
    unsafe { tcp_rpc_server_init_fake_crypto_state_ffi(crypto_flags, out_crypto_flags) }
}

/// Returns default permission mask for tcp-rpc server.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_tcp_rpc_server_default_check_perm(default_rpc_flags: i32) -> i32 {
    tcp_rpc_server_default_check_perm_impl(default_rpc_flags)
}

/// Normalizes rpc-target PID (`ip=0` -> `default_ip`) to match C behavior.
///
/// # Safety
/// `pid` must be a valid writable pointer to `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_normalize_pid(
    pid: *mut MtproxyProcessId,
    default_ip: u32,
) -> i32 {
    unsafe { rpc_target_normalize_pid_ffi(pid, default_ip) }
}

/// Returns default query-type mask for `engine-rpc-common` trivial handlers.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_common_default_query_type_mask() -> i32 {
    engine_rpc_common_default_query_type_mask_impl()
}

/// Returns default parser dispatch decision for `(actor_id, op)` tuple.
///
/// Result values:
/// - `0`: no default handler
/// - `1`: `TL_ENGINE_STAT`
/// - `2`: `TL_ENGINE_NOP`
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_common_default_parse_decision(
    actor_id: i64,
    op: i32,
) -> i32 {
    engine_rpc_common_default_parse_decision_impl(actor_id, op)
}

/// Extracts query-type id from high bits of query `qid`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_query_result_type_id_from_qid(qid: i64) -> i32 {
    engine_rpc_query_result_type_id_from_qid_impl(qid)
}

/// Decides query-result routing behavior (`ignore` / `dispatch` / `skip`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_query_result_dispatch_decision(
    has_table: i32,
    has_handler: i32,
) -> i32 {
    engine_rpc_query_result_dispatch_decision_impl(has_table, has_handler)
}

/// Decides whether action-extra should be duplicated.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_need_dup(flags: i32) -> i32 {
    engine_rpc_need_dup_impl(flags)
}

/// Classifies `query_job_run` flow by op and custom-op availability.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_query_job_dispatch_decision(
    op: i32,
    has_custom_tree: i32,
) -> i32 {
    engine_rpc_query_job_dispatch_decision_impl(op, has_custom_tree)
}

/// Returns whether tcp-rpc op should keep connection reference.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_tcp_should_hold_conn(op: i32) -> i32 {
    engine_rpc_tcp_should_hold_conn_impl(op)
}

/// Returns default `engine-net` port modulo selector (`-1`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_net_default_port_mod() -> i32 {
    engine_net_default_port_mod_impl()
}

/// Runs Rust `try_open_port_range` selector with C callback opening ports.
///
/// Return codes:
/// - `0`: selected port written to `out_selected_port`
/// - `1`: no available port (only when `quit_on_fail == 0`)
/// - `-1`: invalid arguments
/// - `-2`: selection/open failure in quit-on-fail mode
///
/// # Safety
/// `out_selected_port` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_net_try_open_port_range(
    start_port: i32,
    end_port: i32,
    mod_port: i32,
    rem_port: i32,
    quit_on_fail: i32,
    try_open: Option<EngineNetTryOpenPortFn>,
    try_open_ctx: *mut c_void,
    out_selected_port: *mut i32,
) -> i32 {
    unsafe {
        engine_net_try_open_port_range_ffi(
            start_port,
            end_port,
            mod_port,
            rem_port,
            quit_on_fail,
            try_open,
            try_open_ctx,
            out_selected_port,
        )
    }
}

/// Runs Rust `engine_do_open_port` privileged pre-open planning with C callback.
///
/// Return codes:
/// - `0`: privileged pre-open selected/opened port (`out_selected_port` set)
/// - `1`: no privileged pre-open required
/// - `-1`: invalid arguments
/// - `-2`: privileged pre-open failed in quit-on-fail mode
///
/// # Safety
/// `out_selected_port` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_net_open_privileged_port(
    port: i32,
    start_port: i32,
    end_port: i32,
    port_mod: i32,
    tcp_enabled: i32,
    quit_on_fail: i32,
    try_open: Option<EngineNetTryOpenPortFn>,
    try_open_ctx: *mut c_void,
    out_selected_port: *mut i32,
) -> i32 {
    unsafe {
        engine_net_open_privileged_port_ffi(
            port,
            start_port,
            end_port,
            port_mod,
            tcp_enabled,
            quit_on_fail,
            try_open,
            try_open_ctx,
            out_selected_port,
        )
    }
}

/// Marks one engine signal as pending.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_signal_set_pending(sig: i32) {
    engine_signal_set_pending_impl(sig);
}

/// Checks if an engine signal is currently pending (`1` / `0`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_signal_check_pending(sig: i32) -> i32 {
    engine_signal_check_pending_impl(sig)
}

/// Checks and clears one pending engine signal (`1` / `0`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_signal_check_pending_and_clear(sig: i32) -> i32 {
    engine_signal_check_pending_and_clear_impl(sig)
}

/// Reports whether interrupt signals are pending (`SIGINT`/`SIGTERM`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_interrupt_signal_raised() -> i32 {
    engine_interrupt_signal_raised_impl()
}

/// Drains pending engine signals constrained by `allowed_signals`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_process_signals_allowed(
    allowed_signals: u64,
    dispatch: Option<EngineSignalDispatchFn>,
    dispatch_ctx: *mut c_void,
) -> i32 {
    engine_process_signals_allowed_impl(allowed_signals, dispatch, dispatch_ctx)
}

/// Computes `engine-rpc` result flags normalization (`old_flags & 0xffff`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_result_new_flags(old_flags: i32) -> i32 {
    engine_rpc_result_new_flags_impl(old_flags)
}

/// Computes `engine-rpc` result header length from flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_engine_rpc_result_header_len(flags: i32) -> i32 {
    engine_rpc_result_header_len_impl(flags)
}

/// Computes mtproto external-connection hash bucket.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_mtproto_ext_conn_hash(
    in_fd: i32,
    in_conn_id: i64,
    hash_shift: i32,
) -> i32 {
    mtproto_ext_conn_hash_impl(in_fd, in_conn_id, hash_shift)
}

/// Computes mtproto connection tag (`1 + (generation & 0xffffff)`).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_mtproto_conn_tag(generation: i32) -> i32 {
    mtproto_conn_tag_impl(generation)
}
