//! FFI export surface for compatibility/runtime shims.

use super::core::*;
use crate::*;
use std::ffi::CStr;

/// Returns FFI API version to C callers.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_api_version() -> u32 {
    crate::FFI_API_VERSION
}

/// Performs a minimal startup compatibility handshake.
///
/// Return codes:
/// - `0`: handshake accepted
/// - `-1`: incompatible API version
#[no_mangle]
pub extern "C" fn mtproxy_ffi_startup_handshake(expected_api_version: u32) -> i32 {
    if expected_api_version == crate::FFI_API_VERSION {
        0
    } else {
        -1
    }
}

/// Returns extracted Step 9 boundary contract for mp-queue/jobs migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyConcurrencyBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_concurrency_boundary(
    out: *mut MtproxyConcurrencyBoundary,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    *out_ref = MtproxyConcurrencyBoundary {
        boundary_version: CONCURRENCY_BOUNDARY_VERSION,
        mpq_contract_ops: MPQ_CONTRACT_OPS,
        mpq_implemented_ops: MPQ_IMPLEMENTED_OPS,
        jobs_contract_ops: JOBS_CONTRACT_OPS,
        jobs_implemented_ops: JOBS_IMPLEMENTED_OPS,
    };
    0
}

/// Returns extracted Step 10 boundary contract for net-core migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyNetworkBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_network_boundary(out: *mut MtproxyNetworkBoundary) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    *out_ref = MtproxyNetworkBoundary {
        boundary_version: NETWORK_BOUNDARY_VERSION,
        net_events_contract_ops: NET_EVENTS_CONTRACT_OPS,
        net_events_implemented_ops: NET_EVENTS_IMPLEMENTED_OPS,
        net_timers_contract_ops: NET_TIMERS_CONTRACT_OPS,
        net_timers_implemented_ops: NET_TIMERS_IMPLEMENTED_OPS,
        net_msg_buffers_contract_ops: NET_MSG_BUFFERS_CONTRACT_OPS,
        net_msg_buffers_implemented_ops: NET_MSG_BUFFERS_IMPLEMENTED_OPS,
    };
    0
}

/// Returns extracted Step 11 boundary contract for RPC/TCP migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyRpcBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_rpc_boundary(out: *mut MtproxyRpcBoundary) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    *out_ref = MtproxyRpcBoundary {
        boundary_version: RPC_BOUNDARY_VERSION,
        tcp_rpc_common_contract_ops: TCP_RPC_COMMON_CONTRACT_OPS,
        tcp_rpc_common_implemented_ops: TCP_RPC_COMMON_IMPLEMENTED_OPS,
        tcp_rpc_client_contract_ops: TCP_RPC_CLIENT_CONTRACT_OPS,
        tcp_rpc_client_implemented_ops: TCP_RPC_CLIENT_IMPLEMENTED_OPS,
        tcp_rpc_server_contract_ops: TCP_RPC_SERVER_CONTRACT_OPS,
        tcp_rpc_server_implemented_ops: TCP_RPC_SERVER_IMPLEMENTED_OPS,
        rpc_targets_contract_ops: RPC_TARGETS_CONTRACT_OPS,
        rpc_targets_implemented_ops: RPC_TARGETS_IMPLEMENTED_OPS,
    };
    0
}

/// Returns extracted Step 12 boundary contract for crypto integration migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyCryptoBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_crypto_boundary(out: *mut MtproxyCryptoBoundary) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    *out_ref = MtproxyCryptoBoundary {
        boundary_version: CRYPTO_BOUNDARY_VERSION,
        net_crypto_aes_contract_ops: NET_CRYPTO_AES_CONTRACT_OPS,
        net_crypto_aes_implemented_ops: NET_CRYPTO_AES_IMPLEMENTED_OPS,
        net_crypto_dh_contract_ops: NET_CRYPTO_DH_CONTRACT_OPS,
        net_crypto_dh_implemented_ops: NET_CRYPTO_DH_IMPLEMENTED_OPS,
        aesni_contract_ops: AESNI_CONTRACT_OPS,
        aesni_implemented_ops: AESNI_IMPLEMENTED_OPS,
    };
    0
}

/// Returns extracted Step 13 boundary contract for engine/mtproto app migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyApplicationBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_application_boundary(
    out: *mut MtproxyApplicationBoundary,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    *out_ref = MtproxyApplicationBoundary {
        boundary_version: APPLICATION_BOUNDARY_VERSION,
        engine_rpc_contract_ops: ENGINE_RPC_CONTRACT_OPS,
        engine_rpc_implemented_ops: ENGINE_RPC_IMPLEMENTED_OPS,
        mtproto_proxy_contract_ops: MTPROTO_PROXY_CONTRACT_OPS,
        mtproto_proxy_implemented_ops: MTPROTO_PROXY_IMPLEMENTED_OPS,
    };
    0
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
    let Some(name_ref) = (unsafe { ref_from_ptr(name) }) else {
        return -1;
    };
    let Some(kind_ref) = (unsafe { mut_ref_from_ptr(out_kind) }) else {
        return -1;
    };
    let Some(ip_ref) = (unsafe { mut_ref_from_ptr(out_ipv4) }) else {
        return -1;
    };
    let name = unsafe { CStr::from_ptr(name_ref) };
    let (kind, ip) = resolver_gethostbyname_plan_impl(name.to_bytes());
    *kind_ref = kind;
    *ip_ref = ip;
    0
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
    if !(0..=16).contains(&extra_num) {
        return 0;
    }

    let extra = if extra_num == 0 {
        &[]
    } else {
        let Ok(count) = usize::try_from(extra_num) else {
            return 0;
        };
        let Some(values) = (unsafe { slice_from_ptr(extra_key_signatures, count) }) else {
            return 0;
        };
        values
    };
    net_select_best_key_signature_impl(main_secret_len, main_key_signature, key_signature, extra)
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
    let Some(rule_text_ref) = (unsafe { ref_from_ptr(rule_text) }) else {
        eprintln!("expected <local-addr>:<global-addr> in --nat-info");
        return -1;
    };
    let rule = unsafe { CStr::from_ptr(rule_text_ref) };
    let Ok(rule_text) = rule.to_str() else {
        eprintln!("expected <local-addr>:<global-addr> in --nat-info");
        return -1;
    };
    net_add_nat_info_impl(rule_text)
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_payload_len) }) else {
        return -1;
    };
    let Some(h) = (unsafe { copy_bytes::<5>(header) }) else {
        return -1;
    };
    match net_tcp_tls_parse_header_impl(&h) {
        Ok(payload_len) => {
            *out_ref = payload_len;
            0
        }
        Err(()) => -1,
    }
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_skip_bytes) }) else {
        return -1;
    };
    match net_tcp_reader_skip_from_parse_result_impl(parse_res, buffered_bytes, need_more_bytes) {
        Some(skip) => {
            *out_ref = skip;
            1
        }
        None => 0,
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
    if len < 0 {
        return -1;
    }
    let Ok(len) = usize::try_from(len) else {
        return -1;
    };
    let Some(domain) = (unsafe { slice_from_ptr(domain, len) }) else {
        return -1;
    };
    net_tcp_rpc_ext_domain_bucket_index_impl(domain)
}

/// Computes 16-byte client-random cache hash bucket index (`14` bits).
///
/// # Safety
/// `random` must point to at least `16` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_tcp_rpc_ext_client_random_bucket_index(
    random: *const u8,
) -> i32 {
    let Some(random_buf) = (unsafe { copy_bytes::<16>(random) }) else {
        return -1;
    };
    net_tcp_rpc_ext_client_random_bucket_index_impl(&random_buf)
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
    let Some(out_size_ref) = (unsafe { mut_ref_from_ptr(out_size) }) else {
        return -1;
    };
    let Some(out_profile_ref) = (unsafe { mut_ref_from_ptr(out_profile) }) else {
        return -1;
    };
    let Some((size, profile)) =
        net_tcp_rpc_ext_select_server_hello_profile_impl(min_len, max_len, sum_len, sample_count)
    else {
        return -1;
    };
    *out_size_ref = size;
    *out_profile_ref = profile;
    0
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
    let (
        Some(rpc_ready),
        Some(rpc_close),
        Some(rpc_alarm),
        Some(rpc_wakeup),
        Some(fail_connection),
        Some(job_decref),
        Some(event_free),
    ) = (
        rpc_ready,
        rpc_close,
        rpc_alarm,
        rpc_wakeup,
        fail_connection,
        job_decref,
        event_free,
    )
    else {
        return -1;
    };
    net_thread_run_notification_event_impl(
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

/// Returns HTTP status text and normalizes unknown status code to `500`.
///
/// # Safety
/// `code` must be a valid writable pointer to `i32`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_http_error_msg_text(code: *mut i32) -> *const c_char {
    let Some(code_ref) = (unsafe { mut_ref_from_ptr(code) }) else {
        return core::ptr::null();
    };
    let in_code = *code_ref;
    let (normalized_code, message_ptr) = net_http_error_msg_text_impl(in_code);
    *code_ref = normalized_code;
    message_ptr
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
    if out_len < 29 {
        return -1;
    }
    let Ok(out_count) = usize::try_from(out_len) else {
        return -1;
    };
    let Some(out_slice) = (unsafe { mut_slice_from_ptr(out.cast::<u8>(), out_count) }) else {
        return -1;
    };
    let date = net_http_gen_date_impl(time);
    out_slice[..29].copy_from_slice(&date);
    if out_count > 29 {
        out_slice[29] = 0;
    }
    0
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
    let Some(date_text_ref) = (unsafe { ref_from_ptr(date_text) }) else {
        return -8;
    };
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_time) }) else {
        return -8;
    };
    let text = unsafe { CStr::from_ptr(date_text_ref) };
    let Ok(text) = text.to_str() else {
        return -8;
    };
    match net_http_gen_time_impl(text) {
        Ok(time) => {
            *out_ref = time;
            0
        }
        Err(code) => code,
    }
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
    if b_len <= 0 {
        return -1;
    }
    let Ok(buffer_len) = usize::try_from(b_len) else {
        return -1;
    };
    let Some(out) = (unsafe { mut_slice_from_ptr(buffer.cast::<u8>(), buffer_len) }) else {
        return -1;
    };

    if q_headers_len < 0 || arg_len < 0 {
        out[0] = 0;
        return -1;
    }
    let Ok(headers_len) = usize::try_from(q_headers_len) else {
        out[0] = 0;
        return -1;
    };
    let Ok(name_len) = usize::try_from(arg_len) else {
        out[0] = 0;
        return -1;
    };
    let Some(headers) = (unsafe { slice_from_ptr(q_headers.cast::<u8>(), headers_len) }) else {
        out[0] = 0;
        return -1;
    };
    let Some(name) = (unsafe { slice_from_ptr(arg_name.cast::<u8>(), name_len) }) else {
        out[0] = 0;
        return -1;
    };
    net_http_get_header_impl(headers, out, name)
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
    if buffer_size_values <= 0 {
        return -1;
    }
    let Ok(count) = usize::try_from(buffer_size_values) else {
        return -1;
    };
    let Some(sizes) = (unsafe { slice_from_ptr(buffer_sizes, count) }) else {
        return -1;
    };
    msg_buffers_pick_size_index_impl(sizes, size_hint)
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
    let Some(out_word) = (unsafe { mut_ref_from_ptr(out_prefix_word) }) else {
        return -1;
    };
    let Some(out_bytes) = (unsafe { mut_ref_from_ptr(out_prefix_bytes) }) else {
        return -1;
    };
    let (prefix_word, prefix_bytes) = tcp_rpc_encode_compact_header_impl(payload_len, is_medium);
    *out_word = prefix_word;
    *out_bytes = prefix_bytes;
    0
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
    let Some(out_len) = (unsafe { mut_ref_from_ptr(out_payload_len) }) else {
        return -1;
    };
    let Some(out_bytes) = (unsafe { mut_ref_from_ptr(out_header_bytes) }) else {
        return -1;
    };

    let remaining = if first_byte == 0x7f {
        // Need 3 more bytes for wide format
        let Some(ptr) = (unsafe { ref_from_ptr(remaining_bytes) }) else {
            return -1;
        };
        let slice = unsafe { core::slice::from_raw_parts(ptr, 3) };
        let mut arr = [0_u8; 3];
        arr.copy_from_slice(slice);
        Some(arr)
    } else {
        None
    };

    match tcp_rpc_decode_compact_header_impl(first_byte, remaining) {
        Some((payload_len, header_bytes)) => {
            *out_len = payload_len;
            *out_bytes = header_bytes;
            0
        }
        None => -1,
    }
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
    if out_extra_key_signatures_len < 0 {
        return -1;
    }
    let Ok(packet_count) = usize::try_from(packet_len) else {
        return -1;
    };
    let Some(packet_bytes) = (unsafe { slice_from_ptr(packet, packet_count) }) else {
        return -1;
    };
    if out_nonce_len != 16 {
        return -2;
    }
    let Some(out_nonce_out) = (unsafe { mut_ref_from_ptr(out_nonce.cast::<[u8; 16]>()) })
    else {
        return -1;
    };
    let Some(schema_ref) = (unsafe { mut_ref_from_ptr(out_schema) }) else {
        return -1;
    };
    let Some(key_select_ref) = (unsafe { mut_ref_from_ptr(out_key_select) }) else {
        return -1;
    };
    let Some(crypto_ts_ref) = (unsafe { mut_ref_from_ptr(out_crypto_ts) }) else {
        return -1;
    };
    let Some(extra_keys_count_ref) = (unsafe { mut_ref_from_ptr(out_extra_keys_count) }) else {
        return -1;
    };
    let Some(dh_params_select_ref) = (unsafe { mut_ref_from_ptr(out_dh_params_select) }) else {
        return -1;
    };
    let Some(has_dh_params_ref) = (unsafe { mut_ref_from_ptr(out_has_dh_params) }) else {
        return -1;
    };

    let Ok(extra_count) = usize::try_from(out_extra_key_signatures_len) else {
        return -1;
    };
    let out_extra_key_signatures = if extra_count == 0 {
        &mut []
    } else {
        match unsafe { mut_slice_from_ptr(out_extra_key_signatures, extra_count) } {
            Some(extra) => extra,
            None => return -1,
        }
    };

    tcp_rpc_parse_nonce_packet_impl(
        packet_bytes,
        schema_ref,
        key_select_ref,
        crypto_ts_ref,
        out_nonce_out,
        extra_keys_count_ref,
        out_extra_key_signatures,
        dh_params_select_ref,
        has_dh_params_ref,
    )
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
    let Ok(packet_count) = usize::try_from(packet_len) else {
        return -1;
    };
    let Some(packet_bytes) = (unsafe { slice_from_ptr(packet, packet_count) }) else {
        return -1;
    };
    let Some(schema_ref) = (unsafe { mut_ref_from_ptr(out_schema) }) else {
        return -1;
    };
    let Some(key_select_ref) = (unsafe { mut_ref_from_ptr(out_key_select) }) else {
        return -1;
    };
    let Some(has_dh_params_ref) = (unsafe { mut_ref_from_ptr(out_has_dh_params) }) else {
        return -1;
    };

    tcp_rpc_client_process_nonce_packet_impl(
        packet_bytes,
        allow_unencrypted,
        allow_encrypted,
        require_dh,
        has_crypto_temp,
        nonce_time,
        main_secret_len,
        main_key_signature,
        schema_ref,
        key_select_ref,
        has_dh_params_ref,
    )
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
    let Ok(packet_count) = usize::try_from(packet_len) else {
        return -1;
    };
    let Some(packet_bytes) = (unsafe { slice_from_ptr(packet, packet_count) }) else {
        return -1;
    };
    let Some(schema_ref) = (unsafe { mut_ref_from_ptr(out_schema) }) else {
        return -1;
    };
    let Some(key_select_ref) = (unsafe { mut_ref_from_ptr(out_key_select) }) else {
        return -1;
    };
    let Some(has_dh_params_ref) = (unsafe { mut_ref_from_ptr(out_has_dh_params) }) else {
        return -1;
    };

    tcp_rpc_server_process_nonce_packet_impl(
        packet_bytes,
        allow_unencrypted,
        allow_encrypted,
        now_ts,
        main_secret_len,
        main_key_signature,
        schema_ref,
        key_select_ref,
        has_dh_params_ref,
    )
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
    let Ok(packet_count) = usize::try_from(packet_len) else {
        return -1;
    };
    let Some(packet_bytes) = (unsafe { slice_from_ptr(packet, packet_count) }) else {
        return -1;
    };
    let Some(flags_ref) = (unsafe { mut_ref_from_ptr(out_flags) }) else {
        return -1;
    };
    let Some(sender_pid_ref) = (unsafe { mut_ref_from_ptr(out_sender_pid) }) else {
        return -1;
    };
    let Some(peer_pid_ref) = (unsafe { mut_ref_from_ptr(out_peer_pid) }) else {
        return -1;
    };

    tcp_rpc_parse_handshake_packet_impl(packet_bytes, flags_ref, sender_pid_ref, peer_pid_ref)
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

/// Normalizes rpc-target PID (`ip=0` -> `default_ip`) to match C behavior.
///
/// # Safety
/// `pid` must be a valid writable pointer to `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_rpc_target_normalize_pid(
    pid: *mut MtproxyProcessId,
    default_ip: u32,
) -> i32 {
    let Some(pid_ref) = (unsafe { mut_ref_from_ptr(pid) }) else {
        return -1;
    };
    rpc_target_normalize_pid_impl(pid_ref, default_ip);
    0
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_selected_port) }) else {
        return -1;
    };

    match engine_net_try_open_port_range_impl(
        start_port,
        end_port,
        mod_port,
        rem_port,
        quit_on_fail != 0,
        try_open,
        try_open_ctx,
    ) {
        Ok(Some(port)) => {
            *out_ref = port;
            0
        }
        Ok(None) => 1,
        Err(()) => {
            if quit_on_fail != 0 {
                -2
            } else {
                -1
            }
        }
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_selected_port) }) else {
        return -1;
    };

    match engine_net_open_privileged_port_impl(
        port,
        start_port,
        end_port,
        port_mod,
        tcp_enabled != 0,
        quit_on_fail != 0,
        try_open,
        try_open_ctx,
    ) {
        Ok(Some(selected_port)) => {
            *out_ref = selected_port;
            0
        }
        Ok(None) => 1,
        Err(()) => {
            if quit_on_fail != 0 {
                -2
            } else {
                -1
            }
        }
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
