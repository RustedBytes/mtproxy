use super::*;

/// Mirrors core API version for Rust callers.
#[must_use]
pub fn ffi_api_version() -> u32 {
    FFI_API_VERSION
}

/// Returns FFI API version to C callers.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_api_version() -> u32 {
    FFI_API_VERSION
}

/// Performs a minimal startup compatibility handshake.
///
/// Return codes:
/// - `0`: handshake accepted
/// - `-1`: incompatible API version
#[no_mangle]
pub extern "C" fn mtproxy_ffi_startup_handshake(expected_api_version: u32) -> i32 {
    if expected_api_version == FFI_API_VERSION {
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
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
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
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
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
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
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
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
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
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyApplicationBoundary {
        boundary_version: APPLICATION_BOUNDARY_VERSION,
        engine_rpc_contract_ops: ENGINE_RPC_CONTRACT_OPS,
        engine_rpc_implemented_ops: ENGINE_RPC_IMPLEMENTED_OPS,
        mtproto_proxy_contract_ops: MTPROTO_PROXY_CONTRACT_OPS,
        mtproto_proxy_implemented_ops: MTPROTO_PROXY_IMPLEMENTED_OPS,
    };
    0
}

fn net_epoll_conv_flags_impl(flags: i32) -> i32 {
    if flags == 0 {
        return 0;
    }
    let flags_u = u32::from_ne_bytes(flags.to_ne_bytes());
    let mut out = EPOLLERR;
    if (flags_u & EVT_READ) != 0 {
        out |= EPOLLIN;
    }
    if (flags_u & EVT_WRITE) != 0 {
        out |= EPOLLOUT;
    }
    if (flags_u & EVT_SPEC) != 0 {
        out |= EPOLLRDHUP | EPOLLPRI;
    }
    if (flags_u & EVT_LEVEL) == 0 {
        out |= EPOLLET;
    }
    i32::from_ne_bytes(out.to_ne_bytes())
}

fn net_epoll_unconv_flags_impl(epoll_flags: i32) -> i32 {
    let flags_u = u32::from_ne_bytes(epoll_flags.to_ne_bytes());
    let mut out = EVT_FROM_EPOLL;
    if (flags_u & (EPOLLIN | EPOLLERR)) != 0 {
        out |= EVT_READ;
    }
    if (flags_u & EPOLLOUT) != 0 {
        out |= EVT_WRITE;
    }
    if (flags_u & (EPOLLRDHUP | EPOLLPRI)) != 0 {
        out |= EVT_SPEC;
    }
    i32::from_ne_bytes(out.to_ne_bytes())
}

#[allow(clippy::cast_possible_truncation)]
fn net_timers_wait_msec_impl(wakeup_time: f64, now: f64) -> i32 {
    let wait_time = wakeup_time - now;
    if wait_time <= 0.0 {
        return 0;
    }
    let millis = (wait_time * 1000.0) + 1.0;
    if !millis.is_finite() || millis >= f64::from(i32::MAX) {
        i32::MAX
    } else {
        millis as i32
    }
}

fn msg_buffers_pick_size_index_impl(buffer_sizes: &[i32], size_hint: i32) -> i32 {
    if buffer_sizes.is_empty() {
        return -1;
    }
    let mut idx = i32::try_from(buffer_sizes.len()).unwrap_or(i32::MAX) - 1;
    if size_hint >= 0 {
        while idx > 0 {
            let prev_idx = usize::try_from(idx - 1).unwrap_or(0);
            if buffer_sizes[prev_idx] < size_hint {
                break;
            }
            idx -= 1;
        }
    }
    idx
}

fn tcp_rpc_encode_compact_header_impl(payload_len: i32, is_medium: i32) -> (i32, i32) {
    if is_medium != 0 {
        return (payload_len, 4);
    }
    if payload_len <= 0x7e * 4 {
        return (payload_len >> 2, 1);
    }
    let len_u = u32::from_ne_bytes(payload_len.to_ne_bytes());
    let encoded = (len_u << 6) | 0x7f;
    (i32::from_ne_bytes(encoded.to_ne_bytes()), 4)
}

fn tcp_rpc_client_packet_len_state_impl(packet_len: i32, max_packet_len: i32) -> i32 {
    if packet_len <= 0
        || (packet_len & 3) != 0
        || (max_packet_len > 0 && packet_len > max_packet_len)
    {
        return TCP_RPC_PACKET_LEN_STATE_INVALID;
    }
    if packet_len == 4 {
        return TCP_RPC_PACKET_LEN_STATE_SKIP;
    }
    if packet_len < 16 {
        return TCP_RPC_PACKET_LEN_STATE_SHORT;
    }
    TCP_RPC_PACKET_LEN_STATE_READY
}

fn tcp_rpc_server_packet_header_malformed_impl(packet_len: i32) -> i32 {
    i32::from(
        packet_len <= 0 || (packet_len & i32::from_ne_bytes(0xc000_0003_u32.to_ne_bytes())) != 0,
    )
}

fn tcp_rpc_server_packet_len_state_impl(packet_len: i32, max_packet_len: i32) -> i32 {
    if max_packet_len > 0 && packet_len > max_packet_len {
        return TCP_RPC_PACKET_LEN_STATE_INVALID;
    }
    if packet_len == 4 {
        return TCP_RPC_PACKET_LEN_STATE_SKIP;
    }
    if packet_len < 16 {
        return TCP_RPC_PACKET_LEN_STATE_INVALID;
    }
    TCP_RPC_PACKET_LEN_STATE_READY
}

fn rpc_target_normalize_pid_impl(pid: &mut MtproxyProcessId, default_ip: u32) {
    if pid.ip == 0 {
        pid.ip = default_ip;
    }
}

fn engine_rpc_result_new_flags_impl(old_flags: i32) -> i32 {
    old_flags & 0xffff
}

fn engine_rpc_result_header_len_impl(flags: i32) -> i32 {
    if flags == 0 {
        0
    } else {
        8
    }
}

fn mtproto_conn_tag_impl(generation: i32) -> i32 {
    mtproxy_core::runtime::mtproto::proxy::mtproto_conn_tag(generation)
}

fn mtproto_ext_conn_hash_impl(in_fd: i32, in_conn_id: i64, hash_shift: i32) -> i32 {
    mtproxy_core::runtime::mtproto::proxy::mtproto_ext_conn_hash(in_fd, in_conn_id, hash_shift)
}

/// Converts net event flags into Linux epoll flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_epoll_conv_flags(flags: i32) -> i32 {
    net_epoll_conv_flags_impl(flags)
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
    if buffer_sizes.is_null() || buffer_size_values <= 0 {
        return -1;
    }
    let Ok(count) = usize::try_from(buffer_size_values) else {
        return -1;
    };
    let sizes = unsafe { core::slice::from_raw_parts(buffer_sizes, count) };
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
    if out_prefix_word.is_null() || out_prefix_bytes.is_null() {
        return -1;
    }
    let (prefix_word, prefix_bytes) = tcp_rpc_encode_compact_header_impl(payload_len, is_medium);
    let out_word = unsafe { &mut *out_prefix_word };
    let out_bytes = unsafe { &mut *out_prefix_bytes };
    *out_word = prefix_word;
    *out_bytes = prefix_bytes;
    0
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
    if pid.is_null() {
        return -1;
    }
    let pid_ref = unsafe { &mut *pid };
    rpc_target_normalize_pid_impl(pid_ref, default_ip);
    0
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
