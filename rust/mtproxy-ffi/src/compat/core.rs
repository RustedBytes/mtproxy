pub(super) use crate::ffi_util::{
    copy_bytes, mut_ref_from_ptr, mut_slice_from_ptr, ref_from_ptr, slice_from_ptr,
};
use crate::*;
use std::os::unix::fs::MetadataExt;

/// Mirrors core API version for Rust callers.
#[must_use]
pub fn ffi_api_version() -> u32 {
    FFI_API_VERSION
}

pub(super) fn net_epoll_conv_flags_impl(flags: i32) -> i32 {
    mtproxy_core::runtime::net::events::epoll_conv_flags(flags)
}

pub(super) fn net_epoll_unconv_flags_impl(epoll_flags: i32) -> i32 {
    mtproxy_core::runtime::net::events::epoll_unconv_flags(epoll_flags)
}

pub(super) fn net_timers_wait_msec_impl(wakeup_time: f64, now: f64) -> i32 {
    mtproxy_core::runtime::net::timers::wait_msec(wakeup_time, now)
}

pub(super) fn net_select_best_key_signature_impl(
    main_secret_len: i32,
    main_key_signature: i32,
    key_signature: i32,
    extra_key_signatures: &[i32],
) -> i32 {
    mtproxy_core::runtime::net::config::select_best_key_signature(
        main_secret_len,
        main_key_signature,
        key_signature,
        extra_key_signatures,
    )
}

pub(super) fn net_connection_is_active_impl(flags: i32) -> i32 {
    if mtproxy_core::runtime::net::connections::connection_is_active(flags) {
        1
    } else {
        0
    }
}

pub(super) fn net_compute_conn_events_impl(flags: i32, use_epollet: i32) -> i32 {
    mtproxy_core::runtime::net::connections::compute_conn_events(flags, use_epollet != 0)
}

pub(super) fn net_add_nat_info_impl(rule_text: &str) -> i32 {
    let Some((local, global)) = rule_text.rsplit_once(':') else {
        eprintln!("expected <local-addr>:<global-addr> in --nat-info");
        return -1;
    };
    let Ok(local_ip) = local.parse::<std::net::Ipv4Addr>() else {
        eprintln!("cannot translate host '{}' in --nat-info", local);
        return -1;
    };
    let Ok(global_ip) = global.parse::<std::net::Ipv4Addr>() else {
        eprintln!("cannot translate host '{}' in --nat-info", global);
        return -1;
    };
    match mtproxy_core::runtime::net::connections::nat_add_rule(
        u32::from(local_ip),
        u32::from(global_ip),
    ) {
        Ok(idx) => idx,
        Err(mtproxy_core::runtime::net::connections::NatAddRuleError::TooManyRules) => {
            eprintln!("too many rules in --nat-info");
            -1
        }
    }
}

pub(super) fn net_translate_ip_impl(local_ip: u32) -> u32 {
    mtproxy_core::runtime::net::connections::nat_translate_ip(local_ip)
}

pub(super) fn net_msg_tl_marker_kind_impl(marker: i32) -> i32 {
    mtproxy_core::runtime::net::msg::tl_string_marker_kind(marker)
}

pub(super) fn net_msg_tl_padding_impl(total_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::msg::tl_string_padding(total_bytes)
}

pub(super) fn net_msg_encrypt_decrypt_effective_bytes_impl(
    requested_bytes: i32,
    total_bytes: i32,
    block_size: i32,
) -> i32 {
    mtproxy_core::runtime::net::msg::encrypt_decrypt_effective_bytes(
        requested_bytes,
        total_bytes,
        block_size,
    )
}

pub(super) fn net_tcp_aes_aligned_len_impl(total_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::aes_aligned_len(total_bytes)
}

pub(super) fn net_tcp_aes_needed_output_bytes_impl(total_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::aes_needed_output_bytes(total_bytes)
}

pub(super) fn net_tcp_tls_encrypt_chunk_len_impl(total_bytes: i32, is_tls: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::tls_encrypt_chunk_len(total_bytes, is_tls != 0)
}

pub(super) fn net_tcp_tls_header_needed_bytes_impl(available: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::tls_header_needed_bytes(available)
}

pub(super) fn net_tcp_tls_parse_header_impl(header: &[u8; 5]) -> Result<i32, ()> {
    mtproxy_core::runtime::net::tcp_connections::tls_header_payload_len(header).ok_or(())
}

pub(super) fn net_tcp_tls_decrypt_chunk_len_impl(
    available: i32,
    left_tls_packet_length: i32,
) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::tls_decrypt_chunk_len(
        available,
        left_tls_packet_length,
    )
}

pub(super) fn net_tcp_reader_negative_skip_take_impl(skip_bytes: i32, available_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::reader_negative_skip_take(
        skip_bytes,
        available_bytes,
    )
}

pub(super) fn net_tcp_reader_negative_skip_next_impl(skip_bytes: i32, taken_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::reader_negative_skip_next(skip_bytes, taken_bytes)
}

pub(super) fn net_tcp_reader_positive_skip_next_impl(skip_bytes: i32, available_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::reader_positive_skip_next(
        skip_bytes,
        available_bytes,
    )
}

pub(super) fn net_tcp_reader_skip_from_parse_result_impl(
    parse_res: i32,
    buffered_bytes: i32,
    need_more_bytes: i32,
) -> Option<i32> {
    mtproxy_core::runtime::net::tcp_connections::reader_skip_from_parse_result(
        parse_res,
        buffered_bytes,
        need_more_bytes,
    )
}

pub(super) fn net_tcp_reader_precheck_result_impl(flags: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::reader_precheck_result(flags)
}

pub(super) fn net_tcp_reader_should_continue_impl(
    skip_bytes: i32,
    flags: i32,
    status_is_conn_error: i32,
) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::reader_should_continue(
        skip_bytes,
        flags,
        status_is_conn_error,
    )
}

pub(super) fn net_tcp_rpc_ext_domain_bucket_index_impl(domain: &[u8]) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_ext_server::domain_bucket_index(domain)
}

pub(super) fn net_tcp_rpc_ext_client_random_bucket_index_impl(random: &[u8; 16]) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_ext_server::client_random_bucket_index(random)
}

pub(super) fn net_tcp_rpc_ext_select_server_hello_profile_impl(
    min_len: i32,
    max_len: i32,
    sum_len: i32,
    sample_count: i32,
) -> Option<(i32, i32)> {
    mtproxy_core::runtime::net::tcp_rpc_ext_server::select_server_hello_profile(
        min_len,
        max_len,
        sum_len,
        sample_count,
    )
}

pub(super) fn net_stats_recent_idle_percent_impl(a_idle_time: f64, a_idle_quotient: f64) -> f64 {
    mtproxy_core::runtime::net::stats::recent_idle_percent(a_idle_time, a_idle_quotient)
}

pub(super) fn net_stats_average_idle_percent_impl(tot_idle_time: f64, uptime: i32) -> f64 {
    mtproxy_core::runtime::net::stats::average_idle_percent(tot_idle_time, uptime)
}

pub(super) type NetThreadRpcReadyFn = unsafe extern "C" fn(*mut c_void) -> i32;
pub(super) type NetThreadRpcFn = unsafe extern "C" fn(*mut c_void);
pub(super) type NetThreadFailConnectionFn = unsafe extern "C" fn(*mut c_void, i32);

pub(super) struct NetThreadCallbackOps {
    rpc_ready: NetThreadRpcReadyFn,
    rpc_close: NetThreadRpcFn,
    rpc_alarm: NetThreadRpcFn,
    rpc_wakeup: NetThreadRpcFn,
    fail_connection: NetThreadFailConnectionFn,
    job_decref: NetThreadRpcFn,
    event_free: NetThreadRpcFn,
}

impl mtproxy_core::runtime::net::thread::NotificationEventOps for NetThreadCallbackOps {
    fn rpc_ready(&mut self, who: *mut c_void) -> i32 {
        unsafe { (self.rpc_ready)(who) }
    }

    fn rpc_close(&mut self, who: *mut c_void) {
        unsafe { (self.rpc_close)(who) };
    }

    fn rpc_alarm(&mut self, who: *mut c_void) {
        unsafe { (self.rpc_alarm)(who) };
    }

    fn rpc_wakeup(&mut self, who: *mut c_void) {
        unsafe { (self.rpc_wakeup)(who) };
    }

    fn fail_connection(&mut self, who: *mut c_void, code: i32) {
        unsafe { (self.fail_connection)(who, code) };
    }

    fn job_decref(&mut self, who: *mut c_void) {
        unsafe { (self.job_decref)(who) };
    }

    fn free_event(&mut self, event: *mut c_void) {
        unsafe { (self.event_free)(event) };
    }
}

pub(super) fn net_thread_run_notification_event_impl(
    event_type: i32,
    who: *mut c_void,
    event: *mut c_void,
    rpc_ready: NetThreadRpcReadyFn,
    rpc_close: NetThreadRpcFn,
    rpc_alarm: NetThreadRpcFn,
    rpc_wakeup: NetThreadRpcFn,
    fail_connection: NetThreadFailConnectionFn,
    job_decref: NetThreadRpcFn,
    event_free: NetThreadRpcFn,
) -> i32 {
    let mut ops = NetThreadCallbackOps {
        rpc_ready,
        rpc_close,
        rpc_alarm,
        rpc_wakeup,
        fail_connection,
        job_decref,
        event_free,
    };
    match mtproxy_core::runtime::net::thread::run_notification_event(
        event_type, who, event, &mut ops,
    ) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

pub(super) fn net_http_error_msg_text_impl(code: i32) -> (i32, *const c_char) {
    let (normalized_code, message) =
        mtproxy_core::runtime::net::http_server::http_error_msg_text(code);
    (normalized_code, message.as_ptr().cast::<c_char>())
}

pub(super) fn net_http_gen_date_impl(time: i32) -> [u8; 29] {
    mtproxy_core::runtime::net::http_server::gen_http_date(time)
}

pub(super) fn net_http_gen_time_impl(date_text: &str) -> Result<i32, i32> {
    mtproxy_core::runtime::net::http_server::gen_http_time(date_text)
}

pub(super) fn net_http_get_header_impl(headers: &[u8], out: &mut [u8], arg_name: &[u8]) -> i32 {
    let Some(value) =
        mtproxy_core::runtime::net::http_server::get_http_header_value(headers, arg_name)
    else {
        out[0] = 0;
        return -1;
    };

    let max_copy = out.len().saturating_sub(1);
    let copy_len = core::cmp::min(value.len(), max_copy);
    out[..copy_len].copy_from_slice(&value[..copy_len]);
    out[copy_len] = 0;
    i32::try_from(copy_len).unwrap_or(i32::MAX)
}

pub(super) fn msg_buffers_pick_size_index_impl(buffer_sizes: &[i32], size_hint: i32) -> i32 {
    mtproxy_core::runtime::net::msg_buffers::pick_size_index(buffer_sizes, size_hint)
}

pub(super) fn tcp_rpc_encode_compact_header_impl(payload_len: i32, is_medium: i32) -> (i32, i32) {
    mtproxy_core::runtime::net::tcp_rpc_common::encode_compact_header(payload_len, is_medium)
}

pub(super) fn tcp_rpc_decode_compact_header_impl(
    first_byte: u8,
    remaining_bytes: Option<[u8; 3]>,
) -> Option<(i32, i32)> {
    mtproxy_core::runtime::net::tcp_rpc_common::decode_compact_header(first_byte, remaining_bytes)
}

pub(super) fn tcp_rpc_client_packet_len_state_impl(packet_len: i32, max_packet_len: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_client::packet_len_state(packet_len, max_packet_len)
}

pub(super) fn tcp_rpc_server_packet_header_malformed_impl(packet_len: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_server::packet_header_malformed(packet_len)
}

pub(super) fn tcp_rpc_server_packet_len_state_impl(packet_len: i32, max_packet_len: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_server::packet_len_state(packet_len, max_packet_len)
}

const RPC_PACKET_PING: i32 = i32::from_ne_bytes(0x5730_a2df_u32.to_ne_bytes());
const RPC_PACKET_PONG: i32 = i32::from_ne_bytes(0x8430_eaa7_u32.to_ne_bytes());
const RPCF_ALLOW_UNENC: i32 = 1;
const RPCF_ALLOW_ENC: i32 = 2;
const RPCF_REQ_DH: i32 = 4;
const RPCF_ALLOW_SKIP_DH: i32 = 8;
const RPCF_ENC_SENT: i32 = 16;
const RPCF_QUICKACK: i32 = 512;
const RPCF_USE_CRC32C: i32 = 2048;

fn process_id_from_ffi(pid: &MtproxyProcessId) -> mtproxy_core::runtime::net::tcp_rpc_common::ProcessId {
    mtproxy_core::runtime::net::tcp_rpc_common::ProcessId {
        ip: pid.ip,
        port: pid.port,
        pid: pid.pid,
        utime: pid.utime,
    }
}

pub(super) fn tcp_rpc_server_default_execute_should_pong_impl(op: i32, raw_total_bytes: i32) -> i32 {
    i32::from(op == RPC_PACKET_PING && raw_total_bytes == 12)
}

pub(super) fn tcp_rpc_server_default_execute_set_pong_impl(packet_words: &mut [i32; 3]) {
    packet_words[0] = RPC_PACKET_PONG;
}

pub(super) fn tcp_rpc_server_build_handshake_packet_impl(
    crypto_flags: i32,
    sender_pid: &MtproxyProcessId,
    peer_pid: &MtproxyProcessId,
    out_packet: &mut [u8],
) -> i32 {
    use mtproxy_core::runtime::net::tcp_rpc_common::{HandshakePacket, PacketSerialization};

    let packet = HandshakePacket::new(
        crypto_flags & RPCF_USE_CRC32C,
        process_id_from_ffi(sender_pid),
        process_id_from_ffi(peer_pid),
    );
    let bytes = packet.to_bytes();
    if out_packet.len() < bytes.len() {
        return -1;
    }
    out_packet[..bytes.len()].copy_from_slice(bytes);
    i32::try_from(bytes.len()).unwrap_or(i32::MAX)
}

pub(super) fn tcp_rpc_server_build_handshake_error_packet_impl(
    error_code: i32,
    sender_pid: &MtproxyProcessId,
    out_packet: &mut [u8],
) -> i32 {
    use mtproxy_core::runtime::net::tcp_rpc_common::HandshakeErrorPacket;

    let packet = HandshakeErrorPacket::new(error_code, process_id_from_ffi(sender_pid));
    let bytes = packet.to_bytes();
    if out_packet.len() < bytes.len() {
        return -1;
    }
    out_packet[..bytes.len()].copy_from_slice(bytes);
    i32::try_from(bytes.len()).unwrap_or(i32::MAX)
}

pub(super) fn tcp_rpc_server_validate_handshake_header_impl(
    packet_num: i32,
    packet_type: i32,
    packet_len: i32,
    handshake_packet_len: i32,
) -> i32 {
    if packet_num != -1
        || packet_type != mtproxy_core::runtime::net::tcp_rpc_common::RpcPacketType::Handshake as i32
    {
        return -2;
    }
    if packet_len != handshake_packet_len {
        return -3;
    }
    0
}

pub(super) fn tcp_rpc_server_validate_handshake_impl(
    packet_flags: i32,
    peer_pid_matches: i32,
    ignore_pid: i32,
    default_rpc_flags: i32,
    out_enable_crc32c: &mut i32,
) -> i32 {
    if peer_pid_matches == 0 && ignore_pid == 0 {
        return -4;
    }
    if (packet_flags & 0xff) != 0 {
        return -7;
    }
    *out_enable_crc32c =
        i32::from((packet_flags & default_rpc_flags & RPCF_USE_CRC32C) != 0);
    0
}

pub(super) fn tcp_rpc_server_validate_nonce_header_impl(
    packet_num: i32,
    packet_type: i32,
    packet_len: i32,
    nonce_packet_min_len: i32,
    nonce_packet_max_len: i32,
) -> i32 {
    if packet_num != -2
        || packet_type != mtproxy_core::runtime::net::tcp_rpc_common::RpcPacketType::Nonce as i32
    {
        return -2;
    }
    if packet_len < nonce_packet_min_len || packet_len > nonce_packet_max_len {
        return -3;
    }
    0
}

pub(super) fn tcp_rpc_server_should_notify_close_impl(has_rpc_close: i32) -> i32 {
    i32::from(has_rpc_close != 0)
}

pub(super) fn tcp_rpc_server_do_wakeup_impl() -> i32 {
    0
}

pub(super) fn tcp_rpc_server_should_set_wantwr_impl(out_total_bytes: i32) -> i32 {
    i32::from(out_total_bytes > 0)
}

pub(super) fn tcp_rpc_server_notification_pending_queries_impl() -> i32 {
    0
}

pub(super) fn tcp_rpc_server_init_accepted_state_impl(
    has_perm_callback: i32,
    perm_flags: i32,
    out_crypto_flags: &mut i32,
    out_in_packet_num: &mut i32,
    out_out_packet_num: &mut i32,
) -> i32 {
    if has_perm_callback != 0 {
        let masked =
            perm_flags & (RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC | RPCF_REQ_DH | RPCF_ALLOW_SKIP_DH);
        if (masked & (RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC)) == 0 {
            return -1;
        }
        *out_crypto_flags = masked;
    } else {
        *out_crypto_flags = RPCF_ALLOW_UNENC;
    }
    *out_in_packet_num = -2;
    *out_out_packet_num = -2;
    0
}

pub(super) fn tcp_rpc_server_init_accepted_nohs_state_impl(
    out_crypto_flags: &mut i32,
    out_in_packet_num: &mut i32,
) -> i32 {
    *out_crypto_flags = RPCF_QUICKACK | RPCF_ALLOW_UNENC;
    *out_in_packet_num = -3;
    0
}

pub(super) fn tcp_rpc_server_init_fake_crypto_state_impl(
    crypto_flags: i32,
    out_crypto_flags: &mut i32,
) -> i32 {
    if (crypto_flags & RPCF_ALLOW_UNENC) == 0 {
        return -1;
    }
    if (crypto_flags & (RPCF_ALLOW_ENC | RPCF_ENC_SENT)) != 0 {
        return -1;
    }
    *out_crypto_flags = crypto_flags | RPCF_ENC_SENT;
    1
}

pub(super) fn tcp_rpc_server_default_check_perm_impl(default_rpc_flags: i32) -> i32 {
    RPCF_ALLOW_ENC | RPCF_REQ_DH | default_rpc_flags
}

pub(super) fn tcp_rpc_parse_nonce_packet_impl(
    packet: &[u8],
    out_schema: &mut i32,
    out_key_select: &mut i32,
    out_crypto_ts: &mut i32,
    out_nonce: &mut [u8; 16],
    out_extra_keys_count: &mut i32,
    out_extra_key_signatures: &mut [i32],
    out_dh_params_select: &mut i32,
    out_has_dh_params: &mut i32,
) -> i32 {
    let Some(parsed) = mtproxy_core::runtime::net::tcp_rpc_common::parse_nonce_packet(packet)
    else {
        return -1;
    };

    let extra_keys_count = parsed.extra_keys_count;
    let expected_extra = match usize::try_from(extra_keys_count) {
        Ok(count) => count,
        Err(_) => return -2,
    };
    if expected_extra > out_extra_key_signatures.len() {
        return -2;
    }

    *out_schema = parsed.crypto_schema.to_i32();
    *out_key_select = parsed.key_select;
    *out_crypto_ts = parsed.crypto_ts;
    out_nonce.copy_from_slice(&parsed.crypto_nonce);
    *out_extra_keys_count = extra_keys_count;
    *out_dh_params_select = parsed.dh_params_select;
    *out_has_dh_params = if parsed.has_dh_params { 1 } else { 0 };
    for (dst, value) in out_extra_key_signatures
        .iter_mut()
        .zip(parsed.extra_key_select.iter().take(expected_extra))
    {
        *dst = *value;
    }
    0
}

pub(super) fn tcp_rpc_client_process_nonce_packet_impl(
    packet: &[u8],
    allow_unencrypted: i32,
    allow_encrypted: i32,
    require_dh: i32,
    has_crypto_temp: i32,
    nonce_time: i32,
    main_secret_len: i32,
    main_key_signature: i32,
    out_schema: &mut i32,
    out_key_select: &mut i32,
    out_has_dh_params: &mut i32,
) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_client::process_nonce_packet_for_compat(
        packet,
        allow_unencrypted != 0,
        allow_encrypted != 0,
        require_dh != 0,
        has_crypto_temp != 0,
        nonce_time,
        main_secret_len,
        main_key_signature,
        out_schema,
        out_key_select,
        out_has_dh_params,
    )
}

pub(super) fn tcp_rpc_server_process_nonce_packet_impl(
    packet: &[u8],
    allow_unencrypted: i32,
    allow_encrypted: i32,
    now_ts: i32,
    main_secret_len: i32,
    main_key_signature: i32,
    out_schema: &mut i32,
    out_key_select: &mut i32,
    out_has_dh_params: &mut i32,
) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_server::process_nonce_packet_for_compat(
        packet,
        allow_unencrypted != 0,
        allow_encrypted != 0,
        now_ts,
        main_secret_len,
        main_key_signature,
        out_schema,
        out_key_select,
        out_has_dh_params,
    )
}

pub(super) fn tcp_rpc_parse_handshake_packet_impl(
    packet: &[u8],
    out_flags: &mut i32,
    out_sender_pid: &mut MtproxyProcessId,
    out_peer_pid: &mut MtproxyProcessId,
) -> i32 {
    let Some(parsed) = mtproxy_core::runtime::net::tcp_rpc_common::parse_handshake_packet(packet)
    else {
        return -1;
    };

    *out_flags = parsed.flags;
    *out_sender_pid = MtproxyProcessId {
        ip: parsed.sender_pid.ip,
        port: parsed.sender_pid.port,
        pid: parsed.sender_pid.pid,
        utime: parsed.sender_pid.utime,
    };
    *out_peer_pid = MtproxyProcessId {
        ip: parsed.peer_pid.ip,
        port: parsed.peer_pid.port,
        pid: parsed.peer_pid.pid,
        utime: parsed.peer_pid.utime,
    };
    0
}

pub(super) unsafe fn tcp_rpc_parse_nonce_packet_ffi(
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
    let Some(out_nonce_out) = (unsafe { mut_ref_from_ptr(out_nonce.cast::<[u8; 16]>()) }) else {
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

pub(super) unsafe fn tcp_rpc_client_process_nonce_packet_ffi(
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

pub(super) unsafe fn tcp_rpc_server_process_nonce_packet_ffi(
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

pub(super) unsafe fn tcp_rpc_parse_handshake_packet_ffi(
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

pub(super) unsafe fn tcp_rpc_server_default_execute_set_pong_ffi(
    packet_words: *mut i32,
    packet_words_len: i32,
) -> i32 {
    if packet_words_len != 3 {
        return -1;
    }
    let Some(packet_words_ref) = (unsafe { mut_ref_from_ptr(packet_words.cast::<[i32; 3]>()) })
    else {
        return -1;
    };
    tcp_rpc_server_default_execute_set_pong_impl(packet_words_ref);
    0
}

pub(super) unsafe fn tcp_rpc_server_build_handshake_packet_ffi(
    crypto_flags: i32,
    sender_pid: *const MtproxyProcessId,
    peer_pid: *const MtproxyProcessId,
    out_packet: *mut u8,
    out_packet_len: i32,
) -> i32 {
    let Ok(out_len) = usize::try_from(out_packet_len) else {
        return -1;
    };
    let Some(sender_pid_ref) = (unsafe { ref_from_ptr(sender_pid) }) else {
        return -1;
    };
    let Some(peer_pid_ref) = (unsafe { ref_from_ptr(peer_pid) }) else {
        return -1;
    };
    let Some(out_packet_ref) = (unsafe { mut_slice_from_ptr(out_packet, out_len) }) else {
        return -1;
    };
    tcp_rpc_server_build_handshake_packet_impl(
        crypto_flags,
        sender_pid_ref,
        peer_pid_ref,
        out_packet_ref,
    )
}

pub(super) unsafe fn tcp_rpc_server_build_handshake_error_packet_ffi(
    error_code: i32,
    sender_pid: *const MtproxyProcessId,
    out_packet: *mut u8,
    out_packet_len: i32,
) -> i32 {
    let Ok(out_len) = usize::try_from(out_packet_len) else {
        return -1;
    };
    let Some(sender_pid_ref) = (unsafe { ref_from_ptr(sender_pid) }) else {
        return -1;
    };
    let Some(out_packet_ref) = (unsafe { mut_slice_from_ptr(out_packet, out_len) }) else {
        return -1;
    };
    tcp_rpc_server_build_handshake_error_packet_impl(error_code, sender_pid_ref, out_packet_ref)
}

pub(super) unsafe fn tcp_rpc_server_validate_handshake_ffi(
    packet_flags: i32,
    peer_pid_matches: i32,
    ignore_pid: i32,
    default_rpc_flags: i32,
    out_enable_crc32c: *mut i32,
) -> i32 {
    let Some(enable_crc32c_ref) = (unsafe { mut_ref_from_ptr(out_enable_crc32c) }) else {
        return -1;
    };
    tcp_rpc_server_validate_handshake_impl(
        packet_flags,
        peer_pid_matches,
        ignore_pid,
        default_rpc_flags,
        enable_crc32c_ref,
    )
}

pub(super) unsafe fn tcp_rpc_server_init_accepted_state_ffi(
    has_perm_callback: i32,
    perm_flags: i32,
    out_crypto_flags: *mut i32,
    out_in_packet_num: *mut i32,
    out_out_packet_num: *mut i32,
) -> i32 {
    let Some(out_crypto_flags_ref) = (unsafe { mut_ref_from_ptr(out_crypto_flags) }) else {
        return -1;
    };
    let Some(out_in_packet_num_ref) = (unsafe { mut_ref_from_ptr(out_in_packet_num) }) else {
        return -1;
    };
    let Some(out_out_packet_num_ref) = (unsafe { mut_ref_from_ptr(out_out_packet_num) }) else {
        return -1;
    };
    tcp_rpc_server_init_accepted_state_impl(
        has_perm_callback,
        perm_flags,
        out_crypto_flags_ref,
        out_in_packet_num_ref,
        out_out_packet_num_ref,
    )
}

pub(super) unsafe fn tcp_rpc_server_init_accepted_nohs_state_ffi(
    out_crypto_flags: *mut i32,
    out_in_packet_num: *mut i32,
) -> i32 {
    let Some(out_crypto_flags_ref) = (unsafe { mut_ref_from_ptr(out_crypto_flags) }) else {
        return -1;
    };
    let Some(out_in_packet_num_ref) = (unsafe { mut_ref_from_ptr(out_in_packet_num) }) else {
        return -1;
    };
    tcp_rpc_server_init_accepted_nohs_state_impl(out_crypto_flags_ref, out_in_packet_num_ref)
}

pub(super) unsafe fn tcp_rpc_server_init_fake_crypto_state_ffi(
    crypto_flags: i32,
    out_crypto_flags: *mut i32,
) -> i32 {
    let Some(out_crypto_flags_ref) = (unsafe { mut_ref_from_ptr(out_crypto_flags) }) else {
        return -1;
    };
    tcp_rpc_server_init_fake_crypto_state_impl(crypto_flags, out_crypto_flags_ref)
}

pub(super) fn rpc_target_normalize_pid_impl(pid: &mut MtproxyProcessId, default_ip: u32) {
    let mut core_pid = mtproxy_core::runtime::net::rpc_targets::ProcessId {
        ip: pid.ip,
        port: pid.port,
        pid: pid.pid,
        utime: pid.utime,
    };
    mtproxy_core::runtime::net::rpc_targets::normalize_pid(&mut core_pid, default_ip);
    pid.ip = core_pid.ip;
    pid.port = core_pid.port;
    pid.pid = core_pid.pid;
    pid.utime = core_pid.utime;
}

pub(super) type EngineNetTryOpenPortFn = unsafe extern "C" fn(i32, *mut c_void) -> i32;
pub(super) type EngineSignalDispatchFn = unsafe extern "C" fn(i32, *mut c_void);

pub(super) fn engine_rpc_common_default_query_type_mask_impl() -> i32 {
    mtproxy_core::runtime::engine::rpc_common::default_query_type_mask()
}

pub(super) fn engine_rpc_common_default_parse_decision_impl(actor_id: i64, op: i32) -> i32 {
    match mtproxy_core::runtime::engine::rpc_common::default_parse_decision(actor_id, op) {
        mtproxy_core::runtime::engine::rpc_common::DefaultParseDecision::None => 0,
        mtproxy_core::runtime::engine::rpc_common::DefaultParseDecision::Stat => 1,
        mtproxy_core::runtime::engine::rpc_common::DefaultParseDecision::Nop => 2,
    }
}

pub(super) fn engine_rpc_query_result_type_id_from_qid_impl(qid: i64) -> i32 {
    mtproxy_core::runtime::engine::rpc::query_result_type_id_from_qid(qid)
}

pub(super) fn engine_rpc_query_result_dispatch_decision_impl(
    has_table: i32,
    has_handler: i32,
) -> i32 {
    match mtproxy_core::runtime::engine::rpc::query_result_dispatch_decision(
        has_table != 0,
        has_handler != 0,
    ) {
        mtproxy_core::runtime::engine::rpc::QueryResultDispatchDecision::IgnoreNoTable => 0,
        mtproxy_core::runtime::engine::rpc::QueryResultDispatchDecision::Dispatch => 1,
        mtproxy_core::runtime::engine::rpc::QueryResultDispatchDecision::SkipUnknown => 2,
    }
}

pub(super) fn engine_rpc_need_dup_impl(flags: i32) -> i32 {
    if mtproxy_core::runtime::engine::rpc::act_extra_need_dup(flags) {
        1
    } else {
        0
    }
}

pub(super) fn engine_rpc_query_job_dispatch_decision_impl(op: i32, has_custom_tree: i32) -> i32 {
    match mtproxy_core::runtime::engine::rpc::query_job_dispatch_decision(op, has_custom_tree != 0)
    {
        mtproxy_core::runtime::engine::rpc::QueryJobDispatchDecision::InvokeParse => 0,
        mtproxy_core::runtime::engine::rpc::QueryJobDispatchDecision::Custom => 1,
        mtproxy_core::runtime::engine::rpc::QueryJobDispatchDecision::Ignore => 2,
    }
}

pub(super) fn engine_rpc_tcp_should_hold_conn_impl(op: i32) -> i32 {
    if mtproxy_core::runtime::engine::rpc::tcp_op_should_hold_conn(op) {
        1
    } else {
        0
    }
}

pub(super) fn engine_net_default_port_mod_impl() -> i32 {
    mtproxy_core::runtime::engine::net::DEFAULT_PORT_MOD
}

pub(super) fn engine_net_try_open_port_range_impl(
    start_port: i32,
    end_port: i32,
    mod_port: i32,
    rem_port: i32,
    quit_on_fail: bool,
    try_open: Option<EngineNetTryOpenPortFn>,
    try_open_ctx: *mut c_void,
) -> Result<Option<i32>, ()> {
    let Some(try_open_fn) = try_open else {
        return Err(());
    };
    mtproxy_core::runtime::engine::net::try_open_port_range_with(
        start_port,
        end_port,
        mod_port,
        rem_port,
        quit_on_fail,
        |port| unsafe { try_open_fn(port, try_open_ctx) != 0 },
    )
    .map_err(|_| ())
}

pub(super) fn engine_net_open_privileged_port_impl(
    port: i32,
    start_port: i32,
    end_port: i32,
    port_mod: i32,
    tcp_enabled: bool,
    quit_on_fail: bool,
    try_open: Option<EngineNetTryOpenPortFn>,
    try_open_ctx: *mut c_void,
) -> Result<Option<i32>, ()> {
    let Some(try_open_fn) = try_open else {
        return Err(());
    };
    mtproxy_core::runtime::engine::net::open_privileged_port_with(
        port,
        start_port,
        end_port,
        port_mod,
        tcp_enabled,
        quit_on_fail,
        |candidate| unsafe { try_open_fn(candidate, try_open_ctx) != 0 },
    )
    .map_err(|_| ())
}

pub(super) fn engine_signal_set_pending_impl(sig: i32) {
    let Ok(sig_u32) = u32::try_from(sig) else {
        return;
    };
    mtproxy_core::runtime::engine::signals::signal_set_pending(sig_u32);
}

pub(super) fn engine_signal_check_pending_impl(sig: i32) -> i32 {
    let Ok(sig_u32) = u32::try_from(sig) else {
        return 0;
    };
    if mtproxy_core::runtime::engine::signals::signal_check_pending(sig_u32) {
        1
    } else {
        0
    }
}

pub(super) fn engine_signal_check_pending_and_clear_impl(sig: i32) -> i32 {
    let Ok(sig_u32) = u32::try_from(sig) else {
        return 0;
    };
    if mtproxy_core::runtime::engine::signals::signal_check_pending_and_clear(sig_u32) {
        1
    } else {
        0
    }
}

pub(super) fn engine_interrupt_signal_raised_impl() -> i32 {
    if mtproxy_core::runtime::engine::signals::interrupt_signal_raised() {
        1
    } else {
        0
    }
}

pub(super) fn engine_process_signals_allowed_impl(
    allowed_signals: u64,
    dispatch: Option<EngineSignalDispatchFn>,
    dispatch_ctx: *mut c_void,
) -> i32 {
    let processed = mtproxy_core::runtime::engine::signals::engine_process_signals_allowed_with(
        allowed_signals,
        |sig| {
            if let Some(dispatch_fn) = dispatch {
                let Ok(sig_i32) = i32::try_from(sig) else {
                    return;
                };
                unsafe {
                    dispatch_fn(sig_i32, dispatch_ctx);
                }
            }
        },
    );
    i32::try_from(processed).unwrap_or(i32::MAX)
}

pub(super) fn engine_rpc_result_new_flags_impl(old_flags: i32) -> i32 {
    old_flags & 0xffff
}

pub(super) fn engine_rpc_result_header_len_impl(flags: i32) -> i32 {
    if flags == 0 {
        0
    } else {
        8
    }
}

pub(super) fn mtproto_conn_tag_impl(generation: i32) -> i32 {
    mtproxy_core::runtime::mtproto::proxy::mtproto_conn_tag(generation)
}

pub(super) fn mtproto_ext_conn_hash_impl(in_fd: i32, in_conn_id: i64, hash_shift: i32) -> i32 {
    mtproxy_core::runtime::mtproto::proxy::mtproto_ext_conn_hash(in_fd, in_conn_id, hash_shift)
}

pub(super) const RESOLVER_LOOKUP_SYSTEM_DNS: i32 = 0;
pub(super) const RESOLVER_LOOKUP_NOT_FOUND: i32 = 1;
pub(super) const RESOLVER_LOOKUP_HOSTS_IPV4: i32 = 2;

pub(super) static RESOLVER_STATE: Mutex<mtproxy_core::runtime::net::resolver::ResolverState> =
    Mutex::new(mtproxy_core::runtime::net::resolver::ResolverState::new());

pub(super) fn resolver_reload_hosts_from_system(
    state: &mut mtproxy_core::runtime::net::resolver::ResolverState,
) -> i32 {
    let Ok(metadata) = fs::metadata(mtproxy_core::runtime::net::resolver::HOSTS_FILE) else {
        return state.kdb_load_hosts(mtproxy_core::runtime::net::resolver::HostsLoadInput::Error);
    };
    if !metadata.is_file() {
        return state.kdb_load_hosts(mtproxy_core::runtime::net::resolver::HostsLoadInput::Error);
    }

    let Ok(size) = i64::try_from(metadata.len()) else {
        return state.kdb_load_hosts(mtproxy_core::runtime::net::resolver::HostsLoadInput::Error);
    };
    let Ok(contents) = fs::read(mtproxy_core::runtime::net::resolver::HOSTS_FILE) else {
        return state.kdb_load_hosts(mtproxy_core::runtime::net::resolver::HostsLoadInput::Error);
    };
    let Ok(mtime) = i32::try_from(metadata.mtime()) else {
        return state.kdb_load_hosts(mtproxy_core::runtime::net::resolver::HostsLoadInput::Error);
    };
    let meta = mtproxy_core::runtime::net::resolver::HostsFileMetadata { size, mtime };
    state.kdb_load_hosts(mtproxy_core::runtime::net::resolver::HostsLoadInput::Data {
        metadata: meta,
        contents: &contents,
    })
}

pub(super) fn resolver_kdb_load_hosts_impl() -> i32 {
    let mut state = RESOLVER_STATE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    resolver_reload_hosts_from_system(&mut state)
}

pub(super) fn resolver_kdb_hosts_loaded_impl() -> i32 {
    let state = RESOLVER_STATE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    state.kdb_hosts_loaded()
}

pub(super) fn resolver_gethostbyname_plan_impl(name: &[u8]) -> (i32, u32) {
    let mut state = RESOLVER_STATE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let plan = state.kdb_gethostbyname_plan_with_lazy_load(name, |resolver| {
        let _ = resolver_reload_hosts_from_system(resolver);
    });
    match plan {
        mtproxy_core::runtime::net::resolver::HostLookupPlan::SystemDns(_)
        | mtproxy_core::runtime::net::resolver::HostLookupPlan::Ipv6Literal(_) => {
            (RESOLVER_LOOKUP_SYSTEM_DNS, 0)
        }
        mtproxy_core::runtime::net::resolver::HostLookupPlan::NotFound => {
            (RESOLVER_LOOKUP_NOT_FOUND, 0)
        }
        mtproxy_core::runtime::net::resolver::HostLookupPlan::HostsIpv4(ip) => {
            (RESOLVER_LOOKUP_HOSTS_IPV4, ip)
        }
    }
}

pub(super) fn startup_handshake_impl(expected_api_version: u32) -> i32 {
    if expected_api_version == FFI_API_VERSION {
        0
    } else {
        -1
    }
}

fn concurrency_boundary() -> MtproxyConcurrencyBoundary {
    MtproxyConcurrencyBoundary {
        boundary_version: CONCURRENCY_BOUNDARY_VERSION,
        mpq_contract_ops: MPQ_CONTRACT_OPS,
        mpq_implemented_ops: MPQ_IMPLEMENTED_OPS,
        jobs_contract_ops: JOBS_CONTRACT_OPS,
        jobs_implemented_ops: JOBS_IMPLEMENTED_OPS,
    }
}

fn network_boundary() -> MtproxyNetworkBoundary {
    MtproxyNetworkBoundary {
        boundary_version: NETWORK_BOUNDARY_VERSION,
        net_events_contract_ops: NET_EVENTS_CONTRACT_OPS,
        net_events_implemented_ops: NET_EVENTS_IMPLEMENTED_OPS,
        net_timers_contract_ops: NET_TIMERS_CONTRACT_OPS,
        net_timers_implemented_ops: NET_TIMERS_IMPLEMENTED_OPS,
        net_msg_buffers_contract_ops: NET_MSG_BUFFERS_CONTRACT_OPS,
        net_msg_buffers_implemented_ops: NET_MSG_BUFFERS_IMPLEMENTED_OPS,
    }
}

fn rpc_boundary() -> MtproxyRpcBoundary {
    MtproxyRpcBoundary {
        boundary_version: RPC_BOUNDARY_VERSION,
        tcp_rpc_common_contract_ops: TCP_RPC_COMMON_CONTRACT_OPS,
        tcp_rpc_common_implemented_ops: TCP_RPC_COMMON_IMPLEMENTED_OPS,
        tcp_rpc_client_contract_ops: TCP_RPC_CLIENT_CONTRACT_OPS,
        tcp_rpc_client_implemented_ops: TCP_RPC_CLIENT_IMPLEMENTED_OPS,
        tcp_rpc_server_contract_ops: TCP_RPC_SERVER_CONTRACT_OPS,
        tcp_rpc_server_implemented_ops: TCP_RPC_SERVER_IMPLEMENTED_OPS,
        rpc_targets_contract_ops: RPC_TARGETS_CONTRACT_OPS,
        rpc_targets_implemented_ops: RPC_TARGETS_IMPLEMENTED_OPS,
    }
}

fn crypto_boundary() -> MtproxyCryptoBoundary {
    MtproxyCryptoBoundary {
        boundary_version: CRYPTO_BOUNDARY_VERSION,
        net_crypto_aes_contract_ops: NET_CRYPTO_AES_CONTRACT_OPS,
        net_crypto_aes_implemented_ops: NET_CRYPTO_AES_IMPLEMENTED_OPS,
        net_crypto_dh_contract_ops: NET_CRYPTO_DH_CONTRACT_OPS,
        net_crypto_dh_implemented_ops: NET_CRYPTO_DH_IMPLEMENTED_OPS,
        aesni_contract_ops: AESNI_CONTRACT_OPS,
        aesni_implemented_ops: AESNI_IMPLEMENTED_OPS,
    }
}

fn application_boundary() -> MtproxyApplicationBoundary {
    MtproxyApplicationBoundary {
        boundary_version: APPLICATION_BOUNDARY_VERSION,
        engine_rpc_contract_ops: ENGINE_RPC_CONTRACT_OPS,
        engine_rpc_implemented_ops: ENGINE_RPC_IMPLEMENTED_OPS,
        mtproto_proxy_contract_ops: MTPROTO_PROXY_CONTRACT_OPS,
        mtproto_proxy_implemented_ops: MTPROTO_PROXY_IMPLEMENTED_OPS,
    }
}

pub(super) unsafe fn get_concurrency_boundary_ffi(out: *mut MtproxyConcurrencyBoundary) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    *out_ref = concurrency_boundary();
    0
}

pub(super) unsafe fn get_network_boundary_ffi(out: *mut MtproxyNetworkBoundary) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    *out_ref = network_boundary();
    0
}

pub(super) unsafe fn get_rpc_boundary_ffi(out: *mut MtproxyRpcBoundary) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    *out_ref = rpc_boundary();
    0
}

pub(super) unsafe fn get_crypto_boundary_ffi(out: *mut MtproxyCryptoBoundary) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    *out_ref = crypto_boundary();
    0
}

pub(super) unsafe fn get_application_boundary_ffi(out: *mut MtproxyApplicationBoundary) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    *out_ref = application_boundary();
    0
}

pub(super) unsafe fn resolver_gethostbyname_plan_ffi(
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

pub(super) unsafe fn net_select_best_key_signature_ffi(
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

pub(super) unsafe fn net_add_nat_info_ffi(rule_text: *const c_char) -> i32 {
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

pub(super) unsafe fn net_tcp_tls_parse_header_ffi(
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

pub(super) unsafe fn net_tcp_reader_skip_from_parse_result_ffi(
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

pub(super) unsafe fn net_tcp_rpc_ext_domain_bucket_index_ffi(domain: *const u8, len: i32) -> i32 {
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

pub(super) unsafe fn net_tcp_rpc_ext_client_random_bucket_index_ffi(random: *const u8) -> i32 {
    let Some(random_buf) = (unsafe { copy_bytes::<16>(random) }) else {
        return -1;
    };
    net_tcp_rpc_ext_client_random_bucket_index_impl(&random_buf)
}

pub(super) unsafe fn net_tcp_rpc_ext_select_server_hello_profile_ffi(
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

pub(super) unsafe fn net_thread_run_notification_event_ffi(
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

pub(super) unsafe fn net_http_error_msg_text_ffi(code: *mut i32) -> *const c_char {
    let Some(code_ref) = (unsafe { mut_ref_from_ptr(code) }) else {
        return core::ptr::null();
    };
    let in_code = *code_ref;
    let (normalized_code, message_ptr) = net_http_error_msg_text_impl(in_code);
    *code_ref = normalized_code;
    message_ptr
}

pub(super) unsafe fn net_http_gen_date_ffi(out: *mut c_char, out_len: i32, time: i32) -> i32 {
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

pub(super) unsafe fn net_http_gen_time_ffi(date_text: *const c_char, out_time: *mut i32) -> i32 {
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

pub(super) unsafe fn net_http_get_header_ffi(
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

pub(super) unsafe fn msg_buffers_pick_size_index_ffi(
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

pub(super) unsafe fn tcp_rpc_encode_compact_header_ffi(
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

pub(super) unsafe fn tcp_rpc_decode_compact_header_ffi(
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
        let Some(arr) = (unsafe { copy_bytes::<3>(remaining_bytes) }) else {
            return -1;
        };
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

pub(super) unsafe fn rpc_target_normalize_pid_ffi(
    pid: *mut MtproxyProcessId,
    default_ip: u32,
) -> i32 {
    let Some(pid_ref) = (unsafe { mut_ref_from_ptr(pid) }) else {
        return -1;
    };
    rpc_target_normalize_pid_impl(pid_ref, default_ip);
    0
}

pub(super) unsafe fn engine_net_try_open_port_range_ffi(
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

pub(super) unsafe fn engine_net_open_privileged_port_ffi(
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
