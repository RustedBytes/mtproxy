use crate::*;
pub(super) use crate::ffi_util::{
    copy_bytes, mut_ref_from_ptr, mut_slice_from_ptr, ref_from_ptr, slice_from_ptr,
};
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

pub(super) fn net_tcp_tls_decrypt_chunk_len_impl(available: i32, left_tls_packet_length: i32) -> i32 {
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

pub(super) fn tcp_rpc_client_packet_len_state_impl(packet_len: i32, max_packet_len: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_client::packet_len_state(packet_len, max_packet_len)
}

pub(super) fn tcp_rpc_server_packet_header_malformed_impl(packet_len: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_server::packet_header_malformed(packet_len)
}

pub(super) fn tcp_rpc_server_packet_len_state_impl(packet_len: i32, max_packet_len: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_server::packet_len_state(packet_len, max_packet_len)
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

pub(super) fn engine_rpc_query_result_dispatch_decision_impl(has_table: i32, has_handler: i32) -> i32 {
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
