use super::*;
use std::os::unix::fs::MetadataExt;

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
    mtproxy_core::runtime::net::events::epoll_conv_flags(flags)
}

fn net_epoll_unconv_flags_impl(epoll_flags: i32) -> i32 {
    mtproxy_core::runtime::net::events::epoll_unconv_flags(epoll_flags)
}

fn net_timers_wait_msec_impl(wakeup_time: f64, now: f64) -> i32 {
    mtproxy_core::runtime::net::timers::wait_msec(wakeup_time, now)
}

fn net_select_best_key_signature_impl(
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

fn net_connection_is_active_impl(flags: i32) -> i32 {
    if mtproxy_core::runtime::net::connections::connection_is_active(flags) {
        1
    } else {
        0
    }
}

fn net_compute_conn_events_impl(flags: i32, use_epollet: i32) -> i32 {
    mtproxy_core::runtime::net::connections::compute_conn_events(flags, use_epollet != 0)
}

fn net_add_nat_info_impl(rule_text: &str) -> i32 {
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

fn net_translate_ip_impl(local_ip: u32) -> u32 {
    mtproxy_core::runtime::net::connections::nat_translate_ip(local_ip)
}

fn net_msg_tl_marker_kind_impl(marker: i32) -> i32 {
    mtproxy_core::runtime::net::msg::tl_string_marker_kind(marker)
}

fn net_msg_tl_padding_impl(total_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::msg::tl_string_padding(total_bytes)
}

fn net_msg_encrypt_decrypt_effective_bytes_impl(
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

fn net_tcp_aes_aligned_len_impl(total_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::aes_aligned_len(total_bytes)
}

fn net_tcp_aes_needed_output_bytes_impl(total_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::aes_needed_output_bytes(total_bytes)
}

fn net_tcp_tls_encrypt_chunk_len_impl(total_bytes: i32, is_tls: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::tls_encrypt_chunk_len(total_bytes, is_tls != 0)
}

fn net_tcp_tls_header_needed_bytes_impl(available: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::tls_header_needed_bytes(available)
}

fn net_tcp_tls_parse_header_impl(header: &[u8; 5]) -> Result<i32, ()> {
    mtproxy_core::runtime::net::tcp_connections::tls_header_payload_len(header).ok_or(())
}

fn net_tcp_tls_decrypt_chunk_len_impl(available: i32, left_tls_packet_length: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::tls_decrypt_chunk_len(
        available,
        left_tls_packet_length,
    )
}

fn net_tcp_reader_negative_skip_take_impl(skip_bytes: i32, available_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::reader_negative_skip_take(
        skip_bytes,
        available_bytes,
    )
}

fn net_tcp_reader_negative_skip_next_impl(skip_bytes: i32, taken_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::reader_negative_skip_next(skip_bytes, taken_bytes)
}

fn net_tcp_reader_positive_skip_next_impl(skip_bytes: i32, available_bytes: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::reader_positive_skip_next(
        skip_bytes,
        available_bytes,
    )
}

fn net_tcp_reader_skip_from_parse_result_impl(
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

fn net_tcp_reader_precheck_result_impl(flags: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_connections::reader_precheck_result(flags)
}

fn net_tcp_reader_should_continue_impl(
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

fn net_tcp_rpc_ext_domain_bucket_index_impl(domain: &[u8]) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_ext_server::domain_bucket_index(domain)
}

fn net_tcp_rpc_ext_client_random_bucket_index_impl(random: &[u8; 16]) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_ext_server::client_random_bucket_index(random)
}

fn net_tcp_rpc_ext_select_server_hello_profile_impl(
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

fn net_stats_recent_idle_percent_impl(a_idle_time: f64, a_idle_quotient: f64) -> f64 {
    mtproxy_core::runtime::net::stats::recent_idle_percent(a_idle_time, a_idle_quotient)
}

fn net_stats_average_idle_percent_impl(tot_idle_time: f64, uptime: i32) -> f64 {
    mtproxy_core::runtime::net::stats::average_idle_percent(tot_idle_time, uptime)
}

type NetThreadRpcReadyFn = unsafe extern "C" fn(*mut c_void) -> i32;
type NetThreadRpcFn = unsafe extern "C" fn(*mut c_void);
type NetThreadFailConnectionFn = unsafe extern "C" fn(*mut c_void, i32);

struct NetThreadCallbackOps {
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

fn net_thread_run_notification_event_impl(
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

fn net_http_error_msg_text_impl(code: i32) -> (i32, *const c_char) {
    let (normalized_code, message) =
        mtproxy_core::runtime::net::http_server::http_error_msg_text(code);
    (normalized_code, message.as_ptr().cast::<c_char>())
}

fn net_http_gen_date_impl(time: i32) -> [u8; 29] {
    mtproxy_core::runtime::net::http_server::gen_http_date(time)
}

fn net_http_gen_time_impl(date_text: &str) -> Result<i32, i32> {
    mtproxy_core::runtime::net::http_server::gen_http_time(date_text)
}

fn net_http_get_header_impl(headers: &[u8], out: &mut [u8], arg_name: &[u8]) -> i32 {
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

fn msg_buffers_pick_size_index_impl(buffer_sizes: &[i32], size_hint: i32) -> i32 {
    mtproxy_core::runtime::net::msg_buffers::pick_size_index(buffer_sizes, size_hint)
}

fn tcp_rpc_encode_compact_header_impl(payload_len: i32, is_medium: i32) -> (i32, i32) {
    mtproxy_core::runtime::net::tcp_rpc_common::encode_compact_header(payload_len, is_medium)
}

fn tcp_rpc_client_packet_len_state_impl(packet_len: i32, max_packet_len: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_client::packet_len_state(packet_len, max_packet_len)
}

fn tcp_rpc_server_packet_header_malformed_impl(packet_len: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_server::packet_header_malformed(packet_len)
}

fn tcp_rpc_server_packet_len_state_impl(packet_len: i32, max_packet_len: i32) -> i32 {
    mtproxy_core::runtime::net::tcp_rpc_server::packet_len_state(packet_len, max_packet_len)
}

fn rpc_target_normalize_pid_impl(pid: &mut MtproxyProcessId, default_ip: u32) {
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

const RESOLVER_LOOKUP_SYSTEM_DNS: i32 = 0;
const RESOLVER_LOOKUP_NOT_FOUND: i32 = 1;
const RESOLVER_LOOKUP_HOSTS_IPV4: i32 = 2;

static RESOLVER_STATE: Mutex<mtproxy_core::runtime::net::resolver::ResolverState> =
    Mutex::new(mtproxy_core::runtime::net::resolver::ResolverState::new());

fn resolver_reload_hosts_from_system(
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

fn resolver_kdb_load_hosts_impl() -> i32 {
    let mut state = RESOLVER_STATE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    resolver_reload_hosts_from_system(&mut state)
}

fn resolver_kdb_hosts_loaded_impl() -> i32 {
    let state = RESOLVER_STATE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    state.kdb_hosts_loaded()
}

fn resolver_gethostbyname_plan_impl(name: &[u8]) -> (i32, u32) {
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
    if name.is_null() || out_kind.is_null() || out_ipv4.is_null() {
        return -1;
    }
    let name = unsafe { CStr::from_ptr(name) };
    let (kind, ip) = resolver_gethostbyname_plan_impl(name.to_bytes());
    let kind_ref = unsafe { &mut *out_kind };
    let ip_ref = unsafe { &mut *out_ipv4 };
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
        if extra_key_signatures.is_null() {
            return 0;
        }
        let Ok(count) = usize::try_from(extra_num) else {
            return 0;
        };
        unsafe { core::slice::from_raw_parts(extra_key_signatures, count) }
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
    if rule_text.is_null() {
        eprintln!("expected <local-addr>:<global-addr> in --nat-info");
        return -1;
    }
    let rule = unsafe { CStr::from_ptr(rule_text) };
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
    if header.is_null() || out_payload_len.is_null() {
        return -1;
    }
    let mut h = [0u8; 5];
    let header_slice = unsafe { core::slice::from_raw_parts(header, 5) };
    h.copy_from_slice(header_slice);
    match net_tcp_tls_parse_header_impl(&h) {
        Ok(payload_len) => {
            let out_ref = unsafe { &mut *out_payload_len };
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
    if out_skip_bytes.is_null() {
        return -1;
    }
    match net_tcp_reader_skip_from_parse_result_impl(parse_res, buffered_bytes, need_more_bytes) {
        Some(skip) => {
            let out_ref = unsafe { &mut *out_skip_bytes };
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
    if domain.is_null() || len < 0 {
        return -1;
    }
    let Ok(len) = usize::try_from(len) else {
        return -1;
    };
    let domain = unsafe { core::slice::from_raw_parts(domain, len) };
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
    if random.is_null() {
        return -1;
    }
    let random_slice = unsafe { core::slice::from_raw_parts(random, 16) };
    let mut random_buf = [0_u8; 16];
    random_buf.copy_from_slice(random_slice);
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
    if out_size.is_null() || out_profile.is_null() {
        return -1;
    }
    let Some((size, profile)) =
        net_tcp_rpc_ext_select_server_hello_profile_impl(min_len, max_len, sum_len, sample_count)
    else {
        return -1;
    };
    let out_size_ref = unsafe { &mut *out_size };
    let out_profile_ref = unsafe { &mut *out_profile };
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
    if code.is_null() {
        return core::ptr::null();
    }
    let in_code = unsafe { *code };
    let (normalized_code, message_ptr) = net_http_error_msg_text_impl(in_code);
    let code_ref = unsafe { &mut *code };
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
    if out.is_null() || out_len < 29 {
        return -1;
    }
    let Ok(out_count) = usize::try_from(out_len) else {
        return -1;
    };
    let out_slice = unsafe { core::slice::from_raw_parts_mut(out.cast::<u8>(), out_count) };
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
    if date_text.is_null() || out_time.is_null() {
        return -8;
    }
    let text = unsafe { CStr::from_ptr(date_text) };
    let Ok(text) = text.to_str() else {
        return -8;
    };
    match net_http_gen_time_impl(text) {
        Ok(time) => {
            let out_ref = unsafe { &mut *out_time };
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
    if buffer.is_null() || b_len <= 0 {
        return -1;
    }
    let Ok(buffer_len) = usize::try_from(b_len) else {
        return -1;
    };
    let out = unsafe { core::slice::from_raw_parts_mut(buffer.cast::<u8>(), buffer_len) };

    if q_headers.is_null() || arg_name.is_null() || q_headers_len < 0 || arg_len < 0 {
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
    let headers = unsafe { core::slice::from_raw_parts(q_headers.cast::<u8>(), headers_len) };
    let name = unsafe { core::slice::from_raw_parts(arg_name.cast::<u8>(), name_len) };
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
