use super::*;
use crate::ffi_util::{mut_ref_from_ptr, mut_slice_from_ptr, ref_from_ptr, slice_from_ptr};

fn mtproto_proxy_collect_argv(argc: i32, argv: *const *const c_char) -> Option<Vec<String>> {
    if argc < 0 {
        return None;
    }
    if argc == 0 {
        return Some(vec!["mtproto-proxy".to_owned()]);
    }
    if argv.is_null() {
        return None;
    }

    let count = usize::try_from(argc).ok()?;
    let raw = unsafe { slice_from_ptr(argv, count) }?;
    let mut out = Vec::with_capacity(count.max(1));
    for &arg_ptr in raw {
        let arg_ref = unsafe { ref_from_ptr(arg_ptr) }?;
        let arg = unsafe { CStr::from_ptr(arg_ref) }
            .to_string_lossy()
            .into_owned();
        out.push(arg);
    }
    if out.is_empty() {
        out.push("mtproto-proxy".to_owned());
    }
    Some(out)
}

/// Prints CLI usage/help for the Rust MTProxy entrypoint.
///
/// # Safety
/// `program_name` may be null; otherwise it must point to a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_proxy_usage(program_name: *const c_char) -> i32 {
    let program_name = if program_name.is_null() {
        "mtproto-proxy".to_owned()
    } else {
        let Some(program_name_ref) = (unsafe { ref_from_ptr(program_name) }) else {
            return -1;
        };
        unsafe { CStr::from_ptr(program_name_ref) }
            .to_string_lossy()
            .into_owned()
    };

    let usage = mtproxy_bin::entrypoint::usage_text(&program_name);
    eprint!("{usage}");
    0
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
    let Some(args) = mtproto_proxy_collect_argv(argc, argv) else {
        eprintln!("ERROR: invalid argv passed to mtproxy_ffi_mtproto_proxy_main");
        return 1;
    };
    mtproxy_bin::entrypoint::run_from_argv(&args)
}

fn cfg_bytes_from_cstr(cur: *const c_char, len: usize) -> Option<&'static [u8]> {
    unsafe { slice_from_ptr(cur.cast::<u8>(), len) }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn copy_mtproto_parse_error_message(out: &mut MtproxyMtprotoParseFunctionResult, message: &str) {
    let bytes = message.as_bytes();
    let cap = out.error.len().saturating_sub(1);
    let n = bytes.len().min(cap);
    for (dst, src) in out.error.iter_mut().take(n).zip(bytes.iter().copied()) {
        *dst = c_char::from_ne_bytes([src]);
    }
    if let Some(last) = out.error.get_mut(n) {
        *last = 0;
    }
    out.error_len = i32::try_from(n).unwrap_or(i32::MAX);
}

fn saturating_i32_from_usize(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;

fn mtproto_cfg_collect_auth_cluster_ids(
    mc: &MtproxyMfConfig,
    out: &mut [i32; MTPROTO_CFG_MAX_CLUSTERS],
) -> usize {
    let count = usize::try_from(mc.auth_clusters).unwrap_or(0);
    let bounded = count.min(MTPROTO_CFG_MAX_CLUSTERS);
    for (idx, slot) in out.iter_mut().enumerate().take(bounded) {
        *slot = mc.auth_cluster[idx].cluster_id;
    }
    bounded
}

fn mtproto_cfg_default_cluster_index(mc: &MtproxyMfConfig, auth_clusters: usize) -> Option<usize> {
    if mc.default_cluster.is_null() {
        return None;
    }
    let base = mc.auth_cluster.as_ptr().cast::<u8>() as usize;
    let ptr = mc.default_cluster.cast::<u8>() as usize;
    let elem = core::mem::size_of::<MtproxyMfCluster>();
    let span = auth_clusters.checked_mul(elem)?;
    if ptr < base || ptr >= base.saturating_add(span) {
        return None;
    }
    let offset = ptr - base;
    if (offset % elem) != 0 {
        return None;
    }
    Some(offset / elem)
}

fn mtproto_cfg_forget_cluster_targets(cluster: &mut MtproxyMfCluster) {
    if !cluster.cluster_targets.is_null() {
        cluster.cluster_targets = core::ptr::null_mut();
    }
    cluster.targets_num = 0;
    cluster.write_targets_num = 0;
    cluster.targets_allocated = 0;
}

fn mtproto_cfg_clear_cluster(
    group_stats: &mut MtproxyMfGroupStats,
    cluster: &mut MtproxyMfCluster,
) {
    mtproto_cfg_forget_cluster_targets(cluster);
    cluster.flags = 0;
    group_stats.tot_clusters = group_stats.tot_clusters.wrapping_sub(1);
}

/// Clears runtime config snapshot and optionally destroys target objects.
///
/// # Safety
/// `mc` must point to a writable `struct mf_config` when non-null.
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn clear_config(mc: *mut MtproxyMfConfig, do_destroy_targets: c_int) {
    let Some(mc_ref) = (unsafe { mut_ref_from_ptr(mc) }) else {
        return;
    };
    let tot_targets = usize::try_from(mc_ref.tot_targets)
        .unwrap_or(0)
        .min(MTPROTO_CFG_MAX_TARGETS);
    if do_destroy_targets != 0 {
        for idx in 0..tot_targets {
            let target = mc_ref.targets[idx];
            if unsafe { verbosity } >= 1 {
                unsafe { kprintf(b"destroying target %p\n\0".as_ptr().cast(), target) };
            }
            unsafe {
                destroy_target(1, target);
            }
        }
        for idx in 0..tot_targets {
            mc_ref.targets[idx] = core::ptr::null_mut();
        }
    }

    let auth_clusters = usize::try_from(mc_ref.auth_clusters)
        .unwrap_or(0)
        .min(MTPROTO_CFG_MAX_CLUSTERS);
    for idx in 0..auth_clusters {
        mtproto_cfg_clear_cluster(&mut mc_ref.auth_stats, &mut mc_ref.auth_cluster[idx]);
    }
    mc_ref.tot_targets = 0;
    mc_ref.auth_clusters = 0;
    mc_ref.auth_stats = MtproxyMfGroupStats { tot_clusters: 0 };
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
    let Some(mc_ref) = (unsafe { mut_ref_from_ptr(mc) }) else {
        return core::ptr::null_mut();
    };
    let mut cluster_ids = [0i32; MTPROTO_CFG_MAX_CLUSTERS];
    let auth_clusters = mtproto_cfg_collect_auth_cluster_ids(mc_ref, &mut cluster_ids);
    let default_cluster_index = mtproto_cfg_default_cluster_index(mc_ref, auth_clusters);
    let mut out_cluster_index = -1;

    let lookup_rc = unsafe {
        mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
            cluster_ids.as_ptr(),
            auth_clusters as u32,
            cluster_id,
            if force != 0 { 1 } else { 0 },
            default_cluster_index
                .and_then(|idx| i32::try_from(idx).ok())
                .unwrap_or(0),
            i32::from(default_cluster_index.is_some()),
            &raw mut out_cluster_index,
        )
    };
    if lookup_rc == MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK {
        if let Ok(idx) = usize::try_from(out_cluster_index) {
            if idx < auth_clusters {
                return &mut mc_ref.auth_cluster[idx];
            }
        }
        return if force != 0 {
            mc_ref.default_cluster
        } else {
            core::ptr::null_mut()
        };
    }
    if lookup_rc == MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND {
        return if force != 0 {
            mc_ref.default_cluster
        } else {
            core::ptr::null_mut()
        };
    }
    if force != 0 {
        mc_ref.default_cluster
    } else {
        core::ptr::null_mut()
    }
}

/// Resolves target hostname from parser cursor and stores it into `default_cfg_ct`.
///
/// # Safety
/// Uses global parser cursors from C runtime and mutates `default_cfg_ct`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_resolve_default_target_from_cfg_cur() -> c_int {
    let host = unsafe { cfg_gethost() };
    if host.is_null() {
        return -1;
    }
    let host_ref = unsafe { &*host };
    if host_ref.h_addr_list.is_null() {
        return -1;
    }
    let addr = unsafe { *host_ref.h_addr_list };
    if addr.is_null() {
        return -1;
    }

    if host_ref.h_addrtype == AF_INET {
        let in_addr = unsafe { *(addr.cast::<MtproxyInAddr>()) };
        unsafe {
            default_cfg_ct.target = in_addr;
            default_cfg_ct.target_ipv6 = [0; 16];
        }
        return 0;
    }
    if host_ref.h_addrtype == AF_INET6 {
        unsafe {
            default_cfg_ct.target.s_addr = 0;
            core::ptr::copy_nonoverlapping(
                addr.cast::<u8>(),
                core::ptr::addr_of_mut!(default_cfg_ct.target_ipv6).cast::<u8>(),
                16,
            );
        }
        return 0;
    }

    unsafe { mtproto_cfg_syntax_literal(b"cannot resolve hostname\0") };
    -1
}

/// Updates endpoint-specific defaults used by `create_target`.
///
/// # Safety
/// Mutates process-global `default_cfg_ct` fields.
#[allow(clippy::cast_possible_truncation)]
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_set_default_target_endpoint(
    port: u16,
    min_connections: i64,
    max_connections: i64,
    reconnect_timeout: c_double,
) {
    unsafe {
        default_cfg_ct.port = c_int::from(port);
        default_cfg_ct.min_connections = min_connections as c_int;
        default_cfg_ct.max_connections = max_connections as c_int;
        default_cfg_ct.reconnect_timeout = reconnect_timeout;
    }
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
    let Some(mc_ref) = (unsafe { mut_ref_from_ptr(mc) }) else {
        return;
    };
    let Ok(target_index_usize) = usize::try_from(target_index) else {
        return;
    };
    if target_index_usize >= MTPROTO_CFG_MAX_TARGETS {
        return;
    }
    let mut was_created = -1;
    let target = unsafe { create_target(&raw mut default_cfg_ct, &raw mut was_created) };
    mc_ref.targets[target_index_usize] = target;

    if unsafe { verbosity } >= 3 {
        let ipv4 = unsafe { default_cfg_ct.target.s_addr.to_ne_bytes() };
        unsafe {
            kprintf(
                b"new target %p created (%d): ip %d.%d.%d.%d, port %d\n\0"
                    .as_ptr()
                    .cast(),
                target,
                was_created,
                c_int::from(ipv4[0]),
                c_int::from(ipv4[1]),
                c_int::from(ipv4[2]),
                c_int::from(ipv4[3]),
                default_cfg_ct.port,
            );
        }
    }
}

/// Returns current wall-clock unix seconds.
///
/// # Safety
/// Calls C runtime `time(0)` via FFI.
#[allow(clippy::cast_possible_truncation)]
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_now_or_time() -> c_int {
    unsafe { time(core::ptr::null_mut()) as c_int }
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
    let Some(str_ref) = (unsafe { ref_from_ptr(str) }) else {
        return -1;
    };
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_ip) }) else {
        return -1;
    };
    let input = unsafe { CStr::from_ptr(str_ref) }.to_string_lossy();
    let parsed = mtproxy_core::runtime::mtproto::proxy::parse_text_ipv4(&input);
    *out_ref = parsed;
    0
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
    let Some(str_ref) = (unsafe { ref_from_ptr(str) }) else {
        return -1;
    };
    let Some(out_ip_slice) = (unsafe { mut_slice_from_ptr(out_ip, 16) }) else {
        return -1;
    };
    let Some(out_consumed_ref) = (unsafe { mut_ref_from_ptr(out_consumed) }) else {
        return -1;
    };
    let input = unsafe { CStr::from_ptr(str_ref) }.to_string_lossy();
    let mut parsed_ip = [0u8; 16];
    let consumed = mtproxy_core::runtime::mtproto::proxy::parse_text_ipv6(&mut parsed_ip, &input);
    out_ip_slice.copy_from_slice(&parsed_ip);
    *out_consumed_ref = consumed;
    0
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = slice_from_ptr(header, header_len) else {
        return -1;
    };
    *out_ref = MtproxyMtprotoPacketInspectResult::default();

    match mtproxy_core::runtime::mtproto::proxy::inspect_mtproto_packet_header(bytes, packet_len) {
        Some(mtproxy_core::runtime::mtproto::proxy::MtprotoPacketKind::Encrypted {
            auth_key_id,
        }) => {
            out_ref.kind = MTPROTO_PACKET_KIND_ENCRYPTED;
            out_ref.auth_key_id = auth_key_id;
        }
        Some(mtproxy_core::runtime::mtproto::proxy::MtprotoPacketKind::UnencryptedDh {
            inner_len,
            function,
        }) => {
            out_ref.kind = MTPROTO_PACKET_KIND_UNENCRYPTED_DH;
            out_ref.inner_len = inner_len;
            out_ref.function_id = function;
        }
        None => {
            out_ref.kind = MTPROTO_PACKET_KIND_INVALID;
        }
    }
    0
}

fn mtproto_parse_client_packet_impl(data: &[u8], out: &mut MtproxyMtprotoClientPacketParseResult) {
    use mtproxy_core::runtime::mtproto::proxy::RpcClientPacket;

    match mtproxy_core::runtime::mtproto::proxy::parse_client_packet(data) {
        RpcClientPacket::Pong => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_PONG;
            out.op = mtproxy_core::runtime::mtproto::proxy::RPC_PONG;
        }
        RpcClientPacket::ProxyAns {
            flags,
            out_conn_id,
            payload,
        } => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_PROXY_ANS;
            out.op = mtproxy_core::runtime::mtproto::proxy::RPC_PROXY_ANS;
            out.flags = flags;
            out.out_conn_id = out_conn_id;
            let payload_offset = data.len().saturating_sub(payload.len());
            out.payload_offset = saturating_i32_from_usize(payload_offset);
        }
        RpcClientPacket::SimpleAck {
            out_conn_id,
            confirm,
        } => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_SIMPLE_ACK;
            out.op = mtproxy_core::runtime::mtproto::proxy::RPC_SIMPLE_ACK;
            out.out_conn_id = out_conn_id;
            out.confirm = confirm;
        }
        RpcClientPacket::CloseExt { out_conn_id } => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_CLOSE_EXT;
            out.op = mtproxy_core::runtime::mtproto::proxy::RPC_CLOSE_EXT;
            out.out_conn_id = out_conn_id;
        }
        RpcClientPacket::Unknown { op } => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_UNKNOWN;
            out.op = op;
        }
        RpcClientPacket::Malformed { op } => {
            out.kind = MTPROTO_CLIENT_PACKET_KIND_MALFORMED;
            out.op = op;
        }
    }
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = slice_from_ptr(data, len) else {
        return -1;
    };
    *out_ref = MtproxyMtprotoClientPacketParseResult {
        kind: MTPROTO_CLIENT_PACKET_KIND_INVALID,
        ..MtproxyMtprotoClientPacketParseResult::default()
    };
    mtproto_parse_client_packet_impl(bytes, out_ref);
    0
}

fn mtproto_parse_function_impl(
    data: &[u8],
    actor_id: i64,
    out: &mut MtproxyMtprotoParseFunctionResult,
) {
    let mut in_state = mtproxy_core::runtime::config::tl_parse::TlInState::new(data);
    match mtproxy_core::runtime::mtproto::proxy::parse_mtfront_function(&mut in_state, actor_id) {
        Ok(()) => {
            out.status = 0;
            out.consumed = saturating_i32_from_usize(in_state.position());
        }
        Err(err) => {
            out.status = -1;
            out.consumed = saturating_i32_from_usize(in_state.position());
            out.errnum = err.errnum;
            copy_mtproto_parse_error_message(out, &err.message);
        }
    }
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = slice_from_ptr(data, len) else {
        return -1;
    };
    *out_ref = MtproxyMtprotoParseFunctionResult::default();
    mtproto_parse_function_impl(bytes, actor_id, out_ref);
    0
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_PREINIT_ERR_INVALID_ARGS;
    };
    let snapshot = mtproxy_core::runtime::mtproto::config::preinit_config_snapshot(
        mtproxy_core::runtime::mtproto::config::MtprotoConfigDefaults {
            min_connections: default_min_connections,
            max_connections: default_max_connections,
        },
    );
    let Ok(tot_targets) = i32::try_from(snapshot.tot_targets) else {
        return MTPROTO_CFG_PREINIT_ERR_INTERNAL;
    };
    let Ok(auth_clusters) = i32::try_from(snapshot.auth_clusters) else {
        return MTPROTO_CFG_PREINIT_ERR_INTERNAL;
    };
    *out_ref = MtproxyMtprotoCfgPreinitResult {
        tot_targets,
        auth_clusters,
        min_connections: snapshot.min_connections,
        max_connections: snapshot.max_connections,
        timeout_seconds: snapshot.timeout_seconds,
        default_cluster_id: snapshot.default_cluster_id,
    };
    MTPROTO_CFG_PREINIT_OK
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    };
    let Ok(max_clusters_usize) = usize::try_from(max_clusters) else {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    };
    let Some(cluster_ids_slice) = (unsafe { slice_from_ptr(cluster_ids, clusters_len_usize) })
    else {
        return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS;
    };
    match mtproxy_core::runtime::mtproto::config::decide_proxy_cluster_apply(
        cluster_ids_slice,
        cluster_id,
        max_clusters_usize,
    ) {
        Ok(decision) => {
            let Ok(cluster_index) = i32::try_from(decision.cluster_index) else {
                return MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INTERNAL;
            };
            *out_ref = MtproxyMtprotoCfgClusterApplyDecisionResult {
                kind: mtproto_cfg_cluster_apply_decision_kind_to_ffi(decision.kind),
                cluster_index,
            };
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK
        }
        Err(err) => mtproto_cfg_cluster_apply_decision_err_to_code(err),
    }
}

fn mtproto_cfg_cluster_apply_decision_kind_to_ffi(
    kind: mtproxy_core::runtime::mtproto::config::MtprotoClusterApplyDecisionKind,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoClusterApplyDecisionKind;
    match kind {
        MtprotoClusterApplyDecisionKind::CreateNew => {
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW
        }
        MtprotoClusterApplyDecisionKind::AppendLast => {
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST
        }
    }
}

fn mtproto_cfg_cluster_apply_decision_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::TooManyAuthClusters(_) => {
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_TOO_MANY_AUTH_CLUSTERS
        }
        MtprotoDirectiveParseError::ProxiesIntermixed(_) => {
            MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_PROXIES_INTERMIXED
        }
        _ => MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INTERNAL,
    }
}

fn mtproto_cfg_cluster_targets_action_to_ffi(
    action: mtproxy_core::runtime::mtproto::config::MtprotoClusterTargetsAction,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoClusterTargetsAction;
    match action {
        MtprotoClusterTargetsAction::KeepExisting => {
            MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING
        }
        MtprotoClusterTargetsAction::Clear => MTPROTO_CFG_CLUSTER_TARGETS_ACTION_CLEAR,
        MtprotoClusterTargetsAction::SetToTargetIndex => {
            MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET
        }
    }
}

fn mtproto_cfg_parse_proxy_target_step_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::TooManyAuthClusters(_) => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_AUTH_CLUSTERS
        }
        MtprotoDirectiveParseError::ProxiesIntermixed(_) => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PROXIES_INTERMIXED
        }
        MtprotoDirectiveParseError::TooManyTargets(_) => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_TARGETS
        }
        MtprotoDirectiveParseError::HostnameExpected => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_HOSTNAME_EXPECTED
        }
        MtprotoDirectiveParseError::PortNumberExpected => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_EXPECTED
        }
        MtprotoDirectiveParseError::PortOutOfRange(_) => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_RANGE
        }
        MtprotoDirectiveParseError::ExpectedSemicolon(_) => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_EXPECTED_SEMICOLON
        }
        MtprotoDirectiveParseError::InternalClusterExtendInvariant => {
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_CLUSTER_EXTEND_INVARIANT
        }
        _ => MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL,
    }
}

fn mtproto_cfg_parse_full_pass_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::InvalidTimeout(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TIMEOUT
        }
        MtprotoDirectiveParseError::InvalidMaxConnections(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MAX_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidMinConnections(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MIN_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidTargetId(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TARGET_ID
        }
        MtprotoDirectiveParseError::SpaceExpectedAfterTargetId => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_TARGET_ID_SPACE
        }
        MtprotoDirectiveParseError::TooManyAuthClusters(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_AUTH_CLUSTERS
        }
        MtprotoDirectiveParseError::TooManyTargets(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_TARGETS
        }
        MtprotoDirectiveParseError::HostnameExpected => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_HOSTNAME_EXPECTED
        }
        MtprotoDirectiveParseError::PortNumberExpected => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_EXPECTED
        }
        MtprotoDirectiveParseError::PortOutOfRange(_) => MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_RANGE,
        MtprotoDirectiveParseError::ProxiesIntermixed(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXIES_INTERMIXED
        }
        MtprotoDirectiveParseError::ProxyDirectiveExpected => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXY_EXPECTED
        }
        MtprotoDirectiveParseError::ExpectedSemicolon(_) => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON
        }
        MtprotoDirectiveParseError::MissingProxyDirectives => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES
        }
        MtprotoDirectiveParseError::NoProxyServersDefined => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_NO_PROXY_SERVERS_DEFINED
        }
        MtprotoDirectiveParseError::InternalClusterExtendInvariant => {
            MTPROTO_CFG_PARSE_FULL_PASS_ERR_CLUSTER_EXTEND_INVARIANT
        }
    }
}

fn mtproto_directive_token_kind_to_ffi(
    kind: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveTokenKind,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveTokenKind;
    match kind {
        MtprotoDirectiveTokenKind::Eof => MTPROTO_DIRECTIVE_TOKEN_KIND_EOF,
        MtprotoDirectiveTokenKind::Timeout => MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT,
        MtprotoDirectiveTokenKind::DefaultCluster => MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER,
        MtprotoDirectiveTokenKind::ProxyFor => MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR,
        MtprotoDirectiveTokenKind::Proxy => MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY,
        MtprotoDirectiveTokenKind::MaxConnections => MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS,
        MtprotoDirectiveTokenKind::MinConnections => MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS,
    }
}

fn mtproto_cfg_scan_directive_token_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::InvalidTimeout(_) => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TIMEOUT
        }
        MtprotoDirectiveParseError::InvalidMaxConnections(_) => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MAX_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidMinConnections(_) => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MIN_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidTargetId(_) => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TARGET_ID
        }
        MtprotoDirectiveParseError::SpaceExpectedAfterTargetId => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_TARGET_ID_SPACE
        }
        MtprotoDirectiveParseError::ProxyDirectiveExpected => {
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_PROXY_EXPECTED
        }
        _ => MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INTERNAL,
    }
}

fn mtproto_cfg_parse_directive_step_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::InvalidTimeout(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TIMEOUT
        }
        MtprotoDirectiveParseError::InvalidMaxConnections(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MAX_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidMinConnections(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MIN_CONNECTIONS
        }
        MtprotoDirectiveParseError::InvalidTargetId(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TARGET_ID
        }
        MtprotoDirectiveParseError::SpaceExpectedAfterTargetId => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TARGET_ID_SPACE
        }
        MtprotoDirectiveParseError::ProxyDirectiveExpected => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXY_EXPECTED
        }
        MtprotoDirectiveParseError::TooManyAuthClusters(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TOO_MANY_AUTH_CLUSTERS
        }
        MtprotoDirectiveParseError::ProxiesIntermixed(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXIES_INTERMIXED
        }
        MtprotoDirectiveParseError::ExpectedSemicolon(_) => {
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_EXPECTED_SEMICOLON
        }
        _ => MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INTERNAL,
    }
}

fn mtproto_cfg_finalize_err_to_code(
    err: mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError,
) -> i32 {
    use mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError;
    match err {
        MtprotoDirectiveParseError::MissingProxyDirectives => {
            MTPROTO_CFG_FINALIZE_ERR_MISSING_PROXY_DIRECTIVES
        }
        MtprotoDirectiveParseError::NoProxyServersDefined => {
            MTPROTO_CFG_FINALIZE_ERR_NO_PROXY_SERVERS_DEFINED
        }
        _ => MTPROTO_CFG_FINALIZE_ERR_INTERNAL,
    }
}

fn mtproto_old_cluster_from_ffi(
    state: &MtproxyMtprotoOldClusterState,
) -> Option<mtproxy_core::runtime::mtproto::config::MtprotoClusterState> {
    let first_target_index = if state.has_first_target_index != 0 {
        Some(usize::try_from(state.first_target_index).ok()?)
    } else {
        None
    };
    Some(
        mtproxy_core::runtime::mtproto::config::MtprotoClusterState {
            cluster_id: state.cluster_id,
            targets_num: state.targets_num,
            write_targets_num: state.write_targets_num,
            flags: state.flags,
            first_target_index,
        },
    )
}

fn mtproto_old_cluster_to_ffi(
    state: &mtproxy_core::runtime::mtproto::config::MtprotoClusterState,
) -> Option<MtproxyMtprotoOldClusterState> {
    let (has_first_target_index, first_target_index) = if let Some(first) = state.first_target_index
    {
        (1, u32::try_from(first).ok()?)
    } else {
        (0, 0)
    };
    Some(MtproxyMtprotoOldClusterState {
        cluster_id: state.cluster_id,
        targets_num: state.targets_num,
        write_targets_num: state.write_targets_num,
        flags: state.flags,
        first_target_index,
        has_first_target_index,
    })
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_GETLEX_EXT_ERR_INVALID_ARGS;
    };
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_GETLEX_EXT_ERR_INVALID_ARGS;
    };
    let mut cursor = 0usize;
    let lex = mtproxy_core::runtime::mtproto::config::cfg_getlex_ext(bytes, &mut cursor);
    *out_ref = MtproxyMtprotoCfgGetlexExtResult {
        advance: cursor,
        lex,
    };
    MTPROTO_CFG_GETLEX_EXT_OK
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_ARGS;
    };
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_ARGS;
    };
    match mtproxy_core::runtime::mtproto::config::cfg_scan_directive_token(
        bytes,
        min_connections,
        max_connections,
    ) {
        Ok(preview) => {
            *out_ref = MtproxyMtprotoCfgDirectiveTokenResult {
                kind: mtproto_directive_token_kind_to_ffi(preview.kind),
                advance: preview.advance,
                value: preview.value,
            };
            MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK
        }
        Err(err) => mtproto_cfg_scan_directive_token_err_to_code(err),
    }
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    let Ok(max_clusters_usize) = usize::try_from(max_clusters) else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };
    let Some(cluster_ids_slice) = (unsafe { slice_from_ptr(cluster_ids, clusters_len_usize) })
    else {
        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS;
    };

    match mtproxy_core::runtime::mtproto::config::cfg_parse_directive_step(
        bytes,
        min_connections,
        max_connections,
        cluster_ids_slice,
        max_clusters_usize,
    ) {
        Ok(step) => {
            let (cluster_decision_kind, cluster_index) =
                if let Some(decision) = step.cluster_apply_decision {
                    let Ok(cluster_index) = i32::try_from(decision.cluster_index) else {
                        return MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INTERNAL;
                    };
                    (
                        mtproto_cfg_cluster_apply_decision_kind_to_ffi(decision.kind),
                        cluster_index,
                    )
                } else {
                    (0, -1)
                };
            *out_ref = MtproxyMtprotoCfgDirectiveStepResult {
                kind: mtproto_directive_token_kind_to_ffi(step.kind),
                advance: step.advance,
                value: step.value,
                cluster_decision_kind,
                cluster_index,
            };
            MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK
        }
        Err(err) => mtproto_cfg_parse_directive_step_err_to_code(err),
    }
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Ok(current_targets_usize) = usize::try_from(current_targets) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Ok(max_targets_usize) = usize::try_from(max_targets) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Ok(max_clusters_usize) = usize::try_from(max_clusters) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Ok(current_auth_tot_clusters_usize) = usize::try_from(current_auth_tot_clusters) else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };
    let Some(cluster_ids_slice) = (unsafe { slice_from_ptr(cluster_ids, clusters_len_usize) })
    else {
        return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
    };

    let last_cluster_state = if has_last_cluster_state != 0 {
        let Some(state_ref) = (unsafe { ref_from_ptr(last_cluster_state) }) else {
            return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
        };
        let Some(state) = mtproto_old_cluster_from_ffi(state_ref) else {
            return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS;
        };
        Some(state)
    } else {
        None
    };

    match mtproxy_core::runtime::mtproto::config::cfg_parse_proxy_target_step(
        bytes,
        current_targets_usize,
        max_targets_usize,
        min_connections,
        max_connections,
        cluster_ids_slice,
        target_dc,
        max_clusters_usize,
        create_targets != 0,
        current_auth_tot_clusters_usize,
        last_cluster_state,
    ) {
        Ok(step) => {
            let Ok(target_index) = u32::try_from(step.target_index) else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let Ok(tot_targets_after) = u32::try_from(step.tot_targets_after) else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let Ok(cluster_index) = i32::try_from(step.cluster_apply_decision.cluster_index) else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let Ok(auth_clusters_after) = u32::try_from(step.auth_clusters_after) else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let Ok(auth_tot_clusters_after) = u32::try_from(step.auth_tot_clusters_after) else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let Some(cluster_state_after) = mtproto_old_cluster_to_ffi(&step.cluster_state_after)
            else {
                return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
            };
            let cluster_targets_action =
                mtproto_cfg_cluster_targets_action_to_ffi(step.cluster_targets_action);
            let cluster_targets_index = if step.cluster_targets_action
                == mtproxy_core::runtime::mtproto::config::MtprotoClusterTargetsAction::SetToTargetIndex
            {
                let Some(first) = step.cluster_state_after.first_target_index else {
                    return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
                };
                let Ok(idx) = u32::try_from(first) else {
                    return MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL;
                };
                idx
            } else {
                0
            };

            *out_ref = MtproxyMtprotoCfgParseProxyTargetStepResult {
                advance: step.advance,
                target_index,
                host_len: step.target.host_len,
                port: step.target.port,
                min_connections: step.target.min_connections,
                max_connections: step.target.max_connections,
                tot_targets_after,
                cluster_decision_kind: mtproto_cfg_cluster_apply_decision_kind_to_ffi(
                    step.cluster_apply_decision.kind,
                ),
                cluster_index,
                auth_clusters_after,
                auth_tot_clusters_after,
                cluster_state_after,
                cluster_targets_action,
                cluster_targets_index,
            };
            MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK
        }
        Err(err) => mtproto_cfg_parse_proxy_target_step_err_to_code(err),
    }
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    };
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    };
    let Ok(max_clusters_usize) = usize::try_from(max_clusters) else {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    };
    let Ok(max_targets_usize) = usize::try_from(max_targets) else {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    };
    let Ok(actions_capacity_usize) = usize::try_from(actions_capacity) else {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    };
    if max_clusters_usize == 0 || max_clusters_usize > MTPROTO_CFG_FULL_PASS_MAX_CLUSTERS {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    }
    if actions_capacity_usize > 0 && actions.is_null() {
        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
    }

    let mut planned_actions = vec![
        mtproxy_core::runtime::mtproto::config::MtprotoProxyTargetPassAction::default();
        actions_capacity_usize
    ];
    let defaults = mtproxy_core::runtime::mtproto::config::MtprotoConfigDefaults {
        min_connections: default_min_connections,
        max_connections: default_max_connections,
    };
    match mtproxy_core::runtime::mtproto::config::cfg_parse_config_full_pass::<
        MTPROTO_CFG_FULL_PASS_MAX_CLUSTERS,
    >(
        bytes,
        defaults,
        create_targets != 0,
        max_clusters_usize,
        max_targets_usize,
        &mut planned_actions,
    ) {
        Ok(result) => {
            if result.actions_len > actions_capacity_usize {
                return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
            }
            if result.actions_len > 0 {
                let Some(out_actions) =
                    (unsafe { mut_slice_from_ptr(actions, actions_capacity_usize) })
                else {
                    return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS;
                };
                for idx in 0..result.actions_len {
                    let action = planned_actions[idx];
                    let step = action.step;
                    let Ok(target_index) = u32::try_from(step.target_index) else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let Ok(tot_targets_after) = u32::try_from(step.tot_targets_after) else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let Ok(cluster_index) =
                        i32::try_from(step.cluster_apply_decision.cluster_index)
                    else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let Ok(auth_clusters_after) = u32::try_from(step.auth_clusters_after) else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let Ok(auth_tot_clusters_after) = u32::try_from(step.auth_tot_clusters_after)
                    else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let Some(cluster_state_after) =
                        mtproto_old_cluster_to_ffi(&step.cluster_state_after)
                    else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    let cluster_targets_action =
                        mtproto_cfg_cluster_targets_action_to_ffi(step.cluster_targets_action);
                    let cluster_targets_index = if step.cluster_targets_action
                        == mtproxy_core::runtime::mtproto::config::MtprotoClusterTargetsAction::SetToTargetIndex
                    {
                        let Some(first) = step.cluster_state_after.first_target_index else {
                            return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                        };
                        let Ok(idx) = u32::try_from(first) else {
                            return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                        };
                        idx
                    } else {
                        0
                    };
                    out_actions[idx] = MtproxyMtprotoCfgProxyAction {
                        host_offset: action.host_offset,
                        step: MtproxyMtprotoCfgParseProxyTargetStepResult {
                            advance: step.advance,
                            target_index,
                            host_len: step.target.host_len,
                            port: step.target.port,
                            min_connections: step.target.min_connections,
                            max_connections: step.target.max_connections,
                            tot_targets_after,
                            cluster_decision_kind: mtproto_cfg_cluster_apply_decision_kind_to_ffi(
                                step.cluster_apply_decision.kind,
                            ),
                            cluster_index,
                            auth_clusters_after,
                            auth_tot_clusters_after,
                            cluster_state_after,
                            cluster_targets_action,
                            cluster_targets_index,
                        },
                    };
                }
            }

            let Ok(tot_targets) = u32::try_from(result.tot_targets) else {
                return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
            };
            let Ok(auth_clusters) = u32::try_from(result.auth_clusters) else {
                return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
            };
            let Ok(auth_tot_clusters) = u32::try_from(result.auth_tot_clusters) else {
                return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
            };
            let Ok(actions_len) = u32::try_from(result.actions_len) else {
                return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
            };
            let (has_default_cluster_index, default_cluster_index) =
                if let Some(idx) = result.default_cluster_index {
                    let Ok(idx_u32) = u32::try_from(idx) else {
                        return MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL;
                    };
                    (1, idx_u32)
                } else {
                    (0, 0)
                };
            *out_ref = MtproxyMtprotoCfgParseFullResult {
                tot_targets,
                auth_clusters,
                auth_tot_clusters,
                min_connections: result.min_connections,
                max_connections: result.max_connections,
                timeout_seconds: result.timeout_seconds,
                default_cluster_id: result.default_cluster_id,
                have_proxy: i32::from(result.have_proxy),
                default_cluster_index,
                has_default_cluster_index,
                actions_len,
            };
            MTPROTO_CFG_PARSE_FULL_PASS_OK
        }
        Err(err) => mtproto_cfg_parse_full_pass_err_to_code(err),
    }
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_advance) }) else {
        return MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS;
    };
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS;
    };
    let mut cursor = 0usize;
    match mtproxy_core::runtime::mtproto::config::cfg_expect_semicolon(bytes, &mut cursor) {
        Ok(()) => {
            *out_ref = cursor;
            MTPROTO_CFG_EXPECT_SEMICOLON_OK
        }
        Err(
            mtproxy_core::runtime::mtproto::config::MtprotoDirectiveParseError::ExpectedSemicolon(
                _,
            ),
        ) => MTPROTO_CFG_EXPECT_SEMICOLON_ERR_EXPECTED,
        Err(_) => MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS,
    }
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_cluster_index) }) else {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    };
    let default_idx = if has_default_cluster_index != 0 {
        let Ok(idx) = usize::try_from(default_cluster_index) else {
            return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
        };
        if idx >= clusters_len_usize {
            return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
        }
        Some(idx)
    } else {
        None
    };
    let Some(cluster_ids_slice) = (unsafe { slice_from_ptr(cluster_ids, clusters_len_usize) })
    else {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    };
    let lookup = mtproxy_core::runtime::mtproto::config::mf_cluster_lookup_index(
        cluster_ids_slice,
        cluster_id,
        if force != 0 { default_idx } else { None },
    );
    let Some(idx) = lookup else {
        *out_ref = -1;
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND;
    };
    let Ok(idx_i32) = i32::try_from(idx) else {
        return MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS;
    };
    *out_ref = idx_i32;
    MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK
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
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS;
    };
    let Ok(clusters_len_usize) = usize::try_from(clusters_len) else {
        return MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS;
    };
    let Some(cluster_ids_slice) = (unsafe { slice_from_ptr(cluster_ids, clusters_len_usize) })
    else {
        return MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS;
    };
    match mtproxy_core::runtime::mtproto::config::finalize_parse_config_state(
        have_proxy != 0,
        cluster_ids_slice,
        default_cluster_id,
    ) {
        Ok(default_cluster_index) => {
            let (has_default_cluster_index, default_cluster_index) =
                if let Some(idx) = default_cluster_index {
                    let Ok(idx_u32) = u32::try_from(idx) else {
                        return MTPROTO_CFG_FINALIZE_ERR_INTERNAL;
                    };
                    (1, idx_u32)
                } else {
                    (0, 0)
                };
            *out_ref = MtproxyMtprotoCfgFinalizeResult {
                default_cluster_index,
                has_default_cluster_index,
            };
            MTPROTO_CFG_FINALIZE_OK
        }
        Err(err) => mtproto_cfg_finalize_err_to_code(err),
    }
}

unsafe fn mtproto_cfg_syntax_literal(msg: &[u8]) {
    unsafe { syntax(msg.as_ptr().cast()) };
}

unsafe fn mtproto_cfg_report_parse_full_pass_error(pass_rc: i32, tot_targets: c_int) {
    match pass_rc {
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TIMEOUT => {
            unsafe { mtproto_cfg_syntax_literal(b"invalid timeout\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MAX_CONNECTIONS => {
            unsafe { mtproto_cfg_syntax_literal(b"invalid max connections\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MIN_CONNECTIONS => {
            unsafe { mtproto_cfg_syntax_literal(b"invalid min connections\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TARGET_ID => {
            unsafe {
                mtproto_cfg_syntax_literal(b"invalid target id (integer -32768..32767 expected)\0")
            };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_TARGET_ID_SPACE => {
            unsafe { mtproto_cfg_syntax_literal(b"space expected after target id\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_AUTH_CLUSTERS => {
            unsafe { mtproto_cfg_syntax_literal(b"too many auth clusters\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXIES_INTERMIXED => {
            unsafe { mtproto_cfg_syntax_literal(b"proxies for dc intermixed\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON => {
            unsafe { mtproto_cfg_syntax_literal(b"';' expected\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXY_EXPECTED => {
            unsafe { mtproto_cfg_syntax_literal(b"'proxy <ip>:<port>;' expected\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_TARGETS => {
            unsafe { syntax(b"too many targets (%d)\0".as_ptr().cast(), tot_targets) };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_HOSTNAME_EXPECTED => {
            unsafe { mtproto_cfg_syntax_literal(b"hostname expected\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_EXPECTED => {
            unsafe { mtproto_cfg_syntax_literal(b"port number expected\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_RANGE => {
            unsafe { mtproto_cfg_syntax_literal(b"port number out of range\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_CLUSTER_EXTEND_INVARIANT => {
            unsafe { mtproto_cfg_syntax_literal(b"IMPOSSIBLE\0") };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES => {
            unsafe {
                mtproto_cfg_syntax_literal(
                    b"expected to find a mtproto-proxy configuration with `proxy' directives\0",
                )
            };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_NO_PROXY_SERVERS_DEFINED => {
            unsafe {
                mtproto_cfg_syntax_literal(
                    b"no MTProto next proxy servers defined to forward queries to\0",
                )
            };
        }
        _ => unsafe { mtproto_cfg_syntax_literal(b"internal parser full-pass failure\0") },
    }
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
    if (flags & 4) == 0 {
        return -1;
    }
    let Some(mc_ref) = (unsafe { mut_ref_from_ptr(mc.cast::<MtproxyMfConfig>()) }) else {
        return -1;
    };
    let mc_ptr = mc_ref as *mut MtproxyMfConfig;

    if (flags & 17) == 0 && unsafe { load_config(config_filename.cast_const(), config_fd) } < 0 {
        return -2;
    }

    unsafe { reset_config() };
    let parse_start = unsafe { cfg_cur };
    let parse_end = unsafe { cfg_end };
    if parse_start.is_null() || parse_end.is_null() {
        unsafe { mtproto_cfg_syntax_literal(b"internal parser cursor mismatch\0") };
        return -1;
    }
    let parse_delta = unsafe { parse_end.offset_from(parse_start) };
    if parse_delta < 0 {
        unsafe { mtproto_cfg_syntax_literal(b"internal parser cursor mismatch\0") };
        return -1;
    }
    let parse_len = parse_delta as usize;

    let actions = unsafe {
        calloc(
            MTPROTO_CFG_MAX_TARGETS,
            core::mem::size_of::<MtproxyMtprotoCfgProxyAction>(),
        )
    }
    .cast::<MtproxyMtprotoCfgProxyAction>();
    if actions.is_null() {
        unsafe { mtproto_cfg_syntax_literal(b"out of memory while parsing configuration\0") };
        return -1;
    }

    let mut res = -1;
    let mut parsed = MtproxyMtprotoCfgParseFullResult::default();
    'parse: loop {
        let pass_rc = unsafe {
            mtproxy_ffi_mtproto_cfg_parse_full_pass(
                parse_start.cast_const(),
                parse_len,
                i64::from(default_cfg_min_connections),
                i64::from(default_cfg_max_connections),
                if (flags & 1) != 0 { 1 } else { 0 },
                MTPROTO_CFG_MAX_CLUSTERS as u32,
                MTPROTO_CFG_MAX_TARGETS as u32,
                actions,
                MTPROTO_CFG_MAX_TARGETS as u32,
                &raw mut parsed,
            )
        };
        if pass_rc != MTPROTO_CFG_PARSE_FULL_PASS_OK {
            unsafe { mtproto_cfg_report_parse_full_pass_error(pass_rc, mc_ref.tot_targets) };
            break 'parse;
        }

        mc_ref.tot_targets = parsed.tot_targets as c_int;
        mc_ref.auth_clusters = parsed.auth_clusters as c_int;
        mc_ref.auth_stats.tot_clusters = parsed.auth_tot_clusters as c_int;
        mc_ref.min_connections = parsed.min_connections as c_int;
        mc_ref.max_connections = parsed.max_connections as c_int;
        mc_ref.timeout = parsed.timeout_seconds;
        mc_ref.default_cluster_id = parsed.default_cluster_id;
        mc_ref.have_proxy = if parsed.have_proxy != 0 { 1 } else { 0 };
        mc_ref.default_cluster = core::ptr::null_mut();

        let Ok(actions_len) = usize::try_from(parsed.actions_len) else {
            unsafe { mtproto_cfg_syntax_literal(b"internal parser action count mismatch\0") };
            break 'parse;
        };
        if actions_len > MTPROTO_CFG_MAX_TARGETS {
            unsafe { mtproto_cfg_syntax_literal(b"internal parser action count mismatch\0") };
            break 'parse;
        }

        for i in 0..actions_len {
            let action = unsafe { *actions.add(i) };
            if action.host_offset > parse_len {
                unsafe { mtproto_cfg_syntax_literal(b"internal parser host offset mismatch\0") };
                break 'parse;
            }
            let Some(host_advance) = action.host_offset.checked_add(action.step.advance) else {
                unsafe { mtproto_cfg_syntax_literal(b"internal parser target advance mismatch\0") };
                break 'parse;
            };
            if host_advance > parse_len {
                unsafe { mtproto_cfg_syntax_literal(b"internal parser target advance mismatch\0") };
                break 'parse;
            }

            let host_cur = unsafe { parse_start.add(action.host_offset) };
            unsafe { cfg_cur = host_cur };
            if unsafe { mtproxy_ffi_mtproto_cfg_resolve_default_target_from_cfg_cur() } < 0 {
                break 'parse;
            }

            if action.step.target_index >= MTPROTO_CFG_MAX_TARGETS as u32
                || action.step.target_index >= parsed.tot_targets
            {
                unsafe { mtproto_cfg_syntax_literal(b"internal parser target index mismatch\0") };
                break 'parse;
            }
            unsafe { cfg_cur = host_cur.add(action.step.advance) };
            unsafe {
                mtproxy_ffi_mtproto_cfg_set_default_target_endpoint(
                    action.step.port,
                    action.step.min_connections,
                    action.step.max_connections,
                    1.0 + 0.1 * drand48(),
                );
            }

            if (flags & 1) != 0 {
                unsafe { mtproxy_ffi_mtproto_cfg_create_target(mc_ptr, action.step.target_index) };
            }

            if action.step.cluster_index < 0
                || action.step.cluster_index >= MTPROTO_CFG_MAX_CLUSTERS as i32
            {
                unsafe {
                    mtproto_cfg_syntax_literal(b"internal parser cluster decision mismatch\0")
                };
                break 'parse;
            }
            if action.step.auth_clusters_after > MTPROTO_CFG_MAX_CLUSTERS as u32 {
                unsafe {
                    mtproto_cfg_syntax_literal(b"internal parser auth cluster count mismatch\0")
                };
                break 'parse;
            }

            let Ok(cluster_index) = usize::try_from(action.step.cluster_index) else {
                unsafe {
                    mtproto_cfg_syntax_literal(b"internal parser cluster decision mismatch\0")
                };
                break 'parse;
            };
            let mfc = &mut mc_ref.auth_cluster[cluster_index];
            mfc.flags = action.step.cluster_state_after.flags as c_int;
            mfc.targets_num = action.step.cluster_state_after.targets_num as c_int;
            mfc.write_targets_num = action.step.cluster_state_after.write_targets_num as c_int;
            mfc.targets_allocated = 0;
            mfc.cluster_id = action.step.cluster_state_after.cluster_id;
            match action.step.cluster_targets_action {
                MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING => {}
                MTPROTO_CFG_CLUSTER_TARGETS_ACTION_CLEAR => {
                    mfc.cluster_targets = core::ptr::null_mut();
                }
                MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET => {
                    if (flags & 1) == 0 {
                        unsafe {
                            mtproto_cfg_syntax_literal(
                                b"internal parser cluster target action mismatch\0",
                            )
                        };
                        break 'parse;
                    }
                    if action.step.cluster_targets_index >= MTPROTO_CFG_MAX_TARGETS as u32
                        || action.step.cluster_targets_index >= action.step.tot_targets_after
                    {
                        unsafe {
                            mtproto_cfg_syntax_literal(
                                b"internal parser cluster target index mismatch\0",
                            )
                        };
                        break 'parse;
                    }
                    let target_index = action.step.cluster_targets_index as usize;
                    mfc.cluster_targets = &mut mc_ref.targets[target_index];
                }
                _ => {
                    unsafe {
                        mtproto_cfg_syntax_literal(
                            b"internal parser cluster target action mismatch\0",
                        )
                    };
                    break 'parse;
                }
            }

            if action.step.cluster_decision_kind
                == MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW
            {
                if unsafe { verbosity } >= 3 {
                    unsafe {
                        kprintf(
                            b"-> added target to new auth_cluster #%d\n\0"
                                .as_ptr()
                                .cast(),
                            action.step.cluster_index,
                        );
                    }
                }
            } else if action.step.cluster_decision_kind
                == MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST
                && unsafe { verbosity } >= 3
            {
                unsafe {
                    kprintf(
                        b"-> added target to old auth_cluster #%d\n\0"
                            .as_ptr()
                            .cast(),
                        action.step.cluster_index,
                    );
                }
            }
        }

        mc_ref.tot_targets = parsed.tot_targets as c_int;
        mc_ref.auth_clusters = parsed.auth_clusters as c_int;
        mc_ref.auth_stats.tot_clusters = parsed.auth_tot_clusters as c_int;
        mc_ref.have_proxy = if parsed.have_proxy != 0 { 1 } else { 0 };
        if parsed.has_default_cluster_index != 0 {
            if parsed.default_cluster_index >= parsed.auth_clusters
                || parsed.default_cluster_index >= MTPROTO_CFG_MAX_CLUSTERS as u32
            {
                unsafe {
                    mtproto_cfg_syntax_literal(b"internal parser default cluster index mismatch\0")
                };
                break 'parse;
            }
            let default_index = parsed.default_cluster_index as usize;
            mc_ref.default_cluster = &mut mc_ref.auth_cluster[default_index];
        } else {
            mc_ref.default_cluster = core::ptr::null_mut();
        }

        res = 0;
        break 'parse;
    }

    unsafe { free(actions.cast()) };
    res
}

/// Full `do_reload_config()` runtime path extracted from C implementation.
///
/// # Safety
/// Uses and mutates process-global C runtime state (`CurConf`, `NextConf`, parser globals).
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_do_reload_config(flags: i32) -> i32 {
    if (flags & 4) == 0 {
        return -1;
    }

    let mut fd = -1;
    if (flags & 16) == 0 {
        fd = unsafe { open(config_filename.cast_const(), O_RDONLY_FLAG) };
        if fd < 0 {
            unsafe {
                kprintf(
                    b"cannot re-read config file %s: %m\n\0".as_ptr().cast(),
                    config_filename,
                );
            }
            return -1;
        }

        let reload_hosts = unsafe { kdb_load_hosts() };
        if reload_hosts > 0 && unsafe { verbosity } >= 1 {
            unsafe { kprintf(b"/etc/hosts changed, reloaded\n\0".as_ptr().cast()) };
        }
    }

    let mut res = unsafe { mtproxy_ffi_mtproto_cfg_parse_config(NextConf.cast(), flags & !1, fd) };

    if fd >= 0 {
        unsafe { close(fd) };
    }

    if res < 0 {
        unsafe {
            kprintf(
                b"error while re-reading config file %s, new configuration NOT applied\n\0"
                    .as_ptr()
                    .cast(),
                config_filename,
            );
        }
        return res;
    }

    if (flags & 32) != 0 {
        return 0;
    }

    res = unsafe { mtproxy_ffi_mtproto_cfg_parse_config(NextConf.cast(), flags | 1, -1) };
    if res < 0 {
        unsafe { clear_config(NextConf, 0) };
        unsafe {
            kprintf(
                b"fatal error while re-reading config file %s\n\0"
                    .as_ptr()
                    .cast(),
                config_filename,
            )
        };
        unsafe { exit(-res) };
    }

    let old_cur_conf = unsafe { CurConf };
    unsafe {
        CurConf = NextConf;
        NextConf = old_cur_conf;
    }

    unsafe { clear_config(NextConf, 1) };
    if (flags & 1) != 0 {
        unsafe { create_all_outbound_connections() };
    }

    let cur_conf = unsafe { CurConf };
    if !cur_conf.is_null() {
        let cur_conf_ref = unsafe { &mut *cur_conf };
        let cur_now = unsafe { mtproxy_ffi_mtproto_cfg_now_or_time() };
        cur_conf_ref.config_loaded_at = cur_now;
        cur_conf_ref.config_bytes = unsafe { config_bytes };
        cur_conf_ref.config_md5_hex = unsafe { malloc(33).cast() };
        if !cur_conf_ref.config_md5_hex.is_null() {
            unsafe {
                md5_hex_config(cur_conf_ref.config_md5_hex);
                *cur_conf_ref.config_md5_hex.add(32) = 0;
            }
        }
    }

    unsafe {
        kprintf(
            b"configuration file %s re-read successfully (%d bytes parsed), new configuration active\n\0"
                .as_ptr()
                .cast(),
            config_filename,
            config_bytes,
        );
    }

    0
}
