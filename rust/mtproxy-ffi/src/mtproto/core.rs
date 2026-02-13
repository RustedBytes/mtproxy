use crate::*;
pub(super) use crate::ffi_util::{mut_ref_from_ptr, mut_slice_from_ptr, ref_from_ptr, slice_from_ptr};

pub(super) fn mtproto_proxy_collect_argv(argc: i32, argv: *const *const c_char) -> Option<Vec<String>> {
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
        out.push(cstr_to_owned(arg_ptr)?);
    }
    if out.is_empty() {
        out.push("mtproto-proxy".to_owned());
    }
    Some(out)
}

pub(super) fn cstr_to_owned(ptr: *const c_char) -> Option<String> {
    let ptr_ref = unsafe { ref_from_ptr(ptr) }?;
    let owned = unsafe { CStr::from_ptr(ptr_ref) }
        .to_string_lossy()
        .into_owned();
    Some(owned)
}

pub(super) fn cfg_bytes_from_cstr(cur: *const c_char, len: usize) -> Option<&'static [u8]> {
    unsafe { slice_from_ptr(cur.cast::<u8>(), len) }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(super) fn copy_mtproto_parse_error_message(out: &mut MtproxyMtprotoParseFunctionResult, message: &str) {
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

pub(super) fn saturating_i32_from_usize(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

pub(super) const AF_INET: c_int = 2;
pub(super) const AF_INET6: c_int = 10;

pub(super) fn mtproto_cfg_collect_auth_cluster_ids(
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

pub(super) fn mtproto_cfg_default_cluster_index(mc: &MtproxyMfConfig, auth_clusters: usize) -> Option<usize> {
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

pub(super) fn mtproto_cfg_forget_cluster_targets(cluster: &mut MtproxyMfCluster) {
    if !cluster.cluster_targets.is_null() {
        cluster.cluster_targets = core::ptr::null_mut();
    }
    cluster.targets_num = 0;
    cluster.write_targets_num = 0;
    cluster.targets_allocated = 0;
}

pub(super) fn mtproto_cfg_clear_cluster(
    group_stats: &mut MtproxyMfGroupStats,
    cluster: &mut MtproxyMfCluster,
) {
    mtproto_cfg_forget_cluster_targets(cluster);
    cluster.flags = 0;
    group_stats.tot_clusters = group_stats.tot_clusters.wrapping_sub(1);
}

/// Updates endpoint-specific defaults used by `create_target`.
///
/// # Safety
/// Mutates process-global `default_cfg_ct` fields.
#[allow(clippy::cast_possible_truncation)]

/// Returns current wall-clock unix seconds.
///
/// # Safety
/// Calls C runtime `time(0)` via FFI.
#[allow(clippy::cast_possible_truncation)]

pub(super) fn mtproto_parse_client_packet_impl(data: &[u8], out: &mut MtproxyMtprotoClientPacketParseResult) {
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

pub(super) fn mtproto_parse_function_impl(
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

pub(super) fn mtproto_cfg_cluster_apply_decision_kind_to_ffi(
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

pub(super) fn mtproto_cfg_cluster_apply_decision_err_to_code(
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

pub(super) fn mtproto_cfg_cluster_targets_action_to_ffi(
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

pub(super) fn mtproto_cfg_parse_proxy_target_step_err_to_code(
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

pub(super) fn mtproto_cfg_parse_full_pass_err_to_code(
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

pub(super) fn mtproto_directive_token_kind_to_ffi(
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

pub(super) fn mtproto_cfg_scan_directive_token_err_to_code(
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

pub(super) fn mtproto_cfg_parse_directive_step_err_to_code(
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

pub(super) fn mtproto_cfg_finalize_err_to_code(
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

pub(super) fn mtproto_old_cluster_from_ffi(
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

pub(super) fn mtproto_old_cluster_to_ffi(
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

pub(super) fn mtproto_cfg_syntax_literal(msg: &[u8]) {
    unsafe { syntax(msg.as_ptr().cast()) };
}

pub(super) fn mtproto_cfg_report_parse_full_pass_error(pass_rc: i32, tot_targets: c_int) {
    match pass_rc {
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TIMEOUT => {
            mtproto_cfg_syntax_literal(b"invalid timeout\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MAX_CONNECTIONS => {
            mtproto_cfg_syntax_literal(b"invalid max connections\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MIN_CONNECTIONS => {
            mtproto_cfg_syntax_literal(b"invalid min connections\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TARGET_ID => {
            mtproto_cfg_syntax_literal(b"invalid target id (integer -32768..32767 expected)\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_TARGET_ID_SPACE => {
            mtproto_cfg_syntax_literal(b"space expected after target id\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_AUTH_CLUSTERS => {
            mtproto_cfg_syntax_literal(b"too many auth clusters\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXIES_INTERMIXED => {
            mtproto_cfg_syntax_literal(b"proxies for dc intermixed\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON => {
            mtproto_cfg_syntax_literal(b"';' expected\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXY_EXPECTED => {
            mtproto_cfg_syntax_literal(b"'proxy <ip>:<port>;' expected\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_TARGETS => {
            unsafe { syntax(b"too many targets (%d)\0".as_ptr().cast(), tot_targets) };
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_HOSTNAME_EXPECTED => {
            mtproto_cfg_syntax_literal(b"hostname expected\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_EXPECTED => {
            mtproto_cfg_syntax_literal(b"port number expected\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_RANGE => {
            mtproto_cfg_syntax_literal(b"port number out of range\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_CLUSTER_EXTEND_INVARIANT => {
            mtproto_cfg_syntax_literal(b"IMPOSSIBLE\0");
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES => {
            mtproto_cfg_syntax_literal(
                b"expected to find a mtproto-proxy configuration with `proxy' directives\0",
            );
        }
        MTPROTO_CFG_PARSE_FULL_PASS_ERR_NO_PROXY_SERVERS_DEFINED => {
            mtproto_cfg_syntax_literal(
                b"no MTProto next proxy servers defined to forward queries to\0",
            );
        }
        _ => mtproto_cfg_syntax_literal(b"internal parser full-pass failure\0"),
    }
}
