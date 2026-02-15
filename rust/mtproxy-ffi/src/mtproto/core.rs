pub(super) use crate::ffi_util::{
    mut_ref_from_ptr, mut_slice_from_ptr, ref_from_ptr, slice_from_ptr,
};
use crate::*;

pub(super) fn mtproto_proxy_collect_argv(
    argc: i32,
    argv: *const *const c_char,
) -> Option<Vec<String>> {
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
pub(super) fn copy_mtproto_parse_error_message(
    out: &mut MtproxyMtprotoParseFunctionResult,
    message: &str,
) {
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

static MTPROTO_EXT_CONN_TABLE: std::sync::LazyLock<
    Mutex<mtproxy_core::runtime::mtproto::proxy::ExtConnectionTable>,
> = std::sync::LazyLock::new(|| {
    Mutex::new(mtproxy_core::runtime::mtproto::proxy::ExtConnectionTable::new())
});

fn ext_conn_lock(
) -> std::sync::MutexGuard<'static, mtproxy_core::runtime::mtproto::proxy::ExtConnectionTable> {
    MTPROTO_EXT_CONN_TABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ext_conn_to_ffi(
    conn: mtproxy_core::runtime::mtproto::proxy::ExtConnection,
) -> MtproxyMtprotoExtConnection {
    MtproxyMtprotoExtConnection {
        in_fd: conn.in_fd,
        in_gen: conn.in_gen,
        out_fd: conn.out_fd,
        out_gen: conn.out_gen,
        in_conn_id: conn.in_conn_id,
        out_conn_id: conn.out_conn_id,
        auth_key_id: conn.auth_key_id,
    }
}

pub(super) unsafe fn mtproto_ext_conn_reset_ffi() {
    let mut table = ext_conn_lock();
    *table = mtproxy_core::runtime::mtproto::proxy::ExtConnectionTable::new();
}

pub(super) unsafe fn mtproto_ext_conn_create_ffi(
    in_fd: c_int,
    in_gen: c_int,
    in_conn_id: i64,
    out_fd: c_int,
    out_gen: c_int,
    auth_key_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    let created = match table.get_ext_connection_by_in_conn_id(
        in_fd,
        in_gen,
        in_conn_id,
        mtproxy_core::runtime::mtproto::proxy::ExtConnLookupMode::CreateIfMissing,
    ) {
        Ok(mtproxy_core::runtime::mtproto::proxy::ExtConnLookupOutcome::Created(conn)) => conn,
        Ok(mtproxy_core::runtime::mtproto::proxy::ExtConnLookupOutcome::AlreadyExists)
        | Ok(mtproxy_core::runtime::mtproto::proxy::ExtConnLookupOutcome::Found(_)) => return 0,
        Ok(_) => return 0,
        Err(_) => return -1,
    };
    let bind_target = if out_fd != 0 {
        Some((out_fd, out_gen))
    } else {
        None
    };
    match table.bind_ext_connection(created.in_fd, created.in_conn_id, bind_target, auth_key_id) {
        Ok(conn) => {
            *out_ref = ext_conn_to_ffi(conn);
            1
        }
        Err(_) => {
            let _ = table.remove_ext_connection_by_in_conn_id(created.in_fd, created.in_conn_id);
            -1
        }
    }
}

pub(super) unsafe fn mtproto_ext_conn_get_by_in_fd_ffi(
    in_fd: c_int,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let table = ext_conn_lock();
    match table.get_ext_connection_by_in_fd(in_fd) {
        Ok(Some(conn)) => {
            *out_ref = ext_conn_to_ffi(conn);
            1
        }
        Ok(None) => 0,
        Err(_) => -1,
    }
}

pub(super) unsafe fn mtproto_ext_conn_get_by_out_conn_id_ffi(
    out_conn_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let table = ext_conn_lock();
    if let Some(conn) = table.find_ext_connection_by_out_conn_id(out_conn_id) {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) unsafe fn mtproto_ext_conn_update_auth_key_ffi(
    in_fd: c_int,
    in_conn_id: i64,
    auth_key_id: i64,
) -> i32 {
    let mut table = ext_conn_lock();
    if table
        .update_auth_key(in_fd, in_conn_id, auth_key_id)
        .is_ok()
    {
        1
    } else {
        0
    }
}

pub(super) unsafe fn mtproto_ext_conn_remove_by_out_conn_id_ffi(
    out_conn_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    if let Some(conn) = table.take_ext_connection_by_out_conn_id(out_conn_id) {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) unsafe fn mtproto_ext_conn_remove_by_in_conn_id_ffi(
    in_fd: c_int,
    in_conn_id: i64,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    if let Some(conn) = table.take_ext_connection_by_in_conn_id(in_fd, in_conn_id) {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) unsafe fn mtproto_ext_conn_remove_any_by_out_fd_ffi(
    out_fd: c_int,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    if let Some(conn) = table.pop_any_ext_connection_by_out_fd(out_fd) {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) unsafe fn mtproto_ext_conn_remove_any_by_in_fd_ffi(
    in_fd: c_int,
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    if let Some(conn) = table.pop_any_ext_connection_by_in_fd(in_fd) {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) unsafe fn mtproto_ext_conn_lru_insert_ffi(in_fd: c_int, in_gen: c_int) -> i32 {
    let mut table = ext_conn_lock();
    match table.lru_insert_by_in_fd_gen(in_fd, in_gen) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

pub(super) unsafe fn mtproto_ext_conn_lru_delete_ffi(in_fd: c_int) -> i32 {
    let mut table = ext_conn_lock();
    match table.lru_delete_by_in_fd(in_fd) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

pub(super) unsafe fn mtproto_ext_conn_lru_pop_oldest_ffi(
    out: *mut MtproxyMtprotoExtConnection,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let mut table = ext_conn_lock();
    if let Some(conn) = table.lru_pop_oldest() {
        *out_ref = ext_conn_to_ffi(conn);
        1
    } else {
        0
    }
}

pub(super) unsafe fn mtproto_ext_conn_counts_ffi(
    out_current: *mut i64,
    out_created: *mut i64,
) -> i32 {
    let Some(out_current_ref) = (unsafe { mut_ref_from_ptr(out_current) }) else {
        return -1;
    };
    let Some(out_created_ref) = (unsafe { mut_ref_from_ptr(out_created) }) else {
        return -1;
    };
    let table = ext_conn_lock();
    *out_current_ref = i64::try_from(table.ext_connections()).unwrap_or(i64::MAX);
    *out_created_ref = i64::try_from(table.ext_connections_created()).unwrap_or(i64::MAX);
    0
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn mtproto_build_rpc_proxy_req_ffi(
    flags: c_int,
    out_conn_id: i64,
    remote_ipv6: *const u8,
    remote_port: c_int,
    our_ipv6: *const u8,
    our_port: c_int,
    proxy_tag: *const u8,
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
    let Some(out_len_ref) = (unsafe { mut_ref_from_ptr(out_len) }) else {
        return -1;
    };
    let Some(remote_ipv6_slice) = (unsafe { slice_from_ptr(remote_ipv6, 16) }) else {
        return -1;
    };
    let Some(our_ipv6_slice) = (unsafe { slice_from_ptr(our_ipv6, 16) }) else {
        return -1;
    };
    let Some(payload_slice) = (unsafe { slice_from_ptr(payload, payload_len) }) else {
        return -1;
    };

    let mut remote_ipv6_arr = [0u8; 16];
    remote_ipv6_arr.copy_from_slice(remote_ipv6_slice);
    let mut our_ipv6_arr = [0u8; 16];
    our_ipv6_arr.copy_from_slice(our_ipv6_slice);

    let proxy_tag = if (flags & 8) != 0 {
        let Some(tag) = (unsafe { slice_from_ptr(proxy_tag, proxy_tag_len) }) else {
            return -1;
        };
        Some(tag)
    } else {
        None
    };
    let http_query_info = if (flags & 4) != 0 {
        let Some(origin) = (unsafe { slice_from_ptr(http_origin, http_origin_len) }) else {
            return -1;
        };
        let Some(referer) = (unsafe { slice_from_ptr(http_referer, http_referer_len) }) else {
            return -1;
        };
        let Some(user_agent) = (unsafe { slice_from_ptr(http_user_agent, http_user_agent_len) })
        else {
            return -1;
        };
        Some(mtproxy_core::runtime::mtproto::proxy::HttpQueryInfo {
            origin,
            referer,
            user_agent,
        })
    } else {
        None
    };

    let input = mtproxy_core::runtime::mtproto::proxy::ProxyReqBuildInput {
        flags,
        out_conn_id,
        remote_ipv6: remote_ipv6_arr,
        remote_port,
        our_ipv6: our_ipv6_arr,
        our_port,
        proxy_tag,
        http_query_info,
        payload: payload_slice,
    };

    let mut scratch_cap = payload_len
        .saturating_add(proxy_tag_len)
        .saturating_add(http_origin_len)
        .saturating_add(http_referer_len)
        .saturating_add(http_user_agent_len)
        .saturating_add(256)
        .max(64);

    loop {
        let mut scratch = vec![0u8; scratch_cap];
        match mtproxy_core::runtime::mtproto::proxy::build_rpc_proxy_req(&mut scratch, &input) {
            Ok(used) => {
                *out_len_ref = used;
                if out_buf.is_null() || out_cap < used {
                    return 1;
                }
                let Some(out_slice) = (unsafe { mut_slice_from_ptr(out_buf, out_cap) }) else {
                    return -1;
                };
                out_slice[..used].copy_from_slice(&scratch[..used]);
                return 0;
            }
            Err(err) => {
                if err.errnum != mtproxy_core::runtime::config::tl_parse::TL_ERROR_NOT_ENOUGH_DATA {
                    return -2;
                }
                let next = scratch_cap.saturating_mul(2);
                if next <= scratch_cap {
                    return -2;
                }
                scratch_cap = next;
            }
        }
    }
}

pub(super) unsafe fn mtproto_build_http_ok_header_ffi(
    keep_alive: c_int,
    extra_headers: c_int,
    content_len: c_int,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if content_len < 0 {
        return -2;
    }
    let Some(out_len_ref) = (unsafe { mut_ref_from_ptr(out_len) }) else {
        return -1;
    };

    let connection = if keep_alive != 0 {
        "keep-alive"
    } else {
        "close"
    };
    let extra = if extra_headers != 0 {
        "Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: POST, OPTIONS\r\n\
Access-Control-Allow-Headers: origin, content-type\r\n\
Access-Control-Max-Age: 1728000\r\n"
    } else {
        ""
    };
    let header = format!(
        "HTTP/1.1 200 OK\r\nConnection: {connection}\r\nContent-type: application/octet-stream\r\nPragma: no-cache\r\nCache-control: no-store\r\n{extra}Content-length: {content_len}\r\n\r\n"
    );
    let bytes = header.as_bytes();
    *out_len_ref = bytes.len();
    if out_buf.is_null() || out_cap < bytes.len() {
        return 1;
    }
    let Some(out_slice) = (unsafe { mut_slice_from_ptr(out_buf, out_cap) }) else {
        return -1;
    };
    out_slice[..bytes.len()].copy_from_slice(bytes);
    0
}

pub(super) unsafe fn mtproto_client_send_non_http_wrap_ffi(
    tlio_in: *mut c_void,
    tlio_out: *mut c_void,
) -> i32 {
    let tlio_in = tlio_in.cast::<crate::tl_parse::abi::TlInState>();
    let tlio_out = tlio_out.cast::<crate::tl_parse::abi::TlOutState>();
    let unread = unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_fetch_unread(tlio_in) };
    if unread < 0 {
        return -1;
    }
    let copy_rc =
        unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_copy_through(tlio_in, tlio_out, unread, 1) };
    if copy_rc < 0 {
        return -1;
    }
    let mut sent_kind = 0;
    let end_rc =
        unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_store_end_ext(tlio_out, 0, &mut sent_kind) };
    if end_rc < 0 {
        return -1;
    }
    0
}

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

pub(super) fn mtproto_cfg_default_cluster_index(
    mc: &MtproxyMfConfig,
    auth_clusters: usize,
) -> Option<usize> {
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

pub(super) fn mtproto_parse_client_packet_impl(
    data: &[u8],
    out: &mut MtproxyMtprotoClientPacketParseResult,
) {
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

fn mtproto_client_packet_fill_ext_fields(
    out: &mut MtproxyMtprotoClientPacketProcessResult,
    ext: mtproxy_core::runtime::mtproto::proxy::ExtConnection,
) {
    out.in_fd = ext.in_fd;
    out.in_gen = ext.in_gen;
    out.in_conn_id = ext.in_conn_id;
    out.out_fd = ext.out_fd;
    out.out_gen = ext.out_gen;
    out.auth_key_id = ext.auth_key_id;
}

pub(super) fn mtproto_process_client_packet_impl(
    data: &[u8],
    conn_fd: i32,
    conn_gen: i32,
    out: &mut MtproxyMtprotoClientPacketProcessResult,
) {
    use mtproxy_core::runtime::mtproto::proxy::RpcClientPacket;

    *out = MtproxyMtprotoClientPacketProcessResult::default();

    match mtproxy_core::runtime::mtproto::proxy::parse_client_packet(data) {
        RpcClientPacket::ProxyAns {
            flags,
            out_conn_id,
            payload,
        } => {
            let payload_offset = data.len().saturating_sub(payload.len());
            let payload_offset_i32 = saturating_i32_from_usize(payload_offset);
            if payload_offset_i32 < 0 {
                out.kind = MTPROTO_CLIENT_PACKET_ACTION_INVALID;
                return;
            }
            out.payload_offset = payload_offset_i32;
            out.flags = flags;
            out.out_conn_id = out_conn_id;

            let table = ext_conn_lock();
            if let Some(ext) = table.find_ext_connection_by_out_conn_id(out_conn_id) {
                if ext.out_fd == conn_fd && ext.out_gen == conn_gen {
                    out.kind = MTPROTO_CLIENT_PACKET_ACTION_PROXY_ANS_FORWARD;
                    mtproto_client_packet_fill_ext_fields(out, ext);
                } else {
                    out.kind = MTPROTO_CLIENT_PACKET_ACTION_PROXY_ANS_NOTIFY_CLOSE;
                }
            } else {
                out.kind = MTPROTO_CLIENT_PACKET_ACTION_PROXY_ANS_NOTIFY_CLOSE;
            }
        }
        RpcClientPacket::SimpleAck {
            out_conn_id,
            confirm,
        } => {
            out.confirm = confirm;
            out.out_conn_id = out_conn_id;
            let table = ext_conn_lock();
            if let Some(ext) = table.find_ext_connection_by_out_conn_id(out_conn_id) {
                if ext.out_fd == conn_fd && ext.out_gen == conn_gen {
                    out.kind = MTPROTO_CLIENT_PACKET_ACTION_SIMPLE_ACK_FORWARD;
                    mtproto_client_packet_fill_ext_fields(out, ext);
                } else {
                    out.kind = MTPROTO_CLIENT_PACKET_ACTION_SIMPLE_ACK_NOTIFY_CLOSE;
                }
            } else {
                out.kind = MTPROTO_CLIENT_PACKET_ACTION_SIMPLE_ACK_NOTIFY_CLOSE;
            }
        }
        RpcClientPacket::CloseExt { out_conn_id } => {
            out.out_conn_id = out_conn_id;
            let mut table = ext_conn_lock();
            if let Some(ext) = table.take_ext_connection_by_out_conn_id(out_conn_id) {
                out.kind = MTPROTO_CLIENT_PACKET_ACTION_CLOSE_EXT_REMOVED;
                mtproto_client_packet_fill_ext_fields(out, ext);
            } else {
                out.kind = MTPROTO_CLIENT_PACKET_ACTION_CLOSE_EXT_NOOP;
            }
        }
        RpcClientPacket::Pong
        | RpcClientPacket::Unknown { .. }
        | RpcClientPacket::Malformed { .. } => {
            out.kind = MTPROTO_CLIENT_PACKET_ACTION_INVALID;
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

pub(super) unsafe fn mtproto_proxy_usage_ffi(program_name: *const c_char) -> i32 {
    let program_name = if program_name.is_null() {
        "mtproto-proxy".to_owned()
    } else {
        let Some(program_name_ref) = cstr_to_owned(program_name) else {
            return -1;
        };
        program_name_ref
    };

    let usage = mtproxy_bin::entrypoint::usage_text(&program_name);
    eprint!("{usage}");
    0
}

pub(super) unsafe fn mtproto_proxy_main_ffi(argc: i32, argv: *const *const c_char) -> i32 {
    let Some(args) = mtproto_proxy_collect_argv(argc, argv) else {
        eprintln!("ERROR: invalid argv passed to mtproxy_ffi_mtproto_proxy_main");
        return 1;
    };
    mtproxy_bin::entrypoint::run_from_argv(&args)
}

#[allow(private_interfaces)]
pub(super) unsafe fn clear_config_ffi(mc: *mut MtproxyMfConfig, do_destroy_targets: c_int) {
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

#[allow(private_interfaces)]
pub(super) unsafe fn mf_cluster_lookup_ffi(
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
    let lookup = mtproxy_core::runtime::mtproto::config::mf_cluster_lookup_index(
        &cluster_ids[..auth_clusters],
        cluster_id,
        if force != 0 {
            default_cluster_index
        } else {
            None
        },
    );
    if let Some(idx) = lookup {
        if idx < auth_clusters {
            return &mut mc_ref.auth_cluster[idx];
        }
    }
    if force != 0 {
        mc_ref.default_cluster
    } else {
        core::ptr::null_mut()
    }
}

pub(super) unsafe fn mtproto_cfg_resolve_default_target_from_cfg_cur_ffi() -> c_int {
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

    mtproto_cfg_syntax_literal(b"cannot resolve hostname\0");
    -1
}

pub(super) unsafe fn mtproto_cfg_set_default_target_endpoint_ffi(
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

#[allow(private_interfaces)]
pub(super) unsafe fn mtproto_cfg_create_target_ffi(mc: *mut MtproxyMfConfig, target_index: u32) {
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

pub(super) unsafe fn mtproto_cfg_now_or_time_ffi() -> c_int {
    unsafe { time(core::ptr::null_mut()) as c_int }
}

pub(super) unsafe fn mtproto_parse_text_ipv4_ffi(str: *const c_char, out_ip: *mut u32) -> i32 {
    let Some(input) = cstr_to_owned(str) else {
        return -1;
    };
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_ip) }) else {
        return -1;
    };
    let parsed = mtproxy_core::runtime::mtproto::proxy::parse_text_ipv4(&input);
    *out_ref = parsed;
    0
}

pub(super) unsafe fn mtproto_parse_text_ipv6_ffi(
    str: *const c_char,
    out_ip: *mut u8,
    out_consumed: *mut i32,
) -> i32 {
    let Some(input) = cstr_to_owned(str) else {
        return -1;
    };
    let Some(out_ip_slice) = (unsafe { mut_slice_from_ptr(out_ip, 16) }) else {
        return -1;
    };
    let Some(out_consumed_ref) = (unsafe { mut_ref_from_ptr(out_consumed) }) else {
        return -1;
    };
    let mut parsed_ip = [0u8; 16];
    let consumed = mtproxy_core::runtime::mtproto::proxy::parse_text_ipv6(&mut parsed_ip, &input);
    out_ip_slice.copy_from_slice(&parsed_ip);
    *out_consumed_ref = consumed;
    0
}

pub(super) unsafe fn mtproto_inspect_packet_header_ffi(
    header: *const u8,
    header_len: usize,
    packet_len: i32,
    out: *mut MtproxyMtprotoPacketInspectResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = (unsafe { slice_from_ptr(header, header_len) }) else {
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

pub(super) unsafe fn mtproto_parse_client_packet_ffi(
    data: *const u8,
    len: usize,
    out: *mut MtproxyMtprotoClientPacketParseResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = (unsafe { slice_from_ptr(data, len) }) else {
        return -1;
    };
    *out_ref = MtproxyMtprotoClientPacketParseResult {
        kind: MTPROTO_CLIENT_PACKET_KIND_INVALID,
        ..MtproxyMtprotoClientPacketParseResult::default()
    };
    mtproto_parse_client_packet_impl(bytes, out_ref);
    0
}

pub(super) unsafe fn mtproto_process_client_packet_ffi(
    data: *const u8,
    len: usize,
    conn_fd: c_int,
    conn_gen: c_int,
    out: *mut MtproxyMtprotoClientPacketProcessResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = (unsafe { slice_from_ptr(data, len) }) else {
        return -1;
    };
    *out_ref = MtproxyMtprotoClientPacketProcessResult::default();
    mtproto_process_client_packet_impl(bytes, conn_fd, conn_gen, out_ref);
    0
}

pub(super) unsafe fn mtproto_parse_function_ffi(
    data: *const u8,
    len: usize,
    actor_id: i64,
    out: *mut MtproxyMtprotoParseFunctionResult,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(bytes) = (unsafe { slice_from_ptr(data, len) }) else {
        return -1;
    };
    *out_ref = MtproxyMtprotoParseFunctionResult::default();
    mtproto_parse_function_impl(bytes, actor_id, out_ref);
    0
}

pub(super) unsafe fn mtproto_cfg_preinit_ffi(
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

pub(super) unsafe fn mtproto_cfg_decide_cluster_apply_ffi(
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

pub(super) unsafe fn mtproto_cfg_getlex_ext_ffi(
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

pub(super) unsafe fn mtproto_cfg_scan_directive_token_ffi(
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

pub(super) unsafe fn mtproto_cfg_parse_directive_step_ffi(
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

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn mtproto_cfg_parse_proxy_target_step_ffi(
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

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn mtproto_cfg_parse_full_pass_ffi(
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

pub(super) unsafe fn mtproto_cfg_expect_semicolon_ffi(
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

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn mtproto_cfg_lookup_cluster_index_ffi(
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

pub(super) unsafe fn mtproto_cfg_finalize_ffi(
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

pub(super) unsafe fn mtproto_cfg_parse_config_ffi(
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
        mtproto_cfg_syntax_literal(b"internal parser cursor mismatch\0");
        return -1;
    }
    let parse_delta = unsafe { parse_end.offset_from(parse_start) };
    if parse_delta < 0 {
        mtproto_cfg_syntax_literal(b"internal parser cursor mismatch\0");
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
        mtproto_cfg_syntax_literal(b"out of memory while parsing configuration\0");
        return -1;
    }

    let mut res = -1;
    let mut parsed = MtproxyMtprotoCfgParseFullResult::default();
    'parse: loop {
        let pass_rc = unsafe {
            mtproto_cfg_parse_full_pass_ffi(
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
            mtproto_cfg_report_parse_full_pass_error(pass_rc, mc_ref.tot_targets);
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
            mtproto_cfg_syntax_literal(b"internal parser action count mismatch\0");
            break 'parse;
        };
        if actions_len > MTPROTO_CFG_MAX_TARGETS {
            mtproto_cfg_syntax_literal(b"internal parser action count mismatch\0");
            break 'parse;
        }

        for i in 0..actions_len {
            let action = unsafe { *actions.add(i) };
            if action.host_offset > parse_len {
                mtproto_cfg_syntax_literal(b"internal parser host offset mismatch\0");
                break 'parse;
            }
            let Some(host_advance) = action.host_offset.checked_add(action.step.advance) else {
                mtproto_cfg_syntax_literal(b"internal parser target advance mismatch\0");
                break 'parse;
            };
            if host_advance > parse_len {
                mtproto_cfg_syntax_literal(b"internal parser target advance mismatch\0");
                break 'parse;
            }

            let host_cur = unsafe { parse_start.add(action.host_offset) };
            unsafe { cfg_cur = host_cur };
            if unsafe { mtproto_cfg_resolve_default_target_from_cfg_cur_ffi() } < 0 {
                break 'parse;
            }

            if action.step.target_index >= MTPROTO_CFG_MAX_TARGETS as u32
                || action.step.target_index >= parsed.tot_targets
            {
                mtproto_cfg_syntax_literal(b"internal parser target index mismatch\0");
                break 'parse;
            }
            unsafe { cfg_cur = host_cur.add(action.step.advance) };
            unsafe {
                mtproto_cfg_set_default_target_endpoint_ffi(
                    action.step.port,
                    action.step.min_connections,
                    action.step.max_connections,
                    1.0 + 0.1 * drand48(),
                );
            }

            if (flags & 1) != 0 {
                unsafe { mtproto_cfg_create_target_ffi(mc_ptr, action.step.target_index) };
            }

            if action.step.cluster_index < 0
                || action.step.cluster_index >= MTPROTO_CFG_MAX_CLUSTERS as i32
            {
                mtproto_cfg_syntax_literal(b"internal parser cluster decision mismatch\0");
                break 'parse;
            }
            if action.step.auth_clusters_after > MTPROTO_CFG_MAX_CLUSTERS as u32 {
                mtproto_cfg_syntax_literal(b"internal parser auth cluster count mismatch\0");
                break 'parse;
            }

            let Ok(cluster_index) = usize::try_from(action.step.cluster_index) else {
                mtproto_cfg_syntax_literal(b"internal parser cluster decision mismatch\0");
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
                        mtproto_cfg_syntax_literal(
                            b"internal parser cluster target action mismatch\0",
                        );
                        break 'parse;
                    }
                    if action.step.cluster_targets_index >= MTPROTO_CFG_MAX_TARGETS as u32
                        || action.step.cluster_targets_index >= action.step.tot_targets_after
                    {
                        mtproto_cfg_syntax_literal(
                            b"internal parser cluster target index mismatch\0",
                        );
                        break 'parse;
                    }
                    let target_index = action.step.cluster_targets_index as usize;
                    mfc.cluster_targets = &mut mc_ref.targets[target_index];
                }
                _ => {
                    mtproto_cfg_syntax_literal(b"internal parser cluster target action mismatch\0");
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
                mtproto_cfg_syntax_literal(b"internal parser default cluster index mismatch\0");
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

pub(super) unsafe fn mtproto_cfg_do_reload_config_ffi(flags: i32) -> i32 {
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

    let mut res = unsafe { mtproto_cfg_parse_config_ffi(NextConf.cast(), flags & !1, fd) };

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

    res = unsafe { mtproto_cfg_parse_config_ffi(NextConf.cast(), flags | 1, -1) };
    if res < 0 {
        unsafe { clear_config_ffi(NextConf, 0) };
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

    unsafe { clear_config_ffi(NextConf, 1) };
    if (flags & 1) != 0 {
        unsafe { create_all_outbound_connections() };
    }

    let cur_conf = unsafe { CurConf };
    if !cur_conf.is_null() {
        let cur_conf_ref = unsafe { &mut *cur_conf };
        let cur_now = unsafe { mtproto_cfg_now_or_time_ffi() };
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
