//! FFI export surface for mtproto runtime.

use super::core::*;
use crate::*;

/// Prints CLI usage/help for the Rust MTProxy entrypoint.
///
/// # Safety
/// `program_name` may be null; otherwise it must point to a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_proxy_usage(program_name: *const c_char) -> i32 {
    unsafe { mtproto_proxy_usage_ffi(program_name) }
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
    unsafe { mtproto_proxy_main_ffi(argc, argv) }
}

/// Clears runtime config snapshot and optionally destroys target objects.
///
/// # Safety
/// `mc` must point to a writable `struct mf_config` when non-null.
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn clear_config(mc: *mut MtproxyMfConfig, do_destroy_targets: c_int) {
    unsafe { clear_config_ffi(mc, do_destroy_targets) };
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
    unsafe { mf_cluster_lookup_ffi(mc, cluster_id, force) }
}

/// Resolves target hostname from parser cursor and stores it into `default_cfg_ct`.
///
/// # Safety
/// Uses global parser cursors from C runtime and mutates `default_cfg_ct`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_resolve_default_target_from_cfg_cur() -> c_int {
    unsafe { mtproto_cfg_resolve_default_target_from_cfg_cur_ffi() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_set_default_target_endpoint(
    port: u16,
    min_connections: i64,
    max_connections: i64,
    reconnect_timeout: c_double,
) {
    unsafe {
        mtproto_cfg_set_default_target_endpoint_ffi(
            port,
            min_connections,
            max_connections,
            reconnect_timeout,
        )
    };
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
    unsafe { mtproto_cfg_create_target_ffi(mc, target_index) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_now_or_time() -> c_int {
    unsafe { mtproto_cfg_now_or_time_ffi() }
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
    unsafe { mtproto_parse_text_ipv4_ffi(str, out_ip) }
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
    unsafe { mtproto_parse_text_ipv6_ffi(str, out_ip, out_consumed) }
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
    unsafe { mtproto_inspect_packet_header_ffi(header, header_len, packet_len, out) }
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
    unsafe { mtproto_parse_client_packet_ffi(data, len, out) }
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
    unsafe { mtproto_parse_function_ffi(data, len, actor_id, out) }
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
    unsafe { mtproto_cfg_preinit_ffi(default_min_connections, default_max_connections, out) }
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
    unsafe {
        mtproto_cfg_decide_cluster_apply_ffi(
            cluster_ids,
            clusters_len,
            cluster_id,
            max_clusters,
            out,
        )
    }
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
    unsafe { mtproto_cfg_getlex_ext_ffi(cur, len, out) }
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
    unsafe { mtproto_cfg_scan_directive_token_ffi(cur, len, min_connections, max_connections, out) }
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
    unsafe {
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
    unsafe {
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
    unsafe {
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
    unsafe { mtproto_cfg_expect_semicolon_ffi(cur, len, out_advance) }
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
    unsafe {
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
    unsafe {
        mtproto_cfg_finalize_ffi(
            have_proxy,
            cluster_ids,
            clusters_len,
            default_cluster_id,
            out,
        )
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
    unsafe { mtproto_cfg_parse_config_ffi(mc, flags, config_fd) }
}

/// Full `do_reload_config()` runtime path extracted from C implementation.
///
/// # Safety
/// Uses and mutates process-global C runtime state (`CurConf`, `NextConf`, parser globals).
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_mtproto_cfg_do_reload_config(flags: i32) -> i32 {
    unsafe { mtproto_cfg_do_reload_config_ffi(flags) }
}
