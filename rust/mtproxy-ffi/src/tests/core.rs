use super::{
    ffi_api_version, mtproxy_ffi_aesni_crypt, mtproxy_ffi_aesni_ctx_free,
    mtproxy_ffi_aesni_ctx_init, mtproxy_ffi_api_version, mtproxy_ffi_cfg_getint_signed_zero,
    mtproxy_ffi_cfg_getword_len, mtproxy_ffi_cfg_skipspc, mtproxy_ffi_cpuid_fill,
    mtproxy_ffi_crc32_check_and_repair, mtproxy_ffi_crc32_partial, mtproxy_ffi_crc32c_partial,
    mtproxy_ffi_crypto_aes_create_keys, mtproxy_ffi_crypto_dh_first_round,
    mtproxy_ffi_crypto_dh_get_params_select, mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin,
    mtproxy_ffi_crypto_dh_second_round, mtproxy_ffi_crypto_dh_third_round,
    mtproxy_ffi_crypto_rand_bytes, mtproxy_ffi_crypto_tls_generate_public_key,
    mtproxy_ffi_engine_interrupt_signal_raised, mtproxy_ffi_engine_net_default_port_mod,
    mtproxy_ffi_engine_net_open_privileged_port, mtproxy_ffi_engine_net_try_open_port_range,
    mtproxy_ffi_engine_process_signals_allowed,
    mtproxy_ffi_engine_rpc_common_default_parse_decision,
    mtproxy_ffi_engine_rpc_common_default_query_type_mask, mtproxy_ffi_engine_rpc_need_dup,
    mtproxy_ffi_engine_rpc_query_job_dispatch_decision,
    mtproxy_ffi_engine_rpc_query_result_dispatch_decision,
    mtproxy_ffi_engine_rpc_query_result_type_id_from_qid, mtproxy_ffi_engine_rpc_result_header_len,
    mtproxy_ffi_engine_rpc_result_new_flags, mtproxy_ffi_engine_rpc_tcp_should_hold_conn,
    mtproxy_ffi_engine_signal_check_pending, mtproxy_ffi_engine_signal_check_pending_and_clear,
    mtproxy_ffi_engine_signal_set_pending, mtproxy_ffi_get_application_boundary,
    mtproxy_ffi_get_concurrency_boundary, mtproxy_ffi_get_crypto_boundary,
    mtproxy_ffi_get_network_boundary, mtproxy_ffi_get_precise_time, mtproxy_ffi_get_rpc_boundary,
    mtproxy_ffi_get_utime_monotonic, mtproxy_ffi_gf32_combine_clmul,
    mtproxy_ffi_gf32_compute_powers_clmul, mtproxy_ffi_matches_pid, mtproxy_ffi_md5,
    mtproxy_ffi_md5_hex, mtproxy_ffi_msg_buffers_pick_size_index,
    mtproxy_ffi_mtproto_cfg_decide_cluster_apply, mtproxy_ffi_mtproto_cfg_expect_semicolon,
    mtproxy_ffi_mtproto_cfg_finalize, mtproxy_ffi_mtproto_cfg_getlex_ext,
    mtproxy_ffi_mtproto_cfg_lookup_cluster_index, mtproxy_ffi_mtproto_cfg_parse_directive_step,
    mtproxy_ffi_mtproto_cfg_parse_full_pass, mtproxy_ffi_mtproto_cfg_parse_proxy_target_step,
    mtproxy_ffi_mtproto_cfg_preinit, mtproxy_ffi_mtproto_cfg_scan_directive_token,
    mtproxy_ffi_mtproto_conn_tag, mtproxy_ffi_mtproto_ext_conn_hash,
    mtproxy_ffi_mtproto_inspect_packet_header, mtproxy_ffi_mtproto_parse_client_packet,
    mtproxy_ffi_mtproto_parse_function, mtproxy_ffi_mtproto_parse_text_ipv4,
    mtproxy_ffi_mtproto_parse_text_ipv6, mtproxy_ffi_net_add_nat_info,
    mtproxy_ffi_net_compute_conn_events, mtproxy_ffi_net_connection_is_active,
    mtproxy_ffi_net_epoll_conv_flags, mtproxy_ffi_net_epoll_unconv_flags,
    mtproxy_ffi_net_http_error_msg_text, mtproxy_ffi_net_http_gen_date,
    mtproxy_ffi_net_http_gen_time, mtproxy_ffi_net_select_best_key_signature,
    mtproxy_ffi_net_timers_wait_msec, mtproxy_ffi_net_translate_ip,
    mtproxy_ffi_parse_meminfo_summary, mtproxy_ffi_parse_proc_stat_line, mtproxy_ffi_parse_statm,
    mtproxy_ffi_pid_init_common, mtproxy_ffi_precise_now_rdtsc_value,
    mtproxy_ffi_precise_now_value, mtproxy_ffi_process_id_is_newer,
    mtproxy_ffi_read_proc_stat_file, mtproxy_ffi_rpc_target_normalize_pid, mtproxy_ffi_sha1,
    mtproxy_ffi_sha1_two_chunks, mtproxy_ffi_sha256, mtproxy_ffi_sha256_hmac,
    mtproxy_ffi_sha256_two_chunks, mtproxy_ffi_startup_handshake,
    mtproxy_ffi_tcp_rpc_client_packet_len_state, mtproxy_ffi_tcp_rpc_encode_compact_header,
    mtproxy_ffi_tcp_rpc_server_packet_header_malformed,
    mtproxy_ffi_tcp_rpc_server_packet_len_state, mtproxy_ffi_tl_parse_answer_header,
    mtproxy_ffi_tl_parse_query_header, MtproxyAesKeyData, MtproxyApplicationBoundary,
    MtproxyCfgIntResult, MtproxyCfgScanResult, MtproxyConcurrencyBoundary, MtproxyCpuid,
    MtproxyCryptoBoundary, MtproxyMeminfoSummary, MtproxyMtprotoCfgClusterApplyDecisionResult,
    MtproxyMtprotoCfgDirectiveStepResult, MtproxyMtprotoCfgDirectiveTokenResult,
    MtproxyMtprotoCfgFinalizeResult, MtproxyMtprotoCfgGetlexExtResult,
    MtproxyMtprotoCfgParseFullResult, MtproxyMtprotoCfgParseProxyTargetStepResult,
    MtproxyMtprotoCfgPreinitResult, MtproxyMtprotoCfgProxyAction,
    MtproxyMtprotoClientPacketParseResult, MtproxyMtprotoOldClusterState,
    MtproxyMtprotoPacketInspectResult, MtproxyMtprotoParseFunctionResult, MtproxyNetworkBoundary,
    MtproxyProcStats, MtproxyProcessId, MtproxyRpcBoundary, MtproxyTlHeaderParseResult,
    AESNI_CIPHER_AES_256_CTR, AESNI_CONTRACT_OPS, AESNI_IMPLEMENTED_OPS,
    APPLICATION_BOUNDARY_VERSION, CONCURRENCY_BOUNDARY_VERSION, CPUID_MAGIC, CRC32_REFLECTED_POLY,
    CRYPTO_BOUNDARY_VERSION, DH_KEY_BYTES, DH_PARAMS_SELECT, ENGINE_RPC_CONTRACT_OPS,
    ENGINE_RPC_IMPLEMENTED_OPS, EPOLLERR, EPOLLET, EPOLLIN, EPOLLOUT, EPOLLPRI, EPOLLRDHUP,
    EVT_FROM_EPOLL, EVT_LEVEL, EVT_READ, EVT_SPEC, EVT_WRITE, FFI_API_VERSION,
    GF32_CLMUL_POWERS_LEN, JOBS_CONTRACT_OPS, JOBS_IMPLEMENTED_OPS, MPQ_CONTRACT_OPS,
    MPQ_IMPLEMENTED_OPS, MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_PROXIES_INTERMIXED,
    MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_TOO_MANY_AUTH_CLUSTERS,
    MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST,
    MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW, MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK,
    MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING,
    MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET, MTPROTO_CFG_EXPECT_SEMICOLON_ERR_EXPECTED,
    MTPROTO_CFG_EXPECT_SEMICOLON_OK, MTPROTO_CFG_FINALIZE_ERR_MISSING_PROXY_DIRECTIVES,
    MTPROTO_CFG_FINALIZE_ERR_NO_PROXY_SERVERS_DEFINED, MTPROTO_CFG_FINALIZE_OK,
    MTPROTO_CFG_GETLEX_EXT_OK, MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND,
    MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK, MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_EXPECTED_SEMICOLON,
    MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXIES_INTERMIXED, MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK,
    MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON,
    MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES, MTPROTO_CFG_PARSE_FULL_PASS_OK,
    MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_CLUSTER_EXTEND_INVARIANT,
    MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_EXPECTED_SEMICOLON,
    MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PROXIES_INTERMIXED,
    MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK, MTPROTO_CFG_PREINIT_ERR_INVALID_ARGS,
    MTPROTO_CFG_PREINIT_OK, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MAX_CONNECTIONS,
    MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MIN_CONNECTIONS,
    MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TARGET_ID,
    MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TIMEOUT,
    MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_TARGET_ID_SPACE, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK,
    MTPROTO_CLIENT_PACKET_KIND_CLOSE_EXT, MTPROTO_CLIENT_PACKET_KIND_MALFORMED,
    MTPROTO_CLIENT_PACKET_KIND_PONG, MTPROTO_CLIENT_PACKET_KIND_PROXY_ANS,
    MTPROTO_CLIENT_PACKET_KIND_SIMPLE_ACK, MTPROTO_CLIENT_PACKET_KIND_UNKNOWN,
    MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER, MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS,
    MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS, MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR,
    MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT, MTPROTO_PACKET_KIND_ENCRYPTED,
    MTPROTO_PACKET_KIND_INVALID, MTPROTO_PACKET_KIND_UNENCRYPTED_DH, MTPROTO_PROXY_CONTRACT_OPS,
    MTPROTO_PROXY_IMPLEMENTED_OPS, NETWORK_BOUNDARY_VERSION, NET_CRYPTO_AES_CONTRACT_OPS,
    NET_CRYPTO_AES_IMPLEMENTED_OPS, NET_CRYPTO_DH_CONTRACT_OPS, NET_CRYPTO_DH_IMPLEMENTED_OPS,
    NET_EVENTS_CONTRACT_OPS, NET_EVENTS_IMPLEMENTED_OPS, NET_MSG_BUFFERS_CONTRACT_OPS,
    NET_MSG_BUFFERS_IMPLEMENTED_OPS, NET_TIMERS_CONTRACT_OPS, NET_TIMERS_IMPLEMENTED_OPS,
    RPC_BOUNDARY_VERSION, RPC_INVOKE_REQ, RPC_REQ_RESULT, RPC_TARGETS_CONTRACT_OPS,
    RPC_TARGETS_IMPLEMENTED_OPS, TCP_RPC_CLIENT_CONTRACT_OPS, TCP_RPC_CLIENT_IMPLEMENTED_OPS,
    TCP_RPC_COMMON_CONTRACT_OPS, TCP_RPC_COMMON_IMPLEMENTED_OPS, TCP_RPC_PACKET_LEN_STATE_INVALID,
    TCP_RPC_PACKET_LEN_STATE_READY, TCP_RPC_PACKET_LEN_STATE_SHORT, TCP_RPC_PACKET_LEN_STATE_SKIP,
    TCP_RPC_SERVER_CONTRACT_OPS, TCP_RPC_SERVER_IMPLEMENTED_OPS, TLS_REQUEST_PUBLIC_KEY_BYTES,
};
use core::ffi::c_void;

#[repr(C)]
struct EngineSignalDispatchCapture {
    calls: i32,
    last_sig: i32,
    rearm_signal: i32,
}

#[repr(C)]
struct EngineNetTryOpenCapture {
    success_port: i32,
    calls: i32,
    last_port: i32,
}

unsafe extern "C" fn capture_engine_signal(sig: i32, ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let capture = unsafe { &mut *ctx.cast::<EngineSignalDispatchCapture>() };
    capture.calls += 1;
    capture.last_sig = sig;
    if capture.rearm_signal != 0 {
        mtproxy_ffi_engine_signal_set_pending(sig);
    }
}

unsafe extern "C" fn capture_engine_net_try_open(port: i32, ctx: *mut c_void) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    let capture = unsafe { &mut *ctx.cast::<EngineNetTryOpenCapture>() };
    capture.calls += 1;
    capture.last_port = port;
    if capture.success_port == port {
        1
    } else {
        0
    }
}

#[test]
fn reports_same_api_version_for_rust_and_c_entrypoints() {
    assert_eq!(ffi_api_version(), FFI_API_VERSION);
    assert_eq!(mtproxy_ffi_api_version(), FFI_API_VERSION);
}

#[test]
fn startup_handshake_accepts_expected_api() {
    assert_eq!(mtproxy_ffi_startup_handshake(FFI_API_VERSION), 0);
}

#[test]
fn startup_handshake_rejects_incompatible_api() {
    assert_eq!(mtproxy_ffi_startup_handshake(FFI_API_VERSION + 1), -1);
}

#[test]
fn concurrency_boundary_contract_is_reported() {
    let mut out = MtproxyConcurrencyBoundary::default();
    assert_eq!(
        unsafe { mtproxy_ffi_get_concurrency_boundary(&raw mut out) },
        0
    );
    assert_eq!(out.boundary_version, CONCURRENCY_BOUNDARY_VERSION);
    assert_eq!(out.mpq_contract_ops, MPQ_CONTRACT_OPS);
    assert_eq!(out.jobs_contract_ops, JOBS_CONTRACT_OPS);
    assert_eq!(out.mpq_implemented_ops, MPQ_IMPLEMENTED_OPS);
    assert_eq!(out.jobs_implemented_ops, JOBS_IMPLEMENTED_OPS);
}

#[test]
fn network_boundary_contract_is_reported() {
    let mut out = MtproxyNetworkBoundary::default();
    assert_eq!(unsafe { mtproxy_ffi_get_network_boundary(&raw mut out) }, 0);
    assert_eq!(out.boundary_version, NETWORK_BOUNDARY_VERSION);
    assert_eq!(out.net_events_contract_ops, NET_EVENTS_CONTRACT_OPS);
    assert_eq!(out.net_events_implemented_ops, NET_EVENTS_IMPLEMENTED_OPS);
    assert_eq!(out.net_timers_contract_ops, NET_TIMERS_CONTRACT_OPS);
    assert_eq!(out.net_timers_implemented_ops, NET_TIMERS_IMPLEMENTED_OPS);
    assert_eq!(
        out.net_msg_buffers_contract_ops,
        NET_MSG_BUFFERS_CONTRACT_OPS
    );
    assert_eq!(
        out.net_msg_buffers_implemented_ops,
        NET_MSG_BUFFERS_IMPLEMENTED_OPS
    );
}

#[test]
fn rpc_boundary_contract_is_reported() {
    let mut out = MtproxyRpcBoundary::default();
    assert_eq!(unsafe { mtproxy_ffi_get_rpc_boundary(&raw mut out) }, 0);
    assert_eq!(out.boundary_version, RPC_BOUNDARY_VERSION);
    assert_eq!(out.tcp_rpc_common_contract_ops, TCP_RPC_COMMON_CONTRACT_OPS);
    assert_eq!(
        out.tcp_rpc_common_implemented_ops,
        TCP_RPC_COMMON_IMPLEMENTED_OPS
    );
    assert_eq!(out.tcp_rpc_client_contract_ops, TCP_RPC_CLIENT_CONTRACT_OPS);
    assert_eq!(
        out.tcp_rpc_client_implemented_ops,
        TCP_RPC_CLIENT_IMPLEMENTED_OPS
    );
    assert_eq!(out.tcp_rpc_server_contract_ops, TCP_RPC_SERVER_CONTRACT_OPS);
    assert_eq!(
        out.tcp_rpc_server_implemented_ops,
        TCP_RPC_SERVER_IMPLEMENTED_OPS
    );
    assert_eq!(out.rpc_targets_contract_ops, RPC_TARGETS_CONTRACT_OPS);
    assert_eq!(out.rpc_targets_implemented_ops, RPC_TARGETS_IMPLEMENTED_OPS);
}

#[test]
fn crypto_boundary_contract_is_reported() {
    let mut out = MtproxyCryptoBoundary::default();
    assert_eq!(unsafe { mtproxy_ffi_get_crypto_boundary(&raw mut out) }, 0);
    assert_eq!(out.boundary_version, CRYPTO_BOUNDARY_VERSION);
    assert_eq!(out.net_crypto_aes_contract_ops, NET_CRYPTO_AES_CONTRACT_OPS);
    assert_eq!(
        out.net_crypto_aes_implemented_ops,
        NET_CRYPTO_AES_IMPLEMENTED_OPS
    );
    assert_eq!(out.net_crypto_dh_contract_ops, NET_CRYPTO_DH_CONTRACT_OPS);
    assert_eq!(
        out.net_crypto_dh_implemented_ops,
        NET_CRYPTO_DH_IMPLEMENTED_OPS
    );
    assert_eq!(out.aesni_contract_ops, AESNI_CONTRACT_OPS);
    assert_eq!(out.aesni_implemented_ops, AESNI_IMPLEMENTED_OPS);
}

#[test]
fn application_boundary_contract_is_reported() {
    let mut out = MtproxyApplicationBoundary::default();
    assert_eq!(
        unsafe { mtproxy_ffi_get_application_boundary(&raw mut out) },
        0
    );
    assert_eq!(out.boundary_version, APPLICATION_BOUNDARY_VERSION);
    assert_eq!(out.engine_rpc_contract_ops, ENGINE_RPC_CONTRACT_OPS);
    assert_eq!(out.engine_rpc_implemented_ops, ENGINE_RPC_IMPLEMENTED_OPS);
    assert_eq!(out.mtproto_proxy_contract_ops, MTPROTO_PROXY_CONTRACT_OPS);
    assert_eq!(
        out.mtproto_proxy_implemented_ops,
        MTPROTO_PROXY_IMPLEMENTED_OPS
    );
}

#[test]
fn engine_rpc_common_dispatch_helpers_match_default_c_rules() {
    let tl_engine_stat = i32::from_ne_bytes(0xefb3_c36b_u32.to_ne_bytes());
    let tl_engine_nop = i32::from_ne_bytes(0x166b_b7c6_u32.to_ne_bytes());

    assert_eq!(mtproxy_ffi_engine_rpc_common_default_query_type_mask(), 0x7);

    assert_eq!(
        mtproxy_ffi_engine_rpc_common_default_parse_decision(0, tl_engine_stat),
        1
    );
    assert_eq!(
        mtproxy_ffi_engine_rpc_common_default_parse_decision(0, tl_engine_nop),
        2
    );
    assert_eq!(
        mtproxy_ffi_engine_rpc_common_default_parse_decision(1, tl_engine_stat),
        0
    );
    assert_eq!(
        mtproxy_ffi_engine_rpc_common_default_parse_decision(0, 0x1234_5678),
        0
    );
}

#[test]
fn engine_rpc_decision_helpers_match_c_routing_rules() {
    let qid = i64::from_ne_bytes(0xA123_4567_89ab_cdef_u64.to_ne_bytes());
    assert_eq!(
        mtproxy_ffi_engine_rpc_query_result_type_id_from_qid(qid),
        10
    );
    assert_eq!(
        mtproxy_ffi_engine_rpc_query_result_dispatch_decision(0, 0),
        0
    );
    assert_eq!(
        mtproxy_ffi_engine_rpc_query_result_dispatch_decision(1, 1),
        1
    );
    assert_eq!(
        mtproxy_ffi_engine_rpc_query_result_dispatch_decision(1, 0),
        2
    );

    assert_eq!(mtproxy_ffi_engine_rpc_need_dup(0), 1);
    assert_eq!(mtproxy_ffi_engine_rpc_need_dup(1), 0);

    let rpc_invoke_req = i32::from_ne_bytes(0x2374_df3d_u32.to_ne_bytes());
    let rpc_pong = i32::from_ne_bytes(0x8430_eaa7_u32.to_ne_bytes());
    assert_eq!(
        mtproxy_ffi_engine_rpc_query_job_dispatch_decision(rpc_invoke_req, 0),
        0
    );
    assert_eq!(
        mtproxy_ffi_engine_rpc_query_job_dispatch_decision(0x1234_5678, 1),
        1
    );
    assert_eq!(
        mtproxy_ffi_engine_rpc_query_job_dispatch_decision(0x1234_5678, 0),
        2
    );
    assert_eq!(mtproxy_ffi_engine_rpc_tcp_should_hold_conn(rpc_pong), 0);
    assert_eq!(mtproxy_ffi_engine_rpc_tcp_should_hold_conn(0x1234_5678), 1);
}

#[test]
fn engine_net_default_port_mod_is_minus_one() {
    assert_eq!(mtproxy_ffi_engine_net_default_port_mod(), -1);
}

#[test]
fn engine_net_try_open_port_range_bridge_selects_and_reports_failures() {
    let mut capture = EngineNetTryOpenCapture {
        success_port: 1003,
        calls: 0,
        last_port: 0,
    };
    let mut selected = -1;
    let rc = unsafe {
        mtproxy_ffi_engine_net_try_open_port_range(
            1000,
            1010,
            3,
            1,
            1,
            Some(capture_engine_net_try_open),
            (&raw mut capture).cast(),
            &raw mut selected,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(selected, 1003);
    assert!(capture.calls > 0);

    capture.success_port = -1;
    let rc = unsafe {
        mtproxy_ffi_engine_net_try_open_port_range(
            10,
            12,
            0,
            -1,
            0,
            Some(capture_engine_net_try_open),
            (&raw mut capture).cast(),
            &raw mut selected,
        )
    };
    assert_eq!(rc, 1);

    let rc = unsafe {
        mtproxy_ffi_engine_net_try_open_port_range(
            10,
            12,
            0,
            -1,
            1,
            Some(capture_engine_net_try_open),
            (&raw mut capture).cast(),
            &raw mut selected,
        )
    };
    assert_eq!(rc, -2);
}

#[test]
fn engine_net_open_privileged_port_bridge_applies_engine_rules() {
    let mut capture = EngineNetTryOpenCapture {
        success_port: 443,
        calls: 0,
        last_port: 0,
    };
    let mut selected = -1;

    let rc = unsafe {
        mtproxy_ffi_engine_net_open_privileged_port(
            443,
            0,
            0,
            -1,
            1,
            1,
            Some(capture_engine_net_try_open),
            (&raw mut capture).cast(),
            &raw mut selected,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(selected, 443);

    capture.success_port = 1002;
    let rc = unsafe {
        mtproxy_ffi_engine_net_open_privileged_port(
            0,
            1000,
            1010,
            -1,
            1,
            1,
            Some(capture_engine_net_try_open),
            (&raw mut capture).cast(),
            &raw mut selected,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(selected, 1002);

    let calls_before_none = capture.calls;
    let rc = unsafe {
        mtproxy_ffi_engine_net_open_privileged_port(
            1500,
            1500,
            1600,
            -1,
            1,
            1,
            Some(capture_engine_net_try_open),
            (&raw mut capture).cast(),
            &raw mut selected,
        )
    };
    assert_eq!(rc, 1);
    assert_eq!(capture.calls, calls_before_none);
}

#[test]
fn engine_signal_helpers_bridge_pending_and_interrupt_state() {
    while mtproxy_ffi_engine_signal_check_pending_and_clear(15) != 0 {}
    assert_eq!(mtproxy_ffi_engine_signal_check_pending(15), 0);
    assert_eq!(mtproxy_ffi_engine_interrupt_signal_raised(), 0);

    mtproxy_ffi_engine_signal_set_pending(15);
    assert_eq!(mtproxy_ffi_engine_signal_check_pending(15), 1);
    assert_eq!(mtproxy_ffi_engine_interrupt_signal_raised(), 1);
    assert_eq!(mtproxy_ffi_engine_signal_check_pending_and_clear(15), 1);
    assert_eq!(mtproxy_ffi_engine_signal_check_pending(15), 0);
}

#[test]
fn engine_signal_processing_helper_respects_allowed_mask_and_single_pass_rule() {
    while mtproxy_ffi_engine_signal_check_pending_and_clear(10) != 0 {}
    while mtproxy_ffi_engine_signal_check_pending_and_clear(15) != 0 {}

    mtproxy_ffi_engine_signal_set_pending(10);
    mtproxy_ffi_engine_signal_set_pending(15);

    let mut capture = EngineSignalDispatchCapture {
        calls: 0,
        last_sig: 0,
        rearm_signal: 1,
    };
    let processed = mtproxy_ffi_engine_process_signals_allowed(
        1u64 << 10,
        Some(capture_engine_signal),
        (&raw mut capture).cast(),
    );
    assert_eq!(processed, 1);
    assert_eq!(capture.calls, 1);
    assert_eq!(capture.last_sig, 10);

    // SIGUSR1 was re-armed during callback, but C-style single-pass processing
    // must not dispatch it twice in one drain.
    assert_eq!(mtproxy_ffi_engine_signal_check_pending(10), 1);
    // SIGTERM is not in allowed mask and must stay pending.
    assert_eq!(mtproxy_ffi_engine_signal_check_pending(15), 1);

    assert_eq!(mtproxy_ffi_engine_signal_check_pending_and_clear(10), 1);
    assert_eq!(mtproxy_ffi_engine_signal_check_pending_and_clear(15), 1);
}

#[test]
fn engine_rpc_result_helpers_match_current_rules() {
    assert_eq!(mtproxy_ffi_engine_rpc_result_new_flags(0), 0);
    assert_eq!(mtproxy_ffi_engine_rpc_result_new_flags(0x1234_5678), 0x5678);
    assert_eq!(
        mtproxy_ffi_engine_rpc_result_new_flags(i32::from_ne_bytes(0xffff_ffff_u32.to_ne_bytes())),
        0xffff
    );
    assert_eq!(mtproxy_ffi_engine_rpc_result_header_len(0), 0);
    assert_eq!(mtproxy_ffi_engine_rpc_result_header_len(1), 8);
    assert_eq!(
        mtproxy_ffi_engine_rpc_result_header_len(i32::from_ne_bytes(0x8000_0000_u32.to_ne_bytes())),
        8
    );
}

#[test]
fn mtproto_helpers_match_current_rules() {
    assert_eq!(mtproxy_ffi_mtproto_conn_tag(0), 1);
    assert_eq!(mtproxy_ffi_mtproto_conn_tag(0x1234_5678), 0x0034_5679);
    assert_eq!(
        mtproxy_ffi_mtproto_conn_tag(i32::from_ne_bytes(0xffff_ffff_u32.to_ne_bytes())),
        0x0100_0000
    );

    let c_hash = |in_fd: i32, in_conn_id: i64, shift: i32| -> i32 {
        let in_fd_u = u64::from_ne_bytes(i64::from(in_fd).to_ne_bytes());
        let in_conn_id_u = u64::from_ne_bytes(in_conn_id.to_ne_bytes());
        let h = in_fd_u
            .wrapping_mul(11_400_714_819_323_198_485)
            .wrapping_add(in_conn_id_u.wrapping_mul(13_043_817_825_332_782_213));
        i32::try_from(h >> (64 - u32::try_from(shift).unwrap_or(0))).unwrap_or(-1)
    };
    assert_eq!(
        mtproxy_ffi_mtproto_ext_conn_hash(42, 0x1234_5678_9abc_def0_i64, 20),
        c_hash(42, 0x1234_5678_9abc_def0_i64, 20)
    );
    assert_eq!(
        mtproxy_ffi_mtproto_ext_conn_hash(-1, -17, 20),
        c_hash(-1, -17, 20)
    );
    assert_eq!(mtproxy_ffi_mtproto_ext_conn_hash(1, 2, 0), -1);
}

#[test]
fn mtproto_text_parsers_are_wired_to_core_proxy_module() {
    let mut out_ip = 0u32;
    assert_eq!(
        unsafe {
            mtproxy_ffi_mtproto_parse_text_ipv4(b"127.0.0.1\0".as_ptr().cast(), &raw mut out_ip)
        },
        0
    );
    assert_eq!(out_ip, 0x7f00_0001);

    let mut out_ipv6 = [0u8; 16];
    let mut consumed = 0i32;
    assert_eq!(
        unsafe {
            mtproxy_ffi_mtproto_parse_text_ipv6(
                b"::1\0".as_ptr().cast(),
                out_ipv6.as_mut_ptr(),
                &raw mut consumed,
            )
        },
        0
    );
    assert_eq!(consumed, 3);
    assert_eq!(out_ipv6, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
}

#[test]
fn mtproto_packet_inspect_bridge_classifies_header_shapes() {
    let mut out = MtproxyMtprotoPacketInspectResult::default();
    let mut header = [0u8; 28];

    header[0..8].copy_from_slice(&0x1122_3344_5566_7788_i64.to_le_bytes());
    assert_eq!(
        unsafe {
            mtproxy_ffi_mtproto_inspect_packet_header(
                header.as_ptr(),
                header.len(),
                64,
                &raw mut out,
            )
        },
        0
    );
    assert_eq!(out.kind, MTPROTO_PACKET_KIND_ENCRYPTED);
    assert_eq!(out.auth_key_id, 0x1122_3344_5566_7788_i64);

    header.fill(0);
    header[16..20].copy_from_slice(&20_i32.to_le_bytes());
    header[20..24].copy_from_slice(&0x6046_9778_i32.to_le_bytes());
    assert_eq!(
        unsafe {
            mtproxy_ffi_mtproto_inspect_packet_header(
                header.as_ptr(),
                header.len(),
                40,
                &raw mut out,
            )
        },
        0
    );
    assert_eq!(out.kind, MTPROTO_PACKET_KIND_UNENCRYPTED_DH);
    assert_eq!(out.inner_len, 20);
    assert_eq!(out.function_id, 0x6046_9778_i32);

    header[20..24].copy_from_slice(&0_i32.to_le_bytes());
    assert_eq!(
        unsafe {
            mtproxy_ffi_mtproto_inspect_packet_header(
                header.as_ptr(),
                header.len(),
                40,
                &raw mut out,
            )
        },
        0
    );
    assert_eq!(out.kind, MTPROTO_PACKET_KIND_INVALID);
}

#[test]
fn mtproto_client_packet_parser_bridge_parses_supported_shapes() {
    let mut out = MtproxyMtprotoClientPacketParseResult::default();

    let pong = 0x8430_eaa7_u32.to_le_bytes();
    assert_eq!(
        unsafe { mtproxy_ffi_mtproto_parse_client_packet(pong.as_ptr(), pong.len(), &raw mut out) },
        0
    );
    assert_eq!(out.kind, MTPROTO_CLIENT_PACKET_KIND_PONG);
    assert_eq!(out.op, i32::from_ne_bytes(0x8430_eaa7_u32.to_ne_bytes()));

    let mut proxy_ans = [0u8; 24];
    proxy_ans[0..4].copy_from_slice(&0x4403_da0d_i32.to_le_bytes());
    proxy_ans[4..8].copy_from_slice(&7_i32.to_le_bytes());
    proxy_ans[8..16].copy_from_slice(&0x0102_0304_0506_0708_i64.to_le_bytes());
    proxy_ans[16..24].copy_from_slice(&0x1122_3344_5566_7788_i64.to_le_bytes());
    assert_eq!(
        unsafe {
            mtproxy_ffi_mtproto_parse_client_packet(
                proxy_ans.as_ptr(),
                proxy_ans.len(),
                &raw mut out,
            )
        },
        0
    );
    assert_eq!(out.kind, MTPROTO_CLIENT_PACKET_KIND_PROXY_ANS);
    assert_eq!(out.flags, 7);
    assert_eq!(out.out_conn_id, 0x0102_0304_0506_0708_i64);
    assert_eq!(out.payload_offset, 16);

    let mut ack = [0u8; 16];
    ack[0..4].copy_from_slice(&0x3bac_409b_i32.to_le_bytes());
    ack[4..12].copy_from_slice(&0x1111_2222_3333_4444_i64.to_le_bytes());
    ack[12..16].copy_from_slice(&0xaabb_ccdd_u32.to_le_bytes());
    assert_eq!(
        unsafe { mtproxy_ffi_mtproto_parse_client_packet(ack.as_ptr(), ack.len(), &raw mut out) },
        0
    );
    assert_eq!(out.kind, MTPROTO_CLIENT_PACKET_KIND_SIMPLE_ACK);
    assert_eq!(out.out_conn_id, 0x1111_2222_3333_4444_i64);
    assert_eq!(
        u32::from_ne_bytes(out.confirm.to_ne_bytes()),
        0xaabb_ccdd_u32
    );

    let mut close_ext = [0u8; 12];
    close_ext[0..4].copy_from_slice(&0x5eb6_34a2_i32.to_le_bytes());
    close_ext[4..12].copy_from_slice(&0x9999_8888_7777_6666_u64.to_le_bytes());
    assert_eq!(
        unsafe {
            mtproxy_ffi_mtproto_parse_client_packet(
                close_ext.as_ptr(),
                close_ext.len(),
                &raw mut out,
            )
        },
        0
    );
    assert_eq!(out.kind, MTPROTO_CLIENT_PACKET_KIND_CLOSE_EXT);
    assert_eq!(
        out.out_conn_id,
        i64::from_ne_bytes(0x9999_8888_7777_6666_u64.to_ne_bytes())
    );

    let mut malformed = [0u8; 15];
    malformed[0..4].copy_from_slice(&0x3bac_409b_i32.to_le_bytes());
    assert_eq!(
        unsafe {
            mtproxy_ffi_mtproto_parse_client_packet(
                malformed.as_ptr(),
                malformed.len(),
                &raw mut out,
            )
        },
        0
    );
    assert_eq!(out.kind, MTPROTO_CLIENT_PACKET_KIND_MALFORMED);
    assert_eq!(out.op, 0x3bac_409b_i32);

    let unknown = 0x1234_5678_i32.to_le_bytes();
    assert_eq!(
        unsafe {
            mtproxy_ffi_mtproto_parse_client_packet(unknown.as_ptr(), unknown.len(), &raw mut out)
        },
        0
    );
    assert_eq!(out.kind, MTPROTO_CLIENT_PACKET_KIND_UNKNOWN);
    assert_eq!(out.op, 0x1234_5678_i32);
}

#[test]
fn mtproto_parse_function_bridge_returns_core_errors_and_consumed_bytes() {
    let mut out = MtproxyMtprotoParseFunctionResult::default();
    let op = 0x1234_5678_i32.to_le_bytes();

    assert_eq!(
        unsafe { mtproxy_ffi_mtproto_parse_function(op.as_ptr(), op.len(), 1, &raw mut out) },
        0
    );
    assert_eq!(out.status, -1);
    assert_eq!(out.errnum, -2002);
    assert_eq!(out.consumed, 0);

    assert_eq!(
        unsafe { mtproxy_ffi_mtproto_parse_function(op.as_ptr(), op.len(), 0, &raw mut out) },
        0
    );
    assert_eq!(out.status, -1);
    assert_eq!(out.errnum, -2000);
    assert_eq!(out.consumed, 4);
}

#[test]
fn mtproto_config_preinit_helper_returns_expected_defaults() {
    let mut out = MtproxyMtprotoCfgPreinitResult::default();
    let rc = unsafe { mtproxy_ffi_mtproto_cfg_preinit(3, 40, &raw mut out) };
    assert_eq!(rc, MTPROTO_CFG_PREINIT_OK);
    assert_eq!(out.tot_targets, 0);
    assert_eq!(out.auth_clusters, 0);
    assert_eq!(out.min_connections, 3);
    assert_eq!(out.max_connections, 40);
    assert!((out.timeout_seconds - 0.3).abs() < 1e-9);
    assert_eq!(out.default_cluster_id, 0);
}

#[test]
fn mtproto_config_preinit_helper_rejects_null_output() {
    let rc = unsafe { mtproxy_ffi_mtproto_cfg_preinit(3, 40, core::ptr::null_mut()) };
    assert_eq!(rc, MTPROTO_CFG_PREINIT_ERR_INVALID_ARGS);
}

#[test]
fn mtproto_config_cluster_apply_decision_helper_matches_c_rules() {
    let cluster_ids = [4, -2];
    let mut out = MtproxyMtprotoCfgClusterApplyDecisionResult::default();
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            7,
            8,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK);
    assert_eq!(out.kind, MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW);
    assert_eq!(out.cluster_index, 2);

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            -2,
            8,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK);
    assert_eq!(
        out.kind,
        MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST
    );
    assert_eq!(out.cluster_index, 1);
}

#[test]
fn mtproto_config_cluster_apply_decision_helper_reports_errors() {
    let cluster_ids = [4, -2, 7];
    let mut out = MtproxyMtprotoCfgClusterApplyDecisionResult::default();
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            -2,
            8,
            &raw mut out,
        )
    };
    assert_eq!(
        rc,
        MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_PROXIES_INTERMIXED
    );

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            99,
            u32::try_from(cluster_ids.len()).expect("len fits"),
            &raw mut out,
        )
    };
    assert_eq!(
        rc,
        MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_TOO_MANY_AUTH_CLUSTERS
    );
}

#[test]
fn mtproto_config_getlex_helper_returns_lexeme_and_advance() {
    let input = b"  proxy_for";
    let mut out = MtproxyMtprotoCfgGetlexExtResult::default();
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_getlex_ext(input.as_ptr().cast(), input.len(), &raw mut out)
    };
    assert_eq!(rc, MTPROTO_CFG_GETLEX_EXT_OK);
    assert_eq!(out.lex, i32::from(b'Y'));
    assert_eq!(out.advance, input.len());
}

#[test]
fn mtproto_config_directive_token_helper_matches_parser_rules() {
    let mut out = MtproxyMtprotoCfgDirectiveTokenResult::default();

    let timeout = b"timeout 250";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_scan_directive_token(
            timeout.as_ptr().cast(),
            timeout.len(),
            2,
            64,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK);
    assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT);
    assert_eq!(out.value, 250);
    assert_eq!(out.advance, timeout.len());

    let default_cluster = b"default -2";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_scan_directive_token(
            default_cluster.as_ptr().cast(),
            default_cluster.len(),
            2,
            64,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK);
    assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER);
    assert_eq!(out.value, -2);

    let proxy_for = b"proxy_for -2   dc1:443";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_scan_directive_token(
            proxy_for.as_ptr().cast(),
            proxy_for.len(),
            2,
            64,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK);
    assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR);
    assert_eq!(out.value, -2);
    assert_eq!(out.advance, 15);

    let max_invalid = b"max_connections 1";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_scan_directive_token(
            max_invalid.as_ptr().cast(),
            max_invalid.len(),
            2,
            64,
            &raw mut out,
        )
    };
    assert_eq!(
        rc,
        MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MAX_CONNECTIONS
    );

    let min_invalid = b"min_connections 100";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_scan_directive_token(
            min_invalid.as_ptr().cast(),
            min_invalid.len(),
            2,
            64,
            &raw mut out,
        )
    };
    assert_eq!(
        rc,
        MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MIN_CONNECTIONS
    );

    let timeout_invalid = b"timeout 1";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_scan_directive_token(
            timeout_invalid.as_ptr().cast(),
            timeout_invalid.len(),
            2,
            64,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TIMEOUT);

    let target_id_invalid = b"default 40000";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_scan_directive_token(
            target_id_invalid.as_ptr().cast(),
            target_id_invalid.len(),
            2,
            64,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TARGET_ID);

    let target_space_missing = b"proxy_for 1dc1:443";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_scan_directive_token(
            target_space_missing.as_ptr().cast(),
            target_space_missing.len(),
            2,
            64,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_TARGET_ID_SPACE);

    let min_ok = b"min_connections 5";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_scan_directive_token(
            min_ok.as_ptr().cast(),
            min_ok.len(),
            2,
            64,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK);
    assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS);
    assert_eq!(out.value, 5);

    let max_ok = b"max_connections 64";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_scan_directive_token(
            max_ok.as_ptr().cast(),
            max_ok.len(),
            2,
            64,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK);
    assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS);
    assert_eq!(out.value, 64);
}

#[test]
fn mtproto_config_parse_directive_step_helper_consumes_scalar_semicolon() {
    let mut out = MtproxyMtprotoCfgDirectiveStepResult::default();
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_directive_step(
            b"timeout 250;".as_ptr().cast(),
            12,
            2,
            64,
            core::ptr::null(),
            0,
            8,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK);
    assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT);
    assert_eq!(out.advance, 12);
    assert_eq!(out.value, 250);
    assert_eq!(out.cluster_decision_kind, 0);
    assert_eq!(out.cluster_index, -1);
}

#[test]
fn mtproto_config_parse_directive_step_helper_returns_proxy_decision() {
    let cluster_ids = [4, -2];
    let mut out = MtproxyMtprotoCfgDirectiveStepResult::default();
    let input = b"proxy_for -2   dc1:443;";
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_directive_step(
            input.as_ptr().cast(),
            input.len(),
            2,
            64,
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            8,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK);
    assert_eq!(out.kind, MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR);
    assert_eq!(out.advance, 15);
    assert_eq!(out.value, -2);
    assert_eq!(
        out.cluster_decision_kind,
        MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST
    );
    assert_eq!(out.cluster_index, 1);
}

#[test]
fn mtproto_config_parse_directive_step_helper_reports_expected_errors() {
    let mut out = MtproxyMtprotoCfgDirectiveStepResult::default();
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_directive_step(
            b"timeout 250".as_ptr().cast(),
            11,
            2,
            64,
            core::ptr::null(),
            0,
            8,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_EXPECTED_SEMICOLON);

    let cluster_ids = [4, -2, 7];
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_directive_step(
            b"proxy_for -2 dc1:443".as_ptr().cast(),
            20,
            2,
            64,
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            8,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXIES_INTERMIXED);
}

#[test]
fn mtproto_config_parse_proxy_target_step_helper_returns_apply_mutation() {
    let cluster_ids = [-2];
    let last_cluster_state = MtproxyMtprotoOldClusterState {
        cluster_id: -2,
        targets_num: 2,
        write_targets_num: 2,
        flags: 1,
        first_target_index: 0,
        has_first_target_index: 1,
    };
    let mut out = MtproxyMtprotoCfgParseProxyTargetStepResult::default();
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
            b"dc3:445;".as_ptr().cast(),
            8,
            2,
            16,
            5,
            10,
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            -2,
            8,
            1,
            1,
            &raw const last_cluster_state,
            1,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK);
    assert_eq!(out.advance, 8);
    assert_eq!(out.target_index, 2);
    assert_eq!(out.port, 445);
    assert_eq!(out.cluster_index, 0);
    assert_eq!(
        out.cluster_decision_kind,
        MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST
    );
    assert_eq!(out.cluster_state_after.targets_num, 3);
    assert_eq!(
        out.cluster_targets_action,
        MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING
    );
}

#[test]
fn mtproto_config_parse_proxy_target_step_helper_reports_expected_errors() {
    let cluster_ids = [4, -2, 7];
    let mut out = MtproxyMtprotoCfgParseProxyTargetStepResult::default();

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
            b"dc3:445;".as_ptr().cast(),
            8,
            2,
            16,
            5,
            10,
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            -2,
            8,
            1,
            1,
            core::ptr::null(),
            0,
            &raw mut out,
        )
    };
    assert_eq!(
        rc,
        MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PROXIES_INTERMIXED
    );

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
            b"dc3:445".as_ptr().cast(),
            7,
            2,
            16,
            5,
            10,
            core::ptr::null(),
            0,
            0,
            8,
            1,
            0,
            core::ptr::null(),
            0,
            &raw mut out,
        )
    };
    assert_eq!(
        rc,
        MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_EXPECTED_SEMICOLON
    );

    let last_cluster_state = MtproxyMtprotoOldClusterState {
        cluster_id: -2,
        targets_num: 2,
        write_targets_num: 2,
        flags: 1,
        first_target_index: 1,
        has_first_target_index: 1,
    };
    let cluster_ids = [-2];
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
            b"dc3:445;".as_ptr().cast(),
            8,
            2,
            16,
            5,
            10,
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            -2,
            8,
            1,
            1,
            &raw const last_cluster_state,
            1,
            &raw mut out,
        )
    };
    assert_eq!(
        rc,
        MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_CLUSTER_EXTEND_INVARIANT
    );
}

#[test]
fn mtproto_config_parse_proxy_target_step_helper_create_new_reports_target_pointer_action() {
    let cluster_ids = [-2];
    let mut out = MtproxyMtprotoCfgParseProxyTargetStepResult::default();
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
            b"dc4:446;".as_ptr().cast(),
            8,
            2,
            16,
            5,
            10,
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            9,
            8,
            1,
            1,
            core::ptr::null(),
            0,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK);
    assert_eq!(out.cluster_index, 1);
    assert_eq!(
        out.cluster_decision_kind,
        MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW
    );
    assert_eq!(
        out.cluster_targets_action,
        MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET
    );
    assert_eq!(out.cluster_targets_index, out.target_index);
    assert_eq!(out.auth_clusters_after, 2);
    assert_eq!(out.auth_tot_clusters_after, 2);
}

#[test]
fn mtproto_config_parse_full_pass_helper_returns_action_plan_and_final_state() {
    let input = b"min_connections 5; max_connections 10; timeout 250; default -2; proxy_for -2 dc1:443; proxy_for -2 dc2:444;";
    let mut actions = [MtproxyMtprotoCfgProxyAction::default(); 4];
    let mut out = MtproxyMtprotoCfgParseFullResult::default();
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_full_pass(
            input.as_ptr().cast(),
            input.len(),
            2,
            64,
            1,
            8,
            16,
            actions.as_mut_ptr(),
            u32::try_from(actions.len()).expect("len fits"),
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_PARSE_FULL_PASS_OK);
    assert_eq!(out.min_connections, 5);
    assert_eq!(out.max_connections, 10);
    assert!((out.timeout_seconds - 0.25).abs() < 1e-9);
    assert_eq!(out.default_cluster_id, -2);
    assert_eq!(out.have_proxy, 1);
    assert_eq!(out.tot_targets, 2);
    assert_eq!(out.auth_clusters, 1);
    assert_eq!(out.auth_tot_clusters, 1);
    assert_eq!(out.actions_len, 2);
    assert_eq!(out.has_default_cluster_index, 1);
    assert_eq!(out.default_cluster_index, 0);
    assert_eq!(actions[0].step.target_index, 0);
    assert_eq!(actions[0].step.port, 443);
    assert_eq!(actions[1].step.target_index, 1);
    assert_eq!(actions[1].step.port, 444);
}

#[test]
fn mtproto_config_parse_full_pass_helper_reports_terminal_and_syntax_errors() {
    let mut actions = [MtproxyMtprotoCfgProxyAction::default(); 2];
    let mut out = MtproxyMtprotoCfgParseFullResult::default();

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_full_pass(
            b"timeout 100;".as_ptr().cast(),
            12,
            2,
            64,
            0,
            8,
            16,
            actions.as_mut_ptr(),
            u32::try_from(actions.len()).expect("len fits"),
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES);

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_parse_full_pass(
            b"proxy dc1:443".as_ptr().cast(),
            13,
            2,
            64,
            0,
            8,
            16,
            actions.as_mut_ptr(),
            u32::try_from(actions.len()).expect("len fits"),
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON);
}

#[test]
fn mtproto_config_expect_semicolon_helper_matches_parser_behavior() {
    let mut advance = 0usize;
    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_expect_semicolon(b";".as_ptr().cast(), 1, &raw mut advance)
    };
    assert_eq!(rc, MTPROTO_CFG_EXPECT_SEMICOLON_OK);
    assert_eq!(advance, 1);

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_expect_semicolon(b" ".as_ptr().cast(), 1, &raw mut advance)
    };
    assert_eq!(rc, MTPROTO_CFG_EXPECT_SEMICOLON_ERR_EXPECTED);
}

#[test]
fn mtproto_config_cluster_lookup_helper_matches_c_rules() {
    let cluster_ids = [-2, 0, 7];
    let mut out_cluster_index = -1;

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            0,
            0,
            0,
            0,
            &raw mut out_cluster_index,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK);
    assert_eq!(out_cluster_index, 1);

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            42,
            0,
            0,
            0,
            &raw mut out_cluster_index,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND);
    assert_eq!(out_cluster_index, -1);

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            42,
            1,
            2,
            1,
            &raw mut out_cluster_index,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK);
    assert_eq!(out_cluster_index, 2);
}

#[test]
fn mtproto_config_finalize_helper_enforces_terminal_checks() {
    let cluster_ids = [-2, 0];
    let mut out = MtproxyMtprotoCfgFinalizeResult::default();

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_finalize(
            1,
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            0,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_FINALIZE_OK);
    assert_eq!(out.has_default_cluster_index, 1);
    assert_eq!(out.default_cluster_index, 1);

    let rc = unsafe {
        mtproxy_ffi_mtproto_cfg_finalize(
            0,
            cluster_ids.as_ptr(),
            u32::try_from(cluster_ids.len()).expect("len fits"),
            0,
            &raw mut out,
        )
    };
    assert_eq!(rc, MTPROTO_CFG_FINALIZE_ERR_MISSING_PROXY_DIRECTIVES);

    let rc = unsafe { mtproxy_ffi_mtproto_cfg_finalize(1, core::ptr::null(), 0, 0, &raw mut out) };
    assert_eq!(rc, MTPROTO_CFG_FINALIZE_ERR_NO_PROXY_SERVERS_DEFINED);
}

#[test]
fn crypto_dh_prefix_check_matches_current_rules() {
    let prime_prefix = [0x89u8, 0x52, 0x13, 0x1b, 0x1e, 0x3a, 0x69, 0xba];
    let mut data = [0u8; 256];
    assert_eq!(
        unsafe {
            mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin(
                data.as_ptr(),
                data.len(),
                prime_prefix.as_ptr(),
                prime_prefix.len(),
            )
        },
        0
    );
    data[7] = 1;
    assert_eq!(
        unsafe {
            mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin(
                data.as_ptr(),
                data.len(),
                prime_prefix.as_ptr(),
                prime_prefix.len(),
            )
        },
        1
    );
    data[0] = 0x90;
    assert_eq!(
        unsafe {
            mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin(
                data.as_ptr(),
                data.len(),
                prime_prefix.as_ptr(),
                prime_prefix.len(),
            )
        },
        0
    );
}

#[test]
fn crypto_aes_create_keys_is_deterministic_for_fixed_input() {
    let nonce_server = [0x11u8; 16];
    let nonce_client = [0x22u8; 16];
    let server_ipv6 = [0x33u8; 16];
    let client_ipv6 = [0x44u8; 16];
    let secret = [0x55u8; 32];
    let temp_key = [0x66u8; 64];

    let mut out_a = MtproxyAesKeyData::default();
    let mut out_b = MtproxyAesKeyData::default();
    assert_eq!(
        unsafe {
            mtproxy_ffi_crypto_aes_create_keys(
                &raw mut out_a,
                1,
                nonce_server.as_ptr(),
                nonce_client.as_ptr(),
                1_700_000_000,
                0x0a00_0001,
                443,
                server_ipv6.as_ptr(),
                0x0a00_0002,
                32000,
                client_ipv6.as_ptr(),
                secret.as_ptr(),
                i32::try_from(secret.len()).unwrap_or(i32::MAX),
                temp_key.as_ptr(),
                i32::try_from(temp_key.len()).unwrap_or(i32::MAX),
            )
        },
        1
    );
    assert_eq!(
        unsafe {
            mtproxy_ffi_crypto_aes_create_keys(
                &raw mut out_b,
                1,
                nonce_server.as_ptr(),
                nonce_client.as_ptr(),
                1_700_000_000,
                0x0a00_0001,
                443,
                server_ipv6.as_ptr(),
                0x0a00_0002,
                32000,
                client_ipv6.as_ptr(),
                secret.as_ptr(),
                i32::try_from(secret.len()).unwrap_or(i32::MAX),
                temp_key.as_ptr(),
                i32::try_from(temp_key.len()).unwrap_or(i32::MAX),
            )
        },
        1
    );
    assert_eq!(out_a, out_b);
    assert_ne!(out_a.write_key, [0u8; 32]);
    assert_ne!(out_a.read_key, [0u8; 32]);
}

#[test]
fn crypto_aes_create_keys_rejects_short_secret() {
    let nonce_server = [0x11u8; 16];
    let nonce_client = [0x22u8; 16];
    let server_ipv6 = [0x33u8; 16];
    let client_ipv6 = [0x44u8; 16];
    let secret = [0x55u8; 16];
    let temp_key = [0x66u8; 8];
    let mut out = MtproxyAesKeyData::default();
    assert_eq!(
        unsafe {
            mtproxy_ffi_crypto_aes_create_keys(
                &raw mut out,
                0,
                nonce_server.as_ptr(),
                nonce_client.as_ptr(),
                1_700_000_000,
                0,
                443,
                server_ipv6.as_ptr(),
                0,
                32000,
                client_ipv6.as_ptr(),
                secret.as_ptr(),
                i32::try_from(secret.len()).unwrap_or(i32::MAX),
                temp_key.as_ptr(),
                i32::try_from(temp_key.len()).unwrap_or(i32::MAX),
            )
        },
        -1
    );
}

#[test]
fn aesni_crypt_rejects_invalid_args() {
    assert_eq!(
        unsafe {
            mtproxy_ffi_aesni_crypt(
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                16,
            )
        },
        -1
    );
    assert_eq!(
        unsafe {
            mtproxy_ffi_aesni_crypt(
                core::ptr::dangling_mut::<core::ffi::c_void>(),
                core::ptr::null(),
                core::ptr::null_mut(),
                -1,
            )
        },
        -1
    );
}

#[test]
fn crypto_dh_roundtrip_exports_work() {
    assert_eq!(mtproxy_ffi_crypto_dh_get_params_select(), DH_PARAMS_SELECT);

    let mut g_a = [0u8; DH_KEY_BYTES];
    let mut a = [0u8; DH_KEY_BYTES];
    assert_eq!(
        unsafe { mtproxy_ffi_crypto_dh_first_round(g_a.as_mut_ptr(), a.as_mut_ptr()) },
        1
    );
    assert_ne!(g_a, [0u8; DH_KEY_BYTES]);
    assert_ne!(a, [0u8; DH_KEY_BYTES]);

    let mut g_ab = [0u8; DH_KEY_BYTES];
    assert_eq!(
        unsafe { mtproxy_ffi_crypto_dh_third_round(g_ab.as_mut_ptr(), g_a.as_ptr(), a.as_ptr()) },
        i32::try_from(DH_KEY_BYTES).unwrap_or(i32::MAX)
    );
    assert_ne!(g_ab, [0u8; DH_KEY_BYTES]);

    let mut g_a_srv = [0u8; DH_KEY_BYTES];
    let mut g_ab_server = [0u8; DH_KEY_BYTES];
    assert_eq!(
        unsafe {
            mtproxy_ffi_crypto_dh_second_round(
                g_ab_server.as_mut_ptr(),
                g_a_srv.as_mut_ptr(),
                g_a.as_ptr(),
            )
        },
        i32::try_from(DH_KEY_BYTES).unwrap_or(i32::MAX)
    );
    assert_ne!(g_a_srv, [0u8; DH_KEY_BYTES]);
    assert_ne!(g_ab_server, [0u8; DH_KEY_BYTES]);
}

#[test]
fn aesni_context_lifecycle_is_exported() {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    let mut input = [0u8; 64];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::try_from(0x80 + i).unwrap_or(0);
    }
    for (i, b) in iv.iter_mut().enumerate() {
        *b = u8::try_from(0x90 + i).unwrap_or(0);
    }
    for (i, b) in input.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap_or(0);
    }

    let mut ctx: *mut core::ffi::c_void = core::ptr::null_mut();
    assert_eq!(
        unsafe {
            mtproxy_ffi_aesni_ctx_init(
                AESNI_CIPHER_AES_256_CTR,
                key.as_ptr(),
                iv.as_ptr(),
                1,
                &raw mut ctx,
            )
        },
        0
    );
    assert!(!ctx.is_null());
    let mut output = [0u8; 64];
    assert_eq!(
        unsafe { mtproxy_ffi_aesni_crypt(ctx, input.as_ptr(), output.as_mut_ptr(), 64) },
        0
    );
    assert_ne!(output, [0u8; 64]);
    assert_eq!(unsafe { mtproxy_ffi_aesni_ctx_free(ctx) }, 0);
}

#[test]
fn tls_public_key_and_rand_exports_work() {
    let mut random = [0u8; 7];
    assert_eq!(
        unsafe {
            mtproxy_ffi_crypto_rand_bytes(
                random.as_mut_ptr(),
                i32::try_from(random.len()).unwrap_or(i32::MAX),
            )
        },
        0
    );
    assert_ne!(random, [0u8; 7]);

    let mut public_key = [0u8; TLS_REQUEST_PUBLIC_KEY_BYTES];
    assert_eq!(
        unsafe { mtproxy_ffi_crypto_tls_generate_public_key(public_key.as_mut_ptr()) },
        0
    );
    assert_ne!(public_key, [0u8; TLS_REQUEST_PUBLIC_KEY_BYTES]);
}

#[test]
fn net_epoll_flag_conversions_match_c_semantics() {
    let evt_read = i32::from_ne_bytes(EVT_READ.to_ne_bytes());
    let evt_write = i32::from_ne_bytes(EVT_WRITE.to_ne_bytes());
    let evt_spec = i32::from_ne_bytes(EVT_SPEC.to_ne_bytes());
    let evt_level = i32::from_ne_bytes(EVT_LEVEL.to_ne_bytes());

    let conv = mtproxy_ffi_net_epoll_conv_flags(evt_read | evt_spec);
    let conv_u = u32::from_ne_bytes(conv.to_ne_bytes());
    assert_ne!(conv_u & EPOLLERR, 0);
    assert_ne!(conv_u & EPOLLIN, 0);
    assert_ne!(conv_u & EPOLLRDHUP, 0);
    assert_ne!(conv_u & EPOLLPRI, 0);
    assert_ne!(conv_u & EPOLLET, 0);

    let conv_level = mtproxy_ffi_net_epoll_conv_flags(evt_read | evt_write | evt_level);
    let conv_level_u = u32::from_ne_bytes(conv_level.to_ne_bytes());
    assert_ne!(conv_level_u & EPOLLIN, 0);
    assert_ne!(conv_level_u & EPOLLOUT, 0);
    assert_eq!(conv_level_u & EPOLLET, 0);

    let unconv = mtproxy_ffi_net_epoll_unconv_flags(i32::from_ne_bytes(
        (EPOLLIN | EPOLLOUT | EPOLLERR).to_ne_bytes(),
    ));
    let unconv_u = u32::from_ne_bytes(unconv.to_ne_bytes());
    assert_ne!(unconv_u & EVT_FROM_EPOLL, 0);
    assert_ne!(unconv_u & EVT_READ, 0);
    assert_ne!(unconv_u & EVT_WRITE, 0);
    assert_eq!(unconv_u & EVT_SPEC, 0);
}

#[test]
fn net_timers_wait_msec_matches_current_formula() {
    assert_eq!(mtproxy_ffi_net_timers_wait_msec(10.125, 10.000), 126);
    assert_eq!(mtproxy_ffi_net_timers_wait_msec(10.000, 10.010), 0);
    assert_eq!(mtproxy_ffi_net_timers_wait_msec(10.000, 10.000), 0);
}

#[test]
fn net_select_best_key_signature_matches_c_semantics() {
    let main_key_signature = i32::from_ne_bytes(0x12_34_56_78_u32.to_ne_bytes());
    let extras = [7, main_key_signature, 19];

    assert_eq!(
        unsafe {
            mtproxy_ffi_net_select_best_key_signature(
                3,
                main_key_signature,
                main_key_signature,
                0,
                core::ptr::null(),
            )
        },
        0
    );

    assert_eq!(
        unsafe {
            mtproxy_ffi_net_select_best_key_signature(
                32,
                main_key_signature,
                main_key_signature,
                0,
                core::ptr::null(),
            )
        },
        main_key_signature
    );

    assert_eq!(
        unsafe {
            mtproxy_ffi_net_select_best_key_signature(
                32,
                main_key_signature,
                11,
                i32::try_from(extras.len()).unwrap_or(i32::MAX),
                extras.as_ptr(),
            )
        },
        main_key_signature
    );

    assert_eq!(
        unsafe {
            mtproxy_ffi_net_select_best_key_signature(
                32,
                main_key_signature,
                11,
                1,
                extras.as_ptr(),
            )
        },
        0
    );
}

#[test]
fn net_connection_helpers_match_c_semantics() {
    const C_WANTRD: i32 = 1;
    const C_WANTWR: i32 = 2;
    const C_ERROR: i32 = 0x8;
    const C_NORD: i32 = 0x10;
    const C_NOWR: i32 = 0x20;
    const C_FAILED: i32 = 0x80;
    const C_NET_FAILED: i32 = 0x80_000;
    const C_READY_PENDING: i32 = 0x0100_0000;
    const C_CONNECTED: i32 = 0x0200_0000;

    let evt_spec = i32::from_ne_bytes(EVT_SPEC.to_ne_bytes());
    let evt_write = i32::from_ne_bytes(EVT_WRITE.to_ne_bytes());
    let evt_read = i32::from_ne_bytes(EVT_READ.to_ne_bytes());
    let evt_level = i32::from_ne_bytes(EVT_LEVEL.to_ne_bytes());

    assert_eq!(mtproxy_ffi_net_connection_is_active(C_CONNECTED), 1);
    assert_eq!(
        mtproxy_ffi_net_connection_is_active(C_CONNECTED | C_READY_PENDING),
        0
    );
    assert_eq!(mtproxy_ffi_net_connection_is_active(0), 0);

    assert_eq!(mtproxy_ffi_net_compute_conn_events(C_ERROR, 1), 0);
    assert_eq!(
        mtproxy_ffi_net_compute_conn_events(0, 1),
        evt_read | evt_write | evt_spec
    );

    assert_eq!(
        mtproxy_ffi_net_compute_conn_events(C_WANTRD, 0),
        evt_read | evt_spec
    );
    assert_eq!(
        mtproxy_ffi_net_compute_conn_events(C_WANTRD | C_NORD, 0),
        evt_read | evt_spec | evt_level
    );
    assert_eq!(
        mtproxy_ffi_net_compute_conn_events(C_WANTWR | C_NOWR, 0),
        evt_write | evt_spec | evt_level
    );
    assert_eq!(mtproxy_ffi_net_compute_conn_events(C_ERROR, 0), 0);
    assert_eq!(mtproxy_ffi_net_compute_conn_events(C_FAILED, 0), 0);
    assert_eq!(mtproxy_ffi_net_compute_conn_events(C_NET_FAILED, 0), 0);
}

#[test]
fn net_nat_helpers_match_c_semantics() {
    let invalid = b"broken-rule\0";
    assert_eq!(
        unsafe { mtproxy_ffi_net_add_nat_info(invalid.as_ptr().cast()) },
        -1
    );

    let rule_a = b"198.51.100.11:203.0.113.21\0";
    let rule_b = b"198.51.100.12:203.0.113.22\0";
    assert!(unsafe { mtproxy_ffi_net_add_nat_info(rule_a.as_ptr().cast()) } >= 0);
    assert!(unsafe { mtproxy_ffi_net_add_nat_info(rule_b.as_ptr().cast()) } >= 0);

    let local_a = u32::from(std::net::Ipv4Addr::new(198, 51, 100, 11));
    let global_a = u32::from(std::net::Ipv4Addr::new(203, 0, 113, 21));
    assert_eq!(mtproxy_ffi_net_translate_ip(local_a), global_a);

    let passthrough = u32::from(std::net::Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(mtproxy_ffi_net_translate_ip(passthrough), passthrough);
}

#[test]
fn net_http_error_msg_text_matches_c_semantics() {
    let mut code = 404;
    let msg_ptr = unsafe { mtproxy_ffi_net_http_error_msg_text(&raw mut code) };
    assert!(!msg_ptr.is_null());
    let msg = unsafe { std::ffi::CStr::from_ptr(msg_ptr) };
    assert_eq!(msg.to_str().unwrap_or_default(), "Not Found");
    assert_eq!(code, 404);

    code = 777;
    let msg_ptr = unsafe { mtproxy_ffi_net_http_error_msg_text(&raw mut code) };
    assert!(!msg_ptr.is_null());
    let msg = unsafe { std::ffi::CStr::from_ptr(msg_ptr) };
    assert_eq!(msg.to_str().unwrap_or_default(), "Internal Server Error");
    assert_eq!(code, 500);

    let null_msg = unsafe { mtproxy_ffi_net_http_error_msg_text(core::ptr::null_mut()) };
    assert!(null_msg.is_null());
}

#[test]
fn net_http_time_helpers_match_c_semantics() {
    let mut out = [0i8; 30];
    assert_eq!(
        unsafe {
            mtproxy_ffi_net_http_gen_date(
                out.as_mut_ptr(),
                i32::try_from(out.len()).unwrap_or(i32::MAX),
                0,
            )
        },
        0
    );
    let date = unsafe { std::ffi::CStr::from_ptr(out.as_ptr()) };
    assert_eq!(
        date.to_str().unwrap_or_default(),
        "Thu, 01 Jan 1970 00:00:00 GMT"
    );

    let mut parsed = -1;
    let rc = unsafe { mtproxy_ffi_net_http_gen_time(out.as_ptr(), &raw mut parsed) };
    assert_eq!(rc, 0);
    assert_eq!(parsed, 0);

    let invalid_tz = b"Thu, 01 Jan 1970 00:00:00 UTC\0";
    let rc = unsafe { mtproxy_ffi_net_http_gen_time(invalid_tz.as_ptr().cast(), &raw mut parsed) };
    assert_eq!(rc, -16);

    assert_eq!(
        unsafe { mtproxy_ffi_net_http_gen_time(core::ptr::null(), &raw mut parsed) },
        -8
    );
}

#[test]
fn msg_buffers_pick_size_index_matches_c_policy() {
    let sizes = [48, 512, 2_048, 16_384, 262_144];
    let all_idx = unsafe {
        mtproxy_ffi_msg_buffers_pick_size_index(
            sizes.as_ptr(),
            i32::try_from(sizes.len()).unwrap_or(i32::MAX),
            -1,
        )
    };
    assert_eq!(all_idx, 4);

    let idx = unsafe {
        mtproxy_ffi_msg_buffers_pick_size_index(
            sizes.as_ptr(),
            i32::try_from(sizes.len()).unwrap_or(i32::MAX),
            3000,
        )
    };
    assert_eq!(idx, 3);

    let tiny = unsafe {
        mtproxy_ffi_msg_buffers_pick_size_index(
            sizes.as_ptr(),
            i32::try_from(sizes.len()).unwrap_or(i32::MAX),
            40,
        )
    };
    assert_eq!(tiny, 0);
}

#[test]
fn tcp_rpc_compact_header_encoding_matches_c_logic() {
    let mut prefix_word = 0;
    let mut prefix_bytes = 0;
    assert_eq!(
        unsafe {
            mtproxy_ffi_tcp_rpc_encode_compact_header(
                512,
                1,
                &raw mut prefix_word,
                &raw mut prefix_bytes,
            )
        },
        0
    );
    assert_eq!(prefix_word, 512);
    assert_eq!(prefix_bytes, 4);

    assert_eq!(
        unsafe {
            mtproxy_ffi_tcp_rpc_encode_compact_header(
                64,
                0,
                &raw mut prefix_word,
                &raw mut prefix_bytes,
            )
        },
        0
    );
    assert_eq!(prefix_word, 16);
    assert_eq!(prefix_bytes, 1);

    assert_eq!(
        unsafe {
            mtproxy_ffi_tcp_rpc_encode_compact_header(
                2000,
                0,
                &raw mut prefix_word,
                &raw mut prefix_bytes,
            )
        },
        0
    );
    let expected_u = (u32::from_ne_bytes(2000_i32.to_ne_bytes()) << 6) | 0x7f;
    assert_eq!(u32::from_ne_bytes(prefix_word.to_ne_bytes()), expected_u);
    assert_eq!(prefix_bytes, 4);
}

#[test]
fn tcp_rpc_packet_len_state_helpers_match_current_rules() {
    assert_eq!(
        mtproxy_ffi_tcp_rpc_client_packet_len_state(4, 1024),
        TCP_RPC_PACKET_LEN_STATE_SKIP
    );
    assert_eq!(
        mtproxy_ffi_tcp_rpc_client_packet_len_state(12, 1024),
        TCP_RPC_PACKET_LEN_STATE_SHORT
    );
    assert_eq!(
        mtproxy_ffi_tcp_rpc_client_packet_len_state(16, 1024),
        TCP_RPC_PACKET_LEN_STATE_READY
    );
    assert_eq!(
        mtproxy_ffi_tcp_rpc_client_packet_len_state(3, 1024),
        TCP_RPC_PACKET_LEN_STATE_INVALID
    );
    assert_eq!(
        mtproxy_ffi_tcp_rpc_client_packet_len_state(2048, 1024),
        TCP_RPC_PACKET_LEN_STATE_INVALID
    );

    assert_eq!(mtproxy_ffi_tcp_rpc_server_packet_header_malformed(0), 1);
    assert_eq!(
        mtproxy_ffi_tcp_rpc_server_packet_header_malformed(i32::from_ne_bytes(
            0xc000_0000_u32.to_ne_bytes()
        )),
        1
    );
    assert_eq!(mtproxy_ffi_tcp_rpc_server_packet_header_malformed(16), 0);
    assert_eq!(
        mtproxy_ffi_tcp_rpc_server_packet_len_state(4, 1024),
        TCP_RPC_PACKET_LEN_STATE_SKIP
    );
    assert_eq!(
        mtproxy_ffi_tcp_rpc_server_packet_len_state(16, 1024),
        TCP_RPC_PACKET_LEN_STATE_READY
    );
    assert_eq!(
        mtproxy_ffi_tcp_rpc_server_packet_len_state(2048, 1024),
        TCP_RPC_PACKET_LEN_STATE_INVALID
    );
}

#[test]
fn rpc_target_pid_normalization_matches_c_fallback() {
    let mut pid = MtproxyProcessId {
        ip: 0,
        port: 443,
        pid: 10,
        utime: 100,
    };
    assert_eq!(
        unsafe { mtproxy_ffi_rpc_target_normalize_pid(&raw mut pid, 0x7f00_0001) },
        0
    );
    assert_eq!(pid.ip, 0x7f00_0001);
}

#[test]
fn crc32_matches_known_vector() {
    let data = b"123456789";
    // compute_crc32 semantics: crc32_partial(seed=~0) ^ ~0
    let partial = unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), data.len(), u32::MAX) };
    let final_crc = partial ^ u32::MAX;
    assert_eq!(final_crc, 0xcbf4_3926);
}

#[test]
fn crc32_is_incremental() {
    let data = b"incremental-crc32-test-vector";

    let full = unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), data.len(), 0x1234_5678) };

    let first = unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), 8, 0x1234_5678) };
    let rest_ptr = data[8..].as_ptr();
    let rest_len = data.len() - 8;
    let split = unsafe { mtproxy_ffi_crc32_partial(rest_ptr, rest_len, first) };

    assert_eq!(full, split);
}

#[test]
fn crc32c_matches_known_vector() {
    let data = b"123456789";
    let partial = unsafe { mtproxy_ffi_crc32c_partial(data.as_ptr(), data.len(), u32::MAX) };
    let final_crc = partial ^ u32::MAX;
    assert_eq!(final_crc, 0xe306_9283);
}

#[test]
fn crc32_check_and_repair_fixes_single_bit_flip() {
    let mut data = *b"abcdef012345";
    let original_crc =
        (unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), data.len(), u32::MAX) }) ^ u32::MAX;
    let mut stored_crc = original_crc;
    data[4] ^= 0x04;

    let rc = unsafe {
        mtproxy_ffi_crc32_check_and_repair(data.as_mut_ptr(), data.len(), &raw mut stored_crc)
    };
    assert_eq!(rc, 1);
    assert_eq!(stored_crc, original_crc);
    assert_eq!(&data, b"abcdef012345");
}

#[test]
fn gf32_combine_clmul_matches_legacy_vector_when_supported() {
    #[cfg(target_arch = "x86_64")]
    {
        if !std::arch::is_x86_feature_detected!("pclmulqdq") {
            return;
        }
    }

    let mut powers = [0u32; GF32_CLMUL_POWERS_LEN];
    unsafe {
        mtproxy_ffi_gf32_compute_powers_clmul(powers.as_mut_ptr(), CRC32_REFLECTED_POLY);
    }
    let out = unsafe { mtproxy_ffi_gf32_combine_clmul(powers.as_ptr(), 0x89ab_cdef, 17) };
    assert_eq!(out, 0x7be9_6e74_df25_97cc);
}

#[test]
fn pid_helpers_match_expected_semantics() {
    let mut pid = MtproxyProcessId::default();
    let rc = unsafe { mtproxy_ffi_pid_init_common(&raw mut pid) };
    assert_eq!(rc, 0);
    let raw_pid = i32::try_from(std::process::id()).unwrap_or_default();
    let raw_pid_bits = u32::from_ne_bytes(raw_pid.to_ne_bytes());
    let expected_pid = u16::try_from(raw_pid_bits & u32::from(u16::MAX)).unwrap_or_default();
    assert_eq!(pid.pid, expected_pid);
    assert_ne!(pid.pid, 0);
    assert_ne!(pid.utime, 0);

    let mut y = pid;
    y.pid = 0;
    assert_eq!(
        unsafe { mtproxy_ffi_matches_pid(&raw const pid, &raw const y) },
        1
    );
    y.pid = pid.pid;
    assert_eq!(
        unsafe { mtproxy_ffi_matches_pid(&raw const pid, &raw const y) },
        2
    );
}

#[test]
fn process_id_is_newer_follows_pid_window_rule() {
    let a = MtproxyProcessId {
        ip: 1,
        port: 80,
        pid: 1000,
        utime: 10,
    };
    let mut b = a;
    b.pid = 900;
    assert_eq!(
        unsafe { mtproxy_ffi_process_id_is_newer(&raw const a, &raw const b) },
        1
    );
}

#[test]
fn cpuid_fill_produces_magic_on_x86() {
    let mut out = MtproxyCpuid::default();
    let rc = unsafe { mtproxy_ffi_cpuid_fill(&raw mut out) };
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        assert_eq!(rc, 0);
        assert_eq!(out.magic, CPUID_MAGIC);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        assert_eq!(rc, -2);
    }
}

#[test]
fn md5_and_md5_hex_match_known_vector() {
    let data = b"123456789";
    let mut digest = [0u8; 16];
    assert_eq!(
        unsafe { mtproxy_ffi_md5(data.as_ptr(), data.len(), digest.as_mut_ptr()) },
        0
    );
    assert_eq!(
        digest,
        [
            0x25, 0xf9, 0xe7, 0x94, 0x32, 0x3b, 0x45, 0x38, 0x85, 0xf5, 0x18, 0x1f, 0x1b, 0x62,
            0x4d, 0x0b,
        ]
    );

    let mut hex = [0i8; 32];
    assert_eq!(
        unsafe { mtproxy_ffi_md5_hex(data.as_ptr(), data.len(), hex.as_mut_ptr()) },
        0
    );
    let hex_bytes: Vec<u8> = hex
        .iter()
        .map(|v| u8::try_from(*v).unwrap_or_default())
        .collect();
    assert_eq!(&hex_bytes, b"25f9e794323b453885f5181f1b624d0b");
}

#[test]
fn sha1_matches_known_vector_and_two_chunk_variant() {
    let data = b"abc";
    let mut digest = [0u8; 20];
    assert_eq!(
        unsafe { mtproxy_ffi_sha1(data.as_ptr(), data.len(), digest.as_mut_ptr()) },
        0
    );
    assert_eq!(
        digest,
        [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ]
    );

    let mut split_digest = [0u8; 20];
    assert_eq!(
        unsafe {
            mtproxy_ffi_sha1_two_chunks(
                b"a".as_ptr(),
                1,
                b"bc".as_ptr(),
                2,
                split_digest.as_mut_ptr(),
            )
        },
        0
    );
    assert_eq!(digest, split_digest);
}

#[test]
fn sha256_and_hmac_match_known_vectors() {
    let data = b"abc";
    let mut digest = [0u8; 32];
    assert_eq!(
        unsafe { mtproxy_ffi_sha256(data.as_ptr(), data.len(), digest.as_mut_ptr()) },
        0
    );
    assert_eq!(
        digest,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );

    let mut split_digest = [0u8; 32];
    assert_eq!(
        unsafe {
            mtproxy_ffi_sha256_two_chunks(
                b"a".as_ptr(),
                1,
                b"bc".as_ptr(),
                2,
                split_digest.as_mut_ptr(),
            )
        },
        0
    );
    assert_eq!(digest, split_digest);

    let mut hmac = [0u8; 32];
    assert_eq!(
        unsafe {
            mtproxy_ffi_sha256_hmac(
                b"key".as_ptr(),
                3,
                b"The quick brown fox jumps over the lazy dog".as_ptr(),
                43,
                hmac.as_mut_ptr(),
            )
        },
        0
    );
    assert_eq!(
        hmac,
        [
            0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f,
            0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc,
            0x2d, 0x1a, 0x3c, 0xd8,
        ]
    );
}

#[test]
fn precise_time_exports_update_thread_local_values() {
    let t = mtproxy_ffi_get_utime_monotonic();
    assert!(t > 0.0);
    assert!(mtproxy_ffi_precise_now_value() > 0.0);
    assert!(mtproxy_ffi_precise_now_rdtsc_value() >= 0);

    let p = mtproxy_ffi_get_precise_time(0);
    assert!(p >= 0);
}

#[test]
fn cfg_primitives_scan_lengths_and_signed_int() {
    let src = b" \t# comment\nproxy_for -123;";
    let mut scan = MtproxyCfgScanResult::default();
    assert_eq!(
        unsafe {
            mtproxy_ffi_cfg_skipspc(
                src.as_ptr().cast(),
                src.len(),
                0,
                (&raw mut scan).cast::<MtproxyCfgScanResult>(),
            )
        },
        0
    );
    assert_eq!(scan.line_no, 1);
    assert_eq!(scan.ch, i32::from(b'p'));

    let word_ptr = unsafe { src.as_ptr().add(scan.advance) };
    assert_eq!(
        unsafe { mtproxy_ffi_cfg_getword_len(word_ptr.cast(), src.len() - scan.advance) },
        9
    );

    let int_ptr = unsafe { word_ptr.add(9) };
    let mut parsed = MtproxyCfgIntResult::default();
    assert_eq!(
        unsafe {
            mtproxy_ffi_cfg_getint_signed_zero(
                int_ptr.cast(),
                src.len() - scan.advance - 9,
                &raw mut parsed,
            )
        },
        0
    );
    assert_eq!(parsed.value, -123);
    assert!(parsed.consumed >= 4);
}

#[test]
fn tl_parse_query_and_answer_header_vectors() {
    let mut query = Vec::new();
    query.extend_from_slice(&RPC_INVOKE_REQ.to_le_bytes());
    query.extend_from_slice(&0x1122_3344_5566_7788_i64.to_le_bytes());
    query.extend_from_slice(&0x166b_b7c6_i32.to_le_bytes());

    let mut q = MtproxyTlHeaderParseResult::default();
    assert_eq!(
        unsafe { mtproxy_ffi_tl_parse_query_header(query.as_ptr(), query.len(), &raw mut q) },
        0
    );
    assert_eq!(q.status, 0);
    assert_eq!(q.consumed, 12);
    assert_eq!(q.op, RPC_INVOKE_REQ);

    let mut answer = Vec::new();
    answer.extend_from_slice(&RPC_REQ_RESULT.to_le_bytes());
    answer.extend_from_slice(&0x0102_0304_0506_0708_i64.to_le_bytes());
    answer.extend_from_slice(&0x166b_b7c6_i32.to_le_bytes());

    let mut a = MtproxyTlHeaderParseResult::default();
    assert_eq!(
        unsafe { mtproxy_ffi_tl_parse_answer_header(answer.as_ptr(), answer.len(), &raw mut a) },
        0
    );
    assert_eq!(a.status, 0);
    assert_eq!(a.consumed, 12);
    assert_eq!(a.op, RPC_REQ_RESULT);
}

#[test]
fn observability_helpers_parse_and_format() {
    let statm = b"10 20 30 40 50 60";
    let mut out = [0i64; 6];
    assert_eq!(
        unsafe {
            mtproxy_ffi_parse_statm(
                statm.as_ptr().cast(),
                statm.len(),
                6,
                4096,
                out.as_mut_ptr(),
            )
        },
        0
    );
    assert_eq!(out[0], 10 * 4096);
    assert_eq!(out[5], 60 * 4096);

    let meminfo = b"MemFree: 1 kB\nCached: 2 kB\nSwapTotal: 3 kB\nSwapFree: 4 kB\n";
    let mut summary = MtproxyMeminfoSummary::default();
    assert_eq!(
        unsafe {
            mtproxy_ffi_parse_meminfo_summary(
                meminfo.as_ptr().cast(),
                meminfo.len(),
                &raw mut summary,
            )
        },
        0
    );
    assert_eq!(summary.found_mask, 15);
    assert_eq!(summary.mem_free, 1024);

    let proc_line = b"1 (x) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39\n";
    let mut ps = MtproxyProcStats::default();
    assert_eq!(
        unsafe {
            mtproxy_ffi_parse_proc_stat_line(
                proc_line.as_ptr().cast(),
                proc_line.len(),
                &raw mut ps,
            )
        },
        0
    );
    assert_eq!(ps.pid, 1);
    assert_eq!(ps.state, i8::from_ne_bytes([b'R']));

    let mut ps_live = MtproxyProcStats::default();
    let pid = i32::try_from(std::process::id()).unwrap_or_default();
    assert_eq!(
        unsafe { mtproxy_ffi_read_proc_stat_file(pid, 0, &raw mut ps_live) },
        0
    );
    assert_eq!(ps_live.pid, pid);
}
