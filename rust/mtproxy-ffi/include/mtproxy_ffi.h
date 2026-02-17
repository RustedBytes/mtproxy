#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mtproxy_ffi_process_id {
  uint32_t ip;
  int16_t port;
  uint16_t pid;
  int32_t utime;
} mtproxy_ffi_process_id_t;

typedef struct mtproxy_ffi_rpc_target_tree mtproxy_ffi_rpc_target_tree_t;

typedef struct mtproxy_ffi_aes_key_data {
  uint8_t read_key[32];
  uint8_t read_iv[16];
  uint8_t write_key[32];
  uint8_t write_iv[16];
} mtproxy_ffi_aes_key_data_t;

typedef struct mtproxy_ffi_aes_secret {
  int32_t refcnt;
  int32_t secret_len;
  uint8_t secret[260];
} mtproxy_ffi_aes_secret_t;

typedef struct mtproxy_ffi_crypto_temp_dh_params {
  int32_t magic;
  int32_t dh_params_select;
  uint8_t a[256];
} mtproxy_ffi_crypto_temp_dh_params_t;

typedef struct mtproxy_ffi_cpuid {
  int32_t magic;
  int32_t ebx;
  int32_t ecx;
  int32_t edx;
} mtproxy_ffi_cpuid_t;

typedef struct mtproxy_ffi_cfg_scan_result {
  size_t advance;
  int32_t line_no;
  int32_t ch;
} mtproxy_ffi_cfg_scan_result_t;

typedef struct mtproxy_ffi_cfg_int_result {
  int64_t value;
  size_t consumed;
} mtproxy_ffi_cfg_int_result_t;

typedef struct mtproxy_ffi_mtproto_cfg_getlex_ext_result {
  size_t advance;
  int32_t lex;
} mtproxy_ffi_mtproto_cfg_getlex_ext_result_t;

typedef struct mtproxy_ffi_mtproto_cfg_directive_token_result {
  int32_t kind;
  size_t advance;
  int64_t value;
} mtproxy_ffi_mtproto_cfg_directive_token_result_t;

typedef struct mtproxy_ffi_mtproto_cfg_directive_step_result {
  int32_t kind;
  size_t advance;
  int64_t value;
  int32_t cluster_decision_kind;
  int32_t cluster_index;
} mtproxy_ffi_mtproto_cfg_directive_step_result_t;

typedef struct mtproxy_ffi_mtproto_cfg_finalize_result {
  uint32_t default_cluster_index;
  int32_t has_default_cluster_index;
} mtproxy_ffi_mtproto_cfg_finalize_result_t;

typedef struct mtproxy_ffi_mtproto_cfg_preinit_result {
  int32_t tot_targets;
  int32_t auth_clusters;
  int64_t min_connections;
  int64_t max_connections;
  double timeout_seconds;
  int32_t default_cluster_id;
} mtproxy_ffi_mtproto_cfg_preinit_result_t;

typedef struct mtproxy_ffi_mtproto_cfg_cluster_apply_decision_result {
  int32_t kind;
  int32_t cluster_index;
} mtproxy_ffi_mtproto_cfg_cluster_apply_decision_result_t;

typedef struct mtproxy_ffi_mtproto_old_cluster_state {
  int32_t cluster_id;
  uint32_t targets_num;
  uint32_t write_targets_num;
  uint32_t flags;
  uint32_t first_target_index;
  int32_t has_first_target_index;
} mtproxy_ffi_mtproto_old_cluster_state_t;

typedef struct mtproxy_ffi_mtproto_cfg_parse_proxy_target_step_result {
  size_t advance;
  uint32_t target_index;
  uint8_t host_len;
  uint16_t port;
  int64_t min_connections;
  int64_t max_connections;
  uint32_t tot_targets_after;
  int32_t cluster_decision_kind;
  int32_t cluster_index;
  uint32_t auth_clusters_after;
  uint32_t auth_tot_clusters_after;
  mtproxy_ffi_mtproto_old_cluster_state_t cluster_state_after;
  int32_t cluster_targets_action;
  uint32_t cluster_targets_index;
} mtproxy_ffi_mtproto_cfg_parse_proxy_target_step_result_t;

typedef struct mtproxy_ffi_mtproto_cfg_proxy_action {
  size_t host_offset;
  mtproxy_ffi_mtproto_cfg_parse_proxy_target_step_result_t step;
} mtproxy_ffi_mtproto_cfg_proxy_action_t;

typedef struct mtproxy_ffi_mtproto_cfg_parse_full_result {
  uint32_t tot_targets;
  uint32_t auth_clusters;
  uint32_t auth_tot_clusters;
  int64_t min_connections;
  int64_t max_connections;
  double timeout_seconds;
  int32_t default_cluster_id;
  int32_t have_proxy;
  uint32_t default_cluster_index;
  int32_t has_default_cluster_index;
  uint32_t actions_len;
} mtproxy_ffi_mtproto_cfg_parse_full_result_t;

typedef struct mtproxy_ffi_mtproto_packet_inspect_result {
  int32_t kind;
  int64_t auth_key_id;
  int32_t inner_len;
  int32_t function_id;
} mtproxy_ffi_mtproto_packet_inspect_result_t;

typedef struct mtproxy_ffi_mtproto_parse_function_result {
  int32_t status;
  int32_t consumed;
  int32_t errnum;
  int32_t error_len;
  char error[192];
} mtproxy_ffi_mtproto_parse_function_result_t;

typedef struct mtproxy_ffi_mtproto_client_packet_parse_result {
  int32_t kind;
  int32_t op;
  int32_t flags;
  int64_t out_conn_id;
  int32_t confirm;
  int32_t payload_offset;
} mtproxy_ffi_mtproto_client_packet_parse_result_t;

typedef struct mtproxy_ffi_mtproto_ext_connection {
  int32_t in_fd;
  int32_t in_gen;
  int32_t out_fd;
  int32_t out_gen;
  int64_t in_conn_id;
  int64_t out_conn_id;
  int64_t auth_key_id;
} mtproxy_ffi_mtproto_ext_connection_t;

typedef struct mtproxy_ffi_mtproto_client_packet_process_result {
  int32_t kind;
  int32_t payload_offset;
  int32_t flags;
  int32_t confirm;
  int64_t out_conn_id;
  int32_t in_fd;
  int32_t in_gen;
  int64_t in_conn_id;
  int32_t out_fd;
  int32_t out_gen;
  int64_t auth_key_id;
} mtproxy_ffi_mtproto_client_packet_process_result_t;

enum { MTPROXY_FFI_MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND = 1 };
enum { MTPROXY_FFI_MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS = (-1) };

enum { MTPROXY_FFI_MTPROTO_CFG_FINALIZE_OK = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS = (-1) };
enum { MTPROXY_FFI_MTPROTO_CFG_FINALIZE_ERR_MISSING_PROXY_DIRECTIVES = (-2) };
enum { MTPROXY_FFI_MTPROTO_CFG_FINALIZE_ERR_NO_PROXY_SERVERS_DEFINED = (-3) };
enum { MTPROXY_FFI_MTPROTO_CFG_FINALIZE_ERR_INTERNAL = (-4) };

enum { MTPROXY_FFI_MTPROTO_CFG_PREINIT_OK = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_PREINIT_ERR_INVALID_ARGS = (-1) };
enum { MTPROXY_FFI_MTPROTO_CFG_PREINIT_ERR_INTERNAL = (-2) };

enum { MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS = (-1) };
enum { MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_TOO_MANY_AUTH_CLUSTERS = (-2) };
enum { MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_PROXIES_INTERMIXED = (-3) };
enum { MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INTERNAL = (-4) };

enum { MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW = 1 };
enum { MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST = 2 };

enum { MTPROXY_FFI_MTPROTO_CFG_GETLEX_EXT_OK = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_GETLEX_EXT_ERR_INVALID_ARGS = (-1) };

enum { MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_ARGS = (-1) };
enum { MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TIMEOUT = (-2) };
enum { MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MAX_CONNECTIONS = (-3) };
enum { MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MIN_CONNECTIONS = (-4) };
enum { MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TARGET_ID = (-5) };
enum { MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_TARGET_ID_SPACE = (-6) };
enum { MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_PROXY_EXPECTED = (-7) };
enum { MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INTERNAL = (-8) };

enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS = (-1) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TIMEOUT = (-2) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MAX_CONNECTIONS = (-3) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MIN_CONNECTIONS = (-4) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TARGET_ID = (-5) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TARGET_ID_SPACE = (-6) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXY_EXPECTED = (-7) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TOO_MANY_AUTH_CLUSTERS = (-8) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXIES_INTERMIXED = (-9) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_EXPECTED_SEMICOLON = (-10) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INTERNAL = (-11) };

enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS = (-1) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_AUTH_CLUSTERS = (-2) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PROXIES_INTERMIXED = (-3) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_TARGETS = (-4) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_HOSTNAME_EXPECTED = (-5) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_EXPECTED = (-6) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_RANGE = (-7) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_EXPECTED_SEMICOLON = (-8) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_CLUSTER_EXTEND_INVARIANT = (-9) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL = (-10) };

enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_OK = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS = (-1) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TIMEOUT = (-2) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MAX_CONNECTIONS = (-3) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MIN_CONNECTIONS = (-4) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TARGET_ID = (-5) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_TARGET_ID_SPACE = (-6) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXY_EXPECTED = (-7) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_AUTH_CLUSTERS = (-8) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXIES_INTERMIXED = (-9) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON = (-10) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_TARGETS = (-11) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_HOSTNAME_EXPECTED = (-12) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_EXPECTED = (-13) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_RANGE = (-14) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_CLUSTER_EXTEND_INVARIANT = (-15) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES = (-16) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_NO_PROXY_SERVERS_DEFINED = (-17) };
enum { MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL = (-18) };

enum { MTPROXY_FFI_MTPROTO_CFG_EXPECT_SEMICOLON_OK = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS = (-1) };
enum { MTPROXY_FFI_MTPROTO_CFG_EXPECT_SEMICOLON_ERR_EXPECTED = (-2) };

enum { MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_EOF = 0 };
enum { MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT = 1 };
enum { MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER = 2 };
enum { MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR = 3 };
enum { MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY = 4 };
enum { MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS = 5 };
enum { MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS = 6 };

enum { MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING = 0 };
enum { MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_CLEAR = 1 };
enum { MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET = 2 };

enum { MTPROXY_FFI_MTPROTO_PACKET_KIND_INVALID = 0 };
enum { MTPROXY_FFI_MTPROTO_PACKET_KIND_ENCRYPTED = 1 };
enum { MTPROXY_FFI_MTPROTO_PACKET_KIND_UNENCRYPTED_DH = 2 };

enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_INVALID = 0 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_PONG = 1 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_PROXY_ANS = 2 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_SIMPLE_ACK = 3 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_CLOSE_EXT = 4 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_UNKNOWN = 5 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_MALFORMED = 6 };

enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_ACTION_INVALID = 0 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_ACTION_PROXY_ANS_FORWARD = 1 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_ACTION_PROXY_ANS_NOTIFY_CLOSE = 2 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_ACTION_SIMPLE_ACK_FORWARD = 3 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_ACTION_SIMPLE_ACK_NOTIFY_CLOSE = 4 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_ACTION_CLOSE_EXT_REMOVED = 5 };
enum { MTPROXY_FFI_MTPROTO_CLIENT_PACKET_ACTION_CLOSE_EXT_NOOP = 6 };

typedef struct mtproxy_ffi_tl_header_parse_result {
  int32_t status;
  int32_t consumed;
  int32_t op;
  int32_t real_op;
  int32_t flags;
  int64_t qid;
  int64_t actor_id;
  int32_t errnum;
  int32_t error_len;
  char error[192];
} mtproxy_ffi_tl_header_parse_result_t;

typedef struct mtproxy_ffi_proc_stats {
  int32_t pid;
  char comm[256];
  int8_t state;
  int32_t ppid;
  int32_t pgrp;
  int32_t session;
  int32_t tty_nr;
  int32_t tpgid;
  uint64_t flags;
  uint64_t minflt;
  uint64_t cminflt;
  uint64_t majflt;
  uint64_t cmajflt;
  uint64_t utime;
  uint64_t stime;
  int64_t cutime;
  int64_t cstime;
  int64_t priority;
  int64_t nice;
  int64_t num_threads;
  int64_t itrealvalue;
  uint64_t starttime;
  uint64_t vsize;
  int64_t rss;
  uint64_t rlim;
  uint64_t startcode;
  uint64_t endcode;
  uint64_t startstack;
  uint64_t kstkesp;
  uint64_t kstkeip;
  uint64_t signal;
  uint64_t blocked;
  uint64_t sigignore;
  uint64_t sigcatch;
  uint64_t wchan;
  uint64_t nswap;
  uint64_t cnswap;
  int32_t exit_signal;
  int32_t processor;
  uint64_t rt_priority;
  uint64_t policy;
  uint64_t delayacct_blkio_ticks;
} mtproxy_ffi_proc_stats_t;

typedef struct mtproxy_ffi_meminfo_summary {
  int64_t mem_free;
  int64_t mem_cached;
  int64_t swap_total;
  int64_t swap_free;
  int32_t found_mask;
} mtproxy_ffi_meminfo_summary_t;

enum { MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION = 1u };

enum { MTPROXY_FFI_MPQ_OP_PUSH = (1u << 0) };
enum { MTPROXY_FFI_MPQ_OP_POP = (1u << 1) };
enum { MTPROXY_FFI_MPQ_OP_IS_EMPTY = (1u << 2) };
enum { MTPROXY_FFI_MPQ_OP_PUSH_W = (1u << 3) };
enum { MTPROXY_FFI_MPQ_OP_POP_W = (1u << 4) };
enum { MTPROXY_FFI_MPQ_OP_POP_NW = (1u << 5) };

enum { MTPROXY_FFI_JOBS_OP_CREATE_ASYNC_JOB = (1u << 0) };
enum { MTPROXY_FFI_JOBS_OP_SCHEDULE_JOB = (1u << 1) };
enum { MTPROXY_FFI_JOBS_OP_JOB_SIGNAL = (1u << 2) };
enum { MTPROXY_FFI_JOBS_OP_JOB_INCREF = (1u << 3) };
enum { MTPROXY_FFI_JOBS_OP_JOB_DECREF = (1u << 4) };
enum { MTPROXY_FFI_JOBS_OP_RUN_PENDING_MAIN_JOBS = (1u << 5) };
enum { MTPROXY_FFI_JOBS_OP_NOTIFY_JOB_CREATE = (1u << 6) };

typedef struct mtproxy_ffi_concurrency_boundary {
  uint32_t boundary_version;
  uint32_t mpq_contract_ops;
  uint32_t mpq_implemented_ops;
  uint32_t jobs_contract_ops;
  uint32_t jobs_implemented_ops;
} mtproxy_ffi_concurrency_boundary_t;

enum { MTPROXY_FFI_NETWORK_BOUNDARY_VERSION = 1u };

enum { MTPROXY_FFI_NET_EVENTS_OP_EPOLL_CONV_FLAGS = (1u << 0) };
enum { MTPROXY_FFI_NET_EVENTS_OP_EPOLL_UNCONV_FLAGS = (1u << 1) };

enum { MTPROXY_FFI_NET_TIMERS_OP_WAIT_MSEC = (1u << 0) };

enum { MTPROXY_FFI_NET_MSGBUFFERS_OP_PICK_SIZE_INDEX = (1u << 0) };

typedef struct mtproxy_ffi_network_boundary {
  uint32_t boundary_version;
  uint32_t net_events_contract_ops;
  uint32_t net_events_implemented_ops;
  uint32_t net_timers_contract_ops;
  uint32_t net_timers_implemented_ops;
  uint32_t net_msg_buffers_contract_ops;
  uint32_t net_msg_buffers_implemented_ops;
} mtproxy_ffi_network_boundary_t;

enum { MTPROXY_FFI_RPC_BOUNDARY_VERSION = 1u };

enum { MTPROXY_FFI_TCP_RPC_COMMON_OP_COMPACT_ENCODE = (1u << 0) };

enum { MTPROXY_FFI_TCP_RPC_CLIENT_OP_PACKET_LEN_STATE = (1u << 0) };
enum { MTPROXY_FFI_TCP_RPC_CLIENT_OP_PARSE_NONCE_PACKET = (1u << 1) };
enum { MTPROXY_FFI_TCP_RPC_CLIENT_OP_PROCESS_NONCE_PACKET = (1u << 2) };

enum { MTPROXY_FFI_TCP_RPC_SERVER_OP_HEADER_MALFORMED = (1u << 0) };
enum { MTPROXY_FFI_TCP_RPC_SERVER_OP_PACKET_LEN_STATE = (1u << 1) };
enum { MTPROXY_FFI_TCP_RPC_SERVER_OP_PARSE_NONCE_PACKET = (1u << 2) };
enum { MTPROXY_FFI_TCP_RPC_SERVER_OP_PARSE_HANDSHAKE_PACKET = (1u << 3) };
enum { MTPROXY_FFI_TCP_RPC_SERVER_OP_PROCESS_NONCE_PACKET = (1u << 4) };

enum { MTPROXY_FFI_RPC_TARGETS_OP_NORMALIZE_PID = (1u << 0) };

typedef struct mtproxy_ffi_rpc_boundary {
  uint32_t boundary_version;
  uint32_t tcp_rpc_common_contract_ops;
  uint32_t tcp_rpc_common_implemented_ops;
  uint32_t tcp_rpc_client_contract_ops;
  uint32_t tcp_rpc_client_implemented_ops;
  uint32_t tcp_rpc_server_contract_ops;
  uint32_t tcp_rpc_server_implemented_ops;
  uint32_t rpc_targets_contract_ops;
  uint32_t rpc_targets_implemented_ops;
} mtproxy_ffi_rpc_boundary_t;

enum { MTPROXY_FFI_CRYPTO_BOUNDARY_VERSION = 1u };

enum { MTPROXY_FFI_NET_CRYPTO_AES_OP_CREATE_KEYS = (1u << 0) };

enum { MTPROXY_FFI_NET_CRYPTO_DH_OP_IS_GOOD_RPC_DH_BIN = (1u << 0) };
enum { MTPROXY_FFI_NET_CRYPTO_DH_OP_GET_PARAMS_SELECT = (1u << 1) };
enum { MTPROXY_FFI_NET_CRYPTO_DH_OP_FIRST_ROUND = (1u << 2) };
enum { MTPROXY_FFI_NET_CRYPTO_DH_OP_SECOND_ROUND = (1u << 3) };
enum { MTPROXY_FFI_NET_CRYPTO_DH_OP_THIRD_ROUND = (1u << 4) };

enum { MTPROXY_FFI_AESNI_OP_EVP_CRYPT = (1u << 0) };
enum { MTPROXY_FFI_AESNI_OP_CTX_INIT = (1u << 1) };
enum { MTPROXY_FFI_AESNI_OP_CTX_FREE = (1u << 2) };

enum { MTPROXY_FFI_AESNI_CIPHER_AES_256_CBC = 1 };
enum { MTPROXY_FFI_AESNI_CIPHER_AES_256_CTR = 2 };

typedef struct mtproxy_ffi_crypto_boundary {
  uint32_t boundary_version;
  uint32_t net_crypto_aes_contract_ops;
  uint32_t net_crypto_aes_implemented_ops;
  uint32_t net_crypto_dh_contract_ops;
  uint32_t net_crypto_dh_implemented_ops;
  uint32_t aesni_contract_ops;
  uint32_t aesni_implemented_ops;
} mtproxy_ffi_crypto_boundary_t;

enum { MTPROXY_FFI_APPLICATION_BOUNDARY_VERSION = 1u };

enum { MTPROXY_FFI_ENGINE_RPC_OP_RESULT_NEW_FLAGS = (1u << 0) };
enum { MTPROXY_FFI_ENGINE_RPC_OP_RESULT_HEADER_LEN = (1u << 1) };

enum { MTPROXY_FFI_MTPROTO_PROXY_OP_EXT_CONN_HASH = (1u << 0) };
enum { MTPROXY_FFI_MTPROTO_PROXY_OP_CONN_TAG = (1u << 1) };

typedef struct mtproxy_ffi_application_boundary {
  uint32_t boundary_version;
  uint32_t engine_rpc_contract_ops;
  uint32_t engine_rpc_implemented_ops;
  uint32_t mtproto_proxy_contract_ops;
  uint32_t mtproto_proxy_implemented_ops;
} mtproxy_ffi_application_boundary_t;

typedef int32_t (*mtproxy_ffi_jobs_process_fn)(void *job);
struct async_job;
struct raw_message;
struct job_message;
struct event_timer;
typedef int32_t (*mtproxy_ffi_engine_net_try_open_port_fn)(int32_t port, void *ctx);
typedef void (*mtproxy_ffi_engine_signal_dispatch_fn)(int32_t sig, void *ctx);

enum { MTPROXY_FFI_ENGINE_RPC_COMMON_PARSE_NONE = 0 };
enum { MTPROXY_FFI_ENGINE_RPC_COMMON_PARSE_STAT = 1 };
enum { MTPROXY_FFI_ENGINE_RPC_COMMON_PARSE_NOP = 2 };

enum { MTPROXY_FFI_ENGINE_RPC_QR_IGNORE_NO_TABLE = 0 };
enum { MTPROXY_FFI_ENGINE_RPC_QR_DISPATCH = 1 };
enum { MTPROXY_FFI_ENGINE_RPC_QR_SKIP_UNKNOWN = 2 };

enum { MTPROXY_FFI_ENGINE_RPC_QJ_INVOKE_PARSE = 0 };
enum { MTPROXY_FFI_ENGINE_RPC_QJ_CUSTOM = 1 };
enum { MTPROXY_FFI_ENGINE_RPC_QJ_IGNORE = 2 };

enum { MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_SKIP = 0 };
enum { MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_READY = 1 };
enum { MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_INVALID = (-1) };
enum { MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_SHORT = (-2) };

// FFI API surface version exposed by Rust side.
uint32_t mtproxy_ffi_api_version(void);

// Startup handshake between C and Rust layers.
// Returns 0 on success, -1 on version mismatch.
int32_t mtproxy_ffi_startup_handshake(uint32_t expected_api_version);

// Rust-side implementations of legacy checks from common/rust-ffi-bridge.c.
int32_t mtproxy_ffi_rust_bridge_startup_check(void);
int32_t mtproxy_ffi_rust_bridge_check_concurrency_boundary(void);
int32_t mtproxy_ffi_rust_bridge_check_network_boundary(void);
int32_t mtproxy_ffi_rust_bridge_check_rpc_boundary(void);
int32_t mtproxy_ffi_rust_bridge_check_crypto_boundary(void);
int32_t mtproxy_ffi_rust_bridge_check_application_boundary(void);
int32_t mtproxy_ffi_rust_bridge_enable_concurrency_bridges(void);
int32_t mtproxy_ffi_rust_bridge_enable_crc32_bridge(void);
int32_t mtproxy_ffi_rust_bridge_enable_crc32c_bridge(void);

// Reports extracted Step 9 boundary contract for mp-queue/jobs operations.
int32_t mtproxy_ffi_get_concurrency_boundary(mtproxy_ffi_concurrency_boundary_t *out);

// Reports extracted Step 10 boundary contract for net core operations.
int32_t mtproxy_ffi_get_network_boundary(mtproxy_ffi_network_boundary_t *out);

// Reports extracted Step 11 boundary contract for RPC/TCP operations.
int32_t mtproxy_ffi_get_rpc_boundary(mtproxy_ffi_rpc_boundary_t *out);

// Reports extracted Step 12 boundary contract for crypto integration operations.
int32_t mtproxy_ffi_get_crypto_boundary(mtproxy_ffi_crypto_boundary_t *out);

// Reports extracted Step 13 boundary contract for engine/mtproto application operations.
int32_t mtproxy_ffi_get_application_boundary(mtproxy_ffi_application_boundary_t *out);

// mp-queue helper: creates one Rust-backed queue handle (`waitable != 0` => `_w` semantics).
int32_t mtproxy_ffi_mpq_handle_create(int32_t waitable, void **out_handle);

// mp-queue helper: destroys one Rust-backed queue handle.
int32_t mtproxy_ffi_mpq_handle_destroy(void *handle);

// mp-queue helper: clears queue contents.
int32_t mtproxy_ffi_mpq_handle_clear(void *handle);

// mp-queue helper: push (`mpq_push` equivalent), writes enqueue position to `out_pos`.
int32_t mtproxy_ffi_mpq_handle_push(void *handle, void *value, int32_t flags, int64_t *out_pos);

// mp-queue helper: pop (`mpq_pop` equivalent).
// Returns `1` when one value is dequeued, `0` when queue is empty.
int32_t mtproxy_ffi_mpq_handle_pop(void *handle, int32_t flags, void **out_value);

// mp-queue helper: emptiness check (`mpq_is_empty` equivalent).
// Returns `1` when queue is empty, `0` when non-empty.
int32_t mtproxy_ffi_mpq_handle_is_empty(void *handle);

// mp-queue helper: waitable push (`mpq_push_w` equivalent), writes position to `out_pos`.
// Returns `-2` when queue was created as non-waitable.
int32_t mtproxy_ffi_mpq_handle_push_w(void *handle, void *value, int32_t flags, int64_t *out_pos);

// mp-queue helper: waitable pop (`mpq_pop_w` equivalent).
// Returns `1` when one value is dequeued; returns `-2` for non-waitable queue.
int32_t mtproxy_ffi_mpq_handle_pop_w(void *handle, int32_t flags, void **out_value);

// mp-queue helper: non-blocking waitable pop (`mpq_pop_nw` equivalent).
// Returns `1` when one value is dequeued, `0` when no value was produced.
// Returns `-2` for non-waitable queue.
int32_t mtproxy_ffi_mpq_handle_pop_nw(void *handle, int32_t flags, void **out_value);

// Rust implementation of legacy `common/mp-queue-rust.c` helpers.
int32_t mtproxy_ffi_mpq_rust_bridge_enable(void);
int32_t mtproxy_ffi_mpq_rust_queue_attached(void *mq);
int32_t mtproxy_ffi_mpq_rust_queue_waitable(void *mq);
int32_t mtproxy_ffi_mpq_rust_init_queue(void *mq, int32_t waitable);
void mtproxy_ffi_mpq_rust_clear_queue(void *mq);
int32_t mtproxy_ffi_mpq_rust_is_empty(void *mq);
long mtproxy_ffi_mpq_rust_push_w(void *mq, void *value, int32_t flags);
void *mtproxy_ffi_mpq_rust_pop_nw(void *mq, int32_t flags);
int32_t mtproxy_ffi_mpq_rust_attached_queues(void);

// jobs helper: initializes Rust/Tokio main-queue bridge.
int32_t mtproxy_ffi_jobs_tokio_init(void);

// jobs helper: enqueue one opaque `job_t` into Rust/Tokio queue by job class.
int32_t mtproxy_ffi_jobs_tokio_enqueue_class(int32_t job_class, void *job);

// jobs helper: dequeue one opaque `job_t` from Rust/Tokio class queue.
// Returns 1 when a job is produced, 0 when queue is empty/disconnected.
int32_t mtproxy_ffi_jobs_tokio_dequeue_class(
  int32_t job_class,
  int32_t blocking,
  void **out_job
);

// jobs helper: enqueue one opaque `job_t` into Rust/Tokio subclass queue.
int32_t mtproxy_ffi_jobs_tokio_enqueue_subclass(
  int32_t job_class,
  int32_t subclass_id,
  void *job
);

// jobs helper: dequeue one opaque `job_t` from Rust/Tokio subclass queue.
// Returns 1 when a job is produced, 0 when queue is empty/disconnected.
int32_t mtproxy_ffi_jobs_tokio_dequeue_subclass(
  int32_t job_class,
  int32_t subclass_id,
  int32_t blocking,
  void **out_job
);

// jobs helper: subclass scheduler gate API (lock + pending counters).
int32_t mtproxy_ffi_jobs_tokio_subclass_enter(int32_t job_class, int32_t subclass_id);
int32_t mtproxy_ffi_jobs_tokio_subclass_has_pending(int32_t job_class, int32_t subclass_id);
int32_t mtproxy_ffi_jobs_tokio_subclass_mark_processed(int32_t job_class, int32_t subclass_id);
int32_t mtproxy_ffi_jobs_tokio_subclass_exit_or_continue(int32_t job_class, int32_t subclass_id);
int32_t mtproxy_ffi_jobs_tokio_subclass_permit_acquire(int32_t job_class, int32_t subclass_id);
int32_t mtproxy_ffi_jobs_tokio_subclass_permit_release(int32_t job_class, int32_t subclass_id);

// jobs helper: enqueue one opaque `job_t` into Rust/Tokio main queue.
int32_t mtproxy_ffi_jobs_tokio_enqueue_main(void *job);

// jobs helper: drain Rust/Tokio main queue via C callback.
// `max_items == 0` means "drain all currently available jobs".
int32_t mtproxy_ffi_jobs_tokio_drain_main(
  mtproxy_ffi_jobs_process_fn process_one_job,
  int32_t max_items
);

// jobs helper: Tokio-backed timer-manager queue primitives.
int32_t mtproxy_ffi_jobs_tokio_timer_queue_create(void);
int32_t mtproxy_ffi_jobs_tokio_timer_queue_destroy(int32_t queue_id);
int32_t mtproxy_ffi_jobs_tokio_timer_queue_push(int32_t queue_id, void *ptr);
int32_t mtproxy_ffi_jobs_tokio_timer_queue_pop(int32_t queue_id, void **out_ptr);

// jobs helper: Tokio-backed message-queue primitives.
int32_t mtproxy_ffi_jobs_tokio_message_queue_create(void);
int32_t mtproxy_ffi_jobs_tokio_message_queue_destroy(int32_t queue_id);
int32_t mtproxy_ffi_jobs_tokio_message_queue_push(int32_t queue_id, void *ptr);
int32_t mtproxy_ffi_jobs_tokio_message_queue_pop(int32_t queue_id, void **out_ptr);

// jobs helper: Rust-backed processing of subclass queue token.
void mtproxy_ffi_jobs_process_one_sublist(uintptr_t subclass_token_id, int32_t class_id);

// jobs helper: Rust-backed message queue operations for `struct async_job`.
void mtproxy_ffi_jobs_job_message_send(
  struct async_job *job,
  struct async_job *src,
  uint32_t type,
  struct raw_message *raw_message,
  int32_t dup,
  int32_t payload_ints,
  const uint32_t *payload,
  uint32_t flags,
  void (*destroy)(struct job_message *message)
);
void mtproxy_ffi_jobs_job_message_queue_work(
  struct async_job *job,
  int32_t (*receive_message)(struct async_job *job, struct job_message *message, void *extra),
  void *extra,
  uint32_t mask
);
void mtproxy_ffi_jobs_job_message_queue_free(struct async_job *job);
void mtproxy_ffi_jobs_job_message_free_default(struct job_message *message);
int32_t mtproxy_ffi_jobs_job_free(int32_t job_tag_int, struct async_job *job);
int32_t mtproxy_ffi_jobs_job_timer_wakeup_gateway(struct event_timer *et);

// net-events helpers for incremental event-loop migration.
int32_t mtproxy_ffi_net_epoll_conv_flags(int32_t flags);
int32_t mtproxy_ffi_net_epoll_unconv_flags(int32_t epoll_flags);

// net-timers helper for timeout conversion.
int32_t mtproxy_ffi_net_timers_wait_msec(double wakeup_time, double now);

// net-msg-buffers helper for size-class selection.
int32_t mtproxy_ffi_msg_buffers_pick_size_index(
  const int32_t *buffer_sizes,
  int32_t buffer_size_values,
  int32_t size_hint
);

// net-msg helpers: TL-string marker/padding and encrypt/decrypt byte clamp.
int32_t mtproxy_ffi_net_msg_tl_marker_kind(int32_t marker);
int32_t mtproxy_ffi_net_msg_tl_padding(int32_t total_bytes);
int32_t mtproxy_ffi_net_msg_encrypt_decrypt_effective_bytes(
  int32_t requested_bytes,
  int32_t total_bytes,
  int32_t block_size
);

// net-thread helper: runs one notification event via callback bridge.
int32_t mtproxy_ffi_net_thread_run_notification_event(
  int32_t event_type,
  void *who,
  void *event,
  int32_t (*rpc_ready)(void *who),
  void (*rpc_close)(void *who),
  void (*rpc_alarm)(void *who),
  void (*rpc_wakeup)(void *who),
  void (*fail_connection)(void *who, int32_t code),
  void (*job_decref)(void *who),
  void (*event_free)(void *event)
);

// common/resolver helpers: kdb state reload and gethostbyname planning.
enum { MTPROXY_FFI_RESOLVER_LOOKUP_SYSTEM_DNS = 0 };
enum { MTPROXY_FFI_RESOLVER_LOOKUP_NOT_FOUND = 1 };
enum { MTPROXY_FFI_RESOLVER_LOOKUP_HOSTS_IPV4 = 2 };
int32_t mtproxy_ffi_resolver_kdb_load_hosts(void);
int32_t mtproxy_ffi_resolver_kdb_hosts_loaded(void);
int32_t mtproxy_ffi_resolver_gethostbyname_plan(
  const char *name,
  int32_t *out_kind,
  uint32_t *out_ipv4
);

// net-stats helpers: idle percentage math extracted from net-stats.c.
double mtproxy_ffi_net_stats_recent_idle_percent(double a_idle_time, double a_idle_quotient);
double mtproxy_ffi_net_stats_average_idle_percent(double tot_idle_time, int32_t uptime);

// net-tcp-connections helpers: AES/TLS framing length helpers.
int32_t mtproxy_ffi_net_tcp_aes_aligned_len(int32_t total_bytes);
int32_t mtproxy_ffi_net_tcp_aes_needed_output_bytes(int32_t total_bytes);
int32_t mtproxy_ffi_net_tcp_tls_encrypt_chunk_len(int32_t total_bytes, int32_t is_tls);
int32_t mtproxy_ffi_net_tcp_tls_header_needed_bytes(int32_t available);
int32_t mtproxy_ffi_net_tcp_tls_parse_header(const uint8_t header[5], int32_t *out_payload_len);
int32_t mtproxy_ffi_net_tcp_tls_decrypt_chunk_len(int32_t available, int32_t left_tls_packet_length);
int32_t mtproxy_ffi_net_tcp_reader_negative_skip_take(int32_t skip_bytes, int32_t available_bytes);
int32_t mtproxy_ffi_net_tcp_reader_negative_skip_next(int32_t skip_bytes, int32_t taken_bytes);
int32_t mtproxy_ffi_net_tcp_reader_positive_skip_next(int32_t skip_bytes, int32_t available_bytes);
int32_t mtproxy_ffi_net_tcp_reader_skip_from_parse_result(
  int32_t parse_res,
  int32_t buffered_bytes,
  int32_t need_more_bytes,
  int32_t *out_skip_bytes
);
int32_t mtproxy_ffi_net_tcp_reader_precheck_result(int32_t flags);
int32_t mtproxy_ffi_net_tcp_reader_should_continue(
  int32_t skip_bytes,
  int32_t flags,
  int32_t status_is_conn_error
);

// net-tcp-rpc-ext-server helpers: domain/random bucket hashes and hello-size profile.
int32_t mtproxy_ffi_net_tcp_rpc_ext_domain_bucket_index(const uint8_t *domain, int32_t len);
int32_t mtproxy_ffi_net_tcp_rpc_ext_client_random_bucket_index(const uint8_t random[16]);
int32_t mtproxy_ffi_net_tcp_rpc_ext_select_server_hello_profile(
  int32_t min_len,
  int32_t max_len,
  int32_t sum_len,
  int32_t sample_count,
  int32_t *out_size,
  int32_t *out_profile
);
int32_t mtproxy_ffi_net_tcp_rpc_ext_is_allowed_timestamp(
  int32_t timestamp, int32_t now, int32_t first_client_random_time, int32_t has_first_client_random
);
int32_t mtproxy_ffi_net_tcp_rpc_ext_tls_has_bytes(int32_t pos, int32_t length, int32_t len);
int32_t mtproxy_ffi_net_tcp_rpc_ext_tls_read_length(const uint8_t *response, int32_t response_len, int32_t *pos);
int32_t mtproxy_ffi_net_tcp_rpc_ext_tls_expect_bytes(
  const uint8_t *response, int32_t response_len, int32_t pos, const uint8_t *expected, int32_t expected_len
);
int32_t mtproxy_ffi_net_tcp_rpc_ext_get_domain_server_hello_encrypted_size(
  int32_t base_size, int32_t use_random, int32_t rand_value
);
int32_t mtproxy_ffi_net_tcp_rpc_ext_add_length(
  uint8_t *buffer, int32_t buffer_len, int32_t *pos, int32_t length
);
int32_t mtproxy_ffi_net_tcp_rpc_ext_add_string(
  uint8_t *buffer, int32_t buffer_len, int32_t *pos, const uint8_t *data, int32_t data_len
);
int32_t mtproxy_ffi_net_tcp_rpc_ext_add_grease(
  uint8_t *buffer, int32_t buffer_len, int32_t *pos, const uint8_t *greases, int32_t greases_len, int32_t num
);
int32_t mtproxy_ffi_net_tcp_rpc_ext_add_random_bytes(
  uint8_t *buffer, int32_t buffer_len, int32_t *pos, const uint8_t *rand_bytes, int32_t rand_bytes_len
);
int32_t mtproxy_ffi_net_tcp_rpc_ext_add_public_key(
  uint8_t *buffer, int32_t buffer_len, int32_t *pos, const uint8_t *public_key
);

// net-tcp-rpc-common helper: computes compact/medium packet length prefix.
int32_t mtproxy_ffi_tcp_rpc_encode_compact_header(
  int32_t payload_len,
  int32_t is_medium,
  int32_t *out_prefix_word,
  int32_t *out_prefix_bytes
);

// net-tcp-rpc-common helper: decodes compact packet header.
// Returns 0 on success, -1 on error. remaining_bytes can be NULL for compact format.
int32_t mtproxy_ffi_tcp_rpc_decode_compact_header(
  uint8_t first_byte,
  const uint8_t *remaining_bytes,
  int32_t *out_payload_len,
  int32_t *out_header_bytes
);

// net-tcp-rpc-common helper: sets default RPC flags.
// Returns the new flags value after applying AND and OR operations.
uint32_t mtproxy_ffi_tcp_rpc_set_default_rpc_flags(
  uint32_t and_flags,
  uint32_t or_flags
);

// net-tcp-rpc-common helper: gets default RPC flags.
uint32_t mtproxy_ffi_tcp_rpc_get_default_rpc_flags(void);

// net-tcp-rpc-common helper: sets maximum DH accept rate.
void mtproxy_ffi_tcp_rpc_set_max_dh_accept_rate(int32_t rate);

// net-tcp-rpc-common helper: gets maximum DH accept rate.
int32_t mtproxy_ffi_tcp_rpc_get_max_dh_accept_rate(void);

// net-tcp-rpc-common helper: constructs a ping packet.
// Returns 0 on success, -1 on error. out_packet must point to a 12-byte buffer.
int32_t mtproxy_ffi_tcp_rpc_construct_ping_packet(
  int64_t ping_id,
  uint8_t *out_packet
);

// net-tcp-rpc-common helper: attempts to add a DH accept operation under rate limiting.
// Returns 0 if allowed, -1 if rate limit exceeded.
// Updates out_remaining and out_last_time with new state values.
int32_t mtproxy_ffi_tcp_rpc_add_dh_accept(
  double remaining,
  double last_time,
  int32_t max_rate,
  double precise_now,
  double *out_remaining,
  double *out_last_time
);

// net-tcp-rpc-common helper: parses a raw nonce packet.
// Returns 0 on success, -1 on parse failure, negative values on argument mismatch.
int32_t mtproxy_ffi_tcp_rpc_parse_nonce_packet(
  const uint8_t *packet,
  int32_t packet_len,
  int32_t *out_schema,
  int32_t *out_key_select,
  int32_t *out_crypto_ts,
  uint8_t *out_nonce,
  int32_t out_nonce_len,
  int32_t *out_extra_keys_count,
  int32_t *out_extra_key_signatures,
  int32_t out_extra_key_signatures_len,
  int32_t *out_dh_params_select,
  int32_t *out_has_dh_params
);

int32_t mtproxy_ffi_tcp_rpc_client_process_nonce_packet(
  const uint8_t *packet,
  int32_t packet_len,
  int32_t allow_unencrypted,
  int32_t allow_encrypted,
  int32_t require_dh,
  int32_t has_crypto_temp,
  int32_t nonce_time,
  int32_t main_secret_len,
  int32_t main_key_signature,
  int32_t *out_schema,
  int32_t *out_key_select,
  int32_t *out_has_dh_params
);

// net-tcp-rpc-common helper: parses handshake packet and sender/peer PIDs.
int32_t mtproxy_ffi_tcp_rpc_parse_handshake_packet(
  const uint8_t *packet,
  int32_t packet_len,
  int32_t *out_flags,
  mtproxy_ffi_process_id_t *out_sender_pid,
  mtproxy_ffi_process_id_t *out_peer_pid
);

// net-tcp-rpc-client helper: classifies packet length from non-compact mode parser.
int32_t mtproxy_ffi_tcp_rpc_client_packet_len_state(int32_t packet_len, int32_t max_packet_len);
int32_t mtproxy_ffi_net_tcp_rpc_client_parse_execute(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_client_connected(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_client_close_connection(void *c, int32_t who);
int32_t mtproxy_ffi_net_tcp_rpc_client_check_ready(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_client_default_check_ready(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_client_init_outbound(void *c);
void mtproxy_ffi_net_tcp_rpc_client_force_enable_dh(void);
int32_t mtproxy_ffi_net_tcp_rpc_client_default_check_perm(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_client_init_crypto(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_client_start_crypto(
  void *c,
  char *nonce,
  int32_t key_select,
  uint8_t *temp_key,
  int32_t temp_key_len
);

// net-tcp-rpc-server runtime: parser/callback/crypto path exported to C wrappers.
int32_t mtproxy_ffi_net_tcp_rpc_server_default_execute(void *c, int32_t op, void *raw);
int32_t mtproxy_ffi_net_tcp_rpc_server_parse_execute(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_server_wakeup(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_server_alarm(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_server_do_wakeup(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_server_init_accepted(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_server_close_connection(void *c, int32_t who);
int32_t mtproxy_ffi_net_tcp_rpc_server_init_accepted_nohs(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_server_default_check_perm(void *c);
int32_t mtproxy_ffi_net_tcp_rpc_server_init_crypto(void *c, void *packet);

// net-tcp-rpc-server helpers: classifies malformed header and packet length state.
int32_t mtproxy_ffi_tcp_rpc_server_packet_header_malformed(int32_t packet_len);
int32_t mtproxy_ffi_tcp_rpc_server_packet_len_state(int32_t packet_len, int32_t max_packet_len);
int32_t mtproxy_ffi_tcp_rpc_server_process_nonce_packet(
  const uint8_t *packet,
  int32_t packet_len,
  int32_t allow_unencrypted,
  int32_t allow_encrypted,
  int32_t now_ts,
  int32_t main_secret_len,
  int32_t main_key_signature,
  int32_t *out_schema,
  int32_t *out_key_select,
  int32_t *out_has_dh_params
);
int32_t mtproxy_ffi_tcp_rpc_server_default_execute_should_pong(
  int32_t op,
  int32_t raw_total_bytes
);
int32_t mtproxy_ffi_tcp_rpc_server_default_execute_set_pong(
  int32_t *packet_words,
  int32_t packet_words_len
);
int32_t mtproxy_ffi_tcp_rpc_server_build_handshake_packet(
  int32_t crypto_flags,
  const mtproxy_ffi_process_id_t *sender_pid,
  const mtproxy_ffi_process_id_t *peer_pid,
  uint8_t *out_packet,
  int32_t out_packet_len
);
int32_t mtproxy_ffi_tcp_rpc_server_build_handshake_error_packet(
  int32_t error_code,
  const mtproxy_ffi_process_id_t *sender_pid,
  uint8_t *out_packet,
  int32_t out_packet_len
);
int32_t mtproxy_ffi_tcp_rpc_server_validate_handshake_header(
  int32_t packet_num,
  int32_t packet_type,
  int32_t packet_len,
  int32_t handshake_packet_len
);
int32_t mtproxy_ffi_tcp_rpc_server_validate_nonce_header(
  int32_t packet_num,
  int32_t packet_type,
  int32_t packet_len,
  int32_t nonce_packet_min_len,
  int32_t nonce_packet_max_len
);
int32_t mtproxy_ffi_tcp_rpc_server_validate_handshake(
  int32_t packet_flags,
  int32_t peer_pid_matches,
  int32_t ignore_pid,
  int32_t default_rpc_flags,
  int32_t *out_enable_crc32c
);
int32_t mtproxy_ffi_tcp_rpc_server_should_set_wantwr(int32_t out_total_bytes);
int32_t mtproxy_ffi_tcp_rpc_server_should_notify_close(int32_t has_rpc_close);
int32_t mtproxy_ffi_tcp_rpc_server_do_wakeup(void);
int32_t mtproxy_ffi_tcp_rpc_server_notification_pending_queries(void);
int32_t mtproxy_ffi_tcp_rpc_server_init_accepted_state(
  int32_t has_perm_callback,
  int32_t perm_flags,
  int32_t *out_crypto_flags,
  int32_t *out_in_packet_num,
  int32_t *out_out_packet_num
);
int32_t mtproxy_ffi_tcp_rpc_server_init_accepted_nohs_state(
  int32_t *out_crypto_flags,
  int32_t *out_in_packet_num
);
int32_t mtproxy_ffi_tcp_rpc_server_init_fake_crypto_state(
  int32_t crypto_flags,
  int32_t *out_crypto_flags
);
int32_t mtproxy_ffi_tcp_rpc_server_default_check_perm(int32_t default_rpc_flags);

// net-rpc-targets helper: normalizes zero-ip PID to default local IP.
int32_t mtproxy_ffi_rpc_target_normalize_pid(mtproxy_ffi_process_id_t *pid, uint32_t default_ip);
mtproxy_ffi_rpc_target_tree_t *mtproxy_ffi_rpc_target_tree_acquire(
  mtproxy_ffi_rpc_target_tree_t *tree
);
void mtproxy_ffi_rpc_target_tree_release(mtproxy_ffi_rpc_target_tree_t *tree);
mtproxy_ffi_rpc_target_tree_t *mtproxy_ffi_rpc_target_tree_insert(
  mtproxy_ffi_rpc_target_tree_t *tree,
  const mtproxy_ffi_process_id_t *pid,
  void *target
);
void *mtproxy_ffi_rpc_target_tree_lookup(
  mtproxy_ffi_rpc_target_tree_t *tree,
  const mtproxy_ffi_process_id_t *pid
);
int32_t mtproxy_ffi_rpc_target_insert_conn(
  void *conn,
  mtproxy_ffi_rpc_target_tree_t **tree_slot,
  void *module_stat_tls,
  uint32_t default_ip
);
int32_t mtproxy_ffi_rpc_target_delete_conn(
  void *conn,
  mtproxy_ffi_rpc_target_tree_t **tree_slot,
  void *module_stat_tls,
  uint32_t default_ip
);
void *mtproxy_ffi_rpc_target_lookup_runtime(
  mtproxy_ffi_rpc_target_tree_t *tree,
  const mtproxy_ffi_process_id_t *pid,
  uint32_t default_ip
);
void *mtproxy_ffi_rpc_target_choose_connection_runtime(
  void *target,
  const mtproxy_ffi_process_id_t *pid
);
int32_t mtproxy_ffi_rpc_target_choose_random_connections_runtime(
  void *target,
  const mtproxy_ffi_process_id_t *pid,
  int32_t limit,
  void **buf
);
int32_t mtproxy_ffi_rpc_targets_prepare_stat_runtime(
  void *sb,
  void **module_stat_array,
  int32_t module_stat_len
);
void *mtproxy_ffi_rpc_target_lookup(
  mtproxy_ffi_rpc_target_tree_t *tree,
  const mtproxy_ffi_process_id_t *pid,
  uint32_t default_ip
);
void *mtproxy_ffi_rpc_target_lookup_hp(
  mtproxy_ffi_rpc_target_tree_t *tree,
  uint32_t ip,
  int32_t port,
  uint32_t default_ip
);
void *mtproxy_ffi_rpc_target_lookup_target_runtime(
  void *target,
  mtproxy_ffi_rpc_target_tree_t *tree,
  uint32_t default_ip
);
int32_t mtproxy_ffi_rpc_target_get_state_runtime(
  void *target,
  const mtproxy_ffi_process_id_t *pid
);

// net-crypto-aes helper: derives session keys/ivs from handshake material.
int32_t mtproxy_ffi_crypto_aes_create_keys(
  mtproxy_ffi_aes_key_data_t *out,
  int32_t am_client,
  const uint8_t nonce_server[16],
  const uint8_t nonce_client[16],
  int32_t client_timestamp,
  uint32_t server_ip,
  uint16_t server_port,
  const uint8_t server_ipv6[16],
  uint32_t client_ip,
  uint16_t client_port,
  const uint8_t client_ipv6[16],
  const uint8_t *secret,
  int32_t secret_len,
  const uint8_t *temp_key,
  int32_t temp_key_len
);

// net-crypto-aes module migration helpers.
int32_t mtproxy_ffi_crypto_aes_fetch_stat(
  int32_t *allocated_aes_crypto,
  int32_t *allocated_aes_crypto_temp
);
int32_t mtproxy_ffi_crypto_aes_conn_init(
  void **conn_crypto_slot,
  const mtproxy_ffi_aes_key_data_t *key_data,
  int32_t key_data_len,
  int32_t use_ctr_mode
);
int32_t mtproxy_ffi_crypto_aes_conn_free(
  void **conn_crypto_slot,
  void **conn_crypto_temp_slot
);
int32_t mtproxy_ffi_crypto_aes_load_pwd_file(
  const char *filename,
  uint8_t *pwd_config_buf,
  int32_t pwd_config_capacity,
  int32_t *pwd_config_len_out,
  char *pwd_config_md5_out,
  mtproxy_ffi_aes_secret_t *main_secret
);
int32_t mtproxy_ffi_crypto_aes_generate_nonce(uint8_t out[16]);
void *mtproxy_ffi_crypto_alloc_temp(int32_t len);
int32_t mtproxy_ffi_crypto_free_temp(void *ptr, int32_t len);

// net-crypto-dh helper: validates peer DH blob prefix against known prime prefix.
int32_t mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin(
  const uint8_t *data,
  size_t len,
  const uint8_t *prime_prefix,
  size_t prime_prefix_len
);

// net-crypto-dh helpers for full DH round migration.
int32_t mtproxy_ffi_crypto_dh_get_params_select(void);
int32_t mtproxy_ffi_crypto_dh_first_round(uint8_t g_a[256], uint8_t a_out[256]);
int32_t mtproxy_ffi_crypto_dh_second_round(uint8_t g_ab[256], uint8_t g_a[256], const uint8_t g_b[256]);
int32_t mtproxy_ffi_crypto_dh_third_round(uint8_t g_ab[256], const uint8_t g_b[256], const uint8_t a[256]);
int32_t mtproxy_ffi_crypto_dh_init_params(int32_t *out_dh_params_select);
int32_t mtproxy_ffi_crypto_dh_fetch_tot_rounds(int64_t out_rounds[3]);
int32_t mtproxy_ffi_crypto_dh_first_round_stateful(
  uint8_t g_a[256],
  mtproxy_ffi_crypto_temp_dh_params_t *dh_params,
  int32_t dh_params_select
);
int32_t mtproxy_ffi_crypto_dh_second_round_stateful(
  uint8_t g_ab[256],
  uint8_t g_a[256],
  const uint8_t g_b[256]
);
int32_t mtproxy_ffi_crypto_dh_third_round_stateful(
  uint8_t g_ab[256],
  const uint8_t g_b[256],
  const mtproxy_ffi_crypto_temp_dh_params_t *dh_params
);

// generic crypto helpers for TLS-obfuscated transport paths.
int32_t mtproxy_ffi_crypto_rand_bytes(uint8_t *out, int32_t len);
int32_t mtproxy_ffi_crypto_tls_generate_public_key(uint8_t out[32]);

// crypto/aesni helper: Rust-backed AES block/stream transform.
int32_t mtproxy_ffi_aesni_crypt(void *ctx, const uint8_t *in, uint8_t *out, int32_t size);
int32_t mtproxy_ffi_aesni_ctx_init(
  int32_t cipher_kind,
  const uint8_t key[32],
  const uint8_t iv[16],
  int32_t is_encrypt,
  void **out_ctx
);
int32_t mtproxy_ffi_aesni_ctx_free(void *ctx);

// engine-rpc helpers for TL result header normalization.
int32_t mtproxy_ffi_engine_rpc_common_default_query_type_mask(void);
int32_t mtproxy_ffi_engine_rpc_common_default_parse_decision(
  int64_t actor_id,
  int32_t op
);
int32_t mtproxy_ffi_engine_rpc_query_result_type_id_from_qid(int64_t qid);
int32_t mtproxy_ffi_engine_rpc_query_result_dispatch_decision(
  int32_t has_table,
  int32_t has_handler
);
int32_t mtproxy_ffi_engine_rpc_need_dup(int32_t flags);
int32_t mtproxy_ffi_engine_rpc_query_job_dispatch_decision(
  int32_t op,
  int32_t has_custom_tree
);
int32_t mtproxy_ffi_engine_rpc_custom_op_insert(uint32_t op, void *entry);
void *mtproxy_ffi_engine_rpc_custom_op_lookup(uint32_t op);
int32_t mtproxy_ffi_engine_rpc_custom_op_has_any(void);
int32_t mtproxy_ffi_engine_rpc_tcp_should_hold_conn(int32_t op);
int32_t mtproxy_ffi_engine_net_default_port_mod(void);
int32_t mtproxy_ffi_engine_net_try_open_port_range(
  int32_t start_port,
  int32_t end_port,
  int32_t mod_port,
  int32_t rem_port,
  int32_t quit_on_fail,
  mtproxy_ffi_engine_net_try_open_port_fn try_open,
  void *try_open_ctx,
  int32_t *out_selected_port
);
int32_t mtproxy_ffi_engine_net_open_privileged_port(
  int32_t port,
  int32_t start_port,
  int32_t end_port,
  int32_t port_mod,
  int32_t tcp_enabled,
  int32_t quit_on_fail,
  mtproxy_ffi_engine_net_try_open_port_fn try_open,
  void *try_open_ctx,
  int32_t *out_selected_port
);
void mtproxy_ffi_engine_signal_set_pending(int32_t sig);
int32_t mtproxy_ffi_engine_signal_check_pending(int32_t sig);
int32_t mtproxy_ffi_engine_signal_check_pending_and_clear(int32_t sig);
int32_t mtproxy_ffi_engine_interrupt_signal_raised(void);
int32_t mtproxy_ffi_engine_process_signals_allowed(
  uint64_t allowed_signals,
  mtproxy_ffi_engine_signal_dispatch_fn dispatch,
  void *dispatch_ctx
);
int32_t mtproxy_ffi_engine_rpc_result_new_flags(int32_t old_flags);
int32_t mtproxy_ffi_engine_rpc_result_header_len(int32_t flags);

// mtproto-proxy helpers for external-connection hashing/tagging.
int32_t mtproxy_ffi_mtproto_ext_conn_hash(int32_t in_fd, int64_t in_conn_id, int32_t hash_shift);
int32_t mtproxy_ffi_mtproto_conn_tag(int32_t generation);
int32_t mtproxy_ffi_mtproto_parse_text_ipv4(const char *str, uint32_t *out_ip);
int32_t mtproxy_ffi_mtproto_parse_text_ipv6(
  const char *str,
  uint8_t out_ip[16],
  int32_t *out_consumed
);
int32_t mtproxy_ffi_mtproto_inspect_packet_header(
  const uint8_t *header,
  size_t header_len,
  int32_t packet_len,
  mtproxy_ffi_mtproto_packet_inspect_result_t *out
);
int32_t mtproxy_ffi_mtproto_parse_function(
  const uint8_t *data,
  size_t len,
  int64_t actor_id,
  mtproxy_ffi_mtproto_parse_function_result_t *out
);
int32_t mtproxy_ffi_mtproto_parse_client_packet(
  const uint8_t *data,
  size_t len,
  mtproxy_ffi_mtproto_client_packet_parse_result_t *out
);
int32_t mtproxy_ffi_mtproto_process_client_packet(
  const uint8_t *data,
  size_t len,
  int32_t conn_fd,
  int32_t conn_gen,
  mtproxy_ffi_mtproto_client_packet_process_result_t *out
);
int32_t mtproxy_ffi_mtproto_process_client_packet_runtime(
  void *tlio_in,
  void *c
);
void mtproxy_ffi_mtproto_push_rpc_confirmation_runtime(
  int32_t c_tag_int,
  void *c,
  int32_t confirm
);
void *mtproxy_ffi_mtproto_mtfront_parse_function_runtime(
  void *tlio_in,
  int64_t actor_id
);
int32_t mtproxy_ffi_mtproto_process_http_query(
  void *tlio_in,
  void *hqj
);
int32_t mtproxy_ffi_mtproto_http_query_job_run(
  void *job,
  int32_t op,
  void *jt
);
int32_t mtproxy_ffi_mtproto_callback_job_run(
  void *job,
  int32_t op,
  void *jt
);
int32_t mtproxy_ffi_mtproto_client_packet_job_run(
  void *job,
  int32_t op,
  void *jt
);
int32_t mtproxy_ffi_mtproto_client_send_message_runtime(
  int32_t c_tag_int,
  void *c,
  int64_t in_conn_id,
  void *tlio_in,
  int32_t flags
);
void mtproxy_ffi_mtproto_add_stats(void *w);
void mtproxy_ffi_mtproto_compute_stats_sum(void);
void mtproxy_ffi_mtproto_check_all_conn_buffers(void);
int32_t mtproxy_ffi_mtproto_check_conn_buffers_runtime(void *c);
void mtproxy_ffi_mtproto_update_local_stats_copy(void *s);
void mtproxy_ffi_mtproto_mtfront_prepare_stats(void *sb);
int32_t mtproxy_ffi_mtproto_hts_stats_execute(
  void *c,
  void *msg,
  int32_t op
);
int32_t mtproxy_ffi_mtproto_hts_execute(
  void *c,
  void *msg,
  int32_t op
);
int32_t mtproxy_ffi_mtproto_rpcc_execute(
  void *c,
  int32_t op,
  void *msg
);
int32_t mtproxy_ffi_mtproto_mtfront_client_ready(void *c);
int32_t mtproxy_ffi_mtproto_ext_rpcs_execute(
  void *c,
  int32_t op,
  void *msg
);
int32_t mtproxy_ffi_mtproto_mtfront_client_close(void *c, int32_t who);
int32_t mtproxy_ffi_mtproto_do_close_in_ext_conn(void *data, int32_t s_len);
int32_t mtproxy_ffi_mtproto_ext_rpc_ready(void *c);
int32_t mtproxy_ffi_mtproto_ext_rpc_close(void *c, int32_t who);
int32_t mtproxy_ffi_mtproto_proxy_rpc_ready(void *c);
int32_t mtproxy_ffi_mtproto_proxy_rpc_close(void *c, int32_t who);
int32_t mtproxy_ffi_mtproto_do_rpcs_execute(void *data, int32_t s_len);
int32_t mtproxy_ffi_mtproto_finish_postponed_http_response(void *data, int32_t len);
int32_t mtproxy_ffi_mtproto_http_alarm(void *c);
int32_t mtproxy_ffi_mtproto_http_close(void *c, int32_t who);
int32_t mtproxy_ffi_mtproto_f_parse_option(int32_t val);
void mtproxy_ffi_mtproto_mtfront_prepare_parse_options(void);
void mtproxy_ffi_mtproto_check_children_dead(void);
void mtproxy_ffi_mtproto_check_children_status(void);
void mtproxy_ffi_mtproto_check_special_connections_overflow(void);
void mtproxy_ffi_mtproto_kill_children(int32_t signal);
void mtproxy_ffi_mtproto_cron(void);
void mtproxy_ffi_mtproto_usage(void);
void mtproxy_ffi_mtproto_mtfront_parse_extra_args(int32_t argc, char **argv);
void mtproxy_ffi_mtproto_mtfront_sigusr1_handler(void);
void mtproxy_ffi_mtproto_mtfront_on_exit(void);
void mtproxy_ffi_mtproto_mtfront_pre_init(void);
void mtproxy_ffi_mtproto_mtfront_pre_start(void);
void mtproxy_ffi_mtproto_mtfront_pre_loop(void);
void mtproxy_ffi_mtproto_ext_conn_reset(void);
int32_t mtproxy_ffi_mtproto_ext_conn_create(
  int32_t in_fd,
  int32_t in_gen,
  int64_t in_conn_id,
  int32_t out_fd,
  int32_t out_gen,
  int64_t auth_key_id,
  mtproxy_ffi_mtproto_ext_connection_t *out
);
int32_t mtproxy_ffi_mtproto_ext_conn_get_by_in_fd(
  int32_t in_fd,
  mtproxy_ffi_mtproto_ext_connection_t *out
);
int32_t mtproxy_ffi_mtproto_ext_conn_get_by_out_conn_id(
  int64_t out_conn_id,
  mtproxy_ffi_mtproto_ext_connection_t *out
);
int32_t mtproxy_ffi_mtproto_ext_conn_update_auth_key(
  int32_t in_fd,
  int64_t in_conn_id,
  int64_t auth_key_id
);
int32_t mtproxy_ffi_mtproto_ext_conn_remove_by_out_conn_id(
  int64_t out_conn_id,
  mtproxy_ffi_mtproto_ext_connection_t *out
);
int32_t mtproxy_ffi_mtproto_ext_conn_remove_by_in_conn_id(
  int32_t in_fd,
  int64_t in_conn_id,
  mtproxy_ffi_mtproto_ext_connection_t *out
);
int32_t mtproxy_ffi_mtproto_ext_conn_remove_any_by_out_fd(
  int32_t out_fd,
  mtproxy_ffi_mtproto_ext_connection_t *out
);
int32_t mtproxy_ffi_mtproto_ext_conn_remove_any_by_in_fd(
  int32_t in_fd,
  mtproxy_ffi_mtproto_ext_connection_t *out
);
int32_t mtproxy_ffi_mtproto_ext_conn_lru_insert(int32_t in_fd, int32_t in_gen);
int32_t mtproxy_ffi_mtproto_ext_conn_lru_delete(int32_t in_fd);
int32_t mtproxy_ffi_mtproto_ext_conn_lru_pop_oldest(
  mtproxy_ffi_mtproto_ext_connection_t *out
);
int32_t mtproxy_ffi_mtproto_ext_conn_counts(
  int64_t *out_current,
  int64_t *out_created
);
void mtproxy_ffi_mtproto_notify_ext_connection_runtime(
  const mtproxy_ffi_mtproto_ext_connection_t *ex,
  int32_t send_notifications
);
void mtproxy_ffi_mtproto_remove_ext_connection_runtime(
  const mtproxy_ffi_mtproto_ext_connection_t *ex,
  int32_t send_notifications
);
int32_t mtproxy_ffi_mtproto_build_rpc_proxy_req(
  int32_t flags,
  int64_t out_conn_id,
  const uint8_t remote_ipv6[16],
  int32_t remote_port,
  const uint8_t our_ipv6[16],
  int32_t our_port,
  const uint8_t *proxy_tag,
  size_t proxy_tag_len,
  const uint8_t *http_origin,
  size_t http_origin_len,
  const uint8_t *http_referer,
  size_t http_referer_len,
  const uint8_t *http_user_agent,
  size_t http_user_agent_len,
  const uint8_t *payload,
  size_t payload_len,
  uint8_t *out_buf,
  size_t out_cap,
  size_t *out_len
);
int32_t mtproxy_ffi_mtproto_build_http_ok_header(
  int32_t keep_alive,
  int32_t extra_headers,
  int32_t content_len,
  uint8_t *out_buf,
  size_t out_cap,
  size_t *out_len
);
int32_t mtproxy_ffi_mtproto_client_send_non_http_wrap(
  void *tlio_in,
  void *tlio_out
);
int32_t mtproxy_ffi_mtproto_http_send_message(
  void *c,
  void *tlio_in,
  int32_t flags
);

// mtproto-proxy entrypoint helpers for legacy C wrapper.
int32_t mtproxy_ffi_mtproto_proxy_usage(const char *program_name);
int32_t mtproxy_ffi_mtproto_proxy_main(
  int32_t argc,
  const char *const *argv
);

// mtproto-config helpers for Step 15 parser/apply runtime migration.
int32_t mtproxy_ffi_mtproto_cfg_preinit(
  int64_t default_min_connections,
  int64_t default_max_connections,
  mtproxy_ffi_mtproto_cfg_preinit_result_t *out
);
int32_t mtproxy_ffi_mtproto_cfg_decide_cluster_apply(
  const int32_t *cluster_ids,
  uint32_t clusters_len,
  int32_t cluster_id,
  uint32_t max_clusters,
  mtproxy_ffi_mtproto_cfg_cluster_apply_decision_result_t *out
);
int32_t mtproxy_ffi_mtproto_cfg_getlex_ext(
  const char *cur,
  size_t len,
  mtproxy_ffi_mtproto_cfg_getlex_ext_result_t *out
);
int32_t mtproxy_ffi_mtproto_cfg_scan_directive_token(
  const char *cur,
  size_t len,
  int64_t min_connections,
  int64_t max_connections,
  mtproxy_ffi_mtproto_cfg_directive_token_result_t *out
);
int32_t mtproxy_ffi_mtproto_cfg_parse_directive_step(
  const char *cur,
  size_t len,
  int64_t min_connections,
  int64_t max_connections,
  const int32_t *cluster_ids,
  uint32_t clusters_len,
  uint32_t max_clusters,
  mtproxy_ffi_mtproto_cfg_directive_step_result_t *out
);
int32_t mtproxy_ffi_mtproto_cfg_parse_proxy_target_step(
  const char *cur,
  size_t len,
  uint32_t current_targets,
  uint32_t max_targets,
  int64_t min_connections,
  int64_t max_connections,
  const int32_t *cluster_ids,
  uint32_t clusters_len,
  int32_t target_dc,
  uint32_t max_clusters,
  int32_t create_targets,
  uint32_t current_auth_tot_clusters,
  const mtproxy_ffi_mtproto_old_cluster_state_t *last_cluster_state,
  int32_t has_last_cluster_state,
  mtproxy_ffi_mtproto_cfg_parse_proxy_target_step_result_t *out
);
int32_t mtproxy_ffi_mtproto_cfg_parse_full_pass(
  const char *cur,
  size_t len,
  int64_t default_min_connections,
  int64_t default_max_connections,
  int32_t create_targets,
  uint32_t max_clusters,
  uint32_t max_targets,
  mtproxy_ffi_mtproto_cfg_proxy_action_t *actions,
  uint32_t actions_capacity,
  mtproxy_ffi_mtproto_cfg_parse_full_result_t *out
);
int32_t mtproxy_ffi_mtproto_cfg_expect_semicolon(
  const char *cur,
  size_t len,
  size_t *out_advance
);
int32_t mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
  const int32_t *cluster_ids,
  uint32_t clusters_len,
  int32_t cluster_id,
  int32_t force,
  int32_t default_cluster_index,
  int32_t has_default_cluster_index,
  int32_t *out_cluster_index
);
int32_t mtproxy_ffi_mtproto_cfg_finalize(
  int32_t have_proxy,
  const int32_t *cluster_ids,
  uint32_t clusters_len,
  int32_t default_cluster_id,
  mtproxy_ffi_mtproto_cfg_finalize_result_t *out
);
int32_t mtproxy_ffi_mtproto_cfg_parse_config(
  void *mc,
  int32_t flags,
  int32_t config_fd
);
int32_t mtproxy_ffi_mtproto_cfg_do_reload_config(int32_t flags);

// CRC32 (IEEE, reflected polynomial 0xEDB88320) partial update.
// Semantics match C `crc32_partial` function.
uint32_t mtproxy_ffi_crc32_partial(const uint8_t *data, size_t len, uint32_t crc);

// CRC32C (Castagnoli, reflected polynomial 0x82F63B78) partial update.
// Semantics match C `crc32c_partial` function.
uint32_t mtproxy_ffi_crc32c_partial(const uint8_t *data, size_t len, uint32_t crc);

// CRC32 combine for concatenated blocks.
uint32_t mtproxy_ffi_crc32_combine(uint32_t crc1, uint32_t crc2, int64_t len2);

// CRC32C combine for concatenated blocks.
uint32_t mtproxy_ffi_crc32c_combine(uint32_t crc1, uint32_t crc2, int64_t len2);

// CRC64 (reflected polynomial 0xC96C5795D7870F42) partial update.
uint64_t mtproxy_ffi_crc64_partial(const uint8_t *data, size_t len, uint64_t crc);

// CRC64 combine for concatenated blocks.
uint64_t mtproxy_ffi_crc64_combine(uint64_t crc1, uint64_t crc2, int64_t len2);

// Feeds one byte into reflected CRC64 state.
uint64_t mtproxy_ffi_crc64_feed_byte(uint64_t crc, uint8_t b);

// GF32 helpers for CRC combine support.
void mtproxy_ffi_gf32_compute_powers_generic(uint32_t *powers, size_t size, uint32_t poly);
void mtproxy_ffi_gf32_compute_powers_clmul(uint32_t *powers, uint32_t poly);
uint32_t mtproxy_ffi_gf32_combine_generic(const uint32_t *powers, uint32_t crc1, int64_t len2);
uint64_t mtproxy_ffi_gf32_combine_clmul(const uint32_t *powers, uint32_t crc1, int64_t len2);

// CRC32 repair helpers.
int32_t mtproxy_ffi_crc32_find_corrupted_bit(int32_t size, uint32_t d);
int32_t mtproxy_ffi_crc32_repair_bit(uint8_t *input, size_t len, int32_t k);
int32_t mtproxy_ffi_crc32_check_and_repair(uint8_t *input, size_t len, uint32_t *input_crc32);

// PID helpers compatible with common/pid.c semantics.
int32_t mtproxy_ffi_pid_init_common(mtproxy_ffi_process_id_t *pid);
int32_t mtproxy_ffi_pid_init_client(mtproxy_ffi_process_id_t *pid, uint32_t ip);
int32_t mtproxy_ffi_pid_init_server(mtproxy_ffi_process_id_t *pid, uint32_t ip, int32_t port);
int32_t mtproxy_ffi_matches_pid(const mtproxy_ffi_process_id_t *x, const mtproxy_ffi_process_id_t *y);
int32_t mtproxy_ffi_process_id_is_newer(const mtproxy_ffi_process_id_t *a, const mtproxy_ffi_process_id_t *b);

// CPUID helper compatible with common/cpuid.c.
// Returns 0 on success, negative on failure.
int32_t mtproxy_ffi_cpuid_fill(mtproxy_ffi_cpuid_t *out);

// Hash helpers for mixed-mode delegation.
// All return 0 on success, negative on invalid input.
int32_t mtproxy_ffi_md5(const uint8_t *input, size_t len, uint8_t output[16]);
int32_t mtproxy_ffi_md5_hex(const uint8_t *input, size_t len, char output[32]);
int32_t mtproxy_ffi_md5_hmac(
  const uint8_t *key,
  size_t key_len,
  const uint8_t *input,
  size_t len,
  uint8_t output[16]
);
int32_t mtproxy_ffi_sha1(const uint8_t *input, size_t len, uint8_t output[20]);
int32_t mtproxy_ffi_sha1_two_chunks(
  const uint8_t *input1,
  size_t len1,
  const uint8_t *input2,
  size_t len2,
  uint8_t output[20]
);
int32_t mtproxy_ffi_sha256(const uint8_t *input, size_t len, uint8_t output[32]);
int32_t mtproxy_ffi_sha256_two_chunks(
  const uint8_t *input1,
  size_t len1,
  const uint8_t *input2,
  size_t len2,
  uint8_t output[32]
);
int32_t mtproxy_ffi_sha256_hmac(
  const uint8_t *key,
  size_t key_len,
  const uint8_t *input,
  size_t len,
  uint8_t output[32]
);

// precise-time helpers for mixed-mode delegation.
double mtproxy_ffi_get_utime_monotonic(void);
double mtproxy_ffi_get_double_time(void);
double mtproxy_ffi_get_utime(int32_t clock_id);
int64_t mtproxy_ffi_get_precise_time(uint32_t precision);
double mtproxy_ffi_precise_now_value(void);
int64_t mtproxy_ffi_precise_now_rdtsc_value(void);
int64_t mtproxy_ffi_precise_time_value(void);
int64_t mtproxy_ffi_precise_time_rdtsc_value(void);

// parse-config helpers for incremental parser migration.
int32_t mtproxy_ffi_cfg_skipspc(
  const char *cur,
  size_t len,
  int32_t line_no,
  mtproxy_ffi_cfg_scan_result_t *out
);
int32_t mtproxy_ffi_cfg_skipspc_global(void);
int32_t mtproxy_ffi_cfg_skspc(
  const char *cur,
  size_t len,
  int32_t line_no,
  mtproxy_ffi_cfg_scan_result_t *out
);
int32_t mtproxy_ffi_cfg_skspc_global(void);
int32_t mtproxy_ffi_cfg_getword_len(const char *cur, size_t len);
int32_t mtproxy_ffi_cfg_getword_global(void);
int32_t mtproxy_ffi_cfg_getstr_len(const char *cur, size_t len);
int32_t mtproxy_ffi_cfg_getstr_global(void);
int32_t mtproxy_ffi_cfg_getlex_global(void);
int32_t mtproxy_ffi_cfg_getint(
  const char *cur,
  size_t len,
  mtproxy_ffi_cfg_int_result_t *out
);
int64_t mtproxy_ffi_cfg_getint_global(void);
int32_t mtproxy_ffi_cfg_getint_zero(
  const char *cur,
  size_t len,
  mtproxy_ffi_cfg_int_result_t *out
);
int64_t mtproxy_ffi_cfg_getint_zero_global(void);
int32_t mtproxy_ffi_cfg_getint_signed_zero(
  const char *cur,
  size_t len,
  mtproxy_ffi_cfg_int_result_t *out
);
int64_t mtproxy_ffi_cfg_getint_signed_zero_global(void);
int32_t mtproxy_ffi_cfg_expect_lexem(int32_t lexem);
int32_t mtproxy_ffi_cfg_expect_word(const char *name, int32_t len);
int32_t mtproxy_ffi_cfg_reset_config(
  char *config_buff,
  int32_t config_bytes,
  char **cfg_start,
  char **cfg_end,
  char **cfg_cur,
  int32_t *cfg_lno
);
int32_t mtproxy_ffi_cfg_load_config(
  const char *file,
  int32_t fd,
  int32_t max_config_size,
  char **config_buff,
  char **config_name,
  int32_t *config_bytes,
  char **cfg_start,
  char **cfg_end,
  char **cfg_cur,
  int32_t *cfg_lno
);
int32_t mtproxy_ffi_cfg_md5_hex_config(const char *config_buff, int32_t config_bytes, char *out);
int32_t mtproxy_ffi_cfg_close_config(
  char **config_buff,
  char **config_name,
  int32_t *config_bytes,
  char **cfg_start,
  char **cfg_end,
  char **cfg_cur,
  int32_t *fd
);
void *mtproxy_ffi_cfg_gethost_ex(int32_t verb);
void *mtproxy_ffi_cfg_gethost(void);

// TL header parsing helpers for incremental migration.
int32_t mtproxy_ffi_tl_parse_query_header(
  const uint8_t *data,
  size_t len,
  mtproxy_ffi_tl_header_parse_result_t *out
);
int32_t mtproxy_ffi_tl_parse_answer_header(
  const uint8_t *data,
  size_t len,
  mtproxy_ffi_tl_header_parse_result_t *out
);

// TL runtime helpers for incremental `common/tl-parse.h` migration.
int32_t mtproxy_ffi_tl_fetch_check(void *tlio_in, int32_t nbytes);
int32_t mtproxy_ffi_tl_fetch_lookup_int(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_lookup_second_int(void *tlio_in);
int64_t mtproxy_ffi_tl_fetch_lookup_long(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_lookup_data(void *tlio_in, void *data, int32_t len);
int32_t mtproxy_ffi_tl_fetch_int(void *tlio_in);
double mtproxy_ffi_tl_fetch_double(void *tlio_in);
int64_t mtproxy_ffi_tl_fetch_long(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_raw_data(void *tlio_in, void *buf, int32_t len);
void mtproxy_ffi_tl_fetch_mark(void *tlio_in);
void mtproxy_ffi_tl_fetch_mark_restore(void *tlio_in);
void mtproxy_ffi_tl_fetch_mark_delete(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_string_len(void *tlio_in, int32_t max_len);
int32_t mtproxy_ffi_tl_fetch_pad(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_string_data(void *tlio_in, char *buf, int32_t len);
int32_t mtproxy_ffi_tl_fetch_skip_string_data(void *tlio_in, int32_t len);
int32_t mtproxy_ffi_tl_fetch_string(void *tlio_in, char *buf, int32_t max_len);
int32_t mtproxy_ffi_tl_fetch_skip_string(void *tlio_in, int32_t max_len);
int32_t mtproxy_ffi_tl_fetch_string0(void *tlio_in, char *buf, int32_t max_len);
int32_t mtproxy_ffi_tl_fetch_check_str_end(void *tlio_in, int32_t size);
int32_t mtproxy_ffi_tl_fetch_unread(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_skip(void *tlio_in, int32_t len);
int32_t mtproxy_ffi_tl_fetch_end(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_error(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_int_range(void *tlio_in, int32_t min, int32_t max);
int32_t mtproxy_ffi_tl_fetch_positive_int(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_nonnegative_int(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_int_subset(void *tlio_in, int32_t set);
int64_t mtproxy_ffi_tl_fetch_long_range(void *tlio_in, int64_t min, int64_t max);
int64_t mtproxy_ffi_tl_fetch_positive_long(void *tlio_in);
int64_t mtproxy_ffi_tl_fetch_nonnegative_long(void *tlio_in);
int32_t mtproxy_ffi_tl_fetch_raw_message(void *tlio_in, void *raw, int32_t bytes);
int32_t mtproxy_ffi_tl_fetch_lookup_raw_message(void *tlio_in, void *raw, int32_t bytes);
void *mtproxy_ffi_tl_store_get_ptr(void *tlio_out, int32_t size);
void *mtproxy_ffi_tl_store_get_prepend_ptr(void *tlio_out, int32_t size);
int32_t mtproxy_ffi_tl_store_int(void *tlio_out, int32_t value);
int32_t mtproxy_ffi_tl_store_long(void *tlio_out, int64_t value);
int32_t mtproxy_ffi_tl_store_double(void *tlio_out, double value);
int32_t mtproxy_ffi_tl_store_raw_data(void *tlio_out, const void *data, int32_t len);
int32_t mtproxy_ffi_tl_store_raw_msg(void *tlio_out, void *raw, int32_t dup);
int32_t mtproxy_ffi_tl_store_string_len(void *tlio_out, int32_t len);
int32_t mtproxy_ffi_tl_store_pad(void *tlio_out);
int32_t mtproxy_ffi_tl_store_string_data(void *tlio_out, const char *s, int32_t len);
int32_t mtproxy_ffi_tl_store_string(void *tlio_out, const char *s, int32_t len);
int32_t mtproxy_ffi_tl_store_clear(void *tlio_out);
int32_t mtproxy_ffi_tl_store_clean(void *tlio_out);
int32_t mtproxy_ffi_tl_store_pos(void *tlio_out);
int32_t mtproxy_ffi_tl_copy_through(void *tlio_in, void *tlio_out, int32_t len, int32_t advance);

// proc-stat/common-stats helpers for observability migration.
int32_t mtproxy_ffi_parse_proc_stat_line(
  const char *line,
  size_t len,
  mtproxy_ffi_proc_stats_t *out
);
int32_t mtproxy_ffi_read_proc_stat_file(
  int32_t pid,
  int32_t tid,
  mtproxy_ffi_proc_stats_t *out
);
// ============================================================================
// proc-stat/common-stats helpers for observability migration.
// ============================================================================

// Stats buffer structure for collecting statistics output
typedef struct mtproxy_ffi_stats_buffer {
  char *buff;
  int32_t pos;
  int32_t size;
  int32_t flags;
} mtproxy_ffi_stats_buffer_t;

// Memory statistics structure
typedef struct mtproxy_ffi_am_memory_stat {
  int64_t vm_size;
  int64_t vm_rss;
  int64_t vm_data;
  int64_t mem_free;
  int64_t swap_total;
  int64_t swap_free;
  int64_t swap_used;
  int64_t mem_cached;
} mtproxy_ffi_am_memory_stat_t;

// Stat function callback type
typedef void (*mtproxy_ffi_stat_fun_t)(mtproxy_ffi_stats_buffer_t *sb);

// TL parser stats formatter migrated from common/tl-parse.c
int32_t mtproxy_ffi_tl_parse_prepare_stat(mtproxy_ffi_stats_buffer_t *sb);

// Get memory usage for a process
int32_t mtproxy_ffi_am_get_memory_usage(
  int32_t pid,
  int64_t *a,
  int32_t m
);

// Get memory statistics
int32_t mtproxy_ffi_am_get_memory_stats(
  mtproxy_ffi_am_memory_stat_t *s,
  int32_t flags
);

// Register a stats collector callback function
int32_t mtproxy_ffi_sb_register_stat_fun(mtproxy_ffi_stat_fun_t func);

// Initialize stats buffer with existing buffer
void mtproxy_ffi_sb_init(
  mtproxy_ffi_stats_buffer_t *sb,
  char *buff,
  int32_t size
);

// Allocate stats buffer
void mtproxy_ffi_sb_alloc(
  mtproxy_ffi_stats_buffer_t *sb,
  int32_t size
);

// Release stats buffer
void mtproxy_ffi_sb_release(mtproxy_ffi_stats_buffer_t *sb);

// Prepare stats buffer by calling registered callbacks
void mtproxy_ffi_sb_prepare(mtproxy_ffi_stats_buffer_t *sb);

// Printf to stats buffer (va_list version for wrapping)
void mtproxy_ffi_sb_vprintf(
  mtproxy_ffi_stats_buffer_t *sb,
  const char *format,
  __builtin_va_list args
);

// Add memory stats to buffer
void mtproxy_ffi_sb_memory(
  mtproxy_ffi_stats_buffer_t *sb,
  int32_t flags
);

// Print query stats with QPS calculation
void mtproxy_ffi_sb_print_queries(
  mtproxy_ffi_stats_buffer_t *sb,
  const char *desc,
  int64_t q,
  int32_t now_val,
  int32_t start_time_val
);

// Sum integers from array of pointers
int32_t mtproxy_ffi_sb_sum_i(
  void **base,
  int32_t len,
  int32_t offset
);

// Sum long longs from array of pointers
int64_t mtproxy_ffi_sb_sum_ll(
  void **base,
  int32_t len,
  int32_t offset
);

// Sum doubles from array of pointers
double mtproxy_ffi_sb_sum_f(
  void **base,
  int32_t len,
  int32_t offset
);

// Print date to stats buffer
void mtproxy_ffi_sbp_print_date(
  mtproxy_ffi_stats_buffer_t *sb,
  const char *key,
  long unix_time
);

int32_t mtproxy_ffi_parse_statm(
  const char *buf,
  size_t len,
  int32_t m,
  int64_t page_size,
  int64_t *out_values
);
int32_t mtproxy_ffi_parse_meminfo_summary(
  const char *buf,
  size_t len,
  mtproxy_ffi_meminfo_summary_t *out
);

// kprintf helper: formats `[pid][YYYY-MM-DD HH:MM:SS.UUUUUU local] ` prefix.
int32_t mtproxy_ffi_format_log_prefix(
  int32_t pid,
  int32_t year,
  int32_t mon,
  int32_t mday,
  int32_t hour,
  int32_t min,
  int32_t sec,
  int32_t usec,
  char *out,
  size_t out_len
);

// ============================================================================
// server-functions helpers for privilege management and resource limits
// ============================================================================

// Parse memory limit with K/M/G/T suffixes.
// Returns the parsed value in bytes, or -1 on error.
long long rust_parse_memory_limit(const char *s);

// Change user and group privileges.
// username: Username to switch to (NULL = default "mtproxy")
// groupname: Group name to switch to (NULL = user's primary group)
// Returns 0 on success, -1 on failure.
int32_t rust_change_user_group(const char *username, const char *groupname);

// Change user privileges.
// username: Username to switch to (NULL = default "mtproxy")
// Returns 0 on success, -1 on failure.
int32_t rust_change_user(const char *username);

// Raise file descriptor limit.
// maxfiles: Desired maximum number of open files
// Returns 0 on success, -1 on failure.
int32_t rust_raise_file_rlimit(int32_t maxfiles);

// Print stack backtrace to stderr.
void rust_print_backtrace(void);

// server-functions parser/runtime helpers implemented in Rust
void rust_sf_init_parse_options(
  uint32_t keep_mask,
  const uint32_t *keep_options_custom_list,
  size_t keep_options_custom_list_len
);
int32_t rust_sf_parse_option_add(
  const char *name,
  int32_t arg,
  int32_t val,
  uint32_t flags,
  int32_t (*func)(int32_t),
  const char *help
);
void rust_sf_register_parse_option_ex_or_die(
  const char *name,
  int32_t arg,
  int32_t val,
  uint32_t flags,
  int32_t (*func)(int32_t),
  const char *help
);
void rust_sf_register_parse_option_or_die(
  const char *name,
  int32_t arg,
  int32_t val,
  const char *help
);
int32_t rust_sf_parse_option_alias(const char *name, int32_t val);
int32_t rust_sf_parse_option_long_alias(const char *name, const char *alias_name);
int32_t rust_sf_remove_parse_option(int32_t val);
int32_t rust_sf_parse_usage(void);
int32_t rust_sf_parse_engine_options_long(int32_t argc, char **argv);
int32_t rust_sf_add_builtin_parse_options(void);
void rust_sf_ksignal(int32_t sig, void (*handler)(int32_t));
void rust_sf_set_debug_handlers(void);

#ifdef __cplusplus
}
#endif
