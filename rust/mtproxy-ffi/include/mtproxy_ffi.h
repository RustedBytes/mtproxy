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

#define MTPROXY_FFI_MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK                  0
#define MTPROXY_FFI_MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND           1
#define MTPROXY_FFI_MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_ERR_INVALID_ARGS   (-1)

#define MTPROXY_FFI_MTPROTO_CFG_FINALIZE_OK                               0
#define MTPROXY_FFI_MTPROTO_CFG_FINALIZE_ERR_INVALID_ARGS                (-1)
#define MTPROXY_FFI_MTPROTO_CFG_FINALIZE_ERR_MISSING_PROXY_DIRECTIVES    (-2)
#define MTPROXY_FFI_MTPROTO_CFG_FINALIZE_ERR_NO_PROXY_SERVERS_DEFINED    (-3)
#define MTPROXY_FFI_MTPROTO_CFG_FINALIZE_ERR_INTERNAL                    (-4)

#define MTPROXY_FFI_MTPROTO_CFG_PREINIT_OK                     0
#define MTPROXY_FFI_MTPROTO_CFG_PREINIT_ERR_INVALID_ARGS      (-1)
#define MTPROXY_FFI_MTPROTO_CFG_PREINIT_ERR_INTERNAL          (-2)

#define MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_OK                           0
#define MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INVALID_ARGS            (-1)
#define MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_TOO_MANY_AUTH_CLUSTERS (-2)
#define MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_PROXIES_INTERMIXED     (-3)
#define MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_ERR_INTERNAL                (-4)

#define MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW  1
#define MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST 2

#define MTPROXY_FFI_MTPROTO_CFG_GETLEX_EXT_OK                     0
#define MTPROXY_FFI_MTPROTO_CFG_GETLEX_EXT_ERR_INVALID_ARGS      (-1)

#define MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK                            0
#define MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_ARGS             (-1)
#define MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TIMEOUT          (-2)
#define MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MAX_CONNECTIONS  (-3)
#define MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MIN_CONNECTIONS  (-4)
#define MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TARGET_ID        (-5)
#define MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_TARGET_ID_SPACE          (-6)
#define MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_PROXY_EXPECTED           (-7)
#define MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INTERNAL                 (-8)

#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK                            0
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_ARGS             (-1)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TIMEOUT          (-2)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MAX_CONNECTIONS  (-3)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MIN_CONNECTIONS  (-4)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TARGET_ID        (-5)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TARGET_ID_SPACE          (-6)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXY_EXPECTED           (-7)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TOO_MANY_AUTH_CLUSTERS  (-8)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXIES_INTERMIXED      (-9)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_EXPECTED_SEMICOLON      (-10)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INTERNAL                 (-11)

#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK                               0
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INVALID_ARGS                (-1)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_AUTH_CLUSTERS      (-2)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PROXIES_INTERMIXED          (-3)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_TARGETS            (-4)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_HOSTNAME_EXPECTED           (-5)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_EXPECTED               (-6)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_RANGE                  (-7)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_EXPECTED_SEMICOLON          (-8)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_CLUSTER_EXTEND_INVARIANT    (-9)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_INTERNAL                    (-10)

#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_OK                               0
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_ARGS                (-1)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TIMEOUT             (-2)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MAX_CONNECTIONS     (-3)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MIN_CONNECTIONS     (-4)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TARGET_ID           (-5)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_TARGET_ID_SPACE             (-6)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXY_EXPECTED              (-7)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_AUTH_CLUSTERS     (-8)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXIES_INTERMIXED         (-9)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON         (-10)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_TARGETS           (-11)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_HOSTNAME_EXPECTED          (-12)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_EXPECTED              (-13)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_RANGE                 (-14)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_CLUSTER_EXTEND_INVARIANT   (-15)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES   (-16)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_NO_PROXY_SERVERS_DEFINED   (-17)
#define MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INTERNAL                   (-18)

#define MTPROXY_FFI_MTPROTO_CFG_EXPECT_SEMICOLON_OK                     0
#define MTPROXY_FFI_MTPROTO_CFG_EXPECT_SEMICOLON_ERR_INVALID_ARGS      (-1)
#define MTPROXY_FFI_MTPROTO_CFG_EXPECT_SEMICOLON_ERR_EXPECTED          (-2)

#define MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_EOF              0
#define MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT          1
#define MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER  2
#define MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR        3
#define MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY            4
#define MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS  5
#define MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS  6

#define MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING 0
#define MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_CLEAR         1
#define MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET    2

#define MTPROXY_FFI_MTPROTO_PACKET_KIND_INVALID        0
#define MTPROXY_FFI_MTPROTO_PACKET_KIND_ENCRYPTED      1
#define MTPROXY_FFI_MTPROTO_PACKET_KIND_UNENCRYPTED_DH 2

#define MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_INVALID    0
#define MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_PONG       1
#define MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_PROXY_ANS  2
#define MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_SIMPLE_ACK 3
#define MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_CLOSE_EXT  4
#define MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_UNKNOWN    5
#define MTPROXY_FFI_MTPROTO_CLIENT_PACKET_KIND_MALFORMED  6

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

#define MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION 1u

#define MTPROXY_FFI_MPQ_OP_PUSH      (1u << 0)
#define MTPROXY_FFI_MPQ_OP_POP       (1u << 1)
#define MTPROXY_FFI_MPQ_OP_IS_EMPTY  (1u << 2)
#define MTPROXY_FFI_MPQ_OP_PUSH_W    (1u << 3)
#define MTPROXY_FFI_MPQ_OP_POP_W     (1u << 4)
#define MTPROXY_FFI_MPQ_OP_POP_NW    (1u << 5)

#define MTPROXY_FFI_JOBS_OP_CREATE_ASYNC_JOB      (1u << 0)
#define MTPROXY_FFI_JOBS_OP_SCHEDULE_JOB          (1u << 1)
#define MTPROXY_FFI_JOBS_OP_JOB_SIGNAL            (1u << 2)
#define MTPROXY_FFI_JOBS_OP_JOB_INCREF            (1u << 3)
#define MTPROXY_FFI_JOBS_OP_JOB_DECREF            (1u << 4)
#define MTPROXY_FFI_JOBS_OP_RUN_PENDING_MAIN_JOBS (1u << 5)
#define MTPROXY_FFI_JOBS_OP_NOTIFY_JOB_CREATE     (1u << 6)

typedef struct mtproxy_ffi_concurrency_boundary {
  uint32_t boundary_version;
  uint32_t mpq_contract_ops;
  uint32_t mpq_implemented_ops;
  uint32_t jobs_contract_ops;
  uint32_t jobs_implemented_ops;
} mtproxy_ffi_concurrency_boundary_t;

#define MTPROXY_FFI_NETWORK_BOUNDARY_VERSION 1u

#define MTPROXY_FFI_NET_EVENTS_OP_EPOLL_CONV_FLAGS   (1u << 0)
#define MTPROXY_FFI_NET_EVENTS_OP_EPOLL_UNCONV_FLAGS (1u << 1)

#define MTPROXY_FFI_NET_TIMERS_OP_WAIT_MSEC (1u << 0)

#define MTPROXY_FFI_NET_MSGBUFFERS_OP_PICK_SIZE_INDEX (1u << 0)

typedef struct mtproxy_ffi_network_boundary {
  uint32_t boundary_version;
  uint32_t net_events_contract_ops;
  uint32_t net_events_implemented_ops;
  uint32_t net_timers_contract_ops;
  uint32_t net_timers_implemented_ops;
  uint32_t net_msg_buffers_contract_ops;
  uint32_t net_msg_buffers_implemented_ops;
} mtproxy_ffi_network_boundary_t;

#define MTPROXY_FFI_RPC_BOUNDARY_VERSION 1u

#define MTPROXY_FFI_TCP_RPC_COMMON_OP_COMPACT_ENCODE      (1u << 0)

#define MTPROXY_FFI_TCP_RPC_CLIENT_OP_PACKET_LEN_STATE    (1u << 0)

#define MTPROXY_FFI_TCP_RPC_SERVER_OP_HEADER_MALFORMED    (1u << 0)
#define MTPROXY_FFI_TCP_RPC_SERVER_OP_PACKET_LEN_STATE    (1u << 1)

#define MTPROXY_FFI_RPC_TARGETS_OP_NORMALIZE_PID          (1u << 0)

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

#define MTPROXY_FFI_CRYPTO_BOUNDARY_VERSION 1u

#define MTPROXY_FFI_NET_CRYPTO_AES_OP_CREATE_KEYS         (1u << 0)

#define MTPROXY_FFI_NET_CRYPTO_DH_OP_IS_GOOD_RPC_DH_BIN   (1u << 0)
#define MTPROXY_FFI_NET_CRYPTO_DH_OP_GET_PARAMS_SELECT    (1u << 1)
#define MTPROXY_FFI_NET_CRYPTO_DH_OP_FIRST_ROUND          (1u << 2)
#define MTPROXY_FFI_NET_CRYPTO_DH_OP_SECOND_ROUND         (1u << 3)
#define MTPROXY_FFI_NET_CRYPTO_DH_OP_THIRD_ROUND          (1u << 4)

#define MTPROXY_FFI_AESNI_OP_EVP_CRYPT                    (1u << 0)
#define MTPROXY_FFI_AESNI_OP_CTX_INIT                     (1u << 1)
#define MTPROXY_FFI_AESNI_OP_CTX_FREE                     (1u << 2)

#define MTPROXY_FFI_AESNI_CIPHER_AES_256_CBC              1
#define MTPROXY_FFI_AESNI_CIPHER_AES_256_CTR              2

typedef struct mtproxy_ffi_crypto_boundary {
  uint32_t boundary_version;
  uint32_t net_crypto_aes_contract_ops;
  uint32_t net_crypto_aes_implemented_ops;
  uint32_t net_crypto_dh_contract_ops;
  uint32_t net_crypto_dh_implemented_ops;
  uint32_t aesni_contract_ops;
  uint32_t aesni_implemented_ops;
} mtproxy_ffi_crypto_boundary_t;

#define MTPROXY_FFI_APPLICATION_BOUNDARY_VERSION 1u

#define MTPROXY_FFI_ENGINE_RPC_OP_RESULT_NEW_FLAGS    (1u << 0)
#define MTPROXY_FFI_ENGINE_RPC_OP_RESULT_HEADER_LEN   (1u << 1)

#define MTPROXY_FFI_MTPROTO_PROXY_OP_EXT_CONN_HASH    (1u << 0)
#define MTPROXY_FFI_MTPROTO_PROXY_OP_CONN_TAG         (1u << 1)

typedef struct mtproxy_ffi_application_boundary {
  uint32_t boundary_version;
  uint32_t engine_rpc_contract_ops;
  uint32_t engine_rpc_implemented_ops;
  uint32_t mtproto_proxy_contract_ops;
  uint32_t mtproto_proxy_implemented_ops;
} mtproxy_ffi_application_boundary_t;

typedef int32_t (*mtproxy_ffi_jobs_process_fn)(void *job);

#define MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_SKIP    0
#define MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_READY   1
#define MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_INVALID (-1)
#define MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_SHORT   (-2)

// FFI API surface version exposed by Rust side.
uint32_t mtproxy_ffi_api_version(void);

// Startup handshake between C and Rust layers.
// Returns 0 on success, -1 on version mismatch.
int32_t mtproxy_ffi_startup_handshake(uint32_t expected_api_version);

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
#define MTPROXY_FFI_RESOLVER_LOOKUP_SYSTEM_DNS 0
#define MTPROXY_FFI_RESOLVER_LOOKUP_NOT_FOUND  1
#define MTPROXY_FFI_RESOLVER_LOOKUP_HOSTS_IPV4 2
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

// net-tcp-rpc-common helper: computes compact/medium packet length prefix.
int32_t mtproxy_ffi_tcp_rpc_encode_compact_header(
  int32_t payload_len,
  int32_t is_medium,
  int32_t *out_prefix_word,
  int32_t *out_prefix_bytes
);

// net-tcp-rpc-client helper: classifies packet length from non-compact mode parser.
int32_t mtproxy_ffi_tcp_rpc_client_packet_len_state(int32_t packet_len, int32_t max_packet_len);

// net-tcp-rpc-server helpers: classifies malformed header and packet length state.
int32_t mtproxy_ffi_tcp_rpc_server_packet_header_malformed(int32_t packet_len);
int32_t mtproxy_ffi_tcp_rpc_server_packet_len_state(int32_t packet_len, int32_t max_packet_len);

// net-rpc-targets helper: normalizes zero-ip PID to default local IP.
int32_t mtproxy_ffi_rpc_target_normalize_pid(mtproxy_ffi_process_id_t *pid, uint32_t default_ip);

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
int32_t mtproxy_ffi_cfg_skspc(
  const char *cur,
  size_t len,
  int32_t line_no,
  mtproxy_ffi_cfg_scan_result_t *out
);
int32_t mtproxy_ffi_cfg_getword_len(const char *cur, size_t len);
int32_t mtproxy_ffi_cfg_getstr_len(const char *cur, size_t len);
int32_t mtproxy_ffi_cfg_getint(
  const char *cur,
  size_t len,
  mtproxy_ffi_cfg_int_result_t *out
);
int32_t mtproxy_ffi_cfg_getint_zero(
  const char *cur,
  size_t len,
  mtproxy_ffi_cfg_int_result_t *out
);
int32_t mtproxy_ffi_cfg_getint_signed_zero(
  const char *cur,
  size_t len,
  mtproxy_ffi_cfg_int_result_t *out
);

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

#ifdef __cplusplus
}
#endif
