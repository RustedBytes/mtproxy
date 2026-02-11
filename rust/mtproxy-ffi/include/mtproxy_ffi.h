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

// generic crypto helpers for TLS-obfuscated transport paths.
int32_t mtproxy_ffi_crypto_rand_bytes(uint8_t *out, int32_t len);
int32_t mtproxy_ffi_crypto_tls_generate_public_key(uint8_t out[32]);

// crypto/aesni helper: OpenSSL-backed EVP_CipherUpdate glue.
int32_t mtproxy_ffi_aesni_crypt(void *evp_ctx, const uint8_t *in, uint8_t *out, int32_t size);
int32_t mtproxy_ffi_aesni_ctx_init(
  int32_t cipher_kind,
  const uint8_t key[32],
  const uint8_t iv[16],
  int32_t is_encrypt,
  void **out_ctx
);
int32_t mtproxy_ffi_aesni_ctx_free(void *evp_ctx);

// engine-rpc helpers for TL result header normalization.
int32_t mtproxy_ffi_engine_rpc_result_new_flags(int32_t old_flags);
int32_t mtproxy_ffi_engine_rpc_result_header_len(int32_t flags);

// mtproto-proxy helpers for external-connection hashing/tagging.
int32_t mtproxy_ffi_mtproto_ext_conn_hash(int32_t in_fd, int64_t in_conn_id, int32_t hash_shift);
int32_t mtproxy_ffi_mtproto_conn_tag(int32_t generation);

// CRC32 (IEEE, reflected polynomial 0xEDB88320) partial update.
// Semantics match C `crc32_partial` function.
uint32_t mtproxy_ffi_crc32_partial(const uint8_t *data, size_t len, uint32_t crc);

// CRC32C (Castagnoli, reflected polynomial 0x82F63B78) partial update.
// Semantics match C `crc32c_partial` function.
uint32_t mtproxy_ffi_crc32c_partial(const uint8_t *data, size_t len, uint32_t crc);

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

#ifdef __cplusplus
}
#endif
