#pragma once

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef void *mqn_value_t;

struct mp_queue_block;

struct mp_queue {
  struct mp_queue_block *mq_head __attribute__((aligned(64)));
  int mq_magic;
  struct mp_queue_block *mq_tail __attribute__((aligned(64)));
};

struct job_thread;
struct job_class;
struct async_job;
typedef struct async_job *job_t;

typedef int (*job_function_t)(job_t job, int op, struct job_thread *JT);


#define PTR_MOVE(__ptr_v)                                                      \
  ({                                                                           \
    typeof(__ptr_v) __ptr_v_save = __ptr_v;                                    \
    __ptr_v = NULL;                                                            \
    __ptr_v_save;                                                              \
  })

#define JOB_REF_ARG(__name) [[maybe_unused]] int __name##_tag_int, job_t __name

struct job_thread *jobs_get_this_job_thread(void);

int job_free(JOB_REF_ARG(job));

enum {
  JC_MAIN = 3,
  JC_ENGINE = 8,
  JC_MAX = 0xf,
};

struct async_job {
  int j_flags;
  int j_status;
  int j_sigclass;
  int j_refcnt;
  int j_error;
  int j_children;
  int j_align;
  int j_custom_bytes;
  unsigned int j_type;
  int j_subclass;
  struct job_thread *j_thread;
  job_function_t j_execute;
  job_t j_parent;
  long long j_custom[0] __attribute__((aligned(64)));
} __attribute__((aligned(64)));

struct job_thread {
  pthread_t pthread_id;
  int id;
  int thread_class;
  int job_class_mask;
  int status;
  long long jobs_performed;
  struct mp_queue *job_queue;
  struct async_job *current_job;
  double current_job_start_time, last_job_time, tot_jobs_time;
  int jobs_running[JC_MAX + 1];
  long long jobs_created;
  long long jobs_active;
  int thread_system_id;
  struct drand48_data rand_data;
  job_t timer_manager;
  double wakeup_time;
  struct job_class *job_class;
} __attribute__((aligned(128)));

typedef struct {
  long long vm_size;
  long long vm_rss;
  long long vm_data;
  long long mem_free;
  long long swap_total;
  long long swap_free;
  long long swap_used;
  long long mem_cached;
} am_memory_stat_t;

typedef struct stats_buffer {
  char *buff;
  int pos;
  int size;
  int flags;
} stats_buffer_t;

typedef void (*stat_fun_t)(stats_buffer_t *sb);

#pragma pack(push, 4)
struct process_id {
  unsigned ip;
  short port;
  unsigned short pid;
  int utime;
};

struct process_id_ext {
  unsigned ip;
  short port;
  unsigned short pid;
  int utime;
  int actor_id;
};
#pragma pack(pop)

typedef struct process_id npid_t;

struct proc_stats {
  int pid;
  char comm[256];
  char state;
  int ppid;
  int pgrp;
  int session;
  int tty_nr;
  int tpgid;
  unsigned long flags;
  unsigned long minflt;
  unsigned long cminflt;
  unsigned long majflt;
  unsigned long cmajflt;
  unsigned long utime;
  unsigned long stime;
  long cutime;
  long cstime;
  long priority;
  long nice;
  long num_threads;
  long itrealvalue;
  unsigned long starttime;
  unsigned long vsize;
  long rss;
  unsigned long rlim;
  unsigned long startcode;
  unsigned long endcode;
  unsigned long startstack;
  unsigned long kstkesp;
  unsigned long kstkeip;
  unsigned long signal;
  unsigned long blocked;
  unsigned long sigignore;
  unsigned long sigcatch;
  unsigned long wchan;
  unsigned long nswap;
  unsigned long cnswap;
  int exit_signal;
  int processor;
  unsigned long rt_priority;
  unsigned long policy;
  unsigned long long delayacct_blkio_ticks;
};

struct raw_message;
struct query_work_params;
struct tl_in_state;
struct tl_out_state;

struct tl_in_methods {
  void (*fetch_raw_data)(struct tl_in_state *tlio, void *buf, int len);
  void (*fetch_move)(struct tl_in_state *tlio, int len);
  void (*fetch_lookup)(struct tl_in_state *tlio, void *buf, int len);
  void (*fetch_clear)(struct tl_in_state *tlio);
  void (*fetch_mark)(struct tl_in_state *tlio);
  void (*fetch_mark_restore)(struct tl_in_state *tlio);
  void (*fetch_mark_delete)(struct tl_in_state *tlio);
  void (*fetch_raw_message)(struct tl_in_state *tlio, struct raw_message *raw,
                            int len);
  void (*fetch_lookup_raw_message)(struct tl_in_state *tlio,
                                   struct raw_message *raw, int len);
  int flags;
  int prepend_bytes;
};

struct tl_out_methods {
  void *(*store_get_ptr)(struct tl_out_state *tlio, int len);
  void *(*store_get_prepend_ptr)(struct tl_out_state *tlio, int len);
  void (*store_raw_data)(struct tl_out_state *tlio, const void *buf, int len);
  void (*store_raw_msg)(struct tl_out_state *tlio, struct raw_message *raw);
  void (*store_read_back)(struct tl_out_state *tlio, int len);
  void (*store_read_back_nondestruct)(struct tl_out_state *tlio, void *buf,
                                      int len);
  unsigned (*store_crc32_partial)(struct tl_out_state *tlio, int len,
                                  unsigned start);
  void (*store_flush)(struct tl_out_state *tlio);
  void (*store_clear)(struct tl_out_state *tlio);
  void (*copy_through[10])(struct tl_in_state *tlio_src,
                           struct tl_out_state *tlio_dst, int len, int advance);
  void (*store_prefix)(struct tl_out_state *tlio);
  int flags;
  int prepend_bytes;
};

enum tl_type {
  tl_type_none,
  tl_type_str,
  tl_type_raw_msg,
  tl_type_tcp_raw_msg,
};

struct tl_in_state {
  enum tl_type in_type;
  const struct tl_in_methods *in_methods;
  void *in;
  void *in_mark;
  int in_remaining;
  int in_pos;
  int in_mark_pos;
  int in_flags;
  char *error;
  int errnum;
  struct process_id in_pid_buf;
  struct process_id *in_pid;
};

struct tl_out_state {
  enum tl_type out_type;
  const struct tl_out_methods *out_methods;
  void *out;
  void *out_extra;
  int out_pos;
  int out_remaining;
  int *out_size;
  char *error;
  int errnum;
  long long out_qid;
  struct process_id out_pid_buf;
  struct process_id *out_pid;
};

struct tl_query_header {
  long long qid;
  long long actor_id;
  int flags;
  int op;
  int real_op;
  int ref_cnt;
  struct query_work_params *qw_params;
};

enum {
  TL_STAT = 0x9d56e6b2,
  RPC_INVOKE_REQ = 0x2374df3d,
  RPC_INVOKE_KPHP_REQ = 0x99a37fda,
  RPC_REQ_RUNNING = 0x346d5efa,
  RPC_REQ_ERROR = 0x7ae432f5,
  RPC_REQ_RESULT = 0x63aeda4e,
  RPC_READY = 0x6a34cac7,
  RPC_STOP_READY = 0x59d86654,
  RPC_SEND_SESSION_MSG = 0x1ed5a3cc,
  RPC_RESPONSE_INDIRECT = 0x2194f56e,
  RPC_PING = 0x5730a2df,
  RPC_PONG = 0x8430eaa7,
  RPC_DEST_ACTOR = 0x7568aabd,
  RPC_DEST_ACTOR_FLAGS = 0xf0a5acf7,
  RPC_DEST_FLAGS = 0xe352035e,
  RPC_REQ_RESULT_FLAGS = 0x8cc84ce1,
  MAX_TL_STRING_LENGTH = 0xffffff,
  TL_ERROR_RETRY = 503,
  TL_BOOL_TRUE = 0x997275b5,
  TL_BOOL_FALSE = 0xbc799737,
  TL_BOOL_STAT = 0x92cbcbfa,
  TL_INT = 0xa8509bda,
  TL_LONG = 0x22076cba,
  TL_DOUBLE = 0x2210c154,
  TL_STRING = 0xb5286e24,
  TL_MAYBE_TRUE = 0x3f9c8ef8,
  TL_MAYBE_FALSE = 0x27930a7b,
  TL_VECTOR = 0x1cb5c415,
  TL_VECTOR_TOTAL = 0x10133f47,
  TL_TUPLE = 0x9770768a,
  TL_DICTIONARY = 0x1f4c618f,
};

enum {
  TL_ERROR_SYNTAX = -1000,
  TL_ERROR_EXTRA_DATA = -1001,
  TL_ERROR_HEADER = -1002,
  TL_ERROR_WRONG_QUERY_ID = -1003,
  TL_ERROR_NOT_ENOUGH_DATA = -1004,
};

enum {
  TL_ERROR_UNKNOWN_FUNCTION_ID = -2000,
  TL_ERROR_PROXY_NO_TARGET = -2001,
  TL_ERROR_WRONG_ACTOR_ID = -2002,
  TL_ERROR_TOO_LONG_STRING = -2003,
  TL_ERROR_VALUE_NOT_IN_RANGE = -2004,
  TL_ERROR_QUERY_INCORRECT = -2005,
  TL_ERROR_BAD_VALUE = -2006,
  TL_ERROR_BINLOG_DISABLED = -2007,
  TL_ERROR_FEATURE_DISABLED = -2008,
  TL_ERROR_QUERY_IS_EMPTY = -2009,
  TL_ERROR_INVALID_CONNECTION_ID = -2010,
  TL_ERROR_WRONG_SPLIT = -2011,
  TL_ERROR_TOO_BIG_OFFSET = -2012,
};

enum {
  TL_ERROR_QUERY_TIMEOUT = -3000,
  TL_ERROR_PROXY_INVALID_RESPONSE = -3001,
  TL_ERROR_NO_CONNECTIONS = -3002,
  TL_ERROR_INTERNAL = -3003,
  TL_ERROR_AIO_FAIL = -3004,
  TL_ERROR_AIO_TIMEOUT = -3005,
  TL_ERROR_BINLOG_WAIT_TIMEOUT = -3006,
  TL_ERROR_AIO_MAX_RETRY_EXCEEDED = -3007,
  TL_ERROR_TTL = -3008,
  TL_ERROR_BAD_METAFILE = -3009,
  TL_ERROR_NOT_READY = -3010,
  TL_ERROR_STORAGE_CACHE_MISS = -3500,
  TL_ERROR_STORAGE_CACHE_NO_MTPROTO_CONN = -3501,
};

enum {
  TL_ERROR_UNKNOWN = -4000,
};

typedef unsigned (*crc32_partial_func_t)(const void *data, long len,
                                         unsigned crc);

typedef struct mtproxy_ffi_process_id {
  uint32_t ip;
  int16_t port;
  uint16_t pid;
  int32_t utime;
} mtproxy_ffi_process_id_t;

typedef struct mtproxy_ffi_process_id_ext {
  uint32_t ip;
  int16_t port;
  uint16_t pid;
  int32_t utime;
  int32_t actor_id;
} mtproxy_ffi_process_id_ext_t;

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

enum { MTPROXY_FFI_MAX_CFG_CLUSTERS = 1024 };
enum { MTPROXY_FFI_MAX_CFG_TARGETS = 4096 };

typedef void *mtproxy_ffi_conn_target_job_t;

struct mf_cluster {
  int targets_num;
  int write_targets_num;
  int targets_allocated;
  int flags;
  int cluster_id;
  mtproxy_ffi_conn_target_job_t *cluster_targets;
};

struct mf_group_stats {
  int tot_clusters;
};

struct mf_config {
  int tot_targets;
  int auth_clusters;
  int default_cluster_id;
  int min_connections;
  int max_connections;
  double timeout;
  int config_bytes;
  int config_loaded_at;
  char *config_md5_hex;
  struct mf_group_stats auth_stats;
  int have_proxy;
  struct mf_cluster *default_cluster;
  mtproxy_ffi_conn_target_job_t targets[MTPROXY_FFI_MAX_CFG_TARGETS];
  struct mf_cluster auth_cluster[MTPROXY_FFI_MAX_CFG_CLUSTERS];
};

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
struct process_id;
struct query_work_params;
struct tl_act_extra;
struct rpc_custom_op;
struct tcp_rpc_server_functions;
struct http_server_functions;
typedef int32_t (*mtproxy_ffi_engine_net_try_open_port_fn)(int32_t port, void *ctx);
typedef void (*mtproxy_ffi_engine_signal_dispatch_fn)(int32_t sig, void *ctx);
typedef void (*mtproxy_ffi_engine_rpc_custom_op_fn)(void *tlio_in, void *params);
typedef void (*mtproxy_ffi_engine_rpc_query_result_fn)(void *tlio_in, void *query_header);
typedef void *(*mtproxy_ffi_engine_rpc_parse_fn)(void *tlio_in, int64_t actor_id);
typedef void (*mtproxy_ffi_engine_rpc_stat_fn)(void *tlio_out);
typedef int32_t (*mtproxy_ffi_engine_rpc_get_op_fn)(void *tlio_in);
typedef void (*tl_query_result_fun_t)(struct tl_in_state *tlio_in,
                                      struct tl_query_header *h);

// Legacy net/*.h compatibility ABI now provided by Rust bindings header.
enum {
  MAX_EVENT_TIMERS = (1 << 19),
};

typedef struct event_timer event_timer_t;
struct event_timer {
  int h_idx;
  int flags;
  int (*wakeup)(event_timer_t *et);
  double wakeup_time;
  double real_wakeup_time;
};

#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

enum {
  MAX_EVENTS = (1 << 19),
  MAX_UDP_SENDBUF_SIZE = (1 << 24),
  MAX_UDP_RCVBUF_SIZE = (1 << 24),
  PRIVILEGED_TCP_PORTS = 1024,
};

enum {
  EVT_READ = 4,
  EVT_WRITE = 2,
  EVT_SPEC = 1,
  EVT_RWX = EVT_READ | EVT_WRITE | EVT_SPEC,
  EVT_LEVEL = 8,
  EVT_CLOSED = 0x40,
  EVT_IN_EPOLL = 0x20,
  EVT_NEW = 0x100,
  EVT_NOHUP = 0x200,
  EVT_FROM_EPOLL = 0x400,
};

enum {
  EVA_CONTINUE = 0,
  EVA_RERUN = -2,
  EVA_REMOVE = -3,
  EVA_DESTROY = -5,
  EVA_ERROR = -8,
  EVA_FATAL = -666,
};

typedef struct event_descr event_t;
typedef int (*event_handler_t)(int fd, void *data, event_t *ev);

struct event_descr {
  int fd;
  int state;
  int ready;
  int epoll_state;
  int epoll_ready;
  int timeout;
  int priority;
  int in_queue;
  long long timestamp;
  long long refcnt;
  event_handler_t work;
  void *data;
};

extern double last_epoll_wait_at;
extern int ev_heap_size;
extern event_t Events[MAX_EVENTS];
extern double tot_idle_time, a_idle_time, a_idle_quotient;
extern int epoll_fd;
extern volatile int main_thread_interrupt_status;
extern int tcp_maximize_buffers;

enum {
  SM_UDP = 1,
  SM_IPV6 = 2,
  SM_IPV6_ONLY = 4,
  SM_LOWPRIO = 8,
  SM_REUSE = 16,
  SM_SPECIAL = 0x10000,
  SM_NOQACK = 0x20000,
  SM_RAWMSG = 0x40000,
};

extern int epoll_sleep_ns;

enum {
  MSG_STD_BUFFER = 2048,
  MSG_SMALL_BUFFER = 512,
  MSG_TINY_BUFFER = 48,
};
enum {
  MSG_BUFFERS_CHUNK_SIZE = ((1 << 21) - 64),
};
enum {
  MSG_DEFAULT_MAX_ALLOCATED_BYTES = (1 << 28),
};
#ifdef _LP64
enum {
  MSG_MAX_ALLOCATED_BYTES = (1LL << 40),
};
#else
enum {
  MSG_MAX_ALLOCATED_BYTES = (1LL << 30),
};
#endif
enum {
  MSG_BUFFER_FREE_MAGIC = 0x4abdc351,
  MSG_BUFFER_USED_MAGIC = 0x72e39317,
  MSG_BUFFER_SPECIAL_MAGIC = 0x683caad3,
};
enum {
  MSG_CHUNK_USED_MAGIC = 0x5c75e681,
  MSG_CHUNK_USED_LOCKED_MAGIC = ~MSG_CHUNK_USED_MAGIC,
  MSG_CHUNK_HEAD_MAGIC = 0x2dfecca3,
  MSG_CHUNK_HEAD_LOCKED_MAGIC = ~MSG_CHUNK_HEAD_MAGIC,
};
enum {
  MAX_BUFFER_SIZE_VALUES = 16,
};

struct msg_buffers_chunk;
struct msg_buffer {
  struct msg_buffers_chunk *chunk;
#ifndef _LP64
  int resvd;
#endif
  int refcnt;
  int magic;
  char data[0];
};

enum {
  BUFF_HD_BYTES = offsetof(struct msg_buffer, data),
};

struct msg_buffers_chunk {
  int magic;
  int buffer_size;
  int (*free_buffer)(struct msg_buffers_chunk *C, struct msg_buffer *B);
  struct msg_buffers_chunk *ch_next, *ch_prev;
  struct msg_buffers_chunk *ch_head;
  struct msg_buffer *first_buffer;
  int two_power;
  int tot_buffers;
  int bs_inverse;
  int bs_shift;
  struct mp_queue *free_block_queue;
  int thread_class;
  int thread_subclass;
  int refcnt;
  union {
    struct {
      int tot_chunks;
      int free_buffers;
    };
    unsigned short free_cnt[0];
  };
};

struct buffers_stat {
  long long total_used_buffers_size;
  long long allocated_buffer_bytes;
  long long buffer_chunk_alloc_ops;
  int total_used_buffers;
  int allocated_buffer_chunks, max_allocated_buffer_chunks, max_buffer_chunks;
  long long max_allocated_buffer_bytes;
};

void mtproxy_ffi_net_msg_buffers_fetch_buffers_stat(struct buffers_stat *bs);
int32_t mtproxy_ffi_net_msg_buffers_init(long max_buffer_bytes);
struct msg_buffer *mtproxy_ffi_net_msg_buffers_alloc(struct msg_buffer *neighbor, int32_t size_hint);
int32_t mtproxy_ffi_net_msg_buffers_free(struct msg_buffer *buffer);
int32_t mtproxy_ffi_net_msg_buffers_reach_limit(double ratio);
double mtproxy_ffi_net_msg_buffers_usage(void);

#define fetch_buffers_stat mtproxy_ffi_net_msg_buffers_fetch_buffers_stat
#define init_msg_buffers mtproxy_ffi_net_msg_buffers_init
#define alloc_msg_buffer mtproxy_ffi_net_msg_buffers_alloc
#define free_msg_buffer mtproxy_ffi_net_msg_buffers_free
#define msg_buffer_reach_limit mtproxy_ffi_net_msg_buffers_reach_limit
#define msg_buffer_usage mtproxy_ffi_net_msg_buffers_usage

struct msg_part {
#ifndef _LP64
  int resvd;
#endif
  int refcnt;
  int magic;
  struct msg_part *next;
  struct msg_buffer *part;
  int offset;
  int data_end;
};

enum {
  MSG_PART_MAGIC = 0x8341aa7,
  MSG_PART_LOCKED_MAGIC = ~MSG_PART_MAGIC,
};
struct msg_part *new_msg_part(struct msg_part *neighbor, struct msg_buffer *X);

enum {
  RM_INIT_MAGIC = 0x23513473,
};
enum {
  RM_TMP_MAGIC = 0x52a717f3,
};
enum {
  RM_PREPEND_RESERVE = 128,
};

struct raw_message {
  struct msg_part *first, *last;
  int total_bytes;
  int magic;
  int first_offset;
  int last_offset;
};

int rwm_free(struct raw_message *raw);
int rwm_init(struct raw_message *raw, int alloc_bytes);
int rwm_create(struct raw_message *raw, const void *data, int alloc_bytes);
void rwm_clone(struct raw_message *dest_raw, struct raw_message *src_raw);
void rwm_move(struct raw_message *dest_raw, struct raw_message *src_raw);
int rwm_push_data(struct raw_message *raw, const void *data, int alloc_bytes);
int rwm_push_data_ext(struct raw_message *raw, const void *data, int alloc_bytes, int prepend, int small_buffer, int std_buffer);
int rwm_push_data_front(struct raw_message *raw, const void *data, int alloc_bytes);
int rwm_fetch_data(struct raw_message *raw, void *data, int bytes);
int rwm_skip_data(struct raw_message *raw, int bytes);
int rwm_fetch_lookup(struct raw_message *raw, void *buf, int bytes);
int rwm_fetch_data_back(struct raw_message *raw, void *data, int bytes);
int rwm_trunc(struct raw_message *raw, int len);
int rwm_union(struct raw_message *raw, struct raw_message *tail);
int rwm_split_head(struct raw_message *head, struct raw_message *raw, int bytes);
void *rwm_prepend_alloc(struct raw_message *raw, int alloc_bytes);
void *rwm_postpone_alloc(struct raw_message *raw, int alloc_bytes);

int rwm_prepare_iovec(const struct raw_message *raw, struct iovec *iov, int iov_len, int bytes);
int rwm_dump(struct raw_message *raw);
unsigned rwm_custom_crc32(struct raw_message *raw, int bytes, crc32_partial_func_t custom_crc32_partial);

int rwm_process(struct raw_message *raw, int bytes, int (*process_block)(void *extra, const void *data, int len), void *extra);
enum {
  RMPF_ADVANCE = 1,
  RMPF_TRUNCATE = 2,
};
int rwm_process_ex(struct raw_message *raw, int bytes, int offset, int flags, int (*process_block)(void *extra, const void *data, int len), void *extra);
int rwm_process_from_offset(struct raw_message *raw, int bytes, int offset, int (*process_block)(void *extra, const void *data, int len), void *extra);
int rwm_transform_from_offset(struct raw_message *raw, int bytes, int offset, int (*transform_block)(void *extra, void *data, int len), void *extra);
int rwm_process_and_advance(struct raw_message *raw, int bytes, int (*process_block)(void *extra, const void *data, int len), void *extra);
int rwm_encrypt_decrypt_to(struct raw_message *raw, struct raw_message *res, int bytes, void *ctx, int block_size);

void *rwm_get_block_ptr(struct raw_message *raw);
int rwm_get_block_ptr_bytes(struct raw_message *raw);

extern struct raw_message empty_rwm;

// engine-rpc.h compatibility ABI now provided by Rust bindings header.
struct query_work_params {
  struct event_timer ev;
  enum tl_type type;
  struct process_id pid;
  struct raw_message src;
  struct tl_query_header *h;
  struct raw_message *result;
  int error_code;
  int answer_sent;
  int wait_coord;
  char *error;
  void *wait_pos;
  struct paramed_type *P;
  long long start_rdtsc;
  long long total_work_rdtsc;
  job_t all_list;
  int fd;
  int generation;
};

struct tl_act_extra {
  int size;
  int flags;
  int attempt;
  int type;
  int op;
  int subclass;
  unsigned long long hash;
  long long start_rdtsc;
  long long cpu_rdtsc;
  struct tl_out_state *tlio_out;
  int (*act)(job_t, struct tl_act_extra *data);
  void (*free)(struct tl_act_extra *data);
  struct tl_act_extra *(*dup)(struct tl_act_extra *data);
  struct tl_query_header *header;
  struct raw_message **raw;
  char **error;
  job_t extra_ref;
  int *error_code;
  int extra[0];
};

#pragma pack(push, 4)
struct rpc_custom_op {
  unsigned op;
  void (*func)(struct tl_in_state *tlio_in, struct query_work_params *params);
};
#pragma pack(pop)

enum {
  MAX_CONNECTIONS = 65536,
  PRIME_TARGETS = 99961,
  CONN_CUSTOM_DATA_BYTES = 256,
};

typedef job_t connection_job_t;
typedef job_t socket_connection_job_t;
typedef job_t listening_connection_job_t;
typedef job_t conn_target_job_t;

typedef struct conn_functions {
  int magic;
  int flags;
  char *title;
  int (*accept)(connection_job_t c);
  int (*init_accepted)(connection_job_t c);
  int (*reader)(connection_job_t c);
  int (*writer)(connection_job_t c);
  int (*close)(connection_job_t c, int who);
  int (*parse_execute)(connection_job_t c);
  int (*init_outbound)(connection_job_t c);
  int (*connected)(connection_job_t c);
  int (*check_ready)(connection_job_t c);
  int (*wakeup_aio)(connection_job_t c, int r);
  int (*write_packet)(connection_job_t c, struct raw_message *raw);
  int (*flush)(connection_job_t c);
  int (*free)(connection_job_t c);
  int (*free_buffers)(connection_job_t c);
  int (*read_write)(connection_job_t c);
  int (*wakeup)(connection_job_t c);
  int (*alarm)(connection_job_t c);
  int (*socket_read_write)(connection_job_t c);
  int (*socket_reader)(connection_job_t c);
  int (*socket_writer)(connection_job_t c);
  int (*socket_connected)(connection_job_t c);
  int (*socket_free)(connection_job_t c);
  int (*socket_close)(connection_job_t c);
  int (*data_received)(connection_job_t c, int r);
  int (*data_sent)(connection_job_t c, int w);
  int (*ready_to_write)(connection_job_t c);
  int (*crypto_init)(connection_job_t c, void *key_data, int key_data_len);
  int (*crypto_free)(connection_job_t c);
  int (*crypto_encrypt_output)(connection_job_t c);
  int (*crypto_decrypt_input)(connection_job_t c);
  int (*crypto_needed_output_bytes)(connection_job_t c);
} conn_type_t;

int check_conn_functions(conn_type_t *type, int listening);
void assert_net_cpu_thread(void);
void assert_engine_thread(void);
int prepare_stats(char *buf, int size);
extern int max_special_connections, active_special_connections;

int32_t mtproxy_ffi_net_select_best_key_signature(
    int32_t main_secret_len,
    int32_t main_key_signature,
    int32_t key_signature,
    int32_t extra_num,
    const int32_t *extra_key_signatures);

#pragma pack(push, 4)
struct tcp_rpc_nonce_packet {
  int type;
  int key_select;
  int crypto_schema;
  int crypto_ts;
  char crypto_nonce[16];
};
enum { RPC_MAX_EXTRA_KEYS = 8 };
#pragma pack(pop)

struct tcp_rpc_data {
  int flags;
  int in_packet_num;
  int out_packet_num;
  int crypto_flags;
  struct process_id remote_pid;
  char nonce[16];
  int nonce_time;
  int in_rpc_target;
  union {
    void *user_data;
    void *extra;
  };
  int extra_int;
  int extra_int2;
  int extra_int3;
  int extra_int4;
  double extra_double, extra_double2;
  crc32_partial_func_t custom_crc_partial;
};

enum {
  RPCF_ENC_SENT = 16,
  RPCF_SEQNO_HOLES = 256,
  RPCF_QUICKACK = 512,
  RPCF_COMPACT_OFF = 1024,
  RPCF_USE_CRC32C = 2048,
};

enum {
  RPC_F_PAD = 0x8000000,
  RPC_F_DROPPED = 0x10000000,
  RPC_F_MEDIUM = 0x20000000,
  RPC_F_COMPACT = 0x40000000,
  RPC_F_COMPACT_MEDIUM = RPC_F_COMPACT | RPC_F_MEDIUM,
  RPC_F_QUICKACK = 0x80000000,
  RPC_F_EXTMODE1 = 0x10000,
  RPC_F_EXTMODE2 = 0x20000,
  RPC_F_EXTMODE3 = 0x30000,
};

enum {
  RPC_NONCE = 0x7acb87aa,
  RPC_HANDSHAKE = 0x7682eef5,
  RPC_HANDSHAKE_ERROR = 0x6a27beda,
};

enum {
  RPC_CRYPTO_NONE = 0,
  RPC_CRYPTO_AES = 1,
  RPC_CRYPTO_AES_EXT = 2,
  RPC_CRYPTO_AES_DH = 3,
};

void mtproxy_ffi_net_tcp_rpc_common_conn_send(
    int32_t c_tag_int,
    connection_job_t c,
    struct raw_message *raw,
    int32_t flags);
void mtproxy_ffi_net_tcp_rpc_common_conn_send_data(
    int32_t c_tag_int,
    connection_job_t c,
    int32_t len,
    void *data);
void mtproxy_ffi_net_tcp_rpc_common_conn_send_data_init(
    connection_job_t c,
    int32_t len,
    void *data);
void mtproxy_ffi_net_tcp_rpc_common_conn_send_data_im(
    int32_t c_tag_int,
    connection_job_t c,
    int32_t len,
    void *data);
int32_t mtproxy_ffi_net_tcp_rpc_common_default_execute(
    connection_job_t c,
    int32_t op,
    struct raw_message *raw);
int32_t mtproxy_ffi_net_tcp_rpc_common_write_packet(
    connection_job_t c,
    struct raw_message *raw);
int32_t mtproxy_ffi_net_tcp_rpc_common_write_packet_compact(
    connection_job_t c,
    struct raw_message *raw);
uint32_t mtproxy_ffi_net_tcp_rpc_common_set_default_rpc_flags(
    uint32_t and_flags,
    uint32_t or_flags);
int mtproxy_ffi_net_tcp_rpc_common_copy_remote_pid(connection_job_t c, struct process_id *out_pid);

void tcp_rpc_conn_send(int32_t c_tag_int, connection_job_t c, struct raw_message *raw, int flags);
void tcp_rpc_conn_send_data(int32_t c_tag_int, connection_job_t c, int len, void *Q);
void tcp_rpc_conn_send_data_init(connection_job_t c, int len, void *Q);
void tcp_rpc_conn_send_data_im(int32_t c_tag_int, connection_job_t c, int len, void *Q);
int tcp_rpc_default_execute(connection_job_t c, int op, struct raw_message *raw);
int tcp_rpc_flush_packet(connection_job_t c);
extern conn_type_t ct_tcp_rpc_ext_server;

typedef job_t rpc_target_job_t;
struct tree_connection;
struct rpc_target_info {
  struct event_timer timer;
  int a, b;
  struct tree_connection *conn_tree;
  struct process_id PID;
};

enum {
  RPCF_ALLOW_UNENC = 1,
  RPCF_ALLOW_ENC = 2,
  RPCF_REQ_DH = 4,
  RPCF_ALLOW_SKIP_DH = 8,
};
enum {
  TCP_RPC_IGNORE_PID = 4,
};

struct http_server_functions {
  void *info;
  int (*execute)(connection_job_t c, struct raw_message *raw, int op);
  int (*ht_wakeup)(connection_job_t c);
  int (*ht_alarm)(connection_job_t c);
  int (*ht_close)(connection_job_t c, int who);
};

struct hts_data {
  int query_type;
  int query_flags;
  int query_words;
  int header_size;
  int first_line_size;
  int data_size;
  int host_offset;
  int host_size;
  int uri_offset;
  int uri_size;
  int http_ver;
  int wlen;
  char word[16];
  void *extra;
  int extra_int;
  int extra_int2;
  int extra_int3;
  int extra_int4;
  double extra_double, extra_double2;
  int parse_state;
  int query_seqno;
};

enum hts_query_type {
  htqt_none,
  htqt_head,
  htqt_get,
  htqt_post,
  htqt_options,
  htqt_error,
  htqt_empty
};

extern conn_type_t ct_http_server;
extern int http_connections;
extern long long http_queries, http_bad_headers, http_queries_size;
extern char *extra_http_response_headers;

struct tcp_rpc_client_functions {
  void *info;
  void *rpc_extra;
  int (*execute)(connection_job_t c, int op, struct raw_message *raw);
  int (*check_ready)(connection_job_t c);
  int (*flush_packet)(connection_job_t c);
  int (*rpc_check_perm)(connection_job_t c);
  int (*rpc_init_crypto)(connection_job_t c);
  int (*rpc_start_crypto)(connection_job_t c, char *nonce, int key_select, unsigned char *temp_key, int temp_key_len);
  int (*rpc_wakeup)(connection_job_t c);
  int (*rpc_alarm)(connection_job_t c);
  int (*rpc_ready)(connection_job_t c);
  int (*rpc_close)(connection_job_t c, int who);
  int max_packet_len;
  int mode_flags;
};

extern conn_type_t ct_tcp_rpc_client;
int tcp_rpcc_default_check_perm(connection_job_t c);
int tcp_rpcc_init_crypto(connection_job_t c);
int tcp_rpcc_start_crypto(connection_job_t c, char *nonce, int key_select, unsigned char *temp_key, int temp_key_len);
int tcp_rpcc_default_check_ready(connection_job_t c);

struct tcp_rpc_server_functions {
  void *info;
  void *rpc_extra;
  int (*execute)(connection_job_t c, int op, struct raw_message *raw);
  int (*check_ready)(connection_job_t c);
  int (*flush_packet)(connection_job_t c);
  int (*rpc_check_perm)(connection_job_t c);
  int (*rpc_init_crypto)(connection_job_t c, struct tcp_rpc_nonce_packet *P);
  void *nop;
  int (*rpc_wakeup)(connection_job_t c);
  int (*rpc_alarm)(connection_job_t c);
  int (*rpc_ready)(connection_job_t c);
  int (*rpc_close)(connection_job_t c, int who);
  int max_packet_len;
  int mode_flags;
  void *memcache_fallback_type, *memcache_fallback_extra;
  void *http_fallback_type, *http_fallback_extra;
};

extern conn_type_t ct_tcp_rpc_server;

// engine.h compatibility ABI now provided by Rust bindings header.
typedef struct {
  void (*cron)(void);
  void (*precise_cron)(void);
  void (*on_exit)(void);
  int (*on_waiting_exit)(
      void); // returns 0 -> stop wait and exit, X > 0 wait X microsenconds */
  void (*on_safe_quit)(void);

  void (*close_net_sockets)(void);

  unsigned long long flags;
  unsigned long long allowed_signals;
  unsigned long long forbidden_signals;
  unsigned long long default_modules;
  unsigned long long default_modules_disabled;

  void (*prepare_stats)(stats_buffer_t *sb);

  void (*prepare_parse_options)(void);
  int (*parse_option)(int val);
  void (*parse_extra_args)(int count, char *args[]);

  void (*pre_init)(void);

  void (*pre_start)(void);

  void (*pre_loop)(void);
  int (*run_script)(void);

  const char *FullVersionStr;
  const char *ShortVersionStr;

  int epoll_timeout;
  double aio_timeout;

  struct tl_act_extra *(*parse_function)(struct tl_in_state *tlio_in,
                                         long long actor_id);
  int (*get_op)(struct tl_in_state *tlio_in);

  void (*signal_handlers[65])(void);
  struct rpc_custom_op *custom_ops;

  struct tcp_rpc_server_functions *tcp_methods;

  conn_type_t *http_type;
  struct http_server_functions *http_functions;

  int cron_subclass;
  int precise_cron_subclass;
} server_functions_t;

typedef struct {
  struct in_addr settings_addr;
  int do_not_open_port;
  int epoll_wait_timeout;
  int sfd;

  unsigned long long modules;
  int port;
  int start_port, end_port;

  int backlog;
  int maxconn;
  int required_io_threads;
  int required_cpu_threads;
  int required_tcp_cpu_threads;
  int required_tcp_io_threads;

  char *aes_pwd_file;

  server_functions_t *F;
} engine_t;

typedef struct event_precise_cron {
  struct event_precise_cron *next, *prev;
  void (*wakeup)(struct event_precise_cron *arg);
} event_precise_cron_t;

// Legacy engine.h compatibility ABI now provided by Rust bindings header.
// GLIBC defines SIGRTMAX as a function in C, but engine ABI expects 64.
enum { OUR_SIGRTMAX = 64 };

static inline unsigned long long SIG2INT(const int sig) {
  return (sig == OUR_SIGRTMAX) ? 1ull : (1ull << (unsigned long long)sig);
}

static const unsigned long long ENGINE_NO_PORT = 4ull;

extern double precise_now_diff;
extern engine_t *engine_state;
int default_main(server_functions_t *F, int argc, char *argv[]);

enum {
  MIN_PWD_LEN = 32,
  MAX_PWD_LEN = 256,
};
static const char DEFAULT_PWD_FILE[] = "secret";

int aes_crypto_init(connection_job_t c, void *key_data, int key_data_len);
int aes_crypto_ctr128_init(connection_job_t c, void *key_data, int key_data_len);
void fetch_aes_crypto_stat(int *allocated_aes_crypto_ptr, int *allocated_aes_crypto_temp_ptr);

typedef struct aes_secret {
  int refcnt;
  int secret_len;
  union {
    char secret[MAX_PWD_LEN + 4];
    int key_signature;
  };
} aes_secret_t;

extern aes_secret_t main_secret;

struct aes_key_data {
  unsigned char read_key[32];
  unsigned char read_iv[16];
  unsigned char write_key[32];
  unsigned char write_iv[16];
};

enum {
  AES_KEY_DATA_LEN = sizeof(struct aes_key_data),
};

struct aes_crypto {
  void *read_aeskey;
  void *write_aeskey;
};

extern int aes_initialized;

int aes_create_keys(
    struct aes_key_data *R,
    int am_client,
    const char nonce_server[16],
    const char nonce_client[16],
    int client_timestamp,
    unsigned server_ip,
    unsigned short server_port,
    const unsigned char server_ipv6[16],
    unsigned client_ip,
    unsigned short client_port,
    const unsigned char client_ipv6[16],
    const aes_secret_t *key,
    const unsigned char *temp_key,
    int temp_key_len);

void *alloc_crypto_temp(int len);

enum {
  CRYPTO_TEMP_DH_PARAMS_MAGIC = 0xab45ccd3,
};

struct crypto_temp_dh_params {
  int magic;
  int dh_params_select;
  unsigned char a[256];
};

extern int dh_params_select;

int init_dh_params(void);
int dh_first_round(unsigned char g_a[256], struct crypto_temp_dh_params *dh_params);
int dh_second_round(unsigned char g_ab[256], unsigned char g_a[256], const unsigned char g_b[256]);
int dh_third_round(unsigned char g_ab[256], const unsigned char g_b[256], struct crypto_temp_dh_params *dh_params);

int32_t mtproxy_ffi_net_tcp_connections_cpu_tcp_free_connection_buffers(connection_job_t c);
int32_t mtproxy_ffi_net_tcp_connections_cpu_tcp_server_writer(connection_job_t c);
int32_t mtproxy_ffi_net_tcp_connections_cpu_tcp_server_reader(connection_job_t c);
int32_t mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_encrypt_output(connection_job_t c);
int32_t mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_decrypt_input(connection_job_t c);
int32_t mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_needed_output_bytes(connection_job_t c);
int32_t mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_encrypt_output(connection_job_t c);
int32_t mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_decrypt_input(connection_job_t c);
int32_t mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_needed_output_bytes(connection_job_t c);

#define cpu_tcp_free_connection_buffers mtproxy_ffi_net_tcp_connections_cpu_tcp_free_connection_buffers
#define cpu_tcp_server_writer mtproxy_ffi_net_tcp_connections_cpu_tcp_server_writer
#define cpu_tcp_server_reader mtproxy_ffi_net_tcp_connections_cpu_tcp_server_reader
#define cpu_tcp_aes_crypto_encrypt_output mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_encrypt_output
#define cpu_tcp_aes_crypto_decrypt_input mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_decrypt_input
#define cpu_tcp_aes_crypto_needed_output_bytes mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_needed_output_bytes
#define cpu_tcp_aes_crypto_ctr128_encrypt_output mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_encrypt_output
#define cpu_tcp_aes_crypto_ctr128_decrypt_input mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_decrypt_input
#define cpu_tcp_aes_crypto_ctr128_needed_output_bytes mtproxy_ffi_net_tcp_connections_cpu_tcp_aes_crypto_ctr128_needed_output_bytes

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

// net-msg helpers: encrypt/decrypt byte clamp.
int32_t mtproxy_ffi_net_msg_encrypt_decrypt_effective_bytes(
  int32_t requested_bytes,
  int32_t total_bytes,
  int32_t block_size
);

// common/resolver helpers: kdb state reload and gethostbyname planning.
enum { MTPROXY_FFI_RESOLVER_LOOKUP_SYSTEM_DNS = 0 };
enum { MTPROXY_FFI_RESOLVER_LOOKUP_NOT_FOUND = 1 };
enum { MTPROXY_FFI_RESOLVER_LOOKUP_HOSTS_IPV4 = 2 };
int32_t mtproxy_ffi_resolver_gethostbyname_plan(
  const char *name,
  int32_t *out_kind,
  uint32_t *out_ipv4
);

// net-stats helpers: idle percentage math extracted from net-stats.c.
double mtproxy_ffi_net_stats_recent_idle_percent(double a_idle_time, double a_idle_quotient);
double mtproxy_ffi_net_stats_average_idle_percent(double tot_idle_time, int32_t uptime);

// net-tcp-connections helpers: AES/TLS framing length helpers.
int32_t mtproxy_ffi_net_tcp_reader_skip_from_parse_result(
  int32_t parse_res,
  int32_t buffered_bytes,
  int32_t need_more_bytes,
  int32_t *out_skip_bytes
);
int32_t mtproxy_ffi_net_tcp_reader_should_continue(
  int32_t skip_bytes,
  int32_t flags,
  int32_t status_is_conn_error
);

// net-tcp-rpc-ext-server helpers: domain/random bucket hashes and hello-size profile.
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
void mtproxy_ffi_engine_enable_ipv6(void);
void mtproxy_ffi_engine_disable_ipv6(void);
int32_t mtproxy_ffi_engine_check_ipv6_enabled(void);
int32_t mtproxy_ffi_engine_check_ipv6_disabled(void);
void mtproxy_ffi_engine_enable_tcp(void);
void mtproxy_ffi_engine_disable_tcp(void);
int32_t mtproxy_ffi_engine_check_tcp_enabled(void);
int32_t mtproxy_ffi_engine_check_tcp_disabled(void);
void mtproxy_ffi_engine_enable_multithread(void);
void mtproxy_ffi_engine_disable_multithread(void);
int32_t mtproxy_ffi_engine_check_multithread_enabled(void);
int32_t mtproxy_ffi_engine_check_multithread_disabled(void);
void mtproxy_ffi_engine_enable_slave_mode(void);
void mtproxy_ffi_engine_disable_slave_mode(void);
int32_t mtproxy_ffi_engine_check_slave_mode_enabled(void);
int32_t mtproxy_ffi_engine_check_slave_mode_disabled(void);
void mtproxy_ffi_engine_set_aes_pwd_file(const char *s);
const char *mtproxy_ffi_engine_get_aes_pwd_file(void);
void mtproxy_ffi_engine_set_backlog(int32_t s);
int32_t mtproxy_ffi_engine_get_backlog(void);
void mtproxy_ffi_engine_set_required_io_threads(int32_t s);
int32_t mtproxy_ffi_engine_get_required_io_threads(void);
void mtproxy_ffi_engine_set_required_cpu_threads(int32_t s);
int32_t mtproxy_ffi_engine_get_required_cpu_threads(void);
void mtproxy_ffi_engine_set_required_tcp_cpu_threads(int32_t s);
int32_t mtproxy_ffi_engine_get_required_tcp_cpu_threads(void);
void mtproxy_ffi_engine_set_required_tcp_io_threads(int32_t s);
int32_t mtproxy_ffi_engine_get_required_tcp_io_threads(void);
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
void *mtproxy_ffi_engine_rpc_tl_aio_init_store(int32_t type, struct process_id *pid, int64_t qid);
void mtproxy_ffi_engine_rpc_register_custom_op_cb(
  uint32_t op,
  mtproxy_ffi_engine_rpc_custom_op_fn func
);
void mtproxy_ffi_engine_rpc_engine_work_rpc_req_result(void *tlio_in, void *params);
void mtproxy_ffi_engine_rpc_tl_default_act_free(struct tl_act_extra *extra);
void mtproxy_ffi_engine_rpc_tl_query_result_fun_set(
  mtproxy_ffi_engine_rpc_query_result_fn func,
  int32_t query_type_id
);
void mtproxy_ffi_engine_rpc_engine_tl_init(
  mtproxy_ffi_engine_rpc_parse_fn parse,
  mtproxy_ffi_engine_rpc_stat_fn stat,
  mtproxy_ffi_engine_rpc_get_op_fn get_op,
  double timeout
);
void mtproxy_ffi_engine_rpc_tl_engine_store_stats(void *tlio_out);
int32_t mtproxy_ffi_engine_rpc_create_query_job(
  void *job,
  struct raw_message *raw,
  void *query_header,
  double timeout,
  struct process_id *remote_pid,
  int32_t out_type,
  int32_t fd,
  int32_t generation
);
int64_t mtproxy_ffi_engine_rpc_tl_generate_next_qid(int32_t query_type_id);
int32_t mtproxy_ffi_engine_rpc_create_query_custom_job(
  void *job,
  struct raw_message *raw,
  double timeout,
  int32_t fd,
  int32_t generation
);
int32_t mtproxy_ffi_engine_rpc_default_tl_close_conn(void *c, int32_t who);
int32_t mtproxy_ffi_engine_rpc_default_tl_tcp_rpcs_execute(
  void *c,
  int32_t op,
  struct raw_message *raw
);
int32_t mtproxy_ffi_engine_rpc_tl_store_stats(
  void *tlio_out,
  const char *s,
  int32_t raw
);

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
void mtproxy_ffi_mtproto_update_local_stats_copy(void *s);
void mtproxy_ffi_mtproto_precise_cron(void);
void mtproxy_ffi_mtproto_on_child_termination_handler(void);
int32_t mtproxy_ffi_mtproto_data_received(void *c, int32_t bytes_received);
int32_t mtproxy_ffi_mtproto_data_sent(void *c, int32_t bytes_sent);
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
int32_t mtproxy_ffi_mtproto_ext_rpc_ready(void *c);
int32_t mtproxy_ffi_mtproto_ext_rpc_close(void *c, int32_t who);
int32_t mtproxy_ffi_mtproto_http_alarm(void *c);
int32_t mtproxy_ffi_mtproto_http_close(void *c, int32_t who);
int32_t mtproxy_ffi_mtproto_f_parse_option(int32_t val);
void mtproxy_ffi_mtproto_mtfront_prepare_parse_options(void);
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
int32_t mtproxy_ffi_mtproto_proxy_main(
  int32_t argc,
  const char *const *argv
);
int32_t mtproxy_ffi_mtproto_legacy_main(
  int32_t argc,
  char **argv
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
