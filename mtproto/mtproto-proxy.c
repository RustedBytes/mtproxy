/*
    This file is part of MTProto-proxy

    MTProto-proxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    MTProto-Server is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MTProto-Server.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2012-2018 Nikolai Durov
              2012-2014 Andrey Lopatin
              2014-2018 Telegram Messenger Inc
*/
#include "net/net-rpc-flags.h"
#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/rust-ffi-bridge.h"
#include "common/tl-parse.h"
#include "engine/engine-net.h"
#include "engine/engine.h"
#include "kprintf.h"
#include "mtproto-common.h"
#include "mtproto-config.h"
#include "net/net-crypto-aes.h"
#include "net/net-crypto-dh.h"
#include "net/net-events.h"
#include "net/net-http-server.h"
#include "net/net-rpc-targets.h"
#include "net/net-tcp-rpc-client.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-tcp-rpc-server.h"
#include "precise-time.h"
#include "resolver.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"
#include "server-functions.h"

static const char VersionStr[] = "mtproxy-0.02";
static const char CommitStr[] =
#ifdef COMMIT
    COMMIT;
#else
    "unknown";
#endif

const char FullVersionStr[] =
    "mtproxy-0.02 compiled at " __DATE__ " " __TIME__ " by gcc " __VERSION__ " "
#ifdef __LP64__
    "64-bit"
#else
    "32-bit"
#endif
    " after commit "
#ifdef COMMIT
    COMMIT;
#else
    "unknown";
#endif

// #define DEFAULT_OUTBOUND_CONNECTION_CREATION_RATE	1000000

enum mtproxy_constants {
  EXT_CONN_TABLE_SIZE = 1 << 22,
  EXT_CONN_HASH_SHIFT = 20,
  EXT_CONN_HASH_SIZE = 1 << EXT_CONN_HASH_SHIFT,
  MAX_HTTP_LISTEN_PORTS = 128,
  RESPONSE_FAIL_TIMEOUT = 5,
  CONNECT_TIMEOUT = 3,
  MAX_POST_SIZE = 262144 * 4 - 4096,
  DEFAULT_WINDOW_CLAMP = 131072,
  MAX_CONNECTION_BUFFER_SPACE = 1 << 25,
  PROXY_MODE_OUT = 2,
  TL_HTTP_QUERY_INFO = (int)0xd45ab381u,
  TL_PROXY_TAG = (int)0xdb1e26aeu,
  STATS_BUFF_SIZE = 1 << 20,
  DEFAULT_CFG_MIN_CONNECTIONS = 4,
  DEFAULT_CFG_MAX_CONNECTIONS = 8,
  MAX_WORKERS = 256,
};

static const double default_ping_interval = 5.0;
double ping_interval = 5.0;
int window_clamp;

int proxy_mode;

conn_type_t ct_http_server_mtfront, ct_tcp_rpc_ext_server_mtfront,
    ct_tcp_rpc_server_mtfront;

long long connections_failed_lru, connections_failed_flood;
long long api_invoke_requests;

volatile int sigpoll_cnt;

int stats_buff_len;
char stats_buff[STATS_BUFF_SIZE];

// current HTTP query headers
char cur_http_origin[1024], cur_http_referer[1024], cur_http_user_agent[1024];
int cur_http_origin_len, cur_http_referer_len, cur_http_user_agent_len;

int check_conn_buffers(connection_job_t c);
void lru_insert_conn(connection_job_t c);

/*
 *
 *	CONFIGURATION PARSER SETUP
 *
 */

int default_cfg_min_connections = DEFAULT_CFG_MIN_CONNECTIONS;
int default_cfg_max_connections = DEFAULT_CFG_MAX_CONNECTIONS;

struct tcp_rpc_client_functions mtfront_rpc_client;

conn_type_t ct_tcp_rpc_client_mtfront;

struct conn_target_info default_cfg_ct = {
    .min_connections = DEFAULT_CFG_MIN_CONNECTIONS,
    .max_connections = DEFAULT_CFG_MAX_CONNECTIONS,
    .type = &ct_tcp_rpc_client_mtfront,
    .extra = (void *)&mtfront_rpc_client,
    .reconnect_timeout = 17};

/*
 *
 *		EXTERNAL CONNECTIONS TABLE
 *
 */

typedef mtproxy_ffi_mtproto_ext_connection_t ext_connection_t;

static inline void check_engine_class(void) { check_thread_class(JC_ENGINE); }

static inline void ext_conn_fetch_counts(long long *current,
                                         long long *created) {
  int64_t cur = 0;
  int64_t cre = 0;
  int32_t rc = mtproxy_ffi_mtproto_ext_conn_counts(&cur, &cre);
  if (rc < 0) {
    *current = 0;
    *created = 0;
    return;
  }
  *current = cur;
  *created = cre;
}

static inline int get_ext_connection_by_in_fd(int in_fd,
                                              ext_connection_t *Ex) {
  check_engine_class();
  assert((unsigned)in_fd < MAX_CONNECTIONS);
  int32_t rc = mtproxy_ffi_mtproto_ext_conn_get_by_in_fd(in_fd, Ex);
  assert(rc >= 0);
  return rc > 0;
}

static inline int
find_ext_connection_by_out_conn_id(long long out_conn_id, ext_connection_t *Ex) {
  check_engine_class();
  int32_t rc = mtproxy_ffi_mtproto_ext_conn_get_by_out_conn_id(out_conn_id, Ex);
  assert(rc >= 0);
  return rc > 0;
}

static int _notify_remote_closed(JOB_REF_ARG(C), long long out_conn_id);

static void notify_ext_connection(const ext_connection_t *Ex,
                                  int send_notifications) {
  assert(Ex);
  assert(Ex->out_conn_id);
  if (Ex->out_fd) {
    assert((unsigned)Ex->out_fd < MAX_CONNECTIONS);
    if (send_notifications & 1) {
      connection_job_t CO =
          connection_get_by_fd_generation(Ex->out_fd, Ex->out_gen);
      if (CO) {
        _notify_remote_closed(JOB_REF_PASS(CO), Ex->out_conn_id);
      }
    }
  }
  if (Ex->in_fd) {
    assert((unsigned)Ex->in_fd < MAX_CONNECTIONS);
    if (send_notifications & 2) {
      connection_job_t CI =
          connection_get_by_fd_generation(Ex->in_fd, Ex->in_gen);
      if (Ex->in_conn_id) {
        assert(0);
      } else {
        if (CI) {
          fail_connection(CI, -33);
          job_decref(JOB_REF_PASS(CI));
        }
      }
    }
  }
}

void remove_ext_connection(const ext_connection_t *Ex, int send_notifications) {
  assert(Ex);
  assert(Ex->out_conn_id);
  ext_connection_t cur;
  if (!find_ext_connection_by_out_conn_id(Ex->out_conn_id, &cur)) {
    return;
  }
  notify_ext_connection(&cur, send_notifications);
  ext_connection_t removed = {0};
  int32_t rc =
      mtproxy_ffi_mtproto_ext_conn_remove_by_out_conn_id(cur.out_conn_id,
                                                         &removed);
  assert(rc >= 0);
}

/*
 *
 *	MULTIPROCESS STATISTICS
 *
 */

struct worker_stats {
  int cnt;
  int updated_at;

  struct buffers_stat bufs;
  struct connections_stat conn;
  int allocated_aes_crypto, allocated_aes_crypto_temp;
  long long tot_dh_rounds[3];

  int ev_heap_size;
  int http_connections;

  long long get_queries;
  int pending_http_queries;

  long long accept_calls_failed, accept_nonblock_set_failed,
      accept_connection_limit_failed, accept_rate_limit_failed,
      accept_init_accepted_failed;

  long long active_rpcs, active_rpcs_created;
  long long rpc_dropped_running, rpc_dropped_answers;
  long long tot_forwarded_queries, expired_forwarded_queries;
  long long tot_forwarded_responses;
  long long dropped_queries, dropped_responses;
  long long tot_forwarded_simple_acks, dropped_simple_acks;
  long long mtproto_proxy_errors;

  long long connections_failed_lru, connections_failed_flood;

  long long ext_connections, ext_connections_created;
  long long http_queries, http_bad_headers;
};

struct worker_stats *WStats, SumStats;
int worker_id, workers, slave_mode, parent_pid;
int pids[MAX_WORKERS];

long long get_queries;
int pending_http_queries;

long long active_rpcs, active_rpcs_created;
long long rpc_dropped_running, rpc_dropped_answers;
long long tot_forwarded_queries, expired_forwarded_queries, dropped_queries;
long long tot_forwarded_responses, dropped_responses;
long long tot_forwarded_simple_acks, dropped_simple_acks;
long long mtproto_proxy_errors;

char proxy_tag[16];
int proxy_tag_set;

static void update_local_stats_copy(struct worker_stats *S) {
  mtproxy_ffi_mtproto_update_local_stats_copy(S);
}

void add_stats(struct worker_stats *W) {
  mtproxy_ffi_mtproto_add_stats(W);
}

void update_local_stats(void) {
  if (!slave_mode) {
    return;
  }
  update_local_stats_copy(WStats + worker_id * 2);
  update_local_stats_copy(WStats + worker_id * 2 + 1);
}

void compute_stats_sum(void) {
  if (!workers) {
    return;
  }
  memset(&SumStats, 0, sizeof(SumStats));
  int i;
  for (i = 0; i < workers; i++) {
    static struct worker_stats W;
    struct worker_stats *F;
    int s_cnt;
    do {
      F = WStats + i * 2;
      do {
        barrier();
        s_cnt = (++F)->cnt;
        if (!(s_cnt & 1)) {
          break;
        }
        s_cnt = (--F)->cnt;
      } while (s_cnt & 1);
      barrier();
      memcpy(&W, F, sizeof(W));
      barrier();
    } while (s_cnt != F->cnt);
    add_stats(&W);
  }
}

/*
 *
 *		SERVER
 *
 */

void mtfront_prepare_stats(stats_buffer_t *sb) {
  mtproxy_ffi_mtproto_mtfront_prepare_stats(sb);
}

/*
 *
 *      JOB UTILS
 *
 */

typedef int (*job_callback_func_t)(void *data, int len);
void schedule_job_callback(int context, job_callback_func_t func, void *data,
                           int len);

struct job_callback_info {
  job_callback_func_t func;
  void *data[0];
};

int callback_job_run(job_t job, int op, struct job_thread *JT) {
  struct job_callback_info *D = (struct job_callback_info *)(job->j_custom);
  switch (op) {
  case JS_RUN:
    return D->func(D->data, job->j_custom_bytes -
                                offsetof(struct job_callback_info, data));
    // return JOB_COMPLETED;
  case JS_FINISH:
    return job_free(JOB_REF_PASS(job));
  default:
    assert(0);
  }
}

void schedule_job_callback(int context, job_callback_func_t func, void *data,
                           int len) {
  job_t job = create_async_job(
      callback_job_run,
      JSP_PARENT_RWE | JSC_ALLOW(context, JS_RUN) | JSIG_FAST(JS_FINISH), -2,
      offsetof(struct job_callback_info, data) + len, 0, JOB_REF_NULL);
  assert(job);
  struct job_callback_info *D = (struct job_callback_info *)(job->j_custom);
  D->func = func;
  memcpy(D->data, data, len);
  schedule_job(JOB_REF_PASS(job));
}

/*
 *
 *	RPC CLIENT
 *
 */

int client_send_message(JOB_REF_ARG(C), long long in_conn_id,
                        struct tl_in_state *tlio_in, int flags);

int mtfront_client_ready(connection_job_t C);
int mtfront_client_close(connection_job_t C, int who);
int rpcc_execute(connection_job_t C, int op, struct raw_message *msg);
int tcp_rpcc_check_ready(connection_job_t C);

struct tcp_rpc_client_functions mtfront_rpc_client = {
    .execute = rpcc_execute,
    .check_ready = tcp_rpcc_default_check_ready,
    .flush_packet = tcp_rpc_flush_packet,
    .rpc_check_perm = tcp_rpcc_default_check_perm,
    .rpc_init_crypto = tcp_rpcc_init_crypto,
    .rpc_start_crypto = tcp_rpcc_start_crypto,
    .rpc_ready = mtfront_client_ready,
    .rpc_close = mtfront_client_close};

int rpcc_exists;

static int _notify_remote_closed(JOB_REF_ARG(C), long long out_conn_id) {
  {
    struct tl_out_state *tlio_out = tl_out_state_alloc();
    tls_init_tcp_raw_msg(tlio_out, JOB_REF_PASS(C), 0);
    tl_store_int(RPC_CLOSE_CONN);
    tl_store_long(out_conn_id);
    tl_store_end_ext(0);
    tl_out_state_free(tlio_out);
  }
  return 1;
}

void push_rpc_confirmation(JOB_REF_ARG(C), int confirm) {
  mtproxy_ffi_mtproto_push_rpc_confirmation_runtime(C_tag_int, C, confirm);
}

struct client_packet_info {
  struct event_timer ev;
  struct raw_message msg;
  connection_job_t conn;
};

extern int32_t mtproxy_ffi_mtproto_process_client_packet_runtime(void *tlio_in,
                                                                  void *c);

int process_client_packet(struct tl_in_state *tlio_in, connection_job_t C) {
  return mtproxy_ffi_mtproto_process_client_packet_runtime(tlio_in, C);
}

int client_packet_job_run(job_t job, int op, struct job_thread *JT) {
  return mtproxy_ffi_mtproto_client_packet_job_run(job, op, JT);
}

int rpcc_execute(connection_job_t C, int op, struct raw_message *msg) {
  vkprintf(2, "rpcc_execute: fd=%d, op=%08x, len=%d\n", CONN_INFO(C)->fd, op,
           msg->total_bytes);
  CONN_INFO(C)->last_response_time = precise_now;

  switch (op) {
  case RPC_PONG:
    break;
  case RPC_PROXY_ANS:
  case RPC_SIMPLE_ACK:
  case RPC_CLOSE_EXT: {
    job_t job = create_async_job(
        client_packet_job_run,
        JSP_PARENT_RWE | JSC_ALLOW(JC_ENGINE, JS_RUN) |
            JSC_ALLOW(JC_ENGINE, JS_ABORT) | JSC_ALLOW(JC_ENGINE, JS_ALARM) |
            JSC_ALLOW(JC_ENGINE, JS_FINISH),
        -2, sizeof(struct client_packet_info), JT_HAVE_TIMER, JOB_REF_NULL);
    struct client_packet_info *D = (struct client_packet_info *)(job->j_custom);
    D->msg = *msg;
    D->conn = job_incref(C);
    schedule_job(JOB_REF_PASS(job));
    return 1;
  }
  default:
    vkprintf(1, "unknown RPC operation %08x, ignoring\n", op);
  }
  return 0;
}

static inline int get_conn_tag(connection_job_t C) {
  int generation = CONN_INFO(C)->generation;
  int tag = mtproxy_ffi_mtproto_conn_tag(generation);
  assert((unsigned)tag > 0 && (unsigned)tag <= 0x1000000u);
  return tag;
}

int mtfront_client_ready(connection_job_t C) {
  check_engine_class();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert((unsigned)fd < MAX_CONNECTIONS);
  assert(!D->extra_int);
  D->extra_int = get_conn_tag(C);
  vkprintf(1, "Connected to RPC Middle-End (fd=%d)\n", fd);
  rpcc_exists++;

  CONN_INFO(C)->last_response_time = precise_now;
  return 0;
}

int mtfront_client_close(connection_job_t C, int who) {
  check_engine_class();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert((unsigned)fd < MAX_CONNECTIONS);
  vkprintf(1, "Disconnected from RPC Middle-End (fd=%d)\n", fd);
  if (D->extra_int) {
    assert(D->extra_int == get_conn_tag(C));
    ext_connection_t Ex;
    for (;;) {
      int32_t rc = mtproxy_ffi_mtproto_ext_conn_remove_any_by_out_fd(fd, &Ex);
      assert(rc >= 0);
      if (rc <= 0) {
        break;
      }
      notify_ext_connection(&Ex, 2);
    }
  }
  D->extra_int = 0;
  return 0;
}

/*
 *
 *	HTTP INTERFACE
 *
 */

int hts_execute(connection_job_t C, struct raw_message *msg, int op);
int mtproto_http_alarm(connection_job_t C);
int mtproto_http_close(connection_job_t C, int who);

int hts_stats_execute(connection_job_t C, struct raw_message *msg, int op);

struct http_server_functions http_methods = {.execute = hts_execute,
                                             .ht_alarm = mtproto_http_alarm,
                                             .ht_close = mtproto_http_close};

struct http_server_functions http_methods_stats = {.execute =
                                                       hts_stats_execute};

int ext_rpcs_execute(connection_job_t C, int op, struct raw_message *msg);

int mtproto_ext_rpc_ready(connection_job_t C);
int mtproto_ext_rpc_close(connection_job_t C, int who);

struct tcp_rpc_server_functions ext_rpc_methods = {
    .execute = ext_rpcs_execute,
    .check_ready = server_check_ready,
    .flush_packet = tcp_rpc_flush_packet,
    .rpc_ready = mtproto_ext_rpc_ready,
    .rpc_close = mtproto_ext_rpc_close,
    //.http_fallback_type = &ct_http_server_mtfront,
    //.http_fallback_extra = &http_methods,
    .max_packet_len = MAX_POST_SIZE,
};

int mtproto_proxy_rpc_ready(connection_job_t C);
int mtproto_proxy_rpc_close(connection_job_t C, int who);

// ENGINE context
int do_close_in_ext_conn(void *_data, int s_len) {
  assert(s_len == 4);
  int fd = *(int *)_data;
  ext_connection_t Ex;
  if (get_ext_connection_by_in_fd(fd, &Ex)) {
    remove_ext_connection(&Ex, 1);
  }
  return JOB_COMPLETED;
}

// NET_CPU context
int mtproto_http_close(connection_job_t C, int who) {
  assert((unsigned)CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf(3, "http connection closing (%d) by %d, %d queries pending\n",
           CONN_INFO(C)->fd, who, CONN_INFO(C)->pending_queries);
  if (CONN_INFO(C)->pending_queries) {
    assert(CONN_INFO(C)->pending_queries == 1);
    pending_http_queries--;
    CONN_INFO(C)->pending_queries = 0;
  }
  schedule_job_callback(JC_ENGINE, do_close_in_ext_conn, &CONN_INFO(C)->fd, 4);
  return 0;
}

int mtproto_ext_rpc_ready(connection_job_t C) {
  assert((unsigned)CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf(1, "Client connected to proxy (fd=%d, %s:%d -> %s:%d)\n",
           CONN_INFO(C)->fd, show_remote_ip(C), CONN_INFO(C)->remote_port,
           show_our_ip(C), CONN_INFO(C)->our_port);
  vkprintf(3, "ext_rpc connection ready (%d)\n", CONN_INFO(C)->fd);
  lru_insert_conn(C);
  return 0;
}

int mtproto_ext_rpc_close(connection_job_t C, int who) {
  assert((unsigned)CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf(3, "ext_rpc connection closing (%d) by %d\n", CONN_INFO(C)->fd, who);
  ext_connection_t Ex;
  if (get_ext_connection_by_in_fd(CONN_INFO(C)->fd, &Ex)) {
    remove_ext_connection(&Ex, 1);
  }
  return 0;
}

int mtproto_proxy_rpc_ready(connection_job_t C) {
  check_engine_class();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert((unsigned)fd < MAX_CONNECTIONS);
  vkprintf(3, "proxy_rpc connection ready (%d)\n", fd);
  assert(!D->extra_int);
  D->extra_int = -get_conn_tag(C);
  lru_insert_conn(C);
  return 0;
}

int mtproto_proxy_rpc_close(connection_job_t C, int who) {
  check_engine_class();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert((unsigned)fd < MAX_CONNECTIONS);
  vkprintf(3, "proxy_rpc connection closing (%d) by %d\n", fd, who);
  if (D->extra_int) {
    assert(D->extra_int == -get_conn_tag(C));
    ext_connection_t Ex;
    for (;;) {
      int32_t rc = mtproxy_ffi_mtproto_ext_conn_remove_any_by_in_fd(fd, &Ex);
      assert(rc >= 0);
      if (rc <= 0) {
        break;
      }
      notify_ext_connection(&Ex, 1);
    }
  }
  D->extra_int = 0;
  return 0;
}

char mtproto_cors_http_headers[] =
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: origin, content-type\r\n"
    "Access-Control-Max-Age: 1728000\r\n";

extern int32_t mtproxy_ffi_mtproto_forward_tcp_query(
    void *tlio_in, void *c, void *target, int32_t flags, int64_t auth_key_id,
    const int32_t *remote_ip_port, const int32_t *our_ip_port);
extern int32_t mtproxy_ffi_mtproto_forward_mtproto_packet(
    void *tlio_in, void *c, int32_t len, const int32_t *remote_ip_port,
    int32_t rpc_flags);
extern void *mtproxy_ffi_mtproto_choose_proxy_target(int32_t target_dc);

int forward_mtproto_packet(struct tl_in_state *tlio_in, connection_job_t C,
                           int len, int remote_ip_port[5], int rpc_flags);
int forward_tcp_query(struct tl_in_state *tlio_in, connection_job_t C,
                      conn_target_job_t S, int flags, long long auth_key_id,
                      int remote_ip_port[5], int our_ip_port[5]);

struct http_query_info {
  struct event_timer ev;
  connection_job_t conn;
  struct raw_message msg;
  int conn_fd;
  int conn_generation;
  int flags;
  int query_type;
  int header_size;
  int data_size;
  int first_line_size;
  int host_offset;
  int host_size;
  int uri_offset;
  int uri_size;
  char header[0];
};

int process_http_query(struct tl_in_state *tlio_in, job_t HQJ) {
  return mtproxy_ffi_mtproto_process_http_query(tlio_in, HQJ);
}

int http_query_job_run(job_t job, int op, struct job_thread *JT) {
  return mtproxy_ffi_mtproto_http_query_job_run(job, op, JT);
}

int hts_stats_execute(connection_job_t c, struct raw_message *msg, int op) {
  return mtproxy_ffi_mtproto_hts_stats_execute(c, msg, op);
}

// NET-CPU context
int hts_execute(connection_job_t c, struct raw_message *msg, int op) {
  return mtproxy_ffi_mtproto_hts_execute(c, msg, op);
}

struct rpcs_exec_data {
  struct raw_message msg;
  connection_job_t conn;
  int op;
  int rpc_flags;
};

int do_rpcs_execute(void *_data, int s_len) {
  struct rpcs_exec_data *data = _data;
  assert(s_len == sizeof(struct rpcs_exec_data));
  assert(data);

  lru_insert_conn(data->conn);

  int len = data->msg.total_bytes;
  struct tl_in_state *tlio_in = tl_in_state_alloc();
  tlf_init_raw_message(tlio_in, &data->msg, len, 0);

  int res =
      forward_mtproto_packet(tlio_in, data->conn, len, 0, data->rpc_flags);
  tl_in_state_free(tlio_in);
  job_decref(JOB_REF_PASS(data->conn));

  if (!res) {
    vkprintf(1, "ext_rpcs_execute: cannot forward mtproto packet\n");
  }
  return JOB_COMPLETED;
}

int ext_rpcs_execute(connection_job_t c, int op, struct raw_message *msg) {
  int len = msg->total_bytes;

  vkprintf(2, "ext_rpcs_execute: fd=%d, op=%08x, len=%d\n", CONN_INFO(c)->fd,
           op, len);

  if (len > MAX_POST_SIZE) {
    vkprintf(1, "ext_rpcs_execute: packet too long (%d bytes), skipping\n",
             len);
    return SKIP_ALL_BYTES;
  }

  // lru_insert_conn (c); // dangerous in net-cpu context
  if (check_conn_buffers(c) < 0) {
    return SKIP_ALL_BYTES;
  }

  struct rpcs_exec_data data;
  rwm_move(&data.msg, msg);
  data.conn = job_incref(c);
  data.rpc_flags =
      TCP_RPC_DATA(c)->flags &
      (RPC_F_QUICKACK | RPC_F_DROPPED | RPC_F_COMPACT_MEDIUM | RPC_F_EXTMODE3);

  schedule_job_callback(JC_ENGINE, do_rpcs_execute, &data,
                        sizeof(struct rpcs_exec_data));

  return 1;
}

// NET-CPU context
int mtproto_http_alarm(connection_job_t C) {
  vkprintf(2, "http_alarm() for connection %d\n", CONN_INFO(C)->fd);

  assert(CONN_INFO(C)->status == conn_working);
  HTS_DATA(C)->query_flags &= ~QF_KEEPALIVE;

  write_http_error(C, 500);

  if (CONN_INFO(C)->pending_queries) {
    assert(CONN_INFO(C)->pending_queries == 1);
    --pending_http_queries;
    CONN_INFO(C)->pending_queries = 0;
  }

  HTS_DATA(C)->parse_state = -1;
  connection_write_close(C);

  return 0;
}

// NET-CPU context
int finish_postponed_http_response(void *_data, int len) {
  assert(len == sizeof(connection_job_t));
  connection_job_t C = *(connection_job_t *)_data;
  if (!check_job_completion(C)) {
    assert(CONN_INFO(C)->pending_queries >= 0);
    assert(CONN_INFO(C)->pending_queries > 0);
    assert(CONN_INFO(C)->pending_queries == 1);
    CONN_INFO(C)->pending_queries = 0;
    --pending_http_queries;
    // check_conn_buffers (C);
    http_flush(C, 0);
  } else {
    assert(!CONN_INFO(C)->pending_queries);
  }
  job_decref(JOB_REF_PASS(C));
  return JOB_COMPLETED;
}

// ENGINE context
// problem: mtproto_http_alarm() may be invoked in parallel in NET-CPU context
int http_send_message(JOB_REF_ARG(C), struct tl_in_state *tlio_in, int flags) {
  return mtproxy_ffi_mtproto_http_send_message(C, tlio_in, flags);
}

int client_send_message(JOB_REF_ARG(C), long long in_conn_id,
                        struct tl_in_state *tlio_in, int flags) {
  return mtproxy_ffi_mtproto_client_send_message_runtime(
      C_tag_int, C, in_conn_id, tlio_in, flags);
}

/* ------------- process normal (encrypted) packet ----------------- */

// connection_job_t get_target_connection (conn_target_job_t S, int rotate);

conn_target_job_t choose_proxy_target(int target_dc) {
  return mtproxy_ffi_mtproto_choose_proxy_target(target_dc);
}

int forward_mtproto_packet(struct tl_in_state *tlio_in, connection_job_t C,
                           int len, int remote_ip_port[5], int rpc_flags) {
  return mtproxy_ffi_mtproto_forward_mtproto_packet(tlio_in, C, len,
                                                    remote_ip_port, rpc_flags);
}

/*
 *
 *	QUERY FORWARDING
 *
 */

/* ----------- query rpc forwarding ------------ */

int forward_tcp_query(struct tl_in_state *tlio_in, connection_job_t c,
                      conn_target_job_t S, int flags, long long auth_key_id,
                      int remote_ip_port[5], int our_ip_port[5]) {
  return mtproxy_ffi_mtproto_forward_tcp_query(tlio_in, c, S, flags, auth_key_id,
                                               remote_ip_port, our_ip_port);
}

/* -------------------------- EXTERFACE ---------------------------- */

struct tl_act_extra *mtfront_parse_function(struct tl_in_state *tlio_in,
                                            long long actor_id) {
  return (struct tl_act_extra *)mtproxy_ffi_mtproto_mtfront_parse_function_runtime(
      tlio_in, actor_id);
}

/* ------------------------ FLOOD CONTROL -------------------------- */

void lru_delete_conn(connection_job_t c) {
  int32_t rc = mtproxy_ffi_mtproto_ext_conn_lru_delete(CONN_INFO(c)->fd);
  assert(rc >= 0);
}

void lru_insert_conn(connection_job_t c) {
  int32_t rc = mtproxy_ffi_mtproto_ext_conn_lru_insert(CONN_INFO(c)->fd,
                                                        CONN_INFO(c)->generation);
  assert(rc >= 0);
}

void check_all_conn_buffers(void) {
  mtproxy_ffi_mtproto_check_all_conn_buffers();
}

int check_conn_buffers(connection_job_t c) {
  int tot_used_bytes =
      CONN_INFO(c)->in.total_bytes + CONN_INFO(c)->in_u.total_bytes +
      CONN_INFO(c)->out.total_bytes + CONN_INFO(c)->out_p.total_bytes;
  if (tot_used_bytes > MAX_CONNECTION_BUFFER_SPACE) {
    vkprintf(2,
             "check_conn_buffers(): closing connection %d because of %d buffer "
             "bytes used (%d max)\n",
             CONN_INFO(c)->fd, tot_used_bytes, MAX_CONNECTION_BUFFER_SPACE);
    fail_connection(c, -429);
    ++connections_failed_flood;
    return -1;
  }
  return 0;
}

// invoked in NET-CPU context!
int mtfront_data_received(connection_job_t c, int bytes_received) {
  // check_conn_buffers (c);
  return 0;
}

// invoked in NET-CPU context!
int mtfront_data_sent(connection_job_t c, int bytes_sent) {
  // lru_insert_conn (c);
  return 0;
}

void init_ct_server_mtfront(void) {
  assert(check_conn_functions(&ct_http_server, 1) >= 0);
  memcpy(&ct_http_server_mtfront, &ct_http_server, sizeof(conn_type_t));
  memcpy(&ct_tcp_rpc_ext_server_mtfront, &ct_tcp_rpc_ext_server,
         sizeof(conn_type_t));
  memcpy(&ct_tcp_rpc_server_mtfront, &ct_tcp_rpc_server, sizeof(conn_type_t));
  memcpy(&ct_tcp_rpc_client_mtfront, &ct_tcp_rpc_client, sizeof(conn_type_t));
  ct_http_server_mtfront.data_received = &mtfront_data_received;
  ct_tcp_rpc_ext_server_mtfront.data_received = &mtfront_data_received;
  ct_tcp_rpc_server_mtfront.data_received = &mtfront_data_received;
  ct_http_server_mtfront.data_sent = &mtfront_data_sent;
  ct_tcp_rpc_ext_server_mtfront.data_sent = &mtfront_data_sent;
  ct_tcp_rpc_server_mtfront.data_sent = &mtfront_data_sent;
}

/*
 *
 *	PARSE ARGS & INITIALIZATION
 *
 */

static void check_children_dead(void) {
  mtproxy_ffi_mtproto_check_children_dead();
}

static void kill_children(int signal) {
  int i;
  assert(workers);
  for (i = 0; i < workers; i++) {
    if (pids[i]) {
      kill(pids[i], signal);
    }
  }
}

// SIGCHLD
void on_child_termination(void) {}

void check_children_status(void) {
  mtproxy_ffi_mtproto_check_children_status();
}

void check_special_connections_overflow(void) {
  if (max_special_connections && !slave_mode) {
    int max_user_conn = workers ? SumStats.conn.max_special_connections
                                : max_special_connections;
    int cur_user_conn = workers ? SumStats.conn.active_special_connections
                                : active_special_connections;
    if (cur_user_conn * 10 > max_user_conn * 9) {
      vkprintf(0, "CRITICAL: used %d user connections out of %d\n",
               cur_user_conn, max_user_conn);
    }
  }
}

void cron(void) {
  check_children_status();
  compute_stats_sum();
  check_special_connections_overflow();
  check_all_conn_buffers();
}

int sfd;
int http_ports_num;
int http_sfd[MAX_HTTP_LISTEN_PORTS], http_port[MAX_HTTP_LISTEN_PORTS];
int domain_count;
int secret_count;

// static double next_create_outbound;
// int outbound_connections_per_second =
// DEFAULT_OUTBOUND_CONNECTION_CREATION_RATE;

void mtfront_pre_loop(void) {
  mtproxy_ffi_mtproto_mtfront_pre_loop();
}

void precise_cron(void) { update_local_stats(); }

void mtfront_sigusr1_handler(void) {
  reopen_logs_ext(slave_mode);
  if (workers) {
    kill_children(SIGUSR1);
  }
}

/*
 *
 *		MAIN
 *
 */

void usage(void) {
  printf("usage: %s [-v] [-6] [-p<port>] [-H<http-port>{,<http-port>}] "
         "[-M<workers>] [-u<username>] [-b<backlog>] [-c<max-conn>] "
         "[-l<log-name>] [-W<window-size>] <config-file>\n",
         progname);
  printf("%s\n", FullVersionStr);
  printf("\tSimple MT-Proto proxy\n");
  parse_usage();
  exit(2);
}

server_functions_t mtproto_front_functions;
int f_parse_option(int val) {
  return mtproxy_ffi_mtproto_f_parse_option(val);
}

void mtfront_prepare_parse_options(void) {
  parse_option("http-stats", no_argument, 0, 2000,
               "allow http server to answer on stats queries");
  parse_option("mtproto-secret", required_argument, 0, 'S',
               "16-byte secret in hex mode");
  parse_option("proxy-tag", required_argument, 0, 'P',
               "16-byte proxy tag in hex mode to be passed along with all "
               "forwarded queries");
  parse_option("domain", required_argument, 0, 'D',
               "adds allowed domain for TLS-transport mode, disables other "
               "transports; can be specified more than once");
  parse_option("max-special-connections", required_argument, 0, 'C',
               "sets maximal number of accepted client connections per worker");
  parse_option("window-clamp", required_argument, 0, 'W',
               "sets window clamp for client TCP connections");
  parse_option("http-ports", required_argument, 0, 'H',
               "comma-separated list of client (HTTP) ports to listen");
  // parse_option ("outbound-connections-ps", required_argument, 0, 'o', "limits
  // creation rate of outbound connections to mtproto-servers (default %d)",
  // DEFAULT_OUTBOUND_CONNECTION_CREATION_RATE);
  parse_option("slaves", required_argument, 0, 'M',
               "spawn several slave workers; not recommended for TLS-transport "
               "mode for better replay protection");
  parse_option(
      "ping-interval", required_argument, 0, 'T',
      "sets ping interval in second for local TCP connections (default %.3lf)",
      default_ping_interval);
}

void mtfront_parse_extra_args(int argc, char *argv[]) {
  if (argc != 1) {
    usage();
    exit(2);
  }
  config_filename = argv[0];
  vkprintf(0, "config_filename = '%s'\n", config_filename);
}

// executed BEFORE dropping privileges
void mtfront_pre_init(void) {
  mtproxy_ffi_mtproto_mtfront_pre_init();
}

void mtfront_pre_start(void) {
  int res = mtproxy_ffi_mtproto_cfg_do_reload_config(0x17);

  if (res < 0) {
    fprintf(stderr, "config check failed! (code %d)\n", res);
    exit(-res);
  }

  assert(CurConf->have_proxy);

  proxy_mode |= PROXY_MODE_OUT;
  mtfront_rpc_client.mode_flags |= TCP_RPC_IGNORE_PID;
  ct_tcp_rpc_client_mtfront.flags |= C_EXTERNAL;

  assert(proxy_mode == PROXY_MODE_OUT);
}

void mtfront_on_exit(void) {
  if (workers) {
    if (signal_check_pending(SIGTERM)) {
      kill_children(SIGTERM);
    }
    check_children_dead();
  }
}

server_functions_t mtproto_front_functions = {
    .default_modules_disabled = 0,
    .cron = cron,
    .precise_cron = precise_cron,
    .pre_init = mtfront_pre_init,
    .pre_start = mtfront_pre_start,
    .pre_loop = mtfront_pre_loop,
    .on_exit = mtfront_on_exit,
    .prepare_stats = mtfront_prepare_stats,
    .parse_option = f_parse_option,
    .prepare_parse_options = mtfront_prepare_parse_options,
    .parse_extra_args = mtfront_parse_extra_args,
    .epoll_timeout = 1,
    .FullVersionStr = FullVersionStr,
    .ShortVersionStr = "mtproxy",
    .parse_function = mtfront_parse_function,
    .flags = ENGINE_NO_PORT
    //.http_functions = &http_methods_stats
};

int main(int argc, char *argv[]) {
  mtproto_front_functions.allowed_signals |= SIG2INT(SIGCHLD);
  mtproto_front_functions.signal_handlers[SIGCHLD] = on_child_termination;
  mtproto_front_functions.signal_handlers[SIGUSR1] = mtfront_sigusr1_handler;
  return default_main(&mtproto_front_functions, argc, argv);
}
