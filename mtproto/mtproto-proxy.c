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

#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/tl-parse.h"
#include "engine/engine-net.h"
#include "engine/engine.h"
#include "kprintf.h"
#include "mtproto-config.h"
#include "net/net-http-server.h"
#include "net/net-tcp-rpc-client.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-tcp-rpc-server.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

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

void remove_ext_connection(const ext_connection_t *Ex, int send_notifications) {
  check_engine_class();
  mtproxy_ffi_mtproto_remove_ext_connection_runtime(Ex, send_notifications);
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
  mtproxy_ffi_mtproto_compute_stats_sum();
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
  return mtproxy_ffi_mtproto_callback_job_run(job, op, JT);
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
  return mtproxy_ffi_mtproto_rpcc_execute(C, op, msg);
}

int mtfront_client_ready(connection_job_t C) {
  check_engine_class();
  return mtproxy_ffi_mtproto_mtfront_client_ready(C);
}

int mtfront_client_close(connection_job_t C, int who) {
  check_engine_class();
  return mtproxy_ffi_mtproto_mtfront_client_close(C, who);
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
  return mtproxy_ffi_mtproto_do_close_in_ext_conn(_data, s_len);
}

// NET_CPU context
int mtproto_http_close(connection_job_t C, int who) {
  return mtproxy_ffi_mtproto_http_close(C, who);
}

int mtproto_ext_rpc_ready(connection_job_t C) {
  return mtproxy_ffi_mtproto_ext_rpc_ready(C);
}

int mtproto_ext_rpc_close(connection_job_t C, int who) {
  return mtproxy_ffi_mtproto_ext_rpc_close(C, who);
}

int mtproto_proxy_rpc_ready(connection_job_t C) {
  check_engine_class();
  return mtproxy_ffi_mtproto_proxy_rpc_ready(C);
}

int mtproto_proxy_rpc_close(connection_job_t C, int who) {
  check_engine_class();
  return mtproxy_ffi_mtproto_proxy_rpc_close(C, who);
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
  return mtproxy_ffi_mtproto_do_rpcs_execute(_data, s_len);
}

int ext_rpcs_execute(connection_job_t c, int op, struct raw_message *msg) {
  return mtproxy_ffi_mtproto_ext_rpcs_execute(c, op, msg);
}

// NET-CPU context
int mtproto_http_alarm(connection_job_t C) {
  return mtproxy_ffi_mtproto_http_alarm(C);
}

// NET-CPU context
int finish_postponed_http_response(void *_data, int len) {
  return mtproxy_ffi_mtproto_finish_postponed_http_response(_data, len);
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
  return mtproxy_ffi_mtproto_check_conn_buffers_runtime(c);
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

static void kill_children(int signal) {
  mtproxy_ffi_mtproto_kill_children(signal);
}

// SIGCHLD
void on_child_termination(void) {}

void check_children_status(void) {
  mtproxy_ffi_mtproto_check_children_status();
}

void check_special_connections_overflow(void) {
  mtproxy_ffi_mtproto_check_special_connections_overflow();
}

void cron(void) {
  mtproxy_ffi_mtproto_cron();
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
  mtproxy_ffi_mtproto_usage();
}

server_functions_t mtproto_front_functions;
int f_parse_option(int val) {
  return mtproxy_ffi_mtproto_f_parse_option(val);
}

void mtfront_prepare_parse_options(void) {
  mtproxy_ffi_mtproto_mtfront_prepare_parse_options();
}

void mtfront_parse_extra_args(int argc, char *argv[]) {
  mtproxy_ffi_mtproto_mtfront_parse_extra_args(argc, argv);
}

// executed BEFORE dropping privileges
void mtfront_pre_init(void) {
  mtproxy_ffi_mtproto_mtfront_pre_init();
}

void mtfront_pre_start(void) {
  mtproxy_ffi_mtproto_mtfront_pre_start();
}

void mtfront_on_exit(void) {
  mtproxy_ffi_mtproto_mtfront_on_exit();
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
