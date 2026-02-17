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
  MAX_HTTP_LISTEN_PORTS = 128,
  MAX_POST_SIZE = 262144 * 4 - 4096,
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

void add_stats(struct worker_stats *W) { mtproxy_ffi_mtproto_add_stats(W); }

void update_local_stats(void) {
  if (!slave_mode) {
    return;
  }
  update_local_stats_copy(WStats + worker_id * 2);
  update_local_stats_copy(WStats + worker_id * 2 + 1);
}

void compute_stats_sum(void) { mtproxy_ffi_mtproto_compute_stats_sum(); }

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
 *	RPC CLIENT
 *
 */

struct tcp_rpc_client_functions mtfront_rpc_client = {
    .execute = (int (*)(connection_job_t, int, struct raw_message *))
        mtproxy_ffi_mtproto_rpcc_execute,
    .check_ready = tcp_rpcc_default_check_ready,
    .flush_packet = tcp_rpc_flush_packet,
    .rpc_check_perm = tcp_rpcc_default_check_perm,
    .rpc_init_crypto = tcp_rpcc_init_crypto,
    .rpc_start_crypto = tcp_rpcc_start_crypto,
    .rpc_ready = (int (*)(connection_job_t))mtproxy_ffi_mtproto_mtfront_client_ready,
    .rpc_close = (int (*)(connection_job_t, int))mtproxy_ffi_mtproto_mtfront_client_close};

int rpcc_exists;

/*
 *
 *	HTTP INTERFACE
 *
 */

struct http_server_functions http_methods = {
    .execute = (int (*)(connection_job_t, struct raw_message *, int))
        mtproxy_ffi_mtproto_hts_execute,
    .ht_alarm = (int (*)(connection_job_t))mtproxy_ffi_mtproto_http_alarm,
    .ht_close = (int (*)(connection_job_t, int))mtproxy_ffi_mtproto_http_close};

struct http_server_functions http_methods_stats = {
    .execute = (int (*)(connection_job_t, struct raw_message *, int))
        mtproxy_ffi_mtproto_hts_stats_execute};

struct tcp_rpc_server_functions ext_rpc_methods = {
    .execute = (int (*)(connection_job_t, int, struct raw_message *))
        mtproxy_ffi_mtproto_ext_rpcs_execute,
    .check_ready = server_check_ready,
    .flush_packet = tcp_rpc_flush_packet,
    .rpc_ready = (int (*)(connection_job_t))mtproxy_ffi_mtproto_ext_rpc_ready,
    .rpc_close = (int (*)(connection_job_t, int))mtproxy_ffi_mtproto_ext_rpc_close,
    //.http_fallback_type = &ct_http_server_mtfront,
    //.http_fallback_extra = &http_methods,
    .max_packet_len = MAX_POST_SIZE,
};

char mtproto_cors_http_headers[] =
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: origin, content-type\r\n"
    "Access-Control-Max-Age: 1728000\r\n";

/* -------------------------- EXTERFACE ---------------------------- */

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

// SIGCHLD
void on_child_termination(void) {}

int sfd;
int http_ports_num;
int http_sfd[MAX_HTTP_LISTEN_PORTS], http_port[MAX_HTTP_LISTEN_PORTS];
int domain_count;
int secret_count;

// static double next_create_outbound;
// int outbound_connections_per_second =
// DEFAULT_OUTBOUND_CONNECTION_CREATION_RATE;

void precise_cron(void) { update_local_stats(); }

/*
 *
 *		MAIN
 *
 */

void usage(void) { mtproxy_ffi_mtproto_usage(); }

server_functions_t mtproto_front_functions = {
    .default_modules_disabled = 0,
    .cron = mtproxy_ffi_mtproto_cron,
    .precise_cron = precise_cron,
    .pre_init = mtproxy_ffi_mtproto_mtfront_pre_init,
    .pre_start = mtproxy_ffi_mtproto_mtfront_pre_start,
    .pre_loop = mtproxy_ffi_mtproto_mtfront_pre_loop,
    .on_exit = mtproxy_ffi_mtproto_mtfront_on_exit,
    .prepare_stats = mtfront_prepare_stats,
    .parse_option = mtproxy_ffi_mtproto_f_parse_option,
    .prepare_parse_options = mtproxy_ffi_mtproto_mtfront_prepare_parse_options,
    .parse_extra_args = mtproxy_ffi_mtproto_mtfront_parse_extra_args,
    .epoll_timeout = 1,
    .FullVersionStr = FullVersionStr,
    .ShortVersionStr = "mtproxy",
    .parse_function = (struct tl_act_extra * (*)(struct tl_in_state *, long long))
        mtproxy_ffi_mtproto_mtfront_parse_function_runtime,
    .flags = ENGINE_NO_PORT
    //.http_functions = &http_methods_stats
};

int main(int argc, char *argv[]) {
  mtproto_front_functions.allowed_signals |= SIG2INT(SIGCHLD);
  mtproto_front_functions.signal_handlers[SIGCHLD] = on_child_termination;
  mtproto_front_functions.signal_handlers[SIGUSR1] =
      mtproxy_ffi_mtproto_mtfront_sigusr1_handler;
  return default_main(&mtproto_front_functions, argc, argv);
}
