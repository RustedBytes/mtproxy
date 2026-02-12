/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation, either version 2 of the License,
   or (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see
   <http://www.gnu.org/licenses/>.

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin

    Copyright 2014      Telegram Messenger Inc
              2014      Nikolai Durov
              2014      Andrey Lopatin

    Copyright 2015-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
*/

#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "jobs/jobs.h"
#include "net/net-events.h"
#include "common/mp-queue.h"
#include "kprintf.h"
#include "net/net-connections.h"
#include "precise-time.h"
#include "server-functions.h"
#include "vv/vv-tree.h"

#include "net/net-msg-buffers.h"
#include "net/net-tcp-connections.h"

#include "common/common-stats.h"

#define USE_EPOLLET 1

#define MODULE connections

static int max_accept_rate;
static double cur_accept_rate_remaining;
static double cur_accept_rate_time;
static int max_connection;
static int conn_generation;
static int max_connection_fd = MAX_CONNECTIONS;

int active_special_connections, max_special_connections = MAX_CONNECTIONS;

int special_listen_sockets;

static struct {
  int fd, generation;
} special_socket[MAX_SPECIAL_LISTEN_SOCKETS];

static struct mp_queue *free_later_queue;

MODULE_STAT_TYPE {
  int active_connections, active_dh_connections;
  int outbound_connections, active_outbound_connections,
      ready_outbound_connections, listening_connections;
  int allocated_outbound_connections, allocated_inbound_connections;
  int inbound_connections, active_inbound_connections;

  long long outbound_connections_created, inbound_connections_accepted;
  int ready_targets;

  long long netw_queries, netw_update_queries, total_failed_connections,
      total_connect_failures, unused_connections_closed;

  int allocated_targets, active_targets, inactive_targets, free_targets;
  int allocated_connections, allocated_socket_connections;
  long long accept_calls_failed, accept_nonblock_set_failed,
      accept_connection_limit_failed, accept_rate_limit_failed,
      accept_init_accepted_failed;

  long long tcp_readv_calls, tcp_writev_calls, tcp_readv_intr, tcp_writev_intr;
  long long tcp_readv_bytes, tcp_writev_bytes;

  int free_later_size;
  long long free_later_total;
};

MODULE_INIT

MODULE_STAT_FUNCTION
SB_SUM_ONE_I(active_connections);
SB_SUM_ONE_I(active_dh_connections);

SB_SUM_ONE_I(outbound_connections);
SB_SUM_ONE_I(ready_outbound_connections);
SB_SUM_ONE_I(active_outbound_connections);
SB_SUM_ONE_LL(outbound_connections_created);
SB_SUM_ONE_LL(total_connect_failures);

SB_SUM_ONE_I(inbound_connections);
// SB_SUM_ONE_I (ready_inbound_connections);
SB_SUM_ONE_I(active_inbound_connections);
SB_SUM_ONE_LL(inbound_connections_accepted);

SB_SUM_ONE_I(listening_connections);
SB_SUM_ONE_LL(unused_connections_closed);
SB_SUM_ONE_I(ready_targets);
SB_SUM_ONE_I(allocated_targets);
SB_SUM_ONE_I(active_targets);
SB_SUM_ONE_I(inactive_targets);
SB_SUM_ONE_I(free_targets);
sb_printf(sb,
          "max_connections\t%d\n"
          "active_special_connections\t%d\n"
          "max_special_connections\t%d\n",
          max_connection_fd, active_special_connections,
          max_special_connections);
SBP_PRINT_I32(max_accept_rate);
SBP_PRINT_DOUBLE(cur_accept_rate_remaining);
SBP_PRINT_I32(max_connection);
SBP_PRINT_I32(conn_generation);

SB_SUM_ONE_I(allocated_connections);
SB_SUM_ONE_I(allocated_outbound_connections);
SB_SUM_ONE_I(allocated_inbound_connections);
SB_SUM_ONE_I(allocated_socket_connections);
SB_SUM_ONE_LL(tcp_readv_calls);
SB_SUM_ONE_LL(tcp_readv_intr);
SB_SUM_ONE_LL(tcp_readv_bytes);
SB_SUM_ONE_LL(tcp_writev_calls);
SB_SUM_ONE_LL(tcp_writev_intr);
SB_SUM_ONE_LL(tcp_writev_bytes);
SB_SUM_ONE_I(free_later_size);
SB_SUM_ONE_LL(free_later_total);

SB_SUM_ONE_LL(accept_calls_failed);
SB_SUM_ONE_LL(accept_nonblock_set_failed);
SB_SUM_ONE_LL(accept_connection_limit_failed);
SB_SUM_ONE_LL(accept_rate_limit_failed);
SB_SUM_ONE_LL(accept_init_accepted_failed);
MODULE_STAT_FUNCTION_END

void fetch_connections_stat(struct connections_stat *st) {
  st->active_connections = SB_SUM_I(active_connections);
  st->active_dh_connections = SB_SUM_I(active_dh_connections);
  st->outbound_connections = SB_SUM_I(outbound_connections);
  st->active_outbound_connections = SB_SUM_I(active_outbound_connections);
  st->ready_outbound_connections = SB_SUM_I(ready_outbound_connections);
  st->max_special_connections = max_special_connections;
  st->active_special_connections = active_special_connections;
  st->allocated_connections = SB_SUM_I(allocated_connections);
  st->allocated_outbound_connections = SB_SUM_I(allocated_outbound_connections);
  st->allocated_inbound_connections = SB_SUM_I(allocated_inbound_connections);
  st->allocated_socket_connections = SB_SUM_I(allocated_socket_connections);
  st->allocated_targets = SB_SUM_I(allocated_targets);
  st->ready_targets = SB_SUM_I(ready_targets);
  st->active_targets = SB_SUM_I(active_targets);
  st->inactive_targets = SB_SUM_I(inactive_targets);
  st->tcp_readv_calls = SB_SUM_LL(tcp_readv_calls);
  st->tcp_readv_intr = SB_SUM_LL(tcp_readv_intr);
  st->tcp_readv_bytes = SB_SUM_LL(tcp_readv_bytes);
  st->tcp_writev_calls = SB_SUM_LL(tcp_writev_calls);
  st->tcp_writev_intr = SB_SUM_LL(tcp_writev_intr);
  st->tcp_writev_bytes = SB_SUM_LL(tcp_writev_bytes);
  st->accept_calls_failed = SB_SUM_LL(accept_calls_failed);
  st->accept_nonblock_set_failed = SB_SUM_LL(accept_nonblock_set_failed);
  st->accept_rate_limit_failed = SB_SUM_LL(accept_rate_limit_failed);
  st->accept_init_accepted_failed = SB_SUM_LL(accept_init_accepted_failed);
  st->accept_connection_limit_failed = SB_SUM_LL(accept_connection_limit_failed);
}

void connection_event_incref(int fd, long long val);

extern int32_t mtproxy_ffi_net_connection_is_active(int32_t flags);
extern int32_t mtproxy_ffi_net_compute_conn_events(int32_t flags,
                                                   int32_t use_epollet);
extern int32_t mtproxy_ffi_net_add_nat_info(const char *rule_text);
extern uint32_t mtproxy_ffi_net_translate_ip(uint32_t local_ip);
extern int32_t mtproxy_ffi_net_connections_server_check_ready(int32_t status,
                                                              int32_t ready);
extern int32_t mtproxy_ffi_net_connections_accept_rate_decide(
    int32_t max_accept_rate, double now, double current_remaining,
    double current_time, double *out_remaining, double *out_time);
extern int32_t mtproxy_ffi_net_connections_compute_next_reconnect(
    double reconnect_timeout, double next_reconnect_timeout,
    int32_t active_outbound_connections, double now, double random_unit,
    double *out_next_reconnect, double *out_next_reconnect_timeout);
extern int32_t mtproxy_ffi_net_connections_target_bucket_ipv4(
    size_t type_addr, uint32_t addr_s_addr, int32_t port, int32_t prime_targets);
extern int32_t mtproxy_ffi_net_connections_target_bucket_ipv6(
    size_t type_addr, const uint8_t *addr_ipv6, int32_t port,
    int32_t prime_targets);
extern int32_t mtproxy_ffi_net_connections_target_ready_transition(
    int32_t was_ready, int32_t now_ready, int32_t *out_ready_outbound_delta,
    int32_t *out_ready_targets_delta);
extern int32_t mtproxy_ffi_net_connections_target_needed_connections(
    int32_t min_connections, int32_t max_connections, int32_t bad_connections,
    int32_t stopped_connections);
extern int32_t mtproxy_ffi_net_connections_target_should_attempt_reconnect(
    double now, double next_reconnect, int32_t active_outbound_connections);
extern int32_t mtproxy_ffi_net_connections_target_ready_bucket(int32_t ready);
extern int32_t mtproxy_ffi_net_connections_target_find_bad_should_select(
    int32_t has_selected, int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_target_remove_dead_connection_deltas(
    int32_t flags, int32_t *out_active_outbound_delta,
    int32_t *out_outbound_delta);
extern int32_t mtproxy_ffi_net_connections_target_tree_update_action(
    int32_t tree_changed);
extern int32_t mtproxy_ffi_net_connections_target_connect_socket_action(
    int32_t has_ipv4_target);
extern int32_t
mtproxy_ffi_net_connections_target_create_insert_should_insert(
    int32_t has_connection);
extern int32_t mtproxy_ffi_net_connections_target_lookup_match_action(
    int32_t mode);
extern int32_t mtproxy_ffi_net_connections_target_lookup_miss_action(
    int32_t mode);
extern int32_t mtproxy_ffi_net_connections_target_free_action(
    int32_t global_refcnt, int32_t has_conn_tree, int32_t has_ipv4_target);
extern int32_t mtproxy_ffi_net_connections_destroy_target_transition(
    int32_t new_global_refcnt, int32_t *out_active_targets_delta,
    int32_t *out_inactive_targets_delta);
extern int32_t mtproxy_ffi_net_connections_create_target_transition(
    int32_t target_found, int32_t old_global_refcnt,
    int32_t *out_active_targets_delta, int32_t *out_inactive_targets_delta,
    int32_t *out_was_created);
extern double mtproxy_ffi_net_connections_target_job_boot_delay(void);
extern double mtproxy_ffi_net_connections_target_job_retry_delay(void);
extern int32_t mtproxy_ffi_net_connections_target_job_should_run_tick(
    int32_t is_alarm, int32_t timer_check_ok);
extern int32_t
mtproxy_ffi_net_connections_target_job_update_mode(int32_t global_refcnt);
extern int32_t mtproxy_ffi_net_connections_target_job_post_tick_action(
    int32_t is_completed, int32_t global_refcnt, int32_t has_conn_tree);
extern int32_t mtproxy_ffi_net_connections_target_job_finalize_free_action(
    int32_t free_target_rc);
extern int32_t mtproxy_ffi_net_connections_conn_job_run_actions(int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_conn_job_ready_pending_should_promote_status(
    int32_t status);
extern int32_t
mtproxy_ffi_net_connections_conn_job_ready_pending_cas_failure_expected(
    int32_t status);
extern int32_t mtproxy_ffi_net_connections_conn_job_alarm_should_call(
    int32_t timer_check_ok, int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_conn_job_abort_has_error(int32_t flags);
extern int32_t mtproxy_ffi_net_connections_conn_job_abort_should_close(
    int32_t previous_flags);
extern int32_t
mtproxy_ffi_net_connections_socket_job_run_should_call_read_write(
    int32_t flags);
extern int32_t mtproxy_ffi_net_connections_socket_job_run_should_signal_aux(
    int32_t flags, int32_t new_epoll_status, int32_t current_epoll_status);
extern int32_t
mtproxy_ffi_net_connections_socket_job_aux_should_update_epoll(int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_socket_reader_should_run(int32_t flags);
extern int32_t mtproxy_ffi_net_connections_socket_reader_io_action(
    int32_t read_result, int32_t read_errno, int32_t eagain_errno,
    int32_t eintr_errno);
extern int32_t
mtproxy_ffi_net_connections_socket_writer_should_run(int32_t flags);
extern int32_t mtproxy_ffi_net_connections_socket_writer_io_action(
    int32_t write_result, int32_t write_errno, int32_t eagain_count,
    int32_t eagain_errno, int32_t eintr_errno, int32_t eagain_limit,
    int32_t *out_next_eagain_count);
extern int32_t
mtproxy_ffi_net_connections_socket_writer_should_call_ready_to_write(
    int32_t check_watermark, int32_t total_bytes, int32_t write_low_watermark);
extern int32_t
mtproxy_ffi_net_connections_socket_writer_should_abort_on_stop(int32_t stop,
                                                               int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_socket_read_write_connect_action(int32_t flags);
extern int32_t mtproxy_ffi_net_connections_socket_gateway_clear_flags(
    int32_t event_state, int32_t event_ready);
extern int32_t mtproxy_ffi_net_connections_socket_gateway_abort_action(
    int32_t has_epollerr, int32_t has_disconnect);
extern int32_t mtproxy_ffi_net_connections_listening_job_action(
    int32_t op, int32_t js_run, int32_t js_aux);
extern int32_t mtproxy_ffi_net_connections_listening_init_fd_action(
    int32_t fd, int32_t max_connection_fd);
extern int32_t
mtproxy_ffi_net_connections_listening_init_update_max_connection(
    int32_t fd, int32_t max_connection);
extern int32_t mtproxy_ffi_net_connections_listening_init_mode_policy(
    int32_t mode, int32_t sm_lowprio, int32_t sm_special, int32_t sm_noqack,
    int32_t sm_ipv6, int32_t sm_rawmsg);
extern int32_t mtproxy_ffi_net_connections_connection_event_should_release(
    int64_t new_refcnt, int32_t has_data);
extern int32_t mtproxy_ffi_net_connections_connection_get_by_fd_action(
    int32_t is_listening_job, int32_t is_socket_job, int32_t socket_flags);
extern int32_t mtproxy_ffi_net_connections_connection_generation_matches(
    int32_t found_generation, int32_t expected_generation);
extern int32_t mtproxy_ffi_net_connections_check_conn_functions_default_mask(
    int32_t has_title, int32_t has_socket_read_write,
    int32_t has_socket_reader, int32_t has_socket_writer,
    int32_t has_socket_close, int32_t has_close, int32_t has_init_outbound,
    int32_t has_wakeup, int32_t has_alarm, int32_t has_connected,
    int32_t has_flush, int32_t has_check_ready, int32_t has_read_write,
    int32_t has_free, int32_t has_socket_connected, int32_t has_socket_free);
extern int32_t mtproxy_ffi_net_connections_check_conn_functions_accept_mask(
    int32_t listening, int32_t has_accept, int32_t has_init_accepted);
extern int32_t mtproxy_ffi_net_connections_check_conn_functions_raw_policy(
    int32_t is_rawmsg, int32_t has_free_buffers, int32_t has_reader,
    int32_t has_writer, int32_t has_parse_execute, int32_t *out_assign_mask,
    int32_t *out_nonraw_assert_mask);
extern int32_t mtproxy_ffi_net_connections_target_pick_should_skip(
    int32_t allow_stopped, int32_t has_selected, int32_t selected_ready);
extern int32_t mtproxy_ffi_net_connections_target_pick_should_select(
    int32_t allow_stopped, int32_t candidate_ready, int32_t has_selected,
    int32_t selected_unreliability, int32_t candidate_unreliability);
extern int32_t mtproxy_ffi_net_connections_target_pick_should_incref(
    int32_t has_selected);
extern int32_t mtproxy_ffi_net_connections_connection_write_close_action(
    int32_t status, int32_t has_io_conn);
extern int32_t mtproxy_ffi_net_connections_connection_timeout_action(
    int32_t flags, double timeout);
extern int32_t mtproxy_ffi_net_connections_fail_connection_action(
    int32_t previous_flags, int32_t current_error);
extern int32_t mtproxy_ffi_net_connections_free_connection_allocated_deltas(
    int32_t basic_type, int32_t *out_allocated_outbound_delta,
    int32_t *out_allocated_inbound_delta);
extern int32_t mtproxy_ffi_net_connections_close_connection_failure_deltas(
    int32_t error, int32_t flags, int32_t *out_total_failed_delta,
    int32_t *out_total_connect_failures_delta, int32_t *out_unused_closed_delta);
extern int32_t mtproxy_ffi_net_connections_close_connection_has_isdh(
    int32_t flags);
extern int32_t mtproxy_ffi_net_connections_close_connection_basic_deltas(
    int32_t basic_type, int32_t flags, int32_t has_target,
    int32_t *out_outbound_delta, int32_t *out_inbound_delta,
    int32_t *out_active_outbound_delta, int32_t *out_active_inbound_delta,
    int32_t *out_active_connections_delta, int32_t *out_signal_target);
extern int32_t mtproxy_ffi_net_connections_close_connection_has_special(
    int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_close_connection_should_signal_special_aux(
    int32_t orig_special_connections, int32_t max_special_connections);
extern int32_t
mtproxy_ffi_net_connections_alloc_connection_basic_type_policy(
    int32_t basic_type, int32_t *out_initial_flags,
    int32_t *out_initial_status, int32_t *out_is_outbound_path);
extern int32_t mtproxy_ffi_net_connections_alloc_connection_success_deltas(
    int32_t basic_type, int32_t has_target, int32_t *out_outbound_delta,
    int32_t *out_allocated_outbound_delta, int32_t *out_outbound_created_delta,
    int32_t *out_inbound_accepted_delta, int32_t *out_allocated_inbound_delta,
    int32_t *out_inbound_delta, int32_t *out_active_inbound_delta,
    int32_t *out_active_connections_delta, int32_t *out_target_outbound_delta,
    int32_t *out_should_incref_target);
extern int32_t mtproxy_ffi_net_connections_alloc_connection_listener_flags(
    int32_t listening_flags);
extern int32_t mtproxy_ffi_net_connections_alloc_connection_special_action(
    int32_t active_special_connections, int32_t max_special_connections);
extern int32_t mtproxy_ffi_net_connections_alloc_connection_failure_action(
    int32_t flags);
extern int32_t mtproxy_ffi_net_connections_socket_job_action(
    int32_t op, int32_t js_abort, int32_t js_run, int32_t js_aux,
    int32_t js_finish);
extern int32_t mtproxy_ffi_net_connections_socket_job_abort_error(void);
extern int32_t mtproxy_ffi_net_connections_fail_socket_connection_action(
    int32_t previous_flags);
extern int32_t mtproxy_ffi_net_connections_alloc_socket_connection_plan(
    int32_t conn_flags, int32_t use_epollet, int32_t *out_socket_flags,
    int32_t *out_initial_epoll_status, int32_t *out_allocated_socket_delta);
extern int32_t mtproxy_ffi_net_connections_socket_free_plan(
    int32_t has_conn, int32_t *out_fail_error,
    int32_t *out_allocated_socket_delta);

void tcp_set_max_accept_rate(int rate) { max_accept_rate = rate; }

static int tcp_recv_buffers_num;
static int tcp_recv_buffers_total_size;
static struct iovec tcp_recv_iovec[MAX_TCP_RECV_BUFFERS + 1];
static struct msg_buffer *tcp_recv_buffers[MAX_TCP_RECV_BUFFERS];

int prealloc_tcp_buffers(void) {
  assert(!tcp_recv_buffers_num);

  int i;
  for (i = MAX_TCP_RECV_BUFFERS - 1; i >= 0; i--) {
    struct msg_buffer *X =
        alloc_msg_buffer((tcp_recv_buffers_num) ? tcp_recv_buffers[i + 1] : 0,
                         TCP_RECV_BUFFER_SIZE);
    if (!X) {
      vkprintf(0, "**FATAL**: cannot allocate tcp receive buffer\n");
      exit(2);
    }
    vkprintf(3, "allocated %d byte tcp receive buffer #%d at %p\n",
             X->chunk->buffer_size, i, X);
    tcp_recv_buffers[i] = X;
    tcp_recv_iovec[i + 1].iov_base = X->data;
    tcp_recv_iovec[i + 1].iov_len = X->chunk->buffer_size;
    ++tcp_recv_buffers_num;
    tcp_recv_buffers_total_size += X->chunk->buffer_size;
  }
  return tcp_recv_buffers_num;
}

int tcp_prepare_iovec(struct iovec *iov, int *iovcnt, int maxcnt,
                      struct raw_message *raw) {
  int t = rwm_prepare_iovec(raw, iov, maxcnt, raw->total_bytes);
  if (t < 0) {
    *iovcnt = maxcnt;
    int i;
    t = 0;
    for (i = 0; i < maxcnt; i++) {
      t += iov[i].iov_len;
    }
    assert(t < raw->total_bytes);
    return t;
  } else {
    *iovcnt = t;
    return raw->total_bytes;
  }
}

void assert_main_thread(void) {}
void assert_net_cpu_thread(void) {}
void assert_net_net_thread(void) {}
void assert_engine_thread(void) {
  assert(this_job_thread && (this_job_thread->thread_class == JC_ENGINE ||
                             this_job_thread->thread_class == JC_MAIN));
}

socket_connection_job_t alloc_new_socket_connection(connection_job_t C);

#if USE_EPOLLET
static inline int compute_conn_events(socket_connection_job_t c) {
  int32_t events =
      mtproxy_ffi_net_compute_conn_events(SOCKET_CONN_INFO(c)->flags, 1);
  assert(events == 0 || events == (EVT_READ | EVT_WRITE | EVT_SPEC));
  return events;
}
#else
static inline int compute_conn_events(connection_job_t c) {
  return mtproxy_ffi_net_compute_conn_events(CONN_INFO(c)->flags, 0);
}
#endif

void connection_write_close(connection_job_t C) {
  enum {
    CONNECTION_WRITE_CLOSE_ACTION_NOOP = 0,
    CONNECTION_WRITE_CLOSE_ACTION_SET_IO_STOPREAD = 1 << 0,
    CONNECTION_WRITE_CLOSE_ACTION_SET_CONN_STOPREAD = 1 << 1,
    CONNECTION_WRITE_CLOSE_ACTION_SET_STATUS_WRITE_CLOSE = 1 << 2,
    CONNECTION_WRITE_CLOSE_ACTION_SIGNAL_RUN = 1 << 3,
  };

  struct connection_info *c = CONN_INFO(C);
  socket_connection_job_t S = c->io_conn;

  int32_t action = mtproxy_ffi_net_connections_connection_write_close_action(
      c->status, S != NULL);
  assert((action &
          ~(CONNECTION_WRITE_CLOSE_ACTION_SET_IO_STOPREAD |
            CONNECTION_WRITE_CLOSE_ACTION_SET_CONN_STOPREAD |
            CONNECTION_WRITE_CLOSE_ACTION_SET_STATUS_WRITE_CLOSE |
            CONNECTION_WRITE_CLOSE_ACTION_SIGNAL_RUN)) == 0);
  if (action == CONNECTION_WRITE_CLOSE_ACTION_NOOP) {
    return;
  }

  if (action & CONNECTION_WRITE_CLOSE_ACTION_SET_IO_STOPREAD) {
    assert(S);
    __sync_fetch_and_or(&SOCKET_CONN_INFO(S)->flags, C_STOPREAD);
  }
  if (action & CONNECTION_WRITE_CLOSE_ACTION_SET_CONN_STOPREAD) {
    __sync_fetch_and_or(&c->flags, C_STOPREAD);
  }
  if (action & CONNECTION_WRITE_CLOSE_ACTION_SET_STATUS_WRITE_CLOSE) {
    c->status = conn_write_close;
  }

  if (action & CONNECTION_WRITE_CLOSE_ACTION_SIGNAL_RUN) {
    job_signal(JOB_REF_CREATE_PASS(C), JS_RUN);
  }
}

static inline void disable_qack(int fd) {
  vkprintf(2, "disable TCP_QUICKACK for %d\n", fd);
  assert(setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (int[]){0}, sizeof(int)) >=
         0);
}

int set_connection_timeout(connection_job_t C, double timeout) {
  enum {
    CONNECTION_TIMEOUT_ACTION_SKIP_ERROR = 0,
    CONNECTION_TIMEOUT_ACTION_INSERT_TIMER = 1,
    CONNECTION_TIMEOUT_ACTION_REMOVE_TIMER = 2,
  };

  struct connection_info *c = CONN_INFO(C);

  int32_t timeout_action = mtproxy_ffi_net_connections_connection_timeout_action(
      c->flags, timeout);
  assert(timeout_action == CONNECTION_TIMEOUT_ACTION_SKIP_ERROR ||
         timeout_action == CONNECTION_TIMEOUT_ACTION_INSERT_TIMER ||
         timeout_action == CONNECTION_TIMEOUT_ACTION_REMOVE_TIMER);
  if (timeout_action == CONNECTION_TIMEOUT_ACTION_SKIP_ERROR) {
    return 0;
  }

  __sync_fetch_and_and(&c->flags, ~C_ALARM);

  if (timeout_action == CONNECTION_TIMEOUT_ACTION_INSERT_TIMER) {
    job_timer_insert(C, precise_now + timeout);
  } else {
    job_timer_remove(C);
  }
  return 0;
}

int clear_connection_timeout(connection_job_t C) {
  set_connection_timeout(C, 0);
  return 0;
}

/*
  can be called from any thread and without lock
  just sets error code and sends JS_ABORT to connection job
*/
void fail_connection(connection_job_t C, int err) {
  enum {
    FAIL_CONNECTION_ACTION_NOOP = 0,
    FAIL_CONNECTION_ACTION_SET_STATUS_ERROR = 1 << 0,
    FAIL_CONNECTION_ACTION_SET_ERROR_CODE = 1 << 1,
    FAIL_CONNECTION_ACTION_SIGNAL_ABORT = 1 << 2,
  };

  struct connection_info *c = CONN_INFO(C);

  int32_t previous_flags = __sync_fetch_and_or(&c->flags, C_ERROR);
  int32_t action = mtproxy_ffi_net_connections_fail_connection_action(
      previous_flags, c->error);
  assert((action &
          ~(FAIL_CONNECTION_ACTION_SET_STATUS_ERROR |
            FAIL_CONNECTION_ACTION_SET_ERROR_CODE |
            FAIL_CONNECTION_ACTION_SIGNAL_ABORT)) == 0);

  if (action & FAIL_CONNECTION_ACTION_SET_STATUS_ERROR) {
    c->status = conn_error;
  }
  if (action & FAIL_CONNECTION_ACTION_SET_ERROR_CODE) {
    c->error = err;
  }
  if (action & FAIL_CONNECTION_ACTION_SIGNAL_ABORT) {
    job_signal(JOB_REF_CREATE_PASS(C), JS_ABORT);
  }
}

/*
  just runs ->reader and ->writer virtual methods
*/
int cpu_server_read_write(connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);

  c->type->reader(C);
  c->type->writer(C);
  return 0;
}

/*
  frees connection structure, including mpq and buffers
*/
int cpu_server_free_connection(connection_job_t C) {
  assert_net_cpu_thread();
  assert(C->j_refcnt == 1);

  struct connection_info *c = CONN_INFO(C);
  if (!(c->flags & C_ERROR)) {
    vkprintf(0, "target = %p, basic=%d\n", c->target, c->basic_type);
  }
  assert(c->flags & C_ERROR);
  assert(c->flags & C_FAILED);
  assert(!c->target);
  assert(!c->io_conn);

  vkprintf(1, "Closing connection socket #%d\n", c->fd);

  while (1) {
    struct raw_message *raw = mpq_pop_nw(c->out_queue, 4);
    if (!raw) {
      break;
    }
    rwm_free(raw);
    free(raw);
  }

  free_mp_queue(c->out_queue);
  c->out_queue = NULL;

  while (1) {
    struct raw_message *raw = mpq_pop_nw(c->in_queue, 4);
    if (!raw) {
      break;
    }
    rwm_free(raw);
    free(raw);
  }

  free_mp_queue(c->in_queue);
  c->in_queue = NULL;

  if (c->type->crypto_free) {
    c->type->crypto_free(C);
  }

  close(c->fd);
  c->fd = -1;

  int32_t allocated_outbound_delta = 0;
  int32_t allocated_inbound_delta = 0;
  int32_t free_stats_rc = mtproxy_ffi_net_connections_free_connection_allocated_deltas(
      c->basic_type, &allocated_outbound_delta, &allocated_inbound_delta);
  assert(free_stats_rc == 0);

  MODULE_STAT->allocated_connections--;
  MODULE_STAT->allocated_outbound_connections += allocated_outbound_delta;
  MODULE_STAT->allocated_inbound_connections += allocated_inbound_delta;

  return c->type->free_buffers(C);
}

/*
  deletes link to io_conn
  deletes link to target
  aborts pending queries
  updates stats
*/
int cpu_server_close_connection(connection_job_t C, int who) {
  assert_net_cpu_thread();
  struct connection_info *c = CONN_INFO(C);

  assert(c->flags & C_ERROR);
  assert(c->status == conn_error);
  assert(c->flags & C_FAILED);

  int32_t total_failed_delta = 0;
  int32_t total_connect_failures_delta = 0;
  int32_t unused_closed_delta = 0;
  int32_t close_failure_rc =
      mtproxy_ffi_net_connections_close_connection_failure_deltas(
          c->error, c->flags, &total_failed_delta, &total_connect_failures_delta,
          &unused_closed_delta);
  assert(close_failure_rc == 0);
  MODULE_STAT->total_failed_connections += total_failed_delta;
  MODULE_STAT->total_connect_failures += total_connect_failures_delta;
  MODULE_STAT->unused_connections_closed += unused_closed_delta;

  int32_t has_isdh =
      mtproxy_ffi_net_connections_close_connection_has_isdh(c->flags);
  assert(has_isdh == 0 || has_isdh == 1);
  if (has_isdh) {
    MODULE_STAT->active_dh_connections--;
    __sync_fetch_and_and(&c->flags, ~C_ISDH);
  }

  assert(c->io_conn);
  job_signal(JOB_REF_PASS(c->io_conn), JS_ABORT);

  int32_t outbound_delta = 0;
  int32_t inbound_delta = 0;
  int32_t active_outbound_delta = 0;
  int32_t active_inbound_delta = 0;
  int32_t active_connections_delta = 0;
  int32_t signal_target = 0;
  int32_t close_basic_rc = mtproxy_ffi_net_connections_close_connection_basic_deltas(
      c->basic_type, c->flags, c->target != NULL, &outbound_delta, &inbound_delta,
      &active_outbound_delta, &active_inbound_delta, &active_connections_delta,
      &signal_target);
  assert(close_basic_rc == 0);
  assert(signal_target == 0 || signal_target == 1);

  MODULE_STAT->outbound_connections += outbound_delta;
  MODULE_STAT->inbound_connections += inbound_delta;
  MODULE_STAT->active_outbound_connections += active_outbound_delta;
  MODULE_STAT->active_inbound_connections += active_inbound_delta;
  MODULE_STAT->active_connections += active_connections_delta;

  if (signal_target) {
    assert(c->target);
    job_signal(JOB_REF_PASS(c->target), JS_RUN);
  }

  int32_t has_special =
      mtproxy_ffi_net_connections_close_connection_has_special(c->flags);
  assert(has_special == 0 || has_special == 1);
  if (has_special) {
    c->flags &= ~C_SPECIAL;
    int orig_special_connections =
        __sync_fetch_and_add(&active_special_connections, -1);
    int32_t signal_special_aux =
        mtproxy_ffi_net_connections_close_connection_should_signal_special_aux(
            orig_special_connections, max_special_connections);
    assert(signal_special_aux == 0 || signal_special_aux == 1);
    if (signal_special_aux) {
      int i;
      for (i = 0; i < special_listen_sockets; i++) {
        connection_job_t LC = connection_get_by_fd_generation(
            special_socket[i].fd, special_socket[i].generation);
        assert(LC);
        job_signal(JOB_REF_PASS(LC), JS_AUX);
      }
    }
  }

  job_timer_remove(C);
  return 0;
}

int do_connection_job(job_t job, int op, struct job_thread *JT) {
  enum {
    CONN_JOB_RUN_SKIP = 0,
    CONN_JOB_RUN_DO_READ_WRITE = 1,
    CONN_JOB_RUN_HANDLE_READY_PENDING = 2,
  };

  connection_job_t C = job;

  struct connection_info *c = CONN_INFO(C);

  if (op == JS_RUN) { // RUN IN NET-CPU THREAD
    assert_net_cpu_thread();
    int32_t run_actions =
        mtproxy_ffi_net_connections_conn_job_run_actions(c->flags);
    assert((run_actions &
            ~(CONN_JOB_RUN_DO_READ_WRITE | CONN_JOB_RUN_HANDLE_READY_PENDING)) ==
           0);

    if (run_actions != CONN_JOB_RUN_SKIP) {
      if (run_actions & CONN_JOB_RUN_HANDLE_READY_PENDING) {
        assert(c->flags & C_CONNECTED);
        __sync_fetch_and_and(&c->flags, ~C_READY_PENDING);
        MODULE_STAT->active_outbound_connections++;
        MODULE_STAT->active_connections++;
        if (c->target) {
          __sync_fetch_and_add(
              &CONN_TARGET_INFO(c->target)->active_outbound_connections, 1);
        }

        int32_t should_promote_status =
            mtproxy_ffi_net_connections_conn_job_ready_pending_should_promote_status(
                c->status);
        assert(should_promote_status == 0 || should_promote_status == 1);
        if (should_promote_status) {
          if (!__sync_bool_compare_and_swap(&c->status, conn_connecting,
                                            conn_working)) {
            int32_t expected_failure =
                mtproxy_ffi_net_connections_conn_job_ready_pending_cas_failure_expected(
                    c->status);
            assert(expected_failure == 1);
          }
        }
        c->type->connected(C);
      }

      assert(run_actions & CONN_JOB_RUN_DO_READ_WRITE);
      c->type->read_write(C);
    }
    return 0;
  }
  if (op == JS_ALARM) { // RUN IN NET-CPU THREAD
    int32_t should_call_alarm =
        mtproxy_ffi_net_connections_conn_job_alarm_should_call(
            job_timer_check(job), c->flags);
    assert(should_call_alarm == 0 || should_call_alarm == 1);
    if (should_call_alarm) {
      c->type->alarm(C);
    }
    return 0;
  }
  if (op == JS_ABORT) { // RUN IN NET-CPU THREAD
    int32_t has_error =
        mtproxy_ffi_net_connections_conn_job_abort_has_error(c->flags);
    assert(has_error == 1);
    int32_t old_flags = __sync_fetch_and_or(&c->flags, C_FAILED);
    int32_t should_close =
        mtproxy_ffi_net_connections_conn_job_abort_should_close(old_flags);
    assert(should_close == 0 || should_close == 1);
    if (should_close) {
      c->type->close(C, 0);
    }
    return JOB_COMPLETED;
  }
  if (op == JS_FINISH) { // RUN IN NET-CPU THREAD
    assert(C->j_refcnt == 1);
    c->type->free(C);
    return job_free(JOB_REF_PASS(C));
  }
  return JOB_ERROR;
}

/*
  allocates inbound or outbound connection
  runs init_accepted or init_outbound
  updates stats
  creates socket_connection
*/
connection_job_t alloc_new_connection(int cfd, conn_target_job_t CTJ,
                                      listening_connection_job_t LCJ,
                                      int basic_type, conn_type_t *conn_type,
                                      void *conn_extra, unsigned peer,
                                      unsigned char peer_ipv6[16],
                                      int peer_port) {
  enum {
    ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL1 = 1 << 0,
    ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL0 = 1 << 1,
    ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE = 1 << 2,
  };

  if (cfd < 0) {
    return NULL;
  }
  assert_main_thread();

  struct conn_target_info *CT = CTJ ? CONN_TARGET_INFO(CTJ) : NULL;
  struct listening_connection_info *LC = LCJ ? LISTEN_CONN_INFO(LCJ) : NULL;

  unsigned flags;
  if ((flags = fcntl(cfd, F_GETFL, 0) < 0) ||
      fcntl(cfd, F_SETFL, flags | O_NONBLOCK) < 0) {
    kprintf("cannot set O_NONBLOCK on accepted socket #%d: %m\n", cfd);
    MODULE_STAT->accept_nonblock_set_failed++;
    close(cfd);
    return NULL;
  }

  flags = 1;
  setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));
  if (tcp_maximize_buffers) {
    maximize_sndbuf(cfd, 0);
    maximize_rcvbuf(cfd, 0);
  }

  int32_t fd_action = mtproxy_ffi_net_connections_listening_init_fd_action(
      cfd, max_connection_fd);
  assert(fd_action == 0 || fd_action == 1);
  if (fd_action) {
    vkprintf(2, "cfd = %d, max_connection_fd = %d\n", cfd, max_connection_fd);
    MODULE_STAT->accept_connection_limit_failed++;
    close(cfd);
    return NULL;
  }

  max_connection = mtproxy_ffi_net_connections_listening_init_update_max_connection(
      cfd, max_connection);

  connection_job_t C = create_async_job(
      do_connection_job,
      JSC_ALLOW(JC_CONNECTION, JS_RUN) | JSC_ALLOW(JC_CONNECTION, JS_ALARM) |
          JSC_ALLOW(JC_CONNECTION, JS_ABORT) |
          JSC_ALLOW(JC_CONNECTION, JS_FINISH),
      -2, sizeof(struct connection_info), JT_HAVE_TIMER, JOB_REF_NULL);

  struct connection_info *c = CONN_INFO(C);
  // memset (c, 0, sizeof (*c)); /* no need, create_async_job memsets itself */

  c->fd = cfd;
  c->target = CTJ;
  c->generation = new_conn_generation();

  int32_t initial_flags = 0;
  int32_t initial_status = conn_none;
  int32_t is_outbound_path = 0;
  int32_t basic_policy_rc =
      mtproxy_ffi_net_connections_alloc_connection_basic_type_policy(
          basic_type, &initial_flags, &initial_status, &is_outbound_path);
  assert(basic_policy_rc == 0);
  assert(is_outbound_path == 0 || is_outbound_path == 1);

  c->flags = initial_flags; // SS ? C_WANTWR : C_WANTRD;

  int raw = C_RAWMSG;

  if (raw) {
    c->flags |= C_RAWMSG;
    rwm_init(&c->in, 0);
    rwm_init(&c->out, 0);
    rwm_init(&c->in_u, 0);
    rwm_init(&c->out_p, 0);
  } else {
    assert(0);
  }

  c->type = conn_type;
  c->extra = conn_extra;
  assert(c->type);

  c->basic_type = basic_type;
  c->status = initial_status;

  c->flags |= c->type->flags & C_EXTERNAL;
  if (LC) {
    c->flags |= LC->flags & C_EXTERNAL;
  }

  union sockaddr_in46 self;
  unsigned self_addrlen = sizeof(self);
  memset(&self, 0, sizeof(self));
  getsockname(cfd, (struct sockaddr *)&self, &self_addrlen);

  if (self.a4.sin_family == AF_INET) {
    assert(self_addrlen == sizeof(struct sockaddr_in));
    c->our_ip = ntohl(self.a4.sin_addr.s_addr);
    c->our_port = ntohs(self.a4.sin_port);
    assert(peer);
    c->remote_ip = peer;
  } else {
    assert(self.a6.sin6_family == AF_INET6);
    assert(!peer);
    if (is_4in6(peer_ipv6)) {
      assert(is_4in6(self.a6.sin6_addr.s6_addr));
      c->our_ip = ntohl(extract_4in6(self.a6.sin6_addr.s6_addr));
      c->our_port = ntohs(self.a6.sin6_port);
      c->remote_ip = ntohl(extract_4in6(peer_ipv6));
    } else {
      memcpy(c->our_ipv6, self.a6.sin6_addr.s6_addr, 16);
      c->our_port = ntohs(self.a6.sin6_port);
      c->flags |= C_IPV6;
      memcpy(c->remote_ipv6, peer_ipv6, 16);
    }
  }
  c->remote_port = peer_port;

  c->in_queue = alloc_mp_queue_w();
  c->out_queue = alloc_mp_queue_w();
  // c->out_packet_queue = alloc_mp_queue_w ();

  if (is_outbound_path) {
    vkprintf(1, "New outbound connection #%d %s:%d -> %s:%d\n", c->fd,
             show_our_ip(C), c->our_port, show_remote_ip(C), c->remote_port);
  } else {
    vkprintf(1, "New inbound connection #%d %s:%d -> %s:%d\n", c->fd,
             show_remote_ip(C), c->remote_port, show_our_ip(C), c->our_port);
  }

  int (*func)(connection_job_t) =
      is_outbound_path ? c->type->init_outbound : c->type->init_accepted;

  vkprintf(3, "func = %p\n", func);

  if (func(C) >= 0) {
    int32_t outbound_delta = 0;
    int32_t allocated_outbound_delta = 0;
    int32_t outbound_created_delta = 0;
    int32_t inbound_accepted_delta = 0;
    int32_t allocated_inbound_delta = 0;
    int32_t inbound_delta = 0;
    int32_t active_inbound_delta = 0;
    int32_t active_connections_delta = 0;
    int32_t target_outbound_delta = 0;
    int32_t should_incref_target = 0;
    int32_t success_deltas_rc =
        mtproxy_ffi_net_connections_alloc_connection_success_deltas(
            basic_type, CTJ != NULL, &outbound_delta, &allocated_outbound_delta,
            &outbound_created_delta, &inbound_accepted_delta,
            &allocated_inbound_delta, &inbound_delta, &active_inbound_delta,
            &active_connections_delta, &target_outbound_delta,
            &should_incref_target);
    assert(success_deltas_rc == 0);
    assert(should_incref_target == 0 || should_incref_target == 1);

    MODULE_STAT->outbound_connections += outbound_delta;
    MODULE_STAT->allocated_outbound_connections += allocated_outbound_delta;
    MODULE_STAT->outbound_connections_created += outbound_created_delta;
    MODULE_STAT->inbound_connections_accepted += inbound_accepted_delta;
    MODULE_STAT->allocated_inbound_connections += allocated_inbound_delta;
    MODULE_STAT->inbound_connections += inbound_delta;
    MODULE_STAT->active_inbound_connections += active_inbound_delta;
    MODULE_STAT->active_connections += active_connections_delta;

    if (should_incref_target) {
      assert(CTJ && CT);
      job_incref(CTJ);
    }
    if (target_outbound_delta != 0) {
      assert(CT);
      CT->outbound_connections += target_outbound_delta;
    }

    if (!is_outbound_path) {
      if (LCJ) {
        c->listening = LC->fd;
        c->listening_generation = LC->generation;
        int32_t listener_flags =
            mtproxy_ffi_net_connections_alloc_connection_listener_flags(
                LC->flags);
        assert((listener_flags & ~(C_NOQACK | C_SPECIAL)) == 0);
        c->flags |= listener_flags;

        c->window_clamp = LC->window_clamp;

        if (listener_flags & C_SPECIAL) {
          __sync_fetch_and_add(&active_special_connections, 1);
          int32_t special_action =
              mtproxy_ffi_net_connections_alloc_connection_special_action(
                  active_special_connections, max_special_connections);
          assert((special_action &
                  ~(ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL1 |
                    ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL0 |
                    ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE)) == 0);

          if (special_action & ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL1) {
            vkprintf(1,
                     "ERROR: forced to accept connection when special "
                     "connections limit was reached (%d of %d)\n",
                     active_special_connections, max_special_connections);
          }
          if (special_action & ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL0) {
            vkprintf(0,
                     "ERROR: forced to accept connection when special "
                     "connections limit was reached (%d of %d)\n",
                     active_special_connections, max_special_connections);
          }
          if (special_action & ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE) {
            vkprintf(2, "**Invoking epoll_remove(%d)\n", LC->fd);
            epoll_remove(LC->fd);
          }
        }
      }
      if (c->window_clamp) {
        if (setsockopt(cfd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &c->window_clamp,
                       4) < 0) {
          vkprintf(0,
                   "error while setting window size for socket #%d to %d: %m\n",
                   cfd, c->window_clamp);
        } else {
          int t1 = -1, t2 = -1;
          socklen_t s1 = 4, s2 = 4;
          getsockopt(cfd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &t1, &s1);
          getsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &t2, &s2);
          vkprintf(2,
                   "window clamp for socket #%d is %d, receive buffer is %d\n",
                   cfd, t1, t2);
        }
      }
    }

    alloc_new_socket_connection(C);

    MODULE_STAT->allocated_connections++;

    return C;
  } else {
    enum {
      ALLOC_CONNECTION_FAILURE_ACTION_NONE = 0,
      ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED = 1 << 0,
      ALLOC_CONNECTION_FAILURE_ACTION_FREE_RAWMSG = 1 << 1,
      ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE = 1 << 2,
      ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE = 1 << 3,
    };

    int32_t failure_action =
        mtproxy_ffi_net_connections_alloc_connection_failure_action(c->flags);
    assert((failure_action &
            ~(ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED |
              ALLOC_CONNECTION_FAILURE_ACTION_FREE_RAWMSG |
              ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE |
              ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE)) == 0);
    assert(failure_action != ALLOC_CONNECTION_FAILURE_ACTION_NONE);

    if (failure_action & ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED) {
      MODULE_STAT->accept_init_accepted_failed++;
    }
    if (failure_action & ALLOC_CONNECTION_FAILURE_ACTION_FREE_RAWMSG) {
      rwm_free(&c->in);
      rwm_free(&c->out);
      rwm_free(&c->in_u);
      rwm_free(&c->out_p);
    }
    if (failure_action & ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE) {
      c->basic_type = ct_none;
    }
    close(cfd);

    free_mp_queue(c->in_queue);
    free_mp_queue(c->out_queue);

    job_free(JOB_REF_PASS(C));
    if (failure_action & ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE) {
      this_job_thread->jobs_active--;
    }

    return NULL;
  }
}

/*
  Have to have lock on socket_connection to run this method

  removes event from evemt heap and epoll
*/
void fail_socket_connection(socket_connection_job_t C, int who) {
  enum {
    FAIL_SOCKET_CONNECTION_ACTION_NOOP = 0,
    FAIL_SOCKET_CONNECTION_ACTION_CLEANUP = 1,
  };

  assert_main_thread();

  struct socket_connection_info *c = SOCKET_CONN_INFO(C);
  assert(C->j_flags & JF_LOCKED);

  int32_t previous_flags = __sync_fetch_and_or(&c->flags, C_ERROR);
  int32_t action =
      mtproxy_ffi_net_connections_fail_socket_connection_action(previous_flags);
  assert(action == FAIL_SOCKET_CONNECTION_ACTION_NOOP ||
         action == FAIL_SOCKET_CONNECTION_ACTION_CLEANUP);
  if (action == FAIL_SOCKET_CONNECTION_ACTION_CLEANUP) {
    job_timer_remove(C);

    remove_event_from_heap(c->ev, 0);
    connection_event_incref(c->fd, -1);
    epoll_insert(c->fd, 0);
    c->ev = NULL;

    c->type->socket_close(C);

    fail_connection(c->conn, who);
  }
}

/*
  Frees socket_connection structure
  Removes link to cpu_connection
*/
int net_server_socket_free(socket_connection_job_t C) {
  enum {
    SOCKET_FREE_ACTION_NONE = 0,
    SOCKET_FREE_ACTION_FAIL_CONN = 1,
  };

  assert_net_net_thread();

  struct socket_connection_info *c = SOCKET_CONN_INFO(C);

  assert(!c->ev);
  assert(c->flags & C_ERROR);

  int32_t fail_error = 0;
  int32_t allocated_socket_delta = 0;
  int32_t socket_free_action = mtproxy_ffi_net_connections_socket_free_plan(
      c->conn != NULL, &fail_error, &allocated_socket_delta);
  assert(socket_free_action == SOCKET_FREE_ACTION_NONE ||
         socket_free_action == SOCKET_FREE_ACTION_FAIL_CONN);
  if (socket_free_action == SOCKET_FREE_ACTION_FAIL_CONN) {
    assert(c->conn);
    fail_connection(c->conn, fail_error);
    job_decref(JOB_REF_PASS(c->conn));
  }

  while (1) {
    struct raw_message *raw = mpq_pop_nw(c->out_packet_queue, 4);
    if (!raw) {
      break;
    }
    rwm_free(raw);
    free(raw);
  }

  free_mp_queue(c->out_packet_queue);

  rwm_free(&c->out);

  MODULE_STAT->allocated_socket_connections += allocated_socket_delta;
  return 0;
}

/*
  Reads data from socket until all data is read
  Then puts it to conn->in_queue and send JS_RUN signal
*/
int net_server_socket_reader(socket_connection_job_t C) {
  enum {
    SOCKET_READER_IO_HAVE_DATA = 0,
    SOCKET_READER_IO_BREAK = 1,
    SOCKET_READER_IO_CONTINUE_INTR = 2,
    SOCKET_READER_IO_FATAL_ABORT = 3,
  };

  assert_net_net_thread();
  struct socket_connection_info *c = SOCKET_CONN_INFO(C);

  while (1) {
    int32_t should_run =
        mtproxy_ffi_net_connections_socket_reader_should_run(c->flags);
    assert(should_run == 0 || should_run == 1);
    if (!should_run) {
      break;
    }

    if (!tcp_recv_buffers_num) {
      prealloc_tcp_buffers();
    }

    struct raw_message *in = malloc(sizeof(*in));
    rwm_init(in, 0);

    int s = tcp_recv_buffers_total_size;
    assert(s > 0);

    int p = 1;

    __sync_fetch_and_or(&c->flags, C_NORD);
    int r = readv(c->fd, tcp_recv_iovec + p, MAX_TCP_RECV_BUFFERS + 1 - p);
    int read_errno = (r < 0) ? errno : 0;
    MODULE_STAT->tcp_readv_calls++;

    int32_t io_action = mtproxy_ffi_net_connections_socket_reader_io_action(
        r, read_errno, EAGAIN, EINTR);
    assert(io_action == SOCKET_READER_IO_HAVE_DATA ||
           io_action == SOCKET_READER_IO_BREAK ||
           io_action == SOCKET_READER_IO_CONTINUE_INTR ||
           io_action == SOCKET_READER_IO_FATAL_ABORT);

    if (io_action == SOCKET_READER_IO_CONTINUE_INTR) {
      __sync_fetch_and_and(&c->flags, ~C_NORD);
      MODULE_STAT->tcp_readv_intr++;
      continue;
    }
    if (io_action == SOCKET_READER_IO_FATAL_ABORT) {
      vkprintf(1, "Connection %d: Fatal error %m\n", c->fd);
      job_signal(JOB_REF_CREATE_PASS(C), JS_ABORT);
      __sync_fetch_and_or(&c->flags, C_NET_FAILED);
      return 0;
    }
    if (io_action == SOCKET_READER_IO_HAVE_DATA) {
      __sync_fetch_and_and(&c->flags, ~C_NORD);
    }

    if (verbosity > 0 && r < 0 && read_errno != EAGAIN) {
      perror("recv()");
    }
    if (r < 0) {
      vkprintf(2, "readv from %d: %d read out of %d (errno=%d %s)\n", c->fd, r,
               s, read_errno, strerror(read_errno));
    } else {
      vkprintf(2, "readv from %d: %d read out of %d\n", c->fd, r, s);
    }

    if (io_action == SOCKET_READER_IO_BREAK) {
      rwm_free(in);
      free(in);
      break;
    }
    assert(io_action == SOCKET_READER_IO_HAVE_DATA);

    MODULE_STAT->tcp_readv_bytes += r;
    struct msg_part *mp = 0;
    assert(p == 1);
    mp = new_msg_part(0, tcp_recv_buffers[p - 1]);
    assert(tcp_recv_buffers[p - 1]->data == tcp_recv_iovec[p].iov_base);
    mp->offset = 0;
    mp->data_end =
        r > tcp_recv_iovec[p].iov_len ? tcp_recv_iovec[p].iov_len : r;
    r -= mp->data_end;
    in->first = in->last = mp;
    in->total_bytes = mp->data_end;
    in->first_offset = 0;
    in->last_offset = mp->data_end;
    p++;

    int rs = r;
    while (rs > 0) {
      mp = new_msg_part(0, tcp_recv_buffers[p - 1]);
      mp->offset = 0;
      mp->data_end =
          rs > tcp_recv_iovec[p].iov_len ? tcp_recv_iovec[p].iov_len : rs;
      rs -= mp->data_end;
      in->last->next = mp;
      in->last = mp;
      in->last_offset = mp->data_end;
      in->total_bytes += mp->data_end;
      p++;
    }
    assert(!rs);

    int i;
    for (i = 0; i < p - 1; i++) {
      struct msg_buffer *X =
          alloc_msg_buffer(tcp_recv_buffers[i], TCP_RECV_BUFFER_SIZE);
      if (!X) {
        vkprintf(0, "**FATAL**: cannot allocate tcp receive buffer\n");
        assert(0);
      }
      tcp_recv_buffers[i] = X;
      tcp_recv_iovec[i + 1].iov_base = X->data;
      tcp_recv_iovec[i + 1].iov_len = X->chunk->buffer_size;
    }

    assert(c->conn);
    mpq_push_w(CONN_INFO(c->conn)->in_queue, in, 0);
    job_signal(JOB_REF_CREATE_PASS(c->conn), JS_RUN);
  }
  return 0;
}

/*
  Get data from out raw message and writes it to socket
*/
int net_server_socket_writer(socket_connection_job_t C) {
  enum {
    SOCKET_WRITER_IO_HAVE_DATA = 0,
    SOCKET_WRITER_IO_BREAK_EAGAIN = 1,
    SOCKET_WRITER_IO_CONTINUE_INTR = 2,
    SOCKET_WRITER_IO_FATAL_EAGAIN_LIMIT = 3,
    SOCKET_WRITER_IO_FATAL_OTHER = 4,
  };

  assert_net_net_thread();
  struct socket_connection_info *c = SOCKET_CONN_INFO(C);

  struct raw_message *out = &c->out;

  int check_watermark = out->total_bytes >= c->write_low_watermark;
  int t = 0;

  int stop = c->flags & C_STOPWRITE;

  while (1) {
    int32_t should_run =
        mtproxy_ffi_net_connections_socket_writer_should_run(c->flags);
    assert(should_run == 0 || should_run == 1);
    if (!should_run) {
      break;
    }

    if (!out->total_bytes) {
      __sync_fetch_and_and(&c->flags, ~C_WANTWR);
      break;
    }

    struct iovec iov[384];
    int iovcnt = -1;

    int s = tcp_prepare_iovec(iov, &iovcnt, sizeof(iov) / sizeof(iov[0]), out);
    assert(iovcnt > 0 && s > 0);

    __sync_fetch_and_or(&c->flags, C_NOWR);
    int r = writev(c->fd, iov, iovcnt);
    MODULE_STAT->tcp_writev_calls++;

    int32_t next_eagain_count = c->eagain_count;
    int32_t io_action = mtproxy_ffi_net_connections_socket_writer_io_action(
        r, (r < 0) ? errno : 0, c->eagain_count, EAGAIN, EINTR, 100,
        &next_eagain_count);
    assert(io_action == SOCKET_WRITER_IO_HAVE_DATA ||
           io_action == SOCKET_WRITER_IO_BREAK_EAGAIN ||
           io_action == SOCKET_WRITER_IO_CONTINUE_INTR ||
           io_action == SOCKET_WRITER_IO_FATAL_EAGAIN_LIMIT ||
           io_action == SOCKET_WRITER_IO_FATAL_OTHER);
    c->eagain_count = next_eagain_count;

    if (io_action == SOCKET_WRITER_IO_CONTINUE_INTR) {
      __sync_fetch_and_and(&c->flags, ~C_NOWR);
      MODULE_STAT->tcp_writev_intr++;
      continue;
    }
    if (io_action == SOCKET_WRITER_IO_FATAL_EAGAIN_LIMIT) {
      kprintf("Too much EAGAINs for connection %d (%s), dropping\n", c->fd,
              show_remote_socket_ip(C));
      job_signal(JOB_REF_CREATE_PASS(C), JS_ABORT);
      __sync_fetch_and_or(&c->flags, C_NET_FAILED);
      return 0;
    }
    if (io_action == SOCKET_WRITER_IO_FATAL_OTHER) {
      vkprintf(1, "Connection %d: Fatal error %m\n", c->fd);
      job_signal(JOB_REF_CREATE_PASS(C), JS_ABORT);
      __sync_fetch_and_or(&c->flags, C_NET_FAILED);
      return 0;
    }
    if (io_action == SOCKET_WRITER_IO_HAVE_DATA) {
      __sync_fetch_and_and(&c->flags, ~C_NOWR);
      MODULE_STAT->tcp_writev_bytes += r;
      t += r;
    }

    if (verbosity && r < 0 && errno != EAGAIN) {
      perror("writev()");
    }
    vkprintf(2, "send/writev() to %d: %d written out of %d in %d chunks\n",
             c->fd, r, s, iovcnt);

    if (r > 0) {
      rwm_skip_data(out, r);
      if (c->type->data_sent) {
        c->type->data_sent(C, r);
      }
    }
  }

  int32_t should_call_ready_to_write =
      mtproxy_ffi_net_connections_socket_writer_should_call_ready_to_write(
          check_watermark, out->total_bytes, c->write_low_watermark);
  assert(should_call_ready_to_write == 0 || should_call_ready_to_write == 1);
  if (should_call_ready_to_write) {
    if (c->type->ready_to_write) {
      c->type->ready_to_write(C);
    }
  }

  int32_t should_abort_on_stop =
      mtproxy_ffi_net_connections_socket_writer_should_abort_on_stop(
          !!stop, c->flags);
  assert(should_abort_on_stop == 0 || should_abort_on_stop == 1);
  if (should_abort_on_stop) {
    vkprintf(1, "Closing write_close socket\n");
    job_signal(JOB_REF_CREATE_PASS(C), JS_ABORT);
    __sync_fetch_and_or(&c->flags, C_NET_FAILED);
  }

  vkprintf(2, "socket_server_writer: written %d bytes to %d, flags=0x%08x\n", t,
           c->fd, c->flags);
  return out->total_bytes;
}

/*
  checks if outbound connections become connected
  merges contents of out_packet_queue mpq to out raw message
  runs socket_reader and socket_writer
*/
int net_server_socket_read_write(socket_connection_job_t C) {
  enum {
    SOCKET_READ_WRITE_CONNECT_RETURN_ZERO = 0,
    SOCKET_READ_WRITE_CONNECT_RETURN_COMPUTE_EVENTS = 1,
    SOCKET_READ_WRITE_CONNECT_MARK_CONNECTED = 2,
    SOCKET_READ_WRITE_CONNECT_CONTINUE_IO = 3,
  };

  assert_net_net_thread();

  struct socket_connection_info *c = SOCKET_CONN_INFO(C);

  int32_t connect_action =
      mtproxy_ffi_net_connections_socket_read_write_connect_action(c->flags);
  assert(connect_action == SOCKET_READ_WRITE_CONNECT_RETURN_ZERO ||
         connect_action == SOCKET_READ_WRITE_CONNECT_RETURN_COMPUTE_EVENTS ||
         connect_action == SOCKET_READ_WRITE_CONNECT_MARK_CONNECTED ||
         connect_action == SOCKET_READ_WRITE_CONNECT_CONTINUE_IO);

  if (connect_action == SOCKET_READ_WRITE_CONNECT_RETURN_ZERO) {
    return 0;
  }
  if (connect_action == SOCKET_READ_WRITE_CONNECT_RETURN_COMPUTE_EVENTS) {
    return compute_conn_events(C);
  }
  if (connect_action == SOCKET_READ_WRITE_CONNECT_MARK_CONNECTED) {
    __sync_fetch_and_and(&c->flags, C_PERMANENT);
    __sync_fetch_and_or(&c->flags, C_WANTRD | C_CONNECTED);
    __sync_fetch_and_or(&CONN_INFO(c->conn)->flags,
                        C_READY_PENDING | C_CONNECTED);

    c->type->socket_connected(C);
    job_signal(JOB_REF_CREATE_PASS(c->conn), JS_RUN);
  }
  assert(connect_action == SOCKET_READ_WRITE_CONNECT_MARK_CONNECTED ||
         connect_action == SOCKET_READ_WRITE_CONNECT_CONTINUE_IO);

  vkprintf(2, "END processing connection %d, flags=%d\n", c->fd, c->flags);

  while (mtproxy_ffi_net_connections_socket_reader_should_run(c->flags)) {
    c->type->socket_reader(C);
  }

  struct raw_message *out = &c->out;

  while (1) {
    struct raw_message *raw = mpq_pop_nw(c->out_packet_queue, 4);
    if (!raw) {
      break;
    }
    rwm_union(out, raw);
    free(raw);
  }

  if (out->total_bytes) {
    __sync_fetch_and_or(&c->flags, C_WANTWR);
  }

  while (mtproxy_ffi_net_connections_socket_writer_should_run(c->flags)) {
    c->type->socket_writer(C);
  }

  return compute_conn_events(C);
}

/*
  removes C_NOWR and C_NORD flags if necessary
  reads errors from socket
  sends JS_RUN signal to socket_connection
*/
int net_server_socket_read_write_gateway(int fd, void *data, event_t *ev) {
  enum {
    SOCKET_GATEWAY_ABORT_NONE = 0,
    SOCKET_GATEWAY_ABORT_EPOLLERR = 1,
    SOCKET_GATEWAY_ABORT_DISCONNECT = 2,
  };

  assert_main_thread();
  if (!data) {
    return EVA_REMOVE;
  }

  assert((int)ev->refcnt);

  socket_connection_job_t C = (socket_connection_job_t)data;
  assert(C);
  struct socket_connection_info *c = SOCKET_CONN_INFO(C);
  assert(c->type);

  if (ev->ready & EVT_FROM_EPOLL) {
    // update C_NORD / C_NOWR only if we arrived from epoll()
    vkprintf(2, "fd=%d state=%d ready=%d epoll_ready=%d\n", ev->fd, ev->state,
             ev->ready, ev->epoll_ready);
    ev->ready &= ~EVT_FROM_EPOLL;

    int32_t clear_flags = mtproxy_ffi_net_connections_socket_gateway_clear_flags(
        ev->state, ev->ready);
    assert((clear_flags & ~(C_NORD | C_NOWR)) == 0);
    __sync_fetch_and_and(&c->flags, ~clear_flags);

    int32_t abort_action = mtproxy_ffi_net_connections_socket_gateway_abort_action(
        !!(ev->epoll_ready & EPOLLERR),
        !!(ev->epoll_ready & (EPOLLHUP | EPOLLERR | EPOLLRDHUP | EPOLLPRI)));
    assert(abort_action == SOCKET_GATEWAY_ABORT_NONE ||
           abort_action == SOCKET_GATEWAY_ABORT_EPOLLERR ||
           abort_action == SOCKET_GATEWAY_ABORT_DISCONNECT);

    if (abort_action == SOCKET_GATEWAY_ABORT_EPOLLERR) {
      int error = 0;
      socklen_t errlen = sizeof(error);
      if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen) ==
          0) {
        vkprintf(1, "got error for tcp socket #%d, [%s]:%d : %s\n", c->fd,
                 show_remote_socket_ip(C), c->remote_port, strerror(error));
      }

      job_signal(JOB_REF_CREATE_PASS(C), JS_ABORT);
      return EVA_REMOVE;
    }
    if (abort_action == SOCKET_GATEWAY_ABORT_DISCONNECT) {
      vkprintf(!(ev->epoll_ready & EPOLLPRI),
               "socket #%d: disconnected (epoll_ready=%02x), cleaning\n", c->fd,
               ev->epoll_ready);

      job_signal(JOB_REF_CREATE_PASS(C), JS_ABORT);
      return EVA_REMOVE;
    }
  }

  job_signal(JOB_REF_CREATE_PASS(C), JS_RUN);
  return EVA_CONTINUE;
}

int do_socket_connection_job(job_t job, int op, struct job_thread *JT) {
  enum {
    SOCKET_JOB_ACTION_ERROR = 0,
    SOCKET_JOB_ACTION_ABORT = 1,
    SOCKET_JOB_ACTION_RUN = 2,
    SOCKET_JOB_ACTION_AUX = 3,
    SOCKET_JOB_ACTION_FINISH = 4,
  };

  socket_connection_job_t C = job;

  struct socket_connection_info *c = SOCKET_CONN_INFO(C);

  int32_t action = mtproxy_ffi_net_connections_socket_job_action(
      op, JS_ABORT, JS_RUN, JS_AUX, JS_FINISH);
  assert(action == SOCKET_JOB_ACTION_ERROR ||
         action == SOCKET_JOB_ACTION_ABORT || action == SOCKET_JOB_ACTION_RUN ||
         action == SOCKET_JOB_ACTION_AUX ||
         action == SOCKET_JOB_ACTION_FINISH);

  if (action == SOCKET_JOB_ACTION_ABORT) { // MAIN THREAD
    int32_t abort_who = mtproxy_ffi_net_connections_socket_job_abort_error();
    fail_socket_connection(C, abort_who);
    return JOB_COMPLETED;
  }
  if (action == SOCKET_JOB_ACTION_RUN) { // IO THREAD
    int32_t run_flags = c->flags;
    int32_t should_call_read_write =
        mtproxy_ffi_net_connections_socket_job_run_should_call_read_write(
            run_flags);
    assert(should_call_read_write == 0 || should_call_read_write == 1);
    if (should_call_read_write) {
      int res = c->type->socket_read_write(job);
      int32_t should_signal_aux =
          mtproxy_ffi_net_connections_socket_job_run_should_signal_aux(
              run_flags, res, c->current_epoll_status);
      assert(should_signal_aux == 0 || should_signal_aux == 1);
      if (should_signal_aux) {
        c->current_epoll_status = res;
        return JOB_SENDSIG(JS_AUX);
      }
    }
    return 0;
  }
  if (action == SOCKET_JOB_ACTION_AUX) { // MAIN THREAD
    int32_t should_update_epoll =
        mtproxy_ffi_net_connections_socket_job_aux_should_update_epoll(
            c->flags);
    assert(should_update_epoll == 0 || should_update_epoll == 1);
    if (should_update_epoll) {
      epoll_insert(c->fd, compute_conn_events(job));
    }
    return 0;
  }

  if (action == SOCKET_JOB_ACTION_FINISH) { // ANY THREAD
    assert(C->j_refcnt == 1);
    c->type->socket_free(C);
    return job_free(JOB_REF_PASS(C));
  }

  return JOB_ERROR;
}

/*
  creates socket_connection structure
  insert event to epoll
*/
socket_connection_job_t alloc_new_socket_connection(connection_job_t C) {
  assert_main_thread();
  struct connection_info *c = CONN_INFO(C);

  socket_connection_job_t S = create_async_job(
      do_socket_connection_job,
      JSC_ALLOW(JC_CONNECTION_IO, JS_RUN) |
          JSC_ALLOW(JC_CONNECTION_IO, JS_ALARM) |
          JSC_ALLOW(JC_EPOLL, JS_ABORT) |
          JSC_ALLOW(JC_CONNECTION_IO, JS_FINISH) | JSC_ALLOW(JC_EPOLL, JS_AUX),
      -2, sizeof(struct socket_connection_info), JT_HAVE_TIMER, JOB_REF_NULL);
  S->j_refcnt = 2;
  struct socket_connection_info *s = SOCKET_CONN_INFO(S);
  // memset (s, 0, sizeof (*s)); /* no need, create_async_job memsets itself */

  int32_t socket_flags = 0;
  int32_t initial_epoll_status = 0;
  int32_t allocated_socket_delta = 0;
  int32_t alloc_plan_rc = mtproxy_ffi_net_connections_alloc_socket_connection_plan(
      c->flags, 1, &socket_flags, &initial_epoll_status, &allocated_socket_delta);
  assert(alloc_plan_rc == 0);

  s->fd = c->fd;
  s->type = c->type;
  s->conn = job_incref(C);
  s->flags = socket_flags;

  s->our_ip = c->our_ip;
  s->our_port = c->our_port;
  memcpy(s->our_ipv6, c->our_ipv6, 16);

  s->remote_ip = c->remote_ip;
  s->remote_port = c->remote_port;
  memcpy(s->remote_ipv6, c->remote_ipv6, 16);

  s->out_packet_queue = alloc_mp_queue_w();

  struct event_descr *ev = Events + s->fd;
  assert(!ev->data);
  assert(!ev->refcnt);

  s->ev = ev;

  epoll_sethandler(s->fd, 0, net_server_socket_read_write_gateway, S);

  s->current_epoll_status = initial_epoll_status;
  epoll_insert(s->fd, s->current_epoll_status);

  c->io_conn = S;

  rwm_init(&s->out, 0);
  unlock_job(JOB_REF_CREATE_PASS(S));

  MODULE_STAT->allocated_socket_connections += allocated_socket_delta;
  return S;
}

/*
  accepts new connections
  executes alloc_new_connection ()
*/
int net_accept_new_connections(listening_connection_job_t LCJ) {
  struct listening_connection_info *LC = LISTEN_CONN_INFO(LCJ);

  union sockaddr_in46 peer;
  unsigned peer_addrlen;
  int cfd, acc = 0;

  while (Events[LC->fd].state & EVT_IN_EPOLL) {
    peer_addrlen = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    cfd = accept(LC->fd, (struct sockaddr *)&peer, &peer_addrlen);

    vkprintf(2, "%s: cfd = %d\n", __func__, cfd);
    if (cfd < 0) {
      if (errno != EAGAIN) {
        MODULE_STAT->accept_calls_failed++;
      }
      if (!acc) {
        vkprintf((errno == EAGAIN) * 2,
                 "accept(%d) unexpectedly returns %d: %m\n", LC->fd, cfd);
      }
      break;
    }

    acc++;
    MODULE_STAT->inbound_connections_accepted++;

    if (max_accept_rate) {
      double new_remaining = cur_accept_rate_remaining;
      double new_time = cur_accept_rate_time;
      int32_t allow = mtproxy_ffi_net_connections_accept_rate_decide(
          max_accept_rate, precise_now, cur_accept_rate_remaining,
          cur_accept_rate_time, &new_remaining, &new_time);
      assert(allow == 0 || allow == 1);
      cur_accept_rate_remaining = new_remaining;
      cur_accept_rate_time = new_time;

      if (!allow) {
        MODULE_STAT->accept_rate_limit_failed++;
        close(cfd);
        continue;
      }
    }

    if (LC->flags & C_IPV6) {
      assert(peer_addrlen == sizeof(struct sockaddr_in6));
      assert(peer.a6.sin6_family == AF_INET6);
    } else {
      assert(peer_addrlen == sizeof(struct sockaddr_in));
      assert(peer.a4.sin_family == AF_INET);
    }

    connection_job_t C;
    if (peer.a4.sin_family == AF_INET) {
      C = alloc_new_connection(cfd, NULL, LCJ, ct_inbound, LC->type, LC->extra,
                               ntohl(peer.a4.sin_addr.s_addr), NULL,
                               ntohs(peer.a4.sin_port));
    } else {
      C = alloc_new_connection(cfd, NULL, LCJ, ct_inbound, LC->type, LC->extra,
                               0, peer.a6.sin6_addr.s6_addr,
                               ntohs(peer.a6.sin6_port));
    }
    if (C) {
      assert(CONN_INFO(C)->io_conn);
      unlock_job(JOB_REF_PASS(C));
    }
  }
  return 0;
}

int do_listening_connection_job(job_t job, int op, struct job_thread *JT) {
  enum {
    LISTENING_JOB_ACTION_ERROR = 0,
    LISTENING_JOB_ACTION_RUN = 1,
    LISTENING_JOB_ACTION_AUX = 2,
  };

  listening_connection_job_t LCJ = job;

  int32_t action = mtproxy_ffi_net_connections_listening_job_action(
      op, JS_RUN, JS_AUX);
  assert(action == LISTENING_JOB_ACTION_ERROR ||
         action == LISTENING_JOB_ACTION_RUN ||
         action == LISTENING_JOB_ACTION_AUX);

  if (action == LISTENING_JOB_ACTION_RUN) {
    net_accept_new_connections(LCJ);
    return 0;
  } else if (action == LISTENING_JOB_ACTION_AUX) {
    vkprintf(2, "**Invoking epoll_insert(%d,%d)\n", LISTEN_CONN_INFO(LCJ)->fd,
             EVT_RWX);
    epoll_insert(LISTEN_CONN_INFO(LCJ)->fd, EVT_RWX);
    return 0;
  }
  return JOB_ERROR;
}

int init_listening_connection_ext(int fd, conn_type_t *type, void *extra,
                                  int mode, int prio) {
  enum {
    LISTENING_INIT_FD_OK = 0,
    LISTENING_INIT_FD_REJECT = 1,
    LISTENING_MODE_LOWPRIO = 1,
    LISTENING_MODE_SPECIAL = 1 << 1,
    LISTENING_MODE_NOQACK = 1 << 2,
    LISTENING_MODE_IPV6 = 1 << 3,
    LISTENING_MODE_RAWMSG = 1 << 4,
  };

  if (check_conn_functions(type, 1) < 0) {
    return -1;
  }
  int32_t fd_action = mtproxy_ffi_net_connections_listening_init_fd_action(
      fd, max_connection_fd);
  assert(fd_action == LISTENING_INIT_FD_OK ||
         fd_action == LISTENING_INIT_FD_REJECT);
  if (fd_action == LISTENING_INIT_FD_REJECT) {
    vkprintf(0, "TOO big fd for listening connection %d (max %d)\n", fd,
             max_connection_fd);
    return -1;
  }
  max_connection = mtproxy_ffi_net_connections_listening_init_update_max_connection(
      fd, max_connection);

  listening_connection_job_t LCJ = create_async_job(
      do_listening_connection_job,
      JSC_ALLOW(JC_EPOLL, JS_RUN) | JSC_ALLOW(JC_EPOLL, JS_AUX) |
          JSC_ALLOW(JC_EPOLL, JS_FINISH),
      -2, sizeof(struct listening_connection_info), JT_HAVE_TIMER,
      JOB_REF_NULL);
  LCJ->j_refcnt = 2;

  struct listening_connection_info *LC = LISTEN_CONN_INFO(LCJ);
  memset(LC, 0, sizeof(*LC));

  LC->fd = fd;
  LC->type = type;
  LC->extra = extra;

  struct event_descr *ev = Events + fd;
  assert(!ev->data);
  assert(!ev->refcnt);
  LC->ev = ev;

  LC->generation = new_conn_generation();

  int32_t mode_policy = mtproxy_ffi_net_connections_listening_init_mode_policy(
      mode, SM_LOWPRIO, SM_SPECIAL, SM_NOQACK, SM_IPV6, SM_RAWMSG);
  assert((mode_policy & ~(LISTENING_MODE_LOWPRIO | LISTENING_MODE_SPECIAL |
                          LISTENING_MODE_NOQACK | LISTENING_MODE_IPV6 |
                          LISTENING_MODE_RAWMSG)) == 0);

  if (mode_policy & LISTENING_MODE_LOWPRIO) {
    prio = 10;
  }

  if (mode_policy & LISTENING_MODE_SPECIAL) {
    LC->flags |= C_SPECIAL;
    int idx = __sync_fetch_and_add(&special_listen_sockets, 1);
    assert(idx < MAX_SPECIAL_LISTEN_SOCKETS);
    special_socket[idx].fd = LC->fd;
    special_socket[idx].generation = LC->generation;
  }

  if (mode_policy & LISTENING_MODE_NOQACK) {
    LC->flags |= C_NOQACK;
    disable_qack(LC->fd);
  }

  if (mode_policy & LISTENING_MODE_IPV6) {
    LC->flags |= C_IPV6;
  }

  if (mode_policy & LISTENING_MODE_RAWMSG) {
    LC->flags |= C_RAWMSG;
  }

  epoll_sethandler(fd, prio, net_server_socket_read_write_gateway, LCJ);
  epoll_insert(fd, EVT_RWX);

  MODULE_STAT->listening_connections++;

  unlock_job(JOB_REF_PASS(LCJ));

  return 0;
}

int init_listening_connection(int fd, conn_type_t *type, void *extra) {
  return init_listening_connection_ext(fd, type, extra, 0, -10);
}

int init_listening_tcpv6_connection(int fd, conn_type_t *type, void *extra,
                                    int mode) {
  return init_listening_connection_ext(fd, type, extra, mode, -10);
}

void connection_event_incref(int fd, long long val) {
  struct event_descr *ev = &Events[fd];

  long long new_refcnt = __sync_add_and_fetch(&ev->refcnt, val);
  int32_t should_release = mtproxy_ffi_net_connections_connection_event_should_release(
      new_refcnt, ev->data != NULL);
  assert(should_release == 0 || should_release == 1);
  if (should_release) {
    socket_connection_job_t C = ev->data;
    ev->data = NULL;
    job_decref(JOB_REF_PASS(C));
  }
}

connection_job_t connection_get_by_fd(int fd) {
  enum {
    CONN_GET_BY_FD_ACTION_RETURN_SELF = 1,
    CONN_GET_BY_FD_ACTION_RETURN_NULL = 2,
    CONN_GET_BY_FD_ACTION_RETURN_CONN = 3,
  };

  struct event_descr *ev = &Events[fd];
  if (!(int)(ev->refcnt) || !ev->data) {
    return NULL;
  }

  while (1) {
    long long v = __sync_fetch_and_add(&ev->refcnt, (1ll << 32));
    if (((int)v) != 0) {
      break;
    }
    v = __sync_fetch_and_add(&ev->refcnt, -(1ll << 32));
    if (((int)v) != 0) {
      continue;
    }
    return NULL;
  }
  __sync_fetch_and_add(&ev->refcnt, 1 - (1ll << 32));
  socket_connection_job_t C = job_incref(ev->data);

  connection_event_incref(fd, -1);

  int32_t is_listening_job = (C->j_execute == &do_listening_connection_job);
  int32_t is_socket_job = (C->j_execute == &do_socket_connection_job);
  int32_t socket_flags =
      is_socket_job ? SOCKET_CONN_INFO(C)->flags : 0;
  int32_t action = mtproxy_ffi_net_connections_connection_get_by_fd_action(
      is_listening_job, is_socket_job, socket_flags);
  assert(action == CONN_GET_BY_FD_ACTION_RETURN_SELF ||
         action == CONN_GET_BY_FD_ACTION_RETURN_NULL ||
         action == CONN_GET_BY_FD_ACTION_RETURN_CONN);

  if (action == CONN_GET_BY_FD_ACTION_RETURN_SELF) {
    return C;
  }

  assert(is_socket_job);
  struct socket_connection_info *c = SOCKET_CONN_INFO(C);
  if (action == CONN_GET_BY_FD_ACTION_RETURN_NULL) {
    job_decref(JOB_REF_PASS(C));
    return NULL;
  }

  assert(action == CONN_GET_BY_FD_ACTION_RETURN_CONN);
  assert(c->conn);
  connection_job_t C2 = job_incref(c->conn);
  job_decref(JOB_REF_PASS(C));
  return C2;
}

connection_job_t connection_get_by_fd_generation(int fd, int generation) {
  connection_job_t C = connection_get_by_fd(fd);
  if (C) {
    int32_t generation_matches =
        mtproxy_ffi_net_connections_connection_generation_matches(
            CONN_INFO(C)->generation, generation);
    assert(generation_matches == 0 || generation_matches == 1);
    if (!generation_matches) {
      job_decref(JOB_REF_PASS(C));
      return NULL;
    }
  }
  return C;
}

int server_check_ready(connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  int32_t ready =
      mtproxy_ffi_net_connections_server_check_ready(c->status, c->ready);
  assert(ready >= cr_notyet && ready <= cr_failed);
  c->ready = ready;
  return ready;
}

int server_noop(connection_job_t C) { return 0; }

int server_failed(connection_job_t C) {
  kprintf("connection %d: call to pure virtual method\n", CONN_INFO(C)->fd);
  assert(0);
  return -1;
}

int server_flush(connection_job_t C) {
  // job_signal (job_incref (C), JS_RUN);
  return 0;
}

int check_conn_functions(conn_type_t *type, int listening) {
  enum {
    CHECK_CONN_DEFAULT_SET_TITLE = 1 << 0,
    CHECK_CONN_DEFAULT_SET_SOCKET_READ_WRITE = 1 << 1,
    CHECK_CONN_DEFAULT_SET_SOCKET_READER = 1 << 2,
    CHECK_CONN_DEFAULT_SET_SOCKET_WRITER = 1 << 3,
    CHECK_CONN_DEFAULT_SET_SOCKET_CLOSE = 1 << 4,
    CHECK_CONN_DEFAULT_SET_CLOSE = 1 << 5,
    CHECK_CONN_DEFAULT_SET_INIT_OUTBOUND = 1 << 6,
    CHECK_CONN_DEFAULT_SET_WAKEUP = 1 << 7,
    CHECK_CONN_DEFAULT_SET_ALARM = 1 << 8,
    CHECK_CONN_DEFAULT_SET_CONNECTED = 1 << 9,
    CHECK_CONN_DEFAULT_SET_FLUSH = 1 << 10,
    CHECK_CONN_DEFAULT_SET_CHECK_READY = 1 << 11,
    CHECK_CONN_DEFAULT_SET_READ_WRITE = 1 << 12,
    CHECK_CONN_DEFAULT_SET_FREE = 1 << 13,
    CHECK_CONN_DEFAULT_SET_SOCKET_CONNECTED = 1 << 14,
    CHECK_CONN_DEFAULT_SET_SOCKET_FREE = 1 << 15,
    CHECK_CONN_ACCEPT_SET_ACCEPT_LISTEN = 1 << 0,
    CHECK_CONN_ACCEPT_SET_ACCEPT_FAILED = 1 << 1,
    CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_NOOP = 1 << 2,
    CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_FAILED = 1 << 3,
    CHECK_CONN_RAW_SET_FREE_BUFFERS = 1 << 0,
    CHECK_CONN_RAW_SET_READER = 1 << 1,
    CHECK_CONN_RAW_SET_WRITER = 1 << 2,
    CHECK_CONN_NONRAW_ASSERT_FREE_BUFFERS = 1 << 0,
    CHECK_CONN_NONRAW_ASSERT_READER = 1 << 1,
    CHECK_CONN_NONRAW_ASSERT_WRITER = 1 << 2,
  };

  if (type->magic != CONN_FUNC_MAGIC) {
    return -1;
  }

  int32_t default_mask =
      mtproxy_ffi_net_connections_check_conn_functions_default_mask(
          type->title != NULL, type->socket_read_write != NULL,
          type->socket_reader != NULL, type->socket_writer != NULL,
          type->socket_close != NULL, type->close != NULL,
          type->init_outbound != NULL, type->wakeup != NULL,
          type->alarm != NULL, type->connected != NULL, type->flush != NULL,
          type->check_ready != NULL, type->read_write != NULL,
          type->free != NULL, type->socket_connected != NULL,
          type->socket_free != NULL);
  assert((default_mask & ~(CHECK_CONN_DEFAULT_SET_TITLE |
                           CHECK_CONN_DEFAULT_SET_SOCKET_READ_WRITE |
                           CHECK_CONN_DEFAULT_SET_SOCKET_READER |
                           CHECK_CONN_DEFAULT_SET_SOCKET_WRITER |
                           CHECK_CONN_DEFAULT_SET_SOCKET_CLOSE |
                           CHECK_CONN_DEFAULT_SET_CLOSE |
                           CHECK_CONN_DEFAULT_SET_INIT_OUTBOUND |
                           CHECK_CONN_DEFAULT_SET_WAKEUP |
                           CHECK_CONN_DEFAULT_SET_ALARM |
                           CHECK_CONN_DEFAULT_SET_CONNECTED |
                           CHECK_CONN_DEFAULT_SET_FLUSH |
                           CHECK_CONN_DEFAULT_SET_CHECK_READY |
                           CHECK_CONN_DEFAULT_SET_READ_WRITE |
                           CHECK_CONN_DEFAULT_SET_FREE |
                           CHECK_CONN_DEFAULT_SET_SOCKET_CONNECTED |
                           CHECK_CONN_DEFAULT_SET_SOCKET_FREE)) == 0);

  if (default_mask & CHECK_CONN_DEFAULT_SET_TITLE) {
    type->title = "(unknown)";
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_READ_WRITE) {
    type->socket_read_write = net_server_socket_read_write;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_READER) {
    type->socket_reader = net_server_socket_reader;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_WRITER) {
    type->socket_writer = net_server_socket_writer;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_CLOSE) {
    type->socket_close = server_noop;
  }

  int32_t accept_mask = mtproxy_ffi_net_connections_check_conn_functions_accept_mask(
      !!listening, type->accept != NULL, type->init_accepted != NULL);
  assert((accept_mask & ~(CHECK_CONN_ACCEPT_SET_ACCEPT_LISTEN |
                          CHECK_CONN_ACCEPT_SET_ACCEPT_FAILED |
                          CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_NOOP |
                          CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_FAILED)) == 0);

  if (accept_mask & CHECK_CONN_ACCEPT_SET_ACCEPT_LISTEN) {
    type->accept = net_accept_new_connections;
  }
  if (accept_mask & CHECK_CONN_ACCEPT_SET_ACCEPT_FAILED) {
    type->accept = server_failed;
  }
  if (accept_mask & CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_NOOP) {
    type->init_accepted = server_noop;
  }
  if (accept_mask & CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_FAILED) {
    type->init_accepted = server_failed;
  }

  if (default_mask & CHECK_CONN_DEFAULT_SET_CLOSE) {
    type->close = cpu_server_close_connection;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_INIT_OUTBOUND) {
    type->init_outbound = server_noop;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_WAKEUP) {
    type->wakeup = server_noop;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_ALARM) {
    type->alarm = server_noop;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_CONNECTED) {
    type->connected = server_noop;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_FLUSH) {
    type->flush = server_flush;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_CHECK_READY) {
    type->check_ready = server_check_ready;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_READ_WRITE) {
    type->read_write = cpu_server_read_write;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_FREE) {
    type->free = cpu_server_free_connection;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_CONNECTED) {
    type->socket_connected = server_noop;
  }
  if (default_mask & CHECK_CONN_DEFAULT_SET_SOCKET_FREE) {
    type->socket_free = net_server_socket_free;
  }

  int32_t raw_assign_mask = 0;
  int32_t nonraw_assert_mask = 0;
  int32_t raw_rc = mtproxy_ffi_net_connections_check_conn_functions_raw_policy(
      !!(type->flags & C_RAWMSG), type->free_buffers != NULL,
      type->reader != NULL, type->writer != NULL, type->parse_execute != NULL,
      &raw_assign_mask, &nonraw_assert_mask);
  assert(raw_rc == 0 || raw_rc == -1);
  assert((raw_assign_mask & ~(CHECK_CONN_RAW_SET_FREE_BUFFERS |
                              CHECK_CONN_RAW_SET_READER |
                              CHECK_CONN_RAW_SET_WRITER)) == 0);
  assert((nonraw_assert_mask & ~(CHECK_CONN_NONRAW_ASSERT_FREE_BUFFERS |
                                 CHECK_CONN_NONRAW_ASSERT_READER |
                                 CHECK_CONN_NONRAW_ASSERT_WRITER)) == 0);

  if (type->flags & C_RAWMSG) {
    if (raw_assign_mask & CHECK_CONN_RAW_SET_FREE_BUFFERS) {
      type->free_buffers = cpu_tcp_free_connection_buffers;
    }
    if (raw_assign_mask & CHECK_CONN_RAW_SET_READER) {
      type->reader = cpu_tcp_server_reader;
    }
    if (raw_rc < 0) {
      return -1;
    }
    if (raw_assign_mask & CHECK_CONN_RAW_SET_WRITER) {
      type->writer = cpu_tcp_server_writer;
    }
  } else {
    if (nonraw_assert_mask & CHECK_CONN_NONRAW_ASSERT_FREE_BUFFERS) {
      assert(0);
    }
    if (nonraw_assert_mask & CHECK_CONN_NONRAW_ASSERT_READER) {
      assert(0);
    }
    if (nonraw_assert_mask & CHECK_CONN_NONRAW_ASSERT_WRITER) {
      assert(0);
    }
  }
  return 0;
}

/* CONN TARGETS {{{ */

void compute_next_reconnect(conn_target_job_t CT) {
  struct conn_target_info *S = CONN_TARGET_INFO(CT);
  double next_reconnect = 0.0;
  double next_reconnect_timeout = S->next_reconnect_timeout;
  int32_t rc = mtproxy_ffi_net_connections_compute_next_reconnect(
      S->reconnect_timeout, S->next_reconnect_timeout,
      S->active_outbound_connections, precise_now, drand48_j(),
      &next_reconnect, &next_reconnect_timeout);
  assert(rc == 0);
  S->next_reconnect = next_reconnect;
  S->next_reconnect_timeout = next_reconnect_timeout;
}

static void count_connection_num(connection_job_t C, void *good_c,
                                 void *stopped_c, void *bad_c) {
  int cr = CONN_INFO(C)->type->check_ready(C);
  int32_t bucket = mtproxy_ffi_net_connections_target_ready_bucket(cr);
  if (bucket == 0) {
    return;
  } else if (bucket == 1) {
    (*(int *)good_c)++;
  } else if (bucket == 2) {
    (*(int *)stopped_c)++;
  } else if (bucket == 3) {
    (*(int *)bad_c)++;
  } else {
    assert(bucket == -1);
    assert(0);
  }
}

static void find_bad_connection(connection_job_t C, void *x) {
  connection_job_t *T = x;
  int32_t should_select = mtproxy_ffi_net_connections_target_find_bad_should_select(
      *T != NULL, CONN_INFO(C)->flags);
  assert(should_select == 0 || should_select == 1);
  if (should_select) {
    *T = C;
  }
}

/*
  Deletes failed connections (with flag C_ERROR) from target's tree
*/
void destroy_dead_target_connections(conn_target_job_t CTJ) {
  struct conn_target_info *CT = CONN_TARGET_INFO(CTJ);

  struct tree_connection *T = get_tree_ptr_connection(&CT->conn_tree);

  while (1) {
    connection_job_t CJ = NULL;
    tree_act_ex_connection(T, find_bad_connection, &CJ);
    if (!CJ) {
      break;
    }

    int32_t active_outbound_delta = 0;
    int32_t outbound_delta = 0;
    int32_t rc_deltas =
        mtproxy_ffi_net_connections_target_remove_dead_connection_deltas(
            CONN_INFO(CJ)->flags, &active_outbound_delta, &outbound_delta);
    assert(rc_deltas == 0);
    __sync_fetch_and_add(&CT->active_outbound_connections, active_outbound_delta);
    __sync_fetch_and_add(&CT->outbound_connections, outbound_delta);

    T = tree_delete_connection(T, CJ);
  }

  int good_c = 0, bad_c = 0, stopped_c = 0;

  tree_act_ex3_connection(T, count_connection_num, &good_c, &stopped_c, &bad_c);

  int was_ready = CT->ready_outbound_connections;
  CT->ready_outbound_connections = good_c;

  int32_t ready_outbound_delta = 0;
  int32_t ready_targets_delta = 0;
  int32_t rc = mtproxy_ffi_net_connections_target_ready_transition(
      was_ready, CT->ready_outbound_connections, &ready_outbound_delta,
      &ready_targets_delta);
  assert(rc == 0);
  MODULE_STAT->ready_outbound_connections += ready_outbound_delta;
  MODULE_STAT->ready_targets += ready_targets_delta;

  int32_t tree_update_action = mtproxy_ffi_net_connections_target_tree_update_action(
      T != CT->conn_tree);
  assert(tree_update_action == 0 || tree_update_action == 1);
  if (tree_update_action == 0) {
    tree_free_connection(T);
  } else {
    struct tree_connection *old = CT->conn_tree;
    CT->conn_tree = T;
    barrier();
    __sync_synchronize();
    free_tree_ptr_connection(old);
  }
}

/*
  creates new connections for target
  must be called in main thread, because we can allocate new connections only in
  main thread
*/
int create_new_connections(conn_target_job_t CTJ) {
  assert_main_thread();

  destroy_dead_target_connections(CTJ);
  struct conn_target_info *CT = CONN_TARGET_INFO(CTJ);

  int count = 0, good_c = 0, bad_c = 0, stopped_c = 0, need_c;

  tree_act_ex3_connection(CT->conn_tree, count_connection_num, &good_c,
                          &stopped_c, &bad_c);

  int was_ready = CT->ready_outbound_connections;
  CT->ready_outbound_connections = good_c;

  int32_t ready_outbound_delta = 0;
  int32_t ready_targets_delta = 0;
  int32_t rc = mtproxy_ffi_net_connections_target_ready_transition(
      was_ready, CT->ready_outbound_connections, &ready_outbound_delta,
      &ready_targets_delta);
  assert(rc == 0);
  MODULE_STAT->ready_outbound_connections += ready_outbound_delta;
  MODULE_STAT->ready_targets += ready_targets_delta;

  need_c = mtproxy_ffi_net_connections_target_needed_connections(
      CT->min_connections, CT->max_connections, bad_c, stopped_c);
  assert(need_c <= CT->max_connections);

  if (mtproxy_ffi_net_connections_target_should_attempt_reconnect(
          precise_now, CT->next_reconnect, CT->active_outbound_connections)) {
    struct tree_connection *T = get_tree_ptr_connection(&CT->conn_tree);

    while (CT->outbound_connections < need_c) {
      int cfd = -1;
      int32_t connect_action =
          mtproxy_ffi_net_connections_target_connect_socket_action(
              CT->target.s_addr != 0);
      assert(connect_action == 1 || connect_action == 2);
      if (connect_action == 1) {
        cfd = client_socket(CT->target.s_addr, CT->port, 0);
        vkprintf(1, "Created NEW connection #%d to %s:%d\n", cfd,
                 inet_ntoa(CT->target), CT->port);
      } else {
        cfd = client_socket_ipv6(CT->target_ipv6, CT->port, SM_IPV6);
        vkprintf(1, "Created NEW ipv6 connection #%d to [%s]:%d\n", cfd,
                 show_ipv6(CT->target_ipv6), CT->port);
      }
      if (cfd < 0) {
        if (connect_action == 1) {
          vkprintf(1, "error connecting to %s:%d: %m\n", inet_ntoa(CT->target),
                   CT->port);
        } else {
          vkprintf(1, "error connecting to [%s]:%d\n",
                   show_ipv6(CT->target_ipv6), CT->port);
        }
        break;
      }

      connection_job_t C = alloc_new_connection(
          cfd, CTJ, NULL, ct_outbound, CT->type, CT->extra,
          ntohl(CT->target.s_addr), CT->target_ipv6, CT->port);

      int32_t should_insert =
          mtproxy_ffi_net_connections_target_create_insert_should_insert(
              C != NULL);
      assert(should_insert == 0 || should_insert == 1);
      if (should_insert) {
        assert(C);
        assert(CONN_INFO(C)->io_conn);
        count++;
        unlock_job(JOB_REF_CREATE_PASS(C));
        T = tree_insert_connection(T, C, lrand48_j());
      } else {
        break;
      }
    }

    int32_t tree_update_action = mtproxy_ffi_net_connections_target_tree_update_action(
        T != CT->conn_tree);
    assert(tree_update_action == 0 || tree_update_action == 1);
    if (tree_update_action == 0) {
      tree_free_connection(T);
    } else {
      struct tree_connection *old = CT->conn_tree;
      CT->conn_tree = T;
      __sync_synchronize();
      free_tree_ptr_connection(old);
    }

    compute_next_reconnect(CTJ);
  }

  return count;
}

conn_target_job_t HTarget[PRIME_TARGETS];
pthread_mutex_t TargetsLock = PTHREAD_MUTEX_INITIALIZER;

/* must be called with mutex held */
/* mode = 0 -- lookup, mode = 1 -- insert, mode = -1 -- delete */
static conn_target_job_t find_target(struct in_addr ad, int port,
                                     conn_type_t *type, void *extra, int mode,
                                     conn_target_job_t new_target) {
  enum {
    TARGET_LOOKUP_MATCH_REMOVE_AND_RETURN = 1,
    TARGET_LOOKUP_MATCH_RETURN_FOUND = 2,
    TARGET_LOOKUP_MATCH_ASSERT_INVALID = 3,
    TARGET_LOOKUP_MISS_INSERT_NEW = 1,
    TARGET_LOOKUP_MISS_RETURN_NULL = 2,
    TARGET_LOOKUP_MISS_ASSERT_INVALID = 3,
  };

  assert(ad.s_addr);
  int32_t h1_i32 = mtproxy_ffi_net_connections_target_bucket_ipv4(
      (size_t)type, ad.s_addr, port, PRIME_TARGETS);
  assert(h1_i32 >= 0 && h1_i32 < PRIME_TARGETS);
  unsigned h1 = (unsigned)h1_i32;
  conn_target_job_t *prev = HTarget + h1, cur;
  while ((cur = *prev) != 0) {
    struct conn_target_info *S = CONN_TARGET_INFO(cur);
    if (S->target.s_addr == ad.s_addr && S->port == port && S->type == type &&
        S->extra == extra) {
      int32_t match_action =
          mtproxy_ffi_net_connections_target_lookup_match_action(mode);
      assert(match_action == TARGET_LOOKUP_MATCH_REMOVE_AND_RETURN ||
             match_action == TARGET_LOOKUP_MATCH_RETURN_FOUND ||
             match_action == TARGET_LOOKUP_MATCH_ASSERT_INVALID);
      if (match_action == TARGET_LOOKUP_MATCH_REMOVE_AND_RETURN) {
        *prev = S->hnext;
        S->hnext = 0;
        return cur;
      }
      if (match_action == TARGET_LOOKUP_MATCH_RETURN_FOUND) {
        return cur;
      }
      assert(match_action == TARGET_LOOKUP_MATCH_ASSERT_INVALID);
      assert(!mode);
      return 0;
    }
    prev = &S->hnext;
  }
  int32_t miss_action = mtproxy_ffi_net_connections_target_lookup_miss_action(
      mode);
  assert(miss_action == TARGET_LOOKUP_MISS_INSERT_NEW ||
         miss_action == TARGET_LOOKUP_MISS_RETURN_NULL ||
         miss_action == TARGET_LOOKUP_MISS_ASSERT_INVALID);
  if (miss_action == TARGET_LOOKUP_MISS_INSERT_NEW) {
    CONN_TARGET_INFO(new_target)->hnext = HTarget[h1];
    HTarget[h1] = new_target;
    return new_target;
  }
  if (miss_action == TARGET_LOOKUP_MISS_RETURN_NULL) {
    return 0;
  }
  assert(miss_action == TARGET_LOOKUP_MISS_ASSERT_INVALID);
  assert(mode >= 0);
  return 0;
}

/* must be called with mutex held */
/* mode = 0 -- lookup, mode = 1 -- insert, mode = -1 -- delete */
static conn_target_job_t find_target_ipv6(unsigned char ad_ipv6[16], int port,
                                          conn_type_t *type, void *extra,
                                          int mode,
                                          conn_target_job_t new_target) {
  enum {
    TARGET_LOOKUP_MATCH_REMOVE_AND_RETURN = 1,
    TARGET_LOOKUP_MATCH_RETURN_FOUND = 2,
    TARGET_LOOKUP_MATCH_ASSERT_INVALID = 3,
    TARGET_LOOKUP_MISS_INSERT_NEW = 1,
    TARGET_LOOKUP_MISS_RETURN_NULL = 2,
    TARGET_LOOKUP_MISS_ASSERT_INVALID = 3,
  };

  assert(*(long long *)ad_ipv6 || ((long long *)ad_ipv6)[1]);
  int32_t h1_i32 = mtproxy_ffi_net_connections_target_bucket_ipv6(
      (size_t)type, ad_ipv6, port, PRIME_TARGETS);
  assert(h1_i32 >= 0 && h1_i32 < PRIME_TARGETS);
  unsigned h1 = (unsigned)h1_i32;
  conn_target_job_t *prev = HTarget + h1, cur;
  while ((cur = *prev) != 0) {
    struct conn_target_info *S = CONN_TARGET_INFO(cur);
    if (((long long *)S->target_ipv6)[1] == ((long long *)ad_ipv6)[1] &&
        *(long long *)S->target_ipv6 == *(long long *)ad_ipv6 &&
        S->port == port && S->type == type && !S->target.s_addr &&
        S->extra == extra) {
      int32_t match_action =
          mtproxy_ffi_net_connections_target_lookup_match_action(mode);
      assert(match_action == TARGET_LOOKUP_MATCH_REMOVE_AND_RETURN ||
             match_action == TARGET_LOOKUP_MATCH_RETURN_FOUND ||
             match_action == TARGET_LOOKUP_MATCH_ASSERT_INVALID);
      if (match_action == TARGET_LOOKUP_MATCH_REMOVE_AND_RETURN) {
        *prev = S->hnext;
        S->hnext = 0;
        return cur;
      }
      if (match_action == TARGET_LOOKUP_MATCH_RETURN_FOUND) {
        return cur;
      }
      assert(match_action == TARGET_LOOKUP_MATCH_ASSERT_INVALID);
      assert(!mode);
      return 0;
    }
    prev = &S->hnext;
  }
  int32_t miss_action = mtproxy_ffi_net_connections_target_lookup_miss_action(
      mode);
  assert(miss_action == TARGET_LOOKUP_MISS_INSERT_NEW ||
         miss_action == TARGET_LOOKUP_MISS_RETURN_NULL ||
         miss_action == TARGET_LOOKUP_MISS_ASSERT_INVALID);
  if (miss_action == TARGET_LOOKUP_MISS_INSERT_NEW) {
    CONN_TARGET_INFO(new_target)->hnext = HTarget[h1];
    HTarget[h1] = new_target;
    return new_target;
  }
  if (miss_action == TARGET_LOOKUP_MISS_RETURN_NULL) {
    return 0;
  }
  assert(miss_action == TARGET_LOOKUP_MISS_ASSERT_INVALID);
  assert(mode >= 0);
  return 0;
}

static int free_target(conn_target_job_t CTJ) {
  enum {
    TARGET_FREE_ACTION_REJECT = 0,
    TARGET_FREE_ACTION_DELETE_IPV4 = 1,
    TARGET_FREE_ACTION_DELETE_IPV6 = 2,
  };

  pthread_mutex_lock(&TargetsLock);
  struct conn_target_info *CT = CONN_TARGET_INFO(CTJ);
  int32_t free_action = mtproxy_ffi_net_connections_target_free_action(
      CT->global_refcnt, CT->conn_tree != NULL, CT->target.s_addr != 0);
  assert(free_action == TARGET_FREE_ACTION_REJECT ||
         free_action == TARGET_FREE_ACTION_DELETE_IPV4 ||
         free_action == TARGET_FREE_ACTION_DELETE_IPV6);
  if (free_action == TARGET_FREE_ACTION_REJECT) {
    pthread_mutex_unlock(&TargetsLock);
    return -1;
  }

  assert(CT && CT->type && !CT->global_refcnt);
  assert(!CT->conn_tree);
  if (free_action == TARGET_FREE_ACTION_DELETE_IPV4) {
    vkprintf(1, "Freeing unused target to %s:%d\n", inet_ntoa(CT->target),
             CT->port);
    assert(CTJ ==
           find_target(CT->target, CT->port, CT->type, CT->extra, -1, 0));
  } else {
    assert(free_action == TARGET_FREE_ACTION_DELETE_IPV6);
    vkprintf(1, "Freeing unused ipv6 target to [%s]:%d\n",
             show_ipv6(CT->target_ipv6), CT->port);
    assert(CTJ == find_target_ipv6(CT->target_ipv6, CT->port, CT->type,
                                   CT->extra, -1, 0));
  }

  pthread_mutex_unlock(&TargetsLock);

  MODULE_STAT->inactive_targets--;
  MODULE_STAT->free_targets++;

  job_decref(JOB_REF_PASS(CTJ));

  return 1;
}

static void fail_connection_gw(connection_job_t C) { fail_connection(C, -17); }

int clean_unused_target(conn_target_job_t CTJ) {
  assert(CTJ);
  struct conn_target_info *CT = CONN_TARGET_INFO(CTJ);
  assert(CT->type);
  if (CT->global_refcnt) {
    return 0;
  }
  if (CT->conn_tree) {
    tree_act_connection(CT->conn_tree, fail_connection_gw);
    return 0;
  }
  job_timer_remove(CTJ);
  return 0;
}

int destroy_target(JOB_REF_ARG(CTJ)) {
  struct conn_target_info *CT = CONN_TARGET_INFO(CTJ);
  assert(CT);
  assert(CT->type);
  assert(CT->global_refcnt > 0);

  int r = __sync_add_and_fetch(&CT->global_refcnt, -1);
  int32_t active_targets_delta = 0;
  int32_t inactive_targets_delta = 0;
  int32_t signal_run = mtproxy_ffi_net_connections_destroy_target_transition(
      r, &active_targets_delta, &inactive_targets_delta);
  assert(signal_run == 0 || signal_run == 1);
  MODULE_STAT->active_targets += active_targets_delta;
  MODULE_STAT->inactive_targets += inactive_targets_delta;

  if (signal_run) {
    job_signal(JOB_REF_PASS(CTJ), JS_RUN);
  } else {
    job_decref(JOB_REF_PASS(CTJ));
  }
  return r;
}

int do_conn_target_job(job_t job, int op, struct job_thread *JT) {
  enum {
    TARGET_JOB_UPDATE_INACTIVE_CLEANUP = 0,
    TARGET_JOB_UPDATE_CREATE_CONNECTIONS = 1,
    TARGET_JOB_POST_RETURN_ZERO = 0,
    TARGET_JOB_POST_SCHEDULE_RETRY = 1,
    TARGET_JOB_POST_ATTEMPT_FREE = 2,
    TARGET_JOB_FINALIZE_COMPLETED = 1,
    TARGET_JOB_FINALIZE_SCHEDULE_RETRY = 2,
  };

  if (epoll_fd <= 0) {
    job_timer_insert(job,
                     precise_now + mtproxy_ffi_net_connections_target_job_boot_delay());
    return 0;
  }
  conn_target_job_t CTJ = job;
  struct conn_target_info *CT = CONN_TARGET_INFO(CTJ);

  if (op == JS_ALARM || op == JS_RUN) {
    int32_t timer_check_ok = (op != JS_ALARM) || job_timer_check(job);
    int32_t should_run = mtproxy_ffi_net_connections_target_job_should_run_tick(
        op == JS_ALARM, timer_check_ok);
    assert(should_run == 0 || should_run == 1);
    if (!should_run) {
      return 0;
    }

    int32_t update_mode =
        mtproxy_ffi_net_connections_target_job_update_mode(CT->global_refcnt);
    assert(update_mode == TARGET_JOB_UPDATE_INACTIVE_CLEANUP ||
           update_mode == TARGET_JOB_UPDATE_CREATE_CONNECTIONS);
    if (update_mode == TARGET_JOB_UPDATE_INACTIVE_CLEANUP) {
      destroy_dead_target_connections(CTJ);
      clean_unused_target(CTJ);
      compute_next_reconnect(CTJ);
    } else {
      create_new_connections(CTJ);
    }

    int32_t post_action = mtproxy_ffi_net_connections_target_job_post_tick_action(
        !!(CTJ->j_flags & JF_COMPLETED), CT->global_refcnt, !!CT->conn_tree);
    assert(post_action == TARGET_JOB_POST_RETURN_ZERO ||
           post_action == TARGET_JOB_POST_SCHEDULE_RETRY ||
           post_action == TARGET_JOB_POST_ATTEMPT_FREE);

    if (post_action == TARGET_JOB_POST_RETURN_ZERO) {
      return 0;
    }

    double retry_delay = mtproxy_ffi_net_connections_target_job_retry_delay();
    if (post_action == TARGET_JOB_POST_SCHEDULE_RETRY) {
      job_timer_insert(CTJ, precise_now + retry_delay);
      return 0;
    }

    assert(post_action == TARGET_JOB_POST_ATTEMPT_FREE);
    int32_t finalize_action =
        mtproxy_ffi_net_connections_target_job_finalize_free_action(
            free_target(CTJ));
    assert(finalize_action == TARGET_JOB_FINALIZE_COMPLETED ||
           finalize_action == TARGET_JOB_FINALIZE_SCHEDULE_RETRY);
    if (finalize_action == TARGET_JOB_FINALIZE_COMPLETED) {
      return JOB_COMPLETED;
    }
    job_timer_insert(CTJ, precise_now + retry_delay);
    return 0;
  }
  if (op == JS_FINISH) {
    assert(CTJ->j_flags & JF_COMPLETED);
    MODULE_STAT->allocated_targets--;
    return job_free(JOB_REF_PASS(job));
  }

  return JOB_ERROR;
}

conn_target_job_t create_target(struct conn_target_info *source,
                                int *was_created) {
  if (check_conn_functions(source->type, 0) < 0) {
    return NULL;
  }
  pthread_mutex_lock(&TargetsLock);

  conn_target_job_t T =
      source->target.s_addr
          ? find_target(source->target, source->port, source->type,
                        source->extra, 0, 0)
          : find_target_ipv6(source->target_ipv6, source->port, source->type,
                             source->extra, 0, 0);

  if (T) {
    struct conn_target_info *t = CONN_TARGET_INFO(T);

    t->min_connections = source->min_connections;
    t->max_connections = source->max_connections;
    t->reconnect_timeout = source->reconnect_timeout;

    int32_t old_global_refcnt = __sync_fetch_and_add(&t->global_refcnt, 1);
    int32_t active_targets_delta = 0;
    int32_t inactive_targets_delta = 0;
    int32_t created_state = 0;
    int32_t rc = mtproxy_ffi_net_connections_create_target_transition(
        1, old_global_refcnt, &active_targets_delta, &inactive_targets_delta,
        &created_state);
    assert(rc == 0);
    MODULE_STAT->active_targets += active_targets_delta;
    MODULE_STAT->inactive_targets += inactive_targets_delta;
    if (was_created) {
      *was_created = created_state;
    }

    job_incref(T);
  } else {
    // assert (MODULE_STAT->allocated_targets < MAX_TARGETS);
    T = create_async_job(
        do_conn_target_job,
        JSC_ALLOW(JC_EPOLL, JS_RUN) | JSC_ALLOW(JC_EPOLL, JS_ABORT) |
            JSC_ALLOW(JC_EPOLL, JS_ALARM) | JSC_ALLOW(JC_EPOLL, JS_FINISH),
        -2, sizeof(struct conn_target_info), JT_HAVE_TIMER, JOB_REF_NULL);
    T->j_refcnt = 2;

    struct conn_target_info *t = CONN_TARGET_INFO(T);
    memcpy(t, source, sizeof(*source));
    job_timer_init(T);

    // t->generation = 1;
    int32_t active_targets_delta = 0;
    int32_t inactive_targets_delta = 0;
    int32_t created_state = 0;
    int32_t rc = mtproxy_ffi_net_connections_create_target_transition(
        0, 0, &active_targets_delta, &inactive_targets_delta, &created_state);
    assert(rc == 0);
    MODULE_STAT->active_targets += active_targets_delta;
    MODULE_STAT->inactive_targets += inactive_targets_delta;
    MODULE_STAT->allocated_targets++;

    if (source->target.s_addr) {
      find_target(source->target, source->port, source->type, source->extra, 1,
                  T);
    } else {
      find_target_ipv6(source->target_ipv6, source->port, source->type,
                       source->extra, 1, T);
    }

    if (was_created) {
      *was_created = created_state;
    }
    t->global_refcnt = 1;
    schedule_job(JOB_REF_CREATE_PASS(T));
  }

  pthread_mutex_unlock(&TargetsLock);

  return T;
}

void tcp_set_max_connections(int maxconn) {
  max_connection_fd = maxconn;
  if (!max_special_connections || max_special_connections > maxconn) {
    max_special_connections = maxconn;
  }
}

int create_all_outbound_connections_limited(int limit) { return 0; }

int create_all_outbound_connections(void) {
  return create_all_outbound_connections_limited(0x7fffffff);
}

struct conn_target_pick_ctx {
  connection_job_t *selected;
  int32_t allow_stopped;
};

static void target_pick_policy_callback(connection_job_t C, void *x) {
  struct conn_target_pick_ctx *ctx = x;
  connection_job_t *P = ctx->selected;
  int32_t has_selected = (*P != NULL);
  int32_t selected_ready = has_selected ? CONN_INFO(*P)->ready : 0;
  int32_t should_skip = mtproxy_ffi_net_connections_target_pick_should_skip(
      ctx->allow_stopped, has_selected, selected_ready);
  assert(should_skip == 0 || should_skip == 1);
  if (should_skip) {
    return;
  }

  int32_t candidate_ready = CONN_INFO(C)->type->check_ready(C);
  int32_t selected_unreliability =
      has_selected ? CONN_INFO(*P)->unreliability : 0;
  int32_t should_select = mtproxy_ffi_net_connections_target_pick_should_select(
      ctx->allow_stopped, candidate_ready, has_selected,
      selected_unreliability, CONN_INFO(C)->unreliability);
  assert(should_select == 0 || should_select == 1);
  if (should_select) {
    *P = C;
    return;
  }
}

connection_job_t conn_target_get_connection(conn_target_job_t CT,
                                            int allow_stopped) {
  assert(CT);

  struct conn_target_info *t = CONN_TARGET_INFO(CT);

  struct tree_connection *T = get_tree_ptr_connection(&t->conn_tree);

  connection_job_t S = NULL;
  struct conn_target_pick_ctx ctx = {
      .selected = &S,
      .allow_stopped = !!allow_stopped,
  };
  tree_act_ex_connection(T, target_pick_policy_callback, &ctx);

  int32_t should_incref =
      mtproxy_ffi_net_connections_target_pick_should_incref(S != NULL);
  assert(should_incref == 0 || should_incref == 1);
  if (should_incref) {
    assert(S);
    job_incref(S);
  }
  tree_free_connection(T);

  return S;
}

void insert_free_later_struct(struct free_later *F) {
  if (!free_later_queue) {
    free_later_queue = alloc_mp_queue_w();
  }
  mpq_push_w(free_later_queue, F, 0);
  MODULE_STAT->free_later_size++;
  MODULE_STAT->free_later_total++;
}

void free_later_act(void) {
  if (!free_later_queue) {
    return;
  }
  while (1) {
    struct free_later *F = mpq_pop_nw(free_later_queue, 4);
    if (!F) {
      return;
    }
    MODULE_STAT->free_later_size--;
    F->free(F->ptr);
    free(F);
  }
}

void free_connection_tree_ptr(struct tree_connection *T) {
  free_tree_ptr_connection(T);
}

void incr_active_dh_connections(void) { MODULE_STAT->active_dh_connections++; }

int new_conn_generation(void) {
  return __sync_fetch_and_add(&conn_generation, 1);
}

int get_cur_conn_generation(void) { return conn_generation; }

// -----

int net_add_nat_info(char *str) { return mtproxy_ffi_net_add_nat_info(str); }

unsigned nat_translate_ip(unsigned local_ip) {
  return mtproxy_ffi_net_translate_ip(local_ip);
}
